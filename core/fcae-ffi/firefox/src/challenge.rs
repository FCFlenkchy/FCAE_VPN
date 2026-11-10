use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use http::Method;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use crate::control::{ControlPlane, ControlRequest, ControlResponse};
use crate::error::{FirefoxError, Result};

const SOLVE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_ROUNDS: usize = 8;
const MAX_SCRIPT_ATTEMPTS: usize = 3;
const SCRIPT_ERROR_HOST: &str = "Fastly challenge script";
const POW_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[async_trait]
pub trait CaptchaSolver: Send + Sync {
    async fn solve(&self, image_data_url: &str) -> Result<String>;
}

pub struct ChallengeService {
    captcha: Option<Arc<dyn CaptchaSolver>>,
    slot: tokio::sync::Mutex<()>,
}

pub(crate) async fn recover_406(
    http: &ControlPlane,
    challenges: Option<&ChallengeService>,
    request: ControlRequest,
    mut response: ControlResponse,
) -> Result<ControlResponse> {
    let mut attempts = 0;
    while response.status == 406 {
        if attempts >= 3 {
            return Err(FirefoxError::ChallengeRequired);
        }
        let challenges = challenges.ok_or(FirefoxError::ChallengeRequired)?;
        let origin = format!("https://{}", request.host);
        challenges.solve(http, &response, &origin).await?;
        attempts += 1;
        response = http.send(request.clone()).await?;
    }
    Ok(response)
}

impl ChallengeService {
    pub fn new(captcha: Option<Arc<dyn CaptchaSolver>>) -> Self {
        Self { captcha, slot: tokio::sync::Mutex::new(()) }
    }

    pub async fn solve(&self, parent: &ControlPlane, rejection: &ControlResponse, rejection_origin: &str) -> Result<()> {
        let result = tokio::time::timeout(SOLVE_TIMEOUT, async {
            let _slot = self.slot.lock().await;
            let mut failures = Vec::new();
            let rejection_page = std::str::from_utf8(&rejection.body).ok().filter(|body| is_challenge_page(body));
            let mut bases = Vec::new();
            for base in [rejection_origin, "https://api.accounts.firefox.com", "https://accounts.firefox.com"] {
                if trusted_challenge_base(base) && !bases.contains(&base) {
                    bases.push(base);
                }
            }
            let rejected_base = bases.first().copied() == Some(rejection_origin);
            for (index, base) in bases.iter().enumerate() {
                for attempt in 0..MAX_SCRIPT_ATTEMPTS {
                    let solver_http = parent.fresh_jar().with_timeout(SOLVE_TIMEOUT).with_challenge_h2();
                    let solved = if index == 0 && rejected_base && attempt == 0 {
                        if let Some(page) = rejection_page {
                            if let Some(host) = base.strip_prefix("https://") {
                                solver_http.store_cookies(host, &rejection.headers);
                            }
                            self.solve_page(&solver_http, base, page).await
                        } else {
                            self.solve_host(&solver_http, base).await
                        }
                    } else {
                        self.solve_host(&solver_http, base).await
                    };
                    match solved {
                        Ok(()) if !solver_http.has_cookies() => {
                            failures.push(format!("{base}: challenge completed but no cookies were issued"));
                        }
                        Ok(()) => {
                            parent.import_cookies_for_hosts(&solver_http, &[
                                "accounts.firefox.com",
                                "api.accounts.firefox.com",
                                "oauth.accounts.firefox.com",
                                "vpn.mozilla.org",
                            ]);
                            return Ok(());
                        }
                        Err(FirefoxError::ChallengeRequired) => return Err(FirefoxError::ChallengeRequired),
                        Err(error) if is_script_state_rejection(&error) && attempt + 1 < MAX_SCRIPT_ATTEMPTS => continue,
                        Err(error) => failures.push(format!("{base}: {error}")),
                    }
                    break;
                }
            }
            Err(FirefoxError::Protocol(format!("Fastly challenge failed ({})", failures.join("; "))))
        }).await.map_err(|_| FirefoxError::Timeout(SOLVE_TIMEOUT))?;
        result
    }

    async fn solve_host(&self, http: &ControlPlane, base: &str) -> Result<()> {
        let page_url = format!("{base}/");
        let (page, challenged) = fetch_challenge_page(http, &page_url).await?;
        if !challenged {
            return Err(FirefoxError::Protocol("host did not serve a Fastly challenge page".into()));
        }
        self.solve_page(http, base, &page).await
    }

    async fn solve_page(&self, http: &ControlPlane, base: &str, page: &str) -> Result<()> {
        let page_url = format!("{base}/");
        let prefix = challenge_prefix(page).ok_or_else(|| FirefoxError::Protocol("challenge asset prefix is missing".into()))?;
        let script = fetch_text(http, &format!("{base}{prefix}/script.js?reload=true")).await?;
        let (mut challenges, mut token) = parse_challenge_init(&script, &prefix)?;

        for _ in 0..MAX_ROUNDS {
            let mut answers = Vec::with_capacity(challenges.len());
            for challenge in challenges {
                answers.push(self.answer(http, &format!("{base}{prefix}"), &token, challenge).await?);
            }
            let body = serde_json::json!({"token": token, "data": answers});
            let request = ControlRequest::new(Method::POST, &format!("{base}{prefix}/fst-post-back"))?
                .header("accept", "application/json")?
                .header("origin", base)?
                .json(&body)?;
            let response = http.send(request).await?;
            if response.status != 200 {
                return Err(FirefoxError::Protocol(format!("challenge post-back returned HTTP {}", response.status)));
            }
            let result: PostBackResponse = response.json()?;
            match result.next_round()? {
                None => {
                    let (_, still_challenged) = fetch_challenge_page(http, &page_url).await?;
                    if still_challenged {
                        return Err(FirefoxError::Protocol("challenge cookie was not accepted".into()));
                    }
                    return Ok(());
                }
                Some((next_challenges, next_token)) => {
                    challenges = next_challenges;
                    token = next_token;
                }
            }
        }
        Err(FirefoxError::Protocol("Fastly challenge exceeded its round limit".into()))
    }

    async fn answer(&self, http: &ControlPlane, prefix: &str, token: &str, challenge: Challenge) -> Result<serde_json::Value> {
        match challenge.ty.as_str() {
            "pow" => {
                let data: PowData = serde_json::from_value(challenge.data)?;
                let answer = solve_pow(&data.base, &data.hash)
                    .ok_or_else(|| FirefoxError::Protocol("proof-of-work challenge has no solution".into()))?;
                Ok(serde_json::json!({"ty":"pow", "base":data.base, "answer":answer, "hmac":data.hmac, "expires":data.expires}))
            }
            "pat" => Ok(serde_json::json!({"ty":"pat", "auth":fetch_pat(http, prefix, token).await?})),
            "clientmetrics" => Ok(serde_json::json!({
                "ty":"clientmetrics", "webdriver":false,
                "bot_detection_result":{"bot_detected":false,"bot_kind":null},
                "browser_metrics":{"client_data":"{}","error_trace":null},
                "detector_results":{}, "v":2
            })),
            "captcha" => {
                let solver = self.captcha.as_ref().ok_or(FirefoxError::ChallengeRequired)?;
                let data: CaptchaData = serde_json::from_value(challenge.data)?;
                if !data.image_b64.starts_with("data:image/") || data.image_b64.len() > 2 * 1024 * 1024 {
                    return Err(FirefoxError::Protocol("unrecognized CAPTCHA data".into()));
                }
                let answer = solver.solve(&data.image_b64).await?;
                if answer.trim().is_empty() || answer.len() > 256 {
                    return Err(FirefoxError::Protocol("CAPTCHA answer is empty or too long".into()));
                }
                Ok(serde_json::json!({"ty":"captcha", "answer":answer.trim()}))
            }
            _ => Err(FirefoxError::Protocol(format!("unsupported Fastly challenge type {}", challenge.ty))),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Challenge {
    ty: String,
    data: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct PowData {
    base: String,
    expires: String,
    hmac: String,
    hash: String,
}

#[derive(Debug, Deserialize)]
struct CaptchaData {
    image_b64: String,
}

#[derive(Debug, Deserialize)]
struct PostBackResponse {
    #[serde(default)]
    status: String,
    #[serde(default)]
    ch: Vec<Challenge>,
    #[serde(default)]
    tok: String,
}

impl PostBackResponse {
    fn next_round(self) -> Result<Option<(Vec<Challenge>, String)>> {
        if self.status == "success" {
            return Ok(None);
        }
        if self.ch.is_empty() || self.tok.is_empty() {
            return Err(FirefoxError::Protocol("challenge did not provide another round".into()));
        }
        Ok(Some((self.ch, self.tok)))
    }
}

fn is_script_state_rejection(error: &FirefoxError) -> bool {
    matches!(error, FirefoxError::Http { host, status: 400, .. } if host == SCRIPT_ERROR_HOST)
}

fn trusted_challenge_base(base: &str) -> bool {
    matches!(base,
        "https://api.accounts.firefox.com"
            | "https://accounts.firefox.com"
            | "https://oauth.accounts.firefox.com"
            | "https://vpn.mozilla.org"
    )
}

fn is_challenge_page(body: &str) -> bool {
    !body.is_empty()
        && body.contains("/_fs-ch-")
        && (body.contains("Client Challenge") || body.contains("script.js") || body.contains("fst-post-back"))
}

async fn fetch_challenge_page(http: &ControlPlane, url: &str) -> Result<(String, bool)> {
    let request = ControlRequest::new(Method::GET, url)?
        .header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")?;
    let response = http.send(request).await?;
    let body = String::from_utf8(response.body).map_err(|_| FirefoxError::Protocol("challenge resource is not UTF-8".into()))?;
    let challenged = is_challenge_page(&body);
    if response.status != 200 && !challenged {
        return Err(FirefoxError::Protocol(format!("challenge page returned HTTP {}", response.status)));
    }
    Ok((body, challenged))
}

async fn fetch_text(http: &ControlPlane, url: &str) -> Result<String> {
    let request = ControlRequest::new(Method::GET, url)?
        .header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")?;
    let response = http.send(request).await?;
    if response.status != 200 {
        return Err(FirefoxError::Http {
            host: SCRIPT_ERROR_HOST.into(),
            status: response.status,
            errno: None,
            retry_after: response.retry_after(),
            message: "challenge script request failed".into(),
        });
    }
    String::from_utf8(response.body).map_err(|_| FirefoxError::Protocol("challenge resource is not UTF-8".into()))
}

fn pat_request(prefix: &str, token: &str) -> Result<ControlRequest> {
    let mut url = url::Url::parse(&format!("{prefix}/pat"))?;
    url.query_pairs_mut().append_pair("token", token);
    let origin = prefix.split("/_fs-ch-").next().unwrap_or(prefix);
    let mut request = ControlRequest::new(Method::POST, url.as_str())?
        .header("accept", "text/plain")?
        .header("content-type", "application/json")?
        .header("origin", origin)?;
    request.body = Some(Vec::new());
    Ok(request)
}

async fn fetch_pat(http: &ControlPlane, prefix: &str, token: &str) -> Result<String> {
    let response = http.send(pat_request(prefix, token)?).await?;
    if matches!(response.status, 400 | 401) {
        return Ok(String::new());
    }
    if response.status != 200 {
        return Err(FirefoxError::Protocol(format!("PAT request returned HTTP {}", response.status)));
    }
    let value: serde_json::Value = response.json()?;
    value.get("auth").and_then(serde_json::Value::as_str).filter(|auth| !auth.is_empty()).map(str::to_string)
        .ok_or_else(|| FirefoxError::Protocol("PAT response has no auth token".into()))
}

fn solve_pow(base: &str, target_hex: &str) -> Option<String> {
    let target = hex::decode(target_hex).ok()?;
    if target.len() != 32 || base.len() > 4096 {
        return None;
    }
    let mut input = Vec::with_capacity(base.len() + 2);
    input.extend_from_slice(base.as_bytes());
    input.extend_from_slice(b"aa");
    for first in POW_ALPHABET {
        input[base.len()] = *first;
        for second in POW_ALPHABET {
            input[base.len() + 1] = *second;
            if Sha256::digest(&input).as_slice() == target {
                return Some(format!("{}{}", *first as char, *second as char));
            }
        }
    }
    None
}

fn challenge_prefix(page: &str) -> Option<String> {
    let start = page.find("/_fs-ch-")?;
    let suffix = page[start + 8..].bytes().take_while(u8::is_ascii_alphanumeric).count();
    (suffix > 0).then(|| page[start..start + 8 + suffix].to_string())
}

fn parse_challenge_init(script: &str, prefix: &str) -> Result<(Vec<Challenge>, String)> {
    let mut legacy = None;
    for (index, _) in script.rmatch_indices("init") {
        if index > 0 && (script.as_bytes()[index - 1].is_ascii_alphanumeric() || script.as_bytes()[index - 1] == b'_') {
            continue;
        }
        let mut rest = &script[index + 4..];
        rest = rest.trim_start();
        let Some(after_open) = rest.strip_prefix('(') else { continue };
        rest = after_open.trim_start();
        if !rest.starts_with('[') {
            continue;
        }
        let Some((challenges, used)) = decode_one::<Vec<Challenge>>(rest) else { continue };
        if challenges.is_empty() || challenges.len() > 16
            || challenges.iter().any(|challenge| challenge.ty.trim().is_empty())
        {
            continue;
        }
        rest = rest[used..].trim_start();
        let Some(after_comma) = rest.strip_prefix(',') else { continue };
        let Some((token, used)) = decode_one::<String>(after_comma.trim_start()) else { continue };
        if token.trim().is_empty() {
            continue;
        }
        rest = after_comma.trim_start()[used..].trim_start();
        if rest.starts_with(')') {
            if legacy.is_none() {
                legacy = Some((challenges, token));
            }
            continue;
        }
        let Some(after_comma) = rest.strip_prefix(',') else { continue };
        let Some((script_prefix, used)) = decode_one::<String>(after_comma.trim_start()) else { continue };
        rest = after_comma.trim_start()[used..].trim_start();
        while let Some(comment) = rest.strip_prefix("/*") {
            let Some(end) = comment.find("*/") else { break };
            rest = comment[end + 2..].trim_start();
        }
        if script_prefix == prefix && has_init_delimiter(rest) {
            return Ok((challenges, token));
        }
    }
    legacy.ok_or_else(|| FirefoxError::Protocol("valid Fastly challenge init call was not found".into()))
}

fn has_init_delimiter(rest: &str) -> bool {
    rest.starts_with(')') || rest.strip_prefix(',').is_some_and(|tail| !tail.trim_start().is_empty())
}

fn decode_one<T: DeserializeOwned>(input: &str) -> Option<(T, usize)> {
    let mut stream = serde_json::Deserializer::from_str(input).into_iter::<T>();
    let value = stream.next()?.ok()?;
    Some((value, stream.byte_offset()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    #[test]
    fn post_back_accepts_next_round_without_status() {
        let result: PostBackResponse = serde_json::from_str(
            r#"{"ch":[{"ty":"pow","data":{"base":"seed","hash":"target","hmac":"signature","expires":"later"}},{"ty":"clientmetrics","data":{}}],"tok":"next-token"}"#,
        ).unwrap();
        let (challenges, token) = result.next_round().unwrap().unwrap();
        assert_eq!(challenges.len(), 2);
        assert_eq!(challenges[0].ty, "pow");
        assert_eq!(challenges[1].ty, "clientmetrics");
        assert_eq!(token, "next-token");
    }

    #[test]
    fn post_back_accepts_success_without_next_round() {
        let result: PostBackResponse = serde_json::from_str(r#"{"status":"success"}"#).unwrap();
        assert!(result.next_round().unwrap().is_none());
    }

    #[test]
    fn post_back_rejects_incomplete_next_round() {
        for body in [r#"{}"#, r#"{"ch":[{"ty":"pat","data":{}}]}"#, r#"{"tok":"next-token"}"#] {
            let result: PostBackResponse = serde_json::from_str(body).unwrap();
            assert!(result.next_round().is_err());
        }
    }

    #[test]
    fn post_back_rejects_invalid_status_type() {
        assert!(serde_json::from_str::<PostBackResponse>(r#"{"status":42}"#).is_err());
    }

    #[test]
    fn pat_post_has_explicit_empty_body() {
        let request = pat_request("https://accounts.firefox.com/_fs-ch-test", "a+b /?").unwrap();
        assert_eq!(request.method, Method::POST);
        assert_eq!(request.body.as_deref(), Some(&b""[..]));
        assert_eq!(request.path, "/_fs-ch-test/pat?token=a%2Bb+%2F%3F");
    }

    #[test]
    fn rejection_cookies_can_seed_an_isolated_solver_jar() {
        let parent = ControlPlane::new(crate::dialer::Dialer::new(None, None, 10).unwrap());
        let solver = parent.fresh_jar();
        let mut headers = HeaderMap::new();
        headers.append(http::header::SET_COOKIE, "challenge_session=value; Path=/; Secure".parse().unwrap());
        solver.store_cookies("api.accounts.firefox.com", &headers);
        assert!(solver.has_cookies());
        assert!(!parent.has_cookies());
    }

    #[test]
    fn only_script_400_restarts_with_a_fresh_page() {
        let script_error = |status| FirefoxError::Http {
            host: SCRIPT_ERROR_HOST.into(), status, errno: None, retry_after: None, message: String::new(),
        };
        assert!(is_script_state_rejection(&script_error(400)));
        assert!(!is_script_state_rejection(&script_error(429)));
        assert!(!is_script_state_rejection(&FirefoxError::Http {
            host: "api.accounts.firefox.com".into(), status: 400, errno: Some(125), retry_after: None, message: String::new(),
        }));
    }
}
