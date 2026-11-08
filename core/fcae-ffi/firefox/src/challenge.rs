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
const POW_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[async_trait]
pub trait CaptchaSolver: Send + Sync {
    async fn solve(&self, image_data_url: &str) -> Result<String>;
}

pub struct ChallengeService {
    captcha: Option<Arc<dyn CaptchaSolver>>,
    slot: tokio::sync::Mutex<()>,
}

impl ChallengeService {
    pub fn new(captcha: Option<Arc<dyn CaptchaSolver>>) -> Self {
        Self { captcha, slot: tokio::sync::Mutex::new(()) }
    }

    pub async fn solve(&self, parent: &ControlPlane, rejection: &ControlResponse, rejection_origin: &str) -> Result<()> {
        let result = tokio::time::timeout(SOLVE_TIMEOUT, async {
            let _slot = self.slot.lock().await;
            let mut last = FirefoxError::ChallengeRequired;
            let rejection_page = std::str::from_utf8(&rejection.body).ok().filter(|body| is_challenge_page(body));
            let mut bases = Vec::new();
            for base in [rejection_origin, "https://api.accounts.firefox.com", "https://accounts.firefox.com"] {
                if trusted_challenge_base(base) && !bases.contains(&base) {
                    bases.push(base);
                }
            }
            let rejected_base = bases.first().copied() == Some(rejection_origin);
            for (index, base) in bases.iter().enumerate() {
                let solver_http = parent.fresh_jar().with_timeout(SOLVE_TIMEOUT);
                let solved = if index == 0 && rejected_base {
                    if let Some(page) = rejection_page {
                        self.solve_page(&solver_http, base, page).await
                    } else {
                        self.solve_host(&solver_http, base).await
                    }
                } else {
                    self.solve_host(&solver_http, base).await
                };
                match solved {
                    Ok(()) => {
                        parent.import_cookies_for_hosts(&solver_http, &[
                            "accounts.firefox.com",
                            "api.accounts.firefox.com",
                            "oauth.accounts.firefox.com",
                            "vpn.mozilla.org",
                        ]);
                        return Ok(());
                    }
                    Err(error) => last = error,
                }
            }
            Err(last)
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
            if result.status == "success" {
                let (_, still_challenged) = fetch_challenge_page(http, &page_url).await?;
                if still_challenged {
                    return Err(FirefoxError::Protocol("challenge cookie was not accepted".into()));
                }
                return Ok(());
            }
            if result.ch.is_empty() || result.tok.is_empty() {
                return Err(FirefoxError::Protocol("challenge did not provide another round".into()));
            }
            challenges = result.ch;
            token = result.tok;
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
    status: String,
    #[serde(default)]
    ch: Vec<Challenge>,
    #[serde(default)]
    tok: String,
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
        return Err(FirefoxError::Protocol(format!("challenge resource returned HTTP {}", response.status)));
    }
    Ok((body, challenged))
}

async fn fetch_text(http: &ControlPlane, url: &str) -> Result<String> {
    let request = ControlRequest::new(Method::GET, url)?
        .header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")?;
    let response = http.send(request).await?;
    if response.status != 200 {
        return Err(FirefoxError::Protocol(format!("challenge resource returned HTTP {}", response.status)));
    }
    String::from_utf8(response.body).map_err(|_| FirefoxError::Protocol("challenge resource is not UTF-8".into()))
}

async fn fetch_pat(http: &ControlPlane, prefix: &str, token: &str) -> Result<String> {
    let mut url = url::Url::parse(&format!("{prefix}/pat"))?;
    url.query_pairs_mut().append_pair("token", token);
    let origin = prefix.split("/_fs-ch-").next().unwrap_or(prefix);
    let request = ControlRequest::new(Method::POST, url.as_str())?
        .header("accept", "text/plain")?
        .header("content-type", "application/json")?
        .header("origin", origin)?;
    let response = http.send(request).await?;
    if matches!(response.status, 400 | 401) {
        return Ok(String::new());
    }
    if response.status != 200 {
        return Err(FirefoxError::Protocol(format!("PAT request returned HTTP {}", response.status)));
    }
    let value: serde_json::Value = response.json()?;
    value.get("auth").and_then(serde_json::Value::as_str).map(str::to_string)
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
    for (index, _) in script.rmatch_indices("init") {
        if index > 0 && script.as_bytes()[index - 1].is_ascii_alphanumeric() {
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
        rest = rest[used..].trim_start();
        let Some(after_comma) = rest.strip_prefix(',') else { continue };
        let Some((token, used)) = decode_one::<String>(after_comma.trim_start()) else { continue };
        rest = after_comma.trim_start()[used..].trim_start();
        let Some(after_comma) = rest.strip_prefix(',') else { continue };
        let Some((script_prefix, used)) = decode_one::<String>(after_comma.trim_start()) else { continue };
        rest = after_comma.trim_start()[used..].trim_start();
        while let Some(comment) = rest.strip_prefix("/*") {
            let Some(end) = comment.find("*/") else { break };
            rest = comment[end + 2..].trim_start();
        }
        if script_prefix == prefix && !token.is_empty() && !challenges.is_empty()
            && challenges.iter().all(|challenge| !challenge.ty.is_empty())
            && (rest.starts_with(')') || rest.starts_with(','))
        {
            return Ok((challenges, token));
        }
    }
    Err(FirefoxError::Protocol("valid Fastly challenge init call was not found".into()))
}

fn decode_one<T: DeserializeOwned>(input: &str) -> Option<(T, usize)> {
    let mut stream = serde_json::Deserializer::from_str(input).into_iter::<T>();
    let value = stream.next()?.ok()?;
    Some((value, stream.byte_offset()))
}
