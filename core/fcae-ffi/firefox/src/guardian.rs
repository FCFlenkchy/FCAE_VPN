use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use http::{HeaderMap, Method};
use serde::Deserialize;

use crate::challenge::{recover_406, ChallengeService};
use crate::control::{ControlPlane, ControlRequest, ControlResponse};
use crate::error::{FirefoxError, Result};
use crate::types::{ProxyPass, ProxyPassClaims, Usage};

const DEFAULT_ENDPOINT: &str = "https://vpn.mozilla.org";
const CLOCK_TOLERANCE: Duration = Duration::from_secs(60);
const MAX_PASS_LIFETIME: Duration = Duration::from_secs(31 * 24 * 60 * 60);

#[derive(Debug, Clone, Deserialize)]
pub struct Entitlement {
    #[serde(default)]
    pub subscribed: bool,
    #[serde(default)]
    pub uid: i64,
    #[serde(default, rename = "maxBytes")]
    pub max_bytes: String,
    #[serde(default)]
    pub limited_bandwidth: bool,
}

#[derive(Clone)]
pub struct Guardian {
    http: ControlPlane,
    endpoint: String,
    challenges: Option<Arc<ChallengeService>>,
}

impl Guardian {
    pub fn new(http: ControlPlane) -> Self {
        Self { http, endpoint: DEFAULT_ENDPOINT.into(), challenges: None }
    }

    pub fn with_challenges(mut self, challenges: Option<Arc<ChallengeService>>) -> Self {
        self.challenges = challenges;
        self
    }

    pub fn with_endpoint(http: ControlPlane, endpoint: &str) -> Result<Self> {
        let parsed = url::Url::parse(endpoint)?;
        if parsed.scheme() != "https" || parsed.host_str().is_none() || !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(FirefoxError::InvalidConfig("Guardian endpoint must be a credential-free HTTPS URL".into()));
        }
        Ok(Self { http, endpoint: endpoint.trim_end_matches('/').into(), challenges: None })
    }

    async fn get(&self, method: Method, path: &str, access_token: &str) -> Result<ControlResponse> {
        let request = ControlRequest::new(method, &format!("{}{path}", self.endpoint))?
            .header("authorization", format!("Bearer {access_token}"))?
            .header("content-type", "application/json")?
            .header("cache-control", "max-age=0")?;
        let response = self.http.send(request.clone()).await?;
        recover_406(&self.http, self.challenges.as_deref(), request, response).await
    }

    pub async fn fetch_pass(&self, access_token: &str) -> Result<ProxyPass> {
        let received_at = SystemTime::now();
        let response = self.get(Method::GET, "/api/v1/fpn/token", access_token).await?;
        if response.status != 200 {
            return Err(guardian_error(response));
        }
        let token: TokenResponse = response.json()?;
        if token.token.is_empty() || token.token.len() > 16 * 1024 {
            return Err(FirefoxError::Protocol("Guardian returned an empty or oversized proxy pass".into()));
        }
        let claims = parse_claims(&token.token)?;
        let (not_before, expires_at) = anchor_claims(&claims, received_at)?;
        let usage = parse_usage(&response.headers).ok();
        Ok(ProxyPass { token: token.token, claims, received_at, not_before, expires_at, usage })
    }

    pub async fn entitlement(&self, access_token: &str) -> Result<Entitlement> {
        let response = self.get(Method::GET, "/api/v1/fpn/status", access_token).await?;
        if response.status != 200 {
            return Err(guardian_error(response));
        }
        Ok(response.json()?)
    }

    pub async fn activate(&self, access_token: &str) -> Result<Entitlement> {
        let response = self.get(Method::POST, "/api/v1/fpn/activate", access_token).await?;
        if response.status != 200 {
            return Err(guardian_error(response));
        }
        Ok(response.json()?)
    }

    pub async fn usage(&self, access_token: &str) -> Result<Usage> {
        let response = self.get(Method::HEAD, "/api/v1/fpn/token", access_token).await?;
        if response.status == 403 {
            let response = self.get(Method::GET, "/api/v1/fpn/token", access_token).await?;
            if response.status == 403 {
                return Err(FirefoxError::NotEntitled);
            }
            if response.status == 200 || response.status == 429 {
                return parse_usage(&response.headers);
            }
            return Err(guardian_error(response));
        }
        if response.status == 200 || response.status == 429 {
            return parse_usage(&response.headers);
        }
        Err(guardian_error(response))
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
}

fn parse_claims(token: &str) -> Result<ProxyPassClaims> {
    let mut parts = token.split('.');
    let (Some(_head), Some(payload), Some(_signature), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(FirefoxError::Protocol("proxy pass is not a three-part JWT".into()));
    };
    let decoded = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('='))
        .map_err(|_| FirefoxError::Protocol("proxy pass payload is not base64url".into()))?;
    if decoded.len() > 64 * 1024 {
        return Err(FirefoxError::Protocol("proxy pass claims are too large".into()));
    }
    let claims: ProxyPassClaims = serde_json::from_slice(&decoded)?;
    if claims.exp <= 0 {
        return Err(FirefoxError::Protocol("proxy pass has no expiration".into()));
    }
    Ok(claims)
}

fn anchor_claims(claims: &ProxyPassClaims, received: SystemTime) -> Result<(SystemTime, SystemTime)> {
    let start = if claims.nbf > 0 { claims.nbf } else { claims.iat };
    let raw_expiry = UNIX_EPOCH.checked_add(Duration::from_secs(claims.exp as u64))
        .ok_or_else(|| FirefoxError::Protocol("proxy pass expiration is out of range".into()))?;
    if start <= 0 {
        return Ok((received, raw_expiry));
    }
    if claims.exp <= start {
        return Err(FirefoxError::Protocol("proxy pass expires before it becomes valid".into()));
    }
    let lifetime = Duration::from_secs((claims.exp - start) as u64);
    if lifetime > MAX_PASS_LIFETIME {
        return Err(FirefoxError::Protocol("proxy pass lifetime exceeds the accepted limit".into()));
    }
    let raw_start = UNIX_EPOCH.checked_add(Duration::from_secs(start as u64))
        .ok_or_else(|| FirefoxError::Protocol("proxy pass start time is out of range".into()))?;
    let difference = received.duration_since(raw_start).unwrap_or_else(|error| error.duration());
    if difference <= CLOCK_TOLERANCE {
        Ok((raw_start, raw_expiry))
    } else {
        Ok((received, received.checked_add(lifetime).ok_or_else(|| FirefoxError::Protocol("proxy pass expiration overflow".into()))?))
    }
}

fn parse_usage(headers: &HeaderMap) -> Result<Usage> {
    let get = |name: &str| headers.get(name).and_then(|value| value.to_str().ok()).map(str::trim).filter(|value| !value.is_empty());
    if get("x-quota-unlimited").is_some_and(|value| value.eq_ignore_ascii_case("true")) {
        return Ok(Usage { unlimited: true, ..Usage::default() });
    }
    let limit = get("x-quota-limit").ok_or_else(|| FirefoxError::Protocol("quota limit is missing".into()))?
        .parse::<i64>().ok().filter(|value| *value >= 0)
        .ok_or_else(|| FirefoxError::Protocol("invalid quota limit".into()))?;
    let remaining = get("x-quota-remaining").ok_or_else(|| FirefoxError::Protocol("remaining quota is missing".into()))?
        .parse::<i64>().ok().filter(|value| *value >= 0 && *value <= limit)
        .ok_or_else(|| FirefoxError::Protocol("invalid remaining quota".into()))?;
    let raw_reset = get("x-quota-reset").ok_or_else(|| FirefoxError::Protocol("quota reset is missing".into()))?;
    let reset = DateTime::parse_from_rfc3339(raw_reset).map(|value| value.with_timezone(&Utc)).ok()
        .or_else(|| raw_reset.parse::<i64>().ok().filter(|seconds| *seconds > 0)
            .and_then(|seconds| DateTime::from_timestamp(seconds, 0)));
    let reset = reset.ok_or_else(|| FirefoxError::Protocol("invalid quota reset time".into()))?;
    Ok(Usage { unlimited: false, limit, remaining, reset: Some(reset) })
}

fn guardian_error(response: ControlResponse) -> FirefoxError {
    let usage = parse_usage(&response.headers).ok();
    match response.status {
        401 => FirefoxError::ReauthRequired,
        403 => FirefoxError::NotEntitled,
        429 => FirefoxError::QuotaExhausted(usage.as_ref().map(Usage::reset_suffix).unwrap_or_default()),
        451 => FirefoxError::RegionUnavailable,
        _ => FirefoxError::Http {
            host: "vpn.mozilla.org".into(),
            status: response.status,
            errno: response.errno(),
            retry_after: response.retry_after(),
            message: response.message(),
        },
    }
}
