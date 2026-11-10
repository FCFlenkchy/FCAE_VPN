use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http::Method;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::challenge::{recover_406, ChallengeService};
use crate::control::{ControlPlane, ControlRequest, ControlResponse};
use crate::crypto::{derive_auth_pw, derive_hawk, hawk_header, normalize_code, normalize_email, random_urlsafe, valid_email};
use crate::error::{FirefoxError, Result};

pub const FXA_AUTH: &str = "https://api.accounts.firefox.com/v1";
pub const FXA_OAUTH: &str = "https://oauth.accounts.firefox.com/v1";
pub const FIREFOX_CLIENT_ID: &str = "5882386c6d801776";
pub const FIREFOX_SCOPE: &str = "profile https://identity.mozilla.com/apps/vpn";
pub const LEGACY_FIREFOX_CLIENT_ID: &str = "a2270f727f45f648";
pub const LEGACY_FIREFOX_SCOPE: &str = "https://identity.mozilla.com/apps/secure-proxy";

#[derive(Debug, Clone, Deserialize)]
pub struct LoginResponse {
    pub uid: String,
    #[serde(rename = "sessionToken")]
    pub session_token: String,
    pub verified: bool,
    #[serde(default)]
    pub email: String,
    #[serde(default, rename = "verificationMethod")]
    pub verification_method: Option<String>,
    #[serde(default, rename = "verificationReason")]
    pub verification_reason: Option<String>,
    #[serde(default, rename = "authAt")]
    pub auth_at: u64,
}

impl Drop for LoginResponse {
    fn drop(&mut self) {
        self.session_token.zeroize();
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: u64,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub token_type: String,
}

#[derive(Clone)]
pub struct Fxa {
    http: ControlPlane,
    challenges: Option<Arc<ChallengeService>>,
}

impl Fxa {
    pub fn new(http: ControlPlane) -> Self {
        Self { http, challenges: None }
    }

    pub fn with_challenges(mut self, challenges: Arc<ChallengeService>) -> Self {
        self.challenges = Some(challenges);
        self
    }

    pub(crate) fn challenge_service(&self) -> Option<Arc<ChallengeService>> {
        self.challenges.clone()
    }

    async fn request(&self, request: ControlRequest) -> Result<ControlResponse> {
        let response = self.http.send(request.clone()).await?;
        recover_406(&self.http, self.challenges.as_deref(), request, response).await
    }

    pub async fn login(&self, email: &str, password: &str, unblock_code: Option<&str>) -> Result<LoginResponse> {
        let email = normalize_email(email);
        if !valid_email(&email) || password.is_empty() || password.len() > 1024 {
            return Err(FirefoxError::InvalidConfig("a valid email and non-empty password are required".into()));
        }
        match self.login_as(&email, None, password, unblock_code, true).await {
            Err(FirefoxError::EmailCaseCorrection(corrected)) if !corrected.is_empty() && corrected != email => {
                match self.login_as(&corrected, Some(&email), password, unblock_code, true).await {
                    Err(error) if is_request_blocked(&error) => {
                        Err(FirefoxError::UnblockCodeRequired(corrected))
                    }
                    result => result,
                }
            }
            Err(error) if is_request_blocked(&error) => Err(FirefoxError::UnblockCodeRequired(email)),
            result => result,
        }
    }

    async fn login_as(&self, email: &str, original: Option<&str>, password: &str, unblock_code: Option<&str>, verification: bool) -> Result<LoginResponse> {
        let result = self.login_attempt(email, original, password, unblock_code, verification).await;
        match result {
            Err(FirefoxError::Http { status: 400, errno: Some(107), .. }) if verification => {
                self.login_attempt(email, original, password, unblock_code, false).await
            }
            result => result,
        }
    }

    async fn login_attempt(&self, email: &str, original: Option<&str>, password: &str, unblock_code: Option<&str>, verification: bool) -> Result<LoginResponse> {
        let mut auth_pw = derive_auth_pw(email, password);
        let mut body = serde_json::json!({
            "email": email,
            "authPW": hex::encode(auth_pw),
        });
        if let Some(original) = original {
            body["originalLoginEmail"] = serde_json::Value::String(original.to_string());
        }
        if verification {
            body["verificationMethod"] = serde_json::Value::String("email-2fa".into());
        }
        if let Some(code) = unblock_code.map(normalize_code).filter(|code| !code.is_empty()) {
            body["unblockCode"] = serde_json::Value::String(code.to_ascii_uppercase());
        }
        auth_pw.zeroize();
        let request = ControlRequest::new(Method::POST, &format!("{FXA_AUTH}/account/login"))?.json(&body)?;
        let response = self.request(request).await?;
        if response.status == 400 && response.errno() == Some(120) {
            let value: serde_json::Value = response.json()?;
            let corrected = value.get("email").and_then(serde_json::Value::as_str).unwrap_or("").to_string();
            return Err(FirefoxError::EmailCaseCorrection(corrected));
        }
        ensure_success(&response, "api.accounts.firefox.com")?;
        let mut login: LoginResponse = response.json()?;
        if login.uid.is_empty() || login.session_token.is_empty() {
            return Err(FirefoxError::Protocol("FxA sign-in response is missing account credentials".into()));
        }
        login.email = email.to_string();
        Ok(login)
    }

    pub async fn send_unblock_code(&self, email: &str) -> Result<()> {
        let body = serde_json::json!({"email": normalize_email(email)});
        let response = self.request(ControlRequest::new(Method::POST, &format!("{FXA_AUTH}/account/login/send_unblock_code"))?.json(&body)?).await?;
        ensure_success(&response, "api.accounts.firefox.com")
    }

    pub async fn verify_email_code(&self, session_token: &str, code: &str) -> Result<()> {
        let code = normalize_code(code);
        if code.is_empty() {
            return Err(FirefoxError::InvalidConfig("the emailed verification code cannot be empty".into()));
        }
        let body = serde_json::to_vec(&serde_json::json!({"code": code}))?;
        self.hawk_json(Method::POST, &format!("{FXA_AUTH}/session/verify_code"), session_token, body).await?;
        Ok(())
    }

    pub async fn resend_email_code(&self, session_token: &str) -> Result<()> {
        self.hawk_json(Method::POST, &format!("{FXA_AUTH}/session/resend_code"), session_token, b"{}".to_vec()).await?;
        Ok(())
    }

    pub async fn verify_totp(&self, session_token: &str, code: &str) -> Result<()> {
        let code = normalize_code(code);
        if code.is_empty() {
            return Err(FirefoxError::InvalidConfig("the authenticator code cannot be empty".into()));
        }
        let body = serde_json::to_vec(&serde_json::json!({"code": code}))?;
        let response = self.hawk_json(Method::POST, &format!("{FXA_AUTH}/session/verify/totp"), session_token, body).await?;
        let result: serde_json::Value = response.json()?;
        if result.get("success").and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(FirefoxError::Http {
                host: "api.accounts.firefox.com".into(),
                status: 400,
                errno: None,
                retry_after: None,
                message: "the authenticator code was not accepted".into(),
            });
        }
        Ok(())
    }

    pub async fn session_verified(&self, session_token: &str) -> Result<bool> {
        let response = self.hawk(Method::GET, &format!("{FXA_AUTH}/recovery_email/status"), session_token, None).await?;
        ensure_success(&response, "api.accounts.firefox.com")?;
        let status: serde_json::Value = response.json()?;
        status.get("verified").and_then(serde_json::Value::as_bool)
            .ok_or_else(|| FirefoxError::Protocol("FxA session status is missing verified state".into()))
    }

    pub async fn oauth_from_session(&self, session_token: &str) -> Result<OAuthTokens> {
        let (id, mut key) = derive_hawk(session_token, "sessionToken")?;
        let body = serde_json::to_vec(&serde_json::json!({
            "client_id": FIREFOX_CLIENT_ID,
            "grant_type": "fxa-credentials",
            "scope": FIREFOX_SCOPE,
            "access_type": "offline",
        }))?;
        let url = format!("{FXA_AUTH}/oauth/token");
        let authorization = hawk_header("POST", &url, &id, &key, Some(&body))?;
        let request = oauth_request(&url, body.clone())?.header("authorization", &authorization)?;
        let response = self.http.send(request).await;
        key.zeroize();
        match response {
            Ok(response) if response.status == 200 => parse_tokens(response),
            Ok(response) if response.status == 406 => self.oauth_code(session_token).await,
            Ok(response) => Err(api_error("api.accounts.firefox.com", response)),
            Err(error) => Err(error),
        }
    }

    async fn oauth_code(&self, session_token: &str) -> Result<OAuthTokens> {
        let (id, mut key) = derive_hawk(session_token, "sessionToken")?;
        let verifier = random_urlsafe(32);
        let state = random_urlsafe(24);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let body = serde_json::to_vec(&serde_json::json!({
            "client_id": FIREFOX_CLIENT_ID,
            "response_type": "code",
            "scope": FIREFOX_SCOPE,
            "state": state,
            "access_type": "offline",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }))?;
        let url = format!("{FXA_AUTH}/oauth/authorization");
        let authorization = hawk_header("POST", &url, &id, &key, Some(&body))?;
        key.zeroize();
        let response = self.request(oauth_request(&url, body)?.header("authorization", &authorization)?).await?;
        ensure_success(&response, "api.accounts.firefox.com")?;
        let grant: serde_json::Value = response.json()?;
        if grant.get("state").and_then(serde_json::Value::as_str) != Some(state.as_str()) {
            return Err(FirefoxError::Protocol("OAuth authorization state mismatch".into()));
        }
        let code = grant.get("code").and_then(serde_json::Value::as_str)
            .filter(|code| !code.is_empty())
            .ok_or_else(|| FirefoxError::Protocol("OAuth authorization response has no code".into()))?;
        let body = serde_json::json!({
            "client_id": FIREFOX_CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
        });
        let response = self.request(oauth_request(&format!("{FXA_OAUTH}/token"), serde_json::to_vec(&body)?)?).await?;
        ensure_success(&response, "oauth.accounts.firefox.com")?;
        parse_tokens(response)
    }

    pub async fn refresh_token(&self, refresh_token: &str, client_id: &str, scope: &str) -> Result<OAuthTokens> {
        let body = serde_json::to_vec(&serde_json::json!({
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "ttl": 1296000,
            "scope": scope,
        }))?;
        let request = oauth_request(&format!("{FXA_AUTH}/oauth/token"), body.clone())?;
        let primary = self.http.send(request.clone()).await?;
        let (response, response_host) = if primary.status == 406 {
            let alternate = self.http.send(oauth_request(&format!("{FXA_OAUTH}/token"), body)?).await;
            match alternate {
                Ok(response) if response.status != 406 => (response, "oauth.accounts.firefox.com"),
                _ => (recover_406(&self.http, self.challenges.as_deref(), request, primary).await?, "api.accounts.firefox.com"),
            }
        } else {
            (primary, "api.accounts.firefox.com")
        };
        let rejected = if response_host == "oauth.accounts.firefox.com" {
            response.status == 400 && response.errno() == Some(108)
        } else {
            matches!(response.status, 400 | 401 | 403) && response.errno() != Some(107)
        };
        if rejected {
            return Err(FirefoxError::ReauthRequired);
        }
        ensure_success(&response, response_host)?;
        parse_tokens(response)
    }

    pub async fn destroy_session(&self, session_token: &str) -> Result<()> {
        self.hawk_json(Method::POST, &format!("{FXA_AUTH}/session/destroy"), session_token, b"{}".to_vec()).await?;
        Ok(())
    }

    pub async fn register_device(&self, refresh_token: &str, id: Option<&str>) -> Result<String> {
        if refresh_token.is_empty() {
            return Err(FirefoxError::ReauthRequired);
        }
        let mut body = serde_json::json!({"name":"Firefox's built-in VPN", "type":"desktop"});
        if let Some(id) = id.filter(|id| !id.is_empty()) {
            body["id"] = serde_json::Value::String(id.to_string());
        }
        let response = self.request(ControlRequest::new(Method::POST, &format!("{FXA_AUTH}/account/device"))?
            .header("authorization", format!("Bearer {refresh_token}"))?
            .json(&body)?).await?;
        if matches!(response.status, 400 | 401 | 403) && response.errno() != Some(107) {
            return Err(FirefoxError::ReauthRequired);
        }
        ensure_success(&response, "api.accounts.firefox.com")?;
        let value: serde_json::Value = response.json()?;
        value.get("id").and_then(serde_json::Value::as_str).filter(|id| !id.is_empty()).map(str::to_string)
            .ok_or_else(|| FirefoxError::Protocol("device registration response has no id".into()))
    }

    pub async fn revoke_token(&self, token: &str, client_id: &str) -> Result<()> {
        if token.is_empty() {
            return Ok(());
        }
        let body = serde_json::json!({"client_id":client_id, "token":token});
        let response = self.request(ControlRequest::new(Method::POST, &format!("{FXA_OAUTH}/destroy"))?.json(&body)?).await?;
        if response.status == 400 || response.status == 401 || response.status == 403 {
            return Ok(());
        }
        ensure_success(&response, "oauth.accounts.firefox.com")
    }

    pub async fn password_forgot_code(&self, email: &str) -> Result<()> {
        let body = serde_json::json!({"email": normalize_email(email), "service": "sync"});
        let response = self.request(ControlRequest::new(Method::POST, &format!("{FXA_AUTH}/account/password/forgot/send_code"))?.json(&body)?).await?;
        ensure_success(&response, "api.accounts.firefox.com")
    }

    pub async fn password_forgot_verify(&self, email: &str, code: &str) -> Result<String> {
        let body = serde_json::json!({"email": normalize_email(email), "code": normalize_code(code)});
        let response = self.request(ControlRequest::new(Method::POST, &format!("{FXA_AUTH}/account/password/forgot/verify_code"))?.json(&body)?).await?;
        ensure_success(&response, "api.accounts.firefox.com")?;
        let value: serde_json::Value = response.json()?;
        value.get("accountResetToken").and_then(serde_json::Value::as_str).map(str::to_string)
            .ok_or_else(|| FirefoxError::Protocol("password reset response is missing accountResetToken".into()))
    }

    pub async fn password_reset(&self, email: &str, code: &str, new_password: &str) -> Result<()> {
        if new_password.is_empty() || new_password.len() > 1024 {
            return Err(FirefoxError::InvalidConfig("the new password must be non-empty and at most 1024 bytes".into()));
        }
        let email = normalize_email(email);
        let reset_token = zeroize::Zeroizing::new(self.password_forgot_verify(&email, code).await?);
        let mut auth_pw = derive_auth_pw(&email, new_password);
        let body = serde_json::to_vec(&serde_json::json!({"authPW": hex::encode_upper(auth_pw)}))?;
        auth_pw.zeroize();
        let url = format!("{FXA_AUTH}/account/reset");
        let (id, mut key) = derive_hawk(&reset_token, "accountResetToken")?;
        let authorization = hawk_header("POST", &url, &id, &key, Some(&body))?;
        key.zeroize();
        let request = ControlRequest::new(Method::POST, &url)?
            .header("authorization", &authorization)?
            .header("content-type", "application/json")?;
        let mut request = request;
        request.body = Some(body);
        let response = self.request(request).await?;
        ensure_success(&response, "api.accounts.firefox.com")
    }

    async fn hawk_json(&self, method: Method, url: &str, token: &str, body: Vec<u8>) -> Result<ControlResponse> {
        let response = self.hawk(method, url, token, Some(body)).await?;
        ensure_success(&response, "api.accounts.firefox.com")?;
        Ok(response)
    }

    async fn hawk(&self, method: Method, url: &str, token: &str, body: Option<Vec<u8>>) -> Result<ControlResponse> {
        let (id, mut key) = derive_hawk(token, "sessionToken")?;
        let authorization = hawk_header(method.as_str(), url, &id, &key, body.as_deref())?;
        key.zeroize();
        let mut request = ControlRequest::new(method, url)?.header("authorization", &authorization)?;
        if let Some(body) = body {
            request.body = Some(body);
            request.headers.push((http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/json")));
        }
        self.request(request).await
    }
}

fn oauth_request(url: &str, body: Vec<u8>) -> Result<ControlRequest> {
    let mut request = ControlRequest::new(Method::POST, url)?
        .header("accept", "application/json;q=0.9,*/*;q=0.2")?
        .header("accept-language", "en-US, en")?
        .header("cache-control", "no-cache")?
        .header("pragma", "no-cache")?
        .header("sec-fetch-dest", "empty")?
        .header("sec-fetch-mode", "no-cors")?
        .header("sec-fetch-site", "none")?
        .header("priority", "u=4")?;
    request.body = Some(body);
    request.headers.push((http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/json; charset=utf-8")));
    Ok(request)
}

fn is_request_blocked(error: &FirefoxError) -> bool {
    matches!(error, FirefoxError::Http { status: 400, errno: Some(125), .. })
}

fn parse_tokens(response: ControlResponse) -> Result<OAuthTokens> {
    let tokens: OAuthTokens = response.json()?;
    if tokens.access_token.is_empty() || tokens.expires_in == 0 {
        return Err(FirefoxError::Protocol("OAuth response is missing an access token or lifetime".into()));
    }
    Ok(tokens)
}

fn ensure_success(response: &ControlResponse, host: &str) -> Result<()> {
    if (200..300).contains(&response.status) {
        Ok(())
    } else {
        Err(api_error(host, response.clone()))
    }
}

fn api_error(host: &str, response: ControlResponse) -> FirefoxError {
    FirefoxError::Http {
        host: host.into(),
        status: response.status,
        errno: response.errno(),
        retry_after: response.retry_after(),
        message: response.message(),
    }
}
