use std::collections::HashMap;
use std::sync::{Arc, OnceLock, Weak};
use std::time::{Duration, Instant};

use chrono::Utc;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::control::ControlPlane;
use crate::error::{FirefoxError, Result};
use crate::fxa::{Fxa, LoginResponse};
use crate::guardian::{Entitlement, Guardian};
use crate::server_list::RemoteSettings;
use crate::store::AccountStore;
use crate::types::{Account, Country, Credentials, ProxyPass, TransportPreference, Usage};

const PENDING_LIFETIME: Duration = Duration::from_secs(15 * 60);
const OAUTH_CONFIRM_RETRY: Duration = Duration::from_secs(3);
static TOKEN_LOCKS: OnceLock<parking_lot::Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>> = OnceLock::new();
static ACTIVATION_LOCKS: OnceLock<parking_lot::Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>> = OnceLock::new();

fn account_lock(
    registry: &OnceLock<parking_lot::Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>>,
    store: &AccountStore,
    id: &str,
) -> Arc<tokio::sync::Mutex<()>> {
    let key = store.root().join("accounts").join(id).to_string_lossy().into_owned();
    let mut locks = registry.get_or_init(|| parking_lot::Mutex::new(HashMap::new())).lock();
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

fn token_lock(store: &AccountStore, id: &str) -> Arc<tokio::sync::Mutex<()>> {
    account_lock(&TOKEN_LOCKS, store, id)
}

fn activation_lock(store: &AccountStore, id: &str) -> Arc<tokio::sync::Mutex<()>> {
    account_lock(&ACTIVATION_LOCKS, store, id)
}

#[derive(Debug, Clone)]
pub enum LoginOutcome {
    Complete(Account),
    EmailCode(PendingLogin),
    EmailLink(PendingLogin),
    Totp(PendingLogin),
    UnblockCode(UnblockCodePrompt),
}

#[derive(Debug, Clone)]
pub struct PendingLogin {
    pub id: String,
    pub email: String,
}

#[derive(Debug, Clone)]
pub struct UnblockCodePrompt {
    pub email: String,
    pub sent: bool,
}

struct PendingSession {
    email: String,
    session_token: String,
    created: Instant,
}

impl Drop for PendingSession {
    fn drop(&mut self) {
        self.session_token.zeroize();
    }
}

#[derive(Clone)]
pub struct Accounts {
    store: AccountStore,
    http: ControlPlane,
    fxa: Fxa,
    guardian: Guardian,
    remote: RemoteSettings,
    pending: Arc<tokio::sync::Mutex<HashMap<String, PendingSession>>>,
}

impl Accounts {
    pub fn new(store: AccountStore, http: ControlPlane, fxa: Fxa) -> Self {
        let guardian = Guardian::new(http.clone()).with_challenges(fxa.challenge_service());
        let remote = RemoteSettings::new(http.clone());
        Self { store, http, fxa, guardian, remote, pending: Arc::new(tokio::sync::Mutex::new(HashMap::new())) }
    }

    pub fn set_transport(&self, transport: TransportPreference) {
        self.http.set_transport(transport);
    }

    pub fn store(&self) -> &AccountStore {
        &self.store
    }

    pub async fn locations(&self) -> Result<Vec<Country>> {
        self.remote.load(&self.store).await
    }

    pub async fn refresh_locations(&self) -> Result<Vec<Country>> {
        self.remote.refresh(&self.store).await
    }

    pub fn list(&self) -> Result<Vec<Account>> {
        self.store.list()
    }

    pub async fn login(&self, email: &str, password: &str, unblock_code: Option<&str>) -> Result<LoginOutcome> {
        self.pending.lock().await.retain(|_, pending| pending.created.elapsed() < PENDING_LIFETIME);
        let sent = unblock_code.map(crate::crypto::normalize_code).filter(|code| !code.is_empty()).is_none();
        let mut login = match self.fxa.login(email, password, unblock_code).await {
            Err(FirefoxError::UnblockCodeRequired(email)) => {
                if sent {
                    self.fxa.send_unblock_code(&email).await?;
                }
                return Ok(LoginOutcome::UnblockCode(UnblockCodePrompt { email, sent }));
            }
            result => result?,
        };
        if login.verified {
            return self.finish_login(login).await.map(LoginOutcome::Complete);
        }
        let id = crate::crypto::random_urlsafe(24);
        let prompt = PendingLogin { id: id.clone(), email: login.email.clone() };
        let method = login.verification_method.take();
        self.pending.lock().await.insert(id, PendingSession {
            email: std::mem::take(&mut login.email),
            session_token: std::mem::take(&mut login.session_token),
            created: Instant::now(),
        });
        match method.as_deref() {
            Some("totp-2fa") => Ok(LoginOutcome::Totp(prompt)),
            Some("email") => Ok(LoginOutcome::EmailLink(prompt)),
            _ => Ok(LoginOutcome::EmailCode(prompt)),
        }
    }

    pub async fn verify_email(&self, id: &str, code: &str) -> Result<Account> {
        let (email, token) = self.pending_parts(id).await?;
        self.fxa.verify_email_code(&token, code).await?;
        self.finish_pending(id, email, token).await
    }

    pub async fn verify_totp(&self, id: &str, code: &str) -> Result<Account> {
        let (email, token) = self.pending_parts(id).await?;
        self.fxa.verify_totp(&token, code).await?;
        if !self.fxa.session_verified(&token).await? {
            return Err(FirefoxError::VerificationRequired);
        }
        self.finish_pending(id, email, token).await
    }

    pub async fn confirm_email_link(&self, id: &str) -> Result<Account> {
        let (email, token) = self.pending_parts(id).await?;
        if !self.fxa.session_verified(&token).await? {
            return Err(FirefoxError::Protocol("the emailed confirmation link has not been opened yet".into()));
        }
        self.finish_pending(id, email, token).await
    }

    pub async fn resend_email(&self, id: &str) -> Result<()> {
        let (_, token) = self.pending_parts(id).await?;
        self.fxa.resend_email_code(&token).await
    }

    pub async fn cancel_login(&self, id: &str) {
        let pending = self.pending.lock().await.remove(id);
        if let Some(pending) = pending {
            if let Err(error) = self.fxa.destroy_session(&pending.session_token).await {
                log::debug!("[firefox] cancelled FxA session cleanup failed: {error}");
            }
        }
    }

    pub async fn send_unblock_code(&self, email: &str) -> Result<()> {
        self.fxa.send_unblock_code(email).await
    }

    pub async fn forgot_password(&self, email: &str) -> Result<()> {
        self.fxa.password_forgot_code(email).await
    }

    pub async fn verify_password_reset(&self, email: &str, code: &str) -> Result<String> {
        self.fxa.password_forgot_verify(email, code).await
    }

    pub async fn reset_password(&self, email: &str, code: &str, new_password: &str) -> Result<Vec<String>> {
        self.fxa.password_reset(email, code, new_password).await?;
        let normalized = crate::crypto::normalize_email(email);
        let mut removed = Vec::new();
        for account in self.store.list()? {
            if account.email.eq_ignore_ascii_case(&normalized) {
                let lock = token_lock(&self.store, &account.id);
                let _guard = lock.lock().await;
                self.store.remove(&account.id)?;
                removed.push(account.id);
            }
        }
        Ok(removed)
    }

    pub async fn remove(&self, id: &str) -> Result<()> {
        let lock = token_lock(&self.store, id);
        let _guard = lock.lock().await;
        if let Ok(credentials) = self.store.credentials(id) {
            if let Err(error) = self.fxa.revoke_token(&credentials.refresh_token, credentials.oauth_client_id()).await {
                log::warn!("[firefox] OAuth revocation failed during account removal: {error}");
            }
        }
        self.store.remove(id)
    }

    pub fn tokens(&self, account_id: &str) -> Result<TokenManager> {
        self.store.get(account_id)?;
        Ok(TokenManager {
            account_id: account_id.to_string(),
            store: self.store.clone(),
            fxa: self.fxa.clone(),
            guardian: self.guardian.clone(),
            credentials: token_lock(&self.store, account_id),
            activation: activation_lock(&self.store, account_id),
        })
    }

    pub async fn ensure_device(&self, account_id: &str) -> Result<()> {
        let account = self.store.get(account_id)?;
        let credentials = self.store.credentials(account_id)?;
        let fingerprint = hex::encode(&Sha256::digest(credentials.refresh_token.as_bytes())[..6]);
        if account.device_id.is_some() && account.device_token.as_deref() == Some(fingerprint.as_str()) {
            return Ok(());
        }
        let id = self.fxa.register_device(&credentials.refresh_token, account.device_id.as_deref()).await?;
        self.store.set_device(account_id, &id, &fingerprint)
    }

    async fn pending_parts(&self, id: &str) -> Result<(String, Zeroizing<String>)> {
        let pending = self.pending.lock().await;
        let pending = pending.get(id).filter(|pending| pending.created.elapsed() < PENDING_LIFETIME)
            .ok_or(FirefoxError::VerificationRequired)?;
        Ok((pending.email.clone(), Zeroizing::new(pending.session_token.clone())))
    }

    async fn finish_pending(&self, id: &str, email: String, token: Zeroizing<String>) -> Result<Account> {
        let login = LoginResponse {
            uid: String::new(),
            session_token: token.to_string(),
            verified: true,
            email,
            verification_method: None,
            verification_reason: None,
            auth_at: 0,
        };
        let account = self.finish_login(login).await?;
        self.pending.lock().await.remove(id);
        Ok(account)
    }

    async fn finish_login(&self, login: LoginResponse) -> Result<Account> {
        let mut token_attempt = 0;
        let tokens = loop {
            match self.fxa.oauth_from_session(&login.session_token).await {
                Ok(tokens) => break tokens,
                Err(FirefoxError::Http { errno: Some(104 | 138), .. }) if token_attempt < 9 => {
                    token_attempt += 1;
                    tokio::time::sleep(OAUTH_CONFIRM_RETRY).await;
                }
                Err(error) => return Err(error),
            }
        };
        let refresh_token = tokens.refresh_token.clone().filter(|token| !token.is_empty())
            .ok_or_else(|| FirefoxError::Protocol("OAuth sign-in response has no offline refresh token".into()))?;
        let scope = if tokens.scope.is_empty() { crate::fxa::FIREFOX_SCOPE.to_string() } else { tokens.scope };
        let credentials = Credentials {
            access_token: tokens.access_token,
            refresh_token,
            client_id: crate::fxa::FIREFOX_CLIENT_ID.into(),
            oauth_scope: crate::fxa::FIREFOX_SCOPE.into(),
            scope,
            obtained_at: Utc::now(),
            expires_in: tokens.expires_in,
        };
        let existing = self.store.list()?.into_iter().find(|account| account.email.eq_ignore_ascii_case(&login.email));
        let account = if let Some(existing) = existing {
            let lock = token_lock(&self.store, &existing.id);
            let _guard = lock.lock().await;
            self.store.add(&login.email, &credentials)?
        } else {
            self.store.add(&login.email, &credentials)?
        };
        if let Err(error) = self.fxa.destroy_session(&login.session_token).await {
            log::debug!("[firefox] FxA session cleanup failed: {error}");
        }
        drop(credentials);
        if let Err(error) = self.ensure_device(&account.id).await {
            log::warn!("[firefox] connected-services registration failed: {error}");
        }
        match self.tokens(&account.id)?.usage_with_activation().await {
            Ok(_) => self.store.get(&account.id),
            Err(error) => {
                log::warn!("[firefox] initial account usage unavailable reason={}", error.reason_code());
                Ok(account)
            }
        }
    }
}

#[derive(Clone)]
pub struct TokenManager {
    account_id: String,
    store: AccountStore,
    fxa: Fxa,
    guardian: Guardian,
    credentials: Arc<tokio::sync::Mutex<()>>,
    activation: Arc<tokio::sync::Mutex<()>>,
}

impl TokenManager {
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    async fn access_token(&self) -> Result<Zeroizing<String>> {
        let _guard = self.credentials.lock().await;
        let mut credentials = self.store.credentials(&self.account_id)?;
        if credentials.needs_refresh(Utc::now()) {
            self.refresh_locked(&mut credentials).await?;
        }
        Ok(Zeroizing::new(credentials.access_token.clone()))
    }

    async fn refresh_rejected(&self, rejected: &str) -> Result<Zeroizing<String>> {
        let _guard = self.credentials.lock().await;
        let mut credentials = self.store.credentials(&self.account_id)?;
        if credentials.access_token != rejected {
            return Ok(Zeroizing::new(credentials.access_token.clone()));
        }
        self.refresh_locked(&mut credentials).await?;
        Ok(Zeroizing::new(credentials.access_token.clone()))
    }

    async fn refresh_locked(&self, credentials: &mut Credentials) -> Result<()> {
        let client_id = credentials.oauth_client_id().to_string();
        let oauth_scope = credentials.oauth_request_scope().to_string();
        let refreshed = self.fxa.refresh_token(&credentials.refresh_token, &client_id, &oauth_scope).await?;
        let mut refresh_token = refreshed.refresh_token.filter(|token| !token.is_empty())
            .unwrap_or_else(|| credentials.refresh_token.clone());
        let scope = if refreshed.scope.is_empty() { oauth_scope.clone() } else { refreshed.scope };
        let replacement = Credentials {
            access_token: refreshed.access_token,
            refresh_token: refresh_token.clone(),
            scope,
            client_id,
            oauth_scope,
            obtained_at: Utc::now(),
            expires_in: refreshed.expires_in,
        };
        self.store.save_credentials(&self.account_id, &replacement)?;
        *credentials = replacement;
        refresh_token.zeroize();
        Ok(())
    }

    pub async fn fetch_pass(&self) -> Result<ProxyPass> {
        match self.fetch_pass_once().await {
            Err(FirefoxError::NotEntitled) => {
                self.activate_if_needed().await?;
                self.fetch_pass_once().await
            }
            result => result,
        }
    }

    async fn fetch_pass_once(&self) -> Result<ProxyPass> {
        for attempt in 0..2 {
            let token = self.access_token().await?;
            match self.guardian.fetch_pass(&token).await {
                Err(FirefoxError::ReauthRequired) if attempt == 0 => {
                    let _ = self.refresh_rejected(&token).await?;
                }
                result => {
                    if let Ok(pass) = &result {
                        if let Some(usage) = &pass.usage {
                            if let Err(error) = self.store.set_usage(&self.account_id, usage) {
                                log::warn!("[firefox] could not cache account quota: {error}");
                            }
                        }
                    }
                    return result;
                }
            }
        }
        Err(FirefoxError::ReauthRequired)
    }

    async fn activate_if_needed(&self) -> Result<()> {
        let _guard = self.activation.lock().await;
        for attempt in 0..2 {
            let token = self.access_token().await?;
            match self.guardian.activation_check(&token).await {
                Err(FirefoxError::ReauthRequired) if attempt == 0 => {
                    let _ = self.refresh_rejected(&token).await?;
                }
                Ok((false, _)) => return Ok(()),
                Ok((true, relay)) => {
                    log::info!("[firefox] activating account VPN entitlement");
                    self.guardian.activate_on_route(&token, relay).await?;
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
        Err(FirefoxError::ReauthRequired)
    }

    async fn usage_with_activation(&self) -> Result<Usage> {
        match self.usage().await {
            Err(FirefoxError::NotEntitled) => {
                self.activate_if_needed().await?;
                self.usage().await
            }
            result => result,
        }
    }

    pub async fn entitlement(&self) -> Result<Entitlement> {
        for attempt in 0..2 {
            let token = self.access_token().await?;
            match self.guardian.entitlement(&token).await {
                Err(FirefoxError::ReauthRequired) if attempt == 0 => {
                    let _ = self.refresh_rejected(&token).await?;
                }
                result => return result,
            }
        }
        Err(FirefoxError::ReauthRequired)
    }

    pub async fn activate(&self) -> Result<Entitlement> {
        for attempt in 0..2 {
            let token = self.access_token().await?;
            match self.guardian.activate(&token).await {
                Err(FirefoxError::ReauthRequired) if attempt == 0 => {
                    let _ = self.refresh_rejected(&token).await?;
                }
                result => return result,
            }
        }
        Err(FirefoxError::ReauthRequired)
    }

    pub async fn usage(&self) -> Result<Usage> {
        for attempt in 0..2 {
            let token = self.access_token().await?;
            match self.guardian.usage(&token).await {
                Err(FirefoxError::ReauthRequired) if attempt == 0 => {
                    let _ = self.refresh_rejected(&token).await?;
                }
                result => {
                    if let Ok(usage) = &result {
                        self.store.set_usage(&self.account_id, usage)?;
                    }
                    return result;
                }
            }
        }
        Err(FirefoxError::ReauthRequired)
    }
}

#[cfg(test)]
mod activation_tests {
    use super::*;

    #[test]
    fn activation_lock_is_shared_per_account_but_separate_from_token_lock() {
        let dir = tempfile::tempdir().unwrap();
        let store = AccountStore::new(dir.path()).unwrap();
        let first = activation_lock(&store, "account-a");
        let second = activation_lock(&store, "account-a");
        let other = activation_lock(&store, "account-b");
        let credentials = token_lock(&store, "account-a");
        assert!(Arc::ptr_eq(&first, &second));
        assert!(!Arc::ptr_eq(&first, &other));
        assert!(!Arc::ptr_eq(&first, &credentials));
    }
}
