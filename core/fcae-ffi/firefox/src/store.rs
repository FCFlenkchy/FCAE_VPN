use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;
use rand::{rngs::OsRng, RngCore};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tempfile::NamedTempFile;

use crate::error::{FirefoxError, Result};
use crate::types::{Account, Credentials};

const MAX_ACCOUNT_FILE: u64 = 256 * 1024;
const MAX_CACHE_FILE: u64 = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct AccountStore {
    root: PathBuf,
}

impl AccountStore {
    pub fn new(data_dir: impl AsRef<Path>) -> Result<Self> {
        let root = data_dir.as_ref().join("firefox");
        ensure_private_dir(&root)?;
        ensure_private_dir(&root.join("accounts"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn list(&self) -> Result<Vec<Account>> {
        let mut accounts = Vec::new();
        let entries = fs::read_dir(self.root.join("accounts")).map_err(storage)?;
        for entry in entries {
            let entry = entry.map_err(storage)?;
            if !entry.file_type().map_err(storage)?.is_dir() {
                continue;
            }
            let id = entry.file_name().to_string_lossy().into_owned();
            if !valid_id(&id) {
                continue;
            }
            match read_json::<Account>(&entry.path().join("account.json"), MAX_ACCOUNT_FILE) {
                Ok(account) if account.id == id => accounts.push(account),
                Ok(_) => log::warn!("[firefox] skipped account with mismatched id {id}"),
                Err(error) => log::warn!("[firefox] skipped unreadable account {id}: {error}"),
            }
        }
        accounts.sort_by_key(|account| account.added_at);
        Ok(accounts)
    }

    pub fn get(&self, id: &str) -> Result<Account> {
        self.validate_id(id)?;
        read_json(&self.account_dir(id).join("account.json"), MAX_ACCOUNT_FILE)
            .map_err(|_| FirefoxError::AccountNotFound)
    }

    pub fn resolve(&self, requested: Option<&str>) -> Result<Account> {
        if let Some(id) = requested.filter(|id| !id.trim().is_empty()) {
            return self.get(id.trim());
        }
        let mut accounts = self.list()?;
        match accounts.len() {
            0 => Err(FirefoxError::AccountNotFound),
            1 => Ok(accounts.remove(0)),
            _ => Err(FirefoxError::InvalidConfig(
                "more than one Firefox Account exists; select an account ID".into(),
            )),
        }
    }

    pub fn add(&self, email: &str, credentials: &Credentials) -> Result<Account> {
        if credentials.refresh_token.is_empty() {
            return Err(FirefoxError::Protocol("OAuth response has no refresh token".into()));
        }
        let existing = self.list()?.into_iter().find(|account| account.email.eq_ignore_ascii_case(email));
        let account = match existing {
            Some(mut account) => {
                account.email = email.to_string();
                account
            }
            None => {
                let mut bytes = [0u8; 16];
                OsRng.fill_bytes(&mut bytes);
                Account {
                    id: hex::encode(bytes),
                    email: email.to_string(),
                    added_at: Utc::now(),
                    device_id: None,
                    device_token: None,
                    usage: None,
                }
            }
        };
        self.save(&account)?;
        self.save_credentials(&account.id, credentials)?;
        Ok(account)
    }

    pub fn save(&self, account: &Account) -> Result<()> {
        self.validate_id(&account.id)?;
        let dir = self.account_dir(&account.id);
        ensure_private_dir(&dir)?;
        write_json(&dir.join("account.json"), account)
    }

    pub fn remove(&self, id: &str) -> Result<()> {
        self.validate_id(id)?;
        let path = self.account_dir(id);
        match fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(FirefoxError::AccountNotFound),
            Err(error) => Err(storage(error)),
        }
    }

    pub fn credentials(&self, id: &str) -> Result<Credentials> {
        self.validate_id(id)?;
        read_json(&self.account_dir(id).join("credentials.json"), MAX_ACCOUNT_FILE)
            .map_err(|_| FirefoxError::ReauthRequired)
    }

    pub fn save_credentials(&self, id: &str, credentials: &Credentials) -> Result<()> {
        self.validate_id(id)?;
        let dir = self.account_dir(id);
        ensure_private_dir(&dir)?;
        write_json(&dir.join("credentials.json"), credentials)
    }

    pub fn set_device(&self, id: &str, device_id: &str, token_fingerprint: &str) -> Result<()> {
        let mut account = self.get(id)?;
        account.device_id = Some(device_id.to_string());
        account.device_token = Some(token_fingerprint.to_string());
        self.save(&account)
    }

    pub fn set_usage(&self, id: &str, usage: &crate::types::Usage) -> Result<()> {
        let mut account = self.get(id)?;
        account.usage = Some(usage.clone());
        self.save(&account)
    }

    pub fn read_cache<T: DeserializeOwned>(&self, name: &str) -> Result<T> {
        if !valid_file_name(name) {
            return Err(FirefoxError::InvalidConfig("invalid cache name".into()));
        }
        read_json(&self.root.join(name), MAX_CACHE_FILE)
    }

    pub fn write_cache<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        if !valid_file_name(name) {
            return Err(FirefoxError::InvalidConfig("invalid cache name".into()));
        }
        write_json(&self.root.join(name), value)
    }

    fn account_dir(&self, id: &str) -> PathBuf {
        self.root.join("accounts").join(id)
    }

    fn validate_id(&self, id: &str) -> Result<()> {
        if valid_id(id) {
            Ok(())
        } else {
            Err(FirefoxError::InvalidConfig("invalid Firefox Account ID".into()))
        }
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn storage(error: std::io::Error) -> FirefoxError {
    FirefoxError::Storage(error.to_string())
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(storage)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(storage)?;
    }
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<T> {
    let metadata = fs::metadata(path).map_err(storage)?;
    if metadata.len() > limit {
        return Err(FirefoxError::Storage(format!("{} is too large", path.display())));
    }
    let data = fs::read(path).map_err(storage)?;
    Ok(serde_json::from_slice(&data)?)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let data = serde_json::to_vec(value)?;
    let parent = path.parent().ok_or_else(|| FirefoxError::Storage("storage path has no parent".into()))?;
    ensure_private_dir(parent)?;
    let mut file = NamedTempFile::new_in(parent).map_err(storage)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file().set_permissions(fs::Permissions::from_mode(0o600)).map_err(storage)?;
    }
    file.write_all(&data).map_err(storage)?;
    file.as_file().sync_all().map_err(storage)?;
    file.persist(path).map_err(|error| storage(error.error))?;
    #[cfg(unix)]
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}
