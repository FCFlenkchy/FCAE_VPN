//! The user's saved Xray-core / sing-box configs.
//!
//! Both cores are built in and driven in-process, so a "config" here is the
//! profile the bridge turns into the core's own config: a share link or a
//! complete native JSON object, tagged with the core that understands it and
//! named by the user. What the UI's config editor writes and the session reads
//! back is the *list* of them, so this module lives in the runtime rather than
//! in a bridge: a bridge would have to re-validate what the UI just accepted,
//! and two validators drift apart.
//!
//! The list is one JSON document, which keeps the ABI to a single string:
//!
//! ```json
//! [
//!   {"name": "Home", "backend": "sing-box", "config": {"outbounds": [ … ]}},
//!   {"name": "Backup", "backend": "xray", "config": "vless://…"}
//! ]
//! ```
//!
//! Entries are referenced by position (`"#0"`) or by name, because that is
//! what the UIs already have: a protocol-list position and a label.
//!
//! Parsing a profile and knowing which core reads it is [`crate::sing_xray`]'s
//! job; this module owns the list around those profiles — the limits, the
//! unique names, and the references that point into it.

use fcae_abi::FcaeBackend;
use serde_json::Value;

use crate::config::backend_label;
use crate::sing_xray::{native_dialect, CoreProfile};

/// Upper bound on saved configs. A menu longer than this is not a menu.
pub const MAX_ENTRIES: usize = 64;
/// Longest accepted display name, in bytes.
pub const MAX_NAME: usize = 48;
/// Largest single config accepted, in bytes. A native config with inlined
/// certificates stays well below this; anything larger is a file the user
/// meant to point the core at, which neither core supports here.
pub const MAX_CONFIG: usize = 128 * 1024;
/// Largest accepted saved-configs document, in bytes. It has to survive a Binder
/// transaction on Android, where the whole parcel is ~1 MiB.
pub const MAX_DOCUMENT: usize = 256 * 1024;

/// One saved config: a name the user picked, the core that reads it, and the
/// profile itself, already parsed and validated.
#[derive(Debug, Clone, PartialEq)]
pub struct SavedConfig {
    pub name: String,
    pub backend: FcaeBackend,
    pub profile: CoreProfile,
}

/// The saved configs, in the order the UI lists them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SavedConfigs {
    entries: Vec<SavedConfig>,
}

impl SavedConfigs {
    pub fn entries(&self) -> &[SavedConfig] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn get(&self, index: usize) -> Option<&SavedConfig> {
        self.entries.get(index)
    }

    /// Parse and validate the saved-configs document.
    ///
    /// An empty or all-whitespace document is no saved configs: a session that
    /// uses no core must not have to send `[]`, and a UI that has never opened
    /// its config editor must not have to send anything at all.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(Self::default());
        }
        if text.len() > MAX_DOCUMENT {
            return Err(format!(
                "the saved core configs document is {} bytes; the limit is {MAX_DOCUMENT}",
                text.len()
            ));
        }
        let value: Value = serde_json::from_str(text)
            .map_err(|error| format!("the saved core configs are not valid JSON: {error}"))?;
        let list = value
            .as_array()
            .ok_or_else(|| "the saved core configs must be a JSON array".to_string())?;
        if list.len() > MAX_ENTRIES {
            return Err(format!(
                "{} saved core configs; the limit is {MAX_ENTRIES}",
                list.len()
            ));
        }
        let mut entries: Vec<SavedConfig> = Vec::with_capacity(list.len());
        for (index, item) in list.iter().enumerate() {
            let entry =
                parse_entry(item).map_err(|error| format!("saved config #{}: {error}", index + 1))?;
            // Two entries with the same name cannot be told apart in the
            // protocol list, and a name is a legal reference, so it must be
            // unambiguous.
            if let Some(previous) = entries
                .iter()
                .find(|other| other.name.eq_ignore_ascii_case(&entry.name))
            {
                return Err(format!(
                    "saved config #{} is named {:?}, which {:?} already uses; names must be unique",
                    index + 1,
                    entry.name,
                    previous.name
                ));
            }
            entries.push(entry);
        }
        Ok(Self { entries })
    }

    /// Resolve a reference from the ABI to an entry.
    ///
    /// Accepts `#<index>` (the position in the document, which is what an int
    /// list of protocol positions already carries) or the entry's name,
    /// matched case-insensitively.
    pub fn resolve(&self, reference: &str) -> Result<&SavedConfig, String> {
        let reference = reference.trim();
        if let Some(index) = reference.strip_prefix('#') {
            let index: usize = index
                .parse()
                .map_err(|_| format!("{reference:?} is not a saved core config reference"))?;
            return self.entries.get(index).ok_or_else(|| {
                format!(
                    "{reference:?} does not name a saved core config; there are {}",
                    self.entries.len()
                )
            });
        }
        self.entries
            .iter()
            .find(|entry| entry.name.eq_ignore_ascii_case(reference))
            .ok_or_else(|| {
                if self.entries.is_empty() {
                    format!("{reference:?} names a saved core config, but none are saved")
                } else {
                    format!(
                        "{reference:?} does not name a saved core config (saved: {})",
                        self.entries
                            .iter()
                            .map(|entry| entry.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            })
    }
}

/// Validate one saved config exactly the way the list does, and return the
/// profile the core will run.
///
/// The config editors reach this through `fcae_core_check_profile`, so the
/// bytes the user is about to store are held to the same standard as the ones
/// the session loads: a config that saves is a config that starts.
pub fn check_config(backend: FcaeBackend, text: &str) -> Result<CoreProfile, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("the config is empty".into());
    }
    if text.len() > MAX_CONFIG {
        return Err(format!(
            "the config is {} bytes; the limit is {MAX_CONFIG}",
            text.len()
        ));
    }
    let profile = CoreProfile::parse(text)?;
    // A native config names its own dialect; storing one under the other tag is
    // a mistake the core could only report as a parse failure at start.
    if let Some(dialect) = native_dialect(text) {
        if dialect != backend {
            return Err(format!(
                "the config has {} outbounds but is tagged {}",
                backend_label(dialect),
                backend_label(backend)
            ));
        }
    }
    Ok(profile)
}

fn parse_entry(value: &Value) -> Result<SavedConfig, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "each saved config must be a JSON object".to_string())?;

    let name = object
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "a saved config needs a non-empty \"name\"".to_string())?;
    if name.len() > MAX_NAME {
        return Err(format!(
            "name {name:?} is {} bytes; the limit is {MAX_NAME}",
            name.len()
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(format!("name {name:?} contains control characters"));
    }

    let backend = match object
        .get("backend")
        .and_then(Value::as_str)
        .map(|backend| backend.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("xray") => FcaeBackend::Xray,
        Some("sing-box") | Some("singbox") | Some("sing_box") => FcaeBackend::SingBox,
        Some(other) => {
            return Err(format!(
                "backend {other:?} is not one of \"xray\" or \"sing-box\""
            ))
        }
        None => return Err("a saved config needs a \"backend\" of \"xray\" or \"sing-box\"".into()),
    };

    let config = object
        .get("config")
        .ok_or_else(|| "a saved config needs a \"config\"".to_string())?;
    // A link is a string; a native config is the object itself. Accepting both
    // shapes here is what lets the editor store exactly what the user typed.
    let text = match config {
        Value::String(text) => text.clone(),
        Value::Object(_) => config.to_string(),
        _ => {
            return Err(
                "\"config\" must be a share link string or a native config JSON object".into(),
            )
        }
    };
    let profile =
        check_config(backend, &text).map_err(|error| format!("name {name:?}: {error}"))?;

    Ok(SavedConfig {
        name: name.to_string(),
        backend,
        profile,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_documents_are_no_saved_configs() {
        assert!(SavedConfigs::parse("").unwrap().is_empty());
        assert!(SavedConfigs::parse("  \n\t ").unwrap().is_empty());
    }

    #[test]
    fn links_and_native_configs_both_parse() {
        let saved = SavedConfigs::parse(
            r##"[
                {"name": "Home", "backend": "sing-box", "config": "socks5://127.0.0.1:1080"},
                {"name": "Backup", "backend": "xray", "config": {"outbounds": []}}
            ]"##,
        )
        .unwrap();
        assert_eq!(saved.len(), 2);
        assert_eq!(saved.get(0).unwrap().backend, FcaeBackend::SingBox);
        assert_eq!(saved.get(1).unwrap().backend, FcaeBackend::Xray);
        assert!(matches!(
            saved.get(1).unwrap().profile,
            CoreProfile::Native(_)
        ));
    }

    #[test]
    fn references_resolve_by_position_and_by_name() {
        let saved = SavedConfigs::parse(
            r##"[{"name": "Home", "backend": "xray", "config": "socks5://127.0.0.1:1080"}]"##,
        )
        .unwrap();
        assert_eq!(saved.resolve("#0").unwrap().name, "Home");
        assert_eq!(saved.resolve(" home ").unwrap().name, "Home");
        assert!(saved.resolve("#1").is_err());
        assert!(saved.resolve("Work").is_err());
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let error = SavedConfigs::parse(
            r##"[
                {"name": "Home", "backend": "xray", "config": "socks5://127.0.0.1:1080"},
                {"name": "home", "backend": "sing-box", "config": "socks5://127.0.0.1:1081"}
            ]"##,
        )
        .unwrap_err();
        assert!(error.contains("unique"), "{error}");
    }

    #[test]
    fn a_bad_entry_names_itself() {
        let error = SavedConfigs::parse(
            r##"[{"name": "Broken", "backend": "xray", "config": "not a link"}]"##,
        )
        .unwrap_err();
        assert!(error.contains("Broken"), "{error}");
    }

    #[test]
    fn a_native_config_under_the_wrong_tag_is_rejected() {
        let error = SavedConfigs::parse(
            r##"[{"name": "Mine", "backend": "xray", "config":
                {"outbounds": [{"type": "vmess", "tag": "proxy"}]}}]"##,
        )
        .unwrap_err();
        assert!(error.contains("sing-box outbounds"), "{error}");
    }

    #[test]
    fn unknown_backends_are_rejected() {
        let error = SavedConfigs::parse(
            r##"[{"name": "X", "backend": "v2ray", "config": "socks5://127.0.0.1:1080"}]"##,
        )
        .unwrap_err();
        assert!(error.contains("v2ray"), "{error}");
    }

    #[test]
    fn an_empty_config_is_rejected_by_the_checker() {
        assert!(check_config(FcaeBackend::Xray, "   ").is_err());
        assert!(check_config(FcaeBackend::Xray, "socks5://127.0.0.1:1080").is_ok());
    }
}
