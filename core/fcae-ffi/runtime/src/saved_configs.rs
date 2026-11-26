//! The user's saved Xray, sing-box and Mihomo configs.
//!
//! These cores are built in and driven in-process, so a "config" here is the
//! profile the bridge turns into the selected core's own config: a share link
//! or a complete native profile, tagged with the core that understands it and
//! named by the user. What the UI's config editor writes and the session reads
//! back is the *list* of them, so this module lives in the runtime rather than
//! in a bridge: a bridge would have to re-validate what the UI just accepted,
//! and the validators would drift apart.
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
//! Parsing a profile and knowing which core reads it is [`crate::proxy_cores`]'s
//! job; this module owns the list around those profiles — the limits, the
//! unique names, and the references that point into it.

use fcae_abi::FcaeBackend;
use serde_json::Value;

use crate::config::backend_label;
use crate::proxy_cores::{native_dialect_value, CoreProfile};

/// Upper bound on saved configs, and the only place a count is checked: the
/// UIs neither show nor enforce it, because a library is the user's own list.
/// It exists so a corrupt document cannot ask for an unbounded parse, and the
/// document's byte limit is what actually bounds a real one.
pub const MAX_ENTRIES: usize = 1000;
/// Longest accepted display name, in bytes.
pub const MAX_NAME: usize = 48;
/// Largest single config accepted, in bytes. A native config with inlined
/// certificates stays well below this; anything larger is a file the user
/// meant to point the core at, which neither core supports here.
pub const MAX_CONFIG: usize = 128 * 1024;
/// Largest accepted saved-configs document, in bytes. It has to survive a Binder
/// transaction on Android, where the whole parcel is ~1 MiB: a thousand share
/// links fit, and the margin the rest of the session needs stays free.
pub const MAX_DOCUMENT: usize = 512 * 1024;

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

type Validator = fn(&CoreProfile) -> Result<(), String>;
static VALIDATORS: once_cell::sync::Lazy<
    parking_lot::RwLock<std::collections::HashMap<u32, Validator>>,
> = once_cell::sync::Lazy::new(|| parking_lot::RwLock::new(std::collections::HashMap::new()));

/// Installed by compiled core bridges; schema checking must not start a core.
pub fn register_validator(backend: FcaeBackend, validator: Validator) {
    VALIDATORS.write().insert(backend as u32, validator);
}

/// Validate one saved config exactly the way the list does, and return the
/// profile the core will run.
///
/// The config editors reach this through `fcae_core_check_profile`, so the
/// bytes the user is about to store are held to the same standard as the ones
/// the session loads. Compiled bridges preflight the schema without starting
/// a core; network access and runtime resources are checked at start.
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
    let profile = CoreProfile::parse_for_backend(text, backend)?;
    if backend == FcaeBackend::Mihomo {
        crate::mihomo::validate(&profile)?;
    }
    // A native config names its own dialect; storing one under the other tag is
    // a mistake the core could only report as a parse failure at start.
    if let CoreProfile::Native(value) = &profile {
        if let Some(dialect) = native_dialect_value(value) {
            if dialect != backend {
                return Err(format!(
                    "the config has {} outbounds but is tagged {}",
                    backend_label(dialect),
                    backend_label(backend)
                ));
            }
        }
    }
    // A scheme only one core implements is refused for the other here, where
    // the editor can say why, rather than as a start failure later.
    if let CoreProfile::Link(outbound) = &profile {
        if !outbound.carried_by(backend) {
            return Err(outbound.refusal(backend));
        }
    }
    let validator = VALIDATORS.read().get(&(backend as u32)).copied();
    if let Some(validate) = validator {
        validate(&profile)?;
    }
    Ok(profile)
}

/// The name a config gives itself, for an entry the user left unnamed.
///
/// A share link names itself in its `#fragment`. The schemes that have none
/// keep the name in their payload (VMess `ps`, SSR `remarks`, mieru
/// `profile`), and a link a core takes as its own native proxy (TrustTunnel,
/// AnyConnect) names that proxy. A native config has no single convention, so
/// only the labels the common exporters write are read: a top-level `remarks`
/// (also spelled `remark` or `name`), or the name of the document's only server
/// (Mihomo `name`; sing-box and Xray `tag`, unless the tag only says what it is
/// on). Everything else answers `None`, and the caller makes a name up.
///
/// This never validates: a link the selected core cannot run still says what it
/// is called, and the editor reports why it cannot be saved separately.
pub fn suggested_name(backend: FcaeBackend, text: &str) -> Option<String> {
    let text = text.trim().trim_start_matches('\u{feff}').trim_start();
    if text.is_empty() || text.len() > MAX_CONFIG {
        return None;
    }
    let text = crate::proxy_cores::profile::unescaped_link(text);
    let text = text.as_ref();
    let link = text.split_once("://").is_some_and(|(scheme, _)| {
        !scheme.is_empty()
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
    });
    // A share link is one line. The parsers read on past the end of it, so a
    // pasted list would name its first link after everything that follows.
    let text = match text.lines().next() {
        Some(first) if link => first.trim_end(),
        _ => text,
    };
    let named = |name: &String| !name.trim().is_empty();
    let profile = CoreProfile::parse_for_backend(text, backend).ok();
    let name = match &profile {
        Some(CoreProfile::Link(outbound)) => outbound.remark.clone().filter(named),
        // A link one core turns into its own native proxy is asked as a link
        // first: what the conversion calls the proxy is the last resort.
        Some(CoreProfile::Native(_)) if link => None,
        Some(CoreProfile::Native(value)) => native_name(value, backend),
        None => None,
    };
    let name = name
        .or_else(|| link.then(|| link_name(text)).flatten())
        .or_else(|| match &profile {
            Some(CoreProfile::Native(value)) if link => native_name(value, backend),
            _ => None,
        });
    name.as_deref().and_then(clean_name)
}

/// What a share link calls itself, read from the link alone: its `#fragment`,
/// or else the field of the payload that the schemes without one keep a name
/// in. A `remarks` among the parameters of any other link is not read: the
/// link parser refuses a parameter it does not know, so that link is never
/// saved.
fn link_name(text: &str) -> Option<String> {
    use crate::proxy_cores::profile::{b64_decode, percent_decode, Query};
    let (scheme, rest) = text.split_once("://")?;
    let named = |name: &String| !name.trim().is_empty();
    let (body, fragment) = match rest.split_once('#') {
        Some((body, fragment)) => (body, Some(fragment)),
        None => (rest, None),
    };
    if let Some(name) = fragment.map(percent_decode).filter(named) {
        return Some(name);
    }
    let (payload, params) = body.split_once('?').unwrap_or((body, ""));
    let name = match scheme.to_ascii_lowercase().as_str() {
        // vmess://<base64 JSON>: `ps` is the name every client writes there.
        "vmess" => {
            let json: Value = serde_json::from_str(&b64_decode(payload)?).ok()?;
            json.get("ps")?.as_str()?.to_owned()
        }
        // ssr://<base64 of server:port:…:password/?…&remarks=<base64 name>>
        "ssr" => {
            let decoded = b64_decode(payload.trim_end_matches('/'))?;
            let (_, inner) = decoded.split_once("/?")?;
            b64_decode(Query::parse(inner).get("remarks")?)?
        }
        // mierus://…?profile=<name>: what the mieru client lists the server
        // as. Its own default for that is no name.
        "mierus" => {
            let params = Query::parse(params);
            let profile = params.get("profile")?;
            if generic_label(profile) {
                return None;
            }
            profile.to_owned()
        }
        _ => return None,
    };
    Some(name).filter(named)
}

/// Whether `label` says what kind of thing it is on rather than which one:
/// `proxy`, `out`, `vless-out`, `proxy-1`. The cores route by these tags, so
/// exporters and hand-written configs spell them like that, and one of them
/// tells two saved configs apart no better than no name at all.
fn generic_label(label: &str) -> bool {
    const WORDS: &[&str] = &[
        "proxy",
        "proxies",
        "out",
        "outbound",
        "outbounds",
        "default",
        // The protocols, as the cores and their share links spell them.
        "vless",
        "vmess",
        "trojan",
        "shadowsocks",
        "ss",
        "ssr",
        "socks",
        "http",
        "https",
        "hysteria",
        "hy",
        "tuic",
        "wireguard",
        "wg",
        "anytls",
        "naive",
        "ssh",
        "shadowtls",
        "snell",
        "mieru",
        "tor",
    ];
    // Only ASCII punctuation separates words here: a flag or any other
    // character outside ASCII is part of a name, never of a label like these.
    label
        .split(|c: char| c.is_ascii() && !c.is_ascii_alphanumeric())
        // A counter does not make it a name: `proxy-2`, `out2`, `socks5`.
        .map(|word| word.trim_end_matches(|c: char| c.is_ascii_digit()))
        .filter(|word| !word.is_empty())
        .all(|word| WORDS.contains(&word.to_ascii_lowercase().as_str()))
}

/// The label a native config carries for itself, when it carries exactly one.
fn native_name(value: &Value, backend: FcaeBackend) -> Option<String> {
    let text = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
            .map(str::to_owned)
    };
    // A label for the whole document. `remarks` is what the v2rayN family
    // writes and reads back; the other spellings are accepted for a label
    // written by hand. No core has a setting of its own under any of them.
    for key in ["remarks", "remark", "name"] {
        if let Some(label) = text(value.get(key)) {
            return Some(label);
        }
    }
    // Otherwise the document's only server names it. Names this module's own
    // conversions give a proxy are not the user's.
    let own = |name: &String| !name.starts_with("FCAE-");
    // A tag is what the routing refers to, and often nothing more than that.
    let tag = |server: &Value| {
        text(server.get("tag"))
            .filter(own)
            .filter(|tag| !generic_label(tag))
    };
    // The entries of `section` that are servers: `utility` lists the kinds,
    // read from the field `kind`, that only route traffic.
    fn servers<'a>(
        value: &'a Value,
        section: &str,
        kind: &str,
        utility: &[&str],
    ) -> Vec<&'a Value> {
        value
            .get(section)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|entry| {
                !entry
                    .get(kind)
                    .and_then(Value::as_str)
                    .is_some_and(|kind| utility.contains(&kind))
            })
            .collect()
    }
    match backend {
        FcaeBackend::Mihomo => {
            let proxies = value.get("proxies")?.as_array()?;
            match proxies.as_slice() {
                // Mihomo's `name` is what its own interfaces show: a name
                // whatever it says.
                [only] => text(only.get("name")).filter(own),
                _ => None,
            }
        }
        FcaeBackend::SingBox => {
            let mut all = servers(
                value,
                "outbounds",
                "type",
                &["direct", "block", "dns", "selector", "urltest"],
            );
            all.extend(servers(value, "endpoints", "type", &[]));
            match all.as_slice() {
                [only] => tag(only),
                _ => None,
            }
        }
        FcaeBackend::Xray => {
            let all = servers(
                value,
                "outbounds",
                "protocol",
                &["freedom", "blackhole", "dns", "loopback"],
            );
            match all.as_slice() {
                [only] => tag(only),
                _ => None,
            }
        }
        _ => None,
    }
}

/// `name` with every flag spelled as the country code it stands for.
///
/// A flag is a pair of regional indicator letters, and the app's font has a
/// glyph for neither: a feed that names its servers by flag alone would list
/// them all as the same two placeholders. The pair is the country's ISO code
/// letter for letter, so the code is what the name keeps, as a word of its own.
fn spell_flags(name: &str) -> String {
    const A: u32 = 0x1F1E6; // REGIONAL INDICATOR SYMBOL LETTER A
    let letter = |c: char| {
        let code = c as u32;
        (A..A + 26)
            .contains(&code)
            .then(|| char::from(b'A' + (code - A) as u8))
    };
    let mut spelled = String::with_capacity(name.len());
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        let pair = letter(c).zip(chars.peek().copied().and_then(letter));
        let Some((first, second)) = pair else {
            spelled.push(c);
            continue;
        };
        chars.next();
        if spelled.chars().next_back().is_some_and(char::is_alphanumeric) {
            spelled.push(' ');
        }
        spelled.push(first);
        spelled.push(second);
        if chars
            .peek()
            .is_some_and(|next| next.is_alphanumeric() || letter(*next).is_some())
        {
            spelled.push(' ');
        }
    }
    spelled
}

/// A name the library accepts: no control characters, no surrounding space,
/// at most [`MAX_NAME`] bytes, cut on a character boundary.
fn clean_name(name: &str) -> Option<String> {
    let name: String = spell_flags(name)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let name = name.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut end = name.len().min(MAX_NAME);
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    let name = name[..end].trim_end();
    (!name.is_empty()).then(|| name.to_owned())
}

/// What a saved config lets a session serve, and the ports it pins for those
/// listeners.
///
/// A share link is a single outbound and the bridge builds the session's
/// listeners around it, so it serves both and pins neither. A native config
/// brings its own inbounds; the bridge rewrites managed listeners and supplies
/// a SOCKS listener when missing. A lone SOCKS5 inbound cannot answer an HTTP proxy
/// however the toggle is set — and where it names a port, that port is the
/// config's own opinion, not the app default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Listeners {
    /// Bitwise [`fcae_abi::FCAE_CORE_LISTENER_SOCKS`] and `_HTTP`.
    pub kinds: u32,
    /// The port the config pins for its SOCKS5 inbound, if any.
    pub socks_port: Option<u16>,
    /// The port the config pins for its HTTP inbound, if any.
    pub http_port: Option<u16>,
}

pub fn listeners(backend: FcaeBackend, text: &str) -> Listeners {
    let config = match CoreProfile::parse_for_backend(text.trim(), backend) {
        Ok(CoreProfile::Link(_)) => {
            return Listeners {
                kinds: fcae_abi::FCAE_CORE_LISTENER_SOCKS | fcae_abi::FCAE_CORE_LISTENER_HTTP,
                ..Listeners::default()
            }
        }
        Ok(CoreProfile::Native(config)) => config,
        // Unusable: the editor refuses it, and nothing can be served from it.
        Err(_) => return Listeners::default(),
    };
    if backend == FcaeBackend::Mihomo {
        let mut result = Listeners::default();
        for (key, kind) in [("socks-port", 1u32), ("port", 2), ("mixed-port", 3)] {
            if let Some(port) = config.get(key).and_then(Value::as_u64).and_then(|n| u16::try_from(n).ok()).filter(|n| *n != 0) {
                result.kinds |= kind;
                if kind & 1 != 0 { result.socks_port = result.socks_port.or(Some(port)); }
                if kind & 2 != 0 { result.http_port = result.http_port.or(Some(port)); }
            }
        }
        // A profile with no explicit listeners uses the session's listeners.
        if result.kinds == 0 { result.kinds = 3; }
        return result;
    }
    // The dialects name the same two facts differently, and the tag is what the
    // user chose to store the config under.
    let xray = backend == FcaeBackend::Xray;
    let kind_key = if xray { "protocol" } else { "type" };
    let port_key = if xray { "port" } else { "listen_port" };
    let mut listeners = Listeners::default();
    for inbound in config
        .get("inbounds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let kind = inbound
            .get(kind_key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !matches!(kind.as_str(), "socks" | "mixed" | "http") {
            continue;
        }
        // Xray accepts a number or a numeric string here; sing-box only a number.
        let port = inbound
            .get(port_key)
            .and_then(|value| match value {
                Value::Number(_) => value.as_u64(),
                Value::String(text) => text.trim().parse::<u64>().ok(),
                _ => None,
            })
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0);
        if kind == "http" {
            listeners.kinds |= fcae_abi::FCAE_CORE_LISTENER_HTTP;
            listeners.http_port = listeners.http_port.or(port);
        } else {
            listeners.kinds |= fcae_abi::FCAE_CORE_LISTENER_SOCKS;
            listeners.socks_port = listeners.socks_port.or(port);
        }
    }
    // Native outbound-only and TUN-only profiles use a managed SOCKS listener.
    if listeners.kinds == 0 { listeners.kinds = fcae_abi::FCAE_CORE_LISTENER_SOCKS; }
    listeners
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
        Some("mihomo") | Some("clash-meta") => FcaeBackend::Mihomo,
        Some("sing-box") | Some("singbox") | Some("sing_box") => FcaeBackend::SingBox,
        Some(other) => {
            return Err(format!(
                "backend {other:?} is not one of \"xray\", \"sing-box\" or \"mihomo\""
            ))
        }
        None => {
            return Err(
                "a saved config needs a \"backend\" of \"xray\", \"sing-box\" or \"mihomo\"".into(),
            )
        }
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
                "\"config\" must be a share link string or a native config object".into(),
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

    #[test]
    fn xray_only_encryption_is_refused_for_sing_box_and_accepted_for_xray() {
        let key32 = "A".repeat(43);
        let link = format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=\
             mlkem768x25519plus.native.0rtt.{key32}"
        );
        assert!(check_config(FcaeBackend::Xray, &link).is_ok());
        let error = check_config(FcaeBackend::SingBox, &link).expect_err("sing-box cannot carry it");
        assert!(error.contains("Xray"), "{error}");
        assert!(error.contains("encryption"), "{error}");
    }

    #[test]
    fn hysteria2_links_are_accepted_for_all_three_cores() {
        let link = "hysteria2://secret@example.com:443?sni=www.example.com#fast";
        assert!(check_config(FcaeBackend::SingBox, link).is_ok());
        assert!(check_config(FcaeBackend::Xray, link).is_ok());
        assert!(check_config(FcaeBackend::Mihomo, link).is_ok());
    }

    #[test]
    fn listeners_follow_the_config() {
        let both = fcae_abi::FCAE_CORE_LISTENER_SOCKS | fcae_abi::FCAE_CORE_LISTENER_HTTP;
        // A link is wrapped by the bridge, so it answers both and pins neither.
        let link = listeners(FcaeBackend::Xray, "socks5://u:p@127.0.0.1:1080");
        assert_eq!(link.kinds, both);
        assert_eq!((link.socks_port, link.http_port), (None, None));
        // A native config serves the inbound types it declares, at its own ports.
        let socks_only = listeners(FcaeBackend::Xray, r#"{"inbounds":
            [{"protocol": "socks", "port": 10808}], "outbounds": [{"protocol": "freedom"}]}"#);
        assert_eq!(socks_only.kinds, fcae_abi::FCAE_CORE_LISTENER_SOCKS);
        assert_eq!(socks_only.socks_port, Some(10808));
        assert_eq!(socks_only.http_port, None);
        let mixed_and_http = listeners(FcaeBackend::SingBox, r#"{"inbounds":
            [{"type": "mixed", "listen_port": 2080}, {"type": "http", "listen_port": 2081}],
            "outbounds": [{"type": "direct"}]}"#);
        assert_eq!(mixed_and_http.kinds, both);
        assert_eq!((mixed_and_http.socks_port, mixed_and_http.http_port), (Some(2080), Some(2081)));
        let http_only = listeners(FcaeBackend::SingBox, r#"{"inbounds": [{"type": "http"}],
            "outbounds": [{"type": "direct"}]}"#);
        assert_eq!(http_only.kinds, fcae_abi::FCAE_CORE_LISTENER_HTTP);
        assert_eq!(listeners(FcaeBackend::SingBox, "not a link").kinds, 0);
    }

    #[test]
    fn a_share_link_is_named_by_its_fragment() {
        let link = "vless://2f8a4c8e-4d0a-4f8e-9c1b-6f7d0a1b2c3d@example.com:443?security=tls&type=tcp#%F0%9F%87%A9%F0%9F%87%AA%20Berlin%2001";
        // The flag is spelled as the country code it stands for.
        assert_eq!(
            suggested_name(FcaeBackend::Xray, link).as_deref(),
            Some("DE Berlin 01")
        );
        // The same link names itself whichever core is asked.
        assert_eq!(
            suggested_name(FcaeBackend::SingBox, link),
            suggested_name(FcaeBackend::Xray, link)
        );
        assert_eq!(
            suggested_name(
                FcaeBackend::Xray,
                "trojan://secret@example.com:443?security=tls"
            ),
            None
        );
        assert_eq!(
            suggested_name(FcaeBackend::Xray, "trojan://secret@example.com:443#%20%20"),
            None
        );
    }

    #[test]
    fn a_vmess_payload_is_named_by_its_ps_field() {
        use base64::Engine as _;
        let payload = serde_json::json!({
            "v": "2", "ps": "Home VMess", "add": "example.com", "port": "443",
            "id": "2f8a4c8e-4d0a-4f8e-9c1b-6f7d0a1b2c3d", "aid": "0", "net": "tcp",
            "type": "none", "tls": "tls"
        });
        let link = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(payload.to_string())
        );
        assert_eq!(
            suggested_name(FcaeBackend::Xray, &link).as_deref(),
            Some("Home VMess")
        );
        // A fragment, where a client appends one, is the more specific name.
        assert_eq!(
            suggested_name(FcaeBackend::Xray, &format!("{link}#Renamed")).as_deref(),
            Some("Renamed")
        );
    }

    #[test]
    fn a_link_is_named_by_its_own_line_only() {
        let list = "trojan://secret@a.example.com:443?security=tls#Alpha\r\ntrojan://secret@b.example.com:443?security=tls#Beta\n";
        assert_eq!(
            suggested_name(FcaeBackend::Xray, list).as_deref(),
            Some("Alpha")
        );
        // The second link's name is not the first one's.
        let unnamed_first = "trojan://secret@a.example.com:443?security=tls\ntrojan://secret@b.example.com:443?security=tls#Beta";
        assert_eq!(suggested_name(FcaeBackend::Xray, unnamed_first), None);
    }

    #[test]
    fn an_unsupported_link_still_names_itself() {
        // Unknown to every parser here: the fragment is all that can be read.
        assert_eq!(
            suggested_name(FcaeBackend::Xray, "futureproto://host:1#Edge%20node").as_deref(),
            Some("Edge node")
        );
    }

    #[test]
    fn native_configs_use_the_labels_exporters_write() {
        let xray = r#"{"remarks":"Office","outbounds":[{"protocol":"freedom"}]}"#;
        assert_eq!(
            suggested_name(FcaeBackend::Xray, xray).as_deref(),
            Some("Office")
        );
        assert_eq!(
            suggested_name(
                FcaeBackend::Xray,
                r#"{"outbounds":[{"protocol":"freedom"}]}"#
            ),
            None
        );
        let mihomo = "proxies:\n  - {name: Tokyo, type: socks5, server: example.com, port: 1080}\n";
        assert_eq!(
            suggested_name(FcaeBackend::Mihomo, mihomo).as_deref(),
            Some("Tokyo")
        );
        let two = "proxies:\n  - {name: A, type: socks5, server: a.example, port: 1080}\n  - {name: B, type: socks5, server: b.example, port: 1080}\n";
        assert_eq!(suggested_name(FcaeBackend::Mihomo, two), None);
        // A bare proxy without a name gets one from the bridge; that is not the user's.
        assert_eq!(
            suggested_name(
                FcaeBackend::Mihomo,
                "{type: socks5, server: example.com, port: 1080}"
            ),
            None
        );
        let sing_box = r#"{"outbounds":[{"type":"direct","tag":"direct"},{"type":"socks","tag":"Paris","server":"example.com","server_port":1080}]}"#;
        assert_eq!(
            suggested_name(FcaeBackend::SingBox, sing_box).as_deref(),
            Some("Paris")
        );
    }

    #[test]
    fn a_link_without_a_fragment_is_named_by_its_payload() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        // ShadowsocksR keeps the name inside the payload, base64 once more.
        let ssr = |params: &str| {
            format!(
                "ssr://{}",
                URL_SAFE_NO_PAD.encode(format!(
                    "example.com:8388:origin:aes-256-cfb:plain:{}/?{params}",
                    URL_SAFE_NO_PAD.encode("secret")
                ))
            )
        };
        let named = ssr(&format!(
            "remarks={}&group={}",
            URL_SAFE_NO_PAD.encode("Tokyo \u{1f1ef}\u{1f1f5} 02"),
            URL_SAFE_NO_PAD.encode("Blue Cloud")
        ));
        assert_eq!(
            suggested_name(FcaeBackend::Mihomo, &named).as_deref(),
            Some("Tokyo JP 02")
        );
        // It says the same to a core that cannot run it.
        assert_eq!(
            suggested_name(FcaeBackend::Xray, &named),
            suggested_name(FcaeBackend::Mihomo, &named)
        );
        assert_eq!(suggested_name(FcaeBackend::Mihomo, &ssr("obfsparam=")), None);

        let mieru = |profile: &str| {
            format!("mierus://user:secret@example.com?port=6666&protocol=TCP&profile={profile}")
        };
        assert_eq!(
            suggested_name(FcaeBackend::Mihomo, &mieru("Home%20line")).as_deref(),
            Some("Home line")
        );
        // The client's own word for "nothing was typed here".
        assert_eq!(suggested_name(FcaeBackend::Mihomo, &mieru("default")), None);
        // A fragment is the link's name wherever else one is written.
        assert_eq!(
            suggested_name(FcaeBackend::Mihomo, &format!("{}#Garden", mieru("Home%20line")))
                .as_deref(),
            Some("Garden")
        );
    }

    #[test]
    fn a_link_a_core_takes_natively_is_named_by_the_proxy_it_becomes() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        assert_eq!(
            suggested_name(
                FcaeBackend::SingBox,
                "anyconnect://connect?host=vpn.example.com&name=Office"
            )
            .as_deref(),
            Some("Office")
        );
        assert_eq!(
            suggested_name(
                FcaeBackend::SingBox,
                "anyconnect://connect?host=vpn.example.com"
            ),
            None
        );
        // A TrustTunnel deep link is a list of tag, length, value fields.
        let trusttunnel = |name: Option<&str>| {
            let mut fields: Vec<(u8, &str)> = vec![
                (1, "vpn.example.com"),
                (2, "203.0.113.5:443"),
                (5, "user"),
                (6, "secret"),
            ];
            if let Some(name) = name {
                fields.push((12, name));
            }
            let mut bytes = Vec::new();
            for (tag, value) in fields {
                bytes.push(tag);
                bytes.push(value.len() as u8);
                bytes.extend_from_slice(value.as_bytes());
            }
            format!("tt://?{}", URL_SAFE_NO_PAD.encode(bytes))
        };
        assert_eq!(
            suggested_name(FcaeBackend::Mihomo, &trusttunnel(Some("Home tunnel"))).as_deref(),
            Some("Home tunnel")
        );
        // Unnamed, the proxy it becomes carries the bridge's name, not a user's.
        assert_eq!(suggested_name(FcaeBackend::Mihomo, &trusttunnel(None)), None);
    }

    #[test]
    fn a_tag_that_only_says_what_it_is_on_is_not_a_name() {
        for tag in [
            "proxy", "Proxy-1", "out", "vless-out", "socks5", "hy2_out", "ss", "default", "2",
        ] {
            assert!(generic_label(tag), "{tag}");
        }
        for tag in [
            "Paris",
            "my-proxy",
            "office vless",
            "\u{1f1e9}\u{1f1ea} proxy 1",
            "\u{6771}\u{4eac}",
        ] {
            assert!(!generic_label(tag), "{tag}");
        }
        let sing_box = |tag: &str| {
            format!(
                r#"{{"outbounds":[{{"type":"direct","tag":"direct"}},{{"type":"socks","tag":"{tag}","server":"example.com","server_port":1080}}]}}"#
            )
        };
        assert_eq!(suggested_name(FcaeBackend::SingBox, &sing_box("proxy")), None);
        assert_eq!(
            suggested_name(FcaeBackend::SingBox, &sing_box("socks-out")),
            None
        );
        assert_eq!(
            suggested_name(FcaeBackend::SingBox, &sing_box("Lisbon 3")).as_deref(),
            Some("Lisbon 3")
        );
        // Mihomo shows a proxy's `name` to its user: it is one whatever it says.
        assert_eq!(
            suggested_name(
                FcaeBackend::Mihomo,
                "proxies:\n  - {name: proxy, type: socks5, server: example.com, port: 1080}\n"
            )
            .as_deref(),
            Some("proxy")
        );
    }

    #[test]
    fn an_xray_config_is_named_by_its_label_or_its_only_server() {
        let xray = |label: &str, tag: &str| {
            format!(
                r#"{{{label}"outbounds":[{{"protocol":"socks","tag":"{tag}","settings":{{"servers":[{{"address":"example.com","port":1080}}]}}}},{{"protocol":"freedom","tag":"direct"}}]}}"#
            )
        };
        assert_eq!(
            suggested_name(FcaeBackend::Xray, &xray("", "Berlin")).as_deref(),
            Some("Berlin")
        );
        assert_eq!(suggested_name(FcaeBackend::Xray, &xray("", "proxy")), None);
        assert_eq!(
            suggested_name(FcaeBackend::Xray, &xray(r#""remark":"Work","#, "proxy")).as_deref(),
            Some("Work")
        );
        // The document's own label outranks its server's, and `remarks` the
        // other spellings.
        assert_eq!(
            suggested_name(
                FcaeBackend::Xray,
                &xray(r#""name":"Home","remarks":"Office","#, "Berlin")
            )
            .as_deref(),
            Some("Office")
        );
        assert_eq!(
            suggested_name(FcaeBackend::Xray, &xray(r#""name":"Home","#, "Berlin")).as_deref(),
            Some("Home")
        );
        // One outbound on its own is a config of one server.
        assert_eq!(
            suggested_name(
                FcaeBackend::Xray,
                r#"{"protocol":"socks","tag":"Lisbon","settings":{"servers":[{"address":"example.com","port":1080}]}}"#
            )
            .as_deref(),
            Some("Lisbon")
        );
        // Two servers are not one name.
        let two = r#"{"outbounds":[{"protocol":"socks","tag":"Berlin"},{"protocol":"socks","tag":"Paris"}]}"#;
        assert_eq!(suggested_name(FcaeBackend::Xray, two), None);
    }

    /// A feed collected from Telegram channels, as it arrives: links escaped
    /// by the page they were copied from and stamped with the channel's name,
    /// servers named by flag alone, and VMess entries from a generator that
    /// writes `null` for what it leaves out and adds fields of its own.
    #[test]
    fn a_channel_feed_is_read_whole() {
        use crate::proxy_cores::profile::Security;
        use base64::Engine as _;
        let uuid = "2f6b1c3e-8a4d-4f0b-9c57-0d1e2a3b4c5d";
        let key = "A".repeat(43);
        let vmess = |json: String| {
            format!(
                "vmess://{}",
                base64::engine::general_purpose::STANDARD.encode(json)
            )
        };
        let feed = [
            (
                format!(
                    "vless://{uuid}@203.0.113.7:23576?security=reality&amp;encryption=none\
                     &amp;pbk={key}&amp;headerType=none&amp;fp=chrome&amp;type=tcp\
                     &amp;flow=xtls-rprx-vision&amp;sni=example.com&amp;sid=01#🇺🇸"
                ),
                "US",
            ),
            // The channel's stamp, twice, and a path on a transport with none.
            (
                format!(
                    "vless://{uuid}@203.0.113.8:23576?Telegram=@channel&amp;Telegram=@channel\
                     &amp;security=reality&amp;pbk={key}&amp;fp=chrome&amp;type=tcp\
                     &amp;flow=xtls-rprx-vision&amp;sni=example.com&amp;sid=01&amp;path=/#🇳🇱"
                ),
                "NL",
            ),
            // A certificate flag where no certificate is checked.
            (
                format!(
                    "vless://{uuid}@203.0.113.9:23576?flow=xtls-rprx-vision&security=reality\
                     &allowInsecure=0&encryption=none&type=tcp&sni=example.com&sid=01\
                     &fp=chrome&pbk={key}&headerType=none#🇳🇱"
                ),
                "NL",
            ),
            (
                "ss://YWVzLTEyOC1nY206c2hhZG93c29ja3M@203.0.113.10:443#@channel".to_owned(),
                "@channel",
            ),
            (
                vmess(format!(
                    r#"{{"add":"203.0.113.11","aid":"0","alpn":null,"fp":null,"host":"","id":"{uuid}","net":"tcp","path":"/","port":18000,"ps":"\ud83c\udde8\ud83c\udde6 Join+Telegram:@channel \ud83c\udde8\ud83c\udde6","scy":null,"skip-cert-verify":true,"sni":null,"tls":"","type":null,"v":null}}"#
                )),
                "CA Join+Telegram:@channel CA",
            ),
            (
                vmess(format!(
                    r#"{{"add":"203.0.113.12","aid":"0","host":"","id":"{uuid}","net":"tcp","path":"","port":"18000","ps":"\ud83c\uddfa\ud83c\uddf8 Join","scy":"auto","sni":"","test_name":"2","tls":"","type":"none","v":"2","skip-cert-verify":true}}"#
                )),
                "US Join",
            ),
        ];
        for (link, name) in &feed {
            for backend in [FcaeBackend::Xray, FcaeBackend::SingBox, FcaeBackend::Mihomo] {
                if let Err(reason) = check_config(backend, link) {
                    panic!("{backend:?} refused {link}: {reason}");
                }
                assert_eq!(
                    suggested_name(backend, link).as_deref(),
                    Some(*name),
                    "{link}"
                );
            }
        }
        // The escaped link is the link it was before the page escaped it.
        let Ok(CoreProfile::Link(outbound)) = check_config(FcaeBackend::Xray, &feed[0].0) else {
            panic!("a share link is one outbound");
        };
        assert_eq!(
            (outbound.server.as_str(), outbound.port),
            ("203.0.113.7", 23576)
        );
        assert!(matches!(
            &outbound.security,
            Security::Reality { sni, short_id, public_key, .. }
                if sni == "example.com" && short_id == "01" && *public_key == key
        ));
        // Where a certificate is checked, the Clash spelling of the flag still
        // switches the check off.
        let tls = vmess(format!(
            r#"{{"add":"203.0.113.13","id":"{uuid}","net":"tcp","port":443,"ps":"x","tls":"tls","sni":"example.com","skip-cert-verify":true}}"#
        ));
        let Ok(CoreProfile::Link(outbound)) =
            CoreProfile::parse_for_backend(&tls, FcaeBackend::SingBox)
        else {
            panic!("a share link is one outbound");
        };
        assert!(matches!(
            outbound.security,
            Security::Tls {
                allow_insecure: true,
                ..
            }
        ));
        // Reading past a label is not reading past a setting.
        let reality = format!("security=reality&pbk={key}&sni=example.com");
        for refused in [
            format!("vless://{uuid}@203.0.113.7:443?{reality}&type=tcp&headerType=http&path=/x#a"),
            format!("vless://{uuid}@203.0.113.7:443?{reality}&type=tcp&obfs=1#a"),
            format!("vless://{uuid}@203.0.113.7:443?{reality}&allowInsecure=maybe#a"),
        ] {
            assert!(
                check_config(FcaeBackend::Xray, &refused).is_err(),
                "{refused}"
            );
        }
    }

    #[test]
    fn flags_are_spelled_as_country_codes() {
        assert_eq!(clean_name("🇺🇸").as_deref(), Some("US"));
        assert_eq!(clean_name("🇩🇪Berlin 2").as_deref(), Some("DE Berlin 2"));
        assert_eq!(clean_name("Fast🇯🇵").as_deref(), Some("Fast JP"));
        assert_eq!(clean_name("🇺🇸🇩🇪 relay").as_deref(), Some("US DE relay"));
        assert_eq!(clean_name("[🇬🇧] London").as_deref(), Some("[GB] London"));
        // One indicator on its own is not a flag.
        assert_eq!(clean_name("🇺 x").as_deref(), Some("🇺 x"));
    }

    #[test]
    fn suggested_names_fit_the_library() {
        let long = format!("trojan://secret@example.com:443#{}", "\u{00e9}".repeat(60));
        let name = suggested_name(FcaeBackend::Xray, &long).unwrap();
        assert!(name.len() <= MAX_NAME);
        assert!(name.chars().all(|c| c == '\u{00e9}'));
        assert_eq!(
            suggested_name(
                FcaeBackend::Xray,
                "trojan://secret@example.com:443#a%0Ab%09c"
            )
            .as_deref(),
            Some("a b c")
        );
        assert_eq!(suggested_name(FcaeBackend::Xray, ""), None);
    }
}
