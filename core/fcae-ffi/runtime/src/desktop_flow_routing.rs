//! Process-aware captured-flow routing through the existing exit SOCKS chain.
//! This is not OS-level exclusion or a system-wide, crash-persistent kill switch.
use crate::{
    config::SessionConfig,
    error::{CoreError, Result},
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        LazyLock, Mutex,
    },
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowPolicy {
    pub revision: u64,
    pub provider: String,
    pub mode: u8,
    pub paths: BTreeSet<String>,
}
static NEXT: AtomicU64 = AtomicU64::new(1);
#[derive(Default)]
struct State {
    requested: Option<FlowPolicy>,
    active: Option<u64>,
    message: String,
}
static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| Mutex::new(State::default()));
fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}
fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::InvalidConfig(message.into())
}
pub fn parse(value: &Value) -> Result<Option<FlowPolicy>> {
    if value["schema_version"]
        .as_u64()
        .is_some_and(|version| version != 1)
    {
        return Err(invalid("unsupported app-flow policy schema"));
    }
    let mode = value["mode"]
        .as_u64()
        .filter(|m| *m <= 2)
        .ok_or_else(|| invalid("invalid app-routing mode"))? as u8;
    if mode == 0 {
        return Ok(None);
    }
    let provider = value["provider"].as_str().unwrap_or("captured_flow");
    if provider != "captured_flow" && !(cfg!(target_os = "macos") && provider == "macos_ne") {
        return Err(invalid(
            "app-routing provider is unavailable on this platform",
        ));
    }
    if value["fail_closed"].as_bool() == Some(true) {
        return Err(invalid(
            "the flow provider has no independent crash-persistent kill switch",
        ));
    }
    let platform = if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unsupported"
    };
    if value["platform"]
        .as_str()
        .is_some_and(|requested| requested != platform)
    {
        return Err(invalid("application policy belongs to another platform; imported selectors were not reinterpreted"));
    }
    let values = value["apps"]
        .as_array()
        .ok_or_else(|| invalid("app routing requires an executable path list"))?;
    if values.len() > 8192 {
        return Err(invalid("too many app selectors"));
    }
    let mut paths = BTreeSet::new();
    for value in values {
        let path = value
            .as_str()
            .ok_or_else(|| invalid("selector must be an executable path"))?;
        if path.is_empty()
            || path.len() > 32768
            || path.chars().any(char::is_control)
            || !std::path::Path::new(path).is_absolute()
            || std::path::Path::new(path)
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(invalid("application selectors must be absolute executable paths without control characters or parent traversal"));
        }
        paths.insert(path.to_owned());
    }
    if mode == 1 && paths.is_empty() {
        return Err(invalid(
            "include mode needs at least one selected executable",
        ));
    }
    if mode == 2 && paths.is_empty() {
        return Ok(None);
    }
    let mut revision = NEXT.load(Ordering::Relaxed);
    loop {
        let next = revision
            .checked_add(1)
            .ok_or_else(|| invalid("policy revision exhausted"))?;
        match NEXT.compare_exchange_weak(revision, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(current) => revision = current,
        }
    }
    let revision = state()
        .requested
        .as_ref()
        .filter(|policy| {
            policy.mode == mode && policy.paths == paths && policy.provider == provider
        })
        .map_or(revision, |policy| policy.revision);
    Ok(Some(FlowPolicy {
        revision,
        provider: provider.to_owned(),
        mode,
        paths,
    }))
}
pub fn snapshot() -> Option<FlowPolicy> {
    state().requested.clone()
}
pub fn request(value: &Value) -> Value {
    match value["action"].as_str().unwrap_or("") {
        "flow_configure" => match parse(value) {
            Ok(policy) => {
                let mut s = state();
                s.requested = policy;
                s.message.clear();
            }
            Err(error) => {
                return json!({"ok":false,"active":state().active.is_some(),"message":error.to_string()})
            }
        },
        "flow_status" => {}
        _ => return json!({"ok":false,"message":"unknown flow routing operation"}),
    }
    let s = state();
    json!({"ok":true,"active":s.active.is_some(),"message":s.message,"requested_revision":s.requested.as_ref().map(|p|p.revision),"active_revision":s.active})
}
pub fn submitted(policy: Option<&FlowPolicy>) {
    let mut s = state();
    if s.requested.is_none() {
        s.requested = policy.cloned();
    }
}
pub fn acknowledge(revision: u64) {
    let mut s = state();
    s.active = Some(revision);
    s.message="App routing active.".into();
}
pub fn acknowledge_macos_ne(revision: u64) {
    let mut s = state();
    s.active = Some(revision);
    s.message=format!("Signed macOS transparent-proxy revision {revision} acknowledged. VPN-required TCP/UDP uses the existing exit chain; declined flows remain OS-routed. Signed identities and explicit helpers only. Shared OS DNS is not isolated per app. New flows only; no independent crash-persistent kill switch.");
}
pub fn withdrawn(revision: u64) {
    let mut s = state();
    if s.active == Some(revision) {
        s.active = None;
        s.message.clear();
    }
}
pub fn degraded(revision: u64, message: &str) {
    let mut s = state();
    if s.active == Some(revision) {
        s.active = None;
        s.message = format!("Captured-flow routing degraded: {message}; reconnect required.");
    }
}

impl FlowPolicy {
    /// Re-resolve identities on the supervisor, never on a GUI render frame.
    pub fn resolve(&self) -> Result<Self> {
        let own = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|e| invalid(e.to_string()))?;
        let mut result = self.clone();
        result.paths.clear();
        for name in &self.paths {
            let path = std::fs::canonicalize(name)
                .map_err(|e| invalid(format!("cannot resolve selected executable {name}: {e}")))?;
            if !path.is_file() {
                return Err(invalid("selected application is not an executable file"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if std::fs::metadata(&path)
                    .map_err(|e| invalid(e.to_string()))?
                    .permissions()
                    .mode()
                    & 0o111
                    == 0
                {
                    return Err(invalid("selected path is not executable"));
                }
            }
            if path == own {
                return Err(invalid("FCAE's own transport process cannot be selected"));
            }
            let text = path
                .to_str()
                .ok_or_else(|| invalid("selected executable path must be UTF-8"))?
                .to_owned();
            result.paths.insert(native_path(text));
        }
        Ok(result)
    }
    /// Generate only route data: the embedded core still validates its grammar
    /// before any capture routes/DNS are installed. No direct fallback exists
    /// for VPN-required flows, including unsupported UDP on TCP-only exits.
    pub fn config(
        &self,
        cfg: &SessionConfig,
        socks: SocketAddr,
        device: &str,
        udp: bool,
    ) -> Result<Value> {
        if !socks.ip().is_loopback() || socks.port() == 0 {
            return Err(invalid("flow routing needs a live loopback SOCKS exit"));
        }
        if device.is_empty()
            || device.len() > 64
            || !device
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
        {
            return Err(invalid("invalid flow TUN device name"));
        }
        let mut addresses = vec![cfg.tun.ipv4.clone()];
        if let Some(v6) = &cfg.tun.ipv6 {
            addresses.push(v6.clone());
        }
        let own = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|e| invalid(e.to_string()))?;
        let own = own
            .to_str()
            .ok_or_else(|| invalid("FCAE executable path must be UTF-8"))?
            .to_owned();
        let own = native_path(own);
        let own_rule = {
            #[cfg(windows)]
            {
                process_rule(std::iter::once(own.as_str()), "fcae-direct")
            }
            #[cfg(not(windows))]
            {
                json!({"process_path":[own],"action":"route","outbound":"fcae-direct"})
            }
        };
        let bypass_selected = self.mode == 2;
        let mut rules = vec![json!({"ip_cidr":addresses,"action":"reject"})];
        if bypass_selected {
            rules.push(own_rule.clone());
            rules.push(process_rule(
                self.paths.iter().map(String::as_str),
                "fcae-direct",
            ));
        }
        rules.push(json!({"port":53,"action":"route","outbound":"fcae-exit"}));
        if !bypass_selected {
            rules.push(own_rule);
        }
        if self.mode == 1 {
            rules.push(process_rule(
                self.paths.iter().map(String::as_str),
                "fcae-exit",
            ));
            // An empty/unresolved owner must not match the unmatched-app rule.
            rules.push(
                json!({"process_path_regex":[".+"],"action":"route","outbound":"fcae-direct"}),
            );
        } else if self.mode != 0 && self.mode != 2 {
            return Err(invalid("invalid application routing mode"));
        }
        let mut exit = json!({"type":"socks","tag":"fcae-exit","server":socks.ip().to_string(),"server_port":socks.port(),"version":"5","inet4_bind_address":"127.0.0.1","inet6_bind_address":"::1"});
        if !udp {
            exit["network"] = json!("tcp");
        }
        let direct = json!({"type":"direct","tag":"fcae-direct"});
        #[cfg(target_os = "macos")]
        let direct = {
            // The Darwin default-interface monitor can fall back to a probe
            // whose route changes to our /1 capture. Pin the pre-capture egress
            // rather than allowing a DIRECT socket to be recaptured by us.
            let output = crate::tun_dns::run("route", &["-n", "get", "default"])?;
            let name = output
                .lines()
                .find_map(|line| line.trim().strip_prefix("interface:"))
                .map(str::trim)
                .filter(|name| {
                    !name.is_empty()
                        && name.len() <= 15
                        && *name != device
                        && *name != "lo0"
                        && name
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                })
                .ok_or_else(|| {
                    invalid("no unambiguous pre-capture egress interface for flow routing")
                })?;
            let mut pinned = direct;
            pinned["bind_interface"] = json!(name);
            pinned
        };
        Ok(json!({"log":{"disabled":cfg.tun.singbox_tun_log_disabled(),"level":cfg.tun.singbox_tun_log_level()},
            "inbounds":[{"type":"tun","tag":"fcae-app-flows","interface_name":device,"address":addresses,"mtu":cfg.tun.mtu,"auto_route":false,"dns_mode":"disabled"}],
            "outbounds":[exit,direct],
            "route":{"auto_detect_interface":true,"find_process":true,"rules":rules,"final":"fcae-exit"}}))
    }
}

fn native_path(text: String) -> String {
    #[cfg(windows)]
    {
        text.strip_prefix("\\\\?\\").unwrap_or(&text).to_owned()
    }
    #[cfg(not(windows))]
    {
        text
    }
}

fn process_rule<'a>(paths: impl Iterator<Item = &'a str>, outbound: &str) -> Value {
    #[cfg(windows)]
    {
        let patterns: Vec<String> = paths
            .map(|path| {
                let mut pattern = String::from("(?i)^");
                for c in path.chars() {
                    if "\\.+*?()|[]{}^$".contains(c) {
                        pattern.push('\\');
                    }
                    pattern.push(c);
                }
                pattern.push('$');
                pattern
            })
            .collect();
        json!({"process_path_regex":patterns,"action":"route","outbound":outbound})
    }
    #[cfg(not(windows))]
    {
        json!({"process_path":paths.collect::<Vec<_>>(),"action":"route","outbound":outbound})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SELECTED_PATH: &str = "/opt/apps/browser";

    fn bypass_policy() -> FlowPolicy {
        FlowPolicy {
            revision: 1,
            provider: "captured_flow".into(),
            mode: 2,
            paths: BTreeSet::from([SELECTED_PATH.into()]),
        }
    }

    #[test]
    fn sing_box_tun_log_is_independent_of_the_proxy_core_log_level() {
        use crate::config::TUN_LOG_DEBUG;
        use fcae_abi::FcaeEngineLog;

        let mut cfg = SessionConfig::default();
        cfg.tun.tun_log_level = TUN_LOG_DEBUG;
        assert_eq!(cfg.core.log_level, FcaeEngineLog::Off);
        let config = bypass_policy()
            .config(&cfg, "127.0.0.1:1080".parse().unwrap(), "fcae0", true)
            .unwrap();
        assert_eq!(config["log"]["disabled"], false);
        assert_eq!(config["log"]["level"], "debug");
    }

    #[test]
    fn bypassed_app_route_precedes_forced_dns_exit() {
        let cfg = SessionConfig::default();
        let policy = bypass_policy();
        let config = policy
            .config(
                &cfg,
                "127.0.0.1:1080".parse().unwrap(),
                "fcae0",
                true,
            )
            .unwrap();
        let rules = config["route"]["rules"].as_array().unwrap();
        let app_rule = rules
            .iter()
            .position(|rule| {
                rule["outbound"] == "fcae-direct"
                    && ["process_path", "process_path_regex"].iter().any(|key| {
                        rule[*key].as_array().is_some_and(|paths| {
                            paths.iter().any(|path| {
                                path.as_str().is_some_and(|path| path.contains(SELECTED_PATH))
                            })
                        })
                    })
            })
            .unwrap();
        let dns_rule = rules
            .iter()
            .position(|rule| rule["port"].as_u64() == Some(53))
            .unwrap();

        assert!(app_rule < dns_rule);
        assert_eq!(rules[dns_rule]["outbound"], "fcae-exit");
    }
}
