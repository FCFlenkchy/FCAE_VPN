//! Mihomo runs in a private process per hop: its upstream router is a singleton.
use crate::{
    backend::{
        Backend, BackendContext, BackendHandle, BackendId, Capabilities, Counters, Endpoints,
    },
    error::{CoreError, Result},
    sing_xray::{CoreProfile, Outbound, Plan, Protocol, Rules, Security, Transport},
    upstream::ProxyKind,
};
use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
    task::JoinHandle,
};

const UPSTREAM: &str = "FCAE-UPSTREAM";
const PROXY: &str = "FCAE-PROXY";
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static LISTENERS: Mutex<Vec<crate::sing_xray::CoreListener>> = Mutex::new(Vec::new());
pub fn listeners() -> Vec<crate::sing_xray::CoreListener> {
    LISTENERS.lock().clone()
}

pub fn is_native(value: &Value) -> bool {
    [
        "proxies",
        "proxy-groups",
        "proxy-providers",
        "mixed-port",
        "socks-port",
    ]
    .iter()
    .any(|key| value.get(*key).is_some())
}

/// Fail rather than discard a share link option that has no verified mapping.
pub fn proxy(outbound: &Outbound) -> std::result::Result<Value, String> {
    let refuse = |field: &str| {
        format!("Mihomo share-link conversion does not support {field}; use a native Mihomo config")
    };
    if outbound.finalmask.is_some() {
        return Err(refuse("finalmask"));
    }
    if outbound.dial.uot.is_some() || outbound.dial.packet_encoding.is_some() {
        return Err(refuse("explicit UDP framing"));
    }
    let mut result = json!({"name":PROXY,"server":outbound.server,"port":outbound.port,"udp":true,"tfo":outbound.dial.tfo});
    match &outbound.protocol {
        Protocol::Vless {
            uuid,
            flow,
            encryption,
        } => {
            if encryption.is_some() {
                return Err(refuse("VLESS encryption"));
            }
            result["type"] = json!("vless");
            result["uuid"] = json!(uuid);
            if let Some(flow) = flow {
                result["flow"] = json!(flow);
            }
        }
        Protocol::Vmess {
            uuid,
            alter_id,
            security,
        } => {
            result["type"] = json!("vmess");
            result["uuid"] = json!(uuid);
            result["alterId"] = json!(alter_id);
            result["cipher"] = json!(security);
        }
        Protocol::Trojan { password } => {
            result["type"] = json!("trojan");
            result["password"] = json!(password);
        }
        Protocol::Shadowsocks {
            method,
            password,
            plugin,
        } => {
            if plugin.is_some() {
                return Err(refuse("SIP003 plugin options"));
            }
            result["type"] = json!("ss");
            result["cipher"] = json!(method);
            result["password"] = json!(password);
        }
        Protocol::Socks { user, password } | Protocol::Http { user, password } => {
            result["type"] = json!(if matches!(outbound.protocol, Protocol::Socks { .. }) {
                "socks5"
            } else {
                "http"
            });
            if let Some(user) = user {
                result["username"] = json!(user);
            }
            if let Some(password) = password {
                result["password"] = json!(password);
            }
        }
        Protocol::AnyTls { password } => {
            result["type"] = json!("anytls");
            result["password"] = json!(password);
        }
        Protocol::Hysteria2 {
            password,
            obfs,
            up_mbps,
            down_mbps,
            ports,
            hop_interval,
            pin,
        } => {
            if pin.is_some() {
                return Err(refuse("Hysteria2 public-key pin"));
            }
            result["type"] = json!("hysteria2");
            result["password"] = json!(password);
            if let Some(up) = up_mbps {
                result["up"] = json!(up);
            }
            if let Some(down) = down_mbps {
                result["down"] = json!(down);
            }
            if !ports.is_empty() {
                result["ports"] = json!(ports.join(","));
            }
            if let Some(interval) = hop_interval {
                result["hop-interval"] = json!(interval);
            }
            if let Some(obfs) = obfs {
                if obfs.kind != "salamander"
                    || obfs.min_packet_size.is_some()
                    || obfs.max_packet_size.is_some()
                {
                    return Err(refuse("Hysteria2 obfuscation"));
                }
                result["obfs"] = json!(obfs.kind);
                result["obfs-password"] = json!(obfs.password);
            }
        }
        Protocol::Tuic {
            uuid,
            password,
            congestion_control,
            udp_relay_mode,
            zero_rtt,
        } => {
            result["type"] = json!("tuic");
            result["uuid"] = json!(uuid);
            result["password"] = json!(password);
            result["reduce-rtt"] = json!(zero_rtt);
            if let Some(value) = congestion_control {
                result["congestion-controller"] = json!(value);
            }
            if let Some(value) = udp_relay_mode {
                result["udp-relay-mode"] = json!(value);
            }
        }
        _ => return Err(refuse(outbound.protocol.name())),
    }
    match &outbound.security {
        Security::None => {}
        Security::Tls {
            sni,
            alpn,
            fingerprint,
            allow_insecure,
            pinned_cert_sha256,
            verify_cert_by_name,
            ech,
        } => {
            if pinned_cert_sha256.is_some() || verify_cert_by_name.is_some() || ech.is_some() {
                return Err(refuse("TLS pin/name/ECH overrides"));
            }
            result["tls"] = json!(true);
            result["skip-cert-verify"] = json!(allow_insecure);
            if let Some(sni) = sni {
                result["servername"] = json!(sni);
                result["sni"] = json!(sni);
            }
            if !alpn.is_empty() {
                result["alpn"] = json!(alpn);
            }
            if let Some(fp) = fingerprint {
                result["client-fingerprint"] = json!(fp);
            }
        }
        Security::Reality {
            sni,
            fingerprint,
            public_key,
            short_id,
            spider_x,
            mldsa65_verify,
        } => {
            if mldsa65_verify.is_some() || (!spider_x.is_empty() && spider_x != "/") {
                return Err(refuse("REALITY spiderX/ML-DSA"));
            }
            result["tls"] = json!(true);
            result["servername"] = json!(sni);
            result["client-fingerprint"] = json!(fingerprint);
            result["reality-opts"] = json!({"public-key":public_key,"short-id":short_id});
        }
    }
    match &outbound.transport {
        Transport::Tcp => {}
        Transport::Ws {
            path,
            host,
            max_early_data,
            early_data_header,
        } => {
            result["network"] = json!("ws");
            result["ws-opts"] = json!({"path":path});
            if let Some(host) = host {
                result["ws-opts"]["headers"] = json!({"Host":host});
            }
            if let Some(value) = max_early_data {
                result["ws-opts"]["max-early-data"] = json!(value);
            }
            if let Some(value) = early_data_header {
                result["ws-opts"]["early-data-header-name"] = json!(value);
            }
        }
        Transport::Grpc {
            service,
            multi_mode,
            authority,
        } => {
            if *multi_mode || authority.is_some() {
                return Err(refuse("gRPC authority/multiMode"));
            }
            result["network"] = json!("grpc");
            result["grpc-opts"] = json!({"grpc-service-name":service});
        }
        Transport::H2 { path, host, method } => {
            if method.as_deref().is_some_and(|m| m != "GET") {
                return Err(refuse("custom HTTP/2 method"));
            }
            result["network"] = json!("h2");
            result["h2-opts"] = json!({"path":path});
            if let Some(host) = host {
                result["h2-opts"]["host"] =
                    json!(host.split(',').map(str::trim).collect::<Vec<_>>());
            }
        }
        other => return Err(refuse(other.name())),
    }
    Ok(result)
}

pub fn validate(profile: &CoreProfile) -> std::result::Result<(), String> {
    match profile {
        CoreProfile::Link(outbound) => {
            proxy(outbound)?;
        }
        CoreProfile::Native(config) => {
            if !is_native(config) {
                return Err("not a native Mihomo config (expected proxies, proxy-groups or proxy-providers)".into());
            }
            if config.get("outbounds").is_some() {
                return Err("Mihomo uses proxies, not Xray/sing-box outbounds".into());
            }
            if config
                .get("listeners")
                .and_then(Value::as_array)
                .is_some_and(|v| !v.is_empty())
            {
                return Err("custom Mihomo listeners are not supported by the app's managed listener planner; use port/socks-port/mixed-port".into());
            }
            for key in [
                "ss-config",
                "vmess-config",
                "tuic-server",
                "tunnels",
                "authentication",
            ] {
                if config
                    .get(key)
                    .is_some_and(|v| !v.is_null() && v != &json!([]) && v != &json!(""))
                {
                    return Err(format!(
                        "Mihomo {key} is not supported by the managed listener planner"
                    ));
                }
            }
            for key in ["proxies", "proxy-groups", "rules", "listeners"] {
                if config.get(key).is_some_and(|v| !v.is_array()) {
                    return Err(format!("Mihomo {key} must be a list"));
                }
            }
            if let Some(providers) = config.get("proxy-providers") {
                let providers = providers
                    .as_object()
                    .ok_or("Mihomo proxy-providers must be a mapping")?;
                for provider in providers.values() {
                    if !provider.is_object()
                        || provider.get("override").is_some_and(|v| !v.is_object())
                    {
                        return Err(
                            "Mihomo proxy provider and its override must be mappings".into()
                        );
                    }
                }
            }
            for entry in config
                .get("proxies")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if entry.get("name").and_then(Value::as_str).is_none()
                    || entry.get("type").and_then(Value::as_str).is_none()
                {
                    return Err("each Mihomo proxy needs name and type".into());
                }
            }
        }
    }
    Ok(())
}

pub fn generate(plan: &Plan<'_>) -> std::result::Result<Value, String> {
    validate(plan.profile)?;
    let mut value = match plan.profile {
        CoreProfile::Native(config) => config.clone(),
        CoreProfile::Link(outbound) => {
            json!({"mode":"rule","proxies":[proxy(outbound)?],"rules":[format!("MATCH,{PROXY}")]})
        }
    };
    // The app owns TUN and public listeners. No second TUN, transparent proxy,
    // unauthenticated controller or automatic system changes from a pasted config.
    for key in [
        "tun",
        "listeners",
        "external-controller",
        "external-controller-tls",
        "external-controller-unix",
        "external-controller-pipe",
        "external-ui",
        "external-ui-url",
        "authentication",
        "iptables",
        "ntp",
    ] {
        value.as_object_mut().unwrap().remove(key);
    }
    value["tun"] = json!({"enable":false});
    value["redir-port"] = json!(0);
    value["tproxy-port"] = json!(0);
    value["mixed-port"] = json!(0);
    value["socks-port"] = json!(plan.socks.map_or(0, |v| v.port()));
    value["port"] = json!(plan.http.map_or(0, |v| v.port()));
    if let (Some(socks), Some(http)) = (plan.socks, plan.http) {
        if socks == http {
            value["mixed-port"] = json!(socks.port());
            value["socks-port"] = json!(0);
            value["port"] = json!(0);
        }
    }
    if let Some(dns) = value.get_mut("dns").and_then(Value::as_object_mut) {
        // DNS remains available inside the core, never as an unmanaged server.
        dns.remove("listen");
    }

    let bind = plan
        .socks
        .or(plan.http)
        .map(|v| v.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    value["allow-lan"] = json!(!bind.is_loopback());
    value["bind-address"] = json!(bind.to_string());
    value["log-level"] = json!(match plan.level {
        crate::sing_xray::Level::Off => "silent",
        crate::sing_xray::Level::Error => "error",
        crate::sing_xray::Level::Warn => "warning",
        crate::sing_xray::Level::Info => "info",
        _ => "debug",
    });
    value["geo-auto-update"] = json!(false);
    if let Some(upstream) = plan.upstream {
        let proxies = value
            .as_object_mut()
            .unwrap()
            .entry("proxies")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or("Mihomo proxies must be a list")?;
        if proxies
            .iter()
            .any(|p| p.get("name").and_then(Value::as_str) == Some(UPSTREAM))
        {
            return Err(format!("{UPSTREAM} is reserved for the app's chain"));
        }
        let mut via = json!({"name":UPSTREAM,"type":if upstream.kind==ProxyKind::Socks5{"socks5"}else{"http"},"server":upstream.host,"port":upstream.port,"udp":upstream.kind==ProxyKind::Socks5});
        if let Some(user) = &upstream.user {
            via["username"] = json!(user);
        }
        if let Some(password) = &upstream.password {
            via["password"] = json!(password);
        }
        for proxy in proxies.iter_mut() {
            if proxy["type"] == "direct" {
                let name = proxy["name"].clone();
                *proxy = via.clone();
                proxy["name"] = name;
            } else if proxy.get("dialer-proxy").is_none() {
                proxy["dialer-proxy"] = json!(UPSTREAM);
            }
        }
        proxies.push(via);
        // A built-in DIRECT/COMPATIBLE target has no configurable dialer.
        // Rewrite only routing targets, never arbitrary user strings/passwords.
        fn chain_targets(value: &mut Value) {
            match value {
                Value::Array(items) => {
                    for item in items {
                        chain_targets(item);
                    }
                }
                Value::Object(items) => {
                    for (key, item) in items {
                        if key == "proxies" || key == "rules" || key == "sub-rules" {
                            chain_targets(item);
                        }
                    }
                }
                Value::String(rule) => {
                    if rule.is_empty() {
                        return;
                    }
                    let mut parts: Vec<_> = rule.split(',').map(str::to_owned).collect();
                    let target = if parts.last().is_some_and(|p| p == "no-resolve") {
                        parts.len().saturating_sub(2)
                    } else {
                        parts.len().saturating_sub(1)
                    };
                    if matches!(parts[target].as_str(), "DIRECT" | "COMPATIBLE") {
                        parts[target] = UPSTREAM.into();
                        *rule = parts.join(",");
                    }
                }
                _ => {}
            }
        }
        for key in ["rules", "proxy-groups"] {
            if let Some(rules) = value.get_mut(key) {
                chain_targets(rules);
            }
        }
        if let Some(sub_rules) = value.get_mut("sub-rules").and_then(Value::as_object_mut) {
            for rules in sub_rules.values_mut() {
                chain_targets(rules);
            }
        }
        if value["mode"]
            .as_str()
            .is_some_and(|v| v.eq_ignore_ascii_case("direct"))
        {
            value["mode"] = json!("rule");
            value["rules"] = json!([format!("MATCH,{UPSTREAM}")]);
        }
        if value["mode"]
            .as_str()
            .is_some_and(|v| v.eq_ignore_ascii_case("global"))
        {
            let names: Vec<Value> = value["proxies"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|p| p.get("name").cloned())
                .collect();
            let groups = value
                .as_object_mut()
                .unwrap()
                .entry("proxy-groups")
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .unwrap();
            if !groups.iter().any(|g| g["name"] == "GLOBAL") {
                groups.push(json!({"name":"GLOBAL", "type":"select", "proxies":names}));
            }
        }
        if let Some(providers) = value
            .get_mut("proxy-providers")
            .and_then(Value::as_object_mut)
        {
            for provider in providers.values_mut() {
                provider["proxy"] = json!(UPSTREAM);
                if provider.get("override").is_none() {
                    provider["override"] = json!({});
                }
                provider["override"]["dialer-proxy"] = json!(UPSTREAM);
            }
        }
    }
    let rules = Rules::build(plan.routing)?;
    let mut prepend = Vec::new();
    for (entries, target, domain) in [
        (&rules.block_domains, "REJECT", true),
        (&rules.block_ips, "REJECT", false),
        (&rules.direct_domains, "DIRECT", true),
        (&rules.direct_ips, "DIRECT", false),
    ] {
        for entry in entries {
            let entry = if !domain && !entry.contains('/') {
                format!("{entry}/{}", if entry.contains(':') { 128 } else { 32 })
            } else {
                entry.clone()
            };
            prepend.push(json!(format!(
                "{},{entry},{target}",
                if domain {
                    "DOMAIN-SUFFIX"
                } else if entry.contains(':') {
                    "IP-CIDR6"
                } else {
                    "IP-CIDR"
                }
            )));
        }
    }
    if !prepend.is_empty() {
        let existing = value
            .as_object_mut()
            .unwrap()
            .entry("rules")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or("Mihomo rules must be a list")?;
        prepend.append(existing);
        *existing = prepend;
    }
    Ok(value)
}

fn binary() -> std::result::Result<PathBuf, String> {
    if cfg!(target_os = "ios") {
        return Err("Mihomo's process isolation is unavailable on iOS".into());
    }
    let name = if cfg!(windows) {
        "mihomo.exe"
    } else if cfg!(target_os = "android") {
        "libmihomo_exec.so"
    } else {
        "mihomo"
    };
    let path = if let Some(path) = std::env::var_os("FCAE_MIHOMO_PATH") {
        PathBuf::from(path)
    } else if cfg!(target_os = "android") {
        PathBuf::from(
            std::env::var_os("AETHER_NATIVE_LIB_DIR")
                .ok_or("Android native library directory is not initialized")?,
        )
        .join(name)
    } else {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        exe.parent()
            .ok_or("application has no directory")?
            .join(name)
    };
    if !path.is_file() {
        return Err(format!(
            "Mihomo executable is not packaged at {}",
            path.display()
        ));
    }
    Ok(path)
}

pub struct MihomoBackend;
struct Process {
    child: Mutex<Child>,
    _directory: tempfile::TempDir,
    tasks: Vec<JoinHandle<()>>,
    endpoint: Endpoints,
    counters: Arc<Mutex<(Instant, Counters)>>,
    id: u64,
    rtt_ms: Arc<AtomicU32>,
    rtt_stop: Arc<AtomicBool>,
}
impl Drop for Process {
    fn drop(&mut self) {
        self.rtt_stop.store(true, Ordering::Release);
        LISTENERS
            .lock()
            .retain(|listener| listener.handle != self.id);
        for task in &self.tasks {
            task.abort();
        }
        let _ = self.child.get_mut().start_kill();
        crate::sing_xray::retire_live(fcae_abi::FcaeBackend::Mihomo, self.id);
    }
}
#[async_trait]
impl Backend for MihomoBackend {
    fn id(&self) -> BackendId {
        BackendId::Mihomo
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            socks: true,
            http_proxy: true,
            gateway_scanning: false,
            routing_rules: true,
            requires_privileges: false,
        }
    }
    fn availability(&self) -> std::result::Result<(), String> {
        binary().map(|_| ())
    }
    async fn start(&self, cx: BackendContext) -> Result<Box<dyn BackendHandle>> {
        let executable = binary().map_err(CoreError::StartFailed)?;
        let profile = cx
            .config
            .core
            .profile
            .as_ref()
            .ok_or_else(|| CoreError::InvalidConfig("Mihomo needs a saved config".into()))?;
        let (socks, http) = crate::sing_xray::plan_listeners(&cx.config)?;
        let mut peer_ip = match profile.endpoint() {
            Some((host, port)) => crate::sing_xray::resolve_peer(&cx.config, host, port).await?,
            None => None,
        };
        if cx.config.is_tun() && cx.config.upstream_proxy.is_none() {
            if let CoreProfile::Native(native) = profile {
                let mut hosts = Vec::new();
                for proxy in native
                    .get("proxies")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(host) = proxy.get("server").and_then(Value::as_str) {
                        hosts.push((
                            host.to_owned(),
                            proxy.get("port").and_then(Value::as_u64).unwrap_or(443) as u16,
                        ));
                    }
                }
                for providers in ["proxy-providers", "rule-providers"] {
                    for provider in native
                        .get(providers)
                        .and_then(Value::as_object)
                        .into_iter()
                        .flat_map(|p| p.values())
                    {
                        if let Some(url) = provider.get("url").and_then(Value::as_str) {
                            if let Ok(url) = reqwest::Url::parse(url) {
                                if let Some(host) = url.host_str() {
                                    hosts.push((
                                        host.to_owned(),
                                        url.port_or_known_default().unwrap_or(443),
                                    ));
                                }
                            }
                        }
                    }
                }
                for (host, port) in hosts {
                    let resolved = crate::sing_xray::resolve_peer(&cx.config, &host, port).await?;
                    let addresses = crate::backend::bypass_peers(resolved.as_deref());
                    peer_ip = crate::backend::append_bypass(peer_ip.as_deref(), &addresses);
                }
            }
        }
        let mut config = generate(&Plan {
            profile,
            socks,
            http,
            level: crate::sing_xray::Level::of(cx.config.core.log_level),
            upstream: cx.config.upstream_proxy.as_ref(),
            routing: &cx.config.routing,
            dial: None,
        })
        .map_err(CoreError::InvalidConfig)?;
        let reserved =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(start_error)?;
        let control = reserved.local_addr().map_err(start_error)?;
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|e| CoreError::Internal(e.to_string()))?;
        let secret: String = random.iter().map(|b| format!("{b:02x}")).collect();
        config["external-controller"] = json!(control.to_string());
        config["secret"] = json!(secret);
        config["external-controller-cors"] =
            json!({"allow-origins":[],"allow-private-network":false});
        if let Some(parent) = cx.config.data_dir.as_deref() {
            std::fs::create_dir_all(parent).map_err(start_error)?;
        }
        let directory = tempfile::Builder::new()
            .prefix("fcae-mihomo-")
            .tempdir_in(
                cx.config
                    .data_dir
                    .as_deref()
                    .map(std::path::Path::new)
                    .unwrap_or(std::env::temp_dir().as_path()),
            )
            .map_err(start_error)?;
        let file = directory.path().join("config.json");
        // The enclosing directory is private (0700 on Unix), including caches.
        std::fs::write(
            &file,
            serde_json::to_vec(&config).map_err(|e| CoreError::InvalidConfig(e.to_string()))?,
        )
        .map_err(start_error)?;
        let mut check = Command::new(&executable);
        check
            .arg("-t")
            .arg("-d")
            .arg(directory.path())
            .arg("-f")
            .arg(&file)
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null());
        #[cfg(windows)]
        check.creation_flags(0x08000000);
        let checked = tokio::time::timeout(Duration::from_secs(30), check.output())
            .await
            .map_err(|_| CoreError::Timeout(Duration::from_secs(30)))?
            .map_err(start_error)?;
        if !checked.status.success() {
            return Err(CoreError::InvalidConfig(format!(
                "Mihomo validation failed: {}{}",
                String::from_utf8_lossy(&checked.stdout),
                String::from_utf8_lossy(&checked.stderr)
            )));
        }
        drop(reserved);
        let mut command = Command::new(executable);
        command
            .arg("-d")
            .arg(directory.path())
            .arg("-f")
            .arg(file)
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        #[cfg(windows)]
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        let mut child = command.spawn().map_err(start_error)?;
        let mut tasks = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            tasks.push(log_lines(stdout));
        }
        if let Some(stderr) = child.stderr.take() {
            tasks.push(log_lines(stderr));
        }
        let counters = Arc::new(Mutex::new((Instant::now(), Counters::default())));
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(750))
            .build()
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        let mut process = Process {
            child: Mutex::new(child),
            _directory: directory,
            tasks,
            endpoint: Endpoints {
                socks,
                http,
                peer_ip,
                udp: true,
                psiphon_dns: false,
            },
            counters: Arc::clone(&counters),
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            rtt_ms: Arc::new(AtomicU32::new(0)),
            rtt_stop: Arc::new(AtomicBool::new(false)),
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if cx.cancel.is_cancelled() {
                return Err(CoreError::StartFailed("Mihomo start cancelled".into()));
            }
            if let Some(status) = process.child.lock().try_wait().map_err(start_error)? {
                return Err(CoreError::StartFailed(format!(
                    "Mihomo exited during startup: {status}"
                )));
            }
            if let Ok(response) = client
                .get(format!("http://{control}/version"))
                .bearer_auth(&secret)
                .send()
                .await
            {
                if response.status().is_success() && probe(socks, http).await.is_ok() {
                    break;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(CoreError::Timeout(Duration::from_secs(30)));
            }
            tokio::select! {_=cx.cancel.cancelled()=>return Err(CoreError::StartFailed("Mihomo start cancelled".into())),_=tokio::time::sleep(Duration::from_millis(100))=>{}}
        }
        if let Some(probe) = crate::sing_xray::RttProbe::plan(
            profile,
            cx.config.upstream_proxy.clone(),
            &process.endpoint,
        ) {
            let rtt_ms = Arc::clone(&process.rtt_ms);
            let stop = Arc::clone(&process.rtt_stop);
            std::thread::Builder::new()
                .name("fcae-mihomo-rtt".into())
                .spawn(move || crate::sing_xray::measure_until_known(&probe, &rtt_ms, &stop))
                .map_err(start_error)?;
        }
        process.tasks.push(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let Ok(response) = client
                    .get(format!("http://{control}/connections"))
                    .bearer_auth(&secret)
                    .send()
                    .await
                else {
                    continue;
                };
                if !response.status().is_success() {
                    continue;
                }
                let Ok(text) = response.text().await else {
                    continue;
                };
                let Ok(value) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                let Some(rx) = value["downloadTotal"].as_u64() else {
                    continue;
                };
                let Some(tx) = value["uploadTotal"].as_u64() else {
                    continue;
                };
                let mut state = counters.lock();
                let elapsed = state.0.elapsed().as_secs_f64().max(0.001);
                state.1.rx_bytes_sec =
                    (rx.saturating_sub(state.1.total_rx) as f64 / elapsed) as u64;
                state.1.tx_bytes_sec =
                    (tx.saturating_sub(state.1.total_tx) as f64 / elapsed) as u64;
                state.1.total_rx = rx;
                state.1.total_tx = tx;
                state.0 = Instant::now();
            }
        }));
        for (address, proto) in [(socks, "socks"), (http, "http")] {
            if let Some(address) = address {
                LISTENERS.lock().push(crate::sing_xray::CoreListener {
                    handle: process.id,
                    label: String::new(),
                    proto: proto.into(),
                    port: address.port(),
                    any: address.ip().is_unspecified(),
                });
            }
        }
        crate::sing_xray::publish_live(
            fcae_abi::FcaeBackend::Mihomo,
            process.id,
            cx.config
                .core
                .selection_name()
                .unwrap_or_default()
                .to_owned(),
        );
        Ok(Box::new(process))
    }
}
fn start_error(error: std::io::Error) -> CoreError {
    CoreError::StartFailed(format!("Mihomo: {error}"))
}
fn log_lines<R: tokio::io::AsyncRead + Unpin + Send + 'static>(reader: R) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut reader = BufReader::new(reader);
        let mut line = Vec::new();
        loop {
            line.clear();
            let read = (&mut reader).take(16384).read_until(b'\n', &mut line).await;
            match read {
                Ok(0) | Err(_) => break,
                _ => log::info!("[Mihomo] {}", String::from_utf8_lossy(&line).trim_end()),
            }
        }
    })
}
async fn probe(socks: Option<SocketAddr>, http: Option<SocketAddr>) -> std::io::Result<()> {
    let address = socks
        .or(http)
        .ok_or_else(|| std::io::Error::other("no listener"))?;
    let address = if address.ip().is_unspecified() {
        SocketAddr::from((Ipv4Addr::LOCALHOST, address.port()))
    } else {
        address
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        let mut stream = tokio::net::TcpStream::connect(address).await?;
        if socks.is_some() {
            stream.write_all(&[5, 1, 0]).await?;
            let mut reply = [0; 2];
            stream.read_exact(&mut reply).await?;
            if reply != [5, 0] {
                return Err(std::io::Error::other("invalid SOCKS greeting"));
            }
        }
        Ok(())
    })
    .await
    .map_err(|_| std::io::Error::other("listener probe timeout"))?
}
#[async_trait]
impl BackendHandle for Process {
    fn endpoints(&self) -> Endpoints {
        self.endpoint.clone()
    }
    async fn wait(&self) -> Result<()> {
        loop {
            if let Some(status) = self.child.lock().try_wait().map_err(start_error)? {
                return Err(CoreError::StartFailed(format!("Mihomo exited: {status}")));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    async fn stop(&self, timeout: Duration) -> Result<()> {
        self.rtt_stop.store(true, Ordering::Release);
        {
            let mut child = self.child.lock();
            if child.try_wait().map_err(start_error)?.is_some() {
                return Ok(());
            }
            child.start_kill().map_err(start_error)?;
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.child.lock().try_wait().map_err(start_error)?.is_some() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(CoreError::Timeout(timeout));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    fn carrier_up(&self) -> bool {
        matches!(self.child.lock().try_wait(), Ok(None))
    }
    fn counters(&self) -> Counters {
        Counters {
            rtt_ms: self.rtt_ms.load(Ordering::Acquire),
            ..self.counters.lock().1
        }
    }
}
