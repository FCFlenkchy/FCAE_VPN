//! Mihomo profile validation and managed config generation.
use crate::sing_xray::{CoreProfile, Outbound, Plan, Protocol, Rules, Security, Transport};
use crate::upstream::ProxyKind;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr};

const UPSTREAM: &str = "FCAE-UPSTREAM";
const PROXY: &str = "FCAE-PROXY";
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
