//! Xray-core config generation.
//!
//! The bridge owns the generated config completely: listeners, outbound,
//! optional upstream `dialerProxy`, and the app's split-routing rules. Nothing
//! is left to Xray's own defaults, so the same session profile behaves the same
//! way on every release.

use fcae_abi::FcaeBackend;
use fcae_runtime::sing_xray::Level;
use fcae_runtime::sing_xray::Plan;
use fcae_runtime::sing_xray::Rules;
use fcae_runtime::sing_xray::{CoreProfile, Outbound, Protocol, Security, Transport};
use fcae_runtime::upstream::{ProxyKind, UpstreamProxy};
use serde_json::{Map, Value, json};

const PROXY_TAG: &str = "proxy";
const DIRECT_TAG: &str = "direct";
const BLOCK_TAG: &str = "block";
const UPSTREAM_TAG: &str = "fcae-upstream";
/// Tag for the listener that stands in for a native config's TUN inbound when
/// that inbound carries no tag of its own.
const TUN_LISTENER_TAG: &str = "fcae-in";

pub fn generate(plan: &Plan<'_>) -> Result<Value, String> {
    match plan.profile {
        CoreProfile::Native(config) => native(config, plan),
        CoreProfile::Link(outbound) => {
            // The QUIC and AnyTLS families exist only in sing-box; the editor
            // refuses such a link already, but a caller that ships a profile
            // without a library comes through here.
            if !outbound.carried_by(FcaeBackend::Xray) {
                return Err(outbound.refusal(FcaeBackend::Xray));
            }
            if plan.socks.is_none() && plan.http.is_none() {
                return Err("the session has no listener for the core to serve".into());
            }
            config(plan, outbound, &Rules::build(plan.routing)?)
        }
    }
}

fn config(plan: &Plan<'_>, outbound: &Outbound, rules: &Rules) -> Result<Value, String> {
    let mut inbounds = Vec::with_capacity(2);
    if let Some(socks) = plan.socks {
        inbounds.push(json!({
            "tag": "socks-in",
            "protocol": "socks",
            "listen": socks.ip().to_string(),
            "port": socks.port(),
            "settings": {"auth": "noauth", "udp": true},
            "sniffing": {"enabled": false},
        }));
    }
    if let Some(http) = plan.http {
        inbounds.push(json!({
            "tag": "http-in",
            "protocol": "http",
            "listen": http.ip().to_string(),
            "port": http.port(),
            "settings": {},
            "sniffing": {"enabled": false},
        }));
    }

    let mut outbounds = Vec::with_capacity(4);
    outbounds.push(outbound_config(outbound, plan.upstream.is_some())?);
    if let Some(upstream) = plan.upstream {
        outbounds.push(upstream_config(upstream));
    }
    // `direct` and `block` always exist: the routing rules name their tags.
    outbounds.push(json!({"tag": DIRECT_TAG, "protocol": "freedom"}));
    outbounds.push(json!({"tag": BLOCK_TAG, "protocol": "blackhole"}));

    Ok(json!({
        // `access: none` matters: Xray defaults the access log to the console
        // and would otherwise print a line per connection from a GUI process.
        "log": {"loglevel": level(plan.level), "access": "none"},
        // Counters need the stats app, and the policy flags are what make the
        // handlers register a counter in the first place: without both the core
        // runs and reports no bytes at all.
        "stats": {},
        "policy": {"system": system_stats()},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": routing_rules(rules)},
    }))
}

/// The policy flags the app's counters read. Inbound counters are the client's
/// own traffic; the outbound ones are the fallback for a native config whose
/// listeners carry no tag, which Xray does not count.
fn system_stats() -> Value {
    json!({
        "statsInboundUplink": true,
        "statsInboundDownlink": true,
        "statsOutboundUplink": true,
        "statsOutboundDownlink": true,
    })
}

/// Xray's `loglevel` grammar: `none`, `error`, `warning` (the default), `info`,
/// `debug`. Anything else silently degrades to `warning`, so `warn` must be
/// spelled the long way.
fn level(level: Level) -> &'static str {
    match level {
        Level::Off => "none",
        Level::Error => "error",
        Level::Warn => "warning",
        Level::Info => "info",
        // Xray has no level below debug.
        Level::Debug | Level::Trace => "debug",
    }
}

fn outbound_config(outbound: &Outbound, chained: bool) -> Result<Value, String> {
    let (protocol, settings) = match &outbound.protocol {
        Protocol::Vless { uuid, flow, encryption } => {
            // Xray reads `encryption` itself: `none`, or its ML-KEM dot config,
            // which it splits into keys and padding at start.
            let mut user = json!({
                "id": uuid,
                "encryption": encryption.as_deref().unwrap_or("none"),
            });
            if let Some(flow) = flow {
                user["flow"] = json!(flow);
            }
            (
                "vless",
                json!({"vnext": [{
                    "address": outbound.server,
                    "port": outbound.port,
                    "users": [user],
                }]}),
            )
        }
        Protocol::Vmess {
            uuid,
            alter_id,
            security,
        } => (
            "vmess",
            json!({"vnext": [{
                "address": outbound.server,
                "port": outbound.port,
                "users": [{"id": uuid, "alterId": alter_id, "security": security}],
            }]}),
        ),
        Protocol::Trojan { password } => (
            "trojan",
            json!({"servers": [{
                "address": outbound.server,
                "port": outbound.port,
                "password": password,
            }]}),
        ),
        Protocol::Shadowsocks {
            method, password, ..
        } => (
            "shadowsocks",
            json!({"servers": [{
                "address": outbound.server,
                "port": outbound.port,
                "method": method,
                "password": password,
            }]}),
        ),
        Protocol::Socks { user, password } => (
            "socks",
            json!({"servers": [account_server(
                &outbound.server,
                outbound.port,
                user.as_deref(),
                password.as_deref(),
            )]}),
        ),
        Protocol::Http { user, password } => (
            "http",
            json!({"servers": [account_server(
                &outbound.server,
                outbound.port,
                user.as_deref(),
                password.as_deref(),
            )]}),
        ),
        // sing-box's own protocols: Xray-core has no outbound for any of them,
        // so the session is refused with the reason instead of a config the
        // core would reject with a protocol name nobody can act on.
        Protocol::Hysteria2 { .. } | Protocol::Tuic { .. } | Protocol::AnyTls { .. } => {
            return Err(outbound.refusal(FcaeBackend::Xray))
        }
    };

    let mut value = json!({"tag": PROXY_TAG, "protocol": protocol, "settings": settings});
    let stream = stream_settings(outbound, chained)?;
    if !stream.is_empty() {
        value["streamSettings"] = Value::Object(stream);
    }
    Ok(value)
}

fn account_server(address: &str, port: u16, user: Option<&str>, password: Option<&str>) -> Value {
    let mut server = json!({"address": address, "port": port});
    if let Some(user) = user {
        let mut account = json!({"user": user});
        if let Some(password) = password {
            account["pass"] = json!(password);
        }
        server["users"] = json!([account]);
    }
    server
}

fn stream_settings(
    outbound: &Outbound,
    chained: bool,
) -> Result<Map<String, Value>, String> {
    let mut stream = Map::new();
    let network = match &outbound.transport {
        Transport::Tcp => "tcp",
        Transport::Ws { .. } => "ws",
        Transport::HttpUpgrade { .. } => "httpupgrade",
        Transport::Grpc { .. } => "grpc",
        Transport::Kcp { .. } => "kcp",
        Transport::Xhttp { .. } => "xhttp",
        // `generate` refuses these for Xray before a config is built.
        Transport::H2 { .. } => return Err(outbound.refusal(FcaeBackend::Xray)),
    };
    if network != "tcp" {
        stream.insert("network".into(), json!(network));
    }
    match &outbound.security {
        Security::None => {}
        Security::Tls {
            sni,
            alpn,
            fingerprint,
            pinned_cert_sha256,
            verify_cert_by_name,
            ech,
            ..
        } => {
            stream.insert("security".into(), json!("tls"));
            let mut tls = Map::new();
            if let Some(sni) = sni {
                tls.insert("serverName".into(), json!(sni));
            }
            if !alpn.is_empty() {
                tls.insert("alpn".into(), json!(alpn));
            }
            if let Some(fingerprint) = fingerprint {
                tls.insert("fingerprint".into(), json!(fingerprint));
            }
            if let Some(pinned) = pinned_cert_sha256 {
                tls.insert("pinnedPeerCertSha256".into(), json!(pinned));
            }
            if let Some(names) = verify_cert_by_name {
                tls.insert("verifyPeerCertByName".into(), json!(names));
            }
            if let Some(ech) = ech {
                tls.insert("echConfigList".into(), json!(ech));
            }
            stream.insert("tlsSettings".into(), Value::Object(tls));
        }
        Security::Reality {
            sni,
            fingerprint,
            public_key,
            short_id,
            spider_x,
            mldsa65_verify,
        } => {
            stream.insert("security".into(), json!("reality"));
            let mut reality = Map::new();
            reality.insert("serverName".into(), json!(sni));
            reality.insert("fingerprint".into(), json!(fingerprint));
            reality.insert("publicKey".into(), json!(public_key));
            reality.insert("shortId".into(), json!(short_id));
            reality.insert("spiderX".into(), json!(spider_x));
            if let Some(verify) = mldsa65_verify {
                reality.insert("mldsa65Verify".into(), json!(verify));
            }
            stream.insert("realitySettings".into(), Value::Object(reality));
        }
    }
    match &outbound.transport {
        Transport::Tcp | Transport::H2 { .. } => {}
        Transport::Ws {
            path,
            host,
            max_early_data,
            ..
        } => {
            let mut ws = Map::new();
            ws.insert("path".into(), json!(early_data_path(path, *max_early_data)));
            if let Some(host) = host {
                ws.insert("headers".into(), json!({"Host": host}));
            }
            stream.insert("wsSettings".into(), Value::Object(ws));
        }
        Transport::HttpUpgrade {
            path,
            host,
            max_early_data,
        } => {
            let mut upgrade = Map::new();
            upgrade.insert("path".into(), json!(early_data_path(path, *max_early_data)));
            if let Some(host) = host {
                upgrade.insert("host".into(), json!(host));
            }
            stream.insert("httpupgradeSettings".into(), Value::Object(upgrade));
        }
        Transport::Grpc {
            service,
            authority,
            multi_mode,
        } => {
            let mut grpc = Map::new();
            grpc.insert("serviceName".into(), json!(service));
            if let Some(authority) = authority {
                grpc.insert("authority".into(), json!(authority));
            }
            if *multi_mode {
                grpc.insert("multiMode".into(), json!(true));
            }
            stream.insert("grpcSettings".into(), Value::Object(grpc));
        }
        Transport::Kcp {
            mtu,
            tti,
            uplink_capacity,
            downlink_capacity,
            congestion,
            read_buffer,
            write_buffer,
        } => {
            let mut kcp = Map::new();
            for (key, value) in [
                ("mtu", mtu),
                ("tti", tti),
                ("uplinkCapacity", uplink_capacity),
                ("downlinkCapacity", downlink_capacity),
                ("readBufferSize", read_buffer),
                ("writeBufferSize", write_buffer),
            ] {
                if let Some(value) = value {
                    kcp.insert(key.to_string(), json!(value));
                }
            }
            if let Some(congestion) = congestion {
                kcp.insert("congestion".into(), json!(congestion));
            }
            stream.insert("kcpSettings".into(), Value::Object(kcp));
        }
        Transport::Xhttp {
            path,
            host,
            mode,
            extra,
        } => {
            let mut xhttp = Map::new();
            xhttp.insert("path".into(), json!(path));
            if let Some(host) = host {
                xhttp.insert("host".into(), json!(host));
            }
            if let Some(mode) = mode {
                xhttp.insert("mode".into(), json!(mode));
            }
            // Xray reads `extra` as the whole settings object once it is there,
            // so it goes in as one value rather than being unpacked here.
            if let Some(extra) = extra {
                let extra: Value = serde_json::from_str(extra)
                    .map_err(|error| format!("xhttp extra is not JSON: {error}"))?;
                xhttp.insert("extra".into(), extra);
            }
            stream.insert("xhttpSettings".into(), Value::Object(xhttp));
        }
    }
    if let Some(finalmask) = &outbound.finalmask {
        let finalmask: Value = serde_json::from_str(finalmask)
            .map_err(|error| format!("finalmask fm is not JSON: {error}"))?;
        stream.insert("finalmask".into(), finalmask);
    }
    if chained {
        stream.insert("dialerProxy".into(), json!(UPSTREAM_TAG));
    }
    Ok(stream)
}

/// Xray takes early data as an `ed` query inside the transport's own path and
/// strips it before the request goes out; the count is not a separate setting.
fn early_data_path(path: &str, count: Option<u32>) -> String {
    match count {
        Some(count) => {
            let separator = if path.contains('?') { '&' } else { '?' };
            format!("{path}{separator}ed={count}")
        }
        None => path.to_string(),
    }
}

fn upstream_config(upstream: &UpstreamProxy) -> Value {
    let protocol = match upstream.kind {
        ProxyKind::Http => "http",
        ProxyKind::Socks5 => "socks",
    };
    json!({
        "tag": UPSTREAM_TAG,
        "protocol": protocol,
        "settings": {"servers": [account_server(
            &upstream.host,
            upstream.port,
            upstream.user.as_deref(),
            upstream.password.as_deref(),
        )]},
    })
}

fn routing_rules(rules: &Rules) -> Vec<Value> {
    let mut out = Vec::with_capacity(4);
    if !rules.block_ips.is_empty() {
        out.push(json!({"type": "field", "ip": rules.block_ips, "outbound": BLOCK_TAG}));
    }
    if !rules.block_domains.is_empty() {
        out.push(json!({
            "type": "field",
            "domain": domains(&rules.block_domains),
            "outbound": BLOCK_TAG,
        }));
    }
    if !rules.direct_ips.is_empty() {
        out.push(json!({"type": "field", "ip": rules.direct_ips, "outbound": DIRECT_TAG}));
    }
    if !rules.direct_domains.is_empty() {
        out.push(json!({
            "type": "field",
            "domain": domains(&rules.direct_domains),
            "outbound": DIRECT_TAG,
        }));
    }
    out
}

/// `domain:` covers the name and its subdomains, `full:` pins the exact host, so
/// a rule for `example.com` also matches `example.com` itself.
fn domains(domains: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(domains.len() * 2);
    for domain in domains {
        out.push(format!("domain:{domain}"));
        out.push(format!("full:{domain}"));
    }
    out
}

fn native(config: &Value, plan: &Plan<'_>) -> Result<Value, String> {
    if plan.socks.is_none() {
        return Err("the session has no SOCKS listener for the native config to serve".into());
    }
    if plan.upstream.is_some() {
        return Err(
            "chaining a native Xray config behind an upstream proxy is not supported; use a share link"
                .into(),
        );
    }
    if !Rules::build(plan.routing)?.is_empty() {
        log::warn!("[xray] inline routing rules are ignored for a native config; its own routing wins");
    }

    let mut config = config.clone();
    let object = config
        .as_object_mut()
        .ok_or("native config must be a JSON object")?;

    match object.get_mut("log").and_then(Value::as_object_mut) {
        Some(log) => {
            log.insert("loglevel".into(), json!(level(plan.level)));
        }
        None => {
            object.insert("log".into(), json!({"loglevel": level(plan.level)}));
        }
    }
    // Same counters as a generated config, merged rather than replaced: the
    // `stats` app may already carry settings and `policy` may hold timeouts or
    // per-level settings this app must not drop.
    object.entry("stats").or_insert_with(|| json!({}));
    merge_system_stats(object);

    let inbounds = match object.remove("inbounds") {
        Some(Value::Array(inbounds)) => inbounds,
        Some(_) => return Err("native config \"inbounds\" must be an array".into()),
        None => return Err("native config needs an \"inbounds\" array".into()),
    };

    let mut rewritten = Vec::with_capacity(inbounds.len());
    let mut socks_seen = false;
    let mut tun_tag: Option<String> = None;
    for mut inbound in inbounds {
        let protocol = inbound
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        match protocol.as_str() {
            "socks" | "mixed" => {
                socks_seen = true;
                if let Some(socks) = plan.socks {
                    rewrite_listener(&mut inbound, socks, true)?;
                }
            }
            "http" => match plan.http {
                Some(http) => rewrite_listener(&mut inbound, http, false)?,
                None => {
                    log::info!(
                        "[xray] dropping the native http inbound: the session has no HTTP listener"
                    );
                    continue;
                }
            },
            // FCAE owns the TUN device. A `tun` inbound in the pasted config
            // would create a second one, fight the app's engine for it and
            // hijack routes the session already installed.
            "tun" => {
                tun_tag.get_or_insert_with(|| {
                    inbound
                        .get("tag")
                        .and_then(Value::as_str)
                        .unwrap_or(TUN_LISTENER_TAG)
                        .to_owned()
                });
                log::info!("[xray] dropping the native tun inbound: this app owns the TUN device");
                continue;
            }
            _ => {}
        }
        rewritten.push(inbound);
    }
    if !socks_seen {
        // A config written for the `xray` CLI leads with its own TUN. That
        // inbound's traffic now arrives over the session's SOCKS listener, so
        // the listener takes its place — and its tag, which is what the
        // config's own routing rules name.
        let Some(tag) = tun_tag else {
            return Err(
                "native config needs a socks inbound: TUN mode and chained hops dial the core through it"
                    .into(),
            );
        };
        if let Some(socks) = plan.socks {
            log::info!(
                "[xray] native config has no socks inbound; serving the app's SOCKS listener as `{tag}`"
            );
            rewritten.push(json!({
                "tag": tag,
                "protocol": "socks",
                "listen": socks.ip().to_string(),
                "port": socks.port(),
                "settings": {"auth": "noauth", "udp": true},
                "sniffing": {"enabled": false},
            }));
        }
    }
    object.insert("inbounds".into(), Value::Array(rewritten));
    Ok(config)
}

/// Merge the counters' policy flags into a native config's own `policy`, which
/// may be absent, may hold unrelated fields, or may be the wrong shape for the
/// flags to be added to.
fn merge_system_stats(object: &mut Map<String, Value>) {
    let policy = object.entry("policy").or_insert_with(|| json!({}));
    if !policy.is_object() {
        *policy = json!({});
    }
    let policy = policy
        .as_object_mut()
        .expect("policy was just replaced with an object");
    let system = policy.entry("system").or_insert_with(|| json!({}));
    if !system.is_object() {
        *system = json!({});
    }
    let system = system
        .as_object_mut()
        .expect("system was just replaced with an object");
    if let Some(flags) = system_stats().as_object() {
        for (key, value) in flags {
            system.insert(key.clone(), value.clone());
        }
    }
}

fn rewrite_listener(
    inbound: &mut Value,
    address: std::net::SocketAddr,
    udp: bool,
) -> Result<(), String> {
    let object = inbound
        .as_object_mut()
        .ok_or("every native inbound must be a JSON object")?;
    object.insert("listen".into(), json!(address.ip().to_string()));
    object.insert("port".into(), json!(address.port()));
    if udp {
        if let Some(settings) = object.get_mut("settings").and_then(Value::as_object_mut) {
            settings.insert("udp".into(), json!(true));
        } else {
            object.insert("settings".into(), json!({"udp": true}));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcae_runtime::sing_xray::CoreProfile as Profile;
    use fcae_runtime::config::RoutingConfig;
    use std::net::{Ipv4Addr, SocketAddr};

    fn vless() -> Profile {
        Profile::parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443\
             ?type=ws&path=%2Fray&host=cdn.example.com&security=tls&sni=www.example.com#node",
        )
        .expect("profile parses")
    }

    fn routing() -> RoutingConfig {
        RoutingConfig::default()
    }

    fn plan<'a>(
        profile: &'a Profile,
        routing: &'a RoutingConfig,
        upstream: Option<&'a UpstreamProxy>,
    ) -> Plan<'a> {
        Plan {
            profile,
            socks: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 1080))),
            http: None,
            level: Level::Warn,
            upstream,
            routing,
            dial: None,
        }
    }

    fn build(plan: &Plan<'_>) -> Value {
        generate(plan).expect("config builds")
    }

    #[test]
    fn socks_inbound_and_ws_tls_outbound() {
        let profile = vless();
        let routing = routing();
        let config = build(&plan(&profile, &routing, None));
        let inbound = &config["inbounds"][0];
        assert_eq!(inbound["protocol"], "socks");
        assert_eq!(inbound["port"], 1080);
        assert_eq!(inbound["settings"]["udp"], true);
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["protocol"], "vless");
        assert_eq!(outbound["streamSettings"]["network"], "ws");
        assert_eq!(outbound["streamSettings"]["wsSettings"]["path"], "/ray");
        assert_eq!(
            outbound["streamSettings"]["wsSettings"]["headers"]["Host"],
            "cdn.example.com"
        );
        assert_eq!(
            outbound["streamSettings"]["tlsSettings"]["serverName"],
            "www.example.com"
        );
        assert_eq!(config["outbounds"][1]["tag"], DIRECT_TAG);
        assert_eq!(config["outbounds"][2]["tag"], BLOCK_TAG);
        assert_eq!(config["log"]["loglevel"], "warning");
        assert!(config["stats"].is_object());
        assert_eq!(config["policy"]["system"]["statsInboundUplink"], true);
        assert_eq!(config["policy"]["system"]["statsOutboundDownlink"], true);
    }

    #[test]
    fn native_policies_keep_their_own_settings_and_gain_the_counter_flags() {
        let profile = Profile::parse(
            r#"{
                "inbounds": [{"tag": "in", "protocol": "socks", "port": 1080}],
                "outbounds": [{"protocol": "freedom"}],
                "policy": {"system": {"connIdle": 300}, "levels": {"0": {"handshake": 4}}}
            }"#,
        )
        .expect("profile parses");
        let routing = routing();
        let config = build(&plan(&profile, &routing, None));
        assert!(config["stats"].is_object());
        assert_eq!(config["policy"]["system"]["connIdle"], 300);
        assert_eq!(config["policy"]["system"]["statsInboundDownlink"], true);
        assert_eq!(config["policy"]["levels"]["0"]["handshake"], 4);
    }

    #[test]
    fn vless_encryption_reaches_the_user_object() {
        let key32 = "A".repeat(43);
        let encryption = format!("mlkem768x25519plus.native.0rtt.{key32}");
        let profile = Profile::parse(&format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls\
             &encryption={encryption}"
        ))
        .expect("profile parses");
        let routing = routing();
        let config = build(&plan(&profile, &routing, None));
        let user = &config["outbounds"][0]["settings"]["vnext"][0]["users"][0];
        // Verbatim: the core splits the dot config into keys and padding itself.
        assert_eq!(user["encryption"], encryption);
        // A plain link still names `none`, which is what the core expects there.
        let plain = build(&plan(&vless(), &routing, None));
        assert_eq!(
            plain["outbounds"][0]["settings"]["vnext"][0]["users"][0]["encryption"],
            "none"
        );
    }

    #[test]
    fn reality_and_vision_flow_reach_the_wire() {
        let profile = Profile::parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443\
             ?security=reality&sni=www.example.com&pbk=PUBKEY&sid=ab&fp=chrome\
             &flow=xtls-rprx-vision",
        )
        .expect("profile parses");
        let routing = routing();
        let config = build(&plan(&profile, &routing, None));
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["streamSettings"]["security"], "reality");
        assert_eq!(
            outbound["streamSettings"]["realitySettings"]["publicKey"],
            "PUBKEY"
        );
        assert_eq!(outbound["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision");
    }

    #[test]
    fn chained_sessions_detour_through_the_upstream_proxy() {
        let profile = vless();
        let routing = routing();
        let upstream: UpstreamProxy = "socks5://127.0.0.1:9050".parse().expect("upstream parses");
        let config = build(&plan(&profile, &routing, Some(&upstream)));
        assert_eq!(
            config["outbounds"][0]["streamSettings"]["dialerProxy"],
            UPSTREAM_TAG
        );
        assert_eq!(config["outbounds"][1]["tag"], UPSTREAM_TAG);
        assert_eq!(config["outbounds"][1]["protocol"], "socks");
        assert_eq!(
            config["outbounds"][1]["settings"]["servers"][0]["address"],
            "127.0.0.1"
        );
    }

    #[test]
    fn inline_routing_rules_become_xray_rules() {
        let profile = vless();
        let routing = RoutingConfig {
            rules_file: None,
            direct: vec!["10.0.0.0/8".into(), "intranet.example".into()],
            block: vec!["ads.example".into()],
        };
        let config = build(&plan(&profile, &routing, None));
        let rules = config["routing"]["rules"].as_array().expect("rules");
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0]["outbound"], BLOCK_TAG);
        assert_eq!(rules[0]["domain"][0], "domain:ads.example");
        assert_eq!(rules[1]["ip"][0], "10.0.0.0/8");
        assert_eq!(rules[1]["outbound"], DIRECT_TAG);
        assert_eq!(rules[2]["domain"][0], "domain:intranet.example");
    }

    #[test]
    fn native_configs_get_listener_ports_rewritten() {
        let profile = Profile::parse(
            r#"{
                "log": {"loglevel": "info"},
                "inbounds": [
                    {"tag": "socks-in", "protocol": "socks", "listen": "0.0.0.0", "port": 10808},
                    {"tag": "http-in", "protocol": "http", "listen": "0.0.0.0", "port": 10809}
                ],
                "outbounds": [{"protocol": "freedom"}]
            }"#,
        )
        .expect("profile parses");
        let routing = routing();
        let http = SocketAddr::from((Ipv4Addr::LOCALHOST, 1081));
        let mut plan = plan(&profile, &routing, None);
        plan.http = Some(http);
        let config = build(&plan);
        assert_eq!(config["inbounds"][0]["port"], 1080);
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["settings"]["udp"], true);
        assert_eq!(config["inbounds"][1]["port"], 1081);
        assert_eq!(config["log"]["loglevel"], "warning");
        assert_eq!(config["outbounds"][0]["protocol"], "freedom");
    }

    #[test]
    fn native_http_inbound_is_dropped_without_a_listener() {
        let profile = Profile::parse(
            r#"{"inbounds": [
                    {"protocol": "socks", "port": 1},
                    {"protocol": "http", "port": 2}
                ]}"#,
        )
        .expect("profile parses");
        let routing = routing();
        let config = build(&plan(&profile, &routing, None));
        assert_eq!(config["inbounds"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn a_native_tun_inbound_becomes_the_session_listener() {
        let profile = Profile::parse(
            r#"{
                "inbounds": [
                    {"tag": "tun-in", "protocol": "tun", "settings": {"name": "xray0", "mtu": 1500}}
                ],
                "outbounds": [{"protocol": "freedom"}]
            }"#,
        )
        .expect("profile parses");
        let config = build(&plan(&profile, &routing(), None));
        let inbounds = config["inbounds"].as_array().expect("inbounds");
        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0]["protocol"], "socks");
        assert_eq!(inbounds[0]["tag"], "tun-in");
        assert_eq!(inbounds[0]["listen"], "127.0.0.1");
        assert_eq!(inbounds[0]["port"], 1080);
        assert_eq!(inbounds[0]["settings"]["udp"], true);
    }

    #[test]
    fn early_data_reaches_the_path_and_the_tls_pins_reach_the_tls_block() {
        let profile = Profile::parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=ws\
             &path=%2Fray&ed=2048&security=tls&sni=www.example.com&pcs=AB12\
             &vcn=www.example.com&ech=ECHLIST",
        )
        .expect("profile parses");
        let routing = routing();
        let config = build(&plan(&profile, &routing, None));
        let stream = &config["outbounds"][0]["streamSettings"];
        // Xray reads the count out of the path and strips it before sending.
        assert_eq!(stream["wsSettings"]["path"], "/ray?ed=2048");
        assert_eq!(stream["tlsSettings"]["pinnedPeerCertSha256"], "AB12");
        assert_eq!(stream["tlsSettings"]["verifyPeerCertByName"], "www.example.com");
        assert_eq!(stream["tlsSettings"]["echConfigList"], "ECHLIST");
    }

    #[test]
    fn mkcp_xhttp_and_finalmask_reach_the_stream_settings() {
        let routing = routing();
        let kcp = build(&plan(
            &Profile::parse(
                "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=kcp\
                 &mtu=1350&tti=20&uplinkCapacity=5&congestion=false",
            )
            .expect("profile parses"),
            &routing,
            None,
        ));
        let stream = &kcp["outbounds"][0]["streamSettings"];
        assert_eq!(stream["network"], "kcp");
        assert_eq!(stream["kcpSettings"]["mtu"], 1350);
        assert_eq!(stream["kcpSettings"]["tti"], 20);
        assert_eq!(stream["kcpSettings"]["uplinkCapacity"], 5);
        assert_eq!(stream["kcpSettings"]["congestion"], false);

        let xhttp = build(&plan(
            &Profile::parse(
                "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=xhttp\
                 &path=%2Fecho&host=cdn.example.com&mode=auto\
                 &extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D&security=tls\
                 &fm=%7B%22tcp%22%3A%5B%5D%7D",
            )
            .expect("profile parses"),
            &routing,
            None,
        ));
        let stream = &xhttp["outbounds"][0]["streamSettings"];
        assert_eq!(stream["network"], "xhttp");
        assert_eq!(stream["xhttpSettings"]["path"], "/echo");
        assert_eq!(stream["xhttpSettings"]["host"], "cdn.example.com");
        assert_eq!(stream["xhttpSettings"]["mode"], "auto");
        // The link's own settings object, verbatim.
        assert_eq!(stream["xhttpSettings"]["extra"]["xPaddingBytes"], "100-1000");
        assert!(stream["finalmask"]["tcp"].is_array());
    }

    #[test]
    fn settings_xray_removed_are_refused_with_the_core_that_carries_them() {
        let routing = routing();
        for (link, expected) in [
            (
                "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=h2&security=tls",
                "sing-box",
            ),
            (
                "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&allowInsecure=1",
                "sing-box",
            ),
            (
                "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388?plugin=obfs-local%3Bobfs%3Dhttp",
                "sing-box",
            ),
            // A method Xray dropped in favour of the AEAD set.
            ("ss://YWVzLTI1Ni1jZmI6c2VjcmV0@example.com:8388", "sing-box"),
        ] {
            let profile = Profile::parse(link).expect("profile parses");
            let error = generate(&plan(&profile, &routing, None)).expect_err("xray cannot carry it");
            assert!(error.contains(expected), "{link}: {error}");
        }
    }

    #[test]
    fn sing_box_only_links_are_refused_with_the_reason() {
        for text in [
            "hysteria2://secret@example.com:443",
            "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pass@example.com:443",
            "anytls://secret@example.com:443",
        ] {
            let profile = Profile::parse(text).expect("profile parses");
            let routing = routing();
            let error =
                generate(&plan(&profile, &routing, None)).expect_err("xray cannot carry it");
            assert!(error.contains("sing-box"), "{text}: {error}");
        }
    }

    #[test]
    fn native_config_without_socks_inbound_is_refused() {
        let profile =
            Profile::parse(r#"{"inbounds": [{"protocol": "http", "port": 2}]}"#).expect("profile");
        let routing = routing();
        let error = generate(&plan(&profile, &routing, None)).expect_err("must fail");
        assert!(error.contains("socks inbound"), "{error}");
    }

    #[test]
    fn native_config_refuses_chaining_and_reports_a_rule_file() {
        let profile = Profile::parse(r#"{"inbounds": [{"protocol": "socks", "port": 1}]}"#)
            .expect("profile parses");
        let routing = routing();
        let upstream: UpstreamProxy = "socks5://127.0.0.1:9050".parse().expect("upstream");
        let error = generate(&plan(&profile, &routing, Some(&upstream))).expect_err("must fail");
        assert!(error.contains("chaining"), "{error}");

        let with_file = RoutingConfig {
            rules_file: Some("/tmp/rules.json".into()),
            direct: Vec::new(),
            block: Vec::new(),
        };
        let error = generate(&plan(&profile, &with_file, None)).expect_err("must fail");
        assert!(error.contains("rule file"), "{error}");
    }
}
