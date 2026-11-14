//! Xray-core config generation.
//!
//! The bridge owns the generated config completely: listeners, outbound,
//! optional upstream `dialerProxy`, and the app's split-routing rules. Nothing
//! is left to Xray's own defaults, so the same session profile behaves the same
//! way on every release.

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
            if plan.socks.is_none() && plan.http.is_none() {
                return Err("the session has no listener for the core to serve".into());
            }
            Ok(config(plan, outbound, &Rules::build(plan.routing)?))
        }
    }
}

fn config(plan: &Plan<'_>, outbound: &Outbound, rules: &Rules) -> Value {
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
    outbounds.push(outbound_config(outbound, plan.upstream.is_some()));
    if let Some(upstream) = plan.upstream {
        outbounds.push(upstream_config(upstream));
    }
    // `direct` and `block` always exist: the routing rules name their tags.
    outbounds.push(json!({"tag": DIRECT_TAG, "protocol": "freedom"}));
    outbounds.push(json!({"tag": BLOCK_TAG, "protocol": "blackhole"}));

    json!({
        // `access: none` matters: Xray defaults the access log to the console
        // and would otherwise print a line per connection from a GUI process.
        "log": {"loglevel": level(plan.level), "access": "none"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": routing_rules(rules)},
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

fn outbound_config(outbound: &Outbound, chained: bool) -> Value {
    let (protocol, settings) = match &outbound.protocol {
        Protocol::Vless { uuid, flow } => {
            let mut user = json!({"id": uuid, "encryption": "none"});
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
        Protocol::Shadowsocks { method, password } => (
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
    };

    let mut value = json!({"tag": PROXY_TAG, "protocol": protocol, "settings": settings});
    let stream = stream_settings(outbound, chained);
    if !stream.is_empty() {
        value["streamSettings"] = Value::Object(stream);
    }
    value
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

fn stream_settings(outbound: &Outbound, chained: bool) -> Map<String, Value> {
    let mut stream = Map::new();
    let network = match &outbound.transport {
        Transport::Tcp => "tcp",
        Transport::Ws { .. } => "ws",
        Transport::Grpc { .. } => "grpc",
        Transport::H2 { .. } => "h2",
        Transport::HttpUpgrade { .. } => "httpupgrade",
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
            allow_insecure,
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
            if *allow_insecure {
                tls.insert("allowInsecure".into(), json!(true));
            }
            stream.insert("tlsSettings".into(), Value::Object(tls));
        }
        Security::Reality {
            sni,
            fingerprint,
            public_key,
            short_id,
            spider_x,
        } => {
            stream.insert("security".into(), json!("reality"));
            stream.insert(
                "realitySettings".into(),
                json!({
                    "serverName": sni,
                    "fingerprint": fingerprint,
                    "publicKey": public_key,
                    "shortId": short_id,
                    "spiderX": spider_x,
                }),
            );
        }
    }
    match &outbound.transport {
        Transport::Tcp => {}
        Transport::Ws { path, host } => {
            let mut ws = Map::new();
            ws.insert("path".into(), json!(path));
            if let Some(host) = host {
                ws.insert("headers".into(), json!({"Host": host}));
            }
            stream.insert("wsSettings".into(), Value::Object(ws));
        }
        Transport::Grpc { service } => {
            stream.insert("grpcSettings".into(), json!({"serviceName": service}));
        }
        Transport::H2 { path, host } => {
            let mut h2 = Map::new();
            h2.insert("path".into(), json!(path));
            if let Some(host) = host {
                h2.insert("host".into(), json!([host]));
            }
            stream.insert("httpSettings".into(), Value::Object(h2));
        }
        Transport::HttpUpgrade { path, host } => {
            let mut upgrade = Map::new();
            upgrade.insert("path".into(), json!(path));
            if let Some(host) = host {
                upgrade.insert("host".into(), json!(host));
            }
            stream.insert("httpupgradeSettings".into(), Value::Object(upgrade));
        }
    }
    if chained {
        stream.insert("dialerProxy".into(), json!(UPSTREAM_TAG));
    }
    stream
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
        assert_eq!(rules[2]["ip"][0], "10.0.0.0/8");
        assert_eq!(rules[2]["outbound"], DIRECT_TAG);
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
