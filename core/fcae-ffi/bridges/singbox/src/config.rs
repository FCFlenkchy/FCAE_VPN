//! sing-box config generation.
//!
//! sing-box's grammar differs from Xray's in every nesting level — `type`
//! instead of `protocol`, `tls`/`transport` objects instead of `streamSettings`,
//! `route` instead of `routing` — so it gets its own generator rather than a
//! parameterised one. What both must agree on is the *behaviour*: the session's
//! listeners, its upstream detour and its split-routing rules.

use fcae_runtime::upstream::{ProxyKind, UpstreamProxy};
use fcae_runtime::sing_xray::Plan;
use fcae_runtime::sing_xray::Rules;
use fcae_runtime::sing_xray::Level;
use fcae_runtime::sing_xray::{CoreProfile, Outbound, Protocol, Security, Transport};
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
            "type": "socks",
            "tag": "socks-in",
            "listen": socks.ip().to_string(),
            "listen_port": socks.port(),
        }));
    }
    if let Some(http) = plan.http {
        inbounds.push(json!({
            "type": "http",
            "tag": "http-in",
            "listen": http.ip().to_string(),
            "listen_port": http.port(),
        }));
    }

    let mut outbounds = Vec::with_capacity(4);
    outbounds.push(outbound_config(outbound, plan.upstream.is_some()));
    if let Some(upstream) = plan.upstream {
        outbounds.push(upstream_config(upstream));
    }
    // `direct` and `block` always exist: the routing rules name their tags.
    outbounds.push(json!({"type": "direct", "tag": DIRECT_TAG}));
    outbounds.push(json!({"type": "block", "tag": BLOCK_TAG}));

    json!({
        "log": log(plan.level),
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": routing_rules(rules), "final": PROXY_TAG},
    })
}

/// sing-box's log block. `disabled` is the only way to switch its logger off;
/// `error` is merely its quietest level.
fn log(level: Level) -> Value {
    if level == Level::Off {
        return json!({"disabled": true});
    }
    json!({"level": level_name(level), "timestamp": true})
}

fn level_name(level: Level) -> &'static str {
    match level {
        Level::Off | Level::Error => "error",
        Level::Warn => "warn",
        Level::Info => "info",
        Level::Debug => "debug",
        Level::Trace => "trace",
    }
}

fn outbound_config(outbound: &Outbound, chained: bool) -> Value {
    let mut value = match &outbound.protocol {
        Protocol::Vless { uuid, flow } => {
            let mut value = json!({
                "type": "vless",
                "tag": PROXY_TAG,
                "server": outbound.server,
                "server_port": outbound.port,
                "uuid": uuid,
                "packet_encoding": "xudp",
            });
            if let Some(flow) = flow {
                value["flow"] = json!(flow);
            }
            value
        }
        Protocol::Vmess {
            uuid,
            alter_id,
            security,
        } => json!({
            "type": "vmess",
            "tag": PROXY_TAG,
            "server": outbound.server,
            "server_port": outbound.port,
            "uuid": uuid,
            "security": security,
            "alter_id": alter_id,
            "packet_encoding": "xudp",
        }),
        Protocol::Trojan { password } => json!({
            "type": "trojan",
            "tag": PROXY_TAG,
            "server": outbound.server,
            "server_port": outbound.port,
            "password": password,
        }),
        Protocol::Shadowsocks { method, password } => json!({
            "type": "shadowsocks",
            "tag": PROXY_TAG,
            "server": outbound.server,
            "server_port": outbound.port,
            "method": method,
            "password": password,
        }),
        Protocol::Socks { user, password } => {
            let mut value = json!({
                "type": "socks",
                "tag": PROXY_TAG,
                "server": outbound.server,
                "server_port": outbound.port,
                "version": "5",
            });
            with_credentials(&mut value, user.as_deref(), password.as_deref());
            value
        }
        Protocol::Http { user, password } => {
            let mut value = json!({
                "type": "http",
                "tag": PROXY_TAG,
                "server": outbound.server,
                "server_port": outbound.port,
            });
            with_credentials(&mut value, user.as_deref(), password.as_deref());
            value
        }
    };

    match tls_config(&outbound.security, &outbound.server) {
        Some(tls) => value["tls"] = tls,
        None => {
            // Trojan is TLS by contract and sing-box refuses the config
            // outright without it, so a link that said `security=none` still
            // gets TLS rather than a core that exits at startup.
            if matches!(outbound.protocol, Protocol::Trojan { .. }) {
                value["tls"] = json!({"enabled": true});
            }
        }
    }

    if let Some(transport) = transport_config(&outbound.transport) {
        value["transport"] = transport;
    }
    if chained {
        value["detour"] = json!(UPSTREAM_TAG);
    }
    value
}

fn with_credentials(value: &mut Value, user: Option<&str>, password: Option<&str>) {
    if let Some(user) = user {
        value["username"] = json!(user);
        if let Some(password) = password {
            value["password"] = json!(password);
        }
    }
}

fn tls_config(security: &Security, server: &str) -> Option<Value> {
    match security {
        Security::None => None,
        Security::Tls {
            sni,
            alpn,
            fingerprint,
            allow_insecure,
        } => {
            let mut tls = Map::new();
            tls.insert("enabled".into(), json!(true));
            if let Some(sni) = sni.clone().or_else(|| host_of(server)) {
                tls.insert("server_name".into(), json!(sni));
            }
            if !alpn.is_empty() {
                tls.insert("alpn".into(), json!(alpn));
            }
            if *allow_insecure {
                tls.insert("insecure".into(), json!(true));
            }
            if let Some(fingerprint) = fingerprint {
                tls.insert("utls".into(), json!({"enabled": true, "fingerprint": fingerprint}));
            }
            Some(Value::Object(tls))
        }
        Security::Reality {
            sni,
            fingerprint,
            public_key,
            short_id,
            ..
        } => Some(json!({
            "enabled": true,
            "server_name": sni,
            "utls": {"enabled": true, "fingerprint": fingerprint},
            "reality": {"enabled": true, "public_key": public_key, "short_id": short_id},
        })),
    }
}

fn transport_config(transport: &Transport) -> Option<Value> {
    match transport {
        Transport::Tcp => None,
        Transport::Ws { path, host } => {
            let mut headers = Map::new();
            if let Some(host) = host {
                headers.insert("Host".into(), json!(host));
            }
            Some(json!({"type": "ws", "path": path, "headers": headers}))
        }
        Transport::Grpc { service } => Some(json!({"type": "grpc", "service_name": service})),
        Transport::H2 { path, host } => match host {
            Some(host) => Some(json!({"type": "http", "path": path, "host": [host]})),
            None => Some(json!({"type": "http", "path": path})),
        },
        Transport::HttpUpgrade { path, host } => match host {
            Some(host) => Some(json!({"type": "httpupgrade", "path": path, "host": host})),
            None => Some(json!({"type": "httpupgrade", "path": path})),
        },
    }
}

fn upstream_config(upstream: &UpstreamProxy) -> Value {
    let mut value = match upstream.kind {
        ProxyKind::Socks5 => json!({
            "type": "socks",
            "tag": UPSTREAM_TAG,
            "server": upstream.host,
            "server_port": upstream.port,
            "version": "5",
        }),
        ProxyKind::Http => json!({
            "type": "http",
            "tag": UPSTREAM_TAG,
            "server": upstream.host,
            "server_port": upstream.port,
        }),
    };
    with_credentials(
        &mut value,
        upstream.user.as_deref(),
        upstream.password.as_deref(),
    );
    value
}

fn routing_rules(rules: &Rules) -> Vec<Value> {
    let mut out = Vec::with_capacity(4);
    if !rules.block_ips.is_empty() {
        out.push(json!({"ip_cidr": rules.block_ips, "outbound": BLOCK_TAG}));
    }
    if !rules.block_domains.is_empty() {
        out.push(domain_rule(&rules.block_domains, BLOCK_TAG));
    }
    if !rules.direct_ips.is_empty() {
        out.push(json!({"ip_cidr": rules.direct_ips, "outbound": DIRECT_TAG}));
    }
    if !rules.direct_domains.is_empty() {
        out.push(domain_rule(&rules.direct_domains, DIRECT_TAG));
    }
    out
}

/// `domain` pins the exact host, `domain_suffix` covers subdomains; a rule for
/// `example.com` has to match the name itself as well.
fn domain_rule(domains: &[String], outbound: &str) -> Value {
    json!({
        "domain": domains,
        "domain_suffix": domains,
        "outbound": outbound,
    })
}

fn native(config: &Value, plan: &Plan<'_>) -> Result<Value, String> {
    if plan.socks.is_none() {
        return Err("the session has no SOCKS listener for the native config to serve".into());
    }
    if plan.upstream.is_some() {
        return Err(
            "chaining a native sing-box config behind an upstream proxy is not supported; use a share link"
                .into(),
        );
    }
    if !Rules::build(plan.routing)?.is_empty() {
        log::warn!(
            "[sing-box] inline routing rules are ignored for a native config; its own route section wins"
        );
    }

    let mut config = config.clone();
    let object = config
        .as_object_mut()
        .ok_or("native config must be a JSON object")?;

    // The session owns the log block: verbosity comes from the app, not from
    // whatever the pasted config was copied with.
    object.insert("log".into(), log(plan.level));

    let inbounds = match object.remove("inbounds") {
        Some(Value::Array(inbounds)) => inbounds,
        Some(_) => return Err("native config \"inbounds\" must be an array".into()),
        None => return Err("native config needs an \"inbounds\" array".into()),
    };

    let mut rewritten = Vec::with_capacity(inbounds.len());
    let mut socks_seen = false;
    let mut tun_tag: Option<String> = None;
    for mut inbound in inbounds {
        let kind = inbound
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        match kind.as_str() {
            "socks" | "mixed" => {
                socks_seen = true;
                if let Some(socks) = plan.socks {
                    rewrite_listener(&mut inbound, socks)?;
                }
            }
            "http" => match plan.http {
                Some(http) => rewrite_listener(&mut inbound, http)?,
                None => {
                    log::info!(
                        "[sing-box] dropping the native http inbound: the session has no HTTP listener"
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
                log::info!(
                    "[sing-box] dropping the native tun inbound: this app owns the TUN device"
                );
                continue;
            }
            _ => {}
        }
        rewritten.push(inbound);
    }
    if !socks_seen {
        // A config written for the `sing-box` CLI leads with its own TUN. That
        // inbound's traffic now arrives over the session's SOCKS listener, so
        // the listener takes its place — and its tag, which is what the
        // config's own route rules name.
        let Some(tag) = tun_tag else {
            return Err(
                "native config needs a socks inbound: TUN mode and chained hops dial the core through it"
                    .into(),
            );
        };
        if let Some(socks) = plan.socks {
            log::info!(
                "[sing-box] native config has no socks inbound; serving the app's SOCKS listener as `{tag}`"
            );
            rewritten.push(json!({
                "type": "socks",
                "tag": tag,
                "listen": socks.ip().to_string(),
                "listen_port": socks.port(),
            }));
        }
    }
    object.insert("inbounds".into(), Value::Array(rewritten));
    Ok(config)
}

fn rewrite_listener(inbound: &mut Value, address: std::net::SocketAddr) -> Result<(), String> {
    let object = inbound
        .as_object_mut()
        .ok_or("every native inbound must be a JSON object")?;
    object.insert("listen".into(), json!(address.ip().to_string()));
    object.insert("listen_port".into(), json!(address.port()));
    Ok(())
}

fn host_of(server: &str) -> Option<String> {
    server
        .parse::<std::net::IpAddr>()
        .is_err()
        .then(|| server.to_string())
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
        assert_eq!(inbound["type"], "socks");
        assert_eq!(inbound["listen_port"], 1080);
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["type"], "vless");
        assert_eq!(outbound["transport"]["type"], "ws");
        assert_eq!(outbound["transport"]["headers"]["Host"], "cdn.example.com");
        assert_eq!(outbound["tls"]["server_name"], "www.example.com");
        assert_eq!(config["route"]["final"], PROXY_TAG);
        assert_eq!(config["log"]["level"], "warn");
        assert_eq!(config["outbounds"][1]["tag"], DIRECT_TAG);
        assert_eq!(config["outbounds"][2]["tag"], BLOCK_TAG);
    }

    #[test]
    fn a_trojan_link_without_tls_still_gets_tls() {
        let profile = Profile::parse("trojan://secret@example.com:443?security=none")
            .expect("profile parses");
        let routing = routing();
        let config = build(&plan(&profile, &routing, None));
        assert_eq!(config["outbounds"][0]["tls"]["enabled"], true);
    }

    #[test]
    fn chained_sessions_detour_through_the_upstream_proxy() {
        let profile = vless();
        let routing = routing();
        let upstream: UpstreamProxy = "http://user:pass@127.0.0.1:8080".parse().expect("upstream");
        let config = build(&plan(&profile, &routing, Some(&upstream)));
        assert_eq!(config["outbounds"][0]["detour"], UPSTREAM_TAG);
        assert_eq!(config["outbounds"][1]["type"], "http");
        assert_eq!(config["outbounds"][1]["username"], "user");
        assert_eq!(config["outbounds"][1]["password"], "pass");
    }

    #[test]
    fn inline_routing_rules_become_route_rules() {
        let profile = vless();
        let routing = RoutingConfig {
            rules_file: None,
            direct: vec!["10.0.0.0/8".into(), "intranet.example".into()],
            block: vec!["ads.example".into()],
        };
        let config = build(&plan(&profile, &routing, None));
        let rules = config["route"]["rules"].as_array().expect("rules");
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0]["domain"][0], "ads.example");
        assert_eq!(rules[0]["outbound"], BLOCK_TAG);
        assert_eq!(rules[1]["ip_cidr"][0], "10.0.0.0/8");
        assert_eq!(rules[2]["domain_suffix"][0], "intranet.example");
    }

    #[test]
    fn native_configs_are_rewritten_for_the_session() {
        let profile = Profile::parse(
            r#"{
                "log": {"level": "info"},
                "inbounds": [
                    {"type": "socks", "tag": "in", "listen": "0.0.0.0", "listen_port": 2080},
                    {"type": "http", "tag": "web", "listen": "0.0.0.0", "listen_port": 2081}
                ],
                "outbounds": [{"type": "direct", "tag": "direct"}]
            }"#,
        )
        .expect("profile parses");
        let routing = routing();
        let http = SocketAddr::from((Ipv4Addr::LOCALHOST, 1081));
        let mut plan = plan(&profile, &routing, None);
        plan.http = Some(http);
        let config = build(&plan);
        assert_eq!(config["inbounds"][0]["listen_port"], 1080);
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][1]["listen_port"], 1081);
        assert_eq!(config["log"]["level"], "warn");
        assert_eq!(config["outbounds"][0]["tag"], "direct");
    }

    #[test]
    fn a_native_tun_inbound_becomes_the_session_listener() {
        let profile = Profile::parse(
            r#"{
                "inbounds": [
                    {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": true}
                ],
                "outbounds": [{"type": "direct", "tag": "direct"}]
            }"#,
        )
        .expect("profile parses");
        let config = build(&plan(&profile, &routing(), None));
        let inbounds = config["inbounds"].as_array().expect("inbounds");
        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0]["type"], "socks");
        assert_eq!(inbounds[0]["tag"], "tun-in");
        assert_eq!(inbounds[0]["listen"], "127.0.0.1");
        assert_eq!(inbounds[0]["listen_port"], 1080);
    }

    #[test]
    fn native_config_without_socks_inbound_is_refused() {
        let profile =
            Profile::parse(r#"{"inbounds": [{"type": "http", "listen_port": 2}]}"#).expect("profile");
        let routing = routing();
        let error = generate(&plan(&profile, &routing, None)).expect_err("must fail");
        assert!(error.contains("socks inbound"), "{error}");
    }
}
