//! sing-box config generation.
//!
//! sing-box's grammar differs from Xray's in every nesting level — `type`
//! instead of `protocol`, `tls`/`transport` objects instead of `streamSettings`,
//! `route` instead of `routing` — so it gets its own generator rather than a
//! parameterised one. What both must agree on is the *behaviour*: the session's
//! listeners, its upstream detour and its split-routing rules.

use crate::proxy_cores::Level;
use crate::proxy_cores::Plan;
use crate::proxy_cores::Rules;
use crate::proxy_cores::{CoreProfile, Outbound, Protocol, Security, Transport};
use crate::upstream::{ProxyKind, UpstreamProxy};
use fcae_abi::FcaeBackend;
use serde_json::{json, Map, Value};
use std::net::IpAddr;

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
            // sing-box speaks plain VLESS; Xray's VLESS encryption has no field
            // in its grammar. The editor refuses such a link already, but a
            // caller that ships a profile without a library comes through here.
            if !outbound.carried_by(FcaeBackend::SingBox) {
                return Err(outbound.refusal(FcaeBackend::SingBox));
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
    // WireGuard is an endpoint in sing-box 1.11+, and its outbound form was
    // removed in 1.13. An endpoint's tag is a route target like any other, so
    // `final` below names it either way.
    let mut endpoints = Vec::new();
    match wireguard_endpoint(outbound, plan.upstream.is_some(), plan.dial) {
        Some(endpoint) => endpoints.push(endpoint),
        None => outbounds.push(outbound_config(
            outbound,
            plan.upstream.is_some(),
            plan.dial,
        )?),
    }
    if let Some(upstream) = plan.upstream {
        outbounds.push(upstream_config(upstream));
    }
    // `direct` and `block` always exist: the routing rules name their tags.
    outbounds.push(json!({"type": "direct", "tag": DIRECT_TAG}));
    outbounds.push(json!({"type": "block", "tag": BLOCK_TAG}));

    let mut config = Map::new();
    config.insert("log".into(), log(plan.level));
    config.insert("inbounds".into(), Value::Array(inbounds));
    if !endpoints.is_empty() {
        config.insert("endpoints".into(), Value::Array(endpoints));
    }
    config.insert("outbounds".into(), Value::Array(outbounds));
    config.insert(
        "route".into(),
        json!({"rules": routing_rules(rules), "final": PROXY_TAG}),
    );
    Ok(Value::Object(config))
}

/// WireGuard as sing-box wants it: an `endpoint`, whose tag the route names in
/// place of an outbound. `None` for every other protocol.
fn wireguard_endpoint(outbound: &Outbound, chained: bool, dial: Option<IpAddr>) -> Option<Value> {
    let Protocol::WireGuard {
        secret_key,
        address,
        peer,
        mtu,
        reserved,
    } = &outbound.protocol
    else {
        return None;
    };
    // A peer's networks are required here, and an absent one means what the
    // cores default the field to.
    let allowed_ips = if peer.allowed_ips.is_empty() {
        vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
    } else {
        peer.allowed_ips.clone()
    };
    let mut endpoint = json!({
        "type": "wireguard",
        "tag": PROXY_TAG,
        "address": address,
        "private_key": secret_key,
        "peers": [{
            "address": dial_address(outbound, dial),
            "port": outbound.port,
            "public_key": peer.public_key,
            "allowed_ips": allowed_ips,
        }],
    });
    if let Some(key) = &peer.preshared_key {
        endpoint["peers"][0]["pre_shared_key"] = json!(key);
    }
    if let Some(seconds) = peer.keepalive {
        endpoint["peers"][0]["persistent_keepalive_interval"] = json!(seconds);
    }
    if let Some(mtu) = mtu {
        endpoint["mtu"] = json!(mtu);
    }
    // The field belongs to the peer here, and the core takes three bytes or
    // none.
    if !reserved.is_empty() {
        endpoint["peers"][0]["reserved"] = json!(reserved);
    }
    if chained {
        // An endpoint takes the dial fields, so the peer is reached through the
        // upstream proxy. It must not also name a listen port, which the core
        // rejects next to a detour.
        endpoint["detour"] = json!(UPSTREAM_TAG);
    }
    Some(endpoint)
}

/// The address the core dials: the one the platform resolved when it had to,
/// otherwise the profile's own server.
fn dial_address(outbound: &Outbound, dial: Option<IpAddr>) -> String {
    match dial {
        Some(address) => address.to_string(),
        None => outbound.server.clone(),
    }
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

/// One outbound. `dial` is the address the platform resolved for the profile's
/// server: the core is given that address to connect to, while every name the
/// hostname stood in for — SNI, Host header, gRPC authority — stays as the link
/// spelled it.
fn outbound_config(
    outbound: &Outbound,
    chained: bool,
    dial: Option<IpAddr>,
) -> Result<Value, String> {
    let server = dial_address(outbound, dial);
    let mut value = match &outbound.protocol {
        // `generate` refuses a link carrying Xray's VLESS encryption before this
        // point, and sing-box's grammar has no field to put it in.
        Protocol::Vless { uuid, flow, .. } => {
            let mut value = json!({
                "type": "vless",
                "tag": PROXY_TAG,
                "server": server,
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
            "server": server,
            "server_port": outbound.port,
            "uuid": uuid,
            "security": security,
            "alter_id": alter_id,
            "packet_encoding": "xudp",
        }),
        Protocol::Trojan { password } => json!({
            "type": "trojan",
            "tag": PROXY_TAG,
            "server": server,
            "server_port": outbound.port,
            "password": password,
        }),
        Protocol::Shadowsocks {
            method,
            password,
            plugin,
        } => {
            let mut value = json!({
                "type": "shadowsocks",
                "tag": PROXY_TAG,
                "server": server,
                "server_port": outbound.port,
                "method": method,
                "password": password,
            });
            if let Some(plugin) = plugin {
                value["plugin"] = json!(plugin.name);
                if let Some(options) = &plugin.options {
                    value["plugin_opts"] = json!(options);
                }
            }
            value
        }
        Protocol::Socks { user, password } => {
            let mut value = json!({
                "type": "socks",
                "tag": PROXY_TAG,
                "server": server,
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
                "server": server,
                "server_port": outbound.port,
            });
            with_credentials(&mut value, user.as_deref(), password.as_deref());
            value
        }
        Protocol::Hysteria2 {
            password,
            obfs,
            up_mbps,
            down_mbps,
            ports,
            hop_interval,
            ..
        } => {
            let mut value = json!({
                "type": "hysteria2",
                "tag": PROXY_TAG,
                "server": server,
                "server_port": outbound.port,
                "password": password,
            });
            if let Some(obfs) = obfs {
                let mut settings = Map::new();
                settings.insert("type".into(), json!(obfs.kind));
                settings.insert("password".into(), json!(obfs.password));
                // Gecko pads into a window the link may size itself.
                if let Some(size) = obfs.min_packet_size {
                    settings.insert("min_packet_size".into(), json!(size));
                }
                if let Some(size) = obfs.max_packet_size {
                    settings.insert("max_packet_size".into(), json!(size));
                }
                value["obfs"] = Value::Object(settings);
            }
            if let Some(up) = up_mbps {
                value["up_mbps"] = json!(up);
            }
            if let Some(down) = down_mbps {
                value["down_mbps"] = json!(down);
            }
            if !ports.is_empty() {
                value["server_ports"] = json!(ports);
            }
            if let Some(seconds) = hop_interval {
                value["hop_interval"] = json!(format!("{seconds}s"));
            }
            value
        }
        Protocol::Tuic {
            uuid,
            password,
            congestion_control,
            udp_relay_mode,
            zero_rtt,
            disable_sni: _,
        } => {
            let mut value = json!({
                "type": "tuic",
                "tag": PROXY_TAG,
                "server": server,
                "server_port": outbound.port,
                "uuid": uuid,
                "password": password,
            });
            if let Some(control) = congestion_control {
                value["congestion_control"] = json!(control);
            }
            if let Some(mode) = udp_relay_mode {
                value["udp_relay_mode"] = json!(mode);
            }
            if *zero_rtt {
                value["zero_rtt_handshake"] = json!(true);
            }
            value
        }
        Protocol::AnyTls { password } => json!({
            "type": "anytls",
            "tag": PROXY_TAG,
            "server": server,
            "server_port": outbound.port,
            "password": password,
        }),
        // WireGuard is generated as an endpoint; `config` never asks for an
        // outbound here.
        Protocol::WireGuard { .. } => {
            return Err("a wireguard profile is generated as an endpoint".into())
        }
        Protocol::Hysteria {
            auth,
            obfs,
            up_mbps,
            down_mbps,
            ports,
            hop_interval,
            ..
        } => {
            let mut value = json!({
                "type": "hysteria",
                "tag": PROXY_TAG,
                "server": server,
                "server_port": outbound.port,
                "up_mbps": up_mbps,
                "down_mbps": down_mbps,
            });
            if let Some(auth) = auth {
                value["auth_str"] = json!(auth);
            }
            // XPlus's password: the scheme itself is the only obfuscation this
            // outbound implements.
            if let Some(password) = obfs {
                value["obfs"] = json!(password);
            }
            if !ports.is_empty() {
                value["server_ports"] = json!(ports);
            }
            if let Some(seconds) = hop_interval {
                value["hop_interval"] = json!(format!("{seconds}s"));
            }
            value
        }
        Protocol::Naive {
            user,
            password,
            quic,
        } => {
            let mut value = json!({
                "type": "naive",
                "tag": PROXY_TAG,
                "server": server,
                "server_port": outbound.port,
            });
            with_credentials(&mut value, user.as_deref(), password.as_deref());
            if *quic {
                value["quic"] = json!(true);
            }
            value
        }
    };

    match tls_config(&outbound.security, &outbound.server) {
        Some(tls) => value["tls"] = tls,
        None => {
            // Trojan, Hysteria2, TUIC and AnyTLS are TLS by contract and
            // sing-box refuses the config outright without it, so a link that
            // said `security=none` still gets TLS rather than a core that exits
            // at startup.
            if is_tls_by_contract(&outbound.protocol) {
                // These protocols handshake in TLS whatever the link said, and
                // the certificate is the name's: with an address in place of the
                // hostname, the name has to be spelled out or the core would
                // present the address as the SNI.
                let mut tls = Map::new();
                tls.insert("enabled".into(), json!(true));
                if dial.is_some() {
                    if let Some(name) = host_of(&outbound.server) {
                        tls.insert("server_name".into(), json!(name));
                    }
                }
                value["tls"] = Value::Object(tls);
            }
        }
    }
    if let Protocol::Tuic {
        disable_sni: true, ..
    } = &outbound.protocol
    {
        value["tls"]["disable_sni"] = json!(true);
    }
    // Both QUIC v1 and v2 links may pin the server certificate; sing-box reads the
    // same field for either.
    if let Protocol::Hysteria2 { pin: Some(pin), .. } | Protocol::Hysteria { pin: Some(pin), .. } =
        &outbound.protocol
    {
        value["tls"]["certificate_sha256"] = json!([pin]);
    }
    // The two UDP framings a link can name, and the socket flag both cores set;
    // the parser keeps each on the protocol that has a field for it.
    if let Some(uot) = &outbound.dial.uot {
        value["udp_over_tcp"] = match uot.version {
            Some(version) => json!({"enabled": true, "version": version}),
            None => json!(true),
        };
    }
    if let Some(encoding) = outbound.dial.packet_encoding {
        value["packet_encoding"] = json!(encoding.name());
    }
    if outbound.dial.tfo {
        value["tcp_fast_open"] = json!(true);
    }

    if let Some(transport) = transport_config(outbound, dial.is_some())? {
        value["transport"] = transport;
    }
    if chained {
        value["detour"] = json!(UPSTREAM_TAG);
    }
    Ok(value)
}

/// Whether the protocol's own handshake is TLS, which sing-box requires even
/// when the link left `security` unset.
fn is_tls_by_contract(protocol: &Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Trojan { .. }
            | Protocol::Hysteria2 { .. }
            | Protocol::Hysteria { .. }
            | Protocol::Tuic { .. }
            | Protocol::AnyTls { .. }
            | Protocol::Naive { .. }
    )
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
            ech,
            pinned_cert_sha256,
            ..
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
                tls.insert(
                    "utls".into(),
                    json!({"enabled": true, "fingerprint": fingerprint}),
                );
            }
            if let Some(ech) = ech {
                tls.insert("ech".into(), json!({"enabled": true, "config": [ech]}));
            }
            if let Some(pins) = pinned_cert_sha256 {
                tls.insert("certificate_sha256".into(), json!(super::proxy_cores::profile::certificate_pins(pins).expect("pins validated before generation")));
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

/// The outbound's `transport` block, or `None` when it speaks over plain TCP.
fn transport_config(outbound: &Outbound, dialled: bool) -> Result<Option<Value>, String> {
    // With an address in place of the hostname, a Host header the link left out
    // has to name the host itself: the core would otherwise send the address.
    let name = dialled.then(|| host_of(&outbound.server)).flatten();
    let transport = match &outbound.transport {
        Transport::Tcp => return Ok(None),
        Transport::Quic => json!({"type":"quic"}),
        Transport::Ws {
            path,
            host,
            max_early_data,
            early_data_header,
        } => {
            // sing-box's WebSocket block has no `host` field: the Host header
            // is one of the headers it sends.
            let mut headers = Map::new();
            if let Some(host) = host.clone().or_else(|| name.clone()) {
                headers.insert("Host".into(), json!(host));
            }
            let mut ws = Map::new();
            ws.insert("type".into(), json!("ws"));
            ws.insert("path".into(), json!(path));
            if !headers.is_empty() {
                ws.insert("headers".into(), Value::Object(headers));
            }
            if let Some(count) = max_early_data {
                ws.insert("max_early_data".into(), json!(count));
            }
            if let Some(header) = early_data_header {
                ws.insert("early_data_header_name".into(), json!(header));
            }
            Value::Object(ws)
        }
        Transport::HttpUpgrade { path, host, .. } => {
            let mut upgrade = Map::new();
            upgrade.insert("type".into(), json!("httpupgrade"));
            // This block has no early-data field — the count is Xray's, carried
            // inside the path's query by that core alone — so the path goes out
            // as the link spelled it and nothing pretends to set one here.
            upgrade.insert("path".into(), json!(path));
            if let Some(host) = host.clone().or_else(|| name.clone()) {
                upgrade.insert("host".into(), json!(host));
            }
            Value::Object(upgrade)
        }
        Transport::H2 { path, host, method } => {
            let mut http = Map::new();
            http.insert("type".into(), json!("http"));
            http.insert("path".into(), json!(path));
            if let Some(host) = host.clone().or_else(|| name.clone()) {
                http.insert("host".into(), json!([host]));
            }
            if let Some(method) = method {
                http.insert("method".into(), json!(method));
            }
            Value::Object(http)
        }
        // sing-box's gRPC block is the service name and its timeouts; an
        // authority or multi-stream link is refused for sing-box before this.
        Transport::Grpc { service, .. } => {
            json!({"type": "grpc", "service_name": service})
        }
        // `generate` refuses these for sing-box before a config is built.
        Transport::Kcp { .. } | Transport::Xhttp { .. } => {
            return Err(outbound.refusal(FcaeBackend::SingBox))
        }
    };
    Ok(Some(transport))
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
    let native_log = object.entry("log").or_insert_with(|| json!({}));
    let native_log = native_log
        .as_object_mut()
        .ok_or("native log must be an object")?;
    native_log.insert("disabled".into(), json!(plan.level == Level::Off));
    if let Some(level) = log(plan.level).get("level") {
        native_log.insert("level".into(), level.clone());
    } else {
        native_log.remove("level");
    }

    let inbounds = match object.remove("inbounds") {
        Some(Value::Array(inbounds)) => inbounds,
        Some(_) => return Err("native config \"inbounds\" must be an array".into()),
        None => Vec::new(),
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
                if socks_seen {
                    return Err("multiple native SOCKS/mixed inbounds would collide on the managed port; keep one app listener".into());
                }
                socks_seen = true;
                if inbound
                    .get("users")
                    .and_then(Value::as_array)
                    .is_some_and(|users| !users.is_empty())
                {
                    return Err("the managed SOCKS listener must not require authentication; the app's TUN bridge connects without credentials".into());
                }
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
        // A native config can omit listeners or lead with its own TUN. That
        // inbound's traffic now arrives over the session's SOCKS listener, so
        // the listener takes its place — and its tag, which is what the
        // config's own route rules name.
        let tag = tun_tag.unwrap_or_else(|| TUN_LISTENER_TAG.to_owned());
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
    if let Some(upstream) = plan.upstream {
        crate::native_chain::attach(&mut config, upstream_config(upstream), false)?;
    }
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
        .parse::<IpAddr>()
        .is_err()
        .then(|| server.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RoutingConfig;
    use crate::proxy_cores::CoreProfile as Profile;
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

    /// The platform resolved the server for the core: the config dials that
    /// address and still presents the names the hostname stood for, because the
    /// certificate, the Host header and the authority belong to the name.
    #[test]
    fn a_resolved_server_keeps_every_name_it_stood_for() {
        let profile = Profile::parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@front.example.net:443\
             ?type=ws&path=%2Fray&host=cdn.example.com&security=tls#node",
        )
        .expect("profile parses");
        let routing = routing();
        let mut plan = plan(&profile, &routing, None);
        plan.dial = Some("203.0.113.7".parse().expect("an address"));
        let config = build(&plan);
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["server"], "203.0.113.7");
        assert_eq!(outbound["tls"]["server_name"], "cdn.example.com");
        assert_eq!(outbound["transport"]["headers"]["Host"], "cdn.example.com");
    }

    /// Trojan handshakes in TLS whatever the link said, so a config that never
    /// named a name has one filled in from the server it no longer dials by
    /// name: the alternative is presenting the address as the SNI.
    #[test]
    fn a_tls_by_contract_link_names_its_server_when_the_address_replaces_it() {
        let profile = Profile::parse(
            "trojan://pass@front.example.net:443?security=none&type=ws&path=%2Fws#node",
        )
        .expect("profile parses");
        let routing = routing();
        let mut plan = plan(&profile, &routing, None);
        plan.dial = Some("203.0.113.7".parse().expect("an address"));
        let config = build(&plan);
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["server"], "203.0.113.7");
        assert_eq!(outbound["tls"]["server_name"], "front.example.net");
        assert_eq!(
            outbound["transport"]["headers"]["Host"],
            "front.example.net"
        );
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
    fn hysteria2_outbounds_carry_obfs_bandwidth_hopping_and_the_pin() {
        let profile = Profile::parse(
            "hysteria2://secret@example.com:8443?sni=www.example.com&obfs=salamander\
             &obfs-password=salt&up=50&down=200&mport=20000-20100&hop-interval=30\
             &pinSHA256=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .expect("profile parses");
        let routing = routing();
        let config = build(&plan(&profile, &routing, None));
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["type"], "hysteria2");
        assert_eq!(outbound["server_port"], 8443);
        assert_eq!(outbound["password"], "secret");
        assert_eq!(outbound["obfs"]["type"], "salamander");
        assert_eq!(outbound["obfs"]["password"], "salt");
        assert_eq!(outbound["up_mbps"], 50);
        assert_eq!(outbound["down_mbps"], 200);
        assert_eq!(outbound["server_ports"][0], "20000:20100");
        assert_eq!(outbound["hop_interval"], "30s");
        // TLS is the protocol's own handshake, not the link's option.
        assert_eq!(outbound["tls"]["enabled"], true);
        assert_eq!(outbound["tls"]["server_name"], "www.example.com");
        assert!(outbound["tls"]["certificate_sha256"][0].is_string());
    }

    #[test]
    fn tuic_and_anytls_outbounds_reach_the_core() {
        let profile = Profile::parse(
            "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pass@example.com:10443\
             ?congestion_control=bbr&udp_relay_mode=quic&alpn=h3&sni=www.example.com&reduce_rtt=1",
        )
        .expect("profile parses");
        let routing = routing();
        let config = build(&plan(&profile, &routing, None));
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["type"], "tuic");
        assert_eq!(outbound["uuid"], "b831381d-6324-4d53-ad4f-8cda48b30811");
        assert_eq!(outbound["congestion_control"], "bbr");
        assert_eq!(outbound["udp_relay_mode"], "quic");
        assert_eq!(outbound["zero_rtt_handshake"], true);
        assert_eq!(outbound["tls"]["alpn"][0], "h3");

        let profile =
            Profile::parse("anytls://secret@example.com:443?sni=www.example.com&fp=chrome")
                .expect("profile parses");
        let config = build(&plan(&profile, &routing, None));
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["type"], "anytls");
        assert_eq!(outbound["password"], "secret");
        assert_eq!(outbound["tls"]["utls"]["fingerprint"], "chrome");
    }

    #[test]
    fn early_data_and_http2_settings_reach_the_transport_block() {
        let routing = routing();
        let ws = build(&plan(
            &Profile::parse(
                "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=ws&path=%2Fray\
                 &host=cdn.example.com&ed=2048&eh=X-Retry&security=tls&ech=ECHLIST",
            )
            .expect("profile parses"),
            &routing,
            None,
        ));
        let transport = &ws["outbounds"][0]["transport"];
        assert_eq!(transport["type"], "ws");
        assert_eq!(transport["path"], "/ray");
        assert_eq!(transport["headers"]["Host"], "cdn.example.com");
        assert_eq!(transport["max_early_data"], 2048);
        assert_eq!(transport["early_data_header_name"], "X-Retry");
        assert_eq!(ws["outbounds"][0]["tls"]["ech"]["config"][0], "ECHLIST");

        let h2 = build(&plan(
            &Profile::parse(
                "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=http\
                 &path=%2F&host=cdn.example.com&method=GET&security=tls",
            )
            .expect("profile parses"),
            &routing,
            None,
        ));
        let transport = &h2["outbounds"][0]["transport"];
        assert_eq!(transport["type"], "http");
        assert_eq!(transport["host"][0], "cdn.example.com");
        assert_eq!(transport["method"], "GET");
    }

    #[test]
    fn httpupgrade_carries_no_early_data_field() {
        // This transport has no such field, and sing-box refuses a config that
        // names one — an early-data link is Xray's to honour, through the path.
        let routing = routing();
        let config = build(&plan(
            &Profile::parse(
                "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=httpupgrade\
                 &path=%2Fup%3Fed%3D2048&host=cdn.example.com&security=tls",
            )
            .expect("profile parses"),
            &routing,
            None,
        ));
        let transport = &config["outbounds"][0]["transport"];
        assert_eq!(transport["type"], "httpupgrade");
        assert_eq!(transport["path"], "/up");
        assert_eq!(transport["host"], "cdn.example.com");
        assert!(transport.get("max_early_data").is_none());
    }

    #[test]
    fn gecko_obfs_reaches_the_outbound() {
        let routing = routing();
        let config = build(&plan(
            &Profile::parse(
                "hysteria2://secret@example.com:443?obfs=gecko&obfs-password=salt\
                 &minPacketSize=512&maxPacketSize=1200&sni=www.example.com",
            )
            .expect("profile parses"),
            &routing,
            None,
        ));
        let obfs = &config["outbounds"][0]["obfs"];
        assert_eq!(obfs["type"], "gecko");
        assert_eq!(obfs["password"], "salt");
        assert_eq!(obfs["min_packet_size"], 512);
        assert_eq!(obfs["max_packet_size"], 1200);
    }

    #[test]
    fn shadowsocks_plugins_reach_the_outbound() {
        let routing = routing();
        let config = build(&plan(
            &Profile::parse(
                "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388\
                 ?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com",
            )
            .expect("profile parses"),
            &routing,
            None,
        ));
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["plugin"], "obfs-local");
        assert_eq!(outbound["plugin_opts"], "obfs=http;obfs-host=bing.com");
    }

    #[test]
    fn settings_only_xray_has_are_refused_by_name() {
        let routing = routing();
        for link in [
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=kcp&mtu=1350",
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?type=xhttp&path=%2Fecho",
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality&sni=www.example.com&pbk=KEY&pqv=PQKEY",
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&pcs=AB12",
        ] {
            let profile = Profile::parse(link).expect("profile parses");
            let error = generate(&plan(&profile, &routing, None)).expect_err("sing-box cannot carry it");
            assert!(error.contains("Xray"), "{link}: {error}");
        }
    }

    #[test]
    fn vless_encryption_is_refused_for_sing_box() {
        let key32 = "A".repeat(43);
        let profile = Profile::parse(&format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls\
             &encryption=mlkem768x25519plus.native.0rtt.{key32}"
        ))
        .expect("profile parses");
        let routing = routing();
        let error = generate(&plan(&profile, &routing, None))
            .expect_err("sing-box has no VLESS encryption");
        assert!(error.contains("Xray"), "{error}");
        assert!(error.contains("encryption"), "{error}");
        // Plain VLESS is unaffected.
        let config = build(&plan(&vless(), &routing, None));
        assert_eq!(config["outbounds"][0]["type"], "vless");
    }

    /// A WireGuard profile, in the spelling a share link uses.
    const WIREGUARD: &str = "wireguard://HBtvDj96H5wrPU5fYHGCk6S1xtfo+QobLD1OX2BxgpM=\
                             @engage.example.net:51820\
                             ?publickey=HBtvDj96H5wrPU5fYHGCk6S1xtfo+QobLD1OX2BxgpM=\
                             &address=172.16.0.2/32&reserved=0,0,0&keepalive=25";

    #[test]
    fn a_wireguard_link_becomes_an_endpoint_the_route_names() {
        let profile = Profile::parse(WIREGUARD).expect("profile parses");
        let routing = routing();
        let config = build(&plan(&profile, &routing, None));
        // The outbound form of this protocol was removed in sing-box 1.13.
        let endpoint = &config["endpoints"][0];
        assert_eq!(endpoint["type"], "wireguard");
        assert_eq!(endpoint["tag"], PROXY_TAG);
        assert_eq!(endpoint["address"][0], "172.16.0.2/32");
        assert_eq!(endpoint["peers"][0]["address"], "engage.example.net");
        assert_eq!(endpoint["peers"][0]["port"], 51820);
        assert_eq!(endpoint["peers"][0]["persistent_keepalive_interval"], 25);
        assert_eq!(endpoint["peers"][0]["reserved"], json!([0, 0, 0]));
        // Required here, and the same networks the absence means elsewhere.
        assert_eq!(
            endpoint["peers"][0]["allowed_ips"],
            json!(["0.0.0.0/0", "::/0"])
        );
        // An endpoint tag is a route target: `final` still names the proxy, and
        // no outbound stands in for it.
        assert_eq!(config["route"]["final"], PROXY_TAG);
        assert_eq!(config["outbounds"][0]["tag"], DIRECT_TAG);
    }

    #[test]
    fn a_chained_wireguard_endpoint_dials_through_the_upstream() {
        let profile = Profile::parse(WIREGUARD).expect("profile parses");
        let routing = routing();
        let upstream: UpstreamProxy = "socks5://127.0.0.1:9050".parse().expect("upstream");
        let config = build(&plan(&profile, &routing, Some(&upstream)));
        assert_eq!(config["endpoints"][0]["detour"], UPSTREAM_TAG);
        // A detour and a listen port are the same field twice, and the core
        // refuses the pair.
        assert!(config["endpoints"][0].get("listen_port").is_none());
    }

    #[test]
    fn the_resolved_peer_address_replaces_the_name_only() {
        let profile = Profile::parse(WIREGUARD).expect("profile parses");
        let routing = routing();
        let mut plan = plan(&profile, &routing, None);
        plan.dial = Some("203.0.113.7".parse().expect("an address"));
        let config = build(&plan);
        assert_eq!(config["endpoints"][0]["peers"][0]["address"], "203.0.113.7");
    }

    #[test]
    fn a_hysteria_link_becomes_a_hysteria_outbound() {
        let profile = Profile::parse(
            "hysteria://example.com:443?auth=secret&peer=www.example.com&upmbps=50\
             &downmbps=100&obfs=xplus&obfsParam=salt&mport=8000-8100&hop-interval=30",
        )
        .expect("profile parses");
        let routing = routing();
        let config = build(&plan(&profile, &routing, None));
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["type"], "hysteria");
        assert_eq!(outbound["auth_str"], "secret");
        assert_eq!(outbound["up_mbps"], 50);
        assert_eq!(outbound["down_mbps"], 100);
        assert_eq!(outbound["obfs"], "salt");
        assert_eq!(outbound["server_ports"][0], "8000:8100");
        assert_eq!(outbound["hop_interval"], "30s");
        assert_eq!(outbound["tls"]["server_name"], "www.example.com");
    }

    #[test]
    fn a_naive_link_becomes_a_naive_outbound() {
        let profile = Profile::parse("naive+quic://user:pass@example.com:443?sni=www.example.com")
            .expect("profile parses");
        let routing = routing();
        let config = build(&plan(&profile, &routing, None));
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["type"], "naive");
        assert_eq!(outbound["username"], "user");
        assert_eq!(outbound["password"], "pass");
        assert_eq!(outbound["quic"], true);
        assert_eq!(outbound["tls"]["server_name"], "www.example.com");
        // Chromium's handshake is the point of the protocol: nothing else may be
        // set on it.
        assert!(outbound["tls"].get("utls").is_none());
        assert!(outbound["tls"].get("alpn").is_none());
    }

    #[test]
    fn dial_options_reach_the_fields_they_name() {
        let profile = Profile::parse("socks5://u:p@127.0.0.1:1080?uot=1&uotVersion=2&tfo=1")
            .expect("profile parses");
        let routing = routing();
        let config = build(&plan(&profile, &routing, None));
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["type"], "socks");
        assert_eq!(
            outbound["udp_over_tcp"],
            json!({"enabled": true, "version": 2})
        );
        assert_eq!(outbound["tcp_fast_open"], true);

        // The version-less spelling is the boolean the core takes.
        let profile = Profile::parse("socks5://127.0.0.1:1080?uot=1").expect("profile parses");
        let config = build(&plan(&profile, &routing, None));
        assert_eq!(config["outbounds"][0]["udp_over_tcp"], true);

        // A VLESS link's UDP framing.
        let profile = Profile::parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?packetEncoding=packetaddr",
        )
        .expect("profile parses");
        let config = build(&plan(&profile, &routing, None));
        let outbound = &config["outbounds"][0];
        assert_eq!(outbound["packet_encoding"], "packetaddr");
        assert!(outbound.get("tcp_fast_open").is_none());
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
    fn native_config_without_socks_inbound_gets_managed_listener() {
        let profile = Profile::parse(r#"{"inbounds": [{"type": "http", "listen_port": 2}]}"#)
            .expect("profile");
        let routing = routing();
        let config = generate(&plan(&profile, &routing, None)).expect("managed listener");
        assert!(config["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|inbound| inbound
                .get("type")
                .or_else(|| inbound.get("protocol"))
                .and_then(Value::as_str)
                == Some("socks")));
    }
}

/// sing-box's Shadowsocks outbound `method` enum.
fn sing_box_cipher(method: &str) -> bool {
    matches!(
        method,
        "none"
            | "aes-128-gcm"
            | "aes-192-gcm"
            | "aes-256-gcm"
            | "chacha20-ietf-poly1305"
            | "xchacha20-ietf-poly1305"
            | "2022-blake3-aes-128-gcm"
            | "2022-blake3-aes-256-gcm"
            | "2022-blake3-chacha20-poly1305"
            | "aes-128-ctr"
            | "aes-192-ctr"
            | "aes-256-ctr"
            | "aes-128-cfb"
            | "aes-192-cfb"
            | "aes-256-cfb"
            | "rc4-md5"
            | "chacha20-ietf"
            | "xchacha20"
    )
}

/// Protocol availability belongs to sing-box, not to the portable profile model.
pub(crate) fn carries_protocol(protocol: &Protocol) -> bool {
    match protocol {
        Protocol::Vless {
            encryption: Some(_),
            ..
        } => false,
        Protocol::Shadowsocks { method, .. } => sing_box_cipher(method),
        _ => true,
    }
}

pub(crate) fn link_blocker(outbound: &Outbound) -> Option<String> {
    let refuse = |what: &str| {
        Some(format!(
            "{what}; save it as a Xray config, sing-box cannot carry it"
        ))
    };
    let name = outbound.protocol.name();
    if !carries_protocol(&outbound.protocol) {
        return match &outbound.protocol {
            Protocol::Vless { encryption: Some(_), .. } => Some(format!("this {name} link uses Xray-core's VLESS encryption; save it as an Xray config, sing-box cannot carry it")),
            Protocol::Shadowsocks { method, .. } => refuse(&format!("the shadowsocks method {method:?} is not one sing-box implements")),
            _ => refuse(&format!("a {name} link runs on Xray only")),
        };
    }
    match &outbound.transport {
        Transport::Kcp { .. } | Transport::Xhttp { .. } => {
            return refuse(&format!(
                "the {} transport is an Xray-core one",
                outbound.transport.name()
            ))
        }
        Transport::Grpc {
            multi_mode: true, ..
        } => return refuse("gRPC multi-stream mode is an Xray-core setting"),
        Transport::Grpc {
            authority: Some(_), ..
        } => return refuse("the gRPC authority is an Xray-core setting"),
        _ => {}
    }
    if matches!(&outbound.security, Security::Tls { verify_cert_by_name: Some(_), .. }) {
        return refuse("the verified certificate name has no equivalent sing-box TLS field");
    }
    match &outbound.security {
        Security::Reality {
            support_x25519mlkem768: Some(_),
            ..
        } => {
            return Some("the explicit REALITY support-x25519mlkem768 toggle has no mapping in the pinned sing-box core; use Xray for true or Mihomo for this option".into());
        }
        Security::Reality {
            mldsa65_verify: Some(_),
            ..
        } => return refuse("the REALITY ML-DSA-65 key is an Xray-core setting"),
        Security::Reality { spider_x, .. } if !spider_x.is_empty() && spider_x != "/" => {
            return Some("sing-box has no REALITY spiderX field; remove spx or select Xray".into());
        }
        Security::Tls { pinned_cert_sha256: Some(pins), .. } => {
            if let Err(error) = super::proxy_cores::profile::certificate_pins(pins) { return Some(error); }
        },
        _ => {}
    }
    if outbound.finalmask.is_some() {
        return refuse("finalmask is an Xray-core setting");
    }
    None
}
