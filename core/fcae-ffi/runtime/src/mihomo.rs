//! Mihomo profile validation and managed config generation.
use crate::proxy_cores::profile::share_links::{native, only, pairs};
use crate::proxy_cores::profile::{
    b64_decode, checked_host, parse_port, percent_decode, split_fragment, split_host_port,
    split_list, split_query, trim_trailing_path, Query,
};
use crate::proxy_cores::{
    CoreProfile, Outbound, PacketEncoding, Plan, Protocol, Rules, Security, Transport,
};
use crate::upstream::ProxyKind;
use base64::Engine as _;
use fcae_abi::FcaeBackend;
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
        "port",
        "rules",
        "rule-providers",
        "tun",
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
    if outbound.dial.packet_encoding.is_some()
        && !matches!(
            outbound.protocol,
            Protocol::Vless { .. } | Protocol::Vmess { .. }
        )
    {
        return Err(refuse("packet encoding for this protocol"));
    }
    if outbound.dial.uot.is_some() && !matches!(outbound.protocol, Protocol::Shadowsocks { .. }) {
        return Err(refuse("UDP-over-TCP for this protocol"));
    }
    let mut result = json!({"name":PROXY,"server":outbound.server,"port":outbound.port,"udp":true,"tfo":outbound.dial.tfo});
    if let Some(encoding) = &outbound.dial.packet_encoding {
        if *encoding == PacketEncoding::Disabled && matches!(outbound.protocol, Protocol::Vless { .. }) {
            return Err(refuse("packetEncoding=none for VLESS (the pinned core enables XUDP by default)"));
        }
        result["packet-encoding"] = json!(match encoding {
            PacketEncoding::PacketAddr => "packetaddr",
            PacketEncoding::Xudp => "xudp",
            PacketEncoding::Disabled => "none",
        });
    }
    if let Some(uot) = &outbound.dial.uot {
        result["udp-over-tcp"] = json!(true);
        if let Some(version) = uot.version {
            result["udp-over-tcp-version"] = json!(version);
        }
    }
    match &outbound.protocol {
        Protocol::Vless {
            uuid,
            flow,
            encryption,
        } => {
            if let Some(encryption) = encryption {
                result["encryption"] = json!(encryption);
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
            if let Some(plugin) = plugin {
                let simple = plugin.name == "obfs-local";
                if !simple && plugin.name != "v2ray-plugin" {
                    return Err(refuse("SIP003 plugin"));
                }
                result["plugin"] = json!(if simple { "obfs" } else { "v2ray-plugin" });
                let mut opts = json!({});
                if !simple {
                    opts["mode"] = json!("websocket");
                }
                for option in plugin
                    .options
                    .as_deref()
                    .unwrap_or("")
                    .split(';')
                    .filter(|s| !s.is_empty())
                {
                    let (key, value) = option.split_once('=').unwrap_or((option, "true"));
                    let key = if simple {
                        match key {
                            "obfs" => "mode",
                            "obfs-host" => "host",
                            _ => return Err(refuse("simple-obfs option")),
                        }
                    } else {
                        key
                    };
                    match key {
                        "mode" | "host" | "path" => opts[key] = json!(value),
                        "tls" | "mux" | "skip-cert-verify" if !simple => {
                            opts[key] = json!(match value {
                                "true" | "1" => true,
                                "false" | "0" => false,
                                _ => return Err(refuse("plugin boolean")),
                            });
                        }
                        _ => return Err(refuse("SIP003 plugin option")),
                    }
                }
                result["plugin-opts"] = opts;
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
            if let Some(pin) = pin {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(pin)
                    .map_err(|_| refuse("malformed certificate pin"))?;
                result["fingerprint"] =
                    json!(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
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
                result["ports"] = json!(ports
                    .iter()
                    .map(|p| p.replace(':', "-"))
                    .collect::<Vec<_>>()
                    .join(","));
            }
            if let Some(interval) = hop_interval {
                result["hop-interval"] = json!(interval.to_string());
            }
            if let Some(obfs) = obfs {
                if obfs.kind != "salamander" && obfs.kind != "gecko" {
                    return Err(refuse("Hysteria2 obfuscation"));
                }
                result["obfs"] = json!(obfs.kind);
                result["obfs-password"] = json!(obfs.password);
                if let Some(size) = obfs.min_packet_size {
                    result["obfs-min-packet-size"] = json!(size);
                }
                if let Some(size) = obfs.max_packet_size {
                    result["obfs-max-packet-size"] = json!(size);
                }
            }
        }
        Protocol::Tuic {
            uuid,
            password,
            congestion_control,
            udp_relay_mode,
            zero_rtt,
            disable_sni,
        } => {
            result["type"] = json!("tuic");
            result["disable-sni"] = json!(disable_sni);
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
        Protocol::WireGuard {
            secret_key,
            address,
            peer,
            mtu,
            reserved,
        } => {
            result["type"] = json!("wireguard");
            result["private-key"] = json!(secret_key);
            let mut remote =
                json!({"server":outbound.server,"port":outbound.port,"public-key":peer.public_key});
            if let Some(key) = &peer.preshared_key {
                remote["pre-shared-key"] = json!(key);
            }
            remote["allowed-ips"] = if peer.allowed_ips.is_empty() {
                json!(["0.0.0.0/0", "::/0"])
            } else {
                json!(peer.allowed_ips)
            };
            if !reserved.is_empty() {
                remote["reserved"] = json!(reserved);
            }
            result["peers"] = json!([remote]);
            for address in address {
                let ip = address.split('/').next().unwrap_or(address);
                let key = if ip.contains(':') { "ipv6" } else { "ip" };
                if result.get(key).is_some() {
                    return Err(refuse("multiple WireGuard addresses of one family"));
                }
                result[key] = json!(ip);
            }
            if let Some(keepalive) = peer.keepalive {
                result["persistent-keepalive"] = json!(keepalive);
            }
            if let Some(mtu) = mtu {
                result["mtu"] = json!(mtu);
            }
        }
        Protocol::Hysteria {
            auth,
            obfs,
            up_mbps,
            down_mbps,
            ports,
            hop_interval,
            pin,
        } => {
            if let Some(pin) = pin {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(pin)
                    .map_err(|_| refuse("malformed certificate pin"))?;
                result["fingerprint"] =
                    json!(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
            }
            result["type"] = json!("hysteria");
            result["up"] = json!(format!("{up_mbps} Mbps"));
            result["down"] = json!(format!("{down_mbps} Mbps"));
            if let Some(auth) = auth {
                result["auth-str"] = json!(auth);
            }
            if let Some(obfs) = obfs {
                result["obfs"] = json!(obfs);
            }
            if !ports.is_empty() {
                result["ports"] = json!(ports
                    .iter()
                    .map(|p| p.replace(':', "-"))
                    .collect::<Vec<_>>()
                    .join(","));
            }
            if let Some(interval) = hop_interval {
                result["hop-interval"] = json!(interval);
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
            let socks = matches!(outbound.protocol, Protocol::Socks { .. });
            let http = matches!(outbound.protocol, Protocol::Http { .. });
            let quic = matches!(
                outbound.protocol,
                Protocol::Hysteria { .. } | Protocol::Hysteria2 { .. } | Protocol::Tuic { .. }
            );
            if (socks && sni.is_some())
                || ((socks || http) && (!alpn.is_empty() || fingerprint.is_some() || ech.is_some()))
                || (quic && fingerprint.is_some())
            {
                return Err(refuse("TLS option for this protocol"));
            }
            if let Some(pin) = pinned_cert_sha256 {
                let normalized = pin.replace(':', "");
                if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(refuse("multiple or malformed certificate SHA-256 pins"));
                }
                result["fingerprint"] = json!(normalized);
            }
            if let Some(name) = verify_cert_by_name {
                if name.contains(',') {
                    return Err(refuse("multiple certificate verification names"));
                }
                result["name-cert-verify"] = json!(name);
            }
            if let Some(config) = ech {
                result["ech-opts"] = json!({"enable":true,"config":config});
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
            support_x25519mlkem768,
        } => {
            if !matches!(
                outbound.protocol,
                Protocol::Vless { .. } | Protocol::Vmess { .. } | Protocol::Trojan { .. }
            ) {
                return Err(refuse("REALITY for this protocol"));
            }
            if mldsa65_verify.is_some() || (!spider_x.is_empty() && spider_x != "/") {
                return Err(refuse("REALITY spiderX/ML-DSA (the pinned Mihomo core has neither field; use an Xray config for these settings)"));
            }
            result["tls"] = json!(true);
            result["servername"] = json!(sni);
            result["client-fingerprint"] = json!(fingerprint);
            result["reality-opts"] = json!({"public-key":public_key,"short-id":short_id});
            if let Some(enabled) = support_x25519mlkem768 {
                result["reality-opts"]["support-x25519mlkem768"] = json!(enabled);
            }
        }
    }
    if !matches!(outbound.transport, Transport::Tcp) {
        let allowed = match outbound.protocol {
            Protocol::Vless { .. } => matches!(
                outbound.transport,
                Transport::Ws { .. }
                    | Transport::HttpUpgrade { .. }
                    | Transport::Grpc { .. }
                    | Transport::H2 { .. }
                    | Transport::Xhttp { .. }
            ),
            Protocol::Vmess { .. } => !matches!(outbound.transport, Transport::Xhttp { .. }),
            Protocol::Trojan { .. } => matches!(
                outbound.transport,
                Transport::Ws { .. } | Transport::HttpUpgrade { .. } | Transport::Grpc { .. }
            ),
            _ => false,
        };
        if !allowed {
            return Err(refuse("transport for this protocol"));
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
        Transport::HttpUpgrade {
            path,
            host,
            max_early_data,
        } => {
            result["network"] = json!("ws");
            result["ws-opts"] = json!({"path":path,"v2ray-http-upgrade":true});
            if let Some(host) = host {
                result["ws-opts"]["headers"] = json!({"Host":host});
            }
            if let Some(size) = max_early_data {
                result["ws-opts"]["max-early-data"] = json!(size);
            }
        }
        Transport::Xhttp {
            path,
            host,
            mode,
            extra,
        } => {
            result["network"] = json!("xhttp");
            result["xhttp-opts"] = json!({"path":path});
            if let Some(extra) = extra {
                let extra: Value =
                    serde_json::from_str(extra).map_err(|e| format!("invalid XHTTP extra: {e}"))?;
                let extra = extra.as_object().ok_or("XHTTP extra must be an object")?;
                for (key, value) in extra {
                    if key == "xmux" {
                        result["xhttp-opts"]["reuse-settings"] = xhttp_reuse(value)?;
                        continue;
                    }
                    let target = match key.as_str() {
                        "headers" => "headers",
                        "noGRPCHeader" => "no-grpc-header",
                        "xPaddingBytes" => "x-padding-bytes",
                        "xPaddingObfsMode" => "x-padding-obfs-mode",
                        "xPaddingKey" => "x-padding-key",
                        "xPaddingHeader" => "x-padding-header",
                        "xPaddingPlacement" => "x-padding-placement",
                        "xPaddingMethod" => "x-padding-method",
                        "uplinkHTTPMethod" => "uplink-http-method",
                        "sessionIDPlacement" | "sessionPlacement" => "session-placement",
                        "sessionIDKey" | "sessionKey" => "session-key",
                        "sessionIDTable" | "sessionTable" => "session-table",
                        "sessionIDLength" | "sessionLength" => "session-length",
                        "seqPlacement" => "seq-placement",
                        "seqKey" => "seq-key",
                        "uplinkDataPlacement" => "uplink-data-placement",
                        "uplinkDataKey" => "uplink-data-key",
                        "uplinkChunkSize" => "uplink-chunk-size",
                        "scMaxEachPostBytes" => "sc-max-each-post-bytes",
                        "scMinPostsIntervalMs" => "sc-min-posts-interval-ms",
                        _ => return Err(refuse(&format!("XHTTP extra.{key}"))),
                    };
                    let mapped = if target == "headers" {
                        if !value
                            .as_object()
                            .is_some_and(|headers| headers.values().all(Value::is_string))
                        {
                            return Err("XHTTP headers must map names to strings".into());
                        }
                        value.clone()
                    } else if matches!(target, "no-grpc-header" | "x-padding-obfs-mode") {
                        if !value.is_boolean() {
                            return Err(format!("XHTTP {key} must be boolean"));
                        }
                        value.clone()
                    } else if value.is_string() {
                        value.clone()
                    } else if value.is_u64() {
                        json!(value.to_string())
                    } else {
                        return Err(refuse(&format!("XHTTP extra.{key} value")));
                    };
                    result["xhttp-opts"][target] = mapped;
                }
            }

            if let Some(host) = host {
                result["xhttp-opts"]["host"] = json!(host);
            }
            if let Some(mode) = mode {
                result["xhttp-opts"]["mode"] = json!(mode);
            }
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
            result["network"] = json!("mkcp");
            let mut opts = json!({});
            for (key, value) in [
                ("mtu", mtu),
                ("tti", tti),
                ("uplink-capacity", uplink_capacity),
                ("downlink-capacity", downlink_capacity),
                ("read-buffer", read_buffer),
                ("write-buffer", write_buffer),
            ] {
                if let Some(value) = value {
                    opts[key] = json!(value);
                }
            }
            if let Some(value) = congestion {
                opts["congestion"] = json!(value);
            }
            result["mkcp-opts"] = opts;
        }
    }
    Ok(result)
}

fn xhttp_reuse(value: &Value) -> Result<Value, String> {
    let source = value.as_object().ok_or("XHTTP xmux must be an object")?;
    let mut target = json!({});
    for (key, value) in source {
        let name = match key.as_str() {
            "maxConcurrency" => "max-concurrency",
            "maxConnections" => "max-connections",
            "cMaxReuseTimes" => "c-max-reuse-times",
            "hMaxRequestTimes" => "h-max-request-times",
            "hMaxReusableSecs" => "h-max-reusable-secs",
            "hKeepAlivePeriod" => "h-keep-alive-period",
            _ => {
                return Err(format!(
                    "Mihomo has no verified XHTTP xmux.{key} mapping; use a native config"
                ))
            }
        };
        target[name] = if name == "h-keep-alive-period" {
            if !value.is_i64() {
                return Err("XHTTP hKeepAlivePeriod must be an integer".into());
            }
            value.clone()
        } else if value.is_string() {
            value.clone()
        } else if value.is_u64() {
            json!(value.to_string())
        } else {
            return Err(format!(
                "XHTTP xmux.{key} must be an integer or range string"
            ));
        };
    }
    Ok(target)
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
        crate::proxy_cores::Level::Off => "silent",
        crate::proxy_cores::Level::Error => "error",
        crate::proxy_cores::Level::Warn => "warning",
        crate::proxy_cores::Level::Info => "info",
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

pub(crate) fn parse_link(scheme: &str, rest: &str) -> Result<Value, String> {
    let mut proxy = serde_json::json!({"name":"FCAE-PROXY","type":scheme});
    if scheme == "ssr" {
        let decoded =
            b64_decode(rest.trim_end_matches('/')).ok_or("SSR payload is not base64 UTF-8")?;
        let (body, params) = decoded.split_once("/?").unwrap_or((&decoded, ""));
        let fields: Vec<_> = body.rsplitn(6, ':').collect();
        if fields.len() != 6 {
            return Err("SSR needs server:port:protocol:cipher:obfs:password".into());
        }
        proxy["server"] = serde_json::json!(checked_host(
            fields[5].trim_start_matches('[').trim_end_matches(']')
        )?);
        proxy["port"] = serde_json::json!(parse_port(fields[4])?);
        proxy["protocol"] = serde_json::json!(fields[3]);
        proxy["cipher"] = serde_json::json!(fields[2]);
        proxy["obfs"] = serde_json::json!(fields[1]);
        proxy["password"] = serde_json::json!(if fields[0].is_empty() {
            String::new()
        } else {
            b64_decode(fields[0]).ok_or("invalid SSR password encoding")?
        });
        proxy["udp"] = serde_json::json!(true);
        let query = Query::parse(params);
        for (key, value) in &query.0 {
            let target = match key.as_str() {
                "protoparam" => "protocol-param",
                "obfsparam" => "obfs-param",
                "remarks" | "group" => continue,
                _ => {
                    return Err(format!(
                        "unsupported SSR parameter {key:?}; use a native Mihomo config"
                    ))
                }
            };
            proxy[target] = serde_json::json!(if value.is_empty() {
                String::new()
            } else {
                b64_decode(value).ok_or_else(|| format!("invalid SSR {key} encoding"))?
            });
        }
    } else {
        let (body, _) = split_fragment(rest);
        let (authority, params) = split_query(body);
        let (credentials, target) = authority
            .rsplit_once('@')
            .ok_or("SSH needs username@server")?;
        let (user, password) = credentials
            .split_once(':')
            .map_or((credentials, None), |(u, p)| (u, Some(p)));
        let user = percent_decode(user);
        if user.is_empty() {
            return Err("SSH username is empty".into());
        }
        let (server, port) = split_host_port(trim_trailing_path(target), Some(22))?;
        proxy["server"] = serde_json::json!(server);
        proxy["port"] = serde_json::json!(port);
        proxy["username"] = serde_json::json!(user);
        if let Some(password) = password {
            proxy["password"] = serde_json::json!(percent_decode(password));
        }
        let query = Query::parse(params);
        for (key, value) in &query.0 {
            match key.as_str() {
                "private-key" | "private-key-passphrase" => proxy[key] = serde_json::json!(value),
                "host-key" | "host-key-algorithms" => {
                    proxy[key] = serde_json::json!(split_list(Some(value)))
                }
                _ => {
                    return Err(format!(
                        "unsupported SSH parameter {key:?}; use a native Mihomo config"
                    ))
                }
            }
        }
    }
    Ok(serde_json::json!({"mode":"rule","proxies":[proxy],"rules":["MATCH,FCAE-PROXY"]}))
}

pub(crate) fn parse_mieru(rest: &str, backend: FcaeBackend) -> Result<Value, String> {
    if backend != FcaeBackend::Mihomo {
        return Err("mierus share links require Mihomo".into());
    }
    let (body, _) = split_fragment(rest);
    let (authority, params) = split_query(body);
    let params = pairs(params, &["port", "protocol"])?;
    only(
        &params,
        &[
            "port",
            "protocol",
            "profile",
            "multiplexing",
            "handshake-mode",
            "traffic-pattern",
        ],
    )?;
    let (credentials, target) = authority
        .rsplit_once('@')
        .ok_or("mierus needs username:password@server")?;
    let (username, password) = credentials
        .split_once(':')
        .ok_or("mierus needs username:password")?;
    // The URI's port/protocol pairs, not an authority port, select endpoints.
    let server = target
        .trim_end_matches('/')
        .trim_start_matches('[')
        .trim_end_matches(']');
    checked_host(server)?;
    let ports: Vec<_> = params
        .iter()
        .filter(|(k, _)| k == "port")
        .map(|(_, v)| v)
        .collect();
    let protocols: Vec<_> = params
        .iter()
        .filter(|(k, _)| k == "protocol")
        .map(|(_, v)| v)
        .collect();
    if ports.is_empty() || ports.len() != protocols.len() {
        return Err("mierus needs matching port and protocol parameters".into());
    }
    let mut proxies = Vec::new();
    for (index, (port, protocol)) in ports.iter().zip(protocols).enumerate() {
        if !matches!(protocol.as_str(), "TCP" | "UDP") {
            return Err("Mieru protocol must be TCP or UDP".into());
        }
        let mut proxy = json!({"name":format!("FCAE-MIERU-{index}"),"type":"mieru","server":server,"transport":protocol,"udp":true,"username":percent_decode(username),"password":percent_decode(password)});
        if let Some((start, end)) = port.split_once('-') {
            if parse_port(start)? > parse_port(end)? {
                return Err("reversed Mieru port range".into());
            }
            proxy["port-range"] = json!(port);
        } else {
            proxy["port"] = json!(parse_port(port)?);
        }
        for (key, value) in &params {
            if matches!(
                key.as_str(),
                "multiplexing" | "handshake-mode" | "traffic-pattern"
            ) {
                proxy[key] = json!(value);
            }
        }
        proxies.push(proxy);
    }
    let names: Vec<_> = proxies.iter().map(|p| p["name"].clone()).collect();
    Ok(
        json!({"proxies":proxies,"proxy-groups":[{"name":"FCAE-PROXY","type":"select","proxies":names}],"rules":["MATCH,FCAE-PROXY"]}),
    )
}

pub(crate) fn parse_tuic_v4(rest: &str, backend: FcaeBackend) -> Result<Value, String> {
    if backend != FcaeBackend::Mihomo {
        return Err(
            "TUIC token/v4 links require Mihomo; sing-box supports UUID/password v5".into(),
        );
    }
    let (body, _) = split_fragment(rest);
    let (authority, params) = split_query(body);
    let params = pairs(params, &[])?;
    only(
        &params,
        &[
            "congestion_control",
            "alpn",
            "sni",
            "disable_sni",
            "udp_relay_mode",
        ],
    )?;
    let q = Query(params.iter().cloned().collect());
    let (token, target) = authority
        .rsplit_once('@')
        .ok_or("TUIC v4 needs token@server:port")?;
    let token = percent_decode(token);
    if token.is_empty() {
        return Err("TUIC v4 token is empty".into());
    }
    let (server, port) = split_host_port(trim_trailing_path(target), None)?;
    let mut proxy = json!({"type":"tuic","name":"FCAE-PROXY","server":server,"port":port,"token":token,"udp":true});
    for (source, target) in [
        ("congestion_control", "congestion-controller"),
        ("sni", "sni"),
        ("udp_relay_mode", "udp-relay-mode"),
    ] {
        if let Some(value) = q.get(source) {
            proxy[target] = json!(value);
        }
    }
    if let Some(disable) = q.boolean("disable_sni")? {
        proxy["disable-sni"] = json!(disable);
    }
    let alpn = q.list("alpn");
    if !alpn.is_empty() {
        proxy["alpn"] = json!(alpn);
    }
    Ok(native(proxy, backend))
}
