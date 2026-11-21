//! Verified URI dialects not represented by the common single-outbound model.
//! Schema references are the pinned cores' option/ and infra/conf/ sources;
//! Mieru/realm URI fields follow Mihomo common/convert and Hysteria's URI spec.
use super::*;
use serde_json::json;

pub(super) fn check_encoding(text: &str) -> Result<(), String> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = bytes.get(i + 1).and_then(|b| hex_value(*b));
            let lo = bytes.get(i + 2).and_then(|b| hex_value(*b));
            let (Some(hi), Some(lo)) = (hi, lo) else {
                return Err("share link has an invalid percent escape".into());
            };
            decoded.push((hi << 4) | lo);
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    std::str::from_utf8(&decoded)
        .map_err(|_| "share link contains non-UTF-8 percent-encoded text")?;
    Ok(())
}

pub(crate) fn pairs(params: &str, repeated: &[&str]) -> Result<Vec<(String, String)>, String> {
    let mut result: Vec<(String, String)> = Vec::new();
    for pair in params.split('&').filter(|s| !s.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        // Do not turn invalid escapes into different credentials or hostnames.
        for text in [key, value] {
            let bytes = text.as_bytes();
            for i in 0..bytes.len() {
                if bytes[i] == b'%'
                    && (i + 2 >= bytes.len()
                        || hex_value(bytes[i + 1]).is_none()
                        || hex_value(bytes[i + 2]).is_none())
                {
                    return Err("share link has an invalid percent escape".into());
                }
            }
        }
        let key = percent_decode(key).to_ascii_lowercase();
        if !repeated.contains(&key.as_str()) && result.iter().any(|(k, _)| k == &key) {
            return Err(format!(
                "duplicate share-link parameter {key:?}; use one value"
            ));
        }
        result.push((key, percent_decode(value)));
    }
    Ok(result)
}

pub(crate) fn only(params: &[(String, String)], allowed: &[&str]) -> Result<(), String> {
    for (key, _) in params {
        if !allowed.contains(&key.as_str()) {
            return Err(format!(
                "unsupported share-link parameter {key:?}; use a native config for this option"
            ));
        }
    }
    Ok(())
}

const HY2: &[&str] = &[
    "auth",
    "obfs",
    "obfs-password",
    "obfs_password",
    "sni",
    "peer",
    "insecure",
    "allowinsecure",
    "pinsha256",
    "pin_sha256",
    "pinned_sha256",
    "pin",
    "ech",
    "alpn",
    "security",
    "pcs",
    "vcn",
    "up",
    "upmbps",
    "up_mbps",
    "down",
    "downmbps",
    "down_mbps",
    "mport",
    "ports",
    "hop-interval",
    "hop_interval",
    "minpacketsize",
    "maxpacketsize",
    "fm",
];

pub(super) fn check_hy2_query(params: &str) -> Result<(), String> {
    let params = pairs(params, &[])?;
    only(&params, HY2)?;
    let q = Query(params.iter().cloned().collect());
    for key in ["pcs", "hpkp"] {
        if q.0.get(key).is_some_and(|value| value.trim().is_empty()) {
            return Err(format!("{key} certificate pin cannot be empty"));
        }
    }
    if q.first(&["obfs-password", "obfs_password"]).is_some() && q.get("obfs").is_none() {
        return Err("obfs-password needs an obfs scheme".into());
    }
    if q.first(&["minpacketsize", "maxpacketsize"]).is_some() && q.get("obfs") != Some("gecko") {
        return Err("minPacketSize/maxPacketSize require obfs=gecko".into());
    }
    if q.first(&["hop-interval", "hop_interval"])
        .is_some_and(|s| s.is_empty())
    {
        return Err("hop interval is empty".into());
    }
    for (key, value) in &params {
        if matches!(key.as_str(), "insecure" | "allowinsecure")
            && !matches!(
                value.to_ascii_lowercase().as_str(),
                "0" | "1" | "true" | "false" | "yes" | "no" | "on" | "off"
            )
        {
            return Err(format!("{key} must be a boolean"));
        }
    }
    Ok(())
}

/// The official Hysteria2 authority can carry comma/range ports, including IPv6.
pub(super) fn hy2_address(target: &str) -> Result<(String, u16, Vec<String>), String> {
    let (host, port_text) = if target.starts_with('[') {
        let end = target.find(']').ok_or("unterminated IPv6 address")?;
        (&target[..=end], target[end + 1..].strip_prefix(':'))
    } else {
        match target.rsplit_once(':') {
            Some((host, ports)) => (host, Some(ports)),
            None => (target, None),
        }
    };
    let Some(ports) = port_text.filter(|ports| ports.contains(',') || ports.contains('-')) else {
        let (server, port) = split_host_port(target, Some(443))?;
        return Ok((server, port, Vec::new()));
    };
    let q = Query::parse(&format!("ports={ports}"));
    let ranges = q.ports(&["ports"])?;
    let first = ports
        .split([',', '-', ':'])
        .next()
        .ok_or("empty Hysteria2 port list")?;
    let (server, port) = split_host_port(&format!("{host}:{first}"), Some(443))?;
    Ok((server, port, ranges))
}

pub(crate) fn native(proxy: Value, backend: FcaeBackend) -> Value {
    if backend == FcaeBackend::SingBox {
        json!({"inbounds":[{"type":"socks","tag":"socks-in"},{"type":"http","tag":"http-in"}],"outbounds":[proxy],"route":{"final":"FCAE-PROXY"}})
    } else {
        json!({"mode":"rule","proxies":[proxy],"rules":["MATCH,FCAE-PROXY"]})
    }
}

pub(super) fn native_link(text: &str, backend: FcaeBackend) -> Option<Result<Value, String>> {
    let (scheme, rest) = text.split_once("://")?;
    if !scheme
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
    {
        return None;
    }
    let scheme = scheme.to_ascii_lowercase();
    let result = match scheme.as_str() {
        "socks4" | "socks4a" => {
            Some((|| {
                if backend != FcaeBackend::SingBox {
                    return Err("SOCKS4/4a share links require sing-box; Xray and Mihomo expose SOCKS5 only".into());
                }
                let (body, _) = split_fragment(rest);
                let (address, query) = split_query(body);
                only(&pairs(query, &[])?, &[])?;
                let (auth, target) = address
                    .rsplit_once('@')
                    .map_or((None, address), |(auth, target)| (Some(auth), target));
                let (server, port) = split_host_port(trim_trailing_path(target), Some(1080))?;
                if auth.is_some_and(|user| user.contains(':')) {
                    return Err("SOCKS4/4a carries a user ID, not a password".into());
                }
                let user = auth.map(percent_decode);
                let mut proxy = json!({"type":"socks","tag":"FCAE-PROXY","server":server,"server_port":port,"version":if scheme == "socks4a" {"4a"} else {"4"}});
                if let Some(user) = user {
                    proxy["username"] = json!(user);
                }
                Ok(native(proxy, backend))
            })())
        }
        "ssh" => Some((|| {
            let params = pairs(split_query(split_fragment(rest).0).1, &[])?;
            only(
                &params,
                &[
                    "private-key",
                    "private-key-passphrase",
                    "host-key",
                    "host-key-algorithms",
                ],
            )?;
            if backend == FcaeBackend::SingBox {
                ssh(rest)
            } else if backend == FcaeBackend::Mihomo {
                crate::mihomo::parse_link("ssh", rest)
            } else {
                Err("SSH share links require sing-box or Mihomo".into())
            }
        })()),
        "tuic"
            if split_query(split_fragment(rest).0)
                .0
                .rsplit_once('@')
                .is_some_and(|(auth, _)| !auth.contains(':')) =>
        {
            Some(crate::mihomo::parse_tuic_v4(rest, backend))
        }
        "snell" => Some(snell(rest, backend)),
        "mierus" => Some(crate::mihomo::parse_mieru(rest, backend)),
        "hysteria2+realm" | "hy2+realm" | "hysteria2+realm+http" | "hy2+realm+http" => {
            Some(realm(rest, backend, scheme.ends_with("+http")))
        }
        _ => None,
    };
    result.map(|result| check_encoding(rest).and(result))
}

fn ssh(rest: &str) -> Result<Value, String> {
    let config = crate::mihomo::parse_link("ssh", rest)?;
    let source = &config["proxies"][0];
    let mut proxy = json!({"type":"ssh","tag":"FCAE-PROXY","server":source["server"],"server_port":source["port"],"user":source["username"]});
    for (from, to) in [
        ("password", "password"),
        ("private-key", "private_key"),
        ("private-key-passphrase", "private_key_passphrase"),
        ("host-key", "host_key"),
        ("host-key-algorithms", "host_key_algorithms"),
    ] {
        if let Some(value) = source.get(from) {
            proxy[to] = value.clone();
        }
    }
    Ok(native(proxy, FcaeBackend::SingBox))
}

fn snell(rest: &str, backend: FcaeBackend) -> Result<Value, String> {
    if !matches!(backend, FcaeBackend::SingBox | FcaeBackend::Mihomo) {
        return Err("Xray has no Snell protocol; select sing-box or Mihomo".into());
    }
    let (body, _) = split_fragment(rest);
    let (authority, params) = split_query(body);
    let params = pairs(params, &[])?;
    only(&params, &["version", "obfs", "obfs-host", "reuse", "mode"])?;
    let q = Query(params.iter().cloned().collect());
    let (secret, target) = authority
        .rsplit_once('@')
        .ok_or("Snell needs psk@host:port")?;
    let secret = percent_decode(secret);
    if secret.is_empty() {
        return Err("Snell PSK is empty".into());
    }
    let (server, port) = split_host_port(trim_trailing_path(target), None)?;
    let version: u32 = q.number("version")?.unwrap_or(4);
    if !(if backend == FcaeBackend::SingBox {
        matches!(version, 4 | 6)
    } else {
        matches!(version, 1..=6)
    }) {
        return Err("this Snell version is not supported by the selected pinned core".into());
    }
    let obfs = q.get("obfs").unwrap_or("none");
    if !matches!(obfs, "none" | "http" | "tls") {
        return Err("Snell obfs must be none, http or tls".into());
    }
    if q.get("obfs-host").is_some() && obfs == "none" {
        return Err("obfs-host needs Snell obfuscation".into());
    }
    let mode = q.get("mode").unwrap_or("default");
    if !matches!(mode, "default" | "unshaped" | "unsafe-raw") {
        return Err("unsupported Snell v6 mode".into());
    }
    if version == 6 {
        if !(12..=255).contains(&secret.len()) || obfs != "none" || q.get("obfs-host").is_some() {
            return Err("Snell v6 needs a 12..255 byte PSK and no obfuscation".into());
        }
    } else if q.get("mode").is_some() {
        return Err("Snell mode requires version 6".into());
    }
    let reuse = q.boolean("reuse")?;
    let mut proxy = if backend == FcaeBackend::SingBox {
        json!({"type":"snell","tag":"FCAE-PROXY","server":server,"server_port":port,"psk":secret,"version":version})
    } else {
        json!({"type":"snell","name":"FCAE-PROXY","server":server,"port":port,"psk":secret,"version":version,"udp":version>=3})
    };
    if let Some(reuse) = reuse {
        proxy["reuse"] = json!(reuse);
    }
    if version == 6 {
        proxy["mode"] = json!(mode);
    } else if backend == FcaeBackend::SingBox {
        proxy["obfs_mode"] = json!(obfs);
        if let Some(host) = q.get("obfs-host") {
            proxy["obfs_host"] = json!(host);
        }
    } else if obfs != "none" {
        proxy["obfs-opts"] = json!({"mode":obfs});
        if let Some(host) = q.get("obfs-host") {
            proxy["obfs-opts"]["host"] = json!(host);
        }
    }
    Ok(native(proxy, backend))
}

fn encode(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn realm(rest: &str, backend: FcaeBackend, http: bool) -> Result<Value, String> {
    let (body, _) = split_fragment(rest);
    let (authority_path, params) = split_query(body);
    let params = pairs(params, &["stun"])?;
    let mut allowed = HY2.to_vec();
    allowed.extend(["auth", "stun"]);
    only(&params, &allowed)?;
    let (authority, id) = authority_path
        .split_once('/')
        .ok_or("realm link needs /realm-name")?;
    if id.is_empty() || id.contains('/') {
        return Err("realm link needs one percent-encoded realm name".into());
    }
    let (token, target) = authority.rsplit_once('@').unwrap_or(("", authority));
    let (server, port) = split_host_port(target, Some(if http { 80 } else { 443 }))?;
    let q = Query(params.iter().cloned().collect());
    if q.first(&["mport", "ports", "hop-interval", "hop_interval"])
        .is_some()
    {
        return Err("realm links cannot use port hopping".into());
    }
    let hy_params = params
        .iter()
        .filter(|(k, _)| HY2.contains(&k.as_str()))
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let outbound = parse_hysteria2(&format!(
        "{}@{}:{port}/?{hy_params}",
        encode(q.get("auth").unwrap_or("")),
        if server.contains(':') {
            format!("[{server}]")
        } else {
            server.clone()
        }
    ))?;
    if !outbound.carried_by(backend) {
        return Err(outbound.refusal(backend));
    }
    let url = format!(
        "{}://{}:{port}",
        if http { "http" } else { "https" },
        if server.contains(':') {
            format!("[{server}]")
        } else {
            server.clone()
        }
    );
    let stuns: Vec<_> = params
        .iter()
        .filter(|(k, _)| k == "stun")
        .map(|(_, v)| v.clone())
        .collect();
    if backend == FcaeBackend::Xray {
        let mut stream = crate::xray::hysteria2_stream(&outbound)?;
        let realm_url = format!(
            "{}://{}{}:{port}/{id}",
            if http { "realm+http" } else { "realm" },
            if token.is_empty() {
                String::new()
            } else {
                format!("{token}@")
            },
            if server.contains(':') {
                format!("[{server}]")
            } else {
                server
            }
        );
        let mask = json!({"type":"realm","settings":{"url":realm_url,"stunServers":stuns}});
        let finalmask = stream.entry("finalmask").or_insert_with(|| json!({}));
        let udp = finalmask
            .as_object_mut()
            .ok_or("finalmask must be an object")?
            .entry("udp")
            .or_insert_with(|| json!([]));
        udp.as_array_mut()
            .ok_or("finalmask udp must be an array")?
            .push(mask);
        return Ok(
            json!({"inbounds":[{"protocol":"socks","tag":"socks-in"},{"protocol":"http","tag":"http-in"}],"outbounds":[{"tag":"FCAE-PROXY","protocol":"hysteria","settings":{"version":2,"address":outbound.server,"port":outbound.port},"streamSettings":stream}]}),
        );
    }
    let mut proxy = crate::mihomo::proxy(&outbound)?;
    if backend == FcaeBackend::Mihomo {
        proxy["realm-opts"] = json!({"enable":true,"server-url":url,"token":percent_decode(token),"realm-id":percent_decode(id),"stun-servers":stuns});
    } else if backend == FcaeBackend::SingBox {
        let Protocol::Hysteria2 {
            password,
            obfs,
            up_mbps,
            down_mbps,
            pin,
            ..
        } = &outbound.protocol
        else {
            unreachable!()
        };
        let Security::Tls {
            sni,
            alpn,
            allow_insecure,
            ech,
            ..
        } = &outbound.security
        else {
            unreachable!()
        };
        proxy = json!({"tag":"FCAE-PROXY","type":"hysteria2","password":password,"realm":{"server_url":url,"token":percent_decode(token),"realm_id":percent_decode(id),"stun_servers":stuns},"tls":{"enabled":true,"server_name":sni,"insecure":allow_insecure}});
        if !alpn.is_empty() {
            proxy["tls"]["alpn"] = json!(alpn);
        }
        if let Some(ech) = ech {
            proxy["tls"]["ech"] = json!({"enabled":true,"config":[ech]});
        }
        if let Some(pin) = pin {
            proxy["tls"]["certificate_sha256"] = json!([pin]);
        }
        if let Some(up) = up_mbps {
            proxy["up_mbps"] = json!(up);
        }
        if let Some(down) = down_mbps {
            proxy["down_mbps"] = json!(down);
        }
        if let Some(obfs) = obfs {
            proxy["obfs"] = json!({"type":obfs.kind,"password":obfs.password});
            if let Some(min) = obfs.min_packet_size {
                proxy["obfs"]["min_packet_size"] = json!(min);
            }
            if let Some(max) = obfs.max_packet_size {
                proxy["obfs"]["max_packet_size"] = json!(max);
            }
        }
    } else {
        return Err("realm links require sing-box, Xray or Mihomo".into());
    }
    Ok(native(proxy, backend))
}

/// Reject unsupported URI options instead of accepting a link with missing
/// security/transport semantics. Metadata belongs in the fragment.
pub(super) fn check_query(scheme: &str, rest: &str) -> Result<(), String> {
    if matches!(scheme, "ssr" | "ssh" | "snell" | "mierus") || scheme.contains("+realm") {
        return Ok(());
    }
    let (body, _) = split_fragment(rest);
    let (_, params) = split_query(body);
    let params = pairs(params, &[])?;
    if params.is_empty() {
        return Ok(());
    }
    if matches!(scheme, "hy2" | "hysteria2") {
        return check_hy2_query(split_query(body).1);
    }
    let q = Query(params.iter().cloned().collect());
    for key in ["pcs", "hpkp"] {
        if q.0.get(key).is_some_and(|value| value.trim().is_empty()) {
            return Err(format!("{key} certificate pin cannot be empty"));
        }
    }
    // Parse shared dial options even when disabled; with_dial_options rejects
    // active framing on protocols which cannot carry it.
    let mut allowed = vec![
        "tfo",
        "fastopen",
        "tcpfastopen",
        "tcp-fast-open",
        "uot",
        "udp-over-tcp",
        "udp_over_tcp",
        "uotversion",
        "uot_version",
        "uot-version",
        "packetencoding",
        "packet_encoding",
    ];
    if matches!(scheme, "ss" | "shadowsocks") {
        allowed.push("plugin");
    }
    if matches!(scheme, "wireguard" | "wg") {
        allowed.extend([
            "publickey",
            "public_key",
            "peer_public_key",
            "peerpublickey",
            "presharedkey",
            "preshared_key",
            "pre_shared_key",
            "psk",
            "address",
            "local_address",
            "ip",
            "allowedips",
            "allowed_ips",
            "allowed-ips",
            "persistent-keepalive-interval",
            "persistent_keepalive_interval",
            "persistent-keepalive",
            "persistent_keepalive",
            "keepalive-interval",
            "keepalive_interval",
            "keepalive",
            "mtu",
            "reserved",
            "security",
            "type",
            "net",
            "fm",
        ]);
    }
    if matches!(scheme, "vless" | "vmess" | "trojan") {
        allowed.extend(["type", "net", "security", "fm"]);
        match q
            .first(&["type", "net"])
            .unwrap_or("tcp")
            .to_ascii_lowercase()
            .as_str()
        {
            "ws" => allowed.extend(["path", "host", "ed", "maxearlydata", "eh"]),
            "httpupgrade" => allowed.extend(["path", "host", "ed", "maxearlydata"]),
            "h2" | "http" => allowed.extend(["path", "host", "method"]),
            "grpc" | "gun" => allowed.extend(["servicename", "authority", "mode"]),
            "kcp" | "mkcp" => allowed.extend([
                "mtu",
                "tti",
                "uplinkcapacity",
                "downlinkcapacity",
                "congestion",
                "readbuffersize",
                "writebuffersize",
                "headertype",
                "seed",
            ]),
            "xhttp" | "splithttp" => allowed.extend(["path", "host", "mode", "extra"]),
            _ => allowed.push("headertype"),
        }
        if scheme == "vless" {
            allowed.extend(["encryption", "flow"]);
        }
        if scheme == "vmess" {
            allowed.extend(["scy", "encryption", "aid"]);
            if q.get("scy").zip(q.get("encryption")).is_some_and(|(a,b)| a != b) {
                return Err("VMess scy and encryption specify different ciphers".into());
            }
        }
    }
    let tls_contract = matches!(
        scheme,
        "hy" | "hysteria"
            | "tuic"
            | "anytls"
            | "naive"
            | "naive+https"
            | "naive+quic"
            | "https"
            | "trojan"
    );
    let security = q
        .get("security")
        .unwrap_or(if tls_contract { "tls" } else { "none" });
    if tls_contract && !matches!(scheme, "trojan" | "https") {
        tls_by_contract(&q, scheme)?;
    }
    let reads_security = matches!(
        scheme,
        "vless"
            | "vmess"
            | "trojan"
            | "https"
            | "hy"
            | "hysteria"
            | "tuic"
            | "anytls"
            | "naive"
            | "naive+https"
            | "naive+quic"
    );
    if reads_security {
        allowed.push("security");
    }
    if reads_security && (tls_contract || !security.eq_ignore_ascii_case("none")) {
        if security.eq_ignore_ascii_case("reality") {
            allowed.extend([
                "sni", "peer", "fp", "pbk", "sid", "spx", "pqv", "support-x25519mlkem768",
            ]);
        } else {
            allowed.extend([
                "security",
                "sni",
                "alpn",
                "fp",
                "insecure",
                "allowinsecure",
                "pcs",
                "vcn",
                "ech",
            ]);
            if scheme != "tuic" {
                allowed.push("peer");
            }
        }
    }
    if scheme == "anytls" {
        allowed.push("hpkp");
        if q.get("hpkp").is_some() && q.get("pcs").is_some() {
            return Err("use either AnyTLS hpkp or pcs, not both".into());
        }
    }
    match scheme {
        "tuic" => allowed.extend([
            "congestion_control",
            "congestion-control",
            "udp_relay_mode",
            "udp-relay-mode",
            "zero_rtt_handshake",
            "zero-rtt-handshake",
            "reduce_rtt",
            "allow_insecure",
            "disable_sni",
        ]),
        "hysteria" | "hy" => allowed.extend([
            "auth",
            "protocol",
            "obfs",
            "obfsparam",
            "obfs_param",
            "up",
            "upmbps",
            "up_mbps",
            "down",
            "downmbps",
            "down_mbps",
            "mport",
            "mports",
            "ports",
            "hop-interval",
            "hop_interval",
            "pinsha256",
            "pin_sha256",
            "pinned_sha256",
            "pin",
        ]),
        _ => {}
    }
    only(&params, &allowed)?;
    for (key, value) in &params {
        if matches!(
            key.as_str(),
            "tfo"
                | "fastopen"
                | "tcpfastopen"
                | "tcp-fast-open"
                | "insecure"
                | "allowinsecure"
                | "allow_insecure"
                | "zero_rtt_handshake"
                | "zero-rtt-handshake"
                | "reduce_rtt"
                | "disable_sni"
                | "support-x25519mlkem768"
        ) && !matches!(
            value.to_ascii_lowercase().as_str(),
            "0" | "1" | "true" | "false" | "yes" | "no" | "on" | "off"
        ) {
            return Err(format!("{key} must be a boolean"));
        }
    }
    Ok(())
}

pub(super) fn check_vmess_params(params: &Query) -> Result<(), String> {
    let query = params
        .0
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    check_query("vmess", &format!("unused?{query}"))
}
