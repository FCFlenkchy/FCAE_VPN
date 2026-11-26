//! Portable profiles and URI grammar shared by the embedded cores.
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use fcae_abi::FcaeBackend;
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
#[path = "share_links.rs"]
pub(crate) mod share_links;

/// An outbound's transport, carrying every field a share link can name for it.
///
/// The two cores do not overlap here: Xray-core owns mKCP and XHTTP, sing-box
/// owns plain HTTP/2 — and each refuses the other's, which
/// [`Outbound::carried_by`] reports by name rather than dropping the settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Quic,
    Ws {
        path: String,
        host: Option<String>,
        /// WebSocket early data: Xray keeps the byte count in the path's own
        /// `ed` query, sing-box in `max_early_data`.
        max_early_data: Option<u32>,
        /// The header sing-box sends early data in. Xray-core removed the
        /// setting when it moved early data into the path.
        early_data_header: Option<String>,
    },
    HttpUpgrade {
        path: String,
        host: Option<String>,
        max_early_data: Option<u32>,
    },
    /// HTTP/2 — sing-box's `http` transport. Xray-core removed it in favour of
    /// XHTTP, so this is sing-box-only.
    H2 {
        path: String,
        host: Option<String>,
        method: Option<String>,
    },
    Grpc {
        service: String,
        authority: Option<String>,
        /// Xray's multi-stream mode; sing-box opens one stream per connection.
        multi_mode: bool,
    },
    /// mKCP — Xray-core only. Header and seed are gone from the core, so a link
    /// naming either is refused instead of producing a config it rejects.
    Kcp {
        mtu: Option<u32>,
        tti: Option<u32>,
        uplink_capacity: Option<u32>,
        downlink_capacity: Option<u32>,
        congestion: Option<bool>,
        read_buffer: Option<u32>,
        write_buffer: Option<u32>,
    },
    /// XHTTP (SplitHTTP) — Xray-core only. `extra` is the core's own settings
    /// object for everything a link does not name, carried verbatim.
    Xhttp {
        path: String,
        host: Option<String>,
        mode: Option<String>,
        extra: Option<String>,
    },
}

impl Transport {
    /// The name the cores and the config editor use for this transport.
    pub fn name(&self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Quic => "quic",
            Transport::Ws { .. } => "ws",
            Transport::HttpUpgrade { .. } => "httpupgrade",
            Transport::H2 { .. } => "http",
            Transport::Grpc { .. } => "grpc",
            Transport::Kcp { .. } => "kcp",
            Transport::Xhttp { .. } => "xhttp",
        }
    }

    /// The name this transport puts on the wire, when it has one: the HTTP
    /// `Host` a proxied session presents, which a server's certificate is
    /// issued for whenever it is fronted.
    pub fn presented_host(&self) -> Option<&str> {
        match self {
            Transport::Ws { host, .. }
            | Transport::HttpUpgrade { host, .. }
            | Transport::Xhttp { host, .. } => host.as_deref(),
            // An `h2` link may list several hosts; the first is the authority.
            Transport::H2 { host, .. } => host
                .as_deref()
                .and_then(|hosts| hosts.split(',').next())
                .map(str::trim)
                .filter(|host| !host.is_empty()),
            Transport::Grpc { authority, .. } => authority.as_deref(),
            Transport::Tcp | Transport::Quic | Transport::Kcp { .. } => None,
        }
    }
}

/// The outer security layer of a single outbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Security {
    None,
    Tls {
        sni: Option<String>,
        alpn: Vec<String>,
        /// uTLS fingerprint, e.g. `chrome`.
        fingerprint: Option<String>,
        /// `allowInsecure`. Xray-core removed the setting, so only sing-box can
        /// carry an outbound that asks for it.
        allow_insecure: bool,
        /// `pcs`: hex SHA-256 pins of the server certificate. sing-box takes
        /// the same certificate digest as base64, not its public-key digest.
        pinned_cert_sha256: Option<String>,
        /// `vcn`: the names the peer certificate is verified against.
        /// Xray-core only.
        verify_cert_by_name: Option<String>,
        /// `ech`: the base64 ECH config list, which both cores take verbatim.
        ech: Option<String>,
    },
    Reality {
        sni: String,
        fingerprint: String,
        public_key: String,
        short_id: String,
        spider_x: String,
        /// ML-DSA-65 verification key (`pqv`). Xray-core verifies the server's
        /// handshake with it; sing-box's REALITY has no such field.
        mldsa65_verify: Option<String>,
        /// REALITY key-share compatibility flag. Xray preserves the chosen
        /// fingerprint's hybrid key shares natively; Mihomo needs an opt-in.
        /// Keep absence distinct from false so legacy links retain defaults.
        support_x25519mlkem768: Option<bool>,
    },
}

/// Hysteria2's packet obfuscation: the scheme, its password, and for `gecko` the
/// padding window it fills to.
///
/// sing-box uses an obfs object; Xray expresses the same wire format through
/// its finalmask Salamander/Gecko settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obfs {
    /// `salamander`, or `gecko` with its packet sizes.
    pub kind: String,
    pub password: String,
    /// Gecko pads every packet into this window; `None` keeps the core's own.
    pub min_packet_size: Option<u32>,
    pub max_packet_size: Option<u32>,
}

/// A SIP003 plugin, as a share link spells it: the name up to the first `;` and
/// the plugin's own options after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowSocksPlugin {
    pub name: String,
    pub options: Option<String>,
}

/// A WireGuard peer, as a share link names one: the key it is verified against,
/// the networks it carries, and how often to keep its NAT mapping alive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardPeer {
    /// Padded standard base64, which is the one spelling both cores decode.
    pub public_key: String,
    pub preshared_key: Option<String>,
    /// Empty keeps the cores' own `0.0.0.0/0, ::/0`.
    pub allowed_ips: Vec<String>,
    pub keepalive: Option<u32>,
}

/// Which protocol the outbound speaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Vless {
        uuid: String,
        flow: Option<String>,
        /// Xray's VLESS encryption, as the link spells it
        /// (`mlkem768x25519plus.<mode>.<rtt>.<key>…`); `None` for `none`.
        /// sing-box's VLESS has no such handshake, so this is Xray-only.
        encryption: Option<String>,
    },
    Vmess {
        uuid: String,
        alter_id: u16,
        security: String,
    },
    Trojan {
        password: String,
    },
    Shadowsocks {
        method: String,
        password: String,
        /// SIP003 plugin, which is how sing-box reaches obfs-local and
        /// v2ray-plugin servers. Xray-core has no plugin support at all.
        plugin: Option<ShadowSocksPlugin>,
    },
    Socks {
        user: Option<String>,
        password: Option<String>,
    },
    Http {
        user: Option<String>,
        password: Option<String>,
    },
    /// Hysteria2 — QUIC, TLS by contract; supported by all three pinned cores.
    Hysteria2 {
        password: String,
        /// Packet obfuscation: the scheme, its password, and gecko's sizes.
        obfs: Option<Obfs>,
        /// Bandwidth hint in Mbps, which is what Brutal shapes to.
        up_mbps: Option<u32>,
        down_mbps: Option<u32>,
        /// Port hopping ranges, in sing-box's `server_ports` syntax.
        ports: Vec<String>,
        /// Seconds between hops.
        hop_interval: Option<u64>,
        /// SHA-256 of the server certificate, base64 as sing-box
        /// wants it; share links carry the digest hex-encoded.
        pin: Option<String>,
    },
    /// TUIC — QUIC with its own UUID/password handshake. sing-box only.
    Tuic {
        uuid: String,
        password: String,
        congestion_control: Option<String>,
        udp_relay_mode: Option<String>,
        zero_rtt: bool,
        disable_sni: bool,
    },
    /// AnyTLS — TLS with a padding scheme. sing-box only.
    AnyTls {
        password: String,
    },
    /// WireGuard — a userspace tunnel both cores implement, Xray-core as an
    /// outbound and sing-box as an `endpoint` (its outbound form was removed in
    /// 1.13). A link describes one peer: the endpoint is the profile's server.
    WireGuard {
        /// Client private key, padded standard base64.
        secret_key: String,
        /// Local interface addresses, each at full width (`/32`, `/128`), which
        /// is the only prefix Xray-core's own parser accepts.
        address: Vec<String>,
        peer: WireGuardPeer,
        mtu: Option<u32>,
        /// The three bytes a WARP-style endpoint reads; empty for a plain peer.
        reserved: Vec<u8>,
    },
    /// Hysteria v1 — QUIC with Brutal congestion control. sing-box's `hysteria`
    /// outbound implements it; Xray-core reaches hysteria through its own
    /// transport and finalmask instead, which a v1 link does not spell out.
    Hysteria {
        auth: Option<String>,
        /// XPlus packet obfuscation password.
        obfs: Option<String>,
        /// The bandwidth Brutal shapes to, which sing-box will not start without.
        up_mbps: u32,
        down_mbps: u32,
        ports: Vec<String>,
        hop_interval: Option<u64>,
        pin: Option<String>,
    },
    /// NaiveProxy — HTTP/2 or QUIC inside a Chromium TLS handshake. sing-box
    /// only, and only where the build carries cronet.
    Naive {
        user: Option<String>,
        password: Option<String>,
        quic: bool,
    },
}

impl Protocol {
    /// The name the cores and the config editor use for this protocol.
    pub fn name(&self) -> &'static str {
        match self {
            Protocol::Vless { .. } => "vless",
            Protocol::Vmess { .. } => "vmess",
            Protocol::Trojan { .. } => "trojan",
            Protocol::Shadowsocks { .. } => "shadowsocks",
            Protocol::Socks { .. } => "socks",
            Protocol::Http { .. } => "http",
            Protocol::Hysteria2 { .. } => "hysteria2",
            Protocol::Tuic { .. } => "tuic",
            Protocol::AnyTls { .. } => "anytls",
            Protocol::WireGuard { .. } => "wireguard",
            Protocol::Hysteria { .. } => "hysteria",
            Protocol::Naive { .. } => "naive",
        }
    }

    /// Whether Xray-core's config grammar can express this protocol.
    ///
    /// Hysteria2 is supported; TUIC, AnyTLS, Hysteria v1 and Naive have no
    /// faithful Xray outbound mapping and are refused before startup.
    pub fn xray_carries(&self) -> bool {
        crate::xray::carries_protocol(self)
    }

    /// Whether sing-box can express this outbound.
    ///
    /// Everything but one case: sing-box speaks plain VLESS, without the
    /// ML-KEM handshake Xray added on top, and its outbound grammar has no
    /// field to name one.
    pub fn sing_box_carries(&self) -> bool {
        crate::singbox::carries_protocol(self)
    }
}

/// SOCKS5's UDP-over-TCP framing, which a link spells `uot` and sing-box
/// `udp_over_tcp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uot {
    /// The framing version the link named; `None` is the core's own.
    pub version: Option<u8>,
}

/// How VLESS and VMess frame the UDP traffic they carry, which a link spells
/// `packetEncoding` and sing-box `packet_encoding`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketEncoding {
    PacketAddr,
    Xudp,
    /// Explicitly disable packet-address/XUDP framing where the core permits it.
    Disabled,
}

impl PacketEncoding {
    /// The spelling the link and sing-box's `packet_encoding` share.
    pub fn name(self) -> &'static str {
        match self {
            PacketEncoding::PacketAddr => "packetaddr",
            PacketEncoding::Xudp => "xudp",
            PacketEncoding::Disabled => "",
        }
    }
}

/// Dial-layer settings a link can name for any scheme. Reading them here rather
/// than in each parser is what keeps a scheme whose grammar is otherwise empty
/// (`socks`, `http`) from dropping its query.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DialOptions {
    /// `tfo`: TCP fast open, which both cores set on the socket.
    pub tfo: bool,
    /// `uot`: SOCKS5 UDP over TCP, a sing-box socks-outbound field.
    pub uot: Option<Uot>,
    /// `packetEncoding`: VLESS and VMess UDP framing, a sing-box field.
    pub packet_encoding: Option<PacketEncoding>,
}

impl DialOptions {
    fn parse(query: &Query) -> Result<Self, String> {
        let tfo = ["tfo", "fastopen", "tcpfastopen", "tcp-fast-open"]
            .iter()
            .any(|key| query.flag(key));
        let uot = match query.first(&["uot", "udp-over-tcp", "udp_over_tcp"]) {
            None => None,
            Some(raw) => match raw.to_ascii_lowercase().as_str() {
                "0" | "false" | "no" | "off" => None,
                "1" | "true" | "yes" | "on" => Some(Uot { version: None }),
                other => return Err(format!("uot={other:?} is neither on nor off")),
            },
        };
        // The version implies the framing it belongs to, so a link naming only
        // the version still turns it on.
        let uot = match query.first(&["uotversion", "uot_version", "uot-version"]) {
            None => uot,
            Some(raw) => {
                let version = raw
                    .trim()
                    .parse::<u8>()
                    .ok()
                    .filter(|version| matches!(version, 1 | 2))
                    .ok_or_else(|| format!("uotVersion {raw:?} is not 1 or 2"))?;
                Some(Uot {
                    version: Some(version),
                })
            }
        };
        let packet_encoding = match query.first(&["packetencoding", "packet_encoding"]) {
            None => None,
            Some(raw) => Some(match raw.to_ascii_lowercase().as_str() {
                "packetaddr" | "packet_addr" | "packet" => PacketEncoding::PacketAddr,
                "xudp" => PacketEncoding::Xudp,
                "none" | "" => PacketEncoding::Disabled,
                other => {
                    return Err(format!(
                        "packetEncoding {other:?} is not supported (none, packetaddr, xudp)"
                    ))
                }
            }),
        };
        Ok(Self {
            tfo,
            uot,
            packet_encoding,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    pub protocol: Protocol,
    pub server: String,
    pub port: u16,
    pub transport: Transport,
    pub security: Security,
    /// `fm`: Xray's finalmask, carried as the JSON object the link encoded.
    /// Only Xray-core has the setting.
    pub finalmask: Option<String>,
    /// The settings every scheme can carry on top of its own grammar.
    pub dial: DialOptions,
    /// `#fragment` of the link, carried through for log lines only.
    pub remark: Option<String>,
}

impl Outbound {
    /// Whether `backend` can run this outbound: one answer for the config
    /// editor, the session loader and the bridges, so none of them disagree.
    pub fn carried_by(&self, backend: FcaeBackend) -> bool {
        self.blocker(backend).is_none()
    }

    /// Why `backend` cannot run this outbound, in the words the config editor
    /// shows. Only meaningful when [`Outbound::carried_by`] is false.
    pub fn refusal(&self, backend: FcaeBackend) -> String {
        self.blocker(backend).unwrap_or_else(|| {
            format!(
                "{} can carry this link",
                crate::config::backend_label(backend)
            )
        })
    }

    /// The first setting `backend` cannot express, named along with the core
    /// that can: a link is either carried whole or refused with a reason, never
    /// silently trimmed to what one core happens to understand.
    fn blocker(&self, backend: FcaeBackend) -> Option<String> {
        match backend {
            FcaeBackend::Xray => crate::xray::link_blocker(self),
            FcaeBackend::SingBox => crate::singbox::link_blocker(self),
            FcaeBackend::Mihomo => crate::mihomo::proxy(self).err(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CoreProfile {
    Link(Outbound),
    /// Verbatim native config; the bridge rewrites listeners and log level.
    Native(Value),
}

fn native_json(text: &str) -> Result<Value, String> {
    if let Ok(value) = serde_json::from_str(text) {
        return Ok(value);
    }
    let mut bytes = text.as_bytes().to_vec();
    let mut i = 0;
    let mut quoted = false;
    while i < bytes.len() {
        if quoted {
            match bytes[i] {
                b'\\' => {
                    i += 2;
                    continue;
                }
                b'"' => quoted = false,
                _ => {}
            }
        } else if bytes[i] == b'"' {
            quoted = true;
        } else if bytes[i] == b'#' || (bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/')) {
            while i < bytes.len() && bytes[i] != b'\n' && bytes[i] != b'\r' {
                bytes[i] = b' ';
                i += 1;
            }
            continue;
        } else if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            bytes[i] = b' ';
            bytes[i + 1] = b' ';
            i += 2;
            loop {
                if i + 1 >= bytes.len() {
                    return Err("unterminated JSON block comment".into());
                }
                if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    bytes[i] = b' ';
                    bytes[i + 1] = b' ';
                    i += 2;
                    break;
                }
                if bytes[i] != b'\n' && bytes[i] != b'\r' {
                    bytes[i] = b' ';
                }
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("native config is not valid JSON: {error}"))
}

/// Accept either a complete native document or one native outbound/proxy.
/// Do not rebuild protocol/security settings from an allowlist: the selected
/// embedded core validates its own schema, including new/less common types.
fn normalize_native(mut value: Value, backend: FcaeBackend) -> Result<Value, String> {
    let object = value.as_object().ok_or("native config must be an object")?;
    if [
        "outbounds",
        "endpoints",
        "inbounds",
        "proxies",
        "proxy-groups",
        "proxy-providers",
        "services",
    ]
    .iter()
    .any(|key| object.contains_key(*key))
    {
        return Ok(value);
    }
    let proxy_type = object
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if backend == FcaeBackend::Xray && proxy_type.is_some() {
        return Err(
            "this native outbound uses type, not Xray protocol; select sing-box or Mihomo".into(),
        );
    }
    if backend != FcaeBackend::Xray && object.contains_key("protocol") {
        return Err("this native outbound uses Xray protocol; select Xray".into());
    }
    match backend {
        FcaeBackend::Xray if object.get("protocol").is_some_and(Value::is_string) => {
            Ok(serde_json::json!({"outbounds":[value]}))
        }
        FcaeBackend::SingBox if proxy_type.is_some() => {
            if value.get("protocol").is_some() { return Err("native outbound mixes Xray protocol and sing-box type".into()); }
            let tag = match value.get("tag") {
                None => { value["tag"] = Value::String("FCAE-PROXY".into()); "FCAE-PROXY".to_owned() }
                Some(Value::String(tag)) if !tag.is_empty() => tag.clone(),
                _ => return Err("native outbound tag must be a non-empty string".into()),
            };
            // These are endpoint registrations in the pinned sing-box, not
            // outbounds. Full documents may also carry server-side endpoints.
            let endpoint = matches!(proxy_type.as_deref(), Some("wireguard" | "tailscale" | "openconnect" | "openvpn-client" | "masque-client"));
            if endpoint { Ok(serde_json::json!({"endpoints":[value],"route":{"final":tag}})) }
            else { Ok(serde_json::json!({"outbounds":[value],"route":{"final":tag}})) }
        }
        FcaeBackend::Mihomo if proxy_type.is_some() => {
            let name = match value.get("name") {
                None => { value["name"] = Value::String("FCAE-PROXY".into()); "FCAE-PROXY".to_owned() }
                Some(Value::String(name)) if !name.is_empty() => name.clone(),
                _ => return Err("native proxy name must be a non-empty string".into()),
            };
            if name.contains(',') || name.chars().any(char::is_control) {
                return Err("a standalone Mihomo proxy name cannot contain rule separators; use a full config for this name".into());
            }
            Ok(
                serde_json::json!({"mode":"rule","proxies":[value],"rules":[format!("MATCH,{name}")]}),
            )
        }
        _ => Ok(value),
    }
}

impl CoreProfile {
    /// Resolve verified core-specific URI formats using the selected backend.
    pub fn parse_for_backend(text: &str, backend: FcaeBackend) -> Result<Self, String> {
        let text = text.trim().trim_start_matches('\u{feff}').trim_start();
        let text = unescaped_link(text);
        let text = text.as_ref();
        if let Some(result) = share_links::native_link(text, backend) {
            return result.map(CoreProfile::Native);
        }
        let uri = text.split_once("://").is_some_and(|(scheme, _)| {
            !scheme.is_empty()
                && scheme
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
        });
        let profile = if backend == FcaeBackend::Mihomo && !uri {
            // A single native YAML proxy is as useful as a full proxies list.
            // Complete configurations still pass through unchanged.
            let value = native_json(text).or_else(|_| {
                serde_yaml_ng::from_str::<Value>(text)
                    .map_err(|error| format!("native Mihomo config is invalid: {error}"))
            })?;
            Self::Native(value)
        } else if backend == FcaeBackend::Xray && !uri {
            let value = native_json(text)
                .or_else(|_| serde_yaml_ng::from_str::<Value>(text).map_err(|e| e.to_string()))
                .or_else(|_| {
                    toml::from_str::<Value>(text)
                        .map_err(|e| format!("native Xray config must be JSON, YAML or TOML: {e}"))
                })?;
            Self::Native(value)
        } else {
            Self::parse(text)?
        };
        match profile {
            Self::Native(value) => normalize_native(value, backend).map(Self::Native),
            other => Ok(other),
        }
    }

    /// Parse and validate `core.profile`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim().trim_start_matches('\u{feff}').trim_start();
        let text = unescaped_link(text);
        let text = text.as_ref();
        if text.is_empty() {
            return Err("no profile: set a share link or a native config JSON".into());
        }
        if text.starts_with('{') {
            let value = native_json(text)?;
            if !value.is_object() {
                return Err("native config must be a JSON object".into());
            }
            return Ok(CoreProfile::Native(value));
        }
        if let Ok(value) = serde_yaml_ng::from_str::<Value>(text) {
            if value.is_object() && crate::mihomo::is_native(&value) {
                return Ok(CoreProfile::Native(value));
            }
        }
        if text.starts_with("//") || text.starts_with("/*") || text.starts_with('#') {
            let value = native_json(text)?;
            if !value.is_object() {
                return Err("native config must be a JSON object".into());
            }
            return Ok(CoreProfile::Native(value));
        }
        let Some((scheme, rest)) = text.split_once("://") else {
            return Err(format!(
                "expected a share link (scheme://…) or a JSON object, got {:?}",
                excerpt(text)
            ));
        };
        let scheme = scheme.trim().to_ascii_lowercase();
        share_links::check_encoding(rest)?;
        share_links::check_query(&scheme, rest)?;
        if let Some(result) = share_links::native_link(text, FcaeBackend::Mihomo) {
            return result.map(CoreProfile::Native);
        }
        if matches!(scheme.as_str(), "ssr" | "ssh") {
            return crate::mihomo::parse_link(&scheme, rest).map(CoreProfile::Native);
        }
        let outbound = match scheme.as_str() {
            "vless" => parse_vless(rest)?,
            "vmess" => parse_vmess(rest)?,
            "trojan" => parse_trojan(rest)?,
            "ss" | "shadowsocks" => parse_shadowsocks(rest)?,
            "socks" | "socks5" | "socks5h" => parse_socks(rest)?,
            "http" => parse_http(rest, false)?,
            "https" => parse_http(rest, true)?,
            // Protocol-specific availability is checked against the selected core.
            "hysteria2" | "hy2" => parse_hysteria2(rest)?,
            "tuic" => parse_tuic(rest)?,
            "anytls" => parse_anytls(rest)?,
            "hysteria" | "hy" => parse_hysteria(rest)?,
            "naive" | "naive+https" => parse_naive(rest, false)?,
            "naive+quic" => parse_naive(rest, true)?,
            // Both cores run this one, each in its own shape.
            "wireguard" | "wg" => parse_wireguard(rest)?,
            other => {
                return Err(format!(
                    "unsupported scheme {other:?} (vless, vmess, trojan, ss, socks5, http, \
                     hysteria2, hysteria, tuic, anytls, naive, wireguard, ssh, ssr, snell, mierus, hysteria2+realm)"
                ))
            }
        };
        Ok(CoreProfile::Link(with_dial_options(rest, outbound)?))
    }

    /// Outbound endpoint, when the profile names one.
    pub fn endpoint(&self) -> Option<(&str, u16)> {
        match self {
            CoreProfile::Link(outbound) => Some((outbound.server.as_str(), outbound.port)),
            CoreProfile::Native(_) => None,
        }
    }
}

/// The dial-layer settings a link can name on top of its scheme's own grammar,
/// read once for every scheme and checked against the protocol that will hold
/// them: a setting no config of the core can carry is refused by name.
fn with_dial_options(rest: &str, mut outbound: Outbound) -> Result<Outbound, String> {
    let (body, _) = split_fragment(rest);
    let (_, params) = split_query(body);
    let query = Query::parse(params);
    if !params.is_empty() {
        outbound.dial = DialOptions::parse(&query)?;
    }
    let name = outbound.protocol.name();
    if outbound.dial.uot.is_some()
        && !matches!(
            outbound.protocol,
            Protocol::Socks { .. } | Protocol::Shadowsocks { .. }
        )
    {
        return Err(format!(
            "uot is a socks5 setting or a shadowsocks setting; a {name} link has no field for it"
        ));
    }
    if outbound.dial.packet_encoding.is_some()
        && !matches!(
            outbound.protocol,
            Protocol::Vless { .. } | Protocol::Vmess { .. }
        )
    {
        return Err(format!(
            "packetEncoding is a vless and vmess setting; a {name} link has no field for it"
        ));
    }
    if outbound.dial.tfo
        && matches!(
            outbound.protocol,
            Protocol::WireGuard { .. } | Protocol::Hysteria2 { .. }
        )
    {
        return Err(
            "this protocol dials its peer over UDP; tcp fast open has nothing to open".into(),
        );
    }
    Ok(outbound)
}

/// The core a native config was written for, when its outbounds make it
/// unambiguous.
///
/// The two dialects differ in one place that matters here: an Xray outbound
/// carries a `protocol`, a sing-box outbound a `type` — and sing-box keeps
/// WireGuard and the other endpoints in `endpoints`, whose entries name their
/// type the same way. A config with neither section, an empty one, or one
/// naming both dialects answers `None`.
pub fn native_dialect(text: &str) -> Option<FcaeBackend> {
    let text = text.trim().trim_start_matches('\u{feff}').trim_start();
    let value: Value = native_json(text)
        .ok()
        .or_else(|| serde_yaml_ng::from_str(text).ok())?;
    native_dialect_value(&value)
}

pub(crate) fn native_dialect_value(value: &Value) -> Option<FcaeBackend> {
    if crate::mihomo::is_native(&value) {
        return Some(FcaeBackend::Mihomo);
    }
    let (mut xray, mut sing_box) = (false, false);
    let mut declared = false;
    for section in ["outbounds", "endpoints"] {
        let Some(entries) = value.get(section).and_then(Value::as_array) else {
            continue;
        };
        declared = true;
        for entry in entries {
            let Some(object) = entry.as_object() else {
                continue;
            };
            xray |= object.contains_key("protocol");
            sing_box |= object.contains_key("type");
        }
    }
    if !declared {
        return None;
    }
    match (xray, sing_box) {
        (true, false) => Some(FcaeBackend::Xray),
        (false, true) => Some(FcaeBackend::SingBox),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Link parsers
// ---------------------------------------------------------------------------

fn parse_vless(rest: &str) -> Result<Outbound, String> {
    let (body, remark) = split_fragment(rest);
    let (authority, params) = split_query(body);
    let query = Query::parse(params);
    let (userinfo, target) = authority
        .rsplit_once('@')
        .ok_or("a vless link must be vless://<uuid>@<host>:<port>")?;
    let uuid = percent_decode(userinfo).trim().to_string();
    if !valid_uuid(&uuid) {
        return Err(format!("vless uuid {:?} is not a UUID", excerpt(&uuid)));
    }
    let (server, port) = split_host_port(target, None)?;
    // `encryption` is Xray's own addition: `none`, or its dot config naming the
    // ML-KEM/X25519 handshake. Xray parses the value itself, so this only
    // rejects what the core would reject at start, and only after the editor
    // could have said so.
    let encryption = query
        .get("encryption")
        .map(vless_encryption)
        .transpose()?
        .flatten();
    let flow = query.string("flow");
    if let Some(flow) = flow.as_deref() {
        // The core accepts one flow and nothing else; the `-udp443` variant
        // older links carry is refused rather than passed through as a value
        // the core would exit on.
        if flow != "xtls-rprx-vision" {
            return Err(format!(
                "vless flow={flow:?} is not supported by this core (only xtls-rprx-vision)"
            ));
        }
    }
    let transport = parse_transport(&query)?;
    let security = parse_security(&query, &server, &transport, false)?;
    if flow.is_some() && matches!(security, Security::None) {
        return Err("vless flow requires tls or reality security".into());
    }
    Ok(Outbound {
        protocol: Protocol::Vless {
            uuid,
            flow,
            encryption,
        },
        transport,
        security,
        finalmask: parse_finalmask(&query)?,
        dial: DialOptions::default(),
        server,
        port,
        remark,
    })
}

/// Xray's VLESS encryption value: `none`, or its dot config
/// `mlkem768x25519plus.<native|xorpub|random>.<0rtt|1rtt>.<key>…`.
///
/// The keys are raw URL-safe base64: 32 bytes for X25519, 1184 for an ML-KEM-768
/// encapsulation key. Segments shorter than 20 characters are the padding Xray
/// folds back in with the dots it split on, so they carry no key. This mirrors
/// `infra/conf/vless.go`, which is the only other place that reads the value.
fn vless_encryption(raw: &str) -> Result<Option<String>, String> {
    const SHAPE: &str = "mlkem768x25519plus.<native|xorpub|random>.<0rtt|1rtt>.<key>";
    let text = raw.trim();
    if text.is_empty() || text.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() < 4 || parts[0] != "mlkem768x25519plus" {
        return Err(format!(
            "vless encryption={:?} is not {SHAPE} (an Xray-core link)",
            excerpt(text)
        ));
    }
    if !matches!(parts[1], "native" | "xorpub" | "random") {
        return Err(format!(
            "vless encryption mode {:?} is not native, xorpub or random",
            parts[1]
        ));
    }
    if !matches!(parts[2], "0rtt" | "1rtt") {
        return Err(format!(
            "vless encryption round trip {:?} is not 0rtt or 1rtt",
            parts[2]
        ));
    }
    let mut keys = 0;
    for part in &parts[3..] {
        if part.len() < 20 {
            continue;
        }
        let usable = URL_SAFE_NO_PAD
            .decode(part)
            .is_ok_and(|key| key.len() == 32 || key.len() == 1184);
        if !usable {
            return Err(format!(
                "vless encryption key {:?} is not a base64url X25519 or ML-KEM-768 public key",
                excerpt(part)
            ));
        }
        keys += 1;
    }
    if keys == 0 {
        return Err("vless encryption carries no public key".into());
    }
    Ok(Some(text.to_string()))
}

fn parse_vmess(rest: &str) -> Result<Outbound, String> {
    let (body, remark) = split_fragment(rest);
    // Two shapes carry a vmess outbound: the base64 JSON every client exports,
    // and the URI form that publishes the same settings as a query. A base64
    // blob cannot contain `@`, so the shape decides.
    if split_query(&body).0.rsplit_once('@').is_some() {
        return parse_vmess_uri(&body, remark);
    }
    let decoded = b64_decode(body.trim())
        .ok_or("a vmess link must be vmess://<base64 JSON> or vmess://<uuid>@<host>:<port>?…")?;
    let json: Value = serde_json::from_str(&decoded)
        .map_err(|error| format!("vmess payload is not JSON: {error}"))?;
    let object = json.as_object().ok_or("vmess payload must be an object")?;
    const FIELDS: &[&str] = &[
        "v",
        "ps",
        "add",
        "port",
        "id",
        "aid",
        "scy",
        "net",
        "type",
        "host",
        "path",
        "tls",
        "sni",
        "alpn",
        "fp",
        "insecure",
        "allowInsecure",
        "skip-cert-verify",
        "pbk",
        "sid",
        "spx",
        "pqv",
        "support-x25519mlkem768",
        "ech",
        "pcs",
        "vcn",
        "fm",
        "tfo",
        "packetEncoding",
        "uot",
        "extra",
        "ed",
        "eh",
    ];
    // What a generator adds about the entry itself: what its own test called
    // it, the channel it was published in. No client reads a setting there.
    let label = |key: &str| {
        key == "test_name" || share_links::label_parameter(&key.to_ascii_lowercase())
    };
    if let Some(key) = object
        .keys()
        .find(|key| !FIELDS.contains(&key.as_str()) && !label(key))
    {
        return Err(format!(
            "unsupported VMess JSON field {key:?}; use a native config"
        ));
    }
    for (key, value) in object {
        // `null` is how a generator that always writes the same set of fields
        // leaves one out: the field is absent.
        if value.is_null() || label(key) {
            continue;
        }
        let flag = matches!(
            key.as_str(),
            "insecure"
                | "allowInsecure"
                | "skip-cert-verify"
                | "tfo"
                | "uot"
                | "support-x25519mlkem768"
        );
        let structured = matches!(key.as_str(), "fm" | "extra") && value.is_object();
        let alpn = key == "alpn"
            && value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string));
        if !value.is_string()
            && !value.is_number()
            && !(flag && value.is_boolean())
            && !structured
            && !alpn
        {
            return Err(format!(
                "unsupported value type for VMess JSON field {key:?}; use a native config"
            ));
        }
    }
    let server = json_text(&json, "add").ok_or("vmess payload has no \"add\" server")?;
    let port = parse_port(&json_text(&json, "port").ok_or("vmess payload has no \"port\"")?)?;
    let uuid = json_text(&json, "id").ok_or("vmess payload has no \"id\"")?;
    if !valid_uuid(&uuid) {
        return Err(format!("vmess id {:?} is not a UUID", excerpt(&uuid)));
    }
    let alter_id = json_text(&json, "aid")
        .map(|text| text.parse::<u16>())
        .transpose()
        .map_err(|_| "vmess aid must be 0..65535")?
        .unwrap_or(0);
    let cipher = json_text(&json, "scy").unwrap_or_default();
    // The JSON names the same transports the query grammar does, only under
    // `net`/`path`/`host`, so it is handed to the one parser that knows all of
    // them instead of a second, shorter copy of it. `type` is not one setting:
    // it is the transport's own mode on gRPC and XHTTP, the seed carrier on
    // mKCP and the header obfuscation on plain TCP.
    let network = json_text(&json, "net")
        .map(|net| net.to_ascii_lowercase())
        .unwrap_or_else(|| "tcp".into());
    let kind = json_text(&json, "type");
    let mut params = Query::new();
    params.set("type", Some(network.clone()));
    match network.as_str() {
        "tcp" | "raw" | "none" => params.set("headertype", kind),
        "kcp" | "mkcp" => {
            params.set("headertype", kind);
            // The seed lives in `path` in this grammar; the core removed it
            // along with the header, so it is reported rather than dropped.
            if let Some(seed) = json_text(&json, "path") {
                return Err(format!(
                    "the vmess mKCP seed {:?} was removed from Xray-core (finalmask replaced it)",
                    excerpt(&seed)
                ));
            }
        }
        "grpc" | "gun" => {
            params.set("mode", kind);
            params.set("servicename", json_text(&json, "path"));
            params.set("authority", json_text(&json, "host"));
        }
        "xhttp" | "splithttp" => {
            params.set("mode", kind);
            params.set("path", json_text(&json, "path"));
            params.set("host", json_text(&json, "host"));
        }
        _ => {
            params.set("path", json_text(&json, "path"));
            params.set("host", json_text(&json, "host"));
        }
    }
    for key in [
        "sni",
        "alpn",
        "fp",
        "insecure",
        "pbk",
        "sid",
        "spx",
        "pqv",
        "support-x25519mlkem768",
        "ech",
        "pcs",
        "vcn",
        "tfo",
        "packetEncoding",
        "uot",
        "extra",
        "ed",
        "eh",
    ] {
        let value = match json.get(key) {
            Some(Value::Bool(flag)) => Some(if *flag { "1" } else { "0" }.to_owned()),
            Some(Value::Array(items)) if key == "alpn" => Some(
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            Some(value) if key == "extra" && value.is_object() => Some(value.to_string()),
            _ => json_text(&json, key),
        };
        params.set(&key.to_ascii_lowercase(), value);
    }
    // `skip-cert-verify` is the same flag under the name Clash gives it;
    // generators that write both formats carry it over.
    params.set(
        "allowinsecure",
        ["allowInsecure", "skip-cert-verify"]
            .into_iter()
            .find_map(|key| match json.get(key)? {
                Value::Bool(flag) => Some(if *flag { "1" } else { "0" }.to_owned()),
                _ => json_text(&json, key),
            }),
    );
    if let Some(fm) = json.get("fm").filter(|fm| !fm.is_null()) {
        params.set(
            "fm",
            Some(if fm.is_object() {
                fm.to_string()
            } else {
                fm.as_str()
                    .ok_or("VMess fm must be an object or JSON string")?
                    .to_owned()
            }),
        );
    }
    params.set("security", json_text(&json, "tls"));
    share_links::check_vmess_params(&params)?;
    let transport = parse_transport(&params)?;
    let security = parse_security(&params, &server, &transport, false)?;
    Ok(Outbound {
        protocol: Protocol::Vmess {
            uuid,
            alter_id,
            security: vmess_security(&cipher)?,
        },
        transport,
        security,
        finalmask: parse_finalmask(&params)?,
        dial: DialOptions::parse(&params)?,
        server,
        port,
        remark,
    })
}

/// `vmess://<uuid>@<host>:<port>?type=…&security=…`: the same outbound as the
/// JSON form, spelled as a query. Its credentials carry no cipher, so the core
/// default is what it runs.
fn parse_vmess_uri(body: &str, remark: Option<String>) -> Result<Outbound, String> {
    let (authority, params) = split_query(body);
    let query = Query::parse(params);
    let (userinfo, target) = authority
        .rsplit_once('@')
        .ok_or("a vmess link must be vmess://<uuid>@<host>:<port>")?;
    let uuid = percent_decode(userinfo).trim().to_string();
    if !valid_uuid(&uuid) {
        return Err(format!("vmess id {:?} is not a UUID", excerpt(&uuid)));
    }
    let (server, port) = split_host_port(target, None)?;
    let transport = parse_transport(&query)?;
    // Settled before the struct takes `transport`: the name the security layer
    // presents is the one the transport already puts on the wire.
    let security = parse_security(&query, &server, &transport, false)?;
    Ok(Outbound {
        protocol: Protocol::Vmess {
            uuid,
            alter_id: query
                .number("aid")?
                .map(u16::try_from)
                .transpose()
                .map_err(|_| "vmess aid exceeds 65535")?
                .unwrap_or(0),
            security: vmess_security(query.first(&["scy", "encryption"]).unwrap_or_default())?,
        },
        transport,
        security,
        finalmask: parse_finalmask(&query)?,
        dial: DialOptions::default(),
        server,
        port,
        remark,
    })
}

/// VMess's packet cipher, spelled the way both cores accept it.
///
/// Xray-core knows four of them and silently falls back to `auto` for anything
/// else, while sing-box refuses a value outside its enum outright — so a link
/// that names a cipher neither implements is reported here, and the one cipher
/// only sing-box still carries is left to [`Protocol::xray_carries`].
fn vmess_security(raw: &str) -> Result<String, String> {
    let cipher = match raw.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => "auto",
        "none" | "plain" => "none",
        "zero" => "zero",
        "aes-128-gcm" | "aes128gcm" => "aes-128-gcm",
        "chacha20-poly1305" | "chacha20-ietf-poly1305" | "chacha20poly1305" => "chacha20-poly1305",
        "aes-128-cfb" => "aes-128-cfb",
        other => {
            return Err(format!(
                "vmess security {other:?} is not a cipher these cores implement"
            ))
        }
    };
    Ok(cipher.to_string())
}

fn parse_trojan(rest: &str) -> Result<Outbound, String> {
    let (body, remark) = split_fragment(rest);
    let (authority, params) = split_query(body);
    let query = Query::parse(params);
    let (userinfo, target) = authority
        .rsplit_once('@')
        .ok_or("a trojan link must be trojan://<password>@<host>:<port>")?;
    let password = percent_decode(userinfo);
    if password.is_empty() {
        return Err("trojan password is empty".into());
    }
    // Trojan's own `flow` was an XTLS Vision variant of the protocol and is
    // gone from the core; a link that still asks for one is reported instead of
    // connecting without it.
    if let Some(flow) = query.get("flow").filter(|flow| !flow.is_empty()) {
        return Err(format!(
            "trojan flow={flow:?} was removed from Xray-core \
             (use a VLESS link with xtls-rprx-vision)"
        ));
    }
    let (server, port) = split_host_port(target, None)?;
    let transport = parse_transport(&query)?;
    // Trojan is TLS by definition; links routinely omit `security=tls`. Settled
    // before the struct takes `transport`: the name the security layer presents
    // is the one the transport already puts on the wire.
    let security = parse_security(&query, &server, &transport, true)?;
    Ok(Outbound {
        protocol: Protocol::Trojan { password },
        transport,
        security,
        finalmask: parse_finalmask(&query)?,
        dial: DialOptions::default(),
        server,
        port,
        remark,
    })
}

fn parse_shadowsocks(rest: &str) -> Result<Outbound, String> {
    let (body, remark) = split_fragment(rest);
    let (body, params) = split_query(body);
    let query = Query::parse(params);
    let (credentials, target) = match body.rsplit_once('@') {
        Some((credentials, target)) => (decode_credentials(credentials), target.to_string()),
        None => {
            let decoded = b64_decode(body).ok_or(
                "a ss link must be ss://<base64(method:password)>@host:port \
                 or ss://<base64(method:password@host:port)>",
            )?;
            let (credentials, target) = decoded
                .rsplit_once('@')
                .ok_or("ss credentials must be method:password@host:port")?;
            (credentials.to_string(), target.to_string())
        }
    };
    let (method, password) = credentials
        .split_once(':')
        .ok_or("ss credentials must be method:password")?;
    if method.trim().is_empty() || password.is_empty() {
        return Err("ss credentials must be method:password".into());
    }
    let (server, port) = split_host_port(&target, None)?;
    Ok(Outbound {
        protocol: Protocol::Shadowsocks {
            method: method.trim().to_ascii_lowercase(),
            password: password.to_string(),
            plugin: parse_ss_plugin(&query)?,
        },
        transport: Transport::Tcp,
        security: Security::None,
        finalmask: None,
        dial: DialOptions::default(),
        server,
        port,
        remark,
    })
}

fn parse_socks(rest: &str) -> Result<Outbound, String> {
    let (body, remark) = split_fragment(rest);
    let (body, _params) = split_query(body);
    let (userinfo, target) = match body.rsplit_once('@') {
        Some((userinfo, target)) => (Some(userinfo), target),
        None => (None, body),
    };
    let (server, port) = split_host_port(target, Some(1080))?;
    let (user, password) = split_credentials(userinfo);
    Ok(Outbound {
        protocol: Protocol::Socks { user, password },
        transport: Transport::Tcp,
        security: Security::None,
        server,
        port,
        finalmask: None,
        dial: DialOptions::default(),
        remark,
    })
}

fn parse_http(rest: &str, tls: bool) -> Result<Outbound, String> {
    let (body, remark) = split_fragment(rest);
    let (body, params) = split_query(body);
    let mut query = Query::parse(params);
    let (userinfo, target) = match body.rsplit_once('@') {
        Some((userinfo, target)) => (Some(userinfo), target),
        None => (None, body),
    };
    let (server, port) = split_host_port(target, Some(if tls { 443 } else { 8080 }))?;
    let (user, password) = split_credentials(userinfo);
    // `https` states its own security, so a stray `security=none` in the query
    // cannot quietly turn it into a plaintext proxy; everything else the link
    // names (SNI, ALPN, a fingerprint) is read by the grammar every other
    // scheme uses.
    let security = if tls {
        query.remove("security");
        parse_security(&query, &server, &Transport::Tcp, true)?
    } else {
        Security::None
    };
    Ok(Outbound {
        protocol: Protocol::Http { user, password },
        transport: Transport::Tcp,
        security,
        server,
        port,
        finalmask: None,
        dial: DialOptions::default(),
        remark,
    })
}

// ---------------------------------------------------------------------------
// sing-box share links
// ---------------------------------------------------------------------------
//
// QUIC and TLS-native share links. The selected core's mapping is checked
// independently; Hysteria2 is supported on all three pinned cores.

fn parse_hysteria2(rest: &str) -> Result<Outbound, String> {
    let (body, remark) = split_fragment(rest);
    let (authority, params) = split_query(body);
    let query = Query::parse(params);
    let (userinfo, target) = authority.rsplit_once('@').unwrap_or(("", authority));
    let password = percent_decode(userinfo);
    let password = match query.get("auth") {
        Some(auth) if password.is_empty() || password == auth => auth.to_owned(),
        Some(_) => return Err("hysteria2 auth conflicts with the URI credentials".into()),
        None => password,
    };
    let (server, port, authority_ports) = share_links::hy2_address(trim_trailing_path(target))?;
    let query_ports = query.ports(&["mport", "ports"])?;
    if !authority_ports.is_empty() && !query_ports.is_empty() {
        return Err("hysteria2 ports are specified both in the authority and query".into());
    }
    let ports = if authority_ports.is_empty() {
        query_ports
    } else {
        authority_ports
    };
    // `salamander` is the original scheme and `gecko` the one that pads every
    // packet into a window; both need their password, and gecko takes the size
    // of that window from the link when it names one.
    let obfs = match query.string("obfs").map(|kind| kind.to_ascii_lowercase()) {
        None => None,
        Some(kind) => {
            if !matches!(kind.as_str(), "salamander" | "gecko") {
                return Err(format!(
                    "hysteria2 obfs {kind:?} is not supported (salamander, gecko)"
                ));
            }
            let secret = query
                .first(&["obfs-password", "obfs_password"])
                .ok_or_else(|| format!("hysteria2 obfs={kind} needs obfs-password"))?;
            let (min_packet_size, max_packet_size) = if kind == "gecko" {
                let min = query.number("minpacketsize")?;
                let max = query.number("maxpacketsize")?;
                if min.zip(max).is_some_and(|(min, max)| min > max) {
                    return Err("hysteria2 gecko minPacketSize is larger than maxPacketSize".into());
                }
                (min, max)
            } else {
                (None, None)
            };
            Some(Obfs {
                kind,
                password: secret.to_string(),
                min_packet_size,
                max_packet_size,
            })
        }
    };
    tls_by_contract(&query, "hysteria2")?;
    share_links::check_hy2_query(params)?;
    Ok(Outbound {
        protocol: Protocol::Hysteria2 {
            password,
            obfs,
            up_mbps: query.mbps(&["up", "upmbps", "up_mbps"])?,
            down_mbps: query.mbps(&["down", "downmbps", "down_mbps"])?,
            ports,
            hop_interval: query.seconds(&["hop-interval", "hop_interval"])?,
            pin: query.pin()?,
        },
        transport: Transport::Tcp,
        security: tls_security(
            query
                .string("sni")
                .or_else(|| query.string("peer"))
                .or_else(|| host_name(&server)),
            query.list("alpn"),
            None,
            query.flag("insecure") || query.flag("allowinsecure"),
            Some(&query),
        ),
        server,
        port,
        finalmask: parse_finalmask(&query)?,
        dial: DialOptions::default(),
        remark,
    })
}

fn parse_tuic(rest: &str) -> Result<Outbound, String> {
    let (body, remark) = split_fragment(rest);
    let (authority, params) = split_query(body);
    let query = Query::parse(params);
    let (userinfo, target) = authority
        .rsplit_once('@')
        .ok_or("a tuic link must be tuic://<uuid>:<password>@<host>:<port>")?;
    let (raw_uuid, raw_password) = userinfo
        .split_once(':')
        .ok_or("a tuic link must be tuic://<uuid>:<password>@<host>:<port>")?;
    let uuid = percent_decode(raw_uuid).trim().to_string();
    if !valid_uuid(&uuid) {
        return Err(format!("tuic uuid {:?} is not a UUID", excerpt(&uuid)));
    }
    let (server, port) = split_host_port(trim_trailing_path(target), None)?;
    let congestion_control = query
        .string("congestion_control")
        .or_else(|| query.string("congestion-control"));
    if let Some(control) = congestion_control.as_deref() {
        if !matches!(control, "cubic" | "new_reno" | "bbr") {
            return Err(format!(
                "tuic congestion control {control:?} is not supported (cubic, new_reno, bbr)"
            ));
        }
    }
    let udp_relay_mode = query
        .string("udp_relay_mode")
        .or_else(|| query.string("udp-relay-mode"));
    if let Some(mode) = udp_relay_mode.as_deref() {
        if !matches!(mode, "native" | "quic") {
            return Err(format!(
                "tuic udp relay mode {mode:?} is not supported (native, quic)"
            ));
        }
    }
    tls_by_contract(&query, "tuic")?;
    Ok(Outbound {
        protocol: Protocol::Tuic {
            uuid,
            password: percent_decode(raw_password),
            congestion_control,
            udp_relay_mode,
            disable_sni: query.boolean("disable_sni")?.unwrap_or(false),
            zero_rtt: query.flag("zero_rtt_handshake")
                || query.flag("zero-rtt-handshake")
                || query.flag("reduce_rtt"),
        },
        transport: Transport::Tcp,
        security: tls_security(
            query.string("sni").or_else(|| host_name(&server)),
            query.list("alpn"),
            query.string("fp"),
            query.flag("insecure") || query.flag("allow_insecure") || query.flag("allowinsecure"),
            Some(&query),
        ),
        server,
        port,
        finalmask: None,
        dial: DialOptions::default(),
        remark,
    })
}

fn parse_anytls(rest: &str) -> Result<Outbound, String> {
    let (body, remark) = split_fragment(rest);
    let (authority, params) = split_query(body);
    let query = Query::parse(params);
    let (userinfo, target) = authority.rsplit_once('@').unwrap_or(("", authority));
    let password = percent_decode(userinfo);
    let (server, port) = split_host_port(trim_trailing_path(target), Some(443))?;
    tls_by_contract(&query, "anytls")?;
    Ok(Outbound {
        protocol: Protocol::AnyTls { password },
        transport: Transport::Tcp,
        security: tls_security(
            query
                .string("sni")
                .or_else(|| query.string("peer"))
                .or_else(|| host_name(&server)),
            query.list("alpn"),
            query.string("fp"),
            query.flag("insecure") || query.flag("allowinsecure"),
            Some(&query),
        ),
        server,
        port,
        finalmask: None,
        dial: DialOptions::default(),
        remark,
    })
}

/// Hysteria v1, which sing-box's `hysteria` outbound implements: the auth, the
/// XPlus obfuscation password and the bandwidth Brutal shapes to.
fn parse_hysteria(rest: &str) -> Result<Outbound, String> {
    let (body, remark) = split_fragment(rest);
    let (authority, params) = split_query(body);
    let query = Query::parse(params);
    // The authentication string is a query parameter in this scheme; a link
    // that spells it in the authority is read the same way, and one that does
    // both is refused rather than guessed at.
    let (userinfo, target) = match authority.rsplit_once('@') {
        Some((userinfo, target)) => (Some(userinfo), target),
        None => (None, authority),
    };
    let auth = match (query.string("auth"), userinfo) {
        (Some(auth), None) => Some(auth),
        (Some(_), Some(_)) => {
            return Err(
                "a hysteria link carries auth in the authority or as a parameter, not both".into(),
            )
        }
        (None, Some(userinfo)) => Some(percent_decode(userinfo)),
        (None, None) => None,
    };
    let (server, port) = split_host_port(trim_trailing_path(target), Some(443))?;
    // sing-box's hysteria always carries its QUIC datagrams; the `protocol` a v1
    // link names is the packet obfuscation the original client grew out of, and
    // only `udp` matches what sing-box puts on the wire.
    if let Some(protocol) = query.string("protocol") {
        if !protocol.eq_ignore_ascii_case("udp") {
            return Err(format!(
                "hysteria protocol={protocol:?} is not one sing-box implements (udp)"
            ));
        }
    }
    let obfs = match query.string("obfs") {
        None => {
            if query.first(&["obfsparam", "obfs_param"]).is_some() {
                return Err("hysteria obfsParam needs obfs=xplus".into());
            }
            None
        }
        Some(kind) if kind.eq_ignore_ascii_case("xplus") => {
            let password = query
                .first(&["obfsparam", "obfs_param"])
                .ok_or("hysteria obfs=xplus needs obfsParam, its password")?;
            Some(password.to_string())
        }
        Some(kind) => {
            return Err(format!(
                "hysteria obfs={kind:?} is not one sing-box implements (xplus)"
            ))
        }
    };
    // Brutal shapes the tunnel to a bandwidth the link names, and sing-box's
    // hysteria client refuses to start without one.
    let up_mbps = query
        .mbps(&["up", "upmbps", "up_mbps"])?
        .ok_or("a hysteria link needs upmbps, the bandwidth Brutal shapes to")?;
    let down_mbps = query
        .mbps(&["down", "downmbps", "down_mbps"])?
        .ok_or("a hysteria link needs downmbps, the bandwidth Brutal shapes to")?;
    tls_by_contract(&query, "hysteria")?;
    Ok(Outbound {
        protocol: Protocol::Hysteria {
            auth,
            obfs,
            up_mbps,
            down_mbps,
            ports: query.ports(&["mport", "mports", "ports"])?,
            hop_interval: query.seconds(&["hop-interval", "hop_interval"])?,
            pin: query.pin()?,
        },
        transport: Transport::Tcp,
        security: tls_security(
            query
                .string("sni")
                .or_else(|| query.string("peer"))
                .or_else(|| host_name(&server)),
            query.list("alpn"),
            None,
            query.flag("insecure") || query.flag("allowinsecure"),
            Some(&query),
        ),
        server,
        port,
        finalmask: None,
        dial: DialOptions::default(),
        remark,
    })
}

/// NaiveProxy. Chromium performs the handshake itself, so the TLS block carries
/// a name and nothing else, and the two shapes differ only in their framing.
fn parse_naive(rest: &str, quic: bool) -> Result<Outbound, String> {
    let (body, remark) = split_fragment(rest);
    let (authority, params) = split_query(body);
    let query = Query::parse(params);
    let (userinfo, target) = match authority.rsplit_once('@') {
        Some((userinfo, target)) => (Some(userinfo), target),
        None => (None, authority),
    };
    let (server, port) = split_host_port(trim_trailing_path(target), Some(443))?;
    let (user, password) = split_credentials(userinfo);
    // The traffic shape is the point of the protocol: sing-box hands the
    // connection to cronet, which refuses every handshake setting it cannot
    // mirror from Chrome.
    for (key, what) in [
        ("insecure", "allowInsecure"),
        ("allowinsecure", "allowInsecure"),
        ("alpn", "alpn"),
        ("fp", "uTLS fingerprint"),
    ] {
        if query.get(key).is_some() {
            return Err(format!(
                "naive takes no {what}: Chromium performs the handshake"
            ));
        }
    }
    tls_by_contract(&query, "naive")?;
    Ok(Outbound {
        protocol: Protocol::Naive {
            user,
            password,
            quic,
        },
        transport: Transport::Tcp,
        security: tls_security(
            query
                .string("sni")
                .or_else(|| query.string("peer"))
                .or_else(|| host_name(&server)),
            Vec::new(),
            None,
            false,
            Some(&query),
        ),
        server,
        port,
        finalmask: None,
        dial: DialOptions::default(),
        remark,
    })
}

/// WireGuard, in the shape share links spell it: the private key in the
/// authority, the peer's key and the interface address in the query.
fn parse_wireguard(rest: &str) -> Result<Outbound, String> {
    let (body, remark) = split_fragment(rest);
    let (authority, params) = split_query(body);
    let query = Query::parse(params);
    // A WireGuard link describes a bare tunnel. A transport or a TLS layer named
    // on one has nowhere to go, so it is reported rather than dropped.
    if let Some(network) = query.get("type").or_else(|| query.get("net")) {
        if !matches!(
            network.to_ascii_lowercase().as_str(),
            "tcp" | "raw" | "none"
        ) {
            return Err(format!(
                "a wireguard link has no transport layer; type={network:?} cannot be honoured"
            ));
        }
    }
    if let Some(security) = query.get("security") {
        if !security.eq_ignore_ascii_case("none") {
            return Err(format!(
                "a wireguard link has no TLS layer; security={security:?} cannot be honoured"
            ));
        }
    }
    // Xray-core's wireguard handler dials the peer through its own bind and
    // never consults finalmask, so an `fm` here would be silently ignored.
    if query.get("fm").is_some() {
        return Err(
            "finalmask (fm) does not reach a wireguard outbound: it dials its peer directly".into(),
        );
    }
    let (userinfo, target) = authority
        .rsplit_once('@')
        .ok_or("a wireguard link must be wireguard://<private-key>@<host>:<port>")?;
    let secret_key = wireguard_key(&percent_decode(userinfo), "the wireguard private key")?;
    let (server, port) = split_host_port(trim_trailing_path(target), Some(51820))?;
    let public_key = wireguard_key(
        query
            .first(&[
                "publickey",
                "public_key",
                "peer_public_key",
                "peerpublickey",
            ])
            .ok_or("a wireguard link needs publickey, the key its peer is verified against")?,
        "the wireguard public key",
    )?;
    let preshared_key = query
        .first(&["presharedkey", "preshared_key", "pre_shared_key", "psk"])
        .map(|key| wireguard_key(key, "the wireguard preshared key"))
        .transpose()?;
    let address = query
        .first(&["address", "local_address", "ip"])
        .ok_or("a wireguard link needs address, the address its interface is given")?
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| wireguard_cidr(item, "the wireguard address", true))
        .collect::<Result<Vec<_>, String>>()?;
    if address.is_empty() {
        return Err("a wireguard link needs address, the address its interface is given".into());
    }
    let allowed_ips = match query.first(&["allowedips", "allowed_ips", "allowed-ips"]) {
        Some(list) => list
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(|item| wireguard_cidr(item, "the wireguard allowedips entry", false))
            .collect::<Result<Vec<_>, String>>()?,
        None => Vec::new(),
    };
    let keepalive = match query.first(&[
        "persistent-keepalive-interval",
        "persistent_keepalive_interval",
        "persistent-keepalive",
        "persistent_keepalive",
        "keepalive-interval",
        "keepalive_interval",
        "keepalive",
    ]) {
        Some(raw) => {
            let seconds = raw
                .trim()
                .trim_end_matches(['s', 'S'])
                .parse::<u16>()
                .map_err(|_| format!("wireguard keepalive {raw:?} is not 1–65535 seconds"))?;
            Some(u32::from(seconds))
        }
        None => None,
    };
    Ok(Outbound {
        protocol: Protocol::WireGuard {
            secret_key,
            address,
            peer: WireGuardPeer {
                public_key,
                preshared_key,
                allowed_ips,
                keepalive,
            },
            mtu: query.number("mtu")?.filter(|mtu| *mtu > 0),
            reserved: match query.first(&["reserved"]) {
                Some(raw) => wireguard_reserved(raw)?,
                None => Vec::new(),
            },
        },
        transport: Transport::Tcp,
        security: Security::None,
        finalmask: None,
        dial: DialOptions::default(),
        server,
        port,
        remark,
    })
}

pub(crate) fn certificate_pins(text: &str) -> Result<Vec<String>, String> {
    let mut pins = Vec::new();
    for pin in text.split(',') {
        let bytes = hex_decode(&pin.trim().replace(':', ""))
            .filter(|bytes| bytes.len() == 32)
            .ok_or("certificate pin must be a 32-byte SHA-256 hex digest")?;
        pins.push(STANDARD.encode(bytes));
    }
    Ok(pins)
}

/// A WireGuard key: base64 in either alphabet, padded or not, or the 64-hex form
/// Xray-core also takes. Normalised to padded standard base64, which both cores
/// decode; a key of the wrong width is refused rather than handed to a core that
/// would refuse it at start.
fn wireguard_key(raw: &str, what: &str) -> Result<String, String> {
    let text = raw.trim();
    let key = match hex_decode(text) {
        Some(bytes) if text.len() == 64 => bytes,
        _ => b64_bytes(text)
            .ok_or_else(|| format!("{what} {:?} is not a base64 key", excerpt(text)))?,
    };
    if key.len() != 32 {
        return Err(format!(
            "{what} is {} bytes; a WireGuard key is 32",
            key.len()
        ));
    }
    Ok(STANDARD.encode(key))
}

/// A CIDR both cores' grammars take. `single_host` is the interface address,
/// which Xray-core accepts only at full width.
fn wireguard_cidr(raw: &str, what: &str, single_host: bool) -> Result<String, String> {
    let text = raw.trim();
    let (address, bits) = match text.split_once('/') {
        Some((address, bits)) => (address, Some(bits)),
        None => (text, None),
    };
    let address: IpAddr = address
        .parse()
        .map_err(|_| format!("{what} {text:?} is not an IP address"))?;
    let width = if address.is_ipv4() { 32 } else { 128 };
    let bits = match bits {
        Some(bits) => bits
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|bits| *bits <= width)
            .ok_or_else(|| format!("{what} {text:?} has no prefix length within /{width}"))?,
        None => width,
    };
    if single_host && bits != width {
        return Err(format!(
            "{what} {text:?} must name a single host (/{width})"
        ));
    }
    Ok(format!("{address}/{bits}"))
}

/// WARP's reserved bytes, which both cores take as exactly three or not at all.
fn wireguard_reserved(raw: &str) -> Result<Vec<u8>, String> {
    let text = raw.trim().trim_start_matches('[').trim_end_matches(']');
    let bytes = text
        .split(',')
        .map(|item| {
            item.trim()
                .parse::<u8>()
                .map_err(|_| format!("the wireguard reserved field {raw:?} is not three bytes"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    if bytes.len() != 3 {
        return Err(format!(
            "the wireguard reserved field {raw:?} is {} bytes; the field is three",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// `hysteria2://…@host:443/?…` and friends carry a path separator no other
/// scheme uses; the authority ends at it.
pub(crate) fn trim_trailing_path(target: &str) -> &str {
    target.trim_end_matches('/')
}

/// Split a transport path into the part the core requests and the early-data
/// count it was asked for.
///
/// Xray spells early data as an `ed` query inside the path and strips it before
/// the request goes out; sing-box has a field for the count instead and knows
/// nothing about the query. The path is normalised to what each core should
/// request, so neither sees the other's spelling.
fn split_early_data(path: &str) -> (String, Option<u32>) {
    let Some((base, query)) = path.split_once('?') else {
        return (path.to_string(), None);
    };
    let mut kept = String::new();
    let mut count = None;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        if let Some((key, value)) = pair.split_once('=') {
            if key.eq_ignore_ascii_case("ed") {
                count = count.or_else(|| value.trim().parse::<u32>().ok().filter(|ed| *ed > 0));
                continue;
            }
        }
        if !kept.is_empty() {
            kept.push('&');
        }
        kept.push_str(pair);
    }
    let mut path = base.to_string();
    if !kept.is_empty() {
        path.push('?');
        path.push_str(&kept);
    }
    (path, count)
}

/// The plain TCP transport's own header obfuscation.
///
/// Xray still parses it, but a link can only name the shape (`http`), never the
/// request and response templates the core needs to build one, so a link that
/// asks for it is reported instead of being run without the header it expects.
fn plain_tcp_header(query: &Query) -> Result<(), String> {
    match query.get("headertype") {
        Some(kind) if !kind.eq_ignore_ascii_case("none") => Err(format!(
            "the TCP headerType={kind:?} needs request and response templates a link cannot carry; \
             use finalmask (fm)"
        )),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Shared link grammar
// ---------------------------------------------------------------------------

fn parse_transport(query: &Query) -> Result<Transport, String> {
    let network = query
        .get("type")
        .or_else(|| query.get("net"))
        .unwrap_or("tcp")
        .to_ascii_lowercase();
    // Early data is a count plus, on sing-box, the header it rides in. Links
    // spell the count either as its own parameter or — Xray's own way — as an
    // `ed` query inside the path, so the path is normalised here and the count
    // is what the generators re-emit in each core's own grammar.
    let (path, path_early_data) =
        split_early_data(&query.string("path").unwrap_or_else(|| "/".into()));
    let host = query.string("host");
    let max_early_data = query
        .number("ed")?
        .or(query.number("maxearlydata")?)
        .or(path_early_data)
        .filter(|count| *count > 0);
    if matches!(network.as_str(), "grpc" | "gun") {
        if query
            .get("mode")
            .is_some_and(|mode| !matches!(mode, "gun" | "multi" | "none"))
        {
            return Err("gRPC mode must be gun or multi".into());
        }
    }
    let transport = match network.as_str() {
        // `raw` is the name Xray 25.x gave the plain TCP transport.
        "tcp" | "raw" | "none" => {
            plain_tcp_header(query)?;
            Transport::Tcp
        }
        "quic" => Transport::Quic,
        "ws" => Transport::Ws {
            path,
            host,
            max_early_data,
            early_data_header: query.string("eh"),
        },
        "httpupgrade" => Transport::HttpUpgrade {
            path,
            host,
            max_early_data,
        },
        "h2" | "http" => Transport::H2 {
            path,
            host,
            method: query.string("method"),
        },
        "grpc" | "gun" => Transport::Grpc {
            service: query.string("servicename").unwrap_or_default(),
            authority: query.string("authority"),
            multi_mode: query
                .get("mode")
                .is_some_and(|mode| mode.eq_ignore_ascii_case("multi")),
        },
        // mKCP. Xray-core removed the header and seed fields the transport used
        // to have, and refuses a config that still names them, so a link that
        // does is reported here instead of at start.
        "kcp" | "mkcp" => {
            if let Some(kind) = query
                .get("headertype")
                .filter(|kind| !kind.eq_ignore_ascii_case("none"))
            {
                return Err(format!(
                    "mKCP headerType={kind:?} was removed from Xray-core (finalmask replaced it)"
                ));
            }
            if query.get("seed").is_some() {
                return Err("mKCP seed was removed from Xray-core (finalmask replaced it)".into());
            }
            Transport::Kcp {
                mtu: query.number("mtu")?,
                tti: query.number("tti")?,
                uplink_capacity: query.number("uplinkcapacity")?,
                downlink_capacity: query.number("downlinkcapacity")?,
                congestion: query.boolean("congestion")?,
                read_buffer: query.number("readbuffersize")?,
                write_buffer: query.number("writebuffersize")?,
            }
        }
        // XHTTP. Everything past path, host and mode is the core's own settings
        // object, which the link carries as one URL-encoded JSON value.
        "xhttp" | "splithttp" => {
            let extra = match query.get("extra") {
                Some(raw) => {
                    let value: Value = serde_json::from_str(raw)
                        .map_err(|error| format!("xhttp extra is not JSON: {error}"))?;
                    if !value.is_object() {
                        return Err("xhttp extra must be a JSON object".into());
                    }
                    Some(value.to_string())
                }
                None => None,
            };
            // The core knows four modes and refuses a config that names another
            // one, so the link is checked here where the message can say so.
            let mode = query.string("mode");
            if let Some(mode) = mode.as_deref() {
                const MODES: [&str; 4] = ["auto", "packet-up", "stream-up", "stream-one"];
                if !MODES.contains(&mode) {
                    return Err(format!(
                        "xhttp mode={mode:?} is not one Xray-core runs \
                         (auto, packet-up, stream-up, stream-one)"
                    ));
                }
            }
            Transport::Xhttp {
                path,
                host,
                mode,
                extra,
            }
        }
        other => {
            return Err(format!(
                "unsupported transport {other:?} (tcp, ws, httpupgrade, h2, grpc, kcp, xhttp)"
            ))
        }
    };
    Ok(transport)
}

fn parse_security(
    query: &Query,
    server: &str,
    transport: &Transport,
    implicit_tls: bool,
) -> Result<Security, String> {
    // The name a certificate is issued for. Links spell it out in `sni` only
    // when it differs from the host the transport already presents, so a
    // fronted config — a WebSocket `host`, an `h2` authority, a gRPC authority
    // — is measured against that host and not against the address it dials,
    // which is very often an origin server the certificate has never heard of.
    let server_name = || {
        query
            .string("sni")
            .or_else(|| query.string("peer"))
            .or_else(|| transport.presented_host().and_then(domain_name))
            .or_else(|| host_name(server))
    };
    let mode = query
        .get("security")
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| {
            if implicit_tls {
                "tls".into()
            } else {
                "none".into()
            }
        });
    match mode.as_str() {
        "" | "none" => Ok(Security::None),
        "tls" | "xtls" => Ok(Security::Tls {
            sni: server_name(),
            alpn: query.list("alpn"),
            fingerprint: query.string("fp"),
            allow_insecure: query.flag("allowinsecure") || query.flag("insecure"),
            pinned_cert_sha256: query.string("pcs"),
            verify_cert_by_name: query.string("vcn"),
            ech: query.string("ech"),
        }),
        "reality" => {
            let public_key = query
                .string("pbk")
                .ok_or("reality needs pbk (the server public key)")?;
            let sni = server_name().ok_or("reality needs sni (the camouflaged server name)")?;
            // `spx` is the path the camouflage crawler is shown; the core
            // refuses anything that is not a path, so a link naming one is
            // reported here.
            let spider_x = query.string("spx").unwrap_or_else(|| "/".into());
            if !spider_x.starts_with('/') {
                return Err(format!(
                    "reality spx={:?} must be a path, starting with /",
                    excerpt(&spider_x)
                ));
            }
            Ok(Security::Reality {
                sni,
                fingerprint: query.string("fp").unwrap_or_else(|| "chrome".into()),
                public_key,
                short_id: query.string("sid").unwrap_or_default(),
                spider_x,
                mldsa65_verify: query.string("pqv"),
                support_x25519mlkem768: query
                    .get("support-x25519mlkem768")
                    .map(|_| query.flag("support-x25519mlkem768")),
            })
        }
        other => Err(format!(
            "unsupported security {other:?} (none, tls, reality)"
        )),
    }
}

/// A `tls` block from what a link names, plus the advanced parameters Xray's
/// grammar adds on top of them. `query` is `None` where the caller has no link
/// to read those from.
/// A protocol whose handshake is TLS whatever the link says. Naming another
/// security on one is refused rather than quietly upgraded; `none` is what the
/// family's clients write when they leave the field out.
fn tls_by_contract(query: &Query, name: &str) -> Result<(), String> {
    let Some(security) = query.get("security").map(str::to_ascii_lowercase) else {
        return Ok(());
    };
    if matches!(security.as_str(), "tls" | "xtls" | "none") {
        return Ok(());
    }
    Err(format!(
        "{name} is TLS by definition; security={security:?} cannot be honoured"
    ))
}

fn tls_security(
    sni: Option<String>,
    alpn: Vec<String>,
    fingerprint: Option<String>,
    allow_insecure: bool,
    query: Option<&Query>,
) -> Security {
    Security::Tls {
        sni,
        alpn,
        fingerprint,
        allow_insecure,
        pinned_cert_sha256: query.and_then(|query| query.first(&["pcs", "hpkp"]).map(str::to_owned)),
        verify_cert_by_name: query.and_then(|query| query.string("vcn")),
        ech: query.and_then(|query| query.string("ech")),
    }
}

/// SIP002's `plugin` parameter: the plugin's name up to the first `;`, its own
/// options after it. sing-box is the only core that runs one, and it implements
/// exactly these two.
fn parse_ss_plugin(query: &Query) -> Result<Option<ShadowSocksPlugin>, String> {
    const PLUGINS: [&str; 2] = ["obfs-local", "v2ray-plugin"];
    let Some(raw) = query.get("plugin") else {
        return Ok(None);
    };
    let (name, options) = match raw.split_once(';') {
        Some((name, options)) => (name.trim(), Some(options.trim().to_string())),
        None => (raw.trim(), None),
    };
    // SIP002's own example spells the plugin `simple-obfs`, the name it had
    // before it was renamed; sing-box answers to `obfs-local` alone.
    let name = if name.eq_ignore_ascii_case("simple-obfs") {
        "obfs-local"
    } else {
        name
    };
    if !PLUGINS.contains(&name) {
        return Err(format!(
            "shadowsocks plugin {:?} is not one sing-box implements (obfs-local, v2ray-plugin)",
            excerpt(name)
        ));
    }
    Ok(Some(ShadowSocksPlugin {
        name: name.to_string(),
        options: options.filter(|options| !options.is_empty()),
    }))
}

/// `fm`: Xray's finalmask, a URL-encoded JSON object of the packet masks and
/// the QUIC parameters its own grammar defines. Nothing here is interpreted —
/// the object goes into the generated config as it arrived.
fn parse_finalmask(query: &Query) -> Result<Option<String>, String> {
    let Some(raw) = query.get("fm") else {
        return Ok(None);
    };
    let value: Value =
        serde_json::from_str(raw).map_err(|error| format!("finalmask fm is not JSON: {error}"))?;
    if !value.is_object() {
        return Err("finalmask fm must be a JSON object".into());
    }
    Ok(Some(value.to_string()))
}

/// A share link as it was before a web page escaped it.
///
/// A feed copied out of HTML -- a Telegram post, a paste site -- arrives with
/// every `&` of its links written as `&amp;`, which makes `security` a
/// parameter called `amp;security`. No link spells a parameter that way, so the
/// entity is undone, as many times as it was applied. Only a link is touched: a
/// native config says what it says.
pub(crate) fn unescaped_link(text: &str) -> std::borrow::Cow<'_, str> {
    let link = text.split_once("://").is_some_and(|(scheme, _)| {
        !scheme.is_empty()
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
    });
    if !link || !text.contains("&amp;") {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut plain = text.to_owned();
    while plain.contains("&amp;") {
        plain = plain.replace("&amp;", "&");
    }
    std::borrow::Cow::Owned(plain)
}

pub(crate) fn split_fragment(rest: &str) -> (&str, Option<String>) {
    match rest.split_once('#') {
        Some((body, remark)) => (body, Some(percent_decode(remark))),
        None => (rest, None),
    }
}

pub(crate) fn split_query(body: &str) -> (&str, &str) {
    match body.split_once('?') {
        Some((authority, query)) => (authority, query),
        None => (body, ""),
    }
}

pub(crate) fn split_host_port(
    target: &str,
    default_port: Option<u16>,
) -> Result<(String, u16), String> {
    let target = target.trim();
    if let Some(rest) = target.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("unterminated IPv6 literal in {:?}", excerpt(target)))?;
        if !tail.is_empty() && !tail.starts_with(':') {
            return Err("unexpected text after bracketed IPv6 address".into());
        }
        let port = match tail.strip_prefix(':') {
            Some(port) => parse_port(port)?,
            None => default_port.ok_or_else(|| "missing port".to_string())?,
        };
        return Ok((checked_host(host)?, port));
    }
    if let Some((host, port)) = target.rsplit_once(':') {
        if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) {
            return Ok((checked_host(host)?, parse_port(port)?));
        }
    }
    let port = default_port.ok_or_else(|| format!("missing port in {:?}", excerpt(target)))?;
    Ok((checked_host(target)?, port))
}

pub(crate) fn checked_host(host: &str) -> Result<String, String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("empty host".into());
    }
    if host
        .chars()
        .any(|c| c.is_whitespace() || c == '/' || c == '@')
    {
        return Err(format!("host {:?} is malformed", excerpt(host)));
    }
    Ok(host.to_string())
}

pub(crate) fn parse_port(text: &str) -> Result<u16, String> {
    text.trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| format!("port {:?} is not a port number", excerpt(text)))
}

/// One end of a port-hopping range; unlike [`parse_port`], an open end is a
/// mistake the caller reports.
fn hop_port(text: &str) -> Result<u16, String> {
    text.trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| format!("{:?} is not a port in a hopping range", excerpt(text)))
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push(hex_value(pair[0])? << 4 | hex_value(pair[1])?);
    }
    Some(out)
}

fn split_credentials(userinfo: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(userinfo) = userinfo else {
        return (None, None);
    };
    // Split URI userinfo before unescaping: %3A inside a username is not
    // the username/password delimiter. Legacy base64 credentials split after decoding.
    if let Some((user, password)) = userinfo.split_once(':') {
        return (
            Some(percent_decode(user)).filter(|user| !user.is_empty()),
            Some(percent_decode(password)),
        );
    }
    let unescaped = percent_decode(userinfo);
    let Some(decoded) = b64_decode(&unescaped) else {
        return (Some(unescaped).filter(|user| !user.is_empty()), None);
    };
    match decoded.split_once(':') {
        Some((user, password)) => (
            Some(user.to_string()).filter(|user| !user.is_empty()),
            Some(password.to_string()),
        ),
        None => (Some(decoded).filter(|user| !user.is_empty()), None),
    }
}

/// Credentials arrive either percent-encoded (`user:pass`) or base64-wrapped
/// (`c2VjcmV0`); a base64 blob never contains a colon, so the shape decides.
fn decode_credentials(text: &str) -> String {
    if text.contains(':') {
        percent_decode(text)
    } else {
        b64_decode(text).unwrap_or_else(|| percent_decode(text))
    }
}

fn host_name(server: &str) -> Option<String> {
    server
        .parse::<IpAddr>()
        .is_err()
        .then(|| server.to_string())
}

/// A name a certificate can be issued for: anything but an address literal.
fn domain_name(text: &str) -> Option<String> {
    let text = text.trim().trim_start_matches('[').trim_end_matches(']');
    (!text.is_empty() && text.parse::<IpAddr>().is_err()).then(|| text.to_string())
}

fn valid_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    match bytes.len() {
        36 => bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        }),
        32 => bytes.iter().all(u8::is_ascii_hexdigit),
        _ => false,
    }
}

pub(crate) fn split_list(list: Option<&str>) -> Vec<String> {
    list.map(|text| {
        text.split(',')
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

fn json_text(json: &Value, key: &str) -> Option<String> {
    let text = match json.get(key)? {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        _ => return None,
    };
    let text = text.trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn excerpt(text: &str) -> String {
    const LIMIT: usize = 48;
    if text.chars().count() <= LIMIT {
        return text.to_string();
    }
    let head: String = text.chars().take(LIMIT).collect();
    format!("{head}…")
}

pub(crate) fn percent_decode(text: &str) -> String {
    if !text.contains('%') {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                out.push(high << 4 | low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Share links use unpadded standard base64 for vmess/ss, URL-safe base64 for
/// some clients, and occasionally padding; accept every variant rather than
/// telling the user their working link is wrong.
pub(crate) fn b64_decode(text: &str) -> Option<String> {
    String::from_utf8(b64_bytes(text)?).ok()
}

/// The same four alphabets, for the callers that need the octets rather than a
/// string: a WireGuard key is raw bytes, not text.
fn b64_bytes(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .into_iter()
        .find_map(|engine| engine.decode(text).ok())
}

pub(crate) struct Query(pub(crate) HashMap<String, String>);

impl Query {
    fn new() -> Self {
        Self(HashMap::new())
    }

    /// Set a parameter as if the link had carried it, for the parsers whose
    /// grammar is a JSON object rather than a query string.
    fn set(&mut self, key: &str, value: Option<String>) {
        if let Some(value) = value {
            self.0.insert(key.to_string(), value);
        }
    }

    pub(crate) fn parse(params: &str) -> Self {
        let mut map = HashMap::new();
        for pair in params.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = match pair.split_once('=') {
                Some((key, value)) => (percent_decode(key), percent_decode(value)),
                None => (percent_decode(pair), String::new()),
            };
            map.entry(key.to_ascii_lowercase()).or_insert(value);
        }
        Self(map)
    }

    fn remove(&mut self, key: &str) {
        self.0.remove(key);
    }

    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.0
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    fn string(&self, key: &str) -> Option<String> {
        self.get(key).map(str::to_string)
    }

    pub(crate) fn list(&self, key: &str) -> Vec<String> {
        split_list(self.get(key))
    }

    /// A plain count: `ed`, `mtu`, `readBufferSize`. A value that is not a
    /// number is refused rather than dropped, because the core would either
    /// ignore the setting or fail on it.
    fn number(&self, key: &str) -> Result<Option<u32>, String> {
        let Some(raw) = self.get(key) else {
            return Ok(None);
        };
        raw.trim()
            .parse::<u32>()
            .map(Some)
            .map_err(|_| format!("{key}={raw:?} is not a number"))
    }

    /// A setting that is present and means yes/no: `congestion=false` differs
    /// from an absent `congestion`.
    pub(crate) fn boolean(&self, key: &str) -> Result<Option<bool>, String> {
        let Some(raw) = self.get(key) else {
            return Ok(None);
        };
        match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(Some(true)),
            "0" | "false" | "no" | "off" => Ok(Some(false)),
            _ => Err(format!("{key}={raw:?} is not true or false")),
        }
    }

    /// The first of `keys` the link carries, in a caller-chosen priority
    /// order: clients spell the same parameter differently.
    pub(crate) fn first(&self, keys: &[&str]) -> Option<&str> {
        keys.iter().find_map(|key| self.get(key))
    }

    /// A bandwidth hint in Mbps. Links spell it `50`, `50mbps` or `50Mbps`;
    /// anything else is a link this app cannot honour rather than a number to
    /// guess at.
    fn mbps(&self, keys: &[&str]) -> Result<Option<u32>, String> {
        let Some(raw) = self.first(keys) else {
            return Ok(None);
        };
        let digits: String = raw
            .trim()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let value = digits
            .parse::<u32>()
            .map_err(|_| format!("{raw:?} is not a bandwidth in Mbps"))?;
        Ok((value > 0).then_some(value))
    }

    /// A duration in seconds, for the parameters that take one.
    fn seconds(&self, keys: &[&str]) -> Result<Option<u64>, String> {
        let Some(raw) = self.first(keys) else {
            return Ok(None);
        };
        let digits: String = raw
            .trim()
            .trim_end_matches(['s', 'S'])
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let value = digits
            .parse::<u64>()
            .map_err(|_| format!("{raw:?} is not a duration in seconds"))?;
        Ok((value > 0).then_some(value))
    }

    /// Port hopping, normalised to sing-box's `server_ports` syntax: one
    /// `start:end` range per entry. Links spell one `443-8443`, `443:8443` or a
    /// bare port, comma or semicolon separated.
    fn ports(&self, keys: &[&str]) -> Result<Vec<String>, String> {
        // sing-box expands every port of every range into a slice it then hops
        // over, so a link asking for a million ports is refused, not copied.
        const MAX_HOP_PORTS: u32 = 1024;
        let Some(raw) = self.first(keys) else {
            return Ok(Vec::new());
        };
        let mut ranges = Vec::new();
        let mut total: u32 = 0;
        for item in raw.split([',', ';']) {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let (start, end) = match item.split_once(['-', ':']) {
                Some((start, end)) => (hop_port(start)?, hop_port(end)?),
                None => {
                    let port = hop_port(item)?;
                    (port, port)
                }
            };
            if end < start {
                return Err(format!("port range {item:?} runs backwards"));
            }
            // Summed in the accumulator's own width: one range is at most a
            // u16's worth of ports, but the limit is on the sum.
            total = total.saturating_add(u32::from(end) - u32::from(start) + 1);
            ranges.push(format!("{start}:{end}"));
        }
        if total > MAX_HOP_PORTS {
            return Err(format!(
                "port hopping over {total} ports is more than this app will carry ({MAX_HOP_PORTS})"
            ));
        }
        Ok(ranges)
    }

    /// `pinSHA256`: the hex digest a link carries for the server certificate's
    /// DER encoding, converted to the base64 sing-box's `tls` block takes.
    fn pin(&self) -> Result<Option<String>, String> {
        let Some(raw) = self.first(&["pinsha256", "pin_sha256", "pinned_sha256", "pin"]) else {
            return Ok(None);
        };
        let digest = hex_decode(&raw.trim().replace(':', ""))
            .ok_or_else(|| format!("pinSHA256 {:?} is not a hex digest", excerpt(raw)))?;
        if digest.len() != 32 {
            return Err(format!(
                "pinSHA256 is {} bytes; a SHA-256 digest is 32",
                digest.len()
            ));
        }
        Ok(Some(STANDARD.encode(digest)))
    }

    fn flag(&self, key: &str) -> bool {
        self.get(key).is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
    }
}

// ---------------------------------------------------------------------------
// Session planning
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    fn link(profile: &str) -> Outbound {
        match CoreProfile::parse(profile).expect("profile parses") {
            CoreProfile::Link(outbound) => outbound,
            CoreProfile::Native(_) => panic!("expected a link"),
        }
    }

    /// A vmess link carrying `fields` on top of an endpoint every test shares.
    fn vmess(fields: serde_json::Value) -> String {
        let mut payload = serde_json::json!({
            "add": "v2.example.net",
            "port": "8443",
            "id": UUID,
        });
        for (key, value) in fields.as_object().expect("an object") {
            payload[key.as_str()] = value.clone();
        }
        format!("vmess://{}", STANDARD_NO_PAD.encode(payload.to_string()))
    }

    #[test]
    fn vless_reality_ws_link_expands() {
        let outbound = link(&format!(
            "vless://{UUID}@example.com:443?type=ws&path=%2Fray&host=cdn.example.com\
             &security=reality&sni=www.example.com&pbk=KEY&sid=ab12&fp=chrome#tokyo"
        ));
        assert_eq!(outbound.server, "example.com");
        assert_eq!(outbound.port, 443);
        assert_eq!(
            outbound.transport,
            Transport::Ws {
                path: "/ray".into(),
                host: Some("cdn.example.com".into()),
                max_early_data: None,
                early_data_header: None,
            }
        );
        match outbound.security {
            Security::Reality {
                sni,
                public_key,
                short_id,
                fingerprint,
                ..
            } => {
                assert_eq!(sni, "www.example.com");
                assert_eq!(public_key, "KEY");
                assert_eq!(short_id, "ab12");
                assert_eq!(fingerprint, "chrome");
            }
            other => panic!("expected reality, got {other:?}"),
        }
        assert_eq!(outbound.remark.as_deref(), Some("tokyo"));
    }

    /// A WebSocket link whose `host` fronts a different address: the Host
    /// header is the name the certificate belongs to, so without an explicit
    /// `sni` that header is what TLS has to be measured against. Reading the
    /// name off the address instead fails the handshake on every fronted
    /// config, which is how a link that works elsewhere stops working here.
    #[test]
    fn a_fronted_websocket_link_measures_tls_against_its_host() {
        let outbound = link(&format!(
            "vless://{UUID}@front.example.net:443\
             ?path=%2F9597g17a-g092-470a-b33p-f092e781716a&security=tls&alpn=http%2F1.1\
             &encryption=none&insecure=0&host=cdn.example.org&fp=firefox&type=ws\
             &allowInsecure=0#F"
        ));
        assert_eq!(
            outbound.transport,
            Transport::Ws {
                path: "/9597g17a-g092-470a-b33p-f092e781716a".into(),
                host: Some("cdn.example.org".into()),
                max_early_data: None,
                early_data_header: None,
            }
        );
        match outbound.security {
            Security::Tls {
                sni,
                alpn,
                fingerprint,
                allow_insecure,
                ..
            } => {
                assert_eq!(sni.as_deref(), Some("cdn.example.org"));
                assert_eq!(alpn, vec!["http/1.1".to_string()]);
                assert_eq!(fingerprint.as_deref(), Some("firefox"));
                assert!(!allow_insecure);
            }
            other => panic!("expected tls, got {other:?}"),
        }
    }

    /// An address is not a name: a link that spells its host as one keeps the
    /// server's own name as the SNI, exactly as both cores would.
    #[test]
    fn an_address_host_is_not_mistaken_for_a_name() {
        let outbound = link(&format!(
            "vless://{UUID}@example.com:443?type=ws&host=203.0.113.7&security=tls"
        ));
        match outbound.security {
            Security::Tls { sni, .. } => assert_eq!(sni.as_deref(), Some("example.com")),
            other => panic!("expected tls, got {other:?}"),
        }
    }

    #[test]
    fn vless_vision_flow_needs_tls() {
        let error = CoreProfile::parse(&format!(
            "vless://{UUID}@example.com:80?flow=xtls-rprx-vision&security=none"
        ))
        .expect_err("flow without tls must be rejected");
        assert!(error.contains("flow requires"), "{error}");
    }

    #[test]
    fn vless_rejects_bad_uuid_and_encryption() {
        assert!(CoreProfile::parse("vless://not-a-uuid@example.com:443").is_err());
        let error = CoreProfile::parse(&format!(
            "vless://{UUID}@example.com:443?encryption=aes-128-gcm"
        ))
        .expect_err("a value that is not Xray's dot config must be rejected");
        assert!(error.contains("encryption"), "{error}");
    }

    /// Xray's VLESS encryption, in the shape a `vless://` link carries it: the
    /// scheme, the mode, the round trip, then raw-base64 public keys — 32 bytes
    /// for X25519, 1184 for an ML-KEM-768 encapsulation key.
    fn vless_encryption_link(key: &str) -> String {
        format!("vless://{UUID}@example.com:443?security=tls&encryption={key}")
    }

    #[test]
    fn vless_encryption_is_carried_verbatim() {
        let key32 = "A".repeat(43);
        let mlkem = "A".repeat(1579);
        for good in [
            format!("mlkem768x25519plus.native.0rtt.{key32}"),
            format!("mlkem768x25519plus.xorpub.1rtt.{mlkem}"),
            // Several keys, and the short segments Xray reads back as padding.
            format!("mlkem768x25519plus.random.0rtt.{key32}.{key32}.AABB"),
        ] {
            let outbound = link(&vless_encryption_link(&good));
            match &outbound.protocol {
                Protocol::Vless { encryption, .. } => {
                    // Verbatim: the core parses the dot config itself.
                    assert_eq!(encryption.as_deref(), Some(good.as_str()));
                }
                other => panic!("expected vless, got {other:?}"),
            }
        }
        // `none`, in any spelling, and an empty value, mean no encryption.
        for none in ["none", "NONE", ""] {
            let outbound = link(&format!("vless://{UUID}@example.com:443?encryption={none}"));
            match outbound.protocol {
                Protocol::Vless { encryption, .. } => assert!(encryption.is_none(), "{none:?}"),
                other => panic!("expected vless, got {other:?}"),
            }
        }
    }

    #[test]
    fn vless_encryption_rejects_what_the_core_would() {
        let key32 = "A".repeat(43);
        let short = "A".repeat(24);
        for bad in [
            // Not the scheme, no mode, no round trip, an unknown mode or trip.
            "mlkem768x25519plus".to_string(),
            format!("x25519plus.native.0rtt.{key32}"),
            format!("mlkem768x25519plus.native.{key32}"),
            format!("mlkem768x25519plus.fast.0rtt.{key32}"),
            format!("mlkem768x25519plus.native.2rtt.{key32}"),
            // A key of the wrong size, and one that is not base64url at all.
            format!("mlkem768x25519plus.native.0rtt.{short}"),
            format!("mlkem768x25519plus.native.0rtt.{}+", key32),
        ] {
            let error = CoreProfile::parse(&vless_encryption_link(&bad))
                .expect_err("the core would refuse it at start");
            assert!(error.contains("encryption"), "{bad}: {error}");
        }
    }

    #[test]
    fn vless_encryption_is_xray_only() {
        let key32 = "A".repeat(43);
        let encrypted = link(&vless_encryption_link(&format!(
            "mlkem768x25519plus.native.0rtt.{key32}"
        )));
        assert!(encrypted.carried_by(FcaeBackend::Xray));
        assert!(!encrypted.carried_by(FcaeBackend::SingBox));
        let refusal = encrypted.refusal(FcaeBackend::SingBox);
        assert!(refusal.contains("Xray"), "{refusal}");
        assert!(refusal.contains("sing-box"), "{refusal}");
        // Plain VLESS stays on both cores.
        let plain = link(&format!("vless://{UUID}@example.com:443"));
        assert!(plain.carried_by(FcaeBackend::Xray));
        assert!(plain.carried_by(FcaeBackend::SingBox));
    }

    #[test]
    fn vmess_base64_payload_expands() {
        let payload = serde_json::json!({
            "v": "2",
            "add": "v2.example.net",
            "port": "8443",
            "id": UUID,
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "path": "/vm",
            "host": "cdn.example.net",
            "tls": "tls",
            "sni": "cdn.example.net",
        })
        .to_string();
        let encoded = STANDARD_NO_PAD.encode(payload);
        let outbound = link(&format!("vmess://{encoded}"));
        assert_eq!(outbound.server, "v2.example.net");
        assert_eq!(outbound.port, 8443);
        assert!(matches!(
            outbound.transport,
            Transport::Ws { ref path, .. } if path == "/vm"
        ));
        assert!(matches!(outbound.security, Security::Tls { .. }));

        // `type` was the TCP/mKCP header camouflage, which the core removed.
        let legacy = serde_json::json!({
            "add": "v2.example.net",
            "port": "8443",
            "id": UUID,
            "net": "tcp",
            "type": "http",
        })
        .to_string();
        let encoded = STANDARD_NO_PAD.encode(legacy);
        assert!(CoreProfile::parse(&format!("vmess://{encoded}")).is_err());
    }

    #[test]
    fn shadowsocks_accepts_both_link_shapes() {
        let credentials = STANDARD_NO_PAD.encode("aes-256-gcm:secret");
        let explicit = link(&format!("ss://{credentials}@example.com:8388#node"));
        assert_eq!(explicit.server, "example.com");
        assert_eq!(explicit.port, 8388);
        assert_eq!(
            explicit.protocol,
            Protocol::Shadowsocks {
                method: "aes-256-gcm".into(),
                password: "secret".into(),
                plugin: None,
            }
        );

        let packed = STANDARD_NO_PAD.encode("aes-256-gcm:secret@example.com:8388");
        let opaque = link(&format!("ss://{packed}"));
        assert_eq!(opaque.server, "example.com");
        assert_eq!(opaque.port, 8388);
    }

    #[test]
    fn trojan_defaults_to_tls_and_socks_accepts_v6_literals() {
        let trojan = link("trojan://secret@example.com:443?sni=edge.example.com");
        assert!(matches!(trojan.security, Security::Tls { .. }));

        let socks = link("socks5://user:pass@[2001:db8::1]:1080");
        assert_eq!(socks.server, "2001:db8::1");
        assert_eq!(socks.port, 1080);
        assert_eq!(
            socks.protocol,
            Protocol::Socks {
                user: Some("user".into()),
                password: Some("pass".into())
            }
        );
    }

    #[test]
    fn native_configs_pass_through_and_garbage_is_rejected() {
        assert!(matches!(
            CoreProfile::parse(r#"{"inbounds":[],"outbounds":[]}"#),
            Ok(CoreProfile::Native(_))
        ));
        assert!(CoreProfile::parse("{\"inbounds\":").is_err());
        assert!(CoreProfile::parse("shadowsocks-rust://x").is_err());
        assert!(CoreProfile::parse("   ").is_err());
    }

    #[test]
    fn grpc_multi_mode_and_authority_reach_xray_and_are_refused_for_sing_box() {
        let outbound = link(&format!(
            "vless://{UUID}@example.com:443?type=grpc&mode=multi&serviceName=svc\
             &authority=grpc.example.com"
        ));
        assert_eq!(
            outbound.transport,
            Transport::Grpc {
                service: "svc".into(),
                authority: Some("grpc.example.com".into()),
                multi_mode: true,
            }
        );
        assert!(outbound.carried_by(FcaeBackend::Xray));
        assert!(!outbound.carried_by(FcaeBackend::SingBox));
        assert!(outbound.refusal(FcaeBackend::SingBox).contains("Xray"));
    }

    #[test]
    fn websocket_early_data_is_carried_for_both_cores() {
        let outbound = link(&format!(
            "vless://{UUID}@example.com:443?type=ws&path=%2Fray&ed=2048&eh=X-Retry\
             &security=tls"
        ));
        assert_eq!(
            outbound.transport,
            Transport::Ws {
                path: "/ray".into(),
                host: None,
                max_early_data: Some(2048),
                early_data_header: Some("X-Retry".into()),
            }
        );
        // The header is sing-box's; Xray kept only the count, inside the path.
        assert!(!outbound.carried_by(FcaeBackend::Xray));
        assert!(outbound.carried_by(FcaeBackend::SingBox));
        let plain = link(&format!(
            "vless://{UUID}@example.com:443?type=ws&path=%2Fray&ed=2048&security=tls"
        ));
        assert!(plain.carried_by(FcaeBackend::Xray));
        // Xray spells early data inside the path. It is read out of the query
        // and dropped from the path, so sing-box — which has a field for the
        // count and no such convention — requests what the link meant.
        let inside = link(&format!(
            "vless://{UUID}@example.com:443?type=ws&path=%2Fws%3Fed%3D2048%26x%3D1&security=tls"
        ));
        assert_eq!(
            inside.transport,
            Transport::Ws {
                path: "/ws?x=1".into(),
                host: None,
                max_early_data: Some(2048),
                early_data_header: None,
            }
        );
        assert!(inside.carried_by(FcaeBackend::Xray));
        assert!(inside.carried_by(FcaeBackend::SingBox));
        assert_eq!(split_early_data("/ws"), ("/ws".to_string(), None));
        assert_eq!(split_early_data("/ws?ed=64"), ("/ws".to_string(), Some(64)));
        assert_eq!(split_early_data("/ws?ed=0"), ("/ws".to_string(), None));
    }

    #[test]
    fn a_plain_tcp_header_is_refused_rather_than_dropped() {
        // A link can name the shape of Xray's TCP header but none of the
        // request and response templates it needs, so it is reported.
        let error = CoreProfile::parse(&format!(
            "vless://{UUID}@example.com:443?type=tcp&headerType=http"
        ))
        .expect_err("the header is not expressible from a link");
        assert!(error.contains("headerType"), "{error}");
        // The core's own spelling of "no header" is not a setting at all.
        let plain = link(&format!(
            "vless://{UUID}@example.com:443?type=raw&headerType=none"
        ));
        assert_eq!(plain.transport, Transport::Tcp);
    }

    #[test]
    fn vmess_ciphers_are_normalised_and_a_removed_one_belongs_to_sing_box() {
        let outbound = link(&vmess(serde_json::json!({"scy": "chacha20-ietf-poly1305"})));
        match &outbound.protocol {
            Protocol::Vmess { security, .. } => assert_eq!(security, "chacha20-poly1305"),
            other => panic!("expected vmess, got {other:?}"),
        }
        // Xray-core knows four ciphers and would quietly fall back to `auto`
        // for this one, connecting with a different cipher than the server
        // expects; sing-box still implements it.
        let cfb = link(&vmess(serde_json::json!({"scy": "aes-128-cfb"})));
        assert!(!cfb.carried_by(FcaeBackend::Xray));
        assert!(cfb.carried_by(FcaeBackend::SingBox));
        assert!(cfb.refusal(FcaeBackend::Xray).contains("removed"));
        // Anything else is a cipher neither core has, at save time rather than
        // at start.
        let error = CoreProfile::parse(&vmess(serde_json::json!({"scy": "rc4"})))
            .expect_err("not a vmess cipher");
        assert!(error.contains("cipher"), "{error}");

        // `type` is the transport's own mode on gRPC, not a header.
        let grpc = link(&vmess(serde_json::json!({
            "net": "grpc",
            "path": "svc",
            "host": "cdn.example.net",
            "type": "multi",
        })));
        assert_eq!(
            grpc.transport,
            Transport::Grpc {
                service: "svc".into(),
                authority: Some("cdn.example.net".into()),
                multi_mode: true,
            }
        );
        // mKCP keeps its seed in `path`, and the core removed it.
        let error = CoreProfile::parse(&vmess(serde_json::json!({"net": "kcp", "path": "seed"})))
            .expect_err("the seed is gone from the core");
        assert!(error.contains("seed"), "{error}");
    }

    #[test]
    fn the_uri_vmess_shape_carries_the_same_outbound() {
        let outbound = link(&format!(
            "vmess://{UUID}@example.com:8443?type=ws&path=%2Fvm&host=cdn.example.net\
             &security=tls&sni=cdn.example.net#std"
        ));
        assert_eq!(outbound.server, "example.com");
        assert_eq!(outbound.port, 8443);
        assert_eq!(outbound.remark.as_deref(), Some("std"));
        assert_eq!(
            outbound.transport,
            Transport::Ws {
                path: "/vm".into(),
                host: Some("cdn.example.net".into()),
                max_early_data: None,
                early_data_header: None,
            }
        );
        // The query carries no cipher, so the core default is what it runs.
        match &outbound.protocol {
            Protocol::Vmess {
                security, alter_id, ..
            } => {
                assert_eq!(security, "auto");
                assert_eq!(*alter_id, 0);
            }
            other => panic!("expected vmess, got {other:?}"),
        }
        let error = CoreProfile::parse("vmess://not-a-uuid@example.com:8443")
            .expect_err("vmess needs a UUID");
        assert!(error.contains("UUID"), "{error}");
    }

    #[test]
    fn an_https_proxy_link_is_tls_by_its_scheme() {
        // The scheme decides, so a `security=none` left in the query cannot
        // turn it into a plaintext proxy; the TLS settings it names still apply.
        let outbound =
            link("https://user:pass@proxy.example.com:443?sni=other.example.com&security=none");
        assert_eq!(outbound.port, 443);
        match outbound.security {
            Security::Tls { sni, .. } => assert_eq!(sni.as_deref(), Some("other.example.com")),
            other => panic!("expected TLS, got {other:?}"),
        }
        let plain = link("http://proxy.example.com:8080");
        assert_eq!(plain.security, Security::None);
    }

    #[test]
    fn trojan_flow_is_refused_and_the_simple_obfs_plugin_is_folded() {
        let error = CoreProfile::parse("trojan://pw@example.com:443?flow=xtls-rprx-vision")
            .expect_err("trojan flow is gone from the core");
        assert!(error.contains("flow"), "{error}");
        // SIP002's own example spells the plugin by the name it had before the
        // rename; sing-box answers to `obfs-local` alone.
        let outbound = link(
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388\
             ?plugin=simple-obfs%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com",
        );
        match &outbound.protocol {
            Protocol::Shadowsocks {
                plugin: Some(plugin),
                ..
            } => {
                assert_eq!(plugin.name, "obfs-local");
                assert_eq!(
                    plugin.options.as_deref(),
                    Some("obfs=http;obfs-host=bing.com")
                );
            }
            other => panic!("expected a shadowsocks plugin, got {other:?}"),
        }
    }

    #[test]
    fn mkcp_and_xhttp_links_belong_to_xray() {
        let kcp = link(&format!(
            "vless://{UUID}@example.com:443?type=kcp&mtu=1350&tti=20&uplinkCapacity=5\
             &downlinkCapacity=20&congestion=false&readBufferSize=1&writeBufferSize=1"
        ));
        assert_eq!(
            kcp.transport,
            Transport::Kcp {
                mtu: Some(1350),
                tti: Some(20),
                uplink_capacity: Some(5),
                downlink_capacity: Some(20),
                congestion: Some(false),
                read_buffer: Some(1),
                write_buffer: Some(1),
            }
        );
        assert!(kcp.carried_by(FcaeBackend::Xray));
        assert!(!kcp.carried_by(FcaeBackend::SingBox));
        assert!(kcp.refusal(FcaeBackend::SingBox).contains("Xray"));

        // Header and seed are gone from the core, which refuses a config that
        // still names them.
        assert!(CoreProfile::parse(&format!(
            "vless://{UUID}@example.com:443?type=kcp&headerType=srtp"
        ))
        .is_err());
        assert!(CoreProfile::parse(&format!(
            "vless://{UUID}@example.com:443?type=kcp&seed=abcd"
        ))
        .is_err());

        let extra = "%7B%22xPaddingBytes%22%3A%22100-1000%22%7D";
        let xhttp = link(&format!(
            "vless://{UUID}@example.com:443?type=xhttp&path=%2Fecho&host=cdn.example.com\
             &mode=auto&extra={extra}&security=tls"
        ));
        assert_eq!(
            xhttp.transport,
            Transport::Xhttp {
                path: "/echo".into(),
                host: Some("cdn.example.com".into()),
                mode: Some("auto".into()),
                extra: Some("{\"xPaddingBytes\":\"100-1000\"}".into()),
            }
        );
        assert!(xhttp.carried_by(FcaeBackend::Xray));
        assert!(!xhttp.carried_by(FcaeBackend::SingBox));
        assert!(CoreProfile::parse(&format!(
            "vless://{UUID}@example.com:443?type=xhttp&extra=not-json"
        ))
        .is_err());
    }

    #[test]
    fn http2_is_sing_box_only_now_that_xray_removed_it() {
        let h2 = link(&format!(
            "vless://{UUID}@example.com:443?type=h2&path=%2F&host=cdn.example.com\
             &security=tls"
        ));
        assert_eq!(
            h2.transport,
            Transport::H2 {
                path: "/".into(),
                host: Some("cdn.example.com".into()),
                method: None,
            }
        );
        assert!(h2.carried_by(FcaeBackend::SingBox));
        assert!(!h2.carried_by(FcaeBackend::Xray));
        assert!(h2.refusal(FcaeBackend::Xray).contains("sing-box"));
    }

    #[test]
    fn xray_removed_allow_insecure_and_only_sing_box_takes_it() {
        let outbound = link(&format!(
            "vless://{UUID}@example.com:443?security=tls&allowInsecure=1"
        ));
        assert!(outbound.carried_by(FcaeBackend::SingBox));
        assert!(!outbound.carried_by(FcaeBackend::Xray));
        assert!(outbound.refusal(FcaeBackend::Xray).contains("sing-box"));

        // What replaced it on Xray is a pair of certificate settings.
        let pinned = link(&format!(
            "vless://{UUID}@example.com:443?security=tls&pcs=AB12&vcn=example.com&ech=ECHLIST"
        ));
        assert!(pinned.carried_by(FcaeBackend::Xray));
        assert!(!pinned.carried_by(FcaeBackend::SingBox));
        match pinned.security {
            Security::Tls {
                pinned_cert_sha256,
                verify_cert_by_name,
                ech,
                ..
            } => {
                assert_eq!(pinned_cert_sha256.as_deref(), Some("AB12"));
                assert_eq!(verify_cert_by_name.as_deref(), Some("example.com"));
                assert_eq!(ech.as_deref(), Some("ECHLIST"));
            }
            other => panic!("expected TLS, got {other:?}"),
        }
    }

    #[test]
    fn shadowsocks_plugins_and_stream_ciphers_are_sing_box_only() {
        let plugin = link(
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388\
            ?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com",
        );
        match &plugin.protocol {
            Protocol::Shadowsocks { plugin, .. } => {
                let plugin = plugin.as_ref().expect("plugin parsed");
                assert_eq!(plugin.name, "obfs-local");
                assert_eq!(
                    plugin.options.as_deref(),
                    Some("obfs=http;obfs-host=bing.com")
                );
            }
            other => panic!("expected shadowsocks, got {other:?}"),
        }
        assert!(plugin.carried_by(FcaeBackend::SingBox));
        assert!(!plugin.carried_by(FcaeBackend::Xray));
        assert!(plugin.refusal(FcaeBackend::Xray).contains("sing-box"));
        assert!(
            CoreProfile::parse("ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388?plugin=kcptun")
                .is_err()
        );

        // A stream cipher Xray dropped, and a name only Xray still knows.
        let legacy = link("ss://YWVzLTI1Ni1jZmI6c2VjcmV0@example.com:8388");
        assert!(legacy.carried_by(FcaeBackend::SingBox));
        assert!(!legacy.carried_by(FcaeBackend::Xray));
        let aead = link("ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388");
        assert!(aead.carried_by(FcaeBackend::Xray));
        assert!(aead.carried_by(FcaeBackend::SingBox));
    }

    #[test]
    fn reality_ml_dsa_and_finalmask_are_xray_settings() {
        let outbound = link(&format!(
            "vless://{UUID}@example.com:443?security=reality&sni=www.example.com&pbk=KEY\
             &sid=ab&pqv=PQKEY"
        ));
        match outbound.security {
            Security::Reality { mldsa65_verify, .. } => {
                assert_eq!(mldsa65_verify.as_deref(), Some("PQKEY"))
            }
            other => panic!("expected reality, got {other:?}"),
        }
        assert!(outbound.carried_by(FcaeBackend::Xray));
        assert!(!outbound.carried_by(FcaeBackend::SingBox));

        let mask = "%7B%22tcp%22%3A%5B%5D%7D";
        let masked = link(&format!(
            "vless://{UUID}@example.com:443?security=tls&fm={mask}"
        ));
        assert_eq!(masked.finalmask.as_deref(), Some("{\"tcp\":[]}"));
        assert!(masked.carried_by(FcaeBackend::Xray));
        assert!(!masked.carried_by(FcaeBackend::SingBox));
        assert!(CoreProfile::parse(&format!(
            "vless://{UUID}@example.com:443?security=tls&fm=[]"
        ))
        .is_err());
    }

    #[test]
    fn percent_decoding_survives_truncated_escapes() {
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%41"), "A");
    }

    #[test]
    fn ports_and_hosts_are_validated() {
        assert!(CoreProfile::parse(&format!("vless://{UUID}@example.com:0")).is_err());
        assert!(CoreProfile::parse(&format!("vless://{UUID}@example.com")).is_err());
        assert!(CoreProfile::parse(&format!("vless://{UUID}@:443")).is_err());
    }

    #[test]
    fn hysteria2_links_carry_obfs_bandwidth_hopping_and_the_pin() {
        let outbound = link(
            "hysteria2://pa%3Ass@example.com:8443/?sni=www.example.com&insecure=1\
             &obfs=salamander&obfs-password=salt&up=50&down=200\
             &mport=20000-20100&hop-interval=30\
             &pinSHA256=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f#fast",
        );
        assert_eq!(outbound.server, "example.com");
        assert_eq!(outbound.port, 8443);
        assert_eq!(outbound.remark.as_deref(), Some("fast"));
        match &outbound.protocol {
            Protocol::Hysteria2 {
                password,
                obfs,
                up_mbps,
                down_mbps,
                ports,
                hop_interval,
                pin,
            } => {
                assert_eq!(password, "pa:ss");
                assert_eq!(
                    obfs,
                    &Some(Obfs {
                        kind: "salamander".into(),
                        password: "salt".into(),
                        min_packet_size: None,
                        max_packet_size: None,
                    })
                );
                assert_eq!((*up_mbps, *down_mbps), (Some(50), Some(200)));
                assert_eq!(ports, &vec!["20000:20100".to_string()]);
                assert_eq!(*hop_interval, Some(30));
                // Base64 of the 32-byte digest, which is what sing-box takes.
                assert_eq!(pin.as_deref().map(str::len), Some(44));
            }
            other => panic!("expected hysteria2, got {other:?}"),
        }
        match outbound.security {
            Security::Tls {
                sni,
                allow_insecure,
                ..
            } => {
                assert_eq!(sni.as_deref(), Some("www.example.com"));
                assert!(allow_insecure);
            }
            other => panic!("expected TLS, got {other:?}"),
        }
        assert!(outbound.protocol.xray_carries());
    }

    #[test]
    fn tuic_and_anytls_links_parse() {
        let tuic = link(
            "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pass@example.com:10443\
             ?congestion_control=bbr&udp_relay_mode=quic&alpn=h3&sni=www.example.com\
             &reduce_rtt=1#tuic",
        );
        assert_eq!(tuic.port, 10443);
        match &tuic.protocol {
            Protocol::Tuic {
                uuid,
                password,
                congestion_control,
                udp_relay_mode,
                zero_rtt,
                ..
            } => {
                assert_eq!(uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
                assert_eq!(password, "pass");
                assert_eq!(congestion_control.as_deref(), Some("bbr"));
                assert_eq!(udp_relay_mode.as_deref(), Some("quic"));
                assert!(zero_rtt);
            }
            other => panic!("expected tuic, got {other:?}"),
        }
        assert!(!tuic.protocol.xray_carries());

        let anytls = link("anytls://secret@example.com:443?sni=www.example.com&fp=chrome#a");
        match &anytls.protocol {
            Protocol::AnyTls { password } => assert_eq!(password, "secret"),
            other => panic!("expected anytls, got {other:?}"),
        }
        match &anytls.security {
            Security::Tls { fingerprint, .. } => {
                assert_eq!(fingerprint.as_deref(), Some("chrome"))
            }
            other => panic!("expected TLS, got {other:?}"),
        }
        assert!(!anytls.protocol.xray_carries());
    }

    /// A 32-byte key in the padded standard base64 both cores decode, spelled
    /// out in hex in the test that normalises it.
    const WIREGUARD_KEY: &str = "HBtvDj96H5wrPU5fYHGCk6S1xtfo+QobLD1OX2BxgpM=";

    /// A link whose key is 16 bytes: base64, the right alphabet, the wrong size.
    const SHORT_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAA==";

    fn wireguard_link(query: &str) -> String {
        format!("wireguard://{WIREGUARD_KEY}@engage.example.net:51820?{query}")
    }

    #[test]
    fn a_wireguard_link_normalises_keys_and_addresses_for_both_cores() {
        // Hex is the other spelling Xray-core takes for a key.
        let outbound = link(&format!(
            "wireguard://{}@engage.example.net:51820?publickey={WIREGUARD_KEY}\
             &address=172.16.0.2/32,2606%3A4700%3A110%3A%3A2/128&allowedips=0.0.0.0/0\
             &mtu=1280&reserved=%5B0%2C0%2C0%5D&persistent-keepalive=25s#warp",
            "1c1b6f0e3f7a1f9c2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293"
        ));
        assert_eq!(outbound.remark.as_deref(), Some("warp"));
        match &outbound.protocol {
            Protocol::WireGuard {
                secret_key,
                address,
                peer,
                mtu,
                reserved,
            } => {
                // One key, one length, one alphabet: what both cores decode.
                assert_eq!(secret_key, WIREGUARD_KEY);
                assert_eq!(
                    address,
                    &vec![
                        "172.16.0.2/32".to_string(),
                        "2606:4700:110::2/128".to_string()
                    ]
                );
                assert_eq!(peer.public_key, WIREGUARD_KEY);
                assert_eq!(peer.allowed_ips, vec!["0.0.0.0/0".to_string()]);
                assert_eq!(peer.keepalive, Some(25));
                assert_eq!(*mtu, Some(1280));
                assert_eq!(reserved, &vec![0, 0, 0]);
            }
            other => panic!("expected wireguard, got {other:?}"),
        }
        // The one protocol this round added that both cores run.
        assert!(outbound.carried_by(FcaeBackend::Xray));
        assert!(outbound.carried_by(FcaeBackend::SingBox));
    }

    #[test]
    fn a_wireguard_link_is_refused_where_a_core_would_refuse_it() {
        for (link, expected) in [
            // The peer's key is what the tunnel is verified against, and the
            // interface needs an address.
            (wireguard_link("address=10.0.0.2"), "publickey"),
            (
                format!("wireguard://{WIREGUARD_KEY}@example.net:51820?publickey={WIREGUARD_KEY}"),
                "address",
            ),
            (
                format!(
                    "wireguard://{SHORT_KEY}@example.net:51820?publickey={WIREGUARD_KEY}&address=10.0.0.2"
                ),
                "32",
            ),
            // The peer's key is normalised like the other two, so one that is
            // not a key at all is refused rather than handed to the core.
            (
                wireguard_link("publickey=not-a-key&address=10.0.0.2"),
                "public key",
            ),
            // Xray-core's interface address takes no subnet but a host's.
            (
                wireguard_link(&format!("publickey={WIREGUARD_KEY}&address=10.0.0.0/24")),
                "single host",
            ),
            // Two bytes where the field is three.
            (
                wireguard_link(&format!("publickey={WIREGUARD_KEY}&address=10.0.0.2&reserved=0,0")),
                "three",
            ),
            // A bare tunnel has no transport and no TLS layer to name one on.
            (
                wireguard_link(&format!("publickey={WIREGUARD_KEY}&address=10.0.0.2&type=ws")),
                "transport",
            ),
            (
                wireguard_link(&format!("publickey={WIREGUARD_KEY}&address=10.0.0.2&security=tls")),
                "TLS",
            ),
            // The core's wireguard handler dials the peer itself, so a mask has
            // nothing to reach.
            (
                wireguard_link(&format!("publickey={WIREGUARD_KEY}&address=10.0.0.2&fm=%7B%7D")),
                "finalmask",
            ),
        ] {
            let error = CoreProfile::parse(&link).expect_err("a core would refuse it");
            assert!(error.contains(expected), "{link}: {error}");
        }
    }

    #[test]
    fn a_hysteria_link_carries_its_bandwidth_and_xplus_obfs() {
        let outbound = link(
            "hysteria://engage.example.net:443?auth=secret&peer=www.example.com&insecure=1\
             &upmbps=50&downmbps=100&obfs=xplus&obfsParam=salt&mport=8000-8100\
             &hop-interval=30&protocol=udp#fast",
        );
        match &outbound.protocol {
            Protocol::Hysteria {
                auth,
                obfs,
                up_mbps,
                down_mbps,
                ports,
                hop_interval,
                ..
            } => {
                assert_eq!(auth.as_deref(), Some("secret"));
                assert_eq!(obfs.as_deref(), Some("salt"));
                // Brutal shapes the tunnel to these, and sing-box will not start
                // without them.
                assert_eq!((*up_mbps, *down_mbps), (50, 100));
                assert_eq!(ports, &vec!["8000:8100".to_string()]);
                assert_eq!(*hop_interval, Some(30));
            }
            other => panic!("expected hysteria, got {other:?}"),
        }
        match outbound.security {
            Security::Tls {
                sni,
                allow_insecure,
                ..
            } => {
                assert_eq!(sni.as_deref(), Some("www.example.com"));
                assert!(allow_insecure);
            }
            other => panic!("expected TLS, got {other:?}"),
        }
        assert!(outbound.carried_by(FcaeBackend::SingBox));
        assert!(!outbound.carried_by(FcaeBackend::Xray));

        // A link that spells auth in the authority is read the same way.
        let outbound = link("hysteria://secret@example.net:443?upmbps=10&downmbps=10");
        match &outbound.protocol {
            Protocol::Hysteria { auth, .. } => assert_eq!(auth.as_deref(), Some("secret")),
            other => panic!("expected hysteria, got {other:?}"),
        }
    }

    #[test]
    fn a_hysteria_link_is_refused_where_sing_box_would_refuse_it() {
        for (link, expected) in [
            ("hysteria://example.net:443?downmbps=100", "upmbps"),
            ("hysteria://example.net:443?upmbps=100", "downmbps"),
            // The packet mode and the obfuscation are the ones sing-box has.
            (
                "hysteria://example.net:443?upmbps=1&downmbps=1&protocol=faketcp",
                "protocol",
            ),
            (
                "hysteria://example.net:443?upmbps=1&downmbps=1&obfs=xor&obfsParam=s",
                "xplus",
            ),
            (
                "hysteria://example.net:443?upmbps=1&downmbps=1&obfsParam=s",
                "obfs=xplus",
            ),
            (
                "hysteria://example.net:443?upmbps=1&downmbps=1&obfs=xplus",
                "obfsParam",
            ),
            (
                "hysteria://secret@example.net:443?auth=other&upmbps=1&downmbps=1",
                "not both",
            ),
            // TLS is the protocol's own handshake, not a choice.
            (
                "hysteria://example.net:443?upmbps=1&downmbps=1&security=reality",
                "TLS by definition",
            ),
        ] {
            let error = CoreProfile::parse(link).expect_err("sing-box would refuse it");
            assert!(error.contains(expected), "{link}: {error}");
        }
    }

    /// The protocols whose handshake is TLS by contract take no other security,
    /// and the family's clients write `none` when they leave the field out.
    #[test]
    fn a_tls_by_contract_link_refuses_another_security() {
        for link in [
            "hysteria2://secret@example.net:443?security=reality",
            "hysteria://example.net:443?upmbps=1&downmbps=1&security=reality",
            "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pass@example.net:443?security=reality",
            "anytls://secret@example.net:443?security=reality",
            "naive+https://u:p@example.net:443?security=reality",
        ] {
            let error = CoreProfile::parse(link).expect_err("TLS is the protocol's own");
            assert!(error.contains("TLS by definition"), "{link}: {error}");
        }
        let outbound = link("hysteria2://secret@example.net:443?security=none");
        assert!(matches!(outbound.security, Security::Tls { .. }));
    }

    #[test]
    fn naive_links_carry_credentials_and_no_handshake_settings() {
        let plain = link("naive+https://user:pa%3Ass@example.com:443?peer=www.example.com#n");
        match &plain.protocol {
            Protocol::Naive {
                user,
                password,
                quic,
            } => {
                assert_eq!(user.as_deref(), Some("user"));
                assert_eq!(password.as_deref(), Some("pa:ss"));
                assert!(!quic);
            }
            other => panic!("expected naive, got {other:?}"),
        }
        match plain.security {
            Security::Tls { sni, alpn, .. } => {
                assert_eq!(sni.as_deref(), Some("www.example.com"));
                assert!(alpn.is_empty());
            }
            other => panic!("expected TLS, got {other:?}"),
        }
        assert!(plain.carried_by(FcaeBackend::SingBox));
        assert!(!plain.carried_by(FcaeBackend::Xray));

        let quic = link("naive+quic://user:pass@example.com:443");
        match &quic.protocol {
            Protocol::Naive { quic, .. } => assert!(*quic),
            other => panic!("expected naive, got {other:?}"),
        }

        // Chromium performs the handshake, and sing-box refuses every TLS
        // setting it cannot mirror from Chrome.
        for (link, expected) in [
            (
                "naive+https://u:p@example.com:443?insecure=1",
                "allowInsecure",
            ),
            ("naive+https://u:p@example.com:443?alpn=h2", "alpn"),
            ("naive+https://u:p@example.com:443?fp=chrome", "uTLS"),
            (
                "naive+https://u:p@example.com:443?security=reality",
                "TLS by definition",
            ),
        ] {
            let error = CoreProfile::parse(link).expect_err("sing-box would refuse it");
            assert!(error.contains(expected), "{link}: {error}");
        }
    }

    /// A scheme whose own grammar is just an authority still carries the
    /// settings every link can name.
    #[test]
    fn dial_options_survive_a_scheme_with_no_query_of_its_own() {
        let outbound = link("socks5://u:p@127.0.0.1:1080?tfo=1&uot=1&uotVersion=2");
        assert!(outbound.dial.tfo);
        assert_eq!(outbound.dial.uot, Some(Uot { version: Some(2) }));
        assert_eq!(outbound.dial.packet_encoding, None);
        assert!(outbound.carried_by(FcaeBackend::SingBox));
        // Xray-core has no field for UDP over TCP at all.
        assert!(!outbound.carried_by(FcaeBackend::Xray));

        // The flag alone is the version-less spelling.
        let outbound = link("socks5://127.0.0.1:1080?uot=true");
        assert_eq!(outbound.dial.uot, Some(Uot { version: None }));

        // VLESS and VMess frame their UDP traffic with this one; Xray-core
        // cannot express either value.
        let outbound = link(&format!(
            "vless://{UUID}@example.com:443?packetEncoding=xudp&tfo=true"
        ));
        assert_eq!(outbound.dial.packet_encoding, Some(PacketEncoding::Xudp));
        assert!(outbound.dial.tfo);
        assert!(outbound.carried_by(FcaeBackend::SingBox));
        assert!(!outbound.carried_by(FcaeBackend::Xray));

        // Present but falsey is off, which is what the link asked for.
        let outbound = link("http://u:p@example.com:8080?tfo=0&uot=off");
        assert!(!outbound.dial.tfo);
        assert_eq!(outbound.dial.uot, None);
    }

    #[test]
    fn dial_options_are_refused_where_no_field_can_hold_them() {
        for (profile, expected) in [
            // Each UDP framing belongs to one protocol.
            (
                format!("vless://{UUID}@example.com:443?uot=1"),
                "socks5 setting",
            ),
            (
                "socks5://127.0.0.1:1080?packetEncoding=xudp".to_string(),
                "vless and vmess",
            ),
            // Values neither core implements, refused rather than guessed at.
            (
                "socks5://127.0.0.1:1080?uot=maybe".to_string(),
                "neither on nor off",
            ),
            ("socks5://127.0.0.1:1080?uotVersion=3".to_string(), "1 or 2"),
            (
                format!("vless://{UUID}@example.com:443?packetEncoding=xudp2"),
                "packetaddr, xudp",
            ),
            // A wireguard link carries datagrams, so there is no stream to open.
            (
                wireguard_link(&format!("publickey={WIREGUARD_KEY}&address=10.0.0.2&tfo=1")),
                "nothing to open",
            ),
        ] {
            let error = CoreProfile::parse(&profile).expect_err("no config can hold it");
            assert!(error.contains(expected), "{profile}: {error}");
        }
    }

    #[test]
    fn a_native_config_is_recognised_by_its_endpoints_too() {
        // sing-box reaches WireGuard through `endpoints`, and such a config has
        // no outbound to read a type from.
        assert_eq!(
            native_dialect(
                r#"{"inbounds": [{"type": "socks"}],
                    "endpoints": [{"type": "wireguard", "tag": "wg"}]}"#
            ),
            Some(FcaeBackend::SingBox)
        );
        assert_eq!(
            native_dialect(r#"{"outbounds": [{"protocol": "freedom"}]}"#),
            Some(FcaeBackend::Xray)
        );
        // Nothing to go on, and both dialects at once, are both ambiguous.
        assert_eq!(native_dialect(r#"{"inbounds": []}"#), None);
        assert_eq!(native_dialect(r#"{"outbounds": []}"#), None);
        assert_eq!(
            native_dialect(r#"{"outbounds": [{"protocol": "freedom"}, {"type": "direct"}]}"#),
            None
        );
    }

    #[test]
    fn hysteria2_gecko_obfs_carries_its_packet_window() {
        let outbound = link(
            "hysteria2://secret@example.com:443?obfs=gecko&obfs-password=salt\
             &minPacketSize=512&maxPacketSize=1200#g",
        );
        let Protocol::Hysteria2 { obfs, .. } = &outbound.protocol else {
            panic!("expected hysteria2, got {:?}", outbound.protocol);
        };
        assert_eq!(
            obfs,
            &Some(Obfs {
                kind: "gecko".into(),
                password: "salt".into(),
                min_packet_size: Some(512),
                max_packet_size: Some(1200),
            })
        );
        // Both schemes are sing-box's, and both need their password.
        let error = CoreProfile::parse("hysteria2://secret@example.com:443?obfs=gecko")
            .expect_err("gecko needs obfs-password");
        assert!(error.contains("obfs-password"), "{error}");
        let error = CoreProfile::parse(
            "hysteria2://secret@example.com:443?obfs=gecko&obfs-password=salt\
             &minPacketSize=1200&maxPacketSize=512",
        )
        .expect_err("a window that runs backwards is refused");
        assert!(error.contains("minPacketSize"), "{error}");
        let error =
            CoreProfile::parse("hysteria2://secret@example.com:443?obfs=dns&obfs-password=s")
                .expect_err("only the two schemes sing-box implements are accepted");
        assert!(error.contains("salamander"), "{error}");
    }

    #[test]
    fn quic_link_parameters_this_app_cannot_honour_are_refused() {
        let error = CoreProfile::parse("hysteria2://secret@example.com:443?mport=1-9000")
            .expect_err("a range that large is refused");
        assert!(error.contains("hopping"), "{error}");
        let error = CoreProfile::parse("hysteria2://secret@example.com:443?up=fast")
            .expect_err("bandwidth is a number");
        assert!(error.contains("Mbps"), "{error}");
        let error = CoreProfile::parse("tuic://not-a-uuid:pass@example.com:443")
            .expect_err("tuic needs a UUID");
        assert!(error.contains("uuid"), "{error}");
        assert!(CoreProfile::parse("hysteria2://example.com:443").is_ok());
    }
}
