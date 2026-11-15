//! The Xray-core and sing-box cores: profile, planning and in-process driving.
//!
//! Both cores are built from source at build time into the app's single Go
//! archive — the same one that carries tun2socks and Psiphon — and are started
//! in this process. There is no core executable, no subprocess, no temp config
//! on disk and no second toolchain at runtime.
//!
//! One archive is not a convenience, it is a constraint: a Go program has one
//! runtime, so a second archive would duplicate runtime symbols and give each
//! dependency two copies. The graph unifies cleanly — see `bridges/tun2socks/
//! build.rs` for what was verified — and per-core Cargo features keep a core's
//! Go code out of the binary when its feature is off.
//!
//! This module holds everything the two cores share:
//!
//! * share-link / native-config parsing for [`CoreProfile`] — session configuration,
//!   parsed once with the rest of [`crate::config::SessionConfig`]. The grammar
//!   covers both cores' protocols, including the sing-box-only Hysteria2, TUIC
//!   and AnyTLS, and every transport and security setting either core's own
//!   grammar defines. [`Outbound::carried_by`] answers whether a core can run
//!   one whole — a setting neither can express is refused with the reason
//!   naming the core that can, never dropped,
//! * [`Plan`] and [`plan_listeners`] — what the session asks of the core,
//! * [`Rules`] — the app's split-routing rules, validated,
//! * [`Dialect`] + [`start`] — the only per-core seam: the config dialect and
//!   the C entry points the core's shim exports from the shared archive,
//! * [`native_dialect`] — which core a native config was written for, which is
//!   what [`crate::saved_configs`] tags a saved config with.

use std::collections::HashMap;
use std::ffi::{c_char, c_int, CStr, CString};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use fcae_abi::{FcaeBackend, FcaeEngineLog, FcaeState};
use parking_lot::Mutex;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::backend::{BackendContext, BackendHandle, Counters, Endpoints};
use crate::config::{RoutingConfig, SessionConfig};
use crate::error::{CoreError, Result as CoreResult};
use crate::upstream::{ProxyKind, UpstreamProxy};

/// How long a core gets to accept its first connection.
const READY_TIMEOUT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(250);
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// An outbound's transport, carrying every field a share link can name for it.
///
/// The two cores do not overlap here: Xray-core owns mKCP and XHTTP, sing-box
/// owns plain HTTP/2 — and each refuses the other's, which
/// [`Outbound::carried_by`] reports by name rather than dropping the settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Tcp,
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
            Transport::Ws { .. } => "ws",
            Transport::HttpUpgrade { .. } => "httpupgrade",
            Transport::H2 { .. } => "http",
            Transport::Grpc { .. } => "grpc",
            Transport::Kcp { .. } => "kcp",
            Transport::Xhttp { .. } => "xhttp",
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
        /// `pcs`: hex SHA-256 pins of the server certificate. Xray-core only —
        /// sing-box pins the public key, which is a different digest.
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
    },
}

/// A SIP003 plugin, as a share link spells it: the name up to the first `;` and
/// the plugin's own options after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowSocksPlugin {
    pub name: String,
    pub options: Option<String>,
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
    /// Hysteria2 — QUIC, TLS by contract, Brutal congestion control. sing-box
    /// implements it; Xray-core has no equivalent, so [`Protocol::xray_carries`]
    /// is false.
    Hysteria2 {
        password: String,
        /// Packet obfuscation: the scheme (`salamander`) and its password.
        obfs: Option<(String, String)>,
        /// Bandwidth hint in Mbps, which is what Brutal shapes to.
        up_mbps: Option<u32>,
        down_mbps: Option<u32>,
        /// Port hopping ranges, in sing-box's `server_ports` syntax.
        ports: Vec<String>,
        /// Seconds between hops.
        hop_interval: Option<u64>,
        /// SHA-256 of the server certificate's public key, base64 as sing-box
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
    },
    /// AnyTLS — TLS with a padding scheme. sing-box only.
    AnyTls {
        password: String,
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
        }
    }

    /// Whether Xray-core's config grammar can express this protocol.
    ///
    /// The QUIC and AnyTLS families exist only in sing-box, so a link for one
    /// is refused for Xray here — at save time and again at start — instead of
    /// reaching the core as a config it cannot parse.
    pub fn xray_carries(&self) -> bool {
        match self {
            Protocol::Hysteria2 { .. } | Protocol::Tuic { .. } | Protocol::AnyTls { .. } => false,
            // Xray's cipher list is the AEAD set plus Shadowsocks 2022; the
            // stream ciphers sing-box still carries are gone from it.
            Protocol::Shadowsocks { method, plugin, .. } => {
                plugin.is_none() && xray_cipher(method)
            }
            _ => true,
        }
    }

    /// Whether sing-box can express this outbound.
    ///
    /// Everything but one case: sing-box speaks plain VLESS, without the
    /// ML-KEM handshake Xray added on top, and its outbound grammar has no
    /// field to name one.
    pub fn sing_box_carries(&self) -> bool {
        match self {
            Protocol::Vless { encryption: Some(_), .. } => false,
            // sing-box's outbound method enum is Xray's set plus the stream
            // ciphers; anything else is a link neither core implements.
            Protocol::Shadowsocks { method, .. } => sing_box_cipher(method),
            _ => true,
        }
    }
}

/// Xray's Shadowsocks cipher names, as `cipherFromString` and the 2022 list
/// spell them.
fn xray_cipher(method: &str) -> bool {
    matches!(
        method,
        "aes-128-gcm"
            | "aead_aes_128_gcm"
            | "aes-256-gcm"
            | "aead_aes_256_gcm"
            | "chacha20-poly1305"
            | "aead_chacha20_poly1305"
            | "chacha20-ietf-poly1305"
            | "xchacha20-poly1305"
            | "aead_xchacha20_poly1305"
            | "xchacha20-ietf-poly1305"
            | "none"
            | "plain"
            | "2022-blake3-aes-128-gcm"
            | "2022-blake3-aes-256-gcm"
            | "2022-blake3-chacha20-poly1305"
    )
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
        use FcaeBackend::{SingBox, Xray};
        let label = crate::config::backend_label(backend);
        let other = match backend {
            Xray => crate::config::backend_label(SingBox),
            _ => crate::config::backend_label(Xray),
        };
        let refuse = |what: &str| {
            Some(format!(
                "{what}; save it as a {other} config, {label} cannot carry it"
            ))
        };
        let name = self.protocol.name();
        if backend == Xray && !self.protocol.xray_carries() {
            return match &self.protocol {
                Protocol::Shadowsocks { plugin: Some(plugin), .. } => refuse(&format!(
                    "the shadowsocks plugin {:?} is sing-box only",
                    plugin.name
                )),
                Protocol::Shadowsocks { method, .. } => refuse(&format!(
                    "the shadowsocks method {method:?} was removed from Xray-core"
                )),
                _ => refuse(&format!("a {name} link runs on sing-box only")),
            };
        }
        if backend == SingBox && !self.protocol.sing_box_carries() {
            return match &self.protocol {
                Protocol::Vless { encryption: Some(_), .. } => Some(format!(
                    "this {name} link uses Xray-core's VLESS encryption; save it as an Xray config, {label} cannot carry it"
                )),
                Protocol::Shadowsocks { method, .. } => refuse(&format!(
                    "the shadowsocks method {method:?} is not one {label} implements"
                )),
                _ => refuse(&format!("a {name} link runs on Xray only")),
            };
        }
        match (&self.transport, backend) {
            (Transport::H2 { .. }, Xray) => {
                return refuse(&format!(
                    "Xray-core removed the {} transport in favour of XHTTP",
                    self.transport.name()
                ))
            }
            (Transport::Kcp { .. } | Transport::Xhttp { .. }, SingBox) => {
                return refuse(&format!(
                    "the {} transport is an Xray-core one",
                    self.transport.name()
                ))
            }
            (
                Transport::Ws {
                    early_data_header: Some(_),
                    ..
                },
                Xray,
            ) => {
                return refuse("the WebSocket early-data header is a sing-box setting")
            }
            (Transport::Grpc { multi_mode: true, .. }, SingBox) => {
                return refuse("gRPC multi-stream mode is an Xray-core setting")
            }
            (Transport::Grpc { authority: Some(_), .. }, SingBox) => {
                return refuse("the gRPC authority is an Xray-core setting")
            }
            _ => {}
        }
        match &self.security {
            Security::Reality {
                mldsa65_verify: Some(_),
                ..
            } if backend == SingBox => {
                return refuse("the REALITY ML-DSA-65 key is an Xray-core setting")
            }
            // Xray-core refuses `allowInsecure` outright now and points at the
            // certificate pins; sing-box still takes it.
            Security::Tls {
                allow_insecure: true,
                ..
            } if backend == Xray => {
                return refuse(
                    "Xray-core removed allowInsecure; use the certificate pins, or sing-box",
                )
            }
            Security::Tls {
                pinned_cert_sha256: Some(_),
                ..
            } if backend == SingBox => {
                return refuse("the certificate pin is an Xray-core setting")
            }
            Security::Tls {
                verify_cert_by_name: Some(_),
                ..
            } if backend == SingBox => {
                return refuse("the verified certificate name is an Xray-core setting")
            }
            _ => {}
        }
        if self.finalmask.is_some() && backend == SingBox {
            return refuse("finalmask is an Xray-core setting");
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CoreProfile {
    Link(Outbound),
    /// Verbatim native config; the bridge rewrites listeners and log level.
    Native(Value),
}

impl CoreProfile {
    /// Parse and validate `core.profile`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("no profile: set a share link or a native config JSON".into());
        }
        if text.starts_with('{') {
            let value: Value = serde_json::from_str(text)
                .map_err(|error| format!("native config is not valid JSON: {error}"))?;
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
        let outbound = match scheme.as_str() {
            "vless" => parse_vless(rest)?,
            "vmess" => parse_vmess(rest)?,
            "trojan" => parse_trojan(rest)?,
            "ss" | "shadowsocks" => parse_shadowsocks(rest)?,
            "socks" | "socks5" | "socks5h" => parse_socks(rest)?,
            "http" => parse_http(rest, false)?,
            "https" => parse_http(rest, true)?,
            // sing-box only; the Xray bridge refuses these by name.
            "hysteria2" | "hy2" => parse_hysteria2(rest)?,
            "tuic" => parse_tuic(rest)?,
            "anytls" => parse_anytls(rest)?,
            other => {
                return Err(format!(
                    "unsupported scheme {other:?} (vless, vmess, trojan, ss, socks5, http, \
                     hysteria2, tuic, anytls)"
                ))
            }
        };
        Ok(CoreProfile::Link(outbound))
    }

    /// Outbound endpoint, when the profile names one.
    pub fn endpoint(&self) -> Option<(&str, u16)> {
        match self {
            CoreProfile::Link(outbound) => Some((outbound.server.as_str(), outbound.port)),
            CoreProfile::Native(_) => None,
        }
    }
}

/// The core a native config was written for, when its outbounds make it
/// unambiguous.
///
/// The two dialects differ in one place that matters here: an Xray outbound
/// carries a `protocol`, a sing-box outbound a `type`. Share links are
/// understood by both cores, and an empty or missing `outbounds` says nothing,
/// so both of those answer `None`.
pub fn native_dialect(text: &str) -> Option<FcaeBackend> {
    let value: Value = serde_json::from_str(text).ok()?;
    let outbounds = value.get("outbounds")?.as_array()?;
    let (mut xray, mut sing_box) = (false, false);
    for outbound in outbounds {
        let Some(object) = outbound.as_object() else {
            continue;
        };
        xray |= object.contains_key("protocol");
        sing_box |= object.contains_key("type");
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
        if !matches!(flow, "xtls-rprx-vision" | "xtls-rprx-vision-udp443") {
            return Err(format!(
                "vless flow={flow:?} is not supported (only xtls-rprx-vision)"
            ));
        }
    }
    let security = parse_security(&query, &server, false)?;
    if flow.is_some() && matches!(security, Security::None) {
        return Err("vless flow requires tls or reality security".into());
    }
    Ok(Outbound {
        protocol: Protocol::Vless { uuid, flow, encryption },
        transport: parse_transport(&query)?,
        security,
        finalmask: parse_finalmask(&query)?,
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
    let body = rest.split('#').next().unwrap_or(rest).trim();
    let decoded = b64_decode(body).ok_or("a vmess link must be vmess://<base64 JSON>")?;
    let json: Value = serde_json::from_str(&decoded)
        .map_err(|error| format!("vmess payload is not JSON: {error}"))?;
    let server = json_text(&json, "add").ok_or("vmess payload has no \"add\" server")?;
    let port = parse_port(&json_text(&json, "port").ok_or("vmess payload has no \"port\"")?)?;
    let uuid = json_text(&json, "id").ok_or("vmess payload has no \"id\"")?;
    if !valid_uuid(&uuid) {
        return Err(format!("vmess id {:?} is not a UUID", excerpt(&uuid)));
    }
    let alter_id = json_text(&json, "aid")
        .and_then(|text| text.trim().parse::<u16>().ok())
        .unwrap_or(0);
    let cipher = json_text(&json, "scy").unwrap_or_else(|| "auto".into());
    // `type` is the old TCP/mKCP header obfuscation, which the core removed
    // along with the mKCP header itself: a link still naming one is reported,
    // not quietly downgraded to a plain header.
    if let Some(kind) = json_text(&json, "type") {
        if !kind.eq_ignore_ascii_case("none") {
            return Err(format!(
                "the vmess header type {kind:?} was removed from Xray-core (finalmask replaced it)"
            ));
        }
    }
    // The JSON names the same transports the query grammar does, only under
    // `net`/`path`/`host`, so it is handed to the one parser that knows all of
    // them instead of a second, shorter copy of it.
    let network = json_text(&json, "net");
    let mut params = Query::new();
    params.set("type", network.clone());
    if network.is_some_and(|net| net.eq_ignore_ascii_case("grpc")) {
        params.set(
            "servicename",
            json_text(&json, "path").or_else(|| json_text(&json, "host")),
        );
    } else {
        params.set("path", json_text(&json, "path"));
        params.set("host", json_text(&json, "host"));
    }
    let transport = parse_transport(&params)?;
    let security = if json_text(&json, "tls").is_some_and(|tls| tls.eq_ignore_ascii_case("tls")) {
        tls_security(
            json_text(&json, "sni").or_else(|| json_text(&json, "host")),
            split_list(json_text(&json, "alpn").as_deref()),
            json_text(&json, "fp"),
            false,
            None,
        )
    } else {
        Security::None
    };
    Ok(Outbound {
        protocol: Protocol::Vmess {
            uuid,
            alter_id,
            security: cipher,
        },
        transport,
        security,
        finalmask: None,
        server,
        port,
        remark: percent_text(rest.split_once('#').map(|(_, remark)| remark)),
    })
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
    let (server, port) = split_host_port(target, None)?;
    Ok(Outbound {
        protocol: Protocol::Trojan { password },
        transport: parse_transport(&query)?,
        // Trojan is TLS by definition; links routinely omit `security=tls`.
        security: parse_security(&query, &server, true)?,
        finalmask: parse_finalmask(&query)?,
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
        remark,
    })
}

fn parse_http(rest: &str, tls: bool) -> Result<Outbound, String> {
    let (body, remark) = split_fragment(rest);
    let (body, _params) = split_query(body);
    let (userinfo, target) = match body.rsplit_once('@') {
        Some((userinfo, target)) => (Some(userinfo), target),
        None => (None, body),
    };
    let (server, port) = split_host_port(target, Some(if tls { 443 } else { 8080 }))?;
    let (user, password) = split_credentials(userinfo);
    Ok(Outbound {
        protocol: Protocol::Http { user, password },
        transport: Transport::Tcp,
        security: if tls {
            tls_security(host_name(&server), Vec::new(), None, false, None)
        } else {
            Security::None
        },
        server,
        port,
        finalmask: None,
        remark,
    })
}

// ---------------------------------------------------------------------------
// sing-box share links
// ---------------------------------------------------------------------------
//
// Hysteria2, TUIC and AnyTLS are sing-box's own protocols; Xray-core has no
// equivalent. They are parsed here with the rest of the link grammar so a saved
// config is validated once, and the Xray bridge refuses them by name.

fn parse_hysteria2(rest: &str) -> Result<Outbound, String> {
    let (body, remark) = split_fragment(rest);
    let (authority, params) = split_query(body);
    let query = Query::parse(params);
    let (userinfo, target) = authority
        .rsplit_once('@')
        .ok_or("a hysteria2 link must be hysteria2://<password>@<host>:<port>")?;
    let password = percent_decode(userinfo).trim().to_string();
    if password.is_empty() {
        return Err("a hysteria2 link needs its password".into());
    }
    let (server, port) = split_host_port(trim_trailing_path(target), Some(443))?;
    let obfs = match query.string("obfs").map(|kind| kind.to_ascii_lowercase()) {
        None => None,
        Some(kind) if kind == "salamander" => {
            let secret = query
                .first(&["obfs-password", "obfs_password"])
                .ok_or("hysteria2 obfs=salamander needs obfs-password")?;
            Some((kind, percent_decode(secret)))
        }
        Some(other) => {
            return Err(format!(
                "hysteria2 obfs {other:?} is not supported (only salamander)"
            ))
        }
    };
    Ok(Outbound {
        protocol: Protocol::Hysteria2 {
            password,
            obfs,
            up_mbps: query.mbps(&["up", "upmbps", "up_mbps"])?,
            down_mbps: query.mbps(&["down", "downmbps", "down_mbps"])?,
            ports: query.ports(&["mport", "ports"])?,
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
    Ok(Outbound {
        protocol: Protocol::Tuic {
            uuid,
            password: percent_decode(raw_password),
            congestion_control,
            udp_relay_mode,
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
        remark,
    })
}

fn parse_anytls(rest: &str) -> Result<Outbound, String> {
    let (body, remark) = split_fragment(rest);
    let (authority, params) = split_query(body);
    let query = Query::parse(params);
    let (userinfo, target) = authority
        .rsplit_once('@')
        .ok_or("an anytls link must be anytls://<password>@<host>:<port>")?;
    let password = percent_decode(userinfo).trim().to_string();
    if password.is_empty() {
        return Err("an anytls link needs its password".into());
    }
    let (server, port) = split_host_port(trim_trailing_path(target), Some(443))?;
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
        remark,
    })
}

/// `hysteria2://…@host:443/?…` and friends carry a path separator no other
/// scheme uses; the authority ends at it.
fn trim_trailing_path(target: &str) -> &str {
    target.trim_end_matches('/')
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
    let path = query.string("path").unwrap_or_else(|| "/".into());
    let host = query.string("host");
    // Early data travels as a count plus the header it is sent in; Xray keeps
    // the count in the path query and dropped the header, sing-box names both.
    let max_early_data = query
        .number("ed")?
        .or(query.number("maxearlydata")?)
        .filter(|count| *count > 0);
    let transport = match network.as_str() {
        // `raw` is the name Xray 25.x gave the plain TCP transport.
        "tcp" | "raw" | "none" => Transport::Tcp,
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
            if let Some(kind) = query.get("headertype").filter(|kind| !kind.eq_ignore_ascii_case("none")) {
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
                    let value: Value = serde_json::from_str(raw).map_err(|error| {
                        format!("xhttp extra is not JSON: {error}")
                    })?;
                    if !value.is_object() {
                        return Err("xhttp extra must be a JSON object".into());
                    }
                    Some(value.to_string())
                }
                None => None,
            };
            Transport::Xhttp {
                path,
                host,
                mode: query.string("mode"),
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

fn parse_security(query: &Query, server: &str, implicit_tls: bool) -> Result<Security, String> {
    let mode = query
        .get("security")
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| if implicit_tls { "tls".into() } else { "none".into() });
    match mode.as_str() {
        "" | "none" => Ok(Security::None),
        "tls" | "xtls" => Ok(Security::Tls {
            sni: query
                .string("sni")
                .or_else(|| query.string("peer"))
                .or_else(|| host_name(server)),
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
            let sni = query
                .string("sni")
                .or_else(|| host_name(server))
                .ok_or("reality needs sni (the camouflaged server name)")?;
            Ok(Security::Reality {
                sni,
                fingerprint: query
                    .string("fp")
                    .unwrap_or_else(|| "chrome".into()),
                public_key,
                short_id: query.string("sid").unwrap_or_default(),
                spider_x: query.string("spx").unwrap_or_else(|| "/".into()),
                mldsa65_verify: query.string("pqv"),
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
        pinned_cert_sha256: query.and_then(|query| query.string("pcs")),
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

fn split_fragment(rest: &str) -> (&str, Option<String>) {
    match rest.split_once('#') {
        Some((body, remark)) => (body, Some(percent_decode(remark))),
        None => (rest, None),
    }
}

fn split_query(body: &str) -> (&str, &str) {
    match body.split_once('?') {
        Some((authority, query)) => (authority, query),
        None => (body, ""),
    }
}

fn split_host_port(target: &str, default_port: Option<u16>) -> Result<(String, u16), String> {
    let target = target.trim();
    if let Some(rest) = target.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("unterminated IPv6 literal in {:?}", excerpt(target)))?;
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

fn checked_host(host: &str) -> Result<String, String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("empty host".into());
    }
    if host.chars().any(|c| c.is_whitespace() || c == '/' || c == '@') {
        return Err(format!("host {:?} is malformed", excerpt(host)));
    }
    Ok(host.to_string())
}

fn parse_port(text: &str) -> Result<u16, String> {
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
    let decoded = decode_credentials(userinfo);
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

fn split_list(list: Option<&str>) -> Vec<String> {
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

fn percent_text(text: Option<&str>) -> Option<String> {
    text.map(percent_decode).filter(|text| !text.is_empty())
}

fn excerpt(text: &str) -> String {
    const LIMIT: usize = 48;
    if text.chars().count() <= LIMIT {
        return text.to_string();
    }
    let head: String = text.chars().take(LIMIT).collect();
    format!("{head}…")
}

fn percent_decode(text: &str) -> String {
    if !text.contains('%') {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
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
fn b64_decode(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    for engine in [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(text) {
            if let Ok(decoded) = String::from_utf8(bytes) {
                return Some(decoded);
            }
        }
    }
    None
}

struct Query(HashMap<String, String>);

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

    fn parse(params: &str) -> Self {
        let mut map = HashMap::new();
        for pair in params.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = match pair.split_once('=') {
                Some((key, value)) => (percent_decode(key), percent_decode(value)),
                None => (percent_decode(pair), String::new()),
            };
            map.entry(key.to_ascii_lowercase())
                .or_insert_with(|| value.trim().to_string());
        }
        Self(map)
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.0
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    fn string(&self, key: &str) -> Option<String> {
        self.get(key).map(str::to_string)
    }

    fn list(&self, key: &str) -> Vec<String> {
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
    fn boolean(&self, key: &str) -> Result<Option<bool>, String> {
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
    fn first(&self, keys: &[&str]) -> Option<&str> {
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
    /// public key, converted to the base64 sing-box's `tls` block takes.
    fn pin(&self) -> Result<Option<String>, String> {
        let Some(raw) = self.first(&["pinsha256", "pin_sha256", "pinned_sha256", "pin"]) else {
            return Ok(None);
        };
        let digest = hex_decode(raw.trim())
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

/// Verbosity handed to a core's own logger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    pub fn of(level: FcaeEngineLog) -> Self {
        match level {
            FcaeEngineLog::Off => Self::Off,
            FcaeEngineLog::Error => Self::Error,
            FcaeEngineLog::Warn => Self::Warn,
            FcaeEngineLog::Info => Self::Info,
            FcaeEngineLog::Debug => Self::Debug,
            FcaeEngineLog::Trace => Self::Trace,
        }
    }
}

/// Everything a config generator needs from the session.
pub struct Plan<'a> {
    pub profile: &'a CoreProfile,
    pub socks: Option<SocketAddr>,
    pub http: Option<SocketAddr>,
    pub level: Level,
    pub upstream: Option<&'a UpstreamProxy>,
    pub routing: &'a RoutingConfig,
}

/// Free loopback ports, held until every pick is made so two reservations in one
/// start cannot collide.
#[derive(Default)]
struct Reserved(Vec<std::net::TcpListener>);

impl Reserved {
    fn take(&mut self) -> CoreResult<u16> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|error| {
            CoreError::StartFailed(format!("cannot allocate an internal port: {error}"))
        })?;
        let port = listener
            .local_addr()
            .map_err(|error| {
                CoreError::StartFailed(format!("cannot inspect an internal port: {error}"))
            })?
            .port();
        self.0.push(listener);
        Ok(port)
    }
}

/// Resolve the listeners the core must open for this session.
///
/// `lan_sharing` widens the public listeners to 0.0.0.0; internal ones always
/// stay on loopback. TUN mode and chained hops force a SOCKS listener even when
/// the user switched the public one off, because both dial the core through it.
pub fn plan_listeners(
    config: &SessionConfig,
) -> CoreResult<(Option<SocketAddr>, Option<SocketAddr>)> {
    let mut reserved = Reserved::default();
    let bind = if config.lan_sharing {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::LOCALHOST
    };
    let mut socks = if config.internal_socks {
        Some(SocketAddr::from((Ipv4Addr::LOCALHOST, reserved.take()?)))
    } else if config.socks_port != 0 {
        Some(SocketAddr::from((bind, config.socks_port)))
    } else {
        None
    };
    let http = if config.internal_http {
        Some(SocketAddr::from((Ipv4Addr::LOCALHOST, reserved.take()?)))
    } else if config.http_port != 0 {
        Some(SocketAddr::from((bind, config.http_port)))
    } else {
        None
    };
    if socks.is_none() && (config.is_tun() || config.require_udp_proxy) {
        socks = Some(SocketAddr::from((Ipv4Addr::LOCALHOST, reserved.take()?)));
    }
    drop(reserved);
    if socks.is_none() && http.is_none() {
        return Err(CoreError::InvalidConfig(
            "this core needs a SOCKS5 or HTTP listener; enable one for the session".into(),
        ));
    }
    Ok((socks, http))
}

/// Whether a split-routing entry is a network (IP or CIDR) rather than a name.
pub fn is_network(entry: &str) -> bool {
    match entry.split_once('/') {
        Some((address, prefix)) => {
            address.parse::<IpAddr>().is_ok() && prefix.parse::<u8>().is_ok_and(|p| p <= 128)
        }
        None => entry.parse::<IpAddr>().is_ok(),
    }
}

/// A hostname a split-routing rule may name. Wildcards are accepted because the
/// app's rule box accepts them; the `*.` prefix is stripped before use.
pub fn valid_domain(entry: &str) -> bool {
    let entry = entry.trim_start_matches("*.");
    !entry.is_empty()
        && entry
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        && entry.chars().any(|c| c.is_ascii_alphabetic())
}

/// Split-routing entries, validated and classified once for the generator.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Rules {
    pub direct_ips: Vec<String>,
    pub direct_domains: Vec<String>,
    pub block_ips: Vec<String>,
    pub block_domains: Vec<String>,
}

impl Rules {
    pub fn build(routing: &RoutingConfig) -> std::result::Result<Self, String> {
        if routing.rules_file.is_some() {
            return Err(
                "a routing rule file is not supported by these cores; use inline direct/block rules"
                    .into(),
            );
        }
        let mut rules = Self::default();
        for entry in &routing.direct {
            rules.push(entry, false)?;
        }
        for entry in &routing.block {
            rules.push(entry, true)?;
        }
        Ok(rules)
    }

    pub fn is_empty(&self) -> bool {
        self.direct_ips.is_empty()
            && self.direct_domains.is_empty()
            && self.block_ips.is_empty()
            && self.block_domains.is_empty()
    }

    fn push(&mut self, entry: &str, block: bool) -> std::result::Result<(), String> {
        let entry = entry.trim();
        if entry.is_empty() {
            return Ok(());
        }
        let (ips, domains) = if block {
            (&mut self.block_ips, &mut self.block_domains)
        } else {
            (&mut self.direct_ips, &mut self.direct_domains)
        };
        if is_network(entry) {
            ips.push(entry.to_string());
        } else if valid_domain(entry) {
            domains.push(entry.trim_start_matches("*.").to_ascii_lowercase());
        } else {
            return Err(format!(
                "routing entry {entry:?} is not an IP address, a CIDR or a hostname"
            ));
        }
        Ok(())
    }
}

/// Addresses the TUN bridge must keep off its own device, so the core's uplink
/// does not re-enter the tunnel it just created.
///
/// Resolved only in TUN mode: proxy mode has no route to loop, and a blocked
/// resolver must not fail a session that would otherwise work.
pub async fn resolve_peer(
    config: &SessionConfig,
    server: &str,
    port: u16,
) -> CoreResult<Option<String>> {
    if let Some(pin) = config.force_peer.as_deref() {
        let ip = parse_pin(pin).ok_or_else(|| {
            CoreError::InvalidConfig(format!("force_peer {pin:?} is not an IP address"))
        })?;
        return Ok(Some(ip.to_string()));
    }
    if !config.is_tun() {
        return Ok(None);
    }
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok(routable(ip).then(|| ip.to_string()));
    }
    let resolved = timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((server, port)))
        .await
        .map_err(|_| {
            CoreError::StartFailed(format!("resolving {server} for the TUN bypass route timed out"))
        })?
        .map_err(|error| CoreError::StartFailed(format!("cannot resolve {server}: {error}")))?;
    let mut peers: Vec<String> = Vec::new();
    for address in resolved {
        let ip = address.ip();
        let text = ip.to_string();
        if routable(ip) && !peers.contains(&text) {
            peers.push(text);
        }
    }
    if peers.is_empty() {
        return Err(CoreError::StartFailed(format!(
            "{server} resolved to no routable address; TUN mode would route the tunnel into itself"
        )));
    }
    Ok(Some(peers.join(",")))
}

fn parse_pin(pin: &str) -> Option<IpAddr> {
    let pin = pin.trim();
    if let Ok(address) = pin.parse::<SocketAddr>() {
        return Some(address.ip());
    }
    pin.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .ok()
}

fn routable(ip: IpAddr) -> bool {
    !(ip.is_unspecified() || ip.is_multicast() || ip.is_loopback())
}

// ---------------------------------------------------------------------------
// In-process driving
// ---------------------------------------------------------------------------

/// The C entry points a core's shim exports from the shared Go archive.
///
/// Every core exports the same shapes under its own prefix; holding them in
/// one struct is what lets [`start`] be written once for both cores.
#[derive(Clone, Copy)]
pub struct CoreFfi {
    pub start: unsafe extern "C" fn(*const c_char) -> *mut c_char,
    pub stop: unsafe extern "C" fn(),
    pub running: unsafe extern "C" fn() -> c_int,
    /// Frees a message the shim returned, with the shim's own allocator.
    pub string_free: unsafe extern "C" fn(*mut c_char),
    /// Cumulative `(uplink, downlink)` bytes through the core. Returns 1 when
    /// the core reported a sample and 0 when it has none to report — the
    /// counters are optional, so a config without them is not an error.
    pub stats: unsafe extern "C" fn(*mut i64, *mut i64) -> c_int,
    /// Installs the host log sink (NULL clears it) and its level gate, from the
    /// scale [`log_gate`] produces.
    pub set_log: unsafe extern "C" fn(Option<unsafe extern "C" fn(c_int, *const c_char)>, c_int),
}

/// One core's build identity and config grammar — the only per-core code.
pub trait Dialect: Send + Sync + 'static {
    /// Human-readable name for messages.
    const DISPLAY: &'static str;
    /// The shim this core exports from `libfcae_go_bridge`.
    const FFI: CoreFfi;
    /// The trampoline that receives this core's log lines.
    const LOG_SINK: unsafe extern "C" fn(c_int, *const c_char);

    /// Emit the core's own config for this session.
    fn generate(plan: &Plan<'_>) -> std::result::Result<Value, String>;
}

/// Level gate for a core's logger: 0 leaves it silent, 1..=4 are errors,
/// warnings, info and debug. The scale is the shims': see `xray.set_log` and
/// `sb.set_log` in `bridges/*/go/bridge.go`.
fn log_gate(level: Level) -> c_int {
    match level {
        Level::Off => 0,
        Level::Error => 1,
        Level::Warn => 2,
        Level::Info => 3,
        Level::Debug | Level::Trace => 4,
    }
}

/// Hand one core log line to the app's logger.
///
/// The shims call this from their own goroutines with a NUL-terminated line
/// they own, so it is copied before returning and nothing panics across the cgo
/// boundary.
pub fn forward_log(core: &str, level: c_int, message: *const c_char) {
    if message.is_null() {
        return;
    }
    let level = match level {
        1 => log::Level::Error,
        2 => log::Level::Warn,
        4 => log::Level::Debug,
        _ => log::Level::Info,
    };
    // The gate drops most of what a core emits, so check before building the
    // line, not after.
    if !log::log_enabled!(level) {
        return;
    }
    let _ = std::panic::catch_unwind(|| {
        // SAFETY: the pointer is valid for the duration of the call, as the
        // shims pass a `C.CString` they free immediately afterwards.
        let text = unsafe { CStr::from_ptr(message) }.to_string_lossy();
        log::log!(level, "[{core}] {text}");
    });
}

/// Load the core, start it on the generated config and wait until its listeners
/// answer.
pub async fn start<D: Dialect>(cx: &BackendContext) -> CoreResult<Running> {
    let config = &cx.config;
    // Parsed and validated with the rest of the session config; missing here
    // means the route has no core, which the supervisor never starts.
    let profile = config
        .core
        .profile
        .as_ref()
        .ok_or_else(|| CoreError::InvalidConfig(format!("{} needs core.profile", D::DISPLAY)))?;

    let (socks, http) = plan_listeners(config)?;
    let peer_ip = match profile.endpoint() {
        Some((server, port)) => resolve_peer(config, server, port).await?,
        None => None,
    };

    let generated = D::generate(&Plan {
        profile,
        socks,
        http,
        level: Level::of(config.core.log_level),
        upstream: config.upstream_proxy.as_ref(),
        routing: &config.routing,
    })
    .map_err(|error| CoreError::InvalidConfig(format!("{}: {error}", D::DISPLAY)))?;
    let body = serde_json::to_string(&generated).map_err(|error| {
        CoreError::Internal(format!("cannot serialise the {} config: {error}", D::DISPLAY))
    })?;

    let target = profile
        .endpoint()
        .map(|(server, port)| format!("{server}:{port}"))
        .unwrap_or_else(|| "the native config".to_string());
    cx.report(
        FcaeState::Connecting,
        format!("Starting {} → {target}", D::DISPLAY),
    );

    let endpoints = Endpoints {
        socks,
        http,
        peer_ip,
        udp: true,
        psiphon_dns: false,
    };

    // Starting a core parses its config and binds its listeners, which can take
    // a second or two, so it runs on the blocking pool: a long Go call must not
    // stall a Tokio worker the rest of the session shares.
    let ffi = D::FFI;
    // The sink goes in before the core runs, not after: binding listeners,
    // resolving the server and failing a config all happen during start, and
    // that is exactly what a user needs in the console.
    unsafe { (ffi.set_log)(Some(D::LOG_SINK), log_gate(Level::of(config.core.log_level))) };
    let started = tokio::task::spawn_blocking(move || {
        // Unpacks the embedded cronet DLL where sing-box's loader can find it,
        // if this build embedded one. It has to happen before the core starts:
        // the Go side caches its first load attempt, failures included.
        crate::cronet::prepare();
        call_start(ffi, body)
    })
        .await
        .map_err(|error| {
            CoreError::Internal(format!("the {} start task failed: {error}", D::DISPLAY))
        })?;
    match started {
        Ok(()) => {}
        Err(CallError::Config) => {
            return Err(CoreError::Internal(format!(
                "the generated {} config contains a NUL byte",
                D::DISPLAY
            )))
        }
        Err(CallError::Core(text)) => {
            halt(ffi).await;
            return Err(CoreError::StartFailed(format!("{}: {text}", D::DISPLAY)));
        }
    }

    let running = Running {
        ffi,
        rtt_target: RttTarget::new(profile, config.upstream_proxy.clone()),
        endpoints,
        stopping: AtomicBool::new(false),
        traffic: Mutex::new(Traffic::default()),
        rtt_ms: Arc::new(AtomicU32::new(0)),
        rtt_started: Arc::new(AtomicBool::new(false)),
        rtt_attempts: AtomicU32::new(0),
        rtt_next: Mutex::new(None),
    };
    running.await_ready().await?;
    Ok(running)
}

/// Why a start call failed.
enum CallError {
    /// The config cannot be expressed as a C string — our own bug, not input.
    Config,
    /// The core refused it, with its own message.
    Core(String),
}

/// Enter the core's shim and start it. Blocking.
fn call_start(ffi: CoreFfi, body: String) -> std::result::Result<(), CallError> {
    let json = CString::new(body).map_err(|_| CallError::Config)?;
    // SAFETY: `json` outlives the call and the shim copies it before returning;
    // a non-NULL result is a string the shim allocated, freed by its own
    // allocator through `string_free`.
    unsafe {
        let error = (ffi.start)(json.as_ptr());
        if error.is_null() {
            return Ok(());
        }
        let text = CStr::from_ptr(error).to_string_lossy().into_owned();
        (ffi.string_free)(error);
        Err(CallError::Core(text))
    }
}

/// Stop the core off the async workers. Blocking, idempotent.
async fn halt(ffi: CoreFfi) {
    let _ = tokio::task::spawn_blocking(move || unsafe { (ffi.stop)() }).await;
}

/// A started core. Dropping it is not the teardown path — [`BackendHandle::stop`]
/// is, because it is the only one that can report a timeout.
pub struct Running {
    ffi: CoreFfi,
    endpoints: Endpoints,
    stopping: AtomicBool,
    /// Sample bookkeeping behind [`BackendHandle::counters`].
    traffic: Mutex<Traffic>,
    /// Tunnel round trip in milliseconds; 0 until a probe succeeds.
    rtt_ms: Arc<AtomicU32>,
    /// Held while a probe is in flight, and for good once one has answered.
    rtt_started: Arc<AtomicBool>,
    /// Probes started so far; indexes [`RTT_RETRY`].
    rtt_attempts: AtomicU32,
    /// Earliest time the next probe may start.
    rtt_next: Mutex<Option<Instant>>,
    /// The remote to handshake with, or `None` for an outbound no TCP handshake
    /// can reach.
    rtt_target: Option<RttTarget>,
}

impl Running {
    /// Wait until every listener answers a real handshake.
    ///
    /// A bound-but-uninitialised inbound accepts a connection and drops it, so a
    /// TCP connect alone is not enough: the SOCKS listener is greeted.
    async fn await_ready(&self) -> CoreResult<()> {
        let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
        loop {
            if !self.alive() {
                halt(self.ffi).await;
                return Err(CoreError::StartFailed(
                    "the core exited while starting".to_string(),
                ));
            }
            if let Some(socks) = self.endpoints.socks {
                if probe(socks, true).await.is_ok() {
                    log::info!("[core] listening on {socks}");
                    return Ok(());
                }
            } else if let Some(http) = self.endpoints.http {
                if probe(http, false).await.is_ok() {
                    log::info!("[core] listening on {http}");
                    return Ok(());
                }
            } else {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                halt(self.ffi).await;
                return Err(CoreError::StartFailed(format!(
                    "the core did not accept connections within {}s",
                    READY_TIMEOUT.as_secs()
                )));
            }
            tokio::time::sleep(POLL).await;
        }
    }

    fn alive(&self) -> bool {
        // SAFETY: the shim is linked into this binary for the whole process
        // lifetime, so the pointer is always valid.
        unsafe { (self.ffi.running)() == 1 }
    }

    /// Cumulative `(tx, rx)` bytes from the core, or `None` when it keeps no
    /// counters.
    fn bytes(&self) -> Option<(u64, u64)> {
        let mut uplink: i64 = 0;
        let mut downlink: i64 = 0;
        // SAFETY: the shim writes both values through the pointers, and it is
        // linked into this binary for the whole process lifetime.
        let reported = unsafe { (self.ffi.stats)(&mut uplink, &mut downlink) };
        (reported == 1).then(|| (uplink.max(0) as u64, downlink.max(0) as u64))
    }

    /// Measure the session's handshake with its remote.
    ///
    /// Neither core reports latency without a config section this app does not
    /// own — Xray wants an `observatory`, sing-box a `urltest` group, and both
    /// measure by fetching a URL — so it is measured here instead: the round
    /// trip the session's last leg spends reaching the server the config names.
    /// A direct outbound gets a SYN to the server; a chained one gets the
    /// CONNECT the hop above issues, because that is the path its traffic takes.
    /// No application request is sent: the SYN, or the hop's CONNECT, is the
    /// whole exchange, and no third party is contacted.
    ///
    /// Outbounds no TCP handshake can reach — QUIC end to end — have no reading
    /// ([`RttTarget`]), and none is invented for them.
    ///
    /// A probe that fails is retried on [`RTT_RETRY`]'s spacing: holding the
    /// "already probed" flag across a failure was a one-shot that left a session
    /// whose first probe landed before the tunnel settled with no latency at all
    /// until it was restarted.
    fn measure_rtt(&self) {
        let Some(target) = self.rtt_target.as_ref() else { return };
        if self.rtt_ms.load(Ordering::Acquire) != 0
            || self.rtt_started.swap(true, Ordering::AcqRel)
        {
            return;
        }
        let attempt = self.rtt_attempts.fetch_add(1, Ordering::AcqRel) as usize;
        {
            let mut next = self.rtt_next.lock();
            if next.as_ref().is_some_and(|at| Instant::now() < *at) {
                self.rtt_started.store(false, Ordering::Release);
                return;
            }
            let seconds = RTT_RETRY[attempt.min(RTT_RETRY.len() - 1)];
            *next = Some(Instant::now() + Duration::from_secs(seconds));
        }
        let rtt_ms = Arc::clone(&self.rtt_ms);
        let started = Arc::clone(&self.rtt_started);
        let target = target.clone();
        let spawned = std::thread::Builder::new()
            .name("fcae-core-rtt".into())
            .spawn(move || match handshake(&target) {
                Some(measured) => {
                    log::debug!("[core] handshake to {} took {measured}ms", target.server);
                    rtt_ms.store(measured, Ordering::Release);
                }
                // Cleared, not held: the next sample retries on the spacing
                // above.
                None => started.store(false, Ordering::Release),
            });
        if spawned.is_err() {
            self.rtt_started.store(false, Ordering::Release);
        }
    }
}

/// Seconds between probe attempts, from the end of the previous one. The first
/// few cover a tunnel that is still warming up when the session reports its
/// first sample; the rest keep a route that heals later in the session
/// measurable without spending a thread on a dead one every second.
const RTT_RETRY: [u64; 9] = [0, 2, 5, 15, 30, 60, 120, 300, 600];

/// How long a handshake may take: the SYN, or the CONNECT a fronting hop has to
/// dial and answer. It is a network round trip over a mobile link, not the
/// loopback greeting [`PROBE_TIMEOUT`] covers, so it gets room of its own.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Longest header block a proxy's CONNECT answer may take before it is not one.
const HEAD_LIMIT: usize = 4096;

/// The remote a session handshakes with, and what fronts it.
///
/// `server` stays as the config spells it: a hostname is handed to the hop that
/// fronts this one, which resolves it exactly as the core would, and only a
/// direct outbound resolves it here.
#[derive(Clone)]
struct RttTarget {
    server: String,
    port: u16,
    /// The proxy this core dials through: the hop above it in a chain, or the
    /// user's own upstream proxy.
    via: Option<UpstreamProxy>,
}

impl RttTarget {
    /// The remote to handshake with, or `None` when no TCP handshake can reach
    /// this outbound.
    ///
    /// mKCP rides UDP, and hysteria2 and tuic are QUIC end to end, so a SYN to
    /// their server says nothing about the path the tunnel takes. A native
    /// config has no single remote at all: it brings its own outbounds.
    fn new(profile: &CoreProfile, via: Option<UpstreamProxy>) -> Option<Self> {
        let CoreProfile::Link(outbound) = profile else { return None };
        if matches!(outbound.protocol, Protocol::Hysteria2 { .. } | Protocol::Tuic { .. })
            || matches!(outbound.transport, Transport::Kcp { .. })
        {
            return None;
        }
        Some(Self { server: outbound.server.clone(), port: outbound.port, via })
    }
}

/// Time one handshake with the target's remote, in milliseconds.
fn handshake(target: &RttTarget) -> Option<u32> {
    match &target.via {
        None => handshake_direct(&target.server, target.port),
        Some(proxy) => handshake_via(proxy, target),
    }
}

/// Our own SYN to the server. The handshake is the measurement; nothing is sent
/// after it, and the connection is closed as soon as it is answered.
fn handshake_direct(server: &str, port: u16) -> Option<u32> {
    use std::net::ToSocketAddrs;

    // Resolution is not part of a round trip, so every candidate is resolved
    // before the clock starts; each attempt is then timed on its own, so a
    // first family that goes nowhere cannot inflate the answer that worked.
    let addresses: Vec<std::net::SocketAddr> = (server, port).to_socket_addrs().ok()?.collect();
    for address in addresses {
        let started = Instant::now();
        if std::net::TcpStream::connect_timeout(&address, HANDSHAKE_TIMEOUT).is_ok() {
            return Some(millis_ceil(started.elapsed()));
        }
    }
    None
}

/// The handshake the hop above performs: the proxy is asked to connect, and the
/// time that takes — its own dial to the server, plus the server's answer
/// travelling back — is the round trip to the remote.
fn handshake_via(proxy: &UpstreamProxy, target: &RttTarget) -> Option<u32> {
    use std::io::{Read, Write};

    // Includes the hop's own connection: on a loopback hop it costs nothing,
    // and on the user's proxy it is a leg their traffic really takes.
    let started = Instant::now();
    let mut stream = open(proxy)?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).ok()?;
    match proxy.kind {
        ProxyKind::Socks5 => {
            socks_negotiate(&mut stream, proxy)?;
            stream.write_all(&socks_connect_request(&target.server, target.port)).ok()?;
            // A reply code other than success means the hop could not reach the
            // server, so there is no round trip to report.
            socks_reply(&mut stream)?;
        }
        ProxyKind::Http => {
            stream.write_all(http_connect_request(proxy, target).as_bytes()).ok()?;
            let mut status = [0u8; 12];
            stream.read_exact(&mut status).ok()?;
            // A 2xx is the proxy's own confirmation that the server answered.
            if !status.starts_with(b"HTTP/1.") || status[8] != b' ' || status[9] != b'2' {
                return None;
            }
            skip_headers(&mut stream, [0; 4])?;
        }
    }
    Some(millis_ceil(started.elapsed()))
}

/// Connect to a proxy. Untimed on its own; [`handshake_via`] owns the clock.
fn open(proxy: &UpstreamProxy) -> Option<std::net::TcpStream> {
    use std::net::ToSocketAddrs;

    for address in (proxy.host.as_str(), proxy.port).to_socket_addrs().ok()? {
        if let Ok(stream) = std::net::TcpStream::connect_timeout(&address, HANDSHAKE_TIMEOUT) {
            return Some(stream);
        }
    }
    None
}

/// SOCKS5 method negotiation, plus RFC 1929 when the proxy asks for credentials.
fn socks_negotiate(stream: &mut std::net::TcpStream, proxy: &UpstreamProxy) -> Option<()> {
    use std::io::{Read, Write};

    let credentials = proxy.user.is_some() && proxy.password.is_some();
    let methods: &[u8] = if credentials { &[0x00, 0x02] } else { &[0x00] };
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(0x05);
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).ok()?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).ok()?;
    match choice {
        [0x05, 0x00] => Some(()),
        [0x05, 0x02] => {
            let user = proxy.user.as_deref().unwrap_or("").as_bytes();
            let password = proxy.password.as_deref().unwrap_or("").as_bytes();
            let mut auth = Vec::with_capacity(3 + user.len() + password.len());
            auth.push(0x01);
            auth.push(user.len().min(u8::MAX as usize) as u8);
            auth.extend_from_slice(&user[..user.len().min(u8::MAX as usize)]);
            auth.push(password.len().min(u8::MAX as usize) as u8);
            auth.extend_from_slice(&password[..password.len().min(u8::MAX as usize)]);
            stream.write_all(&auth).ok()?;
            let mut reply = [0u8; 2];
            stream.read_exact(&mut reply).ok()?;
            (reply == [0x01, 0x00]).then_some(())
        }
        _ => None,
    }
}

/// A SOCKS5 CONNECT for the remote, addressed the way the core addresses it: an
/// IP literal as itself, a hostname as a name the proxy resolves.
fn socks_connect_request(server: &str, port: u16) -> Vec<u8> {
    let mut request = Vec::with_capacity(22);
    request.extend_from_slice(&[0x05, 0x01, 0x00]);
    match server.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let host = server.as_bytes();
            let length = host.len().min(u8::MAX as usize);
            request.push(0x03);
            request.push(length as u8);
            request.extend_from_slice(&host[..length]);
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    request
}

/// A proxied CONNECT for the remote, with the proxy's credentials when it has
/// any.
fn http_connect_request(proxy: &UpstreamProxy, target: &RttTarget) -> String {
    let authority = if target.server.contains(':') {
        format!("[{}]:{}", target.server, target.port)
    } else {
        format!("{}:{}", target.server, target.port)
    };
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(user) = proxy.user.as_deref() {
        let password = proxy.password.as_deref().unwrap_or("");
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&crate::upstream::base64(format!("{user}:{password}").as_bytes()));
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request
}

/// Read a SOCKS5 reply in full: version, status, address type, the bound
/// address and its port.
///
/// The address is consumed even though nothing needs it, because a caller that
/// went on to use the connection would otherwise read the tail of the reply as
/// if it were payload.
fn socks_reply(stream: &mut std::net::TcpStream) -> Option<()> {
    use std::io::Read;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).ok()?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return None;
    }
    let mut left = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).ok()?;
            length[0] as usize + 2
        }
        _ => return None,
    };
    let mut skip = [0u8; 18];
    while left > 0 {
        let take = left.min(skip.len());
        stream.read_exact(&mut skip[..take]).ok()?;
        left -= take;
    }
    Some(())
}

/// Read through the blank line that ends an HTTP header block.
///
/// `window` is the last four bytes already consumed, oldest first: a header
/// block can end inside what the caller has read, and re-reading it is not
/// possible.
fn skip_headers(stream: &mut std::net::TcpStream, mut window: [u8; 4]) -> Option<()> {
    use std::io::Read;

    let mut byte = [0u8; 1];
    for _ in 0..HEAD_LIMIT {
        if &window == b"\r\n\r\n" {
            return Some(());
        }
        stream.read_exact(&mut byte).ok()?;
        window.rotate_left(1);
        window[3] = byte[0];
    }
    None
}

/// Milliseconds, rounded up and never zero: the value is also what the UI reads
/// as "measured", and 0 means it has nothing to show.
fn millis_ceil(elapsed: Duration) -> u32 {
    let millis = elapsed.as_micros().div_ceil(1000);
    millis.clamp(1, u32::MAX as u128) as u32
}

/// Bytes-per-second between two samples `elapsed_ms` apart, computed in
/// milliseconds so a fast pump cannot collapse the rate to zero.
fn rate(delta: u64, elapsed_ms: u64) -> u64 {
    delta.saturating_mul(1_000) / elapsed_ms.max(1)
}

/// Rate bookkeeping for one core.
///
/// Totals are cumulative and the pump samples them once a second; the UI wants
/// bytes/sec, so the previous sample is kept here. Owned by the handle rather
/// than a module static, so two cores in one process can never share a
/// baseline, and a restarted core starts a fresh one.
#[derive(Default)]
struct Traffic {
    /// Totals published by the last sample.
    total_tx: u64,
    total_rx: u64,
    /// Baseline of the last rate calculation.
    prev_tx: u64,
    prev_rx: u64,
    at: Option<Instant>,
}

impl Traffic {
    /// Fold one shim sample into a telemetry sample.
    ///
    /// `None` means the core had no totals to report: the previous ones are
    /// republished with zero rates, because a momentary gap must not look like
    /// a restart to [`crate::telemetry`] — it folds the published total when a
    /// sample goes backwards, and folding twice would double-count the session.
    fn counters(&mut self, sample: Option<(u64, u64)>, now: Instant, rtt_ms: u32) -> Counters {
        if let Some((tx, rx)) = sample {
            self.total_tx = tx;
            self.total_rx = rx;
        }
        let (tx_bytes_sec, rx_bytes_sec) = match self.at {
            // The first sample has no baseline; a one-off spike of the session's
            // lifetime bytes would be a lie.
            None => (0, 0),
            Some(at) => {
                let elapsed = now.saturating_duration_since(at).as_millis() as u64;
                (
                    rate(self.total_tx.saturating_sub(self.prev_tx), elapsed),
                    rate(self.total_rx.saturating_sub(self.prev_rx), elapsed),
                )
            }
        };
        self.prev_tx = self.total_tx;
        self.prev_rx = self.total_rx;
        self.at = Some(now);
        Counters {
            total_rx: self.total_rx,
            total_tx: self.total_tx,
            rx_bytes_sec,
            tx_bytes_sec,
            rtt_ms,
        }
    }
}

#[async_trait]
impl BackendHandle for Running {
    fn endpoints(&self) -> Endpoints {
        self.endpoints.clone()
    }

    fn carrier_up(&self) -> bool {
        self.alive()
    }

    /// Cumulative totals read from the core's own stats manager, the rate
    /// between the last two polls, and the tunnel round trip once measured.
    /// Nothing here is estimated: a core that reports no counters publishes
    /// zeros instead of a guess.
    fn counters(&self) -> Counters {
        self.measure_rtt();
        let sample = self.bytes();
        let rtt_ms = self.rtt_ms.load(Ordering::Acquire);
        self.traffic
            .lock()
            .counters(sample, Instant::now(), rtt_ms)
    }

    /// The cores have no "session ended" event to await, so the handle polls the
    /// running flag. A stop this handle asked for is a clean exit.
    async fn wait(&self) -> CoreResult<()> {
        while self.alive() {
            tokio::time::sleep(POLL).await;
        }
        if self.stopping.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(CoreError::StartFailed("the core stopped".into()))
        }
    }

    async fn stop(&self, timeout: Duration) -> CoreResult<()> {
        self.stopping.store(true, Ordering::SeqCst);
        halt(self.ffi).await;
        let deadline = tokio::time::Instant::now() + timeout;
        while self.alive() {
            if tokio::time::Instant::now() >= deadline {
                return Err(CoreError::Timeout(timeout));
            }
            tokio::time::sleep(POLL).await;
        }
        Ok(())
    }
}

async fn probe(address: SocketAddr, socks: bool) -> std::io::Result<()> {
    let mut stream = timeout(PROBE_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))??;
    if !socks {
        return Ok(());
    }
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut reply = [0u8; 2];
    timeout(PROBE_TIMEOUT, stream.read_exact(&mut reply))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "SOCKS5 greeting timed out"))??;
    if reply != [0x05, 0x00] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected SOCKS5 greeting {reply:?}"),
        ));
    }
    Ok(())
}

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
        let plugin = link("ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388\
            ?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com");
        match &plugin.protocol {
            Protocol::Shadowsocks { plugin, .. } => {
                let plugin = plugin.as_ref().expect("plugin parsed");
                assert_eq!(plugin.name, "obfs-local");
                assert_eq!(plugin.options.as_deref(), Some("obfs=http;obfs-host=bing.com"));
            }
            other => panic!("expected shadowsocks, got {other:?}"),
        }
        assert!(plugin.carried_by(FcaeBackend::SingBox));
        assert!(!plugin.carried_by(FcaeBackend::Xray));
        assert!(plugin.refusal(FcaeBackend::Xray).contains("sing-box"));
        assert!(CoreProfile::parse(
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388?plugin=kcptun"
        )
        .is_err());

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
            Security::Reality {
                mldsa65_verify, ..
            } => assert_eq!(mldsa65_verify.as_deref(), Some("PQKEY")),
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
                    &Some(("salamander".to_string(), "salt".to_string()))
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
        // Xray-core has no Hysteria2 outbound: the bridge refuses it by name.
        assert!(!outbound.protocol.xray_carries());
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

    #[test]
    fn quic_link_parameters_this_app_cannot_honour_are_refused() {
        let error = CoreProfile::parse("hysteria2://secret@example.com:443?obfs=gecko")
            .expect_err("only salamander is supported");
        assert!(error.contains("salamander"), "{error}");
        let error = CoreProfile::parse("hysteria2://secret@example.com:443?mport=1-9000")
            .expect_err("a range that large is refused");
        assert!(error.contains("hopping"), "{error}");
        let error = CoreProfile::parse("hysteria2://secret@example.com:443?up=fast")
            .expect_err("bandwidth is a number");
        assert!(error.contains("Mbps"), "{error}");
        let error = CoreProfile::parse("tuic://not-a-uuid:pass@example.com:443")
            .expect_err("tuic needs a UUID");
        assert!(error.contains("uuid"), "{error}");
        let error = CoreProfile::parse("hysteria2://example.com:443")
            .expect_err("hysteria2 needs a password");
        assert!(error.contains("password"), "{error}");
    }

    #[test]
    fn the_log_gate_follows_the_engine_level() {
        assert_eq!(log_gate(Level::Off), 0);
        assert_eq!(log_gate(Level::Error), 1);
        assert_eq!(log_gate(Level::Warn), 2);
        assert_eq!(log_gate(Level::Info), 3);
        assert_eq!(log_gate(Level::Debug), 4);
        assert_eq!(log_gate(Level::Trace), 4);
    }

    #[test]
    fn traffic_rates_follow_the_pump_interval() {
        let start = Instant::now();
        let mut traffic = Traffic::default();
        let first = traffic.counters(Some((1_000, 500)), start, 0);
        assert_eq!((first.total_tx, first.total_rx), (1_000, 500));
        // No baseline yet: totals without an invented rate.
        assert_eq!((first.tx_bytes_sec, first.rx_bytes_sec), (0, 0));
        let second = traffic.counters(Some((3_000, 1_500)), start + Duration::from_secs(2), 42);
        assert_eq!((second.total_tx, second.total_rx), (3_000, 1_500));
        assert_eq!((second.tx_bytes_sec, second.rx_bytes_sec), (1_000, 500));
        assert_eq!(second.rtt_ms, 42);
        // Sub-second pumps are scaled, not truncated: 50 bytes in 500 ms.
        let fast = traffic.counters(Some((3_050, 1_500)), start + Duration::from_millis(2_500), 42);
        assert_eq!(fast.tx_bytes_sec, 100);
    }

    #[test]
    fn a_silent_core_keeps_its_totals_instead_of_restarting_them() {
        let start = Instant::now();
        let mut traffic = Traffic::default();
        traffic.counters(Some((4_000, 2_000)), start, 0);
        // The core reports nothing for one poll: republish, do not reset.
        let gap = traffic.counters(None, start + Duration::from_secs(1), 0);
        assert_eq!((gap.total_tx, gap.total_rx), (4_000, 2_000));
        assert_eq!((gap.tx_bytes_sec, gap.rx_bytes_sec), (0, 0));
        let resumed = traffic.counters(Some((4_500, 2_000)), start + Duration::from_secs(2), 0);
        assert_eq!((resumed.total_tx, resumed.total_rx), (4_500, 2_000));
        assert_eq!(resumed.tx_bytes_sec, 500);
    }

    /// A connected pair whose peer writes `bytes` and hangs up.
    fn loopback(bytes: &'static [u8]) -> std::net::TcpStream {
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept");
            let _ = peer.write_all(bytes);
        });
        std::net::TcpStream::connect(address).expect("connect")
    }

    #[test]
    fn a_socks_reply_is_read_past_its_bound_address() {
        use std::io::Read as _;

        // A bound IPv4 address, then the answer: the helper must stop at the
        // answer, not inside the address it does not need.
        let mut stream = loopback(&[
            0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x1f, 0x90, b'H', b'T',
        ]);
        assert_eq!(socks_reply(&mut stream), Some(()));
        let mut next = [0u8; 2];
        stream.read_exact(&mut next).expect("payload");
        assert_eq!(&next, b"HT");

        // A domain-shaped address carries a length byte of its own.
        let mut stream = loopback(&[
            0x05, 0x00, 0x00, 0x03, 9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0x1f,
            0x90, b'H',
        ]);
        assert_eq!(socks_reply(&mut stream), Some(()));
        let mut next = [0u8; 1];
        stream.read_exact(&mut next).expect("payload");
        assert_eq!(&next, b"H");
    }

    #[test]
    fn a_refused_socks_reply_is_not_a_measurement() {
        // REP 0x05 is "connection refused": the tunnel never came up, so there
        // is nothing to time.
        let mut stream = loopback(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        assert_eq!(socks_reply(&mut stream), None);
    }

    #[test]
    fn a_connect_answer_is_read_to_the_end_of_its_headers() {
        use std::io::Read as _;

        // The tail of the status line, a header, the blank line, then the
        // tunnelled answer.
        let mut stream = loopback(b" 200 Connection established\r\nVia: proxy\r\n\r\nHT");
        skip_headers(&mut stream, [0; 4]).expect("headers end");
        let mut next = [0u8; 2];
        stream.read_exact(&mut next).expect("payload");
        assert_eq!(&next, b"HT");
    }

    /// A listener on loopback that hands every connection to `serve`.
    fn serve(serve: impl FnOnce(std::net::TcpStream) + Send + 'static) -> std::net::SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            serve(stream);
        });
        address
    }

    fn proxy(kind: ProxyKind, address: std::net::SocketAddr) -> UpstreamProxy {
        UpstreamProxy {
            kind,
            host: address.ip().to_string(),
            port: address.port(),
            user: None,
            password: None,
        }
    }

    #[test]
    fn a_direct_handshake_times_the_remote_itself() {
        use std::io::Read as _;

        // The server says nothing; the reading is the handshake, so an accept
        // with no answer at all is still a measurement.
        let address = serve(|mut stream| {
            let mut buffer = [0u8; 1];
            let _ = stream.read(&mut buffer);
        });
        let target = RttTarget {
            server: address.ip().to_string(),
            port: address.port(),
            via: None,
        };
        let measured = handshake(&target).expect("measured");
        assert!(measured >= 1, "a handshake reads as at least a millisecond");
    }

    #[test]
    fn a_handshake_nobody_answers_is_not_a_measurement() {
        // A port with nothing behind it: the tunnel is not up, so there is no
        // round trip to report and the sample retries instead.
        let address = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("address")
        };
        let target = RttTarget {
            server: address.ip().to_string(),
            port: address.port(),
            via: None,
        };
        assert_eq!(handshake(&target), None);
    }

    #[test]
    fn a_chained_session_handshakes_through_the_hop_above() {
        use std::io::{Read as _, Write as _};

        // A hop that answers its CONNECT only after a delay, the way a proxy
        // that has to dial the server does. The reading must include that wait,
        // and the request must name the server as a name for the hop to resolve.
        let address = serve(|mut stream| {
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).expect("greeting");
            stream.write_all(&[0x05, 0x00]).expect("greeting reply");
            let mut head = [0u8; 5];
            stream.read_exact(&mut head).expect("connect head");
            assert_eq!(head[3], 0x03, "the server is handed over as a name");
            let mut rest = vec![0u8; head[4] as usize + 2];
            stream.read_exact(&mut rest).expect("host and port");
            std::thread::sleep(Duration::from_millis(150));
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x1f, 0x90])
                .expect("connect reply");
        });
        let target = RttTarget {
            server: "example.com".into(),
            port: 443,
            via: Some(proxy(ProxyKind::Socks5, address)),
        };
        let measured = handshake(&target).expect("measured");
        assert!(measured >= 100, "the hop's dial was not timed: {measured}ms");
    }

    #[test]
    fn a_hop_that_cannot_reach_the_server_reports_nothing() {
        use std::io::{Read as _, Write as _};

        // SOCKS5 reply 0x05 is "connection refused": the hop tried and failed,
        // so the number would be the hop's, not the server's.
        let address = serve(|mut stream| {
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).expect("greeting");
            stream.write_all(&[0x05, 0x00]).expect("greeting reply");
            let mut rest = [0u8; 7];
            stream.read_exact(&mut rest).expect("connect");
            stream
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .expect("connect reply");
        });
        let target = RttTarget {
            server: "example.com".into(),
            port: 443,
            via: Some(proxy(ProxyKind::Socks5, address)),
        };
        assert_eq!(handshake(&target), None);
    }

    #[test]
    fn a_proxy_that_wants_credentials_gets_them() {
        use std::io::{Read as _, Write as _};

        // RFC 1929: the offer lists "no auth" and "username/password", the proxy
        // picks the latter, and only the right password gets a CONNECT through.
        let address = serve(|mut stream| {
            let mut greeting = [0u8; 4];
            stream.read_exact(&mut greeting).expect("greeting");
            assert_eq!(greeting, [0x05, 0x02, 0x00, 0x02]);
            stream.write_all(&[0x05, 0x02]).expect("method reply");
            let mut head = [0u8; 2];
            stream.read_exact(&mut head).expect("auth head");
            let mut user = vec![0u8; head[1] as usize];
            stream.read_exact(&mut user).expect("user");
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).expect("password length");
            let mut password = vec![0u8; length[0] as usize];
            stream.read_exact(&mut password).expect("password");
            let accepted = user == b"alice" && password == b"secret";
            stream
                .write_all(&[0x01, if accepted { 0x00 } else { 0x01 }])
                .expect("auth reply");
            if !accepted {
                return;
            }
            let mut request = [0u8; 7];
            stream.read_exact(&mut request).expect("connect");
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .expect("connect reply");
        });
        let with = |password: &str| RttTarget {
            server: "example.com".into(),
            port: 443,
            via: Some(UpstreamProxy {
                user: Some("alice".into()),
                password: Some(password.into()),
                ..proxy(ProxyKind::Socks5, address)
            }),
        };
        assert!(handshake(&with("secret")).is_some());
        assert_eq!(handshake(&with("wrong")), None);
    }

    #[test]
    fn an_http_proxy_handshakes_with_connect_and_its_credentials() {
        use std::io::{Read as _, Write as _};

        let address = serve(|mut stream| {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).expect("request");
                head.push(byte[0]);
            }
            let text = String::from_utf8(head).expect("utf-8");
            assert!(text.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            // "alice:secret" in Basic.
            assert!(text.contains("Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answer");
        });
        let target = RttTarget {
            server: "example.com".into(),
            port: 443,
            via: Some(UpstreamProxy {
                user: Some("alice".into()),
                password: Some("secret".into()),
                ..proxy(ProxyKind::Http, address)
            }),
        };
        assert!(handshake(&target).is_some());
    }

    #[test]
    fn an_outbound_no_tcp_handshake_reaches_has_no_target() {
        // QUIC end to end, and mKCP over UDP: a SYN to those servers would
        // measure a path the tunnel never takes.
        for link in [
            "hysteria2://pass@example.com:443?sni=example.com#q",
            "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pass@example.com:443#q",
        ] {
            let profile = CoreProfile::parse(link).expect("profile parses");
            assert!(RttTarget::new(&profile, None).is_none(), "{link}");
        }
        // The TCP dialects all get one, chained or not.
        for link in [
            format!("vless://{UUID}@example.com:443?type=tcp#direct"),
            format!("vless://{UUID}@example.com:443?type=kcp#udp"),
        ] {
            let profile = CoreProfile::parse(&link).expect("profile parses");
            let target = RttTarget::new(&profile, None);
            assert_eq!(target.is_some(), !link.ends_with("#udp"), "{link}");
        }
    }

    #[test]
    fn a_round_trip_is_never_reported_as_nothing() {
        // The value doubles as "measured": a sub-millisecond answer rounds up
        // to 1 instead of reading as unknown, and 1.4 ms is 2 ms, not 1.
        assert_eq!(millis_ceil(Duration::ZERO), 1);
        assert_eq!(millis_ceil(Duration::from_micros(1)), 1);
        assert_eq!(millis_ceil(Duration::from_micros(1_400)), 2);
        assert_eq!(millis_ceil(Duration::from_millis(63)), 63);
        assert_eq!(millis_ceil(Duration::from_millis(1)), 1);
    }
}
