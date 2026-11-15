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
//!   and AnyTLS; [`Protocol::xray_carries`] says which of them Xray-core can
//!   actually run,
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
use crate::upstream::UpstreamProxy;

/// How long a core gets to accept its first connection.
const READY_TIMEOUT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(250);
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Transports both cores can carry an outbound over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Ws { path: String, host: Option<String> },
    Grpc { service: String },
    /// HTTP/2 as Xray names it (sing-box calls the same thing `http`).
    H2 { path: String, host: Option<String> },
    HttpUpgrade { path: String, host: Option<String> },
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
        allow_insecure: bool,
    },
    Reality {
        sni: String,
        fingerprint: String,
        public_key: String,
        short_id: String,
        spider_x: String,
    },
}

/// Which protocol the outbound speaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Vless {
        uuid: String,
        flow: Option<String>,
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
        !matches!(
            self,
            Protocol::Hysteria2 { .. } | Protocol::Tuic { .. } | Protocol::AnyTls { .. }
        )
    }
}

/// Whether `backend` can carry `outbound`.
pub fn carries(backend: FcaeBackend, outbound: &Outbound) -> bool {
    match backend {
        FcaeBackend::Xray => outbound.protocol.xray_carries(),
        FcaeBackend::SingBox => true,
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    pub protocol: Protocol,
    pub server: String,
    pub port: u16,
    pub transport: Transport,
    pub security: Security,
    /// `#fragment` of the link, carried through for log lines only.
    pub remark: Option<String>,
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
    if let Some(encryption) = query.get("encryption") {
        if !encryption.eq_ignore_ascii_case("none") {
            return Err(format!(
                "vless encryption={encryption:?} is not supported (only \"none\")"
            ));
        }
    }
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
        protocol: Protocol::Vless { uuid, flow },
        transport: parse_transport(&query)?,
        security,
        server,
        port,
        remark,
    })
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
    let path = json_text(&json, "path");
    let host = json_text(&json, "host");
    let transport = match json_text(&json, "net")
        .unwrap_or_else(|| "tcp".into())
        .to_ascii_lowercase()
        .as_str()
    {
        "tcp" => Transport::Tcp,
        "ws" => Transport::Ws {
            path: path.unwrap_or_else(|| "/".into()),
            host,
        },
        "h2" | "http" => Transport::H2 {
            path: path.unwrap_or_else(|| "/".into()),
            host,
        },
        "grpc" => Transport::Grpc {
            service: path.or(host).unwrap_or_default(),
        },
        other => {
            return Err(format!(
                "unsupported vmess transport {other:?} (tcp, ws, h2, grpc)"
            ))
        }
    };
    let security = if json_text(&json, "tls").is_some_and(|tls| tls.eq_ignore_ascii_case("tls")) {
        Security::Tls {
            sni: json_text(&json, "sni").or_else(|| json_text(&json, "host")),
            alpn: split_list(json_text(&json, "alpn").as_deref()),
            fingerprint: json_text(&json, "fp"),
            allow_insecure: false,
        }
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
        server,
        port,
        remark,
    })
}

fn parse_shadowsocks(rest: &str) -> Result<Outbound, String> {
    let (body, remark) = split_fragment(rest);
    let (body, _params) = split_query(body);
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
        },
        transport: Transport::Tcp,
        security: Security::None,
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
            Security::Tls {
                sni: host_name(&server),
                alpn: Vec::new(),
                fingerprint: None,
                allow_insecure: false,
            }
        } else {
            Security::None
        },
        server,
        port,
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
        security: Security::Tls {
            sni: query
                .string("sni")
                .or_else(|| query.string("peer"))
                .or_else(|| host_name(&server)),
            alpn: query.list("alpn"),
            fingerprint: None,
            allow_insecure: query.flag("insecure") || query.flag("allowinsecure"),
        },
        server,
        port,
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
        security: Security::Tls {
            sni: query.string("sni").or_else(|| host_name(&server)),
            alpn: query.list("alpn"),
            fingerprint: query.string("fp"),
            allow_insecure: query.flag("insecure")
                || query.flag("allow_insecure")
                || query.flag("allowinsecure"),
        },
        server,
        port,
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
        security: Security::Tls {
            sni: query
                .string("sni")
                .or_else(|| query.string("peer"))
                .or_else(|| host_name(&server)),
            alpn: query.list("alpn"),
            fingerprint: query.string("fp"),
            allow_insecure: query.flag("insecure") || query.flag("allowinsecure"),
        },
        server,
        port,
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
    let transport = match network.as_str() {
        // `raw` is the name Xray 25.x gave the plain TCP transport.
        "tcp" | "raw" | "none" => Transport::Tcp,
        "ws" => Transport::Ws { path, host },
        "h2" | "http" => Transport::H2 { path, host },
        "httpupgrade" => Transport::HttpUpgrade { path, host },
        "grpc" | "gun" => {
            if query.get("mode").is_some_and(|mode| mode.eq_ignore_ascii_case("multi")) {
                return Err("grpc multi-stream mode is not supported; use a single grpc stream".into());
            }
            Transport::Grpc {
                service: query.string("servicename").unwrap_or_default(),
            }
        }
        other => {
            return Err(format!(
                "unsupported transport {other:?} (tcp, ws, grpc, h2, httpupgrade)"
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
            })
        }
        other => Err(format!(
            "unsupported security {other:?} (none, tls, reality)"
        )),
    }
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
            total = total.saturating_add(end - start + 1);
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
        endpoints,
        stopping: AtomicBool::new(false),
        traffic: Mutex::new(Traffic::default()),
        rtt_ms: Arc::new(AtomicU32::new(0)),
        rtt_started: AtomicBool::new(false),
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
    /// One probe per session: set before the probe thread starts, cleared only
    /// if it could not be spawned.
    rtt_started: AtomicBool,
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

    /// Measure the tunnel round trip, once per session.
    ///
    /// Neither core reports latency without a config section this app does not
    /// own (Xray's observatory, sing-box's `urltest` group), so it is measured
    /// the way the Psiphon bridge measures it: one connect through the core's
    /// own listener, timed until the core answers. The probe runs on its own
    /// thread so a stalled tunnel can never delay a telemetry sample.
    fn measure_rtt(&self) {
        if self.rtt_ms.load(Ordering::Acquire) != 0
            || self.rtt_started.swap(true, Ordering::AcqRel)
        {
            return;
        }
        // A SOCKS listener answers a CONNECT only after the outbound dial
        // completes, and so does the HTTP proxy; either is a full tunnel round
        // trip. SOCKS wins because TUN mode always has one.
        let target = match (self.endpoints.socks, self.endpoints.http) {
            (Some(socks), _) => (socks, true),
            (None, Some(http)) => (http, false),
            (None, None) => {
                self.rtt_started.store(false, Ordering::Release);
                return;
            }
        };
        let rtt_ms = Arc::clone(&self.rtt_ms);
        let spawned = std::thread::Builder::new()
            .name("fcae-core-rtt".into())
            .spawn(move || {
                if let Some(measured) = rtt_once(target.0, target.1) {
                    rtt_ms.store(measured, Ordering::Release);
                }
            });
        if spawned.is_err() {
            self.rtt_started.store(false, Ordering::Release);
        }
    }
}

/// Host name and port the latency probe connects to: a plain HTTP port on a
/// host that answers everywhere, so the probe measures the tunnel and not the
/// target.
const RTT_HOST: &str = "www.gstatic.com";
const RTT_PORT: u16 = 80;

/// One tunnelled connect, timed from request to answer.
///
/// The target is named, never resolved locally: the core resolves it, so a
/// blocked local resolver cannot fake or fail a latency reading.
fn rtt_once(address: SocketAddr, socks: bool) -> Option<u32> {
    use std::io::{Read, Write};

    let mut stream = std::net::TcpStream::connect_timeout(&address, PROBE_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT)).ok()?;
    let started = if socks {
        // The greeting never leaves the host, so it is not part of the round
        // trip.
        stream.write_all(&[0x05, 0x01, 0x00]).ok()?;
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).ok()?;
        if greeting != [0x05, 0x00] {
            return None;
        }
        let host = RTT_HOST.as_bytes();
        let mut request = Vec::with_capacity(7 + host.len());
        request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
        request.extend_from_slice(host);
        request.extend_from_slice(&RTT_PORT.to_be_bytes());
        let started = Instant::now();
        stream.write_all(&request).ok()?;
        // VER, REP, RSV, ATYP: the address that follows is not needed.
        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).ok()?;
        if reply[0] != 0x05 || reply[1] != 0x00 {
            return None;
        }
        started
    } else {
        let request = format!(
            "CONNECT {RTT_HOST}:{RTT_PORT} HTTP/1.1\r\nHost: {RTT_HOST}:{RTT_PORT}\r\n\r\n"
        );
        let started = Instant::now();
        stream.write_all(request.as_bytes()).ok()?;
        let mut status = [0u8; 12];
        stream.read_exact(&mut status).ok()?;
        // A status line, and a 2xx/3xx answer: an error page is not a tunnel
        // round trip.
        if !status.starts_with(b"HTTP/1.") || status[8] != b' ' || !matches!(status[9], b'2' | b'3')
        {
            return None;
        }
        started
    };
    let elapsed = started.elapsed().as_millis();
    Some(elapsed.clamp(1, u32::MAX as u128) as u32)
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
                host: Some("cdn.example.com".into())
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
        .expect_err("non-none encryption must be rejected");
        assert!(error.contains("encryption"), "{error}");
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
                password: "secret".into()
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
    fn grpc_multi_mode_is_refused_rather_than_silently_downgraded() {
        let error = CoreProfile::parse(&format!(
            "vless://{UUID}@example.com:443?type=grpc&mode=multi&serviceName=svc"
        ))
        .expect_err("multi mode must be refused");
        assert!(error.contains("multi"), "{error}");
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
}
