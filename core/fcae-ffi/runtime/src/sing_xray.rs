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
//!   parsed once with the rest of [`crate::config::SessionConfig`],
//! * [`Plan`] and [`plan_listeners`] — what the session asks of the core,
//! * [`Rules`] — the app's split-routing rules, validated,
//! * [`Dialect`] + [`start`] — the only per-core seam: the config dialect and
//!   the C entry points the core's shim exports from the shared archive.

use std::collections::HashMap;
use std::ffi::{c_char, c_int, CStr, CString};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use fcae_abi::{FcaeEngineLog, FcaeState};
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
            other => {
                return Err(format!(
                    "unsupported scheme {other:?} (vless, vmess, trojan, ss, socks5, http)"
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
/// Every core exports the same four shapes under its own prefix; holding them in
/// one struct is what lets [`start`] be written once for both cores.
#[derive(Clone, Copy)]
pub struct CoreFfi {
    pub start: unsafe extern "C" fn(*const c_char) -> *mut c_char,
    pub stop: unsafe extern "C" fn(),
    pub running: unsafe extern "C" fn() -> c_int,
    /// Frees a message the shim returned, with the shim's own allocator.
    pub string_free: unsafe extern "C" fn(*mut c_char),
}

/// One core's build identity and config grammar — the only per-core code.
pub trait Dialect: Send + Sync + 'static {
    /// Human-readable name for messages.
    const DISPLAY: &'static str;
    /// The shim this core exports from `libfcae_go_bridge`.
    const FFI: CoreFfi;

    /// Emit the core's own config for this session.
    fn generate(plan: &Plan<'_>) -> std::result::Result<Value, String>;
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
    let started = tokio::task::spawn_blocking(move || call_start(ffi, body))
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
}

#[async_trait]
impl BackendHandle for Running {
    fn endpoints(&self) -> Endpoints {
        self.endpoints.clone()
    }

    fn carrier_up(&self) -> bool {
        self.alive()
    }

    /// The cores expose byte counters only through their stats APIs, which
    /// neither shim enables: a default sample leaves telemetry reporting "no
    /// sample yet" instead of inventing a rate.
    fn counters(&self) -> Counters {
        Counters::default()
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
}
