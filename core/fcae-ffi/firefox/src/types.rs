use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportPreference {
    Auto,
    H2,
    H1,
    H3,
}

impl Default for TransportPreference {
    fn default() -> Self {
        Self::Auto
    }
}

impl TransportPreference {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Some(Self::Auto),
            "h2" | "http2" | "http/2" => Some(Self::H2),
            "h1" | "http1" | "http/1.1" => Some(Self::H1),
            "h3" | "http3" | "http/3" => Some(Self::H3),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::H2 => "h2",
            Self::H1 => "h1",
            Self::H3 => "h3",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub data_dir: PathBuf,
    pub account_id: Option<String>,
    pub location: Option<String>,
    pub server: Option<String>,
    pub transport: TransportPreference,
    pub socks_addr: Option<std::net::SocketAddr>,
    pub http_addr: Option<std::net::SocketAddr>,
    pub upstream_proxy: Option<String>,
    pub ip_version: i32,
    pub connect_timeout: Duration,
    pub routing_rules: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub email: String,
    pub added_at: DateTime<Utc>,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub device_token: Option<String>,
    #[serde(default)]
    pub usage: Option<Usage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub oauth_scope: String,
    pub obtained_at: DateTime<Utc>,
    pub expires_in: u64,
}

impl Credentials {
    pub fn oauth_client_id(&self) -> &str {
        if self.client_id.is_empty() { crate::fxa::LEGACY_FIREFOX_CLIENT_ID } else { &self.client_id }
    }

    pub fn oauth_request_scope(&self) -> &str {
        if self.oauth_scope.is_empty() { crate::fxa::LEGACY_FIREFOX_SCOPE } else { &self.oauth_scope }
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.obtained_at + chrono::Duration::seconds(self.expires_in.min(i64::MAX as u64) as i64)
    }

    pub fn needs_refresh(&self, now: DateTime<Utc>) -> bool {
        self.access_token.is_empty()
            || self.expires_at() - chrono::Duration::minutes(2) <= now
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.scope.zeroize();
        self.client_id.zeroize();
        self.oauth_scope.zeroize();
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Usage {
    pub unlimited: bool,
    pub limit: i64,
    pub remaining: i64,
    #[serde(default)]
    pub reset: Option<DateTime<Utc>>,
}

impl Usage {
    pub fn exhausted(&self) -> bool {
        !self.unlimited && self.remaining <= 0
    }

    pub fn reset_suffix(&self) -> String {
        self.reset
            .map(|at| format!("; resets {}", at.to_rfc3339()))
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyPassClaims {
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub aud: serde_json::Value,
    #[serde(default)]
    pub iat: i64,
    #[serde(default)]
    pub nbf: i64,
    pub exp: i64,
    #[serde(default)]
    pub iss: String,
}

#[derive(Debug)]
pub struct ProxyPass {
    pub token: String,
    pub claims: ProxyPassClaims,
    pub received_at: SystemTime,
    pub not_before: SystemTime,
    pub expires_at: SystemTime,
    pub usage: Option<Usage>,
}

impl ProxyPass {
    pub fn renew_after(&self) -> SystemTime {
        self.expires_at.checked_sub(Duration::from_secs(90)).unwrap_or(self.received_at)
    }
}

impl Drop for ProxyPass {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Protocol {
    pub name: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default, rename = "templateString")]
    pub template_string: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub hostname: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub quarantined: bool,
    #[serde(default)]
    pub protocols: Vec<Protocol>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct City {
    pub name: String,
    pub code: String,
    #[serde(default)]
    pub servers: Vec<Server>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Country {
    pub name: String,
    pub code: String,
    #[serde(default)]
    pub cities: Vec<City>,
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub filter_expression: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub address: String,
    pub host: String,
    pub port: u16,
    pub country_name: String,
    pub country_code: String,
    pub city_name: String,
    pub city_code: String,
}

impl Candidate {
    pub fn authority(&self) -> String {
        authority(&self.host, self.port)
    }

    pub fn location_matches(&self, wanted: &str) -> bool {
        let wanted = wanted.trim();
        wanted.is_empty()
            || self.country_code.eq_ignore_ascii_case(wanted)
            || self.country_name.eq_ignore_ascii_case(wanted)
            || self.city_code.eq_ignore_ascii_case(wanted)
            || self.city_name.eq_ignore_ascii_case(wanted)
            || self.address.eq_ignore_ascii_case(wanted)
            || self.host.eq_ignore_ascii_case(wanted)
    }
}

#[derive(Debug, Clone, Default)]
pub struct PeerSet {
    pub selected: Vec<IpAddr>,
    pub control_plane: Vec<IpAddr>,
}

impl PeerSet {
    pub fn encoded(&self) -> Option<String> {
        let mut out = Vec::<IpAddr>::new();
        for ip in self.selected.iter().chain(self.control_plane.iter()) {
            if !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !out.contains(ip) {
                out.push(*ip);
            }
        }
        if out.is_empty() {
            None
        } else {
            Some(out.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(","))
        }
    }
}

pub fn authority(host: &str, port: u16) -> String {
    let host = host.trim_matches(['[', ']']);
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub fn split_authority(value: &str, default_port: u16) -> Option<(String, u16)> {
    let value = value.trim();
    if value.is_empty() || value.bytes().any(|b| b.is_ascii_whitespace() || b == b'/' || b == b'@') {
        return None;
    }
    if let Ok(addr) = value.parse::<std::net::SocketAddr>() {
        return (addr.port() != 0).then(|| (addr.ip().to_string(), addr.port()));
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return (default_port != 0).then(|| (ip.to_string(), default_port));
    }
    if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        let host = host.parse::<IpAddr>().ok()?.to_string();
        let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
        return Some((host, port));
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.contains(':') => {
            let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
            valid_dns_name(host).then(|| (host.to_ascii_lowercase(), port))
        }
        _ => (default_port != 0 && valid_dns_name(value)).then(|| (value.to_ascii_lowercase(), default_port)),
    }
}

pub fn valid_dns_name(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
