//! User-configured upstream proxy: parsing, the URL form each engine takes,
//! and a loopback SOCKS5 relay for Aether's Tor, which only takes an
//! unauthenticated SOCKS5 proxy at an IP literal.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use fcae_abi::FcaeTorMode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

use crate::error::{CoreError, Result};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HTTP_RESPONSE_HEAD: usize = 16 * 1024;

const SOCKS_GENERAL_FAILURE: u8 = 0x01;
const SOCKS_HOST_UNREACHABLE: u8 = 0x04;
const SOCKS_CONNECTION_REFUSED: u8 = 0x05;
const SOCKS_TTL_EXPIRED: u8 = 0x06;
const SOCKS_COMMAND_UNSUPPORTED: u8 = 0x07;
const SOCKS_ADDRESS_UNSUPPORTED: u8 = 0x08;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    Http,
    Socks5,
}

impl ProxyKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Socks5 => "socks5",
        }
    }

    pub const fn carries_udp(self) -> bool {
        matches!(self, Self::Socks5)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct UpstreamProxy {
    pub kind: ProxyKind,
    /// IP literal (IPv6 without brackets) or hostname.
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
}

impl fmt::Debug for UpstreamProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamProxy")
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Credential-free form, safe for logs.
impl fmt::Display for UpstreamProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.kind.label(), self.endpoint())
    }
}

impl FromStr for UpstreamProxy {
    type Err = String;

    fn from_str(raw: &str) -> std::result::Result<Self, String> {
        let raw = raw.trim();
        let (kind, rest) = match raw.split_once("://") {
            Some((scheme, rest)) => (
                match scheme.to_ascii_lowercase().as_str() {
                    "http" => ProxyKind::Http,
                    "socks4" | "socks4a" => {
                        return Err("socks4 proxies are not supported; use socks5:// or http://".into())
                    }
                    "socks" | "socks5" | "socks5h" => ProxyKind::Socks5,
                    "https" => {
                        return Err("TLS to the proxy (https://) is not supported; use http://".into())
                    }
                    other => {
                        return Err(format!(
                            "unsupported proxy scheme `{other}`; use http, socks5 or socks"
                        ))
                    }
                },
                rest,
            ),
            None => (ProxyKind::Socks5, raw),
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        let (credentials, host, port) = split_credentials(rest)?;
        let (user, password) = match credentials {
            None => (None, None),
            Some(credentials) => {
                let (user, password) = match credentials.split_once(':') {
                    Some((user, password)) => (user, Some(password)),
                    None => (credentials, None),
                };
                (Some(percent_decode(user)?), password.map(percent_decode).transpose()?)
            }
        };
        let user = user.filter(|user| !user.is_empty());
        if password.is_some() && user.is_none() {
            return Err("a proxy password needs a user name".into());
        }
        if kind == ProxyKind::Socks5
            && (user.as_ref().is_some_and(|u| u.len() > 255) || password.as_ref().is_some_and(|p| p.len() > 255))
        {
            return Err("socks5 user names and passwords are limited to 255 bytes".into());
        }
        Ok(Self { kind, host, port, user, password })
    }
}

/// Credentials may precede the address (`user:pass@host:port`, the URL form)
/// or follow it (`host:port@user:pass`). When both readings parse, the one with
/// the more address-like host wins, ties going to the URL form.
fn split_credentials(rest: &str) -> std::result::Result<(Option<&str>, String, u16), String> {
    let Some((leading, endpoint)) = rest.rsplit_once('@') else {
        let (host, port) = split_endpoint(rest)?;
        return Ok((None, host, port));
    };
    let url_form = split_endpoint(endpoint);
    let (address, trailing) = rest.split_once('@').unwrap_or((rest, ""));
    match (url_form, split_endpoint(address)) {
        (Ok((host, _)), Ok((alt_host, alt_port))) if host_rank(&alt_host) > host_rank(&host) => {
            Ok((Some(trailing), alt_host, alt_port))
        }
        (Ok((host, port)), _) => Ok((Some(leading), host, port)),
        (Err(_), Ok((host, port))) => Ok((Some(trailing), host, port)),
        (Err(e), Err(_)) => Err(e),
    }
}

fn host_rank(host: &str) -> u8 {
    if host.parse::<IpAddr>().is_ok() || host.eq_ignore_ascii_case("localhost") {
        2
    } else {
        u8::from(host.contains('.'))
    }
}

fn split_endpoint(endpoint: &str) -> std::result::Result<(String, u16), String> {
    let malformed = || format!("`{endpoint}` is not host:port");
    let (host, port) = match endpoint.strip_prefix('[') {
        Some(rest) => {
            let (host, port) = rest.split_once("]:").ok_or_else(malformed)?;
            host.parse::<Ipv6Addr>().map_err(|_| malformed())?;
            (host, port)
        }
        None => {
            let (host, port) = endpoint.rsplit_once(':').ok_or_else(malformed)?;
            if host.contains(':') {
                return Err("write an IPv6 proxy address in brackets, e.g. socks5://[::1]:1080".into());
            }
            let valid = !host.is_empty()
                && host.len() <= 253
                && host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
            if !valid {
                return Err(format!("`{host}` is not a valid proxy host"));
            }
            (host, port)
        }
    };
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| format!("proxy port `{port}` is not 1..65535"))?;
    Ok((host.to_string(), port))
}

fn percent_decode(text: &str) -> std::result::Result<String, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let byte = bytes
                .get(at + 1..at + 3)
                .and_then(|hex| std::str::from_utf8(hex).ok())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                .ok_or("a `%` in the proxy credentials must start a %XX escape")?;
            out.push(byte);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "the proxy credentials are not valid UTF-8".into())
}

fn percent_encode(text: &str, out: &mut String) {
    use std::fmt::Write;
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
}

impl UpstreamProxy {
    /// Parses an ABI string; NULL or blank means no proxy. Undecodable text
    /// is an error, never "no proxy", so a configured proxy cannot be
    /// silently skipped.
    ///
    /// # Safety
    /// `text` must be NULL or a valid NUL-terminated string.
    pub unsafe fn from_c(text: *const std::ffi::c_char) -> std::result::Result<Option<Self>, String> {
        if text.is_null() {
            return Ok(None);
        }
        let text = std::ffi::CStr::from_ptr(text)
            .to_str()
            .map_err(|_| "the proxy is not valid UTF-8".to_string())?
            .trim();
        if text.is_empty() { Ok(None) } else { text.parse().map(Some) }
    }

    /// An unauthenticated SOCKS5 proxy on this machine, e.g. a [`Relay`].
    pub fn loopback(addr: SocketAddr) -> Self {
        Self { kind: ProxyKind::Socks5, host: addr.ip().to_string(), port: addr.port(), user: None, password: None }
    }

    pub fn endpoint(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// The canonical URL: what both `AETHER_UPSTREAM` and tunnel-core's
    /// `UpstreamProxyURL` take.
    pub fn url(&self) -> String {
        let scheme = self.kind.label();
        let mut url = String::with_capacity(scheme.len() + self.host.len() + 32);
        url.push_str(scheme);
        url.push_str("://");
        if let Some(user) = &self.user {
            percent_encode(user, &mut url);
            if let Some(password) = &self.password {
                url.push(':');
                percent_encode(password, &mut url);
            }
            url.push('@');
        }
        url.push_str(&self.endpoint());
        url
    }

    /// What arti's outbound proxy accepts: SOCKS5 at an IP, no credentials.
    pub fn tor_compatible(&self) -> bool {
        self.kind == ProxyKind::Socks5 && self.user.is_none() && self.host.parse::<IpAddr>().is_ok()
    }

    /// Whether the Aether engine has to be handed a [`Relay`] instead of
    /// this proxy. Tor dials the upstream itself only in Only and Reverse.
    pub fn engine_needs_relay(&self, tor: FcaeTorMode) -> bool {
        matches!(tor, FcaeTorMode::Only | FcaeTorMode::Reverse) && !self.tor_compatible()
    }

    /// Addresses the TUN device has to route around so the session's own
    /// connections to the proxy never enter the tunnel they carry.
    pub async fn bypass_addresses(&self) -> Vec<IpAddr> {
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            return vec![ip];
        }
        match tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((self.host.as_str(), self.port))).await {
            Ok(Ok(addrs)) => {
                let mut ips: Vec<IpAddr> = Vec::new();
                for addr in addrs {
                    if !ips.contains(&addr.ip()) {
                        ips.push(addr.ip());
                    }
                }
                ips
            }
            Ok(Err(error)) => {
                log::warn!("[upstream] cannot resolve {} for its TUN bypass: {error}", self.host);
                Vec::new()
            }
            Err(_) => {
                log::warn!("[upstream] resolving {} for its TUN bypass timed out", self.host);
                Vec::new()
            }
        }
    }

    async fn dial(&self, target: &Target) -> std::result::Result<(TcpStream, Vec<u8>), DialError> {
        let attempt = async {
            let mut stream = TcpStream::connect((self.host.as_str(), self.port)).await.map_err(DialError::io)?;
            let _ = stream.set_nodelay(true);
            let early = match self.kind {
                ProxyKind::Http => self.http_connect(&mut stream, target).await?,
                ProxyKind::Socks5 => {
                    self.socks5_connect(&mut stream, target).await?;
                    Vec::new()
                }
            };
            Ok::<_, DialError>((stream, early))
        };
        tokio::time::timeout(HANDSHAKE_TIMEOUT, attempt)
            .await
            .unwrap_or_else(|_| Err(DialError::new(SOCKS_TTL_EXPIRED, "the upstream proxy did not answer in time")))
    }

    /// Returns any tunnelled bytes that arrived with the response head.
    async fn http_connect(&self, stream: &mut TcpStream, target: &Target) -> std::result::Result<Vec<u8>, DialError> {
        let authority = target.authority();
        let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some(user) = &self.user {
            let credentials = format!("{user}:{}", self.password.as_deref().unwrap_or(""));
            request.push_str("Proxy-Authorization: Basic ");
            request.push_str(&base64(credentials.as_bytes()));
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.map_err(DialError::io)?;

        let mut head = Vec::with_capacity(512);
        let mut chunk = [0u8; 2048];
        let end = loop {
            let read = stream.read(&mut chunk).await.map_err(DialError::io)?;
            if read == 0 {
                return Err(DialError::new(SOCKS_GENERAL_FAILURE, "the http proxy closed the connection"));
            }
            let scan_from = head.len().saturating_sub(3);
            head.extend_from_slice(&chunk[..read]);
            if let Some(at) = head[scan_from..].windows(4).position(|w| w == b"\r\n\r\n") {
                break scan_from + at + 4;
            }
            if head.len() > MAX_HTTP_RESPONSE_HEAD {
                return Err(DialError::new(SOCKS_GENERAL_FAILURE, "the http proxy sent an oversized response"));
            }
        };
        let status_line = head[..end].split(|b| *b == b'\n').next().unwrap_or_default();
        let status = std::str::from_utf8(status_line)
            .ok()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0);
        if !(200..300).contains(&status) {
            let code = match status {
                403 | 407 => SOCKS_CONNECTION_REFUSED,
                502 | 503 | 504 => SOCKS_HOST_UNREACHABLE,
                _ => SOCKS_GENERAL_FAILURE,
            };
            return Err(DialError::new(code, format!("the http proxy answered CONNECT with {status}")));
        }
        Ok(head.split_off(end))
    }

    async fn socks5_connect(&self, stream: &mut TcpStream, target: &Target) -> std::result::Result<(), DialError> {
        let greeting: &[u8] = if self.user.is_some() { &[5, 2, 0, 2] } else { &[5, 1, 0] };
        stream.write_all(greeting).await.map_err(DialError::io)?;
        let mut choice = [0u8; 2];
        stream.read_exact(&mut choice).await.map_err(DialError::io)?;
        if choice[0] != 5 {
            return Err(DialError::new(SOCKS_GENERAL_FAILURE, "the upstream proxy does not speak socks5"));
        }
        match choice[1] {
            0 => {}
            2 if self.user.is_some() => {
                let user = self.user.as_deref().unwrap_or_default().as_bytes();
                let password = self.password.as_deref().unwrap_or_default().as_bytes();
                let mut auth = Vec::with_capacity(3 + user.len() + password.len());
                auth.extend_from_slice(&[1, user.len() as u8]);
                auth.extend_from_slice(user);
                auth.push(password.len() as u8);
                auth.extend_from_slice(password);
                stream.write_all(&auth).await.map_err(DialError::io)?;
                let mut status = [0u8; 2];
                stream.read_exact(&mut status).await.map_err(DialError::io)?;
                if status[1] != 0 {
                    return Err(DialError::new(SOCKS_CONNECTION_REFUSED, "the socks5 proxy rejected the credentials"));
                }
            }
            _ => {
                return Err(DialError::new(SOCKS_CONNECTION_REFUSED, "the socks5 proxy accepts none of the offered auth methods"))
            }
        }
        let mut request = Vec::with_capacity(262);
        request.extend_from_slice(&[5, 1, 0]);
        target.encode_socks5(&mut request);
        stream.write_all(&request).await.map_err(DialError::io)?;

        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await.map_err(DialError::io)?;
        if head[1] != 0 {
            return Err(DialError::new(head[1], format!("the socks5 proxy refused the request ({:#04x})", head[1])));
        }
        let skip = match head[3] {
            1 => 4 + 2,
            4 => 16 + 2,
            3 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await.map_err(DialError::io)?;
                len[0] as usize + 2
            }
            _ => return Err(DialError::new(SOCKS_GENERAL_FAILURE, "the socks5 proxy sent a malformed reply")),
        };
        let mut bound = [0u8; 258];
        stream.read_exact(&mut bound[..skip]).await.map_err(DialError::io)?;
        Ok(())
    }
}

struct DialError {
    code: u8,
    message: String,
}

impl DialError {
    fn new(code: u8, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    fn io(error: io::Error) -> Self {
        let code = match error.kind() {
            io::ErrorKind::ConnectionRefused => SOCKS_CONNECTION_REFUSED,
            io::ErrorKind::TimedOut => SOCKS_TTL_EXPIRED,
            _ => SOCKS_GENERAL_FAILURE,
        };
        Self { code, message: error.to_string() }
    }
}

enum Target {
    Ip(SocketAddr),
    Name(String, u16),
}

impl Target {
    fn authority(&self) -> String {
        match self {
            Self::Ip(addr) => addr.to_string(),
            Self::Name(name, port) => format!("{name}:{port}"),
        }
    }

    fn encode_socks5(&self, out: &mut Vec<u8>) {
        match self {
            Self::Ip(SocketAddr::V4(addr)) => {
                out.push(1);
                out.extend_from_slice(&addr.ip().octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
            Self::Ip(SocketAddr::V6(addr)) => {
                out.push(4);
                out.extend_from_slice(&addr.ip().octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
            Self::Name(name, port) => {
                out.extend_from_slice(&[3, name.len() as u8]);
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
    }
}

fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Loopback, unauthenticated, CONNECT-only SOCKS5 server that forwards every
/// connection through an [`UpstreamProxy`]. It lives exactly as long as the
/// session handle owning it: dropping it aborts the listener and, with its
/// `JoinSet`, every relayed connection.
pub struct Relay {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Relay {
    pub async fn start(proxy: UpstreamProxy) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| CoreError::StartFailed(format!("cannot open the upstream proxy relay: {e}")))?;
        let addr = listener
            .local_addr()
            .map_err(|e| CoreError::StartFailed(format!("cannot open the upstream proxy relay: {e}")))?;
        log::info!("[upstream] relaying {proxy} through socks5://{addr}");
        let proxy = Arc::new(proxy);
        let task = tokio::spawn(async move {
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => match accepted {
                        Ok((client, _)) => {
                            let proxy = proxy.clone();
                            clients.spawn(async move {
                                if let Err(error) = relay_client(client, &proxy).await {
                                    log::debug!("[upstream] relay: {error}");
                                }
                            });
                        }
                        Err(error) => {
                            log::warn!("[upstream] relay accept failed: {error}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    },
                    Some(_) = clients.join_next(), if !clients.is_empty() => {}
                }
            }
        });
        Ok(Self { addr, task })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn relay_client(mut client: TcpStream, proxy: &UpstreamProxy) -> io::Result<()> {
    let _ = client.set_nodelay(true);
    let target = accept_connect(&mut client).await?;
    let (mut upstream, early) = match proxy.dial(&target).await {
        Ok(dialled) => dialled,
        Err(error) => {
            let _ = socks5_reply(&mut client, error.code).await;
            return Err(io::Error::other(format!("{} via {proxy}: {}", target.authority(), error.message)));
        }
    };
    socks5_reply(&mut client, 0).await?;
    if !early.is_empty() {
        client.write_all(&early).await?;
    }
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await.map(|_| ())
}

async fn accept_connect(client: &mut TcpStream) -> io::Result<Target> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "relay client is not socks5"));
    }
    let mut methods = [0u8; 255];
    let methods = &mut methods[..head[1] as usize];
    client.read_exact(methods).await?;
    if !methods.contains(&0) {
        client.write_all(&[5, 0xFF]).await?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "relay client requires authentication"));
    }
    client.write_all(&[5, 0]).await?;

    let mut request = [0u8; 4];
    client.read_exact(&mut request).await?;
    if request[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "malformed socks5 request"));
    }
    if request[1] != 1 {
        socks5_reply(client, SOCKS_COMMAND_UNSUPPORTED).await?;
        return Err(io::Error::new(io::ErrorKind::Unsupported, "the relay only carries CONNECT"));
    }
    match request[3] {
        1 => {
            let mut addr = [0u8; 6];
            client.read_exact(&mut addr).await?;
            let ip = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            Ok(Target::Ip(SocketAddr::new(ip.into(), u16::from_be_bytes([addr[4], addr[5]]))))
        }
        4 => {
            let mut addr = [0u8; 18];
            client.read_exact(&mut addr).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&addr[..16]);
            Ok(Target::Ip(SocketAddr::new(Ipv6Addr::from(octets).into(), u16::from_be_bytes([addr[16], addr[17]]))))
        }
        3 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize + 2];
            client.read_exact(&mut name).await?;
            let port = u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]);
            name.truncate(name.len() - 2);
            let name = String::from_utf8(name)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 host name"))?;
            Ok(Target::Name(name, port))
        }
        _ => {
            socks5_reply(client, SOCKS_ADDRESS_UNSUPPORTED).await?;
            Err(io::Error::new(io::ErrorKind::InvalidData, "unknown socks5 address type"))
        }
    }
}

async fn socks5_reply(client: &mut TcpStream, code: u8) -> io::Result<()> {
    client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> UpstreamProxy {
        text.parse().unwrap_or_else(|e| panic!("{text}: {e}"))
    }

    #[test]
    fn schemes_map_onto_two_kinds() {
        assert_eq!(parse("http://1.2.3.4:8080").kind, ProxyKind::Http);
        assert_eq!(parse("HTTP://1.2.3.4:8080").kind, ProxyKind::Http);
        assert_eq!(parse("socks5://1.2.3.4:1080").kind, ProxyKind::Socks5);
        assert_eq!(parse("socks5h://proxy.example:1080").kind, ProxyKind::Socks5);
        assert_eq!(parse("socks://1.2.3.4:1080").kind, ProxyKind::Socks5);
        assert_eq!(parse("1.2.3.4:1080").kind, ProxyKind::Socks5);
        assert_eq!(parse("socks5://[2001:db8::1]:1080/").host, "2001:db8::1");
    }

    #[test]
    fn malformed_proxies_are_refused() {
        for bad in [
            "", "ftp://1.2.3.4:21", "https://1.2.3.4:443", "socks5://1.2.3.4", "socks5://1.2.3.4:0",
            "socks5://1.2.3.4:70000", "socks5://2001:db8::1:1080", "socks5://bad host:1080",
            "socks4://1.2.3.4:1080", "socks4a://1.2.3.4:1080", "socks5://:p@1.2.3.4:1080", "socks5://u%zz@1.2.3.4:1080",
            "http://1.2.3.4:8080/path",
        ] {
            assert!(bad.parse::<UpstreamProxy>().is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn credentials_round_trip_through_every_url_form() {
        let proxy = parse("socks5://us%3Aer:p@ss:w@1.2.3.4:1080");
        assert_eq!(proxy.user.as_deref(), Some("us:er"));
        assert_eq!(proxy.password.as_deref(), Some("p@ss:w"));
        assert_eq!(proxy.url(), "socks5://us%3Aer:p%40ss%3Aw@1.2.3.4:1080");
        assert_eq!(parse(&proxy.url()), proxy);
        assert_eq!(proxy.to_string(), "socks5://1.2.3.4:1080");
        assert!(!format!("{proxy:?}").contains("p@ss"));
    }

    #[test]
    fn credentials_may_trail_the_address() {
        let canonical = parse("socks5://user:pass@1.2.3.4:1080");
        assert_eq!(parse("socks5://1.2.3.4:1080@user:pass"), canonical);
        assert_eq!(parse("1.2.3.4:1080@user:pass"), canonical);
        assert_eq!(parse("socks5://1.2.3.4:1080@user:pass").url(), "socks5://user:pass@1.2.3.4:1080");
        assert_eq!(parse("http://[2001:db8::1]:8080@u:p").url(), "http://u:p@[2001:db8::1]:8080");
        let numeric = parse("socks5://1.2.3.4:1080@user:1234");
        assert_eq!((numeric.host.as_str(), numeric.port), ("1.2.3.4", 1080));
        assert_eq!((numeric.user.as_deref(), numeric.password.as_deref()), (Some("user"), Some("1234")));
        let named = parse("socks5://proxy.example:1080@user:1234");
        assert_eq!((named.host.as_str(), named.user.as_deref()), ("proxy.example", Some("user")));
        let leading = parse("socks5://user:1234@proxy.example:1080");
        assert_eq!((leading.host.as_str(), leading.port, leading.user.as_deref()), ("proxy.example", 1080, Some("user")));
        let both = parse("socks5://1.1.1.1:1@2.2.2.2:2");
        assert_eq!((both.host.as_str(), both.user.as_deref()), ("2.2.2.2", Some("1.1.1.1")));
    }

    #[test]
    fn canonical_urls() {
        assert_eq!(parse("socks://u@[2001:db8::1]:1080/").url(), "socks5://u@[2001:db8::1]:1080");
        assert_eq!(parse("socks5h://h.example:1080").url(), "socks5://h.example:1080");
        assert_eq!(parse("http://h.example:3128").url(), "http://h.example:3128");
    }

    #[test]
    fn relay_is_used_only_where_the_engine_cannot_dial_itself() {
        let plain = parse("socks5://1.2.3.4:1080");
        let named = parse("socks5://proxy.example:1080");
        let http = parse("http://1.2.3.4:8080");
        for mode in [FcaeTorMode::Off, FcaeTorMode::Chain, FcaeTorMode::Only, FcaeTorMode::Reverse] {
            assert!(!plain.engine_needs_relay(mode));
        }
        assert!(!named.engine_needs_relay(FcaeTorMode::Chain));
        assert!(named.engine_needs_relay(FcaeTorMode::Only));
        assert!(!http.engine_needs_relay(FcaeTorMode::Off));
        assert!(http.engine_needs_relay(FcaeTorMode::Reverse));
    }

    #[test]
    fn base64_matches_rfc4648() {
        for (input, expected) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg==")] {
            assert_eq!(base64(input.as_bytes()), expected);
        }
    }

    async fn fake_socks5_upstream(expect_auth: bool) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut greet = [0u8; 4];
            let n = if expect_auth { 4 } else { 3 };
            s.read_exact(&mut greet[..n]).await.unwrap();
            if expect_auth {
                s.write_all(&[5, 2]).await.unwrap();
                let mut auth = [0u8; 2 + 1 + 1 + 1];
                s.read_exact(&mut auth).await.unwrap();
                assert_eq!(auth, [1, 1, b'u', 1, b'p']);
                s.write_all(&[1, 0]).await.unwrap();
            } else {
                s.write_all(&[5, 0]).await.unwrap();
            }
            let mut req = [0u8; 5];
            s.read_exact(&mut req).await.unwrap();
            assert_eq!(&req[..4], &[5, 1, 0, 3]);
            let mut rest = vec![0u8; req[4] as usize + 2];
            s.read_exact(&mut rest).await.unwrap();
            assert_eq!(&rest[..rest.len() - 2], b"example.com");
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            s.write_all(b"pong").await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn relay_forwards_through_an_authenticated_socks5_upstream() {
        let upstream = fake_socks5_upstream(true).await;
        let mut proxy = UpstreamProxy::loopback(upstream);
        proxy.user = Some("u".into());
        proxy.password = Some("p".into());
        let relay = Relay::start(proxy).await.unwrap();
        let mut c = TcpStream::connect(relay.addr()).await.unwrap();
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut choice = [0u8; 2];
        c.read_exact(&mut choice).await.unwrap();
        assert_eq!(choice, [5, 0]);
        let mut req = vec![5, 1, 0, 3, 11];
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        c.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        let mut pong = [0u8; 4];
        c.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
    }

    #[tokio::test]
    async fn http_connect_keeps_bytes_that_follow_the_response_head() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = s.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(request.starts_with("CONNECT 9.9.9.9:443 HTTP/1.1\r\n"), "{request}");
            assert!(request.contains("Proxy-Authorization: Basic dTpw\r\n"), "{request}");
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nhello").await.unwrap();
        });
        let proxy = parse(&format!("http://u:p@{addr}"));
        let target = Target::Ip("9.9.9.9:443".parse().unwrap());
        let (_stream, early) = proxy.dial(&target).await.ok().unwrap();
        assert_eq!(early, b"hello");
    }
}
