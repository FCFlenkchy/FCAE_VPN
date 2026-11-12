use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use parking_lot::Mutex;
use socket2::{Domain, Protocol, SockAddr, Socket, TcpKeepalive, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use url::Url;

use crate::error::{FirefoxError, Result};
use crate::types::{authority, split_authority};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PROXY_RESPONSE: usize = 16 * 1024;
static KEEPALIVE_WARNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub type ProtectCallback = Arc<dyn Fn(i32) -> bool + Send + Sync + 'static>;

#[derive(Debug, Clone)]
struct UpstreamProxy {
    kind: ProxyKind,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyKind {
    Http,
    Socks5,
}

impl UpstreamProxy {
    fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(FirefoxError::InvalidConfig("empty upstream proxy".into()));
        }
        let with_scheme = if raw.contains("://") { raw.to_string() } else { format!("socks5://{raw}") };
        let url = Url::parse(&with_scheme)?;
        let kind = match url.scheme() {
            "http" => ProxyKind::Http,
            "socks5" | "socks5h" => ProxyKind::Socks5,
            scheme => {
                return Err(FirefoxError::InvalidConfig(format!(
                    "unsupported upstream proxy scheme `{scheme}`"
                )))
            }
        };
        let host = url.host_str().ok_or_else(|| FirefoxError::InvalidConfig("upstream proxy has no host".into()))?;
        if url.path() != "/" && !url.path().is_empty() || url.query().is_some() || url.fragment().is_some() {
            return Err(FirefoxError::InvalidConfig("upstream proxy must contain only host, port and credentials".into()));
        }
        let port = url.port().ok_or_else(|| FirefoxError::InvalidConfig("upstream proxy has no explicit port".into()))?;
        let username = (!url.username().is_empty()).then(|| url.username().to_string());
        let password = url.password().map(str::to_string);
        Ok(Self { kind, host: host.to_string(), port, username, password })
    }
}

#[derive(Clone)]
pub struct Dialer {
    upstream: Option<Arc<UpstreamProxy>>,
    protect: Option<ProtectCallback>,
    ip_version: i32,
    peers: Arc<Mutex<BTreeSet<IpAddr>>>,
}

impl Dialer {
    pub fn new(upstream: Option<&str>, protect: Option<ProtectCallback>, ip_version: i32) -> Result<Self> {
        if !matches!(ip_version, 4 | 6 | 10) {
            return Err(FirefoxError::InvalidConfig(format!("IP version {ip_version} must be 4, 6 or 10")));
        }
        Ok(Self {
            upstream: upstream.map(UpstreamProxy::parse).transpose()?.map(Arc::new),
            protect,
            ip_version,
            peers: Arc::new(Mutex::new(BTreeSet::new())),
        })
    }

    pub fn peer_ips(&self) -> Vec<IpAddr> {
        self.peers.lock().iter().copied().collect()
    }

    pub fn clear_peers(&self) {
        self.peers.lock().clear();
    }

    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            if !self.family_allowed(ip) {
                return Err(FirefoxError::Dns { host: host.into(), message: "address family is disabled".into() });
            }
            self.peers.lock().insert(ip);
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let addrs = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((host, port)))
            .await
            .map_err(|_| FirefoxError::Timeout(CONNECT_TIMEOUT))?
            .map_err(|error| FirefoxError::Dns { host: host.into(), message: error.to_string() })?;
        let mut out = Vec::new();
        for addr in addrs {
            if self.family_allowed(addr.ip()) && !out.contains(&addr) {
                out.push(addr);
            }
        }
        if self.ip_version == 6 {
            out.sort_by_key(|addr| !addr.is_ipv6());
        } else {
            out.sort_by_key(|addr| !addr.is_ipv4());
        }
        if out.is_empty() {
            return Err(FirefoxError::Dns { host: host.into(), message: "no usable address family".into() });
        }
        self.peers.lock().extend(out.iter().map(|addr| addr.ip()));
        Ok(out)
    }

    pub async fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpStream> {
        if let Some(proxy) = &self.upstream {
            return self.connect_upstream(proxy, host, port).await;
        }
        let addresses = self.resolve(host, port).await?;
        let mut last_error = None;
        for address in addresses {
            match self.connect_address(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| FirefoxError::Network(format!("cannot connect to {}", authority(host, port)))))
    }

    pub async fn connect_udp(&self, host: &str, port: u16) -> Result<UdpSocket> {
        if self.upstream.is_some() {
            return Err(FirefoxError::InvalidConfig(
                "a UDP carrier cannot use an HTTP/SOCKS TCP upstream proxy".into(),
            ));
        }
        let addresses = self.resolve(host, port).await?;
        let mut last_error = None;
        for address in addresses {
            match self.udp_address(address).await {
                Ok(socket) => return Ok(socket),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| FirefoxError::Network("no UDP endpoint is usable".into())))
    }

    async fn connect_address(&self, address: SocketAddr) -> Result<TcpStream> {
        let socket = Socket::new(Domain::for_address(address), Type::STREAM, Some(Protocol::TCP)).map_err(io)?;
        socket.set_nonblocking(true).map_err(io)?;
        let keepalive = TcpKeepalive::new().with_time(Duration::from_secs(15));
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "windows"))]
        let keepalive = keepalive.with_interval(Duration::from_secs(15)).with_retries(9);
        if let Err(error) = socket.set_tcp_keepalive(&keepalive) {
            let fallback = socket.set_keepalive(true);
            if !KEEPALIVE_WARNING.swap(true, std::sync::atomic::Ordering::Relaxed) {
                match fallback {
                    Ok(()) => log::warn!("[firefox] TCP keepalive parameters unavailable: {error}; using system settings"),
                    Err(fallback) => log::warn!("[firefox] TCP keepalive unavailable: {error}; fallback failed: {fallback}"),
                }
            }
        }
        self.protect(&socket)?;
        match socket.connect(&SockAddr::from(address)) {
            Ok(()) => {}
            Err(error) if in_progress(&error) => {}
            Err(error) => return Err(io(error)),
        }
        let stream = TcpStream::from_std(socket.into()).map_err(io)?;
        tokio::time::timeout(CONNECT_TIMEOUT, stream.writable())
            .await
            .map_err(|_| FirefoxError::Timeout(CONNECT_TIMEOUT))?
            .map_err(io)?;
        if let Some(error) = stream.take_error().map_err(io)? {
            return Err(io(error));
        }
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }

    async fn udp_address(&self, address: SocketAddr) -> Result<UdpSocket> {
        let socket = Socket::new(Domain::for_address(address), Type::DGRAM, Some(Protocol::UDP)).map_err(io)?;
        socket.set_nonblocking(true).map_err(io)?;
        self.protect(&socket)?;
        socket.connect(&SockAddr::from(address)).map_err(io)?;
        UdpSocket::from_std(socket.into()).map_err(io)
    }

    fn protect(&self, socket: &Socket) -> Result<()> {
        let Some(protect) = &self.protect else { return Ok(()) };
        #[cfg(unix)]
        let accepted = {
            use std::os::fd::AsRawFd;
            protect(socket.as_raw_fd())
        };
        #[cfg(windows)]
        let accepted = {
            use std::os::windows::io::AsRawSocket;
            protect(socket.as_raw_socket() as i32)
        };
        if accepted {
            Ok(())
        } else {
            Err(FirefoxError::Network("VpnService.protect() rejected a carrier socket".into()))
        }
    }

    fn family_allowed(&self, ip: IpAddr) -> bool {
        matches!(self.ip_version, 10)
            || matches!((self.ip_version, ip), (4, IpAddr::V4(_)) | (6, IpAddr::V6(_)))
    }

    async fn connect_upstream(&self, proxy: &UpstreamProxy, host: &str, port: u16) -> Result<TcpStream> {
        let addresses = self.resolve(&proxy.host, proxy.port).await?;
        let mut last_error = None;
        for address in addresses {
            match self.connect_address(address).await {
                Ok(mut stream) => {
                    let result = match proxy.kind {
                        ProxyKind::Http => http_connect(&mut stream, proxy, host, port).await,
                        ProxyKind::Socks5 => socks5_connect(&mut stream, proxy, host, port).await,
                    };
                    match result {
                        Ok(()) => return Ok(stream),
                        Err(error) => last_error = Some(error),
                    }
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| FirefoxError::Network("upstream proxy connection failed".into())))
    }
}

fn in_progress(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(unix)]
    {
        matches!(error.raw_os_error(), Some(libc::EINPROGRESS) | Some(libc::EALREADY) | Some(libc::EINTR))
    }
    #[cfg(windows)]
    {
        matches!(error.raw_os_error(), Some(10035) | Some(10036) | Some(10037))
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

fn io(error: std::io::Error) -> FirefoxError {
    FirefoxError::Network(error.to_string())
}

async fn http_connect(stream: &mut TcpStream, proxy: &UpstreamProxy, host: &str, port: u16) -> Result<()> {
    let target = authority(host, port);
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(username) = &proxy.username {
        let credentials = format!("{username}:{}", proxy.password.as_deref().unwrap_or(""));
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", BASE64.encode(credentials.as_bytes())));
    }
    request.push_str("\r\n");
    tokio::time::timeout(CONNECT_TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| FirefoxError::Timeout(CONNECT_TIMEOUT))??;
    let head = read_head(stream).await?;
    let status = head
        .split(|b| *b == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .unwrap_or(0);
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(FirefoxError::Network(format!("upstream HTTP proxy returned status {status}")))
    }
}

async fn read_head(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let result = tokio::time::timeout(CONNECT_TIMEOUT, async {
        loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(FirefoxError::Network("proxy closed during handshake".into()));
            }
            head.extend_from_slice(&chunk[..read]);
            if head.windows(4).any(|window| window == b"\r\n\r\n") {
                return Ok(head);
            }
            if head.len() > MAX_PROXY_RESPONSE {
                return Err(FirefoxError::Protocol("upstream proxy response is too large".into()));
            }
        }
    })
    .await;
    result.map_err(|_| FirefoxError::Timeout(CONNECT_TIMEOUT))?
}

async fn socks5_connect(stream: &mut TcpStream, proxy: &UpstreamProxy, host: &str, port: u16) -> Result<()> {
    let auth = proxy.username.is_some();
    stream.write_all(if auth { &[5, 1, 2] } else { &[5, 1, 0] }).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method[0] != 5 || method[1] != u8::from(auth) {
        return Err(FirefoxError::Network("upstream SOCKS5 proxy rejected authentication".into()));
    }
    if auth {
        let username = proxy.username.as_deref().unwrap_or("");
        let password = proxy.password.as_deref().unwrap_or("");
        if username.len() > 255 || password.len() > 255 {
            return Err(FirefoxError::InvalidConfig("SOCKS5 credentials are too long".into()));
        }
        let mut request = vec![1, username.len() as u8];
        request.extend_from_slice(username.as_bytes());
        request.push(password.len() as u8);
        request.extend_from_slice(password.as_bytes());
        stream.write_all(&request).await?;
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        if response != [1, 0] {
            return Err(FirefoxError::Network("upstream SOCKS5 credentials were rejected".into()));
        }
    }

    let mut request = vec![5, 1, 0];
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ip) => {
                request.push(1);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(4);
                request.extend_from_slice(&ip.octets());
            }
        }
    } else {
        if host.len() > 255 {
            return Err(FirefoxError::InvalidConfig("target hostname is too long".into()));
        }
        request.extend_from_slice(&[3, host.len() as u8]);
        request.extend_from_slice(host.as_bytes());
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 5 || response[1] != 0 {
        return Err(FirefoxError::Network(format!("upstream SOCKS5 proxy returned reply {}", response[1])));
    }
    skip_socks_address(stream, response[3]).await
}

async fn skip_socks_address(stream: &mut TcpStream, kind: u8) -> Result<()> {
    let length = match kind {
        1 => 4,
        4 => 16,
        3 => stream.read_u8().await? as usize,
        _ => return Err(FirefoxError::Protocol("invalid SOCKS5 address type".into())),
    };
    let mut ignored = vec![0u8; length + 2];
    stream.read_exact(&mut ignored).await?;
    Ok(())
}

#[allow(dead_code)]
fn validate_target(host: &str, port: u16) -> bool {
    port != 0 && split_authority(&authority(host, port), port).is_some()
}
