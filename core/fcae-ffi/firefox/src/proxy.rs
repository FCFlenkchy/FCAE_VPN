use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, Notify};
use tokio::task::AbortHandle;

use crate::error::{FirefoxError, Result};
use crate::transport::Upstream;
use crate::types::{authority, valid_dns_name};

const MAX_HEAD: usize = 32 * 1024;
const MAX_UDP_FLOWS: usize = 256;
const MAX_DATAGRAM: usize = 65_535;
const UDP_REFUSAL_TTL: std::time::Duration = std::time::Duration::from_secs(15);

pub struct LocalProxies {
    upstream: Arc<Upstream>,
    shutdown: Arc<Notify>,
    stopped: Arc<std::sync::atomic::AtomicBool>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    pub socks_addr: Option<SocketAddr>,
    pub http_addr: Option<SocketAddr>,
}

impl LocalProxies {
    pub async fn start(upstream: Arc<Upstream>, socks_addr: Option<SocketAddr>, http_addr: Option<SocketAddr>) -> Result<Arc<Self>> {
        let socks = match socks_addr {
            Some(address) => Some(TcpListener::bind(address).await?),
            None => None,
        };
        let http = match http_addr {
            Some(address) => Some(TcpListener::bind(address).await?),
            None => None,
        };
        let proxies = Arc::new(Self {
            upstream,
            shutdown: Arc::new(Notify::new()),
            stopped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            tasks: Mutex::new(Vec::new()),
            socks_addr: socks.as_ref().and_then(|listener| listener.local_addr().ok()),
            http_addr: http.as_ref().and_then(|listener| listener.local_addr().ok()),
        });
        if let Some(listener) = socks {
            proxies.spawn_accept(listener, false).await;
        }
        if let Some(listener) = http {
            proxies.spawn_accept(listener, true).await;
        }
        Ok(proxies)
    }

    async fn spawn_accept(self: &Arc<Self>, listener: TcpListener, http: bool) {
        let this = Arc::downgrade(self);
        let shutdown = self.shutdown.clone();
        let upstream = self.upstream.clone();
        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = shutdown.notified() => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, _)) = accepted else { break };
                let upstream = upstream.clone();
                let task = tokio::spawn(async move {
                    if http {
                        if let Err(error) = handle_http(stream, upstream).await {
                            log::debug!("[firefox] HTTP proxy connection ended: {error}");
                        }
                    } else if let Err(error) = handle_socks(stream, upstream).await {
                        log::debug!("[firefox] SOCKS connection ended: {error}");
                    }
                });
                let Some(owner) = this.upgrade() else {
                    task.abort();
                    let _ = task.await;
                    break;
                };
                let mut tasks = owner.tasks.lock().await;
                if owner.stopped.load(std::sync::atomic::Ordering::Acquire) {
                    drop(tasks);
                    task.abort();
                    let _ = task.await;
                    break;
                }
                tasks.retain(|task| !task.is_finished());
                tasks.push(task);
            }
        });
        self.tasks.lock().await.push(task);
    }

    pub async fn stop(&self) {
        if self.stopped.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        self.shutdown.notify_waiters();
        let tasks = self.tasks.lock().await.drain(..).collect::<Vec<_>>();
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
        self.upstream.close().await;
    }
}

impl Drop for LocalProxies {
    fn drop(&mut self) {
        self.shutdown.notify_waiters();
        for task in self.tasks.get_mut().drain(..) {
            task.abort();
        }
    }
}

async fn handle_socks(stream: TcpStream, upstream: Arc<Upstream>) -> Result<()> {
    let mut stream = BufReader::new(stream);
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 5 || greeting[1] == 0 {
        return Err(FirefoxError::Protocol("invalid SOCKS5 greeting".into()));
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xff]).await?;
        return Err(FirefoxError::Protocol("SOCKS5 client requires unsupported authentication".into()));
    }
    stream.write_all(&[5, 0]).await?;
    stream.flush().await?;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 {
        return Err(FirefoxError::Protocol("invalid SOCKS5 request".into()));
    }
    let (host, port) = read_socks_address(&mut stream, header[3]).await?;
    let target = authority(&host, port);
    match header[1] {
        1 => {
            if port == 53 && crate::doh::provider(&host).is_some() {
                socks_reply(&mut stream, 0).await?;
                return serve_dns_tcp(&mut stream, &upstream, &host).await;
            }
            match upstream.open_tcp(&target).await {
                Ok(mut tunnel) => {
                    socks_reply(&mut stream, 0).await?;
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tunnel).await;
                }
                Err(error) => {
                    socks_reply(&mut stream, socks_reply_code(&error)).await?;
                    return Err(error);
                }
            }
            Ok(())
        }
        3 => {
            let bind_ip = match stream.get_ref().local_addr()?.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            };
            let client_ip = stream.get_ref().peer_addr()?.ip();
            let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
            let address = socket.local_addr()?;
            let association = UdpAssociation::new(socket, upstream, client_ip);
            socks_reply_addr(&mut stream, 0, address).await?;
            association.run(stream).await
        }
        _ => {
            socks_reply(&mut stream, 7).await?;
            Err(FirefoxError::UnsupportedDestination(format!("SOCKS command {}", header[1])))
        }
    }
}

async fn read_socks_address<S>(stream: &mut S, atyp: u8) -> Result<(String, u16)>
where
    S: AsyncRead + Unpin,
{
    let host = match atyp {
        1 => {
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).await?;
            IpAddr::V4(bytes.into()).to_string()
        }
        4 => {
            let mut bytes = [0u8; 16];
            stream.read_exact(&mut bytes).await?;
            IpAddr::V6(bytes.into()).to_string()
        }
        3 => {
            let length = stream.read_u8().await? as usize;
            if length == 0 {
                return Err(FirefoxError::Protocol("empty SOCKS domain".into()));
            }
            let mut bytes = vec![0u8; length];
            stream.read_exact(&mut bytes).await?;
            let host = String::from_utf8(bytes).map_err(|_| FirefoxError::Protocol("SOCKS domain is not UTF-8".into()))?;
            if !valid_dns_name(&host) {
                return Err(FirefoxError::UnsupportedDestination(host));
            }
            host
        }
        _ => return Err(FirefoxError::Protocol("unknown SOCKS address type".into())),
    };
    let port = stream.read_u16().await?;
    Ok((host, port))
}

async fn socks_reply<S: AsyncWrite + Unpin>(stream: &mut S, code: u8) -> Result<()> {
    socks_reply_addr(stream, code, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await
}

async fn socks_reply_addr<S: AsyncWrite + Unpin>(stream: &mut S, code: u8, address: SocketAddr) -> Result<()> {
    let mut response = vec![5, code, 0];
    match address.ip() {
        IpAddr::V4(ip) => {
            response.push(1);
            response.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            response.push(4);
            response.extend_from_slice(&ip.octets());
        }
    }
    response.extend_from_slice(&address.port().to_be_bytes());
    stream.write_all(&response).await?;
    stream.flush().await?;
    Ok(())
}

fn socks_reply_code(error: &FirefoxError) -> u8 {
    match crate::transport::destination_error(error) {
        Some("destination_ip_prohibited") => return 2,
        Some("destination_ip_unroutable") => return 3,
        Some("destination_not_found" | "destination_unavailable") => return 4,
        Some("connection_refused") => return 5,
        _ => {}
    }
    match error {
        FirefoxError::UnsupportedDestination(_) => 8,
        FirefoxError::Timeout(_) => 6,
        FirefoxError::Blocked => 2,
        _ => 5,
    }
}

#[derive(Default)]
struct UdpRefusals {
    entries: HashMap<(String, String), std::time::Instant>,
}

impl UdpRefusals {
    fn contains(&mut self, key: &(String, String), now: std::time::Instant) -> bool {
        if self.entries.get(key).is_some_and(|until| *until > now) {
            return true;
        }
        self.entries.remove(key);
        false
    }

    fn record(&mut self, key: (String, String), now: std::time::Instant) {
        self.entries.retain(|_, until| *until > now);
        if self.entries.len() < MAX_UDP_FLOWS {
            self.entries.insert(key, now + UDP_REFUSAL_TTL);
        }
    }
}

struct UdpAssociation {
    socket: Arc<UdpSocket>,
    upstream: Arc<Upstream>,
    client_ip: IpAddr,
    flows: Mutex<HashMap<String, Arc<crate::transport::UdpTunnel>>>,
    refused: Mutex<UdpRefusals>,
    opening: Mutex<()>,
    client: Mutex<Option<SocketAddr>>,
    readers: Mutex<Vec<AbortHandle>>,
    dns_slots: Arc<tokio::sync::Semaphore>,
}

impl UdpAssociation {
    fn new(socket: UdpSocket, upstream: Arc<Upstream>, client_ip: IpAddr) -> Arc<Self> {
        Arc::new(Self {
            socket: Arc::new(socket),
            upstream,
            client_ip,
            flows: Mutex::new(HashMap::new()),
            refused: Mutex::new(UdpRefusals::default()),
            opening: Mutex::new(()),
            client: Mutex::new(None),
            readers: Mutex::new(Vec::new()),
            dns_slots: Arc::new(tokio::sync::Semaphore::new(32)),
        })
    }

    async fn run(self: Arc<Self>, mut control: BufReader<TcpStream>) -> Result<()> {
        let mut control_byte = [0u8; 1];
        let mut packet = vec![0u8; MAX_DATAGRAM + 512];
        loop {
            tokio::select! {
                result = control.read(&mut control_byte) => {
                    match result {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                result = self.socket.recv_from(&mut packet) => {
                    let (length, source) = result?;
                    if let Err(error) = self.handle_packet(&packet[..length], source).await {
                        log::debug!("[firefox] SOCKS UDP packet failed: {error}");
                    }
                }
            }
        }
        self.readers.lock().await.retain(|task| {
            task.abort();
            false
        });
        self.flows.lock().await.clear();
        Ok(())
    }

    async fn handle_packet(self: &Arc<Self>, packet: &[u8], source: SocketAddr) -> Result<()> {
        if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 || source.ip() != self.client_ip {
            return Ok(());
        }
        let mut client = self.client.lock().await;
        if let Some(expected) = *client {
            if expected != source {
                return Ok(());
            }
        } else {
            *client = Some(source);
        }
        drop(client);
        let (host, port, payload_offset) = parse_udp_address(packet, 3)?;
        let target = authority(&host, port);
        let payload = &packet[payload_offset..];
        if payload.len() > MAX_DATAGRAM {
            return Ok(());
        }
        if port == 53 && crate::doh::provider(&host).is_some() {
            let Ok(permit) = self.dns_slots.clone().try_acquire_owned() else { return Ok(()) };
            let query = payload.to_vec();
            let header = packet[..payload_offset].to_vec();
            let upstream = self.upstream.clone();
            let socket = self.socket.clone();
            let task = tokio::spawn(async move {
                let _permit = permit;
                match tokio::time::timeout(crate::doh::QUERY_TIMEOUT, crate::doh::exchange(&upstream, &host, &query)).await {
                    Ok(Ok(answer)) => {
                        let mut response = header;
                        response.extend_from_slice(&answer);
                        let _ = socket.send_to(&response, source).await;
                    }
                    Ok(Err(error)) => log::debug!("[firefox] encrypted DNS query failed: {error}"),
                    Err(_) => log::debug!("[firefox] encrypted DNS query timed out"),
                }
            });
            let mut readers = self.readers.lock().await;
            readers.retain(|reader| !reader.is_finished());
            readers.push(task.abort_handle());
            return Ok(());
        }
        let _opening = self.opening.lock().await;
        let existing = {
            let flows = self.flows.lock().await;
            if !flows.contains_key(&target) && flows.len() >= MAX_UDP_FLOWS {
                return Ok(());
            }
            flows.get(&target).cloned()
        };
        let tunnel = if let Some(tunnel) = existing {
            tunnel
        } else {
            let refusal_key = (self.upstream.candidate().address, target.clone());
            if self.refused.lock().await.contains(&refusal_key, std::time::Instant::now()) {
                return Ok(());
            }
            let tunnel = match self.upstream.open_udp(&target).await {
                Ok(tunnel) => Arc::new(tunnel),
                Err(error) => {
                    if crate::transport::destination_error(&error) == Some("destination_ip_prohibited") {
                        self.refused.lock().await.record(refusal_key, std::time::Instant::now());
                    }
                    return Err(error);
                }
            };
            self.flows.lock().await.insert(target.clone(), tunnel.clone());
            let association = self.clone();
            let reader_tunnel = tunnel.clone();
            let reader_target = target.clone();
            let task = tokio::spawn(async move {
                association.read_upstream(reader_tunnel, reader_target).await;
            });
            let mut readers = self.readers.lock().await;
            readers.retain(|reader| !reader.is_finished());
            readers.push(task.abort_handle());
            tunnel
        };
        drop(_opening);
        tunnel.try_send(payload)
    }

    async fn read_upstream(&self, tunnel: Arc<crate::transport::UdpTunnel>, target: String) {
        let header = crate::types::split_authority(&target, 53).map(|(host, port)| {
            let mut header = vec![0, 0, 0];
            append_target_address(&mut header, &host);
            header.extend_from_slice(&port.to_be_bytes());
            header
        });
        let Some(header) = header else {
            self.flows.lock().await.remove(&target);
            return;
        };
        loop {
            match tunnel.recv().await {
                Ok(packet) => {
                    let Some(client) = *self.client.lock().await else { break };
                    let mut response = Vec::with_capacity(header.len() + packet.len());
                    response.extend_from_slice(&header);
                    response.extend_from_slice(&packet);
                    if self.socket.send_to(&response, client).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let mut flows = self.flows.lock().await;
        if flows.get(&target).is_some_and(|current| Arc::ptr_eq(current, &tunnel)) {
            flows.remove(&target);
        }
    }
}

async fn serve_dns_tcp<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, upstream: &Upstream, host: &str) -> Result<()> {
    loop {
        let length = match tokio::time::timeout(std::time::Duration::from_secs(30), stream.read_u16()).await {
            Ok(Ok(length)) => length as usize,
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => return Ok(()),
        };
        if length < 12 {
            return Err(FirefoxError::Protocol("invalid DNS query length".into()));
        }
        let mut query = vec![0; length];
        tokio::time::timeout(crate::doh::QUERY_TIMEOUT, stream.read_exact(&mut query)).await
            .map_err(|_| FirefoxError::Timeout(crate::doh::QUERY_TIMEOUT))??;
        let response = tokio::time::timeout(crate::doh::QUERY_TIMEOUT, crate::doh::exchange(upstream, host, &query)).await
            .map_err(|_| FirefoxError::Timeout(crate::doh::QUERY_TIMEOUT))??;
        stream.write_u16(response.len() as u16).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
}

fn append_target_address(output: &mut Vec<u8>, host: &str) {
    if let Ok(ip) = host.parse::<IpAddr>() {
        append_ip_address(output, ip);
    } else {
        output.push(3);
        output.push(host.len().min(255) as u8);
        output.extend_from_slice(&host.as_bytes()[..host.len().min(255)]);
    }
}

fn append_ip_address(output: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(ip) => {
            output.push(1);
            output.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            output.push(4);
            output.extend_from_slice(&ip.octets());
        }
    }
}

fn parse_udp_address(packet: &[u8], offset: usize) -> Result<(String, u16, usize)> {
    let atyp = *packet.get(offset).ok_or_else(|| FirefoxError::Protocol("truncated SOCKS UDP address".into()))?;
    let mut cursor = offset + 1;
    let host = match atyp {
        1 => {
            let bytes: [u8; 4] = packet.get(cursor..cursor + 4).ok_or_else(|| FirefoxError::Protocol("truncated UDP IPv4 address".into()))?.try_into().unwrap();
            cursor += 4;
            IpAddr::V4(bytes.into()).to_string()
        }
        4 => {
            let bytes: [u8; 16] = packet.get(cursor..cursor + 16).ok_or_else(|| FirefoxError::Protocol("truncated UDP IPv6 address".into()))?.try_into().unwrap();
            cursor += 16;
            IpAddr::V6(bytes.into()).to_string()
        }
        3 => {
            let length = *packet.get(cursor).ok_or_else(|| FirefoxError::Protocol("truncated UDP domain length".into()))? as usize;
            cursor += 1;
            let host = String::from_utf8(packet.get(cursor..cursor + length).ok_or_else(|| FirefoxError::Protocol("truncated UDP domain".into()))?.to_vec())
                .map_err(|_| FirefoxError::Protocol("invalid UDP domain".into()))?;
            if !valid_dns_name(&host) {
                return Err(FirefoxError::UnsupportedDestination(host));
            }
            cursor += length;
            host
        }
        _ => return Err(FirefoxError::Protocol("unknown UDP address type".into())),
    };
    let port = u16::from_be_bytes(packet.get(cursor..cursor + 2).ok_or_else(|| FirefoxError::Protocol("truncated UDP port".into()))?.try_into().unwrap());
    if port == 0 {
        return Err(FirefoxError::UnsupportedDestination("UDP port is zero".into()));
    }
    Ok((host, port, cursor + 2))
}

async fn handle_http(stream: TcpStream, upstream: Arc<Upstream>) -> Result<()> {
    let mut stream = BufReader::new(stream);
    let mut head = Vec::with_capacity(2048);
    loop {
        let mut line = Vec::new();
        let remaining = (MAX_HEAD + 1).saturating_sub(head.len()) as u64;
        let read = (&mut stream).take(remaining).read_until(b'\n', &mut line).await?;
        if read == 0 {
            return Ok(());
        }
        if head.len().saturating_add(line.len()) > MAX_HEAD {
            write_http_error(&mut stream, 431, "request headers too large").await?;
            return Ok(());
        }
        head.extend_from_slice(&line);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&head).map_err(|_| FirefoxError::Protocol("HTTP proxy request is not UTF-8".into()))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| FirefoxError::Protocol("missing HTTP request line".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if method.is_empty() || target.is_empty() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") || parts.next().is_some() {
        return Err(FirefoxError::Protocol("invalid HTTP proxy request line".into()));
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = crate::types::split_authority(target, 443).ok_or_else(|| FirefoxError::UnsupportedDestination(target.into()))?;
        let target = authority(&host, port);
        if port == 53 && crate::doh::provider(&host).is_some() {
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            stream.flush().await?;
            return serve_dns_tcp(&mut stream, &upstream, &host).await;
        }
        match upstream.open_tcp(&target).await {
            Ok(mut tunnel) => {
                stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                stream.flush().await?;
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut tunnel).await;
            }
            Err(_) => write_http_error(&mut stream, 502, "proxy CONNECT failed").await?,
        }
        return Ok(());
    }

    let (origin, path) = if target.contains("://") {
        let url = url::Url::parse(target)?;
        if url.scheme() != "http" || !url.username().is_empty() || url.password().is_some() {
            return Err(FirefoxError::UnsupportedDestination("non-CONNECT proxy requests require a credential-free http:// URL".into()));
        }
        let host = url.host_str().ok_or_else(|| FirefoxError::UnsupportedDestination(target.into()))?;
        let port = url.port().unwrap_or(80);
        let path = if url.path().is_empty() { "/" } else { url.path() };
        (authority(host, port), match url.query() { Some(query) => format!("{path}?{query}"), None => path.to_string() })
    } else {
        if !target.starts_with('/') {
            return Err(FirefoxError::Protocol("HTTP proxy request target must be origin-form or an absolute http:// URL".into()));
        }
        let host = lines.clone().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host").then(|| value.trim())
        }).ok_or_else(|| FirefoxError::Protocol("HTTP request has no Host header".into()))?;
        let (host, port) = crate::types::split_authority(host, 80).ok_or_else(|| FirefoxError::UnsupportedDestination(host.into()))?;
        (authority(&host, port), target.to_string())
    };
    let mut tunnel = match upstream.open_tcp(&origin).await {
        Ok(tunnel) => tunnel,
        Err(_) => {
            write_http_error(&mut stream, 502, "proxy request failed").await?;
            return Ok(());
        }
    };
    let mut forwarded = format!("{method} {path} {version}\r\nHost: {origin}\r\n");
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("host:") || lower.starts_with("proxy-authorization:") || lower.starts_with("proxy-connection:") || lower.starts_with("connection:") || lower.starts_with("keep-alive:") {
            continue;
        }
        forwarded.push_str(line);
        forwarded.push_str("\r\n");
    }
    forwarded.push_str("Connection: close\r\n\r\n");
    tunnel.write_all(forwarded.as_bytes()).await?;
    tunnel.flush().await?;
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tunnel).await;
    Ok(())
}

async fn write_http_error<S: AsyncWrite + Unpin>(stream: &mut S, status: u16, message: &str) -> Result<()> {
    let body = format!("{message}\n");
    let response = format!("HTTP/1.1 {status} Proxy Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod udp_refusal_tests {
    use super::*;

    #[test]
    fn socks_replies_reflect_upstream_destination_errors() {
        for (reason, expected) in [
            ("destination_ip_prohibited", 2), ("destination_ip_unroutable", 3),
            ("destination_not_found", 4), ("destination_unavailable", 4),
            ("connection_refused", 5), ("unknown", 5),
        ] {
            let error = FirefoxError::Http {
                host: "proxy".into(), status: 502, errno: None, retry_after: None,
                message: format!("Fastly; error={reason}"),
            };
            assert_eq!(socks_reply_code(&error), expected, "{reason}");
        }
        assert_eq!(socks_reply_code(&FirefoxError::Timeout(std::time::Duration::from_secs(1))), 6);
    }

    #[test]
    fn refusal_cache_is_bounded_temporary_and_scoped_to_proxy_and_destination() {
        let now = std::time::Instant::now();
        let key = ("proxy-a".to_string(), "1.1.1.1:123".to_string());
        let mut cache = UdpRefusals::default();
        cache.record(key.clone(), now);
        assert!(cache.contains(&key, now));
        assert!(!cache.contains(&("proxy-b".into(), key.1.clone()), now));
        assert!(!cache.contains(&(key.0.clone(), "1.1.1.1:443".into()), now));
        assert!(!cache.contains(&key, now + UDP_REFUSAL_TTL));
        for n in 0..MAX_UDP_FLOWS + 10 {
            cache.record(("proxy".into(), n.to_string()), now);
        }
        assert_eq!(cache.entries.len(), MAX_UDP_FLOWS);
    }
}
