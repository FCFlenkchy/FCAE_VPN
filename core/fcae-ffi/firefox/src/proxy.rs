use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
const MAX_UDP_PENDING_BYTES: usize = 2 * 1024 * 1024;
const UDP_FAILURE_COOLDOWN: Duration = Duration::from_secs(2);
const UDP_UNSUPPORTED_COOLDOWN: Duration = Duration::from_secs(5);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

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
struct PendingUdp {
    packets: VecDeque<Vec<u8>>,
    bytes: usize,
}

enum UdpFlow {
    Opening(PendingUdp),
    Ready { tunnel: Arc<crate::transport::UdpTunnel>, activity: Arc<parking_lot::Mutex<Instant>> },
}

#[derive(Default)]
struct UdpFlows {
    entries: HashMap<String, UdpFlow>,
    pending_bytes: usize,
    failures: HashMap<String, (Instant, String)>,
    unsupported: Option<(Instant, String)>,
}

impl UdpFlows {
    fn enqueue(&mut self, target: &str, payload: &[u8]) -> bool {
        let cost = payload.len().saturating_add(32);
        if self.pending_bytes.saturating_add(cost) > MAX_UDP_PENDING_BYTES { return false; }
        if let Some(UdpFlow::Opening(pending)) = self.entries.get_mut(target) {
            pending.packets.push_back(payload.to_vec());
            pending.bytes += cost;
            self.pending_bytes += cost;
            true
        } else {
            false
        }
    }

    fn blocked(&mut self, target: &str, candidate: &str, now: Instant) -> bool {
        self.failures.retain(|_, (until, address)| *until > now && address == candidate);
        self.unsupported.as_ref().is_some_and(|(until, address)| *until > now && address == candidate)
            || self.failures.contains_key(target)
    }

    fn record_failure(&mut self, target: &str, candidate: &str, h1: bool, error: &FirefoxError, now: Instant) {
        if matches!(error, FirefoxError::Http { status: 502, .. }) { return; }
        self.failures.retain(|_, (until, address)| *until > now && address == candidate);
        if self.failures.len() >= MAX_UDP_FLOWS {
            if let Some(key) = self.failures.keys().next().cloned() { self.failures.remove(&key); }
        }
        self.failures.insert(target.to_string(), (now + UDP_FAILURE_COOLDOWN, candidate.to_string()));
        if h1 && matches!(error, FirefoxError::Http { status: 405 | 501, .. }) {
            self.unsupported = Some((now + UDP_UNSUPPORTED_COOLDOWN, candidate.to_string()));
        }
    }

    fn remove(&mut self, target: &str) -> Option<UdpFlow> {
        let flow = self.entries.remove(target)?;
        if let UdpFlow::Opening(pending) = &flow {
            self.pending_bytes = self.pending_bytes.saturating_sub(pending.bytes);
        }
        Some(flow)
    }
}

struct UdpAssociation {
    socket: Arc<UdpSocket>,
    upstream: Arc<Upstream>,
    client_ip: IpAddr,
    flows: Mutex<UdpFlows>,
    client: Mutex<Option<SocketAddr>>,
    readers: parking_lot::Mutex<Vec<AbortHandle>>,
    stopped: std::sync::atomic::AtomicBool,
    dns_slots: Arc<tokio::sync::Semaphore>,
}

impl UdpAssociation {
    fn new(socket: UdpSocket, upstream: Arc<Upstream>, client_ip: IpAddr) -> Arc<Self> {
        Arc::new(Self {
            socket: Arc::new(socket),
            upstream,
            client_ip,
            flows: Mutex::new(UdpFlows::default()),
            client: Mutex::new(None),
            readers: parking_lot::Mutex::new(Vec::new()),
            stopped: std::sync::atomic::AtomicBool::new(false),
            dns_slots: Arc::new(tokio::sync::Semaphore::new(32)),
        })
    }

    fn track(&self, task: AbortHandle) {
        let mut readers = self.readers.lock();
        if self.stopped.load(std::sync::atomic::Ordering::Acquire) {
            task.abort();
        } else {
            readers.retain(|reader| !reader.is_finished());
            readers.push(task);
        }
    }

    async fn run(self: Arc<Self>, mut control: BufReader<TcpStream>) -> Result<()> {
        let _guard = UdpTaskGuard(self.clone());
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
        {
            let mut readers = self.readers.lock();
            self.stopped.store(true, std::sync::atomic::Ordering::Release);
            readers.drain(..).for_each(|task| task.abort());
        }
        *self.flows.lock().await = UdpFlows::default();
        Ok(())
    }

    async fn handle_packet(self: &Arc<Self>, packet: &[u8], source: SocketAddr) -> Result<()> {
        if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 || source.ip() != self.client_ip {
            return Ok(());
        }
        let mut client = self.client.lock().await;
        if let Some(expected) = *client {
            if expected != source { return Ok(()); }
        } else {
            *client = Some(source);
        }
        drop(client);
        let (host, port, payload_offset) = parse_udp_address(packet, 3)?;
        let target = authority(&host, port);
        let payload = &packet[payload_offset..];
        if payload.len() > MAX_DATAGRAM { return Ok(()); }
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
            self.track(task.abort_handle());
            return Ok(());
        }
        let mut flows = self.flows.lock().await;
        if let Some(UdpFlow::Ready { tunnel, activity }) = flows.entries.get(&target) {
            match tunnel.try_send_with_capacity(payload) {
                Ok(sent) => {
                    if sent { *activity.lock() = Instant::now(); }
                    return Ok(());
                }
                Err(_) => { flows.remove(&target); }
            }
        }
        if flows.entries.contains_key(&target) {
            flows.enqueue(&target, payload);
            return Ok(());
        }
        let candidate = self.upstream.candidate().address;
        if flows.blocked(&target, &candidate, Instant::now()) { return Ok(()); }
        if flows.entries.len() >= MAX_UDP_FLOWS { return Ok(()); }
        flows.entries.insert(target.clone(), UdpFlow::Opening(PendingUdp::default()));
        if !flows.enqueue(&target, payload) {
            flows.remove(&target);
            return Ok(());
        }
        drop(flows);
        let association = self.clone();
        let task = tokio::spawn(async move { association.open_flow(target, candidate).await; });
        self.track(task.abort_handle());
        Ok(())
    }

    async fn open_flow(self: Arc<Self>, target: String, candidate: String) {
        let result = self.upstream.open_udp(&target).await;
        let mut flows = self.flows.lock().await;
        let Some(UdpFlow::Opening(pending)) = flows.remove(&target) else { return };
        let tunnel = match result {
            Ok(tunnel) if !self.stopped.load(std::sync::atomic::Ordering::Acquire) => Arc::new(tunnel),
            Ok(_) => return,
            Err(error) => {
                log::debug!("[firefox] SOCKS UDP flow failed: {error}");
                if self.upstream.candidate().address == candidate {
                    flows.record_failure(&target, &candidate,
                        self.upstream.transport_preference() == crate::types::TransportPreference::H1,
                        &error, Instant::now());
                }
                return;
            }
        };
        for packet in pending.packets {
            if !matches!(tunnel.try_send_with_capacity(&packet), Ok(true)) { break; }
        }
        let activity = Arc::new(parking_lot::Mutex::new(Instant::now()));
        flows.entries.insert(target.clone(), UdpFlow::Ready { tunnel: tunnel.clone(), activity: activity.clone() });
        drop(flows);
        let association = self.clone();
        let task = tokio::spawn(async move { association.read_upstream(tunnel, activity, target).await; });
        self.track(task.abort_handle());
    }

    async fn read_upstream(&self, tunnel: Arc<crate::transport::UdpTunnel>, activity: Arc<parking_lot::Mutex<Instant>>, target: String) {
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
        let mut cleanup = tokio::time::interval_at(tokio::time::Instant::now() + Duration::from_secs(30), Duration::from_secs(30));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let received = tokio::select! {
                result = tunnel.recv() => result,
                _ = cleanup.tick() => {
                    let mut flows = self.flows.lock().await;
                    if !matches!(flows.entries.get(&target), Some(UdpFlow::Ready { tunnel: current, .. }) if Arc::ptr_eq(current, &tunnel)) {
                        break;
                    }
                    if activity.lock().elapsed() >= UDP_IDLE_TIMEOUT {
                        flows.remove(&target);
                        break;
                    }
                    continue;
                }
            };
            match received {
                Ok(packet) => {
                    *activity.lock() = Instant::now();
                    let Some(client) = *self.client.lock().await else { break };
                    let mut response = Vec::with_capacity(header.len() + packet.len());
                    response.extend_from_slice(&header);
                    response.extend_from_slice(&packet);
                    if self.socket.send_to(&response, client).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
        let mut flows = self.flows.lock().await;
        if matches!(flows.entries.get(&target), Some(UdpFlow::Ready { tunnel: current, .. }) if Arc::ptr_eq(current, &tunnel)) {
            flows.remove(&target);
        }
    }
}

struct UdpTaskGuard(Arc<UdpAssociation>);

impl Drop for UdpTaskGuard {
    fn drop(&mut self) {
        let mut readers = self.0.readers.lock();
        self.0.stopped.store(true, std::sync::atomic::Ordering::Release);
        readers.drain(..).for_each(|task| task.abort());
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
mod tests {
    use super::*;

    #[test]
    fn udp_failure_cooldown_is_scoped_and_expires_without_retrying_502() {
        let mut flows = UdpFlows::default();
        let now = Instant::now();
        let error = |status| FirefoxError::Http { host: "proxy".into(), status, errno: None, retry_after: None, message: String::new() };
        flows.record_failure("a", "proxy1", true, &error(502), now);
        assert!(!flows.blocked("a", "proxy1", now));
        flows.record_failure("a", "proxy1", true, &error(405), now);
        assert!(flows.blocked("a", "proxy1", now));
        assert!(flows.blocked("b", "proxy1", now));
        assert!(!flows.blocked("b", "proxy2", now));
        assert!(!flows.blocked("a", "proxy1", now + UDP_UNSUPPORTED_COOLDOWN));
        flows.record_failure("a", "proxy1", false, &FirefoxError::Network("closed".into()), now);
        assert!(!flows.blocked("b", "proxy1", now));
        assert!(flows.blocked("a", "proxy1", now));
        assert!(!flows.blocked("a", "proxy1", now + UDP_FAILURE_COOLDOWN));
    }

    #[test]
    fn pending_udp_packets_are_byte_bounded_and_cleared_on_failure() {
        let mut flows = UdpFlows::default();
        flows.entries.insert("a".into(), UdpFlow::Opening(PendingUdp::default()));
        flows.entries.insert("b".into(), UdpFlow::Opening(PendingUdp::default()));
        for _ in 0..100 { assert!(flows.enqueue("a", b"packet")); }
        assert!(flows.enqueue("b", b"other"));
        let UdpFlow::Opening(pending) = flows.entries.get("a").unwrap() else { panic!("not opening") };
        assert_eq!(pending.packets.len(), 100);
        assert!(!flows.enqueue("a", &vec![0u8; MAX_UDP_PENDING_BYTES]));
        assert!(flows.remove("a").is_some());
        assert_eq!(flows.pending_bytes, 5 + 32);
        assert!(flows.remove("b").is_some());
        assert_eq!(flows.pending_bytes, 0);
    }

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

}
