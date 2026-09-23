//! Zeptun's in-process socks5p adapter. TCP uses strict SOCKS CONNECT;
//! DNS uses one multiplexed Psiphon UDPGW channel with transparent DNS flags.
//! No tun2socks engine, direct resolver, or external process is involved.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{oneshot, Mutex as AsyncMutex, Notify, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, Instant};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(8);
const DIAL_COOLDOWN: Duration = Duration::from_millis(250);
const MAX_DNS: usize = 32768;
const MAX_PENDING: usize = 512;
const DNS_SLOTS: u16 = 8;
const KEEPALIVE: u8 = 1;
const DNS_FLAG: u8 = 4;
const IPV6_FLAG: u8 = 8;

fn error(message: &'static str) -> io::Error {
    io::Error::other(message)
}

pub(crate) struct Adapter {
    endpoint: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Adapter {
    pub(crate) fn start(upstream: SocketAddr, resolvers: Vec<Ipv4Addr>) -> io::Result<Self> {
        if !upstream.ip().is_loopback() || upstream.port() == 0 {
            return Err(error("socks5p requires a loopback Psiphon endpoint"));
        }
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let endpoint = listener.local_addr()?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        // Register the listener before reporting successful startup.
        let listener = {
            let _entered = runtime.enter();
            TcpListener::from_std(listener)?
        };
        let (shutdown, stopped) = oneshot::channel();
        let thread = std::thread::Builder::new().name("hev-socks5p".into()).spawn(move || {
            runtime.block_on(serve(listener, upstream, resolvers, stopped));
        })?;
        Ok(Self { endpoint, shutdown: Some(shutdown), thread: Some(thread) })
    }

    pub(crate) fn endpoint(&self) -> SocketAddr { self.endpoint }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() { let _ = shutdown.send(()); }
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

async fn serve(listener: TcpListener, upstream: SocketAddr, resolvers: Vec<Ipv4Addr>, mut stopped: oneshot::Receiver<()>) {
    let gateway = Arc::new(Gateway::new(upstream, resolvers));
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut stopped => break,
            _ = clients.join_next(), if !clients.is_empty() => {},
            accepted = listener.accept() => {
                let (client, peer) = match accepted {
                    Ok(value) => value,
                    Err(e) => { log::error!("[hev socks5p] accept failed: {e}"); break; }
                };
                if !peer.ip().is_loopback() || clients.len() >= 1024 { continue; }
                let gateway = Arc::clone(&gateway);
                clients.spawn(async move { let _ = serve_client(client, gateway).await; });
            }
        }
    }
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    // Dropping this dedicated runtime also cancels gateway reader/keepalive tasks.
}

async fn read_ip_address<R: AsyncRead + Unpin>(reader: &mut R, kind: u8) -> io::Result<SocketAddr> {
    let ip = match kind {
        1 => { let mut bytes = [0; 4]; reader.read_exact(&mut bytes).await?; IpAddr::V4(bytes.into()) }
        4 => { let mut bytes = [0; 16]; reader.read_exact(&mut bytes).await?; IpAddr::V6(bytes.into()) }
        _ => return Err(error("SOCKS address must be an IP; local DNS resolution is forbidden")),
    };
    Ok(SocketAddr::new(ip, reader.read_u16().await?))
}

async fn reply(client: &mut TcpStream, status: u8, port: u16) -> io::Result<()> {
    let mut bytes = [5, status, 0, 1, 127, 0, 0, 1, 0, 0];
    bytes[8..].copy_from_slice(&port.to_be_bytes());
    client.write_all(&bytes).await
}

async fn negotiate(client: &mut TcpStream) -> io::Result<(u8, SocketAddr)> {
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting).await?;
    if greeting[0] != 5 || greeting[1] == 0 { return Err(error("invalid SOCKS greeting")); }
    let mut methods = vec![0; greeting[1] as usize];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        client.write_all(&[5, 255]).await?;
        return Err(error("SOCKS no-auth method not offered"));
    }
    client.write_all(&[5, 0]).await?;
    let mut request = [0; 4];
    client.read_exact(&mut request).await?;
    if request[0] != 5 || request[2] != 0 { return Err(error("invalid SOCKS request")); }
    let address = match read_ip_address(client, request[3]).await {
        Ok(address) => address,
        Err(e) => { reply(client, 8, 0).await?; return Err(e); }
    };
    Ok((request[1], address))
}

async fn serve_client(mut client: TcpStream, gateway: Arc<Gateway>) -> io::Result<()> {
    let (command, destination) = timeout(HANDSHAKE_TIMEOUT, negotiate(&mut client)).await??;
    match command {
        1 if destination.port() == 53 => {
            reply(&mut client, 0, 0).await?;
            serve_tcp_dns(client, gateway).await
        }
        // Match socks5p: strict Private DNS cannot be carried by these exits.
        1 if destination.port() == 853 => reply(&mut client, 5, 0).await,
        1 => {
            match socks_connect(gateway.upstream, destination).await {
                Ok(mut remote) => {
                    reply(&mut client, 0, 0).await?;
                    tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
                    Ok(())
                }
                Err(_) => reply(&mut client, 5, 0).await,
            }
        }
        3 => serve_udp(client, gateway).await,
        _ => reply(&mut client, 7, 0).await,
    }
}

// Never send CONNECT before the method reply, or application bytes before
// CONNECT succeeds. The local facade safely accepts zeptun's pipelined bytes.
async fn socks_connect(upstream: SocketAddr, destination: SocketAddr) -> io::Result<TcpStream> {
    timeout(HANDSHAKE_TIMEOUT, async {
        let mut stream = TcpStream::connect(upstream).await?;
        stream.set_nodelay(true)?;
        stream.write_all(&[5, 1, 0]).await?;
        let mut method = [0; 2];
        stream.read_exact(&mut method).await?;
        if method != [5, 0] { return Err(error("Psiphon rejected SOCKS authentication")); }
        let mut request = vec![5, 1, 0];
        match destination.ip() {
            IpAddr::V4(ip) => { request.push(1); request.extend_from_slice(&ip.octets()); }
            IpAddr::V6(ip) => { request.push(4); request.extend_from_slice(&ip.octets()); }
        }
        request.extend_from_slice(&destination.port().to_be_bytes());
        stream.write_all(&request).await?;
        let mut response = [0; 4];
        stream.read_exact(&mut response).await?;
        if response[0] != 5 || response[1] != 0 || response[2] != 0 {
            return Err(error("Psiphon rejected SOCKS CONNECT"));
        }
        match response[3] {
            1 | 4 => { read_ip_address(&mut stream, response[3]).await?; }
            3 => {
                let length = stream.read_u8().await? as usize;
                let mut ignored = vec![0; length + 2];
                stream.read_exact(&mut ignored).await?;
            }
            _ => return Err(error("invalid Psiphon SOCKS reply")),
        }
        Ok(stream)
    }).await?
}

fn valid_query(query: &[u8]) -> bool {
    (12..=MAX_DNS).contains(&query.len()) && query[2] & 0x80 == 0
}

fn servfail(query: &[u8]) -> Vec<u8> {
    let mut answer = query.to_vec();
    answer[2] = (answer[2] & 0x79) | 0x80;
    answer[3] = 0x82;
    answer
}

async fn serve_tcp_dns(mut client: TcpStream, gateway: Arc<Gateway>) -> io::Result<()> {
    loop {
        let query = timeout(Duration::from_secs(30), async {
            let size = client.read_u16().await? as usize;
            if !(12..=MAX_DNS).contains(&size) { return Err(error("invalid TCP DNS size")); }
            let mut query = vec![0; size];
            client.read_exact(&mut query).await?;
            if !valid_query(&query) { return Err(error("invalid TCP DNS query")); }
            Ok::<_, io::Error>(query)
        }).await??;
        let answer = gateway.exchange(&query).await.unwrap_or_else(|_| servfail(&query));
        timeout(DNS_TIMEOUT, async {
            client.write_u16(answer.len() as u16).await?;
            client.write_all(&answer).await
        }).await??;
    }
}

fn udp_dns_header(packet: &[u8]) -> Option<usize> {
    if packet.len() < 4 || packet[..3] != [0, 0, 0] { return None; }
    let header = match packet[3] { 1 => 10, 4 => 22, _ => return None };
    if packet.len() < header + 12 { return None; }
    if u16::from_be_bytes([packet[header - 2], packet[header - 1]]) != 53 { return None; }
    valid_query(&packet[header..]).then_some(header)
}

async fn serve_udp(mut control: TcpStream, gateway: Arc<Gateway>) -> io::Result<()> {
    let socket = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
    reply(&mut control, 0, socket.local_addr()?.port()).await?;
    let mut buffer = vec![0; 65535];
    let mut control_byte = [0; 1];
    let mut peer = None;
    let mut queries = JoinSet::new();
    loop {
        tokio::select! {
            _ = control.read(&mut control_byte) => break,
            _ = queries.join_next(), if !queries.is_empty() => {},
            packet = socket.recv_from(&mut buffer) => {
                let (size, source) = packet?;
                if !source.ip().is_loopback() || peer.is_some_and(|p| p != source) { continue; }
                let Some(header) = udp_dns_header(&buffer[..size]) else { continue; };
                peer = Some(source);
                if queries.len() >= 64 { continue; }
                let packet = buffer[..size].to_vec();
                let socket = Arc::clone(&socket);
                let gateway = Arc::clone(&gateway);
                queries.spawn(async move {
                    let answer = gateway.exchange(&packet[header..]).await
                        .unwrap_or_else(|_| servfail(&packet[header..]));
                    let mut response = packet[..header].to_vec();
                    response.extend_from_slice(&answer);
                    let _ = socket.send_to(&response, source).await;
                });
            }
        }
    }
    queries.abort_all();
    while queries.join_next().await.is_some() {}
    Ok(())
}

struct Gateway {
    upstream: SocketAddr,
    resolvers: Vec<Ipv4Addr>,
    next_resolver: AtomicUsize,
    state: AsyncMutex<GatewayState>,
    limit: Semaphore,
}

#[derive(Default)]
struct GatewayState {
    channel: Option<Arc<Channel>>,
    last_dial: Option<Instant>,
}

impl Gateway {
    fn new(upstream: SocketAddr, resolvers: Vec<Ipv4Addr>) -> Self {
        Self { upstream, resolvers, next_resolver: AtomicUsize::new(0), state: AsyncMutex::new(GatewayState::default()), limit: Semaphore::new(MAX_PENDING) }
    }

    fn resolver(&self) -> Option<Ipv4Addr> {
        if self.resolvers.is_empty() { return None; }
        let index = self.next_resolver.fetch_add(1, Ordering::Relaxed) % self.resolvers.len();
        Some(self.resolvers[index])
    }

    async fn channel(&self) -> io::Result<Arc<Channel>> {
        // Hold the lock through the dial: Psiphon replaces the old UDPGW
        // channel if a second one opens for this tunnel.
        let mut state = self.state.lock().await;
        if let Some(channel) = &state.channel {
            if channel.alive.load(Ordering::Acquire) { return Ok(Arc::clone(channel)); }
        }
        if state.last_dial.is_some_and(|last| last.elapsed() < DIAL_COOLDOWN) {
            return Err(error("Psiphon UDPGW reconnect cooldown"));
        }
        state.last_dial = Some(Instant::now());
        let stream = socks_connect(self.upstream, SocketAddr::from(([127, 0, 0, 1], 7300))).await?;
        let (reader, writer) = stream.into_split();
        let channel = Arc::new(Channel {
            writer: AsyncMutex::new(writer), pending: Mutex::new(Pending::default()),
            alive: AtomicBool::new(true), closed: Notify::new(),
        });
        let task_channel = Arc::clone(&channel);
        tokio::spawn(async move { task_channel.read_loop(reader).await; });
        let weak = Arc::downgrade(&channel);
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(20)).await;
                let Some(channel) = weak.upgrade() else { break; };
                if channel.write(&[3, 0, KEEPALIVE, 0, 0]).await.is_err() { break; }
            }
        });
        state.channel = Some(Arc::clone(&channel));
        Ok(channel)
    }

    async fn exchange(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        if !valid_query(query) { return Err(error("invalid Psiphon DNS query")); }
        let _permit = self.limit.try_acquire().map_err(|_| error("Psiphon DNS query table full"))?;
        let mut last_error = error("Psiphon UDPGW unavailable");
        let resolver = self.resolver();
        for attempt in 0..2 {
            if attempt != 0 { sleep(DIAL_COOLDOWN).await; }
            match self.channel().await {
                Ok(channel) => match channel.exchange(query, resolver).await {
                    Ok(answer) => return Ok(answer),
                    Err(e) => last_error = e,
                },
                Err(e) => last_error = e,
            }
        }
        Err(last_error)
    }
}

type Answer = oneshot::Sender<io::Result<Vec<u8>>>;

#[derive(Default)]
struct Pending {
    next_id: u16,
    next_slot: u16,
    entries: HashMap<u16, (u16, Answer)>,
}

struct Channel {
    writer: AsyncMutex<OwnedWriteHalf>,
    pending: Mutex<Pending>,
    alive: AtomicBool,
    closed: Notify,
}

struct Ticket {
    channel: Arc<Channel>,
    id: u16,
}

impl Drop for Ticket {
    fn drop(&mut self) { self.channel.pending.lock().entries.remove(&self.id); }
}

// BadVPN UDPGW: LE length, flags, LE connection ID, raw IP, BE port, DNS.
// A resolver address makes the exit relay to it; 0.0.0.0 plus DNS_FLAG asks
// the exit to use its own resolver.
fn dns_frame(slot: u16, id: u16, query: &[u8], resolver: Option<Ipv4Addr>) -> Vec<u8> {
    let mut frame = vec![0; 11 + query.len()];
    let length = (frame.len() - 2) as u16;
    frame[..2].copy_from_slice(&length.to_le_bytes());
    frame[3..5].copy_from_slice(&slot.to_le_bytes());
    match resolver {
        Some(ip) => frame[5..9].copy_from_slice(&ip.octets()),
        None => frame[2] = DNS_FLAG,
    }
    frame[9..11].copy_from_slice(&53u16.to_be_bytes());
    frame[11..].copy_from_slice(query);
    frame[11..13].copy_from_slice(&id.to_be_bytes());
    frame
}

fn dns_reply(frame: &[u8]) -> Option<(u16, u16, &[u8])> {
    if frame.len() < 3 || frame[0] & KEEPALIVE != 0 || frame[0] & !15 != 0 { return None; }
    let offset = if frame[0] & IPV6_FLAG != 0 { 21 } else { 9 };
    if frame.len() < offset + 12 || frame.len() - offset > MAX_DNS { return None; }
    let payload = &frame[offset..];
    if payload[2] & 0x80 == 0 { return None; }
    Some((u16::from_le_bytes([frame[1], frame[2]]), u16::from_be_bytes([payload[0], payload[1]]), payload))
}

struct WriteGuard<'a> {
    channel: &'a Channel,
    complete: bool,
}

impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        if !self.complete { self.channel.invalidate(); }
    }
}

impl Channel {
    fn invalidate(&self) {
        self.alive.store(false, Ordering::Release);
        self.closed.notify_one();
        for (_, (_, sender)) in self.pending.lock().entries.drain() {
            let _ = sender.send(Err(error("Psiphon UDPGW channel closed")));
        }
    }

    async fn write(&self, frame: &[u8]) -> io::Result<()> {
        if !self.alive.load(Ordering::Acquire) { return Err(error("Psiphon UDPGW channel closed")); }
        let result = timeout(DNS_TIMEOUT, async {
            let mut writer = self.writer.lock().await;
            if !self.alive.load(Ordering::Acquire) { return Err(error("Psiphon UDPGW channel closed")); }
            // Cancellation midway through a frame must retire the stream.
            let mut guard = WriteGuard { channel: self, complete: false };
            writer.write_all(frame).await?;
            guard.complete = true;
            Ok(())
        }).await;
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => { self.invalidate(); Err(e) }
            Err(_) => { self.invalidate(); Err(error("Psiphon UDPGW write timeout")) }
        }
    }

    async fn exchange(self: &Arc<Self>, query: &[u8], resolver: Option<Ipv4Addr>) -> io::Result<Vec<u8>> {
        let (sender, receiver) = oneshot::channel();
        let (id, slot) = {
            let mut pending = self.pending.lock();
            if pending.entries.len() >= MAX_PENDING { return Err(error("Psiphon DNS query table full")); }
            loop {
                pending.next_id = pending.next_id.wrapping_add(1);
                if !pending.entries.contains_key(&pending.next_id) { break; }
            }
            pending.next_slot = pending.next_slot % DNS_SLOTS + 1;
            let id = pending.next_id;
            let slot = pending.next_slot;
            pending.entries.insert(id, (slot, sender));
            (id, slot)
        };
        let _ticket = Ticket { channel: Arc::clone(self), id };
        self.write(&dns_frame(slot, id, query, resolver)).await?;
        let mut answer = timeout(DNS_TIMEOUT, receiver).await
            .map_err(|_| error("Psiphon DNS reply timeout"))?
            .map_err(|_| error("Psiphon DNS query cancelled"))??;
        answer[..2].copy_from_slice(&query[..2]);
        Ok(answer)
    }

    async fn read_loop(self: Arc<Self>, mut reader: OwnedReadHalf) {
        loop {
            if !self.alive.load(Ordering::Acquire) { break; }
            let frame = tokio::select! {
                _ = self.closed.notified() => break,
                result = read_gateway_frame(&mut reader) => match result {
                    Ok(frame) => frame,
                    Err(_) => break,
                },
            };
            if let Some((slot, id, payload)) = dns_reply(&frame) {
                let mut pending = self.pending.lock();
                if pending.entries.get(&id).is_some_and(|(expected, _)| *expected == slot) {
                    if let Some((_, sender)) = pending.entries.remove(&id) {
                        let _ = sender.send(Ok(payload.to_vec()));
                    }
                }
            }
        }
        self.invalidate();
    }
}

async fn read_gateway_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let length = reader.read_u16_le().await? as usize;
    if !(3..=23 + MAX_DNS).contains(&length) { return Err(error("invalid UDPGW frame length")); }
    let mut frame = vec![0; length];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(marker: u8) -> Vec<u8> {
        let mut query = vec![0; 12];
        query[..2].copy_from_slice(&0x1234u16.to_be_bytes());
        query[2] = 1;
        query[11] = marker;
        query
    }

    #[test]
    fn gateway_wire_format_matches_socks5p() {
        let query = query(7);
        let frame = dns_frame(3, 0xabcd, &query, None);
        assert_eq!(&frame[..11], &[21, 0, DNS_FLAG, 3, 0, 0, 0, 0, 0, 0, 53]);
        let addressed = dns_frame(3, 0xabcd, &query, Some(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(&addressed[..11], &[21, 0, 0, 3, 0, 1, 1, 1, 1, 0, 53]);
        assert_eq!(&frame[11..13], &[0xab, 0xcd]);
        assert_eq!(&query[..2], &[0x12, 0x34]);
        let mut body = frame[2..].to_vec();
        body[11] |= 0x80;
        let (slot, id, payload) = dns_reply(&body).unwrap();
        assert_eq!((slot, id), (3, 0xabcd));
        assert_eq!(payload[11], 7);
        assert!(dns_reply(&[KEEPALIVE, 0, 0]).is_none());
        assert!(dns_reply(&body[..10]).is_none());
    }

    #[test]
    fn udp_adaptation_is_dns_only_and_rejects_fragments() {
        let mut packet = vec![0, 0, 0, 1, 1, 1, 1, 1, 0, 53];
        packet.extend_from_slice(&query(1));
        assert_eq!(udp_dns_header(&packet), Some(10));
        packet[2] = 1;
        assert!(udp_dns_header(&packet).is_none());
        packet[2] = 0;
        packet[9] = 54;
        assert!(udp_dns_header(&packet).is_none());
        packet[9] = 53;
        packet[12] |= 0x80;
        assert!(udp_dns_header(&packet).is_none());
        let answer = servfail(&query(1));
        assert_eq!(&answer[..4], &[0x12, 0x34, 0x81, 0x82]);
    }

    async fn strict_accept(listener: &TcpListener, destination: SocketAddr) -> TcpStream {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        assert!(timeout(Duration::from_millis(20), stream.read_u8()).await.is_err());
        stream.write_all(&[5, 0]).await.unwrap();
        let mut header = [0; 4];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(&header[..3], &[5, 1, 0]);
        assert_eq!(read_ip_address(&mut stream, header[3]).await.unwrap(), destination);
        assert!(timeout(Duration::from_millis(20), stream.read_u8()).await.is_err());
        stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        stream
    }

    #[tokio::test]
    async fn facade_accepts_pipeline_but_psiphon_receives_strict_handshake() {
        timeout(Duration::from_secs(3), async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let adapter = Adapter::start(listener.local_addr().unwrap(), Vec::new()).unwrap();
            let server = tokio::spawn(async move {
                let mut stream = strict_accept(&listener, "192.0.2.1:443".parse().unwrap()).await;
                let mut data = [0; 4];
                stream.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"ping");
                stream.write_all(b"pong").await.unwrap();
            });
            let mut client = TcpStream::connect(adapter.endpoint()).await.unwrap();
            let mut pipeline = vec![5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 1, 1, 187];
            pipeline.extend_from_slice(b"ping");
            client.write_all(&pipeline).await.unwrap();
            let mut response = [0; 16];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response[..2], &[5, 0]);
            assert_eq!(&response[12..], b"pong");
            server.await.unwrap();
            drop(client);
            drop(adapter);
        }).await.unwrap();
    }

    #[tokio::test]
    async fn gateway_multiplexes_identical_dns_ids_on_one_channel() {
        timeout(Duration::from_secs(3), async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let gateway = Gateway::new(listener.local_addr().unwrap(), Vec::new());
            let server = tokio::spawn(async move {
                let mut stream = strict_accept(&listener, "127.0.0.1:7300".parse().unwrap()).await;
                let first = read_gateway_frame(&mut stream).await.unwrap();
                let second = read_gateway_frame(&mut stream).await.unwrap();
                assert_eq!(first[0], DNS_FLAG);
                assert_eq!(second[0], DNS_FLAG);
                assert_ne!(&first[9..11], &second[9..11]);
                assert_eq!(&first[3..9], &[0, 0, 0, 0, 0, 53]);
                for mut body in [second, first] {
                    body[11] |= 0x80;
                    stream.write_u16_le(body.len() as u16).await.unwrap();
                    stream.write_all(&body).await.unwrap();
                }
                assert!(timeout(Duration::from_millis(20), listener.accept()).await.is_err());
            });
            let first_query = query(1);
            let second_query = query(2);
            let (first, second) = tokio::join!(gateway.exchange(&first_query), gateway.exchange(&second_query));
            let first = first.unwrap();
            let second = second.unwrap();
            assert_eq!(&first[..2], &[0x12, 0x34]);
            assert_eq!(&second[..2], &[0x12, 0x34]);
            assert_eq!((first[11], second[11]), (1, 2));
            server.await.unwrap();
        }).await.unwrap();
    }
}

#[cfg(test)]
mod dns_transport_tests {
    use super::*;

    async fn open(adapter: SocketAddr, command: u8, ip: [u8; 4], port: u16) -> (TcpStream, u16) {
        let mut stream = TcpStream::connect(adapter).await.unwrap();
        let mut request = vec![5, 1, 0, 5, command, 0, 1];
        request.extend_from_slice(&ip);
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let mut reply = [0; 12];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..4], &[5, 0, 5, 0]);
        (stream, u16::from_be_bytes([reply[10], reply[11]]))
    }

    #[tokio::test]
    async fn udp_and_tcp_dns_share_the_native_gateway_and_keep_query_ids() {
        timeout(Duration::from_secs(3), async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let adapter = Adapter::start(listener.local_addr().unwrap(), Vec::new()).unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 4];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request[..3], &[5, 1, 0]);
                assert_eq!(read_ip_address(&mut stream, request[3]).await.unwrap(), "127.0.0.1:7300".parse().unwrap());
                stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                for _ in 0..2 {
                    let mut body = read_gateway_frame(&mut stream).await.unwrap();
                    assert_eq!(body[0], DNS_FLAG);
                    body[11] |= 0x80;
                    stream.write_u16_le(body.len() as u16).await.unwrap();
                    stream.write_all(&body).await.unwrap();
                }
                assert!(timeout(Duration::from_millis(20), listener.accept()).await.is_err());
            });
            let (control, port) = open(adapter.endpoint(), 3, [0, 0, 0, 0], 0).await;
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let mut query = vec![0; 12];
            query[..3].copy_from_slice(&[0x12, 0x34, 1]);
            let mut packet = vec![0, 0, 0, 1, 1, 1, 1, 1, 0, 53];
            packet.extend_from_slice(&query);
            udp.send_to(&packet, (Ipv4Addr::LOCALHOST, port)).await.unwrap();
            let mut response = [0; 512];
            let (size, _) = udp.recv_from(&mut response).await.unwrap();
            assert_eq!(size, packet.len());
            assert_eq!(&response[..12], &packet[..12]);
            assert_eq!(response[12] & 0x80, 0x80);
            let (mut tcp, _) = open(adapter.endpoint(), 1, [9, 9, 9, 9], 53).await;
            tcp.write_u16(query.len() as u16).await.unwrap();
            tcp.write_all(&query).await.unwrap();
            assert_eq!(tcp.read_u16().await.unwrap(), 12);
            tcp.read_exact(&mut query).await.unwrap();
            assert_eq!(&query[..2], &[0x12, 0x34]);
            assert_eq!(query[2] & 0x80, 0x80);
            // DoT is refused locally, not forwarded to a disallowed exit port.
            let mut dot = TcpStream::connect(adapter.endpoint()).await.unwrap();
            dot.write_all(&[5, 1, 0, 5, 1, 0, 1, 1, 1, 1, 1, 3, 85]).await.unwrap();
            let mut refused = [0; 12];
            dot.read_exact(&mut refused).await.unwrap();
            assert_eq!(refused[3], 5);
            server.await.unwrap();
            // Shutdown also closes live UDP control and TCP DNS sockets.
            drop(adapter);
            let mut byte = [0; 1];
            assert_eq!(tcp.read(&mut byte).await.unwrap(), 0);
            drop(control);
        }).await.unwrap();
    }
}
