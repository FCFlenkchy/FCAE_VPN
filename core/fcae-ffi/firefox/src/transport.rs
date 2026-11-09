use std::hash::{Hash, Hasher};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use http::{HeaderValue, Method};
use parking_lot::{Mutex as SyncMutex, RwLock};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::task::AbortHandle;
use tokio_boring::SslStream;
use zeroize::Zeroizing;

use crate::accounts::TokenManager;
use crate::dialer::Dialer;
use crate::error::{FirefoxError, Result};
use crate::tls::{firefox_user_agent, ALPN_H1, ALPN_H2};
use crate::types::{split_authority, Candidate, ProxyPass, TransportPreference, Usage};

const STREAM_WINDOW: u32 = 1024 * 1024;
const CONNECTION_WINDOW: u32 = 16 * 1024 * 1024;
const MAX_FRAME: u32 = 64 * 1024;
const MAX_HEAD: usize = 16 * 1024;
const MAX_UDP_PACKET: usize = 65_535;
const MAX_UDP_CAPSULE: usize = MAX_UDP_PACKET + 16;
const UDP_QUEUE_BYTES: usize = 256 * 1024;

pub trait TunnelIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TunnelIo for T {}
pub type BoxedTunnel = Box<dyn TunnelIo>;

#[derive(Default)]
pub struct Traffic {
    rx: AtomicU64,
    tx: AtomicU64,
}

impl Traffic {
    pub fn totals(&self) -> (u64, u64) {
        (self.rx.load(Ordering::Relaxed), self.tx.load(Ordering::Relaxed))
    }
}

struct MeteredTunnel {
    inner: BoxedTunnel,
    traffic: Arc<Traffic>,
}

impl AsyncRead for MeteredTunnel {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = output.filled().len();
        let result = Pin::new(&mut *self.inner).poll_read(cx, output);
        if matches!(&result, Poll::Ready(Ok(()))) {
            self.traffic.rx.fetch_add((output.filled().len() - before) as u64, Ordering::Relaxed);
        }
        result
    }
}

impl AsyncWrite for MeteredTunnel {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut *self.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(count)) = &result {
            self.traffic.tx.fetch_add(*count as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

struct SessionInner {
    alive: AtomicBool,
    token: RwLock<Zeroizing<String>>,
    last_activity: AtomicU64,
    active_streams: AtomicUsize,
    driver: SyncMutex<Option<AbortHandle>>,
    keepalive: SyncMutex<Option<AbortHandle>>,
}

impl SessionInner {
    fn kill(&self) {
        self.alive.store(false, Ordering::Release);
        if let Some(handle) = self.driver.lock().take() {
            handle.abort();
        }
    }
}

impl Drop for SessionInner {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
        if let Some(handle) = self.driver.get_mut().take() {
            handle.abort();
        }
        if let Some(handle) = self.keepalive.get_mut().take() {
            handle.abort();
        }
    }
}

#[derive(Clone)]
struct H2Session {
    sender: h2::client::SendRequest<Bytes>,
    authority: String,
    host: String,
    inner: Arc<SessionInner>,
}

impl H2Session {
    async fn connect(dialer: &Dialer, candidate: &Candidate, token: String) -> Result<Self> {
        let tls = crate::tls::connect(dialer, &candidate.host, candidate.port, ALPN_H2).await?;
        crate::tls::require_h2(&tls)?;
        let mut builder = h2::client::Builder::new();
        builder
            .enable_push(false)
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW)
            .max_frame_size(MAX_FRAME)
            .max_header_list_size(64 * 1024);
        let (sender, mut connection) = builder.handshake(tls).await.map_err(h2_error)?;
        let mut ping_pong = connection.ping_pong().ok_or_else(|| FirefoxError::H2("connection has no PING support".into()))?;
        let inner = Arc::new(SessionInner {
            alive: AtomicBool::new(true),
            token: RwLock::new(Zeroizing::new(token)),
            last_activity: AtomicU64::new(now_millis()),
            active_streams: AtomicUsize::new(0),
            driver: SyncMutex::new(None),
            keepalive: SyncMutex::new(None),
        });
        let driver_inner = inner.clone();
        let driver = tokio::spawn(async move {
            if let Err(error) = connection.await {
                log::debug!("[firefox] H2 connection ended: {error}");
            }
            driver_inner.alive.store(false, Ordering::Release);
        });
        *inner.driver.lock() = Some(driver.abort_handle());

        let weak = Arc::downgrade(&inner);
        let keepalive = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            let mut misses = 0;
            loop {
                interval.tick().await;
                let Some(inner) = weak.upgrade() else { break };
                if !inner.alive.load(Ordering::Acquire) {
                    break;
                }
                let sent = now_millis();
                if let Err(error) = ping_pong.send_ping(h2::Ping::opaque()) {
                    log::debug!("[firefox] H2 PING send failed: {error}");
                    inner.kill();
                    break;
                }
                let pong = std::future::poll_fn(|cx| ping_pong.poll_pong(cx));
                match tokio::time::timeout(Duration::from_secs(5), pong).await {
                    Ok(Ok(_)) => misses = 0,
                    Ok(Err(error)) => {
                        log::debug!("[firefox] H2 PING failed: {error}");
                        inner.kill();
                        break;
                    }
                    Err(_) if inner.last_activity.load(Ordering::Acquire) > sent => misses = 0,
                    Err(_) => misses += 1,
                }
                if misses >= 2 {
                    log::debug!("[firefox] H2 keepalive timed out");
                    inner.kill();
                    break;
                }
            }
        });
        *inner.keepalive.lock() = Some(keepalive.abort_handle());
        Ok(Self {
            sender,
            authority: candidate.authority(),
            host: candidate.host.clone(),
            inner,
        })
    }

    fn alive(&self) -> bool {
        self.inner.alive.load(Ordering::Acquire)
    }

    fn kill(&self) {
        self.inner.alive.store(false, Ordering::Release);
        if let Some(handle) = self.inner.driver.lock().take() {
            handle.abort();
        }
    }

    fn update_token(&self, token: &str) {
        *self.inner.token.write() = Zeroizing::new(token.to_string());
    }

    fn token(&self) -> Zeroizing<String> {
        Zeroizing::new(self.inner.token.read().to_string())
    }

    async fn open_tcp(&self, target: &str) -> Result<H2Tunnel> {
        split_authority(target, 443).ok_or_else(|| FirefoxError::UnsupportedDestination(target.into()))?;
        if !self.alive() {
            return Err(FirefoxError::H2("session is closed".into()));
        }
        let token = self.token();
        let mut sender = self.sender.clone();
        sender = sender.ready().await.map_err(h2_error)?;
        let request = connect_request(target, &token, None)?;
        let (response, send) = sender.send_request(request, false).map_err(h2_error)?;
        let response = response.await.map_err(h2_error)?;
        let (parts, recv) = response.into_parts();
        if !parts.status.is_success() {
            return Err(proxy_response_error(&self.authority_host(), parts.status.as_u16(), &parts.headers, recv).await);
        }
        self.inner.active_streams.fetch_add(1, Ordering::Relaxed);
        Ok(H2Tunnel {
            send,
            recv,
            read_chunk: Bytes::new(),
            read_offset: 0,
            inner: self.inner.clone(),
            shutdown: false,
        })
    }

    async fn open_udp(&self, target: &str, traffic: Arc<Traffic>) -> Result<UdpTunnel> {
        let (host, port) = split_authority(target, 53).ok_or_else(|| FirefoxError::UnsupportedDestination(target.into()))?;
        if !self.alive() {
            return Err(FirefoxError::H2("UDP session is closed".into()));
        }
        let token = self.token();
        let path = format!("/.well-known/masque/udp/{}/{port}/", path_segment(&host));
        let authority = self.authority();
        let uri = format!("https://{authority}{path}");
        let mut sender = self.sender.clone();
        sender = sender.ready().await.map_err(h2_error)?;
        let request = connect_request(&uri, &token, Some(h2::ext::Protocol::from_static("connect-udp")))?;
        let (response, send) = sender.send_request(request, false).map_err(h2_error)?;
        let response = response.await.map_err(h2_error)?;
        let (parts, recv) = response.into_parts();
        if !parts.status.is_success() {
            return Err(proxy_response_error(&self.authority_host(), parts.status.as_u16(), &parts.headers, recv).await);
        }
        self.inner.active_streams.fetch_add(1, Ordering::Relaxed);
        Ok(UdpTunnel::new(send, recv, self.inner.clone(), traffic))
    }

    fn authority(&self) -> String {
        self.authority.clone()
    }

    fn authority_host(&self) -> String {
        self.host.clone()
    }
}

fn connect_request(target_or_uri: &str, token: &str, protocol: Option<h2::ext::Protocol>) -> Result<http::Request<()>> {
    let mut builder = http::Request::builder()
        .method(Method::CONNECT)
        .uri(target_or_uri)
        .header("proxy-authorization", HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| FirefoxError::Protocol("proxy pass cannot be encoded as a header".into()))?)
        .header("user-agent", firefox_user_agent());
    if let Some(protocol) = protocol {
        builder = builder.header("capsule-protocol", "?1").extension(protocol);
    }
    builder.body(()).map_err(|error| FirefoxError::Protocol(error.to_string()))
}

pub struct H2Tunnel {
    send: SendStream<Bytes>,
    recv: RecvStream,
    read_chunk: Bytes,
    read_offset: usize,
    inner: Arc<SessionInner>,
    shutdown: bool,
}

impl AsyncRead for H2Tunnel {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.read_offset < self.read_chunk.len() {
                let available = &self.read_chunk[self.read_offset..];
                let count = available.len().min(output.remaining());
                output.put_slice(&available[..count]);
                self.read_offset += count;
                if self.read_offset == self.read_chunk.len() {
                    self.read_chunk = Bytes::new();
                    self.read_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.recv).poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, error))),
                Poll::Ready(Some(Ok(chunk))) => {
                    let _ = self.recv.flow_control().release_capacity(chunk.len());
                    self.inner.last_activity.store(now_millis(), Ordering::Release);
                    if chunk.is_empty() {
                        continue;
                    }
                    self.read_chunk = chunk;
                    self.read_offset = 0;
                }
            }
        }
    }
}

impl AsyncWrite for H2Tunnel {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.send.reserve_capacity(buffer.len().min(MAX_FRAME as usize));
        while self.send.capacity() == 0 {
            match self.send.poll_capacity(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "H2 stream is closed"))),
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, error))),
                Poll::Ready(Some(Ok(_))) => {}
            }
        }
        let count = buffer.len().min(self.send.capacity()).min(MAX_FRAME as usize);
        match self.send.send_data(Bytes::copy_from_slice(&buffer[..count]), false) {
            Ok(()) => {
                self.inner.last_activity.store(now_millis(), Ordering::Release);
                Poll::Ready(Ok(count))
            }
            Err(error) => Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, error))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown {
            self.send.send_data(Bytes::new(), true).map_err(|error| io::Error::new(io::ErrorKind::ConnectionReset, error))?;
            self.shutdown = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for H2Tunnel {
    fn drop(&mut self) {
        if !self.shutdown {
            self.send.send_reset(h2::Reason::CANCEL);
        }
        self.inner.active_streams.fetch_sub(1, Ordering::Relaxed);
    }
}

struct UdpState {
    queued: AtomicUsize,
    closed: AtomicBool,
}

pub struct UdpTunnel {
    outgoing: mpsc::Sender<Bytes>,
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    state: Arc<UdpState>,
    tasks: Vec<AbortHandle>,
    inner: Arc<SessionInner>,
    traffic: Arc<Traffic>,
}

impl UdpTunnel {
    fn new(mut send: SendStream<Bytes>, mut recv: RecvStream, inner: Arc<SessionInner>, traffic: Arc<Traffic>) -> Self {
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<Bytes>(256);
        let (incoming_tx, incoming_rx) = mpsc::channel::<Vec<u8>>(256);
        let state = Arc::new(UdpState { queued: AtomicUsize::new(0), closed: AtomicBool::new(false) });
        let writer_state = state.clone();
        let writer_inner = inner.clone();
        let writer = tokio::spawn(async move {
            while let Some(capsule) = outgoing_rx.recv().await {
                let length = capsule.len();
                let result = send_h2_bytes(&mut send, capsule).await;
                writer_state.queued.fetch_sub(length, Ordering::AcqRel);
                writer_inner.last_activity.store(now_millis(), Ordering::Release);
                if let Err(error) = result {
                    log::debug!("[firefox] UDP H2 writer ended: {error}");
                    break;
                }
            }
            writer_state.closed.store(true, Ordering::Release);
            let _ = send.send_data(Bytes::new(), true);
        });
        let reader_state = state.clone();
        let reader_inner = inner.clone();
        let reader = tokio::spawn(async move {
            let mut capsules = Vec::<u8>::new();
            loop {
                match recv.data().await {
                    Some(Ok(chunk)) => {
                        let _ = recv.flow_control().release_capacity(chunk.len());
                        reader_inner.last_activity.store(now_millis(), Ordering::Release);
                        if capsules.len().saturating_add(chunk.len()) > MAX_UDP_CAPSULE * 2 {
                            break;
                        }
                        capsules.extend_from_slice(&chunk);
                        let mut consumed = 0;
                        while let Some((kind, payload, used)) = next_capsule(&capsules[consumed..]) {
                            consumed += used;
                            if kind != 0 {
                                continue;
                            }
                            let Some((context, context_bytes)) = quic_varint(payload) else { continue };
                            if context != 0 || payload.len() == context_bytes {
                                continue;
                            }
                            let packet = &payload[context_bytes..];
                            if packet.len() > MAX_UDP_PACKET {
                                continue;
                            }
                            let _ = incoming_tx.try_send(packet.to_vec());
                        }
                        if consumed > 0 {
                            capsules.drain(..consumed);
                        }
                    }
                    Some(Err(error)) => {
                        log::debug!("[firefox] UDP H2 reader ended: {error}");
                        break;
                    }
                    None => break,
                }
            }
            reader_state.closed.store(true, Ordering::Release);
        });
        Self {
            outgoing: outgoing_tx,
            incoming: Mutex::new(incoming_rx),
            state,
            tasks: vec![writer.abort_handle(), reader.abort_handle()],
            inner,
            traffic,
        }
    }

    pub fn try_send(&self, packet: &[u8]) -> Result<()> {
        if packet.len() > MAX_UDP_PACKET {
            return Err(FirefoxError::UnsupportedDestination("UDP packet exceeds 65535 bytes".into()));
        }
        if self.state.closed.load(Ordering::Acquire) {
            return Err(FirefoxError::H2("UDP stream is closed".into()));
        }
        let capsule = encode_datagram(packet);
        let mut current = self.state.queued.load(Ordering::Acquire);
        loop {
            if current.saturating_add(capsule.len()) > UDP_QUEUE_BYTES {
                return Ok(());
            }
            match self.state.queued.compare_exchange_weak(current, current + capsule.len(), Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
        match self.outgoing.try_send(Bytes::from(capsule)) {
            Ok(()) => {
                self.traffic.tx.fetch_add(packet.len() as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(capsule)) => {
                self.state.queued.fetch_sub(capsule.len(), Ordering::AcqRel);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(capsule)) => {
                self.state.queued.fetch_sub(capsule.len(), Ordering::AcqRel);
                Err(FirefoxError::H2("UDP stream is closed".into()))
            }
        }
    }

    pub async fn recv(&self) -> Result<Vec<u8>> {
        if self.state.closed.load(Ordering::Acquire) && self.incoming.lock().await.is_empty() {
            return Err(FirefoxError::H2("UDP stream is closed".into()));
        }
        let packet = self.incoming.lock().await.recv().await.ok_or_else(|| FirefoxError::H2("UDP stream ended".into()))?;
        self.traffic.rx.fetch_add(packet.len() as u64, Ordering::Relaxed);
        Ok(packet)
    }
}

impl Drop for UdpTunnel {
    fn drop(&mut self) {
        self.state.closed.store(true, Ordering::Release);
        for task in &self.tasks {
            task.abort();
        }
        self.inner.active_streams.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn send_h2_bytes(send: &mut SendStream<Bytes>, mut bytes: Bytes) -> Result<()> {
    while !bytes.is_empty() {
        send.reserve_capacity(bytes.len().min(MAX_FRAME as usize));
        while send.capacity() == 0 {
            match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(h2_error(error)),
                None => return Err(FirefoxError::H2("stream closed while waiting for capacity".into())),
            }
        }
        let count = bytes.len().min(send.capacity()).min(MAX_FRAME as usize);
        send.send_data(bytes.split_to(count), false).map_err(h2_error)?;
    }
    Ok(())
}

const STREAM_FAILURE_WINDOW: Duration = Duration::from_secs(30);
const STREAM_LOG_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Default)]
struct StreamHealth {
    ambiguous_since: Option<Instant>,
    ambiguous_targets: Vec<u64>,
    last_destination_log: Option<Instant>,
    last_server_log: Option<Instant>,
    last_other_log: Option<Instant>,
}

impl StreamHealth {
    fn clear_ambiguous(&mut self) {
        self.ambiguous_since = None;
        self.ambiguous_targets.clear();
    }

    fn observe_ambiguous(&mut self, protocol: &str, target: &str, now: Instant) -> bool {
        if self.ambiguous_since.is_none_or(|start| now.saturating_duration_since(start) >= STREAM_FAILURE_WINDOW) {
            self.clear_ambiguous();
            self.ambiguous_since = Some(now);
        }
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        protocol.hash(&mut hasher);
        target.hash(&mut hasher);
        let key = hasher.finish();
        if self.ambiguous_targets.len() < 3 && !self.ambiguous_targets.contains(&key) {
            self.ambiguous_targets.push(key);
        }
        self.ambiguous_targets.len() >= 3
    }

    fn take_ambiguous_threshold(&mut self, now: Instant) -> bool {
        let reached = self.ambiguous_targets.len() >= 3
            && self.ambiguous_since.is_some_and(|start| now.saturating_duration_since(start) < STREAM_FAILURE_WINDOW);
        self.clear_ambiguous();
        reached
    }

    fn should_log(&mut self, destination: bool, server: bool, now: Instant) -> bool {
        let last = if destination { &mut self.last_destination_log }
            else if server { &mut self.last_server_log }
            else { &mut self.last_other_log };
        if last.is_none_or(|at| now.saturating_duration_since(at) >= STREAM_LOG_INTERVAL) {
            *last = Some(now);
            true
        } else {
            false
        }
    }
}

pub(crate) fn destination_error(error: &FirefoxError) -> Option<&'static str> {
    let FirefoxError::Http { status, message, .. } = error else { return None };
    if *status != 502 && *status != 503 && *status != 504 { return None; }
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    let mut parameter = false;
    for (index, ch) in message.char_indices().chain(std::iter::once((message.len(), ','))) {
        if escaped { escaped = false; continue; }
        if quoted && ch == '\\' { escaped = true; continue; }
        if ch == '"' { quoted = !quoted; continue; }
        if !quoted && (ch == ';' || ch == ',') {
            if parameter {
                if let Some((key, value)) = message[start..index].trim().split_once('=') {
                    if key.trim().eq_ignore_ascii_case("error") {
                        match value.trim() {
                            "destination_ip_prohibited" => return Some("destination_ip_prohibited"),
                            "destination_ip_unroutable" => return Some("destination_ip_unroutable"),
                            "destination_not_found" => return Some("destination_not_found"),
                            "destination_unavailable" => return Some("destination_unavailable"),
                            "connection_refused" => return Some("connection_refused"),
                            _ => {}
                        }
                    }
                }
            }
            parameter = ch == ';';
            start = index + ch.len_utf8();
        }
    }
    None
}

pub struct Upstream {
    candidate: RwLock<Candidate>,
    candidates: RwLock<Vec<Candidate>>,
    preference: TransportPreference,
    dialer: Dialer,
    tokens: TokenManager,
    timeout: Duration,
    pass: tokio::sync::RwLock<Arc<ProxyPass>>,
    renewal: Mutex<()>,
    failover: Mutex<()>,
    failures: AtomicU32,
    stream_health: SyncMutex<StreamHealth>,
    tcp_session: Mutex<Option<H2Session>>,
    udp_session: Mutex<Option<H2Session>>,
    traffic: Arc<Traffic>,
}

impl Upstream {
    pub async fn new(candidate: Candidate, preference: TransportPreference, dialer: Dialer, tokens: TokenManager, timeout: Duration) -> Result<Self> {
        if preference == TransportPreference::H3 {
            return Err(FirefoxError::H3Unavailable);
        }
        let pass = tokens.fetch_pass().await?;
        Ok(Self {
            candidate: RwLock::new(candidate.clone()),
            candidates: RwLock::new(vec![candidate]),
            preference,
            dialer,
            tokens,
            timeout,
            pass: tokio::sync::RwLock::new(Arc::new(pass)),
            renewal: Mutex::new(()),
            failover: Mutex::new(()),
            failures: AtomicU32::new(0),
            stream_health: SyncMutex::new(StreamHealth::default()),
            tcp_session: Mutex::new(None),
            udp_session: Mutex::new(None),
            traffic: Arc::new(Traffic::default()),
        })
    }

    pub fn set_candidates(&self, candidates: Vec<Candidate>) {
        if !candidates.is_empty() {
            *self.candidates.write() = candidates;
        }
    }

    pub fn traffic(&self) -> Arc<Traffic> {
        self.traffic.clone()
    }

    pub fn candidate(&self) -> Candidate {
        self.candidate.read().clone()
    }

    pub async fn expires_at(&self) -> SystemTime {
        self.pass.read().await.expires_at
    }

    pub async fn usage(&self) -> Option<Usage> {
        self.pass.read().await.usage.clone()
    }

    pub async fn renew(&self, force: bool) -> Result<SystemTime> {
        let _guard = self.renewal.lock().await;
        if !force && SystemTime::now() < self.pass.read().await.renew_after() {
            return Ok(self.pass.read().await.expires_at);
        }
        let pass = self.tokens.fetch_pass().await?;
        let token = Zeroizing::new(pass.token.clone());
        let expiry = pass.expires_at;
        if let Some(session) = self.tcp_session.lock().await.as_ref() {
            session.update_token(&token);
        }
        if let Some(session) = self.udp_session.lock().await.as_ref() {
            session.update_token(&token);
        }
        *self.pass.write().await = Arc::new(pass);
        Ok(expiry)
    }

    async fn current_token(&self) -> Result<Zeroizing<String>> {
        if SystemTime::now() >= self.pass.read().await.renew_after() {
            self.renew(false).await?;
        }
        Ok(Zeroizing::new(self.pass.read().await.token.clone()))
    }

    pub(crate) async fn probe_tcp(&self, target: &str) -> Result<()> {
        drop(self.open_tcp_inner(target).await?);
        Ok(())
    }

    pub(crate) async fn probe_udp(&self, target: &str) -> Result<()> {
        drop(self.open_udp_inner(target).await?);
        Ok(())
    }

    pub async fn open_tcp(&self, target: &str) -> Result<BoxedTunnel> {
        let result = self.open_tcp_inner(target).await;
        self.observe_result("TCP", target, result.as_ref().err()).await;
        result.map(|inner| Box::new(MeteredTunnel { inner, traffic: self.traffic.clone() }) as BoxedTunnel)
    }

    async fn open_tcp_inner(&self, target: &str) -> Result<BoxedTunnel> {
        if self.preference == TransportPreference::H1 {
            return self.open_h1_authorized(target).await.map(|stream| Box::new(stream) as BoxedTunnel);
        }
        let mut last_error = None;
        for attempt in 0..2 {
            let session = match self.get_tcp_session().await {
                Ok(Some(session)) => session,
                Ok(None) => {
                    return self.open_h1_authorized(target).await.map(|stream| Box::new(stream) as BoxedTunnel);
                }
                Err(error) if self.preference == TransportPreference::Auto && !matches!(error, FirefoxError::TlsCertificate { .. }) => {
                    log::debug!("[firefox] H2 session unavailable, using H1: {error}");
                    return self.open_h1_authorized(target).await.map(|stream| Box::new(stream) as BoxedTunnel);
                }
                Err(error) => return Err(error),
            };
            match tokio::time::timeout(self.timeout, session.open_tcp(target)).await {
                Ok(Ok(stream)) => return Ok(Box::new(stream)),
                Ok(Err(FirefoxError::PassRejected)) if attempt == 0 => {
                    self.renew(true).await?;
                }
                Ok(Err(error)) if attempt == 0 && retryable_session_error(&error) => {
                    session.kill();
                    *self.tcp_session.lock().await = None;
                    last_error = Some(error);
                }
                Ok(Err(error)) => return Err(error),
                Err(_) if attempt == 0 => {
                    session.kill();
                    *self.tcp_session.lock().await = None;
                    last_error = Some(FirefoxError::Timeout(self.timeout));
                }
                Err(_) => return Err(FirefoxError::Timeout(self.timeout)),
            }
        }
        let error = last_error.unwrap_or_else(|| FirefoxError::H2("could not open proxy stream".into()));
        if self.preference == TransportPreference::Auto {
            match self.open_h1_authorized(target).await {
                Ok(stream) => Ok(Box::new(stream) as BoxedTunnel),
                Err(h1_error) if !h1_error.is_transient() => Err(h1_error),
                Err(_) => Err(error),
            }
        } else {
            Err(error)
        }
    }

    async fn get_tcp_session(&self) -> Result<Option<H2Session>> {
        let token = self.current_token().await?;
        let mut slot = self.tcp_session.lock().await;
        if slot.as_ref().is_some_and(H2Session::alive) {
            return Ok(slot.clone());
        }
        *slot = None;
        let candidate = self.candidate();
        let session = tokio::time::timeout(self.timeout, H2Session::connect(&self.dialer, &candidate, token.to_string()))
            .await.map_err(|_| FirefoxError::Timeout(self.timeout))??;
        *slot = Some(session.clone());
        Ok(Some(session))
    }

    async fn open_h1_authorized(&self, target: &str) -> Result<BufReader<SslStream<TcpStream>>> {
        for attempt in 0..2 {
            let token = self.current_token().await?;
            match self.open_h1(target, &token).await {
                Err(FirefoxError::PassRejected) if attempt == 0 => {
                    self.renew(true).await?;
                }
                result => return result,
            }
        }
        Err(FirefoxError::PassRejected)
    }

    async fn open_h1(&self, target: &str, token: &str) -> Result<BufReader<SslStream<TcpStream>>> {
        tokio::time::timeout(self.timeout, self.open_h1_inner(target, token))
            .await
            .map_err(|_| FirefoxError::Timeout(self.timeout))?
    }

    async fn open_h1_inner(&self, target: &str, token: &str) -> Result<BufReader<SslStream<TcpStream>>> {
        split_authority(target, 443).ok_or_else(|| FirefoxError::UnsupportedDestination(target.into()))?;
        let candidate = self.candidate();
        let tls = tokio::time::timeout(self.timeout, crate::tls::connect(&self.dialer, &candidate.host, candidate.port, ALPN_H1))
            .await.map_err(|_| FirefoxError::Timeout(self.timeout))??;
        let mut stream = BufReader::new(tls);
        let request = format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Bearer {token}\r\nUser-Agent: {}\r\n\r\n",
            firefox_user_agent()
        );
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let mut head = Vec::with_capacity(1024);
        loop {
            let mut line = Vec::new();
            let remaining = (MAX_HEAD + 1).saturating_sub(head.len()) as u64;
            let read = (&mut stream).take(remaining).read_until(b'\n', &mut line).await?;
            if read == 0 {
                return Err(FirefoxError::Protocol("proxy closed before its CONNECT response".into()));
            }
            if head.len().saturating_add(line.len()) > MAX_HEAD {
                return Err(FirefoxError::Protocol("proxy CONNECT response head is too large".into()));
            }
            head.extend_from_slice(&line);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let (status, headers) = parse_response_head(&head)?;
        if !(200..300).contains(&status) {
            return Err(proxy_status_error(&candidate.host, status, &headers));
        }
        Ok(stream)
    }

    pub async fn open_udp(&self, target: &str) -> Result<UdpTunnel> {
        let result = self.open_udp_inner(target).await;
        self.observe_result("UDP", target, result.as_ref().err()).await;
        result
    }

    async fn open_udp_inner(&self, target: &str) -> Result<UdpTunnel> {
        if self.preference == TransportPreference::H1 {
            return Err(FirefoxError::InvalidConfig(
                "Firefox UDP requires HTTP/2 CONNECT-UDP; select auto or h2".into(),
            ));
        }
        let mut last_error = None;
        for attempt in 0..2 {
            let session = self.get_udp_session().await?;
            match tokio::time::timeout(self.timeout, session.open_udp(target, self.traffic.clone())).await {
                Ok(Ok(tunnel)) => return Ok(tunnel),
                Ok(Err(FirefoxError::PassRejected)) if attempt == 0 => {
                    self.renew(true).await?;
                }
                Ok(Err(error)) if attempt == 0 && retryable_session_error(&error) => {
                    session.kill();
                    *self.udp_session.lock().await = None;
                    last_error = Some(error);
                }
                Ok(Err(error)) => return Err(error),
                Err(_) if attempt == 0 => {
                    session.kill();
                    *self.udp_session.lock().await = None;
                    last_error = Some(FirefoxError::Timeout(self.timeout));
                }
                Err(_) => return Err(FirefoxError::Timeout(self.timeout)),
            }
        }
        Err(last_error.unwrap_or_else(|| FirefoxError::H2("could not open UDP proxy stream".into())))
    }

    async fn get_udp_session(&self) -> Result<H2Session> {
        let token = self.current_token().await?;
        let mut slot = self.udp_session.lock().await;
        if slot.as_ref().is_some_and(H2Session::alive) {
            return Ok(slot.clone().unwrap());
        }
        *slot = None;
        let candidate = self.candidate();
        let session = tokio::time::timeout(self.timeout, H2Session::connect(&self.dialer, &candidate, token.to_string()))
            .await.map_err(|_| FirefoxError::Timeout(self.timeout))??;
        *slot = Some(session.clone());
        Ok(session)
    }

    async fn observe_result(&self, protocol: &str, target: &str, error: Option<&FirefoxError>) {
        let Some(error) = error else {
            self.failures.store(0, Ordering::Release);
            self.stream_health.lock().clear_ambiguous();
            return;
        };
        let destination_reason = destination_error(error);
        let port = split_authority(target, 0).map(|(_, port)| port).unwrap_or(0);
        let now = Instant::now();
        let ambiguous = matches!(error, FirefoxError::Http { status, .. } if *status == 408 || *status >= 500)
            && destination_reason.is_none();
        let (should_log, rotate) = {
            let mut health = self.stream_health.lock();
            let important = matches!(error, FirefoxError::PassRejected | FirefoxError::ReauthRequired
                | FirefoxError::NotEntitled | FirefoxError::QuotaExhausted(_)
                | FirefoxError::RegionUnavailable | FirefoxError::TlsCertificate { .. });
            let should_log = important || health.should_log(destination_reason.is_some(), ambiguous, now);
            let rotate = ambiguous && health.observe_ambiguous(protocol, target, now);
            (should_log, rotate)
        };
        if should_log {
            if let Some(reason) = destination_reason {
                log::info!("[firefox] {protocol} destination on port {port} rejected by proxy ({reason}); other connections may still work");
            } else {
                match error {
                    FirefoxError::Http { status, .. } => log::warn!("[firefox] {protocol} proxy stream to port {port} failed: HTTP {status}; carrier health is assessed separately"),
                    _ => log::warn!("[firefox] {protocol} proxy stream to port {port} failed: {}", error.reason_code()),
                }
            }
        }
        if rotate {
            let _guard = self.failover.lock().await;
            let rotate = self.stream_health.lock().take_ambiguous_threshold(Instant::now());
            if rotate {
                self.rotate_proxy().await;
            }
        } else if !ambiguous && destination_reason.is_none() {
            self.note_error(error).await;
        }
    }

    pub async fn note_error(&self, error: &FirefoxError) {
        let transient = match error {
            FirefoxError::Timeout(_) | FirefoxError::Dns { .. } | FirefoxError::Tls { .. }
            | FirefoxError::H2(_) | FirefoxError::Network(_) => true,
            FirefoxError::Http { status, .. } => *status == 408 || *status >= 500,
            _ => false,
        };
        if !transient {
            return;
        }
        let failures = self.failures.fetch_add(1, Ordering::AcqRel) + 1;
        if failures < 3 {
            return;
        }
        let _guard = self.failover.lock().await;
        if self.failures.load(Ordering::Acquire) < 3 {
            return;
        }
        self.rotate_proxy().await;
    }

    async fn rotate_proxy(&self) {
        self.stream_health.lock().clear_ambiguous();
        let candidates = self.candidates.read().clone();
        if candidates.len() < 2 {
            self.failures.store(0, Ordering::Release);
            return;
        }
        let current = self.candidate.read().address.clone();
        let index = candidates.iter().position(|candidate| candidate.address == current).unwrap_or(0);
        let replacement = candidates[(index + 1) % candidates.len()].clone();
        *self.candidate.write() = replacement.clone();
        self.failures.store(0, Ordering::Release);
        if let Some(session) = self.tcp_session.lock().await.take() {
            session.kill();
        }
        if let Some(session) = self.udp_session.lock().await.take() {
            session.kill();
        }
        log::warn!("[firefox] rotating Mozilla proxy after carrier failures: {}", replacement.address);
    }

    pub async fn close(&self) {
        if let Some(session) = self.tcp_session.lock().await.take() {
            session.kill();
        }
        if let Some(session) = self.udp_session.lock().await.take() {
            session.kill();
        }
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        if let Some(session) = self.tcp_session.get_mut().take() {
            session.kill();
        }
        if let Some(session) = self.udp_session.get_mut().take() {
            session.kill();
        }
    }
}

fn retryable_session_error(error: &FirefoxError) -> bool {
    matches!(error, FirefoxError::H2(_) | FirefoxError::Network(_) | FirefoxError::Tls { .. })
}

async fn proxy_response_error(host: &str, status: u16, headers: &http::HeaderMap, mut body: RecvStream) -> FirefoxError {
    let mut message = headers.get("proxy-status").and_then(|value| value.to_str().ok()).unwrap_or("").to_string();
    if message.is_empty() {
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            match chunk {
                Ok(chunk) => {
                    let remaining = 2048usize.saturating_sub(bytes.len());
                    bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                    let _ = body.flow_control().release_capacity(chunk.len());
                    if bytes.len() >= 2048 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        message = String::from_utf8_lossy(&bytes).chars().filter(|c| !c.is_control()).take(512).collect();
    }
    let mut error = proxy_status_error(host, status, headers);
    if let FirefoxError::Http { message: detail, .. } = &mut error {
        *detail = message;
    }
    error
}

fn proxy_status_error(host: &str, status: u16, headers: &http::HeaderMap) -> FirefoxError {
    match status {
        401 | 407 => FirefoxError::PassRejected,
        403 => FirefoxError::NotEntitled,
        429 => FirefoxError::QuotaExhausted(String::new()),
        451 => FirefoxError::RegionUnavailable,
        _ => FirefoxError::Http {
            host: host.into(),
            status,
            errno: None,
            retry_after: None,
            message: headers.get("proxy-status").and_then(|value| value.to_str().ok()).unwrap_or("proxy CONNECT failed").into(),
        },
    }
}

fn parse_response_head(head: &[u8]) -> Result<(u16, http::HeaderMap)> {
    let mut fields = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut fields);
    match response.parse(head).map_err(|error| FirefoxError::Protocol(error.to_string()))? {
        httparse::Status::Complete(_) => {}
        httparse::Status::Partial => return Err(FirefoxError::Protocol("truncated proxy response".into())),
    }
    let status = response.code.ok_or_else(|| FirefoxError::Protocol("proxy response has no status".into()))?;
    let mut headers = http::HeaderMap::new();
    for field in response.headers.iter() {
        let name = http::HeaderName::from_bytes(field.name.as_bytes()).map_err(|_| FirefoxError::Protocol("invalid proxy header".into()))?;
        let value = HeaderValue::from_bytes(field.value).map_err(|_| FirefoxError::Protocol("invalid proxy header value".into()))?;
        headers.append(name, value);
    }
    Ok((status, headers))
}

fn encode_datagram(packet: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(packet.len() + 8);
    append_quic_varint(&mut output, 0);
    append_quic_varint(&mut output, (packet.len() + 1) as u64);
    output.push(0);
    output.extend_from_slice(packet);
    output
}

fn next_capsule(input: &[u8]) -> Option<(u64, &[u8], usize)> {
    let (kind, kind_len) = quic_varint(input)?;
    let (length, length_len) = quic_varint(&input[kind_len..])?;
    if length > MAX_UDP_CAPSULE as u64 {
        return Some((kind, &[], input.len()));
    }
    let start = kind_len + length_len;
    let end = start.checked_add(length as usize)?;
    if end > input.len() {
        return None;
    }
    Some((kind, &input[start..end], end))
}

fn quic_varint(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let length = 1usize << (first >> 6);
    if input.len() < length {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, length))
}

fn append_quic_varint(output: &mut Vec<u8>, value: u64) {
    if value < 1 << 6 {
        output.push(value as u8);
    } else if value < 1 << 14 {
        output.extend_from_slice(&[(value >> 8) as u8 | 0x40, value as u8]);
    } else if value < 1 << 30 {
        output.extend_from_slice(&[(value >> 24) as u8 | 0x80, (value >> 16) as u8, (value >> 8) as u8, value as u8]);
    } else {
        output.extend_from_slice(&[
            (value >> 56) as u8 | 0xc0, (value >> 48) as u8, (value >> 40) as u8, (value >> 32) as u8,
            (value >> 24) as u8, (value >> 16) as u8, (value >> 8) as u8, value as u8,
        ]);
    }
}

fn path_segment(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis().min(u64::MAX as u128) as u64
}

fn h2_error(error: h2::Error) -> FirefoxError {
    FirefoxError::H2(error.to_string())
}

#[cfg(test)]
mod traffic_tests {
    use super::*;

    fn http_error(status: u16, message: &str) -> FirefoxError {
        FirefoxError::Http { host: "proxy".into(), status, errno: None, retry_after: None, message: message.into() }
    }

    #[test]
    fn destination_error_is_classified_without_treating_opaque_502_as_policy() {
        let policy = http_error(502, "Fastly; error=destination_ip_prohibited");
        assert_eq!(destination_error(&policy), Some("destination_ip_prohibited"));
        let quoted = http_error(502, "Fastly; details=\"ignored; error=destination_ip_prohibited\"; error=connection_refused");
        assert_eq!(destination_error(&quoted), Some("connection_refused"));
        assert_eq!(destination_error(&http_error(502, "Bad Gateway")), None);
        assert_eq!(destination_error(&http_error(502, "Fastly; error=destination_ip_prohibited_extra")), None);
        assert_eq!(destination_error(&http_error(401, "Fastly; error=destination_ip_prohibited")), None);
        assert_eq!(destination_error(&FirefoxError::PassRejected), None);
        let mut headers = http::HeaderMap::new();
        headers.insert("proxy-status", HeaderValue::from_static("Fastly; error=destination_ip_prohibited"));
        assert_eq!(destination_error(&proxy_status_error("proxy", 502, &headers)), Some("destination_ip_prohibited"));
        assert!(matches!(proxy_status_error("proxy", 407, &headers), FirefoxError::PassRejected));
    }

    #[test]
    fn repeated_single_target_does_not_trigger_failover() {
        let now = Instant::now();
        let mut health = StreamHealth::default();
        for _ in 0..100 {
            assert!(!health.observe_ambiguous("UDP", "1.1.1.1:53", now));
        }
        assert!(!health.observe_ambiguous("TCP", "1.1.1.1:443", now));
        assert!(health.observe_ambiguous("TCP", "8.8.8.8:443", now));
        assert!(health.take_ambiguous_threshold(now));
        assert!(!health.take_ambiguous_threshold(now));
        assert!(!health.observe_ambiguous("TCP", "a:443", now));
        assert!(!health.observe_ambiguous("TCP", "b:443", now + STREAM_FAILURE_WINDOW));
        health.clear_ambiguous();
        assert!(!health.observe_ambiguous("TCP", "c:443", now + STREAM_FAILURE_WINDOW));
    }

    #[test]
    fn log_throttle_is_not_reset_by_success_and_keeps_categories_separate() {
        let now = Instant::now();
        let mut health = StreamHealth::default();
        assert!(health.should_log(true, false, now));
        health.clear_ambiguous();
        assert!(!health.should_log(true, false, now));
        assert!(health.should_log(false, true, now));
        assert!(health.should_log(false, false, now));
        assert!(health.should_log(true, false, now + STREAM_LOG_INTERVAL));
    }

    #[tokio::test]
    async fn metered_tunnel_counts_bytes_in_both_directions() {
        let (local, mut remote) = tokio::io::duplex(128);
        let traffic = Arc::new(Traffic::default());
        let mut tunnel = MeteredTunnel { inner: Box::new(local), traffic: traffic.clone() };
        tunnel.write_all(b"hello").await.unwrap();
        let mut received = [0; 5];
        remote.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"hello");
        remote.write_all(b"world!").await.unwrap();
        let mut received = [0; 6];
        tunnel.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"world!");
        assert_eq!(traffic.totals(), (6, 5));
    }
}
