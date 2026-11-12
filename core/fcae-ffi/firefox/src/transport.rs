use std::hash::{Hash, Hasher};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use http::{HeaderValue, Method};
use parking_lot::{Mutex as SyncMutex, RwLock};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::task::{AbortHandle, JoinHandle};
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
    rtt_ms: AtomicU32,
}

impl Traffic {
    pub fn totals(&self) -> (u64, u64) {
        (self.rx.load(Ordering::Relaxed), self.tx.load(Ordering::Relaxed))
    }

    pub fn rtt_ms(&self) -> u32 {
        self.rtt_ms.load(Ordering::Relaxed)
    }

    fn record_rtt(&self, elapsed: Duration) {
        self.rtt_ms.store(elapsed.as_millis().clamp(1, u32::MAX as u128) as u32, Ordering::Relaxed);
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

struct CarrierIo<S> {
    inner: S,
    reads: Arc<AtomicU64>,
    writes: Arc<AtomicU64>,
}

impl<S: AsyncRead + Unpin> AsyncRead for CarrierIo<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = output.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, output);
        if matches!(&result, Poll::Ready(Ok(()))) && output.filled().len() > before {
            self.reads.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CarrierIo<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        if matches!(&result, Poll::Ready(Ok(count)) if *count > 0) {
            self.writes.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct PendingConnect(Option<SendStream<Bytes>>);
impl Drop for PendingConnect {
    fn drop(&mut self) {
        if let Some(send) = &mut self.0 { send.send_reset(h2::Reason::CANCEL); }
    }
}

struct SessionInner {
    alive: AtomicBool,
    accepting: AtomicBool,
    token: RwLock<Zeroizing<String>>,
    carrier_reads: Arc<AtomicU64>,
    carrier_writes: Arc<AtomicU64>,
    app_writes: AtomicU64,
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
    async fn connect(dialer: &Dialer, candidate: &Candidate, token: String, traffic: Arc<Traffic>) -> Result<Self> {
        let tls = crate::tls::connect(dialer, &candidate.host, candidate.port, ALPN_H2).await?;
        crate::tls::require_h2(&tls)?;
        let mut builder = h2::client::Builder::new();
        builder
            .enable_push(false)
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW)
            .max_frame_size(MAX_FRAME)
            .max_header_list_size(64 * 1024);
        let carrier_reads = Arc::new(AtomicU64::new(0));
        let carrier_writes = Arc::new(AtomicU64::new(0));
        let io = CarrierIo { inner: tls, reads: carrier_reads.clone(), writes: carrier_writes.clone() };
        let (sender, mut connection) = builder.handshake(io).await.map_err(h2_error)?;
        let mut ping_pong = connection.ping_pong().ok_or_else(|| FirefoxError::H2("connection has no PING support".into()))?;
        let inner = Arc::new(SessionInner {
            alive: AtomicBool::new(true),
            accepting: AtomicBool::new(true),
            token: RwLock::new(Zeroizing::new(token)),
            carrier_reads,
            carrier_writes,
            app_writes: AtomicU64::new(0),
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
            let period = Duration::from_secs(5);
            let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut misses = 0;
            let mut upload_grace_used = false;
            let mut pending = false;
            let mut started = Instant::now();
            loop {
                interval.tick().await;
                let Some(inner) = weak.upgrade() else { break };
                if !inner.alive.load(Ordering::Acquire) {
                    break;
                }
                let checked = inner.carrier_reads.load(Ordering::Relaxed);
                let writes = inner.carrier_writes.load(Ordering::Relaxed);
                let app_writes = inner.app_writes.load(Ordering::Relaxed);
                if !pending {
                    started = Instant::now();
                    if let Err(error) = ping_pong.send_ping(h2::Ping::opaque()) {
                        log::debug!("[firefox] H2 PING send failed: {error}");
                        if error.is_go_away() { inner.accepting.store(false, Ordering::Release); }
                        else { inner.kill(); }
                        break;
                    }
                    pending = true;
                }
                let pong = std::future::poll_fn(|cx| ping_pong.poll_pong(cx));
                match tokio::time::timeout(period, pong).await {
                    Ok(Ok(_)) => {
                        traffic.record_rtt(started.elapsed());
                        pending = false;
                        misses = 0;
                        upload_grace_used = false;
                    },
                    Ok(Err(error)) => {
                        log::debug!("[firefox] H2 PING failed: {error}");
                        if error.is_go_away() { inner.accepting.store(false, Ordering::Release); }
                        else { inner.kill(); }
                        break;
                    }
                    // h2 permits only one outstanding user PING; keep polling it after a timeout.
                    Err(_) if inner.carrier_reads.load(Ordering::Relaxed) != checked => {
                        misses = 0;
                        upload_grace_used = false;
                    }
                    Err(_) => misses += 1,
                }
                if misses >= 2 {
                    let uploading = inner.app_writes.load(Ordering::Relaxed) != app_writes
                        && inner.carrier_writes.load(Ordering::Relaxed) != writes;
                    if uploading && !upload_grace_used {
                        upload_grace_used = true;
                    } else {
                        log::debug!("[firefox] H2 keepalive timed out");
                        inner.kill();
                        break;
                    }
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
        self.inner.alive.load(Ordering::Acquire) && self.inner.accepting.load(Ordering::Acquire)
    }

    fn stream_error(&self, error: h2::Error) -> FirefoxError {
        if error.is_go_away() || error.is_io() {
            self.inner.accepting.store(false, Ordering::Release);
        }
        h2_error(error)
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
        sender = sender.ready().await.map_err(|error| self.stream_error(error))?;
        let request = connect_request(target, &token, None)?;
        let (response, send) = sender.send_request(request, false).map_err(|error| self.stream_error(error))?;
        let mut pending = PendingConnect(Some(send));
        let response = response.await.map_err(|error| self.stream_error(error))?;
        let (parts, recv) = response.into_parts();
        if !parts.status.is_success() {
            let host = self.authority_host();
            let status = parts.status.as_u16();
            let (error, message) = proxy_response_error(&host, status, &parts.headers, recv).await;
            log_proxy_failure("h2", "TCP", target, &host, status, &error, &message);
            return Err(error);
        }
        self.inner.active_streams.fetch_add(1, Ordering::Relaxed);
        Ok(H2Tunnel {
            send: pending.0.take().expect("pending CONNECT stream"),
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
        sender = sender.ready().await.map_err(|error| self.stream_error(error))?;
        let request = connect_request(&uri, &token, Some(h2::ext::Protocol::from_static("connect-udp")))?;
        let (response, send) = sender.send_request(request, false).map_err(|error| self.stream_error(error))?;
        let mut pending = PendingConnect(Some(send));
        let response = response.await.map_err(|error| self.stream_error(error))?;
        let (parts, recv) = response.into_parts();
        if !parts.status.is_success() {
            let host = self.authority_host();
            let status = parts.status.as_u16();
            let (error, message) = proxy_response_error(&host, status, &parts.headers, recv).await;
            log_proxy_failure("h2", "UDP", target, &host, status, &error, &message);
            return Err(error);
        }
        self.inner.active_streams.fetch_add(1, Ordering::Relaxed);
        Ok(UdpTunnel::new(pending.0.take().expect("pending CONNECT stream"), recv, self.inner.clone(), traffic))
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
                self.inner.app_writes.fetch_add(1, Ordering::Relaxed);
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
    inner: Option<Arc<SessionInner>>,
    traffic: Arc<Traffic>,
}

impl UdpTunnel {
    fn new(mut send: SendStream<Bytes>, mut recv: RecvStream, inner: Arc<SessionInner>, traffic: Arc<Traffic>) -> Self {
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<Bytes>(256);
        let (incoming_tx, incoming_rx) = mpsc::channel::<Vec<u8>>(256);
        let state = Arc::new(UdpState { queued: AtomicUsize::new(0), closed: AtomicBool::new(false) });
        let (closed_tx, mut writer_closed) = tokio::sync::watch::channel(false);
        let mut reader_closed = closed_tx.subscribe();
        let writer_signal = closed_tx.clone();
        let writer_state = state.clone();
        let writer_inner = inner.clone();
        let writer = tokio::spawn(async move {
            loop {
                let capsule = tokio::select! {
                    changed = writer_closed.changed() => { let _ = changed; break; }
                    capsule = outgoing_rx.recv() => match capsule { Some(capsule) => capsule, None => break },
                };
                let length = capsule.len();
                let result = tokio::select! {
                    changed = writer_closed.changed() => { let _ = changed; break; }
                    result = send_h2_bytes(&mut send, capsule) => result,
                };
                writer_state.queued.fetch_sub(length, Ordering::AcqRel);
                if let Err(error) = result {
                    log::debug!("[firefox] UDP H2 writer ended: {error}");
                    break;
                }
                writer_inner.app_writes.fetch_add(1, Ordering::Relaxed);
            }
            writer_state.closed.store(true, Ordering::Release);
            let _ = writer_signal.send(true);
            send.send_reset(h2::Reason::CANCEL);
        });
        let reader_state = state.clone();
        let reader = tokio::spawn(async move {
            let mut capsules = Vec::<u8>::new();
            loop {
                let result = tokio::select! {
                    changed = reader_closed.changed() => { let _ = changed; break; }
                    result = recv.data() => result,
                };
                match result {
                    Some(Ok(chunk)) => {
                        let _ = recv.flow_control().release_capacity(chunk.len());
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
            let _ = closed_tx.send(true);
        });
        Self {
            outgoing: outgoing_tx,
            incoming: Mutex::new(incoming_rx),
            state,
            tasks: vec![writer.abort_handle(), reader.abort_handle()],
            inner: Some(inner),
            traffic,
        }
    }

    fn new_h1<S>(stream: S, traffic: Arc<Traffic>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut read, mut write) = tokio::io::split(stream);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<Bytes>(256);
        let (incoming_tx, incoming_rx) = mpsc::channel::<Vec<u8>>(256);
        let (closed_tx, mut writer_closed) = tokio::sync::watch::channel(false);
        let mut reader_closed = closed_tx.subscribe();
        let writer_signal = closed_tx.clone();
        let state = Arc::new(UdpState { queued: AtomicUsize::new(0), closed: AtomicBool::new(false) });
        let writer_state = state.clone();
        let writer = tokio::spawn(async move {
            loop {
                let capsule = tokio::select! {
                    changed = writer_closed.changed() => { let _ = changed; break; }
                    capsule = outgoing_rx.recv() => match capsule { Some(capsule) => capsule, None => break },
                };
                let length = capsule.len();
                let result = tokio::select! {
                    changed = writer_closed.changed() => { let _ = changed; break; }
                    result = async {
                        write.write_all(&capsule).await?;
                        write.flush().await
                    } => result,
                };
                writer_state.queued.fetch_sub(length, Ordering::AcqRel);
                if let Err(error) = result {
                    log::debug!("[firefox] UDP H1 writer ended: {error}");
                    break;
                }
            }
            writer_state.closed.store(true, Ordering::Release);
            let _ = writer_signal.send(true);
        });
        let reader_state = state.clone();
        let reader = tokio::spawn(async move {
            loop {
                let result = tokio::select! {
                    changed = reader_closed.changed() => { let _ = changed; break; }
                    result = read_h1_capsule(&mut read) => result,
                };
                match result {
                    Ok(Some(packet)) => { let _ = incoming_tx.try_send(packet); }
                    Ok(None) => {}
                    Err(error) => {
                        log::debug!("[firefox] UDP H1 reader ended: {error}");
                        break;
                    }
                }
            }
            reader_state.closed.store(true, Ordering::Release);
            let _ = closed_tx.send(true);
        });
        Self {
            outgoing: outgoing_tx,
            incoming: Mutex::new(incoming_rx),
            state,
            tasks: vec![writer.abort_handle(), reader.abort_handle()],
            inner: None,
            traffic,
        }
    }

    fn closed_error(&self, message: &str) -> FirefoxError {
        if self.inner.is_some() { FirefoxError::H2(message.into()) }
        else { FirefoxError::Network(message.into()) }
    }

    pub fn try_send(&self, packet: &[u8]) -> Result<()> {
        self.try_send_with_capacity(packet).map(|_| ())
    }

    pub(crate) fn try_send_with_capacity(&self, packet: &[u8]) -> Result<bool> {
        if packet.len() > MAX_UDP_PACKET {
            return Err(FirefoxError::UnsupportedDestination("UDP packet exceeds 65535 bytes".into()));
        }
        if self.state.closed.load(Ordering::Acquire) {
            return Err(self.closed_error("UDP stream is closed"));
        }
        let capsule = encode_datagram(packet);
        let mut current = self.state.queued.load(Ordering::Acquire);
        loop {
            if current.saturating_add(capsule.len()) > UDP_QUEUE_BYTES {
                return Ok(false);
            }
            match self.state.queued.compare_exchange_weak(current, current + capsule.len(), Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
        match self.outgoing.try_send(Bytes::from(capsule)) {
            Ok(()) => {
                self.traffic.tx.fetch_add(packet.len() as u64, Ordering::Relaxed);
                Ok(true)
            }
            Err(mpsc::error::TrySendError::Full(capsule)) => {
                self.state.queued.fetch_sub(capsule.len(), Ordering::AcqRel);
                Ok(false)
            }
            Err(mpsc::error::TrySendError::Closed(capsule)) => {
                self.state.queued.fetch_sub(capsule.len(), Ordering::AcqRel);
                Err(self.closed_error("UDP stream is closed"))
            }
        }
    }

    pub async fn recv(&self) -> Result<Vec<u8>> {
        if self.state.closed.load(Ordering::Acquire) && self.incoming.lock().await.is_empty() {
            return Err(self.closed_error("UDP stream is closed"));
        }
        let packet = self.incoming.lock().await.recv().await.ok_or_else(|| self.closed_error("UDP stream ended"))?;
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
        if let Some(inner) = &self.inner {
            inner.active_streams.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

async fn read_h1_varint<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<u64> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes[..1]).await?;
    let length = 1usize << (bytes[0] >> 6);
    reader.read_exact(&mut bytes[1..length]).await?;
    Ok(quic_varint(&bytes[..length]).unwrap().0)
}

async fn read_h1_capsule<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let kind = read_h1_varint(reader).await?;
    let length = read_h1_varint(reader).await?;
    if length > MAX_UDP_CAPSULE as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "UDP capsule exceeds limit"));
    }
    let mut payload = vec![0; length as usize];
    reader.read_exact(&mut payload).await?;
    if kind != 0 { return Ok(None); }
    let (context, offset) = quic_varint(&payload)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing UDP context"))?;
    if context != 0 || payload.len() - offset > MAX_UDP_PACKET { return Ok(None); }
    Ok(Some(payload[offset..].to_vec()))
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

#[derive(Default)]
struct StreamHealth {
    ambiguous_since: Option<Instant>,
    ambiguous_targets: Vec<u64>,
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
}

fn destination_kind(target: &str) -> &'static str {
    use std::net::IpAddr;
    let Some((host, _)) = split_authority(target, 0) else { return "unknown destination" };
    let Ok(ip) = host.parse::<IpAddr>() else { return "hostname" };
    let is_benchmark = |ip: std::net::Ipv4Addr| {
        let octets = ip.octets();
        octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
    };
    if match ip {
        IpAddr::V4(ip) => is_benchmark(ip),
        IpAddr::V6(ip) => ip.to_ipv4_mapped().is_some_and(is_benchmark),
    } {
        return "benchmark-range IP";
    }
    let local_v4 = |ip: std::net::Ipv4Addr| {
        ip.is_private() || ip.is_loopback() || ip.is_link_local()
            || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast()
    };
    let local = match ip {
        IpAddr::V4(ip) => local_v4(ip),
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map(local_v4).unwrap_or_else(|| {
            ip.is_loopback() || ip.is_unspecified() || ip.is_multicast()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }),
    };
    if local { "local or non-unicast IP" } else { "IP address" }
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

const H1_SPARE_MAX_AGE: Duration = Duration::from_secs(20);

type H1Tls = SslStream<TcpStream>;

#[derive(Default)]
struct H1SpareState {
    slot: Option<(Instant, H1Tls)>,
    filling: Option<JoinHandle<()>>,
    generation: u64,
    closed: bool,
}

#[derive(Default)]
struct H1SparePool {
    state: SyncMutex<H1SpareState>,
}

impl H1SparePool {
    fn take_and_refill(self: &Arc<Self>, dialer: &Dialer, candidate: &Candidate, timeout: Duration) -> Option<H1Tls> {
        let mut state = self.state.lock();
        if state.closed {
            return None;
        }
        let spare = state.slot.take().and_then(|(created, stream)| {
            (created.elapsed() < H1_SPARE_MAX_AGE).then_some(stream)
        });
        if state.filling.is_none() {
            let pool = self.clone();
            let dialer = dialer.clone();
            let candidate = candidate.clone();
            let generation = state.generation;
            let task = tokio::spawn(async move {
                let result = tokio::time::timeout(timeout, crate::tls::connect(&dialer, &candidate.host, candidate.port, ALPN_H1)).await;
                let mut state = pool.state.lock();
                if !state.closed && state.generation == generation {
                    if let Ok(Ok(stream)) = result {
                        state.slot = Some((Instant::now(), stream));
                    }
                    state.filling = None;
                }
            });
            state.filling = Some(task);
        }
        spare
    }

    fn invalidate(&self, close: bool) -> Option<JoinHandle<()>> {
        let mut state = self.state.lock();
        state.generation = state.generation.wrapping_add(1);
        state.slot = None;
        state.closed |= close;
        let task = state.filling.take();
        if let Some(task) = &task {
            task.abort();
        }
        task
    }
}

fn retry_stale_h1_spare(response_started: bool, error: &FirefoxError) -> bool {
    !response_started && matches!(error, FirefoxError::Network(_) | FirefoxError::Protocol(_))
}

pub struct Upstream {
    candidate: RwLock<Candidate>,
    candidates: RwLock<Vec<Candidate>>,
    preference: TransportPreference,
    h1_reported: AtomicBool,
    h1_spare: Arc<H1SparePool>,
    h1_udp_reported: AtomicBool,
    h2_reported: AtomicBool,
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
    pub(crate) doh_pool: crate::doh::DohPool,
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
            h1_reported: AtomicBool::new(false),
            h1_spare: Arc::new(H1SparePool::default()),
            h1_udp_reported: AtomicBool::new(false),
            h2_reported: AtomicBool::new(false),
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
            doh_pool: crate::doh::DohPool::default(),
            traffic: Arc::new(Traffic::default()),
        })
    }

    pub fn set_candidates(&self, candidates: Vec<Candidate>) {
        if !candidates.is_empty() {
            *self.candidates.write() = candidates;
        }
    }

    fn report_tunnel_protocol(&self, h2: bool) {
        let reported = if h2 { &self.h2_reported } else { &self.h1_reported };
        if !reported.swap(true, Ordering::Relaxed) {
            log::info!("[firefox] ({}) proxy tunnel connected", if h2 { "h2" } else { "h1" });
        }
    }

    pub(crate) fn transport_preference(&self) -> TransportPreference {
        self.preference
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
            // Token renewal failures are not transport negotiation failures.
            let token = self.current_token().await?;
            let session = match self.get_tcp_session(&token).await {
                Ok(session) => session,
                Err(error) => {
                    if self.preference == TransportPreference::Auto && h1_fallback_allowed(&error) {
                        return self.fallback_h1(target, error).await;
                    }
                    return Err(error);
                }
            };
            match tokio::time::timeout(self.timeout, session.open_tcp(target)).await {
                Ok(Ok(stream)) => {
                    self.report_tunnel_protocol(true);
                    return Ok(Box::new(stream));
                }
                Ok(Err(FirefoxError::PassRejected)) if attempt == 0 => {
                    self.renew(true).await?;
                }
                Ok(Err(error)) if retryable_session_error(&error) && !session.alive() => {
                    self.discard_tcp_session(&session).await;
                    last_error = Some(error);
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(FirefoxError::Timeout(self.timeout)),
            }
        }
        let error = last_error.unwrap_or_else(|| FirefoxError::H2("could not open proxy stream".into()));
        if self.preference == TransportPreference::Auto && h1_fallback_allowed(&error) {
            self.fallback_h1(target, error).await
        } else {
            Err(error)
        }
    }

    async fn discard_tcp_session(&self, failed: &H2Session) {
        let mut slot = self.tcp_session.lock().await;
        if slot.as_ref().is_some_and(|current| Arc::ptr_eq(&current.inner, &failed.inner)) {
            *slot = None;
        }
    }

    async fn fallback_h1(&self, target: &str, h2_error: FirefoxError) -> Result<BoxedTunnel> {
        log::warn!("[firefox] (h2) proxy unavailable reason={}; trying (h1)", crate::control::direct_failure_detail(&h2_error));
        match self.open_h1_authorized(target).await {
            Ok(stream) => Ok(Box::new(stream)),
            Err(error) if !error.is_transient() => Err(error),
            Err(_) => Err(h2_error),
        }
    }

    async fn get_tcp_session(&self, token: &str) -> Result<H2Session> {
        let mut slot = self.tcp_session.lock().await;
        if slot.as_ref().is_some_and(H2Session::alive) {
            return Ok(slot.as_ref().unwrap().clone());
        }
        *slot = None;
        let candidate = self.candidate();
        let result = tokio::time::timeout(self.timeout, H2Session::connect(&self.dialer, &candidate, token.to_string(), self.traffic.clone()))
            .await.unwrap_or_else(|_| Err(FirefoxError::Timeout(self.timeout)));
        let session = result.map_err(|error| {
            log::warn!("[firefox] (h2) proxy connection failed reason={}", crate::control::direct_failure_detail(&error));
            error
        })?;
        *slot = Some(session.clone());
        Ok(session)
    }

    async fn open_h1_authorized(&self, target: &str) -> Result<BufReader<SslStream<TcpStream>>> {
        for attempt in 0..2 {
            let token = self.current_token().await?;
            let started = Instant::now();
            match self.open_h1(target, &token).await {
                Err(FirefoxError::PassRejected) if attempt == 0 => {
                    self.renew(true).await?;
                }
                Ok(stream) => {
                    self.traffic.record_rtt(started.elapsed());
                    self.report_tunnel_protocol(false);
                    return Ok(stream);
                }
                Err(error) => return Err(error),
            }
        }
        Err(FirefoxError::PassRejected)
    }

    async fn open_h1(&self, target: &str, token: &str) -> Result<BufReader<SslStream<TcpStream>>> {
        let result = tokio::time::timeout(self.timeout, self.open_h1_inner(target, token))
            .await.unwrap_or_else(|_| Err(FirefoxError::Timeout(self.timeout)));
        if let Err(error) = &result {
            log::warn!("[firefox] (h1) proxy connection failed reason={}", crate::control::direct_failure_detail(error));
        }
        result
    }

    async fn open_h1_inner(&self, target: &str, token: &str) -> Result<BufReader<H1Tls>> {
        split_authority(target, 443).ok_or_else(|| FirefoxError::UnsupportedDestination(target.into()))?;
        let (candidate, spare) = {
            let candidate = self.candidate.read();
            let spare = self.h1_spare.take_and_refill(&self.dialer, &candidate, self.timeout);
            (candidate.clone(), spare)
        };
        if let Some(spare) = spare {
            let mut response_started = false;
            match self.h1_connect(spare, &candidate, target, token, &mut response_started).await {
                Ok(stream) => return Ok(stream),
                Err(error) if retry_stale_h1_spare(response_started, &error) => {
                    log::debug!("[firefox] (h1) spare connection closed before response; opening a fresh connection");
                }
                Err(error) => return Err(error),
            }
        }
        let tls = crate::tls::connect(&self.dialer, &candidate.host, candidate.port, ALPN_H1).await?;
        let mut response_started = false;
        self.h1_connect(tls, &candidate, target, token, &mut response_started).await
    }

    async fn h1_connect(&self, tls: H1Tls, candidate: &Candidate, target: &str, token: &str, response_started: &mut bool) -> Result<BufReader<H1Tls>> {
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
            let read = match (&mut stream).take(remaining).read_until(b'\n', &mut line).await {
                Ok(read) => read,
                Err(error) => {
                    *response_started |= !line.is_empty();
                    return Err(error.into());
                }
            };
            if read == 0 {
                return Err(FirefoxError::Protocol("proxy closed before its CONNECT response".into()));
            }
            *response_started = true;
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
            let error = proxy_status_error(&candidate.host, status, &headers);
            let message = buffered_proxy_error_message(&headers, stream.buffer());
            log_proxy_failure("h1", "TCP", target, &candidate.host, status, &error, &message);
            return Err(error);
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
            return self.open_h1_udp_authorized(target).await;
        }
        let mut last_error = None;
        for attempt in 0..2 {
            let session = self.get_udp_session().await?;
            match tokio::time::timeout(self.timeout, session.open_udp(target, self.traffic.clone())).await {
                Ok(Ok(tunnel)) => {
                    self.report_tunnel_protocol(true);
                    return Ok(tunnel);
                }
                Ok(Err(FirefoxError::PassRejected)) if attempt == 0 => {
                    self.renew(true).await?;
                }
                Ok(Err(error)) if attempt == 0 && retryable_session_error(&error) && !session.alive() => {
                    self.discard_udp_session(&session).await;
                    last_error = Some(error);
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(FirefoxError::Timeout(self.timeout)),
            }
        }
        Err(last_error.unwrap_or_else(|| FirefoxError::H2("could not open UDP proxy stream".into())))
    }

    async fn discard_udp_session(&self, failed: &H2Session) {
        let mut slot = self.udp_session.lock().await;
        if slot.as_ref().is_some_and(|current| Arc::ptr_eq(&current.inner, &failed.inner)) {
            *slot = None;
        }
    }

    async fn open_h1_udp_authorized(&self, target: &str) -> Result<UdpTunnel> {
        for attempt in 0..2 {
            let token = self.current_token().await?;
            let started = Instant::now();
            let result = tokio::time::timeout(self.timeout, self.open_h1_udp(target, &token))
                .await.unwrap_or_else(|_| Err(FirefoxError::Timeout(self.timeout)));
            match result {
                Err(FirefoxError::PassRejected) if attempt == 0 => { self.renew(true).await?; }
                Ok(stream) => {
                    self.traffic.record_rtt(started.elapsed());
                    self.report_tunnel_protocol(false);
                    if !self.h1_udp_reported.swap(true, Ordering::Relaxed) {
                        log::info!("[firefox] (h1) UDP CONNECT-UDP upgrade established");
                    }
                    return Ok(UdpTunnel::new_h1(stream, self.traffic.clone()));
                }
                Err(error) => return Err(error),
            }
        }
        Err(FirefoxError::PassRejected)
    }

    async fn open_h1_udp(&self, target: &str, token: &str) -> Result<BufReader<SslStream<TcpStream>>> {
        let candidate = self.candidate();
        let tls = crate::tls::connect(&self.dialer, &candidate.host, candidate.port, ALPN_H1).await?;
        if tls.ssl().selected_alpn_protocol().is_some_and(|protocol| protocol != b"http/1.1") {
            return Err(FirefoxError::Protocol("Mozilla proxy did not negotiate HTTP/1.1".into()));
        }
        h1_udp_upgrade(tls, &candidate.authority(), &candidate.host, target, token).await
    }

    async fn get_udp_session(&self) -> Result<H2Session> {
        let token = self.current_token().await?;
        let mut slot = self.udp_session.lock().await;
        if slot.as_ref().is_some_and(H2Session::alive) {
            return Ok(slot.clone().unwrap());
        }
        *slot = None;
        let candidate = self.candidate();
        let result = tokio::time::timeout(self.timeout, H2Session::connect(&self.dialer, &candidate, token.to_string(), self.traffic.clone()))
            .await.unwrap_or_else(|_| Err(FirefoxError::Timeout(self.timeout)));
        let session = result.map_err(|error| {
            log::warn!("[firefox] (h2) proxy connection failed reason={}", crate::control::direct_failure_detail(&error));
            error
        })?;
        *slot = Some(session.clone());
        Ok(session)
    }

    async fn observe_result(&self, protocol: &str, target: &str, error: Option<&FirefoxError>) {
        if protocol == "UDP" {
            if let Some(error) = error {
                if !matches!(error, FirefoxError::Http { .. }) {
                    let port = split_authority(target, 0).map(|(_, port)| port).unwrap_or(0);
                    log::warn!("[firefox] UDP proxy stream to port {port} failed: {}", crate::control::direct_failure_detail(error));
                }
            }
            return;
        }
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
        let rotate = {
            let mut health = self.stream_health.lock();
            ambiguous && health.observe_ambiguous(protocol, target, now)
        };
        if !matches!(error, FirefoxError::Http { .. }) {
            log::warn!("[firefox] {protocol} proxy stream to port {port} failed: {}", crate::control::direct_failure_detail(error));
        }
        if rotate {
            let _guard = self.failover.lock().await;
            let rotate = self.stream_health.lock().take_ambiguous_threshold(Instant::now());
            if rotate {
                self.rotate_proxy().await;
            }
        } else if !ambiguous && destination_reason.is_none() {
            // A stream timeout or reset alone does not establish that its shared carrier failed.
            let live_h2 = matches!(error, FirefoxError::Timeout(_) | FirefoxError::H2(_) | FirefoxError::Network(_))
                && self.tcp_session.lock().await.as_ref().is_some_and(H2Session::alive);
            if !live_h2 { self.note_error(error).await; }
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
        let spare_task = {
            let mut candidate = self.candidate.write();
            *candidate = replacement.clone();
            self.h1_spare.invalidate(false)
        };
        if let Some(task) = spare_task {
            let _ = task.await;
        }
        self.doh_pool.clear();
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
        if let Some(task) = self.h1_spare.invalidate(true) {
            let _ = task.await;
        }
        self.doh_pool.clear();
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
        self.h1_spare.invalidate(true);
        if let Some(session) = self.tcp_session.get_mut().take() {
            session.kill();
        }
        if let Some(session) = self.udp_session.get_mut().take() {
            session.kill();
        }
    }
}

fn h1_fallback_allowed(error: &FirefoxError) -> bool {
    matches!(error, FirefoxError::H2(_) | FirefoxError::Network(_) | FirefoxError::Tls { .. }
        | FirefoxError::Dns { .. } | FirefoxError::Timeout(_) | FirefoxError::Protocol(_))
}

fn retryable_session_error(error: &FirefoxError) -> bool {
    matches!(error, FirefoxError::H2(_) | FirefoxError::Network(_) | FirefoxError::Tls { .. })
}

async fn proxy_response_error(host: &str, status: u16, headers: &http::HeaderMap, mut body: RecvStream) -> (FirefoxError, String) {
    let mut response_message = String::new();
    let mut message = headers.get("proxy-status").and_then(|value| value.to_str().ok()).unwrap_or("").to_string();
    if message.is_empty() {
        let mut bytes = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
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
        }).await;
        response_message = crate::control::diagnostic_error_message(&bytes);
        message = String::from_utf8_lossy(&bytes).chars().filter(|c| !c.is_control()).take(512).collect();
    }
    let mut error = proxy_status_error(host, status, headers);
    if let FirefoxError::Http { message: detail, .. } = &mut error {
        *detail = message;
    }
    (error, response_message)
}

fn buffered_proxy_error_message(headers: &http::HeaderMap, buffered: &[u8]) -> String {
    if headers.contains_key(http::header::TRANSFER_ENCODING) || headers.contains_key(http::header::CONTENT_ENCODING) {
        return String::new();
    }
    let length = headers.get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    match length {
        Some(length) if length <= 2048 && length <= buffered.len() =>
            crate::control::diagnostic_error_message(&buffered[..length]),
        _ => String::new(),
    }
}

fn proxy_failure_description(http: &str, protocol: &str, target: &str, host: &str, status: u16, error: &FirefoxError) -> String {
    let port = split_authority(target, 0).map(|(_, port)| port).unwrap_or(0);
    let kind = destination_kind(target);
    let reason = destination_error(error).unwrap_or("unspecified");
    format!("[firefox] ({http}) {protocol} proxy CONNECT failed: HTTP {status} proxy={host} destination={kind} port={port} reason={reason}")
}

fn log_proxy_failure(http: &str, protocol: &str, target: &str, host: &str, status: u16, error: &FirefoxError, message: &str) {
    let description = proxy_failure_description(http, protocol, target, host, status, error);
    if message.is_empty() {
        log::warn!("{description} category={}", error.reason_code());
    } else {
        log::warn!("{description} category={} message={message}", error.reason_code());
    }
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

async fn h1_udp_upgrade<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S, authority: &str, proxy_host: &str, target: &str, token: &str,
) -> Result<BufReader<S>> {
    let (host, port) = split_authority(target, 53)
        .ok_or_else(|| FirefoxError::UnsupportedDestination(target.into()))?;
    let authority = authority.parse::<http::uri::Authority>()
        .map_err(|_| FirefoxError::Protocol("invalid proxy authority".into()))?;
    let authorization = Zeroizing::new(format!("Bearer {token}"));
    HeaderValue::from_str(&authorization)
        .map_err(|_| FirefoxError::Protocol("proxy pass cannot be encoded as a header".into()))?;
    let path = format!("/.well-known/masque/udp/{}/{port}/", path_segment(&host));
    let request = Zeroizing::new(format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\nProxy-Authorization: {}\r\nUser-Agent: {}\r\n\r\n", authorization.as_str(), firefox_user_agent()));
    let mut stream = BufReader::new(stream);
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut head = Vec::with_capacity(1024);
    let mut total = 0usize;
    loop {
        let mut line = Vec::new();
        let remaining = (MAX_HEAD + 1).saturating_sub(total) as u64;
        let read = (&mut stream).take(remaining).read_until(b'\n', &mut line).await?;
        if read == 0 { return Err(FirefoxError::Protocol("proxy closed before its CONNECT-UDP response".into())); }
        total = total.saturating_add(line.len());
        if total > MAX_HEAD {
            return Err(FirefoxError::Protocol("proxy CONNECT-UDP response head is too large".into()));
        }
        head.extend_from_slice(&line);
        if !head.ends_with(b"\r\n\r\n") { continue; }
        if !head.starts_with(b"HTTP/1.1 ") {
            return Err(FirefoxError::Protocol("CONNECT-UDP upgrade requires HTTP/1.1".into()));
        }
        let (status, headers) = parse_response_head(&head)?;
        if (100..200).contains(&status) && status != 101 {
            head.clear();
            continue;
        }
        if status != 101 {
            let error = proxy_status_error(proxy_host, status, &headers);
            let message = buffered_proxy_error_message(&headers, stream.buffer());
            log_proxy_failure("h1", "UDP", target, proxy_host, status, &error, &message);
            return Err(error);
        }
        validate_h1_udp_upgrade(&headers)?;
        return Ok(stream);
    }
}

fn validate_h1_udp_upgrade(headers: &http::HeaderMap) -> Result<()> {
    let connection_upgrade = headers.get_all("connection").iter().any(|v| v.to_str().ok().is_some_and(|s|
        s.split(',').any(|token| token.trim().eq_ignore_ascii_case("upgrade"))));
    let upgrades: Vec<_> = headers.get_all("upgrade").iter().collect();
    let upgrade_ok = upgrades.len() == 1 && upgrades[0].to_str().ok()
        .is_some_and(|s| s.trim().eq_ignore_ascii_case("connect-udp"));
    let capsules: Vec<_> = headers.get_all("capsule-protocol").iter().collect();
    let capsule_ok = capsules.is_empty() || (capsules.len() == 1 && capsules[0].to_str().ok()
        .is_some_and(|s| s.split(';').next().is_some_and(|value| value.trim() == "?1")));
    if !connection_upgrade || !upgrade_ok || !capsule_ok
        || headers.contains_key("content-length") || headers.contains_key("content-type")
        || headers.contains_key("transfer-encoding") {
        return Err(FirefoxError::Protocol("invalid HTTP/1.1 CONNECT-UDP upgrade response".into()));
    }
    Ok(())
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

fn h2_error(error: h2::Error) -> FirefoxError {
    FirefoxError::H2(error.to_string())
}

#[cfg(test)]
mod traffic_tests {
    use super::*;

    fn http_error(status: u16, message: &str) -> FirefoxError {
        FirefoxError::Http { host: "proxy".into(), status, errno: None, retry_after: None, message: message.into() }
    }

    #[tokio::test]
    async fn carrier_activity_counts_reads_not_queued_writes() {
        let (io, mut peer) = tokio::io::duplex(64);
        let reads = Arc::new(AtomicU64::new(0));
        let writes = Arc::new(AtomicU64::new(0));
        let mut carrier = CarrierIo { inner: io, reads: reads.clone(), writes: writes.clone() };
        carrier.write_all(b"a").await.unwrap();
        assert_eq!(reads.load(Ordering::Relaxed), 0);
        assert_eq!(writes.load(Ordering::Relaxed), 1);
        peer.write_all(b"b").await.unwrap();
        let mut byte = [0u8; 1];
        carrier.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, *b"b");
        assert_eq!(reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn stale_h1_spare_retry_never_retries_a_proxy_response() {
        let closed = FirefoxError::Network("closed".into());
        let eof = FirefoxError::Protocol("closed before response".into());
        assert!(retry_stale_h1_spare(false, &closed));
        assert!(retry_stale_h1_spare(false, &eof));
        assert!(!retry_stale_h1_spare(true, &closed));
        assert!(!retry_stale_h1_spare(true, &eof));
        assert!(!retry_stale_h1_spare(false, &http_error(502, "bad gateway")));
        assert!(!retry_stale_h1_spare(false, &FirefoxError::PassRejected));
    }

    #[tokio::test]
    async fn h1_spare_invalidation_aborts_refill_and_shutdown_stays_closed() {
        let pool = Arc::new(H1SparePool::default());
        let task = tokio::spawn(std::future::pending::<()>());
        pool.state.lock().filling = Some(task);
        let task = pool.invalidate(false).unwrap();
        assert!(task.await.unwrap_err().is_cancelled());
        {
            let state = pool.state.lock();
            assert_eq!(state.generation, 1);
            assert!(state.slot.is_none() && state.filling.is_none() && !state.closed);
        }
        pool.invalidate(true);
        pool.invalidate(false);
        let state = pool.state.lock();
        assert!(state.closed && state.slot.is_none() && state.filling.is_none());
    }

    #[test]
    fn h1_udp_upgrade_response_requires_valid_upgrade_headers() {
        let good = b"HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n";
        let (_, headers) = parse_response_head(good).unwrap();
        assert!(validate_h1_udp_upgrade(&headers).is_ok());
        for bad in [
            &b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: connect-udp\r\n\r\n"[..],
            &b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: other\r\n\r\n"[..],
            &b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nUpgrade: connect-udp\r\n\r\n"[..],
            &b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?0\r\n\r\n"[..],
        ] {
            let (_, headers) = parse_response_head(bad).unwrap();
            assert!(validate_h1_udp_upgrade(&headers).is_err());
        }
    }

    #[tokio::test]
    async fn h1_udp_upgrade_preserves_buffered_capsules_and_tunnels_packets() {
        let (client, server) = tokio::io::duplex(4096);
        let remote = tokio::spawn(async move {
            let mut server = BufReader::new(server);
            let mut head = Vec::new();
            loop {
                let mut line = Vec::new();
                server.read_until(b'\n', &mut line).await.unwrap();
                head.extend_from_slice(&line);
                if head.ends_with(b"\r\n\r\n") { break; }
            }
            let request = String::from_utf8(head).unwrap();
            assert!(request.starts_with("GET /.well-known/masque/udp/2001%3Adb8%3A%3A1/53/ HTTP/1.1\r\n"));
            assert!(request.contains("Host: proxy.example:443\r\n"));
            assert!(request.contains("Proxy-Authorization: Bearer test-pass\r\n"));
            assert!(request.contains("Upgrade: connect-udp\r\n"));
            let mut response = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n".to_vec();
            response.extend_from_slice(&encode_datagram(b"reply"));
            server.write_all(&response).await.unwrap();
            let packet = read_h1_capsule(&mut server).await.unwrap().unwrap();
            assert_eq!(packet, b"hello");
        });
        let stream = h1_udp_upgrade(client, "proxy.example:443", "proxy.example", "[2001:db8::1]:53", "test-pass").await.unwrap();
        let traffic = Arc::new(Traffic::default());
        let tunnel = UdpTunnel::new_h1(stream, traffic.clone());
        assert_eq!(tokio::time::timeout(Duration::from_secs(1), tunnel.recv()).await.unwrap().unwrap(), b"reply");
        tunnel.try_send(b"hello").unwrap();
        remote.await.unwrap();
        assert_eq!(traffic.totals(), (5, 5));
    }

    #[tokio::test]
    async fn h1_udp_rejects_bad_http_status_and_http_10() {
        for (response, status) in [
            (&b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"[..], 405),
            (&b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"[..], 407),
            (&b"HTTP/1.0 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n"[..], 101),
        ] {
            let (client, mut server) = tokio::io::duplex(4096);
            server.write_all(response).await.unwrap();
            let result = h1_udp_upgrade(client, "proxy.example:443", "proxy.example", "1.1.1.1:53", "pass").await;
            match status {
                405 => assert!(matches!(result, Err(FirefoxError::Http { status: 405, .. }))),
                407 => assert!(matches!(result, Err(FirefoxError::PassRejected))),
                _ => assert!(matches!(result, Err(FirefoxError::Protocol(_)))),
            }
        }
    }

    #[tokio::test]
    async fn h1_udp_capsules_enforce_limits_and_skip_unknown_contexts() {
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        writer.write_all(&[0, 2, 1, 9]).await.unwrap();
        assert!(read_h1_capsule(&mut reader).await.unwrap().is_none());
        let mut oversized = vec![0];
        append_quic_varint(&mut oversized, MAX_UDP_CAPSULE as u64 + 1);
        writer.write_all(&oversized).await.unwrap();
        assert_eq!(read_h1_capsule(&mut reader).await.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn h1_fallback_is_limited_to_transport_failures() {
        assert!(h1_fallback_allowed(&FirefoxError::H2("reset".into())));
        assert!(h1_fallback_allowed(&FirefoxError::Timeout(Duration::from_secs(1))));
        assert!(h1_fallback_allowed(&FirefoxError::Protocol("H2 not negotiated".into())));
        assert!(!h1_fallback_allowed(&FirefoxError::TlsCertificate { host: "proxy".into(), message: "invalid".into() }));
        assert!(!h1_fallback_allowed(&FirefoxError::PassRejected));
        assert!(!h1_fallback_allowed(&FirefoxError::QuotaExhausted(String::new())));
        assert!(!h1_fallback_allowed(&http_error(502, "Fastly; error=destination_ip_prohibited")));
    }

    #[test]
    fn destination_diagnostics_do_not_disclose_addresses() {
        for target in ["192.168.1.1:5228", "127.0.0.1:443", "169.254.1.2:443", "[::1]:443", "[fd00::1]:443", "[::ffff:10.0.0.1]:443"] {
            assert_eq!(destination_kind(target), "local or non-unicast IP");
        }
        assert_eq!(destination_kind("198.18.0.1:5228"), "benchmark-range IP");
        assert_eq!(destination_kind("198.19.255.255:443"), "benchmark-range IP");
        assert_eq!(destination_kind("[::ffff:198.18.0.1]:443"), "benchmark-range IP");
        assert_eq!(destination_kind("8.8.8.8:5228"), "IP address");
        assert_eq!(destination_kind("example.com:5228"), "hostname");
        assert_eq!(destination_kind("bad target"), "unknown destination");
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
    fn buffered_http1_error_message_requires_a_complete_bounded_body() {
        let mut headers = http::HeaderMap::new();
        let body = br#"{"message":"not allowed","token":"secret"}"#;
        headers.insert("content-length", HeaderValue::from_str(&body.len().to_string()).unwrap());
        assert_eq!(buffered_proxy_error_message(&headers, body), "not allowed");
        assert_eq!(buffered_proxy_error_message(&headers, &body[..body.len() - 1]), "");
        headers.insert("content-encoding", HeaderValue::from_static("gzip"));
        assert_eq!(buffered_proxy_error_message(&headers, body), "");
    }

    #[test]
    fn connect_diagnostics_identify_policy_without_exposing_destination_or_proxy_details() {
        let error = http_error(502, "Fastly; error=destination_ip_prohibited; details=secret");
        let message = proxy_failure_description("h2", "UDP", "private.example:42139", "proxy.example", 502, &error);
        assert!(message.contains("(h2) UDP"));
        assert!(message.contains("HTTP 502"));
        assert!(message.contains("destination=hostname port=42139"));
        assert!(message.contains("reason=destination_ip_prohibited"));
        assert!(!message.contains("private.example"));
        assert!(!message.contains("secret"));
        let unknown = http_error(502, "private.example or token");
        let message = proxy_failure_description("h1", "TCP", "192.168.1.8:80", "proxy.example", 502, &unknown);
        assert!(message.contains("reason=unspecified"));
        assert!(!message.contains("192.168.1.8"));
        assert!(!message.contains("token"));
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
    fn latency_samples_are_nonzero_and_clamped() {
        let traffic = Traffic::default();
        assert_eq!(traffic.rtt_ms(), 0);
        traffic.record_rtt(Duration::ZERO);
        assert_eq!(traffic.rtt_ms(), 1);
        traffic.record_rtt(Duration::from_millis(42));
        assert_eq!(traffic.rtt_ms(), 42);
        traffic.record_rtt(Duration::from_secs(u64::MAX));
        assert_eq!(traffic.rtt_ms(), u32::MAX);
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
