//! Firefox proxy carrier over the same quiche/BoringSSL stack as Aether.
//! One event-driven connection multiplexes streams; all queues and windows are
//! bounded. Dropping a tunnel wakes the driver and resets only that stream.
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use futures::channel::mpsc;
use futures::{Sink, SinkExt, StreamExt};
use parking_lot::Mutex;
use quiche::h3::{self, NameValue};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Notify};
use tokio::task::AbortHandle;

use crate::dialer::Dialer;
use crate::error::{FirefoxError, Result};
use crate::types::{authority, split_authority, Candidate};

const CHUNK: usize = 16 * 1024;
const CANCEL: u64 = 0x10c; // H3_REQUEST_CANCELLED

type Reply = oneshot::Sender<Result<usize>>;
enum Command {
    Open(Vec<h3::Header>, Flow),
    Write(u64, Bytes, bool, Reply),
}

enum Carrier {
    Direct(UdpSocket),
    Tunnel {
        udp: crate::transport::UdpTunnel,
        peer: SocketAddr,
        local: SocketAddr,
    },
}
impl Carrier {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Direct(socket) => socket.local_addr(),
            Self::Tunnel { local, .. } => Ok(*local),
        }
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Direct(socket) => socket.peer_addr(),
            Self::Tunnel { peer, .. } => Ok(*peer),
        }
    }
    async fn recv(&self, out: &mut [u8]) -> Result<usize> {
        match self {
            Self::Direct(socket) => Ok(socket.recv(out).await?),
            Self::Tunnel { udp, .. } => {
                let packet = udp.recv().await?;
                if packet.len() > out.len() {
                    return Err(error("oversize tunneled QUIC packet"));
                }
                out[..packet.len()].copy_from_slice(&packet);
                Ok(packet.len())
            }
        }
    }
    async fn send(&self, packet: &[u8]) -> Result<()> {
        match self {
            Self::Direct(socket) => {
                socket.send(packet).await?;
            }
            // A full UDP queue drops the datagram, just like a congested UDP
            // socket. QUIC's loss recovery retries it; never grow the queue.
            Self::Tunnel { udp, .. } => {
                udp.try_send_with_capacity(packet)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn endpoint(host: &str, port: u16) -> Candidate {
    Candidate {
        address: authority(host, port),
        host: host.into(),
        port,
        country_name: String::new(),
        country_code: String::new(),
        city_name: String::new(),
        city_code: String::new(),
    }
}

/// Version fallback is not application retry. In particular, neither a valid
/// HTTP error response nor failed certificate verification authorizes it.
pub(crate) fn fallback_allowed(error: &FirefoxError) -> bool {
    matches!(
        error,
        FirefoxError::H3(_)
            | FirefoxError::H2(_)
            | FirefoxError::Network(_)
            | FirefoxError::Timeout(_)
            | FirefoxError::Dns { .. }
            | FirefoxError::Tls { .. }
    )
}

struct Owner {
    sender: mpsc::Sender<Command>,
    candidate: Candidate,
    alive: AtomicBool,
    accepting: AtomicBool,
    wake: Arc<Notify>,
    driver: Mutex<Option<AbortHandle>>,
}

impl Drop for Owner {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.get_mut().take() {
            driver.abort();
        }
    }
}

#[derive(Clone)]
pub(crate) struct Session(Arc<Owner>);

impl Session {
    pub(crate) async fn connect(
        dialer: &Dialer,
        candidate: &Candidate,
        timeout: Duration,
    ) -> Result<Self> {
        dialer.require_direct_quic()?;
        let addresses = dialer.resolve(&candidate.host, candidate.port).await?;
        let mut last = FirefoxError::H3("no usable proxy address".into());
        // The caller supplies an overall deadline as well as this per-address
        // handshake budget. IPv4 failure must not suppress a usable IPv6 peer.
        for peer in addresses {
            let attempt = async {
                let socket = dialer.udp_address(peer).await?;
                Self::handshake(Carrier::Direct(socket), candidate, timeout).await
            };
            match tokio::time::timeout(timeout, attempt).await {
                Ok(Ok(session)) => return Ok(session),
                Ok(Err(failure @ FirefoxError::TlsCertificate { .. })) => return Err(failure),
                Ok(Err(failure)) => last = failure,
                Err(_) => last = FirefoxError::Timeout(timeout),
            }
        }
        Err(last)
    }

    pub(crate) async fn connect_tunnel(
        udp: crate::transport::UdpTunnel,
        peer: SocketAddr,
        host: &str,
        timeout: Duration,
    ) -> Result<Self> {
        // These addresses describe a virtual QUIC path only: no direct resolver
        // lookup, socket, or route is opened outside the established UDP tunnel.
        let local = SocketAddr::new(
            if peer.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            0,
        );
        let candidate = endpoint(host, peer.port());
        tokio::time::timeout(
            timeout,
            Self::handshake(Carrier::Tunnel { udp, peer, local }, &candidate, timeout),
        )
        .await
        .map_err(|_| FirefoxError::Timeout(timeout))?
    }

    async fn handshake(socket: Carrier, candidate: &Candidate, timeout: Duration) -> Result<Self> {
        let local = socket.local_addr()?;
        let peer = socket.peer_addr()?;
        let mut config = crate::tls::quic_config(&candidate.host)?;
        let mut cid = [0; 16];
        rand::thread_rng().fill_bytes(&mut cid);
        let mut conn = quiche::connect(
            Some(&candidate.host),
            &quiche::ConnectionId::from_ref(&cid),
            local,
            peer,
            &mut config,
        )
        .map_err(error)?;
        crate::tls::prepare_quic(&mut conn)?;
        let mut packet = vec![0; 65_535];
        while !conn.is_established() {
            flush(&socket, &mut conn).await?;
            if conn.is_closed() {
                return Err(error("QUIC handshake closed"));
            }
            let wait = conn.timeout().unwrap_or(timeout);
            tokio::select! {
                result = socket.recv(&mut packet) => {
                    let n = result?;
                    conn.recv(&mut packet[..n], quiche::RecvInfo { from: peer, to: local })
                        .map_err(|e| crate::tls::quic_error(&mut conn, &candidate.host, e))?;
                }
                _ = tokio::time::sleep(wait) => conn.on_timeout(),
            }
        }
        let mut settings = h3::Config::new().map_err(error)?;
        settings.set_max_field_section_size(16 * 1024);
        settings.set_qpack_max_table_capacity(0);
        settings.enable_extended_connect(true);
        let mut h3 = h3::Connection::with_transport(&mut conn, &settings).map_err(error)?;
        // SETTINGS must be consumed before Extended CONNECT is sent.
        while h3.peer_settings_raw().is_none() {
            flush(&socket, &mut conn).await?;
            tokio::select! {
                result = socket.recv(&mut packet) => {
                    let n = result?;
                    conn.recv(&mut packet[..n], quiche::RecvInfo { from: peer, to: local })
                        .map_err(|e| crate::tls::quic_error(&mut conn, &candidate.host, e))?;
                }
                _ = tokio::time::sleep(conn.timeout().unwrap_or(timeout)) => conn.on_timeout(),
            }
            loop {
                match h3.poll(&mut conn) {
                    Ok(_) => {}
                    Err(h3::Error::Done) => break,
                    Err(e) => return Err(error(e)),
                }
            }
            if conn.is_closed() {
                return Err(error("proxy closed before HTTP/3 SETTINGS"));
            }
        }
        let (sender, receiver) = mpsc::channel(64);
        let owner = Arc::new(Owner {
            sender,
            candidate: candidate.clone(),
            alive: AtomicBool::new(true),
            accepting: AtomicBool::new(true),
            wake: Arc::new(Notify::new()),
            driver: Mutex::new(None),
        });
        let weak = Arc::downgrade(&owner);
        let wake = owner.wake.clone();
        let task = tokio::spawn(async move {
            let result = drive(socket, conn, h3, receiver, weak.clone(), wake).await;
            if let Some(owner) = weak.upgrade() {
                owner.alive.store(false, Ordering::Release);
            }
            if let Err(error) = result {
                log::debug!("[firefox] H3 carrier ended: {error}");
            }
        });
        *owner.driver.lock() = Some(task.abort_handle());
        Ok(Self(owner))
    }

    pub(crate) fn alive(&self) -> bool {
        self.0.alive.load(Ordering::Acquire) && self.0.accepting.load(Ordering::Acquire)
    }
    pub(crate) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(crate) fn close(&self) {
        self.0.alive.store(false, Ordering::Release);
        self.0.wake.notify_one();
    }

    pub(crate) async fn open(&self, target: &str, token: &str, udp: bool) -> Result<Tunnel> {
        if !self.alive() {
            return Err(error("carrier closed"));
        }
        let candidate = &self.0.candidate;
        let (host, port) = split_authority(target, if udp { 53 } else { 443 })
            .ok_or_else(|| FirefoxError::UnsupportedDestination(target.into()))?;
        http::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| FirefoxError::Protocol("invalid proxy pass header".into()))?;
        let mut headers = vec![h3::Header::new(b":method", b"CONNECT")];
        if udp {
            headers.extend([
                h3::Header::new(b":protocol", b"connect-udp"),
                h3::Header::new(b":scheme", b"https"),
                h3::Header::new(
                    b":authority",
                    authority(&candidate.host, candidate.port).as_bytes(),
                ),
                h3::Header::new(
                    b":path",
                    format!(
                        "/.well-known/masque/udp/{}/{port}/",
                        crate::transport::path_segment(&host)
                    )
                    .as_bytes(),
                ),
                h3::Header::new(b"capsule-protocol", b"?1"),
            ]);
        } else {
            // RFC 9114 CONNECT deliberately has no :scheme or :path.
            headers.push(h3::Header::new(
                b":authority",
                authority(&host, port).as_bytes(),
            ));
        }
        headers.push(h3::Header::new(
            b"proxy-authorization",
            format!("Bearer {token}").as_bytes(),
        ));
        headers.push(h3::Header::new(
            b"user-agent",
            crate::tls::firefox_user_agent().as_bytes(),
        ));
        let (incoming, receiver) = tokio::sync::mpsc::channel(4);
        let (reply, response) = oneshot::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(Mutex::new(None));
        let mut tunnel = Tunnel {
            owner: self.clone(),
            sender: self.0.sender.clone(),
            id: 0,
            receiver,
            current: Bytes::new(),
            pending: None,
            finished: false,
            cancelled: cancelled.clone(),
            failure: failure.clone(),
        };
        let flow = Flow {
            response: Some(reply),
            http: None,
            incoming: Some(incoming),
            cancelled,
            failure,
            outgoing: None,
            readable: false,
            received_fin: false,
            sent_fin: false,
            udp,
            host: candidate.host.clone(),
        };
        tunnel
            .sender
            .send(Command::Open(headers, flow))
            .await
            .map_err(|_| error("carrier closed"))?;
        tunnel.id = response
            .await
            .map_err(|_| error("carrier closed during CONNECT"))??;
        Ok(tunnel)
    }
    pub(crate) async fn exchange(
        &self,
        request: &crate::control::ControlRequest,
    ) -> Result<crate::control::ControlResponse> {
        if !self.alive() {
            return Err(error("HTTP/3 connection closed"));
        }
        let mut headers = vec![
            h3::Header::new(b":method", request.method.as_str().as_bytes()),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(
                b":authority",
                authority(&request.host, request.port).as_bytes(),
            ),
            h3::Header::new(b":path", request.path.as_bytes()),
        ];
        for (name, value) in &request.headers {
            if name == http::header::HOST || name == http::header::CONTENT_LENGTH {
                continue;
            }
            headers.push(h3::Header::new(name.as_str().as_bytes(), value.as_bytes()));
        }
        let body = request.body.clone().unwrap_or_default();
        if body.len() > 2 * 1024 * 1024 {
            return Err(error("HTTP/3 request body exceeds limit"));
        }
        headers.push(h3::Header::new(
            b"content-length",
            body.len().to_string().as_bytes(),
        ));
        let (reply, response) = oneshot::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let _guard = RequestGuard {
            cancelled: cancelled.clone(),
            wake: self.0.wake.clone(),
        };
        let (sent, _) = oneshot::channel();
        let length = body.len();
        let flow = Flow {
            response: None,
            http: Some(HttpFlow {
                reply: Some(reply),
                head: None,
                body: Vec::new(),
                head_only: request.method == http::Method::HEAD,
            }),
            incoming: None,
            cancelled,
            failure: Arc::new(Mutex::new(None)),
            outgoing: Some((Bytes::from(body), true, sent, length)),
            readable: false,
            received_fin: false,
            sent_fin: false,
            udp: false,
            host: request.host.clone(),
        };
        self.0
            .sender
            .clone()
            .send(Command::Open(headers, flow))
            .await
            .map_err(|_| error("HTTP/3 connection closed"))?;
        response.await.map_err(|_| error("HTTP/3 request ended"))?
    }
}

pub(crate) struct Tunnel {
    owner: Session,
    sender: mpsc::Sender<Command>,
    id: u64,
    receiver: tokio::sync::mpsc::Receiver<Bytes>,
    current: Bytes,
    pending: Option<oneshot::Receiver<Result<usize>>>,
    finished: bool,
    cancelled: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<String>>>,
}

impl AsyncRead for Tunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.current.is_empty() {
            match self.receiver.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(chunk)) => {
                    self.current = chunk;
                    self.owner.0.wake.notify_one();
                }
                Poll::Ready(None) => {
                    return Poll::Ready(match self.failure.lock().take() {
                        Some(message) => Err(io::Error::other(message)),
                        None => Ok(()),
                    })
                }
            }
        }
        let n = self.current.len().min(out.remaining());
        out.put_slice(&self.current[..n]);
        self.current.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl Tunnel {
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let Some(reply) = self.pending.as_mut() else {
            return Poll::Ready(Ok(0));
        };
        match std::future::Future::poll(Pin::new(reply), cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending = None;
                Poll::Ready(
                    result
                        .unwrap_or_else(|_| Err(error("carrier closed")))
                        .map_err(|e| io::Error::other(e.to_string())),
                )
            }
        }
    }

    fn queue(&mut self, cx: &mut Context<'_>, bytes: Bytes, fin: bool) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.sender).poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_)) => return Poll::Ready(Err(io::Error::other("H3 carrier closed"))),
            Poll::Ready(Ok(())) => {}
        }
        let (reply, response) = oneshot::channel();
        let id = self.id;
        if Pin::new(&mut self.sender)
            .start_send(Command::Write(id, bytes, fin, reply))
            .is_err()
        {
            return Poll::Ready(Err(io::Error::other("H3 carrier closed")));
        }
        self.pending = Some(response);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Tunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        // A successful poll_write reports bytes as soon as the bounded queue
        // owns them. Pending must not consume bytes: write() is cancel-safe.
        if self.pending.is_some() {
            match self.poll_pending(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(_)) => {}
            }
        }
        if self.finished {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = bytes.len().min(CHUNK);
        let chunk = Bytes::copy_from_slice(&bytes[..n]);
        match self.queue(cx, chunk, false) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_pending(cx).map(|r| r.map(|_| ()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(_)) => {}
        }
        if self.finished {
            return Poll::Ready(Ok(()));
        }
        match self.queue(cx, Bytes::new(), true) {
            Poll::Ready(Ok(())) => {
                self.finished = true;
                self.poll_pending(cx).map(|r| r.map(|_| ()))
            }
            result => result,
        }
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.owner.0.wake.notify_one();
    }
}

struct RequestGuard {
    cancelled: Arc<AtomicBool>,
    wake: Arc<Notify>,
}
impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.wake.notify_one();
    }
}
struct HttpFlow {
    reply: Option<oneshot::Sender<Result<crate::control::ControlResponse>>>,
    head: Option<(u16, http::HeaderMap)>,
    body: Vec<u8>,
    head_only: bool,
}

struct Flow {
    http: Option<HttpFlow>,
    response: Option<oneshot::Sender<Result<u64>>>,
    incoming: Option<tokio::sync::mpsc::Sender<Bytes>>,
    cancelled: Arc<AtomicBool>,
    failure: Arc<Mutex<Option<String>>>,
    outgoing: Option<(Bytes, bool, Reply, usize)>,
    readable: bool,
    received_fin: bool,
    sent_fin: bool,
    udp: bool,
    host: String,
}

impl Flow {
    fn fail(&mut self, failure: FirefoxError) {
        *self.failure.lock() = Some(failure.to_string());
        if let Some(http) = &mut self.http {
            if let Some(reply) = http.reply.take() {
                let _ = reply.send(Err(error(failure.to_string())));
            }
        }
        self.incoming.take();
        if let Some(reply) = self.response.take() {
            let _ = reply.send(Err(failure));
        }
    }
}

async fn drive(
    socket: Carrier,
    mut conn: quiche::Connection,
    mut http: h3::Connection,
    mut commands: mpsc::Receiver<Command>,
    owner: Weak<Owner>,
    wake: Arc<Notify>,
) -> Result<()> {
    let local = socket.local_addr()?;
    let peer = socket.peer_addr()?;
    let mut flows = HashMap::<u64, Flow>::new();
    let mut pending_opens = VecDeque::<(Vec<h3::Header>, Flow)>::new();
    let mut packet = vec![0; 65_535];
    let mut body = vec![0; CHUNK];
    let period = Duration::from_secs(30);
    let mut keepalive = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let outcome = async {
        loop {
            if !owner.upgrade().is_some_and(|o| o.alive.load(Ordering::Acquire)) { break; }
            let mut progressed = false;
            loop {
                match http.poll(&mut conn) {
                    Ok((id, h3::Event::Headers { list, .. })) => {
                        progressed = true;
                        let Some(flow) = flows.get_mut(&id) else { continue };
                        // Ignore informational headers and later trailers.
                        if flow.response.is_none() && flow.http.as_ref().is_none_or(|h| h.head.is_some()) { continue; }
                        let statuses = list.iter().filter(|h| h.name() == b":status").collect::<Vec<_>>();
                        let status = if statuses.len() == 1 && statuses[0].value().len() == 3 {
                            std::str::from_utf8(statuses[0].value()).ok().and_then(|s| s.parse::<u16>().ok())
                        } else { None };
                        if list.iter().any(|h| h.name().starts_with(b":") && h.name() != b":status") {
                            flow.fail(error("unexpected response pseudo-header"));
                            flow.cancelled.store(true, Ordering::Release);
                            continue;
                        }
                        if status.is_some_and(|s| (100..200).contains(&s) && s != 101) { continue; }
                        let mut headers = http::HeaderMap::new();
                        let mut valid_headers = true;
                        for h in &list {
                            if h.name() == b":status" { continue; }
                            if h.name().iter().any(u8::is_ascii_uppercase) || matches!(h.name(),
                                b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding" | b"upgrade") {
                                valid_headers = false;
                                break;
                            }
                            match (http::header::HeaderName::from_bytes(h.name()), http::HeaderValue::from_bytes(h.value())) {
                                (Ok(name), Ok(value)) => { headers.append(name, value); }
                                _ => { valid_headers = false; break; }
                            }
                        }
                        if !valid_headers {
                            flow.fail(error("malformed HTTP/3 response headers"));
                            flow.cancelled.store(true, Ordering::Release);
                            continue;
                        }
                        if let Some(exchange) = &mut flow.http {
                            if let Some(status) = status.filter(|s| (200..600).contains(s)) {
                                exchange.head = Some((status, headers));
                            } else {
                                flow.fail(error("malformed HTTP/3 response status"));
                                flow.cancelled.store(true, Ordering::Release);
                            }
                            continue;
                        }
                        let valid_capsule = !flow.udp || (!headers.contains_key("content-length") && !headers.contains_key("content-type")
                            && !headers.contains_key("transfer-encoding") && !matches!(status, Some(204..=206)));
                        match status {
                            Some(s) if (200..300).contains(&s) && valid_capsule => {
                                if let Some(reply) = flow.response.take() { let _ = reply.send(Ok(id)); }
                            }
                            Some(s) if !(200..300).contains(&s) => {
                                flow.fail(crate::transport::proxy_status_error(&flow.host, s, &headers));
                                flow.cancelled.store(true, Ordering::Release);
                            }
                            _ => { flow.fail(error("malformed CONNECT response")); flow.cancelled.store(true, Ordering::Release); }
                        }
                    }
                    Ok((id, h3::Event::Data)) => { if let Some(flow) = flows.get_mut(&id) { flow.readable = true; } }
                    Ok((id, h3::Event::Finished)) => {
                        if let Some(flow) = flows.get_mut(&id) {
                            flow.received_fin = true;
                            if flow.response.is_some() { flow.fail(error("CONNECT ended without a response")); }
                        }
                    }
                    Ok((id, h3::Event::Reset(code))) => {
                        if let Some(mut flow) = flows.remove(&id) { flow.fail(error(format!("stream reset ({code})"))); }
                    }
                    Ok((_, h3::Event::GoAway)) => { if let Some(o) = owner.upgrade() { o.accepting.store(false, Ordering::Release); } }
                    Ok(_) => {},
                    Err(h3::Error::Done) => break,
                    Err(e) => return Err(error(e)),
                }
            }
            pending_opens.retain(|(_, flow)| !flow.cancelled.load(Ordering::Acquire));
            // Stream credit and connection flow control are backpressure, not
            // carrier failures. Retry queued CONNECTs only on real driver wakes.
            while let Some((headers, mut flow)) = pending_opens.pop_front() {
                if flow.cancelled.load(Ordering::Acquire) { continue; }
                if !owner.upgrade().is_some_and(|o| o.accepting.load(Ordering::Acquire)) {
                    flow.fail(error("proxy sent GOAWAY"));
                    continue;
                }
                if flow.udp && !http.extended_connect_enabled_by_peer() {
                    flow.fail(error("proxy did not enable Extended CONNECT"));
                    continue;
                }
                if flows.len() >= 256 {
                    pending_opens.push_front((headers, flow));
                    break;
                }
                match http.send_request(&mut conn, &headers, false) {
                    Ok(id) => { flows.insert(id, flow); }
                    Err(h3::Error::Done | h3::Error::StreamBlocked |
                        h3::Error::TransportError(quiche::Error::StreamLimit)) => {
                        pending_opens.push_front((headers, flow));
                        break;
                    }
                    Err(e) => flow.fail(error(e)),
                }
            }
            let mut remove = Vec::new();
            for (&id, flow) in &mut flows {
                if flow.cancelled.load(Ordering::Acquire) {
                    let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, CANCEL);
                    let _ = conn.stream_shutdown(id, quiche::Shutdown::Write, CANCEL);
                    remove.push(id);
                    continue;
                }
                if let Some((bytes, fin, _, _)) = &mut flow.outgoing {
                    match http.send_body(&mut conn, id, bytes, *fin) {
                        Ok(n) => {
                            progressed = true;
                            bytes.advance(n);
                            if bytes.is_empty() {
                                let (_, fin, reply, original) = flow.outgoing.take().unwrap();
                                flow.sent_fin |= fin;
                                let _ = reply.send(Ok(original));
                            }
                        }
                        Err(h3::Error::Done | h3::Error::StreamBlocked) => {},
                        Err(e) => { flow.fail(error(e)); remove.push(id); continue; }
                    }
                }
                while flow.readable && flow.response.is_none() {
                    if let Some(exchange) = &mut flow.http {
                        match http.recv_body(&mut conn, id, &mut body) {
                            Ok(n) if n > 0 => {
                                progressed = true;
                                if exchange.head_only || exchange.head.as_ref().is_some_and(|(status, _)| matches!(status, 204 | 304)) {
                                    flow.fail(error("body on a bodyless HTTP response"));
                                    flow.cancelled.store(true, Ordering::Release);
                                    remove.push(id);
                                    break;
                                }
                                if exchange.body.len().saturating_add(n) > 2 * 1024 * 1024 {
                                    flow.fail(error("HTTP/3 response body exceeds limit"));
                                    flow.cancelled.store(true, Ordering::Release);
                                    remove.push(id);
                                    break;
                                }
                                exchange.body.extend_from_slice(&body[..n]);
                            }
                            Ok(_) | Err(h3::Error::Done) => { flow.readable = false; break; }
                            Err(e) => { flow.fail(error(e)); remove.push(id); break; }
                        }
                        continue;
                    }
                    let Some(incoming) = &flow.incoming else { break };
                    if incoming.capacity() == 0 { break; }
                    match http.recv_body(&mut conn, id, &mut body) {
                        Ok(n) if n > 0 => { progressed = true; let _ = incoming.try_send(Bytes::copy_from_slice(&body[..n])); }
                        Ok(_) | Err(h3::Error::Done) => { flow.readable = false; break; }
                        Err(e) => { flow.fail(error(e)); remove.push(id); break; }
                    }
                }
                if flow.received_fin && !flow.readable && flow.http.is_some() {
                    let mut exchange = flow.http.take().unwrap();
                    let result = match exchange.head {
                        Some((status, headers)) => {
                            let lengths = headers.get_all(http::header::CONTENT_LENGTH).iter().collect::<Vec<_>>();
                            let valid_length = lengths.is_empty() || (lengths.len() == 1 &&
                                lengths[0].to_str().ok().and_then(|s| s.parse::<usize>().ok())
                                .is_some_and(|n| exchange.head_only || status == 204 || status == 304 || n == exchange.body.len()));
                            if valid_length { Ok(crate::control::ControlResponse { status, headers, body: exchange.body }) }
                            else { Err(error("invalid HTTP/3 response content length")) }
                        }
                        None => Err(error("HTTP/3 response ended without headers")),
                    };
                    if let Some(reply) = exchange.reply.take() { let _ = reply.send(result); }
                    if !flow.sent_fin { let _ = conn.stream_shutdown(id, quiche::Shutdown::Write, CANCEL); }
                    remove.push(id);
                    continue;
                }
                if flow.received_fin && !flow.readable { flow.incoming.take(); }
                if flow.received_fin && !flow.readable && flow.sent_fin { remove.push(id); }
            }
            for id in remove { flows.remove(&id); }
            flush(&socket, &mut conn).await?;
            if conn.is_closed() { return Err(error("QUIC connection closed")); }
            // Draining DATA can make Finished immediately available in quiche
            // without another UDP packet. Poll internal progress before sleep.
            if progressed { continue; }
            let wait = conn.timeout().unwrap_or(Duration::from_secs(120));
            tokio::select! {
                result = socket.recv(&mut packet) => {
                    let n = result?;
                    match conn.recv(&mut packet[..n], quiche::RecvInfo { from: peer, to: local }) {
                        Ok(_) | Err(quiche::Error::Done) => {}, Err(e) => return Err(error(e)),
                    }
                }
                command = commands.next() => match command {
                    Some(Command::Open(headers, mut flow)) => {
                        if pending_opens.len() >= 64 { flow.fail(error("H3 pending CONNECT queue is full")); }
                        else { pending_opens.push_back((headers, flow)); }
                    }
                    Some(Command::Write(id, bytes, fin, reply)) => {
                        let length = bytes.len();
                        if let Some(flow) = flows.get_mut(&id) {
                            if flow.outgoing.is_none() { flow.outgoing = Some((bytes, fin, reply, length)); }
                            else { let _ = reply.send(Err(error("concurrent write on H3 stream"))); }
                        } else { let _ = reply.send(Err(error("H3 stream closed"))); }
                    }
                    None => break,
                },
                _ = wake.notified() => {},
                _ = keepalive.tick(), if !flows.is_empty() => { let _ = conn.send_ack_eliciting(); }
                _ = tokio::time::sleep(wait) => conn.on_timeout(),
            }
        }
        Ok(())
    }.await;
    // Publish failure before waking CONNECT waiters, so their retry can
    // replace this carrier rather than racing its final close packet.
    if let Some(owner) = owner.upgrade() {
        owner.alive.store(false, Ordering::Release);
    }
    for flow in flows.values_mut() {
        flow.fail(error("carrier closed"));
    }
    for (_, mut flow) in pending_opens {
        flow.fail(error("carrier closed"));
    }
    let _ = conn.close(true, 0x100, b"shutdown");
    let _ = tokio::time::timeout(Duration::from_millis(100), flush(&socket, &mut conn)).await;
    outcome
}

async fn flush(socket: &Carrier, conn: &mut quiche::Connection) -> Result<()> {
    let mut packet = [0; 1350];
    loop {
        match conn.send(&mut packet) {
            Ok((n, info)) => {
                // Honor quiche's pacing rather than emitting a busy burst.
                let at = tokio::time::Instant::from_std(info.at);
                if at > tokio::time::Instant::now() {
                    tokio::time::sleep_until(at).await;
                }
                socket.send(&packet[..n]).await?;
            }
            Err(quiche::Error::Done) => return Ok(()),
            Err(e) => return Err(error(e)),
        }
    }
}

fn error(e: impl std::fmt::Display) -> FirefoxError {
    FirefoxError::H3(e.to_string())
}

struct Cached {
    session: Option<Session>,
    retry_at: Option<std::time::Instant>,
}
struct PoolEntry {
    authority: String,
    used: std::time::Instant,
    value: Arc<tokio::sync::Mutex<Cached>>,
}

/// Bounded, authority-keyed service connections. Cookie jars remain separate;
/// every HTTP request carries its own headers on an independent QUIC stream.
#[derive(Default)]
pub(crate) struct Pool(Mutex<Vec<PoolEntry>>);
impl Pool {
    pub(crate) async fn get(
        &self,
        dialer: &Dialer,
        host: &str,
        port: u16,
        timeout: Duration,
        auto: bool,
    ) -> Result<Session> {
        let key = authority(host, port);
        let now = std::time::Instant::now();
        let slot = {
            let mut entries = self.0.lock();
            entries.retain(|entry| now.duration_since(entry.used) < Duration::from_secs(120));
            if let Some(entry) = entries.iter_mut().find(|entry| entry.authority == key) {
                entry.used = now;
                entry.value.clone()
            } else {
                if entries.len() >= 8 {
                    let oldest = entries
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, e)| e.used)
                        .map(|(i, _)| i)
                        .unwrap();
                    entries.swap_remove(oldest);
                }
                let value = Arc::new(tokio::sync::Mutex::new(Cached {
                    session: None,
                    retry_at: None,
                }));
                entries.push(PoolEntry {
                    authority: key,
                    used: now,
                    value: value.clone(),
                });
                value
            }
        };
        let mut cached = slot.lock().await;
        if let Some(session) = cached.session.as_ref().filter(|s| s.alive()) {
            return Ok(session.clone());
        }
        cached.session = None;
        if auto && cached.retry_at.is_some_and(|at| now < at) {
            return Err(error("HTTP/3 transport cooldown"));
        }
        let budget = if auto {
            (timeout / 3).min(Duration::from_secs(3))
        } else {
            timeout
        };
        let candidate = endpoint(host, port);
        match tokio::time::timeout(budget, Session::connect(dialer, &candidate, budget))
            .await
            .unwrap_or_else(|_| Err(FirefoxError::Timeout(budget)))
        {
            Ok(session) => {
                cached.retry_at = None;
                cached.session = Some(session.clone());
                Ok(session)
            }
            Err(failure) => {
                if auto && fallback_allowed(&failure) {
                    cached.retry_at = Some(std::time::Instant::now() + Duration::from_secs(30));
                }
                Err(failure)
            }
        }
    }
}
