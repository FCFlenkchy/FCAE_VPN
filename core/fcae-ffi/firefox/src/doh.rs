use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use http::Method;

use crate::control::{control_alpn, exchange_h1, exchange_h2, open_h2, ConnectionDriver, ControlRequest, ControlResponse};
use crate::error::{FirefoxError, Result};
use crate::transport::{BoxedTunnel, Upstream};
use crate::types::{authority, TransportPreference};

pub(crate) fn provider(server: &str) -> Option<&'static str> {
    let address = server.parse::<IpAddr>().ok()?;
    match address.to_string().as_str() {
        "1.1.1.1" | "1.0.0.1" | "2606:4700:4700::1111" | "2606:4700:4700::1001" => Some("cloudflare-dns.com"),
        "8.8.8.8" | "8.8.4.4" | "2001:4860:4860::8888" | "2001:4860:4860::8844" => Some("dns.google"),
        _ => None,
    }
}

enum DohConnection {
    H1(tokio_boring::SslStream<BoxedTunnel>),
    H2(Arc<DohH2>),
}

struct DohH2 {
    sender: h2::client::SendRequest<bytes::Bytes>,
    _driver: ConnectionDriver,
}

type DohSlot = Arc<tokio::sync::Mutex<Option<DohConnection>>>;

struct ResolverPool {
    slots: [DohSlot; 4],
    next: AtomicUsize,
    in_flight: tokio::sync::Semaphore,
}

impl Default for ResolverPool {
    fn default() -> Self {
        Self { slots: std::array::from_fn(|_| Arc::new(tokio::sync::Mutex::new(None))), next: AtomicUsize::new(0), in_flight: tokio::sync::Semaphore::new(64) }
    }
}

#[derive(Default)]
pub(crate) struct DohPool {
    connections: parking_lot::Mutex<HashMap<IpAddr, Arc<ResolverPool>>>,
}

impl DohPool {
    fn resolver(&self, server: IpAddr) -> Arc<ResolverPool> {
        self.connections.lock().entry(server).or_default().clone()
    }
}

impl ResolverPool {
    fn slot(&self) -> DohSlot {
        let resolver = self;
        let start = resolver.next.fetch_add(1, Ordering::Relaxed) % resolver.slots.len();
        for offset in 0..resolver.slots.len() {
            let slot = &resolver.slots[(start + offset) % resolver.slots.len()];
            if slot.try_lock().is_ok_and(|connection| connection.is_some()) { return slot.clone(); }
        }
        for offset in 0..resolver.slots.len() {
            let slot = &resolver.slots[(start + offset) % resolver.slots.len()];
            if slot.try_lock().is_ok() { return slot.clone(); }
        }
        resolver.slots[start].clone()
    }

}

impl DohPool {
    pub(crate) fn clear(&self) {
        self.connections.lock().clear();
    }
}

async fn connect(upstream: &Upstream, server: &str, host: &str, force_h1: bool) -> Result<DohConnection> {
    let transport = if force_h1 { TransportPreference::H1 } else { upstream.transport_preference() };
    let tunnel = upstream.open_tcp(&authority(server, 443)).await?;
    let tls = match crate::tls::connect_stream(tunnel, host, control_alpn(transport)).await {
        Err(error @ FirefoxError::TlsCertificate { .. }) => return Err(error),
        Err(_) if transport == TransportPreference::Auto => {
            let tunnel = upstream.open_tcp(&authority(server, 443)).await?;
            crate::tls::connect_stream(tunnel, host, crate::tls::ALPN_H1).await?
        }
        result => result?,
    };
    let is_h2 = tls.ssl().selected_alpn_protocol() == Some(b"h2");
    if transport == TransportPreference::H2 && !is_h2 {
        return Err(FirefoxError::Protocol("DNS resolver did not negotiate HTTP/2".into()));
    }
    if is_h2 {
        match open_h2(tls, false).await {
            Ok((sender, driver)) => Ok(DohConnection::H2(Arc::new(DohH2 { sender, _driver: driver }))),
            Err(error) if transport == TransportPreference::Auto => {
                log::warn!("[firefox] (h2) DNS-over-HTTPS setup failed: {}; trying (h1)", crate::control::direct_failure_detail(&error));
                let tunnel = upstream.open_tcp(&authority(server, 443)).await?;
                let tls = crate::tls::connect_stream(tunnel, host, crate::tls::ALPN_H1).await?;
                Ok(DohConnection::H1(tls))
            }
            Err(error) => Err(error),
        }
    } else {
        Ok(DohConnection::H1(tls))
    }
}

async fn send(connection: &mut DohConnection, request: &ControlRequest) -> Result<(ControlResponse, bool)> {
    match connection {
        DohConnection::H1(stream) => exchange_h1(stream, request, true).await,
        DohConnection::H2(connection) => exchange_h2(connection.sender.clone(), request).await.map(|response| (response, true)),
    }
}

pub(crate) async fn exchange(upstream: &Upstream, server: &str, query: &[u8]) -> Result<Vec<u8>> {
    let host = provider(server).ok_or_else(|| FirefoxError::UnsupportedDestination(server.into()))?;
    let address = server.parse::<IpAddr>().map_err(|_| FirefoxError::UnsupportedDestination(server.into()))?;
    if query.len() < 12 || query.len() > u16::MAX as usize || query[2] & 0x80 != 0 {
        return Err(FirefoxError::Protocol("invalid DNS query".into()));
    }
    let mut request = ControlRequest::new(Method::POST, &format!("https://{host}/dns-query"))?
        .header("content-type", "application/dns-message")?
        .header("accept", "application/dns-message")?;
    request.body = Some(query.to_vec());
    let resolver = upstream.doh_pool.resolver(address);
    let _permit = resolver.in_flight.acquire().await.map_err(|_| FirefoxError::Protocol("DNS resolver pool closed".into()))?;
    let slot = resolver.slot();
    let mut cached = slot.lock().await;
    let reused = cached.is_some();
    if cached.is_none() {
        *cached = Some(connect(upstream, server, host, false).await?);
    }
    if let Some(DohConnection::H2(shared)) = cached.as_ref() {
        let shared = shared.clone();
        drop(cached);
        let mut result = perform(upstream, server, host, query, &request, DohConnection::H2(shared.clone()), reused).await;
        let mut cached = slot.lock().await;
        if matches!(cached.as_ref(), Some(DohConnection::H2(current)) if Arc::ptr_eq(current, &shared)) {
            match &mut result {
                Ok((_, replacement)) => { *cached = replacement.take(); }
                Err(error) if stale_connection_error(error) => { *cached = None; }
                Err(_) => {}
            }
        }
        return result.map(|(answer, _)| answer);
    }
    // H1 must remain exclusively owned and is discarded if this future is cancelled.
    let connection = cached.take().expect("initialized DNS slot");
    let (answer, reusable) = perform(upstream, server, host, query, &request, connection, reused).await?;
    *cached = reusable;
    Ok(answer)
}

async fn perform(upstream: &Upstream, server: &str, host: &str, query: &[u8], request: &ControlRequest,
    mut connection: DohConnection, reused: bool) -> Result<(Vec<u8>, Option<DohConnection>)> {
    let ordinary_query = replay_safe_query(query);
    let mut result = send(&mut connection, request).await;
    if reused && ordinary_query && result.as_ref().err().is_some_and(stale_connection_error) {
        connection = connect(upstream, server, host, false).await?;
        result = send(&mut connection, request).await;
    }
    let (response, reusable) = match result {
        Err(FirefoxError::H2(_)) if ordinary_query && upstream.transport_preference() == TransportPreference::Auto => {
            log::warn!("[firefox] (h2) DNS-over-HTTPS failed; trying (h1)");
            connection = connect(upstream, server, host, true).await?;
            send(&mut connection, request).await?
        }
        result => result?,
    };
    let answer = validate_response(query, response)?;
    Ok((answer, if reusable { Some(connection) } else { None }))
}

fn replay_safe_query(query: &[u8]) -> bool {
    query.len() >= 12 && query[2] & 0xf8 == 0
}

fn stale_connection_error(error: &FirefoxError) -> bool {
    matches!(error, FirefoxError::Network(_) | FirefoxError::H2(_))
        || matches!(error, FirefoxError::Protocol(message) if message == "truncated HTTP/1.1 response head")
}

fn validate_response(query: &[u8], response: ControlResponse) -> Result<Vec<u8>> {
    if response.status != 200 {
        let message = crate::control::diagnostic_error_message(&response.body);
        if message.is_empty() {
            log::warn!("[firefox] DNS-over-HTTPS failed: HTTP {}", response.status);
        } else {
            log::warn!("[firefox] DNS-over-HTTPS failed: HTTP {} message={}", response.status, message);
        }
        return Err(FirefoxError::Http {
            host: "DNS-over-HTTPS".into(), status: response.status, errno: None,
            retry_after: response.retry_after(), message: "resolver request failed".into(),
        });
    }
    let valid_type = response.headers.get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/dns-message"));
    if query.len() < 12 || !valid_type || response.body.len() < 12 || response.body.len() > u16::MAX as usize
        || response.body[..2] != query[..2] || response.body[2] & 0x80 == 0 {
        return Err(FirefoxError::Protocol("invalid DNS-over-HTTPS response".into()));
    }
    Ok(response.body)
}

pub(crate) async fn check(upstream: &Upstream, server: &str) -> Result<()> {
    const QUERY: &[u8] = b"\x91\x47\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let response = exchange(upstream, server, QUERY).await?;
    if response[3] & 0x0f != 0 {
        return Err(FirefoxError::Protocol("DNS-over-HTTPS startup query failed".into()));
    }
    Ok(())
}

pub(crate) const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_standard_dns_queries_can_be_replayed() {
        let mut query = [0u8; 12];
        assert!(replay_safe_query(&query));
        query[2] = 0x28; // UPDATE opcode
        assert!(!replay_safe_query(&query));
        query[2] = 0x80; // response
        assert!(!replay_safe_query(&query));
        assert!(!replay_safe_query(&query[..2]));
    }

    #[test]
    fn pool_clear_discards_resolver_slots_and_502_is_not_a_stale_connection() {
        let pool = DohPool::default();
        let address = "1.1.1.1".parse().unwrap();
        let old = pool.resolver(address).slot();
        pool.clear();
        let new = pool.resolver(address).slot();
        assert!(!Arc::ptr_eq(&old, &new));
        let error = FirefoxError::Http { host: "proxy".into(), status: 502, errno: None, retry_after: None, message: "bad gateway".into() };
        assert!(!stale_connection_error(&error));
        assert!(stale_connection_error(&FirefoxError::Network("closed".into())));
    }

    #[test]
    fn only_known_resolvers_are_mapped_to_their_own_provider() {
        assert_eq!(provider("1.1.1.1"), Some("cloudflare-dns.com"));
        assert_eq!(provider("1.0.0.1"), Some("cloudflare-dns.com"));
        assert_eq!(provider("2606:4700:4700:0:0:0:0:1111"), Some("cloudflare-dns.com"));
        assert_eq!(provider("8.8.8.8"), Some("dns.google"));
        assert_eq!(provider("9.9.9.9"), None);
        assert_eq!(provider("1.1.1.2"), None);
        assert_eq!(provider("192.0.2.53"), None);
    }

    #[test]
    fn rejects_unrelated_or_invalid_responses() {
        let query = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let response = |status, content_type: &str, body: Vec<u8>| {
            let mut headers = http::HeaderMap::new();
            headers.insert(http::header::CONTENT_TYPE, content_type.parse().unwrap());
            ControlResponse { status, headers, body }
        };
        let mut answer = query.to_vec();
        answer[2] = 0x81;
        assert!(validate_response(&query, response(200, "application/dns-message", answer.clone())).is_ok());
        assert!(validate_response(&query, response(503, "application/dns-message", answer.clone())).is_err());
        assert!(validate_response(&query, response(200, "text/plain", answer.clone())).is_err());
        answer[0] ^= 1;
        assert!(validate_response(&query, response(200, "application/dns-message", answer)).is_err());
        assert!(validate_response(&query, response(200, "application/dns-message", query.to_vec())).is_err());
    }
}
