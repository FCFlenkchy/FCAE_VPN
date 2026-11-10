use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_boring::SslStream;
use url::Url;

use crate::dialer::Dialer;
use crate::error::{FirefoxError, Result};
use crate::store::AccountStore;
use crate::tls::{firefox_user_agent, firefox_user_agent_for_major, ALPN_H1, ALPN_H2_H1};

const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_HEADER_LIST: u32 = 128 * 1024;
const MAX_RESPONSE: usize = MAX_BODY + 128 * 1024;

#[derive(Debug, Clone)]
pub struct ControlResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl ControlResponse {
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        Ok(serde_json::from_slice(&self.body)?)
    }

    pub fn message(&self) -> String {
        if is_relay_response(&self.headers) {
            return "relayed service request failed".into();
        }
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&self.body) {
            for key in ["message", "error", "detail"] {
                if let Some(message) = value.get(key).and_then(serde_json::Value::as_str) {
                    return message.chars().take(512).collect();
                }
            }
        }
        String::from_utf8_lossy(&self.body)
            .chars()
            .filter(|c| !c.is_control() || *c == ' ')
            .take(512)
            .collect()
    }

    pub fn errno(&self) -> Option<i64> {
        serde_json::from_slice::<serde_json::Value>(&self.body)
            .ok()?
            .get("errno")?
            .as_i64()
    }

    pub fn retry_after(&self) -> Option<Duration> {
        let value = self.headers.get("retry-after")?.to_str().ok()?.trim();
        if let Ok(seconds) = value.parse::<u64>() {
            return Some(Duration::from_secs(seconds.min(86_400)));
        }
        let at = httpdate::parse_http_date(value).ok()?;
        at.duration_since(SystemTime::now()).ok().map(|d| d.min(Duration::from_secs(86_400)))
    }
}

#[derive(Debug, Clone)]
pub struct ControlRequest {
    pub method: Method,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Option<Vec<u8>>,
}

impl ControlRequest {
    pub fn new(method: Method, raw_url: &str) -> Result<Self> {
        let url = Url::parse(raw_url)?;
        if url.scheme() != "https" || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
            return Err(FirefoxError::InvalidConfig("only credential-free HTTPS control-plane URLs are accepted".into()));
        }
        let host = url.host_str().unwrap().trim_matches(['[', ']']).to_string();
        let port = url.port().unwrap_or(443);
        let path = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None if url.path().is_empty() => "/".into(),
            None => url.path().to_string(),
        };
        Ok(Self { method, host, port, path, headers: Vec::new(), body: None })
    }

    pub fn header(mut self, name: &'static str, value: impl AsRef<str>) -> Result<Self> {
        let name = HeaderName::from_static(name);
        let value = HeaderValue::from_str(value.as_ref())
            .map_err(|_| FirefoxError::Protocol("invalid HTTP header value".into()))?;
        self.headers.push((name, value));
        Ok(self)
    }

    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Result<Self> {
        self.body = Some(serde_json::to_vec(value)?);
        self.headers.push((http::header::CONTENT_TYPE, HeaderValue::from_static("application/json")));
        Ok(self)
    }
}

#[derive(Debug, Clone)]
struct Cookie {
    domain: String,
    path: String,
    name: String,
    value: String,
    expires_at: Option<SystemTime>,
}

impl Cookie {
    fn is_valid(&self, now: SystemTime) -> bool {
        !self.value.is_empty() && self.expires_at.map_or(true, |expiry| expiry > now)
    }
}

#[derive(Clone)]
pub struct ControlPlane {
    dialer: Dialer,
    timeout: Duration,
    user_agent: String,
    cookies: Arc<Mutex<BTreeMap<String, Cookie>>>,
    challenge_h2: Option<Arc<tokio::sync::Mutex<Option<ReusableH2>>>>,
    relay_store: Option<AccountStore>,
}

impl ControlPlane {
    pub fn new(dialer: Dialer) -> Self {
        Self {
            dialer, timeout: Duration::from_secs(20), user_agent: firefox_user_agent(),
            cookies: Arc::new(Mutex::new(BTreeMap::new())), challenge_h2: None, relay_store: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn fresh_jar(&self) -> Self {
        Self {
            dialer: self.dialer.clone(),
            timeout: self.timeout,
            user_agent: self.user_agent.clone(),
            cookies: Arc::new(Mutex::new(BTreeMap::new())),
            challenge_h2: None,
            relay_store: self.relay_store.clone(),
        }
    }

    pub fn with_relay_store(mut self, store: AccountStore) -> Self {
        self.relay_store = Some(store);
        self
    }

    pub(crate) fn with_challenge_h2(mut self) -> Self {
        self.challenge_h2 = Some(Arc::new(tokio::sync::Mutex::new(None)));
        self
    }

    pub async fn with_current_firefox_user_agent(mut self) -> Self {
        const VERSION_URL: &str = "https://product-details.mozilla.org/1.0/firefox_versions.json";
        let probe = self.fresh_jar().with_timeout(Duration::from_secs(3));
        if let Ok(request) = ControlRequest::new(Method::GET, VERSION_URL) {
            if let Ok(response) = probe.send(request).await {
                if response.status == 200 {
                    if let Some(major) = firefox_release_major(&response.body) {
                        self.user_agent = firefox_user_agent_for_major(major);
                    }
                }
            }
        }
        self
    }

    pub fn dialer(&self) -> &Dialer {
        &self.dialer
    }

    pub async fn send(&self, request: ControlRequest) -> Result<ControlResponse> {
        let request = self.decorate(request);
        tokio::time::timeout(self.timeout, self.send_inner(request))
            .await.map_err(|_| FirefoxError::Timeout(self.timeout))?
    }

    async fn send_inner(&self, request: ControlRequest) -> Result<ControlResponse> {
        let relay = match &self.relay_store {
            Some(store) if relay_target_allowed(&request) => store.relay_url()?,
            _ => None,
        };
        let Some(relay) = relay else {
            let host = request.host.clone();
            let response = if let Some(pool) = &self.challenge_h2 {
                self.exchange_challenge(request, pool).await?
            } else {
                self.exchange(request, ALPN_H1, false).await?
            };
            log_http_status(&host, &response, false);
            return Ok(response);
        };
        let safe = request.method == Method::GET || request.method == Method::HEAD;
        let direct = if let Some(pool) = &self.challenge_h2 {
            // A challenge session may have transmitted the request when it fails.
            if safe {
                tokio::time::timeout(Duration::from_secs(8), self.exchange_challenge(request.clone(), pool))
                    .await.unwrap_or_else(|_| Err(FirefoxError::Timeout(Duration::from_secs(8))))
            } else {
                self.exchange_challenge(request.clone(), pool).await
            }
        } else {
            // Only the connection is timed here; no request bytes have been sent yet.
            match tokio::time::timeout(Duration::from_secs(4),
                crate::tls::connect(&self.dialer, &request.host, request.port, ALPN_H1)).await {
                Ok(Ok(tls)) => {
                    let result = if safe {
                        tokio::time::timeout(Duration::from_secs(8), over_h1(tls, &request))
                            .await.unwrap_or_else(|_| Err(FirefoxError::Timeout(Duration::from_secs(8))))
                    } else {
                        over_h1(tls, &request).await
                    };
                    if let Ok(response) = &result {
                        self.store_cookies(&request.host, &response.headers);
                    }
                    result
                },
                Ok(Err(error @ FirefoxError::TlsCertificate { .. })) => return Err(error),
                Ok(Err(_)) | Err(_) => {
                    log::warn!("[firefox] direct service connection failed; trying the configured relay");
                    return self.exchange_relay(&request, &relay).await;
                }
            }
        };
        match direct {
            Ok(response) => {
                log_http_status(&request.host, &response, false);
                if should_relay_region_rejection(&request, response.status) {
                    log::warn!("[firefox] service rejected the region (HTTP 451); trying the configured relay");
                    self.exchange_relay(&request, &relay).await
                } else {
                    Ok(response)
                }
            }
            Err(error @ FirefoxError::TlsCertificate { .. }) => Err(error),
            Err(_) if safe => {
                log::warn!("[firefox] service request failed; trying the configured relay");
                self.exchange_relay(&request, &relay).await
            }
            Err(error) => Err(error),
        }
    }

    async fn exchange_relay(&self, request: &ControlRequest, relay: &Url) -> Result<ControlResponse> {
        let forwarded = relay_request(request, relay)?;
        let response = async {
            let tls = crate::tls::connect(&self.dialer, &forwarded.host, forwarded.port, ALPN_H1).await?;
            over_h1(tls, &forwarded).await
        }.await.map_err(|error| {
            log::warn!("[firefox] relay request failed reason={}", error.reason_code());
            error
        })?;
        log_http_status(&request.host, &response, true);
        if response.headers.contains_key("x-relay-error") ||
            (response.status >= 400 && !is_relay_response(&response.headers)) {
            return Err(FirefoxError::Protocol(format!("relay or service request failed (HTTP {})", response.status)));
        }
        self.store_cookies(&request.host, &response.headers);
        log::info!("[firefox] Firefox service request used the configured relay (HTTP {})", response.status);
        Ok(response)
    }

    pub async fn send_h2(&self, request: ControlRequest) -> Result<ControlResponse> {
        let request = self.decorate(request);
        let host = request.host.clone();
        let response = tokio::time::timeout(self.timeout, self.exchange(request, ALPN_H2_H1, true))
            .await.map_err(|_| FirefoxError::Timeout(self.timeout))??;
        log_http_status(&host, &response, false);
        Ok(response)
    }

    pub fn import_cookies(&self, other: &ControlPlane) {
        let imported = other.cookies.lock().clone();
        self.cookies.lock().extend(imported);
    }

    pub fn has_cookies(&self) -> bool {
        let now = SystemTime::now();
        self.cookies.lock().values().any(|cookie| cookie.is_valid(now))
    }

    pub fn import_cookies_for_hosts(&self, other: &ControlPlane, hosts: &[&str]) {
        let imported = other.cookies.lock().clone();
        let mut target = self.cookies.lock();
        for cookie in imported.into_values() {
            for host in hosts {
                let domain = host.to_ascii_lowercase();
                let key = format!("{domain}|{}|{}", cookie.path, cookie.name);
                target.insert(key, Cookie { domain, ..cookie.clone() });
            }
        }
    }

    fn decorate(&self, mut request: ControlRequest) -> ControlRequest {
        if !has_header(&request, "user-agent") {
            request.headers.push((http::header::USER_AGENT, HeaderValue::from_str(&self.user_agent).unwrap()));
        }
        if !has_header(&request, "accept") {
            request.headers.push((http::header::ACCEPT, HeaderValue::from_static("*/*")));
        }
        if !has_header(&request, "accept-encoding") {
            request.headers.push((http::header::ACCEPT_ENCODING, HeaderValue::from_static("identity")));
        }
        let cookies = self.cookies.lock();
        let now = SystemTime::now();
        let mut values = cookies.values().filter(|cookie| {
            domain_matches(&request.host, &cookie.domain)
                && path_matches(&request.path, &cookie.path)
                && cookie.is_valid(now)
        }).map(|cookie| format!("{}={}", cookie.name, cookie.value)).collect::<Vec<_>>();
        values.sort();
        if !values.is_empty() && !has_header(&request, "cookie") {
            if let Ok(value) = HeaderValue::from_str(&values.join("; ")) {
                request.headers.push((http::header::COOKIE, value));
            }
        }
        request
    }

    async fn exchange(&self, request: ControlRequest, alpn: &[u8], require_h2: bool) -> Result<ControlResponse> {
        let tls = crate::tls::connect(&self.dialer, &request.host, request.port, alpn).await?;
        let is_h2 = tls.ssl().selected_alpn_protocol() == Some(b"h2");
        if require_h2 && !is_h2 {
            return Err(FirefoxError::Protocol("Mozilla did not negotiate HTTP/2".into()));
        }
        let response = if is_h2 { over_h2(tls, &request).await? } else { over_h1(tls, &request).await? };
        self.store_cookies(&request.host, &response.headers);
        Ok(response)
    }

    async fn exchange_challenge(
        &self,
        request: ControlRequest,
        pool: &tokio::sync::Mutex<Option<ReusableH2>>,
    ) -> Result<ControlResponse> {
        let mut session = pool.lock().await;
        if session.as_ref().is_some_and(|current| current.host != request.host || current.port != request.port) {
            *session = None;
        }
        if session.is_none() {
            let tls = match crate::tls::connect(&self.dialer, &request.host, request.port, ALPN_H2_H1).await {
                Ok(tls) => tls,
                Err(error) => {
                    log::debug!("[firefox] challenge HTTP/2 setup failed: {error}");
                    drop(session);
                    return self.exchange(request, ALPN_H1, false).await;
                }
            };
            if tls.ssl().selected_alpn_protocol() != Some(b"h2") {
                drop(session);
                let response = over_h1(tls, &request).await?;
                self.store_cookies(&request.host, &response.headers);
                return Ok(response);
            }
            let mut builder = h2::client::Builder::new();
            builder.enable_push(false).max_header_list_size(MAX_HEADER_LIST);
            let (sender, connection) = match builder.handshake(tls).await {
                Ok(connection) => connection,
                Err(error) => {
                    log::debug!("[firefox] challenge HTTP/2 handshake failed: {error}");
                    drop(session);
                    return self.exchange(request, ALPN_H1, false).await;
                }
            };
            let driver = ConnectionDriver(tokio::spawn(async move { let _ = connection.await; }));
            *session = Some(ReusableH2 { host: request.host.clone(), port: request.port, sender, _driver: driver });
        }
        let sender = session.as_ref().unwrap().sender.clone();
        match exchange_h2(sender, &request).await {
            Ok(response) => {
                self.store_cookies(&request.host, &response.headers);
                Ok(response)
            }
            Err(error) => {
                *session = None;
                Err(error)
            }
        }
    }

    pub(crate) fn store_cookies(&self, request_host: &str, headers: &HeaderMap) {
        for value in headers.get_all(http::header::SET_COOKIE) {
            let Ok(value) = value.to_str() else { continue };
            let mut parts = value.split(';');
            let Some((name, cookie_value)) = parts.next().and_then(|pair| pair.trim().split_once('=')) else { continue };
            if name.is_empty() || cookie_value.len() > 4096 {
                continue;
            }
            let mut domain = request_host.to_ascii_lowercase();
            let mut path = "/".to_string();
            let mut max_age = None;
            let mut expires = None;
            for attribute in parts {
                let (key, value) = attribute.trim().split_once('=').unwrap_or((attribute.trim(), ""));
                if key.eq_ignore_ascii_case("domain") && domain_matches(request_host, value.trim_start_matches('.')) {
                    domain = value.trim_start_matches('.').to_ascii_lowercase();
                } else if key.eq_ignore_ascii_case("path") && value.starts_with('/') {
                    path = value.to_string();
                } else if key.eq_ignore_ascii_case("max-age") {
                    max_age = value.parse::<i64>().ok();
                } else if key.eq_ignore_ascii_case("expires") {
                    expires = httpdate::parse_http_date(value).ok();
                }
            }
            let now = SystemTime::now();
            let expires_at = match max_age {
                Some(age) if age <= 0 => Some(now),
                Some(age) => now.checked_add(Duration::from_secs(age as u64)),
                None => expires,
            };
            let key = format!("{domain}|{path}|{name}");
            if cookie_value.is_empty() || expires_at.is_some_and(|expiry| expiry <= now) {
                self.cookies.lock().remove(&key);
            } else {
                self.cookies.lock().insert(key, Cookie {
                    domain,
                    path,
                    name: name.to_string(),
                    value: cookie_value.to_string(),
                    expires_at,
                });
            }
        }
    }
}

fn firefox_release_major(body: &[u8]) -> Option<u16> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let release = value.get("LATEST_FIREFOX_VERSION")?.as_str()?.trim();
    if release.len() > 24 {
        return None;
    }
    let parts: Vec<_> = release.split('.').collect();
    if !(2..=4).contains(&parts.len()) || parts.iter().any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit())) {
        return None;
    }
    let major = parts[0].parse::<u16>().ok()?;
    (1..=999).contains(&major).then_some(major)
}

fn has_header(request: &ControlRequest, name: &str) -> bool {
    request.headers.iter().any(|(key, _)| key.as_str().eq_ignore_ascii_case(name))
}

fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    let path = request_path.split('?').next().unwrap_or(request_path);
    if cookie_path == "/" || path == cookie_path {
        return true;
    }
    path.strip_prefix(cookie_path).is_some_and(|suffix| {
        !suffix.is_empty() && (cookie_path.ends_with('/') || suffix.starts_with('/'))
    })
}

fn domain_matches(host: &str, domain: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.trim_start_matches('.').trim_end_matches('.').to_ascii_lowercase();
    host == domain || host.strip_suffix(&domain).is_some_and(|prefix| prefix.ends_with('.'))
}

fn relay_request(request: &ControlRequest, relay: &Url) -> Result<ControlRequest> {
    let authority = if request.port == 443 { request.host.clone() }
        else { crate::types::authority(&request.host, request.port) };
    let target = format!("https://{authority}{}", request.path);
    let mut url = relay.clone();
    url.query_pairs_mut().append_pair("url", &target);
    let mut forwarded = ControlRequest::new(request.method.clone(), url.as_str())?;
    forwarded.headers = request.headers.iter().filter(|(name, _)| name.as_str() != "host").cloned().collect();
    forwarded.body = request.body.clone();
    Ok(forwarded)
}

fn should_relay_region_rejection(request: &ControlRequest, status: u16) -> bool {
    status == 451 && (request.method == Method::GET || request.method == Method::HEAD)
}

fn relay_target_allowed(request: &ControlRequest) -> bool {
    request.port == 443 && ["mozilla.org", "mozilla.com", "firefox.com", "github.com", "githubusercontent.com", "jsdelivr.net"]
        .iter().any(|domain| domain_matches(&request.host, domain))
}

fn is_relay_response(headers: &HeaderMap) -> bool {
    ["x-fcae-relay", "x-arman-relay"].iter()
        .any(|name| headers.get(*name).is_some_and(|value| value == "1"))
}

fn log_http_status(host: &str, response: &ControlResponse, relayed: bool) {
    if response.status >= 400 {
        log::warn!("[firefox] service HTTP {} host={} route={}", response.status, host,
            if relayed { "relay" } else { "direct" });
    }
}

struct ConnectionDriver(tokio::task::JoinHandle<()>);

impl Drop for ConnectionDriver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct ReusableH2 {
    host: String,
    port: u16,
    sender: h2::client::SendRequest<Bytes>,
    _driver: ConnectionDriver,
}

async fn over_h2(tls: SslStream<TcpStream>, request: &ControlRequest) -> Result<ControlResponse> {
    let mut builder = h2::client::Builder::new();
    builder.enable_push(false).max_header_list_size(MAX_HEADER_LIST);
    let (client, connection) = builder.handshake(tls).await.map_err(h2_error)?;
    let driver = ConnectionDriver(tokio::spawn(async move { let _ = connection.await; }));
    let result = exchange_h2(client, request).await;
    drop(driver);
    result
}

async fn exchange_h2(client: h2::client::SendRequest<Bytes>, request: &ControlRequest) -> Result<ControlResponse> {
    let mut client = client.ready().await.map_err(h2_error)?;
    let authority = if request.port == 443 { request.host.clone() } else { crate::types::authority(&request.host, request.port) };
    let uri = format!("https://{authority}{}", request.path);
    let mut head = http::Request::builder().method(request.method.clone()).uri(uri);
    for (name, value) in &request.headers {
        head = head.header(name, value);
    }
    if let Some(body) = &request.body {
        head = head.header(http::header::CONTENT_LENGTH, body.len());
    }
    let head = head.body(()).map_err(|error| FirefoxError::Protocol(error.to_string()))?;
    let (answer, mut stream) = client.send_request(head, request.body.is_none()).map_err(h2_error)?;
    if let Some(body) = &request.body {
        stream.send_data(Bytes::copy_from_slice(body), true).map_err(h2_error)?;
    }
    let (parts, mut body) = answer.await.map_err(h2_error)?.into_parts();
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(h2_error)?;
        if data.len().saturating_add(chunk.len()) > MAX_BODY {
            return Err(FirefoxError::Protocol("control-plane response is too large".into()));
        }
        data.extend_from_slice(&chunk);
        let _ = body.flow_control().release_capacity(chunk.len());
    }
    Ok(ControlResponse { status: parts.status.as_u16(), headers: parts.headers, body: data })
}

pub(crate) async fn over_h1<S>(mut tls: S, request: &ControlRequest) -> Result<ControlResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let host = if request.port == 443 { request.host.clone() } else { crate::types::authority(&request.host, request.port) };
    let mut head = format!("{} {} HTTP/1.1\r\nHost: {host}\r\n", request.method, request.path);
    for (name, value) in &request.headers {
        head.push_str(name.as_str());
        head.push_str(": ");
        head.push_str(value.to_str().map_err(|_| FirefoxError::Protocol("non-ASCII HTTP header".into()))?);
        head.push_str("\r\n");
    }
    if let Some(body) = &request.body {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("Connection: close\r\n\r\n");
    let mut wire = head.into_bytes();
    if let Some(body) = &request.body {
        wire.extend_from_slice(body);
    }
    tls.write_all(&wire).await?;
    tls.flush().await?;

    let mut raw = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        let read = tls.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        if raw.len().saturating_add(read) > MAX_RESPONSE {
            return Err(FirefoxError::Protocol("control-plane response is too large".into()));
        }
        raw.extend_from_slice(&chunk[..read]);
        if h1_response_complete(&raw, request.method == Method::HEAD)? {
            break;
        }
    }
    parse_h1_response(&raw, request.method == Method::HEAD)
}

fn h1_response_complete(raw: &[u8], is_head: bool) -> Result<bool> {
    let Some(split) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(false);
    };
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut response = httparse::Response::new(&mut headers);
    if !matches!(response.parse(&raw[..split + 4])
        .map_err(|error| FirefoxError::Protocol(error.to_string()))?, httparse::Status::Complete(_)) {
        return Ok(false);
    }
    let status = response.code.ok_or_else(|| FirefoxError::Protocol("HTTP response has no status".into()))?;
    if status / 100 == 1 {
        return Err(FirefoxError::Protocol("unexpected interim-only HTTP response".into()));
    }
    if is_head || status == 204 || status == 304 {
        return Ok(true);
    }
    let mut length = None;
    let mut chunked = false;
    for field in response.headers.iter() {
        if field.name.eq_ignore_ascii_case("transfer-encoding") {
            chunked |= std::str::from_utf8(field.value).ok()
                .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        } else if field.name.eq_ignore_ascii_case("content-length") {
            let value = std::str::from_utf8(field.value).ok().and_then(|v| v.trim().parse::<usize>().ok())
                .ok_or_else(|| FirefoxError::Protocol("invalid HTTP content length".into()))?;
            if length.is_some_and(|previous| previous != value) {
                return Err(FirefoxError::Protocol("conflicting HTTP content lengths".into()));
            }
            length = Some(value);
        }
    }
    let body = &raw[split + 4..];
    if chunked {
        return h1_chunked_complete(body);
    }
    match length {
        Some(value) if value > MAX_BODY => Err(FirefoxError::Protocol("control-plane response is too large".into())),
        Some(value) => Ok(body.len() >= value),
        None => Ok(false),
    }
}

fn h1_chunked_complete(mut raw: &[u8]) -> Result<bool> {
    let mut total = 0usize;
    loop {
        let Some(end) = raw.windows(2).position(|window| window == b"\r\n") else { return Ok(false) };
        let line = std::str::from_utf8(&raw[..end]).map_err(|_| FirefoxError::Protocol("invalid chunk size".into()))?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| FirefoxError::Protocol("invalid chunk size".into()))?;
        raw = &raw[end + 2..];
        if size == 0 {
            return Ok(raw.starts_with(b"\r\n") || raw.windows(4).any(|window| window == b"\r\n\r\n"));
        }
        total = total.checked_add(size).ok_or_else(|| FirefoxError::Protocol("oversized chunk".into()))?;
        if total > MAX_BODY {
            return Err(FirefoxError::Protocol("control-plane response is too large".into()));
        }
        if raw.len() < size + 2 { return Ok(false) }
        if &raw[size..size + 2] != b"\r\n" {
            return Err(FirefoxError::Protocol("missing chunk terminator".into()));
        }
        raw = &raw[size + 2..];
    }
}

fn parse_h1_response(raw: &[u8], is_head: bool) -> Result<ControlResponse> {
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| FirefoxError::Protocol("truncated HTTP/1.1 response head".into()))?;
    let head = &raw[..split + 4];
    let body = &raw[split + 4..];
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(head).map_err(|error| FirefoxError::Protocol(error.to_string()))? {
        httparse::Status::Complete(_) => {}
        httparse::Status::Partial => return Err(FirefoxError::Protocol("truncated HTTP/1.1 response head".into())),
    }
    let status = response.code.ok_or_else(|| FirefoxError::Protocol("HTTP response has no status".into()))?;
    let mut map = HeaderMap::new();
    let mut chunked = false;
    let mut content_length = None;
    for field in response.headers.iter() {
        let name = HeaderName::from_bytes(field.name.as_bytes()).map_err(|_| FirefoxError::Protocol("invalid response header name".into()))?;
        let value = HeaderValue::from_bytes(field.value).map_err(|_| FirefoxError::Protocol("invalid response header value".into()))?;
        if name == http::header::TRANSFER_ENCODING && value.to_str().ok().is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
            chunked = true;
        }
        if name == http::header::CONTENT_LENGTH {
            content_length = value.to_str().ok().and_then(|v| v.parse::<usize>().ok());
        }
        map.append(name, value);
    }
    if status / 100 == 1 {
        return Err(FirefoxError::Protocol("unexpected interim-only HTTP response".into()));
    }
    let body = if is_head || status == 204 || status == 304 { Vec::new() } else if chunked { dechunk(body)? } else {
        let length = content_length.unwrap_or(body.len());
        if body.len() < length {
            return Err(FirefoxError::Protocol("truncated HTTP response body".into()));
        }
        body[..length].to_vec()
    };
    if body.len() > MAX_BODY {
        return Err(FirefoxError::Protocol("control-plane response is too large".into()));
    }
    Ok(ControlResponse { status, headers: map, body })
}

fn dechunk(mut raw: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let end = raw.windows(2).position(|window| window == b"\r\n")
            .ok_or_else(|| FirefoxError::Protocol("truncated chunk size".into()))?;
        let line = std::str::from_utf8(&raw[..end]).map_err(|_| FirefoxError::Protocol("invalid chunk size".into()))?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| FirefoxError::Protocol("invalid chunk size".into()))?;
        raw = &raw[end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if size > MAX_BODY || out.len().saturating_add(size) > MAX_BODY || raw.len() < size + 2 {
            return Err(FirefoxError::Protocol("invalid or oversized chunk".into()));
        }
        out.extend_from_slice(&raw[..size]);
        if &raw[size..size + 2] != b"\r\n" {
            return Err(FirefoxError::Protocol("missing chunk terminator".into()));
        }
        raw = &raw[size + 2..];
    }
}

fn h2_error(error: h2::Error) -> FirefoxError {
    FirefoxError::H2(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_preserves_target_request_without_forwarding_host() {
        let request = ControlRequest::new(Method::POST, "https://vpn.mozilla.org/api/v1/fpn/activate?x=1").unwrap()
            .header("authorization", "Bearer sensitive").unwrap()
            .header("host", "vpn.mozilla.org").unwrap()
            .json(&serde_json::json!({"test": true})).unwrap();
        let relay = Url::parse("https://relay.example/path?secret=private").unwrap();
        let forwarded = relay_request(&request, &relay).unwrap();
        assert_eq!(forwarded.method, request.method);
        assert_eq!(forwarded.body, request.body);
        assert_eq!(forwarded.host, "relay.example");
        assert!(forwarded.headers.iter().any(|(key, _)| key.as_str() == "authorization"));
        assert!(!forwarded.headers.iter().any(|(key, _)| key.as_str() == "host"));
        let url = Url::parse(&format!("https://{}{}", forwarded.host, forwarded.path)).unwrap();
        let pairs: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(pairs.get("secret").map(String::as_str), Some("private"));
        assert_eq!(pairs.get("url").map(String::as_str), Some("https://vpn.mozilla.org/api/v1/fpn/activate?x=1"));
    }

    #[test]
    fn region_recovery_only_replays_safe_requests() {
        let get = ControlRequest::new(Method::GET, "https://vpn.mozilla.org/api/v1/fpn/token").unwrap();
        let post = ControlRequest::new(Method::POST, "https://vpn.mozilla.org/api/v1/fpn/activate").unwrap();
        assert!(should_relay_region_rejection(&get, 451));
        assert!(!should_relay_region_rejection(&get, 404));
        assert!(!should_relay_region_rejection(&get, 405));
        assert!(!should_relay_region_rejection(&post, 451));
    }

    #[test]
    fn relay_markers_require_the_expected_value_and_hide_error_bodies() {
        let mut response = ControlResponse { status: 404, headers: HeaderMap::new(), body: b"secret in response".to_vec() };
        response.headers.insert("x-fcae-relay", HeaderValue::from_static("1"));
        assert!(is_relay_response(&response.headers));
        assert!(!response.message().contains("secret"));
        response.headers.insert("x-fcae-relay", HeaderValue::from_static("0"));
        assert!(!is_relay_response(&response.headers));
        response.headers.insert("x-arman-relay", HeaderValue::from_static("1"));
        assert!(is_relay_response(&response.headers));
    }

    #[test]
    fn relay_targets_are_restricted_to_service_hosts() {
        for host in ["vpn.mozilla.org", "api.accounts.firefox.com", "raw.githubusercontent.com"] {
            assert!(relay_target_allowed(&ControlRequest::new(Method::GET, &format!("https://{host}/")).unwrap()));
        }
        for host in ["notmozilla.org", "vpn.mozilla.org.example.com", "example.com"] {
            assert!(!relay_target_allowed(&ControlRequest::new(Method::GET, &format!("https://{host}/")).unwrap()));
        }
        assert!(!relay_target_allowed(&ControlRequest::new(Method::GET, "https://vpn.mozilla.org:8443/").unwrap()));
    }

    #[test]
    fn release_version_is_validated() {
        assert_eq!(firefox_release_major(br#"{"LATEST_FIREFOX_VERSION":"159.0.1"}"#), Some(159));
        assert_eq!(firefox_release_major(br#"{"LATEST_FIREFOX_VERSION":"160.0"}"#), Some(160));
        for body in [
            &b"{}"[..],
            &br#"{"LATEST_FIREFOX_VERSION":""}"#[..],
            &br#"{"LATEST_FIREFOX_VERSION":"159.0a1"}"#[..],
            &br#"{"LATEST_FIREFOX_VERSION":"0.0"}"#[..],
            &br#"{"LATEST_FIREFOX_VERSION":"1000.0"}"#[..],
            &br#"{"LATEST_FIREFOX_VERSION":"159..0"}"#[..],
        ] {
            assert_eq!(firefox_release_major(body), None);
        }
    }

    #[test]
    fn h1_framing_completes_without_a_connection_close() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n";
        assert!(!h1_response_complete(head, false).unwrap());
        assert!(h1_response_complete(&[&head[..], b"abc"].concat(), false).unwrap());
        assert!(h1_response_complete(head, true).unwrap());
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n";
        assert!(!h1_response_complete(chunked, false).unwrap());
        assert!(h1_response_complete(&[&chunked[..], b"\r\n"].concat(), false).unwrap());
        assert!(h1_response_complete(&[&chunked[..], b"X-Foo: bar\r\n\r\n"].concat(), false).unwrap());
        assert!(!h1_response_complete(b"HTTP/1.1 200 OK\r\n\r\nabc", false).unwrap());
        assert!(h1_response_complete(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n", false).is_err());
    }

    #[tokio::test]
    async fn h1_returns_a_framed_response_while_the_peer_is_still_open() {
        let (client, mut server) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            let mut request = [0; 1024];
            server.read(&mut request).await.unwrap();
            server.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc").await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let request = ControlRequest::new(Method::GET, "https://example.com/").unwrap();
        let response = tokio::time::timeout(Duration::from_secs(1), over_h1(client, &request))
            .await.unwrap().unwrap();
        assert_eq!(response.body, b"abc");
        peer.abort();
    }

    #[test]
    fn head_response_does_not_require_the_advertised_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\nX-Quota-Limit: 100\r\n\r\n";
        let response = parse_h1_response(raw, true).unwrap();
        assert!(response.body.is_empty());
        assert_eq!(response.headers.get("x-quota-limit").unwrap(), "100");
        assert!(parse_h1_response(raw, false).is_err());
    }

    #[test]
    fn challenge_cookie_is_sent_only_while_valid() {
        let control = ControlPlane::new(Dialer::new(None, None, 10).unwrap());
        let response = parse_h1_response(b"HTTP/1.1 200 OK\r\nSet-Cookie: _fs_ch_st_test=state; Max-Age=10; Path=/\r\nContent-Length: 0\r\n\r\n", false).unwrap();
        control.store_cookies("accounts.firefox.com", &response.headers);
        let request = ControlRequest::new(Method::GET, "https://accounts.firefox.com/_fs-ch-test/script.js?reload=true").unwrap();
        let decorated = control.decorate(request.clone());
        assert!(decorated.headers.iter().any(|(name, value)| name.as_str() == "cookie" && value.to_str().ok() == Some("_fs_ch_st_test=state")));
        let mut cookies = control.cookies.lock();
        for cookie in cookies.values_mut() {
            cookie.expires_at = Some(std::time::UNIX_EPOCH);
        }
        drop(cookies);
        assert!(!control.has_cookies());
        assert!(!control.decorate(request).headers.iter().any(|(name, _)| name.as_str() == "cookie"));
    }

    #[test]
    fn max_age_takes_precedence_and_expired_cookies_are_removed() {
        let control = ControlPlane::new(Dialer::new(None, None, 10).unwrap());
        let mut headers = HeaderMap::new();
        headers.append(http::header::SET_COOKIE, "state=ok; Max-Age=10; Expires=Wed, 01 Jan 2020 00:00:00 GMT; Path=/".parse().unwrap());
        control.store_cookies("accounts.firefox.com", &headers);
        assert!(control.has_cookies());
        headers.clear();
        headers.append(http::header::SET_COOKIE, "state=old; Max-Age=-1; Path=/".parse().unwrap());
        control.store_cookies("accounts.firefox.com", &headers);
        assert!(!control.has_cookies());
    }

    #[test]
    fn fresh_challenge_jar_uses_same_agent_and_encoding() {
        let mut control = ControlPlane::new(Dialer::new(None, None, 10).unwrap());
        control.user_agent = firefox_user_agent_for_major(160);
        let request = ControlRequest::new(Method::POST, "https://api.accounts.firefox.com/v1/account/login").unwrap();
        let decorated = control.decorate(request.clone());
        let solver_request = control.fresh_jar().decorate(request);
        for request in [&decorated, &solver_request] {
            let agent = request.headers.iter().find(|(name, _)| name.as_str() == "user-agent").unwrap().1.to_str().unwrap();
            let encoding = request.headers.iter().find(|(name, _)| name.as_str() == "accept-encoding").unwrap().1.to_str().unwrap();
            assert_eq!(agent, control.user_agent.as_str());
            assert_eq!(encoding, "identity");
        }
    }
}
