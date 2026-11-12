use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use parking_lot::{Mutex, RwLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_boring::SslStream;
use url::Url;

use crate::dialer::Dialer;
use crate::error::{FirefoxError, Result};
use crate::store::AccountStore;
use crate::tls::{firefox_user_agent, firefox_user_agent_for_major, ALPN_H1, ALPN_H2, ALPN_H2_H1};
use crate::types::TransportPreference;

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
    secure: bool,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Option<Vec<u8>>,
}

impl ControlRequest {
    pub fn new(method: Method, raw_url: &str) -> Result<Self> {
        Self::from_url(method, raw_url, false)
    }

    fn from_url(method: Method, raw_url: &str, relay: bool) -> Result<Self> {
        let url = Url::parse(raw_url)?;
        let secure = url.scheme() == "https";
        if (!secure && !(relay && url.scheme() == "http")) || url.host_str().is_none()
            || !url.username().is_empty() || url.password().is_some() {
            return Err(FirefoxError::InvalidConfig("invalid control-plane URL".into()));
        }
        let host = url.host_str().unwrap().trim_matches(['[', ']']).to_string();
        let port = url.port_or_known_default().ok_or_else(|| FirefoxError::InvalidConfig("URL has no port".into()))?;
        let path = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None if url.path().is_empty() => "/".into(),
            None => url.path().to_string(),
        };
        Ok(Self { method, host, port, path, secure, headers: Vec::new(), body: None })
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
    transport: Arc<RwLock<TransportPreference>>,
}

impl ControlPlane {
    pub fn new(dialer: Dialer) -> Self {
        Self {
            dialer, timeout: Duration::from_secs(20), user_agent: firefox_user_agent(),
            cookies: Arc::new(Mutex::new(BTreeMap::new())), challenge_h2: None, relay_store: None,
            transport: Arc::new(RwLock::new(TransportPreference::Auto)),
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
            transport: self.transport.clone(),
        }
    }

    pub fn with_transport(self, transport: TransportPreference) -> Self {
        self.set_transport(transport);
        self
    }

    pub fn set_transport(&self, transport: TransportPreference) {
        *self.transport.write() = transport;
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

    pub(crate) async fn send_via_relay(&self, request: ControlRequest) -> Result<ControlResponse> {
        let request = self.decorate(request);
        if !relay_target_allowed(&request) {
            return Err(FirefoxError::InvalidConfig("relay target is not allowed".into()));
        }
        let relay = match &self.relay_store {
            Some(store) => store.relay_url()?,
            None => None,
        }.ok_or_else(|| FirefoxError::InvalidConfig("Firefox relay is not configured".into()))?;
        let transport = *self.transport.read();
        if transport == TransportPreference::H3 { return Err(FirefoxError::H3Unavailable); }
        tokio::time::timeout(self.timeout, self.exchange_relay(&request, &relay, transport))
            .await.map_err(|_| FirefoxError::Timeout(self.timeout))?
    }

    async fn send_inner(&self, request: ControlRequest) -> Result<ControlResponse> {
        let transport = *self.transport.read();
        if transport == TransportPreference::H3 { return Err(FirefoxError::H3Unavailable); }
        let relay = match &self.relay_store {
            Some(store) if relay_target_allowed(&request) => store.relay_url()?,
            _ => None,
        };
        let Some(relay) = relay else {
            let response = if let Some(pool) = self.challenge_h2.as_ref().filter(|_| transport != TransportPreference::H1) {
                self.exchange_challenge(request, pool, transport).await
            } else {
                self.exchange(request, transport).await
            };
            if let Err(error) = &response {
                log::warn!("[firefox] (mode={}) direct request failed: {}", transport.as_str(), direct_failure_detail(error));
            }
            return response;
        };
        let safe = request.method == Method::GET || request.method == Method::HEAD;
        let direct = if let Some(pool) = self.challenge_h2.as_ref().filter(|_| transport != TransportPreference::H1) {
            // A challenge session may have transmitted the request when it fails.
            if safe {
                tokio::time::timeout(Duration::from_secs(8), self.exchange_challenge(request.clone(), pool, transport))
                    .await.unwrap_or_else(|_| Err(FirefoxError::Timeout(Duration::from_secs(8))))
            } else {
                self.exchange_challenge(request.clone(), pool, transport).await
            }
        } else {
            // Only the connection is timed here; no request bytes have been sent yet.
            match tokio::time::timeout(Duration::from_secs(4),
                connect_control(&self.dialer, &request.host, request.port, transport)).await {
                Ok(Ok(tls)) => {
                    let is_h2 = tls.ssl().selected_alpn_protocol() == Some(b"h2");
                    if transport == TransportPreference::H2 && !is_h2 {
                        log::warn!("[firefox] (h2) direct service did not negotiate HTTP/2; trying the configured relay");
                        return self.exchange_relay(&request, &relay, transport).await;
                    }
                    let exchange = self.exchange_tls(tls, &request, transport, "direct");
                    let result = if safe {
                        tokio::time::timeout(Duration::from_secs(8), exchange)
                            .await.unwrap_or_else(|_| Err(FirefoxError::Timeout(Duration::from_secs(8))))
                    } else {
                        exchange.await
                    };
                    if let Ok(response) = &result {
                        self.store_cookies(&request.host, &response.headers);
                    }
                    result
                },
                Ok(Err(error @ FirefoxError::TlsCertificate { .. })) => {
                    log::warn!("[firefox] (mode={}) direct service connection failed: {}; not bypassing certificate verification", transport.as_str(), direct_failure_detail(&error));
                    return Err(error);
                }
                Ok(Err(error)) => {
                    log::warn!("[firefox] (mode={}) direct service connection failed: {}; trying the configured relay", transport.as_str(), direct_failure_detail(&error));
                    return self.exchange_relay(&request, &relay, transport).await;
                }
                Err(_) => {
                    log::warn!("[firefox] (mode={}) direct service connection failed: timeout after 4s; trying the configured relay", transport.as_str());
                    return self.exchange_relay(&request, &relay, transport).await;
                }
            }
        };
        match direct {
            Ok(response) => {
                if should_relay_response(&request, response.status) {
                    log::warn!("[firefox] service returned HTTP {}; trying the configured relay", response.status);
                    match self.exchange_relay(&request, &relay, transport).await {
                        Ok(relayed) => Ok(relayed),
                        Err(error) => {
                            log::warn!("[firefox] relay retry failed reason={}; keeping the direct response", direct_failure_detail(&error));
                            Ok(response)
                        }
                    }
                } else {
                    Ok(response)
                }
            }
            Err(error @ FirefoxError::TlsCertificate { .. }) => {
                log::warn!("[firefox] (mode={}) direct request failed: {}; not bypassing certificate verification", transport.as_str(), direct_failure_detail(&error));
                Err(error)
            }
            Err(error) if safe => {
                log::warn!("[firefox] (mode={}) direct request failed: {}; trying the configured relay", transport.as_str(), direct_failure_detail(&error));
                self.exchange_relay(&request, &relay, transport).await
            }
            Err(error) => {
                log::warn!("[firefox] (mode={}) direct request failed: {}", transport.as_str(), direct_failure_detail(&error));
                Err(error)
            },
        }
    }

    async fn exchange_relay(&self, request: &ControlRequest, relay: &Url, transport: TransportPreference) -> Result<ControlResponse> {
        let forwarded = relay_request(request, relay)?;
        let response = async {
            if forwarded.secure {
                let tls = connect_control(&self.dialer, &forwarded.host, forwarded.port, transport).await?;
                let is_h2 = tls.ssl().selected_alpn_protocol() == Some(b"h2");
                if transport == TransportPreference::H2 && !is_h2 {
                    log::warn!("[firefox] (h2) relay did not negotiate HTTP/2");
                    return Err(FirefoxError::Protocol("relay did not negotiate HTTP/2".into()));
                }
                self.exchange_tls(tls, &forwarded, transport, "relay").await
            } else if transport == TransportPreference::H1 {
                let stream = self.dialer.connect_tcp(&forwarded.host, forwarded.port).await?;
                logged_h1(stream, &forwarded, "relay").await
            } else {
                let stream = self.dialer.connect_tcp(&forwarded.host, forwarded.port).await?;
                match open_h2(stream, true).await {
                    Ok((sender, driver)) => {
                        let response = logged_h2(sender, &forwarded, "relay").await;
                        drop(driver);
                        if transport == TransportPreference::Auto && matches!(&response, Err(FirefoxError::H2(_)))
                            && (request.method == Method::GET || request.method == Method::HEAD) {
                            let stream = self.dialer.connect_tcp(&forwarded.host, forwarded.port).await?;
                            logged_h1(stream, &forwarded, "relay").await
                        } else {
                            response
                        }
                    }
                    Err(error) if transport == TransportPreference::Auto => {
                        log::warn!("[firefox] (h2) relay setup failed reason={}; trying (h1)", error.reason_code());
                        let stream = self.dialer.connect_tcp(&forwarded.host, forwarded.port).await?;
                        logged_h1(stream, &forwarded, "relay").await
                    }
                    Err(error) => {
                        log::warn!("[firefox] (h2) relay setup failed reason={}", error.reason_code());
                        Err(error)
                    },
                }
            }
        }.await.map_err(|error| {
            log::warn!("[firefox] relay request failed reason={}", direct_failure_detail(&error));
            error
        })?;
        if response.headers.contains_key("x-relay-error") ||
            (response.status >= 400 && !is_relay_response(&response.headers)) {
            return Err(FirefoxError::Protocol(format!("relay or service request failed (HTTP {})", response.status)));
        }
        self.store_cookies(&request.host, &response.headers);
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

    async fn exchange(&self, request: ControlRequest, transport: TransportPreference) -> Result<ControlResponse> {
        let tls = connect_control(&self.dialer, &request.host, request.port, transport).await?;
        let response = self.exchange_tls(tls, &request, transport, "direct").await?;
        self.store_cookies(&request.host, &response.headers);
        Ok(response)
    }

    async fn exchange_tls(&self, tls: SslStream<TcpStream>, request: &ControlRequest, transport: TransportPreference, route: &'static str) -> Result<ControlResponse> {
        let is_h2 = tls.ssl().selected_alpn_protocol() == Some(b"h2");
        if !is_h2 {
            if transport == TransportPreference::H2 {
                return Err(FirefoxError::Protocol("peer did not negotiate HTTP/2".into()));
            }
            return logged_h1(tls, request, route).await;
        }
        let opened = open_h2(tls, transport == TransportPreference::Auto).await;
        let error = match opened {
            Ok((sender, driver)) => {
                let result = logged_h2(sender, request, route).await;
                drop(driver);
                match result {
                    Err(error @ FirefoxError::H2(_)) if transport == TransportPreference::Auto
                        && (request.method == Method::GET || request.method == Method::HEAD) => error,
                    result => return result,
                }
            }
            Err(error) if transport != TransportPreference::Auto => {
                log::warn!("[firefox] (h2) control setup failed route={} reason={}", route, error.reason_code());
                return Err(error);
            }
            Err(error) => error,
        };
        log::warn!("[firefox] (h2) control request failed route={} reason={}; trying (h1)", route, error.reason_code());
        let tls = connect_control(&self.dialer, &request.host, request.port, TransportPreference::H1).await?;
        logged_h1(tls, request, route).await
    }

    async fn exchange_challenge(
        &self,
        request: ControlRequest,
        pool: &tokio::sync::Mutex<Option<ReusableH2>>,
        transport: TransportPreference,
    ) -> Result<ControlResponse> {
        let mut session = pool.lock().await;
        if session.as_ref().is_some_and(|current| current.host != request.host || current.port != request.port) {
            *session = None;
        }
        if session.is_none() {
            let tls = match connect_control(&self.dialer, &request.host, request.port, transport).await {
                Ok(tls) => tls,
                Err(error) => return Err(error),
            };
            if tls.ssl().selected_alpn_protocol() != Some(b"h2") {
                if transport == TransportPreference::H2 {
                    return Err(FirefoxError::Protocol("Mozilla did not negotiate HTTP/2".into()));
                }
                drop(session);
                let response = logged_h1(tls, &request, "direct").await?;
                self.store_cookies(&request.host, &response.headers);
                return Ok(response);
            }
            let mut builder = h2::client::Builder::new();
            builder.enable_push(false).max_header_list_size(MAX_HEADER_LIST);
            let (sender, connection) = match builder.handshake(tls).await {
                Ok(connection) => connection,
                Err(error) => {
                    let error = h2_error(error);
                    if transport != TransportPreference::Auto {
                        log::warn!("[firefox] (h2) challenge setup failed reason={}", error.reason_code());
                        return Err(error);
                    }
                    log::warn!("[firefox] (h2) challenge setup failed reason={}; trying (h1)", error.reason_code());
                    drop(session);
                    return self.exchange(request, TransportPreference::H1).await;
                }
            };
            let driver = ConnectionDriver(tokio::spawn(async move { let _ = connection.await; }));
            *session = Some(ReusableH2 { host: request.host.clone(), port: request.port, sender, _driver: driver });
        }
        let sender = session.as_ref().unwrap().sender.clone();
        match logged_h2(sender, &request, "direct").await {
            Ok(response) => {
                self.store_cookies(&request.host, &response.headers);
                Ok(response)
            }
            Err(error) => {
                *session = None;
                if transport == TransportPreference::Auto && matches!(&error, FirefoxError::H2(_))
                    && (request.method == Method::GET || request.method == Method::HEAD) {
                    drop(session);
                    self.exchange(request, TransportPreference::H1).await
                } else {
                    Err(error)
                }
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
    let mut forwarded = ControlRequest::from_url(request.method.clone(), url.as_str(), true)?;
    forwarded.headers = request.headers.iter().filter(|(name, _)| name.as_str() != "host").cloned().collect();
    forwarded.body = request.body.clone();
    Ok(forwarded)
}

fn should_relay_response(request: &ControlRequest, status: u16) -> bool {
    (request.method == Method::GET || request.method == Method::HEAD) &&
        (matches!(status, 403 | 404 | 405 | 408 | 451) || (500..=599).contains(&status))
}

fn relay_target_allowed(request: &ControlRequest) -> bool {
    request.port == 443 && ["mozilla.org", "mozilla.com", "firefox.com", "github.com", "githubusercontent.com", "jsdelivr.net"]
        .iter().any(|domain| domain_matches(&request.host, domain))
}

pub(crate) fn is_relay_response(headers: &HeaderMap) -> bool {
    headers.iter().any(|(name, value)| {
        let name = name.as_str();
        name.starts_with("x-") && name.ends_with("-relay") && value == "1"
    })
}

pub(crate) fn direct_failure_detail(error: &FirefoxError) -> String {
    let detail = match error {
        FirefoxError::Timeout(duration) => format!("timeout after {duration:?}"),
        FirefoxError::Dns { message, .. } => format!("DNS: {message}"),
        FirefoxError::Tls { message, .. } | FirefoxError::TlsCertificate { message, .. } => format!("TLS: {message}"),
        FirefoxError::Network(message) => format!("network: {message}"),
        FirefoxError::H2(message) => format!("HTTP/2: {message}"),
        FirefoxError::Protocol(message) => format!("protocol: {message}"),
        FirefoxError::Http { status, .. } => format!("HTTP {status}"),
        _ => error.reason_code().to_string(),
    };
    detail.chars().map(|c| if c.is_control() { ' ' } else { c }).take(256).collect()
}

pub(crate) fn diagnostic_error_message(bytes: &[u8]) -> String {
    fn bounded(message: &str) -> String {
        message.chars().map(|c| if c.is_control() { ' ' } else { c })
            .take(256).collect::<String>().trim().to_string()
    }
    let body = match std::str::from_utf8(bytes) {
        Ok(body) => body.trim(),
        Err(_) => return String::new(),
    };
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        for key in ["message", "error", "detail"] {
            if let Some(message) = value.get(key).and_then(serde_json::Value::as_str) {
                return bounded(message);
            }
        }
        String::new()
    } else if !body.starts_with('<') && !body.starts_with('{') && !body.starts_with('[') {
        bounded(body)
    } else {
        String::new()
    }
}

fn direct_response_message(response: &ControlResponse) -> String {
    diagnostic_error_message(&response.body)
}

fn log_control_exchange(route: &str, host: &str, protocol: &str, result: &Result<ControlResponse>) {
    let host = if route == "relay" { "relay" } else { host };
    match result {
        Ok(response) if response.status >= 400 => {
            let message = direct_response_message(response);
            if message.is_empty() {
                log::warn!("[firefox] ({}) {} request failed: HTTP {} host={}", protocol, route, response.status, host);
            } else {
                log::warn!("[firefox] ({}) {} request failed: HTTP {} host={} message={}", protocol, route, response.status, host, message);
            }
        }
        Ok(response) => log::info!("[firefox] ({}) control HTTP {} route={} host={}", protocol, response.status, route, host),
        Err(error) => log::warn!("[firefox] ({}) control request failed route={} host={} reason={}", protocol, route, host, direct_failure_detail(error)),
    }
}

async fn logged_h1<S>(stream: S, request: &ControlRequest, route: &str) -> Result<ControlResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let result = over_h1(stream, request).await;
    log_control_exchange(route, &request.host, "h1", &result);
    result
}

async fn logged_h2(sender: h2::client::SendRequest<Bytes>, request: &ControlRequest, route: &str) -> Result<ControlResponse> {
    let result = exchange_h2(sender, request).await;
    log_control_exchange(route, &request.host, "h2", &result);
    result
}

pub(crate) struct ConnectionDriver(tokio::task::JoinHandle<()>);

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

pub(crate) fn control_alpn(transport: TransportPreference) -> &'static [u8] {
    match transport {
        TransportPreference::H1 => ALPN_H1,
        TransportPreference::H2 => ALPN_H2,
        TransportPreference::Auto => ALPN_H2_H1,
        TransportPreference::H3 => ALPN_H2,
    }
}

async fn connect_control(dialer: &Dialer, host: &str, port: u16, transport: TransportPreference) -> Result<SslStream<TcpStream>> {
    match crate::tls::connect(dialer, host, port, control_alpn(transport)).await {
        Err(FirefoxError::TlsCertificate { host, message }) => Err(FirefoxError::TlsCertificate { host, message }),
        Err(_) if transport == TransportPreference::Auto => crate::tls::connect(dialer, host, port, ALPN_H1).await,
        result => result,
    }
}

pub(crate) async fn open_h2<S>(stream: S, probe: bool) -> Result<(h2::client::SendRequest<Bytes>, ConnectionDriver)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = h2::client::Builder::new();
    builder.enable_push(false).max_header_list_size(MAX_HEADER_LIST);
    let (client, mut connection) = builder.handshake(stream).await.map_err(h2_error)?;
    let mut ping = if probe { connection.ping_pong() } else { None };
    let driver = ConnectionDriver(tokio::spawn(async move { let _ = connection.await; }));
    if probe {
        let ping = ping.as_mut().ok_or_else(|| FirefoxError::Protocol("HTTP/2 probe unavailable".into()))?;
        tokio::time::timeout(Duration::from_secs(3), ping.ping(h2::Ping::opaque()))
            .await.map_err(|_| FirefoxError::Timeout(Duration::from_secs(3)))?.map_err(h2_error)?;
    }
    Ok((client, driver))
}

struct H2ExchangeGuard(Option<h2::SendStream<Bytes>>);

impl Drop for H2ExchangeGuard {
    fn drop(&mut self) {
        if let Some(stream) = &mut self.0 { stream.send_reset(h2::Reason::CANCEL); }
    }
}

pub(crate) async fn exchange_h2(client: h2::client::SendRequest<Bytes>, request: &ControlRequest) -> Result<ControlResponse> {
    let mut client = client.ready().await.map_err(h2_error)?;
    let default_port = if request.secure { 443 } else { 80 };
    let authority = if request.port == default_port && !request.host.contains(':') { request.host.clone() }
        else { crate::types::authority(&request.host, request.port) };
    let scheme = if request.secure { "https" } else { "http" };
    let uri = format!("{scheme}://{authority}{}", request.path);
    let mut head = http::Request::builder().method(request.method.clone()).uri(uri);
    for (name, value) in &request.headers {
        head = head.header(name, value);
    }
    if let Some(body) = &request.body {
        head = head.header(http::header::CONTENT_LENGTH, body.len());
    }
    let head = head.body(()).map_err(|error| FirefoxError::Protocol(error.to_string()))?;
    let (answer, stream) = client.send_request(head, request.body.is_none()).map_err(h2_error)?;
    let mut guard = H2ExchangeGuard(Some(stream));
    if let Some(body) = &request.body {
        guard.0.as_mut().expect("active HTTP/2 request").send_data(Bytes::copy_from_slice(body), true).map_err(h2_error)?;
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
    drop(guard.0.take());
    Ok(ControlResponse { status: parts.status.as_u16(), headers: parts.headers, body: data })
}

pub(crate) async fn over_h1<S>(mut tls: S, request: &ControlRequest) -> Result<ControlResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    exchange_h1(&mut tls, request, false).await.map(|(response, _)| response)
}

pub(crate) async fn exchange_h1<S>(tls: &mut S, request: &ControlRequest, persistent: bool) -> Result<(ControlResponse, bool)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let host = if (request.secure && request.port == 443) || (!request.secure && request.port == 80) {
        if request.host.contains(':') { format!("[{}]", request.host) } else { request.host.clone() }
    } else { crate::types::authority(&request.host, request.port) };
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
    head.push_str(if persistent { "Connection: keep-alive\r\n\r\n" } else { "Connection: close\r\n\r\n" });
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
    let response = parse_h1_response(&raw, request.method == Method::HEAD)?;
    let split = raw.windows(4).position(|window| window == b"\r\n\r\n");
    let close = response.headers.get_all(http::header::CONNECTION).iter().any(|value|
        value.to_str().ok().is_some_and(|text| text.split(',').any(|part| part.trim().eq_ignore_ascii_case("close"))));
    let framed = response.headers.get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok()).and_then(|value| value.trim().parse::<usize>().ok())
        .is_some_and(|length| split.is_some_and(|head| raw.len() == head + 4 + length));
    let reusable = persistent && raw.starts_with(b"HTTP/1.1 ") && !close && framed
        && !response.headers.contains_key(http::header::TRANSFER_ENCODING);
    Ok((response, reusable))
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

    #[tokio::test]
    async fn persistent_h1_reuses_only_complete_framed_responses() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            for index in 0..2 {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(server.read_u8().await.unwrap());
                }
                assert!(std::str::from_utf8(&head).unwrap().contains("Connection: keep-alive"));
                let mut body = [0u8; 3];
                server.read_exact(&mut body).await.unwrap();
                assert_eq!(&body, b"dns");
                let close = if index == 1 { "Connection: close\r\n" } else { "" };
                server.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n{close}\r\nabc").as_bytes()).await.unwrap();
            }
        });
        let mut request = ControlRequest::new(Method::POST, "https://example.com/dns-query").unwrap();
        request.body = Some(b"dns".to_vec());
        let (first, reusable) = exchange_h1(&mut client, &request, true).await.unwrap();
        assert_eq!(first.body, b"abc");
        assert!(reusable);
        let (second, reusable) = exchange_h1(&mut client, &request, true).await.unwrap();
        assert_eq!(second.body, b"abc");
        assert!(!reusable);
        task.await.unwrap();
    }

    #[test]
    fn direct_error_diagnostics_include_only_bounded_messages() {
        let response = |body: &[u8]| ControlResponse { status: 405, headers: HeaderMap::new(), body: body.to_vec() };
        assert_eq!(direct_response_message(&response(br#"{"message":"Method not allowed","token":"secret"}"#)), "Method not allowed");
        assert_eq!(direct_response_message(&response(br#"{"token":"secret"}"#)), "");
        assert_eq!(direct_response_message(&response(br#"{"error":"blocked","token":"secret"}"#)), "blocked");
        assert_eq!(direct_response_message(&response(br#"{"detail":"line one\nline two"}"#)), "line one line two");
        assert_eq!(direct_response_message(&response(&[0xff])), "");
        assert_eq!(direct_response_message(&response(b"line one\nline two")), "line one line two");
        assert_eq!(direct_response_message(&response(b"<html>private</html>")), "");
        assert_eq!(direct_response_message(&response(&vec![b'x'; 500])).len(), 256);
        assert_eq!(direct_failure_detail(&FirefoxError::Network("connection refused".into())), "network: connection refused");
        assert_eq!(direct_failure_detail(&FirefoxError::Protocol("bad response".into())), "protocol: bad response");
        assert_eq!(direct_failure_detail(&FirefoxError::H2("stream reset".into())), "HTTP/2: stream reset");
        assert_eq!(direct_failure_detail(&FirefoxError::Http { host: "example".into(), status: 405, errno: None,
            retry_after: None, message: "private body".into() }), "HTTP 405");
    }

    #[tokio::test]
    async fn relay_only_rejects_disabled_or_disallowed_routes() {
        let dir = tempfile::tempdir().unwrap();
        let store = AccountStore::new(dir.path()).unwrap();
        store.set_relay_url("").unwrap();
        let http = ControlPlane::new(Dialer::new(None, None, 10).unwrap()).with_relay_store(store);
        let activation = ControlRequest::new(Method::POST, "https://vpn.mozilla.org/api/v1/fpn/activate").unwrap();
        assert!(matches!(http.send_via_relay(activation).await, Err(FirefoxError::InvalidConfig(_))));
        let disallowed = ControlRequest::new(Method::POST, "https://example.com/").unwrap();
        assert!(matches!(http.send_via_relay(disallowed).await, Err(FirefoxError::InvalidConfig(_))));
    }

    #[test]
    fn control_transport_policy_is_shared_by_clones_and_fresh_jars() {
        assert_eq!(control_alpn(TransportPreference::Auto), ALPN_H2_H1);
        assert_eq!(control_alpn(TransportPreference::H2), ALPN_H2);
        assert_eq!(control_alpn(TransportPreference::H1), ALPN_H1);
        let parent = ControlPlane::new(Dialer::new(None, None, 10).unwrap());
        let clone = parent.clone();
        let fresh = parent.fresh_jar();
        parent.set_transport(TransportPreference::H1);
        assert_eq!(*clone.transport.read(), TransportPreference::H1);
        assert_eq!(*fresh.transport.read(), TransportPreference::H1);
        clone.set_transport(TransportPreference::H2);
        assert_eq!(*parent.transport.read(), TransportPreference::H2);
    }

    #[test]
    fn relay_preserves_target_request_without_forwarding_host() {
        let request = ControlRequest::new(Method::POST, "https://vpn.mozilla.org/api/v1/fpn/activate?x=1").unwrap()
            .header("authorization", "Bearer sensitive").unwrap()
            .header("host", "vpn.mozilla.org").unwrap()
            .json(&serde_json::json!({"test": true})).unwrap();
        let relay = Url::parse("https://relay.example/private").unwrap();
        let forwarded = relay_request(&request, &relay).unwrap();
        assert_eq!(forwarded.method, request.method);
        assert_eq!(forwarded.body, request.body);
        assert_eq!(forwarded.host, "relay.example");
        assert!(forwarded.headers.iter().any(|(key, _)| key.as_str() == "authorization"));
        assert!(!forwarded.headers.iter().any(|(key, _)| key.as_str() == "host"));
        let url = Url::parse(&format!("https://{}{}", forwarded.host, forwarded.path)).unwrap();
        let pairs: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(url.path(), "/private");
        assert_eq!(pairs.get("url").map(String::as_str), Some("https://vpn.mozilla.org/api/v1/fpn/activate?x=1"));
    }

    #[test]
    fn failed_safe_requests_can_use_the_relay() {
        let get = ControlRequest::new(Method::GET, "https://vpn.mozilla.org/api/v1/fpn/token").unwrap();
        let head = ControlRequest::new(Method::HEAD, "https://vpn.mozilla.org/api/v1/fpn/token").unwrap();
        let post = ControlRequest::new(Method::POST, "https://vpn.mozilla.org/api/v1/fpn/activate").unwrap();
        for status in [403, 404, 405, 408, 451, 500, 503] {
            assert!(should_relay_response(&get, status));
            assert!(should_relay_response(&head, status));
            assert!(!should_relay_response(&post, status));
        }
        for status in [200, 400, 401, 406, 429] {
            assert!(!should_relay_response(&get, status));
        }
    }

    #[test]
    fn relay_url_uses_path_authentication_and_supports_http() {
        let request = ControlRequest::new(Method::GET, "https://vpn.mozilla.org/api/v1/fpn/token").unwrap();
        for (relay_url, secure, port) in [
            (crate::store::DEFAULT_RELAY_URL, true, 443),
            ("http://relay.example/private", false, 80),
            ("http://relay.example:8080/private", false, 8080),
        ] {
            let forwarded = relay_request(&request, &Url::parse(relay_url).unwrap()).unwrap();
            assert_eq!(forwarded.secure, secure);
            assert_eq!(forwarded.port, port);
            assert!(forwarded.path.starts_with(if relay_url == crate::store::DEFAULT_RELAY_URL { "/fcaevpn?" } else { "/private?" }));
            assert!(!forwarded.path.contains("secret="));
        }
        assert!(ControlRequest::new(Method::GET, "http://vpn.mozilla.org/").is_err());
    }

    #[test]
    fn relay_markers_require_the_expected_value_and_hide_error_bodies() {
        let mut response = ControlResponse { status: 404, headers: HeaderMap::new(), body: b"secret in response".to_vec() };
        response.headers.insert("x-fcae-relay", HeaderValue::from_static("1"));
        assert!(is_relay_response(&response.headers));
        assert!(!response.message().contains("secret"));
        response.headers.insert("x-fcae-relay", HeaderValue::from_static("0"));
        assert!(!is_relay_response(&response.headers));
        response.headers.insert("x-example-relay", HeaderValue::from_static("1"));
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
