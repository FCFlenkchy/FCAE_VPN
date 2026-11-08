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
use crate::tls::{firefox_user_agent, ALPN_H2_H1};

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
}

#[derive(Clone)]
pub struct ControlPlane {
    dialer: Dialer,
    timeout: Duration,
    cookies: Arc<Mutex<BTreeMap<String, Cookie>>>,
}

impl ControlPlane {
    pub fn new(dialer: Dialer) -> Self {
        Self { dialer, timeout: Duration::from_secs(20), cookies: Arc::new(Mutex::new(BTreeMap::new())) }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn fresh_jar(&self) -> Self {
        Self { dialer: self.dialer.clone(), timeout: self.timeout, cookies: Arc::new(Mutex::new(BTreeMap::new())) }
    }

    pub fn dialer(&self) -> &Dialer {
        &self.dialer
    }

    pub async fn send(&self, request: ControlRequest) -> Result<ControlResponse> {
        let request = self.decorate(request);
        tokio::time::timeout(self.timeout, self.exchange(request))
            .await
            .map_err(|_| FirefoxError::Timeout(self.timeout))?
    }

    pub fn import_cookies(&self, other: &ControlPlane) {
        let imported = other.cookies.lock().clone();
        self.cookies.lock().extend(imported);
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
            request.headers.push((http::header::USER_AGENT, HeaderValue::from_str(&firefox_user_agent()).unwrap()));
        }
        if !has_header(&request, "accept") {
            request.headers.push((http::header::ACCEPT, HeaderValue::from_static("*/*")));
        }
        if !has_header(&request, "accept-encoding") {
            request.headers.push((http::header::ACCEPT_ENCODING, HeaderValue::from_static("identity")));
        }
        let cookies = self.cookies.lock();
        let mut values = cookies.values().filter(|cookie| {
            domain_matches(&request.host, &cookie.domain)
                && request.path.starts_with(&cookie.path)
                && !cookie.value.is_empty()
        }).map(|cookie| format!("{}={}", cookie.name, cookie.value)).collect::<Vec<_>>();
        values.sort();
        if !values.is_empty() && !has_header(&request, "cookie") {
            if let Ok(value) = HeaderValue::from_str(&values.join("; ")) {
                request.headers.push((http::header::COOKIE, value));
            }
        }
        request
    }

    async fn exchange(&self, request: ControlRequest) -> Result<ControlResponse> {
        let tls = crate::tls::connect(&self.dialer, &request.host, request.port, ALPN_H2_H1).await?;
        let is_h2 = tls.ssl().selected_alpn_protocol() == Some(b"h2");
        let response = if is_h2 { over_h2(tls, &request).await? } else { over_h1(tls, &request).await? };
        self.store_cookies(&request.host, &response.headers);
        Ok(response)
    }

    fn store_cookies(&self, request_host: &str, headers: &HeaderMap) {
        for value in headers.get_all(http::header::SET_COOKIE) {
            let Ok(value) = value.to_str() else { continue };
            let mut parts = value.split(';');
            let Some((name, cookie_value)) = parts.next().and_then(|pair| pair.trim().split_once('=')) else { continue };
            if name.is_empty() || cookie_value.len() > 4096 {
                continue;
            }
            let mut domain = request_host.to_ascii_lowercase();
            let mut path = "/".to_string();
            let mut remove = false;
            for attribute in parts {
                let (key, value) = attribute.trim().split_once('=').unwrap_or((attribute.trim(), ""));
                if key.eq_ignore_ascii_case("domain") && domain_matches(request_host, value.trim_start_matches('.')) {
                    domain = value.trim_start_matches('.').to_ascii_lowercase();
                } else if key.eq_ignore_ascii_case("path") && value.starts_with('/') {
                    path = value.to_string();
                } else if key.eq_ignore_ascii_case("max-age") && value.parse::<i64>() == Ok(0) {
                    remove = true;
                }
            }
            let key = format!("{domain}|{path}|{name}");
            if remove {
                self.cookies.lock().remove(&key);
            } else {
                self.cookies.lock().insert(key, Cookie {
                    domain,
                    path,
                    name: name.to_string(),
                    value: cookie_value.to_string(),
                });
            }
        }
    }
}

fn has_header(request: &ControlRequest, name: &str) -> bool {
    request.headers.iter().any(|(key, _)| key.as_str().eq_ignore_ascii_case(name))
}

fn domain_matches(host: &str, domain: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.trim_start_matches('.').trim_end_matches('.').to_ascii_lowercase();
    host == domain || host.strip_suffix(&domain).is_some_and(|prefix| prefix.ends_with('.'))
}

struct ConnectionDriver(tokio::task::JoinHandle<()>);

impl Drop for ConnectionDriver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn over_h2(tls: SslStream<TcpStream>, request: &ControlRequest) -> Result<ControlResponse> {
    let mut builder = h2::client::Builder::new();
    builder.enable_push(false).max_header_list_size(MAX_HEADER_LIST);
    let (client, connection) = builder.handshake(tls).await.map_err(h2_error)?;
    let driver = ConnectionDriver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let result = async {
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
    }.await;
    drop(driver);
    result
}

async fn over_h1<S>(mut tls: S, request: &ControlRequest) -> Result<ControlResponse>
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
    }
    parse_h1_response(&raw)
}

fn parse_h1_response(raw: &[u8]) -> Result<ControlResponse> {
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
    let body = if chunked { dechunk(body)? } else {
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
