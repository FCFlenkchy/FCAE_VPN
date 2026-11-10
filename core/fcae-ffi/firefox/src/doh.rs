use std::net::IpAddr;
use std::time::Duration;

use http::Method;

use crate::control::{control_alpn, over_h1, over_h2, ControlRequest, ControlResponse};
use crate::error::{FirefoxError, Result};
use crate::transport::Upstream;
use crate::types::{authority, TransportPreference};

pub(crate) fn provider(server: &str) -> Option<&'static str> {
    let address = server.parse::<IpAddr>().ok()?;
    match address.to_string().as_str() {
        "1.1.1.1" | "1.0.0.1" | "2606:4700:4700::1111" | "2606:4700:4700::1001" => Some("cloudflare-dns.com"),
        "8.8.8.8" | "8.8.4.4" | "2001:4860:4860::8888" | "2001:4860:4860::8844" => Some("dns.google"),
        _ => None,
    }
}

pub(crate) async fn exchange(upstream: &Upstream, server: &str, query: &[u8]) -> Result<Vec<u8>> {
    let host = provider(server).ok_or_else(|| FirefoxError::UnsupportedDestination(server.into()))?;
    if query.len() < 12 || query.len() > u16::MAX as usize || query[2] & 0x80 != 0 {
        return Err(FirefoxError::Protocol("invalid DNS query".into()));
    }
    let transport = upstream.transport_preference();
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
        log::warn!("[firefox] (h2) DNS resolver did not negotiate HTTP/2");
        return Err(FirefoxError::Protocol("DNS resolver did not negotiate HTTP/2".into()));
    }
    log::debug!("[firefox] ({}) DNS-over-HTTPS", if is_h2 { "h2" } else { "h1" });
    let mut request = ControlRequest::new(Method::POST, &format!("https://{host}/dns-query"))?
        .header("content-type", "application/dns-message")?
        .header("accept", "application/dns-message")?;
    request.body = Some(query.to_vec());
    let response = if is_h2 {
        match over_h2(tls, &request).await {
            Err(FirefoxError::H2(_)) if transport == TransportPreference::Auto => {
                log::warn!("[firefox] (h2) DNS-over-HTTPS failed; trying (h1)");
                let tunnel = upstream.open_tcp(&authority(server, 443)).await?;
                let tls = crate::tls::connect_stream(tunnel, host, crate::tls::ALPN_H1).await?;
                over_h1(tls, &request).await?
            }
            result => result?,
        }
    } else {
        over_h1(tls, &request).await?
    };
    validate_response(query, response)
}

fn validate_response(query: &[u8], response: ControlResponse) -> Result<Vec<u8>> {
    if response.status != 200 {
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
