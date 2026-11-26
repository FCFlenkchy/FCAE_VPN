//! Fetch an HTTPS proxy subscription for the shared UI's importer.
//!
//! The UI turns the returned upstream-native document into saved Xray,
//! sing-box or Mihomo profiles. This module deliberately only downloads the
//! document: parsing it belongs to the existing core profile validators.

use std::time::Duration;

use reqwest::{redirect::Policy, Client, Url};

/// Bound the response before it crosses the FFI or is parsed by the UI.
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_URL_BYTES: usize = 4096;
/// Longest subscription title kept, in bytes: it labels one list row.
const MAX_TITLE_BYTES: usize = 96;

/// A subscription document and the name its server gives it.
pub struct Subscription {
    pub body: String,
    /// The feed's `profile-title` response header, decoded, or empty when the
    /// server sent none. The UI offers it as the name of the imported group.
    pub title: String,
}

/// Panels send `profile-title` raw (percent-encoded when it is not ASCII) or as
/// `base64:<utf-8>`. Either way it becomes a label: one line, bounded, and
/// without control characters. A value that does not decode is no title.
fn decode_title(raw: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(raw) else {
        return String::new();
    };
    let text = text.trim();
    let decoded = match text.strip_prefix("base64:") {
        Some(encoded) => match crate::proxy_cores::profile::b64_decode(encoded.trim()) {
            Some(decoded) => decoded,
            None => return String::new(),
        },
        None => crate::proxy_cores::profile::percent_decode(text),
    };
    let line: String = decoded
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut end = line.len().min(MAX_TITLE_BYTES);
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    line[..end].trim_end().to_owned()
}

fn has_userinfo(url: &Url) -> bool {
    !url.username().is_empty()
        || url.password().is_some()
        || url
            .as_str()
            .split_once("://")
            .map(|(_, rest)| {
                rest.split(|c| matches!(c, '/' | '?' | '#'))
                    .next()
                    .unwrap_or_default()
                    .contains('@')
            })
            .unwrap_or(true)
}

fn parse_url(text: &str) -> Result<Url, String> {
    if text.is_empty()
        || text.len() > MAX_URL_BYTES
        || text.trim() != text
        || text.chars().any(char::is_control)
    {
        return Err("enter a valid HTTPS subscription URL".into());
    }
    let url = Url::parse(text).map_err(|_| "enter a valid HTTPS subscription URL")?;
    if url.scheme() != "https" || url.host_str().is_none() || has_userinfo(&url) {
        return Err(
            "subscription URLs must use HTTPS and must not contain embedded credentials".into(),
        );
    }
    Ok(url)
}

/// Fetch one subscription document. Redirects stay on HTTPS and are limited to
/// five; the response is capped even when the server omits Content-Length.
pub async fn fetch(url: &str) -> Result<String, String> {
    fetch_titled(url)
        .await
        .map(|subscription| subscription.body)
}

/// [`fetch`], keeping the title the server names the feed with.
pub async fn fetch_titled(url: &str) -> Result<Subscription, String> {
    let url = parse_url(url)?;
    let client = Client::builder()
        .timeout(Duration::from_secs(25))
        .connect_timeout(Duration::from_secs(8))
        .redirect(Policy::custom(|attempt| {
            if attempt.url().scheme() == "https"
                && !has_userinfo(attempt.url())
                && attempt.previous().len() < 5
            {
                attempt.follow()
            } else {
                // A stopped redirect is returned as a non-success response and
                // reported below without exposing its URL or query parameters.
                attempt.stop()
            }
        }))
        .user_agent("FCAE-VPN/1.0")
        .build()
        .map_err(|_| "could not initialize the subscription HTTP client".to_string())?;

    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|error| {
            format!("subscription request failed: {}", error.without_url())
        })?;
    if !response.status().is_success() {
        return Err(format!("subscription server returned HTTP {}", response.status()));
    }
    let title = response
        .headers()
        .get("profile-title")
        .map(|value| decode_title(value.as_bytes()))
        .unwrap_or_default();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY_BYTES as u64)
    {
        return Err(format!(
            "subscription exceeds the {} MiB download limit",
            MAX_BODY_BYTES / (1024 * 1024)
        ));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| {
            format!(
                "could not read the subscription response: {}",
                error.without_url()
            )
        })?
    {
        if body.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
            return Err(format!(
                "subscription exceeds the {} MiB download limit",
                MAX_BODY_BYTES / (1024 * 1024)
            ));
        }
        body.extend_from_slice(&chunk);
    }
    if body.contains(&0) {
        return Err("subscription response contains a NUL byte".into());
    }
    let body = String::from_utf8(body)
        .map_err(|_| "subscription response is not valid UTF-8 text".to_string())?;
    Ok(Subscription { body, title })
}

/// Synchronous bridge for the shared FFI. Call this only from a worker thread;
/// the async HTTP operation can wait up to the configured network timeout.
pub fn fetch_blocking(url: &str) -> Result<String, String> {
    fetch_blocking_titled(url).map(|subscription| subscription.body)
}

/// [`fetch_blocking`], keeping the title the server names the feed with.
pub fn fetch_blocking_titled(url: &str) -> Result<Subscription, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "could not initialize the subscription runtime".to_string())?;
    runtime.block_on(fetch_titled(url))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_urls_without_credentials_are_accepted() {
        assert!(parse_url("https://example.test/list.txt?token=abc").is_ok());
        assert!(parse_url("http://example.test/list.txt").is_err());
        assert!(parse_url("https://user:pass@example.test/list.txt").is_err());
        assert!(parse_url("https://@example.test/list.txt").is_err());
        assert!(parse_url("https://example.test/list.txt\n").is_err());
    }

    #[test]
    fn titles_decode_to_one_bounded_line() {
        assert_eq!(decode_title(b"My Provider"), "My Provider");
        assert_eq!(decode_title(b"  Caf%C3%A9%20VPN "), "Caf\u{e9} VPN");
        // "base64:" + base64("Premium 🚀")
        assert_eq!(
            decode_title(b"base64:UHJlbWl1bSDwn5qA"),
            "Premium \u{1f680}"
        );
        assert_eq!(decode_title(b"base64:not base64 at all!"), "");
        assert_eq!(decode_title(b"line one%0Aline two"), "line one line two");
        assert_eq!(decode_title(&[0xff, 0xfe]), "");
        let long = "\u{e9}".repeat(200);
        let title = decode_title(long.as_bytes());
        assert!(title.len() <= MAX_TITLE_BYTES);
        assert!(title.chars().all(|c| c == '\u{e9}'));
    }
}
