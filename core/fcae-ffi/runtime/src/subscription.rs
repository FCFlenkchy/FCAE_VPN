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
    String::from_utf8(body).map_err(|_| "subscription response is not valid UTF-8 text".into())
}

/// Synchronous bridge for the shared FFI. Call this only from a worker thread;
/// the async HTTP operation can wait up to the configured network timeout.
pub fn fetch_blocking(url: &str) -> Result<String, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "could not initialize the subscription runtime".to_string())?;
    runtime.block_on(fetch(url))
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
}
