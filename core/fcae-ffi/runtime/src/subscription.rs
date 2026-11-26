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

/// A subscription document and the names its server gives it.
pub struct Subscription {
    pub body: String,
    /// The feed's `profile-title` response header, decoded, or empty when the
    /// server sent none. The UI offers it as the name of the imported group.
    pub title: String,
    /// The file name the server sends the document under, without directory
    /// and extension, or empty when it sent none. The panels that serve
    /// Clash-style documents name the feed this way and nowhere else, so the
    /// UI offers it where the feed has no title.
    pub file_name: String,
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
    label(&decoded)
}

/// `text` as a label: one line, bounded, and without control characters.
fn label(text: &str) -> String {
    let line: String = text
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

/// The file name of a `Content-Disposition` header, as a label:
/// `attachment; filename="Blue Cloud.yaml"`, or `filename*=UTF-8''…` when the
/// name is not ASCII. The directory and the extension are the file's, not the
/// feed's, and a name that only says what kind of file it is, or that is a
/// number or a token the file is filed under, names nothing.
fn attachment_name(raw: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(raw) else {
        return String::new();
    };
    // Parameters are separated by `;`, which a quoted value may contain.
    let mut params = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (index, c) in text.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ';' if !quoted => {
                params.push(&text[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    params.push(&text[start..]);

    let (mut plain, mut extended) = (None, None);
    for param in params {
        let Some((key, value)) = param.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim().to_ascii_lowercase().as_str() {
            // RFC 5987: charset'language'percent-encoded.
            "filename*" => {
                let mut parts = value.splitn(3, '\'');
                if let (Some(charset), Some(_), Some(encoded)) =
                    (parts.next(), parts.next(), parts.next())
                {
                    if charset.trim().eq_ignore_ascii_case("utf-8") {
                        extended = Some(crate::proxy_cores::profile::percent_decode(encoded));
                    }
                }
            }
            "filename" => {
                let unquoted = match value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
                    Some(inner) => {
                        let mut out = String::with_capacity(inner.len());
                        let mut chars = inner.chars();
                        while let Some(c) = chars.next() {
                            out.push(if c == '\\' { chars.next().unwrap_or(c) } else { c });
                        }
                        out
                    }
                    None => value.to_owned(),
                };
                // Not in the grammar, but servers percent-encode here as well.
                plain = Some(crate::proxy_cores::profile::percent_decode(&unquoted));
            }
            _ => {}
        }
    }
    let name = extended.or(plain).unwrap_or_default();
    let name = name.rsplit(['/', '\\']).next().unwrap_or_default().trim();
    let stem = match name.rsplit_once('.') {
        Some((stem, extension))
            if !stem.trim().is_empty()
                && ["yaml", "yml", "json", "txt", "conf", "list"]
                    .iter()
                    .any(|known| extension.eq_ignore_ascii_case(known)) =>
        {
            stem.trim()
        }
        _ => name,
    };
    const KINDS: &[&str] = &[
        "config",
        "clash",
        "download",
        "file",
        "index",
        "list",
        "mihomo",
        "nodes",
        "profile",
        "proxies",
        "sing-box",
        "singbox",
        "sub",
        "subscribe",
        "subscription",
        "v2ray",
        "xray",
    ];
    let token = stem.len() >= 16 && stem.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    if token
        || !stem.chars().any(char::is_alphabetic)
        || KINDS.iter().any(|kind| stem.eq_ignore_ascii_case(kind))
    {
        return String::new();
    }
    label(stem)
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
    let file_name = response
        .headers()
        .get(reqwest::header::CONTENT_DISPOSITION)
        .map(|value| attachment_name(value.as_bytes()))
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
    Ok(Subscription {
        body,
        title,
        file_name,
    })
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

    #[test]
    fn a_download_file_name_is_a_label() {
        assert_eq!(
            attachment_name(b"attachment; filename=\"Blue Cloud.yaml\""),
            "Blue Cloud"
        );
        // The extended form is the one that can spell the name, so it wins.
        assert_eq!(
            attachment_name(
                b"attachment; filename=\"fallback.yaml\"; filename*=UTF-8''%E8%93%9D%E4%BA%91.yaml"
            ),
            "\u{84dd}\u{4e91}"
        );
        assert_eq!(attachment_name(b"attachment;filename*=utf-8''North%20Link"), "North Link");
        assert_eq!(attachment_name(b"inline; filename=Caf%C3%A9.txt"), "Caf\u{e9}");
        // A `;` and an escaped quote inside the quotes belong to the name.
        assert_eq!(
            attachment_name(b"attachment; filename=\"a;b \\\"c\\\".json\"; size=3"),
            "a;b \"c\""
        );
        assert_eq!(attachment_name(b"attachment; filename=\"/tmp/dir/North.yml\""), "North");
        // Only the last extension is the file's.
        assert_eq!(attachment_name(b"attachment; filename=v1.2-east.yaml"), "v1.2-east");
        assert_eq!(attachment_name(b"attachment; filename=nordlink.example"), "nordlink.example");
        // What kind of file it is names no feed.
        assert_eq!(attachment_name(b"attachment; filename=config.yaml"), "");
        assert_eq!(attachment_name(b"attachment; filename=\"Subscription\""), "");
        // Nor does what it is filed under.
        assert_eq!(attachment_name(b"attachment; filename=1700000000.yaml"), "");
        assert_eq!(
            attachment_name(b"attachment; filename=\"3f9a1c2b7d4e5f60718293a4b5c6d7e8.txt\""),
            ""
        );
        assert_eq!(
            attachment_name(b"attachment; filename=8d2a3c1e-5b7f-4f0a-9c3d-1e2f3a4b5c6d"),
            ""
        );
        assert_eq!(attachment_name(b"attachment; filename=deadbeef.yaml"), "deadbeef");
        assert_eq!(attachment_name(b"attachment"), "");
        assert_eq!(attachment_name(b"attachment; filename=\"\""), "");
        assert_eq!(attachment_name(b"attachment; filename*=ISO-8859-1''caf%E9"), "");
        assert_eq!(attachment_name(&[0xff, 0xfe]), "");
    }
}
