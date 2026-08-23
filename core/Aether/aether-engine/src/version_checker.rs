//! Version checker – fetches version.json from GitHub and compares with current.
//!
//! Uses reqwest (already in engine deps) for HTTPS. Works on all platforms
//! including Android since reqwest uses rustls (no system OpenSSL needed).

use serde::Deserialize;

const VERSION_URL: &str =
    "https://raw.githubusercontent.com/FCFlenkchy/FCAE_VPN/main/version.json";

/// Matches version.json format at repo root.
#[derive(Debug, Clone, Deserialize)]
pub struct VersionInfo {
    pub version: String,
    #[serde(default)]
    pub release_date: String,
    #[serde(default)]
    pub release_notes: String,
    #[serde(default)]
    pub download_url: String,
}

/// Result of a version check.
#[derive(Debug, Clone)]
pub struct UpdateCheckResult {
    pub update_available: bool,
    pub current_version: String,
    pub latest_version: String,
    pub release_notes: String,
    pub download_url: String,
}

/// Fetch version.json from GitHub (async, non-blocking).
pub async fn fetch_latest_version() -> Result<VersionInfo, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .connect_timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    let resp = client
        .get(VERSION_URL)
        .header("User-Agent", "FCAE-VPN/1.0")
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let info: VersionInfo = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse version.json: {e}"))?;

    Ok(info)
}

/// Compare versions and return update info.
/// Only reports update available if the remote version is strictly different
/// (ignores pre-release suffixes for comparison purposes).
pub fn compare_versions(
    current: &str,
    latest: &VersionInfo,
) -> UpdateCheckResult {
    let cur = strip_v(current);
    let lat = strip_v(&latest.version);
    let update_available = !lat.is_empty() && cur != lat;

    UpdateCheckResult {
        update_available,
        current_version: current.to_string(),
        latest_version: latest.version.clone(),
        release_notes: latest.release_notes.clone(),
        download_url: latest.download_url.clone(),
    }
}

/// Parse version.json content and compare with current version.
/// This is used from Android/Kotlin which handles the HTTP fetch natively
/// (more reliable than reqwest in native threads on Android).
pub fn check_from_json(current: &str, json: &str) -> Result<UpdateCheckResult, String> {
    let info: VersionInfo = serde_json::from_str(json)
        .map_err(|e| format!("Failed to parse version.json: {e}"))?;
    Ok(compare_versions(current, &info))
}

fn strip_v(s: &str) -> String {
    s.strip_prefix('v').unwrap_or(s).to_string()
}
