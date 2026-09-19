//! Update checking: the state machine plus the release manifest itself.
//!
//! This is an *application* concern, not a tunnel concern, so it lives in
//! core — the old ABI reached into `aether_engine::version_checker` directly,
//! which would have broken the moment Aether stopped being the only backend.
//!
//! A manifest that fails to decode is reported with the raw body the server
//! returned (an HTML error page, a redirect, a truncated file): that body is
//! exactly the diagnostic the operator needs, and the message ends with a
//! "could not decode" flag so the UI can tell "no update" from "broken
//! manifest".

use std::cmp::Ordering;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

use parking_lot::Mutex;
use serde::Deserialize;

const VERSION_URL: &str =
    "https://raw.githubusercontent.com/FCFlenkchy/FCAE_VPN/main/version.json";

/// How much of the raw body a decode error keeps: long enough to diagnose an
/// HTML error page, short enough to stay readable in the UI.
const RAW_EXCERPT_MAX: usize = 200;

/// Outcome of a version comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateResult {
    pub update_available: bool,
    pub is_prerelease: bool,
    pub current_version: String,
    pub latest_version: String,
    pub release_notes: String,
    pub download_url: String,
    pub release_date: String,
}

/// Wire format of the release manifest: the full release list, newest first.
pub type VersionInfo = Vec<ReleaseEntry>;

#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseEntry {
    pub version: String,
    pub date: String,
    pub notes: String,
    pub url: String,
}

fn validate(releases: &[ReleaseEntry]) -> Result<(), String> {
    if releases.is_empty() {
        return Err("Release list is empty".into());
    }
    let mut versions = std::collections::HashSet::new();
    for entry in releases {
        parse_version(&entry.version)
            .ok_or_else(|| format!("Invalid release version: {}", entry.version))?;
        if !versions.insert(&entry.version) {
            return Err(format!("Duplicate release version: {}", entry.version));
        }
        let tag = entry.url.strip_prefix(
            "https://github.com/FCFlenkchy/FCAE_VPN/releases/tag/"
        ).ok_or_else(|| format!("Invalid release URL for {}", entry.version))?;
        if tag.is_empty() || !tag.bytes().all(|c| c.is_ascii_alphanumeric() || b"-._+%".contains(&c)) {
            return Err(format!("Invalid release URL for {}", entry.version));
        }
    }
    Ok(())
}

/// Raw body for decode errors: the message crosses the FFI as a C string, so
/// NULs and control characters are stripped, and it is cut off so a whole
/// HTML error page does not end up in the UI.
fn raw_excerpt(raw: &str) -> String {
    let clean: String = raw
        .chars()
        .filter(|c| *c >= ' ' || matches!(c, '\n' | '\t'))
        .collect();
    let clean = clean.trim();
    if clean.len() <= RAW_EXCERPT_MAX {
        return clean.to_owned();
    }
    let mut out: String = clean.chars().take(RAW_EXCERPT_MAX).collect();
    out.push('…');
    out
}

#[derive(Debug, Default)]
struct State {
    in_progress: bool,
    done: bool,
    result: Option<UpdateResult>,
    status: String,
}

static STATE: Mutex<State> = Mutex::new(State {
    in_progress: false,
    done: false,
    result: None,
    status: String::new(),
});

/// Guards against two concurrent checks without holding the state lock across
/// the network call.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Snapshot handed to the FFI.
#[derive(Debug, Clone, Default)]
pub struct UpdateSnapshot {
    pub in_progress: bool,
    pub done: bool,
    pub result: Option<UpdateResult>,
    pub status: String,
}

pub fn snapshot() -> UpdateSnapshot {
    let s = STATE.lock();
    UpdateSnapshot {
        in_progress: s.in_progress,
        done: s.done,
        result: s.result.clone(),
        status: s.status.clone(),
    }
}

fn status_for(r: &UpdateResult) -> String {
    if r.update_available {
        if r.is_prerelease {
            format!("Pre-release available: {}", r.latest_version)
        } else {
            format!("Update available: {}", r.latest_version)
        }
    } else {
        format!("Up to date ({})", r.current_version)
    }
}

fn finish(result: Result<UpdateResult, String>) {
    let mut s = STATE.lock();
    s.in_progress = false;
    s.done = true;
    match result {
        Ok(r) => {
            s.status = status_for(&r);
            s.result = Some(r);
        }
        Err(e) => {
            s.status = format!("Update check failed: {e}");
            s.result = None;
        }
    }
}

/// Fetch version.json from GitHub (async, non-blocking).
async fn fetch_latest_version() -> Result<VersionInfo, String> {
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

    // Read the body as text first so a decode failure can quote what the
    // server actually returned.
    let text = resp
        .text()
        .await
        .map_err(|e| format!("Failed to read version.json body: {e}"))?;
    let info: VersionInfo = serde_json::from_str(&text)
        .map_err(|e| format!("version.json raw: {} -- could not decode: {e}", raw_excerpt(&text)))?;

    validate(&info)?;
    Ok(info)
}

/// Kick off a background check. Returns immediately; poll [`snapshot`].
pub fn check_async(current_version: String, include_prereleases: bool) {
    // compare_exchange, not check-then-set: two UI events landing together
    // used to be able to start two checks.
    if RUNNING
        .compare_exchange(false, true, AtomicOrdering::SeqCst, AtomicOrdering::SeqCst)
        .is_err()
    {
        return;
    }

    {
        let mut s = STATE.lock();
        s.in_progress = true;
        s.done = false;
        s.result = None;
        s.status = "Checking for updates…".into();
    }

    std::thread::Builder::new()
        .name("fcae-update".into())
        .spawn(move || {
            // The fetcher is async and needs a reactor; this is a plain worker
            // thread, so give it a small current-thread runtime rather than
            // requiring a global one.
            let outcome = (|| -> Result<UpdateResult, String> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("failed to build update runtime: {e}"))?;
                let info = rt.block_on(fetch_latest_version())?;
                compare_versions(&current_version, &info, include_prereleases)
            })();
            finish(outcome);
            RUNNING.store(false, AtomicOrdering::SeqCst);
        })
        .ok();
}

/// Evaluate a manifest the host already fetched (Android does its HTTP in
/// Kotlin to avoid DNS problems on native threads).
pub fn check_from_json(current_version: &str, json: &str, include_prereleases: bool) -> bool {
    let outcome = check_json(current_version, json, include_prereleases);
    let ok = outcome.is_ok();
    finish(outcome);
    ok
}

/// Decode + compare without touching the state machine.
fn check_json(current: &str, json: &str, include_prereleases: bool) -> Result<UpdateResult, String> {
    let info: VersionInfo = serde_json::from_str(json)
        .map_err(|e| format!("version manifest raw: {} -- could not decode: {e}", raw_excerpt(json)))?;
    compare_versions(current, &info, include_prereleases)
}

/// Compare a version string against the release manifest.
fn compare_versions(
    current: &str,
    latest: &VersionInfo,
    include_prereleases: bool,
) -> Result<UpdateResult, String> {
    validate(latest)?;
    let current_version = parse_version(current)
        .ok_or_else(|| format!("Cannot compare current version: {current}"))?;
    let best = latest.iter()
        .filter_map(|entry| parse_version(&entry.version).map(|version| (entry, version)))
        .filter(|(_, version)| include_prereleases || !version.is_prerelease())
        .max_by(|(_, a), (_, b)| a.cmp(b));

    let mut result = UpdateResult {
        is_prerelease: current_version.is_prerelease(),
        ..Default::default()
    };
    result.current_version = current.into();
    result.latest_version = current.into();
    if let Some((entry, version)) = best {
        if version >= current_version {
            result.update_available = version > current_version;
            result.latest_version = entry.version.clone();
            result.release_date = entry.date.clone();
            result.release_notes = entry.notes.clone();
            result.download_url = entry.url.clone();
            result.is_prerelease = version.is_prerelease();
        }
    }
    Ok(result)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PreId {
    Num(u64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedVersion {
    nums: [u64; 4],
    prerelease: Vec<PreId>,
}

impl ParsedVersion {
    fn is_prerelease(&self) -> bool {
        !self.prerelease.is_empty()
    }
}

impl Ord for ParsedVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.nums != other.nums {
            return self.nums.cmp(&other.nums);
        }
        match (self.prerelease.is_empty(), other.prerelease.is_empty()) {
            (true, true) => Ordering::Equal,
            // 1.4.0 > 1.4.0-rc.1: a release outranks its own pre-releases.
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => {
                for (a, b) in self.prerelease.iter().zip(other.prerelease.iter()) {
                    let ord = match (a, b) {
                        (PreId::Num(x), PreId::Num(y)) => x.cmp(y),
                        // Numeric identifiers rank below alphanumeric ones.
                        (PreId::Num(_), PreId::Text(_)) => Ordering::Less,
                        (PreId::Text(_), PreId::Num(_)) => Ordering::Greater,
                        (PreId::Text(x), PreId::Text(y)) => x.cmp(y),
                    };
                    if ord != Ordering::Equal {
                        return ord;
                    }
                }
                // All shared identifiers equal: the longer set wins
                // (beta.1 > beta).
                self.prerelease.len().cmp(&other.prerelease.len())
            }
        }
    }
}

impl PartialOrd for ParsedVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn parse_version(raw: &str) -> Option<ParsedVersion> {
    let s = raw.trim();
    let s = s.strip_prefix('v').or_else(|| s.strip_prefix('V')).unwrap_or(s);
    let valid_id = |id: &str| !id.is_empty()
        && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-');
    let s = match s.split_once('+') {
        Some((version, metadata)) => {
            if !metadata.split('.').all(valid_id) { return None; }
            version
        }
        None => s,
    };
    let (core, pre) = if let Some((core, pre)) = s.split_once('_') {
        if pre != "pre-release" && !pre.starts_with("pre-release.") { return None; }
        (core, Some(pre))
    } else {
        match s.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (s, None),
        }
    };
    let parts: Vec<_> = core.split('.').collect();
    if !(3..=4).contains(&parts.len()) { return None; }
    let mut nums = [0; 4];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() || !part.bytes().all(|c| c.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0')) { return None; }
        nums[index] = part.parse().ok()?;
    }
    let mut prerelease = Vec::new();
    if let Some(pre) = pre {
        for id in pre.split('.') {
            if !valid_id(id) { return None; }
            if id.bytes().all(|c| c.is_ascii_digit()) {
                if id.len() > 1 && id.starts_with('0') { return None; }
                prerelease.push(PreId::Num(id.parse().ok()?));
            } else {
                let id = if prerelease.is_empty() && id == "prerelease" { "pre-release" } else { id };
                prerelease.push(PreId::Text(id.into()));
            }
        }
    }
    Some(ParsedVersion { nums, prerelease })
}

fn is_prerelease_tag(raw: &str) -> bool {
    parse_version(raw).map(|v| v.is_prerelease()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog(versions: &[&str]) -> String {
        let releases: Vec<_> = versions.iter().map(|version| serde_json::json!({
            "version": version,
            "date": "2026-09-18",
            "notes": format!("Notes for {version}"),
            "url": format!("https://github.com/FCFlenkchy/FCAE_VPN/releases/tag/{version}")
        })).collect();
        serde_json::to_string(&releases).unwrap()
    }

    // The STATE static is process-wide, so the stateful paths run
    // sequentially in one test; the pure decode/compare paths are stateless
    // and run in parallel.
    #[test]
    fn state_machine_paths() {
        let json = catalog(&["2.0.0"]);
        assert!(check_from_json("1.0.0", &json, false));
        let s = snapshot();
        assert!(s.done);
        assert!(s.result.as_ref().unwrap().update_available);
        assert_eq!(s.status, "Update available: 2.0.0");

        assert!(check_from_json("2.0.0", &json, false));
        let s = snapshot();
        assert!(!s.result.as_ref().unwrap().update_available);
        assert_eq!(s.status, "Up to date (2.0.0)");

        let raw = "<html>not found</html>";
        assert!(!check_from_json("1.0.0", raw, false));
        let s = snapshot();
        assert!(s.done);
        assert!(s.result.is_none());
        assert!(s.status.contains("could not decode"), "{}", s.status);
        assert!(s.status.contains(raw), "{}", s.status);
    }

    #[test]
    fn numeric_and_prerelease_precedence() {
        let v = |s| parse_version(s).unwrap();
        for (older, newer) in [
            ("1.9.9", "1.10.0"), ("1.3.1", "1.3.4_pre-release"),
            ("1.4.0_pre-release.2", "1.4.0_pre-release.10"),
            ("1.4.0_pre-release", "1.4.0"), ("1.0.9.3", "1.0.9.4"),
            ("1.4.0-beta.2", "1.4.0-rc.1"), ("1.4.0-rc.1", "1.4.0"),
        ] { assert!(v(older) < v(newer), "{older} < {newer}"); }
        assert_eq!(v("v1.4.0+build5"), v("1.4.0"));
        assert_eq!(v("V1.4.0"), v("1.4.0.0"));
        assert_eq!(v("v1.4.0-prerelease"), v("1.4.0_pre-release"));
        assert_eq!(v("1.4.0-pre-release"), v("1.4.0_pre-release"));
        assert!(is_prerelease_tag("1.4.0_pre-release"));
        assert!(!is_prerelease_tag("1.4.0+build-5"));
    }

    #[test]
    fn never_offer_an_older_stable_to_a_newer_prerelease() {
        let json = catalog(&["1.3.1"]);
        for current in ["1.3.4_pre-release", "v1.3.4-prerelease"] {
            for allow_pre in [false, true] {
                let r = check_json(current, &json, allow_pre).unwrap();
                assert!(!r.update_available);
                assert_eq!(r.latest_version, current);
                assert!(r.download_url.is_empty());
            }
        }
    }

    #[test]
    fn channel_filters_do_not_change_version_priority() {
        let versions = ["1.3.5_pre-release", "1.3.1", "1.3.4", "1.3.4_pre-release"];
        for versions in [versions.to_vec(), versions.into_iter().rev().collect()] {
            let json = catalog(&versions);
            let stable = check_json("1.3.1", &json, false).unwrap();
            assert_eq!(stable.latest_version, "1.3.4");
            assert!(stable.update_available && !stable.is_prerelease);
            let pre = check_json("1.3.4_pre-release", &json, true).unwrap();
            assert_eq!(pre.latest_version, "1.3.5_pre-release");
            assert!(pre.update_available && pre.is_prerelease);
            assert!(pre.download_url.ends_with("/tag/1.3.5_pre-release"));
            assert_eq!(pre.release_notes, "Notes for 1.3.5_pre-release");
            assert_eq!(pre.release_date, "2026-09-18");
        }
    }

    #[test]
    fn stable_first_list_does_not_control_update_priority() {
        let json = catalog(&["1.4.0", "1.3.1", "1.5.0_pre-release", "1.4.2_pre-release"]);
        let stable = check_json("1.3.1", &json, false).unwrap();
        assert!(stable.update_available);
        assert_eq!(stable.latest_version, "1.4.0");
        let ahead = check_json("1.4.2_pre-release", &json, false).unwrap();
        assert!(!ahead.update_available);
        assert!(ahead.download_url.is_empty());
        let pre = check_json("1.4.2_pre-release", &json, true).unwrap();
        assert!(pre.update_available);
        assert_eq!(pre.latest_version, "1.5.0_pre-release");
    }

    #[test]
    fn stable_supersedes_its_own_prerelease_on_both_channels() {
        let json = catalog(&["1.3.4", "1.3.4_pre-release"]);
        for allow_pre in [false, true] {
            let r = check_json("1.3.4_pre-release", &json, allow_pre).unwrap();
            assert!(r.update_available && !r.is_prerelease);
            assert_eq!(r.latest_version, "1.3.4");
            assert!(!check_json("1.3.4", &json, allow_pre).unwrap().update_available);
        }
    }

    #[test]
    fn disabling_prereleases_never_turns_an_older_stable_into_an_update() {
        let json = catalog(&["1.3.1", "1.3.5_pre-release"]);
        let stable_only = check_json("1.3.4_pre-release", &json, false).unwrap();
        assert!(!stable_only.update_available);
        assert!(stable_only.download_url.is_empty());
        let include_pre = check_json("1.3.4_pre-release", &json, true).unwrap();
        assert!(include_pre.update_available);
        assert_eq!(include_pre.latest_version, "1.3.5_pre-release");
    }

    #[test]
    fn spelling_and_metadata_changes_are_not_updates() {
        let json = catalog(&["1.3.5_pre-release"]);
        assert!(!check_json("v1.3.5-prerelease", &json, true).unwrap().update_available);
        assert!(!check_json("1.3.5_pre-release+local", &json, true).unwrap().update_available);
        assert!(!check_json("1.3.1", &json, false).unwrap().update_available);
    }

    #[test]
    fn malformed_versions_and_lists_are_errors() {
        for value in ["dev", "1", "1..3", "1.2.3.4.5", "1.2.3-", "1.2.3+", "1.2.3-a..b", "1.2.3-01", "01.2.3", "1.2.3+x+y", "1.2.3_", "1.2.3_release"] {
            assert!(parse_version(value).is_none(), "{value}");
        }
        let json = catalog(&["1.3.4"]);
        assert!(check_json("dev", &json, true).is_err());
        assert!(check_json("1.3.1", r#"{"version":"1.3.4"}"#, true).is_err());
        assert!(check_json("1.3.1", &catalog(&["1.3.4", "1.3.4"]), true).is_err());
        assert!(check_json("1.3.1", &catalog(&[]), true).is_err());
        assert!(check_json("1.3.1", &json.replace("https://github.com", "https://example.com"), true).is_err());
    }

    #[test]
    fn decode_errors_show_the_raw_body_and_the_could_not_decode_trailer() {
        let raw = r#"<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message>object not found</Message></Error>"#;
        let err = check_json("1.3.1", raw, true).unwrap_err();
        assert!(err.contains("NoSuchKey"), "raw body missing: {err}");
        assert!(err.contains("could not decode"), "trailer missing: {err}");
    }

    #[test]
    fn raw_excerpt_strips_nuls_and_truncates() {
        let raw = format!("ab\0cd{}", "x".repeat(500));
        let out = raw_excerpt(&raw);
        assert!(!out.contains('\0'));
        assert!(out.len() <= RAW_EXCERPT_MAX + 1);
        assert!(out.ends_with('…'));
    }
}
