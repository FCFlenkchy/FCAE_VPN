//! Version checker – fetches version.json from GitHub and compares with current.
//!
//! version.json carries up to two releases, and each one is tagged with a
//! `type`, so a single file describes both what stable users should get and what
//! pre-release testers should get:
//!
//! ```json
//! {
//!   "type": "release",
//!   "version": "v1.3.2",
//!   "release_date": "2026-09-12",
//!   "release_notes": "...",
//!   "download_url": "https://github.com/FCFlenkchy/FCAE_VPN/releases",
//!
//!   "prerelease": {
//!     "type": "pre-release",
//!     "version": "v1.4.0-beta.2",
//!     "release_date": "2026-09-20",
//!     "release_notes": "...",
//!     "download_url": "https://github.com/FCFlenkchy/FCAE_VPN/releases/tag/v1.4.0-beta.2"
//!   }
//! }
//! ```
//!
//! Rules that matter:
//!
//! * The **top level is the latest release** and must never be a pre-release.
//!   Clients built before pre-release support existed read exactly these four
//!   keys and ignore the rest, so they keep working unchanged.
//! * The optional **`prerelease` block** is the latest pre-release. Only clients
//!   whose "pre-releases" toggle is on look at it.
//! * Comparison is real semver precedence, not string inequality, so
//!   `1.4.0-beta.2 < 1.4.0-rc.1 < 1.4.0` and a pre-release tester is
//!   automatically graduated to the stable build once it is published.
//! * As a safety net, an entry that says `"type": "pre-release"` (or whose
//!   version carries a `-beta`/`-rc` suffix) is never offered to a client that
//!   did not opt into pre-releases — even if it was mistakenly written into the
//!   top-level slot.

use serde::Deserialize;
use std::cmp::Ordering;

const VERSION_URL: &str =
    "https://raw.githubusercontent.com/FCFlenkchy/FCAE_VPN/main/version.json";

/// Matches version.json format at repo root. Unknown keys are ignored by serde,
/// which is what keeps this forward/backward compatible.
#[derive(Debug, Clone, Deserialize)]
pub struct VersionInfo {
    /// "release" | "pre-release" (absent = release).
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    pub version: String,
    #[serde(default, alias = "date")]
    pub release_date: String,
    #[serde(default, alias = "notes")]
    pub release_notes: String,
    #[serde(default)]
    pub download_url: String,
    /// Latest pre-release, if any (absent = there is none).
    #[serde(default)]
    pub prerelease: Option<ReleaseEntry>,
}

/// One release entry — same shape for the stable and the pre-release slot.
#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseEntry {
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    pub version: String,
    #[serde(default, alias = "date")]
    pub release_date: String,
    #[serde(default, alias = "notes")]
    pub release_notes: String,
    #[serde(default)]
    pub download_url: String,
}

impl ReleaseEntry {
    fn is_prerelease(&self) -> bool {
        kind_is_prerelease(self.kind.as_deref()) || !parse_version(&self.version)
            .map(|v| v.prerelease.is_empty())
            .unwrap_or(false)
    }
}

fn kind_is_prerelease(kind: Option<&str>) -> bool {
    matches!(
        kind.map(|k| k.trim().to_ascii_lowercase()).as_deref(),
        Some("pre-release") | Some("prerelease") | Some("pre") | Some("beta") | Some("rc")
    )
}

/// Result of a version check.
#[derive(Debug, Clone)]
pub struct UpdateCheckResult {
    pub update_available: bool,
    pub current_version: String,
    pub latest_version: String,
    pub release_date: String,
    pub release_notes: String,
    pub download_url: String,
    /// True when the entry we are offering is a pre-release, so the UI can label it.
    pub is_prerelease: bool,
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

/// Compare the running version with version.json.
///
/// `include_prereleases` comes from the user's "pre-releases" toggle (default
/// off). With it off only the stable slot is considered; with it on both slots
/// take part and the higher version wins, which also graduates pre-release
/// testers onto the stable build as soon as it supersedes the beta.
pub fn compare_versions(
    current: &str,
    latest: &VersionInfo,
    include_prereleases: bool,
) -> UpdateCheckResult {
    // The top-level block is the stable slot (it may still be *marked* a
    // pre-release by mistake — handled below).
    let stable = ReleaseEntry {
        kind: latest.kind.clone(),
        version: latest.version.clone(),
        release_date: latest.release_date.clone(),
        release_notes: latest.release_notes.clone(),
        download_url: latest.download_url.clone(),
    };

    let mut candidates: Vec<&ReleaseEntry> = Vec::new();
    // A client that did not opt into pre-releases must never be offered one,
    // even if the top-level entry is mislabelled.
    if include_prereleases || !stable.is_prerelease() {
        candidates.push(&stable);
    }
    if include_prereleases {
        if let Some(pre) = latest.prerelease.as_ref() {
            if !pre.version.trim().is_empty() {
                candidates.push(pre);
            }
        }
    }

    let cur_parsed = parse_version(current);

    // Highest version among the candidates we are allowed to see.
    let mut best: Option<(&ReleaseEntry, ParsedVersion)> = None;
    for entry in &candidates {
        if let Some(parsed) = parse_version(&entry.version) {
            if best.as_ref().map_or(true, |(_, bp)| parsed > *bp) {
                best = Some((entry, parsed));
            }
        }
    }

    let (entry, parsed) = match best {
        Some(v) => v,
        None => {
            // Nothing parseable (empty file / all garbage) — report no update
            // and keep showing the stable metadata.
            return UpdateCheckResult {
                update_available: false,
                current_version: current.to_string(),
                latest_version: latest.version.clone(),
                release_date: latest.release_date.clone(),
                release_notes: latest.release_notes.clone(),
                download_url: latest.download_url.clone(),
                is_prerelease: false,
            };
        }
    };

    let update_available = match cur_parsed {
        // Normal case: only a strictly newer version is an update. Equal is
        // "up to date", older is "you are ahead" — neither offers an update.
        Some(cur) => parsed > cur,
        // Unparseable local version (e.g. "dev"): fall back to the old
        // inequality behaviour so development builds still notice releases.
        None => strip_v(current) != strip_v(&entry.version),
    };

    UpdateCheckResult {
        update_available,
        current_version: current.to_string(),
        latest_version: entry.version.clone(),
        release_date: entry.release_date.clone(),
        release_notes: entry.release_notes.clone(),
        download_url: entry.download_url.clone(),
        is_prerelease: entry.is_prerelease(),
    }
}

/// Parse version.json content and compare with current version.
/// This is used from Android/Kotlin which handles the HTTP fetch natively
/// (more reliable than reqwest in native threads on Android).
pub fn check_from_json(
    current: &str,
    json: &str,
    include_prereleases: bool,
) -> Result<UpdateCheckResult, String> {
    let info: VersionInfo = serde_json::from_str(json)
        .map_err(|e| format!("Failed to parse version.json: {e}"))?;
    Ok(compare_versions(current, &info, include_prereleases))
}

fn strip_v(s: &str) -> String {
    s.strip_prefix('v').unwrap_or(s).to_string()
}

// ── Semver-ish parsing & ordering ────────────────────────────────────────
//
// Handles everything this project actually tags: `v1.3.2`, `1.3.2`,
// `v1.0.9.4` (4-component), `v1.4.0-beta.2`, `v1.4.0-rc.1`, `v1.4.0+build5`.
// Build metadata after `+` is ignored, as semver says it should be.

#[derive(Debug, Clone, PartialEq, Eq)]
enum PreId {
    Num(u64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVersion {
    nums: [u64; 4],
    prerelease: Vec<PreId>,
}

impl ParsedVersion {
    pub fn is_prerelease(&self) -> bool {
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

/// Parse a version string. Returns `None` when there are no leading digits
/// (e.g. `"dev"`), which callers treat as "cannot order".
pub fn parse_version(raw: &str) -> Option<ParsedVersion> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let s = s.strip_prefix('v').or_else(|| s.strip_prefix('V')).unwrap_or(s);
    let s = s.split('+').next().unwrap_or(s); // drop build metadata

    let (core, pre_raw) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };

    let mut nums = [0u64; 4];
    let mut seen = 0usize;
    for (i, part) in core.split('.').enumerate() {
        if i >= nums.len() {
            break;
        }
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.parse::<u64>() {
            Ok(v) => {
                nums[i] = v;
                seen += 1;
            }
            Err(_) => return None,
        }
    }
    if seen == 0 {
        return None;
    }

    let mut prerelease = Vec::new();
    if let Some(p) = pre_raw {
        for id in p.split('.') {
            let id = id.trim();
            if id.is_empty() {
                continue;
            }
            match id.parse::<u64>() {
                Ok(n) => prerelease.push(PreId::Num(n)),
                Err(_) => prerelease.push(PreId::Text(id.to_ascii_lowercase())),
            }
        }
    }

    Some(ParsedVersion { nums, prerelease })
}

/// True when the string looks like a pre-release tag (`v1.4.0-beta.2`).
pub fn is_prerelease_tag(raw: &str) -> bool {
    parse_version(raw).map(|v| v.is_prerelease()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(top: &str, kind: &str, pre: Option<(&str, &str)>) -> String {
        let pre_block = match pre {
            Some((v, k)) => format!(
                r#","prerelease":{{"type":"{k}","version":"{v}","release_date":"2026-09-20","release_notes":"beta notes","download_url":"https://example.com/tag/{v}"}}"#
            ),
            None => String::new(),
        };
        format!(
            r#"{{"type":"{kind}","version":"{top}","release_date":"2026-09-12","release_notes":"stable notes","download_url":"https://example.com/releases"{pre_block}}}"#
        )
    }

    fn check(current: &str, json_str: &str, allow_pre: bool) -> UpdateCheckResult {
        check_from_json(current, json_str, allow_pre).expect("parse")
    }

    #[test]
    fn ordering_basics() {
        let v = |s: &str| parse_version(s).unwrap();
        assert!(v("1.3.2") > v("1.3.1"));
        assert!(v("v1.3.2") == v("1.3.2"));
        assert!(v("1.10.0") > v("1.9.9"));
        // A release outranks its own pre-releases.
        assert!(v("1.4.0") > v("1.4.0-rc.1"));
        assert!(v("1.4.0-rc.1") > v("1.4.0-beta.2"));
        assert!(v("1.4.0-beta.10") > v("1.4.0-beta.2"));
        assert!(v("1.4.0-beta.1") > v("1.4.0-beta"));
        assert!(v("1.4.0-beta.1") > v("1.3.9"));
        assert!(v("1.0.9.4") > v("1.0.9.3"));
        assert!(v("1.4.0+build5") == v("1.4.0"));
        assert!(parse_version("dev").is_none());
    }

    /// Toggle OFF: pre-releases are invisible, stable-only behaviour.
    #[test]
    fn stable_channel_ignores_prerelease() {
        let file = json("v1.3.2", "release", Some(("v1.4.0-beta.2", "pre-release")));
        // already on the latest release
        assert!(!check("v1.3.2", &file, false).update_available);
        // behind by a patch → offered the release, never the beta
        let r = check("v1.3.1", &file, false);
        assert!(r.update_available);
        assert_eq!(r.latest_version, "v1.3.2");
        assert!(!r.is_prerelease);
        // a beta tester who switched the toggle off is graduated to stable
        let r = check("v1.4.0-beta.2", &file, false);
        assert!(!r.update_available, "1.4.0-beta.2 is ahead of stable 1.3.2");
        assert_eq!(r.latest_version, "v1.3.2");
    }

    /// Toggle ON: highest of the two slots wins.
    #[test]
    fn prerelease_channel_sees_the_beta() {
        let file = json("v1.3.2", "release", Some(("v1.4.0-beta.2", "pre-release")));
        // stable user who opted in gets the beta
        let r = check("v1.3.2", &file, true);
        assert!(r.update_available);
        assert_eq!(r.latest_version, "v1.4.0-beta.2");
        assert!(r.is_prerelease);
        assert_eq!(r.release_notes, "beta notes");
        // beta tester on an older beta
        assert!(check("v1.4.0-beta.1", &file, true).update_available);
        // beta tester already on the newest beta → up to date
        let r = check("v1.4.0-beta.2", &file, true);
        assert!(!r.update_available);
        assert_eq!(r.latest_version, "v1.4.0-beta.2");
    }

    /// The graduation case: stable overtakes the pre-release.
    #[test]
    fn stable_supersedes_prerelease() {
        let file = json("v1.4.0", "release", Some(("v1.4.0-beta.2", "pre-release")));
        // beta tester is offered the stable — no special casing needed
        let r = check("v1.4.0-beta.2", &file, true);
        assert!(r.update_available);
        assert_eq!(r.latest_version, "v1.4.0");
        assert!(!r.is_prerelease);
        // and a stable user on 1.3.2 as well
        assert!(check("v1.3.2", &file, true).update_available);
        assert!(check("v1.4.0", &file, true).update_available == false);
    }

    /// During a beta cycle the stable slot is untouched, so stable users stay
    /// on the last release while testers move to the beta.
    #[test]
    fn beta_cycle_keeps_stable_users_where_they_are() {
        let file = json("v1.3.2", "release", Some(("v1.4.0-beta.7", "pre-release")));
        let stable = check("v1.3.2", &file, false);
        assert!(!stable.update_available);
        let tester = check("v1.4.0-beta.6", &file, true);
        assert!(tester.update_available);
        assert_eq!(tester.latest_version, "v1.4.0-beta.7");
    }

    /// Safety net: a pre-release mistakenly written into the top-level slot is
    /// still not offered to clients without the toggle.
    #[test]
    fn mislabelled_top_level_never_reaches_stable_users() {
        let file = json("v1.4.0-beta.2", "pre-release", None);
        let r = check("v1.3.2", &file, false);
        assert!(!r.update_available, "beta in the stable slot must be ignored");
        // ...but a beta tester (toggle on) may take it
        let r = check("v1.3.2", &file, true);
        assert!(r.update_available);
        assert!(r.is_prerelease);
    }

    /// A suffix in the version string counts even when `type` is missing/wrong.
    #[test]
    fn suffix_alone_marks_a_prerelease() {
        let file = json("v1.4.0-rc.1", "release", None);
        assert!(!check("v1.3.2", &file, false).update_available);
        assert!(check("v1.3.2", &file, true).update_available);
    }

    /// Old clients (and files without a prerelease block) still behave.
    #[test]
    fn no_prerelease_block() {
        let file = json("v1.3.2", "release", None);
        assert!(check("v1.3.1", &file, true).update_available);
        assert!(!check("v1.3.2", &file, true).update_available);
        assert!(!check("v1.3.3", &file, true).update_available);
        // parity with the legacy `cur != lat` behaviour for unknown versions
        assert!(check("dev", &file, true).update_available);
    }

    #[test]
    fn legacy_keys_still_parse() {
        let legacy = r#"{"version":"v1.3.2","release_date":"2026-09-12","release_notes":"n","download_url":"u"}"#;
        let r = check("v1.3.1", legacy, false);
        assert!(r.update_available);
        assert_eq!(r.latest_version, "v1.3.2");
    }
}
