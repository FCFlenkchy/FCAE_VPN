//! Update checking.
//!
//! This is an *application* concern, not a tunnel concern, so it lives in core
//! rather than inside a backend — the old ABI reached into
//! `aether_engine::version_checker` directly, which meant the update UI would
//! have broken the moment Aether stopped being the only backend.
//!
//! The actual fetch/parse implementation is injected via [`install_provider`]
//! so this module stays dependency-free and unit-testable. The FFI crate wires
//! in the real one at init.

use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;

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

/// Pluggable implementation of the two ways a check can happen.
///
/// Two entry points rather than a `fetch` + `parse` pair, because the network
/// path and the host-supplied-JSON path genuinely differ: Android fetches in
/// Kotlin and only ever needs `parse`, while the desktop path never has the
/// raw body in hand (the engine's fetcher returns a parsed manifest).
#[derive(Clone, Copy)]
pub struct Provider {
    /// Fetch and compare in one blocking step. `Err` carries a user-facing
    /// message.
    pub check: fn(current: &str, include_prereleases: bool) -> Result<UpdateResult, String>,
    /// Compare `current` against a manifest document the host already has.
    pub parse: fn(current: &str, json: &str, include_prereleases: bool) -> Result<UpdateResult, String>,
}

static PROVIDER: Mutex<Option<Provider>> = Mutex::new(None);

pub fn install_provider(p: Provider) {
    *PROVIDER.lock() = Some(p);
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
            s.status = e;
            s.result = None;
        }
    }
}

/// Kick off a background check. Returns immediately; poll [`snapshot`].
pub fn check_async(current_version: String, include_prereleases: bool) {
    // compare_exchange, not check-then-set: two UI events landing together
    // used to be able to start two checks.
    if RUNNING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    let Some(provider) = *PROVIDER.lock() else {
        RUNNING.store(false, Ordering::SeqCst);
        finish(Err("update checking is not available in this build".into()));
        return;
    };

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
            let outcome = (provider.check)(&current_version, include_prereleases);
            finish(outcome);
            RUNNING.store(false, Ordering::SeqCst);
        })
        .ok();
}

/// Evaluate a manifest the host already fetched (Android does its HTTP in
/// Kotlin to avoid DNS problems on native threads).
pub fn check_from_json(current_version: &str, json: &str, include_prereleases: bool) -> bool {
    let Some(provider) = *PROVIDER.lock() else {
        finish(Err("update checking is not available in this build".into()));
        return false;
    };
    let outcome = (provider.parse)(current_version, json, include_prereleases);
    let ok = outcome.is_ok();
    finish(outcome);
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_provider() -> Provider {
        Provider {
            check: |current, pre| {
                (fake_provider().parse)(current, r#"{"stable":"2.0.0"}"#, pre)
            },
            parse: |current, json, _pre| {
                if json.contains("2.0.0") {
                    Ok(UpdateResult {
                        update_available: current != "2.0.0",
                        current_version: current.to_string(),
                        latest_version: "2.0.0".into(),
                        ..Default::default()
                    })
                } else {
                    Err("bad manifest".into())
                }
            },
        }
    }

    #[test]
    fn json_path_reports_an_update() {
        install_provider(fake_provider());
        assert!(check_from_json("1.0.0", r#"{"stable":"2.0.0"}"#, false));
        let s = snapshot();
        assert!(s.done);
        assert!(s.result.as_ref().unwrap().update_available);
        assert_eq!(s.status, "Update available: 2.0.0");
    }

    #[test]
    fn json_path_reports_up_to_date() {
        install_provider(fake_provider());
        assert!(check_from_json("2.0.0", r#"{"stable":"2.0.0"}"#, false));
        let s = snapshot();
        assert!(!s.result.as_ref().unwrap().update_available);
        assert!(s.status.starts_with("Up to date"));
    }

    #[test]
    fn parse_failure_surfaces_the_message() {
        install_provider(fake_provider());
        assert!(!check_from_json("1.0.0", "{}", false));
        let s = snapshot();
        assert!(s.done);
        assert!(s.result.is_none());
        assert_eq!(s.status, "bad manifest");
    }
}
