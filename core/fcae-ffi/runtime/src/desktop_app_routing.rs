//! Narrow, app-owned control surface. There is no executable/helper CLI.
//! Windows/macOS return unavailable until their OS data planes exist.
use serde_json::{json, Value};

pub fn request(input: &str) -> String {
    if input.len() > 65536 {
        return json!({"ok":false,"message":"request too large"}).to_string();
    }
    let value: Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(_) => return json!({"ok":false,"message":"invalid routing request"}).to_string(),
    };
    if value["action"].as_str().is_some_and(|action|action.starts_with("flow_")) {
        return crate::desktop_flow_routing::request(&value).to_string();
    }
    #[cfg(target_os = "linux")]
    let result = linux::request(&value);
    #[cfg(all(windows, target_pointer_width = "64"))]
    let result = crate::windows_app_routing_control::request(&value);
    #[cfg(not(any(target_os = "linux", all(windows, target_pointer_width = "64"))))]
    let result = {
        let _ = value;
        json!({"ok":false,"active":false,"message":"No platform routing provider is installed in this build."})
    };
    result.to_string()
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::app_routing::{Action, Mode, Platform, Policy, Provider, Selector, SCHEMA_VERSION};
    use crate::linux_app_routing::LinuxBypassProvider;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    struct State {
        worker: Option<JoinHandle<()>>,
        stop: Arc<AtomicBool>,
        message: Arc<Mutex<String>>,
        done: Arc<AtomicBool>,
    }
    impl Default for State {
        fn default() -> Self {
            Self {
                worker: None,
                stop: Arc::new(AtomicBool::new(false)),
                message: Arc::new(Mutex::new("No controlled-launch scope is active.".into())),
                done: Arc::new(AtomicBool::new(true)),
            }
        }
    }
    static STATE: std::sync::LazyLock<Mutex<State>> =
        std::sync::LazyLock::new(|| Mutex::new(State::default()));
    fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn request(value: &Value) -> Value {
        let mut state = lock(&STATE);
        if state.done.load(Ordering::Acquire) {
            if let Some(worker) = state.worker.take() {
                let _ = worker.join();
            }
        }
        let action = value["action"].as_str().unwrap_or("");
        match action {
            "status" => {}
            "stop" | "shutdown" => {
                state.stop.store(true, Ordering::Release);
                if action == "shutdown" {
                    if let Some(worker) = state.worker.take() {
                        let _ = worker.join();
                    }
                }
            }
            "launch" | "recover" => {
                if state.worker.is_some() {
                    return json!({"ok":false,"active":true,"message":"A controlled launch is already active."});
                }
                let recover = action == "recover";
                let uid = if recover {
                    1
                } else {
                    match value["uid"]
                        .as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .filter(|n| *n > 0)
                    {
                        Some(uid) => uid,
                        None => {
                            return json!({"ok":false,"message":"Select a non-root target UID."})
                        }
                    }
                };
                let executable = value["executable"].as_str().unwrap_or("").to_owned();
                if !recover && (!Path::new(&executable).is_absolute() || executable.len() > 32768) {
                    return json!({"ok":false,"message":"An absolute executable path is required."});
                }
                state.stop.store(false, Ordering::Release);
                state.done.store(false, Ordering::Release);
                *lock(&state.message) = "Preparing controlled-launch routing...".into();
                let stop = state.stop.clone();
                let done = state.done.clone();
                let message = state.message.clone();
                let worker = thread::Builder::new().name("fcae-app-routing".into()).spawn(move || {
                    let result = std::panic::catch_unwind(|| {
                        if recover { LinuxBypassProvider::recover_stale().map_err(|e| format!("Recovery: {e}")) }
                        else { launch(&executable, uid, &stop, &message) }
                    });
                    *lock(&message) = match result {
                        Ok(Ok(())) => if recover { "Stopped stale scopes recovered; live scopes were left untouched.".into() }
                            else { "Launched scope exited; routing restored.".into() },
                        Ok(Err(error)) => error,
                        Err(_) => "Controlled-launch worker failed; check scope cleanup before retrying.".into(),
                    };
                    done.store(true, Ordering::Release);
                });
                match worker {
                    Ok(worker) => state.worker = Some(worker),
                    Err(error) => {
                        state.done.store(true, Ordering::Release);
                        *lock(&state.message) = format!("Could not start routing worker: {error}");
                    }
                }
            }
            _ => return json!({"ok":false,"message":"Unknown routing operation."}),
        }
        json!({"ok":true,"active":!state.done.load(Ordering::Acquire),"message":lock(&state.message).clone()})
    }
    fn launch(
        executable: &str,
        uid: u32,
        stop: &AtomicBool,
        message: &Mutex<String>,
    ) -> Result<(), String> {
        if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
            return Err("This experimental Linux launch requires FCAE itself to be running as root. No elevation helper is installed.".into());
        }
        let (gid, _, _) = crate::linux_app_routing::launch_user(uid).map_err(|e| e.to_string())?;
        let executable = std::fs::canonicalize(executable).map_err(|e| e.to_string())?;
        let path = executable.to_str().ok_or("Executable path must be UTF-8")?;
        let policy = Policy {
            schema_version: SCHEMA_VERSION,
            revision: 1,
            mode: Mode::Exclude,
            selectors: vec![Selector::LinuxLaunchTarget(path.to_owned())],
            unknown_action: Action::Tunnel,
            fail_closed: false,
        }
        .compile(Platform::Linux)
        .map_err(|e| format!("Policy: {e:?}"))?;
        let mut provider = LinuxBypassProvider::prepare_detected().map_err(|e| e.to_string())?;
        provider
            .install(&policy)
            .map_err(|e| format!("Routing setup: {e:?}"))?;
        if stop.load(Ordering::Acquire) {
            return provider.rollback().map_err(|e| format!("Cleanup: {e:?}"));
        }
        let mut child = provider
            .launch(&executable, &[], uid, gid)
            .map_err(|e| format!("Application launch: {e}"))?;
        *lock(message) = format!(
            "Controlled bypass scope active: {}. Only new sockets in this scope are covered.",
            provider.scope_path().display()
        );
        let mut child_exited = false;
        let mut terminated = false;
        let mut deadline = None;
        loop {
            if stop.load(Ordering::Acquire) && !terminated {
                provider.terminate_scope().map_err(|e| {
                    format!(
                        "Could not stop scope {}: {e}",
                        provider.scope_path().display()
                    )
                })?;
                terminated = true;
                deadline = Some(std::time::Instant::now() + Duration::from_secs(5));
            }
            if !child_exited {
                child_exited = child.try_wait().map_err(|e| e.to_string())?.is_some();
            }
            if child_exited && !provider.scope_populated().map_err(|e| e.to_string())? {
                break;
            }
            if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
                return Err(format!(
                    "Scope {} did not exit after termination; OS state retained for recovery.",
                    provider.scope_path().display()
                ));
            }
            thread::sleep(Duration::from_millis(100));
        }
        provider.rollback().map_err(|e| {
            format!(
                "Cleanup failed; scope {} retained: {e:?}",
                provider.scope_path().display()
            )
        })
    }
}
