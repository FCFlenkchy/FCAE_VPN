//! Entitlement-gated, app-owned macOS transparent-proxy lifecycle. The host
//! callback uses public NetworkExtension APIs; Rust never launches a helper CLI.
use fcae_runtime::{
    backend::{CancelToken, Endpoints},
    config::SessionConfig,
    desktop_flow_routing as policy,
    error::{CoreError, Result},
    session::TunBridge,
};
use serde_json::json;
use std::{
    ffi::{c_char, c_void, CString},
    sync::{
        atomic::{AtomicBool, Ordering},
        LazyLock, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
pub type Control = unsafe extern "C" fn(*const c_char, *mut c_char, u32, *mut c_void) -> bool;
static HOST: LazyLock<Mutex<Option<(Control, usize)>>> = LazyLock::new(|| Mutex::new(None));
fn lock<T>(value: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    value.lock().unwrap_or_else(|e| e.into_inner())
}
pub unsafe fn register(callback: Option<Control>, context: *mut c_void) {
    *lock(&HOST) = callback.map(|callback| (callback, context as usize));
}
pub fn available() -> bool {
    lock(&HOST).is_some()
}
fn request(value: serde_json::Value) -> Result<()> {
    let (callback, context) =
        lock(&HOST)
            .as_ref()
            .copied()
            .ok_or(CoreError::BackendUnavailable(
                "signed macOS transparent-proxy extension",
            ))?;
    let text =
        CString::new(value.to_string()).map_err(|e| CoreError::InvalidConfig(e.to_string()))?;
    let mut output = [0u8; 4096];
    let success = unsafe {
        callback(
            text.as_ptr(),
            output.as_mut_ptr().cast(),
            output.len() as u32,
            context as *mut c_void,
        )
    };
    let size = output.iter().position(|c| *c == 0).unwrap_or(output.len());
    if success {
        Ok(())
    } else {
        Err(CoreError::Internal(format!(
            "macOS app routing: {}",
            String::from_utf8_lossy(&output[..size])
        )))
    }
}
struct Live {
    revision: u64,
    _adapter: Option<fcae_runtime::socks5p::Adapter>,
    checked: Instant,
}
#[derive(Default)]
pub struct MacNeBridge {
    live: Mutex<Option<Live>>,
    operation: Mutex<()>,
    cleanup: Mutex<Option<JoinHandle<()>>>,
    cancelled: AtomicBool,
}
impl MacNeBridge {
    pub fn new() -> Self {
        Self::default()
    }
    fn wait_cleanup(&self) {
        if let Some(worker) = lock(&self.cleanup).take() {
            let _ = worker.join();
        }
    }
    fn begin(
        &self,
        cfg: &SessionConfig,
        endpoints: &Endpoints,
        cancel: Option<&CancelToken>,
    ) -> Result<()> {
        let _operation = lock(&self.operation);
        self.wait_cleanup();
        if lock(&MAINTENANCE).active {
            return Err(CoreError::Internal(
                "macOS extension maintenance is still running".into(),
            ));
        }
        self.cancelled.store(false, Ordering::Release);
        if lock(&self.live).is_some() {
            return Err(CoreError::AlreadyRunning);
        }
        let policy = cfg
            .app_routing
            .as_ref()
            .ok_or_else(|| CoreError::InvalidConfig("no macOS application policy".into()))?
            .resolve()?;
        let (adapter, socks) =
            fcae_runtime::exit_adapter::psiphon_socks5p(cfg, endpoints, "macos-app-routing")?;
        // IPv4 loopback is the explicit host/extension contract. Do not silently
        // connect to an exposed LAN listener or a remotely supplied SOCKS relay.
        if socks.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) || socks.port() == 0 {
            return Err(CoreError::InvalidConfig(
                "macOS extension requires an IPv4 loopback SOCKS exit".into(),
            ));
        }
        if self.cancelled.load(Ordering::Acquire) || cancel.is_some_and(CancelToken::is_cancelled) {
            return Err(CoreError::StartFailed(
                "macOS app-routing start cancelled".into(),
            ));
        }
        if let Err(error) = request(
            json!({"action":"start","schema":1,"mode":policy.mode,"revision":policy.revision,"apps":policy.paths,"port":socks.port(),"udp":endpoints.udp||endpoints.psiphon_dns}),
        ) {
            let _ = request(json!({"action":"stop","schema":1,"revision":policy.revision}));
            return Err(error);
        }
        let mut slot = lock(&self.live);
        if self.cancelled.load(Ordering::Acquire) || cancel.is_some_and(CancelToken::is_cancelled) {
            drop(slot);
            let _ = request(json!({"action":"stop","schema":1,"revision":policy.revision}));
            return Err(CoreError::StartFailed(
                "macOS app-routing start cancelled".into(),
            ));
        }
        policy::acknowledge_macos_ne(policy.revision);
        *slot = Some(Live {
            revision: policy.revision,
            _adapter: adapter,
            checked: Instant::now(),
        });
        Ok(())
    }
}
impl TunBridge for MacNeBridge {
    fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<()> {
        self.begin(cfg, endpoints, None)
    }
    fn start_cancellable(
        &self,
        cfg: &SessionConfig,
        endpoints: &Endpoints,
        cancel: &CancelToken,
    ) -> Result<()> {
        self.begin(cfg, endpoints, Some(cancel))
    }
    fn stop(&self, timeout: Duration) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(live) = lock(&self.live).take() {
            let revision = live.revision;
            let worker = std::thread::Builder::new()
                .name("fcae-ne-cleanup".into())
                .spawn(move || {
                    if let Err(error) =
                        request(json!({"action":"stop","schema":1,"revision":revision}))
                    {
                        policy::degraded(revision, &error.to_string());
                        log::warn!("[app-routing] {error}");
                    }
                    policy::withdrawn(revision);
                    drop(live);
                });
            match worker {
                Ok(worker) => *lock(&self.cleanup) = Some(worker),
                Err(error) => {
                    policy::degraded(revision, &error.to_string());
                    log::error!("[app-routing] cleanup worker failed; extension watchdog will withdraw capture: {error}");
                }
            }
        }
        let deadline = Instant::now() + timeout;
        loop {
            if lock(&self.cleanup)
                .as_ref()
                .is_none_or(|worker| worker.is_finished())
            {
                self.wait_cleanup();
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn reclaim(&self, timeout: Duration) {
        self.stop(timeout);
        self.wait_cleanup();
    }
    fn is_running(&self) -> bool {
        lock(&self.live).is_some()
            || lock(&self.cleanup)
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
    }
    fn check_health(&self, _cfg: &SessionConfig) -> Result<()> {
        let _operation = lock(&self.operation);
        let revision = {
            let mut live = lock(&self.live);
            let live = live.as_mut().ok_or_else(|| {
                CoreError::Internal("macOS app-routing provider is not running".into())
            })?;
            if live.checked.elapsed() < Duration::from_secs(2) {
                return Ok(());
            }
            live.checked = Instant::now();
            live.revision
        };
        let result = request(json!({"action":"status","schema":1,"revision":revision}));
        if let Err(error) = &result {
            policy::degraded(revision, &error.to_string());
        }
        result
    }
}
impl Drop for MacNeBridge {
    fn drop(&mut self) {
        self.stop(Duration::ZERO);
        self.wait_cleanup();
    }
}

#[derive(Default)]
struct Maintenance {
    worker: Option<JoinHandle<()>>,
    message: String,
    active: bool,
}
static MAINTENANCE: LazyLock<Mutex<Maintenance>> =
    LazyLock::new(|| Mutex::new(Maintenance::default()));
pub fn maintenance(action: &str, running: bool) -> Option<String> {
    if action != "macos_ne_remove" && action != "macos_ne_maintenance_status" {
        return None;
    }
    let mut state = lock(&MAINTENANCE);
    if state
        .worker
        .as_ref()
        .is_some_and(|worker| worker.is_finished())
    {
        if let Some(worker) = state.worker.take() {
            let _ = worker.join();
        }
    }
    if action == "macos_ne_remove" {
        if running || state.active {
            return Some(json!({"ok":false,"active":state.active,"message":"Disconnect the VPN and wait for any pending extension work before removing its configuration."}).to_string());
        }
        state.active = true;
        state.message = "Removing inactive FCAE-owned transparent-proxy configuration...".into();
        match std::thread::Builder::new().name("fcae-ne-maintenance".into()).spawn(||{
            let result=request(json!({"action":"remove","schema":1,"revision":0}));
            let mut state=lock(&MAINTENANCE);state.active=false;
            state.message=match result{Ok(())=>"Inactive app-owned configuration removed. Signed extension files remain in the app bundle; connecting with the extension recreates its configuration.".into(),Err(error)=>error.to_string()};
        }){Ok(worker)=>state.worker=Some(worker),Err(error)=>{state.active=false;state.message=format!("Could not start extension maintenance: {error}");}}
    }
    Some(json!({"ok":true,"active":state.active,"message":state.message}).to_string())
}
pub fn shutdown_maintenance() {
    let worker = lock(&MAINTENANCE).worker.take();
    if let Some(worker) = worker {
        let _ = worker.join();
    }
}
