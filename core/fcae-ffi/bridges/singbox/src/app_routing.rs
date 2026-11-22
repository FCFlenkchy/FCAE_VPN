//! Desktop captured-flow TUN on top of an already established exit chain.
//! sing-box owns packet/flow conversion; FCAE retains its existing route/DNS
//! guard, explicit undo, endpoint bypass and crash recovery implementation.
use fcae_runtime::{
    backend::{CancelToken, Endpoints},
    config::SessionConfig,
    desktop_flow_routing::{self},
    error::{CoreError, Result},
    session::TunBridge,
};
use std::{
    ffi::{CStr, CString},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
struct Core(u64);
impl Drop for Core {
    fn drop(&mut self) {
        unsafe {
            super::sb_stop(self.0);
        }
    }
}
struct Live {
    // Explicit Drop order: undo capture/DNS before closing packet transport and
    // the loopback adapter that carries Psiphon's transparent DNS gateway.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    routes: Option<fcae_runtime::unix_tun::TunGuard>,
    #[cfg(windows)]
    routes: Option<fcae_runtime::windows_tun::TunGuard>,
    core: Option<Core>,
    _adapter: Option<fcae_runtime::socks5p::Adapter>,
    revision: u64,
    device: String,
    last_health: Instant,
}
impl Drop for Live {
    fn drop(&mut self) {
        self.routes.take();
        self.core.take();
        self._adapter.take();
        desktop_flow_routing::withdrawn(self.revision);
    }
}
#[derive(Default)]
pub struct FlowTunBridge {
    live: Mutex<Option<Live>>,
    cleanup: Mutex<Option<JoinHandle<()>>>,
    operation: Mutex<()>,
    cancelled: AtomicBool,
}
impl FlowTunBridge {
    pub fn new() -> Self {
        Self::default()
    }
    fn wait_cleanup(&self) {
        if let Some(worker) = lock(&self.cleanup).take() {
            let _ = worker.join();
        }
    }
    fn start_policy(
        &self,
        cfg: &SessionConfig,
        endpoints: &Endpoints,
        cancel: Option<&CancelToken>,
    ) -> Result<()> {
        let _operation = lock(&self.operation);
        self.wait_cleanup();
        if lock(&self.live).is_some() {
            return Err(CoreError::AlreadyRunning);
        }
        self.cancelled.store(false, Ordering::Release);
        let policy = cfg
            .app_routing
            .as_ref()
            .ok_or_else(|| CoreError::InvalidConfig("no captured-flow policy was supplied".into()))?
            .resolve()?;
        if !fcae_go_bridge_supported() {
            return Err(CoreError::BackendUnavailable(
                "embedded sing-box flow router",
            ));
        }
        if !fcae_runtime::privilege::is_privileged() {
            return Err(CoreError::PermissionDenied(
                "desktop flow routing needs the app's normal root/administrator VPN permission"
                    .into(),
            ));
        }
        #[cfg(windows)]
        fcae_runtime::windows_dll::ensure_wintun(fcae_runtime::wintun::wintun_bytes())?;
        let device = device_name(cfg)?;
        let (adapter, socks) =
            fcae_runtime::exit_adapter::psiphon_socks5p(cfg, endpoints, "app-routing")?;
        let value = policy.config(cfg, socks, &device, endpoints.udp || endpoints.psiphon_dns)?;
        let text =
            CString::new(value.to_string()).map_err(|e| CoreError::InvalidConfig(e.to_string()))?;
        unsafe {
            let error = super::sb_check(text.as_ptr());
            if !error.is_null() {
                let message = CStr::from_ptr(error).to_string_lossy().into_owned();
                super::sb_string_free(error);
                return Err(CoreError::InvalidConfig(message));
            }
        }
        let stopped = || {
            self.cancelled.load(Ordering::Acquire) || cancel.is_some_and(CancelToken::is_cancelled)
        };
        if stopped() {
            return Err(CoreError::StartFailed(
                "flow-routing start cancelled".into(),
            ));
        }
        let mut id = 0;
        unsafe {
            let error = super::sb_start(text.as_ptr(), &mut id);
            if !error.is_null() {
                let message = CStr::from_ptr(error).to_string_lossy().into_owned();
                super::sb_string_free(error);
                return Err(CoreError::StartFailed(message));
            }
        }
        let core = Core(id);
        if id == 0 {
            return Err(CoreError::StartFailed(
                "flow core returned no instance handle".into(),
            ));
        }
        let mut live = Live {
            routes: None,
            core: Some(core),
            _adapter: adapter,
            revision: policy.revision,
            device,
            last_health: Instant::now(),
        };
        if stopped() {
            return Err(CoreError::StartFailed(
                "flow-routing start cancelled".into(),
            ));
        }
        let mut routed_cfg = cfg.clone();
        routed_cfg.tun.name = live.device.clone();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if !device_exists(&live.device, Duration::from_secs(3)) {
                return Err(CoreError::StartFailed("flow TUN did not appear".into()));
            }
            live.routes = Some(fcae_runtime::unix_tun::TunGuard::configure(
                &routed_cfg,
                &live.device,
                endpoints.peer_ip.as_deref(),
                false,
            )?);
        }
        #[cfg(windows)]
        {
            live.routes = Some(fcae_runtime::windows_tun::TunGuard::configure_named(
                &routed_cfg,
                endpoints.peer_ip.as_deref(),
            )?);
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(routes) = live.routes.as_mut() {
            routes.check_health()?;
        }
        #[cfg(windows)]
        if let Some(routes) = live.routes.as_ref() {
            routes.check_health()?;
        }
        let mut slot = lock(&self.live);
        if stopped() {
            return Err(CoreError::StartFailed(
                "flow-routing start cancelled".into(),
            ));
        }
        desktop_flow_routing::acknowledge(policy.revision);
        *slot = Some(live);
        Ok(())
    }
}
fn fcae_go_bridge_supported() -> bool {
    fcae_bridge_tun2socks::is_supported()
}
fn device_name(cfg: &SessionConfig) -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        // Pin our own requested utun name; never guess the most recently created
        // interface, which can belong to another VPN starting concurrently.
        let used = fcae_runtime::unix_tun::utun_devices();
        for n in 32..256 {
            let name = format!("utun{n}");
            if !used.contains(&name) {
                return Ok(name);
            }
        }
        let _ = cfg;
        Err(CoreError::StartFailed(
            "no free flow-routing utun name".into(),
        ))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(cfg.tun.name.clone())
    }
}
impl TunBridge for FlowTunBridge {
    fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<()> {
        self.start_policy(cfg, endpoints, None)
    }
    fn start_cancellable(
        &self,
        cfg: &SessionConfig,
        endpoints: &Endpoints,
        cancel: &CancelToken,
    ) -> Result<()> {
        self.start_policy(cfg, endpoints, Some(cancel))
    }
    fn stop(&self, timeout: Duration) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(live) = lock(&self.live).take() {
            let mut cleanup = lock(&self.cleanup);
            if let Some(previous) = cleanup.take() {
                let _ = previous.join();
            }
            // The handle stays owned by this bridge, and startup/reclaim joins
            // it before another device is allowed to reuse routes or DNS.
            match std::thread::Builder::new()
                .name("fcae-flow-cleanup".into())
                .spawn(move || drop(live))
            {
                Ok(worker) => *cleanup = Some(worker),
                Err(error) => log::error!("[app-routing] cleanup worker could not start: {error}"),
            }
        }
        let deadline = Instant::now() + timeout;
        loop {
            let finished = lock(&self.cleanup)
                .as_ref()
                .is_none_or(|worker| worker.is_finished());
            if finished {
                self.wait_cleanup();
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn abort(&self) {
        self.stop(Duration::ZERO);
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
        let mut live = lock(&self.live);
        let live = live
            .as_mut()
            .ok_or_else(|| CoreError::Internal("flow-routing provider is not running".into()))?;
        let result = (|| {
            let core = live
                .core
                .as_ref()
                .ok_or_else(|| CoreError::Internal("flow core handle missing".into()))?;
            if unsafe { super::sb_running(core.0) } == 0 {
                return Err(CoreError::Internal("flow-routing core stopped".into()));
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if !device_exists(&live.device, Duration::ZERO) {
                return Err(CoreError::Internal(
                    "flow-routing interface disappeared".into(),
                ));
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if live.last_health.elapsed() >= Duration::from_secs(2) {
                if let Some(routes) = live.routes.as_mut() {
                    routes.check_health()?;
                }
                live.last_health = Instant::now();
            }
            #[cfg(windows)]
            if let Some(routes) = live.routes.as_ref() {
                routes.check_health()?;
                live.last_health = Instant::now();
            }
            Ok(())
        })();
        if let Err(error) = &result {
            desktop_flow_routing::degraded(live.revision, &error.to_string());
        }
        result
    }
}
impl Drop for FlowTunBridge {
    fn drop(&mut self) {
        self.stop(Duration::ZERO);
        self.wait_cleanup();
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn device_exists(device: &str, budget: Duration) -> bool {
    #[cfg(target_os = "linux")]
    {
        fcae_runtime::unix_tun::wait_for_device(device, false, budget)
    }
    #[cfg(target_os = "macos")]
    {
        let deadline = Instant::now() + budget;
        loop {
            if fcae_runtime::unix_tun::utun_devices()
                .iter()
                .any(|name| name == device)
            {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
