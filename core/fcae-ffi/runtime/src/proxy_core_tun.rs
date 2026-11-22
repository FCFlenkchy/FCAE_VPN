//! Core TUN engines in front of the established exit chain.
//! The embedded core owns packet/flow conversion; FCAE retains route/DNS
//! guard, explicit undo, endpoint bypass and crash recovery implementation.
use crate::{
    backend::{CancelToken, Endpoints},
    config::SessionConfig,
    desktop_flow_routing::{self},
    error::{CoreError, Result},
    proxy_cores::CoreFfi,
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
struct Core(u64, CoreFfi);
impl Drop for Core {
    fn drop(&mut self) {
        unsafe {
            (self.1.stop)(self.0);
        }
    }
}
struct Live {
    // Explicit Drop order: undo capture/DNS before closing packet transport and
    // the loopback adapter that carries Psiphon's transparent DNS gateway.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    routes: Option<crate::unix_tun::TunGuard>,
    #[cfg(windows)]
    routes: Option<crate::windows_tun::TunGuard>,
    core: Option<Core>,
    _adapter: Option<crate::socks5p::Adapter>,
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
pub struct ProxyCoreTunBridge {
    live: Mutex<Option<Live>>,
    cleanup: Mutex<Option<JoinHandle<()>>>,
    operation: Mutex<()>,
    cancelled: AtomicBool,
}
impl ProxyCoreTunBridge {
    pub fn new() -> Self {
        Self::default()
    }
    fn wait_cleanup(&self) {
        if let Some(worker) = lock(&self.cleanup).take() {
            let _ = worker.join();
        }
    }
    pub fn start_with(
        &self,
        cfg: &SessionConfig,
        endpoints: &Endpoints,
        cancel: Option<&CancelToken>,
        ffi: CoreFfi,
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
            .map(|policy| policy.resolve())
            .transpose()?;
        if !crate::privilege::is_privileged() {
            return Err(CoreError::PermissionDenied(
                "desktop flow routing needs the app's normal root/administrator VPN permission"
                    .into(),
            ));
        }
        #[cfg(windows)]
        crate::windows_dll::ensure_wintun(crate::wintun::wintun_bytes())?;
        let device = device_name(cfg)?;
        let (adapter, socks) = crate::exit_adapter::psiphon_socks5p(cfg, endpoints, "app-routing")?;
        let mut value = configuration(
            cfg,
            socks,
            &device,
            endpoints.udp || endpoints.psiphon_dns,
            policy.as_ref(),
        )?;
        if cfg.tun.engine == crate::config::TunEngine::Mihomo {
            crate::destination_routing::apply_mihomo(
                cfg,
                &mut value,
                endpoints.udp || endpoints.psiphon_dns,
            )?;
        }
        let text =
            CString::new(value.to_string()).map_err(|e| CoreError::InvalidConfig(e.to_string()))?;
        let stopped = || {
            self.cancelled.load(Ordering::Acquire) || cancel.is_some_and(CancelToken::is_cancelled)
        };
        if stopped() {
            return Err(CoreError::StartFailed(
                "flow-routing start cancelled".into(),
            ));
        }
        log::info!(
            "[tun] starting {:?}: interface={}, app_policy={}",
            cfg.tun.engine,
            device,
            policy.is_some()
        );
        let start = || -> Result<u64> {
            if stopped() {
                return Err(CoreError::StartFailed("TUN startup cancelled".into()));
            }
            let mut id = 0;
            unsafe {
                let error = (ffi.start)(text.as_ptr(), &mut id);
                if !error.is_null() {
                    let message = CStr::from_ptr(error).to_string_lossy().into_owned();
                    (ffi.string_free)(error);
                    if id != 0 {
                        (ffi.stop)(id);
                    }
                    return Err(CoreError::StartFailed(message));
                }
            }
            if id == 0 {
                return Err(CoreError::StartFailed(
                    "TUN core returned no instance handle".into(),
                ));
            }
            Ok(id)
        };
        #[cfg(windows)]
        let id = crate::windows_dll::start_with_adapter_repair(&device, stopped, start)?;
        #[cfg(not(windows))]
        let id = start()?;
        let core = Core(id, ffi);
        let mut live = Live {
            routes: None,
            core: Some(core),
            _adapter: adapter,
            revision: policy.as_ref().map_or(0, |policy| policy.revision),
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
            live.routes = Some(crate::unix_tun::TunGuard::configure(
                &routed_cfg,
                &live.device,
                endpoints.peer_ip.as_deref(),
                false,
            )?);
        }
        #[cfg(windows)]
        {
            live.routes = Some(crate::windows_tun::TunGuard::configure_named(
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
        if let Some(policy) = policy.as_ref() {
            desktop_flow_routing::acknowledge(policy.revision);
        }
        *slot = Some(live);
        Ok(())
    }
}
fn device_name(cfg: &SessionConfig) -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        // Pin our own requested utun name; never guess the most recently created
        // interface, which can belong to another VPN starting concurrently.
        let used = crate::unix_tun::utun_devices();
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
impl ProxyCoreTunBridge {
    pub fn stop(&self, timeout: Duration) {
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
    pub fn abort(&self) {
        self.stop(Duration::ZERO);
    }
    pub fn reclaim(&self, timeout: Duration) {
        self.stop(timeout);
        self.wait_cleanup();
    }
    pub fn is_running(&self) -> bool {
        lock(&self.live).is_some()
            || lock(&self.cleanup)
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
    }
    pub fn check_health(&self, _cfg: &SessionConfig) -> Result<()> {
        let mut live = lock(&self.live);
        let live = live
            .as_mut()
            .ok_or_else(|| CoreError::Internal("flow-routing provider is not running".into()))?;
        let result = (|| {
            let core = live
                .core
                .as_ref()
                .ok_or_else(|| CoreError::Internal("flow core handle missing".into()))?;
            if unsafe { (core.1.running)(core.0) } == 0 {
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
impl Drop for ProxyCoreTunBridge {
    fn drop(&mut self) {
        self.stop(Duration::ZERO);
        self.wait_cleanup();
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn device_exists(device: &str, budget: Duration) -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::unix_tun::wait_for_device(device, false, budget)
    }
    #[cfg(target_os = "macos")]
    {
        let deadline = Instant::now() + budget;
        loop {
            if crate::unix_tun::utun_devices()
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

fn configuration(
    cfg: &SessionConfig,
    socks: std::net::SocketAddr,
    device: &str,
    udp: bool,
    policy: Option<&desktop_flow_routing::FlowPolicy>,
) -> Result<serde_json::Value> {
    use crate::config::TunEngine;
    use serde_json::json;
    let mut addresses = vec![cfg.tun.ipv4.clone()];
    if let Some(v6) = &cfg.tun.ipv6 {
        addresses.push(v6.clone());
    }
    match cfg.tun.engine {
        TunEngine::MetaSingTun => {
            let mut value = json!({"name":device,"mtu":cfg.tun.mtu,"addresses":addresses,"socks":socks.to_string(),"udp":udp});
            if let Some(policy) = policy {
                let mut routing = policy.config(cfg, socks, device, udp)?;
                routing["inbounds"] = json!([]);
                value["routing"] = routing;
                // DIRECT UDP is supported even if the VPN exit is TCP-only.
                // The native router still rejects VPN-required UDP.
                value["udp"] = json!(true);
            }
            Ok(value)
        }

        TunEngine::Xray => {
            if policy.is_some() {
                return Err(CoreError::InvalidConfig(
                    "Select sing-box or Mihomo TUN for per-app splitting".into(),
                ));
            }
            Ok(
                json!({"log":{"loglevel":"warning"},"inbounds":[{"tag":"fcae-native-tun","protocol":"tun","settings":{"name":device,"mtu":cfg.tun.mtu,"gateway":addresses,"dns":[],"autoSystemRoutingTable":[],"autoOutboundsInterface":""}}],"routing":{"rules":[{"type":"field","inboundTag":["fcae-native-tun"],"outboundTag":"fcae-native-exit"}]},"outbounds":[{"tag":"fcae-native-exit","protocol":"socks","settings":{"servers":[{"address":socks.ip().to_string(),"port":socks.port()}]}}]}),
            )
        }
        TunEngine::Mihomo => {
            let mut rules = vec![
                "DST-PORT,53,fcae-tun-exit".to_owned(),
                "DST-PORT,853,fcae-tun-exit".to_owned(),
            ];
            let process = |path: &str, out: &str| {
                let mut regex = if cfg!(windows) {
                    "(?i)^".to_owned()
                } else {
                    "^".to_owned()
                };
                for c in path.chars() {
                    if c == ',' {
                        regex.push_str("\\x2c");
                    } else {
                        if "\\.+*?()|[]{}^$".contains(c) {
                            regex.push('\\');
                        }
                        regex.push(c);
                    }
                }
                regex.push('$');
                format!("PROCESS-PATH-REGEX,{regex},{out}")
            };
            if let Ok(own) = std::env::current_exe() {
                if let Some(path) = own.to_str() {
                    rules.push(process(path, "fcae-tun-direct"));
                }
            }
            if let Some(policy) = policy {
                for path in &policy.paths {
                    rules.push(process(
                        path,
                        if policy.mode == 1 {
                            "fcae-tun-exit"
                        } else {
                            "fcae-tun-direct"
                        },
                    ));
                }
                if policy.mode == 1 {
                    rules.push("PROCESS-PATH-REGEX,.+,fcae-tun-direct".into());
                }
            }
            rules.push("MATCH,fcae-tun-exit".into());
            // Mihomo skips rules whose outbound cannot carry UDP. Reject
            // VPN-required UDP explicitly so it cannot fall through to DIRECT.
            if !udp {
                let mut guarded = Vec::with_capacity(rules.len() * 2);
                for rule in rules {
                    if let Some(condition) = rule.strip_suffix(",fcae-tun-exit") {
                        guarded.push(if condition == "MATCH" {
                            "NETWORK,udp,REJECT".into()
                        } else {
                            format!("AND,((NETWORK,udp),({condition})),REJECT")
                        });
                    }
                    guarded.push(rule);
                }
                rules = guarded;
            }

            let mut value = json!({"mode":"rule","log-level":"warning","ipv6":cfg.tun.ipv6.is_some(),"find-process-mode":"always","profile":{"store-selected":false,"store-fake-ip":false},"dns":{"enable":false},"tun":{"enable":true,"device":device,"stack":"gvisor","dns-mode":"disabled","mtu":cfg.tun.mtu,"auto-route":false,"auto-redirect":false,"auto-detect-interface":false},"fcae-tun-addresses":addresses,"proxies":[{"name":"fcae-tun-direct","type":"direct"},{"name":"fcae-tun-exit","type":"socks5","server":socks.ip().to_string(),"port":socks.port(),"udp":udp}],"rules":rules});
            #[cfg(target_os = "macos")]
            {
                let output = crate::tun_dns::run("route", &["-n", "get", "default"])?;
                let interface = output
                    .lines()
                    .find_map(|line| line.trim().strip_prefix("interface:"))
                    .map(str::trim)
                    .filter(|name| {
                        !name.is_empty()
                            && *name != device
                            && *name != "lo0"
                            && name.len() <= 15
                            && name
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                    })
                    .ok_or_else(|| {
                        CoreError::InvalidConfig(
                            "no pre-capture egress interface for Mihomo TUN".into(),
                        )
                    })?;
                value["proxies"][0]["interface-name"] = json!(interface);
            }
            #[cfg(not(target_os = "macos"))]
            {
                value["tun"]["auto-detect-interface"] = json!(true);
            }
            Ok(value)
        }
        _ => Err(CoreError::InvalidConfig(
            "not a native core TUN engine".into(),
        )),
    }
}
