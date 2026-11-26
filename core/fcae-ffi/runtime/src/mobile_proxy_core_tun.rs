//! Native-core packet engines over the interface owned by the mobile VPN host.
//! The host retains its descriptor and owns routes, DNS and app selection.
use crate::{
    backend::{CancelToken, Endpoints},
    config::{SessionConfig, TunEngine},
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
struct Core(u64, CoreFfi, Option<crate::socks5p::Adapter>);
impl Drop for Core {
    fn drop(&mut self) {
        unsafe { (self.1.stop)(self.0) };
        self.2.take();
    }
}
#[derive(Default)]
pub struct ProxyCoreTunBridge {
    live: Mutex<Option<Core>>,
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
        let stopped = || {
            self.cancelled.load(Ordering::Acquire) || cancel.is_some_and(CancelToken::is_cancelled)
        };
        if stopped() {
            return Err(CoreError::StartFailed(
                "mobile TUN startup cancelled".into(),
            ));
        }
        let fd = cfg.tun.fd.filter(|fd| *fd >= 0).ok_or_else(|| {
            CoreError::PermissionDenied(
                "the system VPN provider has not supplied its packet interface".into(),
            )
        })?;
        // A valid descriptor is the host's authorization; never open /dev/net/tun,
        // change system routes, or run desktop elevation helpers on mobile.
        let (adapter, socks) = crate::exit_adapter::psiphon_socks5p(cfg, endpoints, "mobile-tun")?;
        if !socks.ip().is_loopback() || socks.port() == 0 {
            return Err(CoreError::InvalidConfig(
                "mobile TUN requires the session's loopback SOCKS exit".into(),
            ));
        }
        let mut value = configuration(cfg, socks, fd, endpoints.udp || endpoints.psiphon_dns)?;
        if cfg.tun.engine == TunEngine::SingBox {
            crate::destination_routing::apply_singbox(
                cfg,
                &mut value,
                socks,
                endpoints.udp || endpoints.psiphon_dns,
            )?;
        }
        let text =
            CString::new(value.to_string()).map_err(|e| CoreError::InvalidConfig(e.to_string()))?;
        let mut id = 0;
        unsafe {
            let error = (ffi.start)(text.as_ptr(), &mut id);
            if !error.is_null() {
                let message = CStr::from_ptr(error).to_string_lossy().into_owned();
                (ffi.string_free)(error);
                return Err(CoreError::StartFailed(message));
            }
        }
        if id == 0 {
            return Err(CoreError::StartFailed(
                "mobile TUN core returned no handle".into(),
            ));
        }
        let core = Core(id, ffi, adapter);
        let mut slot = lock(&self.live);
        if stopped() {
            drop(slot);
            drop(core);
            return Err(CoreError::StartFailed(
                "mobile TUN startup cancelled".into(),
            ));
        }
        *slot = Some(core);
        Ok(())
    }
    pub fn stop(&self, timeout: Duration) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(core) = lock(&self.live).take() {
            self.wait_cleanup();
            let worker = std::thread::Builder::new()
                .name("fcae-mobile-tun-cleanup".into())
                .spawn(move || drop(core));
            match worker {
                Ok(worker) => *lock(&self.cleanup) = Some(worker),
                Err(e) => log::error!("mobile TUN cleanup worker: {e}"),
            }
        }
        let deadline = Instant::now() + timeout;
        while lock(&self.cleanup)
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        if lock(&self.cleanup)
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
        {
            self.wait_cleanup();
        }
    }
    pub fn abort(&self) {
        self.stop(Duration::ZERO)
    }
    pub fn reclaim(&self, timeout: Duration) {
        self.stop(timeout);
        self.wait_cleanup()
    }
    pub fn is_running(&self) -> bool {
        lock(&self.live).is_some()
            || lock(&self.cleanup)
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
    }
    pub fn check_health(&self, _cfg: &SessionConfig) -> Result<()> {
        let live = lock(&self.live);
        let core = live
            .as_ref()
            .ok_or_else(|| CoreError::Internal("mobile TUN core is not running".into()))?;
        if unsafe { (core.1.running)(core.0) } == 0 {
            Err(CoreError::Internal("mobile TUN core stopped".into()))
        } else {
            Ok(())
        }
    }
}
impl Drop for ProxyCoreTunBridge {
    fn drop(&mut self) {
        self.stop(Duration::ZERO);
        self.wait_cleanup();
    }
}
fn configuration(
    cfg: &SessionConfig,
    socks: std::net::SocketAddr,
    fd: i32,
    udp: bool,
) -> Result<serde_json::Value> {
    use serde_json::json;
    let mut addresses = vec![cfg.tun.ipv4.clone()];
    if let Some(v6) = &cfg.tun.ipv6 {
        addresses.push(v6.clone());
    }
    Ok(match cfg.tun.engine {
        TunEngine::MetaSingTun => {
            json!({"fd":fd,"name":"fcae-mobile","mtu":cfg.tun.mtu,"addresses":addresses,"socks":socks.to_string(),"udp":udp,"fcae-tun-log-level":cfg.tun.tun_log_level})
        }
        TunEngine::SingBox => {
            let mut outbound = json!({"tag":"fcae-mobile-exit","type":"socks","server":socks.ip().to_string(),"server_port":socks.port(),"version":"5"});
            if !udp {
                outbound["network"] = json!("tcp");
            }
            json!({"fcae-mobile-fd":fd,"log":{"disabled":cfg.tun.singbox_tun_log_disabled(),"level":cfg.tun.singbox_tun_log_level()},"inbounds":[{"type":"tun","tag":"fcae-mobile-tun","interface_name":"fcae-mobile","mtu":cfg.tun.mtu,"address":addresses,"auto_route":false,"auto_redirect":false,"stack":"gvisor","dns_mode":"disabled"}],"outbounds":[outbound],"route":{"final":"fcae-mobile-exit","auto_detect_interface":false,"find_process":false}})
        }
        TunEngine::Xray => {
            json!({"fcae-mobile-fd":fd,"log":{"loglevel":cfg.tun.xray_tun_log_level()},"inbounds":[{"tag":"fcae-native-tun","protocol":"tun","settings":{"name":"fcae-mobile","mtu":cfg.tun.mtu,"gateway":addresses,"autoOutboundsInterface":"","autoSystemRoutingTable":[],"autoSystemDnsToGateway":false}}],"outbounds":[{"tag":"fcae-native-exit","protocol":"socks","settings":{"servers":[{"address":socks.ip().to_string(),"port":socks.port()}]}}],"routing":{"rules":[{"type":"field","inboundTag":["fcae-native-tun"],"outboundTag":"fcae-native-exit"}]}})
        }
        TunEngine::Mihomo => {
            let mut rules = Vec::new();
            if !udp {
                rules.push("NETWORK,udp,REJECT");
            }
            rules.push("MATCH,fcae-tun-exit");
            // Mihomo's TUN hijacks every query on port 53 unless `dns-hijack` says
            // otherwise (`dns-mode` only governs the system resolver settings), and
            // answers it from its own DNS module. That module is off here, so a
            // hijacked query is dropped: no name resolves through this engine, and
            // the rule that sends port 53 to the exit never sees a packet. The
            // empty list leaves DNS to the rules.
            json!({"fcae-mobile-fd":fd,"fcae-tun-addresses":addresses,"mode":"rule","log-level":cfg.tun.mihomo_tun_log_level(),"ipv6":cfg.tun.ipv6.is_some(),"find-process-mode":"off","profile":{"store-selected":false,"store-fake-ip":false},"dns":{"enable":false},"tun":{"enable":true,"device":"fcae-mobile","stack":"gvisor","dns-mode":"disabled","dns-hijack":[],"mtu":cfg.tun.mtu,"auto-route":false,"auto-redirect":false,"auto-detect-interface":false,"file-descriptor":fd,"recvmsgx":false,"sendmsgx":false},"proxies":[{"name":"fcae-tun-direct","type":"direct"},{"name":"fcae-tun-exit","type":"socks5","server":socks.ip().to_string(),"port":socks.port(),"udp":udp}],"rules":rules})
        }
        _ => {
            return Err(CoreError::InvalidConfig(
                "not a mobile proxy-core TUN engine".into(),
            ))
        }
    })
}
