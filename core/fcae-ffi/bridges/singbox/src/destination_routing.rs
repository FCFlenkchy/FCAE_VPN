//! Shared, per-session SOCKS routing stage before the existing final exit.
//! Packet engines and the native macOS flow provider both consume this endpoint.
use fcae_runtime::{
    backend::Endpoints,
    config::SessionConfig,
    error::{CoreError, Result},
};
use std::{
    ffi::{CStr, CString},
    net::TcpListener,
    sync::Mutex,
};
struct Live {
    handle: u64,
    _adapter: Option<fcae_runtime::socks5p::Adapter>,
    endpoints: Endpoints,
}
impl Drop for Live {
    fn drop(&mut self) {
        unsafe {
            super::sb_stop(self.handle);
        }
    }
}
#[derive(Default)]
pub struct DestinationRouter {
    live: Mutex<Option<Live>>,
}
fn lock<T>(value: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    value.lock().unwrap_or_else(|error| error.into_inner())
}
impl DestinationRouter {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<Endpoints> {
        if !fcae_runtime::destination_routing::uses_shared_stage(cfg) {
            return Ok(endpoints.clone());
        }
        // Off/empty policies still carry captured DNS through the exit. The
        // shared DNS handler also translates UDP DNS for TCP-only exits.
        let dns_only = fcae_runtime::destination_routing::Policy {
            schema: 1,
            mode: 2,
            rules: Vec::new(),
        };
        let policy = if fcae_runtime::destination_routing::uses_native(cfg) {
            &dns_only
        } else {
            cfg.destinations.as_ref().unwrap_or(&dns_only)
        };
        let mut slot = lock(&self.live);
        if let Some(live) = slot.as_ref() {
            return Ok(live.endpoints.clone());
        }
        let (adapter, socks) =
            fcae_runtime::exit_adapter::psiphon_socks5p(cfg, endpoints, "destination-routing")?;
        let reserved = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .map_err(|error| CoreError::Internal(error.to_string()))?;
        let listen = reserved
            .local_addr()
            .map_err(|error| CoreError::Internal(error.to_string()))?;
        let config = fcae_runtime::destination_routing::session_config(
            policy,
            cfg,
            socks,
            listen.port(),
            endpoints.udp || endpoints.psiphon_dns,
        )?;
        let text = CString::new(config.to_string())
            .map_err(|error| CoreError::InvalidConfig(error.to_string()))?;
        unsafe {
            let error = super::sb_check(text.as_ptr());
            if !error.is_null() {
                let text = CStr::from_ptr(error).to_string_lossy().into_owned();
                super::sb_string_free(error);
                return Err(CoreError::InvalidConfig(text));
            }
        }
        // A bind race fails core startup; never treat another process listening
        // on this port as acknowledgement that our router started.
        drop(reserved);
        let mut handle = 0;
        unsafe {
            let error = super::sb_destination_start(text.as_ptr(), &mut handle);
            if !error.is_null() {
                let text = CStr::from_ptr(error).to_string_lossy().into_owned();
                super::sb_string_free(error);
                return Err(CoreError::StartFailed(text));
            }
        }
        if handle == 0 {
            return Err(CoreError::StartFailed(
                "destination router returned no instance handle".into(),
            ));
        }
        let mut routed = endpoints.clone();
        routed.socks = Some(listen);
        routed.psiphon_dns = false;
        // UDP direct is supported even with a TCP-only exit. VPN-required UDP
        // stays on the exit rule and is rejected, never retried as DIRECT.
        routed.udp = true;
        *slot = Some(Live {
            handle,
            _adapter: adapter,
            endpoints: routed.clone(),
        });
        Ok(routed)
    }
    pub fn stop(&self) {
        let live = lock(&self.live).take();
        drop(live);
    }
    pub fn check_health(&self) -> Result<()> {
        let live = lock(&self.live);
        if live
            .as_ref()
            .is_none_or(|live| unsafe { super::sb_running(live.handle) } == 0)
        {
            return Err(CoreError::Internal(
                "destination router stopped; reconnect required".into(),
            ));
        }
        Ok(())
    }
}
impl Drop for DestinationRouter {
    fn drop(&mut self) {
        self.stop();
    }
}
