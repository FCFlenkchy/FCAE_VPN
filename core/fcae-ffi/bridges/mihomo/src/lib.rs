//! # fcae-bridge-mihomo — Mihomo backend
//!
//! Mihomo is compiled from source at build time into the app's single Go
//! archive and started in this process. This crate is its bridge: the Mihomo
//! dialect (config grammar) plus the C entry points of its shim, on top of the
//! shared planning, supervision and teardown in [`fcae_runtime::proxy_cores`].

pub mod config;

use std::ffi::{c_char, c_int};
use std::sync::Arc;

use async_trait::async_trait;
use fcae_abi::FcaeBackend;
use fcae_runtime::backend::{Backend, BackendContext, BackendHandle, BackendId, Capabilities};
use fcae_runtime::proxy_cores::{halt_all, start, CoreFfi, Dialect, Plan};
use fcae_runtime::Result;

// Exported by `bridges/mihomo/go/bridge.go` through the shared archive. The
// prefix is per core: one Go package cannot export `start` twice.
extern "C" {
    fn mihomo_check(config: *const c_char) -> *mut c_char;
    fn mihomo_set_home(path: *const c_char) -> *mut c_char;
    fn mihomo_tun_stop(handle:u64);
    fn mihomo_tun_running(handle:u64)->c_int;
    fn mihomo_tun_start(config:*const c_char,handle:*mut u64)->*mut c_char;
    fn mihomo_start(config: *const c_char, handle: *mut u64) -> *mut c_char;
    fn mihomo_stop(handle: u64);
    fn mihomo_stop_all();
    fn mihomo_running(handle: u64) -> c_int;
    fn mihomo_string_free(value: *mut c_char);
    fn mihomo_stats(handle: u64, uplink: *mut i64, downlink: *mut i64) -> c_int;
    fn mihomo_set_log(sink: LogSink, gate: c_int);
    fn mihomo_set_tun_log(sink: LogSink, gate: c_int);
    fn mihomo_listeners(buf: *mut c_char, capacity: c_int) -> c_int;
}

/// Host log sink, implemented here and called from the core's own goroutines.
type LogSink = Option<unsafe extern "C" fn(c_int, *const c_char)>;

/// Receives the core's log lines and hands them to the app console.
unsafe extern "C" fn log_sink(level: c_int, message: *const c_char) {
    fcae_runtime::proxy_cores::forward_log("mihomo", level, message);
}

unsafe extern "C" fn tun_log_sink(level: c_int, message: *const c_char) {
    fcae_runtime::proxy_cores::forward_log("mihomo-tun", level, message);
}

fn tun_log_gate(level: u8) -> c_int {
    match level {
        3 => 2,
        4 => 3,
        5 => 4,
        _ => 1,
    }
}

pub struct MihomoDialect;

impl Dialect for MihomoDialect {
    const DISPLAY: &'static str = "Mihomo";
    const FFI: CoreFfi = CoreFfi {
        start: mihomo_start,
        stop: mihomo_stop,
        stop_all: mihomo_stop_all,
        running: mihomo_running,
        string_free: mihomo_string_free,
        stats: mihomo_stats,
        set_log: mihomo_set_log,
        listeners: mihomo_listeners,
    };
    const LOG_SINK: unsafe extern "C" fn(c_int, *const c_char) = log_sink;
    // Go's resolver falls back to the platform's own when it cannot read
    // /etc/resolv.conf, which is what Android hands it.
    const RESOLVES_SERVER: bool = true;

    fn generate(plan: &Plan<'_>) -> std::result::Result<serde_json::Value, String> {
        config::generate(plan)
    }
}

pub struct MihomoBackend;

#[async_trait]
impl Backend for MihomoBackend {
    fn id(&self) -> BackendId {
        BackendId::Mihomo
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            socks: true,
            http_proxy: true,
            // The uplink is whatever the profile names; there is no WARP-style
            // gateway to scan or pin.
            gateway_scanning: false,
            routing_rules: true,
            requires_privileges: false,
        }
    }

    fn availability(&self) -> std::result::Result<(), String> {
        if fcae_bridge_tun2socks::is_supported() {
            Ok(())
        } else {
            Err("the Go archive is stubbed in this build; Mihomo cannot start".into())
        }
    }

    async fn start(&self, cx: BackendContext) -> Result<Box<dyn BackendHandle>> {
        let home = cx
            .config
            .data_dir
            .as_ref()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("mihomo");
        let home = std::ffi::CString::new(home.to_string_lossy().as_bytes())
            .map_err(|e| fcae_runtime::error::CoreError::InvalidConfig(e.to_string()))?;
        unsafe {
            let error = mihomo_set_home(home.as_ptr());
            if !error.is_null() {
                let message = std::ffi::CStr::from_ptr(error)
                    .to_string_lossy()
                    .into_owned();
                mihomo_string_free(error);
                return Err(fcae_runtime::error::CoreError::StartFailed(message));
            }
        }
        Ok(Box::new(start::<MihomoDialect>(&cx).await?))
    }

    /// Reclaim the singleton after abandoned or cancelled session starts.
    async fn drain(&self) {
        halt_all(MihomoDialect::FFI, FcaeBackend::Mihomo).await;
    }

    /// [`Self::drain`] without a runtime to run it on.
    ///
    /// The shim's own `stop_all` is synchronous and idempotent, so it can be
    /// called straight from a teardown path that has no async context left --
    /// the last word on a core whose start was abandoned, or whose session
    /// worker died before it could drain.
    fn reclaim_blocking(&self) {
        unsafe { mihomo_stop_all() };
        // Closed, so none of them is live: a teardown that could not await the
        // drain must not leave the connection info listing cores that are gone.
        fcae_runtime::proxy_cores::retire_all(FcaeBackend::Mihomo);
    }
}

/// The in-process core's actual managed listeners.
pub fn listeners() -> Vec<fcae_runtime::proxy_cores::CoreListener> {
    fcae_runtime::proxy_cores::live_listeners(MihomoDialect::FFI)
}

/// Checks the managed configuration through the embedded core's parser, without
/// starting listeners, contacting providers, or replacing a live session.
pub fn install_validator() {
    fcae_runtime::saved_configs::register_validator(FcaeBackend::Mihomo, |profile| {
        let routing = fcae_runtime::config::RoutingConfig::default();
        let plan = Plan { profile, socks: Some("127.0.0.1:1080".parse().unwrap()),
            http: Some("127.0.0.1:1081".parse().unwrap()),
            level: fcae_runtime::proxy_cores::Level::Off, upstream: None, routing: &routing, dial: None };
        let value = config::generate(&plan)?;
        let text = std::ffi::CString::new(value.to_string()).map_err(|_| "config contains NUL")?;
        unsafe {
            let error = mihomo_check(text.as_ptr());
            if error.is_null() { return Ok(()); }
            let message = std::ffi::CStr::from_ptr(error).to_string_lossy().into_owned();
            mihomo_string_free(error);
            Err(message)
        }
    });
}

pub fn register() {
    install_validator();
    fcae_runtime::registry::register(FcaeBackend::Mihomo, || Arc::new(MihomoBackend));
}

pub fn tun_ffi(tun_log_level: u8) -> CoreFfi {
    unsafe { mihomo_set_tun_log(Some(tun_log_sink), tun_log_gate(tun_log_level)); }
    CoreFfi {
        start: mihomo_tun_start,
        stop: mihomo_tun_stop,
        running: mihomo_tun_running,
        ..MihomoDialect::FFI
    }
}
pub fn prepare_tun(cfg:&fcae_runtime::config::SessionConfig)->Result<()> {
    let home=cfg.data_dir.as_ref().map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir).join("mihomo");
    let home=std::ffi::CString::new(home.to_string_lossy().as_bytes()).map_err(|e|fcae_runtime::CoreError::InvalidConfig(e.to_string()))?;
    unsafe{let error=mihomo_set_home(home.as_ptr());if !error.is_null(){let message=std::ffi::CStr::from_ptr(error).to_string_lossy().into_owned();mihomo_string_free(error);return Err(fcae_runtime::CoreError::StartFailed(message));}}
    Ok(())
}
