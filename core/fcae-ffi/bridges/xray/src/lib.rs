//! # fcae-bridge-xray — Xray-core backend
//!
//! Xray-core is compiled from source at build time into the app's single Go
//! archive and started in this process. This crate is its bridge: the Xray
//! dialect (config grammar) plus the C entry points of its shim, on top of the
//! shared planning, supervision and teardown in [`fcae_runtime::proxy_cores`].

pub mod config;

use std::ffi::{c_char, c_int};
use std::sync::Arc;

use async_trait::async_trait;
use fcae_abi::FcaeBackend;
use fcae_runtime::backend::{Backend, BackendContext, BackendHandle, BackendId, Capabilities};
use fcae_runtime::proxy_cores::{CoreFfi, Dialect, Plan, halt_all, start};
use fcae_runtime::Result;

// Exported by `bridges/xray/go/bridge.go` through the shared archive. The
// prefix is per core: one Go package cannot export `start` twice.
extern "C" {
    fn xray_check(config: *const c_char) -> *mut c_char;
    fn xray_tun_start(config:*const c_char,handle:*mut u64)->*mut c_char;
    fn xray_tun_stop(handle:u64);
    fn xray_tun_running(handle:u64)->c_int;
    fn xray_start(config: *const c_char, handle: *mut u64) -> *mut c_char;
    fn xray_stop(handle: u64);
    fn xray_stop_all();
    fn xray_running(handle: u64) -> c_int;
    fn xray_string_free(value: *mut c_char);
    fn xray_stats(handle: u64, uplink: *mut i64, downlink: *mut i64) -> c_int;
    fn xray_set_log(sink: LogSink, gate: c_int);
    fn xray_listeners(buf: *mut c_char, capacity: c_int) -> c_int;
}

/// Host log sink, implemented here and called from the core's own goroutines.
type LogSink = Option<unsafe extern "C" fn(c_int, *const c_char)>;

/// Receives the core's log lines and hands them to the app console.
unsafe extern "C" fn log_sink(level: c_int, message: *const c_char) {
    fcae_runtime::proxy_cores::forward_log("xray", level, message);
}

pub struct XrayDialect;

impl Dialect for XrayDialect {
    const DISPLAY: &'static str = "Xray-core";
    const FFI: CoreFfi = CoreFfi {
        start: xray_start,
        stop: xray_stop,
        stop_all: xray_stop_all,
        running: xray_running,
        string_free: xray_string_free,
        stats: xray_stats,
        set_log: xray_set_log,
        listeners: xray_listeners,
    };
    const LOG_SINK: unsafe extern "C" fn(c_int, *const c_char) = log_sink;
    // Go's resolver falls back to the platform's own when it cannot read
    // /etc/resolv.conf, which is what Android hands it.
    const RESOLVES_SERVER: bool = true;

    fn generate(plan: &Plan<'_>) -> std::result::Result<serde_json::Value, String> {
        config::generate(plan)
    }
}

pub struct XrayBackend;

#[async_trait]
impl Backend for XrayBackend {
    fn id(&self) -> BackendId {
        BackendId::Xray
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
            Err("the Go archive is stubbed in this build; Xray-core cannot start".into())
        }
    }

    async fn start(&self, cx: BackendContext) -> Result<Box<dyn BackendHandle>> {
        Ok(Box::new(start::<XrayDialect>(&cx).await?))
    }

    /// No instance outlives its session.
    ///
    /// A start already stops the instance it abandoned, and a handle stops the
    /// one it owns, so this is the net under the paths that cannot: a stop the
    /// supervisor could not await, a handle dropped where only the guard ran. It
    /// closes every instance of this core, which is what a chained session --
    /// two Xray hops -- needs from it. The shim's stops are idempotent, and they
    /// are what tells the shared Go runtime an engine is gone, which is what
    /// hands the heap back between sessions.
    async fn drain(&self) {
        halt_all(XrayDialect::FFI, FcaeBackend::Xray).await;
    }

    /// [`Self::drain`] without a runtime to run it on.
    ///
    /// The shim's own `stop_all` is synchronous and idempotent, so it can be
    /// called straight from a teardown path that has no async context left --
    /// the last word on a core whose start was abandoned, or whose session
    /// worker died before it could drain.
    fn reclaim_blocking(&self) {
        unsafe { xray_stop_all() };
        // Closed, so none of them is live: a teardown that could not await the
        // drain must not leave the connection info listing cores that are gone.
        fcae_runtime::proxy_cores::retire_all(FcaeBackend::Xray);
    }
}

/// Every inbound of every live xray instance, as the core itself reports
/// them.
///
/// The settings name one port for a session that may run several instances --
/// a chained hop, or a native config with more than one inbound -- so the app
/// asks the core what is actually listening instead of deciding for it.
pub fn listeners() -> Vec<fcae_runtime::proxy_cores::CoreListener> {
    fcae_runtime::proxy_cores::live_listeners(XrayDialect::FFI)
}

/// Checks the managed configuration through the embedded core's parser, without
/// starting listeners, contacting providers, or replacing a live session.
pub fn install_validator() {
    fcae_runtime::saved_configs::register_validator(FcaeBackend::Xray, |profile| {
        let routing = fcae_runtime::config::RoutingConfig::default();
        let plan = Plan { profile, socks: Some("127.0.0.1:1080".parse().unwrap()),
            http: Some("127.0.0.1:1081".parse().unwrap()),
            level: fcae_runtime::proxy_cores::Level::Off, upstream: None, routing: &routing, dial: None };
        let value = config::generate(&plan)?;
        let text = std::ffi::CString::new(value.to_string()).map_err(|_| "config contains NUL")?;
        unsafe {
            let error = xray_check(text.as_ptr());
            if error.is_null() { return Ok(()); }
            let message = std::ffi::CStr::from_ptr(error).to_string_lossy().into_owned();
            xray_string_free(error);
            Err(message)
        }
    });
}

pub fn register() {
    install_validator();
    fcae_runtime::registry::register(FcaeBackend::Xray, || Arc::new(XrayBackend));
}

pub fn tun_ffi()->CoreFfi {CoreFfi{start:xray_tun_start,stop:xray_tun_stop,running:xray_tun_running,..XrayDialect::FFI}}
