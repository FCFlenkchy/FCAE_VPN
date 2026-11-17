//! # fcae-bridge-singbox — sing-box backend
//!
//! sing-box is compiled from source at build time into the app's single Go
//! archive and started in this process. This crate is its bridge: the sing-box
//! dialect (config grammar) plus the C entry points of its shim, on top of the
//! shared planning, supervision and teardown in [`fcae_runtime::sing_xray`].

pub mod config;

use std::ffi::{c_char, c_int};
use std::sync::Arc;

use async_trait::async_trait;
use fcae_abi::FcaeBackend;
use fcae_runtime::backend::{Backend, BackendContext, BackendHandle, BackendId, Capabilities};
use fcae_runtime::sing_xray::{CoreFfi, Dialect, Plan, halt_all, start};
use fcae_runtime::Result;

// Exported by `bridges/singbox/go/bridge.go` through the shared archive. The
// prefix is per core: one Go package cannot export `start` twice.
extern "C" {
    fn sb_start(config: *const c_char, handle: *mut u64) -> *mut c_char;
    fn sb_stop(handle: u64);
    fn sb_stop_all();
    fn sb_running(handle: u64) -> c_int;
    fn sb_string_free(value: *mut c_char);
    fn sb_stats(handle: u64, uplink: *mut i64, downlink: *mut i64) -> c_int;
    fn sb_set_log(sink: LogSink, gate: c_int);
    fn sb_listeners(buf: *mut c_char, capacity: c_int) -> c_int;
}

/// Host log sink, implemented here and called from the core's own goroutines.
type LogSink = Option<unsafe extern "C" fn(c_int, *const c_char)>;

/// Receives the core's log lines and hands them to the app console.
unsafe extern "C" fn log_sink(level: c_int, message: *const c_char) {
    fcae_runtime::sing_xray::forward_log("sing-box", level, message);
}

pub struct SingBoxDialect;

impl Dialect for SingBoxDialect {
    const DISPLAY: &'static str = "sing-box";
    const FFI: CoreFfi = CoreFfi {
        start: sb_start,
        stop: sb_stop,
        stop_all: sb_stop_all,
        running: sb_running,
        string_free: sb_string_free,
        stats: sb_stats,
        set_log: sb_set_log,
        listeners: sb_listeners,
    };
    const LOG_SINK: unsafe extern "C" fn(c_int, *const c_char) = log_sink;
    // The core's own DNS transport reads /etc/resolv.conf and nothing else.
    const RESOLVES_SERVER: bool = false;

    fn generate(plan: &Plan<'_>) -> std::result::Result<serde_json::Value, String> {
        config::generate(plan)
    }
}

pub struct SingBoxBackend;

#[async_trait]
impl Backend for SingBoxBackend {
    fn id(&self) -> BackendId {
        BackendId::SingBox
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
            Err("the Go archive is stubbed in this build; sing-box cannot start".into())
        }
    }

    async fn start(&self, cx: BackendContext) -> Result<Box<dyn BackendHandle>> {
        Ok(Box::new(start::<SingBoxDialect>(&cx).await?))
    }

    /// No instance outlives its session; see the Xray bridge's `drain` for why
    /// the net is here as well as on the stop paths, and why it closes every
    /// instance rather than one.
    async fn drain(&self) {
        halt_all(SingBoxDialect::FFI, FcaeBackend::SingBox).await;
    }

    /// [`Self::drain`] without a runtime to run it on.
    ///
    /// The shim's own `stop_all` is synchronous and idempotent, so it can be
    /// called straight from a teardown path that has no async context left --
    /// the last word on a box whose start was abandoned, or whose session
    /// worker died before it could drain.
    fn reclaim_blocking(&self) {
        unsafe { sb_stop_all() };
        // Closed, so none of them is live: a teardown that could not await the
        // drain must not leave the connection info listing cores that are gone.
        fcae_runtime::sing_xray::retire_all(FcaeBackend::SingBox);
    }
}

/// Every inbound of every live singbox instance, as the core itself reports
/// them.
///
/// The settings name one port for a session that may run several instances --
/// a chained hop, or a native config with more than one inbound -- so the app
/// asks the core what is actually listening instead of deciding for it.
pub fn listeners() -> Vec<fcae_runtime::sing_xray::CoreListener> {
    fcae_runtime::sing_xray::live_listeners(SingBoxDialect::FFI)
}

pub fn register() {
    fcae_runtime::registry::register(FcaeBackend::SingBox, || Arc::new(SingBoxBackend));
}
