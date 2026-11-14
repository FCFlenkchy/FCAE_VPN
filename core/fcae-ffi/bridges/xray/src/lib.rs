//! # fcae-bridge-xray — Xray-core backend
//!
//! Xray-core is compiled from source at build time into the app's single Go
//! archive and started in this process. This crate is its bridge: the Xray
//! dialect (config grammar) plus the C entry points of its shim, on top of the
//! shared planning, supervision and teardown in [`fcae_runtime::sing_xray`].

pub mod config;

use std::ffi::{c_char, c_int};
use std::sync::Arc;

use async_trait::async_trait;
use fcae_abi::FcaeBackend;
use fcae_runtime::backend::{Backend, BackendContext, BackendHandle, BackendId, Capabilities};
use fcae_runtime::sing_xray::{CoreFfi, Dialect, Plan, Running, start};
use fcae_runtime::Result;

// Exported by `bridges/xray/go/bridge.go` through the shared archive. The
// prefix is per core: one Go package cannot export `start` twice.
extern "C" {
    fn xray_start(config: *const c_char) -> *mut c_char;
    fn xray_stop();
    fn xray_running() -> c_int;
    fn xray_string_free(value: *mut c_char);
}

pub struct XrayDialect;

impl Dialect for XrayDialect {
    const DISPLAY: &'static str = "Xray-core";
    const FFI: CoreFfi = CoreFfi {
        start: xray_start,
        stop: xray_stop,
        running: xray_running,
        string_free: xray_string_free,
    };

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
}

pub fn register() {
    fcae_runtime::registry::register(FcaeBackend::Xray, || Arc::new(XrayBackend));
}
