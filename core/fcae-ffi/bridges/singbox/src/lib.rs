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
use fcae_runtime::sing_xray::{CoreFfi, Dialect, Plan, Running, start};
use fcae_runtime::Result;

// Exported by `bridges/singbox/go/bridge.go` through the shared archive. The
// prefix is per core: one Go package cannot export `start` twice.
extern "C" {
    fn sb_start(config: *const c_char) -> *mut c_char;
    fn sb_stop();
    fn sb_running() -> c_int;
    fn sb_string_free(value: *mut c_char);
}

pub struct SingBoxDialect;

impl Dialect for SingBoxDialect {
    const DISPLAY: &'static str = "sing-box";
    const FFI: CoreFfi = CoreFfi {
        start: sb_start,
        stop: sb_stop,
        running: sb_running,
        string_free: sb_string_free,
    };

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
}

pub fn register() {
    fcae_runtime::registry::register(FcaeBackend::SingBox, || Arc::new(SingBoxBackend));
}
