//! # fcae-bridge-psiphon
//!
//! Adapts Psiphon to the [`Backend`] trait.
//!
//! This is a *tunnel* bridge: it implements [`Backend`], meaning it
//! **produces** a SOCKS endpoint. Contrast `fcae-bridge-tun2socks`, which
//! implements `TunBridge` and **consumes** one. Because Psiphon terminates in
//! a local SOCKS5 proxy, **TUN mode works for free**: the supervisor layers
//! the in-process tun2socks bridge over whatever SOCKS endpoint a backend
//! reports, without knowing which backend produced it.
//!
//! ## MobileLibrary, not ClientLibrary
//!
//! Upstream's `ClientLibrary` ships a ready-made cgo C ABI, which is what this
//! bridge used first. It cannot work on Android: its `PsiphonProvider` has no
//! `BindToDevice`, so Psiphon's own sockets are captured by our TUN and the
//! tunnel tries to reach the internet through itself.
//!
//! `MobileLibrary/psi` exposes `BindToDevice` — the hook that maps onto
//! `VpnService.protect(fd)` — but it is a gobind package with no C surface, so
//! `go/bridge.go` wraps it. Desktop uses the same shim with
//! `useDeviceBinder=false`.
//!
//! ## Lifecycle
//!
//! `psi.Start()` is **non-blocking**: it returns once the controller goroutine
//! is launched, and "connected" arrives later as a notice. So unlike the old
//! ClientLibrary path (which blocked until connected and returned the ports in
//! its result JSON), this bridge polls `psi_state()` and reads the SOCKS port
//! from `psi_socks_port()` once the handshake lands.
//!
//! The egress region list has the same shape: Psiphon only reports it after a
//! successful handshake, which is why the UI offers "Auto" until the first
//! connect completes and then fills the list from [`regions`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
#[cfg(all(feature = "enabled", psiphon_linked))]
use fcae_abi::FcaeState;
use fcae_runtime::backend::{
    Backend, BackendContext, BackendHandle, BackendId, Capabilities, Endpoints,
};
use fcae_runtime::error::{CoreError, Result};

/// Serialises tunnel startup. Upstream also guards this, but refusing here
/// produces a better message and avoids touching Go at all.
#[cfg(all(feature = "enabled", psiphon_linked))]
static STARTING: AtomicBool = AtomicBool::new(false);

/// Egress regions reported by the last successful handshake.
///
/// Psiphon only learns these after connecting, so the UI shows "Auto" until
/// the first connect populates this list. Kept process-wide (rather than on
/// the handle) so the list survives a disconnect and the user can pick a
/// region for the *next* session.
static REGIONS: parking_lot::Mutex<Vec<String>> = parking_lot::Mutex::new(Vec::new());

/// Egress regions discovered so far, as ISO country codes.
///
/// Empty until the first successful connect. "" (auto) is always valid and is
/// not included here.
pub fn regions() -> Vec<String> {
    REGIONS.lock().clone()
}

/// Android's `VpnService.protect(fd)`, installed by the FFI layer.
///
/// Stored as a raw pointer because it crosses the C ABI. Null on desktop,
/// where the routing table already excludes our own sockets.
static PROTECT: std::sync::atomic::AtomicPtr<std::ffi::c_void> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// Install the socket-protection callback. Android calls this before start.
pub fn set_protect_callback(cb: Option<unsafe extern "C" fn(std::ffi::c_int) -> std::ffi::c_int>) {
    let raw = cb.map(|f| f as *mut std::ffi::c_void).unwrap_or(std::ptr::null_mut());
    PROTECT.store(raw, Ordering::SeqCst);
}

#[cfg(all(feature = "enabled", psiphon_linked))]
fn protect_hook() -> Option<unsafe extern "C" fn(std::ffi::c_int) -> std::ffi::c_int> {
    let raw = PROTECT.load(Ordering::SeqCst);
    if raw.is_null() {
        None
    } else {
        // SAFETY: only ever set from set_protect_callback, which takes the
        // same fn pointer type.
        Some(unsafe {
            std::mem::transmute::<
                *mut std::ffi::c_void,
                unsafe extern "C" fn(std::ffi::c_int) -> std::ffi::c_int,
            >(raw)
        })
    }
}

/// Register the Psiphon backend. Always call this: when the `enabled` feature
/// is off the backend still registers, but `start` returns a clear
/// "not available in this build" error instead of the id silently missing.
pub fn register() {
    fcae_runtime::registry::register(fcae_abi::FcaeBackend::Psiphon, || Arc::new(PsiphonBackend));
}

pub struct PsiphonBackend;

#[async_trait]
impl Backend for PsiphonBackend {
    fn id(&self) -> BackendId {
        BackendId::Psiphon
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            // Psiphon's defining feature for us: it ends in a local SOCKS5
            // proxy, which is exactly what the TUN bridge needs.
            socks: true,
            http_proxy: true,
            // No Cloudflare-style gateway scanning; the UI should hide scan
            // modes when this backend is selected.
            gateway_scanning: false,
            // Routing is handled by our own supervisor, not by Psiphon.
            routing_rules: false,
            requires_privileges: false,
        }
    }

    #[cfg(not(all(feature = "enabled", psiphon_linked)))]
    fn availability(&self) -> std::result::Result<(), String> {
        Err("Psiphon is registered but this build has no tunnel core linked; \
             rebuild with --features psiphon-live (needs the core/psiphon \
             submodule and a Go toolchain)"
            .to_string())
    }

    #[cfg(not(all(feature = "enabled", psiphon_linked)))]
    async fn start(&self, cx: BackendContext) -> Result<Box<dyn BackendHandle>> {
        // Validate anyway, so a misconfiguration is reported identically in a
        // build that cannot run Psiphon and one that can.
        let _ = validate(&cx.config)?;
        Err(CoreError::BackendUnavailable(
            "psiphon (build without --features fcae-bridge-psiphon/enabled)",
        ))
    }

    #[cfg(all(feature = "enabled", psiphon_linked))]
    async fn start(&self, cx: BackendContext) -> Result<Box<dyn BackendHandle>> {
        let inputs = validate(&cx.config)?;

        if STARTING.swap(true, Ordering::SeqCst) {
            return Err(CoreError::StartFailed(
                "a Psiphon tunnel is already starting".into(),
            ));
        }
        // From here on every exit path must clear STARTING.
        let _guard = StartGuard;

        ffi::install_log_hook();
        // Android hands the protect hook in through
        // fcae_set_psiphon_protect(); on desktop it stays unset and
        // BindToDevice is a no-op.
        ffi::set_protect(protect_hook());

        cx.report(FcaeState::Connecting, "Starting Psiphon…");

        // psi.Start() only launches the controller; it does not wait for a
        // tunnel. Kick it off, then poll for the handshake.
        let launch = inputs.clone();
        let use_binder = cfg!(target_os = "android");
        tokio::task::spawn_blocking(move || ffi::start(&launch, use_binder))
            .await
            .map_err(|e| CoreError::Internal(format!("psiphon start task panicked: {e}")))??;

        cx.report(FcaeState::Connecting, "Establishing Psiphon tunnel…");

        let deadline = std::time::Instant::now() + cx.config.start_timeout();
        let socks_port = loop {
            if cx.cancel.is_cancelled() {
                ffi::stop();
                return Err(CoreError::StartFailed("cancelled".into()));
            }
            if ffi::state() == ffi::STATE_CONNECTED {
                let port = ffi::socks_port();
                if port != 0 {
                    break port;
                }
            }
            if std::time::Instant::now() >= deadline {
                // Leave nothing running behind a failed start.
                ffi::stop();
                return Err(CoreError::StartFailed(format!(
                    "Psiphon did not establish a tunnel within {:?}",
                    cx.config.start_timeout()
                )));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        };

        let found = ffi::regions();
        if !found.is_empty() {
            log::info!("[psiphon] egress regions: {}", found.join(","));
            *REGIONS.lock() = found;
        }

        log::info!("[psiphon] tunnel established, socks 127.0.0.1:{socks_port}");

        Ok(Box::new(PsiphonHandle {
            socks_port,
            http_port: ffi::http_port(),
            stopped: AtomicBool::new(false),
        }))
    }

    fn recover_stale_state(&self) {
        // Psiphon runs in-process; a dead process leaves no orphan to reap.
        // Its datastore is crash-safe and recovered on next start.
        log::debug!("[psiphon] nothing to recover (in-process design)");
    }
}

/// Clears [`STARTING`] however `start` exits.
#[cfg(all(feature = "enabled", psiphon_linked))]
struct StartGuard;

#[cfg(all(feature = "enabled", psiphon_linked))]
impl Drop for StartGuard {
    fn drop(&mut self) {
        STARTING.store(false, Ordering::SeqCst);
    }
}

/// The config values Psiphon needs, validated and owned.
///
/// The fields are consumed by the `ffi` module, which only exists when the
/// c-archive is linked; they are still constructed (and asserted on) by
/// `validate` in every build.
#[derive(Debug, Clone)]
#[cfg_attr(not(all(feature = "enabled", psiphon_linked)), allow(dead_code))]
pub(crate) struct StartInputs {
    pub config_json: String,
    pub embedded_server_list: String,
    pub data_root_dir: String,
}

/// Validate config up front so the user gets the same quality of error as
/// with Aether, rather than a Go-side string.
///
/// Takes the config rather than the whole `BackendContext` so it is directly
/// unit-testable without constructing a telemetry sink and cancel token.
pub(crate) fn validate(cfg: &fcae_runtime::config::SessionConfig) -> Result<StartInputs> {
    let p = &cfg.psiphon;

    let config_json = p
        .config_json
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            CoreError::InvalidConfig(
                "psiphon.config_json is required when the Psiphon backend is selected".into(),
            )
        })?;

    // Fail here rather than inside Go: upstream would reject it too, but the
    // error would arrive as an opaque trace string.
    if !config_json.starts_with('{') {
        return Err(CoreError::InvalidConfig(
            "psiphon.config_json must be a JSON object (it is the Psiphon config, not a path)"
                .into(),
        ));
    }

    let data_root_dir = p
        .data_root_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            CoreError::InvalidConfig(
                "psiphon.data_root_dir is required (Psiphon needs a writable datastore)".into(),
            )
        })?;

    // Psiphon takes the egress region from the config JSON, and
    // MobileLibrary has no setter for it, so splice it in. "" means auto,
    // which is also what upstream treats as "no preference" -- so an unset
    // or empty region is simply left out.
    let region = p
        .egress_region
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let config_json = match region {
        Some(r) => inject_egress_region(config_json, r)?,
        None => config_json.to_string(),
    };

    Ok(StartInputs {
        config_json,
        embedded_server_list: p.embedded_server_list.clone().unwrap_or_default(),
        data_root_dir: data_root_dir.to_string(),
    })
}

/// Set `EgressRegion` in a Psiphon config object.
///
/// Done textually rather than with serde: the crate is compiled into every
/// build and the rest of this bridge is already dependency-free. The value is
/// an ISO country code that we validate, so there is nothing to escape.
fn inject_egress_region(config_json: &str, region: &str) -> Result<String> {
    if !region.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(CoreError::InvalidConfig(format!(
            "psiphon.egress_region {region:?} is not an alphanumeric country code"
        )));
    }

    // Replace an existing key rather than adding a duplicate: Go's json
    // decoder takes the LAST occurrence, so a duplicate would work by
    // accident on one decoder and break on another.
    if let Some(at) = config_json.find("\"EgressRegion\"") {
        let after = &config_json[at + "\"EgressRegion\"".len()..];
        let colon = after.find(':').ok_or_else(|| {
            CoreError::InvalidConfig("psiphon.config_json has a malformed EgressRegion".into())
        })?;
        let rest = &after[colon + 1..];
        let q1 = rest.find('"').ok_or_else(|| {
            CoreError::InvalidConfig("psiphon.config_json EgressRegion is not a string".into())
        })?;
        let q2 = rest[q1 + 1..].find('"').ok_or_else(|| {
            CoreError::InvalidConfig("psiphon.config_json EgressRegion is unterminated".into())
        })?;
        let head_len = at + "\"EgressRegion\"".len() + colon + 1 + q1 + 1;
        return Ok(format!(
            "{}{}{}",
            &config_json[..head_len],
            region,
            &config_json[head_len + q2..]
        ));
    }

    // No key yet: insert right after the opening brace.
    let open = config_json.find('{').ok_or_else(|| {
        CoreError::InvalidConfig("psiphon.config_json is not a JSON object".into())
    })?;
    Ok(format!(
        "{}\"EgressRegion\":\"{}\",{}",
        &config_json[..=open],
        region,
        &config_json[open + 1..]
    ))
}

/// The cgo boundary. Only compiled when the archive is actually linked.
#[cfg(all(feature = "enabled", psiphon_linked))]
mod ffi {
    use fcae_runtime::error::{CoreError, Result};
    use std::ffi::{c_char, c_int, CStr, CString};

    extern "C" {
        fn psi_set_log_callback(cb: Option<unsafe extern "C" fn(c_int, *const c_char)>);
        fn psi_set_protect_callback(cb: Option<unsafe extern "C" fn(c_int) -> c_int>);
        fn psi_start(config_json: *const c_char, embedded: *const c_char, use_binder: c_int)
            -> c_int;
        fn psi_stop() -> c_int;
        fn psi_state() -> c_int;
        fn psi_socks_port() -> c_int;
        fn psi_http_port() -> c_int;
        fn psi_regions() -> *mut c_char;
        fn psi_string_free(s: *mut c_char);
    }

    pub(super) const STATE_STOPPED: i32 = 0;
    pub(super) const STATE_CONNECTED: i32 = 2;

    /// Forwards Psiphon's notices into the host log.
    unsafe extern "C" fn log_trampoline(level: c_int, message: *const c_char) {
        if message.is_null() {
            return;
        }
        let text = CStr::from_ptr(message).to_string_lossy();
        match level {
            1 => log::error!("{text}"),
            2 => log::warn!("{text}"),
            4 => log::debug!("{text}"),
            _ => log::info!("{text}"),
        }
    }

    pub(super) fn install_log_hook() {
        unsafe { psi_set_log_callback(Some(log_trampoline)) };
    }

    /// Install the Android socket-protection hook.
    ///
    /// Without this Psiphon's own sockets are routed into our TUN and the
    /// tunnel deadlocks reaching the internet through itself.
    pub(super) fn set_protect(cb: Option<unsafe extern "C" fn(c_int) -> c_int>) {
        unsafe { psi_set_protect_callback(cb) };
    }

    pub(super) fn start(inputs: &super::StartInputs, use_binder: bool) -> Result<()> {
        let config = CString::new(inputs.config_json.as_str())
            .map_err(|_| CoreError::InvalidConfig("psiphon.config_json contains a NUL".into()))?;
        let servers = CString::new(inputs.embedded_server_list.as_str()).map_err(|_| {
            CoreError::InvalidConfig("psiphon.embedded_server_list contains a NUL".into())
        })?;

        let rc = unsafe {
            psi_start(
                config.as_ptr(),
                servers.as_ptr(),
                if use_binder { 1 } else { 0 },
            )
        };

        match rc {
            0 => Ok(()),
            -1 => Err(CoreError::StartFailed(
                "a Psiphon tunnel is already running".into(),
            )),
            -2 => Err(CoreError::InvalidConfig(
                "Psiphon rejected the config json".into(),
            )),
            -3 => Err(CoreError::StartFailed(
                "Psiphon failed to start; see the log for the controller error".into(),
            )),
            other => Err(CoreError::StartFailed(format!(
                "psi_start returned {other}"
            ))),
        }
    }

    pub(super) fn stop() {
        unsafe { psi_stop() };
    }

    pub(super) fn state() -> i32 {
        unsafe { psi_state() as i32 }
    }

    pub(super) fn socks_port() -> u16 {
        let p = unsafe { psi_socks_port() };
        if p > 0 { p as u16 } else { 0 }
    }

    pub(super) fn http_port() -> u16 {
        let p = unsafe { psi_http_port() };
        if p > 0 { p as u16 } else { 0 }
    }

    /// Egress regions reported after the handshake, as country codes.
    pub(super) fn regions() -> Vec<String> {
        let raw = unsafe { psi_regions() };
        if raw.is_null() {
            return Vec::new();
        }
        let text = unsafe { CStr::from_ptr(raw) }.to_string_lossy().into_owned();
        // The buffer is C.CString'd on the Go side, so it must be released
        // through the Go allocator's free, never Rust's.
        unsafe { psi_string_free(raw) };
        text.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }
}

/// Handle over a running Psiphon tunnel.
#[cfg_attr(not(all(feature = "enabled", psiphon_linked)), allow(dead_code))]
struct PsiphonHandle {
    socks_port: u16,
    http_port: u16,
    stopped: AtomicBool,
}

#[async_trait]
impl BackendHandle for PsiphonHandle {
    fn endpoints(&self) -> Endpoints {
        Endpoints {
            socks: format!("127.0.0.1:{}", self.socks_port).parse().ok(),
            http: (self.http_port != 0)
                .then(|| format!("127.0.0.1:{}", self.http_port).parse().ok())
                .flatten(),
            // Psiphon does not expose the selected server's address, and we
            // do not need it: it dials out through the OS routing table
            // before TUN is raised, and the supervisor excludes the SOCKS
            // loopback rather than a peer IP.
            peer_ip: None,
        }
    }

    async fn wait(&self) -> Result<()> {
        // The shim tracks tunnel count via the Tunnels notice, so a drop is
        // observable now (ClientLibrary gave no such signal and this had to
        // park forever). Returning lets the supervisor reconnect.
        #[cfg(all(feature = "enabled", psiphon_linked))]
        {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if self.stopped.load(Ordering::SeqCst) {
                    return Ok(());
                }
                if ffi::state() == ffi::STATE_STOPPED {
                    return Err(CoreError::Internal("the Psiphon tunnel dropped".into()));
                }
            }
        }
        #[cfg(not(all(feature = "enabled", psiphon_linked)))]
        {
            std::future::pending::<()>().await;
            Ok(())
        }
    }

    async fn stop(&self, _timeout: Duration) -> Result<()> {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        #[cfg(all(feature = "enabled", psiphon_linked))]
        {
            // PsiphonTunnelStop blocks until the controller has cleaned up.
            tokio::task::spawn_blocking(ffi::stop)
                .await
                .map_err(|e| CoreError::Internal(format!("psiphon stop task panicked: {e}")))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_region_is_inserted_when_absent() {
        let out = inject_egress_region(r#"{"PropagationChannelId":"X"}"#, "GB").unwrap();
        assert!(out.contains(r#""EgressRegion":"GB""#), "got: {out}");
        assert!(out.contains(r#""PropagationChannelId":"X""#), "got: {out}");
    }

    /// Go's json decoder takes the LAST duplicate key, so an existing region
    /// must be replaced in place rather than a second one appended.
    #[test]
    fn egress_region_replaces_an_existing_value() {
        let out = inject_egress_region(r#"{"EgressRegion":"US","A":1}"#, "DE").unwrap();
        assert!(out.contains(r#""EgressRegion":"DE""#), "got: {out}");
        assert!(!out.contains("US"), "the old region survived: {out}");
        assert_eq!(out.matches("EgressRegion").count(), 1, "duplicated: {out}");
        assert!(out.contains(r#""A":1"#), "lost a sibling key: {out}");
    }

    #[test]
    fn egress_region_rejects_injection_attempts() {
        assert!(inject_egress_region(r#"{}"#, r#"a","X":"b"#).is_err());
    }

    #[test]
    fn config_json_must_be_json_not_a_path() {
        // A path is the likely mistake; it must be rejected with a message
        // that says so rather than being handed to Go.
        let cfg = make_config(Some("/etc/psiphon.conf"), Some("/tmp/psi"));
        let err = validate(&cfg).unwrap_err();
        assert!(format!("{err}").contains("JSON object"), "got: {err}");
    }

    #[test]
    fn config_json_is_required() {
        let cfg = make_config(None, Some("/tmp/psi"));
        let err = validate(&cfg).unwrap_err();
        assert!(format!("{err}").contains("config_json"), "got: {err}");
    }

    #[test]
    fn data_root_dir_is_required() {
        let cfg = make_config(Some("{}"), None);
        let err = validate(&cfg).unwrap_err();
        assert!(format!("{err}").contains("data_root_dir"), "got: {err}");
    }

    #[test]
    fn a_valid_config_passes() {
        let cfg = make_config(Some(r#"{"PropagationChannelId":"x"}"#), Some("/tmp/psi"));
        let inputs = validate(&cfg).expect("should validate");
        assert_eq!(inputs.data_root_dir, "/tmp/psi");
        assert!(inputs.embedded_server_list.is_empty());
    }

    fn make_config(
        config_json: Option<&str>,
        data_root_dir: Option<&str>,
    ) -> fcae_runtime::config::SessionConfig {
        let mut cfg = fcae_runtime::config::SessionConfig::default();
        cfg.psiphon.config_json = config_json.map(str::to_string);
        cfg.psiphon.data_root_dir = data_root_dir.map(str::to_string);
        cfg
    }

}
