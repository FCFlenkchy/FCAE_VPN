//! # fcae-bridge-psiphon
//!
//! Adapts Psiphon's `ClientLibrary` to the [`Backend`] trait.
//!
//! This is a *tunnel* bridge: it implements [`Backend`], meaning it
//! **produces** a SOCKS endpoint. Contrast `fcae-bridge-tun2socks`, which
//! implements `TunBridge` and **consumes** one. Because Psiphon terminates in
//! a local SOCKS5 proxy, **TUN mode works for free**: the supervisor layers
//! the in-process tun2socks bridge over whatever SOCKS endpoint a backend
//! reports, without knowing which backend produced it.
//!
//! ## No hand-written Go shim
//!
//! Unlike tun2socks, Psiphon already ships a cgo C ABI
//! (`core/psiphon/ClientLibrary/PsiphonTunnel.go`):
//!
//! ```c
//! char *PsiphonTunnelStart(char *configJSON, char *embeddedServerEntryList,
//!                          struct Parameters *params);
//! void  PsiphonTunnelStop(void);
//! ```
//!
//! so `build.rs` compiles that package straight to a c-archive. Nothing to
//! rebase when the submodule is bumped.
//!
//! ## Lifecycle differences from Aether
//!
//! `PsiphonTunnelStart` is **blocking and synchronous**: it returns only once
//! a tunnel is established, the timeout elapses, or it fails. That is the
//! opposite of `aether-engine`'s `run_from_env()`, which returns when the
//! tunnel *dies*. So this bridge runs `start` on a blocking thread and gets
//! the SOCKS port directly from the returned JSON — no port probing and no
//! log scraping needed.
//!
//! Two consequences worth knowing:
//!
//! * The returned `char*` is **owned by Go**. Freeing it from Rust crashes the
//!   process; it is released by the next `PsiphonTunnelStart` or by
//!   `PsiphonTunnelStop`. [`StartOutcome`] copies what it needs immediately.
//! * Upstream guards against concurrent starts with an atomic bool and returns
//!   an error on the second call. [`STARTING`] refuses earlier so the caller
//!   gets a clear message instead of a Go-side error string.

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

        cx.report(FcaeState::Connecting, "Establishing Psiphon tunnel…");

        let timeout_secs = cx.config.start_timeout().as_secs().min(i32::MAX as u64) as i32;

        // PsiphonTunnelStart blocks until connected / timed out / failed, so
        // it must not run on a runtime worker.
        let outcome = tokio::task::spawn_blocking(move || ffi::start(&inputs, timeout_secs))
            .await
            .map_err(|e| CoreError::Internal(format!("psiphon start task panicked: {e}")))??;

        let socks_port = outcome.socks_port.ok_or_else(|| {
            CoreError::StartFailed(
                "Psiphon connected but reported no SOCKS proxy port; \
                 check that DisableLocalSocksProxy is not set in the config JSON"
                    .into(),
            )
        })?;

        log::info!(
            "[psiphon] tunnel established in {} ms, socks 127.0.0.1:{}",
            outcome.connect_time_ms,
            socks_port
        );

        Ok(Box::new(PsiphonHandle {
            socks_port,
            http_port: outcome.http_port.unwrap_or(0),
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

    Ok(StartInputs {
        config_json: config_json.to_string(),
        embedded_server_list: p.embedded_server_list.clone().unwrap_or_default(),
        data_root_dir: data_root_dir.to_string(),
    })
}

/// Parsed form of Psiphon's `startResult` JSON.
#[derive(Debug, Default, PartialEq, Eq)]
#[cfg_attr(not(all(feature = "enabled", psiphon_linked)), allow(dead_code))]
pub(crate) struct StartOutcome {
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub connect_time_ms: i64,
}

/// Result codes from `PsiphonTunnelStart`.
///
/// The parser below is exercised by unit tests in every build, but only
/// *called* by the `ffi` module when the c-archive is linked.
#[cfg_attr(not(all(feature = "enabled", psiphon_linked)), allow(dead_code))]
pub(crate) const CODE_SUCCESS: i64 = 0;
#[cfg_attr(not(all(feature = "enabled", psiphon_linked)), allow(dead_code))]
pub(crate) const CODE_TIMEOUT: i64 = 1;

/// Parse the `startResult` JSON that `PsiphonTunnelStart` returns.
///
/// Hand-rolled rather than pulling in serde_json: the shape is fixed, tiny,
/// and generated by upstream's `json.Marshal`, so it is always flat with no
/// nesting or escapes in the numeric fields. Keeping this dependency-free
/// matters because the crate is compiled into every build.
#[cfg_attr(not(all(feature = "enabled", psiphon_linked)), allow(dead_code))]
pub(crate) fn parse_start_result(json: &str) -> std::result::Result<StartOutcome, String> {
    let code = json_i64(json, "Code").unwrap_or(CODE_SUCCESS);

    if code != CODE_SUCCESS {
        let msg = json_str(json, "Error").unwrap_or_else(|| "unknown error".to_string());
        return Err(if code == CODE_TIMEOUT {
            format!("Psiphon timed out before connecting: {msg}")
        } else {
            format!("Psiphon failed to connect: {msg}")
        });
    }

    Ok(StartOutcome {
        socks_port: json_i64(json, "SOCKSProxyPort").and_then(|v| u16::try_from(v).ok()),
        http_port: json_i64(json, "HTTPProxyPort").and_then(|v| u16::try_from(v).ok()),
        connect_time_ms: json_i64(json, "ConnectTimeMS").unwrap_or(0),
    })
}

/// Read a numeric field from a flat JSON object.
#[cfg_attr(not(all(feature = "enabled", psiphon_linked)), allow(dead_code))]
fn json_i64(json: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle)? + needle.len();
    let rest = json[start..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Read a string field from a flat JSON object, undoing the escapes
/// `json.Marshal` can emit in an error message.
#[cfg_attr(not(all(feature = "enabled", psiphon_linked)), allow(dead_code))]
fn json_str(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle)? + needle.len();
    let rest = json[start..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;

    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => out.push(other),
                None => break,
            },
            other => out.push(other),
        }
    }
    Some(out)
}

/// The cgo boundary. Only compiled when the archive is actually linked.
#[cfg(all(feature = "enabled", psiphon_linked))]
mod ffi {
    use super::{parse_start_result, StartInputs, StartOutcome};
    use fcae_runtime::error::{CoreError, Result};
    use std::ffi::{c_char, CStr, CString};

    /// Mirrors `struct Parameters` in `ClientLibrary/PsiphonTunnel.go`.
    ///
    /// `sizeofStruct` is validated by upstream against its own
    /// `sizeof(Parameters)`, so this layout must track theirs exactly. Field
    /// order and types are copied verbatim from the cgo preamble.
    #[repr(C)]
    struct Parameters {
        sizeof_struct: usize,
        data_root_directory: *mut c_char,
        client_platform: *mut c_char,
        network_id: *mut c_char,
        establish_tunnel_timeout_seconds: *mut i32,
    }

    extern "C" {
        fn PsiphonTunnelStart(
            config_json: *mut c_char,
            embedded_server_entry_list: *mut c_char,
            params: *mut Parameters,
        ) -> *mut c_char;
        fn PsiphonTunnelStop();
    }

    pub(super) fn start(inputs: &StartInputs, timeout_secs: i32) -> Result<StartOutcome> {
        let config = CString::new(inputs.config_json.as_str())
            .map_err(|_| CoreError::InvalidConfig("psiphon.config_json contains a NUL".into()))?;
        let servers = CString::new(inputs.embedded_server_list.as_str()).map_err(|_| {
            CoreError::InvalidConfig("psiphon.embedded_server_list contains a NUL".into())
        })?;
        let data_dir = CString::new(inputs.data_root_dir.as_str())
            .map_err(|_| CoreError::InvalidConfig("psiphon.data_root_dir contains a NUL".into()))?;
        let platform = CString::new(client_platform()).unwrap_or_default();
        // Psiphon requires a non-empty network id; it only affects its own
        // network-change detection, which we do not drive.
        let network_id = CString::new("FCAE").unwrap_or_default();

        let mut timeout = timeout_secs;

        let mut params = Parameters {
            sizeof_struct: std::mem::size_of::<Parameters>(),
            data_root_directory: data_dir.as_ptr() as *mut c_char,
            client_platform: platform.as_ptr() as *mut c_char,
            network_id: network_id.as_ptr() as *mut c_char,
            establish_tunnel_timeout_seconds: &mut timeout as *mut i32,
        };

        // SAFETY: every pointer is valid for the duration of the call (the
        // CStrings and `timeout` outlive it), and PsiphonTunnelStart copies
        // anything it retains onto the Go heap. The returned pointer is owned
        // by Go — we copy out of it and never free it.
        let raw = unsafe {
            PsiphonTunnelStart(
                config.as_ptr() as *mut c_char,
                servers.as_ptr() as *mut c_char,
                &mut params as *mut Parameters,
            )
        };

        if raw.is_null() {
            return Err(CoreError::StartFailed(
                "PsiphonTunnelStart returned no result".into(),
            ));
        }

        let json = unsafe { CStr::from_ptr(raw) }
            .to_string_lossy()
            .into_owned();

        parse_start_result(&json).map_err(CoreError::StartFailed)
    }

    pub(super) fn stop() {
        // SAFETY: documented as safe to call when no tunnel is running, and
        // it is what frees the managed start result.
        unsafe { PsiphonTunnelStop() };
    }

    /// `OS_OSVersion_BundleIdentifier`, per upstream's documented format.
    fn client_platform() -> String {
        let os = if cfg!(target_os = "windows") {
            "Windows"
        } else if cfg!(target_os = "macos") {
            "macOS"
        } else if cfg!(target_os = "android") {
            "Android"
        } else {
            "Linux"
        };
        format!("{os}_com.fc.fcaevpn")
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
        // ClientLibrary gives no "tunnel died" signal — it reports failures
        // through notices we do not subscribe to. Park until stopped; the
        // supervisor's own health checks drive reconnection.
        std::future::pending::<()>().await;
        Ok(())
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
    fn parses_a_successful_start_result() {
        let json = r#"{"Code":0,"ConnectTimeMS":3421,"HTTPProxyPort":8081,"SOCKSProxyPort":1081}"#;
        let out = parse_start_result(json).expect("should succeed");
        assert_eq!(out.socks_port, Some(1081));
        assert_eq!(out.http_port, Some(8081));
        assert_eq!(out.connect_time_ms, 3421);
    }

    #[test]
    fn timeout_is_reported_distinctly_from_other_errors() {
        let json = r#"{"Code":1,"Error":"Timeout occurred before Psiphon connected"}"#;
        let err = parse_start_result(json).unwrap_err();
        assert!(err.contains("timed out"), "got: {err}");
    }

    #[test]
    fn other_errors_carry_the_upstream_message() {
        let json = r#"{"Code":2,"Error":"config load failed"}"#;
        let err = parse_start_result(json).unwrap_err();
        assert!(err.contains("config load failed"), "got: {err}");
        assert!(!err.contains("timed out"));
    }

    /// `omitempty` means a field can simply be absent; that must not be read
    /// as port 0.
    #[test]
    fn absent_ports_are_none_not_zero() {
        let json = r#"{"Code":0,"ConnectTimeMS":10}"#;
        let out = parse_start_result(json).expect("should succeed");
        assert_eq!(out.socks_port, None);
        assert_eq!(out.http_port, None);
    }

    #[test]
    fn escaped_characters_in_an_error_are_unescaped() {
        let json = r#"{"Code":2,"Error":"line one\nline \"two\""}"#;
        let err = parse_start_result(json).unwrap_err();
        assert!(err.contains("line one\nline \"two\""), "got: {err}");
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
