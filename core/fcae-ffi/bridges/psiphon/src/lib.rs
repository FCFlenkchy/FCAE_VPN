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
//! `VpnService.protect(fd)` — but it is a gobind package with no C surface.
//!
//! **Android:** official Psiphon AAR (`android/psiphon`). Do not compile
//! `psi` into `libfcae_go_bridge.so`.
//! **Desktop:** `go/bridge.go` wraps psi; that module is a second Go runtime
//! (`force_shared`) and is not built while `enabled` is off.
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

/// Actual bound desktop listener ports. Android reports them by broadcast.
pub fn proxy_ports() -> (u16, u16) {
    #[cfg(all(feature = "enabled", psiphon_linked))]
    { (ffi::socks_port(), ffi::http_port()) }
    #[cfg(not(all(feature = "enabled", psiphon_linked)))]
    { (0, 0) } // Android learns these from the isolated service broadcasts.
}

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

/// Host view of the underlying network, supplied by the platform layer.
///
/// Android must provide all three: once `DeviceBinder` is set, upstream stops
/// using the standard library resolver, so `dns` becomes the only source of
/// DNS servers and an absent hook means no name resolution at all.
pub type DnsFn = unsafe extern "C" fn() -> *mut std::ffi::c_char;
pub type ConnectivityFn = unsafe extern "C" fn() -> std::ffi::c_int;
pub type NetworkIdFn = unsafe extern "C" fn() -> *mut std::ffi::c_char;

static DNS_HOOK: std::sync::atomic::AtomicPtr<std::ffi::c_void> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
static CONNECTIVITY_HOOK: std::sync::atomic::AtomicPtr<std::ffi::c_void> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
static NETWORK_ID_HOOK: std::sync::atomic::AtomicPtr<std::ffi::c_void> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// Install (or clear, with `None`) the network-state callbacks.
pub fn set_network_callbacks(
    dns: Option<DnsFn>,
    connectivity: Option<ConnectivityFn>,
    network_id: Option<NetworkIdFn>,
) {
    // `as` casts rather than transmutes: a function item coerces to a plain
    // data pointer directly, so there is nothing unsafe to get wrong here.
    let dns = dns.map_or(std::ptr::null_mut(), |f| f as *mut std::ffi::c_void);
    let connectivity =
        connectivity.map_or(std::ptr::null_mut(), |f| f as *mut std::ffi::c_void);
    let network_id =
        network_id.map_or(std::ptr::null_mut(), |f| f as *mut std::ffi::c_void);

    DNS_HOOK.store(dns, Ordering::SeqCst);
    CONNECTIVITY_HOOK.store(connectivity, Ordering::SeqCst);
    NETWORK_ID_HOOK.store(network_id, Ordering::SeqCst);
}

#[cfg(all(feature = "enabled", psiphon_linked))]
fn network_hooks() -> (Option<DnsFn>, Option<ConnectivityFn>, Option<NetworkIdFn>) {
    let dns = DNS_HOOK.load(Ordering::SeqCst);
    let connectivity = CONNECTIVITY_HOOK.load(Ordering::SeqCst);
    let network_id = NETWORK_ID_HOOK.load(Ordering::SeqCst);

    // SAFETY: each slot only ever holds a pointer stored by
    // set_network_callbacks, from a value of exactly the matching
    // function-pointer type.
    unsafe {
        (
            (!dns.is_null()).then(|| std::mem::transmute::<_, DnsFn>(dns)),
            (!connectivity.is_null())
                .then(|| std::mem::transmute::<_, ConnectivityFn>(connectivity)),
            (!network_id.is_null())
                .then(|| std::mem::transmute::<_, NetworkIdFn>(network_id)),
        )
    }
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
        // Android: the official AAR owns the tunnel core. This backend
        // attaches to the AAR's local SOCKS once the host passes the port.
        Ok(())
    }

    #[cfg(not(all(feature = "enabled", psiphon_linked)))]
    async fn start(&self, cx: BackendContext) -> Result<Box<dyn BackendHandle>> {
        // AAR owns the tunnel core and the config JSON. Attach needs only the
        // local SOCKS port — do not require a pasted sponsor config.
        let socks = cx.config.psiphon.socks_port;
        if socks == 0 {
            return Err(CoreError::StartFailed(
                "Android Psiphon is the official AAR (process :psiphon). \
                 Start PsiphonTunnelService first and pass its SOCKS port."
                    .into(),
            ));
        }
        Ok(Box::new(PsiphonHandle {
            socks_port: socks,
            http_port: cx.config.psiphon.http_port,
            stopped: AtomicBool::new(false),
        }))
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
        let protect = protect_hook();
        if cfg!(target_os = "android") && protect.is_none() {
            // Starting here would dial with every socket captured by our own
            // TUN: the tunnel tries to reach the internet through itself and
            // hangs until the start timeout with nothing in the log to say
            // why. Refuse instead of reproducing that silently.
            return Err(CoreError::StartFailed(
                "the VpnService protect hook is not installed; refusing to start Psiphon \
                 inside our own tunnel (call fcae_set_psiphon_protect first)"
                    .into(),
            ));
        }
        ffi::set_protect(protect);

        let (dns, connectivity, network_id) = network_hooks();
        if cfg!(target_os = "android") && dns.is_none() {
            // With DeviceBinder set, upstream disables the standard library
            // resolver, so without this hook there are no DNS servers at all
            // and every dial fails with an opaque resolver error.
            return Err(CoreError::StartFailed(
                "no DNS hook installed; with VpnService protection enabled Psiphon has no \
                 resolver (call fcae_set_psiphon_network_callbacks first)"
                    .into(),
            ));
        }
        ffi::set_network_callbacks(dns, connectivity, network_id);

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
                tokio::task::spawn_blocking(ffi::stop)
                    .await
                    .map_err(|e| CoreError::Internal(format!("psiphon stop task panicked: {e}")))?;
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
                tokio::task::spawn_blocking(ffi::stop)
                    .await
                    .map_err(|e| CoreError::Internal(format!("psiphon stop task panicked: {e}")))?;
                return Err(CoreError::StartFailed(format!(
                    "Psiphon did not establish a tunnel within {:?}",
                    cx.config.start_timeout()
                )));
            }
            // state()/socks_port() are cheap cgo getters: poll at 50 ms
            // (was 250 ms) so a completed handshake is reported to the UI
            // at once instead of up to a quarter second late.
            tokio::time::sleep(Duration::from_millis(50)).await;
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
    /// Already carries EgressRegion and DataRootDirectory: psi.Start() takes
    /// the config object and nothing else.
    pub config_json: String,
    pub embedded_server_list: String,
}

/// Validate config up front so the user gets the same quality of error as
/// with Aether, rather than a Go-side string.
///
/// Takes the config rather than the whole `BackendContext` so it is directly
/// unit-testable without constructing a telemetry sink and cancel token.
///
/// Everything from here to the SERVER_LIST key is only consumed by the
/// desktop live path (`#[cfg(all(feature = "enabled", psiphon_linked)))]`
/// `start()`) and by unit tests. The Android/AAR attach stub builds configs
/// on the Java side, so these are gated out there instead of warning.
#[cfg(any(test, all(feature = "enabled", psiphon_linked)))]
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

    // Psiphon needs a writable datastore. Prefer an explicit
    // psiphon.data_root_dir, but fall back to a subdirectory of the session
    // data_dir so a caller that already set one does not have to repeat it.
    let data_root_dir = match p
        .data_root_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(d) => d.to_string(),
        None => {
            let base = cfg
                .data_dir
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    CoreError::InvalidConfig(
                        "psiphon needs a writable datastore: set psiphon.data_root_dir \
                         (or data_dir, which it will use a `psiphon` subdirectory of)"
                            .into(),
                    )
                })?;
            format!("{}/psiphon", base.trim_end_matches('/'))
        }
    };

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

    // MobileLibrary's psi.Start() takes the config JSON and nothing else --
    // unlike ClientLibrary, which had a dedicated dataRootDirectory parameter.
    // Psiphon reads it from Config.DataRootDirectory, so it has to go into the
    // object. Without this the field was computed, validated and then thrown
    // away (the compiler's "never read" warning), and Psiphon fell back to the
    // process working directory -- not writable on Android.
    let mut config_json = inject_string_field(&config_json, "DataRootDirectory", &data_root_dir)?;
    config_json = inject_psiphon_ports(&config_json, p.socks_port, p.http_port)?;
    config_json = inject_string_field(&config_json, "ListenInterface", if cfg.lan_sharing { "any" } else { "" })?;
    config_json = inject_android_resolver_policy(&config_json)?;

    // Do not volunteer as an in-proxy proxy unless explicitly configured.
    // This is distinct from client dialing, which Auto/tactics may select.
    // InproxyEnabled is not a core field; InproxyAllowClient is server-side
    // and never disabled client WebRTC/STUN participation here.
    if !config_json.contains("\"InproxyEnableProxy\"") {
        config_json = inject_bool_field(&config_json, "InproxyEnableProxy", false)?;
    }
    // BytesTransferred notices feed the UI/notification counters; without
    // this a working tunnel displays 0 B everywhere.
    if !config_json.contains("\"EmitBytesTransferred\"") {
        config_json = inject_bool_field(&config_json, "EmitBytesTransferred", true)?;
    }

    // Server entries fetched out-of-band (tunneled DSL fetches, entry
    // updates pushed by the server) are individually signed and verified
    // against ServerEntrySignaturePublicKey. Without it every tunneled DSL
    // fetch dies with "protocol.ServerEntryFields.VerifySignature: missing
    // public key" even though the tunnel itself is fine. The standard
    // ed25519 key below is the value the open-source Psiphon clients embed;
    // a config that deliberately sets its own key wins.
    if !config_json.contains("\"ServerEntrySignaturePublicKey\"") {
        config_json = inject_string_field(
            &config_json,
            "ServerEntrySignaturePublicKey",
            DEFAULT_SERVER_ENTRY_SIGNATURE_KEY,
        )?;
    }

    // A fresh datastore with no server-entry source can never connect (the
    // bootstrap chicken-and-egg). Fall back to the LEGACY PUBLIC remote
    // server list — the same URL + signature key the open-source Psiphon 3
    // clients shipped (and community clients like Oblivion still ship) — so
    // an unprovisioned build works out of the box. Explicit user config
    // (embedded list / remote list / obfuscated lists / target entry) always
    // wins. NOTE: this is legacy infrastructure; partner provisioning from
    // Psiphon-Labs remains the supported long-term path.
    let mut fell_back = false;
    if !has_server_entry_source(&config_json, p.embedded_server_list.as_deref()) {
        config_json = inject_string_field(
            &config_json,
            "RemoteServerListUrl",
            DEFAULT_SERVER_LIST_URL,
        )?;
        config_json = inject_string_field(
            &config_json,
            "RemoteServerListSignaturePublicKey",
            DEFAULT_SERVER_LIST_SIGNATURE_KEY,
        )?;
        fell_back = true;
    }
    if fell_back {
        log::info!(
            "[psiphon] no server-entry source configured; using the built-in legacy public \
             remote server list (set psiphon.embedded_server_list or RemoteServerListUrl to \
             override)"
        );
    }

    Ok(StartInputs {
        config_json,
        embedded_server_list: p.embedded_server_list.clone().unwrap_or_default(),
    })
}

/// Legacy PUBLIC remote server list served by Psiphon's old S3 bucket — the
/// bootstrap source of the open-source Psiphon 3 clients. Still reachable;
/// hosted and signed by Psiphon infrastructure; may be retired at any time.
#[cfg(any(test, all(feature = "enabled", psiphon_linked)))]
pub(crate) const DEFAULT_SERVER_LIST_URL: &str =
    "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed";

/// Standard ed25519 public key used to verify individually signed server
/// entries (DSL fetches, server-pushed updates) — the same value the
/// open-source Psiphon clients embed. Public; not provisioning.
#[cfg(any(test, all(feature = "enabled", psiphon_linked)))]
pub(crate) const DEFAULT_SERVER_ENTRY_SIGNATURE_KEY: &str =
    "sHuUVTWaRyh5pZwy4UguSgkwmBe0EHtJJkoF5WrxmvA=";

/// Signature public key that authenticates the legacy public remote server
/// list payload (the same value embedded in the open-source Psiphon 3
/// clients). Pairs with [`DEFAULT_SERVER_LIST_URL`].
#[cfg(any(test, all(feature = "enabled", psiphon_linked)))]
pub(crate) const DEFAULT_SERVER_LIST_SIGNATURE_KEY: &str = concat!(
    "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH",
    "5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5",
    "OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42Kcot",
    "LFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6",
    "/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7G",
    "stZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1O",
    "geF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8",
    "u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz",
    "31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xal",
    "KxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=",
);

/// True when at least one tunnel-core server-entry source is configured.
#[cfg(any(test, all(feature = "enabled", psiphon_linked)))]
fn has_server_entry_source(config_json: &str, embedded: Option<&str>) -> bool {
    if embedded.map(str::trim).unwrap_or("") != "" {
        return true;
    }
    [
        "\"RemoteServerListUrl\"",
        "\"RemoteServerListURLs\"",
        "\"ObfuscatedServerListRootURL\"",
        "\"ObfuscatedServerListRootURLs\"",
        "\"TargetServerEntry\"",
    ]
    .iter()
    .any(|k| config_json.contains(k))
}

/// Set `EgressRegion` in a Psiphon config object.
#[cfg(any(test, all(feature = "enabled", psiphon_linked)))]
fn inject_egress_region(config_json: &str, region: &str) -> Result<String> {
    if !region.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(CoreError::InvalidConfig(format!(
            "psiphon.egress_region {region:?} is not an alphanumeric country code"
        )));
    }
    inject_string_field(config_json, "EgressRegion", region)
}

/// Set a bool field in a flat Psiphon config object.
#[cfg(any(test, all(feature = "enabled", psiphon_linked)))]
fn inject_bool_field(config_json: &str, key: &str, value: bool) -> Result<String> {
    let mut object: serde_json::Value = serde_json::from_str(config_json).map_err(|e| {
        CoreError::InvalidConfig(format!("psiphon.config_json is invalid JSON: {e}"))
    })?;
    let map = object.as_object_mut().ok_or_else(|| {
        CoreError::InvalidConfig("psiphon.config_json must be a JSON object".into())
    })?;
    map.insert(key.to_string(), serde_json::Value::Bool(value));
    serde_json::to_string(&object).map_err(|e| {
        CoreError::InvalidConfig(format!("could not render psiphon.config_json: {e}"))
    })
}

/// Set a string field in a flat Psiphon config object.
///
/// Done textually rather than with serde: the crate is compiled into every
/// build and the rest of this bridge is already dependency-free.
///
/// `value` is JSON-escaped, because unlike a country code a filesystem path
/// can legitimately contain a backslash (Windows) or a quote.
#[cfg(any(test, all(feature = "enabled", psiphon_linked)))]
fn inject_string_field(config_json: &str, key: &str, value: &str) -> Result<String> {
    let mut object: serde_json::Value = serde_json::from_str(config_json).map_err(|e| {
        CoreError::InvalidConfig(format!("psiphon.config_json is invalid JSON: {e}"))
    })?;
    let map = object.as_object_mut().ok_or_else(|| {
        CoreError::InvalidConfig("psiphon.config_json must be a JSON object".into())
    })?;
    map.insert(key.to_string(), serde_json::Value::String(value.to_string()));
    serde_json::to_string(&object).map_err(|e| {
        CoreError::InvalidConfig(format!("could not render psiphon.config_json: {e}"))
    })
}

/// Apply the FCAE Psiphon port fields to the real Psiphon config names.
/// Zero removes an existing value so Psiphon is free to choose a port.
#[cfg(any(test, all(feature = "enabled", psiphon_linked)))]
fn inject_psiphon_ports(config_json: &str, socks: u16, http: u16) -> Result<String> {
    let mut object: serde_json::Value = serde_json::from_str(config_json).map_err(|e| {
        CoreError::InvalidConfig(format!("psiphon.config_json is invalid JSON: {e}"))
    })?;
    let map = object.as_object_mut().ok_or_else(|| {
        CoreError::InvalidConfig("psiphon.config_json must be a JSON object".into())
    })?;
    if socks == 0 { map.remove("LocalSocksProxyPort"); }
    else { map.insert("LocalSocksProxyPort".into(), serde_json::Value::from(socks)); }
    if http == 0 { map.remove("LocalHttpProxyPort"); }
    else { map.insert("LocalHttpProxyPort".into(), serde_json::Value::from(http)); }
    serde_json::to_string(&object).map_err(|e| {
        CoreError::InvalidConfig(format!("could not render psiphon.config_json: {e}"))
    })
}


/// Permit the platform resolver even though BindToDevice is configured.
///
/// Upstream disables the standard library resolver whenever a DeviceBinder is
/// set, because the system resolver may route inside the VPN:
///
/// ```text
/// return c.BindToDevice == nil || c.AllowDefaultResolverWithBindToDevice
/// ```
///
/// On Android that is too strict for us: the host OS keeps DNS out of the VPN
/// already, and `VpnService.Builder.addDisallowedApplication(ourselves)` means
/// our own lookups are never captured. Without this flag the resolver is left
/// with whatever `GetDNSServersAsString` returned and nothing else, so a
/// momentary gap in that list turned into "no DNS servers" and killed the
/// connect. The flag is a no-op off Android, where BindToDevice is never set.
#[cfg(any(test, all(feature = "enabled", psiphon_linked)))]
fn inject_android_resolver_policy(config_json: &str) -> Result<String> {
    if !cfg!(target_os = "android") {
        return Ok(config_json.to_string());
    }
    let mut object: serde_json::Value = serde_json::from_str(config_json).map_err(|e| {
        CoreError::InvalidConfig(format!("psiphon.config_json is invalid JSON: {e}"))
    })?;
    let map = object.as_object_mut().ok_or_else(|| {
        CoreError::InvalidConfig("psiphon.config_json must be a JSON object".into())
    })?;
    // Only set it when the caller has not expressed an opinion, so a config
    // that deliberately turns it off keeps working.
    map.entry("AllowDefaultDNSResolverWithBindToDevice")
        .or_insert(serde_json::Value::Bool(true));
    serde_json::to_string(&object).map_err(|e| {
        CoreError::InvalidConfig(format!("could not render psiphon.config_json: {e}"))
    })
}

/// The cgo boundary. Only compiled when the archive is actually linked.
#[cfg(all(feature = "enabled", psiphon_linked))]
mod ffi {
    use fcae_runtime::error::{CoreError, Result};
    use std::ffi::{c_char, c_int, CStr, CString};

    extern "C" {
        fn psi_set_log_callback(cb: Option<unsafe extern "C" fn(c_int, *const c_char)>);
        fn psi_set_protect_callback(cb: Option<unsafe extern "C" fn(c_int) -> c_int>);
        fn psi_set_network_callbacks(
            dns: Option<super::DnsFn>,
            connectivity: Option<super::ConnectivityFn>,
            network_id: Option<super::NetworkIdFn>,
        );
        fn psi_start(config_json: *const c_char, embedded: *const c_char, use_binder: c_int)
            -> c_int;
        fn psi_stop() -> c_int;
        fn psi_state() -> c_int;
        fn psi_socks_port() -> c_int;
        fn psi_http_port() -> c_int;
        fn psi_regions() -> *mut c_char;
        fn psi_string_free(s: *mut c_char);
        fn psi_bytes(up: *mut i64, down: *mut i64);
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

    /// Install the host's view of the underlying network.
    ///
    /// `dns` is mandatory on Android: with BindToDevice configured upstream
    /// refuses the standard library resolver, so this is the only place DNS
    /// servers can come from.
    pub(super) fn set_network_callbacks(
        dns: Option<super::DnsFn>,
        connectivity: Option<super::ConnectivityFn>,
        network_id: Option<super::NetworkIdFn>,
    ) {
        unsafe { psi_set_network_callbacks(dns, connectivity, network_id) };
    }

    pub(super) fn start(inputs: &super::StartInputs, use_binder: bool) -> Result<()> {
        // Fresh session: drop the previous tunnel's RTT measurement.
        PSI_RTT_MS.store(0, std::sync::atomic::Ordering::Relaxed);
        PSI_RTT_NEXT_PROBE_SECS.store(0, std::sync::atomic::Ordering::Relaxed);
        PSI_RTT_ATTEMPTS.store(0, std::sync::atomic::Ordering::Relaxed);
        PSI_RTT_DONE.store(false, std::sync::atomic::Ordering::Relaxed);
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

    /// Live counters for the telemetry pump: cumulative totals plus a naive
    /// bytes/sec rate between successive polls (~500 ms apart).
    pub(super) fn counters() -> fcae_runtime::backend::Counters {
        refresh_rtt();
        let (up, down) = bytes();
        let (total_tx, total_rx, tx_rate, rx_rate) = super::counters_state::sample(up, down);
        fcae_runtime::backend::Counters {
            total_rx,
            total_tx,
            rx_bytes_sec: rx_rate,
            tx_bytes_sec: tx_rate,
            rtt_ms: PSI_RTT_MS.load(std::sync::atomic::Ordering::Relaxed) as u32,
        }
    }

    // ── Tunnel RTT probe ───────────────────────────────────────────────
    //
    // The psiphon shim exports no latency telemetry, so the bridge measures
    // it: one HTTP round trip through the shim's local HTTP proxy
    // (absolute-URI HEAD against Google's generate_204 edge) — a full tunnel
    // round trip to the internet. Runs ONCE per connect (immediate probe
    // plus a small backoff retry budget) — continuous pings would spam the
    // tunnel and the 'port forward failures' counter on a dead server. Runs
    // off-thread so the ~500 ms telemetry pump never blocks. 0 = none yet.
    static PSI_RTT_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static PSI_RTT_PROBE_ACTIVE: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    static PSI_RTT_NEXT_PROBE_SECS: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
    static PSI_RTT_ATTEMPTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static PSI_RTT_DONE: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    fn probe_rtt_once(port: u16) -> Option<u64> {
        use std::io::{BufRead, Write};
        let mut stream = std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            std::time::Duration::from_millis(1500),
        )
        .ok()?;
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(1500)));
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(1500)));
        let started = std::time::Instant::now();
        stream
            .write_all(b"HEAD http://www.gstatic.com/generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n")
            .ok()?;
        let mut status = String::new();
        use std::io::Read;
        std::io::BufReader::new(stream).take(256).read_line(&mut status).ok()?;
        let mut parts = status.split_whitespace();
        if !parts.next()?.starts_with("HTTP/") || parts.next()? != "204" {
            return None;
        }
        Some(started.elapsed().as_millis().max(1) as u64)
    }

    fn refresh_rtt() {
        use std::sync::atomic::Ordering::Relaxed;
        if PSI_RTT_DONE.load(Relaxed) || PSI_RTT_ATTEMPTS.load(Relaxed) >= 4 {
            return;
        }
        let port = http_port();
        if port == 0 {
            PSI_RTT_MS.store(0, Relaxed);
            return;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now < PSI_RTT_NEXT_PROBE_SECS.load(Relaxed) {
            return;
        }
        if PSI_RTT_PROBE_ACTIVE.swap(true, Relaxed) {
            return;
        }
        let attempts = PSI_RTT_ATTEMPTS.fetch_add(1, Relaxed);
        // Backoff per failed attempt (0s, +2s, +4s, +8s), then give up —
        // per-second probes on a dead server only log spam.
        PSI_RTT_NEXT_PROBE_SECS.store(now + (1u64 << (attempts + 1).min(3)), Relaxed);
        std::thread::spawn(move || {
            if let Some(ms) = probe_rtt_once(port) {
                PSI_RTT_MS.store(ms, Relaxed);
                PSI_RTT_DONE.store(true, Relaxed);
            }
            PSI_RTT_PROBE_ACTIVE.store(false, Relaxed);
        });
    }

    /// Cumulative tunneled bytes from the shim's BytesTransferred notices.
    /// Returns (up, down).
    pub(super) fn bytes() -> (u64, u64) {
        let mut up: i64 = 0;
        let mut down: i64 = 0;
        unsafe { psi_bytes(&mut up, &mut down) };
        (up.max(0) as u64, down.max(0) as u64)
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

/// Rate calculation state for [`ffi::counters`]: totals are cumulative, the
/// UI wants bytes/sec, so keep the previous sample here. Everything is
/// lock-free: three atomic snapshots plus a single `OnceLock` epoch that
/// anchors the monotonic clock.
#[cfg(all(feature = "enabled", psiphon_linked))]
mod counters_state {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    use std::time::Instant;

    static LAST_UP: AtomicU64 = AtomicU64::new(0);
    static LAST_DOWN: AtomicU64 = AtomicU64::new(0);
    /// Milliseconds since [`EPOCH`] at the previous sample; 0 = never sampled.
    static LAST_MS: AtomicU64 = AtomicU64::new(0);
    static EPOCH: OnceLock<Instant> = OnceLock::new();

    pub fn sample(up: u64, down: u64) -> (u64, u64, u64, u64) {
        let now_ms = EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64;
        let prev_ms = LAST_MS.swap(now_ms, Ordering::Relaxed);
        let prev_up = LAST_UP.swap(up, Ordering::Relaxed);
        let prev_down = LAST_DOWN.swap(down, Ordering::Relaxed);
        // The first sample has no baseline: report the totals with zero rates
        // rather than a one-off spike of (lifetime bytes / 1s).
        if prev_ms == 0 {
            return (up, down, 0, 0);
        }
        // bytes/sec between successive samples (~500 ms apart), computed in
        // milliseconds so a fast pump does not collapse to 0/1. Saturating
        // end to end: a restarted shim resets its counters to 0 and the
        // deltas must clamp instead of wrapping.
        let dt_ms = now_ms.saturating_sub(prev_ms).max(1);
        let up_rate = up
            .saturating_sub(prev_up)
            .saturating_mul(1_000)
            / dt_ms;
        let down_rate = down
            .saturating_sub(prev_down)
            .saturating_mul(1_000)
            / dt_ms;
        (up, down, up_rate, down_rate)
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
            // Psiphon's local SOCKS5 is CONNECT-only: no UDP ASSOCIATE.
            udp: false,
            dns_over_https: true,
        }
    }

    /// Live traffic counters, fed by the shim's BytesTransferred notices
    /// (enabled by default in validate). Without this the UI and
    /// notification would show 0 B for a fully working Psiphon tunnel.
    /// On Android the AAR owns the tunnel and reports through its own
    /// notification; the shim's counters do not exist there, so report the
    /// zero default (the TUN-side counters stay the source of truth).
    fn counters(&self) -> fcae_runtime::backend::Counters {
        #[cfg(all(feature = "enabled", psiphon_linked))]
        {
            ffi::counters()
        }
        #[cfg(not(all(feature = "enabled", psiphon_linked)))]
        {
            fcae_runtime::backend::Counters::default()
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
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if self.stopped.load(Ordering::SeqCst) {
                    return Ok(());
                }
            }
        }
    }

    async fn stop(&self, _timeout: Duration) -> Result<()> {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        #[cfg(all(feature = "enabled", psiphon_linked))]
        {
            // Fire-and-forget: psi.Stop joins the whole controller before
            // returning, which can take seconds -- far too long to block a
            // disconnect on. The cancel token is already set and `stopped`
            // makes wait() exit immediately, so the tunnel is down from the
            // caller's perspective; the blocking stop runs on its own task.
            tokio::task::spawn_blocking(ffi::stop);
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
    fn lan_toggle_controls_the_actual_psiphon_listen_interface() {
        let mut cfg = make_config(Some(r#"{"ListenInterface":"any"}"#), Some("/tmp/psi"));
        cfg.lan_sharing = false;
        let local: serde_json::Value = serde_json::from_str(&validate(&cfg).unwrap().config_json).unwrap();
        assert_eq!(local["ListenInterface"], "");
        cfg.lan_sharing = true;
        let shared: serde_json::Value = serde_json::from_str(&validate(&cfg).unwrap().config_json).unwrap();
        assert_eq!(shared["ListenInterface"], "any");
    }

    #[test]
    fn psiphon_endpoint_requires_tunneled_https_dns() {
        let handle = PsiphonHandle { socks_port: 1080, http_port: 8080, stopped: AtomicBool::new(false) };
        let endpoints = handle.endpoints();
        assert!(!endpoints.udp);
        assert!(endpoints.dns_over_https);
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
    fn data_root_dir_is_required_when_no_data_dir() {
        let cfg = make_config(Some("{}"), None);
        let err = validate(&cfg).unwrap_err();
        assert!(format!("{err}").contains("data_root_dir"), "got: {err}");
    }

    /// psi.Start() takes only the config object, so the datastore path has to
    /// be spliced into it -- it used to be computed and then dropped.
    #[test]
    fn data_root_dir_lands_in_the_config_json() {
        let cfg = make_config(Some(r#"{"PropagationChannelId":"x"}"#), Some("/tmp/psi"));
        let inputs = validate(&cfg).expect("should validate");
        assert!(
            inputs.config_json.contains(r#""DataRootDirectory":"/tmp/psi""#),
            "got: {}",
            inputs.config_json
        );
    }

    /// Falls back to <data_dir>/psiphon so a caller that already set data_dir
    /// does not have to repeat it.
    #[test]
    fn data_root_dir_falls_back_to_the_session_data_dir() {
        let mut cfg = make_config(Some("{}"), None);
        cfg.data_dir = Some("/var/app".into());
        let inputs = validate(&cfg).expect("should validate");
        assert!(
            inputs.config_json.contains(r#""DataRootDirectory":"/var/app/psiphon""#),
            "got: {}",
            inputs.config_json
        );
    }

    /// A Windows path contains backslashes, which must not corrupt the JSON.
    #[test]
    fn a_path_with_backslashes_is_escaped() {
        let cfg = make_config(Some("{}"), Some(r"C:\Users\me\psi"));
        let inputs = validate(&cfg).expect("should validate");
        assert!(
            inputs.config_json.contains(r#""DataRootDirectory":"C:\\Users\\me\\psi""#),
            "got: {}",
            inputs.config_json
        );
    }

    #[test]
    #[cfg(target_os = "android")]
    fn android_allows_the_default_resolver_alongside_bind_to_device() {
        let cfg = make_config(Some(r#"{"PropagationChannelId":"x"}"#), Some("/tmp/psi"));
        let inputs = validate(&cfg).expect("should validate");
        assert!(
            inputs
                .config_json
                .contains(r#""AllowDefaultDNSResolverWithBindToDevice":true"#),
            "got: {}",
            inputs.config_json
        );
    }

    /// An explicit `false` is a deliberate choice and must survive.
    #[test]
    #[cfg(target_os = "android")]
    fn an_explicit_resolver_policy_is_not_overwritten() {
        let cfg = make_config(
            Some(r#"{"AllowDefaultDNSResolverWithBindToDevice":false}"#),
            Some("/tmp/psi"),
        );
        let inputs = validate(&cfg).expect("should validate");
        assert!(
            inputs
                .config_json
                .contains(r#""AllowDefaultDNSResolverWithBindToDevice":false"#),
            "got: {}",
            inputs.config_json
        );
    }

    /// Desktop never sets BindToDevice, so the flag must stay absent rather
    /// than being written unconditionally.
    #[test]
    #[cfg(not(target_os = "android"))]
    fn desktop_does_not_touch_the_resolver_policy() {
        let cfg = make_config(Some(r#"{"PropagationChannelId":"x"}"#), Some("/tmp/psi"));
        let inputs = validate(&cfg).expect("should validate");
        assert!(
            !inputs
                .config_json
                .contains("AllowDefaultDNSResolverWithBindToDevice"),
            "got: {}",
            inputs.config_json
        );
    }

    #[test]
    fn a_valid_config_passes() {
        let cfg = make_config(Some(r#"{"PropagationChannelId":"x"}"#), Some("/tmp/psi"));
        let inputs = validate(&cfg).expect("should validate");
        assert!(inputs.config_json.contains(r#""PropagationChannelId":"x""#));
        assert!(inputs.embedded_server_list.is_empty());
    }

    /// The out-of-the-box path: a bare config (the all-F sponsor IDs ship no
    /// entries) must gain a server-entry source via the legacy public list
    /// fallback — otherwise a fresh datastore stalls on CandidateServers 0.
    #[test]
    fn the_bare_config_falls_back_to_the_legacy_public_list() {
        let bare = r#"{"PropagationChannelId":"FFFFFFFFFFFFFFFF","SponsorId":"FFFFFFFFFFFFFFFF"}"#;
        assert!(!has_server_entry_source(bare, None));

        // What validate() does when the predicate says "no source":
        let json = inject_string_field(bare, "RemoteServerListUrl", DEFAULT_SERVER_LIST_URL).unwrap();
        let json = inject_string_field(
            &json,
            "RemoteServerListSignaturePublicKey",
            DEFAULT_SERVER_LIST_SIGNATURE_KEY,
        )
        .unwrap();
        assert!(has_server_entry_source(&json, None));
        assert!(json.contains("server_list_compressed"));
        // User fields survive the splice.
        assert!(json.contains(r#""PropagationChannelId":"FFFFFFFFFFFFFFFF""#));
    }

    /// With neither an embedded list nor a remote/obfuscated server list in
    /// config_json, tunnel-core has no way to learn its first server entry:
    /// the predicate behind the startup warning must flag exactly this shape.
    #[test]
    fn the_default_ui_config_has_no_server_entry_source() {
        // kDefaultPsiphonConfig from ui_render.h (plus the injected data dir).
        let bare = concat!(
            r#"{"PropagationChannelId":"FFFFFFFFFFFFFFFF","SponsorId":"FFFFFFFFFFFFFFFF","#,
            r#""ClientVersion":"1","TunnelPoolSize":1,"DisableLocalSocksAuth":true,"#,
            r#""EmitDiagnosticNotices":true,"UseIndistinguishableTLS":true,"#,
            r#""DataRootDirectory":"/tmp/psi"}"#
        );
        assert!(!has_server_entry_source(bare, None));
        assert!(!has_server_entry_source(bare, Some("")));
        // Whitespace-only is still no source...
        assert!(!has_server_entry_source(bare, Some("  \n")));

        // An embedded list satisfies it...
        assert!(has_server_entry_source(bare, Some("oNNXuM6b5Wl3BwEX4xNw")));
        // ...as does any recognised remote/obfuscated list field.
        assert!(has_server_entry_source(
            r#"{"RemoteServerListUrl":"https://example.invalid/server_list"}"#,
            None
        ));
        assert!(has_server_entry_source(
            r#"{"RemoteServerListSignaturePublicKey":"k","RemoteServerListURLs":[{"URL":"aGk="}]}"#,
            None
        ));
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
