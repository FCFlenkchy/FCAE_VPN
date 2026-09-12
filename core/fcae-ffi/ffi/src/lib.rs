//! # fcae-ffi — the C ABI surface
//!
//! The **only** crate in the tree with `#[no_mangle]`. Everything here is a
//! thin, panic-safe translation between C and [`fcae_runtime`]:
//!
//! * marshal pointers → typed Rust values (in `fcae_runtime::config`),
//! * catch panics so a Rust unwind can never cross into C (UB),
//! * map [`CoreError`] → [`FcaeStatus`] and stash the message for
//!   [`fcae_last_error`].
//!
//! Exported surface:
//!
//! * `fcae_*` — the whole API. There is no legacy `aether_*` surface: the old
//!   symbols are gone and every caller moves to this header.

use std::ffi::{c_char, c_void, CStr, CString};
use std::sync::Arc;

use fcae_abi::*;
use fcae_runtime::config;
use fcae_runtime::error::CoreError;
use fcae_runtime::session::{Supervisor, SupervisorConfig, TunBridge};
use fcae_runtime::telemetry::{self, TelemetryCell};
use once_cell::sync::OnceCell;
use parking_lot::Mutex;

mod logger;

/// Process-wide state, created by `fcae_init`.
struct Runtime {
    supervisor: Supervisor,
    telemetry: Arc<TelemetryCell>,
    #[cfg(feature = "tun")]
    bridge: Arc<fcae_bridge_tun2socks::Tun2SocksBridge>,
}

static RUNTIME: OnceCell<Runtime> = OnceCell::new();
static LAST_ERROR: Mutex<Option<CString>> = Mutex::new(None);

fn runtime() -> Result<&'static Runtime, CoreError> {
    RUNTIME.get().ok_or(CoreError::NotInitialized)
}

fn set_last_error(msg: &str) {
    *LAST_ERROR.lock() = CString::new(msg).ok();
}

/// Run `f`, converting errors and panics into an [`FcaeStatus`].
///
/// Catching panics is not optional: unwinding across an `extern "C"` boundary
/// is undefined behaviour, and this library runs inside a GUI process that
/// must survive an engine bug.
fn guard<F>(what: &str, f: F) -> FcaeStatus
where
    F: FnOnce() -> Result<(), CoreError> + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(Ok(())) => {
            set_last_error("");
            FcaeStatus::Ok
        }
        Ok(Err(e)) => {
            let msg = e.to_string();
            log::error!("[ffi] {what}: {msg}");
            set_last_error(&msg);
            e.status()
        }
        Err(_) => {
            let msg = format!("{what}: panicked");
            log::error!("[ffi] {msg}");
            set_last_error(&msg);
            FcaeStatus::Internal
        }
    }
}

/// Copy a Rust string into a fixed C buffer, always NUL-terminating and
/// truncating on a char boundary.
fn fill(buf: &mut [c_char], s: &str) {
    let cap = buf.len().saturating_sub(1);
    let mut end = s.len().min(cap);
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    for (slot, b) in buf.iter_mut().zip(s.as_bytes()[..end].iter()) {
        *slot = *b as c_char;
    }
    buf[end] = 0;
}

// ── Lifecycle ───────────────────────────────────────────────────────────

/// Fill `out` with a fully-defaulted, correctly-stamped config.
///
/// Callers should always start from this rather than zeroing a struct, so
/// `struct_size`/`abi_version` are right and new fields get sane defaults.
///
/// # Safety
/// `out` must point to writable storage of at least `sizeof(FcaeConfig)`.
#[no_mangle]
pub unsafe extern "C" fn fcae_config_default(out: *mut FcaeConfig) -> FcaeStatus {
    if out.is_null() {
        return FcaeStatus::NullArgument;
    }
    let d = config::SessionConfig::default();
    out.write(FcaeConfig {
        struct_size: std::mem::size_of::<FcaeConfig>() as u32,
        abi_version: FCAE_ABI_VERSION,
        backend: FcaeBackend::Aether,
        protocol: FcaeProtocol::Masque,
        mode: FcaeMode::Proxy,
        scan_mode: FcaeScanMode::Balanced,
        ip_version: FcaeIpVersion::V4,
        sys_profile: FcaeSysProfile::Auto,
        lan_sharing: false,
        quick_reconnect: d.quick_reconnect,
        socks_port: d.socks_port,
        http_port: d.http_port,
        force_peer: std::ptr::null(),
        config_path: std::ptr::null(),
        data_dir: std::ptr::null(),
        udp_buf_kb: 0,
        engine_log: FcaeEngineLog::Info,
        obfuscation: FcaeObfuscation {
            noize_profile: std::ptr::null(),
            fragment_enabled: false,
            frag_min_size: 16,
            frag_max_size: 32,
            frag_min_delay_ms: 2,
            frag_max_delay_ms: 10,
            h2_enabled: false,
            ech_enabled: false,
        },
        dns: FcaeDnsConfig {
            server: std::ptr::null(),
            mode: FcaeDnsMode::Udp,
            doh_url: std::ptr::null(),
            ip_prefer: FcaeIpVersion::V4,
            tls_groups: std::ptr::null(),
            sni: std::ptr::null(),
        },
        routing: FcaeRouting {
            rules_file: std::ptr::null(),
            rules_inline: std::ptr::null(),
        },
        zero_trust: FcaeZeroTrust {
            team_name: std::ptr::null(),
            access_token: std::ptr::null(),
            access_email: std::ptr::null(),
        },
        psiphon: FcaePsiphon {
            config_json: std::ptr::null(),
            embedded_server_list: std::ptr::null(),
            egress_region: std::ptr::null(),
            data_root_dir: std::ptr::null(),
        },
        tor: FcaeTor {
            mode: FcaeTorMode::Off,
            bridges: FcaeTorBridges::None,
            bind: std::ptr::null(),
            state_dir: std::ptr::null(),
            bridge_lines: std::ptr::null(),
            pt_path: std::ptr::null(),
        },
        tun_name: std::ptr::null(),
        tun_mtu: 0,
        tun_fd: -1,
        _reserved: [0; 4],
    });
    FcaeStatus::Ok
}

/// Initialise the library. Idempotent; subsequent calls are no-ops that
/// return `Ok`.
///
/// # Safety
/// `options` must point to a valid, correctly-stamped [`FcaeInitOptions`].
#[no_mangle]
pub unsafe extern "C" fn fcae_init(options: *const FcaeInitOptions) -> FcaeStatus {
    let opts = options;
    guard("fcae_init", move || {
        config::check_init_options(opts)?;
        let opts = &*opts;

        if RUNTIME.get().is_some() {
            return Ok(());
        }

        let telemetry = Arc::new(TelemetryCell::new());

        logger::install(opts.log_cb, opts.user_data, opts.max_log_level);

        // Forward state transitions to the host callback, so a UI can react
        // on the edge instead of polling telemetry every frame.
        if let Some(cb) = opts.state_cb {
            let ud = opts.user_data as usize;
            telemetry.set_state_hook(Some(Box::new(move |state| {
                // SAFETY: user_data is opaque to us and the host guarantees
                // it outlives the library (documented in fcae.h).
                unsafe { cb(state, ud as *mut c_void) };
            })));
        }

        // Discover the LAN IP off the critical path.
        {
            let t = telemetry.clone();
            std::thread::spawn(move || t.set_lan_ip(telemetry::detect_lan_ip()));
        }

        // Register backends.
        #[cfg(feature = "aether")]
        fcae_bridge_aether::register();
        #[cfg(feature = "psiphon")]
        fcae_bridge_psiphon::register();

        #[cfg(feature = "tun")]
        let bridge = Arc::new(fcae_bridge_tun2socks::Tun2SocksBridge::new());

        #[cfg(feature = "tun")]
        let tun_bridge: Arc<dyn TunBridge> = bridge.clone();
        #[cfg(not(feature = "tun"))]
        let tun_bridge: Arc<dyn TunBridge> = Arc::new(fcae_runtime::session::NullTunBridge);

        let supervisor = Supervisor::new(
            telemetry.clone(),
            SupervisorConfig {
                tun_bridge,
                #[cfg(feature = "tun")]
                is_privileged: fcae_bridge_tun2socks::platform::is_privileged,
                #[cfg(not(feature = "tun"))]
                is_privileged: || false,
                ..Default::default()
            },
        );

        let _ = RUNTIME.set(Runtime {
            supervisor,
            telemetry,
            #[cfg(feature = "tun")]
            bridge,
        });

        log::info!(
            "[ffi] fcae initialised (abi v{FCAE_ABI_VERSION}, tun2socks: {})",
            tun_backend_description()
        );
        Ok(())
    })
}

fn tun_backend_description() -> String {
    #[cfg(feature = "tun")]
    {
        fcae_bridge_tun2socks::version()
    }
    #[cfg(not(feature = "tun"))]
    {
        "disabled".to_string()
    }
}

/// Start a session.
///
/// # Safety
/// `config` must point to a valid, correctly-stamped [`FcaeConfig`].
#[no_mangle]
pub unsafe extern "C" fn fcae_start(cfg: *const FcaeConfig) -> FcaeStatus {
    guard("fcae_start", move || {
        let rt = runtime()?;
        let parsed = config::parse(cfg)?;

        // Hand the Android descriptor to the bridge before the session runs.
        //
        // In proxy mode the TUN bridge must stay completely out of the way, so
        // any descriptor left over from an earlier TUN session is dropped
        // here. Otherwise the stale fd kept the bridge looking "armed": the
        // supervisor saw a pre-authorised fd and a proxy-only run could still
        // reach into tun2socks.
        #[cfg(feature = "tun")]
        match (parsed.mode, parsed.tun.fd) {
            (fcae_abi::FcaeMode::Tun, Some(fd)) => rt.bridge.set_android_fd(fd),
            (fcae_abi::FcaeMode::Tun, None) => {}
            (fcae_abi::FcaeMode::Proxy, _) => rt.bridge.clear_android_fd(),
        }

        rt.supervisor.start(parsed)
    })
}

/// Stop the session. Blocks until the TUN device is down and routes/DNS are
/// restored, so it is safe to immediately offer "connect" again.
#[no_mangle]
pub extern "C" fn fcae_stop() -> FcaeStatus {
    guard("fcae_stop", || runtime()?.supervisor.stop())
}

/// True while a session is active.
#[no_mangle]
pub extern "C" fn fcae_is_running() -> bool {
    RUNTIME
        .get()
        .map(|rt| rt.supervisor.is_running())
        .unwrap_or(false)
}

/// Write the current telemetry snapshot into `out`.
///
/// # Safety
/// `out` must point to a valid, correctly-stamped [`FcaeTelemetry`].
#[no_mangle]
pub unsafe extern "C" fn fcae_get_telemetry(out: *mut FcaeTelemetry) -> FcaeStatus {
    guard("fcae_get_telemetry", move || {
        let rt = runtime()?;
        let out = out.as_mut().ok_or(CoreError::NullArgument("out"))?;
        if out.abi_version != FCAE_ABI_VERSION
            || out.struct_size as usize != std::mem::size_of::<FcaeTelemetry>()
        {
            return Err(CoreError::AbiMismatch("FcaeTelemetry".into()));
        }

        let s = rt.telemetry.snapshot();
        out.state = s.state;
        out.backend = s.backend;
        out.active_mode = s.mode;
        out.lan_enabled = s.lan_enabled;
        out.rtt_ms = s.counters.rtt_ms;
        out.rx_bytes_sec = s.counters.rx_bytes_sec;
        out.tx_bytes_sec = s.counters.tx_bytes_sec;
        out.total_rx = s.counters.total_rx;
        out.total_tx = s.counters.total_tx;
        out.uptime_secs = s.uptime_secs;
        out.reconnect_count = s.reconnect_count;
        fill(&mut out.connected_peer, &s.connected_peer);
        fill(&mut out.lan_ip, &s.lan_ip);
        fill(&mut out.status_message, &s.status_message);
        fill(&mut out.last_error, &s.last_error);
        Ok(())
    })
}

/// Supply the Android VpnService file descriptor.
///
/// The library **dups** this descriptor and closes only its own copy, so the
/// JVM's `ParcelFileDescriptor` remains the sole owner — this is what removes
/// the Bionic double-close abort that the subprocess design suffered from.
#[no_mangle]
pub extern "C" fn fcae_set_tun_fd(fd: i32) -> FcaeStatus {
    guard("fcae_set_tun_fd", move || {
        let _rt = runtime()?;
        #[cfg(feature = "tun")]
        _rt.bridge.set_android_fd(fd);
        #[cfg(not(feature = "tun"))]
        let _ = fd;
        Ok(())
    })
}

/// True if the process can create a TUN device (admin/root).
#[no_mangle]
pub extern "C" fn fcae_is_privileged() -> bool {
    #[cfg(feature = "tun")]
    {
        fcae_bridge_tun2socks::platform::is_privileged()
    }
    #[cfg(not(feature = "tun"))]
    {
        false
    }
}

/// Message for the most recent failing call on any thread.
///
/// The returned pointer is owned by the library and stays valid until the
/// next failing call.
#[no_mangle]
pub extern "C" fn fcae_last_error() -> *const c_char {
    static EMPTY: &CStr = c"";
    match LAST_ERROR.lock().as_ref() {
        Some(s) => s.as_ptr(),
        None => EMPTY.as_ptr(),
    }
}

/// ABI version this library was built with; compare against
/// `FCAE_ABI_VERSION` from the header to detect a stale binary.
#[no_mangle]
pub extern "C" fn fcae_abi_version() -> u32 {
    FCAE_ABI_VERSION
}

/// Which backends are compiled in. Writes up to `max` ids into `out` and
/// returns how many exist.
///
/// # Safety
/// `out` must point to storage for at least `max` `FcaeBackend` values.
#[no_mangle]
pub unsafe extern "C" fn fcae_available_backends(out: *mut FcaeBackend, max: u32) -> u32 {
    let available = fcae_runtime::registry::available();
    if !out.is_null() {
        for (i, id) in available.iter().take(max as usize).enumerate() {
            out.add(i).write(*id);
        }
    }
    available.len() as u32
}

/// Tear everything down and release resources. After this, `fcae_init` must
/// be called again before any other function.
#[no_mangle]
pub extern "C" fn fcae_shutdown() -> FcaeStatus {
    guard("fcae_shutdown", || {
        if let Some(rt) = RUNTIME.get() {
            let _ = rt.supervisor.stop();
            rt.telemetry.set_state_hook(None);
        }
        logger::uninstall();
        Ok(())
    })
}

// ── Update checking ─────────────────────────────────────────────────────

/// Start an asynchronous update check. Poll with [`fcae_poll_update`].
///
/// Calling this while a check is already running is a no-op.
///
/// # Safety
/// `current_version` must be NULL or a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn fcae_check_update_async(
    current_version: *const c_char,
    include_prereleases: bool,
) -> FcaeStatus {
    guard("fcae_check_update_async", move || {
        runtime()?;
        let cur = config::cstr_opt(current_version).unwrap_or_else(|| "dev".into());
        fcae_runtime::update::check_async(cur, include_prereleases);
        Ok(())
    })
}

/// Evaluate a version manifest the host fetched itself.
///
/// Android does its HTTP in Kotlin (native threads there hit DNS problems),
/// so it uses this instead of [`fcae_check_update_async`].
///
/// # Safety
/// Both arguments must be NULL or valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn fcae_check_update_from_json(
    current_version: *const c_char,
    json: *const c_char,
    include_prereleases: bool,
) -> FcaeStatus {
    guard("fcae_check_update_from_json", move || {
        runtime()?;
        let cur = config::cstr_opt(current_version).unwrap_or_else(|| "dev".into());
        let json = config::cstr_opt(json)
            .ok_or_else(|| CoreError::NullArgument("json"))?;
        if fcae_runtime::update::check_from_json(&cur, &json, include_prereleases) {
            Ok(())
        } else {
            Err(CoreError::Internal(
                fcae_runtime::update::snapshot().status,
            ))
        }
    })
}

/// Read the current update-check state.
///
/// Returns [`FcaeStatus::Ok`] once a check has completed (successfully or
/// not); while one is still running it returns [`FcaeStatus::Timeout`] so the
/// caller can distinguish "no answer yet" from "answered".
///
/// # Safety
/// `out` must point to a valid, correctly-stamped [`FcaeUpdateInfo`].
#[no_mangle]
pub unsafe extern "C" fn fcae_poll_update(out: *mut FcaeUpdateInfo) -> FcaeStatus {
    let out_ptr = out;
    let status = guard("fcae_poll_update", move || {
        let out = out_ptr.as_mut().ok_or(CoreError::NullArgument("out"))?;
        if out.abi_version != FCAE_ABI_VERSION
            || out.struct_size as usize != std::mem::size_of::<FcaeUpdateInfo>()
        {
            return Err(CoreError::AbiMismatch("FcaeUpdateInfo".into()));
        }

        let s = fcae_runtime::update::snapshot();
        out.check_in_progress = s.in_progress;
        out.check_done = s.done;
        fill(&mut out.status_message, &s.status);

        match &s.result {
            Some(r) => {
                out.update_available = r.update_available;
                out.is_prerelease = r.is_prerelease;
                fill(&mut out.latest_version, &r.latest_version);
                fill(&mut out.release_date, &r.release_date);
                fill(&mut out.release_notes, &r.release_notes);
                fill(&mut out.download_url, &r.download_url);
            }
            None => {
                out.update_available = false;
                out.is_prerelease = false;
                fill(&mut out.latest_version, "");
                fill(&mut out.release_date, "");
                fill(&mut out.release_notes, "");
                fill(&mut out.download_url, "");
            }
        }
        Ok(())
    });

    if status != FcaeStatus::Ok {
        return status;
    }
    if fcae_runtime::update::snapshot().done {
        FcaeStatus::Ok
    } else {
        FcaeStatus::Timeout
    }
}
