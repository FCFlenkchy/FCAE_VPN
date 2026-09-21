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

// Backend futures are boxed through this crate; raise the query depth
// limit here too (the attribute is per-crate, not inherited).
#![recursion_limit = "512"]

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
    #[cfg(any(feature = "tun", feature = "zeptun", feature = "hev"))]
    engines: Arc<TunEngines>,
}

/// Both TUN engines, dispatched per session from `SessionConfig::tun.engine`.
///
/// A build may carry tun2socks, zeptun, hev, or any combination; the choice is
/// per-session (the user flips it in Settings), so the supervisor is handed
/// one static `Arc<dyn TunBridge>` here and the decision happens at `start`.
/// The fd setters forward to ALL engines: Android hands the descriptor over
/// before the session parses, and whichever engine later runs must see it.
struct TunEngines {
    #[cfg(feature = "tun")]
    t2s: Arc<fcae_bridge_tun2socks::Tun2SocksBridge>,
    #[cfg(feature = "zeptun")]
    zeptun: Arc<fcae_bridge_zeptun::ZeptunBridge>,
    #[cfg(feature = "hev")]
    hev: Arc<fcae_bridge_hev_socks5_tunnel::HevSocks5TunnelBridge>,
}

impl TunEngines {
    fn set_android_fd(&self, fd: i32) {
        #[cfg(feature = "tun")]
        self.t2s.set_android_fd(fd);
        #[cfg(feature = "zeptun")]
        self.zeptun.set_external_fd(fd);
        #[cfg(feature = "hev")]
        self.hev.set_android_fd(fd);
    }

    fn clear_android_fd(&self) {
        #[cfg(feature = "tun")]
        self.t2s.clear_android_fd();
        #[cfg(feature = "zeptun")]
        self.zeptun.set_external_fd(-1);
        #[cfg(feature = "hev")]
        self.hev.clear_android_fd();
    }

    /// On-demand fd creation is a tun2socks mechanism (its `fd_provider`).
    /// The provider is retained there even when zeptun is the selected
    /// engine: `zeptun_start` borrows it via [`Self::establish_via_provider`]
    /// to hand zeptun the descriptor, since zeptun consumes fds rather than
    /// creating the device.
    #[cfg(feature = "tun")]
    fn set_fd_provider(&self, provider: Option<unsafe extern "C" fn() -> std::ffi::c_int>) {
        self.t2s.set_fd_provider(provider);
    }

    fn t2s_start(
        &self,
        cfg: &config::SessionConfig,
        endpoints: &fcae_runtime::backend::Endpoints,
    ) -> Result<(), CoreError> {
        #[cfg(feature = "tun")]
        {
            self.t2s.start(cfg, endpoints)
        }
        #[cfg(not(feature = "tun"))]
        {
            let _ = (cfg, endpoints);
            Err(CoreError::Internal(
                "the tun2socks TUN engine is not compiled into this build".into(),
            ))
        }
    }

    fn zeptun_start(
        &self,
        cfg: &config::SessionConfig,
        endpoints: &fcae_runtime::backend::Endpoints,
    ) -> Result<(), CoreError> {
        #[cfg(feature = "zeptun")]
        {
            // Deferred interface creation (Android): the provider is a
            // tun2socks mechanism (see `set_fd_provider`), while zeptun only
            // consumes a descriptor. When the session carries no fd of its
            // own, ask the host for one the same way tun2socks would; on
            // desktop no provider is registered and zeptun creates the
            // device itself.
            if cfg.tun.fd.is_none() && self.zeptun.preauthorised_fd().is_none() {
                if let Some(fd) = self.establish_via_provider()? {
                    self.zeptun.set_external_fd(fd);
                }
            }
            self.zeptun.start(cfg, endpoints)
        }
        #[cfg(not(feature = "zeptun"))]
        {
            let _ = (cfg, endpoints);
            Err(CoreError::Internal(
                "the zeptun TUN engine is not compiled into this build (feature `zeptun`)".into(),
            ))
        }
    }

    fn hev_start(
        &self,
        cfg: &config::SessionConfig,
        endpoints: &fcae_runtime::backend::Endpoints,
    ) -> Result<(), CoreError> {
        #[cfg(feature = "hev")]
        {
            // Android: the descriptor belongs to VpnService, so reuse the one
            // the host hands over. Desktop: none exists, and the engine opens
            // the device itself from its config (root, like the other engines).
            if cfg.tun.fd.is_none() && self.hev.preauthorised_fd().is_none() {
                if let Some(fd) = self.establish_via_provider()? {
                    self.hev.set_android_fd(fd);
                }
            }
            self.hev.start(cfg, endpoints)
        }
        #[cfg(not(feature = "hev"))]
        {
            let _ = (cfg, endpoints);
            Err(CoreError::Internal(
                "hev-socks5-tunnel is not compiled into this build".into(),
            ))
        }
    }

    /// Ask the host to build the TUN interface now, if a provider is
    /// registered. `Ok(None)` = no provider (the engine creates the device
    /// itself); `Err` = the host refused to build the interface.
    #[cfg(all(feature = "tun", any(feature = "zeptun", feature = "hev")))]
    fn establish_via_provider(&self) -> Result<Option<i32>, CoreError> {
        if !self.t2s.has_fd_provider() {
            return Ok(None);
        }
        self.t2s.establish_now().map(Some).ok_or_else(|| {
            CoreError::Internal("the host could not establish the VPN interface".into())
        })
    }

    /// The provider is a tun2socks mechanism, so a build that carries only
    /// zeptun or hev has nothing to borrow: those engines take their
    /// descriptor from VpnService (`set_android_fd`) or create the device
    /// themselves.
    #[cfg(all(not(feature = "tun"), any(feature = "zeptun", feature = "hev")))]
    fn establish_via_provider(&self) -> Result<Option<i32>, CoreError> {
        Ok(None)
    }
}

impl TunBridge for TunEngines {
    fn start(
        &self,
        cfg: &config::SessionConfig,
        endpoints: &fcae_runtime::backend::Endpoints,
    ) -> Result<(), CoreError> {
        match cfg.tun.engine {
            config::TunEngine::Tun2socks => self.t2s_start(cfg, endpoints),
            config::TunEngine::Zeptun => self.zeptun_start(cfg, endpoints),
            config::TunEngine::Hev => self.hev_start(cfg, endpoints),
        }
    }

    fn stop(&self, timeout: std::time::Duration) {
        #[cfg(feature = "tun")]
        self.t2s.stop(timeout);
        #[cfg(feature = "zeptun")]
        self.zeptun.stop(timeout);
        #[cfg(feature = "hev")]
        self.hev.stop(timeout);
    }

    fn abort(&self) {
        #[cfg(feature = "tun")]
        self.t2s.abort();
        #[cfg(feature = "zeptun")]
        self.zeptun.abort();
        #[cfg(feature = "hev")]
        self.hev.abort();
    }

    fn is_running(&self) -> bool {
        #[cfg(feature = "tun")]
        {
            if self.t2s.is_running() {
                return true;
            }
        }
        #[cfg(feature = "zeptun")]
        {
            if self.zeptun.is_running() {
                return true;
            }
        }
        #[cfg(feature = "hev")]
        {
            if self.hev.is_running() {
                return true;
            }
        }
        false
    }

    fn preauthorised_fd(&self) -> Option<i32> {
        #[cfg(feature = "tun")]
        {
            if let Some(fd) = self.t2s.preauthorised_fd() {
                return Some(fd);
            }
        }
        #[cfg(feature = "zeptun")]
        {
            if let Some(fd) = self.zeptun.preauthorised_fd() {
                return Some(fd);
            }
        }
        #[cfg(feature = "hev")]
        {
            if let Some(fd) = self.hev.preauthorised_fd() {
                return Some(fd);
            }
        }
        None
    }
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
            // 0 = let Psiphon pick a free port.
            socks_port: 0,
            http_port: 0,
        },
        tor: FcaeTor {
            mode: FcaeTorMode::Off,
            bridges: FcaeTorBridges::None,
            bind: std::ptr::null(),
            socks_port: config::DEFAULT_TOR_SOCKS_PORT,
            state_dir: std::ptr::null(),
            bridge_lines: std::ptr::null(),
            pt_path: std::ptr::null(),
        },
        tun_name: std::ptr::null(),
        tun_mtu: 0,
        tun_fd: -1,
        tor_http_port: 0,
        _reserved: [0; 1],
        tun_tcp_sndbuf: config::DEFAULT_TCP_BUFFER,
        tun_tcp_rcvbuf: config::DEFAULT_TCP_BUFFER,
        // 0 = follow the app default, which is auto-tuning OFF now.
        tun_tcp_auto_tuning: 0,
        // 0 = follow the app default: tun2socks logs stay silent.
        tun2socks_log_level: 0,
        // 0 = tun2socks: the long-tested engine stays the default.
        tun_engine: FCAE_TUN_ENGINE_TUN2SOCKS,
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

        // Re-arm after a previous fcae_shutdown().
        //
        // RUNTIME is a process-wide OnceCell, so the Runtime itself (and the
        // supervisor inside it) is deliberately built only once. But
        // fcae_shutdown() detaches the log callback and the state hook, and
        // a plain early return here left them detached forever: the second
        // fcae_init() was a no-op, so the UI's state_cb never fired again and
        // the app sat on "Disconnected"/"Establishing" no matter what the
        // session actually did. Re-attach the host's callbacks instead.
        if let Some(rt) = RUNTIME.get() {
            logger::install(opts.log_cb, opts.user_data, opts.max_log_level);
            rt.telemetry.set_state_hook(state_hook(opts));
            return Ok(());
        }

        let telemetry = Arc::new(TelemetryCell::new());

        logger::install(opts.log_cb, opts.user_data, opts.max_log_level);

        // Forward state transitions to the host callback, so a UI can react
        // on the edge instead of polling telemetry every frame.
        telemetry.set_state_hook(state_hook(opts));

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

        #[cfg(any(feature = "tun", feature = "zeptun", feature = "hev"))]
        let engines = Arc::new(TunEngines {
            #[cfg(feature = "tun")]
            t2s: Arc::new(fcae_bridge_tun2socks::Tun2SocksBridge::new()),
            #[cfg(feature = "zeptun")]
            zeptun: Arc::new(fcae_bridge_zeptun::ZeptunBridge::new()),
            #[cfg(feature = "hev")]
            hev: Arc::new(fcae_bridge_hev_socks5_tunnel::HevSocks5TunnelBridge::new()),
        });

        #[cfg(any(feature = "tun", feature = "zeptun", feature = "hev"))]
        let tun_bridge: Arc<dyn TunBridge> = engines.clone();
        #[cfg(not(any(feature = "tun", feature = "zeptun", feature = "hev")))]
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
            #[cfg(any(feature = "tun", feature = "zeptun", feature = "hev"))]
            engines,
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
        #[cfg(any(feature = "tun", feature = "zeptun", feature = "hev"))]
        match (parsed.mode, parsed.tun.fd) {
            (fcae_abi::FcaeMode::Tun, Some(fd)) => rt.engines.set_android_fd(fd),
            (fcae_abi::FcaeMode::Tun, None) => {}
            (fcae_abi::FcaeMode::Proxy, _) => rt.engines.clear_android_fd(),
        }

        rt.supervisor.start(parsed)
    })
}

/// Cancel the session and abort TUN descriptors without waiting for native
/// shutdown or routes/DNS restoration. Full cleanup runs on the session worker;
/// reconnect remains gated until the background reaper joins that worker.
#[no_mangle]
pub extern "C" fn fcae_stop() -> FcaeStatus {
    guard("fcae_stop", || runtime()?.supervisor.stop())
}

/// Cancel and abort owned TUN descriptors without joining the session.
/// The host must also close its own VPN descriptor. Full native and OS cleanup
/// runs on the session worker, not this caller. Follow with `fcae_stop()` to
/// arrange reaping. Idempotent; repeated calls do not repeat descriptor abort.
#[no_mangle]
pub extern "C" fn fcae_stop_begin() -> FcaeStatus {
    guard("fcae_stop_begin", || {
        runtime()?.supervisor.begin_stop();
        Ok(())
    })
}

/// Bring the TUN data plane down without cancelling the session or backend.
#[no_mangle]
pub extern "C" fn fcae_pause_tun() -> FcaeStatus {
    guard("fcae_pause_tun", || {
        runtime()?.supervisor.pause_tun();
        Ok(())
    })
}

/// Re-raise TUN on a live paused session. The host must publish a fresh
/// descriptor first (`fcae_set_tun_fd` or the fd provider).
#[no_mangle]
pub extern "C" fn fcae_resume_tun() -> FcaeStatus {
    guard("fcae_resume_tun", || runtime()?.supervisor.resume_tun())
}

/// True while a session is alive and its TUN data plane is paused.
#[no_mangle]
pub extern "C" fn fcae_tun_paused() -> bool {
    RUNTIME
        .get()
        .map(|rt| rt.supervisor.tun_is_paused())
        .unwrap_or(false)
}

/// True while a session is active.
#[no_mangle]
pub extern "C" fn fcae_is_running() -> bool {
    RUNTIME
        .get()
        .map(|rt| rt.supervisor.is_running())
        .unwrap_or(false)
}

/// Detect the local IPv4 address selected by the default route without sending traffic.
#[no_mangle]
pub unsafe extern "C" fn fcae_detect_lan_ip(
    out: *mut c_char,
    capacity: u32,
) -> FcaeStatus {
    guard("fcae_detect_lan_ip", move || {
        if out.is_null() || capacity == 0 {
            return Err(CoreError::NullArgument("out"));
        }
        let ip = telemetry::detect_lan_ip();
        let bytes = ip.as_bytes();
        let len = bytes.len().min(capacity as usize - 1);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out.cast::<u8>(), len);
        *out.add(len) = 0;
        Ok(())
    })
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
        #[cfg(any(feature = "tun", feature = "zeptun", feature = "hev"))]
        _rt.engines.set_android_fd(fd);
        #[cfg(not(any(feature = "tun", feature = "zeptun", feature = "hev")))]
        let _ = fd;
        Ok(())
    })
}

/// Install a callback that creates the TUN device on demand.
///
/// Without this the host must call `fcae_set_tun_fd` up front, which means
/// `VpnService.Builder.establish()` runs *before* the backend has connected:
/// the system routes are live while the tunnel is still dialling, so the
/// backend's own traffic survives only as long as the protect hook catches
/// every socket, and anything missed loops back into our own tunnel.
///
/// With a provider installed the interface is created only once a backend has
/// reported a live SOCKS endpoint. The callback returns a file descriptor, or
/// a negative value if the interface could not be established. The host keeps
/// ownership of the descriptor; the library dups what it needs. Pass NULL to
/// clear.
#[no_mangle]
pub extern "C" fn fcae_set_tun_fd_provider(
    provider: Option<unsafe extern "C" fn() -> std::ffi::c_int>,
) -> FcaeStatus {
    guard("fcae_set_tun_fd_provider", move || {
        let _rt = runtime()?;
        #[cfg(feature = "tun")]
        _rt.engines.set_fd_provider(provider);
        #[cfg(not(feature = "tun"))]
        let _ = provider;
        Ok(())
    })
}

/// True if the process can create a TUN device (admin/root).
///
/// 1.3.5.4 PATCH: previously the check only consulted the tun2socks bridge
/// (and returned `false` outright on builds without the `tun` feature). On a
/// Windows release built with only `zeptun` or `hev`, this caused the C++
/// frontend to skip its UAC elevation prompt even though the chosen engine
/// still requires admin to raise the Wintun adapter. The host saw "CONNECT"
/// start the engine, the bridge then refused to create the device, and the
/// session went ERROR with no obvious cause -- the exact symptom in
/// FCFlenkchy/FCAE_VPN#8. We now OR the privilege status across every TUN
/// bridge that is actually linked into this build.
#[no_mangle]
pub extern "C" fn fcae_is_privileged() -> bool {
    #[cfg(feature = "tun")]
    {
        if fcae_bridge_tun2socks::platform::is_privileged() {
            return true;
        }
    }
    #[cfg(feature = "zeptun")]
    {
        if fcae_bridge_zeptun::platform::is_privileged() {
            return true;
        }
    }
    #[cfg(feature = "hev")]
    {
        if fcae_bridge_hev_socks5_tunnel::platform::is_privileged() {
            return true;
        }
    }
    #[allow(unreachable_code)]
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

/// Describe one backend: name, whether it can actually run, and what it
/// supports.
///
/// Pairs with [`fcae_available_backends`], which only yields bare ids. Ids
/// alone cannot express "compiled in but a stub" or "ignores scan modes", so
/// every UI ended up hardcoding that per backend. Iterate
/// [`fcae_backend_count`] and call this for each index.
///
/// Returns `InvalidConfig` if `index` is out of range. Call this *after*
/// [`fcae_init`]: backends register during init, so before that every entry
/// reports unavailable.
///
/// # Safety
/// `out` must point to a valid, correctly-stamped [`FcaeBackendInfo`].
#[no_mangle]
pub unsafe extern "C" fn fcae_backend_info(index: u32, out: *mut FcaeBackendInfo) -> FcaeStatus {
    guard("fcae_backend_info", move || {
        let out = out.as_mut().ok_or(CoreError::NullArgument("out"))?;
        if out.abi_version != FCAE_ABI_VERSION
            || out.struct_size as usize != std::mem::size_of::<FcaeBackendInfo>()
        {
            return Err(CoreError::AbiMismatch("FcaeBackendInfo".into()));
        }

        let id = *fcae_runtime::registry::ALL
            .get(index as usize)
            .ok_or_else(|| {
                CoreError::InvalidConfig(format!(
                    "backend index {index} is out of range (fcae_backend_count() = {})",
                    fcae_runtime::registry::ALL.len()
                ))
            })?;

        let (available, reason, caps) = fcae_runtime::registry::describe(id);

        out.backend = id;
        fill(&mut out.id, backend_id_str(id));
        fill(&mut out.display_name, backend_display_name(id));
        out.available = available;
        fill(&mut out.unavailable_reason, &reason);
        out.supports_socks = caps.socks;
        out.supports_http_proxy = caps.http_proxy;
        out.supports_gateway_scanning = caps.gateway_scanning;
        out.supports_routing_rules = caps.routing_rules;
        out.requires_privileges = caps.requires_privileges;
        Ok(())
    })
}

/// How many TUN engines [`fcae_tun_engine_info`] can describe. Constant
/// across builds: unavailable engines are reported, not hidden, so a UI can
/// say why (not compiled / stub / disabled on this platform).
#[no_mangle]
pub extern "C" fn fcae_tun_engine_count() -> u32 {
    3
}

/// Detail of one TUN engine: id, name, and whether selecting it can succeed
/// in this build on this platform.
///
/// Engine 0 is always tun2socks, 1 is zeptun, and 2 is Hev,
/// matching `FCAE_TUN_ENGINE_*` — the `index` order is fixed so a UI can
/// also persist the raw `engine` value across runs.
///
/// Unlike [`fcae_backend_info`] this does not require [`fcae_init`]: engine
/// availability is a compile-/platform-time property, not backend runtime
/// state.
///
/// Returns `InvalidConfig` if `index` is out of range.
///
/// # Safety
/// `out` must point to a valid, correctly-stamped [`FcaeTunEngineInfo`].
#[no_mangle]
pub unsafe extern "C" fn fcae_tun_engine_info(index: u32, out: *mut FcaeTunEngineInfo) -> FcaeStatus {
    guard("fcae_tun_engine_info", move || {
        let out = out.as_mut().ok_or(CoreError::NullArgument("out"))?;
        if out.abi_version != FCAE_ABI_VERSION
            || out.struct_size as usize != std::mem::size_of::<FcaeTunEngineInfo>()
        {
            return Err(CoreError::AbiMismatch("FcaeTunEngineInfo".into()));
        }

        let (engine, id, name, available, reason): (u64, &str, &str, bool, &str) = match index {
            0 => (
                FCAE_TUN_ENGINE_TUN2SOCKS,
                "tun2socks",
                "tun2socks",
                cfg!(feature = "tun"),
                if cfg!(feature = "tun") { "" } else { "not compiled into this build" },
            ),
            1 => zeptun_info_fields(),
            2 => hev_info_fields(),
            _ => {
                return Err(CoreError::InvalidConfig(format!(
                    "TUN engine index {index} is out of range (fcae_tun_engine_count() = 3)"
                )))
            }
        };

        out.engine = engine;
        fill(&mut out.id, id);
        fill(&mut out.display_name, name);
        out.available = available;
        fill(&mut out.unavailable_reason, reason);
        Ok(())
    })
}

/// (engine, id, display, available, reason) for zeptun: linked vs stub.
#[cfg(feature = "zeptun")]
fn zeptun_info_fields() -> (u64, &'static str, &'static str, bool, &'static str) {
    if fcae_bridge_zeptun::platform_enabled() {
        (FCAE_TUN_ENGINE_ZEPTUN, "zeptun", "zeptun", true, "")
    } else {
        (
            FCAE_TUN_ENGINE_ZEPTUN,
            "zeptun",
            "zeptun",
            false,
            "zeptun engine not linked (stub build)",
        )
    }
}

#[cfg(not(feature = "zeptun"))]
fn zeptun_info_fields() -> (u64, &'static str, &'static str, bool, &'static str) {
    (
        FCAE_TUN_ENGINE_ZEPTUN,
        "zeptun",
        "zeptun",
        false,
        "not compiled into this build (feature `zeptun`)",
    )
}

/// (engine, id, display, available, reason) for Hev: linked vs stub.
#[cfg(feature = "hev")]
fn hev_info_fields() -> (u64, &'static str, &'static str, bool, &'static str) {
    if fcae_bridge_hev_socks5_tunnel::is_supported() {
        (FCAE_TUN_ENGINE_HEV, "hev-socks5-tunnel", "hev-socks5-tunnel", true, "")
    } else {
        // Windows runs the engine as a sidecar executable (its Windows backend
        // is MSYS-only, so it cannot be linked in), which makes "stub build"
        // the wrong explanation there: what is missing is the executable.
        let reason = if cfg!(windows) {
            "hev-socks5-tunnel.exe is missing from this installation (Windows runs the engine as a sidecar)"
        } else {
            "hev-socks5-tunnel not linked (stub build)"
        };
        (
            FCAE_TUN_ENGINE_HEV,
            "hev-socks5-tunnel",
            "hev-socks5-tunnel",
            false,
            reason,
        )
    }
}

#[cfg(not(feature = "hev"))]
fn hev_info_fields() -> (u64, &'static str, &'static str, bool, &'static str) {
    (
        FCAE_TUN_ENGINE_HEV,
        "hev-socks5-tunnel",
        "hev-socks5-tunnel",
        false,
        "hev-socks5-tunnel not compiled into this build",
    )
}

/// Psiphon egress regions discovered so far, as a comma-separated list of
/// ISO country codes ("GB,DE,US"), written into `out`.
///
/// Empty until the first successful Psiphon connect: the region list arrives
/// in a post-handshake notice, so a UI should offer "Auto" and then refresh
/// from this once connected. Returns the number of bytes that would be
/// written (excluding the NUL), so a caller can detect truncation.
///
/// Safe to call before `fcae_init` — returns an empty string.
///
/// # Safety
/// `out` must point to storage for at least `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn fcae_psiphon_regions(out: *mut c_char, cap: u32) -> u32 {
    #[cfg(feature = "psiphon")]
    let list = fcae_bridge_psiphon::regions().join(",");
    #[cfg(not(feature = "psiphon"))]
    let list = String::new();

    if !out.is_null() && cap > 0 {
        let buf = std::slice::from_raw_parts_mut(out, cap as usize);
        fill(buf, &list);
    }
    list.len() as u32
}

/// Shared text parser for desktop and Android buffer fields; no runtime needed.
#[no_mangle]
pub unsafe extern "C" fn fcae_parse_tcp_buffer_size(text: *const c_char) -> u32 {
    if text.is_null() { return 0; }
    CStr::from_ptr(text).to_str().ok()
        .and_then(|s| config::parse_tcp_buffer_size(s).ok()).unwrap_or(0)
}

/// Psiphon's currently bound SOCKS port, or zero when unavailable.
#[no_mangle]
pub extern "C" fn fcae_psiphon_socks_port() -> u16 {
    #[cfg(feature = "psiphon")]
    { fcae_bridge_psiphon::proxy_ports().0 }
    #[cfg(not(feature = "psiphon"))]
    { 0 }
}

/// Psiphon's currently bound HTTP port, or zero when unavailable.
#[no_mangle]
pub extern "C" fn fcae_psiphon_http_port() -> u16 {
    #[cfg(feature = "psiphon")]
    { fcae_bridge_psiphon::proxy_ports().1 }
    #[cfg(not(feature = "psiphon"))]
    { 0 }
}

/// Android AAR attach request JSON. Returns required bytes excluding NUL.
#[no_mangle]
pub unsafe extern "C" fn fcae_psiphon_attach_request(out: *mut std::ffi::c_char, cap: u32) -> u32 {
    #[cfg(feature = "psiphon")]
    let request = fcae_bridge_psiphon::host_request();
    #[cfg(not(feature = "psiphon"))]
    let request = String::new();
    if !out.is_null() && cap > 0 { fill(std::slice::from_raw_parts_mut(out, cap as usize), &request); }
    request.len() as u32
}

#[no_mangle]
pub extern "C" fn fcae_psiphon_attach_complete(id: u64, socks: u16, http: u16) {
    #[cfg(feature = "psiphon")]
    fcae_bridge_psiphon::host_complete(id, socks, http);
}

/// Install Android's `VpnService.protect(fd)` for Psiphon's own sockets.
///
/// Psiphon dials out while our TUN is up, so without this its connections are
/// captured by the tunnel and it tries to reach the internet through itself.
/// Desktop never needs it: the routing table already excludes our sockets.
/// Pass NULL to clear.
#[no_mangle]
pub extern "C" fn fcae_set_psiphon_protect(
    cb: Option<unsafe extern "C" fn(std::ffi::c_int) -> std::ffi::c_int>,
) -> FcaeStatus {
    guard("fcae_set_psiphon_protect", || {
        #[cfg(feature = "psiphon")]
        fcae_bridge_psiphon::set_protect_callback(cb);
        #[cfg(not(feature = "psiphon"))]
        let _ = cb;
        Ok(())
    })
}

/// Install the host's view of the underlying network for Psiphon.
///
/// `dns` returns a comma-delimited list of the resolvers in use on the
/// underlying network, `connectivity` returns 1 when a usable network exists,
/// and `network_id` returns an identity for the active network. The strings
/// must be `malloc`/`strdup` allocated: ownership passes to the library, which
/// releases them with `free`.
///
/// `dns` is mandatory on Android. Once the protect hook is installed upstream
/// stops using the platform resolver, so without this the tunnel has no DNS
/// servers at all and every dial fails. Pass NULL for any of them to clear.
#[no_mangle]
pub extern "C" fn fcae_set_psiphon_network_callbacks(
    dns: Option<unsafe extern "C" fn() -> *mut c_char>,
    connectivity: Option<unsafe extern "C" fn() -> std::ffi::c_int>,
    network_id: Option<unsafe extern "C" fn() -> *mut c_char>,
) -> FcaeStatus {
    guard("fcae_set_psiphon_network_callbacks", || {
        #[cfg(feature = "psiphon")]
        fcae_bridge_psiphon::set_network_callbacks(dns, connectivity, network_id);
        #[cfg(not(feature = "psiphon"))]
        let _ = (dns, connectivity, network_id);
        Ok(())
    })
}

/// How many backends [`fcae_backend_info`] can describe.
#[no_mangle]
pub extern "C" fn fcae_backend_count() -> u32 {
    fcae_runtime::registry::ALL.len() as u32
}

fn backend_id_str(id: FcaeBackend) -> &'static str {
    match id {
        FcaeBackend::Aether => "aether",
        FcaeBackend::Psiphon => "psiphon",
    }
}

fn backend_display_name(id: FcaeBackend) -> &'static str {
    match id {
        FcaeBackend::Aether => "Aether (WARP / MASQUE)",
        FcaeBackend::Psiphon => "Psiphon",
    }
}

/// Tear everything down and release resources. After this, `fcae_init` must
/// be called again before any other function.
#[no_mangle]
pub extern "C" fn fcae_shutdown() -> FcaeStatus {
    guard("fcae_shutdown", || {
        if let Some(rt) = RUNTIME.get() {
            let _ = rt.supervisor.stop();
            // stop() is instant for the UI; this call additionally means
            // "the process is about to die", so give the background worker
            // a bounded budget to finish its OS restore (routes/DNS) before
            // the exit. See Supervisor::wait_stopped for why the budget does
            // not need to cover the slow backend-join tail.
            rt.supervisor.wait_stopped(std::time::Duration::from_secs(5));
            rt.telemetry.set_state_hook(None);
            // Drop any Android descriptor from the finished session. It is a
            // small integer that the JVM will recycle onto an unrelated file,
            // so a latched value makes the next start dup a stranger's fd.
            #[cfg(any(feature = "tun", feature = "zeptun", feature = "hev"))]
            rt.engines.clear_android_fd();
        }
        logger::uninstall();
        Ok(())
    })
}

/// Build the telemetry state hook that forwards to the host's `state_cb`.
fn state_hook(opts: &FcaeInitOptions) -> Option<Box<dyn Fn(FcaeState) + Send + Sync>> {
    let cb = opts.state_cb?;
    let ud = opts.user_data as usize;
    Some(Box::new(move |state| {
        // SAFETY: user_data is opaque to us and the host guarantees it
        // outlives the library (documented in fcae.h).
        unsafe { cb(state, ud as *mut c_void) };
    }))
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

#[cfg(all(test, feature = "tun", feature = "zeptun", feature = "hev"))]
mod tun_provider_tests {
    use super::*;

    unsafe extern "C" fn provide_fd() -> std::ffi::c_int { 42 }
    unsafe extern "C" fn refuse_fd() -> std::ffi::c_int { -1 }

    #[test]
    fn provider_result_preserves_absence_success_and_failure() {
        let engines = TunEngines {
            t2s: Arc::new(fcae_bridge_tun2socks::Tun2SocksBridge::new()),
            zeptun: Arc::new(fcae_bridge_zeptun::ZeptunBridge::new()),
            hev: Arc::new(fcae_bridge_hev_socks5_tunnel::HevSocks5TunnelBridge::new()),
        };
        assert!(matches!(engines.establish_via_provider(), Ok(None)));
        engines.set_fd_provider(Some(provide_fd));
        assert!(matches!(engines.establish_via_provider(), Ok(Some(42))));
        assert_eq!(engines.t2s.android_fd(), Some(42));
        engines.clear_android_fd();
        engines.set_fd_provider(Some(refuse_fd));
        assert!(matches!(engines.establish_via_provider(), Err(CoreError::Internal(_))));
        assert_eq!(engines.t2s.android_fd(), None);
        engines.set_fd_provider(None);
    }
}
