//! # fcae-bridge-zeptun — in-process TUN bridge (Zig engine)
//!
//! Implements [`fcae_runtime::session::TunBridge`] by driving the **zeptun**
//! userspace network engine inside this process via its stable C ABI
//! (`core/zeptun/include/zeptun.h`), statically linked.
//!
//! This is a drop-in sibling of `fcae-bridge-tun2socks`: both are *TUN*
//! bridges that **consume** the local SOCKS5 endpoint a tunnel bridge
//! (aether / psiphon) **produces**, and expose it as a TUN device. The
//! supervisor layers this over whichever tunnel backend is selected.
//!
//! ## Why it is simpler than the tun2socks bridge
//!
//! | | tun2socks (Go) | zeptun (Zig) |
//! |---|---|---|
//! | interop | cgo c-archive + recovery shims | plain C ABI, no runtime |
//! | Android artifact | c-shared `.so` staged into jniLibs | static `.a` links into libfcae_ffi |
//! | device setup | bridge shell-outs for address/routes/DNS | engine does it (`configure`/`auto_route`) |
//! | protect callback | not needed (loopback-only upstream) | same: FCAE's exit is always `127.0.0.1:port` |
//! | FD device | Go option plumbing | `ZeptunConfig.device_kind = FD` |
//!
//! FCAE only ever points a TUN bridge at a loopback SOCKS listener, so the
//! `zeptun_protect_cb` hook is intentionally not wired here: upstream sockets
//! the engine dials are loopback, never routed into the TUN. Direct/passthrough
//! handlers would need it and are out of scope for this bridge.
//!
//! ## fd ownership
//!
//! On Android the VpnService descriptor is created and owned by the JVM. The
//! bridge **dups** it and hands the dup to zeptun (`device_kind=FD`, created
//! with `zeptun_create`). Zeptun borrows FD devices; the bridge closes its
//! duplicate after `zeptun_destroy`. The original stays with the JVM.
//!
//! ## Build requirements
//!
//! * Zig built artifacts produced OUTSIDE the cargo graph (see `build.rs`):
//!   * desktop → `make -C core/zeptun` (lands in `core/zeptun/zig-out/lib/`)
//!   * android → per-ABI API-24 builds with `-Dandroid-libc` (see CI)
//!     (lands in `core/zeptun/zig-out/android/prebuilt/<abi>/`)
//! * or `FCAE_ZEPTUN_LIBDIR=<dir>` pointing at a directory with `libzeptun.a`.
//!
//! Building without it: `cargo build --features fcae-bridge-zeptun/stub`
//! compiles a stub where TUN reports "unavailable". Do not ship a stub build.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use fcae_runtime::config::{SessionConfig, T2S_LOG_DEBUG, T2S_LOG_ERROR, T2S_LOG_INFO, T2S_LOG_WARN, T2S_LOG_SILENT};
use fcae_runtime::error::{CoreError, Result};
use fcae_runtime::session::TunBridge;
use parking_lot::Mutex;

mod socks5p;
mod socks5t;

// Public for the FFI layer's fcae_is_privileged(), which ORs the privilege
// probe across every TUN bridge linked into the build (see tun2socks).
pub mod platform;

#[cfg(all(windows, wintun_staged))]
static WINTUN_DLL: &[u8] = include_bytes!(env!("FCAE_WINTUN_DLL"));

#[cfg(all(windows, wintun_staged))]
fn wintun_bytes() -> Option<&'static [u8]> {
    Some(WINTUN_DLL)
}

#[cfg(all(windows, not(wintun_staged)))]
fn wintun_bytes() -> Option<&'static [u8]> {
    None
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

const ZEPTUN_OK: c_int = 0;

const ZEPTUN_PRESET_DESKTOP: u32 = 0;
const ZEPTUN_PRESET_MOBILE: u32 = 1;

const ZEPTUN_DEVICE_TUN: u32 = 0;
const ZEPTUN_DEVICE_FD: u32 = 1;

const ZEPTUN_HANDLER_SOCKS5: u32 = 1;

const ZEPTUN_SOCKS5_PIPELINE_AUTO: u8 = 0;

const ZEPTUN_LOG_ERROR: u32 = 0;
const ZEPTUN_LOG_WARN: u32 = 1;
const ZEPTUN_LOG_INFO: u32 = 2;
const ZEPTUN_LOG_DEBUG: u32 = 3;

/// Mirrors `ZeptunConfig` in `core/zeptun/include/zeptun.h`, field for field.
/// `struct_size` lets the engine reject ABI drift.
#[repr(C)]
pub struct ZeptunConfig {
    struct_size: u32,
    preset: u32,
    device_kind: u32,
    tun_fd: i32,
    tun_name: [c_char; 16],
    mtu: u32,
    queues: u16,
    offload: u8,
    configure: u8,
    address4: [c_char; 64],
    address6: [c_char; 64],
    stack_mode: u32,
    handler_kind: u32,
    socks5_server: [c_char; 64],
    socks5_username: [c_char; 256],
    socks5_password: [c_char; 256],
    socks5_udp: u8,
    socks5_pipeline: u8,
    auto_route: u8,
    passthrough_gso: u8,
    fwmark: u32,
    route_table: u32,
    rule_priority: u32,
    io_backend: u32,
    max_tcp_sessions: u32,
    max_udp_sessions: u32,
    tcp_rx_window: u32,
    tcp_tx_buffer: u32,
    udp_idle_timeout_ms: u32,
    tcp_idle_timeout_ms: u32,
    pad0: u32,
    memory_budget_bytes: u64,
    log_level: u32,
    workers: u32,
    reserved: [u32; 8],
}

/// Mirrors `ZeptunStats` — read-only snapshot, cheap enough to poll from a UI.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
pub struct ZeptunStats {
    pub version: u32,
    pub workers: u32,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub parse_errors: u64,
    pub pool_exhausted: u64,
    pub gso_rx_packets: u64,
    pub gso_tx_packets: u64,
    pub gso_segments: u64,
    pub gro_merged: u64,
    pub tcp_active: u64,
    pub tcp_opened: u64,
    pub tcp_closed: u64,
    pub tcp_reset: u64,
    pub tcp_retransmits: u64,
    pub tcp_connect_failed: u64,
    pub tcp_evicted: u64,
    pub udp_active: u64,
    pub udp_opened: u64,
    pub udp_closed: u64,
    pub udp_evicted: u64,
    pub udp_dropped: u64,
    pub icmp_echo: u64,
    pub icmp_time_exceeded: u64,
    pub nat_active: u64,
    pub handoffs: u64,
    pub upstream_rx_bytes: u64,
    pub upstream_tx_bytes: u64,
    pub fragments_reassembled: u64,
    pub timeouts: u64,
    pub socks5_pool_hits: u64,
    pub socks5_pool_retries: u64,
    pub dns_fake_answers: u64,
    pub dns_hijacked: u64,
    pub tcp_migrated: u64,
    pub udp_migrated: u64,
}

#[cfg(zeptun_linked)]
extern "C" {
    fn zeptun_version_string() -> *const c_char;
    fn zeptun_strerror(code: c_int) -> *const c_char;
    fn zeptun_config_init(config: *mut ZeptunConfig, preset: u32) -> c_int;
    fn zeptun_create(config: *const ZeptunConfig, out: *mut *mut c_void) -> c_int;
    fn zeptun_destroy(tun: *mut c_void);
    fn zeptun_set_log_callback(
        cb: Option<unsafe extern "C" fn(*mut c_void, c_int, *const c_char, usize)>,
        ctx: *mut c_void,
        level: c_int,
    ) -> c_int;
    fn zeptun_start(tun: *mut c_void) -> c_int;
    fn zeptun_stop(tun: *mut c_void) -> c_int;
    fn zeptun_stats(tun: *mut c_void, out: *mut ZeptunStats) -> c_int;
    fn zeptun_interface_name(tun: *mut c_void, buffer: *mut c_char, len: usize) -> c_int;
    #[cfg(windows)]
    fn zeptun_set_adapter_guid(tun: *mut c_void, guid: *const c_char) -> c_int;
}

/// Same entry points, used when the engine isn't linked (`stub` feature) so
/// the crate still type-checks everywhere.
#[cfg(not(zeptun_linked))]
mod stub {
    use super::*;
    pub unsafe fn zeptun_version_string() -> *const c_char {
        b"zeptun:unavailable\0".as_ptr().cast()
    }
    pub unsafe fn zeptun_strerror(_code: c_int) -> *const c_char {
        b"zeptun bridge stub\0".as_ptr().cast()
    }
    pub unsafe fn zeptun_config_init(config: *mut ZeptunConfig, _preset: u32) -> c_int {
        if !config.is_null() {
            (*config).struct_size = std::mem::size_of::<ZeptunConfig>() as u32;
        }
        -100
    }
    pub unsafe fn zeptun_create(_c: *const ZeptunConfig, _o: *mut *mut c_void) -> c_int {
        -100
    }
    pub unsafe fn zeptun_destroy(_t: *mut c_void) {}
    pub unsafe fn zeptun_set_log_callback(
        _cb: Option<unsafe extern "C" fn(*mut c_void, c_int, *const c_char, usize)>,
        _ctx: *mut c_void,
        _level: c_int,
    ) -> c_int {
        -100
    }
    pub unsafe fn zeptun_start(_t: *mut c_void) -> c_int {
        -100
    }
    pub unsafe fn zeptun_stop(_t: *mut c_void) -> c_int {
        -100
    }
    pub unsafe fn zeptun_stats(_t: *mut c_void, _o: *mut ZeptunStats) -> c_int {
        -100
    }
    pub unsafe fn zeptun_interface_name(_t: *mut c_void, _b: *mut c_char, _l: usize) -> c_int {
        -100
    }
    #[cfg(windows)]
    pub unsafe fn zeptun_set_adapter_guid(_t: *mut c_void, _g: *const c_char) -> c_int {
        -100
    }
}

#[cfg(not(zeptun_linked))]
#[allow(unused_imports)]
use stub::{
    zeptun_config_init, zeptun_create, zeptun_destroy, zeptun_set_log_callback, zeptun_start,
    zeptun_stats, zeptun_stop, zeptun_strerror, zeptun_version_string, zeptun_interface_name,
};
#[cfg(all(not(zeptun_linked), windows))]
use stub::zeptun_set_adapter_guid;

/// True when the engine archive was linked into this binary.
pub fn is_supported() -> bool {
    cfg!(zeptun_linked)
}

#[cfg(windows)]
const WINTUN_ADAPTER_GUID: &str = "24198F4C-7895-434C-AD65-9E29A92DDC61";

pub fn platform_enabled() -> bool {
    is_supported()
}

/// 1.3.5.4 PATCH: zeptun creates its Wintun adapter in-engine, which is the
/// same admin-gated operation as tun2socks. Re-export the platform check so
/// `fcae_is_privileged()` covers both engines and the C++ UAC prompt fires
/// for zeptun selections too.
pub fn is_privileged() -> bool {
    platform::is_privileged()
}

/// Engine version string zeptun was built from; a placeholder in stub builds.
pub fn version() -> String {
    unsafe { CStr::from_ptr(zeptun_version_string()) }
        .to_string_lossy()
        .into_owned()
}

fn zeptun_err(context: &str, code: c_int) -> CoreError {
    let msg = unsafe { CStr::from_ptr(zeptun_strerror(code)) }.to_string_lossy();
    CoreError::Internal(format!("[zeptun] {context} failed ({code}): {msg}"))
}

fn zeptun_log_level(t2s_level: u8) -> u32 {
    match t2s_level {
        // zeptun's quietest tier is ERROR: it has no OFF, since ERROR covers
        // only hard failures — the same contract tun2socks' "silent" keeps.
        T2S_LOG_SILENT | T2S_LOG_ERROR => ZEPTUN_LOG_ERROR,
        T2S_LOG_WARN => ZEPTUN_LOG_WARN,
        T2S_LOG_INFO => ZEPTUN_LOG_INFO,
        T2S_LOG_DEBUG => ZEPTUN_LOG_DEBUG,
        _ => ZEPTUN_LOG_ERROR,
    }
}

unsafe extern "C" fn log_trampoline(_ctx: *mut c_void, level: c_int, message: *const c_char, len: usize) {
    if message.is_null() {
        return;
    }
    let text = String::from_utf8_lossy(std::slice::from_raw_parts(message.cast(), len));
    let text = text.trim_end();
    match level as u32 {
        ZEPTUN_LOG_ERROR => log::error!("{text}"),
        ZEPTUN_LOG_WARN => log::warn!("{text}"),
        ZEPTUN_LOG_INFO => log::info!("{text}"),
        _ => log::debug!("{text}"), // DEBUG and TRACE
    }
}

fn adapter_name(cfg: &SessionConfig) -> &str {
    if cfg.tun.name.is_empty() { "FCAE_VPN" } else { &cfg.tun.name }
}

fn set_c_str<const N: usize>(field: &mut [c_char; N], value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() >= N {
        return Err(CoreError::Internal(format!(
            "value too long for zeptun config field ({bytes_len} >= {N})",
            bytes_len = bytes.len()
        )));
    }
    let c = CString::new(value).map_err(|_| CoreError::Internal("value contains a NUL".into()))?;
    let src = unsafe { std::slice::from_raw_parts(c.as_ptr(), bytes.len() + 1) };
    field[..bytes.len() + 1].copy_from_slice(src);
    Ok(())
}

/// Owning engine handle. zeptun is thread-safe; lifecycle calls are
/// serialised by the bridge's `active` lock.
struct Handle {
    engine: NonNull<c_void>,
    fd: Option<i32>,
    _psiphon_adapter: Option<socks5p::Adapter>,
    _tor_adapter: Option<socks5t::Adapter>,
    dns: Option<fcae_runtime::tun_dns::DnsGuard>,
    #[cfg(windows)]
    network: Option<fcae_runtime::windows_tun::TunGuard>,
}
unsafe impl Send for Handle {}

impl Handle {
    fn as_ptr(&self) -> *mut c_void {
        self.engine.as_ptr()
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // 'stop' before 'destroy' per the C API contract; both are
        // idempotent in zeptun, and stop here only runs if stop() raced and
        // abandoned the handle.
        #[cfg(windows)]
        drop(self.network.take());
        drop(self.dns.take());
        unsafe {
            zeptun_stop(self.engine.as_ptr());
            zeptun_destroy(self.engine.as_ptr());
            if let Some(fd) = self.fd.take() {
                libc::close(fd);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bridge
// ---------------------------------------------------------------------------

pub struct ZeptunBridge {
    active: Mutex<Option<Handle>>,
    running: AtomicBool,
    /// Set by `stop`/`abort` so an in-flight `start` aborts instead of
    /// bringing the interface up after the user already disconnected.
    closing: AtomicBool,
    /// Android VpnService descriptor set out-of-band via the FFI, in case the
    /// session config didn't carry one.
    external_fd: AtomicI32,
}

impl Default for ZeptunBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl ZeptunBridge {
    pub const fn new() -> Self {
        Self {
            active: Mutex::new(None),
            running: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            external_fd: AtomicI32::new(-1),
        }
    }

    /// Out-of-band TUN fd injection (Android). The host keeps ownership of
    /// the original; the bridge dups what it needs.
    pub fn set_external_fd(&self, fd: i32) {
        self.external_fd.store(fd, Ordering::SeqCst);
    }

    /// Re-point the engine's (single, process-global) log hook at our
    /// trampoline with the session's level. Called on every start: the
    /// level is a per-session setting, so it must not latch from the first.
    fn install_log_hook(&self, level: u32) {
        unsafe {
            zeptun_set_log_callback(Some(log_trampoline), std::ptr::null_mut(), level as c_int);
        }
    }

    /// Live engine counters (see `ZeptunStats`); `None` when not running.
    pub fn stats(&self) -> Option<ZeptunStats> {
        let active = self.active.lock();
        let handle = active.as_ref()?;
        let mut out = ZeptunStats::default();
        let rc = unsafe { zeptun_stats(handle.as_ptr(), &mut out) };
        (rc == ZEPTUN_OK).then_some(out)
    }
}

impl TunBridge for ZeptunBridge {
    fn start(&self, cfg: &SessionConfig, endpoints: &fcae_runtime::backend::Endpoints) -> Result<()> {
        #[cfg(windows)]
        fcae_runtime::windows_tun::validate_backend(cfg, endpoints.peer_ip.as_deref())?;
        if !platform_enabled() {
            return Err(CoreError::Internal(
                "this build was compiled without the zeptun bridge (feature `stub`); \
                 TUN mode is unavailable"
                    .into(),
            ));
        }

        self.closing.store(false, Ordering::SeqCst);
        {
            let active = self.active.lock();
            if active.is_some() {
                log::warn!("[tun] start called while a device is already up; ignoring");
                return Ok(());
            }
        }
        if self.closing.load(Ordering::SeqCst) {
            return Err(CoreError::Internal("TUN start cancelled (session is stopping)".into()));
        }

        let socks = endpoints.socks.ok_or_else(|| {
            CoreError::Internal("TUN requested but the backend exposed no SOCKS endpoint".into())
        })?;

        // The final endpoint marks both standalone and chained Psiphon exits.
        // Tor exits have no UDP ASSOCIATE: socks5t turns UDP/53 into SOCKS
        // CONNECT dest:53 with length-prefixed DNS-over-TCP. Zeptun still
        // ASSOCIATEs at the facade (socks5_udp) so it never talks UDP to Tor.
        let psiphon_adapter = if endpoints.psiphon_dns {
            Some(socks5p::Adapter::start(socks).map_err(|e| {
                CoreError::Internal(format!("zeptun socks5p adapter: {e}"))
            })?)
        } else {
            None
        };
        let tor_adapter = if psiphon_adapter.is_none() && cfg.tor.is_exit() {
            Some(socks5t::Adapter::start(socks).map_err(|e| {
                CoreError::Internal(format!("zeptun socks5t adapter: {e}"))
            })?)
        } else {
            None
        };
        let socks = psiphon_adapter.as_ref().map(|adapter| adapter.endpoint())
            .or_else(|| tor_adapter.as_ref().map(|adapter| adapter.endpoint()))
            .unwrap_or(socks);
        if psiphon_adapter.is_some() {
            log::info!("[zeptun] socks5p: native Psiphon DNS gateway, no direct DNS fallback");
        } else if tor_adapter.is_some() {
            log::info!("[zeptun] socks5t: DNS-over-TCP through Tor SOCKS");
        }

        // Windows needs wintun.dll discoverable before the device is created:
        // zeptun loads it from the application directory or System32.
        #[cfg(windows)]
        platform::ensure_wintun(wintun_bytes())?;

        // config_init must run first: it zeroes the struct, stamps
        // struct_size for the ABI check, and fills preset-secure defaults.
        let preset = if platform::is_android() {
            ZEPTUN_PRESET_MOBILE
        } else {
            ZEPTUN_PRESET_DESKTOP
        };
        let mut config = unsafe {
            let mut c = std::mem::zeroed::<ZeptunConfig>();
            let rc = zeptun_config_init(&mut c, preset);
            if rc != ZEPTUN_OK {
                return Err(zeptun_err("config_init", rc));
            }
            c
        };

        let fd = cfg.tun.fd.or_else(|| {
            let f = self.external_fd.load(Ordering::SeqCst);
            (f >= 0).then_some(f)
        });

        if platform::is_android() && fd.is_none() {
            return Err(CoreError::Internal(
                "zeptun on Android requires a TUN descriptor from VpnService".into(),
            ));
        }

        config.address6.fill(0);
        match fd {
            // Android: VpnService pre-created and pre-configured the device;
            // the engine only owns the data plane.
            Some(_) => {
                config.device_kind = ZEPTUN_DEVICE_FD;
                // VpnService already owns addressing/routing/DNS for this
                // interface; never let the engine re-configure it.
                config.configure = 0;
                config.auto_route = 0;
                set_c_str(&mut config.tun_name, adapter_name(cfg))?;
                config.mtu = cfg.tun.mtu;
                set_c_str(&mut config.address4, &cfg.tun.ipv4)?;
                if let Some(v6) = &cfg.tun.ipv6 {
                    set_c_str(&mut config.address6, v6)?;
                }
            }
            // Desktop: zeptun creates the device AND configures
            // address/routes itself — no platform shell-out, unlike tun2socks.
            None => {
                config.device_kind = ZEPTUN_DEVICE_TUN;
                set_c_str(&mut config.tun_name, adapter_name(cfg))?;
                config.mtu = cfg.tun.mtu;
                config.configure = u8::from(!cfg!(windows));
                config.auto_route = u8::from(!cfg!(windows));
                set_c_str(&mut config.address4, &cfg.tun.ipv4)?;
                if let Some(v6) = &cfg.tun.ipv6 {
                    set_c_str(&mut config.address6, v6)?;
                }
            }
        }

        config.handler_kind = ZEPTUN_HANDLER_SOCKS5;
        set_c_str(&mut config.socks5_server, &socks.to_string())?;
        // UDP ASSOCIATE terminates at our adapter, never at Psiphon/Tor.
        config.socks5_udp = u8::from(endpoints.udp || psiphon_adapter.is_some() || tor_adapter.is_some());
        config.socks5_pipeline = ZEPTUN_SOCKS5_PIPELINE_AUTO;
        config.log_level = zeptun_log_level(cfg.tun.t2s_log_level);
        self.install_log_hook(config.log_level);

        // Keep the duplicated FD alive until the engine is destroyed.
        let mut active = self.active.lock();
        if self.closing.load(Ordering::SeqCst) {
            return Err(CoreError::Internal(
                "TUN start cancelled before engine creation".into(),
            ));
        }

        if let Some(fd) = fd {
            let dup = unsafe { libc::dup(fd) };
            if dup < 0 {
                return Err(CoreError::Internal(format!(
                    "dup(tun fd {fd}) failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            config.tun_fd = dup;
        }

        let mut raw: *mut c_void = std::ptr::null_mut();
        let rc = unsafe { zeptun_create(&config, &mut raw) };
        if rc != ZEPTUN_OK {
            platform::close_dup(fd, &config);
            return Err(zeptun_err("create", rc));
        }
        let handle = NonNull::new(raw).ok_or_else(|| {
            platform::close_dup(fd, &config);
            CoreError::Internal("zeptun_create returned NULL".into())
        })?;
        let mut handle = Handle {
            engine: handle,
            fd: fd.map(|_| config.tun_fd),
            _psiphon_adapter: psiphon_adapter,
            _tor_adapter: tor_adapter,
            dns: None,
            #[cfg(windows)]
            network: None,
        };

        #[cfg(windows)]
        {
            let guid = CString::new(WINTUN_ADAPTER_GUID).unwrap();
            let rc = unsafe { zeptun_set_adapter_guid(handle.as_ptr(), guid.as_ptr()) };
            if rc != ZEPTUN_OK {
                return Err(zeptun_err("set_adapter_guid", rc));
            }
        }

        let rc = unsafe { zeptun_start(handle.as_ptr()) };
        if rc != ZEPTUN_OK {
            return Err(zeptun_err("start", rc)); // Handle drops: stop+destroy.
        }

        if fd.is_none() && !platform::is_android() {
            let mut name = [0 as c_char; 64];
            let rc = unsafe { zeptun_interface_name(handle.as_ptr(), name.as_mut_ptr(), name.len()) };
            if rc < 0 { return Err(zeptun_err("interface_name", rc)); }
            let name = unsafe { CStr::from_ptr(name.as_ptr()) }.to_str()
                .map_err(|_| CoreError::Internal("zeptun returned an invalid interface name".into()))?;
            #[cfg(windows)]
            {
                let mut network_cfg = cfg.clone();
                network_cfg.tun.name = name.to_owned();
                handle.network = Some(fcae_runtime::windows_tun::TunGuard::configure(&network_cfg, endpoints.peer_ip.as_deref())?);
            }
            #[cfg(not(windows))]
            { handle.dns = Some(fcae_runtime::tun_dns::DnsGuard::apply(cfg, name)?); }
        }

        self.running.store(true, Ordering::SeqCst);
        *active = Some(handle);
        log::info!(
            "[tun] up ({}, socks {}, mtu {})",
            version(),
            socks,
            config.mtu
        );
        Ok(())
    }

    fn stop(&self, _timeout: std::time::Duration) {
        // C API has no timeout semantics; the engine's stop is prompt by
        // design (its own worker pool joins under its control).
        self.closing.store(true, Ordering::SeqCst);
        let handle = self.active.lock().take();
        drop(handle);
        if self.running.swap(false, Ordering::SeqCst) {
            log::info!("[tun] down (zeptun)");
        }
        self.external_fd.store(-1, Ordering::SeqCst);
    }

    fn check_health(&self, _cfg: &SessionConfig) -> Result<()> {
        if !self.is_running() {
            return Err(CoreError::Internal("TUN engine stopped unexpectedly".into()));
        }
        #[cfg(windows)]
        { self.active.lock().as_ref().and_then(|a| a.network.as_ref()).map(|g| g.check_health()).transpose()?; }
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn preauthorised_fd(&self) -> Option<i32> {
        let fd = self.external_fd.load(Ordering::SeqCst);
        (fd >= 0).then_some(fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_is_unsupported() {
        if cfg!(zeptun_linked) {
            assert!(is_supported());
        } else {
            assert!(!is_supported());
        }
    }

    #[test]
    fn config_layout_matches_rc() {
        // struct_size is the ABI guarantee; pins the repr(C) layout here so
        // an accidental field reorder fails loudly at build time.
        let mut c: ZeptunConfig = unsafe { std::mem::zeroed() };
        c.struct_size = std::mem::size_of::<ZeptunConfig>() as u32;
        assert_eq!(c.struct_size, 848);
        assert_eq!(std::mem::offset_of!(ZeptunConfig, memory_budget_bytes), 800);
        assert_eq!(std::mem::offset_of!(ZeptunConfig, reserved), 816);
        assert_eq!(std::mem::size_of::<ZeptunStats>(), 312);
    }
}
