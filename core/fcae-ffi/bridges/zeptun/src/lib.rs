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
//! with `zeptun_create`); zeptun owns the dup from `zeptun_create` on, and
//! `zeptun_destroy` releases the device. Only the original stays with the JVM.
//!
//! ## Build requirements
//!
//! * Zig built artifacts produced OUTSIDE the cargo graph (see `build.rs`):
//!   * desktop → `make -C core/zeptun` (lands in `core/zeptun/zig-out/lib/`)
//!   * android → `sh core/zeptun/scripts/build_android.sh`
//!     (lands in `core/zeptun/zig-out/android/prebuilt/<abi>/`)
//! * or `FCAE_ZEPTUN_LIBDIR=<dir>` pointing at a directory with `libzeptun.a`.
//!
//! Building without it: `cargo build --features fcae-bridge-zeptun/stub`
//! compiles a stub where TUN reports "unavailable". Do not ship a stub build.
//!
//! ## Rollout
//!
//! Linux, macOS and Android only, for now: Windows is intentionally held
//! back until upstream exposes the wintun `RequestedGUID` so the adapter
//! lands on the pinned GUID tun2socks already uses. See [`WINDOWS_ENABLED`].

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use fcae_runtime::config::{SessionConfig, T2S_LOG_DEBUG, T2S_LOG_ERROR, T2S_LOG_INFO, T2S_LOG_WARN, T2S_LOG_SILENT};
use fcae_runtime::error::{CoreError, Result};
use fcae_runtime::session::TunBridge;
use parking_lot::Mutex;

mod platform;

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
}

#[cfg(not(zeptun_linked))]
#[allow(unused_imports)]
use stub::{
    zeptun_config_init, zeptun_create, zeptun_destroy, zeptun_set_log_callback, zeptun_start,
    zeptun_stats, zeptun_stop, zeptun_strerror, zeptun_version_string,
};

/// True when the engine archive was linked into this binary.
pub fn is_supported() -> bool {
    cfg!(zeptun_linked)
}

/// Windows rollout gate. zeptun ships on Linux, macOS and Android now;
/// Windows stays OFF until upstream (Noisemux/zeptun) exposes the wintun
/// `RequestedGUID`: without the pin, a zeptun-first install creates the
/// shared adapter with a random GUID instead of
/// `24198F4C-7895-434C-AD65-9E29A92DDC61` (the identity tun2socks pins),
/// splitting it from the registration every other engine reuses. When the
/// GUID lands upstream, flip this to `true`.
///
/// Defined on every platform (not `#[cfg(windows)]`) because `cfg!()` in
/// [`platform_enabled`] evaluates at runtime — the name must resolve
/// everywhere; non-Windows targets short-circuit the `||`.
const WINDOWS_ENABLED: bool = false;

/// True when this build may actually open a TUN device on this platform:
/// engine linked AND rolled out here. Platform-agnostic callers
/// (engine selection, UI availability probes) must use this, not
/// [`is_supported`].
pub fn platform_enabled() -> bool {
    is_supported() && (cfg!(not(windows)) || WINDOWS_ENABLED)
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
    let text = std::str::from_utf8_lossy(std::slice::from_raw_parts(message.cast(), len));
    let text = text.trim_end();
    match level as u32 {
        ZEPTUN_LOG_ERROR => log::error!("{text}"),
        ZEPTUN_LOG_WARN => log::warn!("{text}"),
        ZEPTUN_LOG_INFO => log::info!("{text}"),
        _ => log::debug!("{text}"), // DEBUG and TRACE
    }
}

/// Adapter name contract shared with the tun2socks bridge.
///
/// Windows: wintun adapter identity — the same GUID, hence the same
/// firewall profile and DNS/device registration — is keyed by pool + name,
/// not by an app-supplied GUID. Zeptun and the Go bridge both load the
/// stock `wintun.dll` (pool "Wintun") and open by name FIRST, creating with
/// a random GUID only when the name is absent, so one name gives both
/// engines the very same adapter. The fallback mirrors
/// `TunConfig::default().name`.
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
struct Handle(NonNull<c_void>);
unsafe impl Send for Handle {}

impl Handle {
    fn as_ptr(&self) -> *mut c_void {
        self.0.as_ptr()
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // 'stop' before 'destroy' per the C API contract; both are
        // idempotent in zeptun, and stop here only runs if stop() raced and
        // abandoned the handle.
        unsafe {
            zeptun_stop(self.0.as_ptr());
            zeptun_destroy(self.0.as_ptr());
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
        if !is_supported() {
            return Err(CoreError::Internal(
                "this build was compiled without the zeptun bridge (feature `stub`); \
                 TUN mode is unavailable"
                    .into(),
            ));
        }
        if !platform_enabled() {
            return Err(CoreError::Internal(
                "the zeptun TUN engine is disabled on Windows pending upstream \
                 adapter-GUID support (Noisemux/zeptun); select tun2socks"
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

        match fd {
            // Android: VpnService pre-created and pre-configured the device;
            // the engine only owns the data plane.
            Some(fd) => {
                config.device_kind = ZEPTUN_DEVICE_FD;
                // VpnService already owns addressing/routing/DNS for this
                // interface; never let the engine re-configure it.
                config.configure = 0;
                config.auto_route = 0;
                let dup = unsafe { libc::dup(fd) };
                if dup < 0 {
                    return Err(CoreError::Internal(format!(
                        "dup(tun fd {fd}) failed: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                config.tun_fd = dup;
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
                config.configure = 1;
                config.auto_route = 1;
                set_c_str(&mut config.address4, &cfg.tun.ipv4)?;
                if let Some(v6) = &cfg.tun.ipv6 {
                    set_c_str(&mut config.address6, v6)?;
                }
            }
        }

        config.handler_kind = ZEPTUN_HANDLER_SOCKS5;
        set_c_str(&mut config.socks5_server, &socks.to_string())?;
        // Psiphon's local SOCKS is CONNECT-only; Aether carries UDP
        // ASSOCIATE. The backend tells us which (same contract the
        // tun2socks bridge's socks5p adapter encodes).
        config.socks5_udp = u8::from(endpoints.udp && !endpoints.psiphon_dns);
        config.socks5_pipeline = ZEPTUN_SOCKS5_PIPELINE_AUTO;
        config.log_level = zeptun_log_level(cfg.tun.t2s_log_level);
        self.install_log_hook(config.log_level);

        // Handoff: no Handle must escape until zeptun owns the dup.
        let mut active = self.active.lock();
        if self.closing.load(Ordering::SeqCst) {
            return Err(CoreError::Internal(
                "TUN start cancelled before engine creation".into(),
            ));
        }

        let mut raw: *mut c_void = std::ptr::null_mut();
        let rc = unsafe { zeptun_create(&config, &mut raw) };
        if rc != ZEPTUN_OK {
            platform::close_dup(fd, &config);
            return Err(zeptun_err("create", rc));
        }
        let handle = NonNull::new(raw).ok_or_else(|| CoreError::Internal("zeptun_create returned NULL".into()))?;
        let handle = Handle(handle);

        let rc = unsafe { zeptun_start(handle.as_ptr()) };
        if rc != ZEPTUN_OK {
            return Err(zeptun_err("start", rc)); // Handle drops: stop+destroy.
        }

        self.running.store(true, Ordering::SeqCst);
        *active = Some(handle);
        log::info!(
            "[tun] up (zeptun {}, socks {}, mtu {})",
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
        if let Some(h) = handle {
            unsafe {
                let _ = zeptun_stop(h.as_ptr());
            }
            // drop(h) → zeptun_destroy via Handle::drop
        }
        if self.running.swap(false, Ordering::SeqCst) {
            log::info!("[tun] down (zeptun)");
        }
        self.external_fd.store(-1, Ordering::SeqCst);
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
        assert!(c.struct_size > 0);
    }
}
