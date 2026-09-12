//! # fcae-bridge-tun2socks — in-process TUN bridge
//!
//! Implements [`fcae_runtime::session::TunBridge`] by driving the tun2socks
//! gVisor stack **inside this process** via a Go c-archive.
//!
//! This is the *TUN* bridge: it **consumes** a SOCKS endpoint and exposes it
//! as a TUN device. Contrast `fcae-bridge-aether` / `fcae-bridge-psiphon`,
//! which implement `Backend` and **produce** such an endpoint. The supervisor
//! layers this over whichever tunnel bridge is selected, so a new tunnel gets
//! TUN mode for free.
//!
//! ## What this replaces
//!
//! The previous design spawned `tun2socks(.exe)` as a child process. That
//! required, on every platform: extracting a multi-MB binary to a writable
//! directory, making it executable, clearing `FD_CLOEXEC` so the Android
//! VpnService fd survived `execve`, passing `fd://N`, polling the child, and
//! killing it with `taskkill /F /T` or `SIGKILL` on shutdown — plus an RAII
//! guard because a dropped future would otherwise leak the process.
//!
//! All of that is gone:
//!
//! | | subprocess (old) | in-process (now) |
//! |---|---|---|
//! | delivery | extracted binary / jniLibs `.so` | linked `.a` |
//! | Android APK | duplicate MB-sized binary | none |
//! | VpnService fd | inherited across `execve` | dup'd, handed to Go directly |
//! | shutdown | kill + hope | `t2s_stop()` + join |
//! | failure mode | orphan process | Rust error |
//! | AV false positives | likely | none |
//!
//! ## fd ownership
//!
//! On Android the descriptor belongs to `ParcelFileDescriptor`. The old code
//! called `libc::close()` on it from native code and triggered a Bionic
//! double-close abort on disconnect. Here the bridge **dups** the fd, gives
//! the dup to Go, and closes only the dup — the original stays owned by the
//! JVM.
//!
//! ## Exported C ABI
//!
//! `go/bridge.go` is a cgo shim over the upstream `engine` package, built with
//! `go build -buildmode=c-archive` and linked straight into `libfcae_ffi.a`.
//! Its module (`go/go.mod`) is separate from the submodule and uses a
//! `replace` directive pointing at `core/tun2socks`, so the upstream checkout
//! stays pristine — no local patches to rebase when it is bumped.
//!
//! | symbol | meaning |
//! |---|---|
//! | `t2s_set_log_callback(fn)` | route tun2socks logs into the host logger |
//! | `t2s_start(device, proxy, mtu, loglevel)` | `0` ok, `-1` already running, `-2` bad config, `-3` engine failed |
//! | `t2s_stop()` | idempotent teardown |
//! | `t2s_is_running()` | `1` / `0` |
//! | `t2s_version()` | static string, do not free |
//!
//! All exports serialise on one mutex, so the Rust side needs no extra
//! locking. `-100` is the Rust-side stub sentinel (see below).
//!
//! Upstream's `engine.Start` calls `log.Fatalf` on failure, which would kill
//! the host process — tolerable for a standalone binary, unacceptable in a
//! GUI. `validateKey` pre-checks everything `engine.Start` would reject
//! (empty/invalid device, proxy URL, scheme, MTU range) and refuses the call
//! itself; the remaining paths are wrapped in `recover()`.
//!
//! ## Build requirements
//!
//! * Go 1.22+ (`go` on PATH, or `GO_BIN`)
//! * A C toolchain for the target, because c-archive requires cgo:
//!   * Android → `ANDROID_NDK_HOME` (NDK clang is selected automatically)
//!   * Windows cross-build → `x86_64-w64-mingw32-gcc`
//!   * otherwise → `cc` (override with `CC` or `CGO_CC`)
//!
//! Building without Go: `cargo build --features fcae-bridge-tun2socks/stub` compiles
//! a stub where TUN reports "unavailable" and everything else works. Do not
//! ship a stub build.
//!
//! ## wintun
//!
//! Windows still needs `wintun.dll` — that is the TUN *driver*, not a process.
//! `fcae-build::wintun` downloads and verifies it at build time (with a size
//! sanity check, so a captive-portal HTML page can no longer be embedded as if
//! it were a DLL), and [`platform::ensure_wintun`] places it where the
//! in-process loader will find it.

use std::ffi::{c_char, c_int, CStr, CString};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

use fcae_runtime::backend::Endpoints;
use fcae_runtime::config::SessionConfig;
use fcae_runtime::error::{CoreError, Result};
use fcae_runtime::session::TunBridge;
use parking_lot::Mutex;

pub mod platform;

/// `wintun.dll` staged at build time, embedded so the runtime can drop it
/// next to the executable. The TUN *driver* is still a DLL — only the
/// tun2socks *process* is gone.
#[cfg(all(windows, wintun_staged))]
static WINTUN_DLL: &[u8] = include_bytes!(env!("FCAE_WINTUN_DLL"));

// ── Go c-archive symbols ────────────────────────────────────────────────

#[cfg(tun2socks_linked)]
extern "C" {
    fn t2s_set_log_callback(cb: Option<unsafe extern "C" fn(c_int, *const c_char)>);
    fn t2s_start(device: *const c_char, proxy: *const c_char, mtu: c_int, loglevel: *const c_char)
        -> c_int;
    fn t2s_stop() -> c_int;
    fn t2s_is_running() -> c_int;
    fn t2s_version() -> *const c_char;
}

// Stub build (`--features stub`, or a host without Go): the crate still
// compiles and every call reports the bridge as unavailable.
#[cfg(not(tun2socks_linked))]
#[allow(unused_variables)]
mod stub {
    use super::*;
    pub unsafe fn t2s_set_log_callback(_cb: Option<unsafe extern "C" fn(c_int, *const c_char)>) {}
    pub unsafe fn t2s_start(
        _d: *const c_char,
        _p: *const c_char,
        _m: c_int,
        _l: *const c_char,
    ) -> c_int {
        -100
    }
    pub unsafe fn t2s_stop() -> c_int {
        0
    }
    pub unsafe fn t2s_is_running() -> c_int {
        0
    }
    pub unsafe fn t2s_version() -> *const c_char {
        c"fcae-bridge-tun2socks-bridge/stub".as_ptr()
    }
}
#[cfg(not(tun2socks_linked))]
use stub::*;

/// Receives log lines from the Go side and forwards them into `log`, so
/// tun2socks output lands in the same GUI console as everything else instead
/// of a discarded child stdout.
unsafe extern "C" fn go_log_trampoline(level: c_int, msg: *const c_char) {
    if msg.is_null() {
        return;
    }
    let text = CStr::from_ptr(msg).to_string_lossy();
    match level {
        1 => log::error!("[tun2socks] {text}"),
        2 => log::warn!("[tun2socks] {text}"),
        4 => log::debug!("[tun2socks] {text}"),
        _ => log::info!("[tun2socks] {text}"),
    }
}

/// Bridge ABI version string reported by the Go side.
pub fn version() -> String {
    unsafe {
        let p = t2s_version();
        if p.is_null() {
            "unknown".into()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

/// True when this build actually links the Go engine.
pub const fn is_supported() -> bool {
    cfg!(tun2socks_linked)
}

/// State owned by a live TUN session.
struct Active {
    /// Descriptor we created (desktop) or dup'd (Android) and must close.
    owned_fd: Option<i32>,
    /// Platform state needed to undo routes/DNS.
    undo: platform::TunUndo,
}

/// The bridge. One per process; `TunBridge` methods are safe to call from any
/// thread and are idempotent.
pub struct Tun2SocksBridge {
    active: Mutex<Option<Active>>,
    running: AtomicBool,
    log_installed: AtomicBool,
    /// Android VpnService descriptor set out-of-band via the FFI.
    external_fd: AtomicI32,
}

impl Default for Tun2SocksBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl Tun2SocksBridge {
    pub const fn new() -> Self {
        Self {
            active: Mutex::new(None),
            running: AtomicBool::new(false),
            log_installed: AtomicBool::new(false),
            external_fd: AtomicI32::new(-1),
        }
    }

    /// Supply the Android VpnService file descriptor. Called from the FFI
    /// before `fcae_start`; the bridge never takes ownership of this fd.
    pub fn set_android_fd(&self, fd: i32) {
        self.external_fd.store(fd, Ordering::SeqCst);
    }

    /// Forget a previously supplied descriptor.
    ///
    /// The fd belongs to a single VpnService instance. Once that session ends
    /// the number is meaningless -- and, worse, the kernel will hand the same
    /// integer to an unrelated file later. Leaving it latched made a
    /// subsequent *proxy* session look pre-authorised for TUN and let
    /// `device_spec` dup a stranger's descriptor, which is why proxy mode
    /// appeared to "use tun2socks" when it should not touch it at all.
    pub fn clear_android_fd(&self) {
        self.external_fd.store(-1, Ordering::SeqCst);
    }

    /// The TUN fd handed over by the platform (Android's VpnService), if any.
    ///
    /// This is the authorisation to run TUN mode without elevation: the JVM
    /// already created the interface, so there is nothing left to privilege.
    pub fn android_fd(&self) -> Option<i32> {
        let fd = self.external_fd.load(Ordering::SeqCst);
        if fd >= 0 { Some(fd) } else { None }
    }

    fn install_log_hook(&self) {
        if !self.log_installed.swap(true, Ordering::SeqCst) {
            unsafe { t2s_set_log_callback(Some(go_log_trampoline)) };
        }
    }

    /// Build the tun2socks `--device` argument.
    ///
    /// Returns the device string plus the fd we own (if any).
    fn device_spec(&self, cfg: &SessionConfig) -> Result<(String, Option<i32>)> {
        // Android (or any caller that hands us a descriptor).
        let external = match cfg.tun.fd {
            Some(fd) if fd >= 0 => Some(fd),
            _ => {
                let fd = self.external_fd.load(Ordering::SeqCst);
                (fd >= 0).then_some(fd)
            }
        };

        if let Some(fd) = external {
            // Dup so Go's device.Close() never closes the JVM's descriptor.
            let dup = unsafe { libc::dup(fd) };
            if dup < 0 {
                return Err(CoreError::Internal(format!(
                    "dup() of the VpnService fd {fd} failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            log::info!("[tun] using VpnService fd {fd} (dup -> {dup}), in-process");
            return Ok((format!("fd://{dup}"), Some(dup)));
        }

        // Desktop: tun2socks creates the device itself.
        #[cfg(windows)]
        {
            // A stable GUID keeps Windows from creating "FCAE_VPN 2", "…3"
            // adapters on every reconnect.
            Ok((
                format!(
                    "tun://{}?guid={{24198F4C-7895-434C-AD65-9E29A92DDC61}}",
                    cfg.tun.name
                ),
                None,
            ))
        }
        #[cfg(not(windows))]
        {
            Ok((format!("tun://{}", cfg.tun.name), None))
        }
    }
}

impl TunBridge for Tun2SocksBridge {
    fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<()> {
        if !is_supported() {
            return Err(CoreError::Internal(
                "this build was compiled without the tun2socks bridge (feature `stub`); \
                 TUN mode is unavailable"
                    .into(),
            ));
        }

        let mut slot = self.active.lock();
        if slot.is_some() {
            log::warn!("[tun] start called while a device is already up; ignoring");
            return Ok(());
        }

        let socks = endpoints.socks.ok_or_else(|| {
            CoreError::Internal("TUN requested but the backend exposed no SOCKS endpoint".into())
        })?;

        self.install_log_hook();

        // Windows needs wintun.dll discoverable before the device is created.
        #[cfg(windows)]
        platform::ensure_wintun(wintun_bytes())?;

        let (device, owned_fd) = self.device_spec(cfg)?;
        let proxy = format!("socks5://{}", socks);

        let c_device = CString::new(device.clone())
            .map_err(|_| CoreError::Internal("device string contains a NUL".into()))?;
        let c_proxy = CString::new(proxy.clone())
            .map_err(|_| CoreError::Internal("proxy string contains a NUL".into()))?;
        let c_level = CString::new(if log::log_enabled!(log::Level::Debug) {
            "debug"
        } else {
            "info"
        })
        .expect("static string");

        let rc = unsafe {
            t2s_start(
                c_device.as_ptr(),
                c_proxy.as_ptr(),
                cfg.tun.mtu as c_int,
                c_level.as_ptr(),
            )
        };

        if rc != 0 {
            if let Some(fd) = owned_fd {
                unsafe { libc::close(fd) };
            }
            return Err(CoreError::Internal(match rc {
                -1 => "tun2socks is already running".to_string(),
                -2 => format!("tun2socks rejected the configuration (device={device}, proxy={proxy})"),
                -3 => "the tun2socks engine failed to start (see log for details)".to_string(),
                -100 => "tun2socks bridge not compiled into this build".to_string(),
                other => format!("tun2socks start failed with code {other}"),
            }));
        }

        // Now that the device exists, apply addresses, routes and DNS. The
        // peer IP is excluded so tunnelled traffic does not loop back into
        // the tunnel.
        let undo = platform::configure(cfg, endpoints.peer_ip.as_deref())?;

        self.running.store(true, Ordering::SeqCst);
        *slot = Some(Active { owned_fd, undo });
        log::info!("[tun] up: {device} <-> {proxy} (in-process)");
        Ok(())
    }

    fn stop(&self, timeout: Duration) {
        let Some(active) = self.active.lock().take() else {
            return;
        };

        // Order matters: undo the OS configuration first (while the device
        // still exists, so the route/DNS commands can name it), then stop the
        // stack, then release the descriptor.
        platform::restore(active.undo, timeout);

        let rc = unsafe { t2s_stop() };
        if rc != 0 {
            log::warn!("[tun] t2s_stop returned {rc}");
        }

        if let Some(fd) = active.owned_fd {
            // Only ever our dup — never the JVM's original.
            unsafe { libc::close(fd) };
        }

        self.running.store(false, Ordering::SeqCst);
        log::info!("[tun] down");
    }

    fn preauthorised_fd(&self) -> Option<i32> {
        self.android_fd()
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst) && unsafe { t2s_is_running() } == 1
    }
}

#[cfg(all(windows, wintun_staged))]
fn wintun_bytes() -> Option<&'static [u8]> {
    Some(WINTUN_DLL)
}

#[cfg(all(windows, not(wintun_staged)))]
fn wintun_bytes() -> Option<&'static [u8]> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_build_reports_unavailable_rather_than_panicking() {
        let bridge = Tun2SocksBridge::new();
        assert!(!bridge.is_running());
        // stop() on an idle bridge must be a no-op, not a crash.
        bridge.stop(Duration::from_secs(1));
    }

    /// Regression: the Android fd must not survive its VpnService session.
    ///
    /// A stale descriptor made the supervisor treat a later *proxy* session as
    /// pre-authorised for TUN, and `device_spec` would happily dup whatever
    /// unrelated file the kernel had since assigned to that number.
    #[test]
    fn clearing_the_android_fd_drops_preauthorisation() {
        let bridge = Tun2SocksBridge::new();
        assert!(bridge.android_fd().is_none(), "starts unarmed");

        bridge.set_android_fd(114);
        assert_eq!(bridge.android_fd(), Some(114));
        assert_eq!(bridge.preauthorised_fd(), Some(114));

        bridge.clear_android_fd();
        assert!(bridge.android_fd().is_none());
        assert!(
            bridge.preauthorised_fd().is_none(),
            "a cleared bridge must not authorise TUN"
        );
    }

    #[test]
    fn version_string_is_reported() {
        assert!(version().contains("fcae-bridge-tun2socks-bridge"));
    }

    /// The Windows device string must carry the persistent adapter GUID.
    ///
    /// Without `?guid=`, Wintun allocates a *new* adapter every time the name
    /// is already taken by a leftover from an unclean shutdown, so users
    /// accumulate "FCAE_VPN", "FCAE_VPN 2", "FCAE_VPN 3"... each with its own
    /// stale routes and DNS registration. The GUID pins one adapter that gets
    /// reused across reconnects.
    ///
    /// The value is deliberately identical to the one the old subprocess
    /// passed, so an upgrade adopts the existing adapter instead of stranding
    /// it. Changing it is a breaking change for anyone mid-upgrade.
    #[cfg(windows)]
    #[test]
    fn windows_device_pins_the_persistent_adapter_guid() {
        let bridge = Tun2SocksBridge::new();
        let mut cfg = SessionConfig::default();
        cfg.tun.name = "FCAE_VPN".to_string();
        cfg.tun.fd = None;

        let (device, owned_fd) = bridge.device_spec(&cfg).expect("device spec");

        assert_eq!(
            device,
            "tun://FCAE_VPN?guid={24198F4C-7895-434C-AD65-9E29A92DDC61}"
        );
        assert!(owned_fd.is_none(), "no fd is owned when we create the device");
    }

    /// Non-Windows desktop has no GUID concept; the bare name is correct.
    #[cfg(all(not(windows), not(target_os = "android")))]
    #[test]
    fn unix_device_is_the_bare_name() {
        let bridge = Tun2SocksBridge::new();
        let mut cfg = SessionConfig::default();
        cfg.tun.name = "FCAE_VPN".to_string();
        cfg.tun.fd = None;

        let (device, owned_fd) = bridge.device_spec(&cfg).expect("device spec");

        assert_eq!(device, "tun://FCAE_VPN");
        assert!(owned_fd.is_none());
    }

    /// When a descriptor is supplied (Android VpnService) it wins over any
    /// name-based device, and it is dup'd rather than used directly.
    #[test]
    fn supplied_fd_is_duped_and_used_as_the_device() {
        let bridge = Tun2SocksBridge::new();
        let mut cfg = SessionConfig::default();
        cfg.tun.name = "FCAE_VPN".to_string();

        // A real descriptor we own, so the dup is safe to close.
        let fd = unsafe { libc::dup(0) };
        assert!(fd >= 0, "could not dup stdin for the test");
        cfg.tun.fd = Some(fd);

        let (device, owned) = bridge.device_spec(&cfg).expect("device spec");

        let dup = owned.expect("bridge must own the dup'd fd");
        assert_ne!(dup, fd, "the bridge must dup, never hand Go the original");
        assert_eq!(device, format!("fd://{dup}"));

        unsafe {
            libc::close(dup);
            libc::close(fd);
        }
    }
}
