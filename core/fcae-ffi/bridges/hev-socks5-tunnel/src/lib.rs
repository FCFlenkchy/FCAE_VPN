//! # fcae-bridge-hev-socks5-tunnel — in-process TUN bridge (C engine)
//!
//! Implements [`fcae_runtime::session::TunBridge`] by driving the
//! **hev-socks5-tunnel** userspace network engine inside this process via
//! its stable C ABI (`core/hev-socks5-tunnel/include/hev-socks5-tunnel.h`),
//! statically linked.
//!
//! This is a drop-in sibling of `fcae-bridge-tun2socks` and `fcae-bridge-zeptun`:
//! all are *TUN* bridges that **consume** the local SOCKS5 endpoint a tunnel
//! bridge (aether / psiphon) **produces**, and expose it as a TUN device.
//!
//! ## Why hev-socks5-tunnel
//!
//! hev-socks5-tunnel is a lightweight, high-performance SOCKS5 tunnel engine
//! written in C with coroutine-based I/O. It supports:
//! * TUN/TAP devices on Linux, macOS, Windows (via Wintun), and Android
//! * SOCKS5 UDP and TCP
//! * IPv4 and IPv6
//! * ICMP echo handling
//! * Multi-queue for parallel packet processing
//!
//! The engine is simpler than tun2socks (no Go runtime overhead) and provides
//! comparable performance to zeptun while being easier to cross-compile.
//!
//! ## Build requirements
//!
//! * Built artifacts produced OUTSIDE the cargo graph (see `build.rs`):
//!   * desktop → `make -C core/hev-socks5-tunnel static` (lands in `core/hev-socks5-tunnel/bin/`)
//!   * android → cross-compile with NDK (see CI)
//! * or `FCAE_HEV_LIBDIR=<dir>` pointing at a directory with `libhev-socks5-tunnel.a`.
//!
//! Building without it: `cargo build --features fcae-bridge-hev-socks5-tunnel/stub`
//! compiles a stub where TUN reports "unavailable". Do not ship a stub build.

use std::ffi::{c_char, c_int, c_uchar, c_uint, CStr, CString};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

use fcae_runtime::backend::Endpoints;
use fcae_runtime::config::SessionConfig;
use fcae_runtime::error::{CoreError, Result};
use fcae_runtime::session::TunBridge;
use parking_lot::Mutex;

mod platform;

#[cfg(all(windows, wintun_staged))]
static WINTUN_DLL: &[u8] = include_bytes!(env!("FCAE_HEV_WINTUN_DLL"));

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

#[cfg(hev_linked)]
extern "C" {
    fn hev_socks5_tunnel_main_from_str(
        config_str: *const c_uchar,
        config_len: c_uint,
        tun_fd: c_int,
    ) -> c_int;
    fn hev_socks5_tunnel_quit();
    fn hev_socks5_tunnel_stats(
        tx_packets: *mut usize,
        tx_bytes: *mut usize,
        rx_packets: *mut usize,
        rx_bytes: *mut usize,
    );
}

// Stub build (`--features stub`): the crate still compiles and every call
// reports the bridge as unavailable.
#[cfg(not(hev_linked))]
#[allow(unused_variables)]
mod stub {
    use super::*;
    pub unsafe fn hev_socks5_tunnel_main_from_str(
        _config_str: *const c_uchar,
        _config_len: c_uint,
        _tun_fd: c_int,
    ) -> c_int {
        -100
    }
    pub unsafe fn hev_socks5_tunnel_quit() {}
    pub unsafe fn hev_socks5_tunnel_stats(
        _tx_packets: *mut usize,
        _tx_bytes: *mut usize,
        _rx_packets: *mut usize,
        _rx_bytes: *mut usize,
    ) {
    }
}

#[cfg(not(hev_linked))]
use stub::*;

/// True when this build actually links the C engine.
pub const fn is_supported() -> bool {
    cfg!(hev_linked)
}

/// Traffic statistics from the engine.
#[derive(Default, Clone, Copy, Debug)]
pub struct HevStats {
    pub tx_packets: usize,
    pub tx_bytes: usize,
    pub rx_packets: usize,
    pub rx_bytes: usize,
}

/// State owned by a live TUN session.
struct Active {
    fd: Option<i32>,
}

/// The bridge. One per process; `TunBridge` methods are safe to call from any
/// thread and are idempotent.
pub struct HevSocks5TunnelBridge {
    active: Mutex<Option<Active>>,
    running: AtomicBool,
    closing: AtomicBool,
    /// Android VpnService descriptor set out-of-band via the FFI.
    external_fd: AtomicI32,
}

impl Default for HevSocks5TunnelBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl HevSocks5TunnelBridge {
    pub const fn new() -> Self {
        Self {
            active: Mutex::new(None),
            running: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            external_fd: AtomicI32::new(-1),
        }
    }

    /// Supply the Android VpnService file descriptor. Called from the FFI
    /// before `fcae_start`; the bridge never takes ownership of this fd.
    pub fn set_android_fd(&self, fd: i32) {
        self.external_fd.store(fd, Ordering::SeqCst);
    }

    /// Forget a previously supplied descriptor.
    pub fn clear_android_fd(&self) {
        self.external_fd.store(-1, Ordering::SeqCst);
    }

    /// The TUN fd handed over by the platform (Android's VpnService), if any.
    pub fn android_fd(&self) -> Option<i32> {
        let fd = self.external_fd.load(Ordering::SeqCst);
        (fd >= 0).then_some(fd)
    }

    /// Live engine statistics; `None` when not running.
    pub fn stats(&self) -> Option<HevStats> {
        if !self.running.load(Ordering::SeqCst) {
            return None;
        }
        let mut stats = HevStats::default();
        unsafe {
            hev_socks5_tunnel_stats(
                &mut stats.tx_packets,
                &mut stats.tx_bytes,
                &mut stats.rx_packets,
                &mut stats.rx_bytes,
            );
        }
        Some(stats)
    }

    /// Generate YAML configuration string for hev-socks5-tunnel.
    fn generate_config(cfg: &SessionConfig, endpoints: &Endpoints) -> Result<String> {
        let socks = endpoints.socks.ok_or_else(|| {
            CoreError::Internal("TUN requested but the backend exposed no SOCKS endpoint".into())
        })?;

        // Parse SOCKS address (host:port)
        let socks_str = socks.to_string();
        let parts: Vec<&str> = socks_str.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(CoreError::Internal(format!(
                "invalid SOCKS endpoint format: {socks_str}"
            )));
        }
        let port = parts[0];
        let address = parts[1].trim_start_matches("socks5://");

        let mut yaml = String::new();
        yaml.push_str("tunnel:\n");
        yaml.push_str(&format!("  name: {}\n", cfg.tun.name));
        yaml.push_str(&format!("  mtu: {}\n", cfg.tun.mtu));
        yaml.push_str("  multi-queue: false\n");
        yaml.push_str(&format!("  ipv4: {}\n", cfg.tun.ipv4));
        if let Some(ipv6) = &cfg.tun.ipv6 {
            yaml.push_str(&format!("  ipv6: '{}'\n", ipv6));
        }
        yaml.push_str("  icmp: 'off'\n");
        yaml.push_str("\n");
        yaml.push_str("socks5:\n");
        yaml.push_str(&format!("  port: {}\n", port));
        yaml.push_str(&format!("  address: {}\n", address));
        yaml.push_str("  udp: 'tcp'\n"); // UDP over TCP for reliability
        yaml.push_str("\n");
        yaml.push_str("misc:\n");
        yaml.push_str("  log-level: 'warn'\n");

        Ok(yaml)
    }
}

impl TunBridge for HevSocks5TunnelBridge {
    fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<()> {
        if !is_supported() {
            return Err(CoreError::Internal(
                "hev-socks5-tunnel is not available in this build".into(),
            ));
        }

        self.closing.store(false, Ordering::SeqCst);
        {
            let active = self.active.lock();
            if active.is_some() {
                log::warn!("[hev] start called while a device is already up; ignoring");
                return Ok(());
            }
        }

        if self.closing.load(Ordering::SeqCst) {
            return Err(CoreError::Internal(
                "TUN start cancelled (session is stopping)".into(),
            ));
        }

        // Windows needs wintun.dll discoverable before the device is created:
        // hev-socks5-tunnel loads it from the application directory or System32.
        #[cfg(windows)]
        platform::ensure_wintun(wintun_bytes())?;

        // Get the TUN fd
        let fd = cfg.tun.fd.or_else(|| {
            let f = self.external_fd.load(Ordering::SeqCst);
            (f >= 0).then_some(f)
        });

        let fd = fd.ok_or_else(|| {
            CoreError::Internal(
                "hev-socks5-tunnel requires a TUN descriptor".into(),
            )
        })?;

        // Dup the fd so we own our copy
        let dup = unsafe { libc::dup(fd) };
        if dup < 0 {
            return Err(CoreError::Internal(format!(
                "dup(tun fd {fd}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Generate YAML config
        let config_yaml = Self::generate_config(cfg, endpoints)?;
        let config_cstring = CString::new(config_yaml.clone())
            .map_err(|_| CoreError::Internal("config contains a NUL".into()))?;
        let config_bytes = config_cstring.as_bytes_with_nul();

        log::info!("[hev] starting with config:\n{}", config_yaml);

        // Start the engine in a background thread (it blocks)
        let active = self.active.lock();
        if self.closing.load(Ordering::SeqCst) {
            unsafe { libc::close(dup) };
            return Err(CoreError::Internal(
                "TUN start cancelled before engine start".into(),
            ));
        }

        let config_ptr = config_bytes.as_ptr() as *const c_uchar;
        let config_len = config_bytes.len() as c_uint;

        // Start in background thread
        let running = self.running.clone();
        let closing = self.closing.clone();
        std::thread::spawn(move || {
            let rc = unsafe { hev_socks5_tunnel_main_from_str(config_ptr, config_len, dup) };
            running.store(false, Ordering::SeqCst);
            if rc != 0 && !closing.load(Ordering::SeqCst) {
                log::error!("[hev] engine exited with code {rc}");
            }
        });

        self.running.store(true, Ordering::SeqCst);
        *self.active.lock() = Some(Active { fd: Some(dup) });

        log::info!(
            "[hev] up (socks {}, mtu {})",
            endpoints.socks.unwrap(),
            cfg.tun.mtu
        );
        Ok(())
    }

    fn abort(&self) {
        self.closing.store(true, Ordering::SeqCst);

        let mut active = self.active.lock();
        if let Some(a) = active.take() {
            if let Some(fd) = a.fd {
                unsafe { libc::close(fd) };
            }
        }
        self.clear_android_fd();
        self.running.store(false, Ordering::SeqCst);
    }

    fn stop(&self, timeout: Duration) {
        self.abort();

        // Signal the engine to quit
        unsafe { hev_socks5_tunnel_quit() };

        log::info!("[hev] down");
    }

    fn preauthorised_fd(&self) -> Option<i32> {
        self.android_fd()
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_build_reports_unavailable_rather_than_panicking() {
        let bridge = HevSocks5TunnelBridge::new();
        assert!(!bridge.is_running());
        bridge.stop(Duration::from_secs(1));
    }

    #[test]
    fn clearing_the_android_fd_drops_preauthorisation() {
        let bridge = HevSocks5TunnelBridge::new();
        assert!(bridge.android_fd().is_none());

        bridge.set_android_fd(114);
        assert_eq!(bridge.android_fd(), Some(114));
        assert_eq!(bridge.preauthorised_fd(), Some(114));

        bridge.clear_android_fd();
        assert!(bridge.android_fd().is_none());
        assert!(bridge.preauthorised_fd().is_none());
    }
}
