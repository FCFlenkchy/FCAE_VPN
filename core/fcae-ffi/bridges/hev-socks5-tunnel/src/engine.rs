//! In-process backend: drives the engine's C ABI on the platforms hev
//! supports natively (Linux, macOS, Android). `lib.rs` selects between this
//! module and `sidecar` (Windows) and owns everything they share.

use std::ffi::{c_int, c_uchar, c_uint, CString};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fcae_runtime::backend::Endpoints;
use fcae_runtime::config::SessionConfig;
use fcae_runtime::error::{CoreError, Result};
use fcae_runtime::session::TunBridge;

use parking_lot::Mutex;

use crate::{bare_address, log_level, HevStats};

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

/// How long a new engine waits for the previous one to finish unwinding.
///
/// `pause_tun()` stops the engine and `resume_tun()` starts it again straight
/// away, so the wait is bounded but generous enough to cover a task cycle.
const RESTART_GRACE: Duration = Duration::from_secs(2);

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

/// A live engine thread.
///
/// Retained rather than detached: the thread owns the descriptor the engine
/// drives and the join is what guarantees the engine released the C globals
/// before the next `start` reuses them.
struct Active {
    thread: std::thread::JoinHandle<()>,
}

/// The bridge. One per process; `TunBridge` methods are safe to call from any
/// thread and are idempotent.
pub struct HevSocks5TunnelBridge {
    /// Serialises `start`/`stop`/`abort`. The engine is a process-wide
    /// singleton, so a start must never interleave with a teardown.
    lifecycle: Mutex<()>,
    active: Mutex<Option<Active>>,
    /// Armed from the moment an engine is raised until the C entry point
    /// returns. Shared with the engine thread, which clears it on exit.
    running: Arc<AtomicBool>,
    /// Set by `stop`/`abort`; keeps an engine that exits because we asked it to
    /// from being logged as a failure.
    closing: Arc<AtomicBool>,
    /// Android VpnService descriptor set out-of-band via the FFI.
    external_fd: AtomicI32,
}

impl Default for HevSocks5TunnelBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl HevSocks5TunnelBridge {
    pub fn new() -> Self {
        Self {
            lifecycle: Mutex::new(()),
            active: Mutex::new(None),
            running: Arc::new(AtomicBool::new(false)),
            closing: Arc::new(AtomicBool::new(false)),
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

    /// Trip a live engine's stop flag. Returns whether one was signalled.
    ///
    /// `hev_socks5_tunnel_quit` stores its request in a global: calling it with
    /// no engine inside the entry point would leave the stop bit set, and the
    /// *next* engine would return from `hev_socks5_tunnel_run` immediately —
    /// a tunnel that comes up and forwards nothing. The `running` flag is the
    /// only thing that distinguishes the two cases, so it is swapped first.
    fn signal_stop(&self) -> bool {
        if !self.running.swap(false, Ordering::SeqCst) {
            return false;
        }
        unsafe { hev_socks5_tunnel_quit() };
        true
    }

    /// Join the engine thread once it exited. `true` = the slot is free.
    fn reap_locked(slot: &mut Option<Active>) -> bool {
        if slot.as_ref().is_some_and(|a| a.thread.is_finished()) {
            if let Some(done) = slot.take() {
                let _ = done.thread.join();
            }
        }
        slot.is_none()
    }

    /// Join a previous engine thread, waiting at most `wait` for it to exit.
    /// `true` = the slot is free and the C globals are reusable.
    fn reap(&self, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        loop {
            if Self::reap_locked(&mut self.active.lock()) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl TunBridge for HevSocks5TunnelBridge {
    fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<()> {
        if !is_supported() {
            return Err(CoreError::Internal(
                "hev-socks5-tunnel is not available in this build".into(),
            ));
        }

        let _lifecycle = self.lifecycle.lock();

        // One engine per process: a previous one that is still unwinding must
        // finish before its globals can be reused.
        if !self.reap(RESTART_GRACE) {
            return Err(CoreError::Internal(
                "the previous hev-socks5-tunnel engine is still shutting down".into(),
            ));
        }
        self.closing.store(false, Ordering::SeqCst);

        // Windows needs wintun.dll discoverable before the device is created:
        // hev-socks5-tunnel loads it from the application directory or System32.
        #[cfg(windows)]
        crate::platform::ensure_wintun(wintun_bytes())?;

        // Android: VpnService owns the device and hands over its descriptor,
        // which the engine must reuse. Desktop: no descriptor exists yet, so the
        // engine is asked to create the device itself from the config's tunnel
        // section (root, exactly like the CLI; the other engines do the same).
        let fd = cfg.tun.fd.or_else(|| self.android_fd()).unwrap_or(-1);

        // The engine sets the descriptor non-blocking and keeps it for as long
        // as it runs, so it gets a dup: the caller keeps its own descriptor
        // (VpnService owns that one) and its lifetime.
        let dup = if fd >= 0 {
            let dup = unsafe { libc::dup(fd) };
            if dup < 0 {
                return Err(CoreError::Internal(format!(
                    "dup(tun fd {fd}) failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Some(dup)
        } else {
            None
        };

        let (socks, yaml) = match generate_config(cfg, endpoints) {
            Ok(config) => config,
            Err(e) => {
                if let Some(dup) = dup {
                    unsafe { libc::close(dup) };
                }
                return Err(e);
            }
        };
        let config = match CString::new(yaml) {
            Ok(config) => config,
            Err(_) => {
                if let Some(dup) = dup {
                    unsafe { libc::close(dup) };
                }
                return Err(CoreError::Internal(
                    "hev-socks5-tunnel config contains a NUL byte".into(),
                ));
            }
        };

        log::info!("[hev] starting (socks {socks}, mtu {})", cfg.tun.mtu);

        // Armed *before* the thread exists: the engine may fail and clear the
        // flag before `start` gets to publish the handle, and a flag stored
        // afterwards would leave a dead engine looking live — the next `stop`
        // would then signal the C engine while nothing is inside it, poisoning
        // the stop bit for the engine after that.
        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();
        let closing = self.closing.clone();
        let engine = std::thread::Builder::new()
            .name("hev-socks5-tunnel".into())
            .spawn(move || {
                // The engine parses the YAML on this thread, after `start` has
                // returned, so the buffer is owned here rather than borrowed
                // from a stack frame that is already gone.
                //
                // The length must NOT include the terminating NUL: hev hands
                // both straight to yaml_parser_set_input_string(), and libyaml
                // reads exactly that many bytes — one byte past the document
                // (the NUL) is a parse error, so the whole engine exits with
                // rc -1 before it ever opens the tun device. as_bytes() keeps
                // the buffer NUL-terminated (CString guarantee) while
                // reporting the document length only.
                let bytes = config.as_bytes();
                let rc = unsafe {
                    hev_socks5_tunnel_main_from_str(
                        bytes.as_ptr() as *const c_uchar,
                        bytes.len() as c_uint,
                        dup.unwrap_or(-1),
                    )
                };
                // hev never closes a descriptor it did not create, so the dup
                // is released here, once the engine stopped using it.
                if let Some(dup) = dup {
                    unsafe { libc::close(dup) };
                }
                running.store(false, Ordering::SeqCst);
                if rc != 0 && !closing.load(Ordering::SeqCst) {
                    log::error!("[hev] engine exited with code {rc}");
                }
            });
        let engine = match engine {
            Ok(engine) => engine,
            Err(e) => {
                self.running.store(false, Ordering::SeqCst);
                if let Some(dup) = dup {
                    unsafe { libc::close(dup) };
                }
                return Err(CoreError::Internal(format!(
                    "cannot spawn the hev-socks5-tunnel engine thread: {e}"
                )));
            }
        };

        *self.active.lock() = Some(Active { thread: engine });

        log::info!("[hev] up (socks {socks}, mtu {})", cfg.tun.mtu);
        Ok(())
    }

    fn abort(&self) {
        let _lifecycle = self.lifecycle.lock();
        self.closing.store(true, Ordering::SeqCst);

        // Non-blocking by contract: `hev_socks5_tunnel_quit` only trips the
        // engine's event descriptor. The engine thread owns the TUN dup and
        // closes it when the entry point returns, so nothing is yanked from
        // under a live engine.
        self.signal_stop();
        self.clear_android_fd();
    }

    fn stop(&self, timeout: Duration) {
        let _lifecycle = self.lifecycle.lock();
        self.closing.store(true, Ordering::SeqCst);

        if self.signal_stop() {
            // The engine unwinds cooperatively. Waiting keeps the globals free
            // for `resume_tun()`; a timeout is not fatal, it only means the
            // slot stays occupied until the thread exits on its own.
            if !self.reap(timeout) {
                log::warn!("[hev] engine did not stop within {timeout:?}");
            }
            log::info!("[hev] down");
        }

        // Leave `closing` set. The next start() clears it.
        self.clear_android_fd();
    }

    fn preauthorised_fd(&self) -> Option<i32> {
        self.android_fd()
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// The SOCKS5 endpoint the engine dials, plus the YAML it is configured with.
///
/// Port and address are emitted separately so the engine never has to re-parse a
/// `host:port` string (and IPv6 literals stay unambiguous). The engine creates
/// the device from this config, so its tunnel section has to match the interface
/// the platform layer configures.
fn generate_config(cfg: &SessionConfig, endpoints: &Endpoints) -> Result<(SocketAddr, String)> {
    let socks = endpoints.socks.ok_or_else(|| {
        CoreError::Internal("TUN requested but the backend exposed no SOCKS endpoint".into())
    })?;

    let mut yaml = String::with_capacity(256);
    yaml.push_str("tunnel:\n");
    yaml.push_str(&format!("  name: {}\n", cfg.tun.name));
    #[cfg(windows)]
    yaml.push_str(&format!("  guid: {}\n", crate::WINTUN_ADAPTER_GUID));
    yaml.push_str(&format!("  mtu: {}\n", cfg.tun.mtu));
    yaml.push_str("  multi-queue: false\n");
    yaml.push_str(&format!("  ipv4: {}\n", bare_address(&cfg.tun.ipv4)));
    if let Some(ipv6) = &cfg.tun.ipv6 {
        yaml.push_str(&format!("  ipv6: '{}'\n", bare_address(ipv6)));
    }
    yaml.push_str("  icmp: 'off'\n\n");
    yaml.push_str("socks5:\n");
    yaml.push_str(&format!("  port: {}\n", socks.port()));
    yaml.push_str(&format!("  address: {}\n", socks.ip()));
    yaml.push_str("  udp: 'tcp'\n"); // UDP over TCP for reliability
    yaml.push_str("\nmisc:\n");
    yaml.push_str(&format!(
        "  log-level: '{}'\n",
        log_level(cfg.tun.t2s_log_level)
    ));

    Ok((socks, yaml))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session with no SOCKS endpoint has nothing to forward.
    #[test]
    fn a_session_without_a_socks_endpoint_generates_no_config() {
        let cfg = SessionConfig::default();
        assert!(generate_config(&cfg, &Endpoints::EMPTY).is_err());
    }

    /// The engine calls `inet_pton` on the addresses and derives the netmask
    /// from its own fixed prefix, so a CIDR address would be rejected; the
    /// adapter identity and the log level come from the session too.
    #[test]
    fn the_generated_config_matches_the_engine_and_the_session() {
        let mut cfg = SessionConfig::default();
        cfg.tun.ipv4 = "198.18.0.1/24".into();
        cfg.tun.ipv6 = Some("fc00::1/64".into());
        cfg.tun.t2s_log_level = 4;

        let mut endpoints = Endpoints::EMPTY;
        endpoints.socks = Some("127.0.0.1:1080".parse().expect("valid endpoint"));

        let (socks, yaml) = generate_config(&cfg, &endpoints).expect("config");

        assert_eq!(socks.port(), 1080);
        assert!(yaml.contains("\n  ipv4: 198.18.0.1\n"), "{yaml}");
        assert!(yaml.contains("\n  ipv6: 'fc00::1'\n"), "{yaml}");
        assert!(yaml.contains("\n  port: 1080\n"), "{yaml}");
        assert!(yaml.contains("\n  address: 127.0.0.1\n"), "{yaml}");
        assert!(yaml.contains("  log-level: 'info'\n"), "{yaml}");

        #[cfg(windows)]
        assert!(
            yaml.contains(&format!("\n  guid: {}\n", crate::WINTUN_ADAPTER_GUID)),
            "{yaml}"
        );
    }

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

    /// A session with no SOCKS endpoint has nothing to forward: the start must
    /// fail before a thread or a C global is touched.
    #[test]
    fn start_without_a_socks_endpoint_starts_no_engine() {
        let bridge = HevSocks5TunnelBridge::new();
        let cfg = SessionConfig::default();
        assert!(bridge.start(&cfg, &Endpoints::EMPTY).is_err());
        assert!(!bridge.is_running());
        assert!(bridge.stats().is_none());
    }
}
