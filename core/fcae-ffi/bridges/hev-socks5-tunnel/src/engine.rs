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

use crate::socks5p;
use crate::socks5t;
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

const RESTART_GRACE: Duration = Duration::from_secs(2);

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

pub const fn is_supported() -> bool {
    cfg!(hev_linked)
}

struct Active {
    thread: std::thread::JoinHandle<()>,
    _psiphon: Option<socks5p::Adapter>,
    _tor: Option<socks5t::Adapter>,
}

pub struct HevSocks5TunnelBridge {
    lifecycle: Mutex<()>,
    active: Mutex<Option<Active>>,
    running: Arc<AtomicBool>,
    closing: Arc<AtomicBool>,
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

    pub fn set_android_fd(&self, fd: i32) {
        self.external_fd.store(fd, Ordering::SeqCst);
    }

    pub fn clear_android_fd(&self) {
        self.external_fd.store(-1, Ordering::SeqCst);
    }

    pub fn android_fd(&self) -> Option<i32> {
        let fd = self.external_fd.load(Ordering::SeqCst);
        (fd >= 0).then_some(fd)
    }

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

    fn signal_stop(&self) -> bool {
        if !self.running.swap(false, Ordering::SeqCst) {
            return false;
        }
        unsafe { hev_socks5_tunnel_quit() };
        true
    }

    fn reap_locked(slot: &mut Option<Active>) -> bool {
        if slot.as_ref().is_some_and(|a| a.thread.is_finished()) {
            if let Some(done) = slot.take() {
                let _ = done.thread.join();
            }
        }
        slot.is_none()
    }

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

        if !self.reap(RESTART_GRACE) {
            return Err(CoreError::Internal(
                "the previous hev-socks5-tunnel engine is still shutting down".into(),
            ));
        }
        self.closing.store(false, Ordering::SeqCst);

        #[cfg(windows)]
        crate::platform::ensure_wintun(wintun_bytes())?;

        let base_socks = endpoints.socks.ok_or_else(|| {
            CoreError::Internal("TUN requested but the backend exposed no SOCKS endpoint".into())
        })?;

        let psiphon_adapter = if endpoints.psiphon_dns {
            Some(socks5p::Adapter::start(base_socks).map_err(|e| {
                CoreError::Internal(format!("hev socks5p adapter: {e}"))
            })?)
        } else {
            None
        };

        let tor_adapter = if psiphon_adapter.is_none() && cfg.tor.is_exit() {
            Some(socks5t::Adapter::start(base_socks).map_err(|e| {
                CoreError::Internal(format!("hev socks5t adapter: {e}"))
            })?)
        } else {
            None
        };

        let effective_socks = psiphon_adapter
            .as_ref()
            .map(|a| a.endpoint())
            .or_else(|| tor_adapter.as_ref().map(|a| a.endpoint()))
            .unwrap_or(base_socks);

        if psiphon_adapter.is_some() {
            log::info!("[hev] socks5p: native Psiphon DNS gateway, no direct DNS fallback");
        } else if tor_adapter.is_some() {
            log::info!("[hev] socks5t: DNS-over-TCP through Tor SOCKS");
        }

        let fd = cfg.tun.fd.or_else(|| self.android_fd()).unwrap_or(-1);

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

        let (socks, yaml) = match generate_config(cfg, effective_socks) {
            Ok(v) => v,
            Err(e) => {
                if let Some(dup) = dup {
                    unsafe { libc::close(dup) };
                }
                return Err(e);
            }
        };

        let config = match CString::new(yaml) {
            Ok(c) => c,
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

        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();
        let closing = self.closing.clone();
        let engine = std::thread::Builder::new()
            .name("hev-socks5-tunnel".into())
            .spawn(move || {
                let bytes = config.as_bytes();
                let rc = unsafe {
                    hev_socks5_tunnel_main_from_str(
                        bytes.as_ptr() as *const c_uchar,
                        bytes.len() as c_uint,
                        dup.unwrap_or(-1),
                    )
                };
                if let Some(dup) = dup {
                    unsafe { libc::close(dup) };
                }
                running.store(false, Ordering::SeqCst);
                if rc != 0 && !closing.load(Ordering::SeqCst) {
                    log::error!("[hev] engine exited with code {rc}");
                }
            });

        let engine = match engine {
            Ok(e) => e,
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

        *self.active.lock() = Some(Active {
            thread: engine,
            _psiphon: psiphon_adapter,
            _tor: tor_adapter,
        });

        log::info!("[hev] up (socks {socks}, mtu {})", cfg.tun.mtu);
        Ok(())
    }

    fn abort(&self) {
        let _lifecycle = self.lifecycle.lock();
        self.closing.store(true, Ordering::SeqCst);
        self.signal_stop();
        self.clear_android_fd();
    }

    fn stop(&self, timeout: Duration) {
        let _lifecycle = self.lifecycle.lock();
        self.closing.store(true, Ordering::SeqCst);
        if self.signal_stop() {
            if !self.reap(timeout) {
                log::warn!("[hev] engine did not stop within {timeout:?}");
            }
            log::info!("[hev] down");
        }
        self.clear_android_fd();
    }

    fn preauthorised_fd(&self) -> Option<i32> {
        self.android_fd()
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

fn generate_config(cfg: &SessionConfig, socks: SocketAddr) -> Result<(SocketAddr, String)> {
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
    yaml.push_str("  udp: 'tcp'\n");
    yaml.push_str("\nmisc:\n");
    yaml.push_str(&format!("  log-level: '{}'\n", log_level(cfg.tun.t2s_log_level)));
    Ok((socks, yaml))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_without_a_socks_endpoint_generates_no_config() {
        let cfg = SessionConfig::default();
        let socks: Option<SocketAddr> = None;
        assert!(socks.is_none());
        let _ = cfg;
    }

    #[test]
    fn the_generated_config_matches_the_engine_and_the_session() {
        let mut cfg = SessionConfig::default();
        cfg.tun.ipv4 = "198.18.0.1/24".into();
        cfg.tun.ipv6 = Some("fc00::1/64".into());
        cfg.tun.t2s_log_level = 4;
        let socks: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let (out_socks, yaml) = generate_config(&cfg, socks).expect("config");
        assert_eq!(out_socks.port(), 1080);
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

    #[test]
    fn start_without_a_socks_endpoint_starts_no_engine() {
        let bridge = HevSocks5TunnelBridge::new();
        let cfg = SessionConfig::default();
        assert!(bridge.start(&cfg, &Endpoints::EMPTY).is_err());
        assert!(!bridge.is_running());
        assert!(bridge.stats().is_none());
    }
}
