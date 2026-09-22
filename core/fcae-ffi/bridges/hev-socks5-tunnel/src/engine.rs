use std::ffi::{c_int, c_uchar, c_uint};
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
use crate::{generate_config, HevStats};

const RESTART_GRACE: Duration = Duration::from_secs(2);

#[cfg(hev_linked)]
extern "C" {
    fn hev_socks5_tunnel_main_from_str(config_str: *const c_uchar, config_len: c_uint, tun_fd: c_int) -> c_int;
    fn hev_socks5_tunnel_quit();
    fn hev_socks5_tunnel_stats(tx_packets: *mut usize, tx_bytes: *mut usize, rx_packets: *mut usize, rx_bytes: *mut usize);
}

#[cfg(not(any(hev_linked, hev_dynamic)))]
mod stub {
    use std::ffi::{c_int, c_uchar, c_uint};
    pub unsafe fn hev_socks5_tunnel_main_from_str(_config_str: *const c_uchar, _config_len: c_uint, _tun_fd: c_int) -> c_int { -100 }
    pub fn hev_socks5_tunnel_quit() {}
    pub fn hev_socks5_tunnel_stats(_tx_packets: *mut usize, _tx_bytes: *mut usize, _rx_packets: *mut usize, _rx_bytes: *mut usize) {}
}

unsafe fn engine_main_from_str(config_str: *const c_uchar, config_len: c_uint, tun_fd: c_int) -> c_int {
    #[cfg(hev_linked)]
    { hev_socks5_tunnel_main_from_str(config_str, config_len, tun_fd) }
    #[cfg(not(any(hev_linked, hev_dynamic)))]
    { stub::hev_socks5_tunnel_main_from_str(config_str, config_len, tun_fd) }
    #[cfg(hev_dynamic)]
    { let _ = (config_str, config_len, tun_fd); -100 }
}

fn engine_quit() -> bool {
    #[cfg(hev_linked)]
    { unsafe { hev_socks5_tunnel_quit() }; true }
    #[cfg(not(any(hev_linked, hev_dynamic)))]
    { stub::hev_socks5_tunnel_quit(); true }
    #[cfg(hev_dynamic)]
    { true }
}

unsafe fn engine_stats(tx_packets: *mut usize, tx_bytes: *mut usize, rx_packets: *mut usize, rx_bytes: *mut usize) -> bool {
    #[cfg(hev_linked)]
    { hev_socks5_tunnel_stats(tx_packets, tx_bytes, rx_packets, rx_bytes); true }
    #[cfg(not(any(hev_linked, hev_dynamic)))]
    { stub::hev_socks5_tunnel_stats(tx_packets, tx_bytes, rx_packets, rx_bytes); true }
    #[cfg(hev_dynamic)]
    { let _ = (tx_packets, tx_bytes, rx_packets, rx_bytes); false }
}

pub fn unavailable_reason() -> Option<&'static str> {
    #[cfg(hev_linked)]
    { None }
    #[cfg(not(any(hev_linked, hev_dynamic)))]
    { Some("hev-socks5-tunnel not linked (stub build)") }
    #[cfg(hev_dynamic)]
    { Some("hev-socks5-tunnel dynamic loading is Windows-only") }
}

pub fn is_supported() -> bool { unavailable_reason().is_none() }

struct Engine {
    thread: std::thread::JoinHandle<()>,
    rc: Arc<AtomicI32>,
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
    fn default() -> Self { Self::new() }
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

    pub fn set_android_fd(&self, fd: i32) { self.external_fd.store(fd, Ordering::SeqCst); }
    pub fn clear_android_fd(&self) { self.external_fd.store(-1, Ordering::SeqCst); }
    pub fn android_fd(&self) -> Option<i32> { let fd = self.external_fd.load(Ordering::SeqCst); (fd >= 0).then_some(fd) }

    pub fn stats(&self) -> Option<HevStats> {
        if !self.running.load(Ordering::SeqCst) { return None; }
        let mut stats = HevStats::default();
        let ok = unsafe { engine_stats(&mut stats.tx_packets, &mut stats.tx_bytes, &mut stats.rx_packets, &mut stats.rx_bytes) };
        ok.then_some(stats)
    }

    fn signal_stop(&self) -> bool {
        if !self.running.swap(false, Ordering::SeqCst) { return false; }
        engine_quit()
    }

    fn reap_locked(slot: &mut Option<Active>) -> bool {
        if slot.as_ref().is_some_and(|a| a.thread.is_finished()) {
            if let Some(done) = slot.take() { let _ = done.thread.join(); }
        }
        slot.is_none()
    }

    fn reap(&self, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        loop {
            if Self::reap_locked(&mut self.active.lock()) { return true; }
            if Instant::now() >= deadline { return false; }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn spawn_engine(&self, yaml: &str, fd: i32) -> Result<Engine> {
        let config = std::ffi::CString::new(yaml).map_err(|_| CoreError::Internal("hev-socks5-tunnel config contains a NUL byte".into()))?;
        let dup = if fd >= 0 {
            let dup = unsafe { libc::dup(fd) };
            if dup < 0 { return Err(CoreError::Internal(format!("dup(tun fd {fd}) failed: {}", std::io::Error::last_os_error()))); }
            Some(dup)
        } else { None };
        let running = self.running.clone();
        let closing = self.closing.clone();
        let rc = Arc::new(AtomicI32::new(0));
        let rc_thread = rc.clone();
        self.running.store(true, Ordering::SeqCst);
        let thread = std::thread::Builder::new().name("hev-socks5-tunnel".into()).spawn(move || {
            let bytes = config.as_bytes();
            let code = unsafe { engine_main_from_str(bytes.as_ptr() as *const c_uchar, bytes.len() as c_uint, dup.unwrap_or(-1)) };
            if let Some(dup) = dup { unsafe { libc::close(dup) }; }
            running.store(false, Ordering::SeqCst);
            rc_thread.store(code, Ordering::SeqCst);
            if code != 0 && !closing.load(Ordering::SeqCst) { log::error!("[hev] engine exited with code {code}"); }
        }).map_err(|e| {
            self.running.store(false, Ordering::SeqCst);
            if let Some(dup) = dup { unsafe { libc::close(dup) }; }
            CoreError::Internal(format!("cannot spawn the hev-socks5-tunnel engine thread: {e}"))
        })?;
        Ok(Engine { thread, rc })
    }
}

impl TunBridge for HevSocks5TunnelBridge {
    fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<()> {
        if !is_supported() {
            return Err(CoreError::Internal("hev-socks5-tunnel is not available in this build".into()));
        }
        let _lifecycle = self.lifecycle.lock();
        if !self.reap(RESTART_GRACE) {
            return Err(CoreError::Internal("the previous hev-socks5-tunnel engine is still shutting down".into()));
        }
        self.closing.store(false, Ordering::SeqCst);
        let base_socks = endpoints.socks.ok_or_else(|| CoreError::Internal("TUN requested but the backend exposed no SOCKS endpoint".into()))?;
        let psiphon_adapter = if endpoints.psiphon_dns {
            Some(socks5p::Adapter::start(base_socks).map_err(|e| CoreError::Internal(format!("hev socks5p adapter: {e}")))?)
        } else { None };
        let tor_adapter = if psiphon_adapter.is_none() && cfg.tor.is_exit() {
            Some(socks5t::Adapter::start(base_socks).map_err(|e| CoreError::Internal(format!("hev socks5t adapter: {e}")))?)
        } else { None };
        let effective_socks = psiphon_adapter.as_ref().map(|a| a.endpoint()).or_else(|| tor_adapter.as_ref().map(|a| a.endpoint())).unwrap_or(base_socks);
        let fd = cfg.tun.fd.or_else(|| self.android_fd()).unwrap_or(-1);
        let (_, yaml) = generate_config(cfg, effective_socks)?;
        let engine = self.spawn_engine(&yaml, fd)?;
        let exit_code = engine.rc.clone();
        *self.active.lock() = Some(Active { thread: engine.thread, _psiphon: psiphon_adapter, _tor: tor_adapter });
        if self.active.lock().as_ref().is_some_and(|a| a.thread.is_finished()) {
            return Err(CoreError::Internal(format!("hev-socks5-tunnel exited during startup (code {})", exit_code.load(Ordering::SeqCst))));
        }
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
        self.signal_stop();
        if !self.reap(timeout) {
            log::warn!("[hev] engine did not stop within {timeout:?}; reconnect is blocked until it exits");
        }
        self.clear_android_fd();
    }

    fn preauthorised_fd(&self) -> Option<i32> { self.android_fd() }
    fn is_running(&self) -> bool { self.running.load(Ordering::SeqCst) }

    fn check_health(&self, _cfg: &SessionConfig) -> Result<()> {
        if !self.is_running() { return Err(CoreError::Internal("TUN engine stopped unexpectedly".into())); }
        Ok(())
    }
}
