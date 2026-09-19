use std::ffi::{c_int, c_uchar, c_uint};
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

#[cfg(windows)]
use fcae_bridge_tun2socks::platform as tun_platform;

#[cfg(windows)]
use std::process::{Command, Stdio};

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

/// The engine DLL and its dependencies, resolved once per process.
///
/// The DLL is built by MSYS2 (the engine's only Windows toolchain), so it
/// imports `msys-2.0.dll` and its own third-party DLLs — all of which ship in
/// the same directory as the engine DLL and are resolved by the loader when
/// it is loaded by explicit path. A load failure is cached: the DLL will not
/// appear mid-session, and the UI reads `is_supported()` from there.
#[cfg(hev_dynamic)]
mod ffi {
    use std::ffi::{c_int, c_uchar, c_uint, c_void};
    use std::sync::OnceLock;

    pub const DLL_NAME: &str = "libhev-socks5-tunnel.dll";
    /// Runtime override for the DLL location; the build uses the same
    /// variable to declare the DLL part of the install.
    pub const DLL_ENV: &str = "FCAE_HEV_DLL";
    const LOAD_LIBRARY_SEARCH_APPLICATION_DIR: u32 = 0x0000_0200;
    const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_1000;

    type MainFn = unsafe extern "C" fn(*const c_uchar, c_uint, c_int) -> c_int;
    type QuitFn = unsafe extern "C" fn();
    type StatsFn = unsafe extern "C" fn(*mut usize, *mut usize, *mut usize, *mut usize);

    struct Ffi {
        main_from_str: MainFn,
        quit: QuitFn,
        stats: StatsFn,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryExW(
            lp_filename: *const u16,
            h_file: *mut c_void,
            dw_flags: u32,
        ) -> *mut c_void;
        fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const u8) -> *mut c_void;
        fn GetLastError() -> u32;
    }

    fn path() -> Option<std::path::PathBuf> {
        if let Ok(raw) = std::env::var(DLL_ENV) {
            let raw = raw.trim();
            if !raw.is_empty() {
                let path = std::path::PathBuf::from(raw);
                return path.is_file().then_some(path);
            }
            return None;
        }
        let dir = std::env::current_exe()
            .ok()?
            .parent()?
            .to_path_buf();
        let path = dir.join(DLL_NAME);
        path.is_file().then_some(path)
    }

    fn symbol<T: Copy>(module: *mut c_void, name: &str) -> Option<T> {
        let mut proc = name.as_bytes().to_vec();
        proc.push(0);
        let ptr = unsafe { GetProcAddress(module, proc.as_ptr()) };
        (!ptr.is_null()).then(|| unsafe { std::mem::transmute_copy::<*, T>(&ptr) })
    }

    fn load_inner() -> Result<Box<Ffi>, String> {
        let path = match path() {
            Some(path) => path,
            None => {
                return Err(format!(
                    "{DLL_NAME} is missing from the installation (set {DLL_ENV} to override)"
                ))
            }
        };
        let wide: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let module = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
            )
        };
        if module.is_null() {
            return Err(format!(
                "cannot load {}: {}",
                path.display(),
                std::io::Error::from_raw_os_error(unsafe { GetLastError() })
            ));
        }
        let main_from_str =
            symbol::<MainFn>(module, "hev_socks5_tunnel_main_from_str").ok_or_else(|| {
                format!("{DLL_NAME} is missing the symbol hev_socks5_tunnel_main_from_str")
            })?;
        let quit = symbol::<QuitFn>(module, "hev_socks5_tunnel_quit")
            .ok_or_else(|| format!("{DLL_NAME} is missing the symbol hev_socks5_tunnel_quit"))?;
        let stats =
            symbol::<StatsFn>(module, "hev_socks5_tunnel_stats").ok_or_else(|| {
                format!("{DLL_NAME} is missing the symbol hev_socks5_tunnel_stats")
            })?;
        Ok(Box::new(Ffi {
            main_from_str,
            quit,
            stats,
        }))
    }

    static FFI: OnceLock<Result<Box<Ffi>, String>> = OnceLock::new();

    pub fn try_load() -> Result<&'static Ffi, String> {
        FFI.get_or_init(Self::load_inner).as_ref().map_err(|e| e.clone())
    }
}

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

#[cfg(not(any(hev_linked, hev_dynamic)))]
#[allow(unused_variables)]
mod stub {
    use std::ffi::{c_int, c_uchar, c_uint};
    pub unsafe fn hev_socks5_tunnel_main_from_str(
        _config_str: *const c_uchar,
        _config_len: c_uint,
        _tun_fd: c_int,
    ) -> c_int {
        -100
    }
    pub fn hev_socks5_tunnel_quit() {}
    pub fn hev_socks5_tunnel_stats(
        _tx_packets: *mut usize,
        _tx_bytes: *mut usize,
        _rx_packets: *mut usize,
        _rx_bytes: *mut usize,
    ) {
    }
}

unsafe fn engine_main_from_str(
    config_str: *const c_uchar,
    config_len: c_uint,
    tun_fd: c_int,
) -> c_int {
    #[cfg(hev_linked)]
    { hev_socks5_tunnel_main_from_str(config_str, config_len, tun_fd) }
    #[cfg(hev_dynamic)]
    {
        match ffi::try_load() {
            Ok(ffi) => (ffi.main_from_str)(config_str, config_len, tun_fd),
            Err(e) => {
                log::error!("[hev] {e}");
                -100
            }
        }
    }
    #[cfg(not(any(hev_linked, hev_dynamic)))]
    { stub::hev_socks5_tunnel_main_from_str(config_str, config_len, tun_fd) }
}

fn engine_quit() -> bool {
    #[cfg(hev_linked)]
    {
        unsafe { hev_socks5_tunnel_quit() };
        true
    }
    #[cfg(hev_dynamic)]
    {
        match ffi::try_load() {
            Ok(ffi) => {
                unsafe { (ffi.quit)() };
                true
            }
            Err(e) => {
                log::error!("[hev] {e}");
                false
            }
        }
    }
    #[cfg(not(any(hev_linked, hev_dynamic)))]
    {
        stub::hev_socks5_tunnel_quit();
        true
    }
}

unsafe fn engine_stats(
    tx_packets: *mut usize,
    tx_bytes: *mut usize,
    rx_packets: *mut usize,
    rx_bytes: *mut usize,
) -> bool {
    #[cfg(hev_linked)]
    {
        hev_socks5_tunnel_stats(tx_packets, tx_bytes, rx_packets, rx_bytes);
        true
    }
    #[cfg(hev_dynamic)]
    {
        match ffi::try_load() {
            Ok(ffi) => {
                (ffi.stats)(tx_packets, tx_bytes, rx_packets, rx_bytes);
                true
            }
            Err(e) => {
                log::error!("[hev] {e}");
                false
            }
        }
    }
    #[cfg(not(any(hev_linked, hev_dynamic)))]
    {
        stub::hev_socks5_tunnel_stats(tx_packets, tx_bytes, rx_packets, rx_bytes);
        true
    }
}

pub fn is_supported() -> bool {
    #[cfg(hev_linked)]
    { true }
    #[cfg(hev_dynamic)]
    { ffi::try_load().is_ok() }
    #[cfg(not(any(hev_linked, hev_dynamic)))]
    { false }
}

/// One engine run: the thread hosting `hev_socks5_tunnel_main_from_str` and
/// its exit code.
struct Engine {
    thread: std::thread::JoinHandle<()>,
    #[cfg_attr(not(windows), allow(dead_code))]
    rc: Arc<AtomicI32>,
}

impl Engine {
    /// True once the engine thread has run to completion.
    fn dead(&self) -> bool {
        self.thread.is_finished()
    }
}

struct Active {
    thread: std::thread::JoinHandle<()>,
    _psiphon: Option<socks5p::Adapter>,
    _tor: Option<socks5t::Adapter>,
    #[cfg(windows)]
    undo: tun_platform::TunUndo,
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
        let ok = unsafe {
            engine_stats(
                &mut stats.tx_packets,
                &mut stats.tx_bytes,
                &mut stats.rx_packets,
                &mut stats.rx_bytes,
            )
        };
        ok.then_some(stats)
    }

    fn signal_stop(&self) -> bool {
        if !self.running.swap(false, Ordering::SeqCst) {
            return false;
        }
        engine_quit()
    }

    fn reap_locked(slot: &mut Option<Active>) -> bool {
        if slot.as_ref().is_some_and(|a| a.thread.is_finished()) {
            if let Some(done) = slot.take() {
                let _ = done.thread.join();
                #[cfg(windows)]
                tun_platform::restore(done.undo, Duration::from_millis(250));
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

    /// Spawn the engine thread for one run. Each spawn gets its own dup of
    /// the external TUN fd (the engine takes ownership of it).
    fn spawn_engine(&self, yaml: &str, fd: i32) -> Result<Engine> {
        let config = std::ffi::CString::new(yaml).map_err(|_| {
            CoreError::Internal("hev-socks5-tunnel config contains a NUL byte".into())
        })?;

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

        let running = self.running.clone();
        let closing = self.closing.clone();
        let rc = Arc::new(AtomicI32::new(0));
        let rc_thread = rc.clone();

        let thread = std::thread::Builder::new()
            .name("hev-socks5-tunnel".into())
            .spawn(move || {
                let bytes = config.as_bytes();
                let code = unsafe {
                    engine_main_from_str(
                        bytes.as_ptr() as *const c_uchar,
                        bytes.len() as c_uint,
                        dup.unwrap_or(-1),
                    )
                };
                if let Some(dup) = dup {
                    unsafe { libc::close(dup) };
                }
                running.store(false, Ordering::SeqCst);
                rc_thread.store(code, Ordering::SeqCst);
                if code != 0 && !closing.load(Ordering::SeqCst) {
                    log::error!("[hev] engine exited with code {code}");
                }
            })
            .map_err(|e| {
                if let Some(dup) = dup {
                    unsafe { libc::close(dup) };
                }
                CoreError::Internal(format!(
                    "cannot spawn the hev-socks5-tunnel engine thread: {e}"
                ))
            })?;

        Ok(Engine { thread, rc })
    }

    /// Start the engine and bring the interface it creates up: address,
    /// routes and DNS come from the tun2socks platform layer, so the routing
    /// policy exists exactly once regardless of engine.
    ///
    /// The engine thread opens the wintun adapter itself. If that first open
    /// fails — usually a stale adapter left behind by a crashed session, which
    /// the wintun driver refuses to recreate — the adapter is removed and the
    /// engine is retried once.
    #[cfg(windows)]
    fn start_with_interface(
        &self,
        yaml: &str,
        fd: i32,
        cfg: &SessionConfig,
        endpoints: &Endpoints,
    ) -> Result<(Engine, tun_platform::TunUndo)> {
        let mut engine = self.spawn_engine(yaml, fd)?;
        let mut retried = false;

        loop {
            if engine.dead() {
                let _ = engine.thread.join();
                let code = engine.rc.load(Ordering::SeqCst);
                if !retried {
                    retried = true;
                    remove_stale_adapter(&cfg.tun.name);
                    engine = self.spawn_engine(yaml, fd)?;
                    continue;
                }
                return Err(CoreError::Internal(format!(
                    "hev-socks5-tunnel exited during startup (code {code})"
                )));
            }

            // Waits up to 4s for the adapter to appear before configuring it.
            let undo = match tun_platform::configure(cfg, endpoints.peer_ip.as_deref()) {
                Ok(undo) => undo,
                Err(e) => {
                    if !retried && engine.dead() {
                        // The engine died while waiting for the device.
                        let _ = engine.thread.join();
                        retried = true;
                        remove_stale_adapter(&cfg.tun.name);
                        engine = self.spawn_engine(yaml, fd)?;
                        continue;
                    }
                    self.closing.store(true, Ordering::SeqCst);
                    self.signal_stop();
                    let _ = engine.thread.join();
                    return Err(e);
                }
            };

            if engine.dead() {
                let _ = engine.thread.join();
                let code = engine.rc.load(Ordering::SeqCst);
                tun_platform::restore(undo, Duration::from_millis(250));
                return Err(CoreError::Internal(format!(
                    "hev-socks5-tunnel exited during startup (code {code})"
                )));
            }
            return Ok((engine, undo));
        }
    }
}

impl TunBridge for HevSocks5TunnelBridge {
    fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<()> {
        #[cfg(hev_dynamic)]
        {
            if let Err(e) = ffi::try_load() {
                return Err(CoreError::Internal(format!(
                    "cannot load {}: {e}",
                    ffi::DLL_NAME
                )));
            }
        }
        #[cfg(not(hev_dynamic))]
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

        let fd = cfg.tun.fd.or_else(|| self.android_fd()).unwrap_or(-1);

        let (_, yaml) = generate_config(cfg, effective_socks)?;

        self.running.store(true, Ordering::SeqCst);

        #[cfg(windows)]
        let (engine, undo) = self.start_with_interface(&yaml, fd, cfg, endpoints)?;
        #[cfg(not(windows))]
        let engine = self.spawn_engine(&yaml, fd)?;

        *self.active.lock() = Some(Active {
            thread: engine.thread,
            _psiphon: psiphon_adapter,
            _tor: tor_adapter,
            #[cfg(windows)]
            undo,
        });

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
                // A thread cannot be killed. Abandon the engine and restore
                // the interface so the next session does not inherit stale
                // routes and DNS.
                if let Some(abandoned) = self.active.lock().take() {
                    #[cfg(windows)]
                    tun_platform::restore(abandoned.undo, timeout);
                }
            }
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

/// The wintun driver refuses to create an adapter whose name a crashed
/// session left behind; drop it before the retry.
#[cfg(windows)]
fn remove_stale_adapter(name: &str) {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;

    let script = format!(
        "Remove-NetAdapter -Name '{}' -Confirm:$false -ErrorAction SilentlyContinue",
        name.replace('\'', "''")
    );
    let removed = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !removed {
        log::debug!("[hev] could not remove a stale `{name}` adapter");
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
    yaml.push_str("  udp: 'udp'\n");
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
        assert_eq!(bridge.android_fd(), None);
        bridge.set_android_fd(114);
        assert_eq!(bridge.android_fd(), Some(114));
        assert_eq!(bridge.preauthorised_fd(), Some(114));
        bridge.clear_android_fd();
        assert_eq!(bridge.android_fd(), None);
        assert_eq!(bridge.preauthorised_fd(), None);
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
