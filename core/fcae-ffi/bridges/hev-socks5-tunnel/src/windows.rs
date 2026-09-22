use std::ffi::{c_int, c_uchar, c_uint};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use fcae_runtime::backend::Endpoints;
use fcae_runtime::config::SessionConfig;
use fcae_runtime::error::{CoreError, Result};
use fcae_runtime::session::TunBridge;
use fcae_runtime::windows_dll::{EmbeddedFiles, Library};
use parking_lot::Mutex;

use crate::socks5p;
use crate::{generate_config, HevStats};

const RESTART_GRACE: Duration = Duration::from_secs(2);
const DLL_NAME: &str = "libhev-socks5-tunnel.dll";
const MSYS_NAME: &str = "msys-2.0.dll";

#[cfg(hev_dynamic)]
const EMBEDDED: &[(&str, &[u8])] = &[
    (DLL_NAME, include_bytes!(concat!(env!("OUT_DIR"), "/engine/libhev-socks5-tunnel.dll"))),
    ("libyaml.so", include_bytes!(concat!(env!("OUT_DIR"), "/engine/libyaml.so"))),
    ("liblwip.so", include_bytes!(concat!(env!("OUT_DIR"), "/engine/liblwip.so"))),
    ("libhev-task-system.so", include_bytes!(concat!(env!("OUT_DIR"), "/engine/libhev-task-system.so"))),
    (MSYS_NAME, include_bytes!(concat!(env!("OUT_DIR"), "/engine/msys-2.0.dll"))),
    #[cfg(wintun_staged)]
    ("wintun.dll", include_bytes!(env!("FCAE_HEV_WINTUN_DLL"))),
];

type MainFn = unsafe extern "C" fn(*const c_uchar, c_uint, c_int) -> c_int;
type QuitFn = unsafe extern "C" fn();
type StatsFn = unsafe extern "C" fn(*mut usize, *mut usize, *mut usize, *mut usize);
type InitFn = unsafe extern "C" fn();

struct Ffi {
    main_from_str: MainFn,
    quit: QuitFn,
    stats: StatsFn,
    _libs: Vec<Library>,
    _embedded: Option<EmbeddedFiles>,
}

fn call_msys_init(lib: &Library) -> Result<()> {
    unsafe {
        if let Ok(init) = lib.symbol::<InitFn>(c"msys_dll_init") {
            init();
            return Ok(());
        }
        if let Ok(init) = lib.symbol::<InitFn>(c"cygwin_dll_init") {
            init();
            return Ok(());
        }
    }
    Err(CoreError::Internal(format!("{MSYS_NAME} missing msys_dll_init/cygwin_dll_init")))
}

fn load_from_dir(dir: &Path) -> Result<Ffi> {
    let msys_path = dir.join(MSYS_NAME);
    let engine_path = dir.join(DLL_NAME);
    if !msys_path.is_file() {
        return Err(CoreError::Internal(format!("{} not found beside engine", MSYS_NAME)));
    }
    if !engine_path.is_file() {
        return Err(CoreError::Internal(format!("{} not found", DLL_NAME)));
    }
    let msys_lib = Library::from_path(&msys_path)?;
    call_msys_init(&msys_lib)?;
    let engine_lib = Library::from_path(&engine_path)?;
    unsafe {
        Ok(Ffi {
            main_from_str: engine_lib.symbol(c"hev_socks5_tunnel_main_from_str")?,
            quit: engine_lib.symbol(c"hev_socks5_tunnel_quit")?,
            stats: engine_lib.symbol(c"hev_socks5_tunnel_stats")?,
            _libs: vec![msys_lib, engine_lib],
            _embedded: None,
        })
    }
}

fn load_embedded() -> Result<Ffi> {
    #[cfg(hev_dynamic)]
    {
        let embedded = EmbeddedFiles::stage(EMBEDDED).map_err(|e| CoreError::Internal(e.to_string()))?;
        let mut ffi = load_from_dir(embedded.directory())?;
        ffi._embedded = Some(embedded);
        Ok(ffi)
    }
    #[cfg(not(hev_dynamic))]
    {
        Err(CoreError::Internal("HEV Windows DLL not embedded in this build".into()))
    }
}

fn load() -> Result<Ffi> {
    if let Some(path) = std::env::var_os("FCAE_HEV_DLL") {
        let path = PathBuf::from(path);
        let file = if path.is_file() { path } else { return Err(CoreError::Internal(format!("FCAE_HEV_DLL points at {}, not a file", path.display()))); };
        let dir = file.parent().ok_or_else(|| CoreError::Internal("FCAE_HEV_DLL has no parent".into()))?;
        return load_from_dir(dir);
    }
    load_embedded()
}

pub fn unavailable_reason() -> Option<&'static str> {
    if !cfg!(all(hev_dynamic, wintun_staged)) {
        return Some("HEV Windows DLL or Wintun not embedded");
    }
    static REASON: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    let r = REASON.get_or_init(|| load().map(|_| ()).map_err(|e| e.to_string()));
    r.as_ref().err().map(|s| s.as_str())
}

pub fn is_supported() -> bool { unavailable_reason().is_none() }

fn ffi() -> Result<&'static Ffi> {
    static FFI: OnceLock<std::result::Result<Ffi, String>> = OnceLock::new();
    FFI.get_or_init(|| load().map_err(|e| {
        log::error!("[hev] {e}");
        e.to_string()
    })).as_ref().map_err(|e| CoreError::Internal(e.clone()))
}

struct Engine {
    thread: std::thread::JoinHandle<()>,
    rc: Arc<AtomicI32>,
}

struct Active {
    thread: std::thread::JoinHandle<()>,
    _psiphon: Option<socks5p::Adapter>,
    undo: Option<fcae_runtime::windows_tun::TunGuard>,
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
        let f = ffi().ok()?;
        let mut s = HevStats::default();
        unsafe { (f.stats)(&mut s.tx_packets, &mut s.tx_bytes, &mut s.rx_packets, &mut s.rx_bytes); }
        Some(s)
    }
    fn signal_stop(&self) -> bool {
        if !self.running.swap(false, Ordering::SeqCst) { return false; }
        if let Ok(f) = ffi() { unsafe { (f.quit)() }; true } else { false }
    }
    fn reap_locked(slot: &mut Option<Active>) -> bool {
        if slot.as_ref().is_some_and(|a| a.thread.is_finished()) {
            if let Some(done) = slot.take() {
                let _ = done.thread.join();
                if let Some(undo) = done.undo { fcae_runtime::windows_tun::restore_wrapper(undo); }
            }
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
        let config = std::ffi::CString::new(yaml).map_err(|_| CoreError::Internal("hev config contains NUL".into()))?;
        let dup = if fd >= 0 {
            let d = unsafe { libc::dup(fd) };
            if d < 0 { return Err(CoreError::Internal(format!("dup tun fd failed: {}", std::io::Error::last_os_error()))); }
            Some(d)
        } else { None };
        let running = self.running.clone();
        let closing = self.closing.clone();
        let rc = Arc::new(AtomicI32::new(0));
        let rc2 = rc.clone();
        self.running.store(true, Ordering::SeqCst);
        let thread = std::thread::Builder::new().name("hev-socks5-tunnel".into()).spawn(move || {
            let f = match ffi() {
                Ok(f) => f,
                Err(e) => {
                    log::error!("[hev] {e}");
                    running.store(false, Ordering::SeqCst);
                    rc2.store(-100, Ordering::SeqCst);
                    if let Some(d) = dup { unsafe { libc::close(d) }; }
                    return;
                }
            };
            let code = unsafe { (f.main_from_str)(config.as_bytes().as_ptr() as *const c_uchar, config.as_bytes().len() as c_uint, dup.unwrap_or(-1)) };
            if let Some(d) = dup { unsafe { libc::close(d) }; }
            running.store(false, Ordering::SeqCst);
            rc2.store(code, Ordering::SeqCst);
            if code != 0 && !closing.load(Ordering::SeqCst) { log::error!("[hev] engine exited code {code}"); }
        }).map_err(|e| {
            self.running.store(false, Ordering::SeqCst);
            if let Some(d) = dup { unsafe { libc::close(d) }; }
            CoreError::Internal(format!("spawn hev thread: {e}"))
        })?;
        Ok(Engine { thread, rc })
    }
}

impl TunBridge for HevSocks5TunnelBridge {
    fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<()> {
        fcae_runtime::windows_tun::validate_backend(cfg, endpoints.peer_ip.as_deref())?;
        if !is_supported() {
            return Err(CoreError::Internal(unavailable_reason().unwrap_or("hev unavailable").into()));
        }
        let _l = self.lifecycle.lock();
        if !self.reap(RESTART_GRACE) {
            return Err(CoreError::Internal("previous hev engine shutting down".into()));
        }
        self.closing.store(false, Ordering::SeqCst);
        crate::platform::ensure_wintun(crate::platform::wintun_bytes())?;
        let base_socks = endpoints.socks.ok_or_else(|| CoreError::Internal("TUN needs SOCKS endpoint".into()))?;
        let psiphon = if endpoints.psiphon_dns { Some(socks5p::Adapter::start(base_socks).map_err(|e| CoreError::Internal(format!("hev socks5p: {e}")))?) } else { None };
        let socks = psiphon.as_ref().map(|a| a.endpoint()).unwrap_or(base_socks);
        let fd = cfg.tun.fd.or_else(|| self.android_fd()).unwrap_or(-1);
        let (_, yaml) = generate_config(cfg, socks)?;
        let engine = self.spawn_engine(&yaml, fd)?;
        let exit_code = engine.rc.clone();
        *self.active.lock() = Some(Active { thread: engine.thread, _psiphon: psiphon, undo: None });
        let configured = (|| -> Result<()> {
            let undo = fcae_runtime::windows_tun::TunGuard::configure(cfg, endpoints.peer_ip.as_deref())?;
            self.active.lock().as_mut().ok_or_else(|| CoreError::Internal("HEV startup cancelled".into()))?.undo = Some(undo);
            if self.active.lock().as_ref().is_some_and(|a| a.thread.is_finished()) {
                return Err(CoreError::Internal(format!("hev exited during startup code {}", exit_code.load(Ordering::SeqCst))));
            }
            Ok(())
        })();
        if let Err(e) = configured {
            self.closing.store(true, Ordering::SeqCst);
            self.signal_stop();
            self.reap(RESTART_GRACE);
            return Err(e);
        }
        Ok(())
    }
    fn abort(&self) {
        let _l = self.lifecycle.lock();
        self.closing.store(true, Ordering::SeqCst);
        self.signal_stop();
        self.clear_android_fd();
    }
    fn stop(&self, timeout: Duration) {
        let _l = self.lifecycle.lock();
        self.closing.store(true, Ordering::SeqCst);
        self.signal_stop();
        if !self.reap(timeout) {
            log::warn!("[hev] engine did not stop within {timeout:?}");
            if let Some(active) = self.active.lock().as_mut() {
                if let Some(undo) = active.undo.take() { fcae_runtime::windows_tun::restore_wrapper(undo); }
            }
        }
        self.clear_android_fd();
    }
    fn preauthorised_fd(&self) -> Option<i32> { self.android_fd() }
    fn is_running(&self) -> bool { self.running.load(Ordering::SeqCst) }
    fn check_health(&self, _cfg: &SessionConfig) -> Result<()> {
        if !self.is_running() { return Err(CoreError::Internal("TUN engine stopped".into())); }
        self.active.lock().as_ref().and_then(|a| a.undo.as_ref()).map(|g| g.check_health()).transpose()?;
        Ok(())
    }
}