//! Windows backend: the native MSVC engine DLL is hosted in this process.
//! Loading is lazy, a dedicated call thread serializes `quit`/`stats`, and each
//! engine run gets its own thread.

use std::ffi::{c_int, c_uchar, c_uint, CString};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{mpsc, Arc, OnceLock};
use std::time::{Duration, Instant};

use fcae_runtime::backend::Endpoints;
use fcae_runtime::config::SessionConfig;
use fcae_runtime::error::{CoreError, Result};
use fcae_runtime::session::TunBridge;
use fcae_runtime::windows_dll::{EmbeddedFiles, Library};
use parking_lot::Mutex;

use fcae_runtime::socks5p;
use crate::{generate_config, run_engine, HevStats};

const RESTART_GRACE: Duration = Duration::from_secs(2);
const STATS_TIMEOUT: Duration = Duration::from_millis(250);
const DLL_NAME: &str = "libhev-socks5-tunnel.dll";

#[cfg(hev_dynamic)]
const EMBEDDED: &[(&str, &[u8])] = include!(concat!(env!("OUT_DIR"), "/engine_files.rs"));

type MainFn = unsafe extern "C" fn(*const c_uchar, c_uint, c_int) -> c_int;
type QuitFn = unsafe extern "C" fn();
type StatsFn = unsafe extern "C" fn(*mut usize, *mut usize, *mut usize, *mut usize);

struct Ffi {
    main_from_str: MainFn,
    quit: QuitFn,
    stats: StatsFn,
    _engine: Library,
    _embedded: Option<EmbeddedFiles>,
}

enum Call {
    Quit,
    Stats(mpsc::SyncSender<HevStats>),
}

struct Runtime {
    ffi: Ffi,
    calls: mpsc::Sender<Call>,
}

static RUNTIME: OnceLock<std::result::Result<Runtime, String>> = OnceLock::new();

fn load_from_dir(dir: &Path) -> Result<Ffi> {
    let engine_path = dir.join(DLL_NAME);
    if !engine_path.is_file() {
        return Err(CoreError::Internal(format!("{DLL_NAME} not found")));
    }
    let engine = Library::from_path(&engine_path)?;
    unsafe {
        Ok(Ffi {
            main_from_str: engine.symbol(c"hev_socks5_tunnel_main_from_str")?,
            quit: engine.symbol(c"hev_socks5_tunnel_quit")?,
            stats: engine.symbol(c"hev_socks5_tunnel_stats")?,
            _engine: engine,
            _embedded: None,
        })
    }
}

fn load_embedded() -> Result<Ffi> {
    #[cfg(hev_dynamic)]
    {
        let embedded = EmbeddedFiles::stage("hev", EMBEDDED).map_err(|e| CoreError::Internal(e.to_string()))?;
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
        if !path.is_file() {
            return Err(CoreError::Internal(format!("FCAE_HEV_DLL points at {}, not a file", path.display())));
        }
        let dir = path.parent().ok_or_else(|| CoreError::Internal("FCAE_HEV_DLL has no parent".into()))?;
        return load_from_dir(dir);
    }
    load_embedded()
}

fn serve(queue: mpsc::Receiver<Call>, quit: QuitFn, stats: StatsFn) {
    for call in queue {
        match call {
            Call::Quit => unsafe { quit() },
            Call::Stats(reply) => {
                let mut s = HevStats::default();
                unsafe { stats(&mut s.tx_packets, &mut s.tx_bytes, &mut s.rx_packets, &mut s.rx_bytes) };
                let _ = reply.send(s);
            }
        }
    }
}

fn runtime() -> Result<&'static Runtime> {
    RUNTIME
        .get_or_init(|| {
            std::panic::catch_unwind(load)
                .unwrap_or_else(|_| Err(CoreError::Internal("loading the hev DLL panicked".into())))
                .and_then(|ffi| {
                    let (calls, queue) = mpsc::channel();
                    let (quit, stats) = (ffi.quit, ffi.stats);
                    std::thread::Builder::new()
                        .name("hev-calls".into())
                        .spawn(move || serve(queue, quit, stats))
                        .map_err(|e| CoreError::Internal(format!("cannot start the hev call thread: {e}")))?;
                    Ok(Runtime { ffi, calls })
                })
                .map_err(|e| {
                    log::error!("[hev] {e}");
                    e.to_string()
                })
        })
        .as_ref()
        .map_err(|e| CoreError::Internal(e.clone()))
}

/// The runtime if a start already loaded it; never triggers the load.
fn loaded() -> Option<&'static Runtime> {
    RUNTIME.get()?.as_ref().ok()
}

pub fn unavailable_reason() -> Option<&'static str> {
    // Keep UI capability checks passive; load the DLL on explicit session start.
    if !cfg!(all(hev_dynamic, wintun_staged)) {
        Some("HEV Windows DLL or Wintun not embedded")
    } else {
        None
    }
}

pub fn is_supported() -> bool { unavailable_reason().is_none() }

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
        let (reply, result) = mpsc::sync_channel(1);
        loaded()?.calls.send(Call::Stats(reply)).ok()?;
        result.recv_timeout(STATS_TIMEOUT).ok()
    }
    /// Non-blocking: `quit` is queued to the call thread.
    fn signal_stop(&self) -> bool {
        if !self.running.swap(false, Ordering::SeqCst) { return false; }
        loaded().is_some_and(|rt| rt.calls.send(Call::Quit).is_ok())
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
    fn shutdown(&self, timeout: Duration) {
        self.closing.store(true, Ordering::SeqCst);
        self.signal_stop();
        if !self.reap(timeout) {
            log::warn!("[hev] engine did not stop within {timeout:?}");
            if let Some(active) = self.active.lock().as_mut() {
                if let Some(undo) = active.undo.take() { fcae_runtime::windows_tun::restore_wrapper(undo); }
            }
        }
    }
    /// The engine's exit status once its thread is gone, as a start error.
    fn exited(&self, rc: &AtomicI32) -> Option<CoreError> {
        self.active.lock().as_ref().is_some_and(|a| a.thread.is_finished())
            .then(|| CoreError::Internal(format!("hev exited during startup code {}", rc.load(Ordering::SeqCst))))
    }
    /// Runs the engine on a dedicated thread.
    fn spawn_engine(&self, rt: &'static Runtime, yaml: &str) -> Result<Engine> {
        let config = CString::new(yaml).map_err(|_| CoreError::Internal("hev config contains NUL".into()))?;
        let entry = rt.ffi.main_from_str;
        let running = self.running.clone();
        let closing = self.closing.clone();
        let rc = Arc::new(AtomicI32::new(0));
        let rc_thread = rc.clone();
        self.running.store(true, Ordering::SeqCst);
        let thread = std::thread::Builder::new().name("hev-socks5-tunnel".into()).spawn(move || {
            let bytes = config.as_bytes();
            let code = run_engine(&closing, || unsafe { entry(bytes.as_ptr(), bytes.len() as c_uint, -1) });
            running.store(false, Ordering::SeqCst);
            rc_thread.store(code, Ordering::SeqCst);
            if code != 0 && !closing.load(Ordering::SeqCst) { log::error!("[hev] engine exited code {code}"); }
        }).map_err(|e| {
            self.running.store(false, Ordering::SeqCst);
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
        // Resolve the native bridge before changing engine state or spawning a
        // worker so a missing/incompatible DLL becomes a normal start error.
        let rt = runtime()?;
        let base_socks = endpoints.socks.ok_or_else(|| CoreError::Internal("TUN needs SOCKS endpoint".into()))?;
        let psiphon = if endpoints.psiphon_dns {
            let resolvers = fcae_runtime::tun_dns::psiphon_resolvers(cfg)?;
            Some(socks5p::Adapter::start("hev", base_socks, resolvers).map_err(|e| CoreError::Internal(format!("hev socks5p: {e}")))?)
        } else { None };
        let socks = psiphon.as_ref().map(|a| a.endpoint()).unwrap_or(base_socks);
        let (_, yaml) = generate_config(cfg, socks)?;
        let engine = self.spawn_engine(rt, &yaml)?;
        let exit_code = engine.rc;
        *self.active.lock() = Some(Active { thread: engine.thread, _psiphon: psiphon, undo: None });
        let configured = (|| -> Result<()> {
            let undo = fcae_runtime::windows_tun::TunGuard::configure(cfg, endpoints.peer_ip.as_deref())
                .map_err(|e| self.exited(&exit_code).unwrap_or(e))?;
            self.active.lock().as_mut().ok_or_else(|| CoreError::Internal("HEV startup cancelled".into()))?.undo = Some(undo);
            if let Some(e) = self.exited(&exit_code) { return Err(e); }
            if self.closing.load(Ordering::SeqCst) {
                return Err(CoreError::Internal("TUN start cancelled (session is stopping)".into()));
            }
            Ok(())
        })();
        if let Err(e) = configured {
            self.shutdown(RESTART_GRACE);
            return Err(e);
        }
        Ok(())
    }
    /// Lock-free so a Disconnect never waits behind a start that is still
    /// bringing the adapter up; that start sees `closing` and unwinds itself.
    fn abort(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.signal_stop();
        self.clear_android_fd();
    }
    fn stop(&self, timeout: Duration) {
        let _l = self.lifecycle.lock();
        self.shutdown(timeout);
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
