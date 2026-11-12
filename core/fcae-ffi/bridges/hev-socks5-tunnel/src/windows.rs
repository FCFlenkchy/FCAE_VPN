//! Windows backend: HEV is statically linked and runs in this process.
//! A dedicated call thread serializes quit/stats; each run gets its own thread.

use std::ffi::{c_int, c_uchar, c_uint, CString};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{mpsc, Arc, OnceLock};
use std::time::{Duration, Instant};

use fcae_runtime::backend::Endpoints;
use fcae_runtime::config::SessionConfig;
use fcae_runtime::error::{CoreError, Result};
use fcae_runtime::session::TunBridge;
use parking_lot::Mutex;

use fcae_runtime::socks5p;
use crate::{generate_config, run_engine, HevStats};

const RESTART_GRACE: Duration = Duration::from_secs(2);
const STATS_TIMEOUT: Duration = Duration::from_millis(250);

fn begin_run(running: &AtomicBool, closing: &AtomicBool) -> Result<()> {
    running.store(true, Ordering::SeqCst);
    if closing.load(Ordering::SeqCst) {
        running.store(false, Ordering::SeqCst);
        return Err(CoreError::Internal("TUN start cancelled (session is stopping)".into()));
    }
    Ok(())
}

type MainFn = unsafe extern "C" fn(*const c_uchar, c_uint, c_int) -> c_int;
type QuitFn = unsafe extern "C" fn();
type StatsFn = unsafe extern "C" fn(*mut usize, *mut usize, *mut usize, *mut usize);

#[cfg(hev_linked)]
extern "C" {
    fn hev_socks5_tunnel_main_from_str(config: *const c_uchar, len: c_uint, fd: c_int) -> c_int;
    fn hev_socks5_tunnel_quit();
    fn hev_socks5_tunnel_stats(tx_packets: *mut usize, tx_bytes: *mut usize, rx_packets: *mut usize, rx_bytes: *mut usize);
}

struct Ffi {
    main_from_str: MainFn,
    quit: QuitFn,
    stats: StatsFn,
}

enum Call {
    Quit,
    Stats(mpsc::SyncSender<HevStats>),
    Barrier(mpsc::SyncSender<()>),
}

struct Runtime {
    ffi: Ffi,
    calls: mpsc::Sender<Call>,
}

fn drain_calls(calls: &mpsc::Sender<Call>, enqueue: &Mutex<()>, timeout: Duration) -> Result<()> {
    let (reply, done) = mpsc::sync_channel(1);
    {
        // A stop that observed the previous run must enqueue its quit before
        // this barrier, even if that run has already exited.
        let _enqueue = enqueue.lock();
        calls.send(Call::Barrier(reply))
            .map_err(|_| CoreError::Internal("hev call thread stopped".into()))?;
    }
    done.recv_timeout(timeout)
        .map_err(|_| CoreError::Internal("hev calls from the previous run did not finish".into()))
}

static RUNTIME: OnceLock<std::result::Result<Runtime, String>> = OnceLock::new();

fn load() -> Result<Ffi> {
    #[cfg(hev_linked)]
    {
        Ok(Ffi {
            main_from_str: hev_socks5_tunnel_main_from_str,
            quit: hev_socks5_tunnel_quit,
            stats: hev_socks5_tunnel_stats,
        })
    }
    #[cfg(not(hev_linked))]
    {
        Err(CoreError::Internal("hev-socks5-tunnel not linked (stub build)".into()))
    }
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
            Call::Barrier(reply) => { let _ = reply.send(()); }
        }
    }
}

fn runtime() -> Result<&'static Runtime> {
    RUNTIME
        .get_or_init(|| {
            std::panic::catch_unwind(load)
                .unwrap_or_else(|_| Err(CoreError::Internal("initializing the hev runtime panicked".into())))
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

/// The runtime if a start already initialized it.
fn loaded() -> Option<&'static Runtime> {
    RUNTIME.get()?.as_ref().ok()
}

pub fn unavailable_reason() -> Option<&'static str> {
    if !cfg!(hev_linked) {
        Some("hev-socks5-tunnel not linked (stub build)")
    } else if !cfg!(wintun_staged) {
        Some("Wintun not embedded")
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
    enqueue: Mutex<()>,
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
            enqueue: Mutex::new(()),
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
    /// `quit` is queued to the call thread rather than called on the UI thread.
    fn signal_stop(&self) -> bool {
        let _enqueue = self.enqueue.lock();
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
        begin_run(&self.running, &self.closing)?;
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
        let rt = runtime()?;
        drain_calls(&rt.calls, &self.enqueue, RESTART_GRACE)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn barrier_waits_for_a_stop_enqueued_by_an_exiting_run() {
        let enqueue = Arc::new(Mutex::new(()));
        let (calls, queue) = mpsc::channel();
        let lock = enqueue.lock();
        let calls_for_barrier = calls.clone();
        let enqueue_for_barrier = enqueue.clone();
        let waiter = std::thread::spawn(move || {
            drain_calls(&calls_for_barrier, &enqueue_for_barrier, Duration::from_secs(2))
        });
        assert!(calls.send(Call::Quit).is_ok());
        drop(lock);
        assert!(matches!(queue.recv_timeout(Duration::from_secs(1)).unwrap(), Call::Quit));
        match queue.recv_timeout(Duration::from_secs(1)).unwrap() {
            Call::Barrier(reply) => { reply.send(()).unwrap(); }
            _ => panic!("barrier must follow quit"),
        }
        assert!(waiter.join().unwrap().is_ok());
    }

    #[test]
    fn barrier_fails_if_the_call_thread_is_stuck() {
        let (calls, _queue) = mpsc::channel();
        assert!(drain_calls(&calls, &Mutex::new(()), Duration::from_millis(5)).is_err());
    }

    #[test]
    fn cancelled_start_does_not_mark_engine_running() {
        let running = AtomicBool::new(false);
        let closing = AtomicBool::new(true);
        assert!(begin_run(&running, &closing).is_err());
        assert!(!running.load(Ordering::SeqCst));
        closing.store(false, Ordering::SeqCst);
        assert!(begin_run(&running, &closing).is_ok());
        assert!(running.load(Ordering::SeqCst));
    }
}
