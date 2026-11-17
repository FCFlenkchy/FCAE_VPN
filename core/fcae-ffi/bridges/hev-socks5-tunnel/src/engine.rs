//! The HEV engine host — one implementation for every platform; `cfg` appears
//! only where the platforms genuinely differ.
//!
//! * Windows drives the in-process C engine through a call thread (`hev-calls`)
//!   that serializes `quit`/`stats`, and protects the existing Wintun adapter
//!   with `windows_tun::TunGuard`. The thread belongs to one run: it is created
//!   with it and joined with it, so a stopped session leaves no thread, no
//!   channel and no native handle behind.
//! * Unix hands the engine an fd (Android fd or its own device) and applies
//!   host addresses/routes/DNS through `unix_tun::TunGuard` on Linux/macOS.
//!
//! Both share the lifecycle machinery: reaping, the generation latch for the
//! deferred-cleanup thread, the stop/abort paths and the wait-for-cleanup
//! contract the supervisor relies on across engine switches.

use std::ffi::{c_int, c_uchar, c_uint, CString};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::sync::{mpsc, OnceLock};

use fcae_runtime::backend::Endpoints;
use fcae_runtime::config::SessionConfig;
use fcae_runtime::error::{CoreError, Result};
use fcae_runtime::session::TunBridge;
use fcae_runtime::socks5p;
use parking_lot::Mutex;

use crate::{generate_config, run_engine, HevStats};

const RESTART_GRACE: Duration = Duration::from_secs(2);
/// Poll interval while waiting for the engine thread to exit; the caller's
/// deadline is what bounds the loop.
const REAP_POLL: Duration = Duration::from_millis(5);
#[cfg(windows)]
const STATS_TIMEOUT: Duration = Duration::from_millis(250);

#[cfg(hev_linked)]
extern "C" {
    fn hev_socks5_tunnel_main_from_str(config: *const c_uchar, len: c_uint, fd: c_int) -> c_int;
    fn hev_socks5_tunnel_quit();
    fn hev_socks5_tunnel_stats(tx_packets: *mut usize, tx_bytes: *mut usize, rx_packets: *mut usize, rx_bytes: *mut usize);
}

#[cfg(not(hev_linked))]
mod stub {
    use std::ffi::{c_int, c_uchar, c_uint};
    pub unsafe fn hev_socks5_tunnel_main_from_str(_config_str: *const c_uchar, _config_len: c_uint, _tun_fd: c_int) -> c_int { -100 }
    pub fn hev_socks5_tunnel_quit() {}
    pub fn hev_socks5_tunnel_stats(_tx_packets: *mut usize, _tx_bytes: *mut usize, _rx_packets: *mut usize, _rx_bytes: *mut usize) {}
}

// --- Direct in-process calls (non-Windows) -----------------------------------

#[cfg(not(windows))]
unsafe fn engine_main_from_str(config_str: *const c_uchar, config_len: c_uint, tun_fd: c_int) -> c_int {
    #[cfg(hev_linked)]
    { hev_socks5_tunnel_main_from_str(config_str, config_len, tun_fd) }
    #[cfg(not(hev_linked))]
    { stub::hev_socks5_tunnel_main_from_str(config_str, config_len, tun_fd) }
}

#[cfg(not(windows))]
fn engine_quit() -> bool {
    #[cfg(hev_linked)]
    { unsafe { hev_socks5_tunnel_quit() }; true }
    #[cfg(not(hev_linked))]
    { stub::hev_socks5_tunnel_quit(); true }
}

#[cfg(not(windows))]
unsafe fn engine_stats(tx_packets: *mut usize, tx_bytes: *mut usize, rx_packets: *mut usize, rx_bytes: *mut usize) -> bool {
    #[cfg(hev_linked)]
    { hev_socks5_tunnel_stats(tx_packets, tx_bytes, rx_packets, rx_bytes); true }
    #[cfg(not(hev_linked))]
    { stub::hev_socks5_tunnel_stats(tx_packets, tx_bytes, rx_packets, rx_bytes); true }
}

// --- Serialized call thread (Windows) ----------------------------------------

#[cfg(windows)]
type MainFn = unsafe extern "C" fn(*const c_uchar, c_uint, c_int) -> c_int;
#[cfg(windows)]
type QuitFn = unsafe extern "C" fn();
#[cfg(windows)]
type StatsFn = unsafe extern "C" fn(*mut usize, *mut usize, *mut usize, *mut usize);

#[cfg(windows)]
#[derive(Clone, Copy)]
struct Ffi {
    main_from_str: MainFn,
    quit: QuitFn,
    stats: StatsFn,
}

#[cfg(windows)]
enum Call {
    Quit,
    Stats(mpsc::SyncSender<HevStats>),
}

/// The engine's entry points, loaded once. Function pointers only: no thread,
/// no channel, nothing that could outlive a run.
#[cfg(windows)]
static FFI: OnceLock<std::result::Result<Ffi, String>> = OnceLock::new();

#[cfg(windows)]
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

#[cfg(windows)]
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

#[cfg(windows)]
fn ffi() -> Result<Ffi> {
    FFI.get_or_init(|| {
        std::panic::catch_unwind(load)
            .unwrap_or_else(|_| Err(CoreError::Internal("initializing the hev runtime panicked".into())))
            .map_err(|e| {
                log::error!("[hev] {e}");
                e.to_string()
            })
    })
    .as_ref()
    .map(|engine| *engine)
    .map_err(|error| CoreError::Internal(error.clone()))
}

/// The call thread of one run.
///
/// `quit` and `stats` are native calls that must not run on the UI thread and
/// must not run on the engine's own thread either, so they are handed to this
/// one. It exists exactly as long as the run it serves: a thread for the whole
/// process -- parked on a channel only a static could feed -- was a thread, its
/// stack and its channel left behind by every session that ever used HEV, after
/// the engine it was started for had already been closed.
#[cfg(windows)]
struct Calls {
    /// `None` once the thread has been released; dropping it is what ends the
    /// thread's loop.
    sender: Option<mpsc::Sender<Call>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(windows)]
impl Calls {
    fn spawn(engine: Ffi) -> Result<Self> {
        let (sender, queue) = mpsc::channel();
        let (quit, stats) = (engine.quit, engine.stats);
        let thread = std::thread::Builder::new()
            .name("hev-calls".into())
            .spawn(move || serve(queue, quit, stats))
            .map_err(|e| CoreError::Internal(format!("cannot start the hev call thread: {e}")))?;
        Ok(Self { sender: Some(sender), thread: Some(thread) })
    }

    fn send(&self, call: Call) -> bool {
        self.sender.as_ref().is_some_and(|sender| sender.send(call).is_ok())
    }

    /// Close the channel and wait for the thread to drain what is queued.
    ///
    /// The drain is the point: a `quit` that is still in flight is a native
    /// call the *next* run must not inherit, which is why the join, not the
    /// send, is what makes a stop complete.
    fn finish(&mut self) {
        self.sender = None;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(windows)]
impl Drop for Calls {
    fn drop(&mut self) {
        self.finish();
    }
}

// --- Shared surface -----------------------------------------------------------

pub fn unavailable_reason() -> Option<&'static str> {
    if !cfg!(hev_linked) {
        Some("hev-socks5-tunnel not linked (stub build)")
    } else if cfg!(windows) && !fcae_runtime::wintun::WINTUN_AVAILABLE {
        Some("Wintun not embedded")
    } else {
        None
    }
}

pub fn is_supported() -> bool { unavailable_reason().is_none() }

/// Claim the engine as running unless a stop is already in flight.
fn begin_run(running: &AtomicBool, closing: &AtomicBool) -> Result<()> {
    running.store(true, Ordering::SeqCst);
    if closing.load(Ordering::SeqCst) {
        running.store(false, Ordering::SeqCst);
        return Err(CoreError::Internal("TUN start cancelled (session is stopping)".into()));
    }
    Ok(())
}

struct Engine {
    thread: std::thread::JoinHandle<()>,
    rc: Arc<AtomicI32>,
    /// The run's call thread, handed to the active run so it is released with
    /// it. Dropped here when the start fails before one exists.
    #[cfg(windows)]
    calls: Option<Calls>,
}

struct Active {
    generation: Arc<()>,
    reaping: bool,
    thread: std::thread::JoinHandle<()>,
    /// The run's call thread; released with this run, never before it and never
    /// after it.
    #[cfg(windows)]
    calls: Option<Calls>,
    _psiphon: Option<socks5p::Adapter>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    _host: Option<fcae_runtime::unix_tun::TunGuard>,
    #[cfg(windows)]
    undo: Option<fcae_runtime::windows_tun::TunGuard>,
    log_relay: Option<crate::LogRelay>,
}

/// hev addresses and raises its own device but never touches routes or DNS,
/// so desktop sessions apply them once the device is up.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn configure_host(cfg: &SessionConfig, peer_ip: Option<&str>, #[cfg_attr(target_os = "linux", allow(unused_variables))] before: &[String]) -> Result<fcae_runtime::unix_tun::TunGuard> {
    const BUDGET: Duration = Duration::from_secs(3);
    #[cfg(target_os = "linux")]
    let device = fcae_runtime::unix_tun::wait_for_device(&cfg.tun.name, true, BUDGET).then(|| cfg.tun.name.clone());
    #[cfg(target_os = "macos")]
    let device = fcae_runtime::unix_tun::wait_for_new_utun(before, BUDGET);
    let device = device.ok_or_else(|| CoreError::Internal("hev-socks5-tunnel did not bring its TUN device up".into()))?;
    fcae_runtime::unix_tun::TunGuard::configure(cfg, &device, peer_ip, false)
}

pub struct HevSocks5TunnelBridge {
    lifecycle: Mutex<()>,
    active: Arc<Mutex<Option<Active>>>,
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
            active: Arc::new(Mutex::new(None)),
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
        #[cfg(not(windows))]
        {
            let mut stats = HevStats::default();
            let ok = unsafe { engine_stats(&mut stats.tx_packets, &mut stats.tx_bytes, &mut stats.rx_packets, &mut stats.rx_bytes) };
            ok.then_some(stats)
        }
        #[cfg(windows)]
        {
            // The sender is cloned out from under the lock: the wait for the
            // answer must not hold up a start or a stop of the same run.
            let (reply, result) = mpsc::sync_channel(1);
            let sender = {
                let active = self.active.lock();
                active.as_ref()?.calls.as_ref()?.sender.clone()?
            };
            sender.send(Call::Stats(reply)).ok()?;
            result.recv_timeout(STATS_TIMEOUT).ok()
        }
    }

    /// The engine's quit request. Non-Windows calls in place; Windows queues
    /// the call to the run's own call thread so it never runs on the UI thread.
    fn signal_stop(&self) -> bool {
        if !self.running.swap(false, Ordering::SeqCst) { return false; }
        #[cfg(not(windows))]
        { engine_quit() }
        #[cfg(windows)]
        {
            log::info!("[tun:hev] down");
            // A run that was already reaped has no call thread left, and
            // nothing of it left to quit either.
            let active = self.active.lock();
            active.as_ref().is_some_and(|run| run.calls.as_ref().is_some_and(|calls| calls.send(Call::Quit)))
        }
    }

    /// Send the run's quit through its own call thread when the run is still
    /// alive. Idempotent on the engine side, so a second stop of the same run
    /// costs one native call and never a stuck teardown.
    #[cfg(windows)]
    fn quit_if_live(&self) {
        let active = self.active.lock();
        let Some(run) = active.as_ref() else { return };
        if run.thread.is_finished() { return; }
        if let Some(calls) = run.calls.as_ref() {
            calls.send(Call::Quit);
        }
    }

    fn reap_locked(slot: &mut Option<Active>) -> bool {
        if slot.as_ref().is_some_and(|a| a.thread.is_finished()) {
            if let Some(done) = slot.take() {
                let _ = done.thread.join();
                #[cfg(windows)]
                if let Some(undo) = done.undo {
                    fcae_runtime::windows_tun::restore_wrapper(undo);
                }
                if let Some(relay) = done.log_relay { relay.shutdown(); }
            }
        }
        slot.is_none()
    }

    fn reap(&self, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        loop {
            if Self::reap_locked(&mut self.active.lock()) { return true; }
            if Instant::now() >= deadline { return false; }
            std::thread::sleep(REAP_POLL);
        }
    }

    fn shutdown(&self, timeout: Duration) {
        self.closing.store(true, Ordering::SeqCst);
        self.signal_stop();
        // A stop that raced the start cleared `running` before the run had a
        // call thread to send its quit to, so `signal_stop` had nothing to send
        // to. The run is up now and owes its quit just the same.
        #[cfg(windows)]
        self.quit_if_live();
        if !self.reap(timeout) {
            log::warn!("[hev] engine did not stop within {timeout:?}; cleanup is deferred until it exits");
            self.reap_later();
        }
    }

    /// The engine's exit status once its thread is gone, as a start error.
    fn exited(&self, rc: &AtomicI32) -> Option<CoreError> {
        self.active.lock().as_ref().is_some_and(|a| a.thread.is_finished())
            .then(|| CoreError::Internal(format!("hev-socks5-tunnel exited during startup (code {})", rc.load(Ordering::SeqCst))))
    }

    /// Block a later TUN start until the previous HEV run and its host
    /// configuration have both been released, including across engine switches.
    pub fn wait_for_cleanup(&self) -> Result<()> {
        let _lifecycle = self.lifecycle.lock();
        if self.reap(RESTART_GRACE) {
            Ok(())
        } else {
            Err(CoreError::Internal("previous HEV engine is still shutting down".into()))
        }
    }

    fn reap_later(&self) {
        let generation = {
            let mut active = self.active.lock();
            let Some(run) = active.as_mut() else { return; };
            if run.reaping { return; }
            run.reaping = true;
            run.generation.clone()
        };
        let active = self.active.clone();
        let worker_generation = generation.clone();
        if let Err(error) = std::thread::Builder::new().name("hev-reaper".into()).spawn(move || {
            loop {
                {
                    let mut slot = active.lock();
                    match slot.as_ref() {
                        Some(run) if Arc::ptr_eq(&run.generation, &worker_generation) => {
                            if Self::reap_locked(&mut slot) { return; }
                        }
                        _ => return,
                    }
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }) {
            let mut active = self.active.lock();
            if let Some(run) = active.as_mut().filter(|run| Arc::ptr_eq(&run.generation, &generation)) {
                run.reaping = false;
            }
            log::error!("[hev] cannot start cleanup thread: {error}; cleanup will be retried on the next stop or start");
        }
    }

    /// Runs the engine on a dedicated thread. Unix passes a dup of the TUN fd
    /// (or -1 to let the engine create its own device); Windows passes -1 and
    /// reaches the engine through the call thread.
    fn spawn_engine(&self, yaml: &str, fd: i32) -> Result<Engine> {
        let config = CString::new(yaml).map_err(|_| CoreError::Internal("hev-socks5-tunnel config contains a NUL byte".into()))?;
        #[cfg(not(windows))]
        let dup = if fd >= 0 {
            let dup = unsafe { libc::dup(fd) };
            if dup < 0 { return Err(CoreError::Internal(format!("dup(tun fd {fd}) failed: {}", std::io::Error::last_os_error()))); }
            Some(dup)
        } else { None };
        // The call thread is created before the engine thread: `quit` has to be
        // deliverable from the very first instant the native engine exists,
        // including a stop that arrives while this start is still running.
        #[cfg(windows)]
        let (entry, calls) = {
            let _ = fd;
            let engine = ffi()?;
            (engine.main_from_str, Calls::spawn(engine)?)
        };
        let running = self.running.clone();
        let closing = self.closing.clone();
        let rc = Arc::new(AtomicI32::new(0));
        let rc_thread = rc.clone();
        begin_run(&self.running, &self.closing)?;
        let thread = std::thread::Builder::new().name("hev-socks5-tunnel".into()).spawn(move || {
            let bytes = config.as_bytes();
            #[cfg(not(windows))]
            let code = run_engine(&closing, || unsafe { engine_main_from_str(bytes.as_ptr(), bytes.len() as c_uint, dup.unwrap_or(-1)) });
            #[cfg(windows)]
            let code = {
                log::info!("[hev] entering native engine");
                let code = run_engine(&closing, || unsafe { entry(bytes.as_ptr(), bytes.len() as c_uint, -1) });
                log::info!("[hev] native engine returned code {code}");
                code
            };
            #[cfg(not(windows))]
            if let Some(dup) = dup { unsafe { libc::close(dup) }; }
            running.store(false, Ordering::SeqCst);
            rc_thread.store(code, Ordering::SeqCst);
            if code != 0 && !closing.load(Ordering::SeqCst) { log::error!("[hev] engine exited with code {code}"); }
        }).map_err(|e| {
            self.running.store(false, Ordering::SeqCst);
            #[cfg(not(windows))]
            if let Some(dup) = dup { unsafe { libc::close(dup) }; }
            CoreError::Internal(format!("cannot spawn the hev-socks5-tunnel engine thread: {e}"))
        })?;
        Ok(Engine {
            thread,
            rc,
            #[cfg(windows)]
            calls: Some(calls),
        })
    }
}

impl TunBridge for HevSocks5TunnelBridge {
    fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<()> {
        #[cfg(windows)]
        {
            log::info!("[hev] validating Windows TUN settings");
            fcae_runtime::windows_tun::validate_backend(cfg, endpoints.peer_ip.as_deref())?;
        }
        if !is_supported() {
            #[cfg(windows)]
            return Err(CoreError::Internal(unavailable_reason().unwrap_or("hev unavailable").into()));
            #[cfg(not(windows))]
            return Err(CoreError::Internal("hev-socks5-tunnel is not available in this build".into()));
        }
        let _lifecycle = self.lifecycle.lock();
        if !self.reap(RESTART_GRACE) {
            return Err(CoreError::Internal("the previous hev-socks5-tunnel engine is still shutting down".into()));
        }
        self.closing.store(false, Ordering::SeqCst);
        #[cfg(windows)]
        {
            log::info!("[hev] loading Wintun");
            fcae_runtime::windows_dll::ensure_wintun(fcae_runtime::wintun::wintun_bytes())?;
            log::info!("[hev] Wintun loaded; preparing native engine");
        }
        // Psiphon exits dial through a loopback socks5p adapter so the engine
        // never sees a UDP ASSOCIATE (0x03) it cannot serve; DNS rides the
        // engine's UDP gateway instead.
        let (psiphon_adapter, socks) = fcae_runtime::exit_adapter::psiphon_socks5p(cfg, endpoints, "hev")?;
        let fd = cfg.tun.fd.or_else(|| self.android_fd()).unwrap_or(-1);
        #[cfg(windows)]
        // HEV can only create its adapter (it always passes the shared requested
        // GUID); Wintun keeps one persistent device identity for that GUID, so
        // the shared adapter is reused when it exists and created otherwise.
        // The host-side guard resolves the adapter by GUID first.
        log::info!("[tun:hev] using shared Wintun adapter '{}' (GUID {})", cfg.tun.name, fcae_runtime::config::WINTUN_ADAPTER_GUID);
        let (_, yaml) = generate_config(cfg, socks)?;
        #[cfg(target_os = "macos")]
        let before = fcae_runtime::unix_tun::utun_devices();
        #[cfg(target_os = "linux")]
        let before = Vec::new();
        let engine = self.spawn_engine(&yaml, fd)?;
        let exit_code = engine.rc;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let (host, configured) = match (fd < 0).then(|| configure_host(cfg, endpoints.peer_ip.as_deref(), &before)).transpose() {
            Ok(host) => (host, Ok(())),
            Err(error) => (None, Err(error)),
        };
        #[cfg(all(not(any(target_os = "linux", target_os = "macos")), not(windows)))]
        let configured: Result<()> = Ok(());
        let log_relay = crate::relay_engine_log(cfg.tun.t2s_log_level);
        *self.active.lock() = Some(Active {
            generation: Arc::new(()),
            reaping: false,
            thread: engine.thread,
            #[cfg(windows)]
            calls: engine.calls,
            _psiphon: psiphon_adapter,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            _host: host,
            #[cfg(windows)]
            undo: None,
            log_relay,
        });
        #[cfg(windows)]
        // Windows needs the guard stashed on the active run so `stop` restores
        // routes/DNS even when the engine is already gone; the undo slot exists
        // only after Active does, hence the split from the Unix path above.
        let configured: Result<()> = (|| {
            log::info!("[hev] configuring Windows TUN networking");
            let undo = fcae_runtime::windows_tun::TunGuard::configure(cfg, endpoints.peer_ip.as_deref())
                .map_err(|e| self.exited(&exit_code).unwrap_or(e))?;
            self.active.lock().as_mut().ok_or_else(|| CoreError::Internal("HEV startup cancelled".into()))?.undo = Some(undo);
            if let Some(e) = self.exited(&exit_code) { return Err(e); }
            if self.closing.load(Ordering::SeqCst) {
                return Err(CoreError::Internal("TUN start cancelled (session is stopping)".into()));
            }
            Ok(())
        })();
        let outcome = if let Some(e) = self.exited(&exit_code) {
            Err(e)
        } else if configured.is_ok() && self.closing.load(Ordering::SeqCst) {
            Err(CoreError::Internal("TUN start cancelled (session is stopping)".into()))
        } else {
            configured
        };
        if outcome.is_err() {
            self.shutdown(RESTART_GRACE);
        }
        #[cfg(windows)]
        if outcome.is_ok() {
            log::info!("[tun:hev] up (socks {}, mtu {})", socks, cfg.tun.mtu);
        }
        outcome
    }

    /// Lock-free so a Disconnect never waits behind a start that is still
    /// bringing the adapter up; that start sees `closing` and unwinds itself.
    fn abort(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.signal_stop();
        self.clear_android_fd();
    }

    fn stop(&self, timeout: Duration) {
        let _lifecycle = self.lifecycle.lock();
        self.shutdown(timeout);
        self.clear_android_fd();
    }

    fn preauthorised_fd(&self) -> Option<i32> { self.android_fd() }
    fn is_running(&self) -> bool { self.running.load(Ordering::SeqCst) }

    fn check_health(&self, _cfg: &SessionConfig) -> Result<()> {
        if !self.is_running() { return Err(CoreError::Internal("TUN engine stopped unexpectedly".into())); }
        #[cfg(windows)]
        self.active.lock().as_ref().and_then(|a| a.undo.as_ref()).map(|g| g.check_health()).transpose()?;
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    unsafe extern "C" fn no_main(_: *const c_uchar, _: c_uint, _: c_int) -> c_int { 0 }
    unsafe extern "C" fn no_quit() {}
    unsafe extern "C" fn no_stats(_: *mut usize, _: *mut usize, _: *mut usize, _: *mut usize) {}

    fn test_engine() -> Ffi {
        Ffi { main_from_str: no_main, quit: no_quit, stats: no_stats }
    }

    #[test]
    fn the_call_thread_ends_with_the_run_it_serves() {
        let mut calls = Calls::spawn(test_engine()).expect("call thread spawns");
        assert!(calls.send(Call::Quit), "a live run takes its quit");
        calls.finish();
        assert!(!calls.send(Call::Quit), "a released call thread takes nothing");
        assert!(calls.thread.is_none(), "finish joins the thread");
    }

    #[test]
    fn stats_reach_the_run_through_its_call_thread() {
        let mut calls = Calls::spawn(test_engine()).expect("call thread spawns");
        let (reply, answer) = mpsc::sync_channel(1);
        assert!(calls.send(Call::Stats(reply)));
        assert!(answer.recv_timeout(Duration::from_secs(1)).is_ok());
        calls.finish();
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
