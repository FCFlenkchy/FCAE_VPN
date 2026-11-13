//! Session supervisor.
//!
//! Owns the tokio runtime thread and the strict teardown order that the old
//! FFI implemented by scattering `catch_unwind` blocks, detached PowerShell
//! threads and duplicate cleanups across three files:
//!
//! 1. stop the TUN bridge (so no packets are in flight),
//! 2. stop the backend (sockets, engine threads),
//! 3. run OS-level cleanup (routes/DNS) exactly once,
//! 4. shut the runtime down.
//!
//! Because tun2socks is now in-process, step 1 is a function call and a join
//! rather than `taskkill`/`SIGKILL` plus a hopeful sleep.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use fcae_abi::{FcaeBackend, FcaeMode, FcaeProtocol, FcaeState, FcaeTorMode};
use parking_lot::Mutex;

use crate::backend::{BackendContext, BackendHandle, CancelToken, Endpoints};
use crate::config::{ChainHop, SessionConfig};
use crate::error::{CoreError, Result};
use crate::registry;
use crate::telemetry::{TelemetryCell, TelemetrySink};

/// Grace period after a TUN pause/resume during which health checks are
/// skipped. The device is being torn down or rebuilt and the platform routes
/// are moving with it, so a probe inside this window says nothing about the
/// tunnel that carries it. Pausing the data plane must never be able to end
/// the session -- that is what a stop/start button in TUN mode means.
const TUN_SETTLE: Duration = Duration::from_secs(5);
/// Consecutive failed health ticks before the TUN data plane counts as dead.
/// One failure is a rebuild in flight, not a dropped tunnel; a device that is
/// really gone fails every tick and still reconnects within a few seconds.
const TUN_HEALTH_FAIL_TICKS: u32 = 3;
/// How often the session samples the carrier's link state while chained.
const CARRIER_POLL: Duration = Duration::from_millis(500);
/// Margin past the chained Psiphon backend's own start deadline.
const CHAIN_START_GRACE: Duration = Duration::from_secs(10);

/// Hook that raises a TUN device on top of a backend's SOCKS endpoint.
///
/// The supervisor stays independent of the tun2socks bridge crate (which
/// links Go code) so `fcae-runtime` remains pure Rust and unit-testable; the
/// `fcae-ffi` crate installs the real implementation.
pub trait TunBridge: Send + Sync {
    /// Start forwarding TUN traffic into `endpoints.socks`.
    fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<()>;
    /// Start against the owning session's cancellation token.
    fn start_cancellable(&self, cfg: &SessionConfig, endpoints: &Endpoints, cancel: &CancelToken) -> Result<()> {
        if cancel.is_cancelled() {
            return Err(CoreError::Internal("TUN start cancelled (session is stopping)".into()));
        }
        self.start(cfg, endpoints)
    }
    /// Stop forwarding and release the device. Must be idempotent.
    fn stop(&self, timeout: Duration);
    /// Drop the TUN fds immediately. Must not wait on the data-plane engine.
    ///
    /// Default calls [`stop`] with a zero timeout. Bridges whose `stop`
    /// waits on a Go mutex (tun2socks `engine.Start`) must override this so
    /// notification Disconnect can tear the kernel interface down in
    /// microseconds.
    fn abort(&self) {
        self.stop(Duration::ZERO);
    }
    /// True if a device is currently up.
    fn is_running(&self) -> bool;

    fn check_health(&self, _cfg: &SessionConfig) -> Result<()> { Ok(()) }

    /// A TUN fd the platform already created and handed to us, if any.
    ///
    /// Android's VpnService creates the interface in the JVM and passes the
    /// descriptor down, which IS the authorisation to run TUN mode -- there is
    /// no elevation to acquire and `geteuid() == 0` is never true for an app.
    /// Bridges that create the device themselves keep the default of `None`.
    fn preauthorised_fd(&self) -> Option<i32> {
        None
    }
}

/// A no-op bridge used when the build has no TUN support (or in tests).
pub struct NullTunBridge;

impl TunBridge for NullTunBridge {
    fn start(&self, _cfg: &SessionConfig, _e: &Endpoints) -> Result<()> {
        Err(CoreError::Internal(
            "TUN mode requested but no TUN bridge is installed in this build".into(),
        ))
    }
    fn stop(&self, _timeout: Duration) {}
    fn is_running(&self) -> bool {
        false
    }
}

/// Platform privilege probe, injected for the same reason as `TunBridge`.
pub type PrivilegeCheck = fn() -> bool;

pub struct SupervisorConfig {
    pub tun_bridge: Arc<dyn TunBridge>,
    pub is_privileged: PrivilegeCheck,
    /// Bounded wait for the backend to release resources on stop.
    pub stop_timeout: Duration,
    /// Automatically re-dial when the tunnel drops.
    pub auto_reconnect: bool,
    /// Give up after this many consecutive failed reconnects (0 = never).
    pub max_reconnects: u32,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            tun_bridge: Arc::new(NullTunBridge),
            is_privileged: || true,
            // 2s was too short: a cancelled start still has to abort the
            // engine task and shut the runtime down, and dropping the
            // JoinHandle instead leaked that work into a later connect
            // (crash / "address already in use").
            stop_timeout: Duration::from_millis(250),
            auto_reconnect: true,
            max_reconnects: 0,
        }
    }
}

struct Running {
    cancel: CancelToken,
    thread: std::thread::JoinHandle<()>,
}

/// Snapshot the session thread publishes so [`Supervisor::resume_tun`] can
/// restart the data plane without cancelling the backend.
#[derive(Clone)]
struct LiveTun {
    config: SessionConfig,
    endpoints: Endpoints,
}

/// The single live session.
pub struct Supervisor {
    cfg: SupervisorConfig,
    telemetry: Arc<TelemetryCell>,
    running: Mutex<Option<Running>>,
    /// Set while a stop is in progress so a concurrent start waits rather
    /// than racing the teardown. Arc so a timed-out join can still clear it
    /// from the reaper thread once the session actually exits.
    stopping: Arc<AtomicBool>,
    /// TUN data plane is down while the session/backend stay up (Android
    /// notification Stop). Resume re-raises TUN on the stored endpoints.
    tun_paused: Arc<AtomicBool>,
    tun_control: Arc<Mutex<()>>,
    live_tun: Arc<Mutex<Option<LiveTun>>>,
    /// Deadline of the current TUN transition window ([`TUN_SETTLE`]); health
    /// checks stay out of it so a rebuild cannot be mistaken for a drop.
    tun_settle: Arc<Mutex<Option<std::time::Instant>>>,
}

impl Supervisor {
    pub fn new(telemetry: Arc<TelemetryCell>, cfg: SupervisorConfig) -> Self {
        Self {
            cfg,
            telemetry,
            running: Mutex::new(None),
            stopping: Arc::new(AtomicBool::new(false)),
            tun_paused: Arc::new(AtomicBool::new(false)),
            tun_control: Arc::new(Mutex::new(())),
            live_tun: Arc::new(Mutex::new(None)),
            tun_settle: Arc::new(Mutex::new(None)),
        }
    }

    /// Open (or extend) the transition window that keeps TUN health checks
    /// quiet while the data plane is being rebuilt.
    fn hold_tun_settle(&self) {
        *self.tun_settle.lock() = Some(std::time::Instant::now() + TUN_SETTLE);
    }

    pub fn telemetry(&self) -> &Arc<TelemetryCell> {
        &self.telemetry
    }

    /// True only while the session thread is actually alive.
    ///
    /// A finished-but-unreaped session must not report as running, or the UI
    /// keeps showing "establishing" for a tunnel that already died and never
    /// re-enables its connect button.
    pub fn is_running(&self) -> bool {
        self.running
            .lock()
            .as_ref()
            .is_some_and(|r| !r.thread.is_finished())
    }

    /// Start a session. Returns as soon as the worker thread is spawned; the
    /// caller polls telemetry (or gets `state_cb`) for progress.
    pub fn start(&self, config: SessionConfig) -> Result<()> {
        // A stop that is still draining must finish first, otherwise the new
        // session's TUN setup races the old session's DNS restore — the
        // classic "reconnect leaves DNS pointing at a dead adapter" bug.
        // stop() returns before native cleanup finishes. Reconnect must wait
        // for the background reaper rather than racing that cleanup.
        const DRAIN_BUDGET: Duration = Duration::from_secs(5);
        let deadline = std::time::Instant::now() + DRAIN_BUDGET;
        let (_control, mut slot) = loop {
            let control = self.tun_control.lock();
            let slot = self.running.lock();
            if !self.stopping.load(Ordering::SeqCst) { break (control, slot); }
            drop(slot);
            drop(control);
            if std::time::Instant::now() >= deadline {
                return Err(CoreError::Timeout(DRAIN_BUDGET));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        // Reap a session that already ended by itself.
        //
        // `running` is only cleared by stop(). When the engine terminated on
        // its own -- it errored, the tunnel dropped, or run_session returned
        // -- the thread finished but the slot stayed occupied, so every later
        // start() returned AlreadyRunning. The UI's connect did nothing and
        // it sat on "Disconnected"/"Establishing" until the app was killed,
        // which is exactly the connect-once-then-never-again symptom.
        if slot.as_ref().is_some_and(|r| r.thread.is_finished()) {
            if let Some(dead) = slot.take() {
                let _ = dead.thread.join();
            }
            log::info!("[session] reaped a session that had already exited");
        }
        if slot.is_some() {
            return Err(CoreError::AlreadyRunning);
        }

        if config.is_tun() {
            // On Android the VpnService fd is the authorisation; elsewhere we
            // need real elevation. Check before doing any work so the user
            // gets an immediate, specific error.
            //
            // The fd can arrive by either route: in the config (desktop/tests)
            // or -- on Android -- through fcae_set_tun_fd() straight into the
            // bridge, before fcae_start() is ever called. Only consulting
            // config.tun.fd made Android always look unprivileged, so every
            // TUN start failed with "requires administrator/root privileges".
            let android_fd =
                config.tun.fd.is_some() || self.cfg.tun_bridge.preauthorised_fd().is_some();
            if !android_fd && !(self.cfg.is_privileged)() {
                return Err(CoreError::PermissionDenied(
                    "TUN mode requires administrator/root privileges. \
                     On Windows: run as Administrator. On Linux/macOS: use sudo."
                        .into(),
                ));
            }
        }

        let backend = registry::resolve(config.backend)?;
        let caps = backend.capabilities();
        if config.is_tun() && !caps.socks {
            return Err(CoreError::InvalidConfig(format!(
                "backend `{}` provides no SOCKS endpoint, so TUN mode cannot be layered on it",
                backend.id().as_str()
            )));
        }
        if caps.requires_privileges && !(self.cfg.is_privileged)() {
            return Err(CoreError::PermissionDenied(format!(
                "backend `{}` requires elevated privileges",
                backend.id().as_str()
            )));
        }

        // Keep every route provider alive through final draining. A cancelled
        // downstream start has no handle for stop_all(), so draining only the
        // carrier would leak its listeners or controller past session teardown.
        let mut drain_backends = vec![backend.clone()];
        let ordered_exits: Vec<FcaeBackend> = if config.chain.is_empty()
            && config.psiphon.through_tunnel
            && config.backend != FcaeBackend::Psiphon
        {
            vec![FcaeBackend::Psiphon]
        } else {
            config.chain.iter().map(|hop| hop.backend).collect()
        };
        for exit in ordered_exits {
            let downstream = registry::resolve(exit)?;
            if !drain_backends.iter().any(|present| present.id() == downstream.id()) {
                drain_backends.push(downstream);
            }
        }
        for provider in &drain_backends {
            provider.recover_stale_state();
        }

        self.telemetry
            .begin_session(config.backend, config.mode, config.lan_sharing);

        self.tun_paused.store(false, Ordering::SeqCst);
        *self.live_tun.lock() = None;

        let cancel = CancelToken::new();
        let telemetry = self.telemetry.clone();
        let sink = TelemetrySink::new(telemetry.clone());
        let tun_bridge = self.cfg.tun_bridge.clone();
        let stop_timeout = self.cfg.stop_timeout;
        let auto_reconnect = self.cfg.auto_reconnect;
        let max_reconnects = self.cfg.max_reconnects;
        let cancel_for_thread = cancel.clone();
        let tun_paused = self.tun_paused.clone();
        let tun_control = self.tun_control.clone();
        let live_tun = self.live_tun.clone();
        let tun_settle = self.tun_settle.clone();

        let thread = std::thread::Builder::new()
            .name("fcae-session".into())
            .spawn(move || {
                log::info!("[session] worker entered; initializing async runtime");
                let workers = if cfg!(target_os = "android") { 2 } else { 4 };
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .worker_threads(workers)
                    .thread_name("fcae-worker")
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        telemetry.set_error(format!("failed to build tokio runtime: {e}"));
                        return;
                    }
                };

                // Catch panics so a backend blowing up cannot poison the
                // runtime drop and leave the session flagged as running.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    rt.block_on(run_session(
                        backend.clone(),
                        config,
                        sink,
                        cancel_for_thread,
                        tun_bridge.clone(),
                        stop_timeout,
                        auto_reconnect,
                        max_reconnects,
                        tun_paused,
                        tun_control,
                        live_tun,
                        tun_settle,
                    ))
                }));

                // Teardown order matters: the bridge must be down before the
                // runtime is dropped, because its stop path may need to run
                // blocking OS commands.
                tun_bridge.stop(stop_timeout);
                // A cancelled start may not have returned a BackendHandle.
                // Drain every provider while its runtime is still alive, not
                // just the carrier. Dropping the runtime early force-cancelled
                // Tor despite the no-abort policy in BackendHandle::stop, and
                // let the reaper release the next-start barrier too soon.
                for provider in &drain_backends {
                    rt.block_on(provider.drain());
                }
                drop(rt); // worker/reaper waits; stop() on the UI still returns promptly

                match outcome {
                    Ok(Ok(())) => {
                        telemetry.set_state(FcaeState::Disconnected, "Disconnected".into())
                    }
                    Ok(Err(e)) => {
                        log::error!("[session] {e}");
                        telemetry.set_error(format!("{e}"));
                    }
                    Err(_) => telemetry.set_error("session thread panicked"),
                }
            })
            .map_err(|e| CoreError::Internal(format!("failed to spawn session thread: {e}")))?;

        *slot = Some(Running { cancel, thread });
        Ok(())
    }

    /// Cancel and abort the TUN descriptors without native joins or OS restore.
    /// The caller must close any platform-owned descriptor separately. Follow
    /// with `stop()` to schedule reaping; the session worker owns full cleanup.
    /// Idempotent, including repeated notification/UI disconnect requests.
    pub fn begin_stop(&self) {
        let slot = self.running.lock();
        if let Some(running) = slot.as_ref() {
            if !self.stopping.swap(true, Ordering::SeqCst) {
                running.cancel.cancel();
                // Keep ownership while aborting so a new start cannot install
                // a TUN between cancellation and descriptor closure.
                self.cfg.tun_bridge.abort();
            }
        }
    }

    /// Request shutdown without waiting on Go, backend joins, or OS restore.
    /// Abort descriptors on the caller and let the session worker perform full
    /// cleanup. A background reaper retains the reconnect barrier until that
    /// worker exits. This is a fast control path, not a hard realtime deadline.
    pub fn stop(&self) -> Result<()> {
        let (running, already_stopping) = {
            let mut slot = self.running.lock();
            let Some(running) = slot.take() else {
                // Another stop may already own the worker. Only its reaper
                // may clear `stopping`, never a duplicate Disconnect.
                return Ok(());
            };
            let already_stopping = self.stopping.swap(true, Ordering::SeqCst);
            (running, already_stopping)
        };

        running.cancel.cancel();

        if !already_stopping {
            // Only close descriptors here. stop() may block in platform::restore
            // or Go engine.Stop(); the session worker already owns those calls.
            self.cfg.tun_bridge.abort();
        }
        self.telemetry
            .set_state(FcaeState::Disconnected, "Disconnected".into());

        if running.thread.is_finished() {
            let _ = running.thread.join();
            self.stopping.store(false, Ordering::SeqCst);
        } else {
            // No polling/sleep budget on the UI thread. Keep the barrier set
            // until cleanup completes, including when Disconnect is repeated.
            let flag = self.stopping.clone();
            std::thread::Builder::new()
                .name("fcae-session-reaper".into())
                .spawn(move || {
                    let _ = running.thread.join();
                    flag.store(false, Ordering::SeqCst);
                })
                .map_err(|e| CoreError::Internal(format!("failed to spawn session reaper: {e}")))?;
        }
        Ok(())
    }

    /// Wait for the [`stop`] reaper to finish: the session worker has then
    /// completed its full teardown (TUN down, routes/DNS restored, backend
    /// drained). Returns false when the budget lapses first.
    ///
    /// Disconnects must stay instant, so stop() itself never joins; but a
    /// process that is about to die must not exit before the worker's OS
    /// restore ran — macOS in particular rewrites the physical service's
    /// DNS, and a restore lost to process exit leaves the machine pointing
    /// at a dead resolver until fixed by hand. The restore is the FIRST step
    /// of the worker's teardown, so this budget does not need to cover the
    /// slow tail (a Psiphon controller join); whatever still runs past the
    /// deadline dies with the process, which the kernel cleans up (the
    /// datastores are crash-safe).
    pub fn wait_stopped(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while self.stopping.load(Ordering::SeqCst) {
            if start.elapsed() >= timeout {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        true
    }

    /// Bring the TUN data plane down without cancelling the session. The host
    /// closes its own VPN descriptor; [`Self::resume_tun`] re-raises TUN on a
    /// fresh fd. No-op when no session is alive.
    pub fn pause_tun(&self) {
        let _control = self.tun_control.lock();
        if !self.is_running() || self.stopping.load(Ordering::SeqCst) {
            return;
        }
        if self.tun_paused.swap(true, Ordering::SeqCst) {
            return;
        }
        self.hold_tun_settle();
        self.cfg.tun_bridge.stop(self.cfg.stop_timeout);
    }

    /// Re-raise TUN on a live paused session. The host must publish a fresh
    /// descriptor first (`fcae_set_tun_fd` or the fd provider).
    pub fn resume_tun(&self) -> Result<()> {
        let _control = self.tun_control.lock();
        if !self.is_running() || self.stopping.load(Ordering::SeqCst) {
            return Err(CoreError::Internal(
                "no session to resume TUN for".into(),
            ));
        }
        if !self.tun_paused.load(Ordering::SeqCst) {
            return Ok(());
        }
        // Without a stored live session there is nothing to re-raise the
        // device on. Clearing the pause flag anyway would hand the session a
        // data plane that is not running: the next health tick would then end
        // it -- and with it the backend and its tunnel -- which is exactly the
        // "starting the TUN disconnected Aether" failure. Stay paused and
        // report; a session that is gone is the caller's to reconnect.
        let live = self.live_tun.lock().clone();
        let Some(live) = live.filter(|live| live.config.is_tun()) else {
            return Err(CoreError::Internal(
                "no live session to re-raise the TUN data plane on".into(),
            ));
        };
        let cancel = self.running.lock().as_ref().map(|running| running.cancel.clone())
            .ok_or_else(|| CoreError::Internal("no session to resume TUN for".into()))?;
        self.cfg.tun_bridge.start_cancellable(&live.config, &live.endpoints, &cancel)?;
        if self.stopping.load(Ordering::SeqCst) || !self.is_running() {
            self.cfg.tun_bridge.stop(self.cfg.stop_timeout);
            return Err(CoreError::Internal("session stopped during TUN resume".into()));
        }
        self.hold_tun_settle();
        self.tun_paused.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// True while a session is alive and its TUN data plane is paused.
    pub fn tun_is_paused(&self) -> bool {
        self.is_running() && self.tun_paused.load(Ordering::SeqCst)
    }
}

struct LiveGuard {
    live: Arc<Mutex<Option<LiveTun>>>,
    paused: Arc<AtomicBool>,
    control: Arc<Mutex<()>>,
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        let _control = self.control.lock();
        *self.live.lock() = None;
        self.paused.store(false, Ordering::SeqCst);
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_session(
    backend: Arc<dyn crate::backend::Backend>,
    config: SessionConfig,
    sink: TelemetrySink,
    cancel: CancelToken,
    tun_bridge: Arc<dyn TunBridge>,
    stop_timeout: Duration,
    auto_reconnect: bool,
    max_reconnects: u32,
    tun_paused: Arc<AtomicBool>,
    tun_control: Arc<Mutex<()>>,
    live_tun: Arc<Mutex<Option<LiveTun>>>,
    tun_settle: Arc<Mutex<Option<std::time::Instant>>>,
) -> Result<()> {
    let _live_guard = LiveGuard {
        live: live_tun.clone(),
        paused: tun_paused.clone(),
        control: tun_control.clone(),
    };
    let mut config = config;
    if config.chain.is_empty() && config.psiphon.through_tunnel && config.backend != FcaeBackend::Psiphon {
        config.chain.push(ChainHop::new(FcaeBackend::Psiphon, config.protocol, config.obfuscation.h2_enabled));
    }
    if config.is_tun() {
        let exit = config.exit_backend();
        let exit_protocol = config.chain.last().map(|hop| hop.protocol).unwrap_or(config.protocol);
        let tor_exit = exit == FcaeBackend::Aether && (exit_protocol == FcaeProtocol::Tor
            || (config.chain.is_empty() && matches!(config.tor.mode, FcaeTorMode::Only | FcaeTorMode::Chain)));
        let psiphon_socks_disabled = config.psiphon.config_json.as_deref()
            .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok())
            .and_then(|json| json.get("DisableLocalSocksProxy").and_then(|v| v.as_bool()))
            .unwrap_or(false);
        let missing = if exit == FcaeBackend::Psiphon { psiphon_socks_disabled }
            else { !tor_exit && config.socks_port == 0 };
        if missing {
            return Err(CoreError::InvalidConfig(format!(
                "TUN mode requires SOCKS5; enable SOCKS5 for the {} exit proxy", backend_label(exit)
            )));
        }
    }
    let mut attempt: u32 = 0;

    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        let mut carrier_config = config.clone();
        if !config.chain.is_empty() {
            configure_internal_listeners(&mut carrier_config)?;
            carrier_config.require_udp_proxy = config.chain.first().is_some_and(|hop| hop_needs_udp(&config, *hop));
        }
        let cx = BackendContext::new(carrier_config.clone(), sink.clone(), cancel.clone());
        cx.report(
            if attempt == 0 { FcaeState::Connecting } else { FcaeState::Reconnecting },
            if attempt == 0 { "Connecting…".to_string() } else { format!("Reconnecting (attempt {attempt})…") },
        );
        let start_budget = if carrier_config.tor.is_enabled() {
            carrier_config.tor_start_timeout()
        } else {
            carrier_config.start_timeout()
        };
        log::info!("[session] starting carrier backend (attempt {})", attempt + 1);
        let handle = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            started = backend.start(cx) => started,
            _ = tokio::time::sleep(start_budget) => Err(CoreError::Timeout(start_budget)),
        };
        let handle: Box<dyn BackendHandle> = match handle {
            Ok(handle) => handle,
            Err(error) => {
                let transient = error.is_transient();
                if !transient || !should_retry(auto_reconnect, max_reconnects, attempt, &cancel) {
                    return Err(error);
                }
                attempt += 1;
                sink.set_state(FcaeState::Reconnecting, format!("Connect failed ({error}); retrying…"));
                if backoff(&cancel, attempt).await.is_break() {
                    return Ok(());
                }
                continue;
            }
        };
        log::info!("[session] carrier started; preparing exit route");
        let carrier: Arc<dyn BackendHandle> = Arc::from(handle);
        let mut handles: Vec<Arc<dyn BackendHandle>> = vec![carrier];
        let mut endpoints = handles[0].endpoints();
        if let Some(peers) = &endpoints.peer_ip {
            let display = peers.split(',').next().unwrap_or(peers).trim();
            if !display.is_empty() {
                sink.set_peer(display.to_string());
            }
        }
        let carrier_peers = endpoints.peer_ip.clone();

        if let Err(error) = start_downstream(&config, &mut handles, &mut endpoints, &sink, &cancel, stop_timeout).await {
            stop_all(&mut handles, stop_timeout).await;
            if cancel.is_cancelled() {
                return Ok(());
            }
            if !error.is_transient() || !should_retry(auto_reconnect, max_reconnects, attempt, &cancel) {
                return Err(error);
            }
            attempt += 1;
            sink.set_state(FcaeState::Reconnecting, format!("Chain startup failed ({error}); retrying…"));
            if backoff(&cancel, attempt).await.is_break() {
                return Ok(());
            }
            continue;
        }

        if config.is_tun() && cfg!(not(target_os = "android")) {
            if let Some(proxy) = &config.upstream_proxy {
                let bypass = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        stop_all(&mut handles, stop_timeout).await;
                        return Ok(());
                    }
                    ips = proxy.bypass_addresses() => ips,
                };
                endpoints.peer_ip = crate::backend::append_bypass(endpoints.peer_ip.as_deref(), &bypass);
            }
        }

        if config.is_tun() && endpoints.socks.is_none() {
            stop_all(&mut handles, stop_timeout).await;
            return Err(CoreError::StartFailed(
                "TUN mode requires a SOCKS5 endpoint; enable SOCKS5 for the exit proxy".into(),
            ));
        }

        let tun_start = {
            let _control = tun_control.lock();
            *live_tun.lock() = Some(LiveTun { config: config.clone(), endpoints: endpoints.clone() });
            if config.is_tun() && !cancel.is_cancelled() && !tun_paused.load(Ordering::SeqCst) {
                let started = tun_bridge.start_cancellable(&config, &endpoints, &cancel);
                if started.is_ok() {
                    *tun_settle.lock() = Some(std::time::Instant::now() + TUN_SETTLE);
                }
                started
            } else {
                Ok(())
            }
        };
        if let Err(error) = tun_start {
            log::error!("[session] TUN startup failed: {error}");
            stop_all(&mut handles, stop_timeout).await;
            if cancel.is_cancelled() {
                return Ok(());
            }
            return Err(error);
        }
        if cancel.is_cancelled() {
            tun_bridge.stop(stop_timeout);
            stop_all(&mut handles, stop_timeout).await;
            return Ok(());
        }
        if !config.is_tun() {
            debug_assert!(!tun_bridge.is_running(), "proxy mode must never leave a TUN device up");
        }

        // Publish the already-measured Firefox CONNECT before Connected so
        // the first UI snapshot does not need to wait for the counter pump.
        let chained = !config.chain.is_empty();
        if config.exit_backend() == FcaeBackend::Firefox {
            let mut counters = handles[0].counters();
            if chained {
                counters.rtt_ms = handles.last().map_or(0, |exit| exit.counters().rtt_ms);
            }
            sink.set_counters(counters);
        }
        sink.set_state(
            FcaeState::Connected,
            format!("Connected ({} {})", route_name(&config), if config.mode == FcaeMode::Tun { "TUN" } else { "Proxy" }),
        );

        let carrier_wait_handle = handles[0].clone();
        let carrier_ended = async move { carrier_wait_handle.wait().await };
        let pump_handle = handles[0].clone();
        let firefox_exit_rtt = Arc::new(Mutex::new(
            if chained && config.exit_backend() == FcaeBackend::Firefox { handles.last().cloned() } else { None }
        ));
        let pump_firefox_exit_rtt = firefox_exit_rtt.clone();
        let pump_sink = sink.clone();
        let pump_config = config.clone();
        let pump_tun = tun_bridge.clone();
        let pump_paused = tun_paused.clone();
        let pump_control = tun_control.clone();
        let pump_settle = tun_settle.clone();
        let pump_peers = carrier_peers.clone();
        let pump = async move {
            pump_counters(
                &*pump_handle,
                &pump_sink,
                &pump_config,
                &*pump_tun,
                &pump_paused,
                &pump_control,
                &pump_settle,
                pump_peers.as_deref(),
                &pump_firefox_exit_rtt,
            ).await
        };
        tokio::pin!(carrier_ended, pump);
        let mut hop_up = vec![true; handles.len()];
        let outcome = loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    tun_bridge.stop(stop_timeout);
                    stop_all(&mut handles, stop_timeout).await;
                    return Ok(());
                }
                result = &mut carrier_ended => break result,
                (_, result) = exits_ended(handles[1..].to_vec()), if chained && handles.len() > 1 => break result,
                (index, up) = chain_carrier_changed(handles.clone(), hop_up.clone()), if chained => {
                    if index >= handles.len() {
                        continue;
                    }
                    hop_up[index] = up;
                    if !up {
                        log::info!("[session] chain hop {index} dropped; stopping its downstream exits");
                        stop_after(&mut handles, index, stop_timeout).await;
                        if chained && config.exit_backend() == FcaeBackend::Firefox && handles.len() <= config.chain.len() {
                            *firefox_exit_rtt.lock() = None;
                        }
                        hop_up.truncate(handles.len());
                        let peer_ip = endpoints.peer_ip.clone();
                        endpoints = Endpoints { peer_ip, ..handles[index].endpoints() };
                        *live_tun.lock() = None;
                        continue;
                    }
                    if handles.len() != index + 1 {
                        continue;
                    }
                    log::info!("[session] chain hop {index} is back; rebuilding its downstream exits");
                    let previous = endpoints.clone();
                    let peer_ip = previous.peer_ip.clone();
                    let mut rebuilt = Endpoints { peer_ip, ..handles[index].endpoints() };
                    let restarted = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => {
                            tun_bridge.stop(stop_timeout);
                            stop_all(&mut handles, stop_timeout).await;
                            return Ok(());
                        }
                        result = &mut carrier_ended => break result,
                        result = start_downstream(&config, &mut handles, &mut rebuilt, &sink, &cancel, stop_timeout) => result,
                    };
                    match restarted {
                        Ok(()) => {
                            if chained && config.exit_backend() == FcaeBackend::Firefox {
                                *firefox_exit_rtt.lock() = handles.last().cloned();
                            }
                            let listener_changed = rebuilt.socks != previous.socks || rebuilt.http != previous.http;
                            if listener_changed && config.is_tun() {
                                let _control = tun_control.lock();
                                tun_bridge.stop(stop_timeout);
                                if !tun_paused.load(Ordering::SeqCst) {
                                    if let Err(error) = tun_bridge.start_cancellable(&config, &rebuilt, &cancel) {
                                        break if cancel.is_cancelled() { Ok(()) } else { Err(error) };
                                    }
                                    *tun_settle.lock() = Some(std::time::Instant::now() + TUN_SETTLE);
                                }
                            }
                            endpoints = rebuilt;
                            *live_tun.lock() = Some(LiveTun { config: config.clone(), endpoints: endpoints.clone() });
                            hop_up = vec![true; handles.len()];
                            sink.set_state(
                                FcaeState::Connected,
                                format!("Connected ({} {})", route_name(&config), if config.mode == FcaeMode::Tun { "TUN" } else { "Proxy" }),
                            );
                        }
                        Err(error) => break Err(error),
                    }
                }
                result = &mut pump => break result,
            }
        };

        if should_retry(auto_reconnect, max_reconnects, attempt, &cancel) {
            sink.set_state(FcaeState::Reconnecting, "Tunnel dropped; reconnecting…".into());
        }
        {
            let _control = tun_control.lock();
            *live_tun.lock() = None;
            tun_bridge.stop(stop_timeout);
        }
        stop_all(&mut handles, stop_timeout).await;

        match outcome {
            Ok(()) if cancel.is_cancelled() => return Ok(()),
            Ok(()) | Err(_) if !should_retry(auto_reconnect, max_reconnects, attempt, &cancel) => return outcome,
            _ => {}
        }
        attempt += 1;
        sink.cell().note_reconnect();
        if backoff(&cancel, attempt).await.is_break() {
            return Ok(());
        }
    }
}

async fn chain_carrier_changed(handles: Vec<Arc<dyn BackendHandle>>, previous: Vec<bool>) -> (usize, bool) {
    loop {
        tokio::time::sleep(CARRIER_POLL).await;
        for (index, handle) in handles.iter().enumerate() {
            let up = handle.carrier_up();
            if previous.get(index).copied() != Some(up) {
                return (index, up);
            }
        }
    }
}

async fn exits_ended(handles: Vec<Arc<dyn BackendHandle>>) -> (usize, Result<()>) {
    if handles.is_empty() {
        return std::future::pending().await;
    }
    let (result, index, _) = futures::future::select_all(handles.iter().map(|handle| handle.wait())).await;
    (index, result)
}

async fn stop_after(handles: &mut Vec<Arc<dyn BackendHandle>>, index: usize, timeout: Duration) {
    while handles.len() > index + 1 {
        if let Some(handle) = handles.pop() {
            let _ = handle.stop(timeout).await;
        }
    }
}

async fn stop_all(handles: &mut Vec<Arc<dyn BackendHandle>>, timeout: Duration) {
    while let Some(handle) = handles.pop() {
        let _ = handle.stop(timeout).await;
    }
}

async fn start_downstream(
    config: &SessionConfig,
    handles: &mut Vec<Arc<dyn BackendHandle>>,
    endpoints: &mut Endpoints,
    sink: &TelemetrySink,
    cancel: &CancelToken,
    stop_timeout: Duration,
) -> Result<()> {
    let target_len = config.chain.len() + 1;
    while handles.len() < target_len {
        let hop = handles.len();
        let exit = config.chain[hop - 1];
        let final_hop = hop == config.chain.len();
        let previous = handles[hop - 1].endpoints();
        let (previous_backend, previous_protocol) = if hop == 1 {
            (config.backend, config.protocol)
        } else {
            let prior = config.chain[hop - 2];
            (prior.backend, prior.protocol)
        };
        let previous_name = if previous_backend == FcaeBackend::Aether
            && (previous_protocol == FcaeProtocol::Tor
                || (hop == 1 && matches!(config.tor.mode, FcaeTorMode::Only | FcaeTorMode::Chain))) {
            "Tor"
        } else {
            backend_label(previous_backend)
        };
        let monitored = handles.to_vec();
        let started = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(CoreError::StartFailed("chain cancelled".into())),
            (index, result) = exits_ended(monitored) => {
                let detail = result.err().map(|error| format!(": {error}")).unwrap_or_default();
                Err(CoreError::StartFailed(format!("chain hop {index} dropped while exit {exit:?} was connecting{detail}")))
            }
            result = start_chain_hop(config, exit, final_hop, config.chain.get(hop).is_some_and(|next| hop_needs_udp(config, *next)), &previous, previous_name, sink, cancel) => result,
        };
        match started {
            Ok(handle) => {
                let next = handle.endpoints();
                if (final_hop && config.is_tun() || !final_hop) && next.socks.is_none() {
                    let _ = handle.stop(stop_timeout).await;
                    let required = if final_hop { "TUN mode" } else { "the next chain hop" };
                    return Err(CoreError::StartFailed(format!(
                        "chained {exit:?} has no SOCKS5 endpoint; enable SOCKS5 for {required}"
                    )));
                }
                *endpoints = Endpoints { peer_ip: endpoints.peer_ip.clone(), ..next };
                handles.push(handle);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn chain_upstream(previous: &Endpoints, needs_udp: bool, source: &str) -> Result<crate::upstream::UpstreamProxy> {
    let addr = previous.socks.ok_or_else(|| CoreError::InvalidConfig(format!(
        "the next chain hop requires SOCKS5; enable {source} SOCKS5"
    )))?;
    if needs_udp && !previous.udp {
        return Err(CoreError::InvalidConfig(format!(
            "the next chain hop requires UDP; {source} SOCKS5 is not UDP-capable"
        )));
    }
    Ok(crate::upstream::UpstreamProxy::loopback(addr))
}

async fn start_chain_hop(
    config: &SessionConfig,
    exit: ChainHop,
    final_hop: bool,
    next_needs_udp: bool,
    previous: &Endpoints,
    previous_name: &str,
    sink: &TelemetrySink,
    cancel: &CancelToken,
) -> Result<Arc<dyn BackendHandle>> {
    let backend = exit.backend;
    let mut hop = config.clone();
    hop.backend = backend;
    hop.protocol = exit.protocol;
    hop.obfuscation.h2_enabled = exit.h2_enabled;
    if backend == FcaeBackend::Aether {
        if exit.protocol == FcaeProtocol::Tor {
            hop.tor.mode = FcaeTorMode::Only;
        } else if hop.tor.mode == FcaeTorMode::Only {
            hop.tor.mode = FcaeTorMode::Off;
        }
    }
    hop.chain.clear();
    hop.psiphon.through_tunnel = false;
    hop.mode = if final_hop { config.mode } else { FcaeMode::Proxy };
    hop.lan_sharing = final_hop && config.lan_sharing;
    let upstream = chain_upstream(previous, hop.upstream_requires_udp(), previous_name)?;
    if !final_hop {
        configure_internal_listeners(&mut hop)?;
        hop.require_udp_proxy = next_needs_udp;
    }
    let url = upstream.url();
    if backend == FcaeBackend::Psiphon {
        hop.upstream_proxy = None;
        let json = hop.psiphon.config_json.as_deref().unwrap_or("{}");
        hop.psiphon.config_json = Some(crate::config::inject_upstream_proxy_url(json, &url));
    } else {
        hop.upstream_proxy = Some(upstream);
    }
    let budget = if hop.tor.is_enabled() { hop.tor_start_timeout() } else { hop.start_timeout() } + CHAIN_START_GRACE;
    let backend_impl = registry::resolve(backend)?;
    sink.set_state(FcaeState::Connecting, format!("Establishing {backend:?} chain hop…"));
    let cx = BackendContext::new(hop, sink.clone(), cancel.clone());
    let handle = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(CoreError::StartFailed("chain cancelled".into())),
        result = tokio::time::timeout(budget, backend_impl.start(cx)) => match result {
            Ok(Ok(handle)) => handle,
            Ok(Err(error)) => {
                log::warn!("[session] {backend:?} could not start through {previous_name} SOCKS5: {error}");
                return Err(error);
            }
            Err(_) => return Err(CoreError::StartFailed(format!("{backend:?} chain startup timed out via {url}"))),
        },
    };
    log::info!("[session] chained {backend:?} via {url}");
    Ok(Arc::from(handle))
}

fn hop_needs_udp(config: &SessionConfig, hop: ChainHop) -> bool {
    let mut target = config.clone();
    target.backend = hop.backend;
    target.protocol = hop.protocol;
    target.obfuscation.h2_enabled = hop.h2_enabled;
    if hop.backend == FcaeBackend::Aether {
        if hop.protocol == FcaeProtocol::Tor { target.tor.mode = FcaeTorMode::Only; }
        else if target.tor.mode == FcaeTorMode::Only { target.tor.mode = FcaeTorMode::Off; }
    }
    target.upstream_requires_udp()
}

fn allocate_internal_port(held: &mut Vec<std::net::TcpListener>) -> Result<u16> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| CoreError::StartFailed(format!("cannot allocate an internal listener: {e}")))?;
    let port = listener.local_addr().map(|a| a.port())
        .map_err(|e| CoreError::StartFailed(format!("cannot inspect an internal listener: {e}")))?;
    held.push(listener);
    Ok(port)
}

fn configure_internal_listeners(config: &mut SessionConfig) -> Result<()> {
    config.mode = FcaeMode::Proxy;
    config.lan_sharing = false;
    let has_tor = config.backend == FcaeBackend::Aether && config.tor.is_enabled();
    let is_tor = has_tor && matches!(config.tor.mode, FcaeTorMode::Only | FcaeTorMode::Chain);
    let (socks, http) = match &config.listener_policy {
        Some(p) if is_tor => (p.tor_socks, p.tor_http),
        Some(p) if config.backend == FcaeBackend::Firefox => (p.firefox_socks, p.firefox_http),
        Some(p) if config.backend == FcaeBackend::Aether => (p.aether_socks, p.aether_http),
        _ => (true, false),
    };
    if config.backend == FcaeBackend::Psiphon {
        let disabled = config.psiphon.config_json.as_deref()
            .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok())
            .and_then(|json| json.get("DisableLocalSocksProxy").and_then(|v| v.as_bool()))
            .unwrap_or(false);
        if disabled {
            return Err(CoreError::InvalidConfig("the next chain hop requires SOCKS5; enable Psiphon SOCKS5".into()));
        }
    } else if !socks {
        let name = if is_tor { "Tor" } else { backend_label(config.backend) };
        return Err(CoreError::InvalidConfig(format!("the next chain hop requires SOCKS5; enable {name} SOCKS5")));
    }
    if has_tor && config.listener_policy.as_ref().is_some_and(|p| !p.tor_socks) {
        return Err(CoreError::InvalidConfig("Tor currently requires SOCKS5; enable Tor SOCKS5".into()));
    }
    if config.tor.mode == FcaeTorMode::Chain && config.listener_policy.as_ref().is_some_and(|p| !p.aether_socks) {
        return Err(CoreError::InvalidConfig("Tor through Aether requires Aether SOCKS5; enable Aether SOCKS5".into()));
    }
    config.internal_socks = socks;
    config.internal_http = http;
    let mut held = Vec::new();
    if config.backend == FcaeBackend::Psiphon {
        if !cfg!(target_os = "android") {
            config.psiphon.socks_port = 0;
            config.psiphon.http_port = 0;
        }
    } else {
        config.socks_port = if config.backend == FcaeBackend::Aether && config.tor.mode != FcaeTorMode::Only {
            allocate_internal_port(&mut held)?
        } else { 0 };
        config.http_port = if config.backend == FcaeBackend::Aether && !is_tor && http {
            allocate_internal_port(&mut held)?
        } else { 0 };
    }
    if has_tor {
        let port = allocate_internal_port(&mut held)?;
        config.tor.bind = Some(format!("127.0.0.1:{port}"));
        let tor_http = config.listener_policy.as_ref().is_some_and(|p| p.tor_http);
        config.tor.http_port = if tor_http { allocate_internal_port(&mut held)? } else { 0 };
    }
    Ok(())
}

fn route_name(config: &SessionConfig) -> String {
    if config.chain.is_empty() && !config.psiphon.through_tunnel {
        if config.backend == FcaeBackend::Aether
            && matches!(config.tor.mode, FcaeTorMode::Only | FcaeTorMode::Chain)
        {
            return "Tor".into();
        }
        return backend_label(config.backend).into();
    }
    let mut names = vec![backend_label(config.backend)];
    if config.chain.is_empty() && config.psiphon.through_tunnel {
        names.push("Psiphon");
    } else {
        names.extend(config.chain.iter().map(|hop| backend_label(hop.backend)));
    }
    names.join(" → ")
}

fn backend_label(backend: FcaeBackend) -> &'static str {
    match backend {
        FcaeBackend::Aether => "Aether",
        FcaeBackend::Psiphon => "Psiphon",
        FcaeBackend::Firefox => "Firefox",
    }
}

fn should_retry(auto: bool, max: u32, attempt: u32, cancel: &CancelToken) -> bool {
    auto && !cancel.is_cancelled() && (max == 0 || attempt < max)
}

/// Exponential backoff capped at 30 s, interruptible by cancellation.
async fn backoff(cancel: &CancelToken, attempt: u32) -> std::ops::ControlFlow<()> {
    let secs = 2u64.saturating_pow(attempt.min(5)).min(30);
    tokio::select! {
        _ = cancel.cancelled() => std::ops::ControlFlow::Break(()),
        _ = tokio::time::sleep(Duration::from_secs(secs)) => std::ops::ControlFlow::Continue(()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn pump_counters(
    handle: &dyn BackendHandle,
    sink: &TelemetrySink,
    cfg: &SessionConfig,
    tun: &dyn TunBridge,
    paused: &AtomicBool,
    control: &Mutex<()>,
    settle: &Mutex<Option<std::time::Instant>>,
    carrier_peers: Option<&str>,
    firefox_exit_rtt: &Mutex<Option<Arc<dyn BackendHandle>>>,
) -> Result<()> {
    #[cfg(not(windows))]
    let _ = carrier_peers;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut unhealthy: u32 = 0;
    loop {
        tick.tick().await;
        let mut counters = handle.counters();
        if !cfg.chain.is_empty() && cfg.exit_backend() == FcaeBackend::Firefox {
            counters.rtt_ms = firefox_exit_rtt.lock().as_ref().map_or(0, |exit| exit.counters().rtt_ms);
        }
        sink.set_counters(counters);
        let Some(_control) = control.try_lock() else { continue; };
        if !cfg.is_tun() {
            continue;
        }
        // Paused and mid-transition are both "device down by request": the
        // backend is fine and must not be re-dialled because of it.
        if paused.load(Ordering::SeqCst) || in_tun_settle(settle) {
            unhealthy = 0;
            continue;
        }
        if let Err(error) = tun.check_health(cfg) {
            unhealthy += 1;
            if unhealthy >= TUN_HEALTH_FAIL_TICKS {
                return Err(error);
            }
            log::debug!(
                "[session] TUN health check failed ({unhealthy}/{TUN_HEALTH_FAIL_TICKS}): {error}"
            );
            continue;
        }
        unhealthy = 0;
        // A pause can land while the (possibly slow) health call runs; the
        // re-check keeps Windows route comparison out of that window too.
        if paused.load(Ordering::SeqCst) {
            continue;
        }
        #[cfg(windows)]
        if handle.endpoints().peer_ip.as_deref() != carrier_peers {
            return Err(CoreError::Internal("outer endpoint changed; reconnecting TUN with fresh routes".into()));
        }
    }
}

/// True while the TUN data plane is inside its post-transition grace window.
fn in_tun_settle(settle: &Mutex<Option<std::time::Instant>>) -> bool {
    settle
        .lock()
        .is_some_and(|deadline| std::time::Instant::now() < deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{Backend, BackendId, Capabilities, Counters};
    use async_trait::async_trait;
    use fcae_abi::FcaeBackend;

    /// A bridge that reports a platform-supplied fd, like Android's.
    struct PreauthorisedBridge;

    impl TunBridge for PreauthorisedBridge {
        fn start(&self, _cfg: &SessionConfig, _e: &Endpoints) -> Result<()> {
            Ok(())
        }
        fn stop(&self, _timeout: Duration) {}
        fn is_running(&self) -> bool {
            false
        }
        fn preauthorised_fd(&self) -> Option<i32> {
            Some(42)
        }
    }

    #[test]
    fn a_bridge_held_fd_authorises_tun_without_elevation() {
        // Regression: fcae_set_tun_fd() stores the VpnService fd in the BRIDGE,
        // while the config still carries tun_fd = -1. Checking only the config
        // made every Android TUN start fail with "requires administrator/root
        // privileges" even though the JVM had already created the interface.
        assert!(
            PreauthorisedBridge.preauthorised_fd().is_some(),
            "the bridge must surface the platform-supplied fd"
        );
        assert!(
            NullTunBridge.preauthorised_fd().is_none(),
            "a bridge that creates its own device has nothing pre-authorised"
        );
    }

    struct FakeHandle;

    #[async_trait]
    impl BackendHandle for FakeHandle {
        fn endpoints(&self) -> Endpoints {
            Endpoints {
                socks: Some("127.0.0.1:1819".parse().unwrap()),
                http: None,
                peer_ip: Some("203.0.113.7".into()),
                udp: true,
                psiphon_dns: false,
            }
        }
        async fn wait(&self) -> Result<()> {
            // Stay up until cancelled by the supervisor.
            std::future::pending::<()>().await;
            Ok(())
        }
        async fn stop(&self, _t: Duration) -> Result<()> {
            Ok(())
        }
        fn counters(&self) -> Counters {
            Counters::default()
        }
    }

    struct FakeBackend;

    #[async_trait]
    impl Backend for FakeBackend {
        fn id(&self) -> BackendId {
            BackendId::Aether
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                socks: true,
                http_proxy: true,
                gateway_scanning: true,
                routing_rules: true,
                requires_privileges: false,
            }
        }
        async fn start(&self, _cx: BackendContext) -> Result<Box<dyn BackendHandle>> {
            Ok(Box::new(FakeHandle))
        }
    }

    #[test]
    fn routing_label_names_the_exit_not_the_carrier() {
        let mut cfg = SessionConfig::default();
        assert_eq!(route_name(&cfg), "Aether");
        cfg.tor.mode = FcaeTorMode::Chain;
        assert_eq!(route_name(&cfg), "Tor");
        cfg.tor.mode = FcaeTorMode::Reverse;
        assert_eq!(route_name(&cfg), "Aether");
        cfg.tor.mode = FcaeTorMode::Only;
        assert_eq!(route_name(&cfg), "Tor");
        cfg.psiphon.through_tunnel = true;
        assert_eq!(route_name(&cfg), "Aether → Psiphon");
        cfg.psiphon.through_tunnel = false;
        cfg.chain = vec![
            ChainHop::new(FcaeBackend::Psiphon, cfg.protocol, cfg.obfuscation.h2_enabled),
            ChainHop::new(FcaeBackend::Firefox, cfg.protocol, cfg.obfuscation.h2_enabled),
        ];
        assert_eq!(route_name(&cfg), "Aether → Psiphon → Firefox");
    }

    #[test]
    fn internal_firefox_requires_enabled_socks() {
        let mut cfg = SessionConfig::default();
        cfg.backend = FcaeBackend::Firefox;
        cfg.listener_policy = Some(crate::config::ListenerPolicy {
            aether_socks: true, aether_http: false,
            firefox_socks: false, firefox_http: true,
            tor_socks: true, tor_http: false,
        });
        assert!(configure_internal_listeners(&mut cfg).unwrap_err().to_string().contains("Firefox SOCKS5"));
        cfg.listener_policy.as_mut().unwrap().firefox_socks = true;
        configure_internal_listeners(&mut cfg).unwrap();
        assert!(cfg.internal_socks);
        assert!(cfg.internal_http);
        assert!(!cfg.lan_sharing);
    }

    #[test]
    fn internal_aether_does_not_force_disabled_socks() {
        let mut cfg = SessionConfig::default();
        cfg.listener_policy = Some(crate::config::ListenerPolicy {
            aether_socks: false, aether_http: true,
            firefox_socks: true, firefox_http: true,
            tor_socks: true, tor_http: false,
        });
        assert!(configure_internal_listeners(&mut cfg).unwrap_err().to_string().contains("Aether SOCKS5"));
    }

    #[test]
    fn chain_requires_socks_even_when_http_is_available() {
        let mut endpoints = Endpoints {
            socks: None, http: Some("127.0.0.1:8080".parse().unwrap()),
            peer_ip: None, udp: false, psiphon_dns: false,
        };
        assert!(chain_upstream(&endpoints, false, "Firefox").unwrap_err().to_string().contains("Firefox SOCKS5"));
        assert!(chain_upstream(&endpoints, true, "Firefox").is_err());
        endpoints.socks = Some("127.0.0.1:1080".parse().unwrap());
        assert_eq!(chain_upstream(&endpoints, false, "Firefox").unwrap().kind, crate::upstream::ProxyKind::Socks5);
        assert!(chain_upstream(&endpoints, true, "Firefox").is_err());
        endpoints.udp = true;
        assert_eq!(chain_upstream(&endpoints, true, "Firefox").unwrap().kind, crate::upstream::ProxyKind::Socks5);
    }

    #[test]
    fn tun_without_socks_fails_before_starting_the_data_plane() {
        static STOPPED: AtomicBool = AtomicBool::new(false);
        struct HttpOnlyHandle;
        #[async_trait]
        impl BackendHandle for HttpOnlyHandle {
            fn endpoints(&self) -> Endpoints {
                Endpoints { socks: None, http: Some("127.0.0.1:8080".parse().unwrap()),
                    peer_ip: None, udp: false, psiphon_dns: false }
            }
            async fn wait(&self) -> Result<()> { std::future::pending().await }
            async fn stop(&self, _: Duration) -> Result<()> { STOPPED.store(true, Ordering::SeqCst); Ok(()) }
            fn counters(&self) -> Counters { Counters::default() }
        }
        struct HttpOnlyBackend;
        #[async_trait]
        impl Backend for HttpOnlyBackend {
            fn id(&self) -> BackendId { BackendId::Aether }
            fn capabilities(&self) -> Capabilities { FakeBackend.capabilities() }
            async fn start(&self, _: BackendContext) -> Result<Box<dyn BackendHandle>> { Ok(Box::new(HttpOnlyHandle)) }
        }
        struct NoTun;
        impl TunBridge for NoTun {
            fn start(&self, _: &SessionConfig, _: &Endpoints) -> Result<()> { panic!("TUN must not start") }
            fn stop(&self, _: Duration) {}
            fn is_running(&self) -> bool { false }
        }
        STOPPED.store(false, Ordering::SeqCst);
        let mut cfg = SessionConfig::default();
        cfg.mode = FcaeMode::Tun;
        let sink = TelemetrySink::new(Arc::new(TelemetryCell::new()));
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let result = rt.block_on(run_session(Arc::new(HttpOnlyBackend), cfg, sink,
            CancelToken::new(), Arc::new(NoTun), Duration::from_millis(10), false, 0,
            Arc::new(AtomicBool::new(false)), Arc::new(Mutex::new(())), Arc::new(Mutex::new(None)),
            Arc::new(Mutex::new(None))));
        assert!(result.unwrap_err().to_string().contains("TUN mode requires a SOCKS5 endpoint"));
        assert!(STOPPED.load(Ordering::SeqCst));
    }

    #[test]
    fn psiphon_exits_raise_tun_only_after_connection() {
        static EXIT_READY: AtomicBool = AtomicBool::new(false);
        struct FailedExit;
        #[async_trait]
        impl Backend for FailedExit {
            fn id(&self) -> BackendId { BackendId::Psiphon }
            fn capabilities(&self) -> Capabilities { FakeBackend.capabilities() }
            async fn start(&self, _: BackendContext) -> Result<Box<dyn BackendHandle>> {
                Err(CoreError::StartFailed("exit unavailable".into()))
            }
        }
        struct NoTun;
        impl TunBridge for NoTun {
            fn start(&self, _: &SessionConfig, _: &Endpoints) -> Result<()> {
                panic!("must not route TUN through the carrier after exit failure");
            }
            fn stop(&self, _: Duration) {}
            fn is_running(&self) -> bool { false }
        }
        registry::register(FcaeBackend::Psiphon, || Arc::new(FailedExit));
        let mut cfg = SessionConfig::default();
        cfg.mode = FcaeMode::Tun;
        cfg.psiphon.through_tunnel = true;
        let cell = Arc::new(TelemetryCell::new());
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let result = runtime.block_on(run_session(Arc::new(FakeBackend), cfg,
            TelemetrySink::new(cell.clone()), CancelToken::new(), Arc::new(NoTun),
            Duration::from_millis(10), false, 0,
            Arc::new(AtomicBool::new(false)), Arc::new(Mutex::new(())), Arc::new(Mutex::new(None)),
            Arc::new(Mutex::new(None))));
        assert!(result.is_err());
        assert_ne!(cell.snapshot().state, FcaeState::Connected);

        // Positive half: the TUN gets the exit SOCKS/DNS policy, never the
        // primary's plain SOCKS, while retaining the carrier route exclusion.
        struct ExitHandle;
        #[async_trait]
        impl BackendHandle for ExitHandle {
            fn endpoints(&self) -> Endpoints {
                Endpoints { socks: Some("127.0.0.1:1080".parse().unwrap()), http: None,
                    peer_ip: None, udp: false, psiphon_dns: true }
            }
            async fn wait(&self) -> Result<()> { std::future::pending().await }
            async fn stop(&self, _: Duration) -> Result<()> { Ok(()) }
            fn counters(&self) -> Counters { Counters::default() }
        }
        struct ReadyExit;
        #[async_trait]
        impl Backend for ReadyExit {
            fn id(&self) -> BackendId { BackendId::Psiphon }
            fn capabilities(&self) -> Capabilities { FakeBackend.capabilities() }
            async fn start(&self, cx: BackendContext) -> Result<Box<dyn BackendHandle>> {
                if let Some(json) = cx.config.psiphon.config_json {
                    assert!(json.contains("socks5://127.0.0.1:"));
                }
                assert!(!EXIT_READY.load(Ordering::SeqCst));
                tokio::task::yield_now().await;
                EXIT_READY.store(true, Ordering::SeqCst);
                Ok(Box::new(ExitHandle))
            }
        }
        struct CheckTun { cancel: CancelToken, checked: Arc<AtomicBool>, chained: bool }
        impl TunBridge for CheckTun {
            fn start(&self, _: &SessionConfig, ep: &Endpoints) -> Result<()> {
                assert!(EXIT_READY.load(Ordering::SeqCst), "TUN started before the exit connected");
                assert_eq!(ep.socks.unwrap().port(), 1080);
                assert!(ep.psiphon_dns);
                assert!(!ep.udp);
                assert_eq!(ep.peer_ip.as_deref(), if self.chained { Some("203.0.113.7") } else { None });
                self.checked.store(true, Ordering::SeqCst);
                self.cancel.cancel();
                Ok(())
            }
            fn stop(&self, _: Duration) {}
            fn is_running(&self) -> bool { false }
        }
        registry::register(FcaeBackend::Psiphon, || Arc::new(ReadyExit));
        for chained in [true, false] {
            EXIT_READY.store(false, Ordering::SeqCst);
            let mut cfg = SessionConfig::default();
            cfg.mode = FcaeMode::Tun;
            cfg.backend = if chained { FcaeBackend::Aether } else { FcaeBackend::Psiphon };
            cfg.psiphon.through_tunnel = chained;
            let backend: Arc<dyn Backend> = if chained {
                Arc::new(FakeBackend)
            } else {
                Arc::new(ReadyExit)
            };
            let cancel = CancelToken::new();
            let checked = Arc::new(AtomicBool::new(false));
            runtime.block_on(run_session(backend, cfg, TelemetrySink::new(cell.clone()),
                cancel.clone(), Arc::new(CheckTun { cancel, checked: checked.clone(), chained }),
                Duration::from_millis(10), false, 0,
                Arc::new(AtomicBool::new(false)), Arc::new(Mutex::new(())), Arc::new(Mutex::new(None)),
                Arc::new(Mutex::new(None)))).unwrap();
            assert!(checked.load(Ordering::SeqCst));
        }
    }

    #[test]
    fn deterministic_start_errors_are_not_retried() {
        static TRIES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

        struct Fatal;
        #[async_trait]
        impl Backend for Fatal {
            fn id(&self) -> BackendId {
                BackendId::Aether
            }
            fn capabilities(&self) -> Capabilities {
                Capabilities {
                    socks: true,
                    http_proxy: true,
                    gateway_scanning: false,
                    routing_rules: false,
                    requires_privileges: false,
                }
            }
            async fn start(&self, _: BackendContext) -> Result<Box<dyn BackendHandle>> {
                TRIES.fetch_add(1, Ordering::SeqCst);
                Err(CoreError::PermissionDenied("TUN without elevation".into()))
            }
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(run_session(
            Arc::new(Fatal),
            SessionConfig::default(),
            TelemetrySink::new(Arc::new(TelemetryCell::new())),
            CancelToken::new(),
            Arc::new(NullTunBridge),
            Duration::from_millis(10),
            true,  // auto_reconnect on
            0,     // unlimited budget: the error class, not the budget, must stop it
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(())),
            Arc::new(Mutex::new(None)),
            Arc::new(Mutex::new(None)),
        ));
        assert!(result.is_err());
        assert_eq!(TRIES.load(Ordering::SeqCst), 1);
    }

    fn install_fake() {
        registry::register(FcaeBackend::Aether, || Arc::new(FakeBackend));
    }

    #[test]
    fn start_then_stop_reaches_connected_and_back() {
        install_fake();
        let cell = Arc::new(TelemetryCell::new());
        let sup = Supervisor::new(cell.clone(), SupervisorConfig::default());

        sup.start(SessionConfig::default()).expect("start");

        // Wait for the fake backend to report Connected.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while cell.snapshot().state != FcaeState::Connected {
            assert!(std::time::Instant::now() < deadline, "never connected");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(cell.snapshot().connected_peer, "203.0.113.7");
        assert!(sup.is_running());

        sup.stop().expect("stop");
        assert!(!sup.is_running());
        assert_eq!(cell.snapshot().state, FcaeState::Disconnected);
    }

    #[test]
    fn pause_preserves_session_and_resume_unpauses_only_after_success() {
        use std::sync::atomic::AtomicUsize;

        #[derive(Default)]
        struct CountingBridge {
            starts: AtomicUsize,
            stops: AtomicUsize,
            running: AtomicBool,
            fail_resume: AtomicBool,
            paused: Mutex<Option<Arc<AtomicBool>>>,
        }
        impl TunBridge for CountingBridge {
            fn start(&self, _: &SessionConfig, _: &Endpoints) -> Result<()> {
                if self.starts.fetch_add(1, Ordering::SeqCst) > 0 {
                    assert!(self.paused.lock().as_ref().unwrap().load(Ordering::SeqCst));
                    if self.fail_resume.load(Ordering::SeqCst) {
                        return Err(CoreError::Internal("resume failed".into()));
                    }
                }
                self.running.store(true, Ordering::SeqCst);
                Ok(())
            }
            fn stop(&self, _: Duration) {
                self.stops.fetch_add(1, Ordering::SeqCst);
                self.running.store(false, Ordering::SeqCst);
            }
            fn is_running(&self) -> bool {
                self.running.load(Ordering::SeqCst)
            }
        }

        install_fake();
        let bridge = Arc::new(CountingBridge::default());
        let cell = Arc::new(TelemetryCell::new());
        let sup = Supervisor::new(cell.clone(), SupervisorConfig {
            tun_bridge: bridge.clone(),
            auto_reconnect: false,
            ..Default::default()
        });
        *bridge.paused.lock() = Some(sup.tun_paused.clone());
        let mut cfg = SessionConfig::default();
        cfg.mode = FcaeMode::Tun;
        cfg.tun.fd = Some(3);
        sup.start(cfg).expect("start");

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while cell.snapshot().state != FcaeState::Connected {
            assert!(std::time::Instant::now() < deadline, "never connected");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(bridge.starts.load(Ordering::SeqCst), 1);
        assert!(sup.is_running());

        sup.pause_tun();
        sup.pause_tun();
        assert!(sup.tun_is_paused());
        assert_eq!(cell.snapshot().state, FcaeState::Connected);
        assert!(sup.is_running());
        assert_eq!(bridge.stops.load(Ordering::SeqCst), 1);

        bridge.fail_resume.store(true, Ordering::SeqCst);
        assert!(sup.resume_tun().is_err());
        assert!(sup.tun_is_paused());
        assert!(!bridge.is_running());
        assert!(sup.is_running());
        assert_eq!(cell.snapshot().state, FcaeState::Connected);

        bridge.fail_resume.store(false, Ordering::SeqCst);
        sup.resume_tun().expect("resume");
        sup.resume_tun().expect("duplicate resume");
        assert!(!sup.tun_is_paused());
        assert!(bridge.is_running());
        assert_eq!(bridge.starts.load(Ordering::SeqCst), 3);
        assert_eq!(cell.snapshot().state, FcaeState::Connected);

        sup.stop().expect("stop");
    }

    #[test]
    fn health_checks_skip_tun_transitions_but_detect_real_failures() {
        // A transition (control held, or the settle window) never blames the
        // data plane; a device that fails every tick still ends the session,
        // so recovery from a genuinely dead TUN is unchanged.
        use std::sync::atomic::AtomicUsize;

        struct UnhealthyBridge(AtomicUsize);
        impl TunBridge for UnhealthyBridge {
            fn start(&self, _: &SessionConfig, _: &Endpoints) -> Result<()> { Ok(()) }
            fn stop(&self, _: Duration) {}
            fn is_running(&self) -> bool { false }
            fn check_health(&self, _: &SessionConfig) -> Result<()> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(CoreError::Internal("TUN is down".into()))
            }
        }

        let bridge = UnhealthyBridge(AtomicUsize::new(0));
        let handle = FakeHandle;
        let endpoints = handle.endpoints();
        let sink = TelemetrySink::new(Arc::new(TelemetryCell::new()));
        let mut cfg = SessionConfig::default();
        cfg.mode = FcaeMode::Tun;
        let paused = AtomicBool::new(false);
        let control = Mutex::new(());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let settle = Mutex::new(None);
        {
            let _transition = control.lock();
            let result = runtime.block_on(async {
                tokio::time::timeout(Duration::from_millis(10), pump_counters(
                    &handle, &sink, &cfg, &bridge, &paused, &control, &settle, endpoints.peer_ip.as_deref(), &Mutex::new(None),
                )).await
            });
            assert!(result.is_err());
            assert_eq!(bridge.0.load(Ordering::SeqCst), 0);
        }

        {
            *settle.lock() = Some(std::time::Instant::now() + TUN_SETTLE);
            let result = runtime.block_on(async {
                tokio::time::timeout(Duration::from_millis(300), pump_counters(
                    &handle, &sink, &cfg, &bridge, &paused, &control, &settle, endpoints.peer_ip.as_deref(), &Mutex::new(None),
                )).await
            });
            assert!(result.is_err(), "settle window must outlast the probe");
            assert_eq!(bridge.0.load(Ordering::SeqCst), 0);
        }

        *settle.lock() = None;
        let result = runtime.block_on(pump_counters(
            &handle, &sink, &cfg, &bridge, &paused, &control, &settle, endpoints.peer_ip.as_deref(), &Mutex::new(None),
        ));
        assert!(result.is_err());
        assert!(bridge.0.load(Ordering::SeqCst) >= TUN_HEALTH_FAIL_TICKS as usize);
    }

    #[test]
    fn stop_aborts_once_without_running_full_bridge_cleanup_on_caller() {
        use std::sync::atomic::AtomicUsize;

        #[derive(Default)]
        struct RecordingBridge {
            aborts: AtomicUsize,
            stops: AtomicUsize,
        }
        impl TunBridge for RecordingBridge {
            fn start(&self, _: &SessionConfig, _: &Endpoints) -> Result<()> { Ok(()) }
            fn abort(&self) { self.aborts.fetch_add(1, Ordering::SeqCst); }
            fn stop(&self, _: Duration) { self.stops.fetch_add(1, Ordering::SeqCst); }
            fn is_running(&self) -> bool { false }
        }

        for begin_first in [false, true] {
            let bridge = Arc::new(RecordingBridge::default());
            let sup = Supervisor::new(Arc::new(TelemetryCell::new()), SupervisorConfig {
                tun_bridge: bridge.clone(),
                ..Default::default()
            });
            // Hold the worker open independently of scheduler timing. stop()
            // must return without joining it or invoking the slow bridge path.
            let (release, wait) = std::sync::mpsc::channel::<()>();
            let cancel = CancelToken::new();
            *sup.running.lock() = Some(Running {
                cancel: cancel.clone(),
                thread: std::thread::spawn(move || { let _ = wait.recv(); }),
            });
            if begin_first {
                sup.begin_stop();
                sup.begin_stop();
            }
            sup.stop().unwrap();
            sup.stop().unwrap();
            sup.begin_stop();
            assert!(cancel.is_cancelled());
            assert_eq!(bridge.aborts.load(Ordering::SeqCst), 1);
            assert_eq!(bridge.stops.load(Ordering::SeqCst), 0);
            assert!(sup.stopping.load(Ordering::SeqCst), "worker still owns cleanup");
            release.send(()).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while sup.stopping.load(Ordering::SeqCst) {
                assert!(std::time::Instant::now() < deadline, "reaper did not finish");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    #[test]
    fn duplicate_stop_preserves_reaper_barrier() {
        let sup = Supervisor::new(Arc::new(TelemetryCell::new()), SupervisorConfig::default());
        // Model the interval after stop took the worker but before it joined.
        sup.stopping.store(true, Ordering::SeqCst);
        sup.stop().unwrap();
        sup.begin_stop();
        assert!(sup.stopping.load(Ordering::SeqCst));
    }

    #[test]
    fn idle_stop_does_not_block_next_start() {
        let sup = Supervisor::new(Arc::new(TelemetryCell::new()), SupervisorConfig::default());
        sup.begin_stop();
        sup.stop().unwrap();
        assert!(!sup.stopping.load(Ordering::SeqCst));
    }

    #[test]
    fn double_start_is_rejected() {
        install_fake();
        let cell = Arc::new(TelemetryCell::new());
        let sup = Supervisor::new(cell, SupervisorConfig::default());
        sup.start(SessionConfig::default()).expect("first start");
        let err = sup.start(SessionConfig::default()).unwrap_err();
        assert!(matches!(err, CoreError::AlreadyRunning));
        sup.stop().unwrap();
    }

    #[test]
    fn tun_without_privileges_is_refused_early() {
        install_fake();
        let cell = Arc::new(TelemetryCell::new());
        let sup = Supervisor::new(
            cell,
            SupervisorConfig {
                is_privileged: || false,
                ..Default::default()
            },
        );
        let cfg = SessionConfig {
            mode: FcaeMode::Tun,
            ..Default::default()
        };
        assert!(matches!(
            sup.start(cfg).unwrap_err(),
            CoreError::PermissionDenied(_)
        ));
    }
}
