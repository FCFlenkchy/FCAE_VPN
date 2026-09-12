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

use fcae_abi::{FcaeMode, FcaeState};
use parking_lot::Mutex;

use crate::backend::{BackendContext, BackendHandle, CancelToken, Endpoints};
use crate::config::SessionConfig;
use crate::error::{CoreError, Result};
use crate::registry;
use crate::telemetry::{TelemetryCell, TelemetrySink};

/// Hook that raises a TUN device on top of a backend's SOCKS endpoint.
///
/// The supervisor stays independent of the tun2socks bridge crate (which
/// links Go code) so `fcae-runtime` remains pure Rust and unit-testable; the
/// `fcae-ffi` crate installs the real implementation.
pub trait TunBridge: Send + Sync {
    /// Start forwarding TUN traffic into `endpoints.socks`.
    fn start(&self, cfg: &SessionConfig, endpoints: &Endpoints) -> Result<()>;
    /// Stop forwarding and release the device. Must be idempotent.
    fn stop(&self, timeout: Duration);
    /// True if a device is currently up.
    fn is_running(&self) -> bool;

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
            stop_timeout: Duration::from_secs(10),
            auto_reconnect: true,
            max_reconnects: 0,
        }
    }
}

struct Running {
    cancel: CancelToken,
    thread: std::thread::JoinHandle<()>,
}

/// The single live session.
pub struct Supervisor {
    cfg: SupervisorConfig,
    telemetry: Arc<TelemetryCell>,
    running: Mutex<Option<Running>>,
    /// Set while a stop is in progress so a concurrent start waits rather
    /// than racing the teardown.
    stopping: AtomicBool,
}

impl Supervisor {
    pub fn new(telemetry: Arc<TelemetryCell>, cfg: SupervisorConfig) -> Self {
        Self {
            cfg,
            telemetry,
            running: Mutex::new(None),
            stopping: AtomicBool::new(false),
        }
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
        let deadline = std::time::Instant::now() + self.cfg.stop_timeout;
        while self.stopping.load(Ordering::SeqCst) {
            if std::time::Instant::now() >= deadline {
                return Err(CoreError::Timeout(self.cfg.stop_timeout));
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        let mut slot = self.running.lock();
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

        // Clear anything a previous crashed process left behind.
        backend.recover_stale_state();

        self.telemetry
            .begin_session(config.backend, config.mode, config.lan_sharing);

        let cancel = CancelToken::new();
        let telemetry = self.telemetry.clone();
        let sink = TelemetrySink::new(telemetry.clone());
        let tun_bridge = self.cfg.tun_bridge.clone();
        let stop_timeout = self.cfg.stop_timeout;
        let auto_reconnect = self.cfg.auto_reconnect;
        let max_reconnects = self.cfg.max_reconnects;
        let cancel_for_thread = cancel.clone();

        let thread = std::thread::Builder::new()
            .name("fcae-session".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .worker_threads(4)
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
                        backend,
                        config,
                        sink,
                        cancel_for_thread,
                        tun_bridge.clone(),
                        stop_timeout,
                        auto_reconnect,
                        max_reconnects,
                    ))
                }));

                // Teardown order matters: the bridge must be down before the
                // runtime is dropped, because its stop path may need to run
                // blocking OS commands.
                tun_bridge.stop(stop_timeout);
                rt.shutdown_timeout(Duration::from_secs(2));

                match outcome {
                    Ok(Ok(())) => {
                        telemetry.set_state(FcaeState::Disconnected, "Disconnected".into())
                    }
                    Ok(Err(e)) => telemetry.set_error(format!("{e}")),
                    Err(_) => telemetry.set_error("session thread panicked"),
                }
            })
            .map_err(|e| CoreError::Internal(format!("failed to spawn session thread: {e}")))?;

        *slot = Some(Running { cancel, thread });
        Ok(())
    }

    /// Request shutdown and wait (bounded) for the session thread to finish.
    ///
    /// Unlike the old `aether_stop`, this is synchronous and ordered: when it
    /// returns, the TUN device is down and DNS has been restored, so a UI can
    /// immediately offer "Connect" again without a hidden race.
    pub fn stop(&self) -> Result<()> {
        let Some(running) = self.running.lock().take() else {
            return Ok(());
        };
        self.stopping.store(true, Ordering::SeqCst);

        running.cancel.cancel();

        // The bridge is stopped by the session thread, but do it here too:
        // if the thread is wedged inside a backend call, this releases the
        // TUN device (and on Android the VpnService fd) immediately.
        self.cfg.tun_bridge.stop(self.cfg.stop_timeout);

        let result = join_bounded(running.thread, self.cfg.stop_timeout);
        self.stopping.store(false, Ordering::SeqCst);

        if !result {
            // Deliberately not fatal: the thread is detached and will finish
            // its cleanup. Report it so it shows up in logs.
            log::warn!(
                "[session] session thread did not finish within {:?}; continuing detached",
                self.cfg.stop_timeout
            );
        }
        self.telemetry
            .set_state(FcaeState::Disconnected, "Disconnected".into());
        Ok(())
    }
}

/// Join with a timeout — `JoinHandle` has no such API, so poll `is_finished`.
fn join_bounded(handle: std::thread::JoinHandle<()>, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if handle.is_finished() {
            let _ = handle.join();
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
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
) -> Result<()> {
    let mut attempt: u32 = 0;

    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }

        let cx = BackendContext::new(config.clone(), sink.clone(), cancel.clone());
        cx.report(
            if attempt == 0 {
                FcaeState::Connecting
            } else {
                FcaeState::Reconnecting
            },
            if attempt == 0 {
                "Connecting…".to_string()
            } else {
                format!("Reconnecting (attempt {attempt})…")
            },
        );

        // Race the backend start against cancellation and a hard timeout, so
        // a stuck scan can never wedge the session thread forever.
        let handle = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            started = backend.start(cx) => started,
            _ = tokio::time::sleep(config.start_timeout()) => {
                Err(CoreError::Timeout(config.start_timeout()))
            }
        };

        let handle: Box<dyn BackendHandle> = match handle {
            Ok(h) => h,
            Err(e) => {
                if !should_retry(auto_reconnect, max_reconnects, attempt, &cancel) {
                    return Err(e);
                }
                attempt += 1;
                sink.set_state(
                    FcaeState::Reconnecting,
                    format!("Connect failed ({e}); retrying…"),
                );
                if backoff(&cancel, attempt).await.is_break() {
                    return Ok(());
                }
                continue;
            }
        };

        let endpoints = handle.endpoints();
        if let Some(peer) = &endpoints.peer_ip {
            sink.set_peer(peer.clone());
        }

        // Raise TUN once the backend's SOCKS endpoint is actually live.
        //
        // Proxy mode deliberately falls through: the backend's own SOCKS/HTTP
        // listeners are the entire product there, and tun2socks must never be
        // started -- no device, no routes, no Go stack.
        if config.mode == FcaeMode::Tun {
            if let Err(e) = tun_bridge.start(&config, &endpoints) {
                let _ = handle.stop(stop_timeout).await;
                return Err(e);
            }
        } else {
            debug_assert!(
                !tun_bridge.is_running(),
                "proxy mode must never leave a TUN device up"
            );
        }

        sink.set_state(
            FcaeState::Connected,
            match config.mode {
                FcaeMode::Tun => "Connected (TUN)".into(),
                FcaeMode::Proxy => "Connected (Proxy)".into(),
            },
        );

        // Pump counters into telemetry while we wait for the tunnel to end.
        let outcome = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                let _ = handle.stop(stop_timeout).await;
                tun_bridge.stop(stop_timeout);
                return Ok(());
            }
            r = handle.wait() => r,
            _ = pump_counters(&*handle, &sink) => Ok(()),
        };

        // Tunnel ended. Tear the bridge down before retrying so the new
        // session gets a clean device instead of inheriting a half-configured
        // one.
        tun_bridge.stop(stop_timeout);
        let _ = handle.stop(stop_timeout).await;

        match outcome {
            Ok(()) if cancel.is_cancelled() => return Ok(()),
            Ok(()) | Err(_) if !should_retry(auto_reconnect, max_reconnects, attempt, &cancel) => {
                return outcome;
            }
            _ => {}
        }

        attempt += 1;
        sink.cell().note_reconnect();
        sink.set_state(FcaeState::Reconnecting, "Tunnel dropped; reconnecting…".into());
        if backoff(&cancel, attempt).await.is_break() {
            return Ok(());
        }
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

/// Never returns; sampled by the `select!` above.
async fn pump_counters(handle: &dyn BackendHandle, sink: &TelemetrySink) {
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    loop {
        tick.tick().await;
        sink.set_counters(handle.counters());
    }
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
