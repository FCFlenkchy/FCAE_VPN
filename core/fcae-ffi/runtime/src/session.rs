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

use fcae_abi::{FcaeBackend, FcaeMode, FcaeState, FcaeTorMode};
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

/// The single live session.
pub struct Supervisor {
    cfg: SupervisorConfig,
    telemetry: Arc<TelemetryCell>,
    running: Mutex<Option<Running>>,
    /// Set while a stop is in progress so a concurrent start waits rather
    /// than racing the teardown. Arc so a timed-out join can still clear it
    /// from the reaper thread once the session actually exits.
    stopping: Arc<AtomicBool>,
}

impl Supervisor {
    pub fn new(telemetry: Arc<TelemetryCell>, cfg: SupervisorConfig) -> Self {
        Self {
            cfg,
            telemetry,
            running: Mutex::new(None),
            stopping: Arc::new(AtomicBool::new(false)),
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
        // stop() returns before native cleanup finishes. Reconnect must wait
        // for the background reaper rather than racing that cleanup.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut slot = loop {
            let slot = self.running.lock();
            if !self.stopping.load(Ordering::SeqCst) { break slot; }
            drop(slot);
            if std::time::Instant::now() >= deadline {
                return Err(CoreError::Timeout(Duration::from_secs(2)));
            }
            std::thread::sleep(Duration::from_millis(1));
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
                        backend.clone(),
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
                // A cancelled start may not have returned a BackendHandle.
                // Drain its retained task while its runtime is still alive.
                // Dropping the runtime early force-cancelled Tor despite the
                // no-abort policy in BackendHandle::stop, and let the reaper
                // release the next-start barrier before task destructors ran.
                rt.block_on(backend.drain());
                drop(rt); // worker/reaper waits; stop() on the UI still returns promptly

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
        // Tor bootstrap is far slower than a WARP scan; using only
        // start_timeout() cancelled a healthy tor start, dropped the
        // engine task, and the next disconnect/connect crashed.
        let start_budget = if config.tor.is_enabled() {
            config.tor_start_timeout()
        } else {
            config.start_timeout()
        };
        let handle = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            started = backend.start(cx) => started,
            _ = tokio::time::sleep(start_budget) => {
                Err(CoreError::Timeout(start_budget))
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

        // `handle` needs no `mut` (only `endpoints` below is reassigned).
        let mut endpoints = handle.endpoints();
        if let Some(peer) = &endpoints.peer_ip {
            sink.set_peer(peer.clone());
        }

        // Egress "Psiphon through the tunnel": Aether is up; start Psiphon
        // with UpstreamProxyURL = Aether SOCKS, then tun2socks dials Psiphon.
        //
        // psi_handle owns the second hop and MUST be stopped on every exit
        // path below, in teardown order: TUN first, then Psiphon (it dials
        // through Aether), then Aether. Skipping the psi stop left the
        // controller and its SOCKS listener running after a disconnect --
        // and the next connect failed with "already running" (which is how
        // the unused-variable warning earned its keep as a real leak).
        let mut psi_handle: Option<Box<dyn BackendHandle>> = None;
        if config.psiphon.through_tunnel {
            match start_psiphon_through_tunnel(&config, &endpoints, &sink, &cancel).await {
                Ok(h) => {
                    let psi_ep = h.endpoints();
                    if psi_ep.socks.is_none() {
                        let _ = h.stop(stop_timeout).await;
                        let _ = handle.stop(stop_timeout).await;
                        return Err(CoreError::StartFailed("Psiphon exit has no SOCKS endpoint".into()));
                    }
                    endpoints = Endpoints { peer_ip: endpoints.peer_ip.clone(), ..psi_ep };
                    psi_handle = Some(h);
                }
                Err(e) => {
                    // Never silently send requested Psiphon traffic through
                    // the carrier. No TUN is raised before the final exit.
                    stop_chained_handles(&psi_handle, &handle, stop_timeout).await;
                    if cancel.is_cancelled() { return Ok(()); }
                    return Err(e);
                }
            }
        }

        // Raise TUN once the backend's SOCKS endpoint is actually live.
        //
        // Proxy mode deliberately falls through: the backend's own SOCKS/HTTP
        // listeners are the entire product there, and tun2socks must never be
        // started -- no device, no routes, no Go stack.
        if config.mode == FcaeMode::Tun {
            if cancel.is_cancelled() {
                stop_chained_handles(&psi_handle, &handle, stop_timeout).await;
                return Ok(());
            }
            if let Err(e) = tun_bridge.start(&config, &endpoints) {
                stop_chained_handles(&psi_handle, &handle, stop_timeout).await;
                return Err(e);
            }
            if cancel.is_cancelled() {
                tun_bridge.stop(stop_timeout);
                stop_chained_handles(&psi_handle, &handle, stop_timeout).await;
                return Ok(());
            }
        } else {
            debug_assert!(
                !tun_bridge.is_running(),
                "proxy mode must never leave a TUN device up"
            );
        }

        sink.set_state(
            FcaeState::Connected,
            format!("Connected ({} {})", exit_name(&config),
                if config.mode == FcaeMode::Tun { "TUN" } else { "Proxy" }),
        );

        // Pump counters into telemetry while we wait for the tunnel to end.
        let outcome = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tun_bridge.stop(stop_timeout);
                stop_chained_handles(&psi_handle, &handle, stop_timeout).await;
                return Ok(());
            }
            r = async {
                if let Some(psi) = psi_handle.as_ref() {
                    tokio::select! { r = handle.wait() => r, r = psi.wait() => r }
                } else { handle.wait().await }
            } => r,
            _ = pump_counters(&*handle, &sink) => Ok(()),
        };

        // Tunnel ended. Tear the bridge down before retrying so the new
        // session gets a clean device instead of inheriting a half-configured
        // one. Psiphon (the chained hop) goes down with the bridge, before
        // Aether, so it never outlives its own upstream.
        tun_bridge.stop(stop_timeout);
        stop_chained_handles(&psi_handle, &handle, stop_timeout).await;

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

/// Stop the chained Psiphon hop (if any) and then the primary backend, in
/// that order: psi dials through Aether's SOCKS, so it must not outlive it.
/// Both stops are best-effort and idempotent (each handle guards itself).
async fn stop_chained_handles(
    psi: &Option<Box<dyn BackendHandle>>,
    primary: &Box<dyn BackendHandle>,
    timeout: Duration,
) {
    if let Some(psi) = psi.as_ref() {
        let _ = psi.stop(timeout).await;
    }
    let _ = primary.stop(timeout).await;
}

/// Start Psiphon as the egress hop in front of an already-up Aether SOCKS.
async fn start_psiphon_through_tunnel(
    config: &SessionConfig,
    aether: &Endpoints,
    sink: &TelemetrySink,
    cancel: &CancelToken,
) -> Result<Box<dyn BackendHandle>> {
    let socks = aether.socks.ok_or_else(|| {
        CoreError::StartFailed(
            "Psiphon through the tunnel needs Aether's SOCKS listener".into(),
        )
    })?;
    let url = format!("socks5://{socks}");
    let mut psi_cfg = config.clone();
    psi_cfg.backend = FcaeBackend::Psiphon;
    psi_cfg.psiphon.through_tunnel = false;
    let json = psi_cfg
        .psiphon
        .config_json
        .as_deref()
        .unwrap_or("{}");
    psi_cfg.psiphon.config_json = Some(crate::config::inject_upstream_proxy_url(json, &url));

    let backend = registry::resolve(FcaeBackend::Psiphon)?;
    sink.set_state(
        FcaeState::Connecting,
        format!("Starting Psiphon through {url}…"),
    );
    let cx = BackendContext::new(psi_cfg, sink.clone(), cancel.clone());
    let handle = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(CoreError::StartFailed("chain cancelled".into())),
        r = tokio::time::timeout(config.start_timeout().max(Duration::from_secs(120)), backend.start(cx)) =>
            r.map_err(|_| CoreError::StartFailed("Psiphon exit startup timed out".into()))??,
    };
    log::info!("[session] Psiphon through-tunnel via {url}");
    Ok(handle)
}

fn exit_name(config: &SessionConfig) -> &'static str {
    if config.backend == FcaeBackend::Psiphon || config.psiphon.through_tunnel { "Psiphon" }
    else if matches!(config.tor.mode, FcaeTorMode::Only | FcaeTorMode::Chain) { "Tor" }
    else { "Aether" }
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
                udp: true,
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
        assert_eq!(exit_name(&cfg), "Aether");
        cfg.tor.mode = FcaeTorMode::Chain;
        assert_eq!(exit_name(&cfg), "Tor");
        cfg.tor.mode = FcaeTorMode::Reverse;
        assert_eq!(exit_name(&cfg), "Aether");
        cfg.tor.mode = FcaeTorMode::Only;
        assert_eq!(exit_name(&cfg), "Tor");
        cfg.psiphon.through_tunnel = true;
        assert_eq!(exit_name(&cfg), "Psiphon");
    }

    #[test]
    fn failed_psiphon_chain_never_raises_tun() {
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
            Duration::from_millis(10), false, 0));
        assert!(result.is_err());
        assert_ne!(cell.snapshot().state, FcaeState::Connected);

        // Positive half: the TUN gets the exit SOCKS endpoint, never the
        // primary's plain SOCKS, while retaining the carrier route exclusion.
        struct ExitHandle;
        #[async_trait]
        impl BackendHandle for ExitHandle {
            fn endpoints(&self) -> Endpoints {
                Endpoints { socks: Some("127.0.0.1:1080".parse().unwrap()), http: None,
                    peer_ip: None, udp: true }
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
                assert!(cx.config.psiphon.config_json.unwrap().contains("socks5://127.0.0.1:1819"));
                Ok(Box::new(ExitHandle))
            }
        }
        struct CheckTun { cancel: CancelToken, checked: Arc<AtomicBool> }
        impl TunBridge for CheckTun {
            fn start(&self, _: &SessionConfig, ep: &Endpoints) -> Result<()> {
                assert_eq!(ep.socks.unwrap().port(), 1080);
                assert!(ep.udp);
                assert_eq!(ep.peer_ip.as_deref(), Some("203.0.113.7"));
                self.checked.store(true, Ordering::SeqCst);
                self.cancel.cancel();
                Ok(())
            }
            fn stop(&self, _: Duration) {}
            fn is_running(&self) -> bool { false }
        }
        registry::register(FcaeBackend::Psiphon, || Arc::new(ReadyExit));
        let mut cfg = SessionConfig::default();
        cfg.mode = FcaeMode::Tun;
        cfg.psiphon.through_tunnel = true;
        let cancel = CancelToken::new();
        let checked = Arc::new(AtomicBool::new(false));
        runtime.block_on(run_session(Arc::new(FakeBackend), cfg, TelemetrySink::new(cell),
            cancel.clone(), Arc::new(CheckTun { cancel, checked: checked.clone() }),
            Duration::from_millis(10), false, 0)).unwrap();
        assert!(checked.load(Ordering::SeqCst));
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
