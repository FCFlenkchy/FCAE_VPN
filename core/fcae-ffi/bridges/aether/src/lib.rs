//! # fcae-bridge-aether
//!
//! Adapts the existing `aether-engine` crate to the [`Backend`] trait.
//!
//! This is a *tunnel* bridge: it implements [`Backend`], meaning it
//! **produces** a SOCKS endpoint. Contrast `fcae-bridge-tun2socks`, which
//! implements `TunBridge` and **consumes** one. The supervisor composes the
//! two, which is why any tunnel bridge gets TUN mode without knowing TUN
//! exists.
//!
//! Nothing is vendored here — `aether-engine` lives in `core/Aether/` and is
//! referenced as a path dependency. This crate is ~300 lines of adapter.
//!
//! The engine's public surface is still `run_from_env()` — a single future
//! that reads configuration from environment variables and runs until it
//! fails. This crate is the seam that isolates that legacy shape from the
//! rest of the stack:
//!
//! * config is applied through the one clearly-marked
//!   [`env_compat`](fcae_runtime::config::env_compat) shim,
//! * the engine is told to stay in **proxy mode** — the supervisor owns TUN
//!   now, via the in-process bridge, so the engine no longer spawns
//!   `tun2socks` itself,
//! * readiness is determined by probing the SOCKS port rather than by
//!   substring-matching log lines.
//!
//! When the engine eventually grows a `run(config)` entry point, only this
//! file changes.

use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use fcae_abi::FcaeState;
use fcae_runtime::backend::{
    Backend, BackendContext, BackendHandle, BackendId, Capabilities, Counters, Endpoints,
};
use fcae_abi::FcaeTorMode;
use fcae_runtime::config::{env_compat, SessionConfig};
use fcae_runtime::error::{CoreError, Result};
use fcae_runtime::telemetry::TelemetrySink;
use parking_lot::Mutex;
use tokio::sync::Notify;

/// Register this backend with the core registry.
pub fn register() {
    fcae_runtime::registry::register(fcae_abi::FcaeBackend::Aether, || Arc::new(AetherBackend));
    register_update_provider();
}

pub struct AetherBackend;

#[async_trait]
impl Backend for AetherBackend {
    fn id(&self) -> BackendId {
        BackendId::Aether
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            socks: true,
            http_proxy: true,
            gateway_scanning: true,
            routing_rules: true,
            // Proxy mode needs no elevation; TUN does, and the supervisor
            // checks that separately based on the session mode.
            requires_privileges: false,
        }
    }

    async fn start(&self, cx: BackendContext) -> Result<Box<dyn BackendHandle>> {
        let cfg = cx.config.clone();

        // Project the typed config onto the engine's env vars. This always
        // writes *every* variable it owns, so nothing leaks in from the
        // previous session.
        // Fail fast on a Tor request this binary cannot honour. Without this
        // the engine starts, runs, and only reports "this build has no tor
        // support" from deep inside the egress setup -- by which point the UI
        // is already showing "Connecting".
        if cfg.tor.is_enabled() && !cfg!(feature = "tor") {
            return Err(CoreError::InvalidConfig(format!(
                "tor mode `{}` was requested but this build has no tor support; \
                 rebuild with `--features tor`",
                tor_mode_label(cfg.tor.mode)
            )));
        }

        env_compat::apply(&cfg);
        aether_engine::reset_stats();

        cx.report(FcaeState::Scanning, "Scanning gateways…");

        let done = Arc::new(Notify::new());
        let finished = Arc::new(AtomicBool::new(false));
        let outcome: Arc<Mutex<Option<std::result::Result<(), String>>>> =
            Arc::new(Mutex::new(None));

        // The engine future is driven on the supervisor's runtime. It is
        // spawned rather than awaited so `start` can return once the SOCKS
        // endpoint is live, while the tunnel keeps running.
        let engine_task = {
            let done = done.clone();
            let finished = finished.clone();
            let outcome = outcome.clone();
            let sink = cx.telemetry.clone();
            tokio::spawn(async move {
                let result = aether_engine::run_from_env().await;
                let mapped = match result {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        let msg = format!("{e:#}");
                        sink.set_error(msg.clone());
                        Err(msg)
                    }
                };
                *outcome.lock() = Some(mapped);
                finished.store(true, Ordering::SeqCst);
                done.notify_waiters();
            })
        };

        // Readiness = the SOCKS listener actually accepting connections.
        // Log-scraping for "socks5 ... listening" (the old approach) silently
        // broke whenever a message was reworded, and never fired at all in
        // TUN mode without LAN sharing.
        let socks_addr: SocketAddr = format!("{}:{}", "127.0.0.1", cfg.socks_port)
            .parse()
            .map_err(|e| CoreError::InvalidConfig(format!("bad socks address: {e}")))?;

        cx.report(FcaeState::Connecting, "Establishing tunnel…");

        let ready = wait_for_listener(socks_addr, cfg.start_timeout(), &finished).await;

        if !ready {
            // Either the engine died, or it never opened the port.
            engine_task.abort();
            let msg = outcome
                .lock()
                .clone()
                .and_then(|r| r.err())
                .unwrap_or_else(|| {
                    format!(
                        "the Aether engine did not open its SOCKS listener on {socks_addr} within {:?}",
                        cfg.start_timeout()
                    )
                });
            return Err(CoreError::StartFailed(msg));
        }

        Ok(Box::new(AetherHandle {
            cfg,
            socks_addr,
            task: Mutex::new(Some(engine_task)),
            done,
            finished,
            outcome,
        }))
    }

    fn recover_stale_state(&self) {
        // A previous process may have died with a TUN adapter still up. With
        // the subprocess gone there is no orphan to kill any more — only
        // leftover OS state, which the bridge's own configure step handles by
        // reusing the stable adapter GUID.
        log::debug!("[aether] no stale subprocess state to recover (in-process design)");
    }
}

/// Poll-connect until the listener answers, the engine dies, or we time out.
async fn wait_for_listener(addr: SocketAddr, timeout: Duration, finished: &AtomicBool) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if finished.load(Ordering::SeqCst) {
            return false;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        let probe = tokio::task::spawn_blocking(move || {
            TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
        })
        .await
        .unwrap_or(false);

        if probe {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

struct AetherHandle {
    cfg: SessionConfig,
    socks_addr: SocketAddr,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    done: Arc<Notify>,
    finished: Arc<AtomicBool>,
    outcome: Arc<Mutex<Option<std::result::Result<(), String>>>>,
}

#[async_trait]
impl BackendHandle for AetherHandle {
    fn endpoints(&self) -> Endpoints {
        Endpoints {
            socks: Some(self.socks_addr),
            http: (self.cfg.http_port != 0)
                .then(|| format!("127.0.0.1:{}", self.cfg.http_port).parse().ok())
                .flatten(),
            peer_ip: self.cfg.force_peer.as_ref().and_then(|p| {
                p.rsplit_once(':')
                    .map(|(host, _)| host.trim_matches(['[', ']']).to_string())
                    .or_else(|| Some(p.clone()))
            }),
        }
    }

    async fn wait(&self) -> Result<()> {
        while !self.finished.load(Ordering::SeqCst) {
            self.done.notified().await;
        }
        match self.outcome.lock().clone() {
            Some(Ok(())) | None => Ok(()),
            Some(Err(msg)) => Err(CoreError::Internal(msg)),
        }
    }

    async fn stop(&self, timeout: Duration) -> Result<()> {
        let Some(task) = self.task.lock().take() else {
            return Ok(());
        };

        // The engine has no cooperative shutdown entry point, so aborting the
        // task is still how it ends. The crucial difference from before: no
        // child process, no TUN device and no OS state depend on this task
        // unwinding cleanly — the bridge and the supervisor already own those,
        // and they are torn down first.
        task.abort();

        let _ = tokio::time::timeout(timeout, async {
            let _ = task.await;
        })
        .await;

        Ok(())
    }

    fn counters(&self) -> Counters {
        let (rx, tx) = aether_engine::rates();
        Counters {
            total_rx: aether_engine::total_rx(),
            total_tx: aether_engine::total_tx(),
            rx_bytes_sec: rx,
            tx_bytes_sec: tx,
            rtt_ms: aether_engine::rtt_ms() as u32,
        }
    }
}

fn tor_mode_label(mode: FcaeTorMode) -> &'static str {
    match mode {
        FcaeTorMode::Off => "off",
        FcaeTorMode::Chain => "chain",
        FcaeTorMode::Reverse => "reverse",
        FcaeTorMode::Only => "only",
    }
}

/// Unused today, kept so the file documents where the sink is threaded.
#[allow(dead_code)]
fn _sink_type_check(_s: &TelemetrySink) {}

// ── Update-check provider ───────────────────────────────────────────────

/// Install Aether's `version_checker` as the app's update provider.
///
/// The update check is an application concern, so `fcae-runtime` owns the state
/// machine and only the fetch/parse pair is supplied here. That keeps the
/// version.json format an Aether-repo detail while leaving the UI, the FFI and
/// any future backend untouched.
pub fn register_update_provider() {
    fcae_runtime::update::install_provider(fcae_runtime::update::Provider {
        check: |current, include_prereleases| {
            // The engine's fetcher is async and needs a reactor; core calls us
            // on a plain worker thread, so give it a small current-thread
            // runtime rather than requiring a global one.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("failed to build update runtime: {e}"))?;
            let info = rt.block_on(aether_engine::version_checker::fetch_latest_version())?;
            let r = aether_engine::version_checker::compare_versions(
                current,
                &info,
                include_prereleases,
            );
            Ok(to_core_result(r))
        },
        parse: |current, json, include_prereleases| {
            let r = aether_engine::version_checker::check_from_json(
                current,
                json,
                include_prereleases,
            )?;
            Ok(to_core_result(r))
        },
    });
}

/// Translate the engine's result type into the backend-neutral one.
fn to_core_result(
    r: aether_engine::version_checker::UpdateCheckResult,
) -> fcae_runtime::update::UpdateResult {
    fcae_runtime::update::UpdateResult {
        update_available: r.update_available,
        is_prerelease: r.is_prerelease,
        current_version: r.current_version,
        latest_version: r.latest_version,
        release_notes: r.release_notes,
        download_url: r.download_url,
        release_date: r.release_date,
    }
}
