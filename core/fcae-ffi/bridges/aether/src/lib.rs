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

// The aether engine future this crate awaits is deeply nested; its layout
// is computed here too, so the raised limit has to be repeated (the
// attribute is per-crate, not inherited).
#![recursion_limit = "512"]

use std::io::{Read, Write};
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

/// The most recent engine task, so the next start can make sure the
/// previous engine is fully dead before it binds anything.
///
/// A dying engine is not harmless: its reconnect loop keeps scanning and
/// redialling (sleeps the shutdown signal does not wake), and the next
/// start's shutdown::reset() would clear the flag that loop needs to see
/// -- the old engine would survive, rescan, and hold on while the new one
/// fights it for the ports.
static LAST_ENGINE: Mutex<Option<tokio::task::JoinHandle<()>>> = Mutex::new(None);

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

        // Make sure a previous engine is fully dead BEFORE anything new
        // binds or clears flags (see LAST_ENGINE).
        reap_previous_engine().await;

        env_compat::apply(&cfg);
        aether_engine::reset_stats();

        // Clear the flag the last stop() left behind. Without this, the
        // guard below sees the PREVIOUS stop's request and the new engine
        // never starts: "connect, disconnect, connect -> never works"
        // until the process is restarted. The guard still fires for a
        // stop() that lands AFTER this reset and BEFORE the task's first
        // poll, which is the race it exists for.
        aether_engine::shutdown::reset();

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
                // Completion must be signalled even if this task is ABORTED
                // (a stop() can land mid-start): the waiters in start() and
                // wait() poll `finished`, and would otherwise spin until
                // their own timeout for an engine that will never come.
                struct FinishGuard {
                    finished: Arc<AtomicBool>,
                    done: Arc<Notify>,
                    fired: bool,
                }
                impl Drop for FinishGuard {
                    fn drop(&mut self) {
                        if !self.fired {
                            self.finished.store(true, Ordering::SeqCst);
                            self.done.notify_waiters();
                        }
                    }
                }
                let mut guard = FinishGuard {
                    finished: finished.clone(),
                    done: done.clone(),
                    fired: false,
                };

                // Cancellation is checked before the engine starts: stop()
                // can land between the supervisor deciding to (re)connect and
                // this task being polled, and run_from_env() begins with
                // shutdown::reset(), which would wipe that request and leave
                // the engine running after a stop.
                let result = if aether_engine::shutdown::is_cancelled() {
                    Ok(())
                } else {
                    aether_engine::run_from_env().await
                };
                let mapped = match result {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        let msg = format!("{e:#}");
                        sink.set_error(msg.clone());
                        Err(msg)
                    }
                };
                *outcome.lock() = Some(mapped);
                guard.fired = true;
                finished.store(true, Ordering::SeqCst);
                done.notify_waiters();
            })
        };
        // Sole owner of the handle: the failure paths below abort through
        // it, stop() takes it, and the next start reaps it.
        *LAST_ENGINE.lock() = Some(engine_task);

        // Readiness = the SOCKS listener actually accepting connections.
        // Log-scraping for "socks5 ... listening" (the old approach) silently
        // broke whenever a message was reworded, and never fired at all in
        // TUN mode without LAN sharing.
        //
        // WHICH proxy the traffic must use.
        //
        // Chain mode: traffic only reaches the tor network via the SOCKS port
        // tor itself opens (AETHER_TOR_BIND, default 127.0.0.1:1821). The
        // engine's own port is the *plain* tunnel: in Chain mode it is the
        // carrier tor dials out through, so pointing the TUN (or a SOCKS
        // client) at it bypasses tor completely -- the UI said "tor ready"
        // while every packet left through plain WARP, which is why check
        // sites reported a Cloudflare address instead of a tor exit.
        //
        // Only mode: there is no WARP tunnel, so the engine serves tor on
        // the Tor SOCKS port itself (env_compat points AETHER_SOCKS at it
        // and tor::run_only binds tor to that address). The session's socks
        // port is unused in this mode. The old "tor on 1819" behavior came
        // from run_only binding to the session port: the UI said "Tor SOCKS
        // port: 1821" while nothing listened there, and 1819 -- which looks
        // like the plain tunnel port -- carried the tor traffic.
        //
        // Reverse mode is the opposite: tor is the carrier *underneath* the
        // tunnel, so the engine's SOCKS port is already the correct exit.
        let engine_socks: SocketAddr = if cfg.tor.mode == FcaeTorMode::Only {
            local_dial_addr(
                cfg.tor
                    .bind
                    .as_deref()
                    .ok_or_else(|| CoreError::InvalidConfig("tor is enabled but no bind address".into()))?,
            )?
        } else {
            format!("{}:{}", "127.0.0.1", cfg.socks_port)
                .parse()
                .map_err(|e| CoreError::InvalidConfig(format!("bad socks address: {e}")))?
        };

        let tor_socks: Option<SocketAddr> = match cfg.tor.mode {
            // config::parse always resolves tor.bind, so there is no default
            // to re-derive here -- doing so twice is how the port drifted.
            FcaeTorMode::Chain => Some(
                local_dial_addr(
                    cfg.tor
                        .bind
                        .as_deref()
                        .ok_or_else(|| CoreError::InvalidConfig("tor is enabled but no bind address".into()))?,
                )?,
            ),
            // In Only mode tor IS the session endpoint (see above).
            FcaeTorMode::Only => Some(engine_socks),
            FcaeTorMode::Off | FcaeTorMode::Reverse => None,
        };
        let socks_addr = tor_socks.unwrap_or(engine_socks);
        log::info!(
            "[aether] engine starting: endpoint {}, tor {} (tor port {})",
            engine_socks,
            tor_mode_label(cfg.tor.mode),
            cfg.tor.bind.as_deref().unwrap_or("-"),
        );

        // In Only mode the port we wait on IS tor. A bare TCP connect is not
        // enough there: the engine binds tor's listener before bootstrap
        // finishes (the kernel backlog absorbs connections), so "port open"
        // would report Connected while tor still cannot route a single
        // packet. A real SOCKS5 greeting handshake only succeeds once the
        // engine's accept loop is actually serving -- which is after
        // bootstrap. That is also why "tor never opened SOCKS5" used to
        // happen: the listener answered TCP while arti was still
        // bootstrapping, and the first real requests failed.
        if cfg.tor.mode == FcaeTorMode::Only {
            cx.report(FcaeState::Connecting, "Bootstrapping Tor…");
            let ready = wait_for_socks(engine_socks, cfg.tor_start_timeout(), &finished).await;
            if !ready {
                abort_current_engine();
                let msg = outcome
                    .lock()
                    .clone()
                    .and_then(|r| r.err())
                    .unwrap_or_else(|| {
                        format!(
                            "tor did not answer a SOCKS5 handshake on {engine_socks} within {:?}",
                            cfg.tor_start_timeout()
                        )
                    });
                return Err(CoreError::StartFailed(msg));
            }
            log::info!("[tor] egress ready on {engine_socks}; all traffic leaves through tor");
        } else {
            cx.report(FcaeState::Connecting, "Establishing tunnel…");

            // Wait for the engine's own listener first: in Chain mode tor cannot
            // bootstrap until the carrier tunnel is up, so waiting on tor's port
            // directly would time out for the wrong reason.
            //
            // Reverse mode is the mirror image: the tunnel is dialled THROUGH
            // tor, so its listener cannot open until tor has bootstrapped --
            // minutes over bridges, not seconds. It needs the tor budget or a
            // slow-but-healthy bootstrap reads as a failed start.
            let first_wait = if cfg.tor.mode == FcaeTorMode::Reverse {
                cfg.tor_start_timeout()
            } else {
                cfg.start_timeout()
            };
            let ready = wait_for_listener(engine_socks, first_wait, &finished).await;

            if !ready {
                // Either the engine died, or it never opened the port.
                abort_current_engine();
                let msg = outcome
                    .lock()
                    .clone()
                    .and_then(|r| r.err())
                    .unwrap_or_else(|| {
                        format!(
                            "the Aether engine did not open its SOCKS listener on {engine_socks} within {first_wait:?}"
                        )
                    });
                return Err(CoreError::StartFailed(msg));
            }

            // Tor bootstrap happens after the carrier is up and can take
            // minutes over bridges. Probe with a SOCKS5 handshake: the
            // listener is bound before bootstrap completes, so a bare
            // connect would call tor "ready" while it cannot route anything
            // yet.
            if let Some(tor_addr) = tor_socks {
                cx.report(FcaeState::Connecting, "Bootstrapping Tor…");
                if !wait_for_socks(tor_addr, cfg.tor_start_timeout(), &finished).await {
                    abort_current_engine();
                    let msg = outcome
                        .lock()
                        .clone()
                        .and_then(|r| r.err())
                        .unwrap_or_else(|| {
                            format!(
                                "tor did not answer a SOCKS5 handshake on {tor_addr} within {:?}",
                                cfg.tor_start_timeout()
                            )
                        });
                    return Err(CoreError::StartFailed(msg));
                }
                log::info!("[tor] egress ready on {tor_addr}; tun traffic routed through tor");
            }
        }

        Ok(Box::new(AetherHandle {
            cfg,
            socks_addr,
            sink: cx.telemetry.clone(),
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

/// Abort whatever engine task is currently registered (if any).
fn abort_current_engine() {
    if let Some(h) = LAST_ENGINE.lock().as_ref() {
        h.abort();
    }
}

/// Ensure the previous engine task is fully dead before a new one starts.
///
/// A task that is merely signalled (stop()'s request) can outlive its
/// listeners: the reconnect loop's backoff sleeps are not woken by the
/// signal, so the task keeps scanning and redialling. Worse, if the next
/// start cleared the flag first, that loop would never see the
/// cancellation at all and the old engine would run alongside the new
/// one, fighting it for the ports. So: wait a short while for a
/// signalled task to finish on its own, then abort whatever is left.
async fn reap_previous_engine() {
    let Some(mut prev) = LAST_ENGINE.lock().take() else {
        return;
    };
    if prev.is_finished() {
        return;
    }
    // A signalled engine normally dies within milliseconds of its
    // listeners being dropped; give it a moment, then kill it flat.
    let _ = tokio::time::timeout(Duration::from_millis(500), &mut prev).await;
    prev.abort();
    let _ = prev.await;
}

/// One connect attempt against the tunnel's SOCKS listener.
///
/// Used as a liveness probe: the engine unbinds the listener while it
/// re-dials and rebinds it once a tunnel is serving again, so this tracks the
/// real tunnel state without needing any instrumentation inside the engine.
///
/// Runs on the blocking pool because `connect_timeout` is synchronous; the
/// 250 ms cap keeps a wedged loopback socket from stalling the poll.
async fn probe_listener(addr: SocketAddr) -> bool {
    tokio::task::spawn_blocking(move || {
        TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
    })
    .await
    .unwrap_or(false)
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

/// One SOCKS5 greeting exchange (greeting -> method selection, RFC 1928).
///
/// Unlike a bare TCP connect this only succeeds once the server's accept
/// loop is actually running: the engine binds its listeners before tor
/// bootstraps, and the kernel backlog swallows connects until then, so a
/// connect-based probe reports "ready" too early.
async fn socks5_greeting(addr: SocketAddr) -> bool {
    tokio::task::spawn_blocking(move || {
        let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) else {
            return false;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
        // Version 5, one method: no auth.
        stream.write_all(&[0x05, 0x01, 0x01]).is_ok()
            && {
                let mut reply = [0u8; 2];
                stream.read_exact(&mut reply).is_ok() && reply[0] == 0x05 && reply[1] == 0x00
            }
    })
    .await
    .unwrap_or(false)
}

/// Poll a SOCKS5 greeting until the server answers, it dies, or we time out.
async fn wait_for_socks(addr: SocketAddr, timeout: Duration, finished: &AtomicBool) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if finished.load(Ordering::SeqCst) {
            return false;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        if socks5_greeting(addr).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// The address a local client (the TUN bridge, or a same-host SOCKS client)
/// must dial to reach a listener bound on `bound`: wildcard binds are
/// reached through the loopback.
fn local_dial_addr(bound: &str) -> Result<SocketAddr> {
    let addr: SocketAddr = bound
        .parse()
        .map_err(|e| CoreError::InvalidConfig(format!("bad tor socks address: {e}")))?;
    let ip = match addr.ip() {
        std::net::IpAddr::V4(v4) if v4.is_unspecified() => std::net::Ipv4Addr::LOCALHOST.into(),
        std::net::IpAddr::V6(v6) if v6.is_unspecified() => std::net::Ipv6Addr::LOCALHOST.into(),
        other => other,
    };
    Ok(SocketAddr::new(ip, addr.port()))
}

/// True once nothing else on the machine holds any of `addrs`.
///
/// Probed by actually binding each address: a failed bind is a true "still
/// held", a successful one a true "free". A wildcard (0.0.0.0) probe fails
/// while ANY address -- loopback included -- still holds the port, which is
/// the right test for the engine's own listeners; a specific IP (a tor bind
/// the user pointed at the LAN) is probed on exactly that IP, because other
/// addresses on the same port may be bound independently.
async fn addrs_free(addrs: &[SocketAddr], timeout: Duration) -> bool {
    if addrs.is_empty() {
        return true;
    }
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let free = tokio::task::spawn_blocking({
            let addrs = addrs.to_vec();
            move || {
                for a in addrs {
                    if std::net::TcpListener::bind(a).is_err() {
                        return false;
                    }
                }
                true
            }
        })
        .await
        .unwrap_or(false);
        if free || tokio::time::Instant::now() >= deadline {
            return free;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

struct AetherHandle {
    cfg: SessionConfig,
    socks_addr: SocketAddr,
    /// Used to publish reconnects the engine performs internally.
    sink: TelemetrySink,
    done: Arc<Notify>,
    finished: Arc<AtomicBool>,
    outcome: Arc<Mutex<Option<std::result::Result<(), String>>>>,
}

impl AetherHandle {
    fn held_addrs(&self) -> Vec<SocketAddr> {
        let mut addrs: Vec<SocketAddr> = Vec::new();
        // The engine's own listeners are probed as wildcards (see
        // addrs_free); tor's is probed on the exact host the user set.
        let push_wild = |addrs: &mut Vec<SocketAddr>, port: u16| {
            if port != 0 {
                let a = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port);
                if !addrs.contains(&a) {
                    addrs.push(a);
                }
            }
        };
        let push_exact = |addrs: &mut Vec<SocketAddr>, bound: &str| {
            if let Ok(a) = bound.parse::<SocketAddr>() {
                if !addrs.contains(&a) {
                    addrs.push(a);
                }
            }
        };
        match self.cfg.tor.mode {
            FcaeTorMode::Only => {
                if let Some(b) = self.cfg.tor.bind.as_deref() {
                    push_exact(&mut addrs, b);
                }
            }
            FcaeTorMode::Chain | FcaeTorMode::Reverse => {
                push_wild(&mut addrs, self.cfg.socks_port);
                push_wild(&mut addrs, self.cfg.http_port);
                if let Some(b) = self.cfg.tor.bind.as_deref() {
                    push_exact(&mut addrs, b);
                }
            }
            FcaeTorMode::Off => {
                push_wild(&mut addrs, self.cfg.socks_port);
                push_wild(&mut addrs, self.cfg.http_port);
            }
        }
        addrs
    }
}

#[async_trait]
impl BackendHandle for AetherHandle {
    fn endpoints(&self) -> Endpoints {
        Endpoints {
            socks: Some(self.socks_addr),
            // In Only mode there is no WARP tunnel, so the engine's HTTP
            // listener never exists -- do not advertise it.
            http: (self.cfg.http_port != 0 && self.cfg.tor.mode != FcaeTorMode::Only)
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
        // The engine reconnects internally: run_from_env() loops forever, so
        // the task only ends on a fatal error or shutdown. This future
        // therefore cannot observe a dropped tunnel by itself -- and because
        // the supervisor only reacts when wait() returns, its reconnect path
        // never ran and the UI kept showing "Connected" through an outage.
        //
        // Detect liveness from OUT HERE rather than instrumenting the engine:
        // the tunnel's SOCKS listener is torn down while it re-dials and
        // rebound once a tunnel serves again, so a connect() to the port we
        // already know is an accurate, dependency-free probe. Keeping this in
        // the bridge leaves the upstream engine untouched.
        //
        // Reconnecting itself is left to the engine, which already does it
        // with the right backoff and gateway memory; racing it from here
        // would tear down a tunnel that is busy recovering.
        let mut was_up = true;
        loop {
            if self.finished.load(Ordering::SeqCst) {
                break;
            }

            tokio::select! {
                biased;
                _ = self.done.notified() => break,
                _ = tokio::time::sleep(Duration::from_millis(1000)) => {}
            }

            let up = probe_listener(self.socks_addr).await;
            if up != was_up {
                was_up = up;
                if up {
                    self.sink
                        .set_state(FcaeState::Connected, "Reconnected".into());
                } else {
                    self.sink.set_state(
                        FcaeState::Reconnecting,
                        "Tunnel dropped; reconnecting…".into(),
                    );
                }
            }
        }

        match self.outcome.lock().clone() {
            Some(Ok(())) | None => Ok(()),
            Some(Err(msg)) => Err(CoreError::Internal(msg)),
        }
    }

    async fn stop(&self, timeout: Duration) -> Result<()> {
        let Some(task) = LAST_ENGINE.lock().take() else {
            return Ok(());
        };

        // Ask the engine to wind down first, THEN verify it let go.
        //
        // Aborting alone only cancels the top-level future. The engine spawns
        // a dozen detached tasks (SOCKS/HTTP listeners, netstacks, tunnel
        // drivers) that survive it with their sockets still bound, so the
        // next connect failed on "address already in use" until the whole
        // process was restarted -- the "connects once, then never again"
        // bug. run_from_env() races every long-lived await against this
        // signal, so the listeners are dropped before we stop waiting.
        aether_engine::shutdown::request();

        // request() only sets a flag; the detached tasks drop their sockets
        // on their next poll, a few scheduler ticks away. That lag is the
        // whole of the "disconnect, then the next connect fails" bug: the
        // next start() clears the flag, so any old task that has not
        // noticed the request yet keeps its listener after the new engine
        // has bound -- port taken, start failed. An arbitrary grace cannot
        // fix that (it is a race), so wait for the one condition that is
        // actually true: the port is free. In the normal case the flag is
        // noticed in milliseconds, so this returns almost immediately.
        let addrs = self.held_addrs();
        let grace = Duration::from_millis(1000).min(timeout);
        let ports_down = addrs_free(&addrs, grace).await;

        // The top-level task must not outlive the stop. Its reconnect loop
        // keeps scanning gateways and redialling in the backoff sleeps the
        // shutdown signal does not wake -- a disconnected engine would sit
        // there burning bandwidth until the next connect. Its listeners
        // are gone by now (verified above), so aborting cannot strand a
        // port; if a port was still held, the abort is what releases it.
        let mut task = task;
        task.abort();
        let _ = tokio::time::timeout(Duration::from_millis(200), &mut task).await;

        if !ports_down {
            let remaining = timeout.saturating_sub(grace);
            if !addrs_free(&addrs, remaining.max(Duration::from_millis(100))).await {
                log::warn!(
                    "[aether] {} still held after stop; the next start may fail until they are released",
                    addrs
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }

        Ok(())
    }

    /// Every address this session's engine can still be holding: the SOCKS
    /// listener, the HTTP proxy, and -- whenever tor is on -- tor's own
    /// listener (in Only mode tor IS the session endpoint, so only its
    /// address matters).


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
