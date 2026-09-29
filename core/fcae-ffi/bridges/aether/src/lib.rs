#![recursion_limit = "512"]

mod rates;

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Once};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcae_abi::{FcaeState, FcaeTorMode};
use fcae_runtime::backend::{
    Backend, BackendContext, BackendHandle, BackendId, Capabilities, Counters, Endpoints,
};
use fcae_runtime::config::{env_compat, SessionConfig};
use fcae_runtime::error::{CoreError, Result};
use fcae_runtime::telemetry::TelemetrySink;
use parking_lot::{Condvar, Mutex};
use serde_json::Value;

/// Budget of one SOCKS greeting probe. Long enough for a loaded device, short
/// enough that the 100 ms readiness loop stays responsive.
const PROBE_TIMEOUT: Duration = Duration::from_millis(400);
/// How long a listener left behind by a previous session may take to disappear
/// before a start is refused instead of racing it.
const RELEASE_GRACE: Duration = Duration::from_millis(1_500);
/// Hard cap on a job that was cancelled but never acknowledged it.
const TEARDOWN_BUDGET: Duration = Duration::from_secs(5);
/// Upper bound on `drain()`, which the session worker runs before its runtime
/// is destroyed and which must not hold a disconnect open indefinitely.
const DRAIN_BUDGET: Duration = Duration::from_secs(3);
const REAP_INTERVAL: Duration = Duration::from_millis(50);
/// Upper bound on the carrier endpoints handed to the TUN bridge. Each one
/// costs a host route; the engine's own cache keeps eight.
const MAX_BYPASS_PEERS: usize = 12;
/// Failed liveness greetings before the session is told the tunnel dropped.
/// One is a probe racing an engine-side reconnect, not a dead tunnel.
const LIVENESS_MISSES: u32 = 2;

/// Jobs the engine still owns.
///
/// The engine's runtime is process-global and is never shut down, so a job that
/// is merely cancelled -- or a start that was cancelled before it could return a
/// handle -- keeps running and keeps its SOCKS and HTTP listeners bound. Every
/// job this bridge starts is registered here first, so `drain()` and the
/// teardown reaper can finish what a cancelled start or an impatient caller
/// left behind. The entry is dropped only once the listener is provably gone.
static LIVE_JOBS: LazyLock<Mutex<HashMap<u64, SocketAddr>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

struct PendingTeardown {
    job: u64,
    addr: SocketAddr,
    deadline: Instant,
}

static PENDING: LazyLock<Mutex<Vec<PendingTeardown>>> = LazyLock::new(|| Mutex::new(Vec::new()));
/// Wakes the reaper. The thread has to poll (a listener only proves its release
/// by failing a probe), but it must not tick while there is nothing to reap:
/// the engine runtime outlives every session, so a busy loop here would run for
/// the life of the process.
static WORK: LazyLock<Condvar> = LazyLock::new(Condvar::new);
static REAPER: Once = Once::new();

pub fn register() {
    fcae_runtime::registry::register(fcae_abi::FcaeBackend::Aether, || Arc::new(AetherBackend));
}

pub struct AetherBackend;

#[async_trait]
impl Backend for AetherBackend {
    fn id(&self) -> BackendId { BackendId::Aether }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            socks: true,
            http_proxy: true,
            gateway_scanning: true,
            routing_rules: true,
            requires_privileges: false,
        }
    }

    async fn start(&self, cx: BackendContext) -> Result<Box<dyn BackendHandle>> {
        let mut cfg = cx.config.clone();
        if cfg.tor.is_enabled() && !cfg!(feature = "tor") {
            return Err(CoreError::InvalidConfig(format!(
                "tor mode `{}` was requested but this build has no tor support",
                tor_mode_label(cfg.tor.mode)
            )));
        }
        // The engine always binds a SOCKS listener. Port 0 would hand it an
        // ephemeral port that nothing can name -- not even this bridge -- so
        // the readiness probe below could never succeed; reserve a loopback
        // port and let the engine bind that one.
        if cfg.tor.mode != FcaeTorMode::Only && cfg.socks_port == 0 {
            cfg.socks_port = free_loopback_port()?;
        }

        env_compat::apply(&cfg);
        pin_engine_stats_interval();
        cx.report(FcaeState::Scanning, "Establishing tunnel…");

        // Validate every address before the engine is asked to do anything,
        // so a bad configuration cannot leave a running job behind.
        let engine_socks = if cfg.tor.mode == FcaeTorMode::Only {
            local_dial_addr(tor_bind(&cfg)?)?
        } else {
            loopback_socks(cfg.socks_port)?
        };
        let socks_addr = if cfg.tor.mode == FcaeTorMode::Chain {
            local_dial_addr(tor_bind(&cfg)?)?
        } else {
            engine_socks
        };

        // A start that was dropped before it could return a handle -- the
        // supervisor's start budget, a disconnect during the handshake, or the
        // retry after one of those -- leaves a live job behind that nothing
        // else ever cancels, and that job keeps its SOCKS and HTTP listeners
        // bound. Start by retiring everything this bridge opened before: the
        // session worker is the only caller, so nothing in the registry is
        // owned by a live handle at this point.
        retire_outstanding_jobs();
        wait_for_release(socks_addr, RELEASE_GRACE).await;
        if socks_listening(socks_addr).await {
            return Err(CoreError::StartFailed(format!(
                "{socks_addr} is still answering, so Aether cannot bind its SOCKS listener; \
                 another program holds that port, or a previous session has not released it"
            )));
        }

        cx.report(FcaeState::Connecting, "Establishing tunnel…");
        let job = ffi_start()?;
        LIVE_JOBS.lock().insert(job, socks_addr);

        let timeout = if cfg.tor.is_enabled() { cfg.tor_start_timeout() } else { cfg.start_timeout() };
        let ready = match wait_for_socks(socks_addr, timeout, job).await {
            Ok(ready) => ready,
            Err(error) => {
                retire_job(job, socks_addr);
                return Err(error);
            }
        };
        if !ready {
            retire_job(job, socks_addr);
            return Err(CoreError::StartFailed(format!(
                "Aether did not open its SOCKS listener on {socks_addr} within {timeout:?}"
            )));
        }

        let baseline = aether_engine::stats::snapshot();
        let baseline_rx = baseline.down;
        let baseline_tx = baseline.up;
        let peers = carrier_peers(&cfg);
        if !peers.is_empty() {
            log::debug!(
                "[aether] {} carrier endpoint(s) kept off the tunnel: {:?}",
                peers.len(),
                peers
            );
        }
        Ok(Box::new(AetherHandle {
            rates: Mutex::new(rates::RateMeter::new(baseline)),
            baseline_rx,
            baseline_tx,
            cfg,
            socks_addr,
            sink: cx.telemetry,
            job,
            peers,
            stopped: AtomicBool::new(false),
        }))
    }

    /// Reached after a cancelled start that never returned a handle, and after
    /// every normal session end. No job may outlive the session: the engine
    /// runtime is never shut down, so a survivor would hold the SOCKS and HTTP
    /// ports for the life of the process and every later connect would fail to
    /// bind them.
    async fn drain(&self) {
        retire_outstanding_jobs();
        let deadline = tokio::time::Instant::now() + DRAIN_BUDGET;
        while tokio::time::Instant::now() < deadline && !PENDING.lock().is_empty() {
            tokio::time::sleep(REAP_INTERVAL).await;
        }
        let remaining = PENDING.lock().len();
        if remaining != 0 {
            log::warn!(
                "[aether] {remaining} engine job(s) had not released their listeners when the session ended"
            );
        }
    }
}

/// Cancels every job this bridge opened and never handed to a handle.
fn retire_outstanding_jobs() {
    let outstanding: Vec<(u64, SocketAddr)> = LIVE_JOBS.lock().drain().collect();
    for (job, addr) in outstanding {
        log::debug!("[aether] retiring job {job} left behind by a cancelled start");
        retire_job(job, addr);
    }
}

fn tor_bind(cfg: &SessionConfig) -> Result<&str> {
    cfg.tor.bind.as_deref().ok_or_else(|| {
        CoreError::InvalidConfig("tor is enabled but no bind address was provided".into())
    })
}

fn loopback_socks(port: u16) -> Result<SocketAddr> {
    format!("127.0.0.1:{port}")
        .parse()
        .map_err(|e| CoreError::InvalidConfig(format!("bad socks address: {e}")))
}

/// A concrete loopback port for the engine's own listener when the session
/// asked for none. The engine binds one either way; the difference is that
/// this one can be dialled, so readiness stays observable.
fn free_loopback_port() -> Result<u16> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .map_err(|e| {
            CoreError::StartFailed(format!("no free loopback port for Aether's SOCKS listener: {e}"))
        })
}

/// The engine spawns its own traffic reporter on every core start and its
/// runtime is never torn down, so each reconnect would add another periodic
/// counter line for the life of the process. Statistics stay enabled -- the UI
/// reads them through `counters()` -- but the engine's own reporter is pinned
/// to its maximum interval.
fn pin_engine_stats_interval() {
    if std::env::var_os("AETHER_STATS_SECS").is_none() {
        std::env::set_var("AETHER_STATS_SECS", "86400");
    }
}

/// Carrier endpoints this session's engine may dial, most likely first.
///
/// The TUN bridge installs a bypass route per entry so the engine's own
/// transport never rides the device it carries: an established socket keeps
/// the physical route only until the routing table changes, and a TUN
/// pause/start rewrites it -- which is how stopping the TUN used to take
/// Aether's carrier down with it. Sources, in order: the peer the session
/// pinned, then the engine's `lastconn` sibling file (`peer` plus its
/// `recent` ring). That file is read once the readiness probe has confirmed
/// the SOCKS listener, and the engine records the gateway it dialled *before*
/// it binds that listener -- so even a first session publishes the endpoint it
/// is actually using.
fn carrier_peers(cfg: &SessionConfig) -> Vec<IpAddr> {
    let mut peers = Vec::new();
    if let Some(forced) = cfg.force_peer.as_deref().and_then(parse_peer_ip) {
        peers.push(forced);
    }
    if !cfg.config_path.is_empty() {
        for peer in lastconn_peers(&cfg.config_path) {
            if !peers.contains(&peer) {
                peers.push(peer);
            }
        }
    }
    peers.truncate(MAX_BYPASS_PEERS);
    peers
}

/// `host:port` or a bare address; a host route does not care about the port.
fn parse_peer_ip(text: &str) -> Option<IpAddr> {
    let text = text.trim();
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Some(addr.ip());
    }
    text.parse::<IpAddr>().ok()
}

fn lastconn_peers(config_path: &str) -> Vec<IpAddr> {
    let Ok(text) = std::fs::read_to_string(lastconn_path(config_path)) else {
        return Vec::new();
    };
    let mut peers = Vec::new();
    for entry in quoted_strings(&text) {
        if let Some(ip) = parse_peer_ip(&entry) {
            if !peers.contains(&ip) {
                peers.push(ip);
            }
        }
    }
    peers.truncate(MAX_BYPASS_PEERS);
    peers
}

/// The engine stores `peer = "..."` plus a `recent = [ ... ]` ring, so every
/// quoted string is a candidate endpoint and only whole-address strings pass
/// [`parse_peer_ip`]. A stale, truncated or hand-edited file therefore reads as
/// "no known peers" instead of refusing a session.
fn quoted_strings(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else { break };
        out.push(after[..end].to_string());
        rest = &after[end + 1..];
    }
    out
}

/// `<stem>-lastconn.<ext>` next to the engine's identity file, matching the
/// engine's own `derive_sibling_path`. Kept local so this crate does not have
/// to depend on the engine's path helper.
fn lastconn_path(config_path: &str) -> String {
    let dir_end = config_path
        .rfind(|c| c == '/' || c == '\\')
        .map(|index| index + 1)
        .unwrap_or(0);
    match config_path[dir_end..].rfind('.') {
        Some(relative) => {
            let dot = dir_end + relative;
            format!("{}-lastconn{}", &config_path[..dot], &config_path[dot..])
        }
        None => format!("{config_path}-lastconn"),
    }
}

fn ffi_reply(raw: *mut std::ffi::c_char) -> std::result::Result<Value, String> {
    if raw.is_null() { return Err("Aether FFI returned a null reply".into()); }
    let text = unsafe { CStr::from_ptr(raw) }.to_string_lossy().into_owned();
    unsafe { aether_engine::ffi::aether_string_free(raw) };
    let value: Value = serde_json::from_str(&text)
        .map_err(|e| format!("Aether FFI returned invalid JSON: {e}"))?;
    if value.get("ok").and_then(Value::as_bool) == Some(false) {
        return Err(value.get("error").and_then(Value::as_str).unwrap_or("unknown Aether error").into());
    }
    Ok(value)
}

fn ffi_start() -> Result<u64> {
    let args = CString::new("[]").expect("static JSON has no NUL");
    let reply = ffi_reply(unsafe { aether_engine::ffi::aether_core_start(args.as_ptr()) })
        .map_err(CoreError::StartFailed)?;
    reply.get("job").and_then(Value::as_u64)
        .ok_or_else(|| CoreError::StartFailed("Aether FFI did not return a job id".into()))
}

fn ffi_poll(job: u64) -> std::result::Result<Option<std::result::Result<(), String>>, String> {
    let reply = ffi_reply(aether_engine::ffi::aether_job_poll(job))?;
    if reply.get("state").and_then(Value::as_str) != Some("done") { return Ok(None); }
    let result = reply.get("result").ok_or_else(|| "Aether job completed without a result".to_string())?;
    if result.get("ok").and_then(Value::as_bool) == Some(false) {
        Ok(Some(Err(result.get("error").and_then(Value::as_str).unwrap_or("Aether failed").into())))
    } else {
        Ok(Some(Ok(())))
    }
}

fn ffi_cancel(job: u64) { let _ = ffi_reply(aether_engine::ffi::aether_job_cancel(job)); }
fn ffi_free(job: u64) { let _ = ffi_reply(aether_engine::ffi::aether_job_free(job)); }

/// Cancels a job and hands it to the reaper, which keeps polling until the
/// engine reports it finished and its listener stops answering. Freeing the
/// job instead would drop the engine's registry entry while the task behind it
/// still owns the ports.
fn retire_job(job: u64, addr: SocketAddr) {
    LIVE_JOBS.lock().remove(&job);
    ffi_cancel(job);
    queue_pending(job, addr);
}

fn queue_pending(job: u64, addr: SocketAddr) {
    ensure_reaper();
    {
        let mut pending = PENDING.lock();
        if pending.iter().any(|entry| entry.job == job) { return; }
        pending.push(PendingTeardown {
            job,
            addr,
            deadline: Instant::now() + TEARDOWN_BUDGET,
        });
    }
    WORK.notify_one();
}

fn release_pending(job: u64) {
    PENDING.lock().retain(|entry| entry.job != job);
    ffi_free(job);
}

fn ensure_reaper() {
    REAPER.call_once(|| {
        if std::thread::Builder::new()
            .name("fcae-aether-teardown".into())
            .spawn(reap_loop)
            .is_err()
        {
            // No thread: the job is still cancelled, and the next drain or
            // start re-queues it, so nothing is lost -- only delayed.
            log::warn!("[aether] no teardown thread; a cancelled job is freed on the next session");
        }
    });
}

/// Parked until teardown work is queued, then polls it at `REAP_INTERVAL`
/// until every queued job has provably released its listener.
fn reap_loop() {
    loop {
        let mut pending = PENDING.lock();
        while pending.is_empty() {
            WORK.wait(&mut pending);
        }
        drop(pending);
        loop {
            reap_finished_jobs();
            let mut pending = PENDING.lock();
            if pending.is_empty() { break; }
            WORK.wait_for(&mut pending, REAP_INTERVAL);
        }
    }
}

/// Drives every queued job to a proven release. A probe can take
/// `PROBE_TIMEOUT`, so the queue is snapshotted and each entry is finished
/// outside the lock: the session thread queues teardown work here while it is
/// shutting down and must never wait behind a probe.
fn reap_finished_jobs() {
    let now = Instant::now();
    let snapshot: Vec<(u64, SocketAddr, Instant)> = {
        let pending = PENDING.lock();
        pending.iter().map(|entry| (entry.job, entry.addr, entry.deadline)).collect()
    };
    for (job, addr, deadline) in snapshot {
        let stopped = match ffi_poll(job) {
            Ok(Some(_)) => true,
            // The engine's cancel is a watch channel, so the flag stays set and
            // a task that was busy when it was raised observes it on its next
            // poll. One cancel is enough; from here the reaper only has to wait
            // for the listener to stop answering.
            Ok(None) => false,
            Err(_) => {
                release_pending(job);
                continue;
            }
        };
        if stopped && !socks_probe(addr, PROBE_TIMEOUT) {
            log::debug!("[aether] job {job} released {addr}");
            release_pending(job);
            continue;
        }
        if now < deadline { continue; }
        if stopped {
            // The listener outlived its task, or a later session rebound the
            // address before this job was reaped. Either way it is not ours.
            log::debug!("[aether] job {job} ended while {addr} still answers");
        } else {
            log::warn!(
                "[aether] job {job} did not acknowledge the cancel within {:?}; it may still hold {addr}",
                TEARDOWN_BUDGET
            );
        }
        release_pending(job);
    }
}

async fn wait_for_socks(addr: SocketAddr, timeout: Duration, job: u64) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(result) = ffi_poll(job).map_err(CoreError::StartFailed)? {
            return result.map(|_| false).map_err(CoreError::StartFailed);
        }
        if socks_listening(addr).await { return Ok(true); }
        if tokio::time::Instant::now() >= deadline { return Ok(false); }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_release(addr: SocketAddr, budget: Duration) {
    let deadline = tokio::time::Instant::now() + budget;
    while socks_listening(addr).await {
        if tokio::time::Instant::now() >= deadline { return; }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn socks_probe(addr: SocketAddr, timeout: Duration) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, timeout) else { return false; };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut reply = [0u8; 2];
    stream.write_all(&[0x05, 0x01, 0x00]).is_ok()
        && stream.read_exact(&mut reply).is_ok()
        && reply == [0x05, 0x00]
}

/// Completes a SOCKS5 greeting rather than a bare TCP connect. A socket that is
/// bound but not serving -- a stale listener from a session that has not
/// finished tearing down, or an unrelated process -- is not an endpoint that
/// can carry traffic, and must not be reported as a connected tunnel.
async fn socks_listening(addr: SocketAddr) -> bool {
    tokio::task::spawn_blocking(move || socks_probe(addr, PROBE_TIMEOUT))
        .await
        .unwrap_or(false)
}

fn local_dial_addr(bound: &str) -> Result<SocketAddr> {
    let addr: SocketAddr = bound.parse()
        .map_err(|e| CoreError::InvalidConfig(format!("bad tor socks address: {e}")))?;
    let ip = match addr.ip() {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => std::net::Ipv4Addr::LOCALHOST.into(),
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => std::net::Ipv6Addr::LOCALHOST.into(),
        ip => ip,
    };
    Ok(SocketAddr::new(ip, addr.port()))
}

struct AetherHandle {
    rates: Mutex<rates::RateMeter>,
    baseline_rx: u64,
    baseline_tx: u64,
    cfg: SessionConfig,
    socks_addr: SocketAddr,
    sink: TelemetrySink,
    job: u64,
    /// Carrier endpoints the engine may dial. Handed to the TUN bridge so it
    /// can bypass them: this traffic is the tunnel's own transport, and a
    /// packet that enters the device it carries never comes out.
    peers: Vec<IpAddr>,
    stopped: AtomicBool,
}

#[async_trait]
impl BackendHandle for AetherHandle {
    fn endpoints(&self) -> Endpoints {
        let http_port = if matches!(self.cfg.tor.mode, FcaeTorMode::Only | FcaeTorMode::Chain) {
            self.cfg.tor.http_port
        } else { self.cfg.http_port };
        Endpoints {
            socks: Some(self.socks_addr),
            http: (http_port != 0).then(|| format!("127.0.0.1:{http_port}").parse().ok()).flatten(),
            peer_ip: (!self.peers.is_empty()).then(|| {
                self.peers.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
            }),
            udp: true,
            psiphon_dns: false,
        }
    }

    async fn wait(&self) -> Result<()> {
        let mut was_up = true;
        let mut misses = 0u32;
        loop {
            if self.stopped.load(Ordering::Acquire) { return Ok(()); }
            match ffi_poll(self.job) {
                Ok(Some(result)) => return result.map_err(CoreError::Internal),
                Ok(None) => {}
                // The job is freed as soon as its teardown is proven, so a
                // missing entry after a stop is this handle's own success
                // rather than a tunnel failure to report to the UI.
                Err(error) => {
                    if self.stopped.load(Ordering::Acquire) { return Ok(()); }
                    return Err(CoreError::Internal(error));
                }
            }
            let up = socks_listening(self.socks_addr).await;
            if up {
                misses = 0;
                if !was_up {
                    was_up = true;
                    self.sink
                        .set_state(FcaeState::Connected, "Tunnel reconnected".into());
                }
            } else {
                misses = misses.saturating_add(1);
                // The engine re-dials its carrier on its own; reporting a drop
                // after a single unanswered greeting would flinch the status
                // line and, on Android, make the host re-dial a live session.
                if was_up && misses >= LIVENESS_MISSES {
                    was_up = false;
                    self.sink.set_state(
                        FcaeState::Reconnecting,
                        "Tunnel dropped; reconnecting…".into(),
                    );
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn stop(&self, timeout: Duration) -> Result<()> {
        if self.stopped.swap(true, Ordering::AcqRel) { return Ok(()); }
        let (job, addr) = (self.job, self.socks_addr);
        ffi_cancel(job);
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if ffi_poll(job).ok().flatten().is_some() { break; }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        if ffi_poll(job).ok().flatten().is_some() && !socks_listening(addr).await {
            LIVE_JOBS.lock().remove(&job);
            ffi_free(job);
            return Ok(());
        }
        // The engine has not dropped the task that owns the listeners within
        // the caller's budget. The reaper finishes the job off this thread, so
        // the disconnect stays instant while the ports are still guaranteed to
        // be free before the next connect tries to bind them.
        log::debug!("[aether] {addr} not released within {timeout:?}; finishing in the background");
        retire_job(job, addr);
        Ok(())
    }

    fn counters(&self) -> Counters {
        let snapshot = aether_engine::stats::snapshot();
        let (rx, tx) = self.rates.lock().sample(&snapshot);
        Counters {
            total_rx: snapshot.down.saturating_sub(self.baseline_rx),
            total_tx: snapshot.up.saturating_sub(self.baseline_tx),
            rx_bytes_sec: rx,
            tx_bytes_sec: tx,
            rtt_ms: 0,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("fcae-lastconn-{tag}-{}.toml", std::process::id()))
    }

    #[test]
    fn a_peer_reads_with_or_without_its_port() {
        assert_eq!(parse_peer_ip("162.159.192.1:443"), Some(IpAddr::from([162, 159, 192, 1])));
        assert_eq!(parse_peer_ip(" 188.114.96.1 "), Some(IpAddr::from([188, 114, 96, 1])));
        assert_eq!(
            parse_peer_ip("[2001:db8::1]:443"),
            Some("2001:db8::1".parse().expect("a literal address"))
        );
        assert_eq!(parse_peer_ip("not-an-address"), None);
        assert_eq!(parse_peer_ip(""), None);
    }

    #[test]
    fn the_ring_is_read_from_the_engines_own_file() {
        let path = scratch("ring");
        std::fs::write(
            &path,
            "peer = \"162.159.192.1:443\"\nprofile = \"gfw\"\ncarrier = \"masque-h3\"\nrecent = [\"188.114.96.1:443\", \"162.159.192.1:443\", \"bogus\"]\n",
        )
        .expect("write the engine's file");
        let peers = lastconn_peers(&path.to_string_lossy());
        assert_eq!(
            peers,
            vec![IpAddr::from([162, 159, 192, 1]), IpAddr::from([188, 114, 96, 1])]
        );
        let _ = std::fs::remove_file(&path);
        assert!(lastconn_peers(&path.to_string_lossy()).is_empty());
    }

    #[test]
    fn the_sibling_path_follows_the_engines_layout() {
        assert_eq!(lastconn_path("aether.toml"), "aether-lastconn.toml");
        assert_eq!(lastconn_path("/var/lib/fcae/warp.json"), "/var/lib/fcae/warp-lastconn.json");
        assert_eq!(lastconn_path("identity"), "identity-lastconn");
    }
}
