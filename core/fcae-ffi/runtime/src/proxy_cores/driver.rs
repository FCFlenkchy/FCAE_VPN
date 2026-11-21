//! Shared in-process core lifecycle, logging, counters and tunnel probes.
use super::planning::resolve_address;
use super::{plan_listeners, resolve_peer, CoreProfile, Level, Plan, Protocol, Transport};
use crate::backend::{BackendContext, BackendHandle, Counters, Endpoints};
use crate::error::{CoreError, Result as CoreResult};
use crate::upstream::{ProxyKind, UpstreamProxy};
use async_trait::async_trait;
use fcae_abi::{FcaeBackend, FcaeState};
use parking_lot::Mutex;
use serde_json::Value;
use std::ffi::{c_char, c_int, CStr, CString};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
const READY_TIMEOUT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(250);
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// The C entry points a core's shim exports from the shared Go archive.
///
/// Every core exports the same shapes under its own prefix; holding them in
/// one struct is what lets [`start`] be written once for both cores.
///
/// A shim holds one instance per handle, not one per process: a session can
/// chain a core to itself — two saved Xray configs, two hops — so every call
/// that acts on an instance takes the handle its start wrote back.
#[derive(Clone, Copy)]
pub struct CoreFfi {
    /// Starts one instance and writes its handle to the second argument.
    pub start: unsafe extern "C" fn(*const c_char, *mut u64) -> *mut c_char,
    /// Closes one instance by handle.
    pub stop: unsafe extern "C" fn(u64),
    /// Closes every instance this core still holds: the teardown net under a
    /// start that was abandoned before its handle reached the caller.
    pub stop_all: unsafe extern "C" fn(),
    pub running: unsafe extern "C" fn(u64) -> c_int,
    /// Frees a message the shim returned, with the shim's own allocator.
    pub string_free: unsafe extern "C" fn(*mut c_char),
    /// Cumulative `(uplink, downlink)` bytes through one instance. Returns 1
    /// when the core reported a sample and 0 when it has none to report — the
    /// counters are optional, so a config without them is not an error.
    pub stats: unsafe extern "C" fn(u64, *mut i64, *mut i64) -> c_int,
    /// Installs the host log sink (NULL clears it) and its level gate, from the
    /// scale [`log_gate`] produces.
    pub set_log: unsafe extern "C" fn(Option<unsafe extern "C" fn(c_int, *const c_char)>, c_int),
    /// Every inbound of every live instance as `handle|label|proto|port|scope`
    /// records, `;`-separated: what the core is actually listening on, which is
    /// not what the app's settings say. Answers the bytes it needs when the
    /// buffer is too small, so the caller can ask again.
    pub listeners: unsafe extern "C" fn(*mut c_char, c_int) -> c_int,
}

/// One inbound a live core instance is listening on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreListener {
    /// The handle the shim gave the instance that runs this inbound, which is
    /// what joins the record to the [`LiveInstance`] the session published: the
    /// shim numbers its instances per core, so it is the host side that knows
    /// which route an instance belongs to and where in that route it sits.
    pub handle: u64,
    /// What the config calls itself, from the outbound it declares: `vless
    /// reality`, not an index. Empty when the config declares no outbound of
    /// its own, which is a config that only serves local proxies. This is the
    /// fallback for an instance the session started without a saved config;
    /// a named one is shown under the user's own name.
    pub label: String,
    /// The core's own protocol name, as its config spells it.
    pub proto: String,
    pub port: u16,
    /// Whether the inbound binds every interface rather than loopback alone. A
    /// chained hop serves only the hop below it, so its port must not be
    /// offered on the LAN address.
    pub any: bool,
}

/// What the live instances of one core are listening on.
///
/// A saved config declares the ports its inbounds bind and a chain runs one
/// instance per hop, so the settings hold one number for a session that may
/// have several. This asks the core itself, through the shim that started it.
pub fn live_listeners(ffi: CoreFfi) -> Vec<CoreListener> {
    let mut capacity: usize = 1024;
    for _ in 0..4 {
        let mut buf = vec![0u8; capacity];
        // SAFETY: `buf` is a live, writable buffer of `capacity` bytes and the
        // shim writes at most that many, NUL-terminated.
        let answer =
            unsafe { (ffi.listeners)(buf.as_mut_ptr().cast::<c_char>(), capacity as c_int) };
        if answer < 0 {
            return Vec::new();
        }
        if answer as usize >= capacity {
            // The shim answered with the size it needs and wrote nothing.
            capacity = answer as usize + 1;
            continue;
        }
        let text = match std::str::from_utf8(&buf[..answer as usize]) {
            Ok(text) => text,
            Err(_) => return Vec::new(),
        };
        return parse_listeners(text);
    }
    Vec::new()
}

/// `handle|label|proto|port|scope;...` into typed records, skipping anything
/// unreadable.
fn parse_listeners(text: &str) -> Vec<CoreListener> {
    let mut out = Vec::new();
    for record in text.split(';').filter(|record| !record.is_empty()) {
        let mut fields = record.split('|');
        let (Some(instance), Some(label), Some(proto), Some(port), Some(scope)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let (Ok(handle), Ok(port)) = (instance.parse::<u64>(), port.parse::<u16>()) else {
            continue;
        };
        out.push(CoreListener {
            handle,
            label: label.to_string(),
            proto: proto.to_string(),
            port,
            any: scope == "any",
        });
    }
    out
}

/// One core instance this process is running, and what the session calls it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveInstance {
    pub backend: FcaeBackend,
    /// The handle its shim gave it. Handles count per core, so the same number
    /// can name an Xray instance and a sing-box one: the pair is the identity.
    pub handle: u64,
    /// The user's name for the saved config it runs. Empty for an instance
    /// started without one, which is shown under its config's own description
    /// instead.
    pub name: String,
}

/// Every live core instance, in the order its session started it — the exit
/// first, then each chain hop above it.
///
/// A shim numbers its instances per core for the life of the process, so the
/// two cores of one route both start at one and neither knows the other exists.
/// What the connection info lists is one route, in one order, numbered across
/// every core in it, and the name of each instance is the user's own name for
/// the config — none of which a shim can see: it is handed a config and nothing
/// else. Starts run from the exit upwards and are published as they happen, so
/// the order here is the route's.
static LIVE: Mutex<Vec<LiveInstance>> = Mutex::new(Vec::new());

/// Publish an instance the moment its handle owns the core, and until it is
/// stopped it is what the connection info lists.
fn publish_live(backend: FcaeBackend, handle: u64, name: String) {
    let mut live = LIVE.lock();
    live.retain(|instance| instance.backend != backend || instance.handle != handle);
    live.push(LiveInstance {
        backend,
        handle,
        name,
    });
}

/// Forget one instance once its core is closed. Idempotent.
fn retire_live(backend: FcaeBackend, handle: u64) {
    LIVE.lock()
        .retain(|instance| instance.backend != backend || instance.handle != handle);
}

/// Forget every instance of one core, for a teardown that closed them all.
pub fn retire_all(backend: FcaeBackend) {
    LIVE.lock().retain(|instance| instance.backend != backend);
}

/// The live instances, in route order.
pub fn live_instances() -> Vec<LiveInstance> {
    LIVE.lock().clone()
}

/// One core's build identity and config grammar — the only per-core code.
pub trait Dialect: Send + Sync + 'static {
    /// Human-readable name for messages.
    const DISPLAY: &'static str;
    /// Whether the core resolves an outbound server name itself, with the
    /// platform's resolver behind it. Xray-core does — Go's resolver falls back
    /// to the system's, so a device without `/etc/resolv.conf` still resolves.
    /// sing-box does not: its `local` DNS transport parses that file and, on a
    /// host that has none, queries `127.0.0.1:53` and `[::1]:53`, where nothing
    /// answers. Such a core is handed an address instead.
    const RESOLVES_SERVER: bool;
    /// The shim this core exports from `libfcae_go_bridge`.
    const FFI: CoreFfi;
    /// The trampoline that receives this core's log lines.
    const LOG_SINK: unsafe extern "C" fn(c_int, *const c_char);

    /// Emit the core's own config for this session.
    fn generate(plan: &Plan<'_>) -> std::result::Result<Value, String>;
}

/// Level gate for a core's logger: 0 leaves it silent, 1..=4 are errors,
/// warnings, info and debug. The scale is the shims': see `xray.set_log` and
/// `sb.set_log` in `bridges/*/go/bridge.go`.
fn log_gate(level: Level) -> c_int {
    match level {
        Level::Off => 0,
        Level::Error => 1,
        Level::Warn => 2,
        Level::Info => 3,
        Level::Debug | Level::Trace => 4,
    }
}

pub const CORE_LOG_TARGET: &str = "fcae::core";

/// Hand one core log line to the app's logger.
///
/// The shims call this from their own goroutines with a NUL-terminated line
/// they own, so it is copied before returning and nothing panics across the cgo
/// boundary.
pub fn forward_log(core: &str, level: c_int, message: *const c_char) {
    if message.is_null() {
        return;
    }
    let level = match level {
        1 => log::Level::Error,
        2 => log::Level::Warn,
        4 => log::Level::Debug,
        _ => log::Level::Info,
    };
    // The gate drops most of what a core emits, so check before building the
    // line, not after.
    if !log::log_enabled!(target: CORE_LOG_TARGET, level) {
        return;
    }
    let _ = std::panic::catch_unwind(|| {
        // SAFETY: the pointer is valid for the duration of the call, as the
        // shims pass a `C.CString` they free immediately afterwards.
        let text = unsafe { CStr::from_ptr(message) }.to_string_lossy();
        log::log!(target: CORE_LOG_TARGET, level, "[{core}] {text}");
    });
}

/// Load the core, start it on the generated config and wait until its listeners
/// answer.
pub async fn start<D: Dialect>(cx: &BackendContext) -> CoreResult<Running> {
    let config = &cx.config;
    // Parsed and validated with the rest of the session config; missing here
    // means the route has no core, which the supervisor never starts.
    let profile =
        config.core.profile.as_ref().ok_or_else(|| {
            CoreError::InvalidConfig(format!("{} needs core.profile", D::DISPLAY))
        })?;

    let (socks, http) = plan_listeners(config)?;
    let peer_ip = match profile.endpoint() {
        Some((server, port)) => resolve_peer(config, server, port).await?,
        None => None,
    };
    // A core that cannot resolve is handed addresses: the profile's server and,
    // when the session is chained, the upstream proxy's host.
    let mut dial = None;
    let mut pinned_upstream = None;
    if !D::RESOLVES_SERVER {
        if let CoreProfile::Link(outbound) = profile {
            dial = resolve_address(&outbound.server, outbound.port)
                .await
                .map_err(|error| match error {
                    // The platform is the only resolver this core has, so a
                    // name it cannot resolve is a refusal worth naming the
                    // core in: nothing downstream would explain it better.
                    CoreError::StartFailed(text) => {
                        CoreError::StartFailed(format!("{}: {text}", D::DISPLAY))
                    }
                    other => other,
                })?;
        }
        if let Some(upstream) = config.upstream_proxy.as_ref() {
            if let Some(address) = resolve_address(&upstream.host, upstream.port).await? {
                let mut pinned = upstream.clone();
                pinned.host = address.to_string();
                pinned_upstream = Some(pinned);
            }
        }
    }
    let upstream = pinned_upstream.as_ref().or(config.upstream_proxy.as_ref());

    let generated = D::generate(&Plan {
        profile,
        socks,
        http,
        level: Level::of(config.core.log_level),
        upstream,
        routing: &config.routing,
        dial,
    })
    .map_err(|error| CoreError::InvalidConfig(format!("{}: {error}", D::DISPLAY)))?;
    let body = serde_json::to_string(&generated).map_err(|error| {
        CoreError::Internal(format!(
            "cannot serialise the {} config: {error}",
            D::DISPLAY
        ))
    })?;

    let target = profile
        .endpoint()
        .map(|(server, port)| format!("{server}:{port}"))
        .unwrap_or_else(|| "the native config".to_string());
    cx.report(
        FcaeState::Connecting,
        format!("Starting {} → {target}", D::DISPLAY),
    );

    let endpoints = Endpoints {
        socks,
        http,
        peer_ip,
        udp: true,
        psiphon_dns: false,
    };

    // Starting a core parses its config and binds its listeners, which can take
    // a second or two, so it runs on a thread of its own: a long Go call must
    // not stall a Tokio worker the rest of the session shares.
    let ffi = D::FFI;
    // The sink goes in before the core runs, not after: binding listeners,
    // resolving the server and failing a config all happen during start, and
    // that is exactly what a user needs in the console.
    unsafe {
        (ffi.set_log)(
            Some(D::LOG_SINK),
            log_gate(Level::of(config.core.log_level)),
        )
    };
    // The start blocks in Go, so it runs on its own thread, and the guard owns
    // that thread: see [`CoreStart`] for what a cancelled start would otherwise
    // leave behind.
    let (answered, started) = tokio::sync::oneshot::channel();
    // The handle is published the moment the shim assigns it, so a guard that
    // has to stop an abandoned start knows the instance it owns.
    let handle_slot = Arc::new(AtomicU64::new(0));
    let published = Arc::clone(&handle_slot);
    let worker = std::thread::Builder::new()
        .name("fcae-core-start".into())
        .spawn(move || {
            // Unpacks the embedded cronet DLL where sing-box's loader can find
            // it, if this build embedded one. It has to happen before the core
            // starts: the Go side caches its first load attempt, failures
            // included.
            crate::cronet::prepare();
            let result = call_start(ffi, body);
            if let Ok(id) = &result {
                published.store(*id, Ordering::Release);
            }
            let _ = answered.send(result);
        })
        .map_err(|error| {
            CoreError::Internal(format!("cannot run the {} start: {error}", D::DISPLAY))
        })?;
    let mut owner = CoreStart {
        worker: Some(worker),
        ffi,
        handle: Arc::clone(&handle_slot),
        armed: true,
    };
    let started = started.await.map_err(|_| {
        CoreError::Internal(format!("the {} start ended without answering", D::DISPLAY))
    })?;
    let handle = match started {
        // A shim that claims success without a handle would leave an instance
        // nothing here can stop; the session teardown's `stop_all` is what picks
        // it up, so the refusal still costs no core.
        Ok(0) => {
            return Err(CoreError::Internal(format!(
                "the {} start reported success without an instance handle",
                D::DISPLAY
            )));
        }
        Ok(id) => id,
        Err(CallError::Config) => {
            owner.armed = false;
            return Err(CoreError::Internal(format!(
                "the generated {} config contains a NUL byte",
                D::DISPLAY
            )));
        }
        Err(CallError::Core(text)) => {
            owner.armed = false;
            return Err(CoreError::StartFailed(format!("{}: {text}", D::DISPLAY)));
        }
    };

    let rtt_probe = RttProbe::plan(profile, config.upstream_proxy.clone(), &endpoints);
    // From here the handle owns the core: dropping the handle is what stops a
    // core whose start was abandoned, so the guard has nothing left to do.
    owner.armed = false;
    // Published under the handle that now owns it, so the connection info lists
    // this instance under the user's own name for the config it runs, in the
    // place the route started it — and only stopping it takes it back out.
    publish_live(
        config.backend,
        handle,
        config.core.selection_name().unwrap_or_default().to_owned(),
    );
    let running = Running {
        ffi,
        backend: config.backend,
        handle,
        display: D::DISPLAY,
        endpoints,
        stopping: AtomicBool::new(false),
        traffic: Mutex::new(Traffic::default()),
        rtt_ms: Arc::new(AtomicU32::new(0)),
        rtt_stop: Arc::new(AtomicBool::new(false)),
        rtt_probe,
    };
    // Readiness first: the probe asks the core's own listener for the round
    // trip, and a session that never became ready has nothing to measure and no
    // thread to retire.
    running.await_ready().await?;
    // Then the tunnel itself. The listener answering says the core is up, not
    // that it carries anything, so the session keeps saying "connecting" until
    // one real answer has come back through it — the state the UI paints green
    // means what it says.
    cx.report(
        FcaeState::Connecting,
        format!("Verifying the {} tunnel…", D::DISPLAY),
    );
    if let Err(error) = running.spawn_rtt() {
        running.halt().await;
        return Err(error);
    }
    running.await_tunnel().await?;
    Ok(running)
}

/// Why a start call failed.
enum CallError {
    /// The config cannot be expressed as a C string — our own bug, not input.
    Config,
    /// The core refused it, with its own message.
    Core(String),
}

/// Enter the core's shim and start one instance. Blocking.
///
/// The handle is written by the shim only on success; the `Err` arm means no
/// instance came up, so there is nothing of ours left to stop.
fn call_start(ffi: CoreFfi, body: String) -> std::result::Result<u64, CallError> {
    let json = CString::new(body).map_err(|_| CallError::Config)?;
    let mut handle: u64 = 0;
    // SAFETY: `json` outlives the call and the shim copies it before returning;
    // a non-NULL result is a string the shim allocated, freed by its own
    // allocator through `string_free`. `handle` is a live local the shim writes
    // only after the instance is up.
    unsafe {
        let error = (ffi.start)(json.as_ptr(), &mut handle);
        if error.is_null() {
            return Ok(handle);
        }
        let text = CStr::from_ptr(error).to_string_lossy().into_owned();
        (ffi.string_free)(error);
        Err(CallError::Core(text))
    }
}

/// Stop one instance off the async workers. Blocking, idempotent.
pub async fn halt(ffi: CoreFfi, handle: u64) {
    let _ = tokio::task::spawn_blocking(move || unsafe { (ffi.stop)(handle) }).await;
}

/// Stop every instance of one core: the net a session teardown leaves under the
/// paths that could not stop what they started.
pub async fn halt_all(ffi: CoreFfi, backend: FcaeBackend) {
    let _ = tokio::task::spawn_blocking(move || {
        unsafe { (ffi.stop_all)() };
        // Retirement belongs to the work, not the cancellable awaiter.
        retire_all(backend);
    })
    .await;
}

/// Stop one instance from a caller that cannot await -- a `Drop`, which is where
/// an abandoned start ends up.
fn halt_detached(backend: FcaeBackend, ffi: CoreFfi, handle: u64) {
    // The Go stop joins the core's own goroutines, so it must not run on the
    // thread that is dropping: on the session worker that would hold a
    // disconnect open, and on the UI thread it would freeze the window.
    let _ = std::thread::Builder::new()
        .name("fcae-core-halt".into())
        .spawn(move || {
            unsafe { (ffi.stop)(handle) };
            retire_live(backend, handle);
        });
}

/// A core start that is in flight, and the promise that the core it brings up
/// does not outlive this session.
///
/// `call_start` blocks inside Go, so it runs on its own thread -- and the future
/// awaiting it can be dropped at any moment: a Disconnect during a connect, a
/// chain hop cancelled between two awaits. Dropping the awaiter discards the
/// *answer*, not the work. The core still comes up, keeps its listeners, its
/// goroutines and its whole heap, and nothing is left that knows it exists --
/// which is why every later start of that core was refused with "a core is
/// already running", and why the process kept the memory of a core the user had
/// disconnected from.
///
/// [`Drop`] is the answer: wait for the start to finish, then stop what came up.
/// The wait is on another thread, because the start is blocking and this may be
/// dropped where nothing may block. Disarmed once a handle owns the instance.
struct CoreStart {
    worker: Option<std::thread::JoinHandle<()>>,
    ffi: CoreFfi,
    /// The handle the shim assigned, published by the worker thread. Zero until
    /// the instance is up, which is the one case where there is nothing to stop.
    handle: Arc<AtomicU64>,
    armed: bool,
}

impl Drop for CoreStart {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Some(worker) = self.worker.take() else {
            return;
        };
        let ffi = self.ffi;
        let handle = Arc::clone(&self.handle);
        let _ = std::thread::Builder::new()
            .name("fcae-core-halt".into())
            .spawn(move || {
                let _ = worker.join();
                // The stop has to follow the join, not race it: a stop that
                // arrived while the core was still coming up would find nothing
                // to close and leave the instance running. Reading the handle
                // after the join is what makes it complete.
                let handle = handle.load(Ordering::Acquire);
                if handle != 0 {
                    unsafe { (ffi.stop)(handle) };
                }
            });
    }
}

/// A started core. [`BackendHandle::stop`] is the teardown path — it is the one
/// that can report a timeout — and [`Drop`] is the backstop for a handle that is
/// dropped instead (an abandoned start), which stops the core off-thread.
pub struct Running {
    ffi: CoreFfi,
    /// The core this instance runs. Handles count per core, so this is half of
    /// what identifies the instance in [`LIVE`].
    backend: FcaeBackend,
    /// This instance's handle in its shim. Two hops of one core in a session
    /// hold different handles, which is what keeps their counters apart.
    handle: u64,
    /// What this core calls itself in the text a user reads. `Running` is not
    /// generic over the dialect, and the messages below are shared by both.
    display: &'static str,
    endpoints: Endpoints,
    stopping: AtomicBool,
    /// Sample bookkeeping behind [`BackendHandle::counters`].
    traffic: Mutex<Traffic>,
    /// Tunnel round trip in milliseconds; 0 until a measurement lands.
    rtt_ms: Arc<AtomicU32>,
    /// Set when the session goes down, so the measurement loop outlives neither
    /// the core nor the handle that owns it.
    rtt_stop: Arc<AtomicBool>,
    /// How this session measures its latency, or `None` when it cannot be.
    rtt_probe: Option<RttProbe>,
}

impl Running {
    /// Wait until every listener answers a real handshake.
    ///
    /// A bound-but-uninitialised inbound accepts a connection and drops it, so a
    /// TCP connect alone is not enough: the SOCKS listener is greeted.
    async fn await_ready(&self) -> CoreResult<()> {
        let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
        loop {
            if !self.alive() {
                self.halt().await;
                return Err(CoreError::StartFailed(
                    "the core exited while starting".to_string(),
                ));
            }
            if let Some(socks) = self.endpoints.socks {
                if probe(socks, true).await.is_ok() {
                    log::info!("[core] listening on {socks}");
                    return Ok(());
                }
            } else if let Some(http) = self.endpoints.http {
                if probe(http, false).await.is_ok() {
                    log::info!("[core] listening on {http}");
                    return Ok(());
                }
            } else {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                self.halt().await;
                return Err(CoreError::StartFailed(format!(
                    "the core did not accept connections within {}s",
                    READY_TIMEOUT.as_secs()
                )));
            }
            tokio::time::sleep(POLL).await;
        }
    }

    fn alive(&self) -> bool {
        // SAFETY: the shim is linked into this binary for the whole process
        // lifetime, so the pointer is always valid.
        unsafe { (self.ffi.running)(self.handle) == 1 }
    }

    /// Cumulative `(tx, rx)` bytes from the core, or `None` when it keeps no
    /// counters.
    fn bytes(&self) -> Option<(u64, u64)> {
        let mut uplink: i64 = 0;
        let mut downlink: i64 = 0;
        // SAFETY: the shim writes both values through the pointers, and it is
        // linked into this binary for the whole process lifetime.
        let reported = unsafe { (self.ffi.stats)(self.handle, &mut uplink, &mut downlink) };
        (reported == 1).then(|| (uplink.max(0) as u64, downlink.max(0) as u64))
    }

    /// Start the latency measurement, once per handle.
    ///
    /// This is the Firefox bridge's keepalive shape on the connection this side
    /// can time: a five-second tick that measures until it has a sample,
    /// records that sample, and retires. The first answer sticks — the same
    /// `compare_exchange(0, …)` the Firefox transport uses — so a later, busier
    /// measurement can never rewrite a latency the UI already shows.
    ///
    /// The loop is the handle's own: it wakes every [`POLL`] to watch the stop
    /// flag, so a session that goes down retires it in a quarter second instead
    /// of leaving a thread behind for the life of the process.
    fn spawn_rtt(&self) -> CoreResult<()> {
        let Some(probe) = self.rtt_probe.clone() else {
            return Ok(());
        };
        let rtt_ms = Arc::clone(&self.rtt_ms);
        let stop = Arc::clone(&self.rtt_stop);
        std::thread::Builder::new()
            .name("fcae-core-rtt".into())
            .spawn(move || measure_until_known(&probe, &rtt_ms, &stop))
            .map(drop)
            .map_err(|error| {
                CoreError::StartFailed(format!(
                    "cannot start the latency measurement for {}: {error}",
                    self.display
                ))
            })
    }

    /// Wait for the first round trip through the tunnel.
    ///
    /// The core answers on its listener well before its tunnel has carried
    /// anything — a config with the wrong credentials starts exactly like a
    /// working one — so this is where a session is told apart from a core that
    /// is merely running. A session that gets no answer inside
    /// [`TUNNEL_VERIFY_TIMEOUT`] is refused here instead of being published as
    /// connected and left to fail on the user's first request.
    async fn await_tunnel(&self) -> CoreResult<()> {
        let Some(probe) = self.rtt_probe.as_ref() else {
            // Nothing is measurable, so nothing can be verified: failing a
            // session over a check this app never promised to make would refuse
            // a config that may well work.
            return Ok(());
        };
        let deadline = tokio::time::Instant::now() + TUNNEL_VERIFY_TIMEOUT;
        loop {
            if self.rtt_ms.load(Ordering::Acquire) != 0 {
                return Ok(());
            }
            if !self.alive() {
                self.halt().await;
                return Err(CoreError::StartFailed(format!(
                    "{} exited before its tunnel carried anything",
                    self.display
                )));
            }
            if tokio::time::Instant::now() >= deadline {
                self.halt().await;
                let through = probe
                    .listener()
                    .map(|listener| format!(" through {listener}"))
                    .unwrap_or_default();
                return Err(CoreError::StartFailed(format!(
                    "the {} tunnel carried nothing: no answer came back{through} within {}s",
                    self.display,
                    TUNNEL_VERIFY_TIMEOUT.as_secs()
                )));
            }
            tokio::time::sleep(POLL).await;
        }
    }
}

/// Measure the session's latency until one lands, then stop.
fn measure_until_known(probe: &RttProbe, rtt_ms: &AtomicU32, stop: &AtomicBool) {
    let mut failed: u32 = 0;
    loop {
        if stop.load(Ordering::Acquire) || rtt_ms.load(Ordering::Acquire) != 0 {
            return;
        }
        if let Some(measured) = probe.measure() {
            log::debug!("[core] latency {measured}ms ({})", probe.label());
            // First sample wins, exactly as the Firefox transport records one:
            // a slower measurement later must not rewrite what the UI shows.
            let _ = rtt_ms.compare_exchange(0, measured, Ordering::AcqRel, Ordering::Acquire);
            return;
        }
        failed = failed.saturating_add(1);
        if !sleep_until_next_tick(stop, rtt_ms, retry_delay(failed)) {
            return;
        }
    }
}

/// Wait out `wait`, waking every [`POLL`] so the session's stop is honored
/// promptly. False when the caller should give up.
fn sleep_until_next_tick(stop: &AtomicBool, rtt_ms: &AtomicU32, wait: Duration) -> bool {
    let mut left = wait;
    while !left.is_zero() {
        // Checked before the step as well as after it, so a session that is
        // already down costs no nap at all.
        if stop.load(Ordering::Acquire) || rtt_ms.load(Ordering::Acquire) != 0 {
            return false;
        }
        let step = left.min(POLL);
        std::thread::sleep(step);
        left -= step;
    }
    true
}

/// The Firefox transport's keepalive period, which is what a session falls back
/// to once its first few measurements have already failed.
const RTT_INTERVAL: Duration = Duration::from_secs(5);

/// How long a session gets to prove it carries traffic, counted from the moment
/// its core answers on its listener. Only the far side is being waited for: one
/// request has to come back through the tunnel in this window.
const TUNNEL_VERIFY_TIMEOUT: Duration = Duration::from_secs(15);

/// What the through-the-tunnel probe fetches, in the order it tries them: an
/// empty answer that a captive network cannot fake and that is cheap to serve,
/// so what is measured is the route and not the target. More than one entry
/// because a single host may be blocked in the network the tunnel runs in, and
/// a blocked target is not a broken tunnel.
const RTT_TARGETS: [(&str, &str); 3] = [
    ("www.gstatic.com", "/generate_204"),
    ("cp.cloudflare.com", "/generate_204"),
    ("connectivitycheck.gstatic.com", "/generate_204"),
];
const RTT_PORT: u16 = 80;

/// Delay before the next measurement, by how many have already failed.
///
/// The first attempts are close together because a session is usually still
/// settling when its start hands over — waiting the full keepalive period there
/// would charge a warming tunnel five seconds it does not need. After that the
/// spacing is the Firefox transport's own five seconds.
fn retry_delay(failed: u32) -> Duration {
    match failed {
        0 | 1 => Duration::from_secs(1),
        2 => Duration::from_secs(2),
        _ => RTT_INTERVAL,
    }
}

/// How long a handshake may take: the SYN, or the CONNECT a fronting hop has to
/// dial and answer. It is a network round trip over a mobile link, not the
/// loopback greeting [`PROBE_TIMEOUT`] covers, so it gets room of its own.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Longest header block a proxy's CONNECT answer may take before it is not one.
const HEAD_LIMIT: usize = 4096;

/// The remote a session handshakes with, and what fronts it.
///
/// `server` stays as the config spells it: a hostname is handed to the hop that
/// fronts this one, which resolves it exactly as the core would, and only a
/// direct outbound resolves it here.
#[derive(Clone)]
struct RttTarget {
    server: String,
    port: u16,
    /// The proxy this core dials through: the hop above it in a chain, or the
    /// user's own upstream proxy -- only ever one off this machine, because a
    /// local front answers the CONNECT itself.
    via: Option<UpstreamProxy>,
}

impl RttTarget {
    /// The remote to handshake with, or `None` when no TCP handshake can reach
    /// this outbound — the case [`RttSample::Through`] covers.
    ///
    /// mKCP rides UDP, and hysteria2 and tuic are QUIC end to end, so a SYN to
    /// their server says nothing about the path the tunnel takes. A native
    /// config has no single remote at all: it brings its own outbounds.
    fn new(profile: &CoreProfile, via: Option<UpstreamProxy>) -> Option<Self> {
        let CoreProfile::Link(outbound) = profile else {
            return None;
        };
        if matches!(
            outbound.protocol,
            Protocol::Hysteria2 { .. } | Protocol::Tuic { .. }
        ) || matches!(outbound.transport, Transport::Kcp { .. })
        {
            return None;
        }
        Some(Self {
            server: outbound.server.clone(),
            port: outbound.port,
            via,
        })
    }

    /// Whether the handshake this target describes is fronted by a proxy on this
    /// machine -- a chain hop's own listener, or a client the user runs locally.
    ///
    /// Such a proxy acknowledges the CONNECT from the request alone, so timing it
    /// measures a loopback round trip rather than the tunnel's.
    fn local_via(&self) -> bool {
        self.via.as_ref().is_some_and(UpstreamProxy::is_loopback)
    }
}

/// A session's own listener, which is where the tunnel can be exercised from
/// inside: what it answers there travelled the whole path and came back.
#[derive(Clone, Copy)]
struct Through {
    listener: SocketAddr,
    socks: bool,
}

/// The measurement that becomes the number.
#[derive(Clone)]
enum RttSample {
    /// Time the handshake the session's last leg makes with the server the
    /// config names: a SYN when the outbound dials directly, the CONNECT a
    /// proxy on the network performs when it is chained. No application request
    /// leaves the host. Never used for a hop whose front is local -- that
    /// CONNECT is answered from this machine.
    Handshake(RttTarget),
    /// Time a real answer fetched through the core's own listener, for the
    /// outbounds a TCP handshake cannot describe: hysteria2 and tuic are QUIC
    /// end to end, mKCP rides UDP, a native config has no single remote at all,
    /// and a hop behind a local proxy is acknowledged by that proxy alone.
    Through(Through),
}

/// How a session measures its latency, decided once when it starts.
#[derive(Clone)]
struct RttProbe {
    /// What the published number is.
    sample: RttSample,
    /// What has to answer through the tunnel before that number is published.
    ///
    /// A handshake only proves the far port accepts a connection: a config with
    /// the wrong password answers it as quickly as a working one, so the number
    /// would read as a healthy latency for a tunnel that carries nothing. When
    /// the session opened a listener, one real request has to come back through
    /// it first, and the handshake is only timed once it has. A `Through`
    /// sample needs no separate proof — it is that request.
    verify: Option<Through>,
}

impl RttProbe {
    /// The plan for this session, or `None` when there is nothing honest to
    /// measure.
    fn plan(
        profile: &CoreProfile,
        upstream: Option<UpstreamProxy>,
        endpoints: &Endpoints,
    ) -> Option<Self> {
        // SOCKS5 first: TUN mode always has one, so it is the listener a
        // session is most likely to answer on.
        let through = endpoints
            .socks
            .map(|listener| Through {
                listener,
                socks: true,
            })
            .or_else(|| {
                endpoints.http.map(|listener| Through {
                    listener,
                    socks: false,
                })
            });
        // A hop fronted by a proxy on this machine has no handshake to time: the
        // CONNECT comes back from the front itself, before it has dialled
        // anything, which is how a chained hop came to publish 2-3ms. It is
        // measured the way a QUIC outbound is -- a real answer fetched through
        // its own listener, which covers the whole chain by construction.
        if let Some(target) = RttTarget::new(profile, upstream).filter(|target| !target.local_via())
        {
            return Some(Self {
                sample: RttSample::Handshake(target),
                verify: through,
            });
        }
        // No handshake describes this outbound, so the round trip through the
        // listener is the measurement itself; without a listener there is
        // nothing to measure and nothing is invented.
        let through = through?;
        Some(Self {
            sample: RttSample::Through(through),
            verify: None,
        })
    }

    /// One measurement, in milliseconds.
    fn measure(&self) -> Option<u32> {
        if let Some(verify) = &self.verify {
            tunnel_reaches(verify)?;
        }
        match &self.sample {
            RttSample::Handshake(target) => handshake(target),
            RttSample::Through(through) => through_tunnel(through),
        }
    }

    /// The listener the proof goes through, when there is one.
    fn listener(&self) -> Option<SocketAddr> {
        match (&self.sample, &self.verify) {
            (RttSample::Through(through), _) => Some(through.listener),
            (RttSample::Handshake(_), verify) => verify.as_ref().map(|through| through.listener),
        }
    }

    /// What a log line calls this measurement.
    fn label(&self) -> &'static str {
        match (&self.sample, self.verify.is_some()) {
            (RttSample::Handshake(_), true) => "handshake with the server, proven end to end",
            (RttSample::Handshake(_), false) => "handshake with the server",
            (RttSample::Through(_), _) => "request through the tunnel",
        }
    }
}

/// Time one handshake with the target's remote, in milliseconds.
fn handshake(target: &RttTarget) -> Option<u32> {
    match &target.via {
        None => handshake_direct(&target.server, target.port),
        Some(proxy) => handshake_via(proxy, target),
    }
}

/// Our own SYN to the server. The handshake is the measurement; nothing is sent
/// after it, and the connection is closed as soon as it is answered.
fn handshake_direct(server: &str, port: u16) -> Option<u32> {
    use std::net::ToSocketAddrs;

    // Resolution is not part of a round trip, so every candidate is resolved
    // before the clock starts; each attempt is then timed on its own, so a
    // first family that goes nowhere cannot inflate the answer that worked.
    let addresses: Vec<std::net::SocketAddr> = (server, port).to_socket_addrs().ok()?.collect();
    for address in addresses {
        let started = Instant::now();
        if std::net::TcpStream::connect_timeout(&address, HANDSHAKE_TIMEOUT).is_ok() {
            return Some(millis_ceil(started.elapsed()));
        }
    }
    None
}

/// The handshake the hop above performs: the proxy is asked to connect, and the
/// time that takes — its own dial to the server, plus the server's answer
/// travelling back — is the round trip to the remote.
fn handshake_via(proxy: &UpstreamProxy, target: &RttTarget) -> Option<u32> {
    use std::io::{Read, Write};

    // The connection to the proxy is a leg the traffic really takes, and the
    // proxy is off this machine by construction ([`RttTarget::local_via`]), so
    // timing it here measures the path rather than a loopback greeting.
    let started = Instant::now();
    let mut stream = open(proxy)?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).ok()?;
    match proxy.kind {
        ProxyKind::Socks5 => {
            socks_negotiate(&mut stream, proxy)?;
            stream
                .write_all(&socks_connect_request(&target.server, target.port))
                .ok()?;
            // A reply code other than success means the hop could not reach the
            // server, so there is no round trip to report.
            socks_reply(&mut stream)?;
        }
        ProxyKind::Http => {
            stream
                .write_all(http_connect_request(proxy, target).as_bytes())
                .ok()?;
            let mut status = [0u8; 12];
            stream.read_exact(&mut status).ok()?;
            // A 2xx is the proxy's own confirmation that the server answered.
            if !status.starts_with(b"HTTP/1.") || status[8] != b' ' || status[9] != b'2' {
                return None;
            }
            skip_headers(&mut stream, [0; 4])?;
        }
    }
    Some(millis_ceil(started.elapsed()))
}

/// Open one session to `host` through the core's own listener.
///
/// The proxy's acknowledgement is not a measurement, for the same reason the
/// handshake exists at all: Xray-core answers a SOCKS5 CONNECT as soon as it has
/// parsed the request, before it has dialled anything, so the acknowledgement
/// only proves a loopback round trip.
fn connect_through(through: &Through, host: &str) -> Option<std::net::TcpStream> {
    use std::io::{Read, Write};

    let mut stream = std::net::TcpStream::connect_timeout(&through.listener, PROBE_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).ok()?;
    // The request is one short write; Nagle would fold it into a delayed ACK and
    // charge the measurement for it.
    let _ = stream.set_nodelay(true);

    if through.socks {
        stream.write_all(&[0x05, 0x01, 0x00]).ok()?;
        let mut choice = [0u8; 2];
        stream.read_exact(&mut choice).ok()?;
        if choice != [0x05, 0x00] {
            return None;
        }
        let name = host.as_bytes();
        let mut request = Vec::with_capacity(7 + name.len());
        request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, name.len() as u8]);
        request.extend_from_slice(name);
        request.extend_from_slice(&RTT_PORT.to_be_bytes());
        stream.write_all(&request).ok()?;
        socks_reply(&mut stream)?;
    } else {
        let authority = format!("{host}:{RTT_PORT}");
        let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        stream.write_all(request.as_bytes()).ok()?;
        let mut status = [0u8; 12];
        stream.read_exact(&mut status).ok()?;
        if !status.starts_with(b"HTTP/1.") || !matches!(status[9], b'2' | b'3') {
            return None;
        }
        let mut window = [0u8; 4];
        window.copy_from_slice(&status[8..12]);
        skip_headers(&mut stream, window)?;
    }
    Some(stream)
}

/// Whether one real request comes back through the tunnel, with no clock.
fn tunnel_reaches(through: &Through) -> Option<()> {
    RTT_TARGETS.iter().find_map(|&(host, path)| {
        let mut stream = connect_through(through, host)?;
        exchange(&mut stream, host, path).map(|_| ())
    })
}

/// Time a request answered through the core's own listener, in milliseconds.
fn through_tunnel(through: &Through) -> Option<u32> {
    RTT_TARGETS.iter().find_map(|&(host, path)| {
        let mut stream = connect_through(through, host)?;
        let cold = exchange(&mut stream, host, path)?;
        // The second request rides the connection the first one opened, so the
        // window is the round trip itself and not the tunnel's handshake.
        Some(millis_ceil(
            exchange(&mut stream, host, path).unwrap_or(cold),
        ))
    })
}

/// Send one probe request and time it to the first byte of the answer, then read
/// to the end of that answer's header block so the connection can carry the next
/// one.
fn exchange(stream: &mut std::net::TcpStream, host: &str, path: &str) -> Option<Duration> {
    use std::io::{Read, Write};

    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n");
    let started = Instant::now();
    stream.write_all(request.as_bytes()).ok()?;
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).ok()?;
    // A status line, and an HTTP one: an error page from the proxy itself would
    // be an answer to the proxy, not through the tunnel.
    if first[0] != b'H' {
        return None;
    }
    let waited = started.elapsed();
    let mut window = [0u8; 4];
    window[3] = first[0];
    skip_headers(stream, window)?;
    Some(waited)
}

/// Connect to a proxy. Untimed on its own; [`handshake_via`] owns the clock.
fn open(proxy: &UpstreamProxy) -> Option<std::net::TcpStream> {
    use std::net::ToSocketAddrs;

    for address in (proxy.host.as_str(), proxy.port).to_socket_addrs().ok()? {
        if let Ok(stream) = std::net::TcpStream::connect_timeout(&address, HANDSHAKE_TIMEOUT) {
            return Some(stream);
        }
    }
    None
}

/// SOCKS5 method negotiation, plus RFC 1929 when the proxy asks for credentials.
fn socks_negotiate(stream: &mut std::net::TcpStream, proxy: &UpstreamProxy) -> Option<()> {
    use std::io::{Read, Write};

    let credentials = proxy.user.is_some() && proxy.password.is_some();
    let methods: &[u8] = if credentials { &[0x00, 0x02] } else { &[0x00] };
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(0x05);
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).ok()?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).ok()?;
    match choice {
        [0x05, 0x00] => Some(()),
        [0x05, 0x02] => {
            let user = proxy.user.as_deref().unwrap_or("").as_bytes();
            let password = proxy.password.as_deref().unwrap_or("").as_bytes();
            let mut auth = Vec::with_capacity(3 + user.len() + password.len());
            auth.push(0x01);
            auth.push(user.len().min(u8::MAX as usize) as u8);
            auth.extend_from_slice(&user[..user.len().min(u8::MAX as usize)]);
            auth.push(password.len().min(u8::MAX as usize) as u8);
            auth.extend_from_slice(&password[..password.len().min(u8::MAX as usize)]);
            stream.write_all(&auth).ok()?;
            let mut reply = [0u8; 2];
            stream.read_exact(&mut reply).ok()?;
            (reply == [0x01, 0x00]).then_some(())
        }
        _ => None,
    }
}

/// A SOCKS5 CONNECT for the remote, addressed the way the core addresses it: an
/// IP literal as itself, a hostname as a name the proxy resolves.
fn socks_connect_request(server: &str, port: u16) -> Vec<u8> {
    let mut request = Vec::with_capacity(22);
    request.extend_from_slice(&[0x05, 0x01, 0x00]);
    match server.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let host = server.as_bytes();
            let length = host.len().min(u8::MAX as usize);
            request.push(0x03);
            request.push(length as u8);
            request.extend_from_slice(&host[..length]);
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    request
}

/// A proxied CONNECT for the remote, with the proxy's credentials when it has
/// any.
fn http_connect_request(proxy: &UpstreamProxy, target: &RttTarget) -> String {
    let authority = if target.server.contains(':') {
        format!("[{}]:{}", target.server, target.port)
    } else {
        format!("{}:{}", target.server, target.port)
    };
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(user) = proxy.user.as_deref() {
        let password = proxy.password.as_deref().unwrap_or("");
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&crate::upstream::base64(
            format!("{user}:{password}").as_bytes(),
        ));
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request
}

/// Read a SOCKS5 reply in full: version, status, address type, the bound
/// address and its port.
///
/// The address is consumed even though nothing needs it, because a caller that
/// went on to use the connection would otherwise read the tail of the reply as
/// if it were payload.
fn socks_reply(stream: &mut std::net::TcpStream) -> Option<()> {
    use std::io::Read;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).ok()?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return None;
    }
    let mut left = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).ok()?;
            length[0] as usize + 2
        }
        _ => return None,
    };
    let mut skip = [0u8; 18];
    while left > 0 {
        let take = left.min(skip.len());
        stream.read_exact(&mut skip[..take]).ok()?;
        left -= take;
    }
    Some(())
}

/// Read through the blank line that ends an HTTP header block.
///
/// `window` is the last four bytes already consumed, oldest first: a header
/// block can end inside what the caller has read, and re-reading it is not
/// possible.
fn skip_headers(stream: &mut std::net::TcpStream, mut window: [u8; 4]) -> Option<()> {
    use std::io::Read;

    let mut byte = [0u8; 1];
    for _ in 0..HEAD_LIMIT {
        if &window == b"\r\n\r\n" {
            return Some(());
        }
        stream.read_exact(&mut byte).ok()?;
        window.rotate_left(1);
        window[3] = byte[0];
    }
    None
}

/// Milliseconds, rounded up and never zero: the value is also what the UI reads
/// as "measured", and 0 means it has nothing to show.
fn millis_ceil(elapsed: Duration) -> u32 {
    let millis = elapsed.as_micros().div_ceil(1000);
    millis.clamp(1, u32::MAX as u128) as u32
}

/// Bytes-per-second between two samples `elapsed_ms` apart, computed in
/// milliseconds so a fast pump cannot collapse the rate to zero.
fn rate(delta: u64, elapsed_ms: u64) -> u64 {
    delta.saturating_mul(1_000) / elapsed_ms.max(1)
}

/// Rate bookkeeping for one core.
///
/// Totals are cumulative and the pump samples them once a second; the UI wants
/// bytes/sec, so the previous sample is kept here. Owned by the handle rather
/// than a module static, so two cores in one process can never share a
/// baseline, and a restarted core starts a fresh one.
#[derive(Default)]
struct Traffic {
    /// Totals published by the last sample.
    total_tx: u64,
    total_rx: u64,
    /// Baseline of the last rate calculation.
    prev_tx: u64,
    prev_rx: u64,
    at: Option<Instant>,
}

impl Traffic {
    /// Fold one shim sample into a telemetry sample.
    ///
    /// `None` means the core had no totals to report: the previous ones are
    /// republished with zero rates, because a momentary gap must not look like
    /// a restart to [`crate::telemetry`] — it folds the published total when a
    /// sample goes backwards, and folding twice would double-count the session.
    fn counters(&mut self, sample: Option<(u64, u64)>, now: Instant, rtt_ms: u32) -> Counters {
        if let Some((tx, rx)) = sample {
            self.total_tx = tx;
            self.total_rx = rx;
        }
        let (tx_bytes_sec, rx_bytes_sec) = match self.at {
            // The first sample has no baseline; a one-off spike of the session's
            // lifetime bytes would be a lie.
            None => (0, 0),
            Some(at) => {
                let elapsed = now.saturating_duration_since(at).as_millis() as u64;
                (
                    rate(self.total_tx.saturating_sub(self.prev_tx), elapsed),
                    rate(self.total_rx.saturating_sub(self.prev_rx), elapsed),
                )
            }
        };
        self.prev_tx = self.total_tx;
        self.prev_rx = self.total_rx;
        self.at = Some(now);
        Counters {
            total_rx: self.total_rx,
            total_tx: self.total_tx,
            rx_bytes_sec,
            tx_bytes_sec,
            rtt_ms,
        }
    }
}

#[async_trait]
impl BackendHandle for Running {
    fn endpoints(&self) -> Endpoints {
        self.endpoints.clone()
    }

    fn carrier_up(&self) -> bool {
        self.alive()
    }

    /// Cumulative totals read from the core's own stats manager, the rate
    /// between the last two polls, and the tunnel round trip once measured.
    /// Nothing here is estimated: a core that reports no counters publishes
    /// zeros instead of a guess.
    fn counters(&self) -> Counters {
        let sample = self.bytes();
        let rtt_ms = self.rtt_ms.load(Ordering::Acquire);
        self.traffic.lock().counters(sample, Instant::now(), rtt_ms)
    }

    /// The cores have no "session ended" event to await, so the handle polls the
    /// running flag. A stop this handle asked for is a clean exit.
    async fn wait(&self) -> CoreResult<()> {
        while self.alive() {
            tokio::time::sleep(POLL).await;
        }
        if self.stopping.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(CoreError::StartFailed("the core stopped".into()))
        }
    }

    async fn stop(&self, timeout: Duration) -> CoreResult<()> {
        self.rtt_stop.store(true, Ordering::Release);
        // The deadline includes the blocking native stop, not just the poll
        // after it. A timed-out await does not cancel that cleanup work.
        tokio::time::timeout(timeout, self.halt())
            .await
            .map_err(|_| CoreError::Timeout(timeout))?;
        Ok(())
    }
}

impl Running {
    /// Stop the core and record that this handle asked for it, so its [`Drop`]
    /// does not stop it twice.
    async fn halt(&self) {
        if !self.stopping.swap(true, Ordering::SeqCst) {
            let ffi = self.ffi;
            let handle = self.handle;
            let backend = self.backend;
            let _ = tokio::task::spawn_blocking(move || {
                unsafe { (ffi.stop)(handle) };
                retire_live(backend, handle);
            })
            .await;
        } else {
            // Another stop owns the native work, including registry cleanup.
            while self.alive() {
                tokio::time::sleep(POLL).await;
            }
        }
    }
}

impl Drop for Running {
    /// A handle dropped instead of stopped still owns the core and the
    /// measurement loop, so both are retired here.
    ///
    /// The handle is dropped without a stop whenever the start it belongs to is
    /// abandoned: the supervisor's cancellation can drop the future inside
    /// `await_ready` or `await_tunnel`, after the core is already up. Leaving
    /// the core behind there is the leak of a whole engine per cancelled
    /// connect, so it is stopped -- off this thread, and only when no stop was
    /// asked for.
    fn drop(&mut self) {
        self.rtt_stop.store(true, Ordering::Release);
        if !self.stopping.load(Ordering::SeqCst) {
            halt_detached(self.backend, self.ffi, self.handle);
        }
    }
}

async fn probe(address: SocketAddr, socks: bool) -> std::io::Result<()> {
    let mut stream = timeout(PROBE_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))??;
    if !socks {
        return Ok(());
    }
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut reply = [0u8; 2];
    timeout(PROBE_TIMEOUT, stream.read_exact(&mut reply))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "SOCKS5 greeting timed out")
        })??;
    if reply != [0x05, 0x00] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected SOCKS5 greeting {reply:?}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    /// Stop calls seen by the counting shim below.
    static STOPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    /// The handle the last stop was called with, so a stop of the wrong instance
    /// (or of the whole core) cannot pass as the right one.
    static LAST_STOP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    /// The handle the counting shim hands back from a start.
    const HANDLE: u64 = 7;
    /// The counter is process-wide, so the two guard tests take turns.
    static GUARD_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A shim whose entry points do nothing but count a stop, so a guard can be
    /// exercised without a Go archive behind it.
    fn counting_ffi() -> CoreFfi {
        unsafe extern "C" fn start(_: *const c_char, handle: *mut u64) -> *mut c_char {
            *handle = HANDLE;
            std::ptr::null_mut()
        }
        unsafe extern "C" fn stop(handle: u64) {
            LAST_STOP.store(handle, Ordering::SeqCst);
            STOPS.fetch_add(1, Ordering::SeqCst);
        }
        unsafe extern "C" fn stop_all() {
            // Distinct from a stop: the teardown net must never pass for one.
            LAST_STOP.store(0, Ordering::SeqCst);
            STOPS.fetch_add(1, Ordering::SeqCst);
        }
        unsafe extern "C" fn running(_: u64) -> c_int {
            0
        }
        unsafe extern "C" fn string_free(_: *mut c_char) {}
        unsafe extern "C" fn stats(_: u64, _: *mut i64, _: *mut i64) -> c_int {
            0
        }
        unsafe extern "C" fn set_log(
            _: Option<unsafe extern "C" fn(c_int, *const c_char)>,
            _: c_int,
        ) {
        }
        unsafe extern "C" fn listeners(_: *mut c_char, _: c_int) -> c_int {
            0
        }
        CoreFfi {
            start,
            stop,
            stop_all,
            running,
            string_free,
            stats,
            set_log,
            listeners,
        }
    }

    fn await_stops(total: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while (STOPS.load(Ordering::SeqCst)) < total {
            assert!(
                Instant::now() < deadline,
                "the abandoned start was never stopped"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A record carries the handle that names the instance, its own flavour and
    /// whether its port reaches beyond loopback -- so the host can join the
    /// record to the session that started it and say which core serves which
    /// port, under what name.
    #[test]
    fn listener_records_keep_their_instance_label_and_scope() {
        let parsed = parse_listeners(
            "7|vless reality|socks|1827|local;\
             7|vless reality|http|1828|any;\
             9||socks|9000|local",
        );
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].handle, 7);
        assert_eq!(parsed[0].label, "vless reality");
        assert_eq!(parsed[0].proto, "socks");
        assert_eq!(parsed[0].port, 1827);
        assert!(
            !parsed[0].any,
            "a loopback listener is not offered on the LAN"
        );
        assert_eq!(parsed[1].proto, "http");
        assert!(
            parsed[1].any,
            "a wildcard listener answers on the LAN address"
        );
        assert_eq!(parsed[2].handle, 9, "each instance keeps its own handle");
        assert_eq!(
            parsed[2].label, "",
            "a config with no outbound names nothing"
        );
    }

    /// The registry is what puts a route in one order and numbers it across the
    /// cores it runs: an instance joins it when its start hands it a handle --
    /// the exit first, each hop above it next -- and a stop takes it back out.
    #[test]
    fn live_instances_keep_the_order_their_route_started_them_in() {
        const EXIT: u64 = u64::MAX;
        const HOP: u64 = u64::MAX - 1;
        let listed = |backend: FcaeBackend, handle: u64| {
            live_instances()
                .into_iter()
                .position(|instance| instance.backend == backend && instance.handle == handle)
        };
        publish_live(FcaeBackend::Xray, EXIT, "Home".into());
        publish_live(FcaeBackend::SingBox, HOP, "Backup".into());
        let (exit, hop) = (
            listed(FcaeBackend::Xray, EXIT).expect("the exit is listed"),
            listed(FcaeBackend::SingBox, HOP).expect("the hop is listed"),
        );
        assert!(
            exit < hop,
            "the exit is listed before the hop that dials through it"
        );
        assert_eq!(
            live_instances()[exit].name,
            "Home",
            "the instance is named by its saved config"
        );

        retire_live(FcaeBackend::Xray, EXIT);
        assert_eq!(listed(FcaeBackend::Xray, EXIT), None);
        assert_eq!(
            listed(FcaeBackend::SingBox, HOP),
            Some(0),
            "stopping one instance leaves the others alone"
        );

        retire_all(FcaeBackend::SingBox);
        assert_eq!(listed(FcaeBackend::SingBox, HOP), None);
    }

    /// A record this side cannot read in full is not guessed at.
    #[test]
    fn a_short_listener_record_is_skipped() {
        assert!(parse_listeners("1|socks|1827").is_empty());
        assert!(parse_listeners("1|vless|socks|port|any").is_empty());
        assert_eq!(parse_listeners("1|vless|socks|1827|any;").len(), 1);
    }

    /// The regression behind "sing-box stayed in memory after a disconnect":
    /// dropping the future that awaits a core's start discards the answer, not
    /// the work, so the core comes up with nothing left holding it -- and every
    /// later start of that core was refused as already running.
    #[test]
    fn an_abandoned_start_stops_the_core_it_would_have_left_running() {
        let _turn = GUARD_TESTS.lock().unwrap_or_else(|held| held.into_inner());
        STOPS.store(0, Ordering::SeqCst);
        let guard = CoreStart {
            worker: Some(std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(20))
            })),
            ffi: counting_ffi(),
            handle: Arc::new(AtomicU64::new(HANDLE)),
            armed: true,
        };
        drop(guard);
        // The stop follows the start, never races it: a stop that arrived first
        // would find no instance and the core would run unowned.
        await_stops(1);
        assert_eq!(
            LAST_STOP.load(Ordering::SeqCst),
            HANDLE,
            "the guard stopped something other than the instance it started"
        );
    }

    /// Once a handle owns the core, the guard must not stop it behind the
    /// session's back.
    #[test]
    fn a_disarmed_start_leaves_the_core_alone() {
        let _turn = GUARD_TESTS.lock().unwrap_or_else(|held| held.into_inner());
        STOPS.store(0, Ordering::SeqCst);
        let guard = CoreStart {
            worker: Some(std::thread::spawn(|| {})),
            ffi: counting_ffi(),
            handle: Arc::new(AtomicU64::new(HANDLE)),
            armed: false,
        };
        drop(guard);
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            STOPS.load(Ordering::SeqCst),
            0,
            "a claimed core must survive the guard"
        );
    }

    #[test]
    fn the_log_gate_follows_the_engine_level() {
        assert_eq!(log_gate(Level::Off), 0);
        assert_eq!(log_gate(Level::Error), 1);
        assert_eq!(log_gate(Level::Warn), 2);
        assert_eq!(log_gate(Level::Info), 3);
        assert_eq!(log_gate(Level::Debug), 4);
        assert_eq!(log_gate(Level::Trace), 4);
    }

    #[test]
    fn traffic_rates_follow_the_pump_interval() {
        let start = Instant::now();
        let mut traffic = Traffic::default();
        let first = traffic.counters(Some((1_000, 500)), start, 0);
        assert_eq!((first.total_tx, first.total_rx), (1_000, 500));
        // No baseline yet: totals without an invented rate.
        assert_eq!((first.tx_bytes_sec, first.rx_bytes_sec), (0, 0));
        let second = traffic.counters(Some((3_000, 1_500)), start + Duration::from_secs(2), 42);
        assert_eq!((second.total_tx, second.total_rx), (3_000, 1_500));
        assert_eq!((second.tx_bytes_sec, second.rx_bytes_sec), (1_000, 500));
        assert_eq!(second.rtt_ms, 42);
        // Sub-second pumps are scaled, not truncated: 50 bytes in 500 ms.
        let fast = traffic.counters(
            Some((3_050, 1_500)),
            start + Duration::from_millis(2_500),
            42,
        );
        assert_eq!(fast.tx_bytes_sec, 100);
    }

    #[test]
    fn a_silent_core_keeps_its_totals_instead_of_restarting_them() {
        let start = Instant::now();
        let mut traffic = Traffic::default();
        traffic.counters(Some((4_000, 2_000)), start, 0);
        // The core reports nothing for one poll: republish, do not reset.
        let gap = traffic.counters(None, start + Duration::from_secs(1), 0);
        assert_eq!((gap.total_tx, gap.total_rx), (4_000, 2_000));
        assert_eq!((gap.tx_bytes_sec, gap.rx_bytes_sec), (0, 0));
        let resumed = traffic.counters(Some((4_500, 2_000)), start + Duration::from_secs(2), 0);
        assert_eq!((resumed.total_tx, resumed.total_rx), (4_500, 2_000));
        assert_eq!(resumed.tx_bytes_sec, 500);
    }

    /// A connected pair whose peer writes `bytes` and hangs up.
    fn loopback(bytes: &'static [u8]) -> std::net::TcpStream {
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept");
            let _ = peer.write_all(bytes);
        });
        std::net::TcpStream::connect(address).expect("connect")
    }

    #[test]
    fn a_socks_reply_is_read_past_its_bound_address() {
        use std::io::Read as _;

        // A bound IPv4 address, then the answer: the helper must stop at the
        // answer, not inside the address it does not need.
        let mut stream = loopback(&[0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x1f, 0x90, b'H', b'T']);
        assert_eq!(socks_reply(&mut stream), Some(()));
        let mut next = [0u8; 2];
        stream.read_exact(&mut next).expect("payload");
        assert_eq!(&next, b"HT");

        // A domain-shaped address carries a length byte of its own.
        let mut stream = loopback(&[
            0x05, 0x00, 0x00, 0x03, 9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0x1f,
            0x90, b'H',
        ]);
        assert_eq!(socks_reply(&mut stream), Some(()));
        let mut next = [0u8; 1];
        stream.read_exact(&mut next).expect("payload");
        assert_eq!(&next, b"H");
    }

    #[test]
    fn a_refused_socks_reply_is_not_a_measurement() {
        // REP 0x05 is "connection refused": the tunnel never came up, so there
        // is nothing to time.
        let mut stream = loopback(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        assert_eq!(socks_reply(&mut stream), None);
    }

    #[test]
    fn a_connect_answer_is_read_to_the_end_of_its_headers() {
        use std::io::Read as _;

        // The tail of the status line, a header, the blank line, then the
        // tunnelled answer.
        let mut stream = loopback(b" 200 Connection established\r\nVia: proxy\r\n\r\nHT");
        skip_headers(&mut stream, [0; 4]).expect("headers end");
        let mut next = [0u8; 2];
        stream.read_exact(&mut next).expect("payload");
        assert_eq!(&next, b"HT");
    }

    /// A listener on loopback that hands its one connection to `handler`.
    fn serve(handler: impl FnOnce(std::net::TcpStream) + Send + 'static) -> std::net::SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            handler(stream);
        });
        address
    }

    fn proxy(kind: ProxyKind, address: std::net::SocketAddr) -> UpstreamProxy {
        UpstreamProxy {
            kind,
            host: address.ip().to_string(),
            port: address.port(),
            user: None,
            password: None,
        }
    }

    #[test]
    fn a_direct_handshake_times_the_remote_itself() {
        use std::io::Read as _;

        // The server says nothing; the reading is the handshake, so an accept
        // with no answer at all is still a measurement.
        let address = serve(|mut stream| {
            let mut buffer = [0u8; 1];
            let _ = stream.read(&mut buffer);
        });
        let target = RttTarget {
            server: address.ip().to_string(),
            port: address.port(),
            via: None,
        };
        let measured = handshake(&target).expect("measured");
        assert!(measured >= 1, "a handshake reads as at least a millisecond");
    }

    #[test]
    fn a_handshake_nobody_answers_is_not_a_measurement() {
        // A port with nothing behind it: the tunnel is not up, so there is no
        // round trip to report and the sample retries instead.
        let address = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("address")
        };
        let target = RttTarget {
            server: address.ip().to_string(),
            port: address.port(),
            via: None,
        };
        assert_eq!(handshake(&target), None);
    }

    #[test]
    fn a_chained_session_handshakes_through_the_hop_above() {
        use std::io::{Read as _, Write as _};

        // A hop that answers its CONNECT only after a delay, the way a proxy
        // that has to dial the server does. The reading must include that wait,
        // and the request must name the server as a name for the hop to resolve.
        let address = serve(|mut stream| {
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).expect("greeting");
            stream.write_all(&[0x05, 0x00]).expect("greeting reply");
            let mut head = [0u8; 5];
            stream.read_exact(&mut head).expect("connect head");
            assert_eq!(head[3], 0x03, "the server is handed over as a name");
            let mut rest = vec![0u8; head[4] as usize + 2];
            stream.read_exact(&mut rest).expect("host and port");
            std::thread::sleep(Duration::from_millis(150));
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x1f, 0x90])
                .expect("connect reply");
        });
        let target = RttTarget {
            server: "example.com".into(),
            port: 443,
            via: Some(proxy(ProxyKind::Socks5, address)),
        };
        let measured = handshake(&target).expect("measured");
        assert!(
            measured >= 100,
            "the hop's dial was not timed: {measured}ms"
        );
    }

    #[test]
    fn a_hop_that_cannot_reach_the_server_reports_nothing() {
        use std::io::{Read as _, Write as _};

        // SOCKS5 reply 0x05 is "connection refused": the hop tried and failed,
        // so the number would be the hop's, not the server's.
        let address = serve(|mut stream| {
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).expect("greeting");
            stream.write_all(&[0x05, 0x00]).expect("greeting reply");
            let mut rest = [0u8; 7];
            stream.read_exact(&mut rest).expect("connect");
            stream
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .expect("connect reply");
        });
        let target = RttTarget {
            server: "example.com".into(),
            port: 443,
            via: Some(proxy(ProxyKind::Socks5, address)),
        };
        assert_eq!(handshake(&target), None);
    }

    /// A proxy that asks for RFC 1929 credentials: it offers both methods, picks
    /// the password one, and answers the CONNECT only to the right secret.
    fn credentials_hop() -> std::net::SocketAddr {
        use std::io::{Read as _, Write as _};

        serve(|mut stream| {
            let mut greeting = [0u8; 4];
            stream.read_exact(&mut greeting).expect("greeting");
            assert_eq!(greeting, [0x05, 0x02, 0x00, 0x02]);
            stream.write_all(&[0x05, 0x02]).expect("method reply");
            let mut head = [0u8; 2];
            stream.read_exact(&mut head).expect("auth head");
            let mut user = vec![0u8; head[1] as usize];
            stream.read_exact(&mut user).expect("user");
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).expect("password length");
            let mut password = vec![0u8; length[0] as usize];
            stream.read_exact(&mut password).expect("password");
            let accepted = user == b"alice" && password == b"secret";
            stream
                .write_all(&[0x01, if accepted { 0x00 } else { 0x01 }])
                .expect("auth reply");
            if !accepted {
                return;
            }
            let mut request = [0u8; 7];
            stream.read_exact(&mut request).expect("connect");
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .expect("connect reply");
        })
    }

    #[test]
    fn a_proxy_that_wants_credentials_gets_them() {
        use std::io::{Read as _, Write as _};

        // Its own listener per attempt: a single-shot one would fail the second
        // handshake with a closed port, and the rejection below would then hold
        // for the wrong reason.
        let with = |password: &str| RttTarget {
            server: "example.com".into(),
            port: 443,
            via: Some(UpstreamProxy {
                user: Some("alice".into()),
                password: Some(password.into()),
                ..proxy(ProxyKind::Socks5, credentials_hop())
            }),
        };
        assert!(handshake(&with("secret")).is_some());

        // A proxy that reads the credentials and refuses them: the CONNECT is
        // never asked for, so there is no handshake to report.
        let refusing = serve(|mut stream| {
            let mut greeting = [0u8; 4];
            let _ = stream.read_exact(&mut greeting);
            let _ = stream.write_all(&[0x05, 0x02]);
            let mut head = [0u8; 2];
            let _ = stream.read_exact(&mut head);
            let mut rest = vec![0u8; head[1] as usize + 1];
            let _ = stream.read_exact(&mut rest);
            let mut length = [0u8; 1];
            let _ = stream.read_exact(&mut length);
            let mut password = vec![0u8; length[0] as usize];
            let _ = stream.read_exact(&mut password);
            let _ = stream.write_all(&[0x01, 0x01]);
        });
        let wrong = RttTarget {
            server: "example.com".into(),
            port: 443,
            via: Some(UpstreamProxy {
                user: Some("alice".into()),
                password: Some("wrong".into()),
                ..proxy(ProxyKind::Socks5, refusing)
            }),
        };
        assert_eq!(handshake(&wrong), None);
    }

    #[test]
    fn an_http_proxy_handshakes_with_connect_and_its_credentials() {
        use std::io::{Read as _, Write as _};

        let address = serve(|mut stream| {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).expect("request");
                head.push(byte[0]);
            }
            let text = String::from_utf8(head).expect("utf-8");
            assert!(text.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            // "alice:secret" in Basic.
            assert!(text.contains("Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answer");
        });
        let target = RttTarget {
            server: "example.com".into(),
            port: 443,
            via: Some(UpstreamProxy {
                user: Some("alice".into()),
                password: Some("secret".into()),
                ..proxy(ProxyKind::Http, address)
            }),
        };
        assert!(handshake(&target).is_some());
    }

    #[test]
    fn a_quic_outbound_is_measured_through_the_tunnel_instead() {
        // hysteria2 has no TCP handshake to time, so the plan falls back to a
        // real request through the listener the session opened for itself.
        let listener = std::net::SocketAddr::from(([127, 0, 0, 1], 1080));
        let endpoints = Endpoints {
            socks: Some(listener),
            http: None,
            peer_ip: None,
            udp: true,
            psiphon_dns: false,
        };
        let profile = CoreProfile::parse("hysteria2://pass@example.com:443#q").expect("parses");
        match RttProbe::plan(&profile, None, &endpoints) {
            Some(probe) => {
                let RttSample::Through(through) = probe.sample else {
                    panic!("a QUIC outbound must be measured through the tunnel");
                };
                assert_eq!(through.listener, listener);
                assert!(through.socks);
                // The round trip is the measurement, so there is nothing extra
                // to prove.
                assert!(probe.verify.is_none());
                assert_eq!(probe.listener(), Some(listener));
            }
            _ => panic!("a QUIC outbound must be measured through the tunnel"),
        }
        // Nothing to measure at all when the session opened no listener.
        let bare = Endpoints {
            socks: None,
            http: None,
            peer_ip: None,
            udp: true,
            psiphon_dns: false,
        };
        assert!(RttProbe::plan(&profile, None, &bare).is_none());
        // And a native config has no single remote either.
        let native =
            CoreProfile::parse(r##"{"outbounds": [{"type": "direct", "tag": "direct"}]}"##)
                .expect("parses");
        assert!(matches!(
            RttProbe::plan(&native, None, &endpoints).map(|probe| probe.sample),
            Some(RttSample::Through(_))
        ));
    }

    #[test]
    fn a_through_the_tunnel_measurement_times_the_warm_request() {
        use std::io::{Read as _, Write as _};

        // The session's own listener, answering the way a core does: the
        // CONNECT is acknowledged at once, the first request is slow (that is
        // the handshake to the far end), the second one is not.
        let listener = serve(|mut stream| {
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).expect("greeting");
            stream.write_all(&[0x05, 0x00]).expect("greeting reply");
            let mut head = [0u8; 5];
            stream.read_exact(&mut head).expect("connect head");
            let mut rest = vec![0u8; head[4] as usize + 2];
            stream.read_exact(&mut rest).expect("host and port");
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x1f, 0x90])
                .expect("connect reply");
            for request in 0..2 {
                let mut byte = [0u8; 1];
                let mut window = [0u8; 4];
                while &window != b"\r\n\r\n" {
                    stream.read_exact(&mut byte).expect("request");
                    window.rotate_left(1);
                    window[3] = byte[0];
                }
                if request == 0 {
                    std::thread::sleep(Duration::from_millis(150));
                }
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .expect("answer");
            }
        });
        let through = Through {
            listener,
            socks: true,
        };
        let measured = through_tunnel(&through).expect("measured");
        assert!(measured < 100, "the warm request was {measured}ms");
    }

    #[test]
    fn a_tcp_outbound_has_to_prove_the_tunnel_before_its_handshake_is_published() {
        let listener = std::net::SocketAddr::from(([127, 0, 0, 1], 1080));
        let endpoints = Endpoints {
            socks: Some(listener),
            http: None,
            peer_ip: None,
            udp: true,
            psiphon_dns: false,
        };
        let profile =
            CoreProfile::parse(&format!("vless://{UUID}@example.com:443#tcp")).expect("parses");
        match RttProbe::plan(&profile, None, &endpoints) {
            Some(probe) => {
                assert!(matches!(probe.sample, RttSample::Handshake(_)));
                let through = probe.verify.expect("the handshake is proven first");
                assert_eq!(through.listener, listener);
                assert!(through.socks);
                assert_eq!(probe.listener(), Some(listener));
            }
            None => panic!("a TCP outbound times its handshake, proven through the listener"),
        }
        // No listener means nothing to prove through: the plan stays the bare
        // handshake rather than claiming a proof it cannot make.
        let bare = Endpoints {
            socks: None,
            http: None,
            peer_ip: None,
            udp: true,
            psiphon_dns: false,
        };
        match RttProbe::plan(&profile, None, &bare) {
            Some(probe) => {
                assert!(matches!(probe.sample, RttSample::Handshake(_)));
                assert!(probe.verify.is_none());
                // Nothing could be verified, so nothing is named in a refusal.
                assert_eq!(probe.listener(), None);
            }
            None => panic!("without a listener the handshake stands alone"),
        }
    }

    #[test]
    fn a_hop_behind_a_local_proxy_is_measured_through_the_tunnel() {
        // The hop above a chained core is this app's own listener, and both
        // cores acknowledge a CONNECT as soon as they have parsed it: timing
        // that would publish a loopback round trip -- the 2-3ms a chained hop
        // used to report.
        let listener = std::net::SocketAddr::from(([127, 0, 0, 1], 1830));
        let endpoints = Endpoints {
            socks: Some(listener),
            http: None,
            peer_ip: None,
            udp: true,
            psiphon_dns: false,
        };
        let profile =
            CoreProfile::parse(&format!("vless://{UUID}@example.com:443#tcp")).expect("parses");
        let front = UpstreamProxy::loopback(std::net::SocketAddr::from(([127, 0, 0, 1], 1827)));
        match RttProbe::plan(&profile, Some(front), &endpoints) {
            Some(probe) => {
                let RttSample::Through(through) = probe.sample else {
                    panic!("a local front cannot be timed by a handshake");
                };
                assert_eq!(through.listener, listener);
                assert!(through.socks);
                // The request that travels the whole chain is the measurement.
                assert!(probe.verify.is_none());
            }
            None => panic!("the hop's own listener is measurable"),
        }
        // A proxy off this machine is on the traffic's path, so the handshake it
        // performs stands as the number.
        let remote = proxy(
            ProxyKind::Socks5,
            std::net::SocketAddr::from(([203, 0, 113, 9], 1080)),
        );
        assert!(matches!(
            RttProbe::plan(&profile, Some(remote), &endpoints).map(|probe| probe.sample),
            Some(RttSample::Handshake(_))
        ));
    }

    #[test]
    fn a_tunnel_that_carries_nothing_yields_no_measurement() {
        // The listener accepts the greeting and the CONNECT — as Xray does
        // before it has dialled anything — and then has nothing to answer with.
        let dead = serve(|mut stream| {
            let mut greeting = [0u8; 3];
            let _ = stream.read_exact(&mut greeting);
            let _ = stream.write_all(&[0x05, 0x00]);
            let mut head = [0u8; 5];
            if stream.read_exact(&mut head).is_ok() {
                let mut rest = vec![0u8; head[4] as usize + 2];
                let _ = stream.read_exact(&mut rest);
                let _ = stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            }
            // Closing without an answer is what a refused dial looks like here.
        });
        let through = Through {
            listener: dead,
            socks: true,
        };
        assert_eq!(tunnel_reaches(&through), None);
        assert_eq!(through_tunnel(&through), None);
    }

    #[test]
    fn a_failed_measurement_retries_sooner_at_first() {
        // A session is usually still settling when its start hands over, so the
        // first retries are close together; after that it is the keepalive tick.
        assert_eq!(retry_delay(1), Duration::from_secs(1));
        assert_eq!(retry_delay(2), Duration::from_secs(2));
        assert_eq!(retry_delay(3), RTT_INTERVAL);
        assert_eq!(retry_delay(60), RTT_INTERVAL);
        // A wait that is already satisfied, or whose session is gone, costs no
        // nap at all.
        let stopped = AtomicBool::new(true);
        let unknown = AtomicU32::new(0);
        assert!(!sleep_until_next_tick(&stopped, &unknown, RTT_INTERVAL));
        let running = AtomicBool::new(false);
        let known = AtomicU32::new(20);
        assert!(!sleep_until_next_tick(&running, &known, RTT_INTERVAL));
    }

    #[test]
    fn an_outbound_no_tcp_handshake_reaches_has_no_target() {
        // QUIC end to end, and mKCP over UDP: a SYN to those servers would
        // measure a path the tunnel never takes.
        for link in [
            "hysteria2://pass@example.com:443?sni=example.com#q",
            "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pass@example.com:443#q",
        ] {
            let profile = CoreProfile::parse(link).expect("profile parses");
            assert!(RttTarget::new(&profile, None).is_none(), "{link}");
        }
        // The TCP dialects all get one, chained or not.
        for link in [
            format!("vless://{UUID}@example.com:443?type=tcp#direct"),
            format!("vless://{UUID}@example.com:443?type=kcp#udp"),
        ] {
            let profile = CoreProfile::parse(&link).expect("profile parses");
            let target = RttTarget::new(&profile, None);
            assert_eq!(target.is_some(), !link.ends_with("#udp"), "{link}");
        }
    }

    #[test]
    fn a_round_trip_is_never_reported_as_nothing() {
        // The value doubles as "measured": a sub-millisecond answer rounds up
        // to 1 instead of reading as unknown, and 1.4 ms is 2 ms, not 1.
        assert_eq!(millis_ceil(Duration::ZERO), 1);
        assert_eq!(millis_ceil(Duration::from_micros(1)), 1);
        assert_eq!(millis_ceil(Duration::from_micros(1_400)), 2);
        assert_eq!(millis_ceil(Duration::from_millis(63)), 63);
        assert_eq!(millis_ceil(Duration::from_millis(1)), 1);
    }
}
