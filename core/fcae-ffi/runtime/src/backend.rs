//! The backend plugin contract.
//!
//! A *backend* is anything that can establish a censorship-circumventing
//! tunnel and terminate it in a local SOCKS5 endpoint. Aether does this with
//! MASQUE/WireGuard; Psiphon will do it with its own protocol suite. Neither
//! needs to know about TUN, telemetry plumbing, or the C ABI — the supervisor
//! layers those on top of whatever endpoint the backend reports.

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use fcae_abi::FcaeState;

use crate::config::SessionConfig;
use crate::error::Result;
use crate::telemetry::TelemetrySink;

/// Stable identifier for a backend implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendId {
    Aether,
    Psiphon,
}

impl BackendId {
    pub const fn as_str(self) -> &'static str {
        match self {
            BackendId::Aether => "aether",
            BackendId::Psiphon => "psiphon",
        }
    }
}

/// What a backend can do. The supervisor reads this instead of hardcoding
/// per-backend special cases — e.g. Psiphon has no gateway scanner, so the UI
/// should not show scan modes for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Exposes a local SOCKS5 endpoint (required for the TUN bridge).
    pub socks: bool,
    /// Exposes a local HTTP CONNECT endpoint itself.
    pub http_proxy: bool,
    /// Honours `scan_mode` / gateway probing.
    pub gateway_scanning: bool,
    /// Honours split-tunnel routing rules internally.
    pub routing_rules: bool,
    /// Needs elevation even in proxy mode.
    pub requires_privileges: bool,
}

impl Capabilities {
    pub const NONE: Self = Self {
        socks: false,
        http_proxy: false,
        gateway_scanning: false,
        routing_rules: false,
        requires_privileges: false,
    };
}

/// Cooperative cancellation shared between the supervisor and the backend.
///
/// Deliberately a `tokio::sync::Notify` + flag rather than dropping the
/// future: the old code cancelled by dropping the task, which meant cleanup
/// code after an `.await` simply never ran and the FFI had to compensate with
/// duplicate teardown logic.
#[derive(Clone)]
pub struct CancelToken {
    inner: std::sync::Arc<CancelInner>,
}

struct CancelInner {
    cancelled: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelToken {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(CancelInner {
                cancelled: std::sync::atomic::AtomicBool::new(false),
                notify: tokio::sync::Notify::new(),
            }),
        }
    }

    pub fn cancel(&self) {
        self.inner
            .cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // `notify_waiters` would drop the signal if nobody is waiting yet;
        // `notify_one` stores a permit, so a cancel that races the first
        // `.await` is not lost.
        self.inner.notify.notify_one();
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner
            .cancelled
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Resolves once cancellation is requested. Safe against stale permits:
    /// a leftover permit wakes the loop, the flag is re-checked, and we wait
    /// again if it was spurious.
    pub async fn cancelled(&self) {
        loop {
            if self.is_cancelled() {
                return;
            }
            self.inner.notify.notified().await;
        }
    }
}

/// Everything a backend is handed at start time.
pub struct BackendContext {
    pub config: SessionConfig,
    pub telemetry: TelemetrySink,
    pub cancel: CancelToken,
}

impl BackendContext {
    pub fn new(config: SessionConfig, telemetry: TelemetrySink, cancel: CancelToken) -> Self {
        Self {
            config,
            telemetry,
            cancel,
        }
    }

    /// Convenience: publish a state transition with a human-readable message.
    pub fn report(&self, state: FcaeState, message: impl Into<String>) {
        self.telemetry.set_state(state, message.into());
    }
}

/// What a backend actually brought up.
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// Local SOCKS5 address the TUN bridge (and apps) should dial.
    pub socks: Option<SocketAddr>,
    pub http: Option<SocketAddr>,
    /// Public IP of the selected server, excluded from TUN routes to avoid a
    /// routing loop.
    pub peer_ip: Option<String>,
}

impl Endpoints {
    pub const EMPTY: Self = Self {
        socks: None,
        http: None,
        peer_ip: None,
    };
}

/// A running backend. Dropping this must not be the teardown mechanism —
/// call [`BackendHandle::stop`] so shutdown is ordered and observable.
#[async_trait]
pub trait BackendHandle: Send + Sync {
    /// Endpoints available once `start` returned.
    fn endpoints(&self) -> Endpoints;

    /// Resolves when the tunnel terminates on its own (error or clean exit).
    /// The supervisor selects on this to drive reconnect.
    async fn wait(&self) -> Result<()>;

    /// Request shutdown and wait (bounded) for the backend to release its
    /// sockets, threads and OS state.
    async fn stop(&self, timeout: Duration) -> Result<()>;

    /// Live counters, polled by the telemetry aggregator.
    fn counters(&self) -> Counters {
        Counters::default()
    }
}

/// Traffic counters sampled from a backend.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub total_rx: u64,
    pub total_tx: u64,
    pub rx_bytes_sec: u64,
    pub tx_bytes_sec: u64,
    pub rtt_ms: u32,
}

/// A tunnel implementation.
#[async_trait]
pub trait Backend: Send + Sync {
    fn id(&self) -> BackendId;

    fn capabilities(&self) -> Capabilities;

    /// Bring the tunnel up. Must return only once the endpoints in the
    /// returned handle are actually accepting connections, or an error.
    async fn start(&self, cx: BackendContext) -> Result<Box<dyn BackendHandle>>;

    /// Best-effort global cleanup for state this backend may have left behind
    /// after a crash or a hard kill in a *previous* process lifetime.
    /// Whether a start would actually work, without attempting one.
    ///
    /// A registered backend may still be a compile-time stub; returning the
    /// reason here lets the UI grey the entry out up front instead of after
    /// the user hits Connect.
    fn availability(&self) -> std::result::Result<(), String> {
        Ok(())
    }

    fn recover_stale_state(&self) {}
}
