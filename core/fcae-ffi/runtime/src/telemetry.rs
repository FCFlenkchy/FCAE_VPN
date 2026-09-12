//! Telemetry cell and log bus.
//!
//! One process-wide [`TelemetryCell`] holds the authoritative session state.
//! Backends push into it through a cheap cloneable [`TelemetrySink`]; the FFI
//! reads a snapshot and memcpy's it into the caller's struct.
//!
//! Notably, state is now set **explicitly by the backend**. The old FFI
//! inferred it by substring-matching log lines ("socks5 ... listen" ⇒
//! connected), which silently broke whenever a log message was reworded and
//! could not distinguish a first connect from a reconnect.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

use fcae_abi::{FcaeBackend, FcaeLogLevel, FcaeMode, FcaeState};
use parking_lot::Mutex;

use crate::backend::Counters;

/// Immutable view of the session, handed to the FFI layer.
#[derive(Debug, Clone)]
pub struct TelemetrySnapshot {
    pub state: FcaeState,
    pub backend: FcaeBackend,
    pub mode: FcaeMode,
    pub lan_enabled: bool,
    pub counters: Counters,
    pub uptime_secs: u64,
    pub reconnect_count: u32,
    pub connected_peer: String,
    pub lan_ip: String,
    pub status_message: String,
    pub last_error: String,
}

#[derive(Debug)]
struct Inner {
    state: FcaeState,
    backend: FcaeBackend,
    mode: FcaeMode,
    lan_enabled: bool,
    counters: Counters,
    connected_at: Option<Instant>,
    connected_peer: String,
    lan_ip: String,
    status_message: String,
    last_error: String,
}

impl Inner {
    const fn new() -> Self {
        Self {
            state: FcaeState::Disconnected,
            backend: FcaeBackend::Aether,
            mode: FcaeMode::Proxy,
            lan_enabled: false,
            counters: Counters {
                total_rx: 0,
                total_tx: 0,
                rx_bytes_sec: 0,
                tx_bytes_sec: 0,
                rtt_ms: 0,
            },
            connected_at: None,
            connected_peer: String::new(),
            lan_ip: String::new(),
            status_message: String::new(),
            last_error: String::new(),
        }
    }
}

/// Callback invoked on every state transition (used by the FFI to forward to
/// the host's `state_cb`).
type StateHook = Box<dyn Fn(FcaeState) + Send + Sync>;

pub struct TelemetryCell {
    inner: Mutex<Inner>,
    reconnects: AtomicU32,
    state_hook: Mutex<Option<StateHook>>,
}

impl Default for TelemetryCell {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryCell {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::new()),
            reconnects: AtomicU32::new(0),
            state_hook: Mutex::new(None),
        }
    }

    pub fn set_state_hook(&self, hook: Option<StateHook>) {
        *self.state_hook.lock() = hook;
    }

    /// Reset for a new session, preserving the discovered LAN IP.
    pub fn begin_session(&self, backend: FcaeBackend, mode: FcaeMode, lan_enabled: bool) {
        {
            let mut g = self.inner.lock();
            let lan_ip = std::mem::take(&mut g.lan_ip);
            *g = Inner::new();
            g.lan_ip = lan_ip;
            g.backend = backend;
            g.mode = mode;
            g.lan_enabled = lan_enabled;
            g.state = FcaeState::Provisioning;
            g.status_message = "Provisioning…".into();
        }
        self.reconnects.store(0, Ordering::SeqCst);
        self.fire(FcaeState::Provisioning);
    }

    fn fire(&self, state: FcaeState) {
        if let Some(hook) = self.state_hook.lock().as_ref() {
            hook(state);
        }
    }

    pub fn set_state(&self, state: FcaeState, message: String) {
        let changed = {
            let mut g = self.inner.lock();
            // An error is sticky until the next explicit session start or a
            // successful (re)connect: the Android watchdog calls stop() right
            // after an engine error, and the old code clobbered the reason.
            if g.state == FcaeState::Error && !matches!(state, FcaeState::Connected) {
                g.status_message = message;
                false
            } else {
                let changed = g.state != state;
                g.state = state;
                g.status_message = message;
                if state == FcaeState::Connected {
                    if g.connected_at.is_none() {
                        g.connected_at = Some(Instant::now());
                    }
                    g.last_error.clear();
                } else if state == FcaeState::Disconnected {
                    g.connected_at = None;
                }
                changed
            }
        };
        if changed {
            self.fire(state);
        }
    }

    pub fn set_error(&self, message: impl Into<String>) {
        let msg = message.into();
        {
            let mut g = self.inner.lock();
            g.state = FcaeState::Error;
            g.last_error = msg;
            g.status_message = "Error".into();
            g.connected_at = None;
        }
        self.fire(FcaeState::Error);
    }

    pub fn note_reconnect(&self) {
        self.reconnects.fetch_add(1, Ordering::SeqCst);
        let mut g = self.inner.lock();
        g.connected_at = None;
        g.counters.rx_bytes_sec = 0;
        g.counters.tx_bytes_sec = 0;
    }

    pub fn set_peer(&self, peer: impl Into<String>) {
        self.inner.lock().connected_peer = peer.into();
    }

    pub fn set_lan_ip(&self, ip: impl Into<String>) {
        self.inner.lock().lan_ip = ip.into();
    }

    pub fn set_counters(&self, c: Counters) {
        self.inner.lock().counters = c;
    }

    pub fn snapshot(&self) -> TelemetrySnapshot {
        let g = self.inner.lock();
        TelemetrySnapshot {
            state: g.state,
            backend: g.backend,
            mode: g.mode,
            lan_enabled: g.lan_enabled,
            counters: g.counters,
            uptime_secs: g.connected_at.map(|t| t.elapsed().as_secs()).unwrap_or(0),
            reconnect_count: self.reconnects.load(Ordering::SeqCst),
            connected_peer: g.connected_peer.clone(),
            lan_ip: if g.lan_ip.is_empty() {
                "127.0.0.1".to_string()
            } else {
                g.lan_ip.clone()
            },
            status_message: g.status_message.clone(),
            last_error: g.last_error.clone(),
        }
    }
}

/// Cheap, cloneable writer handed to backends.
#[derive(Clone)]
pub struct TelemetrySink {
    cell: Arc<TelemetryCell>,
}

impl TelemetrySink {
    pub fn new(cell: Arc<TelemetryCell>) -> Self {
        Self { cell }
    }

    pub fn set_state(&self, state: FcaeState, message: String) {
        self.cell.set_state(state, message);
    }

    pub fn set_error(&self, message: impl Into<String>) {
        self.cell.set_error(message);
    }

    pub fn set_peer(&self, peer: impl Into<String>) {
        self.cell.set_peer(peer);
    }

    pub fn set_counters(&self, counters: Counters) {
        self.cell.set_counters(counters);
    }

    pub fn cell(&self) -> &Arc<TelemetryCell> {
        &self.cell
    }
}

/// Best-effort LAN address discovery (no packets are actually sent; connect()
/// on UDP only picks a route).
pub fn detect_lan_ip() -> String {
    use std::net::UdpSocket;
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return "127.0.0.1".into();
    };
    if sock.connect("1.1.1.1:80").is_ok() {
        if let Ok(addr) = sock.local_addr() {
            return addr.ip().to_string();
        }
    }
    "127.0.0.1".into()
}

/// Map a `log` level onto the ABI level.
pub fn abi_level(level: log::Level) -> FcaeLogLevel {
    match level {
        log::Level::Error => FcaeLogLevel::Error,
        log::Level::Warn => FcaeLogLevel::Warn,
        log::Level::Info => FcaeLogLevel::Info,
        log::Level::Debug | log::Level::Trace => FcaeLogLevel::Debug,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_is_sticky_until_reconnect() {
        let cell = TelemetryCell::new();
        cell.begin_session(FcaeBackend::Aether, FcaeMode::Proxy, false);
        cell.set_error("boom");
        // A stop() arriving right after the error must not erase it.
        cell.set_state(FcaeState::Disconnected, "Disconnected".into());
        let snap = cell.snapshot();
        assert_eq!(snap.state, FcaeState::Error);
        assert_eq!(snap.last_error, "boom");

        cell.set_state(FcaeState::Connected, "Connected".into());
        let snap = cell.snapshot();
        assert_eq!(snap.state, FcaeState::Connected);
        assert!(snap.last_error.is_empty());
    }

    #[test]
    fn session_reset_keeps_lan_ip() {
        let cell = TelemetryCell::new();
        cell.set_lan_ip("192.168.1.50");
        cell.begin_session(FcaeBackend::Aether, FcaeMode::Tun, true);
        assert_eq!(cell.snapshot().lan_ip, "192.168.1.50");
        assert_eq!(cell.snapshot().state, FcaeState::Provisioning);
    }
}
