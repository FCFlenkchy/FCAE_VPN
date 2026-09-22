use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

static PEER: Mutex<Option<SocketAddr>> = Mutex::new(None);
static RTT_MS: AtomicU64 = AtomicU64::new(0);

pub fn reset() {
    *PEER.lock().unwrap_or_else(|e| e.into_inner()) = None;
    RTT_MS.store(0, Ordering::Relaxed);
}

pub fn set_rtt_ms(ms: u64) {
    RTT_MS.store(ms, Ordering::Relaxed);
}

pub fn rtt_ms() -> u64 {
    RTT_MS.load(Ordering::Relaxed)
}

pub fn peer() -> Option<SocketAddr> {
    *PEER.lock().unwrap_or_else(|e| e.into_inner())
}

pub struct PeerGuard;

impl Drop for PeerGuard {
    fn drop(&mut self) {
        *PEER.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

pub fn connected_peer(peer: SocketAddr) -> PeerGuard {
    *PEER.lock().unwrap_or_else(|e| e.into_inner()) = Some(peer);
    PeerGuard
}
