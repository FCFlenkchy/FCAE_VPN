use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

static TOTAL_RX: AtomicU64 = AtomicU64::new(0);
static TOTAL_TX: AtomicU64 = AtomicU64::new(0);
static WINDOW_RX: AtomicU64 = AtomicU64::new(0);
static WINDOW_TX: AtomicU64 = AtomicU64::new(0);
static RTT_MS: AtomicU64 = AtomicU64::new(0);

struct RateState {
    last: Instant,
    rx_bps: u64,
    tx_bps: u64,
}

static RATE: Mutex<Option<RateState>> = Mutex::new(None);

#[inline]
pub fn add_rx(n: u64) {
    if n == 0 {
        return;
    }
    TOTAL_RX.fetch_add(n, Ordering::Relaxed);
    WINDOW_RX.fetch_add(n, Ordering::Relaxed);
}

#[inline]
pub fn add_tx(n: u64) {
    if n == 0 {
        return;
    }
    TOTAL_TX.fetch_add(n, Ordering::Relaxed);
    WINDOW_TX.fetch_add(n, Ordering::Relaxed);
}

pub fn total_rx() -> u64 {
    TOTAL_RX.load(Ordering::Relaxed)
}

pub fn total_tx() -> u64 {
    TOTAL_TX.load(Ordering::Relaxed)
}

pub fn set_rtt_ms(ms: u64) {
    RTT_MS.store(ms, Ordering::Relaxed);
}

pub fn rtt_ms() -> u64 {
    RTT_MS.load(Ordering::Relaxed)
}

pub fn rates() -> (u64, u64) {
    let now = Instant::now();
    let mut guard = RATE.lock().unwrap_or_else(|e| e.into_inner());
    let win_rx = WINDOW_RX.swap(0, Ordering::Relaxed);
    let win_tx = WINDOW_TX.swap(0, Ordering::Relaxed);

    match guard.as_mut() {
        None => {
            *guard = Some(RateState {
                last: now,
                rx_bps: 0,
                tx_bps: 0,
            });
            (0, 0)
        }
        Some(s) => {
            let dt = now.duration_since(s.last).as_secs_f64().max(0.001);
            let rx_bps = (win_rx as f64 / dt) as u64;
            let tx_bps = (win_tx as f64 / dt) as u64;
            s.rx_bps = (s.rx_bps / 2).saturating_add(rx_bps / 2);
            s.tx_bps = (s.tx_bps / 2).saturating_add(tx_bps / 2);
            s.last = now;
            (s.rx_bps, s.tx_bps)
        }
    }
}

pub fn reset() {
    TOTAL_RX.store(0, Ordering::Relaxed);
    TOTAL_TX.store(0, Ordering::Relaxed);
    WINDOW_RX.store(0, Ordering::Relaxed);
    WINDOW_TX.store(0, Ordering::Relaxed);
    RTT_MS.store(0, Ordering::Relaxed);
    if let Ok(mut g) = RATE.lock() {
        *g = None;
    }
}
