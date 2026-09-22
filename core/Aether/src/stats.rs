use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static UP: AtomicU64 = AtomicU64::new(0);
static DOWN: AtomicU64 = AtomicU64::new(0);
static ENABLED: AtomicBool = AtomicBool::new(false);
static START: Mutex<Option<Instant>> = Mutex::new(None);

const DEFAULT_REPORT_SECS: u64 = 60;

pub struct Counters {
    pub up: u64,
    pub down: u64,
    pub uptime: Duration,
}

pub fn init() {
    let on = std::env::var("AETHER_STATS")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);

    ENABLED.store(on, Ordering::Relaxed);
    START
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(Instant::now);
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

#[inline]
pub fn add_up(bytes: usize) {
    UP.fetch_add(bytes as u64, Ordering::Relaxed);
}

#[inline]
pub fn add_down(bytes: usize) {
    DOWN.fetch_add(bytes as u64, Ordering::Relaxed);
}

pub fn reset() {
    UP.store(0, Ordering::Relaxed);
    DOWN.store(0, Ordering::Relaxed);
    *START.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
}

pub fn snapshot() -> Counters {
    Counters {
        up: UP.load(Ordering::Relaxed),
        down: DOWN.load(Ordering::Relaxed),
        uptime: START
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(Instant::elapsed)
            .unwrap_or_default(),
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn format_uptime(uptime: Duration) -> String {
    let total = uptime.as_secs();
    let (days, hours, minutes, seconds) = (
        total / 86_400,
        (total % 86_400) / 3600,
        (total % 3600) / 60,
        total % 60,
    );

    if days > 0 {
        format!("{days}d {hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    }
}

fn report_interval() -> Duration {
    let secs = std::env::var("AETHER_STATS_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(DEFAULT_REPORT_SECS);
    Duration::from_secs(secs)
}

pub(crate) fn spawn_reporter() -> crate::TaskGuard {
    let mut tasks = crate::TaskGuard::new();
    if !enabled() {
        return tasks;
    }

    let every = report_interval();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = crate::shutdown::cancelled() => return,
                _ = tokio::time::sleep(every) => {},
            }
            let counters = snapshot();
            log::info!(
                "[=] up {} down {} uptime {}",
                format_bytes(counters.up),
                format_bytes(counters.down),
                format_uptime(counters.uptime)
            );
        }
    });
    tasks.push(task.abort_handle());
    tasks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_counts_stay_in_plain_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn larger_counts_climb_the_units() {
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(5 * 1024 * 1024 * 1024), "5.0 GiB");
    }

    #[test]
    fn uptime_grows_a_day_field_only_when_it_needs_one() {
        assert_eq!(format_uptime(Duration::from_secs(0)), "00:00:00");
        assert_eq!(format_uptime(Duration::from_secs(3661)), "01:01:01");
        assert_eq!(format_uptime(Duration::from_secs(90_061)), "1d 01:01:01");
    }

}
