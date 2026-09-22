use std::time::Duration;

use aether_engine::stats::Counters;

pub(super) struct RateMeter {
    up: u64,
    down: u64,
    at: Duration,
    rates: (u64, u64),
}

impl RateMeter {
    pub(super) fn new(snapshot: Counters) -> Self {
        Self {
            up: snapshot.up,
            down: snapshot.down,
            at: snapshot.uptime,
            rates: (0, 0),
        }
    }

    pub(super) fn sample(&mut self, snapshot: &Counters) -> (u64, u64) {
        if snapshot.uptime < self.at || snapshot.up < self.up || snapshot.down < self.down {
            self.rates = (0, 0);
        } else {
            let elapsed = snapshot.uptime - self.at;
            if elapsed.is_zero() {
                return self.rates;
            }
            let seconds = elapsed.as_secs_f64();
            self.rates = (
                ((snapshot.down - self.down) as f64 / seconds) as u64,
                ((snapshot.up - self.up) as f64 / seconds) as u64,
            );
        }
        self.up = snapshot.up;
        self.down = snapshot.down;
        self.at = snapshot.uptime;
        self.rates
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(up: u64, down: u64, millis: u64) -> Counters {
        Counters { up, down, uptime: Duration::from_millis(millis) }
    }

    #[test]
    fn rates_use_snapshot_deltas_without_consuming_counters() {
        let mut meter = RateMeter::new(snapshot(100, 200, 0));
        let counters = snapshot(1100, 2200, 500);
        assert_eq!(meter.sample(&counters), (4000, 2000));
        assert_eq!((counters.up, counters.down), (1100, 2200));
        assert_eq!(meter.sample(&counters), (4000, 2000));
        assert_eq!(meter.sample(&snapshot(1100, 2200, 1500)), (0, 0));
    }

    #[test]
    fn resetting_the_engine_cannot_underflow_a_rate() {
        let mut meter = RateMeter::new(snapshot(5000, 7000, 2000));
        assert_eq!(meter.sample(&snapshot(0, 0, 0)), (0, 0));
        assert_eq!(meter.sample(&snapshot(100, 200, 1000)), (200, 100));
    }

    #[test]
    fn independent_readers_do_not_steal_bytes() {
        let mut first = RateMeter::new(snapshot(0, 0, 0));
        let mut second = RateMeter::new(snapshot(0, 0, 0));
        assert_eq!(first.sample(&snapshot(100, 200, 1000)), (200, 100));
        assert_eq!(first.sample(&snapshot(300, 600, 2000)), (400, 200));
        assert_eq!(second.sample(&snapshot(300, 600, 2000)), (300, 150));
    }
}
