//! Per-peer failed-auth rate limiter.
//!
//! Defaults from §7.4: 5 failures in 60s → 10 minute lockout.

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct RateLimiterConfig {
    pub threshold: u32,
    pub window: Duration,
    pub lockout: Duration,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            threshold: 5,
            window: Duration::from_secs(60),
            lockout: Duration::from_secs(600),
        }
    }
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Instant { Instant::now() }
}

pub struct RateLimiter<C: Clock = SystemClock> {
    cfg: RateLimiterConfig,
    clock: C,
    state: std::sync::Mutex<HashMap<String, PeerState>>,
}

struct PeerState {
    failures: Vec<Instant>,
    locked_until: Option<Instant>,
}

pub enum CheckResult {
    Allowed,
    Locked { retry_after: Duration },
}

impl RateLimiter<SystemClock> {
    pub fn with_defaults() -> Self {
        Self::new(RateLimiterConfig::default(), SystemClock)
    }
}

impl<C: Clock> RateLimiter<C> {
    pub fn new(cfg: RateLimiterConfig, clock: C) -> Self {
        Self { cfg, clock, state: Default::default() }
    }

    pub fn check(&self, peer: &str) -> CheckResult {
        let now = self.clock.now();
        let mut map = self.state.lock().unwrap();
        let e = map.entry(peer.to_string()).or_insert(PeerState {
            failures: Vec::new(),
            locked_until: None,
        });
        if let Some(until) = e.locked_until {
            if now < until {
                return CheckResult::Locked { retry_after: until - now };
            }
            e.locked_until = None;
            e.failures.clear();
        }
        CheckResult::Allowed
    }

    /// Record a failed auth attempt. Returns `true` if this triggered lockout.
    pub fn record_failure(&self, peer: &str) -> bool {
        let now = self.clock.now();
        let mut map = self.state.lock().unwrap();
        let e = map.entry(peer.to_string()).or_insert(PeerState {
            failures: Vec::new(),
            locked_until: None,
        });
        // drop failures outside the window
        let cutoff = now.checked_sub(self.cfg.window).unwrap_or(now);
        e.failures.retain(|t| *t >= cutoff);
        e.failures.push(now);
        if e.failures.len() as u32 >= self.cfg.threshold {
            e.locked_until = Some(now + self.cfg.lockout);
            true
        } else {
            false
        }
    }

    /// Clear failure history for a peer on successful auth.
    pub fn record_success(&self, peer: &str) {
        self.state.lock().unwrap().remove(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct FakeClock { t: Cell<Instant> }
    impl FakeClock { fn new() -> Self { Self { t: Cell::new(Instant::now()) } } }
    impl FakeClock { fn advance(&self, d: Duration) { self.t.set(self.t.get() + d); } }
    unsafe impl Sync for FakeClock {} // FakeClock used single-threaded in tests
    impl Clock for FakeClock { fn now(&self) -> Instant { self.t.get() } }

    #[test]
    fn allows_under_threshold() {
        let r = RateLimiter::new(RateLimiterConfig::default(), FakeClock::new());
        for _ in 0..4 {
            assert!(matches!(r.check("A"), CheckResult::Allowed));
            assert!(!r.record_failure("A"));
        }
    }

    #[test]
    fn locks_on_threshold() {
        let clock = FakeClock::new();
        let r = RateLimiter::new(RateLimiterConfig::default(), clock);
        for i in 0..4 { assert!(!r.record_failure("A"), "fail {i}"); }
        assert!(r.record_failure("A")); // 5th failure triggers lockout
        assert!(matches!(r.check("A"), CheckResult::Locked { .. }));
    }

    #[test]
    fn success_clears_failures() {
        let r = RateLimiter::new(RateLimiterConfig::default(), FakeClock::new());
        r.record_failure("A");
        r.record_failure("A");
        r.record_success("A");
        for _ in 0..4 { assert!(!r.record_failure("A")); }
    }

    #[test]
    fn failures_expire_after_window() {
        let clock = FakeClock::new();
        let r = RateLimiter::new(
            RateLimiterConfig { threshold: 3, window: Duration::from_secs(10), lockout: Duration::from_secs(60) },
            clock,
        );
        r.record_failure("A");
        r.record_failure("A");
        // advance past window
        r.clock.advance(Duration::from_secs(20));
        assert!(!r.record_failure("A")); // only 1 failure in current window
    }

    #[test]
    fn lockout_clears_after_expiry() {
        let clock = FakeClock::new();
        let r = RateLimiter::new(
            RateLimiterConfig { threshold: 2, window: Duration::from_secs(60), lockout: Duration::from_secs(30) },
            clock,
        );
        r.record_failure("A");
        assert!(r.record_failure("A")); // locked
        r.clock.advance(Duration::from_secs(31));
        assert!(matches!(r.check("A"), CheckResult::Allowed));
    }
}
