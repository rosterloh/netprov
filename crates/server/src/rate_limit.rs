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
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Global tier threshold is this multiple of the per-peer threshold.
const GLOBAL_THRESHOLD_MULTIPLIER: u32 = 5;

/// Backstop cap on the number of tracked peer entries.
const MAX_PEER_ENTRIES: usize = 1024;

pub struct RateLimiter<C: Clock = SystemClock> {
    cfg: RateLimiterConfig,
    global_cfg: RateLimiterConfig,
    clock: C,
    state: std::sync::Mutex<HashMap<String, PeerState>>,
    global: std::sync::Mutex<PeerState>,
}

#[derive(Default)]
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
    /// Global tier config defaults to the same window/lockout as the per-peer
    /// tier, with a threshold `GLOBAL_THRESHOLD_MULTIPLIER` times higher.
    pub fn new(cfg: RateLimiterConfig, clock: C) -> Self {
        let global_cfg = RateLimiterConfig {
            threshold: cfg.threshold.saturating_mul(GLOBAL_THRESHOLD_MULTIPLIER),
            window: cfg.window,
            lockout: cfg.lockout,
        };
        Self::new_with_global(cfg, global_cfg, clock)
    }

    /// Like `new`, but with an explicit global-tier config (e.g. for tests).
    pub fn new_with_global(
        cfg: RateLimiterConfig,
        global_cfg: RateLimiterConfig,
        clock: C,
    ) -> Self {
        Self {
            cfg,
            global_cfg,
            clock,
            state: Default::default(),
            global: std::sync::Mutex::new(PeerState::default()),
        }
    }

    /// Read-only: never inserts a map entry. An unseen peer is simply "not
    /// locked out" — entries are only created by `record_failure`, so `check`
    /// alone can't be used to grow the peer map unbounded.
    pub fn check(&self, peer: &str) -> CheckResult {
        let now = self.clock.now();

        let global = self.global.lock().unwrap();
        if let Some(until) = global.locked_until.filter(|&u| now < u) {
            return CheckResult::Locked {
                retry_after: until - now,
            };
        }
        drop(global);

        let map = self.state.lock().unwrap();
        if let Some(until) = map
            .get(peer)
            .and_then(|e| e.locked_until)
            .filter(|&u| now < u)
        {
            return CheckResult::Locked {
                retry_after: until - now,
            };
        }
        CheckResult::Allowed
    }

    /// Record a failed auth attempt. Returns `true` if this triggered lockout
    /// on either the per-peer or global tier.
    pub fn record_failure(&self, peer: &str) -> bool {
        let now = self.clock.now();

        let peer_locked = {
            let mut map = self.state.lock().unwrap();
            let e = map.entry(peer.to_string()).or_default();
            let cutoff = now.checked_sub(self.cfg.window).unwrap_or(now);
            e.failures.retain(|t| *t >= cutoff);
            e.failures.push(now);
            if e.failures.len() as u32 >= self.cfg.threshold {
                e.locked_until = Some(now + self.cfg.lockout);
                true
            } else {
                false
            }
        };

        self.prune_and_cap(now);

        let global_locked = {
            let mut g = self.global.lock().unwrap();
            let cutoff = now.checked_sub(self.global_cfg.window).unwrap_or(now);
            g.failures.retain(|t| *t >= cutoff);
            g.failures.push(now);
            if g.failures.len() as u32 >= self.global_cfg.threshold {
                g.locked_until = Some(now + self.global_cfg.lockout);
                true
            } else {
                false
            }
        };

        peer_locked || global_locked
    }

    /// Clear failure history for a peer on successful auth.
    pub fn record_success(&self, peer: &str) {
        self.state.lock().unwrap().remove(peer);
    }

    /// Drop stale entries (expired lockout, no failures within the window),
    /// then enforce `MAX_PEER_ENTRIES` by evicting the least-recently-active
    /// entries as a backstop against unbounded growth from rotating peer ids.
    fn prune_and_cap(&self, now: Instant) {
        let mut map = self.state.lock().unwrap();
        let cutoff = now.checked_sub(self.cfg.window).unwrap_or(now);
        map.retain(|_, e| {
            if e.locked_until.is_some_and(|until| now >= until) {
                e.locked_until = None;
                e.failures.clear();
            }
            e.failures.retain(|t| *t >= cutoff);
            e.locked_until.is_some() || !e.failures.is_empty()
        });

        if map.len() > MAX_PEER_ENTRIES {
            let mut by_activity: Vec<(String, Instant)> = map
                .iter()
                .map(|(k, e)| {
                    let last = e.failures.last().copied().unwrap_or(cutoff);
                    (k.clone(), last)
                })
                .collect();
            by_activity.sort_by_key(|(_, t)| *t);
            let excess = map.len() - MAX_PEER_ENTRIES;
            for (k, _) in by_activity.into_iter().take(excess) {
                map.remove(&k);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct FakeClock {
        t: Cell<Instant>,
    }
    impl FakeClock {
        fn new() -> Self {
            Self {
                t: Cell::new(Instant::now()),
            }
        }
    }
    impl FakeClock {
        fn advance(&self, d: Duration) {
            self.t.set(self.t.get() + d);
        }
    }
    unsafe impl Sync for FakeClock {} // FakeClock used single-threaded in tests
    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.t.get()
        }
    }

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
        for i in 0..4 {
            assert!(!r.record_failure("A"), "fail {i}");
        }
        assert!(r.record_failure("A")); // 5th failure triggers lockout
        assert!(matches!(r.check("A"), CheckResult::Locked { .. }));
    }

    #[test]
    fn success_clears_failures() {
        let r = RateLimiter::new(RateLimiterConfig::default(), FakeClock::new());
        r.record_failure("A");
        r.record_failure("A");
        r.record_success("A");
        for _ in 0..4 {
            assert!(!r.record_failure("A"));
        }
    }

    #[test]
    fn failures_expire_after_window() {
        let clock = FakeClock::new();
        let r = RateLimiter::new(
            RateLimiterConfig {
                threshold: 3,
                window: Duration::from_secs(10),
                lockout: Duration::from_secs(60),
            },
            clock,
        );
        r.record_failure("A");
        r.record_failure("A");
        // advance past window
        r.clock.advance(Duration::from_secs(20));
        assert!(!r.record_failure("A")); // only 1 failure in current window
    }

    #[test]
    fn rotating_peer_ids_hit_global_lockout() {
        let clock = FakeClock::new();
        // default global threshold = 5 * per-peer threshold (5) = 25
        let r = RateLimiter::new(RateLimiterConfig::default(), clock);
        for i in 0..24 {
            let peer = format!("peer-{i}");
            assert!(
                !r.record_failure(&peer),
                "peer {i} alone should stay well under the per-peer threshold"
            );
        }
        // the 25th distinct peer failing once trips the global tier even
        // though no single peer came close to the per-peer threshold.
        assert!(r.record_failure("peer-24"));
        assert!(matches!(r.check("peer-24"), CheckResult::Locked { .. }));
        // a brand new, never-before-seen peer id is also locked out.
        assert!(matches!(
            r.check("never-seen-before"),
            CheckResult::Locked { .. }
        ));
    }

    #[test]
    fn prunes_expired_entries() {
        let clock = FakeClock::new();
        let r = RateLimiter::new(
            RateLimiterConfig {
                threshold: 100, // high enough that nothing locks out here
                window: Duration::from_secs(10),
                lockout: Duration::from_secs(30),
            },
            clock,
        );
        for i in 0..10 {
            r.record_failure(&format!("peer-{i}"));
        }
        assert_eq!(r.state.lock().unwrap().len(), 10);

        // advance past the failure window; the next record_failure call
        // triggers pruning, which should drop the now-empty stale entries.
        r.clock.advance(Duration::from_secs(20));
        r.record_failure("trigger");
        assert_eq!(r.state.lock().unwrap().len(), 1);
        assert!(r.state.lock().unwrap().contains_key("trigger"));
    }

    #[test]
    fn caps_map_size_by_evicting_oldest() {
        let clock = FakeClock::new();
        let r = RateLimiter::new(
            RateLimiterConfig {
                threshold: 100_000, // never lock out; only exercise the cap
                window: Duration::from_secs(3600),
                lockout: Duration::from_secs(3600),
            },
            clock,
        );
        let total = MAX_PEER_ENTRIES + 10;
        for i in 0..total {
            r.record_failure(&format!("peer-{i}"));
            r.clock.advance(Duration::from_millis(1));
        }
        let map = r.state.lock().unwrap();
        assert_eq!(map.len(), MAX_PEER_ENTRIES);
        assert!(
            !map.contains_key("peer-0"),
            "oldest entry should be evicted"
        );
        assert!(map.contains_key(&format!("peer-{}", total - 1)));
    }

    #[test]
    fn check_alone_never_inserts_map_entries() {
        let clock = FakeClock::new();
        let r = RateLimiter::new(RateLimiterConfig::default(), clock);
        // Well beyond MAX_PEER_ENTRIES distinct, never-recording peer ids.
        for i in 0..(MAX_PEER_ENTRIES * 2) {
            assert!(matches!(
                r.check(&format!("peer-{i}")),
                CheckResult::Allowed
            ));
        }
        assert_eq!(
            r.state.lock().unwrap().len(),
            0,
            "check() must not insert entries into the peer map"
        );
    }

    #[test]
    fn lockout_clears_after_expiry() {
        let clock = FakeClock::new();
        let r = RateLimiter::new(
            RateLimiterConfig {
                threshold: 2,
                window: Duration::from_secs(60),
                lockout: Duration::from_secs(30),
            },
            clock,
        );
        r.record_failure("A");
        assert!(r.record_failure("A")); // locked
        r.clock.advance(Duration::from_secs(31));
        assert!(matches!(r.check("A"), CheckResult::Allowed));
    }
}
