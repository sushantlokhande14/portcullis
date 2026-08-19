//! Per-tool and per-session rate limiting.
//!
//! Policy answers "may this call happen". Rate limiting answers "may it happen
//! nine hundred more times in the next minute", which is a different question
//! and the one that matters when an agent gets stuck in a loop or is being
//! driven by injected instructions. A tool that is safe once is not
//! automatically safe a thousand times: `gh__create_issue` is genuinely
//! useful and also the shape of a spam run.
//!
//! # Token bucket, and why the refill is continuous
//!
//! A fixed window ("100 per minute") lets 200 calls land in two seconds across
//! a window boundary, which is exactly the burst it was meant to prevent. A
//! bucket refills continuously, so the limit holds across every interval and
//! not merely the ones that align with a clock.
//!
//! Capacity doubles as the burst allowance: a bucket of 10 refilling at 10 per
//! minute permits a burst of 10 and then one call every six seconds.
//!
//! # Monotonic time only
//!
//! Refill is computed from [`Instant`], never from wall clock. A clock stepped
//! backwards by NTP would otherwise make the elapsed interval negative and,
//! depending on how that is handled, either stall every limiter or hand out
//! free capacity. Neither is a good failure mode for a control that exists to
//! bound damage.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A rate limit as written in configuration.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    /// Maximum calls in a full bucket, which is also the burst allowance.
    pub max: u32,
    /// Seconds over which a full bucket refills.
    pub per_seconds: u64,
}

impl RateLimit {
    /// Builds a limit.
    pub fn new(max: u32, per_seconds: u64) -> Self {
        Self { max, per_seconds }
    }

    /// Tokens restored per second.
    fn refill_rate(self) -> f64 {
        if self.per_seconds == 0 {
            return f64::INFINITY;
        }
        #[expect(clippy::cast_precision_loss, reason = "limits are small integers")]
        let rate = f64::from(self.max) / self.per_seconds as f64;
        rate
    }
}

/// The outcome of asking to spend a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The call may proceed.
    Allowed,
    /// The bucket is empty.
    Limited {
        /// How long until one token is available.
        retry_after: Duration,
    },
}

impl Verdict {
    /// Whether the call may proceed.
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    limit: RateLimit,
    last_refill: Instant,
}

impl Bucket {
    fn new(limit: RateLimit, now: Instant) -> Self {
        Self {
            tokens: f64::from(limit.max),
            limit,
            last_refill: now,
        }
    }

    fn try_spend(&mut self, now: Instant) -> Verdict {
        // saturating_duration_since, not `-`: Instant subtraction panics if the
        // arguments are ever ordered unexpectedly, and a limiter is a poor
        // place to introduce a panic.
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens =
            (self.tokens + elapsed * self.limit.refill_rate()).min(f64::from(self.limit.max));
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return Verdict::Allowed;
        }

        let rate = self.limit.refill_rate();
        let seconds = if rate > 0.0 {
            (1.0 - self.tokens) / rate
        } else {
            f64::MAX
        };
        Verdict::Limited {
            retry_after: Duration::from_secs_f64(seconds.min(86_400.0)),
        }
    }
}

/// Buckets for one session.
///
/// Keyed by published tool name. A per-session global limit can be added by
/// registering a limit under [`GLOBAL_KEY`], which every call also checks.
#[derive(Debug, Default)]
pub struct RateLimiter {
    buckets: HashMap<String, Bucket>,
    limits: HashMap<String, RateLimit>,
}

/// The key under which a session-wide limit is registered.
pub const GLOBAL_KEY: &str = "*";

impl RateLimiter {
    /// An empty limiter that permits everything.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a limit for a published tool name, or for [`GLOBAL_KEY`].
    pub fn set(&mut self, key: impl Into<String>, limit: RateLimit) {
        self.limits.insert(key.into(), limit);
    }

    /// Whether any limits are configured.
    pub fn is_empty(&self) -> bool {
        self.limits.is_empty()
    }

    /// Spends a token for a call, checking the tool limit and the global one.
    ///
    /// Both are charged only when both would allow the call. Charging the
    /// global bucket and then refusing on the tool bucket would consume session
    /// budget for a call that never happened, so a caller retrying a limited
    /// tool would slowly starve every other tool.
    pub fn check(&mut self, tool: &str) -> Verdict {
        self.check_at(tool, Instant::now())
    }

    fn check_at(&mut self, tool: &str, now: Instant) -> Verdict {
        let mut keys: Vec<&str> = Vec::with_capacity(2);
        if self.limits.contains_key(tool) {
            keys.push(tool);
        }
        if self.limits.contains_key(GLOBAL_KEY) {
            keys.push(GLOBAL_KEY);
        }
        if keys.is_empty() {
            return Verdict::Allowed;
        }

        // Probe every bucket before spending from any of them.
        let mut worst: Option<Duration> = None;
        for key in &keys {
            let limit = self.limits[*key];
            let bucket = self
                .buckets
                .entry((*key).to_owned())
                .or_insert_with(|| Bucket::new(limit, now));
            let elapsed = now
                .saturating_duration_since(bucket.last_refill)
                .as_secs_f64();
            let available =
                (bucket.tokens + elapsed * limit.refill_rate()).min(f64::from(limit.max));

            if available < 1.0 {
                let rate = limit.refill_rate();
                let seconds = if rate > 0.0 {
                    (1.0 - available) / rate
                } else {
                    f64::MAX
                };
                let retry = Duration::from_secs_f64(seconds.min(86_400.0));
                worst = Some(worst.map_or(retry, |current: Duration| current.max(retry)));
            }
        }

        if let Some(retry_after) = worst {
            return Verdict::Limited { retry_after };
        }

        for key in keys {
            if let Some(bucket) = self.buckets.get_mut(key) {
                bucket.try_spend(now);
            }
        }
        Verdict::Allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(limits: &[(&str, RateLimit)]) -> RateLimiter {
        let mut limiter = RateLimiter::new();
        for (key, limit) in limits {
            limiter.set(*key, *limit);
        }
        limiter
    }

    #[test]
    fn an_unlimited_tool_is_always_allowed() {
        let mut limiter = RateLimiter::new();
        for _ in 0..1000 {
            assert!(limiter.check("fs__read_file").is_allowed());
        }
        assert!(limiter.is_empty());
    }

    #[test]
    fn a_full_bucket_allows_a_burst_then_refuses() {
        let mut limiter = limiter(&[("gh__create_issue", RateLimit::new(3, 60))]);

        for n in 0..3 {
            assert!(
                limiter.check("gh__create_issue").is_allowed(),
                "call {n} should pass"
            );
        }

        let verdict = limiter.check("gh__create_issue");
        assert!(!verdict.is_allowed());
        let Verdict::Limited { retry_after } = verdict else {
            panic!()
        };
        assert!(
            retry_after.as_secs() <= 20,
            "3 per 60s refills one every 20s: {retry_after:?}"
        );
    }

    #[test]
    fn tokens_come_back_continuously_rather_than_at_a_window_edge() {
        // The property a fixed window does not have: capacity returns smoothly,
        // so 2x the limit cannot land across a boundary.
        let start = Instant::now();
        let mut limiter = limiter(&[("t", RateLimit::new(10, 10))]);

        for _ in 0..10 {
            assert!(limiter.check_at("t", start).is_allowed());
        }
        assert!(!limiter.check_at("t", start).is_allowed());

        // One second later, one token at 1/s.
        let later = start + Duration::from_secs(1);
        assert!(limiter.check_at("t", later).is_allowed());
        assert!(
            !limiter.check_at("t", later).is_allowed(),
            "only one token had accrued"
        );
    }

    #[test]
    fn a_bucket_never_overfills_while_idle() {
        let start = Instant::now();
        let mut limiter = limiter(&[("t", RateLimit::new(5, 5))]);

        // An hour of idling must not bank 3600 calls.
        let much_later = start + Duration::from_secs(3600);
        for _ in 0..5 {
            assert!(limiter.check_at("t", much_later).is_allowed());
        }
        assert!(
            !limiter.check_at("t", much_later).is_allowed(),
            "capacity is the ceiling"
        );
    }

    #[test]
    fn a_session_limit_applies_across_every_tool() {
        let start = Instant::now();
        let mut limiter = limiter(&[(GLOBAL_KEY, RateLimit::new(2, 60))]);

        assert!(limiter.check_at("a", start).is_allowed());
        assert!(limiter.check_at("b", start).is_allowed());
        assert!(
            !limiter.check_at("c", start).is_allowed(),
            "the session budget is shared"
        );
    }

    #[test]
    fn a_tool_refusal_does_not_spend_session_budget() {
        // Otherwise a caller retrying one limited tool slowly starves the rest.
        let start = Instant::now();
        let mut limiter = limiter(&[
            ("hot", RateLimit::new(1, 60)),
            (GLOBAL_KEY, RateLimit::new(10, 60)),
        ]);

        assert!(limiter.check_at("hot", start).is_allowed());
        for _ in 0..20 {
            assert!(!limiter.check_at("hot", start).is_allowed());
        }

        // Nine of the ten session tokens must still be there.
        for n in 0..9 {
            assert!(
                limiter.check_at("cold", start).is_allowed(),
                "session token {n} was consumed"
            );
        }
    }

    #[test]
    fn retry_after_reports_the_longer_of_the_two_waits() {
        let start = Instant::now();
        let mut limiter = limiter(&[
            ("t", RateLimit::new(1, 10)),
            (GLOBAL_KEY, RateLimit::new(1, 100)),
        ]);

        assert!(limiter.check_at("t", start).is_allowed());
        let Verdict::Limited { retry_after } = limiter.check_at("t", start) else {
            panic!("should be limited")
        };
        assert!(
            retry_after.as_secs() >= 90,
            "the slower bucket governs: {retry_after:?}"
        );
    }

    #[test]
    fn a_clock_that_appears_to_move_backwards_does_not_panic() {
        // saturating_duration_since is what keeps this from being a panic in a
        // control whose whole job is to stay up.
        let start = Instant::now();
        let mut limiter = limiter(&[("t", RateLimit::new(1, 10))]);

        assert!(
            limiter
                .check_at("t", start + Duration::from_secs(10))
                .is_allowed()
        );
        assert!(
            !limiter.check_at("t", start).is_allowed(),
            "no free capacity from a step back"
        );
    }
}
