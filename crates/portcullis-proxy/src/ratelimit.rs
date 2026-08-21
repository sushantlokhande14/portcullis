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
//! # The limit value lives in portcullis-policy
//!
//! [`RateLimit`] is defined there, not here, because a policy rule carries one
//! and `portcullis-policy` must not depend on the proxy. This module owns the
//! buckets and the clock; the policy crate owns the configured numbers.
//!
//! # Monotonic time only
//!
//! Refill is computed from [`Instant`], never from wall clock. A clock stepped
//! backwards by NTP would otherwise make the elapsed interval negative and,
//! depending on how that is handled, either stall every limiter or hand out
//! free capacity. Neither is a good failure mode for a control that exists to
//! bound damage.

// Re-exported so `crate::ratelimit::RateLimit` still resolves for callers,
// even though the type is defined in portcullis-policy.
pub use portcullis_policy::RateLimit;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Which budget ran out.
///
/// Carried so the message shown to the model can name the right one. Reporting
/// a session limit as a rule limit sends an operator to the wrong line of the
/// policy file, which is worse than saying nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitScope {
    /// The limit written on the rule that allowed the call.
    Rule,
    /// The session-wide limit.
    Session,
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
        /// Which budget was exhausted.
        scope: LimitScope,
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

    /// Charges one token, refilling first.
    ///
    /// Only called after [`RateLimiter::check_at`] has confirmed every bucket
    /// has capacity, so there is nothing to report back.
    fn spend(&mut self, now: Instant) {
        // saturating_duration_since, not `-`: Instant subtraction panics if the
        // arguments are ever ordered unexpectedly, and a limiter is a poor
        // place to introduce a panic.
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens =
            (self.tokens + elapsed * self.limit.refill_rate()).min(f64::from(self.limit.max));
        self.last_refill = now;

        debug_assert!(
            self.tokens >= 1.0,
            "spend called on a bucket with no capacity"
        );
        self.tokens -= 1.0;
    }
}

/// Buckets for one session.
///
/// Keyed by **rule id**, not by tool name. The budget belongs to the rule that
/// allowed the call, so a rule covering `gh__*` with a limit of five per minute
/// grants five calls per minute across all of those tools together. Wanting a
/// separate budget per tool means writing a narrower rule, which is also the
/// change that makes the intent readable in the policy file.
///
/// Keying by tool name instead would have meant deciding what a limit on a rule
/// covering forty tools even means, and any answer to that is a surprise to
/// somebody. A limit that belongs to the thing it is written on is not.
///
/// A session-wide limit is registered under [`GLOBAL_KEY`] and is checked by
/// every call regardless of which rule allowed it.
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

    /// Registers a limit for a rule id, or for [`GLOBAL_KEY`].
    pub fn set(&mut self, key: impl Into<String>, limit: RateLimit) {
        self.limits.insert(key.into(), limit);
    }

    /// Builds a limiter from every limit a policy declares.
    ///
    /// Limits on `deny` rules are skipped: a deny rule refuses every call, so a
    /// rate on it describes how often something that never happens may happen.
    /// Policy validation warns about the combination, so this only has to avoid
    /// acting on it.
    pub fn from_policy(policy: &portcullis_policy::Policy) -> Self {
        let mut limiter = Self::new();

        for rule in policy.rules() {
            if let Some(limit) = rule.rate_limit {
                if rule.action.is_allow() {
                    limiter.set(rule.id.clone(), limit);
                }
            }
        }

        if let Some(limit) = policy.session_rate_limit() {
            limiter.set(GLOBAL_KEY, limit);
        }

        limiter
    }

    /// Whether any limits are configured.
    pub fn is_empty(&self) -> bool {
        self.limits.is_empty()
    }

    /// Spends a token for a call, checking the rule's limit and the session's.
    ///
    /// Both are charged only when both would allow the call. Charging the
    /// global bucket and then refusing on the tool bucket would consume session
    /// budget for a call that never happened, so a caller retrying a limited
    /// tool would slowly starve every other tool.
    pub fn check(&mut self, key: &str) -> Verdict {
        self.check_at(key, Instant::now())
    }

    fn check_at(&mut self, key: &str, now: Instant) -> Verdict {
        let mut keys: Vec<&str> = Vec::with_capacity(2);
        if self.limits.contains_key(key) {
            keys.push(key);
        }
        if self.limits.contains_key(GLOBAL_KEY) {
            keys.push(GLOBAL_KEY);
        }
        if keys.is_empty() {
            return Verdict::Allowed;
        }

        // Probe every bucket before spending from any of them, tracking which
        // one is the binding constraint so the caller can name it.
        let mut worst: Option<(Duration, LimitScope)> = None;
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
                let seconds = (1.0 - available) / limit.refill_rate();
                let retry = Duration::from_secs_f64(seconds.min(86_400.0));
                let scope = if *key == GLOBAL_KEY {
                    LimitScope::Session
                } else {
                    LimitScope::Rule
                };

                // The longest wait governs, since both must have capacity.
                worst = match worst {
                    Some((current, _)) if current >= retry => worst,
                    _ => Some((retry, scope)),
                };
            }
        }

        if let Some((retry_after, scope)) = worst {
            return Verdict::Limited { retry_after, scope };
        }

        for key in keys {
            if let Some(bucket) = self.buckets.get_mut(key) {
                bucket.spend(now);
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
        let Verdict::Limited { retry_after, .. } = verdict else {
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
        let Verdict::Limited { retry_after, .. } = limiter.check_at("t", start) else {
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
