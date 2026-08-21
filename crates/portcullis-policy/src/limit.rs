//! Rate limits as they are written in a policy file.
//!
//! The limit *value* lives here rather than in `portcullis-proxy` alongside the
//! bucket that enforces it, because a rule carries one and `portcullis-policy`
//! must not depend on the proxy. The dependency runs one way: the proxy reads
//! these and builds buckets from them.
//!
//! That split also keeps the arithmetic testable without a clock. Everything on
//! this type is a pure function of the configured numbers; the part that needs
//! time lives in the proxy.

use serde::{Deserialize, Serialize};
use std::fmt;

/// How often a call may be made.
///
/// `max` is both the ceiling and the burst allowance: a limit of 10 per 60
/// seconds permits ten calls immediately, then one every six seconds as the
/// bucket refills.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "RawRateLimit")]
pub struct RateLimit {
    /// Maximum calls in a full bucket, which is also the burst allowance.
    pub max: u32,
    /// Seconds over which a full bucket refills.
    pub per_seconds: u64,
}

/// A rate limit that could not be used.
#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    /// `max` was zero.
    #[error("rate limit has max = 0, which would refuse every call; use an action of deny instead")]
    ZeroMax,

    /// `per_seconds` was zero.
    #[error("rate limit has per_seconds = 0, which is not a rate; remove the limit instead")]
    ZeroPeriod,
}

/// The `rate_limit = { ... }` table as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRateLimit {
    max: u32,
    per_seconds: u64,
}

impl TryFrom<RawRateLimit> for RateLimit {
    type Error = RateLimitError;

    fn try_from(raw: RawRateLimit) -> Result<Self, Self::Error> {
        // Both of these are load errors rather than clamped values. A limit of
        // zero reads as "no calls" but would be indistinguishable at runtime
        // from a bucket that has simply not refilled yet, and an operator who
        // meant to forbid the call should say so with `action = "deny"`, where
        // the denial names the rule.
        if raw.max == 0 {
            return Err(RateLimitError::ZeroMax);
        }
        if raw.per_seconds == 0 {
            return Err(RateLimitError::ZeroPeriod);
        }
        Ok(Self {
            max: raw.max,
            per_seconds: raw.per_seconds,
        })
    }
}

impl RateLimit {
    /// Builds a limit, panicking on the degenerate values.
    ///
    /// Only for tests and callers with literal arguments. Anything parsed goes
    /// through `Deserialize`, which reports these as load errors.
    pub fn new(max: u32, per_seconds: u64) -> Self {
        assert!(max > 0, "rate limit max must be positive");
        assert!(per_seconds > 0, "rate limit period must be positive");
        Self { max, per_seconds }
    }

    /// Tokens restored per second.
    pub fn refill_rate(self) -> f64 {
        #[expect(clippy::cast_precision_loss, reason = "limits are small integers")]
        let rate = f64::from(self.max) / self.per_seconds as f64;
        rate
    }
}

impl fmt::Display for RateLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} per {}s", self.max, self.per_seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    struct Wrapper {
        rate_limit: RateLimit,
    }

    fn parse(text: &str) -> Result<RateLimit, toml::de::Error> {
        toml::from_str::<Wrapper>(text).map(|wrapper| wrapper.rate_limit)
    }

    #[test]
    fn parses_a_well_formed_limit() {
        let limit = parse("rate_limit = { max = 5, per_seconds = 60 }").expect("parses");
        assert_eq!(limit, RateLimit::new(5, 60));
        assert_eq!(limit.to_string(), "5 per 60s");
    }

    #[test]
    fn refill_rate_is_calls_per_second() {
        assert!((RateLimit::new(10, 10).refill_rate() - 1.0).abs() < f64::EPSILON);
        assert!((RateLimit::new(30, 60).refill_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn a_zero_max_is_a_load_error_not_a_silent_block() {
        // An operator who means "never" should write action = "deny", where the
        // refusal names the rule. A max of zero would look identical at runtime
        // to a bucket that has not refilled yet.
        let error = parse("rate_limit = { max = 0, per_seconds = 60 }")
            .unwrap_err()
            .to_string();
        assert!(error.contains("max = 0"), "{error}");
        assert!(
            error.contains("deny"),
            "the message should point at the right tool: {error}"
        );
    }

    #[test]
    fn a_zero_period_is_a_load_error() {
        let error = parse("rate_limit = { max = 5, per_seconds = 0 }")
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a rate"), "{error}");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let error = parse("rate_limit = { max = 5, per_seconds = 60, per_minute = 1 }")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("per_minute") || error.contains("unknown field"),
            "{error}"
        );
    }
}
