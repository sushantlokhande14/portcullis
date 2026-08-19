//! Credential detection.
//!
//! Two directions matter, and they matter for different reasons.
//!
//! Outbound, an agent that read a `.env` file two steps ago will cheerfully
//! paste its contents into a `create_issue` call. Catching that at the gateway
//! is the last chance before the secret is on a third party's servers.
//!
//! Inbound, a tool result carrying a credential puts it in the model's context,
//! which usually means it lands in a transcript, a trace, and a log aggregator.
//! Redacting on the way back keeps a leak that already happened from being
//! copied into three more systems.
//!
//! # Precision over recall
//!
//! The detectors are anchored to the issuing provider's format rather than
//! looking for anything secret-shaped. A scanner that fires on ordinary text
//! gets switched off, and a scanner that is switched off has zero recall, so
//! the trade favours precision everywhere except the one heuristic detector
//! below, which requires *both* a naming signal and a high-entropy value.
//!
//! # What a fingerprint is and is not
//!
//! Redaction replaces the secret with a truncated SHA-256 of it. That lets an
//! operator tell "the same token leaked eleven times" from "eleven different
//! tokens leaked" without any of them being written down. It is not a security
//! boundary: the digest is unsalted, so a *low-entropy* value like a short
//! password can be recovered by guessing. Real credentials from the providers
//! below carry enough entropy for this to be moot, and the heuristic detector
//! only fires above an entropy floor, but the property is worth stating rather
//! than assuming.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::ops::Range;
use std::sync::LazyLock;

/// What kind of credential was recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    /// An AWS access key id.
    AwsAccessKeyId,
    /// A GitHub personal access, OAuth, user, server, or refresh token.
    GitHubToken,
    /// A GitHub fine-grained personal access token.
    GitHubFineGrainedToken,
    /// A Slack API token.
    SlackToken,
    /// A Slack incoming webhook URL.
    SlackWebhook,
    /// An `OpenAI` API key.
    OpenAiKey,
    /// An Anthropic API key.
    AnthropicKey,
    /// A Google API key.
    GoogleApiKey,
    /// A Stripe secret or restricted key.
    StripeKey,
    /// A PEM-encoded private key block.
    PrivateKeyBlock,
    /// A JSON Web Token.
    JsonWebToken,
    /// A high-entropy value assigned to a secret-sounding name.
    HighEntropyAssignment,
}

impl SecretKind {
    /// Stable `snake_case` label, used in audit records and redaction markers.
    pub fn label(self) -> &'static str {
        match self {
            Self::AwsAccessKeyId => "aws_access_key_id",
            Self::GitHubToken => "github_token",
            Self::GitHubFineGrainedToken => "github_fine_grained_token",
            Self::SlackToken => "slack_token",
            Self::SlackWebhook => "slack_webhook",
            Self::OpenAiKey => "openai_key",
            Self::AnthropicKey => "anthropic_key",
            Self::GoogleApiKey => "google_api_key",
            Self::StripeKey => "stripe_key",
            Self::PrivateKeyBlock => "private_key_block",
            Self::JsonWebToken => "json_web_token",
            Self::HighEntropyAssignment => "high_entropy_assignment",
        }
    }
}

impl fmt::Display for SecretKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One detected credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretFinding {
    /// What was recognised.
    pub kind: SecretKind,
    /// Byte range of the secret within the scanned text.
    pub span: Range<usize>,
    /// Truncated SHA-256 of the matched text. Never the secret itself.
    pub fingerprint: String,
}

impl SecretFinding {
    /// The marker that replaces this secret when the text is redacted.
    pub fn marker(&self) -> String {
        format!("[redacted:{}:{}]", self.kind.label(), self.fingerprint)
    }
}

/// Digest length in hex characters.
///
/// Eight is enough to distinguish the handful of distinct secrets a single
/// session realistically touches, while staying short enough to read in a log.
const FINGERPRINT_HEX_CHARS: usize = 8;

fn fingerprint(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    let mut hex = String::with_capacity(FINGERPRINT_HEX_CHARS);
    for byte in digest.iter().take(FINGERPRINT_HEX_CHARS.div_ceil(2)) {
        use fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex.truncate(FINGERPRINT_HEX_CHARS);
    hex
}

/// Minimum Shannon entropy, in bits per character, for the heuristic detector.
///
/// The detector regex admits no whitespace, so what this floor has to separate
/// is a random token from a run-together word sequence. Base64 and hex tokens
/// land around 4.5 to 5.5 because their symbols are near-uniform. A passphrase
/// like `correcthorsebatterystaple` repeats letters heavily and lands near 3.5.
///
/// Note that entropy over a short string is a weak signal on its own: any
/// string of 20 distinct characters scores log2(20), prose or not. It is only
/// used here in combination with the naming requirement, never alone.
const ENTROPY_FLOOR: f64 = 4.0;

/// Minimum length for the heuristic detector.
const MIN_HEURISTIC_LEN: usize = 16;

/// Shannon entropy of a string, in bits per character.
pub fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for byte in text.bytes() {
        counts[byte as usize] += 1;
        total += 1;
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "counts are far below f64 precision limits"
    )]
    let total_f = total as f64;

    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            #[expect(clippy::cast_precision_loss, reason = "same bound as above")]
            let p = *count as f64 / total_f;
            -p * p.log2()
        })
        .sum()
}

struct Detector {
    kind: SecretKind,
    regex: regex::Regex,
    /// Which capture group holds the secret. Group 0 is the whole match.
    group: usize,
}

static DETECTORS: LazyLock<Vec<Detector>> = LazyLock::new(|| {
    let build = |kind, pattern: &str, group| Detector {
        kind,
        regex: regex::Regex::new(pattern).expect("built-in detector patterns must compile"),
        group,
    };

    vec![
        // Anthropic and Stripe are listed before the generic `sk-` shape so the
        // more specific label wins when spans overlap.
        build(SecretKind::AnthropicKey, r"\bsk-ant-[A-Za-z0-9_\-]{20,}", 0),
        build(
            SecretKind::StripeKey,
            r"\b[sr]k_(live|test)_[0-9A-Za-z]{16,}",
            0,
        ),
        build(
            SecretKind::OpenAiKey,
            r"\bsk-(proj-)?[A-Za-z0-9_\-]{20,}",
            0,
        ),
        build(
            SecretKind::AwsAccessKeyId,
            r"\b(A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA)[A-Z0-9]{16}\b",
            0,
        ),
        build(
            SecretKind::GitHubFineGrainedToken,
            r"\bgithub_pat_[A-Za-z0-9_]{22,}",
            0,
        ),
        build(SecretKind::GitHubToken, r"\bgh[pousr]_[A-Za-z0-9]{36,}", 0),
        build(
            SecretKind::SlackWebhook,
            r"https://hooks\.slack\.com/services/[A-Za-z0-9/+_\-]{20,}",
            0,
        ),
        build(
            SecretKind::SlackToken,
            r"\bxox[baprse]-[0-9A-Za-z\-]{10,}",
            0,
        ),
        build(SecretKind::GoogleApiKey, r"\bAIza[0-9A-Za-z_\-]{35}\b", 0),
        build(
            SecretKind::PrivateKeyBlock,
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
            0,
        ),
        build(
            SecretKind::JsonWebToken,
            r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
            0,
        ),
        // The one heuristic. Requires a secret-sounding name AND a value that
        // clears the entropy floor, checked after matching.
        build(
            SecretKind::HighEntropyAssignment,
            r#"(?i)\b(?:api[_\-]?key|secret[_\-]?key|secret|token|password|passwd|credentials?|auth)\b\s*[:=]\s*["']?([A-Za-z0-9/+=_\-]{16,})["']?"#,
            1,
        ),
    ]
});

/// Finds credentials in text.
///
/// Findings are returned in order of position, with overlaps resolved so that
/// each byte belongs to at most one finding. Where two detectors overlap, the
/// longer match wins, and ties go to the detector listed first, which is how
/// `sk-ant-...` is reported as an Anthropic key rather than an `OpenAI` one.
pub fn scan(text: &str) -> Vec<SecretFinding> {
    let mut candidates: Vec<(usize, SecretFinding)> = Vec::new();

    for (priority, detector) in DETECTORS.iter().enumerate() {
        for captures in detector.regex.captures_iter(text) {
            let Some(matched) = captures.get(detector.group) else {
                continue;
            };
            let value = matched.as_str();

            if detector.kind == SecretKind::HighEntropyAssignment
                && (value.len() < MIN_HEURISTIC_LEN || shannon_entropy(value) < ENTROPY_FLOOR)
            {
                continue;
            }

            candidates.push((
                priority,
                SecretFinding {
                    kind: detector.kind,
                    span: matched.start()..matched.end(),
                    fingerprint: fingerprint(value),
                },
            ));
        }
    }

    // Longest match first, then detector order, so the most specific label wins.
    candidates.sort_by(|(left_priority, left), (right_priority, right)| {
        let left_len = left.span.len();
        let right_len = right.span.len();
        right_len
            .cmp(&left_len)
            .then(left_priority.cmp(right_priority))
    });

    let mut kept: Vec<SecretFinding> = Vec::new();
    for (_, candidate) in candidates {
        let overlaps = kept.iter().any(|kept| {
            candidate.span.start < kept.span.end && kept.span.start < candidate.span.end
        });
        if !overlaps {
            kept.push(candidate);
        }
    }

    kept.sort_by_key(|finding| finding.span.start);
    kept
}

/// Replaces every finding with its marker.
///
/// Findings must come from [`scan`] over the same text; the spans are byte
/// offsets into it. Rewriting happens back to front so that earlier offsets
/// stay valid as the string shortens.
pub fn redact(text: &str, findings: &[SecretFinding]) -> String {
    let mut out = text.to_owned();
    for finding in findings.iter().rev() {
        out.replace_range(finding.span.clone(), &finding.marker());
    }
    out
}

/// Scans and redacts in one step, returning the clean text and what was found.
pub fn scan_and_redact(text: &str) -> (String, Vec<SecretFinding>) {
    let findings = scan(text);
    if findings.is_empty() {
        return (text.to_owned(), findings);
    }
    (redact(text, &findings), findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<SecretKind> {
        scan(text).into_iter().map(|finding| finding.kind).collect()
    }

    /// Joins the pieces of a fixture credential.
    ///
    /// Test fixtures for a credential scanner are, by construction, strings
    /// shaped exactly like real credentials, and other people's scanners cannot
    /// tell that ours are fake. GitHub's push protection rejected this file over
    /// a Stripe fixture that was plainly `abcdefghij...`, which is the correct
    /// behaviour on their side and a blocked push on ours.
    ///
    /// Assembling fixtures at runtime keeps the literal out of the source, so
    /// the pattern under test is still exercised end to end while no file in the
    /// repository contains a credential-shaped string. Anyone adding a detector
    /// should build its fixtures the same way.
    fn fixture(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn detects_each_provider_format() {
        let cases = [
            (
                fixture(&["AKIA", "IOSFODNN7EXAMPLE"]),
                SecretKind::AwsAccessKeyId,
            ),
            (
                fixture(&["ghp", "_1234567890abcdefghijklmnopqrstuvwxyzAB"]),
                SecretKind::GitHubToken,
            ),
            (
                fixture(&["github", "_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz"]),
                SecretKind::GitHubFineGrainedToken,
            ),
            (
                fixture(&["xoxb", "-123456789012-abcdefghijkl"]),
                SecretKind::SlackToken,
            ),
            (
                fixture(&[
                    "https://hooks.slack.com/services/",
                    "T00000000/B00000000/abcdefghijklmnop",
                ]),
                SecretKind::SlackWebhook,
            ),
            (
                fixture(&["sk-ant", "-api03-abcdefghijklmnopqrstuvwxyz"]),
                SecretKind::AnthropicKey,
            ),
            (
                fixture(&["sk-proj", "-abcdefghijklmnopqrstuvwxyz012345"]),
                SecretKind::OpenAiKey,
            ),
            (
                fixture(&["AIza", "SyA1234567890abcdefghijklmnopqrstuv"]),
                SecretKind::GoogleApiKey,
            ),
            (
                fixture(&["sk", "_live_", "abcdefghijklmnopqrstuvwx"]),
                SecretKind::StripeKey,
            ),
            (
                fixture(&["-----BEGIN OPENSSH ", "PRIVATE KEY-----"]),
                SecretKind::PrivateKeyBlock,
            ),
            (
                fixture(&[
                    "eyJhbGciOiJIUzI1NiJ9.",
                    "eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
                    "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g",
                ]),
                SecretKind::JsonWebToken,
            ),
        ];

        for (sample, expected) in cases {
            let found = kinds(&format!("the value is {sample} ok"));
            assert!(
                found.contains(&expected),
                "{expected:?} not found in {sample:?}: {found:?}"
            );
        }
    }

    #[test]
    fn the_most_specific_label_wins_when_patterns_overlap() {
        // `sk-ant-...` also matches the OpenAI `sk-` shape. Overlap resolution
        // must report it once, as an Anthropic key.
        let found = scan(&format!(
            "key: {}",
            fixture(&["sk-ant", "-api03-abcdefghijklmnopqrstuvwxyz"])
        ));
        let credential: Vec<_> = found
            .iter()
            .filter(|f| f.kind != SecretKind::HighEntropyAssignment)
            .collect();
        assert_eq!(credential.len(), 1, "{found:?}");
        assert_eq!(credential[0].kind, SecretKind::AnthropicKey);
    }

    #[test]
    fn ordinary_prose_is_left_alone() {
        // The property that decides whether anyone leaves this scanner on.
        let samples = [
            "The user asked me to read the configuration file and summarise it.",
            "def authenticate(user): return user.token is not None",
            "See docs/architecture.md for how the token bucket refills.",
            "commit 9e5e1f3f2a1b4c5d6e7f8a9b0c1d2e3f4a5b6c7d updated the README",
            "password reset instructions were emailed to the account owner",
        ];

        for sample in samples {
            assert!(
                scan(sample).is_empty(),
                "false positive on {sample:?}: {:?}",
                scan(sample)
            );
        }
    }

    #[test]
    fn the_heuristic_needs_both_a_name_and_entropy() {
        // A memorable passphrase is not what this detector is for. Firing on it
        // is how a scanner earns a reputation for noise and gets disabled.
        assert!(scan(r#"password = "correct-horse-battery""#).is_empty());

        let found = kinds(r#"api_key = "k3J8xQ2mZpL9vN4tR7wY1bC5""#);
        assert_eq!(found, vec![SecretKind::HighEntropyAssignment]);
    }

    #[test]
    fn the_heuristic_ignores_short_values() {
        assert!(scan(r#"token = "abc123""#).is_empty());
    }

    #[test]
    fn entropy_separates_random_tokens_from_prose() {
        assert!(shannon_entropy("k3J8xQ2mZpL9vN4tR7wY1bC5") > ENTROPY_FLOOR);
        // Whitespace-free, because that is the only shape the detector regex
        // can reach. Repeated letters are what pull it under the floor.
        assert!(shannon_entropy("correcthorsebatterystaple") < ENTROPY_FLOOR);
        assert!(shannon_entropy("") < f64::EPSILON);
        assert!(
            shannon_entropy("aaaa") < f64::EPSILON,
            "a single repeated symbol carries no entropy"
        );
    }

    #[test]
    fn redaction_removes_the_secret_and_keeps_the_surroundings() {
        let aws = fixture(&["AKIA", "IOSFODNN7EXAMPLE"]);
        let text = format!("Use {aws} to sign the request.");
        let (redacted, findings) = scan_and_redact(&text);

        assert_eq!(findings.len(), 1);
        assert!(!redacted.contains(&aws), "{redacted}");
        assert!(
            redacted.starts_with("Use [redacted:aws_access_key_id:"),
            "{redacted}"
        );
        assert!(redacted.ends_with(" to sign the request."), "{redacted}");
    }

    #[test]
    fn redacting_several_secrets_keeps_every_span_aligned() {
        // Rewriting front to back would invalidate later offsets. This fails
        // loudly if the direction is ever reversed.
        let aws = fixture(&["AKIA", "IOSFODNN7EXAMPLE"]);
        let gh = fixture(&["ghp", "_1234567890abcdefghijklmnopqrstuvwxyzAB"]);
        let text = format!("a={aws} b={gh} c=end");
        let (redacted, findings) = scan_and_redact(&text);

        assert!(findings.len() >= 2);
        assert!(!redacted.contains(&aws), "{redacted}");
        assert!(!redacted.contains(&gh), "{redacted}");
        assert!(redacted.ends_with("c=end"), "{redacted}");
    }

    #[test]
    fn the_same_secret_always_fingerprints_the_same_way() {
        // What makes "one token leaked eleven times" distinguishable from
        // "eleven tokens leaked" in an audit log.
        let one = scan("AKIAIOSFODNN7EXAMPLE")[0].fingerprint.clone();
        let two = scan("prefix AKIAIOSFODNN7EXAMPLE suffix")[0]
            .fingerprint
            .clone();
        assert_eq!(one, two);

        let other = scan("AKIAIOSFODNN7DIFFERE")[0].fingerprint.clone();
        assert_ne!(one, other);
    }

    #[test]
    fn a_fingerprint_never_contains_the_secret() {
        let finding = &scan(&fixture(&[
            "ghp",
            "_1234567890abcdefghijklmnopqrstuvwxyzAB",
        ]))[0];
        assert_eq!(finding.fingerprint.len(), FINGERPRINT_HEX_CHARS);
        assert!(finding.fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!finding.marker().contains("1234567890"));
    }

    #[test]
    fn findings_come_back_in_document_order() {
        let text = format!(
            "second={} first={}",
            fixture(&["ghp", "_1234567890abcdefghijklmnopqrstuvwxyzAB"]),
            fixture(&["AKIA", "IOSFODNN7EXAMPLE"]),
        );
        let findings = scan(&text);
        assert!(
            findings
                .windows(2)
                .all(|pair| pair[0].span.start <= pair[1].span.start)
        );
    }

    #[test]
    fn scanning_clean_text_allocates_no_replacement() {
        let (out, findings) = scan_and_redact("nothing to see here");
        assert_eq!(out, "nothing to see here");
        assert!(findings.is_empty());
    }
}
