//! The audit log.
//!
//! One JSON object per line, append-only. JSONL because the consumers are `jq`
//! and a log shipper, and both want a record that is complete the moment its
//! newline lands. A JSON array would need a closing bracket the process may
//! never live to write.
//!
//! # Arguments are not logged by default
//!
//! A record names the tool, the decision, and the rule. It does not carry the
//! arguments unless asked, because arguments are where the content is: file
//! paths, query text, issue bodies, and every so often a credential. An audit
//! log that quietly accumulates those becomes the most sensitive file on the
//! host, and it is usually the one shipped off it.
//!
//! Instead every record carries a digest of the arguments. That is enough to
//! answer "was this the same call as the one at 14:02?" without keeping the
//! call. When full arguments are switched on they are redacted through the
//! credential scanner first, so the log cannot be a second copy of a secret the
//! gateway just removed from the model's context.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::Mutex;

/// What happened to a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Policy allowed it and the upstream answered.
    Allowed,
    /// Policy refused it.
    Denied,
    /// A rate limit refused it.
    RateLimited,
    /// The upstream failed.
    UpstreamError,
    /// No upstream exposes the tool.
    UnknownTool,
}

/// One audited call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Seconds since the Unix epoch, for correlating with other logs.
    pub ts: u64,
    /// The session this call belonged to.
    pub session: String,
    /// Monotonic counter within the session, so ordering survives equal
    /// timestamps and a log shipper that reorders lines.
    pub seq: u64,
    /// The upstream that owns the tool.
    pub server: String,
    /// The published tool name.
    pub tool: String,
    /// What happened.
    pub outcome: Outcome,
    /// The rule that decided, when one did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// SHA-256 prefix of the canonical arguments.
    pub args_digest: String,
    /// The arguments, redacted, when full logging is on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Value>,
    /// How long the upstream took, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Injection detector labels that fired on the result.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub injection: Vec<String>,
    /// Credential kinds redacted from the result.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub secrets: Vec<String>,
    /// Whether the result was replaced by a scanner.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub blocked: bool,
}

/// Digest length in hex characters.
const DIGEST_HEX_CHARS: usize = 16;

/// Digests arguments in a form that does not depend on key order.
///
/// `serde_json::Value` holds objects in a `BTreeMap` by default, so
/// serialisation is already key-sorted and two calls that differ only in the
/// order their keys arrived produce the same digest. Without that, "is this the
/// same call as before?" would depend on how the client happened to serialise.
pub fn digest_arguments(arguments: Option<&Value>) -> String {
    let canonical = match arguments {
        Some(value) => serde_json::to_string(value).unwrap_or_default(),
        None => String::new(),
    };

    let bytes = Sha256::digest(canonical.as_bytes());
    let mut hex = String::with_capacity(DIGEST_HEX_CHARS);
    for byte in bytes.iter().take(DIGEST_HEX_CHARS / 2) {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Audit log settings.
///
/// Both defaults are the quiet ones: no file, and no arguments. Turning the log
/// on is a deliberate act, and so is deciding to keep the call payloads in it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuditConfig {
    /// Where to append records. `None` disables the log.
    pub path: Option<std::path::PathBuf>,
    /// Whether to include redacted arguments in each record.
    pub log_arguments: bool,
}

/// An append-only JSONL sink.
pub struct AuditLog {
    sink: Mutex<Box<dyn Write + Send>>,
    config: AuditConfig,
    session: String,
    seq: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

impl AuditLog {
    /// Opens the log, creating or appending to the configured file.
    pub fn open(config: AuditConfig, session: impl Into<String>) -> std::io::Result<Self> {
        let sink: Box<dyn Write + Send> = match &config.path {
            Some(path) => Box::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?,
            ),
            None => Box::new(std::io::sink()),
        };
        Ok(Self::with_sink(sink, config, session))
    }

    /// Builds a log over any writer, which is how the tests read it back.
    pub fn with_sink(
        sink: Box<dyn Write + Send>,
        config: AuditConfig,
        session: impl Into<String>,
    ) -> Self {
        Self {
            sink: Mutex::new(sink),
            config,
            session: session.into(),
            seq: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Starts a record for a call.
    pub fn record(
        &self,
        server: &str,
        tool: &str,
        outcome: Outcome,
        arguments: Option<&Value>,
    ) -> AuditRecord {
        AuditRecord {
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs()),
            session: self.session.clone(),
            seq: self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            server: server.to_owned(),
            tool: tool.to_owned(),
            outcome,
            rule: None,
            args_digest: digest_arguments(arguments),
            args: self
                .config
                .log_arguments
                .then(|| redact_arguments(arguments)),
            duration_ms: None,
            injection: Vec::new(),
            secrets: Vec::new(),
            blocked: false,
        }
    }

    /// Appends a record.
    ///
    /// A failure to write is logged and swallowed. Failing the call because the
    /// audit sink is full would let a full disk take out the gateway, and this
    /// is a record of what happened rather than part of the decision. Operators
    /// who need audit to be blocking should ship the file, not couple the proxy
    /// to it; `docs/architecture.md` records the tradeoff.
    pub fn append(&self, record: &AuditRecord) {
        let Ok(mut line) = serde_json::to_string(record) else {
            return;
        };
        line.push('\n');

        let Ok(mut sink) = self.sink.lock() else {
            return;
        };
        if let Err(error) = sink.write_all(line.as_bytes()).and_then(|()| sink.flush()) {
            tracing::warn!(%error, "could not append an audit record");
        }
    }
}

/// Redacts credentials out of arguments before they are written down.
fn redact_arguments(arguments: Option<&Value>) -> Value {
    let Some(value) = arguments else {
        return Value::Null;
    };
    let Ok(text) = serde_json::to_string(value) else {
        return Value::Null;
    };

    let (redacted, findings) = portcullis_scan::secret::scan_and_redact(&text);
    if findings.is_empty() {
        return value.clone();
    }

    // Redaction markers can break the JSON, so fall back to the redacted text
    // as a string rather than emitting something unparseable.
    serde_json::from_str(&redacted).unwrap_or(Value::String(redacted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_policy::{Action, Decision, DecisionSource};
    use serde_json::json;
    use std::sync::{Arc, Mutex as StdMutex};

    #[derive(Clone, Default)]
    struct Buffer(Arc<StdMutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn log(config: AuditConfig) -> (AuditLog, Buffer) {
        let buffer = Buffer::default();
        (
            AuditLog::with_sink(Box::new(buffer.clone()), config, "sess-1"),
            buffer,
        )
    }

    fn lines(buffer: &Buffer) -> Vec<AuditRecord> {
        let raw = buffer.0.lock().unwrap().clone();
        String::from_utf8(raw)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).expect("each line parses on its own"))
            .collect()
    }

    #[test]
    fn each_record_is_one_self_contained_line() {
        let (log, buffer) = log(AuditConfig::default());
        log.append(&log.record("fs", "fs__read_file", Outcome::Allowed, None));
        log.append(&log.record("fs", "fs__write_file", Outcome::Denied, None));

        let records = lines(&buffer);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].seq, 0);
        assert_eq!(
            records[1].seq, 1,
            "sequence orders records even at equal timestamps"
        );
    }

    #[test]
    fn arguments_are_digested_but_not_written_by_default() {
        // The property that keeps the audit log from becoming the most
        // sensitive file on the host.
        let (log, buffer) = log(AuditConfig::default());
        let args = json!({ "path": "/home/u/.ssh/id_rsa" });
        log.append(&log.record("fs", "fs__read_file", Outcome::Denied, Some(&args)));

        let raw = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(
            !raw.contains("id_rsa"),
            "arguments leaked into the log: {raw}"
        );
        assert!(lines(&buffer)[0].args.is_none());
        assert_eq!(lines(&buffer)[0].args_digest.len(), DIGEST_HEX_CHARS);
    }

    #[test]
    fn the_digest_identifies_repeat_calls_regardless_of_key_order() {
        let one = digest_arguments(Some(&json!({ "a": 1, "b": 2 })));
        let two = digest_arguments(Some(&json!({ "b": 2, "a": 1 })));
        assert_eq!(one, two, "the same call must digest the same way");

        assert_ne!(one, digest_arguments(Some(&json!({ "a": 1, "b": 3 }))));
        assert_ne!(one, digest_arguments(None));
    }

    #[test]
    fn full_argument_logging_still_redacts_credentials() {
        // Otherwise the log becomes a second copy of the secret the gateway
        // just stripped out of the model's context.
        let config = AuditConfig {
            log_arguments: true,
            ..Default::default()
        };
        let (log, buffer) = log(config);

        let token = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
        let args = json!({ "body": format!("key is {token}") });
        log.append(&log.record("gh", "gh__create_issue", Outcome::Allowed, Some(&args)));

        let raw = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(!raw.contains(&token), "{raw}");
        assert!(raw.contains("[redacted:aws_access_key_id:"), "{raw}");
    }

    #[test]
    fn scanner_findings_ride_along_on_the_record() {
        let (log, buffer) = log(AuditConfig::default());
        let mut record = log.record("gh", "gh__get_issue", Outcome::Allowed, None);
        record.injection = vec!["instruction_override".to_owned()];
        record.secrets = vec!["github_token".to_owned()];
        record.blocked = true;
        record.duration_ms = Some(42);
        log.append(&record);

        let written = &lines(&buffer)[0];
        assert_eq!(written.injection, vec!["instruction_override"]);
        assert!(written.blocked);
        assert_eq!(written.duration_ms, Some(42));
    }

    #[test]
    fn empty_collections_stay_out_of_the_record() {
        let (log, buffer) = log(AuditConfig::default());
        log.append(&log.record("fs", "fs__read_file", Outcome::Allowed, None));

        let raw = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(!raw.contains("injection"), "{raw}");
        assert!(!raw.contains("blocked"), "{raw}");
    }

    #[test]
    fn a_decision_can_be_attached_by_rule_id() {
        let (log, buffer) = log(AuditConfig::default());
        let decision = Decision {
            action: Action::Deny,
            source: DecisionSource::Rule {
                id: "deny-shell".to_owned(),
                index: 0,
                description: None,
            },
        };

        let mut record = log.record("shell", "shell__run", Outcome::Denied, None);
        record.rule = decision.rule_id().map(str::to_owned);
        log.append(&record);

        assert_eq!(lines(&buffer)[0].rule.as_deref(), Some("deny-shell"));
    }

    #[test]
    fn a_disabled_log_accepts_records_without_writing_anywhere() {
        let log = AuditLog::open(AuditConfig::default(), "sess").expect("opens");
        log.append(&log.record("fs", "fs__read_file", Outcome::Allowed, None));
    }
}
