//! Loading and validating policy files.
//!
//! Loading is strict on purpose. An unknown key, a rule with no id, a regex
//! that does not compile: all of these stop the gateway from starting rather
//! than being logged and skipped. The alternative is a gateway that runs with a
//! policy subtly different from the one on disk, which is the worst outcome
//! available, because everything looks fine.
//!
//! Validation goes further and reports problems the type system cannot catch:
//! rules that can never be reached, negations that will not do what their
//! author expects, and a default that inverts the security posture. These are
//! split into errors, which refuse the load, and warnings, which are printed
//! and allowed. The split is by whether the policy is *wrong* or merely
//! *suspicious*: two rules sharing an id makes audit records ambiguous and is
//! an error; an unreachable rule is dead configuration and is a warning.

use crate::engine::Policy;
use crate::rule::{Action, Rule};
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// The policy schema version this build understands.
pub const SUPPORTED_VERSION: u32 = 1;

/// How seriously to take a validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// The policy is usable but something looks wrong.
    Warning,
    /// The policy is not usable.
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Warning => "warning",
            Self::Error => "error",
        })
    }
}

/// Something validation found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// How seriously to take it.
    pub severity: Severity,
    /// Stable machine-readable code, so CI can allow specific findings.
    pub code: &'static str,
    /// The rule involved, when there is one.
    pub rule_id: Option<String>,
    /// Human-readable detail.
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}]", self.severity, self.code)?;
        if let Some(id) = &self.rule_id {
            write!(f, " rule {id:?}")?;
        }
        write!(f, ": {}", self.message)
    }
}

/// A policy that could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The file could not be read.
    #[error("cannot read policy file {path}: {source}")]
    Io {
        /// The path that failed.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    /// The file was not valid TOML, or did not match the schema.
    #[error("cannot parse policy{}: {source}", DisplayPath(.path.as_deref()))]
    Parse {
        /// The path, when the policy came from a file.
        path: Option<PathBuf>,
        /// The underlying parse failure.
        #[source]
        source: Box<toml::de::Error>,
    },

    /// The file declared a schema version this build does not understand.
    #[error(
        "policy declares version {found}, but this build understands version {SUPPORTED_VERSION}"
    )]
    UnsupportedVersion {
        /// The version the file declared.
        found: u32,
    },

    /// Validation found problems serious enough to refuse the policy.
    #[error("policy is not usable: {}", Bullets(.diagnostics))]
    Invalid {
        /// Every finding, warnings included, so a caller can print them all.
        diagnostics: Vec<Diagnostic>,
    },
}

struct DisplayPath<'a>(Option<&'a Path>);

impl fmt::Display for DisplayPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(path) => write!(f, " file {}", path.display()),
            None => Ok(()),
        }
    }
}

struct Bullets<'a>(&'a [Diagnostic]);

impl fmt::Display for Bullets<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for diagnostic in self.0.iter().filter(|d| d.severity == Severity::Error) {
            write!(f, "\n  - {diagnostic}")?;
        }
        Ok(())
    }
}

/// A policy file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(flatten)]
    policy: Policy,
}

fn default_version() -> u32 {
    SUPPORTED_VERSION
}

/// Parses a policy from TOML text, validating it.
///
/// Warnings are returned alongside the policy; errors refuse the load.
pub fn from_str(text: &str) -> Result<(Policy, Vec<Diagnostic>), LoadError> {
    from_str_named(text, None)
}

/// Reads and validates a policy file.
pub fn from_path(path: impl AsRef<Path>) -> Result<(Policy, Vec<Diagnostic>), LoadError> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    from_str_named(&text, Some(path))
}

fn from_str_named(text: &str, path: Option<&Path>) -> Result<(Policy, Vec<Diagnostic>), LoadError> {
    let document: PolicyDocument = toml::from_str(text).map_err(|source| LoadError::Parse {
        path: path.map(Path::to_path_buf),
        source: Box::new(source),
    })?;

    if document.version != SUPPORTED_VERSION {
        return Err(LoadError::UnsupportedVersion {
            found: document.version,
        });
    }

    let diagnostics = validate(&document.policy);
    if diagnostics.iter().any(|d| d.severity == Severity::Error) {
        return Err(LoadError::Invalid { diagnostics });
    }

    Ok((document.policy, diagnostics))
}

/// Checks a policy for problems the schema cannot express.
///
/// Reachability analysis here is deliberately conservative. Deciding whether
/// one set of glob patterns subsumes another is not worth doing exactly, and a
/// false "this rule is dead" would train operators to ignore the warning. It
/// only reports the cases that are unarguable: an earlier unconditional rule
/// whose patterns visibly cover a later one.
pub fn validate(policy: &Policy) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let rules = policy.rules();

    check_duplicate_ids(rules, &mut diagnostics);
    check_default_posture(policy, &mut diagnostics);

    for (index, rule) in rules.iter().enumerate() {
        check_negation_without_presence(rule, &mut diagnostics);
        check_rate_limit_on_deny(rule, &mut diagnostics);

        if let Some(shadow) = rules[..index].iter().find(|earlier| shadows(earlier, rule)) {
            diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                code: "unreachable-rule",
                rule_id: Some(rule.id.clone()),
                message: format!(
                    "can never apply: rule {:?} appears earlier, has no conditions, and already \
                     covers these tools",
                    shadow.id
                ),
            });
        }
    }

    diagnostics
}

fn check_rate_limit_on_deny(rule: &Rule, diagnostics: &mut Vec<Diagnostic>) {
    if rule.rate_limit.is_some() && !rule.action.is_allow() {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            code: "rate-limit-on-deny",
            rule_id: Some(rule.id.clone()),
            message: "has a rate limit but denies every call, so the limit describes how often                       something that never happens may happen. The limit is ignored"
                .to_owned(),
        });
    }
}

fn check_duplicate_ids(rules: &[Rule], diagnostics: &mut Vec<Diagnostic>) {
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for rule in rules {
        let count = seen.entry(rule.id.as_str()).or_insert(0);
        *count += 1;
        if *count == 2 {
            diagnostics.push(Diagnostic {
                severity: Severity::Error,
                code: "duplicate-rule-id",
                rule_id: Some(rule.id.clone()),
                message: "used by more than one rule; audit records would not identify which rule \
                          decided a call"
                    .to_owned(),
            });
        }
    }
}

fn check_default_posture(policy: &Policy, diagnostics: &mut Vec<Diagnostic>) {
    if policy.default_action() == Action::Allow {
        diagnostics.push(Diagnostic {
            severity: Severity::Warning,
            code: "default-allow",
            rule_id: None,
            message: "default is allow, so any call that matches no rule is forwarded. A call \
                      omitting the arguments a deny rule inspects matches no rule, so deny rules \
                      cannot be relied on under this default"
                .to_owned(),
        });
    }
}

fn check_negation_without_presence(rule: &Rule, diagnostics: &mut Vec<Diagnostic>) {
    for condition in &rule.when {
        if !condition.negate {
            continue;
        }
        let arg = condition.arg.as_str();
        let has_presence_check = rule
            .when
            .iter()
            .any(|other| !other.negate && other.arg.as_str() == arg && other.predicate.is_exists());

        if !has_presence_check {
            diagnostics.push(Diagnostic {
                severity: Severity::Warning,
                code: "vacuous-negation",
                rule_id: Some(rule.id.clone()),
                message: format!(
                    "condition {:?} is negated but nothing requires {arg:?} to be present, so it \
                     holds for calls that omit the argument entirely",
                    condition.describe()
                ),
            });
        }
    }
}

/// Whether `earlier` makes `later` unreachable.
///
/// Conservative by design: only unconditional earlier rules count, and pattern
/// coverage is only recognised when the earlier rule matches everything or has
/// a pattern that literally matches the later one.
fn shadows(earlier: &Rule, later: &Rule) -> bool {
    if !earlier.when.is_empty() {
        return false;
    }

    // An earlier rule restricted to specific servers cannot shadow a rule that
    // may run on others, and comparing glob sets exactly is not worth it.
    if earlier.servers.is_some() {
        return false;
    }

    later.tools.iter().all(|later_pattern| {
        earlier
            .tools
            .iter()
            .any(|earlier_pattern| earlier_pattern.matches(later_pattern.as_str()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(text: &str) -> Result<(Policy, Vec<Diagnostic>), LoadError> {
        from_str(text)
    }

    fn codes(diagnostics: &[Diagnostic]) -> Vec<&str> {
        diagnostics.iter().map(|d| d.code).collect()
    }

    #[test]
    fn loads_a_well_formed_policy() {
        let (policy, warnings) = load(
            r#"
            version = 1
            default = "deny"

            [[rule]]
            id = "allow-reads"
            tools = ["fs.read_*"]
            action = "allow"
            "#,
        )
        .expect("loads");

        assert_eq!(policy.rules().len(), 1);
        assert_eq!(policy.default_action(), Action::Deny);
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn a_missing_version_assumes_the_current_one() {
        assert!(load("default = \"deny\"").is_ok());
    }

    #[test]
    fn a_future_version_is_refused_rather_than_guessed_at() {
        let error = load("version = 99\ndefault = \"deny\"").unwrap_err();
        assert!(
            matches!(error, LoadError::UnsupportedVersion { found: 99 }),
            "{error}"
        );
    }

    #[test]
    fn an_unknown_top_level_key_is_a_load_failure() {
        // A policy file is security configuration. A typo must not be ignored.
        let error = load("defualt = \"deny\"").unwrap_err();
        assert!(matches!(error, LoadError::Parse { .. }), "{error}");
    }

    #[test]
    fn a_bad_regex_fails_the_load_and_names_the_argument() {
        let error = load(
            r#"
            [[rule]]
            id = "r"
            tools = ["*"]
            action = "deny"
            when = [{ arg = "path", matches = "(unclosed" }]
            "#,
        )
        .unwrap_err();

        let text = error.to_string();
        assert!(text.contains("invalid regex"), "{text}");
        assert!(text.contains("path"), "{text}");
    }

    #[test]
    fn duplicate_rule_ids_are_an_error() {
        let error = load(
            r#"
            [[rule]]
            id = "same"
            tools = ["a"]
            action = "allow"

            [[rule]]
            id = "same"
            tools = ["b"]
            action = "deny"
            "#,
        )
        .unwrap_err();

        let LoadError::Invalid { diagnostics } = &error else {
            panic!("{error}")
        };
        assert!(codes(diagnostics).contains(&"duplicate-rule-id"));
        assert!(error.to_string().contains("audit records"), "{error}");
    }

    #[test]
    fn default_allow_loads_but_warns_about_the_posture() {
        let (_, warnings) = load("default = \"allow\"").expect("still usable");
        assert_eq!(codes(&warnings), vec!["default-allow"]);
        assert_eq!(warnings[0].severity, Severity::Warning);
    }

    #[test]
    fn an_unreachable_rule_is_reported() {
        let (_, warnings) = load(
            r#"
            [[rule]]
            id = "allow-everything"
            tools = ["*"]
            action = "allow"

            [[rule]]
            id = "deny-ssh"
            tools = ["fs.read_file"]
            action = "deny"
            "#,
        )
        .expect("loads with a warning");

        assert_eq!(codes(&warnings), vec!["unreachable-rule"]);
        assert_eq!(warnings[0].rule_id.as_deref(), Some("deny-ssh"));
        assert!(
            warnings[0].message.contains("allow-everything"),
            "{}",
            warnings[0].message
        );
    }

    #[test]
    fn a_conditional_earlier_rule_does_not_shadow() {
        // The conservative half: an earlier rule that only applies sometimes
        // leaves later rules reachable, so no warning.
        let (_, warnings) = load(
            r#"
            [[rule]]
            id = "allow-small-reads"
            tools = ["*"]
            action = "allow"
            when = [{ arg = "limit", lt = 100.0 }]

            [[rule]]
            id = "deny-reads"
            tools = ["fs.read_file"]
            action = "deny"
            "#,
        )
        .expect("loads");

        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn a_server_scoped_earlier_rule_does_not_shadow() {
        let (_, warnings) = load(
            r#"
            [[rule]]
            id = "allow-github"
            servers = ["github"]
            tools = ["*"]
            action = "allow"

            [[rule]]
            id = "deny-fs"
            tools = ["fs.*"]
            action = "deny"
            "#,
        )
        .expect("loads");

        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn a_negated_condition_without_a_presence_check_warns() {
        let (_, warnings) = load(
            r#"
            [[rule]]
            id = "allow-non-destructive"
            tools = ["*"]
            action = "allow"
            when = [{ arg = "force", not = true, equals = true }]
            "#,
        )
        .expect("loads");

        assert_eq!(codes(&warnings), vec!["vacuous-negation"]);
        assert!(
            warnings[0].message.contains("omit the argument"),
            "{}",
            warnings[0].message
        );
    }

    #[test]
    fn pairing_a_negation_with_an_exists_check_silences_the_warning() {
        let (_, warnings) = load(
            r#"
            [[rule]]
            id = "allow-non-destructive"
            tools = ["*"]
            action = "allow"
            when = [
              { arg = "force", exists = true },
              { arg = "force", not = true, equals = true },
            ]
            "#,
        )
        .expect("loads");

        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn a_rate_limit_on_an_allow_rule_loads_cleanly() {
        let (policy, warnings) = load(
            r#"
            session_rate_limit = { max = 200, per_seconds = 60 }

            [[rule]]
            id = "allow-drafting"
            tools = ["gh__create_issue"]
            action = "allow"
            rate_limit = { max = 5, per_seconds = 60 }
            "#,
        )
        .expect("loads");

        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(policy.rules()[0].rate_limit.unwrap().max, 5);
        assert_eq!(policy.session_rate_limit().unwrap().max, 200);
    }

    #[test]
    fn a_rate_limit_on_a_deny_rule_warns() {
        // Not an error: the policy still does what it says, the limit is just
        // inert. Saying so beats silently ignoring it.
        let (_, warnings) = load(
            r#"
            [[rule]]
            id = "deny-shell"
            tools = ["shell__*"]
            action = "deny"
            rate_limit = { max = 5, per_seconds = 60 }
            "#,
        )
        .expect("loads");

        assert_eq!(codes(&warnings), vec!["rate-limit-on-deny"]);
    }

    #[test]
    fn a_degenerate_rate_limit_fails_the_load() {
        let error = load(
            r#"
            [[rule]]
            id = "r"
            tools = ["*"]
            action = "allow"
            rate_limit = { max = 0, per_seconds = 60 }
            "#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("max = 0"), "{error}");
    }

    #[test]
    fn the_shipped_default_policy_loads_without_warnings() {
        // The example everyone copies has to be exemplary.
        let text = include_str!("../../../policies/default.toml");
        let (policy, warnings) = from_str(text).expect("the shipped policy must load");

        assert_eq!(policy.default_action(), Action::Deny);
        assert!(!policy.rules().is_empty());
        assert!(
            warnings.is_empty(),
            "shipped policy has warnings: {warnings:?}"
        );
    }

    #[test]
    fn a_missing_file_reports_the_path() {
        let error = from_path("does/not/exist.toml").unwrap_err();
        assert!(matches!(error, LoadError::Io { .. }));
        assert!(error.to_string().contains("exist.toml"), "{error}");
    }
}
