//! The rule model.
//!
//! A rule answers one question: for a given upstream server, tool name, and
//! argument payload, does this rule have anything to say? A rule that applies
//! contributes its [`Action`]; a rule that does not is skipped. Combining rules
//! into a single decision is [`crate::engine`]'s job, not this module's.
//!
//! # Conditions are conjunctive, selections are existential
//!
//! Every entry in `when` must hold for the rule to apply. Within one condition,
//! a wildcard path may select several values, and the condition holds if any of
//! them satisfies the predicate. "All conditions, any value" is the combination
//! that makes deny rules behave: a write batch is denied if *one* of its paths
//! is forbidden, and a rule with several conditions is as specific as it looks.
//!
//! # Negation over an absent argument is vacuously true
//!
//! `{ arg = "path", not = true, contains = ".." }` reads as "path does not
//! contain `..`". If the call omits `path` altogether, nothing is selected,
//! nothing contains `..`, and the condition holds. That is logically correct
//! and operationally surprising, so a rule that must also require presence
//! should say so with a companion `{ arg = "path", exists = true }`. Policy
//! validation warns when a negated condition appears without one.

use crate::argpath::ArgPath;
use crate::glob::Pattern;
use serde::Deserialize;
use serde_json::Value;
use std::fmt;

/// What a rule does when it applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Forward the call to its upstream server.
    Allow,
    /// Refuse the call and tell the model which rule refused it.
    Deny,
}

impl Action {
    /// Whether this action permits the call.
    pub fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        })
    }
}

/// Something a condition can assert about a selected value.
#[derive(Debug, Clone)]
pub enum Predicate {
    /// The path selects at least one value, including an explicit null.
    Exists,
    /// The value equals this JSON value exactly.
    Equals(Value),
    /// The value equals one of these JSON values.
    OneOf(Vec<Value>),
    /// The value is a string containing this substring.
    Contains(String),
    /// The value is a string matching this regular expression.
    ///
    /// Boxed because a compiled `Regex` is large, and most conditions are not
    /// regexes; inlining it would make every `Predicate` pay for the rare case.
    Matches(Box<regex::Regex>),
    /// The value is a string matching this glob.
    Glob(Pattern),
    /// The value is a number strictly greater than this.
    GreaterThan(f64),
    /// The value is a number strictly less than this.
    LessThan(f64),
}

impl Predicate {
    /// Tests one selected value.
    fn test(&self, value: &Value) -> bool {
        match self {
            // Handled by the caller, which knows whether anything was selected.
            Self::Exists => true,
            Self::Equals(expected) => value == expected,
            Self::OneOf(options) => options.contains(value),
            Self::Contains(needle) => value.as_str().is_some_and(|text| text.contains(needle)),
            Self::Matches(regex) => value.as_str().is_some_and(|text| regex.is_match(text)),
            Self::Glob(pattern) => value.as_str().is_some_and(|text| pattern.matches(text)),
            Self::GreaterThan(bound) => value.as_f64().is_some_and(|number| number > *bound),
            Self::LessThan(bound) => value.as_f64().is_some_and(|number| number < *bound),
        }
    }

    /// A short label naming the predicate kind, for explanations and audit.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Exists => "exists",
            Self::Equals(_) => "equals",
            Self::OneOf(_) => "one_of",
            Self::Contains(_) => "contains",
            Self::Matches(_) => "matches",
            Self::Glob(_) => "glob",
            Self::GreaterThan(_) => "gt",
            Self::LessThan(_) => "lt",
        }
    }
}

/// A condition over one argument path.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawCondition")]
pub struct Condition {
    /// Which argument this condition inspects.
    pub arg: ArgPath,
    /// Whether the predicate result is inverted.
    pub negate: bool,
    /// What is asserted about the selected values.
    pub predicate: Predicate,
}

impl Condition {
    /// Evaluates the condition against a tool call's arguments.
    pub fn evaluate(&self, arguments: &Value) -> bool {
        let selected = self.arg.resolve(arguments);

        let satisfied = match &self.predicate {
            // Presence is about the selection itself, not about any value in it.
            Predicate::Exists => !selected.is_empty(),
            predicate => selected.iter().any(|value| predicate.test(value)),
        };

        satisfied != self.negate
    }

    /// Renders the condition the way it would appear in a policy file, for use
    /// in denial messages and `portcullis explain`.
    pub fn describe(&self) -> String {
        let not = if self.negate { "not " } else { "" };
        format!("{} {}{}", self.arg, not, self.predicate.kind())
    }
}

/// The `when = [...]` entry as it appears in a policy file.
///
/// Every predicate is an optional key, and exactly one must be present. A
/// struct with mutually exclusive fields is not the prettiest encoding, but it
/// produces error messages naming the offending keys, which an untagged enum
/// does not.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCondition {
    arg: ArgPath,
    #[serde(default)]
    not: bool,
    equals: Option<Value>,
    one_of: Option<Vec<Value>>,
    contains: Option<String>,
    matches: Option<String>,
    glob: Option<String>,
    gt: Option<f64>,
    lt: Option<f64>,
    exists: Option<bool>,
}

/// A rule that could not be compiled.
#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    /// A condition named no predicate.
    #[error("condition on {arg:?} names no predicate; expected one of {options}")]
    NoPredicate {
        /// The path the condition addressed.
        arg: String,
        /// The accepted predicate keys.
        options: &'static str,
    },

    /// A condition named more than one predicate.
    #[error("condition on {arg:?} names several predicates ({found}); use one per condition")]
    AmbiguousPredicate {
        /// The path the condition addressed.
        arg: String,
        /// The conflicting keys, comma separated.
        found: String,
    },

    /// A regex predicate did not compile.
    #[error("condition on {arg:?} has an invalid regex: {source}")]
    InvalidRegex {
        /// The path the condition addressed.
        arg: String,
        /// The underlying compile failure.
        #[source]
        source: Box<regex::Error>,
    },

    /// A rule declared no tool patterns.
    #[error("rule {id:?} matches no tools; every rule needs at least one tool pattern")]
    NoToolPatterns {
        /// The rule's id.
        id: String,
    },

    /// A rule had a blank id.
    #[error("every rule needs a non-empty id so decisions can name the rule that produced them")]
    MissingId,
}

const PREDICATE_KEYS: &str = "equals, one_of, contains, matches, glob, gt, lt, exists";

impl TryFrom<RawCondition> for Condition {
    type Error = RuleError;

    fn try_from(raw: RawCondition) -> Result<Self, Self::Error> {
        let arg_label = raw.arg.as_str().to_owned();
        let mut named: Vec<&'static str> = Vec::new();

        if raw.equals.is_some() {
            named.push("equals");
        }
        if raw.one_of.is_some() {
            named.push("one_of");
        }
        if raw.contains.is_some() {
            named.push("contains");
        }
        if raw.matches.is_some() {
            named.push("matches");
        }
        if raw.glob.is_some() {
            named.push("glob");
        }
        if raw.gt.is_some() {
            named.push("gt");
        }
        if raw.lt.is_some() {
            named.push("lt");
        }
        if raw.exists.is_some() {
            named.push("exists");
        }

        if named.is_empty() {
            return Err(RuleError::NoPredicate {
                arg: arg_label,
                options: PREDICATE_KEYS,
            });
        }
        if named.len() > 1 {
            return Err(RuleError::AmbiguousPredicate {
                arg: arg_label,
                found: named.join(", "),
            });
        }

        // `exists = false` is spelled as a negated presence check rather than a
        // separate predicate, so `not` and `exists` compose predictably.
        let mut negate = raw.not;
        let predicate = if let Some(value) = raw.equals {
            Predicate::Equals(value)
        } else if let Some(values) = raw.one_of {
            Predicate::OneOf(values)
        } else if let Some(needle) = raw.contains {
            Predicate::Contains(needle)
        } else if let Some(source) = raw.matches {
            let compiled =
                regex::Regex::new(&source).map_err(|source| RuleError::InvalidRegex {
                    arg: arg_label.clone(),
                    source: Box::new(source),
                })?;
            Predicate::Matches(Box::new(compiled))
        } else if let Some(pattern) = raw.glob {
            Predicate::Glob(Pattern::new(pattern))
        } else if let Some(bound) = raw.gt {
            Predicate::GreaterThan(bound)
        } else if let Some(bound) = raw.lt {
            Predicate::LessThan(bound)
        } else {
            let expected = raw.exists.unwrap_or(true);
            negate ^= !expected;
            Predicate::Exists
        };

        Ok(Self {
            arg: raw.arg,
            negate,
            predicate,
        })
    }
}

/// A policy rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawRule")]
pub struct Rule {
    /// Stable identifier, quoted in denials and audit records.
    pub id: String,
    /// Optional human-readable rationale.
    pub description: Option<String>,
    /// Tool name patterns this rule covers, matched against the namespaced
    /// name the client sees.
    pub tools: Vec<Pattern>,
    /// Upstream server names this rule is restricted to. `None` means any.
    pub servers: Option<Vec<Pattern>>,
    /// What to do when the rule applies.
    pub action: Action,
    /// Conditions that must all hold for the rule to apply.
    pub when: Vec<Condition>,
}

/// The `[[rule]]` table as it appears in a policy file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    description: Option<String>,
    #[serde(default)]
    tools: Vec<Pattern>,
    servers: Option<Vec<Pattern>>,
    action: Action,
    #[serde(default)]
    when: Vec<Condition>,
}

impl TryFrom<RawRule> for Rule {
    type Error = RuleError;

    fn try_from(raw: RawRule) -> Result<Self, Self::Error> {
        if raw.id.trim().is_empty() {
            return Err(RuleError::MissingId);
        }
        if raw.tools.is_empty() {
            return Err(RuleError::NoToolPatterns { id: raw.id });
        }
        Ok(Self {
            id: raw.id,
            description: raw.description,
            tools: raw.tools,
            servers: raw.servers,
            action: raw.action,
            when: raw.when,
        })
    }
}

impl Rule {
    /// Whether the rule's tool patterns cover this name.
    pub fn matches_tool(&self, tool: &str) -> bool {
        self.tools.iter().any(|pattern| pattern.matches(tool))
    }

    /// Whether the rule's server restriction admits this upstream.
    ///
    /// A rule with no `servers` key applies to every upstream.
    pub fn matches_server(&self, server: &str) -> bool {
        match &self.servers {
            None => true,
            Some(patterns) => patterns.iter().any(|pattern| pattern.matches(server)),
        }
    }

    /// Whether every condition holds for these arguments.
    ///
    /// A call with no arguments is evaluated against an empty object, so
    /// conditions behave the same whether the client omitted `arguments` or
    /// sent `{}`.
    pub fn conditions_hold(&self, arguments: Option<&Value>) -> bool {
        let empty = Value::Object(serde_json::Map::new());
        let arguments = arguments.unwrap_or(&empty);
        self.when
            .iter()
            .all(|condition| condition.evaluate(arguments))
    }

    /// Whether this rule applies to a call.
    pub fn applies_to(&self, server: &str, tool: &str, arguments: Option<&Value>) -> bool {
        self.matches_server(server) && self.matches_tool(tool) && self.conditions_hold(arguments)
    }

    /// The first condition that fails, for explaining why a rule was skipped.
    pub fn first_unmet_condition(&self, arguments: Option<&Value>) -> Option<&Condition> {
        let empty = Value::Object(serde_json::Map::new());
        let arguments = arguments.unwrap_or(&empty);
        self.when
            .iter()
            .find(|condition| !condition.evaluate(arguments))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn condition(toml_fragment: &str) -> Condition {
        let wrapper: ConditionWrapper =
            toml::from_str(&format!("condition = {toml_fragment}")).expect("parses");
        wrapper.condition
    }

    #[derive(Debug, Deserialize)]
    struct ConditionWrapper {
        condition: Condition,
    }

    fn rule(toml_text: &str) -> Rule {
        toml::from_str(toml_text).expect("rule parses")
    }

    #[test]
    fn equals_matches_exactly() {
        let c = condition(r#"{ arg = "recursive", equals = true }"#);
        assert!(c.evaluate(&json!({ "recursive": true })));
        assert!(!c.evaluate(&json!({ "recursive": false })));
        assert!(!c.evaluate(&json!({})));
    }

    #[test]
    fn contains_only_applies_to_strings() {
        let c = condition(r#"{ arg = "path", contains = ".." }"#);
        assert!(c.evaluate(&json!({ "path": "/a/../b" })));
        assert!(!c.evaluate(&json!({ "path": "/a/b" })));
        assert!(
            !c.evaluate(&json!({ "path": 42 })),
            "a number cannot contain a substring"
        );
    }

    #[test]
    fn matches_compiles_a_regex() {
        let c = condition(r#"{ arg = "path", matches = "(^|/)\\.(ssh|aws)(/|$)" }"#);
        assert!(c.evaluate(&json!({ "path": "/home/u/.ssh/id_rsa" })));
        assert!(c.evaluate(&json!({ "path": ".aws" })));
        assert!(!c.evaluate(&json!({ "path": "/home/u/ssh_notes.md" })));
    }

    #[test]
    fn an_invalid_regex_is_a_compile_error_not_a_silent_pass() {
        let error =
            toml::from_str::<ConditionWrapper>(r#"condition = { arg = "p", matches = "(" }"#)
                .unwrap_err()
                .to_string();
        assert!(error.contains("invalid regex"), "{error}");
    }

    #[test]
    fn one_of_matches_any_listed_value() {
        let c = condition(r#"{ arg = "mode", one_of = ["w", "a"] }"#);
        assert!(c.evaluate(&json!({ "mode": "a" })));
        assert!(!c.evaluate(&json!({ "mode": "r" })));
    }

    #[test]
    fn numeric_bounds_are_strict() {
        let gt = condition(r#"{ arg = "limit", gt = 100.0 }"#);
        assert!(gt.evaluate(&json!({ "limit": 101 })));
        assert!(!gt.evaluate(&json!({ "limit": 100 })));

        let lt = condition(r#"{ arg = "limit", lt = 10.0 }"#);
        assert!(lt.evaluate(&json!({ "limit": 9.5 })));
        assert!(!lt.evaluate(&json!({ "limit": 10 })));
    }

    #[test]
    fn exists_distinguishes_absent_from_null() {
        let c = condition(r#"{ arg = "path", exists = true }"#);
        assert!(
            c.evaluate(&json!({ "path": null })),
            "present-but-null still exists"
        );
        assert!(!c.evaluate(&json!({})));
    }

    #[test]
    fn exists_false_is_the_negation_of_exists() {
        let c = condition(r#"{ arg = "path", exists = false }"#);
        assert!(c.evaluate(&json!({})));
        assert!(!c.evaluate(&json!({ "path": "/tmp" })));
    }

    #[test]
    fn not_inverts_the_predicate() {
        let c = condition(r#"{ arg = "mode", not = true, equals = "r" }"#);
        assert!(c.evaluate(&json!({ "mode": "w" })));
        assert!(!c.evaluate(&json!({ "mode": "r" })));
    }

    #[test]
    fn negation_over_an_absent_argument_is_vacuously_true() {
        // Documented in the module header because it is the surprising case:
        // "path does not contain .." holds when there is no path at all.
        let c = condition(r#"{ arg = "path", not = true, contains = ".." }"#);
        assert!(c.evaluate(&json!({})));
    }

    #[test]
    fn a_wildcard_condition_fires_when_any_element_matches() {
        // The security-relevant case: one forbidden entry in a batch of many
        // must still trip the rule.
        let c = condition(r#"{ arg = "files.*.path", contains = "/etc/" }"#);
        assert!(c.evaluate(&json!({
            "files": [{ "path": "/tmp/a" }, { "path": "/tmp/b" }, { "path": "/etc/shadow" }]
        })));
        assert!(!c.evaluate(&json!({ "files": [{ "path": "/tmp/a" }] })));
    }

    #[test]
    fn a_condition_naming_no_predicate_is_rejected() {
        let error = toml::from_str::<ConditionWrapper>(r#"condition = { arg = "p" }"#)
            .unwrap_err()
            .to_string();
        assert!(error.contains("names no predicate"), "{error}");
    }

    #[test]
    fn a_condition_naming_two_predicates_is_rejected() {
        let error = toml::from_str::<ConditionWrapper>(
            r#"condition = { arg = "p", equals = "a", contains = "b" }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("several predicates"), "{error}");
        assert!(
            error.contains("equals") && error.contains("contains"),
            "{error}"
        );
    }

    #[test]
    fn rule_conditions_are_conjunctive() {
        let r = rule(
            r#"
            id = "deny-recursive-etc"
            tools = ["fs.*"]
            action = "deny"
            when = [
              { arg = "path", contains = "/etc" },
              { arg = "recursive", equals = true },
            ]
            "#,
        );

        assert!(r.applies_to(
            "fs",
            "fs.delete",
            Some(&json!({ "path": "/etc", "recursive": true }))
        ));
        assert!(
            !r.applies_to(
                "fs",
                "fs.delete",
                Some(&json!({ "path": "/etc", "recursive": false }))
            ),
            "every condition must hold, not just one"
        );
    }

    #[test]
    fn rule_without_servers_applies_everywhere() {
        let r = rule("id = \"r\"\ntools = [\"*\"]\naction = \"allow\"");
        assert!(r.matches_server("anything"));
        assert!(r.matches_server(""));
    }

    #[test]
    fn rule_with_servers_is_restricted_to_them() {
        let r = rule("id = \"r\"\ntools = [\"*\"]\nservers = [\"gh-*\"]\naction = \"deny\"");
        assert!(r.matches_server("gh-prod"));
        assert!(!r.matches_server("fs-local"));
    }

    #[test]
    fn a_rule_with_no_tool_patterns_is_rejected() {
        let error = toml::from_str::<Rule>("id = \"r\"\naction = \"deny\"")
            .unwrap_err()
            .to_string();
        assert!(error.contains("matches no tools"), "{error}");
    }

    #[test]
    fn a_rule_with_a_blank_id_is_rejected() {
        let error = toml::from_str::<Rule>("id = \"  \"\ntools = [\"*\"]\naction = \"deny\"")
            .unwrap_err()
            .to_string();
        assert!(error.contains("non-empty id"), "{error}");
    }

    #[test]
    fn unknown_keys_are_rejected_rather_than_ignored() {
        // A typo in a policy file must not silently produce a rule that does
        // something other than what was written.
        let error =
            toml::from_str::<Rule>("id = \"r\"\ntools = [\"*\"]\naction = \"deny\"\ntoolz = []")
                .unwrap_err()
                .to_string();
        assert!(
            error.contains("toolz") || error.contains("unknown field"),
            "{error}"
        );
    }

    #[test]
    fn missing_arguments_are_treated_as_an_empty_object() {
        let r = rule(
            "id = \"r\"\ntools = [\"*\"]\naction = \"deny\"\nwhen = [{ arg = \"p\", exists = true }]",
        );
        assert!(!r.conditions_hold(None));
        assert!(!r.conditions_hold(Some(&json!({}))));
        assert!(r.conditions_hold(Some(&json!({ "p": 1 }))));
    }

    #[test]
    fn reports_the_first_condition_that_failed() {
        let r = rule(
            r#"
            id = "r"
            tools = ["*"]
            action = "deny"
            when = [
              { arg = "a", exists = true },
              { arg = "b", exists = true },
            ]
            "#,
        );

        let unmet = r
            .first_unmet_condition(Some(&json!({ "a": 1 })))
            .expect("one condition failed");
        assert_eq!(unmet.arg.as_str(), "b");
        assert_eq!(unmet.describe(), "b exists");
        assert!(
            r.first_unmet_condition(Some(&json!({ "a": 1, "b": 2 })))
                .is_none()
        );
    }
}
