//! Addressing values inside a tool's arguments.
//!
//! A rule needs to talk about a specific argument: `path`, `options.recursive`,
//! `files.0.name`. This module turns a dotted string into a resolver over
//! [`serde_json::Value`].
//!
//! # Wildcards resolve to a set, not a value
//!
//! `files.*.path` selects every element's `path`. Resolution therefore returns
//! a list, and a condition holds when *any* selected value satisfies it. That
//! choice is deliberate and it is the security-relevant one: a rule that denies
//! writes under `/etc` must fire when one entry out of fifty is under `/etc`,
//! not only when all fifty are. Existential matching is the safe reading for
//! deny rules, which is what these conditions are mostly used for.
//!
//! # An absent path selects nothing
//!
//! Resolving a path that is not present yields an empty list, and a condition
//! over an empty list is false. This is the sharp edge of the whole policy
//! language, so it is worth stating plainly: a rule that says "deny when `path`
//! contains `..`" does **not** fire on a call that omits `path` entirely.
//!
//! That is why the default decision must be `deny`. Under default-deny, a call
//! that dodges every condition falls through to the default and is refused.
//! Under default-allow, the same call sails past every deny rule that could not
//! evaluate. The engine warns about this in validation rather than trusting
//! operators to rediscover it. See [`crate::rule::Predicate::Exists`] for the
//! condition that tests presence directly.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// One step of a path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// A literal key or index. Applied to objects by name and to arrays by
    /// position, so `0` addresses both `{"0": ...}` and the first element.
    Name(String),
    /// `*`: every member of the current array or object.
    Wildcard,
}

/// A compiled argument path.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub struct ArgPath {
    source: String,
    segments: Vec<Segment>,
}

impl ArgPath {
    /// Compiles a dotted path. Every string is a valid path.
    ///
    /// The empty string addresses the arguments object itself, which is useful
    /// for conditions that inspect the whole payload.
    pub fn new(source: impl Into<String>) -> Self {
        let source = source.into();
        let segments = if source.is_empty() {
            Vec::new()
        } else {
            source
                .split('.')
                .map(|part| {
                    if part == "*" {
                        Segment::Wildcard
                    } else {
                        Segment::Name(part.to_owned())
                    }
                })
                .collect()
        };
        Self { source, segments }
    }

    /// The path as written.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Whether the path selects more than one value.
    pub fn has_wildcard(&self) -> bool {
        self.segments
            .iter()
            .any(|segment| matches!(segment, Segment::Wildcard))
    }

    /// Resolves the path against a value, returning every match.
    ///
    /// Returns an empty vector when nothing matches. Callers must treat that as
    /// "no evidence", never as "condition satisfied".
    pub fn resolve<'v>(&self, root: &'v Value) -> Vec<&'v Value> {
        let mut current = vec![root];

        for segment in &self.segments {
            let mut next = Vec::new();
            for value in current {
                match segment {
                    Segment::Name(name) => match value {
                        Value::Object(map) => next.extend(map.get(name)),
                        Value::Array(items) => {
                            if let Ok(index) = name.parse::<usize>() {
                                next.extend(items.get(index));
                            }
                        }
                        _ => {}
                    },
                    Segment::Wildcard => match value {
                        Value::Object(map) => next.extend(map.values()),
                        Value::Array(items) => next.extend(items.iter()),
                        _ => {}
                    },
                }
            }
            if next.is_empty() {
                return Vec::new();
            }
            current = next;
        }

        current
    }
}

impl fmt::Debug for ArgPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ArgPath({:?})", self.source)
    }
}

impl fmt::Display for ArgPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.source.is_empty() {
            "<arguments>"
        } else {
            &self.source
        })
    }
}

impl From<String> for ArgPath {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for ArgPath {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<ArgPath> for String {
    fn from(value: ArgPath) -> Self {
        value.source
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_a_top_level_key() {
        let args = json!({ "path": "/etc/passwd", "mode": "r" });
        assert_eq!(
            ArgPath::new("path").resolve(&args),
            vec![&json!("/etc/passwd")]
        );
    }

    #[test]
    fn resolves_a_nested_key() {
        let args = json!({ "options": { "recursive": true } });
        assert_eq!(
            ArgPath::new("options.recursive").resolve(&args),
            vec![&json!(true)]
        );
    }

    #[test]
    fn resolves_an_array_index() {
        let args = json!({ "files": [{ "name": "a" }, { "name": "b" }] });
        assert_eq!(
            ArgPath::new("files.1.name").resolve(&args),
            vec![&json!("b")]
        );
    }

    #[test]
    fn a_numeric_segment_also_addresses_an_object_key() {
        let args = json!({ "counts": { "0": "zero" } });
        assert_eq!(
            ArgPath::new("counts.0").resolve(&args),
            vec![&json!("zero")]
        );
    }

    #[test]
    fn wildcard_selects_every_array_element() {
        let args = json!({ "files": [{ "path": "/a" }, { "path": "/etc/shadow" }] });
        let found = ArgPath::new("files.*.path").resolve(&args);
        assert_eq!(found, vec![&json!("/a"), &json!("/etc/shadow")]);
    }

    #[test]
    fn wildcard_selects_every_object_value() {
        let args = json!({ "env": { "HOME": "/root", "TOKEN": "sekrit" } });
        let found = ArgPath::new("env.*").resolve(&args);
        assert_eq!(found.len(), 2);
        assert!(found.contains(&&json!("sekrit")));
    }

    #[test]
    fn nested_wildcards_compose() {
        let args = json!({ "jobs": [{ "steps": [{ "run": "curl evil.sh" }] }] });
        assert_eq!(
            ArgPath::new("jobs.*.steps.*.run").resolve(&args),
            vec![&json!("curl evil.sh")]
        );
    }

    #[test]
    fn an_empty_path_selects_the_arguments_object() {
        let args = json!({ "a": 1 });
        assert_eq!(ArgPath::new("").resolve(&args), vec![&args]);
    }

    #[test]
    fn a_missing_path_selects_nothing() {
        // The trap the module docs warn about. A condition over this result is
        // false, so a deny rule keyed on an absent argument does not fire and
        // the call falls through to the default decision.
        let args = json!({ "path": "/tmp/x" });
        assert!(ArgPath::new("recursive").resolve(&args).is_empty());
        assert!(ArgPath::new("options.recursive").resolve(&args).is_empty());
        assert!(ArgPath::new("path.nested").resolve(&args).is_empty());
    }

    #[test]
    fn descending_through_a_scalar_selects_nothing() {
        let args = json!({ "path": "/tmp/x" });
        assert!(ArgPath::new("path.0").resolve(&args).is_empty());
        assert!(ArgPath::new("path.*").resolve(&args).is_empty());
    }

    #[test]
    fn an_out_of_range_index_selects_nothing() {
        let args = json!({ "files": ["a"] });
        assert!(ArgPath::new("files.7").resolve(&args).is_empty());
    }

    #[test]
    fn a_null_value_is_still_a_value() {
        // Present-but-null is distinct from absent, and an Exists condition
        // must be able to tell them apart.
        let args = json!({ "path": null });
        assert_eq!(ArgPath::new("path").resolve(&args), vec![&json!(null)]);
    }

    #[test]
    fn reports_whether_a_path_fans_out() {
        assert!(ArgPath::new("files.*.path").has_wildcard());
        assert!(!ArgPath::new("files.0.path").has_wildcard());
    }

    #[test]
    fn round_trips_through_serde_as_a_plain_string() {
        let path = ArgPath::new("options.recursive");
        assert_eq!(
            serde_json::to_string(&path).unwrap(),
            "\"options.recursive\""
        );
        let decoded: ArgPath = serde_json::from_str("\"options.recursive\"").unwrap();
        assert_eq!(decoded, path);
    }
}
