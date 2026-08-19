//! The portcullis policy language.
//!
//! A policy is an ordered list of rules plus a default. Evaluating a tool call
//! walks the rules in order, and the first one that applies decides. Nothing in
//! this crate performs IO or knows what an upstream server is, which is what
//! lets the whole language be tested against plain JSON values.
//!
//! ```
//! use portcullis_policy::{Action, Rule};
//! use serde_json::json;
//!
//! let rule: Rule = toml::from_str(
//!     r#"
//!     id = "deny-credential-paths"
//!     tools = ["fs.*"]
//!     action = "deny"
//!     when = [{ arg = "path", matches = "(^|/)\\.(ssh|aws)(/|$)" }]
//!     "#,
//! )?;
//!
//! assert_eq!(rule.action, Action::Deny);
//! assert!(rule.applies_to("local-fs", "fs.read_file", Some(&json!({ "path": "/home/u/.ssh/id_rsa" }))));
//! assert!(!rule.applies_to("local-fs", "fs.read_file", Some(&json!({ "path": "/home/u/notes.md" }))));
//! # Ok::<(), toml::de::Error>(())
//! ```

#![doc(html_root_url = "https://docs.rs/portcullis-policy/0.1.0")]

pub mod argpath;
pub mod engine;
pub mod glob;
pub mod load;
pub mod rule;

pub use argpath::ArgPath;
pub use engine::{
    CallContext, Decision, DecisionSource, Explanation, Policy, RuleTrace, TraceOutcome,
};
pub use glob::Pattern;
pub use load::{Diagnostic, LoadError, Severity};
pub use rule::{Action, Condition, Predicate, Rule, RuleError};
