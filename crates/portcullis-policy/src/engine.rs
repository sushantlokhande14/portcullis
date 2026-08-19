//! Evaluating a call against a policy.
//!
//! Rules are ordered and the first one that applies decides. First-match-wins
//! was chosen over the alternatives (deny-overrides, most-specific-wins) for one
//! reason: it is the only ordering where the answer to "why was this denied?" is
//! a single rule that a person can read. Deny-overrides requires scanning every
//! rule to know none of them objected, and most-specific-wins requires the
//! reader to hold a specificity metric in their head. Both make an incident
//! harder, and a policy nobody can reason about under pressure is a policy that
//! gets switched off.
//!
//! The cost is that rule order matters, which is a real footgun: a broad allow
//! near the top silently shadows every narrow deny below it. That is what
//! [`Policy::explain`] and the unreachable-rule validation exist to surface.
//!
//! # The default is the whole security posture
//!
//! A call matching no rule takes [`Policy::default_action`]. Given that an
//! absent argument makes a condition false (see [`crate::argpath`]), a call
//! crafted to dodge every deny rule reaches the default, so `deny` there is
//! what makes the language safe rather than merely expressive.

use crate::rule::{Action, Rule};
use serde::Deserialize;
use serde_json::Value;

/// The call being decided.
#[derive(Debug, Clone, Copy)]
pub struct CallContext<'a> {
    /// The upstream server that owns the tool.
    pub server: &'a str,
    /// The namespaced tool name, as the client sees it.
    pub tool: &'a str,
    /// The call arguments, if any were supplied.
    pub arguments: Option<&'a Value>,
}

impl<'a> CallContext<'a> {
    /// Builds a context.
    pub fn new(server: &'a str, tool: &'a str, arguments: Option<&'a Value>) -> Self {
        Self {
            server,
            tool,
            arguments,
        }
    }
}

/// What produced a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionSource {
    /// A rule applied.
    Rule {
        /// The rule's id.
        id: String,
        /// Its position in the policy, zero-based, for pointing at a line.
        index: usize,
        /// The rule's description, if it had one.
        description: Option<String>,
    },
    /// No rule applied, so the policy default was used.
    Default,
}

/// The outcome of evaluating a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Whether the call may proceed.
    pub action: Action,
    /// What decided it.
    pub source: DecisionSource,
}

impl Decision {
    /// Whether the call may proceed.
    pub fn is_allowed(&self) -> bool {
        self.action.is_allow()
    }

    /// The id of the deciding rule, or `None` when the default decided.
    pub fn rule_id(&self) -> Option<&str> {
        match &self.source {
            DecisionSource::Rule { id, .. } => Some(id),
            DecisionSource::Default => None,
        }
    }

    /// A one-line explanation suitable for showing to the model.
    ///
    /// Denials name the rule. Telling the agent *which* rule refused lets it
    /// choose a different approach instead of retrying the same call, and the
    /// rule id is not sensitive: it is a label the operator wrote.
    pub fn reason(&self) -> String {
        match &self.source {
            DecisionSource::Rule {
                id, description, ..
            } => match description {
                Some(text) => format!("{} by policy rule {id:?}: {text}", self.action),
                None => format!("{} by policy rule {id:?}", self.action),
            },
            DecisionSource::Default => {
                format!(
                    "{} by policy default; no rule matched this call",
                    self.action
                )
            }
        }
    }
}

/// Why a rule did not decide a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceOutcome {
    /// The rule applied and produced the decision.
    Applied,
    /// The rule is restricted to other upstream servers.
    ServerMismatch,
    /// The rule's tool patterns do not cover this tool.
    ToolMismatch,
    /// The rule covered the tool but a condition did not hold.
    ConditionUnmet {
        /// The failing condition, rendered as written.
        condition: String,
    },
    /// Evaluation stopped before reaching this rule.
    NotReached,
}

/// One rule's part in a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleTrace {
    /// Position in the policy, zero-based.
    pub index: usize,
    /// The rule's id.
    pub id: String,
    /// What the rule would have done.
    pub action: Action,
    /// Why it did or did not decide.
    pub outcome: TraceOutcome,
}

/// A decision plus the reasoning that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    /// The decision reached.
    pub decision: Decision,
    /// Every rule, in policy order, and its part in the outcome.
    pub trace: Vec<RuleTrace>,
}

/// An ordered rule list plus a default.
#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    /// Applied when no rule matches.
    #[serde(default = "default_action", rename = "default")]
    default_action: Action,
    /// The rules, in evaluation order.
    #[serde(default, rename = "rule")]
    rules: Vec<Rule>,
}

fn default_action() -> Action {
    Action::Deny
}

impl Default for Policy {
    /// A policy that denies everything.
    ///
    /// This is the correct empty state: a gateway with no rules loaded should
    /// refuse calls, not forward them.
    fn default() -> Self {
        Self {
            default_action: Action::Deny,
            rules: Vec::new(),
        }
    }
}

impl Policy {
    /// Builds a policy from a default and an ordered rule list.
    pub fn new(default_action: Action, rules: Vec<Rule>) -> Self {
        Self {
            default_action,
            rules,
        }
    }

    /// The action taken when no rule matches.
    pub fn default_action(&self) -> Action {
        self.default_action
    }

    /// The rules, in evaluation order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Decides a call.
    ///
    /// Stops at the first applicable rule, so a policy with many rules costs
    /// only as much as the prefix before the match.
    pub fn evaluate(&self, call: &CallContext<'_>) -> Decision {
        for (index, rule) in self.rules.iter().enumerate() {
            if rule.applies_to(call.server, call.tool, call.arguments) {
                return Decision {
                    action: rule.action,
                    source: DecisionSource::Rule {
                        id: rule.id.clone(),
                        index,
                        description: rule.description.clone(),
                    },
                };
            }
        }

        Decision {
            action: self.default_action,
            source: DecisionSource::Default,
        }
    }

    /// Decides a call and records why every rule did or did not apply.
    ///
    /// This is what `portcullis explain` prints. It costs a full pass over the
    /// rules where [`Policy::evaluate`] short-circuits, which is why it is a
    /// separate entry point rather than the hot path.
    pub fn explain(&self, call: &CallContext<'_>) -> Explanation {
        let mut trace = Vec::with_capacity(self.rules.len());
        let mut decision = None;

        for (index, rule) in self.rules.iter().enumerate() {
            if decision.is_some() {
                trace.push(RuleTrace {
                    index,
                    id: rule.id.clone(),
                    action: rule.action,
                    outcome: TraceOutcome::NotReached,
                });
                continue;
            }

            let outcome = if !rule.matches_server(call.server) {
                TraceOutcome::ServerMismatch
            } else if !rule.matches_tool(call.tool) {
                TraceOutcome::ToolMismatch
            } else if let Some(unmet) = rule.first_unmet_condition(call.arguments) {
                TraceOutcome::ConditionUnmet {
                    condition: unmet.describe(),
                }
            } else {
                decision = Some(Decision {
                    action: rule.action,
                    source: DecisionSource::Rule {
                        id: rule.id.clone(),
                        index,
                        description: rule.description.clone(),
                    },
                });
                TraceOutcome::Applied
            };

            trace.push(RuleTrace {
                index,
                id: rule.id.clone(),
                action: rule.action,
                outcome,
            });
        }

        let decision = decision.unwrap_or(Decision {
            action: self.default_action,
            source: DecisionSource::Default,
        });

        Explanation { decision, trace }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy(text: &str) -> Policy {
        toml::from_str(text).expect("policy parses")
    }

    const SAMPLE: &str = r#"
        default = "deny"

        [[rule]]
        id = "allow-reads"
        description = "Reading files is fine"
        tools = ["fs.read_*", "fs.list_*"]
        action = "allow"

        [[rule]]
        id = "deny-credential-paths"
        tools = ["fs.*"]
        action = "deny"
        when = [{ arg = "path", matches = "(^|/)\\.(ssh|aws)(/|$)" }]

        [[rule]]
        id = "allow-github-reads"
        servers = ["github"]
        tools = ["*"]
        action = "allow"
        when = [{ arg = "write", not = true, equals = true }]
    "#;

    #[test]
    fn the_first_applicable_rule_decides() {
        let policy = policy(SAMPLE);
        let args = json!({ "path": "/home/u/notes.md" });
        let decision = policy.evaluate(&CallContext::new("fs", "fs.read_file", Some(&args)));

        assert!(decision.is_allowed());
        assert_eq!(decision.rule_id(), Some("allow-reads"));
    }

    #[test]
    fn an_earlier_allow_shadows_a_later_deny() {
        // The documented footgun of first-match-wins, pinned so nobody "fixes"
        // the ordering into deny-overrides without noticing what changes.
        let policy = policy(SAMPLE);
        let args = json!({ "path": "/home/u/.ssh/id_rsa" });
        let decision = policy.evaluate(&CallContext::new("fs", "fs.read_file", Some(&args)));

        assert!(
            decision.is_allowed(),
            "allow-reads sits above deny-credential-paths"
        );
        assert_eq!(decision.rule_id(), Some("allow-reads"));
    }

    #[test]
    fn a_later_deny_applies_when_no_earlier_rule_matched() {
        let policy = policy(SAMPLE);
        let args = json!({ "path": "/home/u/.aws/credentials" });
        let decision = policy.evaluate(&CallContext::new("fs", "fs.write_file", Some(&args)));

        assert!(!decision.is_allowed());
        assert_eq!(decision.rule_id(), Some("deny-credential-paths"));
        assert!(
            decision.reason().contains("deny-credential-paths"),
            "{}",
            decision.reason()
        );
    }

    #[test]
    fn an_unmatched_call_takes_the_default() {
        let policy = policy(SAMPLE);
        let decision = policy.evaluate(&CallContext::new("postgres", "db.query", None));

        assert!(!decision.is_allowed());
        assert_eq!(decision.rule_id(), None);
        assert_eq!(decision.source, DecisionSource::Default);
        assert!(
            decision.reason().contains("no rule matched"),
            "{}",
            decision.reason()
        );
    }

    #[test]
    fn a_call_that_dodges_every_condition_still_hits_the_default() {
        // The reason default-deny matters. `path` is absent, so the deny rule's
        // condition cannot hold and the rule does not apply, yet the call is
        // still refused because nothing allowed it.
        let policy = policy(SAMPLE);
        let decision = policy.evaluate(&CallContext::new("fs", "fs.write_file", Some(&json!({}))));

        assert!(!decision.is_allowed());
        assert_eq!(decision.source, DecisionSource::Default);
    }

    #[test]
    fn server_restrictions_are_honoured() {
        let policy = policy(SAMPLE);
        let args = json!({ "write": false });

        let allowed = policy.evaluate(&CallContext::new("github", "gh.list_issues", Some(&args)));
        assert!(allowed.is_allowed());
        assert_eq!(allowed.rule_id(), Some("allow-github-reads"));

        let denied = policy.evaluate(&CallContext::new("gitlab", "gl.list_issues", Some(&args)));
        assert!(
            !denied.is_allowed(),
            "the rule is restricted to the github upstream"
        );
        assert_eq!(denied.source, DecisionSource::Default);
    }

    #[test]
    fn an_empty_policy_denies_everything() {
        let policy = Policy::default();
        assert_eq!(policy.default_action(), Action::Deny);
        assert!(
            !policy
                .evaluate(&CallContext::new("any", "any.tool", None))
                .is_allowed()
        );
    }

    #[test]
    fn a_policy_file_without_a_default_denies() {
        // Omitting the default must not quietly mean "allow".
        let policy = policy("[[rule]]\nid = \"r\"\ntools = [\"x\"]\naction = \"allow\"");
        assert_eq!(policy.default_action(), Action::Deny);
    }

    #[test]
    fn explain_records_why_each_rule_did_not_apply() {
        let policy = policy(SAMPLE);
        let args = json!({ "path": "/home/u/.ssh/id_rsa" });
        let explained = policy.explain(&CallContext::new("fs", "fs.write_file", Some(&args)));

        assert_eq!(explained.decision.rule_id(), Some("deny-credential-paths"));
        assert_eq!(explained.trace.len(), 3);
        assert_eq!(explained.trace[0].outcome, TraceOutcome::ToolMismatch);
        assert_eq!(explained.trace[1].outcome, TraceOutcome::Applied);
        assert_eq!(explained.trace[2].outcome, TraceOutcome::NotReached);
    }

    #[test]
    fn explain_names_the_condition_that_failed() {
        let policy = policy(SAMPLE);
        let args = json!({ "path": "/home/u/notes.md" });
        let explained = policy.explain(&CallContext::new("fs", "fs.write_file", Some(&args)));

        let TraceOutcome::ConditionUnmet { condition } = &explained.trace[1].outcome else {
            panic!(
                "expected an unmet condition, got {:?}",
                explained.trace[1].outcome
            );
        };
        assert_eq!(condition, "path matches");
    }

    #[test]
    fn explain_and_evaluate_always_agree() {
        let policy = policy(SAMPLE);
        let cases = [
            CallContext::new("fs", "fs.read_file", None),
            CallContext::new("fs", "fs.write_file", None),
            CallContext::new("github", "gh.create_issue", None),
            CallContext::new("nobody", "nothing", None),
        ];

        for call in cases {
            assert_eq!(
                policy.explain(&call).decision,
                policy.evaluate(&call),
                "explain diverged from evaluate for {}/{}",
                call.server,
                call.tool
            );
        }
    }

    #[test]
    fn explain_falls_through_to_the_default_with_a_full_trace() {
        let policy = policy(SAMPLE);
        let explained = policy.explain(&CallContext::new("redis", "cache.get", None));

        assert_eq!(explained.decision.source, DecisionSource::Default);
        assert_eq!(explained.trace.len(), 3);
        assert!(
            explained
                .trace
                .iter()
                .all(|entry| entry.outcome != TraceOutcome::NotReached),
            "with no rule applying, every rule must have been examined"
        );
    }
}
