//! The gateway: an MCP server to the client, an MCP client to each upstream.
//!
//! # A denial is a tool result, not a protocol error
//!
//! Refusing a call returns a successful JSON-RPC response carrying
//! `isError: true` and a message naming the rule. It is tempting to return a
//! JSON-RPC error instead, since the call did fail, but the two reach different
//! audiences. A protocol error is handled by the client library and the model
//! often never learns why its call did not happen, so it retries the same call.
//! An `isError` result is placed in the context, so the agent can read "denied
//! by policy rule deny-shell" and pick a different approach.
//!
//! Naming the rule is a deliberate disclosure. The id is a label the operator
//! wrote, not a secret, and withholding it produces agents that thrash.
//!
//! # What is forwarded and what is not
//!
//! `initialize`, `tools/list`, `tools/call`, and `ping` are answered here. The
//! gateway synthesises its own handshake rather than proxying one upstream's,
//! because there are several upstreams and their capabilities have to be merged
//! into one answer. Everything else is refused with `METHOD_NOT_FOUND` rather
//! than guessed at: resources and prompts are real MCP features that portcullis
//! does not yet mediate, and quietly forwarding them would put content in the
//! model's context that no policy ever saw. `docs/architecture.md` tracks that
//! gap, and it is one of the better places to contribute.

use crate::inspect::{Inspection, InspectionConfig, inspect};
use crate::ratelimit::{LimitScope, RateLimiter, Verdict};
use crate::registry::ToolRegistry;
use crate::upstream::{Upstream, UpstreamConfig, UpstreamError};
use portcullis_core::mcp::{
    CallToolParams, CallToolResult, Implementation, InitializeResult, ListChangedCapability,
    ListToolsResult, ServerCapabilities,
};
use portcullis_core::{
    ErrorObject, Message, MessageReader, MessageWriter, Request, Response, error_code, method,
};
use portcullis_policy::{CallContext, Decision, DecisionSource, Policy};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

/// Gateway settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// The upstream servers to front.
    #[serde(default, rename = "server")]
    pub servers: Vec<UpstreamConfig>,
    /// Namespace separator for published tool names.
    #[serde(default)]
    pub separator: Option<String>,
    /// How results are scanned on the way back to the client.
    #[serde(default)]
    pub inspection: InspectionConfig,
}

/// Why the gateway could not start.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// No upstream servers were configured.
    #[error("no upstream servers configured; portcullis has nothing to front")]
    NoUpstreams,

    /// Two upstreams share a name.
    #[error(
        "upstream name {name:?} is used more than once; names must be unique to namespace and to scope policy"
    )]
    DuplicateUpstream {
        /// The repeated name.
        name: String,
    },

    /// An upstream failed to start.
    #[error(transparent)]
    Upstream(#[from] UpstreamError),
}

/// The running gateway.
#[derive(Debug)]
pub struct Gateway {
    upstreams: HashMap<String, Arc<Upstream>>,
    registry: ToolRegistry,
    policy: Policy,
    inspection: InspectionConfig,
    /// Buckets for this session, keyed by the id of the rule that allowed the
    /// call. Behind a std Mutex because the check is a few arithmetic
    /// operations and is never held across an await.
    limiter: std::sync::Mutex<RateLimiter>,
    server_info: Implementation,
}

impl Gateway {
    /// Starts every configured upstream and builds the merged tool list.
    ///
    /// Startup is all-or-nothing. A gateway that came up with two of its three
    /// servers would present a tool list that silently differs from the
    /// configuration, and the agent would work around the gap rather than
    /// reporting it.
    pub async fn start(config: &GatewayConfig, policy: Policy) -> Result<Self, GatewayError> {
        if config.servers.is_empty() {
            return Err(GatewayError::NoUpstreams);
        }

        let mut seen = std::collections::HashSet::new();
        for server in &config.servers {
            if !seen.insert(server.name.as_str()) {
                return Err(GatewayError::DuplicateUpstream {
                    name: server.name.clone(),
                });
            }
        }

        let client_info = Implementation::new("portcullis", env!("CARGO_PKG_VERSION"));
        let mut registry = ToolRegistry::new();
        if let Some(separator) = &config.separator {
            registry = registry.with_separator(separator.clone());
        }

        let mut upstreams = HashMap::new();
        for server in &config.servers {
            let upstream = Upstream::spawn(server, client_info.clone()).await?;

            if upstream.advertises_tools() {
                let published = registry.register_from(&upstream).await?;
                tracing::info!(upstream = %server.name, published, "registered upstream tools");
            } else {
                tracing::info!(upstream = %server.name, "upstream advertises no tools");
            }

            upstreams.insert(server.name.clone(), Arc::new(upstream));
        }

        let limiter = RateLimiter::from_policy(&policy);
        if !limiter.is_empty() {
            tracing::info!("rate limits are in force for this session");
        }

        for skipped in registry.skipped() {
            tracing::warn!(
                upstream = %skipped.server,
                tool = %skipped.name,
                reason = %skipped.reason,
                "tool not published"
            );
        }

        Ok(Self {
            upstreams,
            registry,
            policy,
            inspection: config.inspection.clone(),
            limiter: std::sync::Mutex::new(limiter),
            server_info: Implementation::new("portcullis", env!("CARGO_PKG_VERSION")),
        })
    }

    /// The merged tool list.
    pub fn registry(&self) -> &ToolRegistry {
        &self.registry
    }

    /// The policy in force.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Serves one client connection until its stream ends.
    pub async fn serve<R, W>(&self, reader: R, writer: W) -> Result<(), std::io::Error>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut reader = MessageReader::new(reader);
        let mut writer = MessageWriter::new(writer);

        loop {
            let message = match reader.next_message().await {
                Ok(Some(message)) => message,
                Ok(None) => return Ok(()),
                Err(error) => {
                    // One unparseable line from the client is not a reason to
                    // drop a session that is otherwise healthy.
                    tracing::warn!(%error, "discarding a malformed client message");
                    continue;
                }
            };

            match message {
                Message::Request(request) => {
                    let response = self.handle(&request).await;
                    if writer.send(&Message::Response(response)).await.is_err() {
                        return Ok(());
                    }
                }
                // Notifications are one-way by definition, and the ones a
                // client sends (initialized, cancelled) need no upstream action
                // in the current design.
                Message::Notification(notification) => {
                    tracing::debug!(method = %notification.method, "client notification");
                }
                Message::Response(response) => {
                    tracing::debug!(id = %response.id, "unsolicited response from client");
                }
            }
        }
    }

    /// Answers one client request.
    pub async fn handle(&self, request: &Request) -> Response {
        match request.method.as_str() {
            method::INITIALIZE => Response::success(
                request.id.clone(),
                serde_json::to_value(self.initialize_result()).expect("handshake serialises"),
            ),
            method::PING => Response::success(request.id.clone(), json!({})),
            method::TOOLS_LIST => Response::success(
                request.id.clone(),
                serde_json::to_value(ListToolsResult {
                    tools: self.registry.tools().to_vec(),
                    ..Default::default()
                })
                .expect("tool list serialises"),
            ),
            method::TOOLS_CALL => self.handle_tools_call(request).await,
            other => Response::error(
                request.id.clone(),
                ErrorObject::new(
                    error_code::METHOD_NOT_FOUND,
                    format!("portcullis does not mediate {other:?}, so it does not forward it"),
                ),
            ),
        }
    }

    /// The handshake portcullis presents to its client.
    ///
    /// Synthesised rather than proxied. Tool support is advertised whenever any
    /// upstream has tools. `listChanged` is reported as false because the
    /// gateway does not yet forward upstream list-change notifications, and
    /// claiming a capability that is not wired up is worse than omitting it.
    fn initialize_result(&self) -> InitializeResult {
        InitializeResult {
            protocol_version: portcullis_core::PREFERRED_PROTOCOL_VERSION.to_owned(),
            capabilities: ServerCapabilities {
                tools: (!self.registry.tools().is_empty()).then(|| ListChangedCapability {
                    list_changed: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            },
            server_info: self.server_info.clone(),
            instructions: Some(
                "Tool calls through this gateway are subject to policy. A refusal names the \
                 rule that produced it; treat it as final and choose another approach rather \
                 than retrying the same call."
                    .to_owned(),
            ),
            extra: serde_json::Map::new(),
        }
    }

    async fn handle_tools_call(&self, request: &Request) -> Response {
        let params = match parse_call_params(request) {
            Ok(params) => params,
            Err(error) => return Response::error(request.id.clone(), error),
        };

        let Some(route) = self.registry.route(&params.name) else {
            return Response::error(
                request.id.clone(),
                ErrorObject::new(
                    error_code::UNKNOWN_TOOL,
                    format!("no upstream exposes a tool named {:?}", params.name),
                ),
            );
        };

        let decision = self.policy.evaluate(&CallContext::new(
            &route.server,
            &params.name,
            params.arguments.as_ref(),
        ));

        if !decision.is_allowed() {
            tracing::info!(
                tool = %params.name,
                upstream = %route.server,
                rule = decision.rule_id().unwrap_or("<default>"),
                "denied"
            );
            return Response::success(request.id.clone(), denial_result(&params.name, &decision));
        }

        // Policy said yes; the limiter decides whether it may say yes again.
        // The lock is taken and dropped here, never held across the await below.
        if let Verdict::Limited { retry_after, scope } = self.check_rate_limit(&decision) {
            tracing::info!(
                tool = %params.name,
                rule = decision.rule_id().unwrap_or("<default>"),
                retry_after_s = retry_after.as_secs(),
                "rate limited"
            );
            return Response::success(
                request.id.clone(),
                rate_limited_result(&params.name, &decision, retry_after, scope),
            );
        }

        let Some(upstream) = self.upstreams.get(&route.server) else {
            return Response::error(
                request.id.clone(),
                ErrorObject::new(
                    error_code::UPSTREAM_UNAVAILABLE,
                    format!("upstream {:?} is not connected", route.server),
                ),
            );
        };

        // The upstream knows the tool by its own name, not the namespaced one.
        let forwarded = CallToolParams {
            name: route.upstream_name.clone(),
            arguments: params.arguments.clone(),
            extra: params.extra.clone(),
        };

        match upstream
            .request(
                method::TOOLS_CALL,
                Some(serde_json::to_value(forwarded).expect("call params serialise")),
            )
            .await
        {
            Ok(value) => {
                let (value, report) = self.inspect_result(&params.name, value);
                if !report.is_clean() {
                    tracing::info!(
                        tool = %params.name,
                        injection = report.injection.len(),
                        secrets = report.secrets.len(),
                        unicode = report.unicode.len(),
                        blocked = report.blocked,
                        "scanners found something in a tool result"
                    );
                }
                Response::success(request.id.clone(), value)
            }
            Err(error) => {
                tracing::warn!(tool = %params.name, %error, "upstream call failed");
                // An upstream failure is reported to the model as a tool error
                // for the same reason a denial is: so it can react rather than
                // stall on a protocol error it never sees.
                Response::success(
                    request.id.clone(),
                    serde_json::to_value(CallToolResult::error(format!(
                        "portcullis could not complete this call: {error}"
                    )))
                    .expect("result serialises"),
                )
            }
        }
    }

    /// Charges a token against the deciding rule's bucket and the session's.
    ///
    /// A call allowed by the policy default has no rule to charge, so only the
    /// session limit applies to it. That is the right reading: the default is
    /// not a rule an operator wrote a limit on.
    fn check_rate_limit(&self, decision: &Decision) -> Verdict {
        let key = match &decision.source {
            DecisionSource::Rule { id, .. } => id.as_str(),
            DecisionSource::Default => "",
        };

        match self.limiter.lock() {
            Ok(mut limiter) => limiter.check(key),
            // A poisoned lock means another task panicked mid-check. Failing
            // closed here would take the whole session down over one bucket, so
            // the call proceeds and the poisoning is recorded.
            Err(poisoned) => {
                tracing::error!("rate limiter lock was poisoned; allowing the call");
                poisoned.into_inner().check(key)
            }
        }
    }

    /// Runs the scanners over an upstream result.
    ///
    /// A result that will not deserialise into a `CallToolResult` is returned
    /// unchanged rather than rejected. Refusing it would break every server
    /// whose result shape this build does not model, and the passthrough is
    /// recorded as uninspected rather than reported as clean.
    fn inspect_result(&self, tool: &str, value: Value) -> (Value, Inspection) {
        let Ok(mut result) = serde_json::from_value::<CallToolResult>(value.clone()) else {
            tracing::debug!(
                tool,
                "result shape not recognised; forwarded without inspection"
            );
            return (value, Inspection::default());
        };

        let report = inspect(&mut result, &self.inspection);
        if report.is_clean() {
            // Nothing changed, so return the original bytes rather than a
            // re-serialised approximation of them.
            return (value, report);
        }

        match serde_json::to_value(&result) {
            Ok(rewritten) => (rewritten, report),
            Err(error) => {
                tracing::error!(tool, %error, "could not re-serialise a scanned result");
                (value, report)
            }
        }
    }

    /// Shuts every upstream down.
    pub async fn shutdown(&self) {
        for upstream in self.upstreams.values() {
            upstream.shutdown().await;
        }
    }
}

/// Parses `tools/call` parameters, or produces the error to return.
///
/// Split out of the handler so the enforcement path reads as a sequence of
/// decisions rather than being prefixed by twenty lines of deserialisation.
fn parse_call_params(request: &Request) -> Result<CallToolParams, ErrorObject> {
    let Some(raw) = request.params.clone() else {
        return Err(ErrorObject::new(
            error_code::INVALID_PARAMS,
            "tools/call requires params",
        ));
    };

    serde_json::from_value(raw).map_err(|error| {
        ErrorObject::new(
            error_code::INVALID_PARAMS,
            format!("unusable tools/call params: {error}"),
        )
    })
}

/// Builds the `isError` result that a denied call returns.
fn denial_result(tool: &str, decision: &Decision) -> Value {
    let mut result = CallToolResult::error(format!(
        "portcullis denied {tool}: {}. This is a policy decision, not a transient failure; \
         retrying the same call will produce the same result.",
        decision.reason()
    ));

    // Structured detail alongside the prose, so a client that wants to surface
    // the deciding rule in its own UI does not have to parse the sentence.
    result.extra.insert(
        "_portcullis".to_owned(),
        json!({
            "decision": "deny",
            "rule": decision.rule_id(),
            "tool": tool,
        }),
    );

    serde_json::to_value(result).expect("denial result serialises")
}

/// Builds the `isError` result that a rate-limited call returns.
///
/// Distinct wording from a policy denial on purpose. A denial is permanent and
/// the agent should choose another approach; a rate limit is temporary and
/// retrying later is exactly the right response, so the message says which one
/// this is and how long to wait.
fn rate_limited_result(
    tool: &str,
    decision: &Decision,
    retry_after: std::time::Duration,
    scope: LimitScope,
) -> Value {
    let seconds = retry_after.as_secs().max(1);

    // Named from the bucket that actually ran out, not from whether a rule
    // decided the call. A call a rule allowed can still be stopped by the
    // session limit, and pointing the operator at the rule's line would send
    // them hunting for a limit that is not the binding one.
    let scope_text = match (scope, decision.rule_id()) {
        (LimitScope::Session, _) => "the session rate limit".to_owned(),
        (LimitScope::Rule, Some(rule)) => format!("the rate limit on policy rule {rule:?}"),
        (LimitScope::Rule, None) => "a rate limit".to_owned(),
    };

    let mut result = CallToolResult::error(format!(
        "portcullis rate limited {tool}: {scope_text} is exhausted. This is temporary, unlike a policy          denial; retry in about {seconds}s."
    ));

    result.extra.insert(
        "_portcullis".to_owned(),
        json!({
            "decision": "rate_limited",
            "scope": match scope {
                LimitScope::Session => "session",
                LimitScope::Rule => "rule",
            },
            "rule": decision.rule_id(),
            "tool": tool,
            "retry_after_seconds": seconds,
        }),
    );

    serde_json::to_value(result).expect("rate limit result serialises")
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_core::Tool;
    use portcullis_policy::Action;

    fn gateway(policy_text: &str, tools: &[&str]) -> Gateway {
        let (policy, _) = portcullis_policy::load::from_str(policy_text).expect("policy loads");
        let policy_for_limiter = policy.clone();
        let mut registry = ToolRegistry::new();
        registry.register("fs", tools.iter().map(|n| Tool::new(*n)).collect());

        Gateway {
            upstreams: HashMap::new(),
            registry,
            policy,
            inspection: InspectionConfig::default(),
            limiter: std::sync::Mutex::new(RateLimiter::from_policy(&policy_for_limiter)),
            server_info: Implementation::new("portcullis", "0.1.0"),
        }
    }

    fn call(tool: &str, arguments: &Value) -> Request {
        Request::new(
            1,
            method::TOOLS_CALL,
            Some(json!({ "name": tool, "arguments": arguments })),
        )
    }

    fn tool_result(response: &Response) -> CallToolResult {
        serde_json::from_value(response.result().expect("a success response").clone())
            .expect("a tool result")
    }

    const ALLOW_READS: &str = r#"
        default = "deny"
        [[rule]]
        id = "allow-reads"
        tools = ["fs__read_file"]
        action = "allow"
    "#;

    #[tokio::test]
    async fn advertises_the_merged_tool_list() {
        let gateway = gateway(ALLOW_READS, &["read_file", "write_file"]);
        let response = gateway
            .handle(&Request::new(1, method::TOOLS_LIST, None))
            .await;

        let listed: ListToolsResult =
            serde_json::from_value(response.result().unwrap().clone()).unwrap();
        assert_eq!(
            listed
                .tools
                .iter()
                .map(|t| t.name.as_str())
                .collect::<Vec<_>>(),
            vec!["fs__read_file", "fs__write_file"]
        );
    }

    #[tokio::test]
    async fn the_handshake_only_claims_capabilities_that_are_wired_up() {
        let gateway = gateway(ALLOW_READS, &["read_file"]);
        let response = gateway
            .handle(&Request::new(1, method::INITIALIZE, None))
            .await;

        let result: InitializeResult =
            serde_json::from_value(response.result().unwrap().clone()).unwrap();
        assert_eq!(result.server_info.name, "portcullis");
        assert_eq!(
            result.capabilities.tools.unwrap().list_changed,
            Some(false),
            "list_changed must not be claimed while notifications are unforwarded"
        );
    }

    #[tokio::test]
    async fn a_denial_is_a_tool_error_that_names_the_rule() {
        // The central behaviour: the model has to be able to read why.
        let policy = r#"
            default = "allow"
            [[rule]]
            id = "deny-writes"
            description = "Writes need a human"
            tools = ["fs__write_file"]
            action = "deny"
        "#;
        let gateway = gateway(policy, &["read_file", "write_file"]);

        let response = gateway
            .handle(&call("fs__write_file", &json!({ "path": "/tmp/x" })))
            .await;

        assert!(
            !response.is_error(),
            "a denial is a successful response carrying isError"
        );
        let result = tool_result(&response);
        assert!(result.failed());

        let text = result.content[0].as_text().expect("text content");
        assert!(text.contains("deny-writes"), "{text}");
        assert!(text.contains("Writes need a human"), "{text}");
        assert!(text.contains("retrying the same call"), "{text}");

        assert_eq!(result.extra["_portcullis"]["rule"], json!("deny-writes"));
    }

    #[tokio::test]
    async fn a_call_matching_no_rule_takes_the_default() {
        let gateway = gateway(ALLOW_READS, &["read_file", "write_file"]);
        let response = gateway.handle(&call("fs__write_file", &json!({}))).await;

        let result = tool_result(&response);
        assert!(result.failed());
        assert_eq!(
            result.extra["_portcullis"]["rule"],
            Value::Null,
            "the default has no rule id"
        );
        assert_eq!(gateway.policy().default_action(), Action::Deny);
    }

    #[tokio::test]
    async fn an_unknown_tool_is_a_protocol_error() {
        // Distinct from a denial: the tool does not exist, so there is no
        // policy question to answer and nothing for the model to work around.
        let gateway = gateway(ALLOW_READS, &["read_file"]);
        let response = gateway.handle(&call("fs__nonexistent", &json!({}))).await;

        assert_eq!(response.err().unwrap().code, error_code::UNKNOWN_TOOL);
    }

    #[tokio::test]
    async fn unmediated_methods_are_refused_rather_than_forwarded() {
        // Forwarding resources/read would put content in the model's context
        // that no policy inspected.
        let gateway = gateway(ALLOW_READS, &["read_file"]);
        let response = gateway
            .handle(&Request::new(1, method::RESOURCES_READ, None))
            .await;

        let error = response.err().expect("an error");
        assert_eq!(error.code, error_code::METHOD_NOT_FOUND);
        assert!(
            error.message.contains("does not mediate"),
            "{}",
            error.message
        );
    }

    #[tokio::test]
    async fn malformed_call_params_are_rejected_with_a_reason() {
        let gateway = gateway(ALLOW_READS, &["read_file"]);
        let response = gateway
            .handle(&Request::new(
                1,
                method::TOOLS_CALL,
                Some(json!({ "nope": 1 })),
            ))
            .await;

        assert_eq!(response.err().unwrap().code, error_code::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn ping_is_answered_locally() {
        let gateway = gateway(ALLOW_READS, &["read_file"]);
        let response = gateway.handle(&Request::new(1, method::PING, None)).await;
        assert_eq!(response.result(), Some(&json!({})));
    }

    #[tokio::test]
    async fn starting_without_upstreams_fails_loudly() {
        let config = GatewayConfig {
            servers: Vec::new(),
            separator: None,
            inspection: InspectionConfig::default(),
        };
        let error = Gateway::start(&config, Policy::default())
            .await
            .unwrap_err();
        assert!(matches!(error, GatewayError::NoUpstreams), "{error}");
    }

    #[tokio::test]
    async fn duplicate_upstream_names_are_refused_before_anything_starts() {
        let server = |name: &str| UpstreamConfig {
            name: name.to_owned(),
            command: "true".to_owned(),
            args: Vec::new(),
            env: HashMap::new(),
            cwd: None,
        };
        let config = GatewayConfig {
            servers: vec![server("fs"), server("fs")],
            separator: None,
            inspection: InspectionConfig::default(),
        };

        let error = Gateway::start(&config, Policy::default())
            .await
            .unwrap_err();
        assert!(
            matches!(error, GatewayError::DuplicateUpstream { .. }),
            "{error}"
        );
    }
}
