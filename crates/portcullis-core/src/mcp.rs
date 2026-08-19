//! Model Context Protocol types.
//!
//! Only the parts of MCP that portcullis actually reasons about are modelled
//! here: the initialize handshake, tool discovery, and tool invocation. Every
//! other method is forwarded as an opaque [`crate::Message`], because a gateway
//! that needs a type for each method is a gateway that breaks whenever the
//! protocol grows one.
//!
//! # Unknown fields are preserved, not dropped
//!
//! Every type that portcullis deserialises and then re-serialises carries an
//! `extra` map flattened into it. Without that, a round trip through this
//! module would quietly delete any field this build has not heard of, and the
//! client would see a lossy view of its own servers. The gateway is supposed to
//! be transparent about everything it has no opinion on.
//!
//! # Tool annotations are policy inputs
//!
//! [`ToolAnnotations`] carries the server's own claims about a tool: whether it
//! is read-only, whether it is destructive, whether it touches the open world.
//! These are hints, not guarantees, and a hostile server can lie about them.
//! They are modelled because a policy can usefully say "deny anything not
//! annotated read-only" as a backstop, but the policy engine treats a missing
//! annotation as the dangerous case rather than the safe one.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Method names portcullis recognises.
///
/// Anything not listed here is forwarded without inspection.
pub mod method {
    /// Capability negotiation, the first request of any session.
    pub const INITIALIZE: &str = "initialize";
    /// Sent by the client once it has processed the initialize result.
    pub const INITIALIZED: &str = "notifications/initialized";
    /// Liveness check.
    pub const PING: &str = "ping";
    /// Tool discovery.
    pub const TOOLS_LIST: &str = "tools/list";
    /// Tool invocation, the method every policy decision is about.
    pub const TOOLS_CALL: &str = "tools/call";
    /// Emitted by a server when its tool list changes.
    pub const TOOLS_LIST_CHANGED: &str = "notifications/tools/list_changed";
    /// Resource discovery.
    pub const RESOURCES_LIST: &str = "resources/list";
    /// Resource retrieval.
    pub const RESOURCES_READ: &str = "resources/read";
    /// Prompt discovery.
    pub const PROMPTS_LIST: &str = "prompts/list";
    /// Prompt retrieval.
    pub const PROMPTS_GET: &str = "prompts/get";
}

/// Identifies a client or server implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Implementation {
    /// Machine-readable name, for example `portcullis`.
    pub name: String,
    /// Implementation version.
    pub version: String,
    /// Human-readable display name, added in revision 2025-06-18.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Fields this build does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Implementation {
    /// Builds an implementation descriptor with no title.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            title: None,
            extra: Map::new(),
        }
    }
}

/// A capability whose only defined member is a `listChanged` flag.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListChangedCapability {
    /// Whether the peer emits a list-changed notification for this category.
    #[serde(
        default,
        rename = "listChanged",
        skip_serializing_if = "Option::is_none"
    )]
    pub list_changed: Option<bool>,
    /// Fields this build does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Resource capability, which adds subscriptions on top of `listChanged`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcesCapability {
    /// Whether the server supports per-resource subscriptions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscribe: Option<bool>,
    /// Whether the server emits a list-changed notification.
    #[serde(
        default,
        rename = "listChanged",
        skip_serializing_if = "Option::is_none"
    )]
    pub list_changed: Option<bool>,
    /// Fields this build does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What a client says it can do.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientCapabilities {
    /// The client can expose filesystem roots to the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roots: Option<ListChangedCapability>,
    /// The client will service model sampling requests from the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling: Option<Value>,
    /// The client will relay elicitation prompts to the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elicitation: Option<Value>,
    /// Fields this build does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What a server says it can do.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerCapabilities {
    /// The server exposes tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<ListChangedCapability>,
    /// The server exposes resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
    /// The server exposes prompts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompts: Option<ListChangedCapability>,
    /// The server emits log records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<Value>,
    /// The server supports argument autocompletion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completions: Option<Value>,
    /// Fields this build does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Parameters of an `initialize` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitializeParams {
    /// The revision the client wishes to speak.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// What the client can do.
    pub capabilities: ClientCapabilities,
    /// Who the client is.
    #[serde(rename = "clientInfo")]
    pub client_info: Implementation,
    /// Fields this build does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Result of an `initialize` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitializeResult {
    /// The revision the server has settled on.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// What the server can do.
    pub capabilities: ServerCapabilities,
    /// Who the server is.
    #[serde(rename = "serverInfo")]
    pub server_info: Implementation,
    /// Free-form guidance the server wants placed in the model's context.
    ///
    /// This field is attacker-reachable when the upstream server is not fully
    /// trusted, since its whole purpose is to inject text into the prompt. The
    /// proxy runs it through the same scanners as tool output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    /// Fields this build does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A server's own claims about what a tool does.
///
/// All of these are hints. A server that wants to be called will happily
/// annotate a destructive tool as read-only, so policy treats them as one
/// signal among several and never as an authorisation decision on its own.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolAnnotations {
    /// Display title for the tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The tool claims not to modify anything.
    #[serde(
        default,
        rename = "readOnlyHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub read_only_hint: Option<bool>,
    /// The tool claims its updates may be destructive.
    #[serde(
        default,
        rename = "destructiveHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub destructive_hint: Option<bool>,
    /// Repeated identical calls claim to have no additional effect.
    #[serde(
        default,
        rename = "idempotentHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub idempotent_hint: Option<bool>,
    /// The tool claims to reach systems outside the local environment.
    #[serde(
        default,
        rename = "openWorldHint",
        skip_serializing_if = "Option::is_none"
    )]
    pub open_world_hint: Option<bool>,
    /// Fields this build does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl ToolAnnotations {
    /// Whether the tool asserts it is read-only.
    ///
    /// Absent annotations return `false`. A tool that declined to say is
    /// treated as if it had said no, which is the conservative reading.
    pub fn asserts_read_only(&self) -> bool {
        self.read_only_hint == Some(true)
    }

    /// Whether the tool asserts, or declines to deny, that it is destructive.
    ///
    /// The MCP default for `destructiveHint` is `true` when the tool is not
    /// read-only, so silence is treated as destructive here too.
    pub fn may_be_destructive(&self) -> bool {
        match self.destructive_hint {
            Some(value) => value,
            None => !self.asserts_read_only(),
        }
    }
}

/// A tool as advertised by a server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tool {
    /// Unique name within its server. portcullis rewrites this when it
    /// aggregates several servers behind one endpoint.
    pub name: String,
    /// Human-readable display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// What the tool does. This text reaches the model, so it is scannable
    /// content in the same sense that tool output is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema for the arguments. Kept opaque; portcullis does not validate
    /// against it, it only matches policy against the values that arrive.
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    /// JSON Schema for structured output, if the server declares one.
    #[serde(
        default,
        rename = "outputSchema",
        skip_serializing_if = "Option::is_none"
    )]
    pub output_schema: Option<Value>,
    /// The server's claims about the tool's behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
    /// Fields this build does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Tool {
    /// Builds a tool with an empty object schema.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            title: None,
            description: None,
            input_schema: serde_json::json!({ "type": "object" }),
            output_schema: None,
            annotations: None,
            extra: Map::new(),
        }
    }
}

/// Parameters of a `tools/list` request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListToolsParams {
    /// Opaque pagination cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Fields this build does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Result of a `tools/list` request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListToolsResult {
    /// The advertised tools.
    pub tools: Vec<Tool>,
    /// Cursor for the next page, if the list was truncated.
    #[serde(
        default,
        rename = "nextCursor",
        skip_serializing_if = "Option::is_none"
    )]
    pub next_cursor: Option<String>,
    /// Fields this build does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Parameters of a `tools/call` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallToolParams {
    /// The tool to invoke.
    pub name: String,
    /// Arguments, matching the tool's input schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    /// Fields this build does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl CallToolParams {
    /// Builds call parameters.
    pub fn new(name: impl Into<String>, arguments: Option<Value>) -> Self {
        Self {
            name: name.into(),
            arguments,
            extra: Map::new(),
        }
    }
}

/// A content block whose `type` this build understands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TypedContent {
    /// Plain text. This is the variant the scanners care about.
    #[serde(rename = "text")]
    Text {
        /// The text itself.
        text: String,
        /// Fields this build does not model, such as `annotations` or `_meta`.
        #[serde(flatten)]
        extra: Map<String, Value>,
    },
    /// Base64-encoded image data.
    #[serde(rename = "image")]
    Image {
        /// Base64 payload.
        data: String,
        /// Media type of the payload.
        #[serde(rename = "mimeType")]
        mime_type: String,
        /// Fields this build does not model.
        #[serde(flatten)]
        extra: Map<String, Value>,
    },
    /// Base64-encoded audio data.
    #[serde(rename = "audio")]
    Audio {
        /// Base64 payload.
        data: String,
        /// Media type of the payload.
        #[serde(rename = "mimeType")]
        mime_type: String,
        /// Fields this build does not model.
        #[serde(flatten)]
        extra: Map<String, Value>,
    },
    /// A pointer to a resource the client may fetch separately.
    #[serde(rename = "resource_link")]
    ResourceLink {
        /// Resource URI.
        uri: String,
        /// Resource name.
        name: String,
        /// Fields this build does not model.
        #[serde(flatten)]
        extra: Map<String, Value>,
    },
    /// A resource embedded directly in the result.
    #[serde(rename = "resource")]
    Resource {
        /// The embedded resource object, kept opaque.
        resource: Value,
        /// Fields this build does not model.
        #[serde(flatten)]
        extra: Map<String, Value>,
    },
}

/// A content block.
///
/// The [`Content::Unknown`] variant is what makes this forward-compatible: a
/// block whose `type` was introduced after this build is carried through
/// verbatim rather than failing the whole response. The scanners simply have
/// nothing to say about it, which is recorded honestly in the audit log rather
/// than being reported as a clean scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Content {
    /// A block this build understands.
    Typed(TypedContent),
    /// A block this build does not understand, preserved as-is.
    Unknown(Value),
}

impl Content {
    /// Builds a text block.
    pub fn text(text: impl Into<String>) -> Self {
        Self::Typed(TypedContent::Text {
            text: text.into(),
            extra: Map::new(),
        })
    }

    /// Borrows the text of a text block, or `None` for any other block.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Typed(TypedContent::Text { text, .. }) => Some(text),
            _ => None,
        }
    }

    /// Mutably borrows the text of a text block so a scanner can rewrite it.
    pub fn as_text_mut(&mut self) -> Option<&mut String> {
        match self {
            Self::Typed(TypedContent::Text { text, .. }) => Some(text),
            _ => None,
        }
    }

    /// Whether this build understood the block's type.
    pub fn is_understood(&self) -> bool {
        matches!(self, Self::Typed(_))
    }
}

/// Result of a `tools/call` request.
///
/// Note that a failed tool call is a *successful* JSON-RPC response with
/// `isError` set, not a JSON-RPC error. The distinction matters: protocol
/// errors are invisible to the model, whereas `isError` results are handed to
/// it so it can react. portcullis denies calls the same way, as an `isError`
/// result explaining which rule refused, so the agent can choose another path
/// instead of silently stalling.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallToolResult {
    /// The content blocks returned by the tool.
    #[serde(default)]
    pub content: Vec<Content>,
    /// Structured output matching the tool's output schema.
    #[serde(
        default,
        rename = "structuredContent",
        skip_serializing_if = "Option::is_none"
    )]
    pub structured_content: Option<Value>,
    /// Whether the tool itself reported failure.
    #[serde(default, rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
    /// Fields this build does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl CallToolResult {
    /// Builds a successful single-text-block result.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![Content::text(text)],
            ..Self::default()
        }
    }

    /// Builds a failed single-text-block result.
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            content: vec![Content::text(text)],
            is_error: Some(true),
            ..Self::default()
        }
    }

    /// Whether the tool reported failure.
    pub fn failed(&self) -> bool {
        self.is_error == Some(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn initialize_params_round_trip_preserves_unknown_fields() {
        let raw = json!({
            "protocolVersion": "2025-06-18",
            "capabilities": { "roots": { "listChanged": true }, "experimental": { "x": 1 } },
            "clientInfo": { "name": "demo", "version": "1.0", "vendorTag": "acme" },
            "traceId": "abc123"
        });

        let params: InitializeParams = serde_json::from_value(raw.clone()).expect("parses");
        assert_eq!(params.protocol_version, "2025-06-18");
        assert_eq!(
            params.capabilities.roots.as_ref().unwrap().list_changed,
            Some(true)
        );

        let encoded = serde_json::to_value(&params).expect("serialises");
        assert_eq!(
            encoded, raw,
            "round trip dropped a field portcullis does not model"
        );
    }

    #[test]
    fn tool_round_trip_preserves_unknown_fields() {
        let raw = json!({
            "name": "read_file",
            "description": "Reads a file",
            "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } } },
            "annotations": { "readOnlyHint": true, "futureHint": "maybe" },
            "_meta": { "owner": "team-infra" }
        });

        let tool: Tool = serde_json::from_value(raw.clone()).expect("parses");
        assert!(tool.annotations.as_ref().unwrap().asserts_read_only());
        assert_eq!(serde_json::to_value(&tool).unwrap(), raw);
    }

    #[test]
    fn missing_annotations_are_treated_as_destructive() {
        // Silence is not consent. A tool that says nothing about itself gets
        // the conservative reading, not the convenient one.
        let none = ToolAnnotations::default();
        assert!(!none.asserts_read_only());
        assert!(none.may_be_destructive());

        let read_only = ToolAnnotations {
            read_only_hint: Some(true),
            ..Default::default()
        };
        assert!(!read_only.may_be_destructive());

        // An explicit denial of destructiveness is honoured even without a
        // read-only claim, because the server said so on the record.
        let explicit = ToolAnnotations {
            destructive_hint: Some(false),
            ..Default::default()
        };
        assert!(!explicit.may_be_destructive());
    }

    #[test]
    fn text_content_round_trips_with_annotations() {
        let raw =
            json!({ "type": "text", "text": "hello", "annotations": { "audience": ["user"] } });
        let content: Content = serde_json::from_value(raw.clone()).expect("parses");
        assert_eq!(content.as_text(), Some("hello"));
        assert!(content.is_understood());
        assert_eq!(serde_json::to_value(&content).unwrap(), raw);
    }

    #[test]
    fn unknown_content_types_survive_the_round_trip() {
        let raw = json!({ "type": "video", "data": "AAAA", "mimeType": "video/mp4" });
        let content: Content = serde_json::from_value(raw.clone()).expect("parses as unknown");
        assert!(
            !content.is_understood(),
            "a future content type must not be claimed as understood"
        );
        assert_eq!(content.as_text(), None);
        assert_eq!(serde_json::to_value(&content).unwrap(), raw);
    }

    #[test]
    fn every_typed_content_variant_round_trips() {
        let cases = vec![
            json!({ "type": "text", "text": "t" }),
            json!({ "type": "image", "data": "AAAA", "mimeType": "image/png" }),
            json!({ "type": "audio", "data": "AAAA", "mimeType": "audio/wav" }),
            json!({ "type": "resource_link", "uri": "file:///a", "name": "a" }),
            json!({ "type": "resource", "resource": { "uri": "file:///b", "text": "b" } }),
        ];

        for raw in cases {
            let content: Content = serde_json::from_value(raw.clone()).expect("parses");
            assert!(content.is_understood(), "should be typed: {raw}");
            assert_eq!(serde_json::to_value(&content).unwrap(), raw);
        }
    }

    #[test]
    fn scanners_can_rewrite_text_in_place() {
        let mut result = CallToolResult::text("secret");
        *result.content[0].as_text_mut().expect("text block") = "[redacted]".to_owned();
        assert_eq!(result.content[0].as_text(), Some("[redacted]"));
    }

    #[test]
    fn call_tool_result_defaults_to_success() {
        assert!(!CallToolResult::text("ok").failed());
        assert!(CallToolResult::error("denied").failed());
    }

    #[test]
    fn call_tool_result_omits_absent_optionals() {
        let encoded = serde_json::to_value(CallToolResult::text("ok")).unwrap();
        assert_eq!(
            encoded,
            json!({ "content": [{ "type": "text", "text": "ok" }] })
        );
    }

    #[test]
    fn list_tools_result_tolerates_a_missing_cursor() {
        let result: ListToolsResult = serde_json::from_value(json!({ "tools": [] })).unwrap();
        assert!(result.tools.is_empty());
        assert_eq!(result.next_cursor, None);
    }

    #[test]
    fn call_tool_params_accept_absent_arguments() {
        let params: CallToolParams = serde_json::from_value(json!({ "name": "ping" })).unwrap();
        assert_eq!(params.name, "ping");
        assert_eq!(params.arguments, None);
    }
}
