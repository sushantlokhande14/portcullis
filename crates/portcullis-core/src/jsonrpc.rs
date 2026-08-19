//! JSON-RPC 2.0 message types.
//!
//! MCP is JSON-RPC 2.0 with a fixed vocabulary of methods layered on top, so
//! everything here is deliberately protocol-agnostic: it knows about requests,
//! responses, and notifications, and nothing about tools or sessions.
//!
//! Two decisions in this module are worth knowing about before you read it.
//!
//! First, `params` and `result` are kept as [`serde_json::Value`] rather than
//! being parsed into typed payloads at this layer. A gateway forwards far more
//! traffic than it inspects, and reserialising a strongly typed struct would
//! silently drop any field this build does not know about. Keeping the payload
//! opaque means an unrecognised extension survives the round trip intact.
//!
//! Second, [`Message`] has a hand-written [`Deserialize`] impl instead of
//! `#[serde(untagged)]`. An untagged enum reports failure as "data did not match
//! any variant", which is useless when you are debugging a misbehaving server.
//! The hand-written version classifies on the fields JSON-RPC actually uses as
//! discriminators and reports precisely which invariant was violated.

use serde::de::{Error as DeError, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::fmt;

/// The `"jsonrpc": "2.0"` version tag.
///
/// Modelled as its own type so a wrong or missing version is rejected during
/// deserialisation rather than carried around as a string that every call site
/// has to remember to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct V2;

impl Serialize for V2 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("2.0")
    }
}

impl<'de> Deserialize<'de> for V2 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        if raw == "2.0" {
            Ok(Self)
        } else {
            Err(D::Error::custom(format!(
                "unsupported jsonrpc version {raw:?}, expected 2.0"
            )))
        }
    }
}

/// A request identifier.
///
/// JSON-RPC permits a string, a number, or null. MCP forbids null, so this type
/// does not model it: a null id is a malformed MCP message and is rejected at
/// the edge instead of being propagated inward.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    /// A numeric id. This is what essentially every MCP implementation emits.
    Number(i64),
    /// A string id.
    String(String),
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(n) => write!(f, "{n}"),
            Self::String(s) => write!(f, "{s}"),
        }
    }
}

impl From<i64> for RequestId {
    fn from(value: i64) -> Self {
        Self::Number(value)
    }
}

impl From<String> for RequestId {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for RequestId {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

/// A request: a method call that expects a matching [`Response`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Protocol version tag.
    pub jsonrpc: V2,
    /// Correlates this request with its response.
    pub id: RequestId,
    /// The method being invoked, for example `tools/call`.
    pub method: String,
    /// Method parameters, left opaque so unknown fields survive forwarding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl Request {
    /// Builds a request with the version tag filled in.
    pub fn new(id: impl Into<RequestId>, method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: V2,
            id: id.into(),
            method: method.into(),
            params,
        }
    }
}

/// A notification: a method call that must not be answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notification {
    /// Protocol version tag.
    pub jsonrpc: V2,
    /// The method being invoked, for example `notifications/initialized`.
    pub method: String,
    /// Method parameters, left opaque so unknown fields survive forwarding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl Notification {
    /// Builds a notification with the version tag filled in.
    pub fn new(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: V2,
            method: method.into(),
            params,
        }
    }
}

/// The outcome carried by a [`Response`].
///
/// JSON-RPC requires exactly one of `result` or `error` to be present. That is a
/// sum type, even though the encoding is two optional sibling keys. Flattening
/// an enum here makes the invariant unrepresentable in Rust rather than merely
/// documented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponsePayload {
    /// The call succeeded and produced this value.
    #[serde(rename = "result")]
    Result(Value),
    /// The call failed.
    #[serde(rename = "error")]
    Error(ErrorObject),
}

/// A response to a [`Request`], carrying either a result or an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// Protocol version tag.
    pub jsonrpc: V2,
    /// The id of the request being answered.
    pub id: RequestId,
    /// Exactly one of `result` or `error`.
    #[serde(flatten)]
    pub payload: ResponsePayload,
}

impl Response {
    /// Builds a successful response.
    pub fn success(id: impl Into<RequestId>, result: Value) -> Self {
        Self {
            jsonrpc: V2,
            id: id.into(),
            payload: ResponsePayload::Result(result),
        }
    }

    /// Builds an error response.
    pub fn error(id: impl Into<RequestId>, error: ErrorObject) -> Self {
        Self {
            jsonrpc: V2,
            id: id.into(),
            payload: ResponsePayload::Error(error),
        }
    }

    /// Returns the success payload, or `None` if this response is an error.
    pub fn result(&self) -> Option<&Value> {
        match &self.payload {
            ResponsePayload::Result(value) => Some(value),
            ResponsePayload::Error(_) => None,
        }
    }

    /// Returns the error payload, or `None` if this response succeeded.
    pub fn err(&self) -> Option<&ErrorObject> {
        match &self.payload {
            ResponsePayload::Error(error) => Some(error),
            ResponsePayload::Result(_) => None,
        }
    }

    /// Whether this response carries an error.
    pub fn is_error(&self) -> bool {
        matches!(self.payload, ResponsePayload::Error(_))
    }
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorObject {
    /// Numeric error code. See [`error_code`] for the ones portcullis uses.
    pub code: i64,
    /// Short human-readable description.
    pub message: String,
    /// Optional structured detail. portcullis puts the deciding rule here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl ErrorObject {
    /// Builds an error object with no structured detail.
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Attaches structured detail.
    #[must_use]
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }
}

impl fmt::Display for ErrorObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "jsonrpc error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for ErrorObject {}

/// Error codes.
///
/// The first five are the reserved codes from the JSON-RPC 2.0 specification.
/// The rest live in the implementation-defined `-32000..=-32099` band and are
/// specific to portcullis, so a client can distinguish "the gateway refused
/// this" from "the upstream server broke".
pub mod error_code {
    /// Invalid JSON was received.
    pub const PARSE_ERROR: i64 = -32700;
    /// The payload was valid JSON but not a valid request object.
    pub const INVALID_REQUEST: i64 = -32600;
    /// The method does not exist.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// The method exists but the parameters are wrong.
    pub const INVALID_PARAMS: i64 = -32602;
    /// The receiver failed for an unattributable reason.
    pub const INTERNAL_ERROR: i64 = -32603;

    /// A policy rule denied the call.
    pub const POLICY_DENIED: i64 = -32000;
    /// A rate limit was exhausted.
    pub const RATE_LIMITED: i64 = -32001;
    /// The upstream server that owns this tool is not reachable.
    pub const UPSTREAM_UNAVAILABLE: i64 = -32002;
    /// A scanner blocked the content before it reached the model.
    pub const CONTENT_BLOCKED: i64 = -32003;
    /// The requested tool is not exposed by any configured upstream.
    pub const UNKNOWN_TOOL: i64 = -32004;
}

/// Any single JSON-RPC message.
///
/// Batches (a top-level JSON array) are not modelled. MCP removed batching in
/// revision 2025-06-18, and accepting it would mean every downstream stage had
/// to reason about partial failure within a batch. Arrays are rejected with an
/// explicit message rather than a confusing type error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Message {
    /// A call awaiting a response.
    Request(Request),
    /// A response to an earlier call.
    Response(Response),
    /// A one-way call.
    Notification(Notification),
}

impl Message {
    /// The method name, for the two variants that carry one.
    pub fn method(&self) -> Option<&str> {
        match self {
            Self::Request(request) => Some(&request.method),
            Self::Notification(notification) => Some(&notification.method),
            Self::Response(_) => None,
        }
    }

    /// The request id, for the two variants that carry one.
    pub fn id(&self) -> Option<&RequestId> {
        match self {
            Self::Request(request) => Some(&request.id),
            Self::Response(response) => Some(&response.id),
            Self::Notification(_) => None,
        }
    }
}

impl From<Request> for Message {
    fn from(value: Request) -> Self {
        Self::Request(value)
    }
}

impl From<Response> for Message {
    fn from(value: Response) -> Self {
        Self::Response(value)
    }
}

impl From<Notification> for Message {
    fn from(value: Notification) -> Self {
        Self::Notification(value)
    }
}

impl<'de> Deserialize<'de> for Message {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(MessageVisitor)
    }
}

struct MessageVisitor;

impl<'de> Visitor<'de> for MessageVisitor {
    type Value = Message;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON-RPC 2.0 request, response, or notification object")
    }

    fn visit_seq<A>(self, _seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        Err(A::Error::custom(
            "JSON-RPC batches are not supported; MCP removed batching in revision 2025-06-18",
        ))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut jsonrpc: Option<V2> = None;
        let mut id: Option<Value> = None;
        let mut method: Option<String> = None;
        let mut params: Option<Value> = None;
        let mut result: Option<Value> = None;
        let mut error: Option<ErrorObject> = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "jsonrpc" => jsonrpc = Some(map.next_value()?),
                "id" => id = Some(map.next_value()?),
                "method" => method = Some(map.next_value()?),
                "params" => params = Some(map.next_value()?),
                "result" => result = Some(map.next_value()?),
                "error" => error = Some(map.next_value()?),
                // Unknown top-level keys are ignored rather than rejected. A
                // gateway that refuses messages carrying a field it has not
                // heard of is a gateway that breaks on the next revision.
                _ => {
                    let _: serde::de::IgnoredAny = map.next_value()?;
                }
            }
        }

        if jsonrpc.is_none() {
            return Err(A::Error::missing_field("jsonrpc"));
        }

        let id = match id {
            None | Some(Value::Null) => None,
            Some(Value::Number(number)) => {
                Some(RequestId::Number(number.as_i64().ok_or_else(|| {
                    A::Error::custom("request id is not an integer")
                })?))
            }
            Some(Value::String(string)) => Some(RequestId::String(string)),
            Some(_) => {
                return Err(A::Error::custom(
                    "request id must be a string or an integer",
                ));
            }
        };

        let has_payload = result.is_some() || error.is_some();

        match (method, id) {
            (Some(_), _) if has_payload => Err(A::Error::custom(
                "message carries both a method and a response payload",
            )),
            (Some(method), Some(id)) => Ok(Message::Request(Request {
                jsonrpc: V2,
                id,
                method,
                params,
            })),
            (Some(method), None) => Ok(Message::Notification(Notification {
                jsonrpc: V2,
                method,
                params,
            })),
            (None, Some(id)) => match (result, error) {
                (Some(_), Some(_)) => Err(A::Error::custom(
                    "response carries both a result and an error",
                )),
                (Some(result), None) => Ok(Message::Response(Response {
                    jsonrpc: V2,
                    id,
                    payload: ResponsePayload::Result(result),
                })),
                (None, Some(error)) => Ok(Message::Response(Response {
                    jsonrpc: V2,
                    id,
                    payload: ResponsePayload::Error(error),
                })),
                (None, None) => Err(A::Error::custom(
                    "response carries neither a result nor an error",
                )),
            },
            (None, None) => Err(A::Error::custom(
                "message has no method and no id, so it is neither a call nor a response",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(value: serde_json::Value) -> Result<Message, serde_json::Error> {
        serde_json::from_value(value)
    }

    #[test]
    fn classifies_a_request() {
        let message = parse(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "fs.read_file" }
        }))
        .expect("valid request");

        assert!(matches!(message, Message::Request(_)));
        assert_eq!(message.method(), Some("tools/call"));
        assert_eq!(message.id(), Some(&RequestId::Number(1)));
    }

    #[test]
    fn classifies_a_notification_by_the_absence_of_an_id() {
        let message = parse(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .expect("valid notification");

        assert!(matches!(message, Message::Notification(_)));
        assert_eq!(message.id(), None);
    }

    #[test]
    fn treats_an_explicit_null_id_as_a_notification() {
        // MCP forbids a null id on a request. Rather than inventing a third
        // state, a null id is folded into the same shape as an absent one.
        let message = parse(json!({
            "jsonrpc": "2.0",
            "id": null,
            "method": "notifications/cancelled"
        }))
        .expect("null id is tolerated");

        assert!(matches!(message, Message::Notification(_)));
    }

    #[test]
    fn classifies_a_success_response() {
        let message =
            parse(json!({ "jsonrpc": "2.0", "id": "abc", "result": { "tools": [] } })).unwrap();

        let Message::Response(response) = message else {
            panic!("expected a response")
        };
        assert_eq!(response.id, RequestId::String("abc".into()));
        assert!(!response.is_error());
        assert_eq!(response.result(), Some(&json!({ "tools": [] })));
    }

    #[test]
    fn classifies_an_error_response() {
        let message = parse(json!({
            "jsonrpc": "2.0",
            "id": 7,
            "error": { "code": -32601, "message": "no such method" }
        }))
        .unwrap();

        let Message::Response(response) = message else {
            panic!("expected a response")
        };
        assert!(response.is_error());
        assert_eq!(response.err().unwrap().code, error_code::METHOD_NOT_FOUND);
    }

    #[test]
    fn rejects_a_response_carrying_both_result_and_error() {
        let error = parse(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {},
            "error": { "code": -1, "message": "x" }
        }))
        .unwrap_err();

        assert!(
            error.to_string().contains("both a result and an error"),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_response_carrying_neither_result_nor_error() {
        let error = parse(json!({ "jsonrpc": "2.0", "id": 1 })).unwrap_err();
        assert!(
            error.to_string().contains("neither a result nor an error"),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_wrong_protocol_version() {
        let error = parse(json!({ "jsonrpc": "1.0", "id": 1, "method": "ping" })).unwrap_err();
        assert!(
            error.to_string().contains("unsupported jsonrpc version"),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_missing_protocol_version() {
        let error = parse(json!({ "id": 1, "method": "ping" })).unwrap_err();
        assert!(error.to_string().contains("jsonrpc"), "{error}");
    }

    #[test]
    fn rejects_batches_with_an_actionable_message() {
        let error = serde_json::from_str::<Message>("[{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}]")
            .unwrap_err();
        assert!(
            error.to_string().contains("batches are not supported"),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_structured_request_id() {
        let error = parse(json!({ "jsonrpc": "2.0", "id": [1], "method": "ping" })).unwrap_err();
        assert!(
            error.to_string().contains("must be a string or an integer"),
            "{error}"
        );
    }

    #[test]
    fn ignores_unknown_top_level_fields() {
        // Forward compatibility: a field this build has never heard of must not
        // be a parse failure.
        let message =
            parse(json!({ "jsonrpc": "2.0", "id": 1, "method": "ping", "_meta": { "x": 1 } }))
                .expect("unknown fields are ignored");
        assert_eq!(message.method(), Some("ping"));
    }

    #[test]
    fn omits_absent_params_when_serialising() {
        let encoded = serde_json::to_string(&Message::from(Notification::new("ping", None)))
            .expect("serialises");
        assert_eq!(encoded, r#"{"jsonrpc":"2.0","method":"ping"}"#);
    }

    #[test]
    fn round_trips_every_variant() {
        let cases = vec![
            Message::from(Request::new(1, "tools/list", None)),
            Message::from(Request::new(
                "id-2",
                "tools/call",
                Some(json!({ "name": "t" })),
            )),
            Message::from(Notification::new("notifications/initialized", None)),
            Message::from(Response::success(3, json!({ "ok": true }))),
            Message::from(Response::error(
                4,
                ErrorObject::new(error_code::POLICY_DENIED, "denied by rule deny-ssh")
                    .with_data(json!({ "rule": "deny-ssh" })),
            )),
        ];

        for original in cases {
            let encoded = serde_json::to_string(&original).expect("serialises");
            let decoded: Message = serde_json::from_str(&encoded).expect("round trips");
            assert_eq!(
                decoded, original,
                "round trip changed the message: {encoded}"
            );
        }
    }

    #[test]
    fn request_id_displays_without_quoting() {
        assert_eq!(RequestId::Number(12).to_string(), "12");
        assert_eq!(RequestId::from("abc").to_string(), "abc");
    }
}
