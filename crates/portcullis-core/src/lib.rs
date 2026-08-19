//! Protocol foundations for the portcullis gateway.
//!
//! This crate owns the wire format and nothing else. It knows how to parse and
//! serialise JSON-RPC 2.0 messages, how to represent the Model Context Protocol
//! types layered on top of them, and how to move those messages across a
//! transport. It deliberately holds no opinion about policy, scanning, or
//! routing so that the security crates can be tested without a live server and
//! the protocol code can be reused by anything that speaks MCP.
//!
//! The dependency direction across the workspace is one-way:
//!
//! ```text
//! portcullis-core  <-  portcullis-policy
//!        ^          <-  portcullis-scan
//!        |          <-  portcullis-proxy  ->  portcullis-cli
//! ```
//!
//! Nothing in this crate reaches back toward the proxy.

#![doc(html_root_url = "https://docs.rs/portcullis-core/0.1.0")]

pub mod jsonrpc;

pub use jsonrpc::{
    ErrorObject, Message, Notification, Request, RequestId, Response, ResponsePayload, error_code,
};

/// The MCP revision portcullis is built against.
///
/// The gateway is not pinned to this value at runtime. It negotiates whatever
/// revision the client and the upstream servers agree on and passes unknown
/// fields through untouched, so a newer client talking to a newer server keeps
/// working even if this constant has not been bumped yet. See
/// `docs/architecture.md` for why passthrough is the default posture.
pub const PREFERRED_PROTOCOL_VERSION: &str = "2025-06-18";

/// Protocol revisions this build has been exercised against.
pub const KNOWN_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferred_version_is_a_known_version() {
        assert!(KNOWN_PROTOCOL_VERSIONS.contains(&PREFERRED_PROTOCOL_VERSION));
    }
}
