//! The portcullis gateway itself.
//!
//! This crate wires the protocol types, the policy engine, and the scanners
//! into a proxy that speaks MCP on both sides: it is a server to the client and
//! a client to each upstream server.

#![doc(html_root_url = "https://docs.rs/portcullis-proxy/0.1.0")]

pub mod gateway;
pub mod inspect;
pub mod registry;
pub mod upstream;

pub use gateway::{Gateway, GatewayConfig, GatewayError};
pub use inspect::{InjectionHandling, Inspection, InspectionConfig};
pub use registry::{Route, ToolRegistry};
pub use upstream::{Upstream, UpstreamConfig, UpstreamError};
