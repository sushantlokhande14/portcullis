//! Content scanners for the portcullis gateway.
//!
//! Two jobs, pointed in opposite directions. [`secret`] looks for credentials,
//! in arguments on the way out and in results on the way back. The injection
//! scanners look for text that is trying to be read as an instruction rather
//! than as data, which only makes sense on the way back.
//!
//! Every detector is a self-contained rule with its own fixtures, so adding one
//! does not require understanding the proxy. That is deliberate: this is the
//! part of the codebase most worth contributing to and it should have the
//! shallowest on-ramp.

#![doc(html_root_url = "https://docs.rs/portcullis-scan/0.1.0")]

pub mod injection;
pub mod secret;

pub use injection::{InjectionFinding, InjectionKind, Severity};
pub use secret::{SecretFinding, SecretKind};
