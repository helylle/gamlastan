//! IdP response orchestration: composes the IdP primitives into the SAML Web
//! Browser SSO response-assembly flow.
//!
//! See the module submodules for the release seam, denial mapping, parameters,
//! and the response engine.

pub mod release;

pub use release::{AttributeRelease, ChainedRelease, PassThroughRelease};
