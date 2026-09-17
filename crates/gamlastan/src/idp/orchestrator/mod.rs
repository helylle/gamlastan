//! IdP response orchestration: composes the IdP primitives into the SAML Web
//! Browser SSO response-assembly flow.
//!
//! The [`ResponseEngine`] holds the deployment-specific pieces — the release
//! policy, the identity database, the authn broker, the assertion store, and
//! the signer — and exposes two entry points:
//!
//! - [`check_request`] — a pure, no-I/O decision over the ForceAuthn ×
//!   IsPassive × RequestedAuthnContext matrix. It answers the one question the
//!   application must answer: "do I have a session, and which method
//!   established it?"
//! - [`create_authn_response`] / [`create_denial_response`] — assemble and
//!   sign the actual response.
//!
//! The load-bearing distinction (see the module's ADR) is that **what varies
//! by deployment is where released attributes and identity facts come from;
//! what must not vary is how a compliant `Response` is assembled from them**.
//! The release decision is the only injected seam ([`AttributeRelease`]);
//! everything downstream — NameID construction, authn-context matching,
//! audience/conditions, session index and lifetime, and signed protocol
//! errors — is the fixed correctness core.
//!
//! # Example
//!
//! ```
//! use gamlastan::idp::orchestrator::{
//!     check_request, AuthnMethodRef, Disposition, EstablishedSession, ResponseEngine,
//!     ResponseParams,
//! };
//! use gamlastan::idp::{AuthnBroker, IdentDb, ReleasePolicy};
//!
//! // A broker with a password method at level 1.
//! let mut broker = AuthnBroker::new();
//! broker.add(
//!     "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
//!     "/login/password",
//!     1,
//!     None,
//! );
//!
//! // No session and no IsPassive: the request must be authenticated.
//! let idents = IdentDb::in_memory("https://idp.example.org/metadata");
//! let decisions = ReleasePolicy::new();
//! let engine = ResponseEngine {
//!     idp_entity_id: "https://idp.example.org/metadata",
//!     decisions: &decisions,
//!     release: &decisions,
//!     idents: &idents,
//!     broker: &broker,
//!     assertions: None,
//!     signer: &gamlastan::crypto::SamlSigner::new(gamlastan::crypto::KeysManager::new()),
//!     cert_der_b64: "",
//! };
//!
//! let params = test_params();
//! let disposition = check_request(&engine, &params, None);
//! assert!(matches!(disposition, Disposition::Authenticate { .. }));
//!
//! // A reusable session (no ForceAuthn, method satisfies the request) is reused.
//! let session = EstablishedSession {
//!     subject_id: "alice".to_string(),
//!     authn_method: AuthnMethodRef::Inline {
//!         class_ref: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password".to_string(),
//!         authn_authority: None,
//!     },
//!     authn_instant: chrono::Utc::now(),
//!     session_index: "_sess_1".to_string(),
//! };
//! let disposition = check_request(&engine, &params, Some(&session));
//! assert!(matches!(disposition, Disposition::ReuseSession { .. }));
//!
//! fn test_params() -> ResponseParams {
//!     use gamlastan::core::assertion::issuer::Issuer;
//!     use gamlastan::core::identifiers::SamlVersion;
//!     use gamlastan::core::protocol::request::{AuthnRequest, RequestBase};
//!     use gamlastan::metadata::types::endpoint::{Endpoint, IndexedEndpoint};
//!     use gamlastan::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
//!     use gamlastan::metadata::types::sp::SpSsoDescriptor;
//!     use gamlastan::profiles::sso::idp::process_authn_request;
//!
//!     let sp = SpSsoDescriptor {
//!         sso_base: SsoDescriptorBase {
//!             base: RoleDescriptorBase::new(vec![
//!                 "urn:oasis:names:tc:SAML:2.0:protocol".to_string()
//!             ]),
//!             artifact_resolution_services: vec![],
//!             single_logout_services: vec![],
//!             manage_name_id_services: vec![],
//!             name_id_formats: vec![],
//!         },
//!         authn_requests_signed: None,
//!         want_assertions_signed: Some(true),
//!         assertion_consumer_services: vec![IndexedEndpoint::new_default(
//!             Endpoint::new(
//!                 "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
//!                 "https://sp.example.org/acs",
//!             ),
//!             0,
//!         )],
//!         attribute_consuming_services: vec![],
//!     };
//!     let request = AuthnRequest {
//!         base: RequestBase {
//!             id: "_req1".to_string(),
//!             version: SamlVersion::V2_0,
//!             issue_instant: chrono::Utc::now(),
//!             destination: Some("https://idp.example.org/sso".to_string()),
//!             consent: None,
//!             issuer: Some(Issuer::entity("https://sp.example.org/metadata")),
//!             has_signature: false,
//!         },
//!         subject: None,
//!         name_id_policy: None,
//!         conditions: None,
//!         requested_authn_context: None,
//!         scoping: None,
//!         force_authn: None,
//!         is_passive: None,
//!         assertion_consumer_service_index: None,
//!         assertion_consumer_service_url: Some("https://sp.example.org/acs".to_string()),
//!         protocol_binding: Some(
//!             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string(),
//!         ),
//!         attribute_consuming_service_index: None,
//!         provider_name: None,
//!         extensions: None,
//!     };
//!     let processed = process_authn_request(&request, &sp, false).unwrap();
//!     ResponseParams {
//!         processed,
//!         sp_sso: sp,
//!         sp_entity: None,
//!     }
//! }
//! ```

pub mod denial;
pub mod params;
pub mod release;
pub mod respond;

#[cfg(test)]
mod tests;

pub use denial::Denial;
pub use params::{
    AuthenticatedSubject, AuthnMethodRef, Disposition, EstablishedSession, IssuedResponse,
    ResponseOutcome, ResponseParams,
};
pub use release::{AttributeRelease, ChainedRelease, PassThroughRelease};
pub use respond::{check_request, create_authn_response, create_denial_response, ResponseEngine};
