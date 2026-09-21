//! The fixed correctness core: request-constraint checking and response
//! assembly.
//!
//! [`check_request`] is pure and I/O-free — it holds the whole ForceAuthn ×
//! IsPassive × RequestedAuthnContext matrix, so it is the cheapest thing to
//! test exhaustively. [`create_authn_response`] and
//! [`create_denial_response`] perform the actual assembly in a fixed order.

use chrono::Utc;

use crate::core::assertion::name_id::NameId;
use crate::core::protocol::response::Response;
use crate::idp::assertion_store::AssertionStore;
use crate::idp::authn_broker::AuthnBroker;
use crate::idp::ident::NameIdConstructor;
use crate::idp::policy::{sp_attribute_requirements, PolicyError, ReleasePolicy};
use crate::profiles::error::ProfileError;
use crate::profiles::sso::idp::{create_error_response, create_response, sign_response_xml};
use crate::profiles::sso::web_browser::{ResponseOptions, ResponseTimes};
use crate::xml::serialize::SamlSerialize;

use super::denial::Denial;
use super::params::{
    AuthenticatedSubject, Disposition, EstablishedSession, IssuedResponse, ResponseParams,
};
use super::release::AttributeRelease;

/// The response-assembly engine.
///
/// Holds the deployment-specific pieces and the fixed correctness core. The
/// `release` seam is often `decisions` again (an originating IdP applies its
/// `ReleasePolicy`); a proxy passes a
/// [`PassThroughRelease`](super::PassThroughRelease) or
/// [`ChainedRelease`](super::ChainedRelease) instead.
///
/// `idents` is `dyn NameIdConstructor` rather than a concrete
/// `IdentDb<S: IdentityStore>` so this type carries no `IdentityStore`
/// generic — a ready-made framework integration (a fixed function signature
/// registered as a route handler) cannot parameterize that per-application;
/// type-erasing it here means a Redis/SQL-backed `IdentDb` works there too,
/// not just the default in-memory store.
pub struct ResponseEngine<'a> {
    /// This IdP's entity ID (used as the response/assertion `Issuer`).
    pub idp_entity_id: &'a str,
    /// The per-SP decisions: lifetime, NameID format, signing targets, and
    /// `fail_on_missing_requested`.
    pub decisions: &'a ReleasePolicy,
    /// The attribute-release seam. Often `decisions` again.
    pub release: &'a dyn AttributeRelease,
    /// The identity database (NameID construction), type-erased over its
    /// `IdentityStore` backend.
    pub idents: &'a dyn NameIdConstructor,
    /// The authn broker (RequestedAuthnContext matching).
    pub broker: &'a AuthnBroker,
    /// The assertion store, if back-channel queries must be answerable.
    pub assertions: Option<&'a dyn AssertionStore>,
    /// The signer for the response/assertion.
    pub signer: &'a crate::crypto::SamlSigner,
    /// The base64 DER signing certificate for `<ds:KeyInfo>`.
    pub cert_der_b64: &'a str,
}

/// Decide what to do with a request, without any I/O.
///
/// This is the pure core of the ForceAuthn × IsPassive × RequestedAuthnContext
/// matrix. The application answers exactly one question — "do I have a session,
/// and which method established it?" — by passing `session` (or `None`).
///
/// The decision order:
/// 1. If `IsPassive` and there is no reusable session (no session, or
///    `ForceAuthn` defeated reuse, or the session's method does not satisfy the
///    requested context), deny with [`Denial::NoPassive`].
/// 2. If a session exists, is not defeated by `ForceAuthn`, and its method
///    satisfies the requested context, [`Disposition::ReuseSession`].
/// 3. Otherwise, if the broker has methods satisfying the request,
///    [`Disposition::Authenticate`] with those methods.
/// 4. Otherwise (a context was requested and none is available), deny with
///    [`Denial::NoAuthnContext`].
pub fn check_request(
    engine: &ResponseEngine,
    params: &ResponseParams,
    session: Option<&EstablishedSession>,
) -> Disposition {
    let processed = &params.processed;
    let requested = params.requested_authn_context();
    let picked = engine.broker.pick(requested.as_ref());

    // A reusable session is one that exists, is not defeated by ForceAuthn, and
    // whose establishing method satisfies the requested context.
    let reusable = session.filter(|s| {
        !processed.force_authn && session_satisfies(engine.broker, requested.as_ref(), s)
    });

    if processed.is_passive {
        return match reusable {
            Some(session) => Disposition::ReuseSession {
                session: session.clone(),
            },
            None => Disposition::Deny {
                denial: Denial::NoPassive,
            },
        };
    }

    if let Some(session) = reusable {
        return Disposition::ReuseSession {
            session: session.clone(),
        };
    }

    // No reusable session: authenticate, unless a context was requested and the
    // broker has nothing that satisfies it.
    if picked.is_empty() && requested.is_some() {
        return Disposition::Deny {
            denial: Denial::NoAuthnContext,
        };
    }

    Disposition::Authenticate {
        methods: picked.into_iter().cloned().collect(),
    }
}

/// Whether an established session's method satisfies the requested context.
///
/// The session's method is resolved to a class ref and checked against the
/// broker's picked set for the request. With no requested context, any session
/// is acceptable.
fn session_satisfies(
    broker: &AuthnBroker,
    requested: Option<&crate::core::protocol::request::RequestedAuthnContext>,
    session: &EstablishedSession,
) -> bool {
    let (class_ref, _authority) = session.authn_method.resolve(broker);
    class_ref_satisfies(broker, requested, &class_ref)
}

/// Whether a resolved authn context class ref satisfies the requested
/// context. With no constraint (or nothing registered), any class ref is
/// acceptable only when nothing was requested.
fn class_ref_satisfies(
    broker: &AuthnBroker,
    requested: Option<&crate::core::protocol::request::RequestedAuthnContext>,
    class_ref: &str,
) -> bool {
    let picked = broker.pick(requested);
    if picked.is_empty() {
        return requested.is_none();
    }
    picked.iter().any(|m| m.class_ref == class_ref)
}

/// Assemble and sign a successful response for an authenticated subject.
///
/// Fixed order:
/// 1. resolve the SP's required/optional attributes;
/// 2. run the release seam;
/// 3. check `fail_on_missing_requested` (→ [`Denial::MissingRequiredAttributes`]);
/// 4. construct the NameID (→ [`Denial::InvalidNameIdPolicy`] /
///    [`Denial::NameIdCreationNotAllowed`]);
/// 5. resolve the authn context from the subject's method;
/// 6. build `ResponseOptions`;
/// 7. sign per `decisions.sign(sp).resolve(want_assertions_signed)`;
/// 8. store the assertion (if a store is present);
/// 9. return the [`IssuedResponse`].
///
/// A protocol refusal is returned as
/// [`ResponseOutcome::Denied`](super::ResponseOutcome::Denied) with a signed
/// error response; only programming/configuration faults are `Err`.
pub fn create_authn_response(
    engine: &ResponseEngine,
    params: &ResponseParams,
    subject: &AuthenticatedSubject,
) -> Result<super::ResponseOutcome, ProfileError> {
    let processed = &params.processed;
    let sp = &params.sp_sso;

    // 1. Resolve the SP's attribute requirements (indexed or default service).
    let (required, optional) =
        sp_attribute_requirements(sp, processed.attribute_consuming_service_index);

    // 2. Run the release seam. A missing-required-attribute/value refusal is
    //    the SP's own AttributeConsumingService being unsatisfiable — a
    //    protocol denial, not a programming/configuration fault. Only a
    //    genuine release misconfiguration (e.g. an invalid restriction
    //    pattern) is a `ProfileError`.
    let released = match engine.release.release(
        subject.attributes.clone(),
        &processed.sp_entity_id,
        &params.sp_entity_categories(),
        &required,
        &optional,
        params.subject_id_req(),
    ) {
        Ok(attrs) => attrs,
        Err(
            PolicyError::MissingRequiredAttribute(_) | PolicyError::MissingRequiredValue { .. },
        ) => {
            return denied(engine, params, &Denial::MissingRequiredAttributes);
        }
        Err(e) => {
            return Err(ProfileError::Other(format!(
                "attribute release failed: {e}"
            )))
        }
    };

    // 3. fail_on_missing_requested: verify required attributes/values
    //    actually survived release, independent of which `AttributeRelease`
    //    ran. `ReleasePolicy::release` already validates this internally (and
    //    would have taken the branch above instead), but a pass-through or
    //    custom release does not, so this check must not depend on which
    //    implementation was injected.
    if engine
        .decisions
        .fail_on_missing_requested(&processed.sp_entity_id)
        && !required.is_empty()
        && engine
            .decisions
            .validate_required_attributes(&released, &required)
            .is_err()
    {
        return denied(engine, params, &Denial::MissingRequiredAttributes);
    }

    // 4. Construct the NameID, honouring the request's NameIDPolicy and the
    //    IdP's default format. A NameID refusal is a protocol denial.
    let name_id = match construct_name_id(engine, params, subject) {
        Ok(name_id) => name_id,
        Err(denial) => return denied(engine, params, &denial),
    };

    // 5. Resolve the authn context from the subject's method, and verify it
    //    actually satisfies what the SP requested. `check_request` only
    //    offers methods that would satisfy the request via `Disposition`; it
    //    cannot guarantee which method the application ultimately used to
    //    authenticate the subject it hands back here, so that has to be
    //    checked again at the point the response is actually assembled.
    let (class_ref, authority) = subject.authn_method.resolve(engine.broker);
    if !class_ref_satisfies(
        engine.broker,
        params.requested_authn_context().as_ref(),
        &class_ref,
    ) {
        return denied(engine, params, &Denial::NoAuthnContext);
    }

    // 6. Build the response options. Assertion and session lifetimes are
    //    independent: the assertion's own validity window is typically
    //    short, while the SSO session it establishes is usually meant to
    //    outlive any one assertion (E79).
    let now = Utc::now();
    let lifetime = engine.decisions.lifetime(&processed.sp_entity_id);
    let session_lifetime = engine.decisions.session_lifetime(&processed.sp_entity_id);
    let session_not_on_or_after = Some(now + session_lifetime);
    let options = ResponseOptions {
        idp_entity_id: engine.idp_entity_id.to_string(),
        in_response_to: Some(processed.request_id.clone()),
        sp_entity_id: processed.sp_entity_id.clone(),
        acs_url: processed.acs_url.clone(),
        assertion_lifetime_seconds: lifetime.num_seconds().max(0) as u64,
        session_index: subject.session_index.clone(),
        session_not_on_or_after,
        authn_context_class_ref: Some(class_ref),
        client_address: None,
        attributes: released.clone(),
        authenticating_authorities: authority.into_iter().collect(),
    };

    // 7. Sign per the per-SP sign targets, resolved against the SP's
    //    WantAssertionsSigned.
    let want_assertions_signed = sp.want_assertions_signed.unwrap_or(false);
    let sign = engine
        .decisions
        .sign(&processed.sp_entity_id)
        .resolve(want_assertions_signed);

    // Build the (unsigned) response once so the audit identifiers and the
    // stored assertion match the signed XML exactly, then sign that XML.
    let response = create_response(
        &options,
        &name_id,
        ResponseTimes {
            issue_instant: now,
            authn_instant: subject.authn_instant.unwrap_or(now),
        },
    );
    let response_id = response.base.id.clone();
    let assertion_id = response.assertions.first().map(|a| a.id.clone());
    let xml = response
        .to_xml_string()
        .map_err(|e| ProfileError::Other(format!("failed to serialize Response: {e}")))?;
    let signed_xml = sign_response_xml(
        &xml,
        engine.signer,
        engine.cert_der_b64,
        &response_id,
        assertion_id.as_deref(),
        sign.sign_assertion,
        sign.sign_response,
    )?;

    // 8. Store the assertion for back-channel queries, if a store is present.
    if let Some(store) = engine.assertions {
        if let Some(assertion) = response.assertions.first() {
            store.store_assertion(assertion.clone());
        }
    }

    // 9. Return the issued response with its audit identifiers.
    let not_on_or_after = now + lifetime;
    let released_attribute_names = released.iter().map(|a| a.name.clone()).collect();
    Ok(super::ResponseOutcome::Issued(IssuedResponse {
        xml: signed_xml,
        response_id,
        assertion_id,
        name_id,
        session_index: subject.session_index.clone(),
        not_on_or_after,
        released_attribute_names,
    }))
}

/// Assemble and sign a denial (protocol error) response.
///
/// The Response envelope is signed **unconditionally** — an unsigned denial is
/// trivially forgeable — regardless of the per-SP `SignTargets`.
pub fn create_denial_response(
    engine: &ResponseEngine,
    params: &ResponseParams,
    denial: &Denial,
) -> Result<IssuedResponse, ProfileError> {
    let processed = &params.processed;
    let now = Utc::now();

    let response: Response = create_error_response(
        engine.idp_entity_id,
        Some(&processed.request_id),
        &processed.acs_url,
        denial.status(),
        now,
    );
    let response_id = response.base.id.clone();
    let xml = response
        .to_xml_string()
        .map_err(|e| ProfileError::Other(format!("failed to serialize denial Response: {e}")))?;

    // Denials always sign the Response envelope.
    let signed_xml = crate::profiles::sso::idp::sign_response_xml(
        &xml,
        engine.signer,
        engine.cert_der_b64,
        &response_id,
        None,
        false,
        true,
    )?;

    Ok(IssuedResponse {
        xml: signed_xml,
        response_id,
        assertion_id: None,
        name_id: NameId {
            value: String::new(),
            format: None,
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        },
        session_index: None,
        not_on_or_after: now,
        released_attribute_names: vec![],
    })
}

/// Build a `ResponseOutcome::Denied` for the given denial.
fn denied(
    engine: &ResponseEngine,
    params: &ResponseParams,
    denial: &Denial,
) -> Result<super::ResponseOutcome, ProfileError> {
    let response = create_denial_response(engine, params, denial)?;
    Ok(super::ResponseOutcome::Denied {
        denial: *denial,
        response,
    })
}

/// Construct the NameID for the subject, honouring the request's NameIDPolicy
/// and the IdP's default format. Maps `IdentError` to the appropriate denial.
fn construct_name_id(
    engine: &ResponseEngine,
    params: &ResponseParams,
    subject: &AuthenticatedSubject,
) -> Result<NameId, Denial> {
    let policy = params.name_id_policy();
    let default_format = engine
        .decisions
        .nameid_format(&params.processed.sp_entity_id);
    engine
        .idents
        .construct_nameid(
            &subject.subject_id,
            &params.processed.sp_entity_id,
            policy.as_ref(),
            Some(default_format.as_str()),
        )
        .map_err(|e| match e {
            crate::idp::ident::IdentError::CreateNotAllowed => Denial::NameIdCreationNotAllowed,
            _ => Denial::InvalidNameIdPolicy,
        })
}
