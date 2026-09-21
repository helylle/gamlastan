//! Unit tests for the response orchestrator.
//!
//! The highest-value surface is [`check_request`]: it is pure and I/O-free, so
//! the whole ForceAuthn × IsPassive × RequestedAuthnContext matrix can be
//! asserted exhaustively. The remaining tests cover `AuthnMethodRef`
//! resolution (including the ambiguous/unknown broker reference) and the
//! `fail_on_missing_requested` on/off behaviour through
//! [`create_authn_response`].

use chrono::{TimeDelta, Utc};

use crate::core::assertion::attribute::{Attribute, AttributeValue};
use crate::core::constants;
use crate::core::protocol::request::AuthnContextComparison;
use crate::crypto::keys::loader;
use crate::crypto::{KeyUsage, KeysManager, SamlSigner};
use crate::idp::authn_broker::AuthnBroker;
use crate::idp::ident::{IdentDb, IdentityStore};
use crate::idp::orchestrator::release::PassThroughRelease;
use crate::idp::orchestrator::{
    check_request, create_authn_response, AuthnMethodRef, Disposition, EstablishedSession,
    ResponseEngine, ResponseOutcome, ResponseParams,
};
use crate::idp::policy::ReleasePolicy;
use crate::metadata::types::sp::{AttributeConsumingService, RequestedAttribute, SpSsoDescriptor};
use crate::profiles::sso::idp::ProcessedAuthnRequest;

const IDP: &str = "https://idp.example.org/metadata";
const SP: &str = "https://sp.example.org/metadata";
const ACS: &str = "https://sp.example.org/acs";

const PASSWORD: &str = constants::AUTHN_CONTEXT_PASSWORD;
const PPT: &str = constants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT;
const X509: &str = constants::AUTHN_CONTEXT_X509;

const CERT_PEM: &str = include_str!("../../../tests/fixtures/enc-cert.pem");
const KEY_PEM: &str = include_str!("../../../tests/fixtures/enc-key.pem");

/// A signer backed by the fixture RSA key, with the cert as base64 DER.
///
/// Denials sign the Response envelope unconditionally, so any test that
/// exercises the denial path needs a real signing key.
fn fixture_signer() -> (SamlSigner, &'static str) {
    let mut key = loader::load_pem_auto(KEY_PEM.as_bytes(), None).expect("load private key");
    key.usage = KeyUsage::Sign;
    let mut km = KeysManager::new();
    km.add_key(key);
    let signer = SamlSigner::new(km);
    let cert_b64: String = CERT_PEM
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect();
    (signer, Box::leak(cert_b64.into_boxed_str()))
}

/// A broker with three methods at increasing strength.
fn broker() -> AuthnBroker {
    let mut b = AuthnBroker::new();
    b.add(PASSWORD, "/login/password", 1, None);
    b.add(PPT, "/login/ppt", 2, None);
    b.add(X509, "/login/cert", 3, None);
    b
}

/// A `ProcessedAuthnRequest` with the given constraint flags.
fn processed(
    force_authn: bool,
    is_passive: bool,
    class_refs: Vec<&str>,
    comparison: Option<AuthnContextComparison>,
) -> ProcessedAuthnRequest {
    ProcessedAuthnRequest {
        request_id: "_req1".to_string(),
        sp_entity_id: SP.to_string(),
        acs_url: ACS.to_string(),
        acs_binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string(),
        force_authn,
        is_passive,
        requested_name_id_format: None,
        requested_sp_name_qualifier: None,
        allow_create: false,
        has_name_id_policy: false,
        requested_authn_context_class_refs: class_refs.into_iter().map(String::from).collect(),
        authn_context_comparison: comparison,
        attribute_consuming_service_index: None,
        extensions: None,
    }
}

/// An `SpSsoDescriptor` with no attribute requirements.
fn sp_sso() -> SpSsoDescriptor {
    SpSsoDescriptor {
        sso_base: crate::metadata::types::role_descriptor::SsoDescriptorBase {
            base: crate::metadata::types::role_descriptor::RoleDescriptorBase::new(vec![
                "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
            ]),
            artifact_resolution_services: vec![],
            single_logout_services: vec![],
            manage_name_id_services: vec![],
            name_id_formats: vec![],
        },
        authn_requests_signed: None,
        want_assertions_signed: Some(true),
        assertion_consumer_services: vec![],
        attribute_consuming_services: vec![],
    }
}

fn params(p: ProcessedAuthnRequest) -> ResponseParams {
    ResponseParams {
        processed: p,
        sp_sso: sp_sso(),
        sp_entity: None,
    }
}

/// A `ResponseEngine` wired to the test broker and an in-memory identity DB.
fn engine() -> ResponseEngine<'static> {
    static BROKER: std::sync::OnceLock<AuthnBroker> = std::sync::OnceLock::new();
    static IDENTS: std::sync::OnceLock<IdentDb> = std::sync::OnceLock::new();
    static DECISIONS: std::sync::OnceLock<ReleasePolicy> = std::sync::OnceLock::new();
    static SIGNER: std::sync::OnceLock<SamlSigner> = std::sync::OnceLock::new();

    let broker = BROKER.get_or_init(broker);
    let idents = IDENTS.get_or_init(|| IdentDb::in_memory(IDP));
    let decisions = DECISIONS.get_or_init(ReleasePolicy::new);
    let signer = SIGNER.get_or_init(|| SamlSigner::new(KeysManager::new()));

    ResponseEngine {
        idp_entity_id: IDP,
        decisions,
        release: &PassThroughRelease,
        idents,
        broker,
        assertions: None,
        signer,
        cert_der_b64: "",
    }
}

/// A session established by the given method reference.
fn session(method: AuthnMethodRef) -> EstablishedSession {
    EstablishedSession {
        subject_id: "alice".to_string(),
        authn_method: method,
        authn_instant: Utc::now(),
        session_index: "_sess_1".to_string(),
    }
}

// ── check_request: the ForceAuthn × IsPassive × ACR matrix ─────────────────

#[test]
fn no_session_no_passive_authenticates() {
    let engine = engine();
    let p = params(processed(false, false, vec![], None));
    let d = check_request(&engine, &p, None);
    // No constraint: every registered method is offered.
    assert!(matches!(d, Disposition::Authenticate { .. }));
}

#[test]
fn no_session_passive_denies_no_passive() {
    let engine = engine();
    let p = params(processed(false, true, vec![], None));
    let d = check_request(&engine, &p, None);
    assert!(matches!(
        d,
        Disposition::Deny {
            denial: crate::idp::orchestrator::Denial::NoPassive
        }
    ));
}

#[test]
fn reusable_session_is_reused() {
    let engine = engine();
    let p = params(processed(
        false,
        false,
        vec![PASSWORD],
        Some(AuthnContextComparison::Exact),
    ));
    let s = session(AuthnMethodRef::Inline {
        class_ref: PASSWORD.to_string(),
        authn_authority: None,
    });
    let d = check_request(&engine, &p, Some(&s));
    assert!(matches!(d, Disposition::ReuseSession { .. }));
}

#[test]
fn force_authn_defeats_session_reuse() {
    let engine = engine();
    // ForceAuthn set: the session must not be reused even though it satisfies
    // the request.
    let p = params(processed(
        true,
        false,
        vec![PASSWORD],
        Some(AuthnContextComparison::Exact),
    ));
    let s = session(AuthnMethodRef::Inline {
        class_ref: PASSWORD.to_string(),
        authn_authority: None,
    });
    let d = check_request(&engine, &p, Some(&s));
    assert!(matches!(d, Disposition::Authenticate { .. }));
}

#[test]
fn force_authn_plus_passive_denies_no_passive() {
    let engine = engine();
    // ForceAuthn defeats reuse, and IsPassive forbids a fresh login: NoPassive.
    let p = params(processed(
        true,
        true,
        vec![PASSWORD],
        Some(AuthnContextComparison::Exact),
    ));
    let s = session(AuthnMethodRef::Inline {
        class_ref: PASSWORD.to_string(),
        authn_authority: None,
    });
    let d = check_request(&engine, &p, Some(&s));
    assert!(matches!(
        d,
        Disposition::Deny {
            denial: crate::idp::orchestrator::Denial::NoPassive
        }
    ));
}

#[test]
fn session_method_below_minimum_is_not_reused() {
    let engine = engine();
    // Requested PPT at minimum; the session was established by Password (level
    // 1 < 2), so it does not satisfy the request and must not be reused.
    let p = params(processed(
        false,
        false,
        vec![PPT],
        Some(AuthnContextComparison::Minimum),
    ));
    let s = session(AuthnMethodRef::Inline {
        class_ref: PASSWORD.to_string(),
        authn_authority: None,
    });
    let d = check_request(&engine, &p, Some(&s));
    assert!(matches!(d, Disposition::Authenticate { .. }));
}

#[test]
fn session_method_at_or_above_minimum_is_reused() {
    let engine = engine();
    // Requested Password at minimum; the session was established by PPT (level
    // 2 >= 1), so it satisfies the request and is reused.
    let p = params(processed(
        false,
        false,
        vec![PASSWORD],
        Some(AuthnContextComparison::Minimum),
    ));
    let s = session(AuthnMethodRef::Inline {
        class_ref: PPT.to_string(),
        authn_authority: None,
    });
    let d = check_request(&engine, &p, Some(&s));
    assert!(matches!(d, Disposition::ReuseSession { .. }));
}

#[test]
fn exact_unregistered_class_denies_no_authn_context() {
    let engine = engine();
    // An exact request for a class the broker does not register: nothing is
    // picked, so the request is denied.
    let p = params(processed(
        false,
        false,
        vec!["urn:example:unknown"],
        Some(AuthnContextComparison::Exact),
    ));
    let d = check_request(&engine, &p, None);
    assert!(matches!(
        d,
        Disposition::Deny {
            denial: crate::idp::orchestrator::Denial::NoAuthnContext
        }
    ));
}

#[test]
fn minimum_picks_stronger_methods() {
    let engine = engine();
    let p = params(processed(
        false,
        false,
        vec![PASSWORD],
        Some(AuthnContextComparison::Minimum),
    ));
    let d = check_request(&engine, &p, None);
    if let Disposition::Authenticate { methods } = d {
        let refs: Vec<&str> = methods.iter().map(|m| m.class_ref.as_str()).collect();
        // Password (1), PPT (2), X509 (3) all satisfy minimum-Password.
        assert!(refs.contains(&PASSWORD));
        assert!(refs.contains(&PPT));
        assert!(refs.contains(&X509));
    } else {
        panic!("expected Authenticate, got {d:?}");
    }
}

#[test]
fn authenticate_methods_are_strongest_first() {
    // Regression: Disposition::Authenticate's own doc comment promises
    // "strongest preference first", but AuthnBroker::pick preserves
    // registration order (Password=1, PPT=2, X509=3 — weakest first in the
    // test broker). A caller that just takes methods[0] must get the
    // strongest, not the first-registered.
    let engine = engine();
    let p = params(processed(
        false,
        false,
        vec![PASSWORD],
        Some(AuthnContextComparison::Minimum),
    ));
    let Disposition::Authenticate { methods } = check_request(&engine, &p, None) else {
        panic!("expected Authenticate");
    };
    let levels: Vec<u32> = methods.iter().map(|m| m.level).collect();
    assert_eq!(methods[0].class_ref, X509, "strongest method must be first");
    assert!(
        levels.windows(2).all(|w| w[0] >= w[1]),
        "methods must be sorted strongest-first, got levels {levels:?}"
    );
}

#[test]
fn better_excludes_requested_class() {
    let engine = engine();
    let p = params(processed(
        false,
        false,
        vec![PASSWORD],
        Some(AuthnContextComparison::Better),
    ));
    let d = check_request(&engine, &p, None);
    if let Disposition::Authenticate { methods } = d {
        let refs: Vec<&str> = methods.iter().map(|m| m.class_ref.as_str()).collect();
        // "better" than Password: PPT and X509, but not Password itself.
        assert!(!refs.contains(&PASSWORD));
        assert!(refs.contains(&PPT));
        assert!(refs.contains(&X509));
    } else {
        panic!("expected Authenticate, got {d:?}");
    }
}

#[test]
fn passive_with_satisfying_session_reuses() {
    let engine = engine();
    // IsPassive with a session that satisfies the request: reuse, no denial.
    let p = params(processed(
        false,
        true,
        vec![PASSWORD],
        Some(AuthnContextComparison::Exact),
    ));
    let s = session(AuthnMethodRef::Inline {
        class_ref: PASSWORD.to_string(),
        authn_authority: None,
    });
    let d = check_request(&engine, &p, Some(&s));
    assert!(matches!(d, Disposition::ReuseSession { .. }));
}

// ── AuthnMethodRef resolution ───────────────────────────────────────────────

#[test]
fn inline_method_resolves_as_is() {
    let b = broker();
    let m = AuthnMethodRef::Inline {
        class_ref: PPT.to_string(),
        authn_authority: Some("https://upstream.example.org".to_string()),
    };
    let (class_ref, authority) = m.resolve(&b);
    assert_eq!(class_ref, PPT);
    assert_eq!(authority.as_deref(), Some("https://upstream.example.org"));
}

#[test]
fn broker_reference_resolves_from_registration() {
    let b = broker();
    // The broker assigns references "1", "2", "3" in registration order.
    let m = AuthnMethodRef::BrokerReference("2".to_string());
    let (class_ref, authority) = m.resolve(&b);
    assert_eq!(class_ref, PPT);
    assert_eq!(authority, None);
}

#[test]
fn unknown_broker_reference_falls_back_to_reference() {
    let b = broker();
    // An unregistered reference resolves to itself with no authority (a
    // defensive fallback, not an error).
    let m = AuthnMethodRef::BrokerReference("does-not-exist".to_string());
    let (class_ref, authority) = m.resolve(&b);
    assert_eq!(class_ref, "does-not-exist");
    assert_eq!(authority, None);
}

// ── fail_on_missing_requested through create_authn_response ─────────────────

fn mail_attribute() -> Attribute {
    Attribute {
        name: "urn:oid:0.9.2342.19200300.100.1.3".to_string(),
        name_format: Some(constants::ATTRNAME_FORMAT_URI.to_string()),
        friendly_name: Some("mail".to_string()),
        values: vec![AttributeValue::String("alice@example.org".to_string())],
    }
}

/// An `SpSsoDescriptor` whose default AttributeConsumingService requires `mail`.
fn sp_sso_requiring_mail() -> SpSsoDescriptor {
    let mut sp = sp_sso();
    sp.attribute_consuming_services = vec![AttributeConsumingService {
        index: 0,
        is_default: Some(true),
        service_names: vec![],
        service_descriptions: vec![],
        requested_attributes: vec![RequestedAttribute {
            attribute: mail_attribute(),
            is_required: Some(true),
        }],
    }];
    sp
}

fn subject_with_mail() -> crate::idp::orchestrator::AuthenticatedSubject {
    crate::idp::orchestrator::AuthenticatedSubject {
        subject_id: "alice".to_string(),
        attributes: vec![mail_attribute()],
        authn_method: AuthnMethodRef::Inline {
            class_ref: PASSWORD.to_string(),
            authn_authority: None,
        },
        authn_instant: None,
        session_index: Some("_sess_1".to_string()),
    }
}

fn subject_without_mail() -> crate::idp::orchestrator::AuthenticatedSubject {
    crate::idp::orchestrator::AuthenticatedSubject {
        subject_id: "alice".to_string(),
        attributes: vec![],
        authn_method: AuthnMethodRef::Inline {
            class_ref: PASSWORD.to_string(),
            authn_authority: None,
        },
        authn_instant: None,
        session_index: Some("_sess_1".to_string()),
    }
}

/// An engine whose release seam is a pass-through (so the held attributes are
/// what the subject supplied) and whose decisions control
/// `fail_on_missing_requested`. Uses a fixture-backed signer so the denial
/// path (which signs unconditionally) can run.
fn engine_with_decisions(decisions: &ReleasePolicy) -> ResponseEngine<'_> {
    static BROKER: std::sync::OnceLock<AuthnBroker> = std::sync::OnceLock::new();
    static IDENTS: std::sync::OnceLock<IdentDb> = std::sync::OnceLock::new();
    static SIGNER: std::sync::OnceLock<SamlSigner> = std::sync::OnceLock::new();
    static CERT: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

    let broker = BROKER.get_or_init(broker);
    let idents = IDENTS.get_or_init(|| IdentDb::in_memory(IDP));
    let (signer, cert) = fixture_signer();
    let signer = SIGNER.get_or_init(|| signer);
    let cert = CERT.get_or_init(|| cert);

    ResponseEngine {
        idp_entity_id: IDP,
        decisions,
        release: &PassThroughRelease,
        idents,
        broker,
        assertions: None,
        signer,
        cert_der_b64: cert,
    }
}

#[test]
fn fail_on_missing_requested_denies_when_required_attribute_absent() {
    let decisions = ReleasePolicy::new(); // fail_on_missing_requested defaults to true
    let engine = engine_with_decisions(&decisions);
    let mut p = params(processed(false, false, vec![], None));
    p.sp_sso = sp_sso_requiring_mail();

    // The subject holds no `mail`, so the required attribute is missing.
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    assert!(matches!(
        outcome,
        ResponseOutcome::Denied {
            denial: crate::idp::orchestrator::Denial::MissingRequiredAttributes,
            ..
        }
    ));
}

#[test]
fn fail_on_missing_requested_issued_when_attribute_present() {
    let decisions = ReleasePolicy::new();
    let engine = engine_with_decisions(&decisions);
    let mut p = params(processed(false, false, vec![], None));
    p.sp_sso = sp_sso_requiring_mail();

    // The subject holds `mail`, so the required attribute is satisfied.
    let outcome = create_authn_response(&engine, &p, &subject_with_mail()).unwrap();
    assert!(matches!(outcome, ResponseOutcome::Issued(_)));
}

/// An engine whose release seam is the real `ReleasePolicy` (not
/// `PassThroughRelease`) — the documented default for an originating IdP.
fn engine_with_release_policy(decisions: &ReleasePolicy) -> ResponseEngine<'_> {
    static BROKER: std::sync::OnceLock<AuthnBroker> = std::sync::OnceLock::new();
    static IDENTS: std::sync::OnceLock<IdentDb> = std::sync::OnceLock::new();
    static SIGNER: std::sync::OnceLock<SamlSigner> = std::sync::OnceLock::new();
    static CERT: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

    let broker = BROKER.get_or_init(broker);
    let idents = IDENTS.get_or_init(|| IdentDb::in_memory(IDP));
    let (signer, cert) = fixture_signer();
    let signer = SIGNER.get_or_init(|| signer);
    let cert = CERT.get_or_init(|| cert);

    ResponseEngine {
        idp_entity_id: IDP,
        decisions,
        release: decisions,
        idents,
        broker,
        assertions: None,
        signer,
        cert_der_b64: cert,
    }
}

#[test]
fn release_policy_missing_required_attribute_denies_not_errors() {
    // With the real ReleasePolicy as the release seam (an originating IdP,
    // the documented common case), `ReleasePolicy::release` itself refuses a
    // missing required attribute with `PolicyError::MissingRequiredAttribute`.
    // That must surface as a signed `Denial::MissingRequiredAttributes`, not
    // an `Err` (which the Actix/example-idp callers would otherwise turn into
    // an HTTP 500 for what is actually a normal, expected SP-side condition).
    let decisions = ReleasePolicy::new(); // fail_on_missing_requested defaults to true
    let engine = engine_with_release_policy(&decisions);
    let mut p = params(processed(false, false, vec![], None));
    p.sp_sso = sp_sso_requiring_mail();

    let outcome = create_authn_response(&engine, &p, &subject_without_mail())
        .expect("a missing required attribute is a denial, not a ProfileError");
    assert!(matches!(
        outcome,
        ResponseOutcome::Denied {
            denial: crate::idp::orchestrator::Denial::MissingRequiredAttributes,
            ..
        }
    ));
}

#[test]
fn release_policy_missing_required_value_denies_not_errors() {
    // Same as above, but the attribute name is present while the specific
    // required *value* is not - PolicyError::MissingRequiredValue, which must
    // map to the same signed denial.
    let decisions = ReleasePolicy::new();
    let engine = engine_with_release_policy(&decisions);
    let mut p = params(processed(false, false, vec![], None));
    let mut sp = sp_sso_requiring_mail();
    sp.attribute_consuming_services[0].requested_attributes[0]
        .attribute
        .values = vec![AttributeValue::String("required@example.org".to_string())];
    p.sp_sso = sp;

    // The subject holds `mail`, but with a different value than required.
    let outcome = create_authn_response(&engine, &p, &subject_with_mail())
        .expect("a missing required value is a denial, not a ProfileError");
    assert!(matches!(
        outcome,
        ResponseOutcome::Denied {
            denial: crate::idp::orchestrator::Denial::MissingRequiredAttributes,
            ..
        }
    ));
}

#[test]
fn pass_through_release_missing_required_value_is_still_denied() {
    // The value check (step 3) must not depend on which AttributeRelease
    // implementation ran: PassThroughRelease never validates values itself,
    // so this is the only safety net for a proxy shape.
    let decisions = ReleasePolicy::new();
    let engine = engine_with_decisions(&decisions); // release: &PassThroughRelease
    let mut p = params(processed(false, false, vec![], None));
    let mut sp = sp_sso_requiring_mail();
    sp.attribute_consuming_services[0].requested_attributes[0]
        .attribute
        .values = vec![AttributeValue::String("required@example.org".to_string())];
    p.sp_sso = sp;

    let outcome = create_authn_response(&engine, &p, &subject_with_mail())
        .expect("a missing required value is a denial, not a ProfileError");
    assert!(matches!(
        outcome,
        ResponseOutcome::Denied {
            denial: crate::idp::orchestrator::Denial::MissingRequiredAttributes,
            ..
        }
    ));
}

#[test]
fn fail_on_missing_requested_disabled_omits_silently() {
    let decisions = ReleasePolicy::with_default(
        crate::idp::policy::PolicyEntry::new().with_fail_on_missing_requested(false),
    );
    let engine = engine_with_decisions(&decisions);
    let mut p = params(processed(false, false, vec![], None));
    p.sp_sso = sp_sso_requiring_mail();

    // With the flag off, a missing required attribute is a silent omission,
    // not a denial.
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    match outcome {
        ResponseOutcome::Issued(issued) => {
            assert!(issued.released_attribute_names.is_empty());
        }
        other => panic!("expected Issued, got {other:?}"),
    }
}

// ── Authn context revalidation through create_authn_response ───────────────

#[test]
fn create_authn_response_denies_a_method_that_does_not_satisfy_the_request() {
    // check_request only offers methods that would satisfy the request; it
    // cannot guarantee which method the application's callback ultimately
    // used to authenticate the subject it hands to create_authn_response
    // directly. A Password subject for an exact X509 request must not
    // produce a successful assertion claiming a context that was never
    // actually satisfied. Uses a fixture-backed signer since the denial path
    // signs unconditionally.
    let decisions = ReleasePolicy::new();
    let engine = engine_with_decisions(&decisions);
    let p = params(processed(
        false,
        false,
        vec![X509],
        Some(AuthnContextComparison::Exact),
    ));
    let subject = crate::idp::orchestrator::AuthenticatedSubject {
        subject_id: "alice".to_string(),
        attributes: vec![],
        authn_method: AuthnMethodRef::Inline {
            class_ref: PASSWORD.to_string(),
            authn_authority: None,
        },
        authn_instant: None,
        session_index: Some("_sess_1".to_string()),
    };

    let outcome = create_authn_response(&engine, &p, &subject).unwrap();
    assert!(matches!(
        outcome,
        ResponseOutcome::Denied {
            denial: crate::idp::orchestrator::Denial::NoAuthnContext,
            ..
        }
    ));
}

#[test]
fn create_authn_response_issues_when_method_satisfies_the_request() {
    // Positive control: a method that does satisfy the exact request must
    // still succeed - the revalidation must not be overly strict.
    let engine = engine();
    let p = params(processed(
        false,
        false,
        vec![X509],
        Some(AuthnContextComparison::Exact),
    ));
    let subject = crate::idp::orchestrator::AuthenticatedSubject {
        subject_id: "alice".to_string(),
        attributes: vec![],
        authn_method: AuthnMethodRef::Inline {
            class_ref: X509.to_string(),
            authn_authority: None,
        },
        authn_instant: None,
        session_index: Some("_sess_1".to_string()),
    };

    let outcome = create_authn_response(&engine, &p, &subject).unwrap();
    assert!(matches!(outcome, ResponseOutcome::Issued(_)));
}

#[test]
fn issued_not_on_or_after_matches_the_wire_assertion_lifetime() {
    // Regression: the assertion's wire NotOnOrAfter is built from a
    // normalized (whole-second, non-negative) lifetime
    // (`lifetime.num_seconds().max(0)`), but IssuedResponse.not_on_or_after
    // must be derived from that same normalized value, not the raw
    // sub-second TimeDelta, or the two can disagree.
    let decisions = ReleasePolicy::with_default(
        crate::idp::policy::PolicyEntry::new().with_lifetime(TimeDelta::milliseconds(2_500)),
    );
    let engine = engine_with_decisions(&decisions);
    let p = params(processed(false, false, vec![], None));
    let subject = subject_with_mail();

    let before = chrono::Utc::now();
    let outcome = create_authn_response(&engine, &p, &subject).unwrap();
    match outcome {
        ResponseOutcome::Issued(issued) => {
            // The normalized lifetime is 2 whole seconds, not 2.5.
            let expected = before + TimeDelta::seconds(2);
            let delta = (issued.not_on_or_after - expected).num_milliseconds().abs();
            assert!(
                delta < 500,
                "not_on_or_after {} should be ~2s (normalized) after issuance, not 2.5s",
                issued.not_on_or_after
            );
        }
        other => panic!("expected Issued, got {other:?}"),
    }
}

// ── ResponseParams metadata signals ──────────────────────────────────────────

#[test]
fn subject_id_req_reads_the_full_metadata_attribute_name() {
    // Regression: the SP metadata attribute Name is the full URI
    // (SUBJECT_ID_REQ_ATTR), not the short label "subject-id:req". Looking
    // up the short label can never match, so this signal would always read
    // as SubjectIdReq::None regardless of what the SP actually published.
    use crate::metadata::types::entity_descriptor::{EntityDescriptor, EntityRoles};
    use crate::metadata::types::extensions::Extensions;

    let entity = EntityDescriptor {
        entity_id: SP.to_string(),
        id: None,
        valid_until: None,
        cache_duration: None,
        has_signature: false,
        extensions: Some(Extensions::new(format!(
            r#"<mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
              <saml:Attribute Name="{}">
                <saml:AttributeValue>any</saml:AttributeValue>
              </saml:Attribute>
            </mdattr:EntityAttributes>"#,
            crate::idp::entity_category::SUBJECT_ID_REQ_ATTR
        ))),
        roles: EntityRoles::Roles {
            idp_sso: vec![],
            sp_sso: vec![],
            authn_authority: vec![],
            attr_authority: vec![],
            pdp: vec![],
        },
        organization: None,
        contact_persons: vec![],
        additional_metadata_locations: vec![],
    };

    let mut p = params(processed(false, false, vec![], None));
    p.sp_entity = Some(entity);
    assert_eq!(
        p.subject_id_req(),
        crate::idp::entity_category::SubjectIdReq::Any
    );
}

// ── ResponseEngine over a non-default IdentityStore ─────────────────────────

/// A distinct `IdentityStore` impl (not `InMemoryIdentityStore`) — stands in
/// for a Redis/SQL-backed store. Proves `ResponseEngine::idents` (`dyn
/// NameIdConstructor`) actually accepts an `IdentDb` over any store, not
/// just the default.
#[derive(Default)]
struct CustomStore(std::sync::Mutex<std::collections::HashMap<String, String>>);

impl IdentityStore for CustomStore {
    fn get(&self, key: &str) -> Option<String> {
        self.0.lock().unwrap().get(key).cloned()
    }
    fn set(&self, key: &str, value: String) {
        self.0.lock().unwrap().insert(key.to_string(), value);
    }
    fn remove(&self, key: &str) {
        self.0.lock().unwrap().remove(key);
    }
}

#[test]
fn response_engine_accepts_a_non_default_identity_store() {
    let idents = IdentDb::new(CustomStore::default(), IDP);
    let broker = broker();
    let decisions = ReleasePolicy::new();
    let engine = ResponseEngine {
        idp_entity_id: IDP,
        decisions: &decisions,
        release: &decisions,
        idents: &idents, // &IdentDb<CustomStore> coerces to &dyn NameIdConstructor
        broker: &broker,
        assertions: None,
        signer: &SamlSigner::new(KeysManager::new()),
        cert_der_b64: "",
    };

    let p = params(processed(false, false, vec![], None));
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    assert!(matches!(outcome, ResponseOutcome::Issued(_)));
}

// ── NameID construction through create_authn_response ──────────────────────

#[test]
fn no_name_id_policy_uses_decisions_default_format() {
    // `decisions.nameid_format(sp)` defaults to transient; a request with no
    // NameIDPolicy at all must fall back to it rather than erroring.
    let engine = engine();
    let p = params(processed(false, false, vec![], None));
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    match outcome {
        ResponseOutcome::Issued(issued) => {
            assert_eq!(
                issued.name_id.format.as_deref(),
                Some(constants::NAMEID_TRANSIENT)
            );
        }
        other => panic!("expected Issued, got {other:?}"),
    }
}

/// A `ProcessedAuthnRequest` carrying a `NameIDPolicy`.
fn processed_with_name_id_policy(
    format: Option<&str>,
    sp_name_qualifier: Option<&str>,
    allow_create: bool,
) -> ProcessedAuthnRequest {
    let mut p = processed(false, false, vec![], None);
    p.has_name_id_policy = true;
    p.requested_name_id_format = format.map(String::from);
    p.requested_sp_name_qualifier = sp_name_qualifier.map(String::from);
    p.allow_create = allow_create;
    p
}

#[test]
fn sp_name_qualifier_honoured_over_sp_entity_id() {
    let engine = engine();
    let p = params(processed_with_name_id_policy(
        Some(constants::NAMEID_TRANSIENT),
        Some("https://requester.example.org"),
        true,
    ));
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    match outcome {
        ResponseOutcome::Issued(issued) => {
            // The policy's explicit SPNameQualifier wins over the SP entity ID
            // the request actually came from.
            assert_eq!(
                issued.name_id.sp_name_qualifier.as_deref(),
                Some("https://requester.example.org")
            );
        }
        other => panic!("expected Issued, got {other:?}"),
    }
}

#[test]
fn persistent_format_disallowed_create_denies_creation() {
    // Persistent format, AllowCreate=false, and no identifier already exists
    // for this (user, SP) pair: the IdP must refuse to fabricate one.
    let decisions = ReleasePolicy::new();
    let engine = engine_with_decisions(&decisions);
    let p = params(processed_with_name_id_policy(
        Some(constants::NAMEID_PERSISTENT),
        None,
        false,
    ));
    let outcome = create_authn_response(&engine, &p, &subject_without_mail()).unwrap();
    assert!(matches!(
        outcome,
        ResponseOutcome::Denied {
            denial: crate::idp::orchestrator::Denial::NameIdCreationNotAllowed,
            ..
        }
    ));
}

// ── Two-consumer falsification test (ADR's own condition) ──────────────────

#[test]
fn proxy_shape_produces_compliant_response_without_release_policy_filter() {
    // A fixture IdP configured the way a proxy (e.g. tunnelbana) would use the
    // engine: `PassThroughRelease` (attributes already filtered upstream) and
    // an inline authn method carrying a non-empty `authenticating_authorities`
    // chain. If the engine can only produce a compliant response by routing
    // through `ReleasePolicy::filter`, the release seam is the wrong
    // abstraction — this is the ADR's own falsification condition, not a
    // nice-to-have.
    let engine = engine(); // release: &PassThroughRelease, see engine()
    let p = params(processed(false, false, vec![], None));
    let subject = crate::idp::orchestrator::AuthenticatedSubject {
        subject_id: "alice".to_string(),
        attributes: vec![mail_attribute()],
        authn_method: AuthnMethodRef::Inline {
            class_ref: PASSWORD.to_string(),
            authn_authority: Some("https://upstream.example.org/idp".to_string()),
        },
        authn_instant: None,
        session_index: Some("_sess_1".to_string()),
    };

    let outcome = create_authn_response(&engine, &p, &subject).unwrap();
    match outcome {
        ResponseOutcome::Issued(issued) => {
            // The pass-through attribute survived untouched (no
            // ReleasePolicy::filter ran on it).
            assert_eq!(issued.released_attribute_names.len(), 1);
            assert!(issued
                .xml
                .contains("<saml:AuthenticatingAuthority>https://upstream.example.org/idp</saml:AuthenticatingAuthority>"));
        }
        other => panic!("expected Issued, got {other:?}"),
    }
}
