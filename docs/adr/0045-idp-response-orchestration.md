# ADR 0045 - IdP response orchestration as a crate-level engine

- **Status:** Accepted
- **Date:** 2026-09-18
- **Deciders:** gamlastan maintainers
- **Spec:** SAML V2.0 Profiles §4.1 (Web Browser SSO), SAML V2.0 Core §2.5/§2.7
- **Related:** [0008](0008-idp-server-infrastructure.md) (IdP server infrastructure),
  [0033](0033-idp-response-signing-helpers.md) (in-core signing helpers)
- **Implementation:** `crates/gamlastan/src/idp/orchestrator/`,
  `crates/gamlastan-actix/src/idp.rs`, `example-idp/src/main.rs`

## Context

ADR 0008 added `gamlastan::idp` (`policy`, `entity_category`, `ident`, `eptid`,
`authn_broker`, `assertion_store`) and deliberately stopped at the primitives, on
the stated model that an integrator wires a `ReleasePolicy`, an `IdentDb`, an
`AuthnBroker`, and an `AssertionStore`. That boundary didn't hold:
`ReleasePolicy::filter`, `IdentDb::construct_nameid`, `AuthnBroker::pick` and
`Eptid` had zero callers in any response-assembly path.

Meanwhile the consuming contract evolved to expect the primitives' outputs, not
to produce them: `gamlastan-actix`'s `AuthnCallback` returns an already-built
`name_id`, already-filtered `attributes`, and an already-matched
`authn_context_class_ref`. So the crate shipped both the policy engine and an
interface shaped around its outputs, leaving every integrator to write the same
bridge: run the release policy, construct or look up the NameID, match the
requested authn context, populate `ResponseOptions`, sign. That bridge is not
deployment-specific -- it is the SAML Web Browser SSO profile.

Two real consumers needed that bridge, wrote it independently instead of
calling into `gamlastan::idp`, and diverged. `example-idp` is the de-facto
reference implementation (honours `IsPassive`, `ForceAuthn`, ACR comparison,
signed protocol errors) but lived in example code, uncovered by the crate's
compatibility promise. SUNET's `tunnelbana` proxy hand-rolls the same path and
imports nothing from `gamlastan::idp`: its `legacy_eptid` micro-service
reimplements the MD5 construction `idp::eptid` already ships behind
`allow_legacy_md5` (ADR 0036), and its own per-SP policy map is a narrower,
weaker version of `idp::policy::ReleasePolicy` that is missing entity-category
release -- the piece that matters most for a proxy fronting SWAMID SPs.

Separately, the message-building API assumed an originating IdP only:
`create_response` hardcoded `authenticating_authorities: vec![]`, though the
core `AuthnContext` type carries it and the XML layer serialises it. A
proxying IdP is required by SAML Core §2.7.2.2 to name the authority it relied
on and could not, through this API.

## Decision

Add a response-orchestration layer to `gamlastan::idp` that composes the
existing primitives into the profile flow, and move the semantics proven in
`example-idp` into tested library code.

1. `idp::orchestrator::ResponseEngine`, given a processed `AuthnRequest`, SP
   metadata, and identity facts from the application, performs:

   | Step | Existing primitive | Fixed or injected? |
   | --- | --- | --- |
   | Release decision | `ReleasePolicy` + `EntityCategoryPolicy` | Injected (see below) |
   | NameID construction / lookup | `IdentDb` (+ `Eptid`) behind `IdentityStore` | Injected store, fixed mechanics |
   | RequestedAuthnContext match | `AuthnBroker` | Injected broker, fixed comparison semantics |
   | Request-constraint handling | `IsPassive`, `ForceAuthn`, requested NameID format, session expiry | Fixed (`check_request`) |
   | Assemble + sign | `ResponseOptions` -> `create_signed_response` (ADR 0033) | Fixed |
   | Record for back-channel queries | `AssertionStore` | Injected store |

   `RequestedAuthnContext` matching for `Comparison="exact"` is a literal
   match of one of the requested `AuthnContextClassRef` values
   (saml-core-2.0-os 3.3.2.2.1), not "registered at the same security level
   as the requested class" -- pysaml2's own `AuthnBroker` has that looser
   behaviour, and gamlastan intentionally diverges from it for spec
   conformance. `AuthnBroker::allow_exact_level_matching` restores the
   pysaml2-compatible behaviour for integrators who need parity over strict
   conformance.

   NameID construction rejects a `NameIDPolicy/@SPNameQualifier` that names
   an entity other than the verified requester: per saml-core-2.0-os 8.3.7
   it may legitimately name an affiliation the requester belongs to, but
   only when the IdP can verify that membership (`AffiliationDescriptor`),
   which this crate does not implement. Honouring an arbitrary
   requester-supplied value would let one SP request another SP's pairwise
   persistent identifier for the same subject just by naming it in its own
   request -- so a mismatched qualifier is denied (`InvalidNameIdPolicy`)
   rather than passed through. Persistent NameID minting is also
   concurrency-safe: `IdentityStore` gained a provided `compare_and_swap`
   method, and every writer of a user's forward NameID list
   (`store`/`get_or_create_persistent`/`remove_remote`/`remove_local`) goes
   through it with a retry loop, so two concurrent requests (for the same or
   different SPs) can no longer silently drop one writer's update or mint
   two different "stable" persistent identifiers for the same (user, SP).

   Attribute release is a seam, not a hardwired step, because deployments
   legitimately source the released set differently: an originating IdP
   applies federation policy (`ReleasePolicy` + entity categories); a proxy
   receives attributes already filtered upstream and may add a per-requester
   layer, as tunnelbana does. Release is the `AttributeRelease` trait, with
   `ReleasePolicy` itself, `PassThroughRelease` for pre-filtered inputs, and
   `ChainedRelease` composing the two. Everything downstream of it -- NameID
   negotiation, `InResponseTo`, audience and conditions, session index and
   lifetime, `IsPassive`/`ForceAuthn` enforcement, signed protocol errors -- is
   fixed.

   A failure to satisfy a constraint produces a signed SAML protocol error (a
   closed `Denial` enum with a fixed `Status` mapping), not an
   application-level error, matching what `example-idp` did before this ADR.
   Denials always sign the Response envelope unconditionally, regardless of
   the per-SP `SignTargets` -- an unsigned denial is trivially forgeable.

2. Invert the application contract. The application supplies what only it
   knows -- subject identifier, raw attribute values, which authentication
   method actually ran, authn instant, session index (`AuthenticatedSubject`)
   -- and the engine derives `name_id`, released `attributes`, and
   `authn_context_class_ref`. The existing `AuthnCallback`/`AuthnCallbackResult`
   remains as the lower-level escape hatch; `gamlastan-actix` gains
   `AuthnSubjectCallback`/`AuthnSubjectResult`
   (`Authenticated(AuthenticatedSubject) | Redirect(HttpResponse) |
   Deny(Denial)`) alongside it. This is additive; nothing existing breaks.

   The SSO handler calls `check_request` itself, before invoking
   `AuthnSubjectCallback`, and passes the resulting `Disposition` to the
   callback (via a new optional `EstablishedSessionCallback` reporting local
   session state, distinct from `SessionStore`, which tracks SP-participant
   state for SLO). A `Deny` disposition is handled directly as a signed
   protocol error -- the callback is never invoked for it. This is the part
   that actually inverts the contract: the callback no longer has to
   (mis)judge `ForceAuthn`/`IsPassive`/`RequestedAuthnContext` itself, it only
   supplies attributes and performs the login `check_request` says is needed.

   `gamlastan-actix` registers the engine's dependencies as an owned
   `ResponseEngineParts` (`Arc<ReleasePolicy>`, `Arc<dyn AttributeRelease>`,
   `Arc<dyn NameIdConstructor>`, `Arc<AuthnBroker>`, `Arc<SamlSigner>`, ...)
   rather than a `ResponseEngine<'static>` directly: `ResponseEngine` borrows
   by design (a zero-cost fit for one synchronous call), but a route
   handler's signature is fixed and registered once, so requiring `'static`
   on every borrowed dependency would force ordinary application-owned state
   to be leaked. The handler builds a short-lived borrowed `ResponseEngine`
   from `ResponseEngineParts` per request.

3. Keep deployment specifics behind the seams ADR 0008 already defined --
   `IdentityStore`, `AssertionStore`, the `AuthnCallback` escape hatch, and
   `ReleasePolicy`/`EntityCategoryPolicy` configuration. No consumer identity
   model, userdb, or federation policy choice enters the crate.

   `gamlastan-actix`'s trusted-SP registry (`IdpConfig`/`TrustedSp`/
   `TrustedSpResolver`) stores the SP's full `EntityDescriptor`, not just its
   SSO descriptor, keyed by the descriptor's own `entity_id` (no separate
   registration-key field, so the two cannot drift apart) -- entity
   categories and other entity-level extensions need to reach
   `ResponseParams::sp_entity` for the attribute-release seam to see them.

4. In-crate module, not a new crate, consistent with ADR 0008's reasoning: it
   depends only on `gamlastan` internals.

Naming: `idp::orchestrator`, not `idp::server` -- `server` implies a stateful
daemon, a mental model that belongs one layer up in a language binding's own
`Server` facade, not in this crate. `ReleasePolicy::fail_on_missing_requested`
(already existed) now drives `Denial::MissingRequiredAttributes` when a
required attribute the SP asked for was not released, so partial-release
failure is a real protocol error rather than a silent per-integrator choice.

## Consequences

- The `gamlastan::idp` primitives acquired callers; the module is usable as a
  policy-driven IdP rather than a toolkit each integrator assembles from
  scratch.
- Response assembly -- NameID correctness, audience and conditions, what is
  signed -- is exercised by the crate's own test suite and attack corpus
  rather than reimplemented per deployment.
- `example-idp` was rewritten onto the engine: production code (excluding
  tests) shrank from 1516 to 1462 lines, with the hand-rolled
  `build_saml_response`/`build_saml_error_response`/`render_saml_response`/
  `select_authn_context`/`authn_context_satisfies` plumbing replaced by calls
  into `check_request`/`create_authn_response`/`create_denial_response`.
- A convergence path exists for tunnelbana's hand-rolled assembly and its
  `legacy_eptid` micro-service, though adopting it is not a precondition of
  this ADR.
- A second, higher-level authentication contract now needs documenting and
  supporting alongside the existing one. Mitigated by making the old path the
  explicit escape hatch.
- Opinionated ordering: the engine fixes the sequence policy -> NameID ->
  authn context -> assemble. Deployments needing a different order use the
  low-level path.
- Breaking (pre-release): `ResponseOptions` gained
  `authenticating_authorities: Vec<String>` (with a new `impl Default`), and
  `ProcessedAuthnRequest` gained `requested_sp_name_qualifier` and
  `has_name_id_policy`. Every in-crate struct literal was fixed with
  `..Default::default()`. External consumers with hand-built
  `ResponseOptions` literals (tunnelbana: 7 sites across
  `saml2_frontend.rs`, `saml2_backend.rs`, `stepup.rs`, and four test
  files) need a one-line compat patch, prepared separately and offered to
  SUNET alongside this ADR rather than discovered via a failed build.
- Breaking (pre-release): `AuthnBroker::pick` with `Comparison="exact"`
  changed from level-based matching to literal class-ref matching (see
  above). Any integrator relying on the old broadened behaviour must pass
  `allow_exact_level_matching(true)` explicitly.

## Alternatives considered

- **Status quo -- leave orchestration to the integrator (ADR 0008's
  position).** The bridge is not where integrators actually differ: they
  differ in identity sources and policy configuration, both already behind
  seams. What they duplicated was profile mechanics, the crate's subject
  matter, and the duplication was invisible until someone got `InResponseTo`,
  audience restriction, or NameID format subtly wrong.
- **Put the engine in a language binding.** Rejected: layering inversion.
  Orchestration is protocol logic, not language binding; placing it there
  makes it usable from one binding only, so every Rust IdP built on this
  crate re-implements it -- which tunnelbana's SAML frontend had already
  done.
- **Each deployment implements it in application code.** Rejected as a
  general answer: it puts SAML profile mechanics outside the crate whose
  subject matter they are, and makes every deployment the long-term
  maintainer of a private copy.
- **A separate `gamlastan-idp` crate.** Deferred for the reasons ADR 0008
  gave; nothing here changes that calculus.
- **Promote `example-idp` verbatim.** Rejected: it hardcoded single-instance
  choices and an in-memory session model. Its semantics were lifted; its
  structure was not.

## Validation

- `idp/orchestrator/tests.rs`: `Denial::status()` exhaustive; `AttributeRelease`
  impls incl. `ChainedRelease` ordering; the ForceAuthn/IsPassive/
  RequestedAuthnContext matrix, including refusing to reuse a session past
  its own absolute expiry (`authn_instant + session_lifetime`); NameID
  default-format fallback, `SPNameQualifier` precedence and cross-entity
  rejection, `AllowCreate=false` denial; `SessionNotOnOrAfter` on a reused
  session derived from the session's original `authn_instant`, not `now`;
  and a falsification test proving a `PassThroughRelease` + inline-authn-method
  proxy shape produces a compliant response without `ReleasePolicy::filter`
  ever running.
- `idp/ident.rs`: concurrent persistent-NameID minting for the same
  (user, SP) resolves to one identifier; concurrent persistent + transient
  issuance don't clobber each other's forward-list entry; `remove_local`
  racing a concurrent writer never leaves an orphaned reverse-key entry.
- `idp/authn_broker.rs`: exact matching excludes a method registered at the
  same security level under a different, unrequested class ref by default;
  `allow_exact_level_matching` restores the old pysaml2-compatible
  broadening.
- `metadata/types/entity_descriptor.rs`: `saml2_sp_sso_descriptor` selects
  by `protocolSupportEnumeration`, skipping a non-SAML-2.0 role listed
  first in a multi-role entity.
- `tests/idp_orchestration_roundtrip.rs`: orchestrated XML through the real
  SP-side verification path, asserting `InResponseTo`, `NameID`, session
  index, `authenticating_authorities`, and `NotOnOrAfter` all survive, with
  both signatures verifying.
- `tests/idp_release_through_engine.rs`: REFEDS entity-category release
  driven through `create_authn_response`, confirming only the released
  attributes reach the signed XML.
- `tests/attack_corpus.rs` (`orchestrator_attacks`): an explicit, unrecognized
  `AttributeConsumingServiceIndex` is denied rather than silently falling
  through to "no requirements" (which would bypass that service's own
  attribute scoping); an `SPNameQualifier` XML-injection payload equal to
  the requester's own entity ID comes back escaped and inert (a qualifier
  naming a *different* entity is rejected outright before response assembly
  -- covered in `idp/orchestrator/tests.rs`); a denial's `StatusMessage`
  never echoes SP-supplied text.
- `example-idp` rewritten on the engine; all 12 of its tests pass against a
  real fixture signing key (denials now sign unconditionally, so a keyless
  test signer no longer suffices).
- `gamlastan-actix`'s `idp_sso` policy-driven path, exercised end-to-end for
  the first time (it had zero test coverage before this ADR): a callback is
  skipped entirely and a signed denial returned when `check_request` says
  `Deny`; the callback is invoked normally when authentication is needed;
  entity-category release reaches the signed response through the real
  handler (not just the core engine in isolation); a non-default
  `IdentityStore` works through `ResponseEngineParts`; a `TrustedSpResolver`
  returning a mismatched `entity_id` is rejected.
- `cargo clippy -p gamlastan -p gamlastan-actix -p example-idp --tests -- -D
  warnings` and `cargo fmt --check` clean across all three crates.
