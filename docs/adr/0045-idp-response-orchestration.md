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
   | Request-constraint handling | `IsPassive`, `ForceAuthn`, requested NameID format | Fixed (`check_request`) |
   | Assemble + sign | `ResponseOptions` -> `create_signed_response` (ADR 0033) | Fixed |
   | Record for back-channel queries | `AssertionStore` | Injected store |

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

3. Keep deployment specifics behind the seams ADR 0008 already defined --
   `IdentityStore`, `AssertionStore`, the `AuthnCallback` escape hatch, and
   `ReleasePolicy`/`EntityCategoryPolicy` configuration. No consumer identity
   model, userdb, or federation policy choice enters the crate.

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
  `ProcessedAuthnRequest` gained `requested_sp_name_qualifier`. Every
  in-crate struct literal was fixed with `..Default::default()`. External
  consumers with hand-built `ResponseOptions` literals (tunnelbana: 7 sites
  across `saml2_frontend.rs`, `saml2_backend.rs`, `stepup.rs`, and four test
  files) need a one-line compat patch, prepared separately and offered to
  SUNET alongside this ADR rather than discovered via a failed build.

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
  RequestedAuthnContext matrix (13 scenarios); NameID default-format
  fallback, `SPNameQualifier` precedence, `AllowCreate=false` denial; and a
  falsification test proving a `PassThroughRelease` + inline-authn-method
  proxy shape produces a compliant response without `ReleasePolicy::filter`
  ever running.
- `tests/idp_orchestration_roundtrip.rs`: orchestrated XML through the real
  SP-side verification path, asserting `InResponseTo`, `NameID`, session
  index, `authenticating_authorities`, and `NotOnOrAfter` all survive, with
  both signatures verifying.
- `tests/idp_release_through_engine.rs`: REFEDS entity-category release
  driven through `create_authn_response`, confirming only the released
  attributes reach the signed XML.
- `tests/attack_corpus.rs` (`orchestrator_attacks`): an unknown
  `AttributeConsumingServiceIndex` resolves to no requirements rather than
  another service's; an `SPNameQualifier` XML-injection payload comes back
  escaped and inert; a denial's `StatusMessage` never echoes SP-supplied
  text.
- `example-idp` rewritten on the engine; all 12 of its tests pass against a
  real fixture signing key (denials now sign unconditionally, so a keyless
  test signer no longer suffices).
- `cargo clippy -p gamlastan -p gamlastan-actix -p example-idp --tests -- -D
  warnings` and `cargo fmt --check` clean across all three crates.
