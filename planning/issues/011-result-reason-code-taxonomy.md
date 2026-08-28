# M1-011: Define the Appraisal Result and reason-code taxonomy
<!-- labels: type: architecture,area: model,area: verifier,area: privacy,risk: trusted-computing-base,risk: privacy,status: needs-review -->
<!-- milestone: M1 Domain Model -->

## Problem

The verifier state machine can produce one exact-attempt
`VerifiedAttestation`, but it cannot yet turn that capability into a semantic
outcome. Existing `Decision`, `ReasonCode`, and `VerificationOutcome` values are
report-only and do not carry relying-party correlation or typed accepted
claims. A public builder or a flat structure with
optional fields would let callers combine an allow report with unrelated raw
request data, omit required claims, attach accepted claims to failures, or
create contradictory result shapes.

The current reason taxonomy also omits challenge-authentication failure,
unsupported platform, unknown critical requirement, and transient failure.
`ReasonCode::None` encodes absence as a synthetic reason. Existing failure
methods permit every reason-shaped action from every nonterminal phase, which
can report semantically false histories such as replay after freshness passed
or policy denial before policy appraisal.

The architecture reserves `AttestationResult` for the future verifier-protected
object containing an evidence commitment, verifier identity, and signature.
This issue therefore names the unsigned semantic value `AppraisalResult`.

On 2026-08-28, the decision owner approved exact candidate tree
`bc015648a08f10de543b764d8333baaf6e423114` with no requested change. That
approval clears the design blocker and permits `status: ready`; runtime
implementation still requires a separately reviewed and approved plan.

## Security invariants

This issue enforces the pure-model portions of invariants 1-6, 20-21,
25-26, 34, 37-40, 42, and 48.

- Only the complete exact-attempt verifier path may create an allowed
  `AppraisalResult`.
- `Decision`, `ReasonCode`, and `VerificationOutcome` remain reports and cannot
  substitute for `VerifiedAttestation`.
- Every Appraisal Result carries exact relying-party context.
- Only allowed outcomes carry accepted claims.
- Full and restricted outcomes remain bound to the exact policy selected in
  `ExpectedContext`; restricted is not fallback or policy substitution.
- Every unsuccessful outcome carries exactly one phase-eligible coarse reason.
- An Appraisal Result remains unsigned and grants no permit, proof, admission,
  protected Attestation Result, or disciplinary authority.
- Terminal flows retain no attempt binding, replay registration, or attempt
  allocation; success transfers sole binding ownership into the completed
  capability and failure releases it before return.

## Threats addressed

- A1 or faulty orchestration presents a freely constructed allow report as an
  Appraisal Result.
- Trusted orchestration refills result fields from a different request after
  the original request was released.
- A capability from one attempt is substituted into an equal distinct attempt.
- A failure reached after evidence or session appraisal retains accepted
  claims.
- A reason is reported from a phase where its underlying check cannot occur.
- Contradictory outcome data is interpreted inconsistently by later consumers.
- A8 or faulty diagnostics disclose context, timing, key handles, or claims.
- Unsupported, unavailable, transient, revoked, and policy-denied conditions
  collapse into an accusation or indistinguishable generic error.

## In scope

- One pure semantic `AppraisalResult` owned by `ogir-verifier`.
- A private discriminated payload with full allow, restricted allow, and
  unsuccessful shapes.
- Allowed claims containing the accepted `EvidenceProfile` and exact-attempt-
  associated `SessionPublicKeyId`.
- Exact relying-party `ExpectedContext` on every Appraisal Result.
- Successful completion that moves exact context and accepted claims into
  `VerifiedAttestation`, followed by consuming conversion with no refill input.
- Failure transitions that atomically return one unsuccessful Appraisal Result
  and cannot issue a second result.
- Typed accumulation of accepted claims under the existing allocation-identity
  attempt binding before raw request release.
- One exhaustive five-decision/fifteen-reason taxonomy with phase eligibility.
- `VerificationOutcome::reason()` returning `Option<ReasonCode>` so allowed
  reports have no synthetic reason.
- Whole-state terminal replacement, fixed redaction, and explicit limits on
  what provenance the pure types establish.
- Updated model, architecture, threat, test, ADR, glossary, and attack-scenario
  documentation.

## Out of scope

- Evidence-commitment representation, algorithm, or protected result. M1-012
  defines binding-transcript inputs without choosing cryptography; later M2
  protocol work selects commitment, integrity, and wire behavior.
- Verifier identity, signature, signing interface, signing key, or validation.
- Wire encoding, parser, serializer, canonicalization, numeric discriminants,
  protocol registry, or conformance vectors.
- Permit issuance or validation, session-key resolution, proof of possession,
  matchmaking admission, gameplay fallback, or ban policy.
- Result issued-at/expiry, maximum lifetime, authoritative terminal-time
  observation, clock adapter, persistence, renewal, revocation lifecycle, or
  retention enforcement. The future protected-result issuer owns validity.
- Real challenge-authentication, evidence-appraisal, identity, session-key,
  revocation, policy, or result-issuance adapters.
- Cryptographic provenance of copyable accepted-claim values. Their trusted
  producers remain inside the verifier TCB.
- Trusted provenance for unsuccessful Appraisal Results suitable for future
  signing. A future protected-result issuer must establish that separately.
- An open claim map, publisher-defined vocabulary, generic extension registry,
  or downstream capability producer.
- Networking, filesystem, database, async runtime, cryptographic primitive,
  `unsafe` code, or new dependency.

## Trust sources

- Result correlation: `ExpectedContext`, supplied independently by the relying
  party when `VerifierFlow` begins; never refilled from challenge or evidence.
- Accepted evidence profile: future trusted evidence appraiser, carried by the
  exact-attempt `EvidenceAppraised` capability.
- Session public-key handle: future trusted session-binding operation, carried
  by the exact-attempt `SessionBound` capability.
- Full or restricted class: future trusted policy evaluator, carried by
  `PolicySatisfied` after satisfying the exact policy in `ExpectedContext`.
- Result shape, reason eligibility, claim discard, one-use completion, and
  diagnostic redaction: the pure verifier model.
- Final application authorization: a future relying party after validating a
  protected Attestation Result and fresh proof of possession.

The attempt binding proves that a capability belongs to one flow. It does not
cryptographically prove that a copyable profile or key-handle payload originated
in that flow. Correct payload production remains a trusted-producer obligation
and deliberate producer compromise remains A5 residual risk.

## Required interfaces

- Opaque non-`Clone`, non-`Copy` `AppraisalResult` with private context and
  payload.
- Opaque accepted claims with read-only profile and key-handle access.
- One borrowed view. Its failure variant is freely constructible report data;
  allow variants require opaque accepted claims borrowed from an existing
  result. Constructing a view cannot construct or alter the outer result.
- `VerifierFlow::complete() -> VerifiedAttestation`, preserving the existing
  public transition shape.
- `VerifiedAttestation::into_appraisal_result() -> AppraisalResult`, accepting
  no context, decision, reason, or claim refill input.
- Five typed failure actions that return one Appraisal Result and preserve
  immutable terminal state.
- `UnsupportedRequirement` values for version/profile, platform, and unknown
  critical requirement.
- `RetryReason` values for attestation unavailable and transient failure.
- `DenialReason` values exactly `ChallengeAuthenticationFailed`, `NotYetValid`,
  `Expired`, `ReplayDetected`, `ContextBindingMismatch`, `EvidenceInvalid`,
  `PolicyDenied`, and `ProtectedSessionLost`, limited by the eligibility table
  below. `Malformed` and `Revoked` remain available only through their dedicated
  actions.
- No public Appraisal Result constructor, builder, setter, default, report
  conversion, accepted-claim constructor, or signing shortcut.

## Result taxonomy

| Decision | Permitted reason codes |
| --- | --- |
| `Allow` | none |
| `AllowRestricted` | none |
| `Deny` | `Malformed`, `ChallengeAuthenticationFailed`, `NotYetValid`, `Expired`, `ReplayDetected`, `ContextBindingMismatch`, `EvidenceInvalid`, `PolicyDenied`, `Revoked`, `ProtectedSessionLost` |
| `Unsupported` | `UnsupportedVersionOrProfile`, `UnsupportedPlatform`, `UnsupportedCriticalRequirement` |
| `Retry` | `AttestationUnavailable`, `TransientFailure` |

Public report values remain constructible. The invariant is that an
`AppraisalResult` can expose only a valid mapping; constructing arbitrary
`Decision`/`ReasonCode` values does not construct the outer result.

## Phase eligibility

| Current nonterminal phase | Eligible observations |
| --- | --- |
| `EvidenceReceived` | malformed; challenge authentication failed; unavailable; transient failure; unknown critical requirement |
| `ChallengeAuthenticated` | unsupported version/profile; not yet valid; expired; replay; context mismatch; unavailable; transient failure; unknown critical requirement |
| `FreshnessChecked` | identity/context mismatch; unavailable; transient failure; unknown critical requirement |
| `IdentityChecked` | unsupported platform; evidence invalid; unavailable; transient failure; unknown critical requirement |
| `EvidenceAppraised` | session/context mismatch; protected-session lost; unavailable; transient failure; unknown critical requirement |
| `SessionBound` | revoked; protected-session lost; unavailable; transient failure; unknown critical requirement |
| `RevocationChecked` | policy denied; protected-session lost; unavailable; transient failure; unknown critical requirement |
| `PolicySatisfied` | protected-session lost; unavailable; transient failure; unknown critical requirement |

This table refines ADR-0007's all-failure-actions-from-all-nonterminals rule.
The implementation plan must re-freeze the finite action domain and independent
oracle counts before runtime code changes. No stale `48/134` count is reused.

## Positive tests

- Both allowed classes carry the exact originating context, accepted profile,
  session-key handle, and class.
- Every reason appears through its permitted decision and eligible phases.
- Existing canonical seven-gate ordering, all 5,040 permutations, seven
  omissions, and equal-flow capability rejection remain valid.
- A newly frozen independent phase/action oracle and long-history model cover
  every eligibility class and terminal result shape.

## Negative tests

- Reports, decisions, reasons, raw requests, context, challenge data, and
  evidence cannot publicly construct an allowed Appraisal Result.
- A freely constructed failure view cannot construct or mutate the opaque
  Appraisal Result; external code cannot construct accepted claims for an allow
  view.
- Every invalid result mapping and every phase-ineligible reason is rejected
  without state, request, or claim mutation.
- Unsuccessful outcomes expose no accepted claims.
- Each claim-bearing capability from an equal distinct flow is rejected before
  state or claim mutation.
- A mixed payload inside a correctly bound capability is documented as trusted
  producer risk rather than falsely claimed impossible.
- A restricted outcome cannot replace the exact policy in `ExpectedContext`.
- Repeated failure issuance, repeated completion, and reuse of a consumed
  `VerifiedAttestation` fail.
- External safe Rust cannot construct, clone, copy, mutate, or inspect private
  result state.
- Diagnostics omit non-vacuous context, time, profile, key-handle, binding,
  path, control-text, and allocation sentinels.

## Fuzz/property tests

- Recompute and freeze the complete typed phase/action domain, exact success and
  rejection counts, and fixed long-history budget before implementation.
- Retain all gate permutation, omission, phase-before-binding, and equal-flow
  evidence that remains unaffected by reason eligibility.
- Exhaust every permitted result mapping and phase eligibility edge.
- Freeze one-cause mutations for each mapping, eligibility guard, claim
  transfer/discard, authority field, terminal replacement, one-use
  path, and diagnostic surface.
- Add no byte fuzzer or differential decoder because this issue adds no parser,
  serializer, wire format, or untrusted byte interpretation.

## Privacy impact

An Appraisal Result retains relying-party context and, for allowed outcomes, an
accepted profile and correlation-sensitive session-key handle. Default
formatting is fixed and redacted. Explicit accessors are trusted functional
interfaces rather than approved logging sinks.

Unsuccessful outcomes discard staged accepted claims even after appraisal or
session binding, and terminal flows retain no attempt binding, replay
registration, or attempt allocation. The type has no intrinsic expiry and
cannot enforce deletion or secure memory erasure. Future protected-result
transport/storage work must define bounded retention and confidentiality.

Registered scenario owner `initial-maintainer` must approve a privacy review
before expanding any result context/claim field, diagnostic surface,
serializer/wire adapter, persistence/storage/backup path, or logging/telemetry
path.

Reason codes contain no free text, raw evidence, platform detail, player
identity, or accusation. Attestation failure remains non-disciplinary.

## Dependency impact

No new crate, package, feature, transitive dependency, parser, serializer,
cryptographic primitive, I/O boundary, or `unsafe` code. The module uses only
existing workspace types and Rust ownership/privacy. Existing Apache-2.0
boundaries remain unchanged.

## Acceptance criteria

- No allowed Appraisal Result exists without the exact completed capability.
- Exact-attempt-associated profile and key claims move only after phase and
  binding checks; payload truth remains an explicit trusted-producer duty.
- Every Appraisal Result carries exact relying-party context.
- Unsuccessful outcomes contain no accepted claims and exactly one valid,
  phase-eligible coarse reason.
- Full and restricted outcomes remain bound to the exact selected policy.
- Every terminal issues at most one result and remains immutable through one
  whole-state fail-closed replacement.
- Every terminal flow retains no binding, replay registration, or attempt
  allocation, proven through real allocation-lifetime tests.
- Public reports and views grant no result, permit, proof, or admission.
- Default diagnostics expose no private context, timing, claim, binding, or
  key-handle value.
- New finite-model counts are frozen independently before implementation and
  every named mutation is killed for its intended cause.
- Architecture, threat, roadmap, test strategy, ADRs, glossary, and scenarios
  are consistent with the implemented boundary.
- `./scripts/check.sh` and optimized all-feature workspace tests pass without
  dependency, parser, crypto, I/O, or `unsafe` expansion.
- Fresh separate trusted-computing-base and privacy reviews report no unresolved
  finding before publication.

## Primary sources

- Approved written design:
  `docs/superpowers/specs/2026-08-28-m1-011-appraisal-result-design.md`.
- Project authority: `docs/SECURITY_INVARIANTS.md`, `docs/THREAT_MODEL.md`,
  `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `docs/AI_DEVELOPMENT_POLICY.md`,
  ADR-0004, ADR-0005, ADR-0007, and ADR-0008.
- IETF RFC 9334 sections 3, 4.2, 5.1, and 11 for verifier/result/relying-party
  roles, result appraisal, serialization separation, and privacy:
  https://www.rfc-editor.org/rfc/rfc9334.html
- IETF RFC 9711 sections 1.3.1 and 10.5 for verifier-governed result claims and
  separation of attestation from an accompanying PoP transaction:
  https://www.rfc-editor.org/rfc/rfc9711.html
- Rust 1.98 visibility and privacy:
  https://doc.rust-lang.org/1.98.0/reference/visibility-and-privacy.html
- Rust 1.98 ownership and moves:
  https://doc.rust-lang.org/1.98.0/book/ch04-01-what-is-ownership.html

## Implementation evidence

This evidence is time-bounded to the clean reviewed implementation head
`ec21f23e1f0c341551ed599829fcfd10b818040e`, tree
`fd8c5c79f99bd8c1050147b68b776fb4f4a158a6`, before this later local
documentation-only evidence commit. The implementation range from merged base
`955c88e372cffa13f15953085f15887165be62b5` through that reviewed head contains
33 commits. Those commits and this evidence update are unsigned and contain no
DCO trailer; certification, publication, remote review, and merge remain
pending.

Fresh normal and optimized all-feature gates at the reviewed head passed
`./scripts/check.sh` and `cargo test --workspace --all-features --release` with
225 runtime/integration tests, 111 doctests, 14 validated attack scenarios, and
9 indexed ADRs. The finite verifier model covers all `14 * 24 = 336`
phase/action pairs: 50 successful edges, comprising 9 gate/completion edges and
41 phase-eligible failure edges, plus 286 state-preserving rejections. All 5,040
gate permutations admit exactly one canonical ordering and reject the other
5,039. Seven gate omissions and seven equal-data, different-flow capability
substitutions are covered.

The deterministic history proof checks exactly 1,048,576 actions. Its 2,048
scheduled actions are partitioned as
`256 + 864 + 576 + 35 + 312 + 5`; another 1,046,528 fixed-seed actions exercise
arbitrary histories. The arbitrary tail contains exactly 175,120 matching-gate
actions, 174,585 different-flow gate actions, and 21,965 accepted active-state
advances. The public authority proof contains one compile-pass case and 70
single-cause compile-fail doctests.

The frozen mutation campaign ran at exact head `ec21f23` and killed all
`41 + 15 + 27 + 13 + 6 + 19 + 4 + 15 + 14 = 154` one-cause probes. Its report
contains 154 exact-base records and 154 cleanup records, no survivor or invalid
row, and SHA-256
`720fff3ec741338e58069eaf54fd3112c494ceea903db0ff0002024f12247dcc`.
This later issue-only evidence commit does not move the campaign head; the
verifier runtime and test blobs remain respectively
`a392774b96df58d3bca0468a0721318756671b91` and
`daa35bc5845362e0c2adfc32a401876c2c2389ea`.

Separate fresh controller-owned trusted-computing-base and privacy re-reviews
of exact head `ec21f23` reported no Critical, Important, or Minor findings and
returned `Readiness: Yes`. Their residual limitations remain part of this
checkpoint: source-token proofs are not a Rust parser; allocation identity
proves flow association, not payload truth; dropped values are not securely
erased or allocator-zeroized; retained context, profile, and key-handle values
are correlation-sensitive; the unsigned result has no intrinsic expiry or
deletion enforcement; and a publicly constructible failure report does not
establish trusted provenance for future signing.

This pure research-scaffold result establishes no cryptographic payload
provenance, trusted failure provenance, intrinsic validity, signer or signing
interface, protected result, permit, proof of possession, matchmaking
admission, parser or serializer, cryptography, I/O, persistence, or production
adapter. It is not authorized for production enforcement or discipline.

The local issue source is now `status: needs-review`. The live issue remains
OPEN with `status: ready` and its prior ready body because the required separate
issue-edit authorization has not been granted. No GitHub read, edit, remote
access, push, pull request, or other publication action was performed for this
checkpoint.
