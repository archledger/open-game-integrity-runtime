# M1-010: Implement the fail-closed verifier state machine
<!-- labels: type: implementation,area: model,area: verifier,area: privacy,risk: trusted-computing-base,risk: privacy,status: ready -->
<!-- milestone: M1 Domain Model -->

## Problem

The publisher-controlled verifier must not produce an authority-bearing success
before challenge authentication, freshness and exact relying-party context,
attester identity, evidence appraisal, session binding, revocation, and policy
gates all succeed for one exact verification attempt. The current research
function fails closed, but its progress is implicit control flow and its
reporting outcome fields are publicly constructible. A growing sequence of
booleans or ad hoc callbacks would admit contradictory state, gate skipping,
cross-request capability substitution, and fabricated allow-shaped reports.

## Security invariants

This issue enforces the pure-model portions of project invariants 1, 2, 5, 6,
8-10, 20-21, 25-26, 37, and 39-40. Concrete cryptographic, evidence, and
relying-party enforcement remains in the explicitly deferred adapters.

- `Decision` and `ReasonCode` are reporting views, never authorization
  capabilities.
- Only the complete ordered verifier path creates one opaque non-cloneable
  `VerifiedAttestation` bound to the exact in-process verification attempt.
- Both full and restricted success require every mandatory gate.
- A gate capability from another flow is rejected even when both requests have
  byte-for-byte equal security fields.
- Missing, reordered, unknown, contradictory, unavailable, denied, or revoked
  gate state never reaches `Verified`.
- Every terminal phase is permanent and cannot issue a second success
  capability or change terminal classification.
- Expected publisher/game/build/account/match/policy context comes from the
  relying party and is compared before the irreversible freshness claim.
- Default diagnostics expose no request, identifier, nonce, timestamp,
  evidence profile/payload, allocation identity, or private capability binding.

## Threats addressed

- A1 hostile, repeated, or cross-context requests exploit missing or reordered
  verifier gates.
- A1 submits equal request data twice in an attempt to reuse authorization
  progress from one flow in another.
- A1 presents client-controlled expected context or opaque evidence as though
  either were independently authoritative.
- Verifier implementation defects fabricate an allow-shaped report without the
  authority-bearing proof path.
- Faulty verifier orchestration ignores an unknown mandatory gate or mutates a
  failure terminal into success.
- A8 overreaching diagnostics expose evidence or authorization bindings.

## In scope

- One pure deterministic checked runtime graph in `ogir-verifier`.
- Private discriminated state with public redacted phase/action/outcome views.
- Exact success path:

  ```text
  EvidenceReceived
   -> ChallengeAuthenticated
   -> FreshnessChecked
   -> IdentityChecked
   -> EvidenceAppraised
   -> SessionBound
   -> RevocationChecked
   -> PolicySatisfied
   -> Verified
  ```

- Immutable `Malformed`, `Unsupported`, `Retryable`, `Denied`, and `Revoked`
  terminal phases reachable from every nonterminal phase.
- Typed `UnsupportedRequirement::{VersionOrProfile, UnknownMandatoryGate}`
  input so the unknown-required-gate scenario is modeled rather than inferred
  from a generic no-argument failure method.
- Opaque non-`Clone`/non-`Copy` request-bound gate capabilities and
  `VerifiedAttestation`.
- Process-local attempt identity using one private shared allocation plus the
  exact redacted replay registration; no random, hashed, global-counter,
  serialized, or restart-durable identity.
- Private/read-only `VerificationOutcome` construction with complete valid
  decision/reason mapping.
- State-preserving structured transition errors and fixed redacted diagnostics.
- Release of the owned raw request on terminal entry, without claiming secure
  memory erasure.
- Direct `EvidenceBundle` diagnostic redaction because the current derived
  `Debug` exposes its opaque payload.
- Exhaustive, permutation, omission, deterministic property, compile-fail,
  structural privacy, mutation, and machine-readable attack-scenario evidence.

## Out of scope

- Publisher-signature implementation or key selection.
- TPM quote, measured-log, evidence-profile, identity-enrollment, session-key,
  revocation-source, or policy-language implementation.
- Concrete `AttestationResult`, permit fields, signing, serialization,
  transmission, validation, renewal lifecycle, or admission decision.
- Networking, async runtime, database, filesystem, clock source, random-number
  generator, cryptographic primitive, privileged operation, or production key.
- Restart-durable verification-flow capabilities or cross-process capability
  transport.
- Changing the M1-009 local-session capability boundary.

## Trust sources

- Challenge authentication: future publisher-key validator inside the verifier
  trusted computing base.
- Freshness and exact expected context: the existing publisher-authoritative
  `FreshnessGuard`, durable replay store, and relying-party-supplied
  `ExpectedContext` ordering from ADR-0005.
- Identity/evidence/session/revocation/policy completion: future reviewed
  verifier adapters that mint a capability only after their real operation.
- Full versus restricted policy satisfaction: future trusted policy evaluator,
  carried privately by `PolicySatisfied`. Restricted success is a separately
  selected and satisfied policy outcome, never fallback after full-policy
  failure.
- Gate ordering, exact per-attempt capability comparison, terminality, and
  single-use completion: this pure state machine.
- Final application admission: the relying party after validating a future
  signed attestation result and session-key proof; never this report-only API.
- Deliberate compromise of a trusted gate producer/verifier remains an A5
  residual risk; the pure state machine narrows accidental/API misuse but
  cannot make malicious code inside its own trusted crate honest.

## Required interfaces

- Public fieldless `VerificationPhase` and `VerificationAction` enums.
- Public `DenialReason` restricted to not-yet-valid, expired, replay,
  session-binding mismatch, evidence-invalid, policy-denied, and
  protected-session-lost.
- Public non-cloneable opaque `VerifierFlow`, seven gate capabilities, and
  `VerifiedAttestation`.
- `VerifierFlow::begin(VerificationRequest)` owns the request and creates a
  distinct process-local attempt binding.
- Seven explicit capability transitions followed by single-use `complete()`.
- Five typed failure transitions, valid only while nonterminal.
- `VerificationOutcome` with private fields and read-only `decision()` and
  `reason()` accessors.
- `TransitionError::{InvalidTransition, CapabilityRejected}` containing only
  safe phase/action information.
- No public gate-capability, verified-capability, outcome-authority, or trusted
  operation-result constructor.
- Preserve the fail-closed research entry point and all M1-008 freshness
  semantics; its unauthenticated scaffold uses raw irreversible claim without
  minting `FreshnessChecked`, and opaque evidence still never authorizes.

## Positive tests

- All eight ordered success edges for full and restricted policy satisfaction.
- Every failure class from each of eight nonterminal phases.
- Every denial reason and all five `Decision` plus twelve `ReasonCode` values
  through their one valid outcome mapping.
- Exactly one `VerifiedAttestation` from a canonical completed flow.
- The returned `VerifiedAttestation` carries the exact flow allocation identity
  and the privately selected full/restricted class.
- Request ownership ends on each terminal path while minimal redacted binding
  and safe outcome remain observable.

## Negative tests

- All 134 rejected pairs in the 14-phase × 13-action matrix preserve phase,
  outcome, and request-retention state.
- All 5,039 noncanonical permutations of seven gates fail to verify; only the
  canonical permutation can reach `PolicySatisfied`.
- Omitting each mandatory gate independently prevents completion.
- Each of seven capabilities from another flow is consumed and rejected,
  including flows created from equal requests.
- Every terminal rejects every action, repeated completion, and terminal
  reclassification.
- Unknown mandatory gate handling terminates `Unsupported` and cannot be
  ignored.
- External safe Rust cannot construct, clone, copy, inspect, or replace any
  authority-bearing binding/state; cannot fabricate an authoritative outcome;
  and cannot substitute `Decision` for `VerifiedAttestation`.
- Exact redacted diagnostics omit non-vacuous request/evidence/binding
  sentinels and all control/path/CI-command text.
- Direct `EvidenceBundle` formatting omits its payload and profile sentinel.

## Fuzz/property tests

- Exhaust all 14 phases × 13 actions = 182 pairs against an independent literal
  model: exactly 48 transitions succeed and 134 reject unchanged.
- Enumerate all 5,040 permutations of the seven gate capabilities.
- Execute exactly 1,048,576 deterministic actions against an independent
  oracle. Exactly 2,048 scheduled actions guarantee full/restricted deep paths,
  all terminal classes/reasons, and cross-flow rejection; 1,046,528 fixed-seed
  actions exercise arbitrary histories. Coverage counters fail if a required
  deep path is vacuous.
- Add no byte fuzzer or fuzz dependency because this issue adds no parser or
  wire format and exhausts the finite semantic action domain.

## Privacy impact

An active flow privately owns the exact request, including opaque evidence,
only until it becomes terminal. Terminal entry drops that ownership but does
not claim allocator-memory zeroization. Capabilities share only a private
process-local attempt record containing the exact replay registration and
allocation identity. All aggregate diagnostics use fixed redaction. The direct
`EvidenceBundle` `Debug` implementation is hardened because the existing
derived implementation can disclose raw evidence payload bytes.

## Dependency impact

No new crate, package, feature, or transitive dependency. The design uses the
Rust standard library, including `Arc::ptr_eq`, plus existing workspace types.
No `unsafe` code, serializer, random generator, hash, crypto, or I/O boundary is
added. All affected source remains Apache-2.0.

## Acceptance criteria

- The exact approved success/terminal graph is implemented in
  `ogir-verifier` without a second typestate or monolithic authority path.
- Exactly 48 matrix pairs succeed and 134 reject without mutation.
- Only the canonical gate order and both fully satisfied policy classes can
  produce one `VerifiedAttestation`.
- All gate omissions, unknown gates, terminal actions, and equal-data
  cross-flow substitutions fail closed.
- `VerificationOutcome` cannot be externally constructed as authority, and
  every decision/reason pair is valid by construction.
- Active requests are released on terminal entry; diagnostics and direct
  `EvidenceBundle` formatting expose no raw private value.
- Every private authority field and named semantic mutation is killed by a
  specific regression in a disposable worktree.
- Five new verifier scenarios validate under the unchanged bounded schema and
  registered owner/profile taxonomy.
- `./scripts/check.sh` and optimized all-feature workspace tests pass without
  dependency, unsafe-code, or production-adapter changes.
- Fresh separate TCB and privacy reviews report no unresolved finding before
  publication.

## Primary sources

- Approved design:
  `docs/superpowers/specs/2026-08-26-m1-010-verifier-state-machine-design.md`.
- Project authority: `docs/SECURITY_INVARIANTS.md`, `docs/THREAT_MODEL.md`,
  `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `docs/AI_DEVELOPMENT_POLICY.md`,
  ADR-0004, ADR-0005, and ADR-0006.
- IETF RFC 9334 RATS architecture and verifier/relying-party roles:
  https://www.rfc-editor.org/rfc/rfc9334.html
- Rust 1.98 visibility and privacy:
  https://doc.rust-lang.org/1.98.0/reference/visibility-and-privacy.html
- Rust 1.98 `Arc` allocation identity:
  https://doc.rust-lang.org/1.98.0/std/sync/struct.Arc.html#method.ptr_eq
- Rust 1.98 ownership/moves:
  https://doc.rust-lang.org/1.98.0/book/ch04-01-what-is-ownership.html
- Rust API Guidelines for private structs, newtypes, custom types, and boundary
  validation: https://rust-lang.github.io/api-guidelines/
