# M1-012: Define evidence-binding transcript inputs without choosing cryptography
<!-- labels: type: architecture,type: documentation,area: model,area: verifier,area: privacy,risk: trusted-computing-base,risk: privacy,status: ready -->
<!-- milestone: M1 Domain Model -->

## Problem

OGIR has typed challenge, evidence-profile, evidence-carrier, expected-context,
and session-key-handle values, but it does not yet define the complete semantic
claim set that one evidence mechanism must cover for one appraisal attempt.
Without that contract, an implementation can underbind a challenge field,
accept an incomplete or invented claim set, lose claim provenance, substitute a
manifest identity, treat a lookup handle as key authority, or silently reuse
evidence for another protocol purpose.

The canonical domain term is **Evidence-binding transcript**. It is a closed
semantic value, not a byte serialization. `EvidenceBundle` remains the external
profile-specific carrier of claims and proof material. The attester constructs
and covers one transcript; the verifier independently reconstructs the expected
transcript before checking profile coverage and appraising claims.

On 2026-08-31, the decision owner approved candidate specification SHA-256
`60fb29682e939d1b259b84033c113b3096a9e734541b5a0634e8733deebfe591`
without a requested semantic change. That approval permits this
documentation-only contract and plan; it does not authorize runtime code,
cryptographic selection, a commit, or a live GitHub mutation.

## Security invariants

- Changing any transcript semantic causes profile coverage validation to fail.
- The complete authenticated `PublisherChallenge` is bound as one typed
  semantic aggregate, including its `ProtocolVersion`.
- `ExpectedContext` is an independent comparator and is never copied into the
  transcript as evidence.
- Both the actual session public key and `SessionPublicKeyId` are bound; the
  handle alone is not key authority.
- Every registered profile requires all Base claims and may add only declared
  profile-specific claims from the fixed OGIR vocabulary.
- Every required claim appears semantically exactly once with one registered
  provenance class.
- Manifest and measurement identities include their semantic namespace,
  algorithm identity, and value.
- Initial appraisal and same-session renewal authorization are distinct
  semantic purposes; every transcript in either lifecycle path retains the
  fixed OGIR evidence-binding purpose.
- A transcript is evidence input, not an Appraisal Result, protected result,
  permit, admission decision, or disciplinary signal.
- Transcript values and proof material are confidential by default and absent
  from ordinary diagnostics.

## Threats addressed

- Challenge-field, protocol-version, profile, claim, manifest, measurement,
  provenance, actual-key, key-handle, or live-session substitution.
- Omission, duplication, aliasing, or invention of required evidence meanings.
- Cross-publisher, cross-game, cross-build, cross-account, cross-match, cross-
  policy, or cross-session reuse.
- Confusion between hardware-certified, measured-log-derived, and trusted-
  agent-observed provenance.
- Trusting an attester-supplied transcript or client-supplied context as
  independent verifier authority.
- Confusing the exact five semantic purposes: evidence binding, protected
  Attestation Result integrity, permit authorization, session proof of
  possession, and renewal authorization.
- Treating challenge time, verifier evaluation time, or future result validity
  as evidence creation or validity time.
- Expanding publisher-visible claims or diagnostics beyond the fixed evidence
  vocabulary and registered disclosure contract.

Coverage narrows these ambiguity and substitution paths. It does not establish
claim truth by itself, make compromised trusted producers honest, eliminate
full-session relay, or authorize discipline.

Challenge authentication remains a separate verifier operation, not a sixth
semantic purpose. Admission remains downstream and outside the transcript, not
an additional semantic purpose.

## In scope

- Canonical Evidence-binding transcript terminology.
- The relationship between the semantic transcript and the external profile-
  specific `EvidenceBundle` carrier.
- The complete semantic input set and fixed OGIR claim vocabulary.
- Exact claim provenance classes and profile registration rules.
- Semantic manifest and measurement identities, including namespace,
  algorithm identity, and value without selecting an algorithm here.
- Attester construction and independent publisher-verifier reconstruction.
- Initial-appraisal and same-session-renewal lifecycle relationships.
- Positive, single-change negative, shape, cross-context, domain-boundary, and
  time-substitution validation cases.
- Architecture decision, project-documentation, and attack-scenario
  traceability.

## Out of scope

- Rust transcript types or changes to existing Rust types.
- Serializers, parsers, canonical byte representation, field ordering, framing, media types,
  or number-based discriminators.
- Hash, signature, MAC, KDF, commitment, public-key, or key-generation
  algorithms.
- TPM command layouts, qualifying-data layouts, PCR selection, or raw TPM
  structures.
- Public-key encodings, fingerprints, thumbprints, or key-resolution adapters.
- Evidence proof formats, generation, transport, or runtime validation.
- Protected-result signing, integrity protection, validity, or trusted issuer
  behavior.
- Permit issuance or validation, proof of possession, matchmaking admission,
  gameplay fallback, or discipline.
- Telemetry, logging expansion, networking, persistence, storage, backup, async
  runtime, privilege, or `unsafe` code.
- New dependencies, feature flags, crates, packages, or license boundaries.

## Trust sources

- Authenticated challenge semantics originate with the publisher challenge
  issuer and become trusted only after publisher authentication and publisher-
  verifier validation.
- `ExpectedContext` originates independently with the relying party and remains
  authoritative for exact publisher, game, build, account, match, and selected-
  policy comparison.
- Private-key ownership and the actual-key-to-`SessionPublicKeyId` association
  originate with the trusted local key owner; the game and client are never
  authoritative for either.
- Profile claims originate with registered trusted evidence producers. Each
  producer must satisfy the profile-declared hardware-certified, measured-log-
  derived, or trusted-agent-observed provenance contract.
- Transcript construction belongs to the attester. Construction does not make
  attester-supplied values authoritative.
- Independent transcript reconstruction, profile coverage validation,
  provenance validation, and appraisal belong to the publisher verifier.
- Protected-result provenance, validity, commitment, and integrity protection
  belong to a future trusted protected-result issuer and are not established by
  M1-012.

## Required interfaces

These interfaces are semantic contracts, not Rust APIs or wire fields.

Every registered profile requires all eight Base claims:

1. Attesting agent identity
2. Platform identity
3. Boot measurement identity
4. Runtime manifest identity
5. Game manifest identity
6. Process binding identity
7. Protected-session identity
8. Enforcement policy state

The complete profile-specific vocabulary contains exactly these two additional
meanings:

1. Attestation identity
2. Runtime measurement identity

An immutable registered profile contract may add either profile-specific
meaning, after which that claim is required for the profile. Profiles cannot
rename or redefine these meanings, remove a Base claim, make a required claim
optional at runtime, or use an arbitrary extension map. Each required claim has
exactly one registered provenance class and appears semantically exactly once.
Any vocabulary or profile-semantics change requires explicit versioning or a
new profile identity plus architecture, threat, privacy, and scenario review.

The transcript also binds one complete authenticated `PublisherChallenge`, one
exact registered `EvidenceProfile`, the actual ephemeral session public key and
its `SessionPublicKeyId` association, the required evidence-time semantic, the
fixed evidence-binding purpose, and the complete profile-required claim and
provenance set. `EvidenceBundle` carries claims and profile-specific proof
material externally; the complete carrier is not a transcript input.

## Required relationships

### Initial appraisal

- One initial appraisal binds one fresh complete authenticated
  `PublisherChallenge`, including `ProtocolVersion`.
- It binds one registered `EvidenceProfile` and that profile's complete closed
  claim and provenance set.
- It binds one newly created actual ephemeral session public key and its
  `SessionPublicKeyId` association for the same publisher and protected
  session.
- It binds one evidence-time statement accepted under the separately approved
  evidence-time authority contract.
- The attester constructs the transcript and the verifier independently
  reconstructs it from authenticated or registered inputs and untrusted
  candidate claims.
- The profile mechanism covers the exact reconstructed transcript; coverage
  validation remains separate from provenance validation and claim appraisal.
- Overlapping publisher, game, build, account, match, policy, process,
  enforcement, and session meanings describe one live appraisal subject and
  agree with the authenticated challenge and independent expected context.

### Same-session renewal

- Renewal constructs a new evidence-binding transcript with a fresh complete
  challenge, current claims, and a new evidence-time value accepted by the
  future evidence-time authority contract. Its transcript purpose remains fixed
  to OGIR evidence binding; renewal authorization is separate.
- The same actual key and `SessionPublicKeyId` may repeat only if the publisher
  is unchanged, the protected `SessionId` and live subject are unchanged,
  renewal belongs to the existing session lifecycle, policy is not silently
  weakened, the current claim set describes current live state, and the future
  evidence-time authority contract accepts the new evidence.
- This contract does not require profile identity or exact selected-policy
  identity to remain unchanged.
- Prior evidence, a prior carrier, or a prior transcript never becomes new-
  context authorization.
- A new publisher or protected session requires a new key and handle, and a
  terminally ended or invalidated session cannot renew.

## Failure semantics

M1-012 adds no `Decision`, `ReasonCode`, denial variant, verifier state, or
permissive fallback. Later implementation preserves the existing M1-011 coarse,
non-disciplinary mappings:

| Condition | Existing M1-011 mapping |
| --- | --- |
| Malformed transcript shape, including missing, duplicate, invented, aliased, contradictory, or structurally invalid semantics | `Malformed` |
| Unsupported profile or unknown critical semantic | `Unsupported` |
| Authenticated challenge and independent `ExpectedContext` disagree | `ContextBindingMismatch` |
| Actual key, key handle, publisher, or protected-session association disagrees | `ContextBindingMismatch` |
| Profile coverage or claim provenance validation fails | `EvidenceInvalid` |
| A required trusted authority, profile validator, store, or key resolver is unavailable | `Retry` with `AttestationUnavailable` |
| The protected session is lost during the attempt | `ProtectedSessionLost` |
| The evidence-time authority contract is absent | Implementation is blocked; no runtime mapping is authorized |

No failure is evidence that a player cheated. Any failure after the ADR-0005
atomic freshness claim leaves the challenge consumed and requires a newly
issued challenge.

## Evidence-time prerequisite at M1-012 completion

At M1-012 completion, the producer, authority, clock or epoch, validity model,
skew rule, rollback and restart behavior, renewal behavior, and privacy treatment
for evidence creation time had not been approved. No runtime transcript
representation or coverage validator could be designed as final until that
prerequisite was resolved.
`PublisherChallenge.issued_at`, verifier evaluation time, and client wall-clock
time are not substitutes.

The prerequisite could not be bypassed with an omitted, zero-valued, always-
valid, challenge-derived, verifier-time-derived, or result-time-derived
placeholder.

## Evidence-time prerequisite resolution

[M1-012F](012f-evidence-time-authority.md) resolves the common semantic
prerequisite with one challenge-anchored protected local collection interval,
an immutable-profile-registered Evidence Collection Authority, an opaque
publisher/session-scoped epoch relation, a strictly increasing sequence,
snapshot freeze before proof, no client UTC/skew, single-challenge validity,
atomic active-session temporal high-water, and terminal continuity loss.

This is a documentation-level resolution. M2 still owns runtime representation,
profile coverage, parsing, cryptography, and exact numeric limits; M3 owns TPM-
specific mapping. No placeholder is authorized while those prerequisites remain.

## Required tests

### Positive reconstruction

- Initial appraisal: independently constructed attester and verifier semantics
  match exactly for challenge, profile, actual-key and handle association,
  evidence time, claims, and provenance.
- Same-session renewal: a new evidence-binding transcript uses a fresh complete
  challenge, current claims, and a new accepted evidence-time value. The same
  actual key and `SessionPublicKeyId` repeat only when the publisher is
  unchanged, the protected `SessionId` and live subject are unchanged, renewal
  belongs to the existing lifecycle, policy is not silently weakened, current
  claims describe live state, and the evidence-time contract accepts the new
  evidence. Profile identity and exact selected-policy identity need not remain
  unchanged.
- Two distinct registered profiles use all eight Base claims and only their
  declared subset of the two profile-specific meanings, with no arbitrary
  extension.

### Single-change and shape failures

- Change each complete challenge field independently, including
  `ProtocolVersion`, publisher, game, build, account, match, policy identifier,
  policy version, nonce, and challenge-window semantics.
- Change the exact `EvidenceProfile`.
- Omit, duplicate, alias, invent, or make optional each required claim; add an
  undeclared claim or unknown critical semantic; use a known profile-specific
  claim under a profile that did not declare it.
- Change one claim's registered provenance or provide it through the wrong
  validation path.
- Change the actual key, `SessionPublicKeyId`, or only their
  trusted association.
- Change a manifest or measurement semantic namespace, algorithm identity, or
  value independently.
- Change or omit the evidence-time semantic value.
- Reject the complete bundle payload as a transcript input, an attester-
  supplied transcript without independent reconstruction, or a profile name
  without the evidence instance's semantic claims.

Each single semantic change must produce semantic inequality and future profile
coverage failure. No test may infer success from a producer-provided pass label.

### Cross-context and purpose failures

- Reuse evidence across publisher, game, build, account, match, policy,
  protected session, challenge, or expected context.
- Reuse one session's actual key or handle in another session, or pair one
  session's key with another session's handle.
- Reuse initial-appraisal evidence for renewal, prior renewal evidence for a
  fresh challenge, or evidence-binding proof as renewal authorization.
- Reuse evidence-binding proof as an Appraisal Result, protected result,
  permit, admission decision, renewal authorization, or proof of possession.
- Copy challenge `issued_at` or `expires_at`, verifier evaluation time, future
  result validity, permit validity, client wall-clock time, or an always-valid
  placeholder into evidence-time semantics.

### Domain exclusions and scenarios

- Prove `ExpectedContext`, verifier challenge-evaluation time, result values,
  permit values, proof-of-possession values, private key material, and complete
  evidence-carrier payload are excluded from the transcript.
- Register accountable attack scenarios for challenge/profile/claim
  substitution, provenance confusion, key/handle substitution, cross-context
  reuse, protocol-purpose confusion, evidence-time substitution, and transcript
  diagnostic disclosure.

No byte fuzz target or decoder differential test is added because M1-012 adds
no runtime type, parser, serializer, or wire representation. Later M2 parser
work owns bounded fuzzing and differential validation.

## Privacy impact

The transcript is correlation-sensitive because it combines complete challenge
context, profile, evidence claims, manifest and session identities, provenance,
actual public key, lookup handle, and evidence time. Future aggregate
diagnostics must emit one fixed complete redaction marker. Ordinary diagnostics,
logs, metrics, traces, panic/assertion messages, and pointer identities must not
emit transcript values or proof material. Explicit value access is a trusted
functional interface, not an approved diagnostic sink.

Profiles cannot expand the fixed vocabulary or exceed the local maximum-
disclosure policy. Private key material is never present. M1-012 adds no
persistence, transport, backup, telemetry, or retention behavior and makes no
secure-memory-erasure claim. Future transport and storage require explicit
finite retention, confidentiality, deletion, access-control, and backup rules.

## Dependency impact

This issue is documentation-only. It adds no Rust, parser, serializer,
cryptographic primitive, TPM layout, dependency, I/O, persistence, networking,
privilege, `unsafe` code, feature, crate, package, or license-boundary change.

## Acceptance criteria

- The complete authenticated challenge, including every field and
  `ProtocolVersion`, is covered as one typed semantic aggregate.
- The claim set is closed: every profile requires the exact eight Base claims
  and may add only its declared subset of the exact two profile-specific
  meanings.
- Every required claim appears semantically exactly once with its one
  registered provenance class.
- Both the actual key and its `SessionPublicKeyId` association
  are bound without treating the handle as commitment, proof, or authority.
- Manifest and measurement identities include exact semantic namespace,
  algorithm identity, and value without selecting representation or crypto.
- The attester constructs one transcript and the verifier independently
  reconstructs the expected transcript before coverage and appraisal.
- Exactly five semantic purposes remain distinct: evidence binding, protected
  Attestation Result integrity, permit authorization, session proof of
  possession, and renewal authorization.
- Challenge authentication remains a separate verifier operation and admission
  remains downstream and outside the transcript; neither expands the closed
  five-purpose set.
- Failure mapping remains M1-011-compatible, coarse, fail-closed, and non-
  disciplinary, with post-claim failures consuming the challenge.
- Transcript values and proof material remain absent from ordinary diagnostics.
- Positive and negative tests cover every input, exclusion, relationship,
  cross-context substitution, renewal confusion, domain confusion, and time-
  source substitution.
- Attack scenarios record accountable owner and required assurance profile.
- The M1-012 ADR and project documentation trace this exact semantic boundary.
- The unresolved evidence-time prerequisite is explicit and blocks runtime
  representation, coverage validation, proof implementation, and protected-
  result issuance without a permissive placeholder.
- No runtime, wire, cryptographic, TPM, dependency, I/O, persistence,
  privilege, or external GitHub change enters scope.

## Primary sources

- [ADR-0005: Verifier-authoritative nonce freshness with durable replay state](../../docs/adr/0005-verifier-authoritative-challenge-freshness.md).
- [ADR-0007: Attempt-bound fail-closed verifier flow](../../docs/adr/0007-verifier-flow-capabilities.md).
- [ADR-0008: Session public-key identifiers are not authority](../../docs/adr/0008-session-public-key-id-is-not-authority.md).
- [ADR-0009: Capability-gated Appraisal Results](../../docs/adr/0009-capability-gated-appraisal-results.md).
- [M1-012 approved design specification](../../docs/superpowers/specs/2026-08-31-m1-012-evidence-binding-transcript-design.md).
- [IETF RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html) for RATS roles,
  Evidence and Attestation Result separation, and appraisal boundaries.
- [IETF RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html) for profile-
  governed claims, freshness, and proof-of-possession separation.
- `docs/SECURITY_INVARIANTS.md`, `docs/THREAT_MODEL.md`,
  `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, and
  `docs/AI_DEVELOPMENT_POLICY.md` are project authorities for authorization,
  trust, scope, privacy, failure, human review, and roadmap ownership.

M1-012 adopts no TPM wire layout, canonical encoding, commitment, key encoding,
or cryptographic algorithm choice.
