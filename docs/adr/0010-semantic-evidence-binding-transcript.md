# ADR-0010: Use a semantic evidence-binding transcript with an external carrier

- Status: Accepted
- Date: 2026-08-31
- Owners: Initial maintainers
- Related issues: [M1-012](../../planning/issues/012-evidence-binding-transcript-inputs.md)
- Supersedes: None
- Superseded by: None

## Context

OGIR has typed challenge, profile, evidence-carrier, expected-context, and
session-key-handle concepts, but it previously lacked one complete definition
of the semantic subject that an evidence mechanism covers for an appraisal
attempt. An undefined boundary permits omission or substitution of an
authenticated challenge field, drift between a profile and its concrete claims,
loss or reclassification of claim provenance, and confusion between a key
lookup handle and authority over the actual key. It also permits semantic
manifest substitution, reuse across protocol purposes, and disclosure of a
correlation-sensitive aggregate through ordinary diagnostics.

The decision must distinguish evidence meaning from its carrier. The
`EvidenceBundle` is the external, profile-specific carrier of claims and proof
material; it is not itself the Evidence-binding transcript. The semantic
contract must be fixed before a canonical representation, commitment,
cryptographic protection, proof format, wire encoding, or runtime interface can
be selected safely. Those later choices need an unambiguous subject to cover
and validate.

## Decision drivers

- Complete semantic binding of the authenticated challenge, registered
  profile, actual key and handle association, required evidence time, claims,
  provenance, identities, and purpose.
- Independent publisher-verifier reconstruction rather than trust in an
  attester-supplied transcript.
- Profile extensibility through immutable registered contracts and a closed
  vocabulary rather than open claim maps.
- Preservation of `SessionPublicKeyId` as a non-authoritative lookup handle
  under ADR-0008 while still binding its association with the actual public key.
- Privacy minimization through fixed claims, profile disclosure governance, and
  confidential-by-default transcript and proof material.
- Representation neutrality so M1 does not select a canonical byte representation, field
  ordering, algorithm identifiers, or literal domain-separation labels.
- Compatibility with future M2 commitment, protection, wire, validation,
  protected-result, permit, and proof-of-possession work without preselecting
  those mechanisms.

## Options considered

### Include the complete `EvidenceBundle` payload

Rejected. This would appear to cover everything transported, but it would bind
transport accidents, envelope metadata, and unstable profile-specific fields
instead of defining the stable security meaning. The bundle remains external
and carries the claims and proof material that cover the semantic transcript.

### Bind only `EvidenceProfile`

Rejected. A profile identifies a registered contract but does not identify the
concrete claim values, their provenance, the actual key, or the key-handle
association for one evidence instance. Profile-only binding therefore
underbinds the appraisal subject.

### Trust an attester-supplied transcript

Rejected. Attester construction is required to state what was covered, but
accepting that construction as verifier authority removes independent
reconstruction and lets a faulty or compromised producer define the expected
meaning it claims to satisfy.

### Use verifier-only construction

Rejected. Independent verifier construction is necessary, but verifier-only
construction does not define the semantic object the attester and evidence
mechanism covered. Both constructions are required and must be compared for
semantic equality.

### Bind only `SessionPublicKeyId`

Rejected. ADR-0008 defines the handle as non-authoritative and permits no
inference of key identity, commitment, possession, proof, permit, or admission
from its bytes. Binding only the handle would omit the actual public key.

### Bind only the actual session public key

Rejected. This would cover key material while losing the protocol correlation
handle used by later trusted key-resolution and relying-party paths. The
transcript must bind both values and their trusted association.

### Use opaque manifest commitment markers

Rejected. A marker that says a manifest was considered does not identify the
appraised subject and cannot distinguish substitution among game, runtime,
boot, or measurement meanings.

### Use raw digest bytes

Rejected. Equal-width bytes do not state the semantic namespace or algorithm
identity and therefore cannot identify what was measured or how its value is
interpreted. Manifest and measurement identities retain namespace, algorithm
identity, and value as semantic components without selecting their
representation or algorithm here.

### Use one universal claim set

Rejected. A universal set either omits assurance-specific evidence or forces
every profile to disclose and implement claims it cannot justify. Profiles need
bounded additions while retaining a common mandatory Base.

### Permit arbitrary claim maps

Rejected. Open maps permit omission, invention, aliasing, optional-at-runtime
requirements, and provenance drift. They also let a publisher expand disclosed
host information outside the reviewed OGIR vocabulary.

### Freeze literal labels now

Rejected. Literal purpose, claim, namespace, and field labels are
representation choices. Freezing them in M1 would constrain later canonical
encoding and conformance work before those choices are approved.

### Defer all purpose separation

Rejected. Without semantic purpose separation, valid evidence-binding material
could be reused for protected Attestation Result integrity, permit
authorization, session proof of possession, or renewal authorization. Challenge
authentication is a separate verifier operation, and admission is downstream;
neither is a semantic purpose. The five purpose domains must be distinct before
later representations assign literal labels.

### Equate evidence time with challenge time

Rejected. Challenge issuance and validity, verifier evaluation, evidence
creation and validity, and future result validity are different events governed
by different authorities. Reusing challenge time would hide the unresolved
evidence-time producer, clock or epoch, validity, rollback, restart, renewal,
and privacy contract.

## Decision

OGIR defines one normative semantic **Evidence-binding transcript** for each
evidence instance. It is a closed semantic value, not a byte serialization or
runtime API. `EvidenceBundle` remains external and carries profile-specific
claims and proof material; the complete carrier payload is not a transcript
input.

Each transcript binds:

- one complete current typed `PublisherChallenge`: protocol version; publisher
  identifier; game identifier; exact build identifier; publisher-scoped account
  binding; match or protected-session identifier; policy identifier and policy
  version; nonce; and validated challenge window. Future signature, verifier-
  identity, and channel-binding semantics are not current challenge semantics
  and require separate typed challenge review before inclusion;
- one exact immutable registered `EvidenceProfile` contract;
- one actual ephemeral session public key and the trusted association between
  that key and its `SessionPublicKeyId` for the same publisher and protected
  session;
- one evidence-time semantic required by the profile and accepted only under a
  separately approved evidence-time authority contract;
- the fixed OGIR evidence-binding purpose; and
- the complete profile-required claim values, semantic identities, and
  registered provenance classes.

Every profile requires exactly these eight Base claim meanings:

1. Attesting agent identity
2. Platform identity
3. Boot measurement identity
4. Runtime manifest identity
5. Game manifest identity
6. Process binding identity
7. Protected-session identity
8. Enforcement policy state

The closed profile-specific vocabulary contains exactly two additional
meanings:

1. Attestation identity
2. Runtime measurement identity

An immutable profile contract may declare either profile-specific meaning, at
which point it is required for that profile. A profile cannot remove or rename
a Base meaning, redefine any meaning, make a required claim optional at
runtime, or add an arbitrary extension. Every required meaning appears
semantically exactly once and has exactly one registered provenance class:
`hardware-certified`, `measured-log-derived`, or
`trusted-agent-observed`. Each manifest and measurement identity preserves its
semantic namespace, algorithm identity, and value.

The attester constructs the transcript it asks its evidence mechanism to cover.
Construction alone grants no authority to its values. The publisher verifier
independently reconstructs the expected transcript from the authenticated
challenge, immutable profile contract, resolved actual key and handle
association, independently governed evidence-time input, and candidate claims
with their registered provenance. It establishes exact semantic equality
before profile coverage validation and then performs claim and provenance
appraisal separately. Coverage success does not establish claim truth or policy
acceptance, and appraisal cannot mask incomplete coverage.

`ExpectedContext` remains independent relying-party authority for exact
publisher, game, build, account, match, and selected-policy comparison. It is
not transcript evidence and is never copied from candidate claims.

M1-012 defines exactly five distinct semantic purposes: evidence binding,
protected Attestation Result integrity, permit authorization, session proof of
possession, and renewal authorization. Challenge authentication is a separate
verifier operation, and admission is downstream and outside the transcript;
neither belongs to the closed purpose set. Initial appraisal and same-session
renewal each construct a new evidence-binding transcript with a fresh complete
challenge and current claims. The same actual session public key and
`SessionPublicKeyId` may repeat only when the publisher is unchanged, the
protected `SessionId` and live subject are unchanged, renewal belongs to the
existing session lifecycle, policy is not silently weakened, the current claim
set describes current live state, and the future evidence-time authority accepts
the new evidence. A new publisher or protected session requires a new key and
handle. This ADR does not require profile identity or exact selected-policy
identity to remain unchanged. The transcript purpose remains OGIR evidence
binding; renewal authorization is separate and cannot be derived from evidence-
binding proof.

The evidence-time producer, authority, clock or epoch, validity and skew model,
rollback behavior, restart behavior, renewal semantics, and privacy treatment
remain unresolved. This evidence-time prerequisite blocks runtime transcript
representation, coverage validation, evidence-proof implementation, and
protected-result issuance. Challenge issuance or expiry, verifier evaluation,
future result validity, client time, and omitted, zero, always-valid, or derived
placeholders are not substitutes.

This ADR does not select bytes, field ordering, canonicalization, framing,
parsing, media types, algorithm identifiers, cryptographic mechanisms, proof
formats, literal labels, runtime types or APIs, dependencies, TPM layouts or PCR
selection, protected-result issuance, permits, admission, persistence,
transport, or retention enforcement.

## Consequences

The selected contract makes challenge, claim, provenance, key, identity,
context, lifecycle, and purpose substitutions explicit and independently
testable. Profiles can express bounded assurance differences without open maps,
while the mandatory Base and semantic identity rules prevent a profile from
silently narrowing the appraisal subject. Future M2 work receives one stable
semantic subject for representation, coverage, and conformance decisions.

The costs are additional profile-registry governance, explicit handling of each
claim meaning and provenance class, later canonicalization and interoperability
work, and the requirement to resolve the evidence-time prerequisite before any
runtime mechanism can be validly designed. Producers and verifier logic remain
inside the trusted computing base for the truth of their inputs. This ADR alone
creates no runtime behavior, proof, result authority, permit, admission, or
disciplinary conclusion.

## Threat-model impact

This decision narrows A0/A1 cross-context replay and substitution, A4 trusted-
component and provenance confusion, A5 faulty or compromised publisher-side
construction, and A6 profile or manifest drift. It constrains A8 privacy abuse
by closing the vocabulary and requiring default confidentiality. Protected
assets include exact challenge and appraisal context, session-key association,
evidence meaning, protected-session authorization, and unrelated user privacy.

The affected trust boundaries are publisher challenge issuer to attester,
trusted local key owner and evidence producers to attester, attester to
publisher verifier, independent relying party to verifier, profile registry and
reference data to verifier, and future verifier to protected-result issuer. The
verifier must reject missing, duplicated, invented, reclassified, unequal, or
cross-purpose semantics before successful appraisal. No rejection is evidence
that a player cheated and no failure authorizes protected-mode fallback.

Residual risks remain. A compromised trusted producer can emit dishonest but
correctly classified claims; a compromised verifier or issuer remains within
the TCB; cryptographic coverage strength depends on later approved mechanisms;
full-session relay is not eliminated; and evidence-time soundness remains
unresolved. Evidence-time rollback and evidence-producer or protected-session
restart behavior remain design blockers, not accepted runtime cases.

## Privacy impact

The transcript is correlation-sensitive because it combines complete challenge
context, profile, claim values, provenance, manifest and measurement
identities, the actual public key, key handle, protected-session identity, and
evidence time. It and all proof material are confidential by default. Ordinary
debug, error, tracing, metric, crash, and audit output must exclude every
transcript and proof value, all `ExpectedContext` values, all complete challenge
context, all publisher/build/account/game/match/policy bindings, and all
protected-session context values. Private key material is never a transcript
input.

Profiles may disclose only the eight Base meanings and their declared subset of
the two profile-specific meanings, subject to the local maximum-disclosure
policy and registered disclosure class. This documentation-only decision adds
no transport, persistence, backup, telemetry, retention, deletion, or secure-
erasure behavior. Each of those requires separately approved finite purpose,
confidentiality, access-control, deletion, backup, and privacy rules before
operational use.

## Dependency and license impact

This documentation-only decision adds no dependency, transitive package,
trusted-computing-base package, feature, crate, parser, serializer, cryptographic
primitive, TPM library, I/O, networking, persistence, privilege, `unsafe` code,
or license boundary. Existing Apache-2.0 documentation boundaries are
unchanged.

## Validation

- Maintain the issue, architecture, roadmap, threat-model, privacy, and test-
  strategy matrix for the exact transcript inputs, exclusions, trust sources,
  purpose boundaries, evidence-time blocker, and eight-Base-plus-two-profile-
  specific vocabulary.
- Validate machine-readable attack scenarios for challenge/profile/claim
  substitution, provenance confusion, key/handle substitution, cross-context
  reuse, protocol-purpose confusion, evidence-time substitution, and diagnostic
  disclosure, each with an accountable owner and required assurance profile.
- Run the ADR-index gate and full repository documentation/repository gate for
  every change to this decision or its traceability.
- After representation and mechanism choices are separately approved, add
  isolated mutation, property, conformance, parser, and differential tests. They
  must independently prove verifier reconstruction equality, coverage rejection
  for every single semantic mutation, and separate claim/provenance appraisal;
  one stage cannot use another stage's result as its oracle.
- Keep membership, exactly-once shape, isolated value binding for all eight Base
  and both profile-specific meanings, provenance, semantic identity components,
  actual-key/handle association, context reuse, purpose reuse, and renewal
  authorization as distinct assertions.
- Do not define a runtime acceptance test for evidence-time rollback or restart
  until the prerequisite authority contract determines valid behavior.

## Rollback

Changing this accepted semantic contract requires a superseding ADR, explicit
profile migration analysis, compatibility analysis for existing and planned
consumers, and corresponding updates to the issue, model, architecture, threat
model, privacy model, test strategy, and machine-readable scenarios. Accepted
ADR history must not be deleted.

Disabling future protected behavior is a safe operational fallback. Silently
removing a required meaning, opening the vocabulary, accepting an unverified
attester transcript, treating the key handle as authority, collapsing protocol
purposes, or replacing unresolved evidence time with a placeholder is not an
acceptable rollback.

## Primary sources

- [ADR-0005](0005-verifier-authoritative-challenge-freshness.md) defines
  challenge-time authority and durable replay semantics; those semantics do not
  define evidence creation or validity time.
- [ADR-0007](0007-verifier-flow-capabilities.md) defines exact-attempt verifier
  flow authority and keeps report values non-authoritative.
- [ADR-0008](0008-session-public-key-id-is-not-authority.md) defines
  `SessionPublicKeyId` as a lookup handle rather than key, proof, or admission
  authority.
- [ADR-0009](0009-capability-gated-appraisal-results.md) separates the unsigned
  semantic Appraisal Result from a future protected Attestation Result.
- [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html) defines RATS roles,
  Evidence and Attestation Result separation, appraisal boundaries, and
  freshness as an architectural consideration.
- [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html) defines profile-
  governed EAT claims and separates attestation from an accompanying proof-of-
  possession transaction.
- [M1-012](../../planning/issues/012-evidence-binding-transcript-inputs.md),
  [security invariants](../SECURITY_INVARIANTS.md),
  [architecture](../ARCHITECTURE.md), [roadmap](../ROADMAP.md),
  [threat model](../THREAT_MODEL.md), [privacy model](../PRIVACY_MODEL.md),
  [test strategy](../TEST_STRATEGY.md), and
  [AI development policy](../AI_DEVELOPMENT_POLICY.md) are project authorities
  for the exact issue scope, trust, authorization, privacy, failure, validation,
  and human-review requirements.

These sources guide the semantic boundary only. This ADR adopts no TPM wire
layout, qualifying-data mapping, PCR selection, canonical representation,
commitment, key encoding, cryptographic algorithm, or runtime TPM mechanism.
