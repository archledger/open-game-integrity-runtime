# M1-012F Evidence-time authority design

- Status: Proposed
- Date: 2026-09-01
- Decision owner: Initial maintainer
- Related roadmap task: M1-012 prerequisite before task 13 and M2 transcript work
- Related decision: [ADR-0010](../../adr/0010-semantic-evidence-binding-transcript.md)

## Summary

OGIR will describe evidence time as one challenge-anchored, protected local
collection interval for one complete frozen claim snapshot. An immutable
`EvidenceProfile` registers the trusted local collection authority, protected
monotonic source semantics, and finite collection-duration ceiling. The
publisher verifier authenticates the challenge and remains the sole acceptance
authority; it never treats client wall-clock time as evidence time.

The semantic evidence-time value identifies the registered authority contract,
an opaque publisher-and-session-scoped epoch relation, a protected collection
sequence, and collection start and end. Collection starts only after the local
authority receives the exact complete challenge that the evidence will cover.
The authority freezes the complete snapshot before proof creation. The evidence
instance is valid only for that challenge and must reach the publisher verifier
before the challenge expires.

UTC is absent from this contract. There is no client/server skew allowance and
no conversion between local monotonic values and publisher time. Challenge
issuance plus verifier receipt supplies the rough external epoch described by
the nonce freshness model in RFC 9334 Section 10.2. The protected interval adds
snapshot-duration and same-session continuity semantics without pretending to
be synchronized global time.

Within one uninterrupted protected session, collection is serialized. Renewal
uses a fresh challenge, the same protected epoch relation, a strictly increasing
sequence, and a non-overlapping interval. A restart, rollback, reused or
decreased sequence, epoch mismatch, overlap, impossible interval, or loss of
authoritative continuity terminates the protected session without implying
cheating. A temporary authority outage may remain retryable only while the
existing continuity state is intact and recoverable.

This is a documentation-only semantic design. It selects no runtime type, wire
field, clock unit, integer width, TPM structure, persistence adapter,
cryptographic mechanism, proof format, parser, or production duration value.

## Problem

M1-012 requires every evidence-binding transcript to contain one evidence-time
semantic accepted under a separately approved authority contract. It correctly
rejects challenge issuance time, verifier evaluation time, future result time,
permit time, client wall-clock time, zero, omission, and always-valid values as
substitutes. The unresolved contract currently blocks abstract conformance
fixtures, runtime transcript representation, coverage validation, evidence
proof implementation, and protected-result issuance.

The missing design must answer:

- what event evidence time describes;
- which component is authoritative for it;
- how the publisher verifier validates it without trusting client UTC;
- how initial appraisal and renewal relate;
- how rollback, restart, unavailability, disagreement, and future-looking
  values fail closed;
- what temporal state the verifier retains and for how long; and
- which temporal values are prohibited from diagnostics, telemetry, and
  cross-publisher correlation.

The answer must preserve the existing authority split. The publisher controls
challenge time and appraisal. Trusted local producers derive evidence claims.
The generic attester transports candidate evidence but cannot make a candidate
time authoritative. Later M2 work owns representation and cryptographic
coverage.

## Goals

- Define one common semantic subject for evidence creation and freshness.
- Preserve independent publisher verification and challenge freshness.
- Avoid trusting or synchronizing client wall-clock time.
- Bound one complete claim snapshot rather than only proof-signing time.
- Make initial appraisal and same-session renewal ordering explicit.
- Detect rollback, restart, reuse, overlap, and lost continuity fail closed.
- Keep evidence-time values publisher/session scoped and confidential.
- Give task 13 enough semantics for abstract positive and negative fixtures.
- Give later profiles and M2 work explicit obligations without selecting their
  representations or mechanisms.

## Non-goals

This design does not:

- define evidence-time bytes, field names, ordering, serialization, or parser;
- define a Rust API, trait, state machine, storage adapter, or dependency;
- select a TPM clock, TPM counter, PCR, quote field, key, or command;
- select a signature, MAC, hash, commitment, or domain-separation label;
- assign a production collection-duration number;
- synchronize a client clock with a publisher clock;
- define protected Attestation Result, permit, or renewal-authorization
  validity;
- define permit renewal, revocation, admission, or proof of possession;
- add per-claim timestamps or make cached data current merely by collecting it;
- authorize reuse of one evidence snapshot across challenges;
- make a local attester, game, bridge, or client the acceptance authority; or
- treat a temporal failure as evidence that a player cheated.

## Primary sources and project authorities

### Primary standards

- [RFC 9334, Section 10](https://www.rfc-editor.org/rfc/rfc9334.html#section-10)
  defines freshness as an architectural decision and distinguishes synchronized
  clocks, verifier nonces, and epoch identifiers.
- [RFC 9334, Section 10.2](https://www.rfc-editor.org/rfc/rfc9334.html#section-10.2)
  explains that a signed unpredictable verifier nonce establishes a rough epoch
  without a trustworthy attester clock, while applying to the whole claim set.
- [RFC 9334, Section 10.4](https://www.rfc-editor.org/rfc/rfc9334.html#section-10.4)
  warns that claim values may have been generated before signing and makes the
  signer responsible for ensuring that they remain fresh.
- [RFC 9711, Section 4.3.1](https://www.rfc-editor.org/rfc/rfc9711.html#section-4.3.1)
  distinguishes token creation time from older claim-specific observations.
- [RFC 9711, Section 6.3.11](https://www.rfc-editor.org/rfc/rfc9711.html#section-6.3.11)
  requires an EAT profile to specify its freshness mechanism.
- [RFC 9711, Section 9.3](https://www.rfc-editor.org/rfc/rfc9711.html#section-9.3)
  requires every EAT use to provide a freshness mechanism.

### Project authorities

- `docs/SECURITY_INVARIANTS.md`, especially invariants 5, 8-10, 13, 20-22,
  34, 37-42, and 47-48;
- `docs/THREAT_MODEL.md` for replay, rollback, authority confusion, privacy,
  unavailable-state, and non-disciplinary failure requirements;
- `docs/ARCHITECTURE.md` for publisher-verifier challenge time, durable replay
  state, session key/handle lifetime, and fail-closed restart behavior;
- `docs/PROTOCOL.md` for the closed evidence-binding transcript;
- `docs/PRIVACY_MODEL.md` for transcript confidentiality and disclosure limits;
- `docs/TEST_STRATEGY.md` for deterministic adversarial coverage;
- `docs/ROADMAP.md` for M1-012, task 13, M2, and later renewal ownership;
- ADR-0005 for publisher-authoritative challenge freshness;
- ADR-0006 for process-local protected-session lifecycle;
- ADR-0007 for verifier capability ordering and restart limitations;
- ADR-0008 for session public-key handle authority and lifetime;
- ADR-0009 for appraisal-result authority; and
- ADR-0010 for the semantic evidence-binding transcript and external carrier.

## Terminology

### Evidence Collection Authority

The profile-registered trusted local component that controls one collection
operation and vouches for its protected local temporal semantics. It may
coordinate multiple registered claim producers. It does not make every claim
true, authenticate the publisher challenge, appraise policy, issue a protected
result, or authorize admission.

### Collection operation

One serialized, challenge-bound operation that opens a protected interval,
collects or revalidates every profile-required claim, freezes one complete
snapshot, and hands that snapshot to the profile evidence mechanism.

### Frozen snapshot

The immutable complete profile-required claim and provenance set after
collection closes and before proof creation starts. Later mutation requires a
new collection operation and evidence instance.

### Protected epoch relation

An opaque semantic relation proving that collections belong to the same
uninterrupted authority lifetime for one publisher and protected session. It is
not UTC, a raw boot identifier, a raw TPM clock, a device-wide reset counter, or
a globally comparable timestamp.

### Collection sequence

A protected value that strictly increases for each collection opened in one
publisher/session-scoped epoch. Accepted values need not be contiguous because
a collection may be dropped or rejected before the verifier observes it.

### Collection interval

The ordered pair from protected collection start through complete snapshot
freeze. It does not include proof completion, network transport, verifier
evaluation, protected-result issuance, or permit validity.

### Temporal high-water

The verifier's minimum active-session continuity state: the accepted epoch
relation, greatest validated sequence, and latest validated interval end. It is
authorization state, not telemetry.

## Authority model

### Publisher challenge issuer and verifier

The publisher issuer remains authoritative for nonce generation, challenge
window selection, durable registration, and challenge authentication policy.
The publisher verifier remains authoritative for:

- authenticating the complete challenge;
- evaluating the challenge at publisher-authoritative time;
- claiming the nonce through the existing atomic freshness path;
- selecting the immutable profile and publisher policy;
- validating the profile's collection-authority statement and evidence
  coverage;
- atomically checking and advancing active-session temporal high-water; and
- appraising claim truth, provenance, and policy separately.

Publisher time never becomes a transcript evidence-time value.

### Evidence Collection Authority

Each immutable `EvidenceProfile` registers exactly one collection-authority
contract. The contract defines:

- which trusted local component controls collection;
- which protected monotonic source semantics it uses;
- how publisher/session-scoped epoch continuity is established;
- how sequence increase and interval ordering are protected;
- how the complete snapshot becomes immutable at freeze;
- which finite collection-duration ceiling the profile permits;
- how restart, rollback, unsafe source state, and unavailability are reported;
  and
- how the verifier validates the protected temporal statement.

A profile identity or authority-contract change requires explicit versioning or
a new profile identity. An unregistered authority contract is unsupported, not
an optional extension.

### Claim producers

Registered claim producers remain authoritative only within their approved
provenance classes. The collection authority coordinates and freezes their
outputs but cannot promote an untrusted value to hardware-certified,
measured-log-derived, or trusted-agent-observed provenance.

Boot measurements, manifests, or other source facts may originate before the
collection interval. During the interval the registered producer path must
re-derive or revalidate that each bound semantic claim still describes the
current live appraisal subject. Snapshot time does not refresh stale data by
declaration.

### Generic attester and untrusted transport

The generic attester receives the challenge, requests collection, constructs
the candidate transcript, invokes the profile evidence mechanism, and
transports the external `EvidenceBundle`. It cannot choose, rewrite, alias, or
normalize authority identity, epoch, sequence, start, or end. Construction and
transport grant no authority.

The collection authority does not need publisher trust roots. It opens only for
the exact challenge supplied to the collection operation and ensures that the
same complete challenge is covered. The publisher verifier later authenticates
that challenge. A locally supplied fake challenge can waste bounded work but
cannot pass publisher verification.

### Profile evidence mechanism

The profile evidence mechanism covers the complete frozen semantic transcript,
including evidence time. This design does not require the collection authority
and evidence mechanism to be the same implementation, but the immutable profile
must define their trust and handoff relationship without an unprotected rewrite
gap.

## Evidence-time semantic value

One transcript binds one semantic evidence-time value with exactly these
components:

1. the immutable registered collection-authority contract identity;
2. one opaque publisher/session-scoped protected epoch relation;
3. one protected collection sequence;
4. one protected collection start; and
5. one protected snapshot-freeze end.

The components are semantic, not a proposed serialization. Later representation
may avoid literal duplication when the transcript's profile, publisher,
session, key, or handle already supplies scope, but it must preserve exact
equality and domain separation.

The value has these mandatory relationships:

- authority contract matches the exact registered profile;
- publisher and protected session match the complete challenge, live subject,
  actual session public key, and `SessionPublicKeyId` association;
- start and end use one protected source and one epoch relation;
- start is not after end;
- elapsed collection duration is finite and within effective policy;
- the complete snapshot freezes exactly at end;
- the profile mechanism covers the exact value without omission or aliasing;
  and
- no UTC, verifier time, challenge time, result time, permit time, or caller
  time is substituted into any component.

## Collection lifecycle

### Initial appraisal

1. The generic attester receives one complete challenge.
2. The collection authority rejects a second active operation for the same
   protected session.
3. It opens one operation scoped to the challenge publisher, protected session,
   actual session key/handle association, and registered profile.
4. It establishes the publisher/session-scoped protected epoch relation and
   assigns a new protected sequence.
5. It records protected start.
6. It obtains or revalidates every required current claim through the exact
   registered producer and provenance path.
7. It records protected end and atomically freezes the complete snapshot.
8. It refuses mutation or claim addition after freeze.
9. The attester constructs the exact semantic transcript from the challenge,
   profile, key/handle association, evidence time, and frozen claims.
10. The profile mechanism creates coverage over that transcript.
11. The publisher verifier authenticates and claims the challenge through the
    existing freshness path, validates the profile/authority contract,
    validates exact transcript coverage and evidence time, and establishes
    active-session temporal high-water before later claim appraisal.

### Same-session renewal

Renewal creates new evidence. It never reuses the previous snapshot, interval,
sequence, proof, carrier, or challenge.

One renewal is temporally eligible only when:

- it binds a fresh complete challenge;
- publisher, protected `SessionId`, live subject, and key/handle lifecycle are
  unchanged as required by ADR-0010;
- no collection operation is already active;
- the protected epoch relation exactly matches active-session high-water;
- the new sequence is strictly greater than the greatest validated sequence;
- the new start is not earlier than the latest validated end;
- the interval satisfies effective duration policy;
- the current complete claim set is newly collected or revalidated and frozen;
  and
- the evidence reaches the verifier before the new challenge expires.

Profile identity and exact selected-policy identity need not remain unchanged
under ADR-0010. If either changes, the new profile/authority contract must still
prove continuity with the same protected publisher/session-scoped epoch or the
session cannot renew. A profile transition cannot reset sequence or interval
high-water.

### Why sequences may have gaps

The local authority assigns sequence before the publisher verifier can observe
the collection. Network loss, challenge rejection, malformed transport, or
invalid proof can consume a local sequence without producing validated verifier
state. Requiring contiguous accepted values would turn ordinary message loss
into false session loss.

The verifier therefore requires strict increase, not arithmetic succession.
Reuse or decrease is forbidden. Gaps do not authorize missing evidence and do
not weaken single-challenge coverage; each accepted value still carries a fresh
challenge and a complete independently reconstructed transcript.

## Validity and time-domain separation

### Single-challenge validity

One evidence instance is eligible only for its exact complete challenge. The
challenge must be authenticated and fresh under ADR-0005, and the evidence must
reach the verifier before the challenge's half-open expiry boundary. A snapshot
or proof cannot be cached for a later nonce, publisher, session, policy context,
or renewal.

Nonce freshness provides a rough external epoch: the protected evidence could
not cover the unpredictable nonce before receiving it, and publisher receipt
occurs at a known verifier-authoritative time. The local interval describes the
bounded collection between those events. It does not become publisher time.

### Collection-duration policy

Each immutable profile defines a finite hard ceiling compatible with its
protected source and evidence mechanism. Publisher policy may impose an equal
or stricter ceiling. The effective maximum is the stricter accepted value. A
publisher cannot loosen the registered profile ceiling, and a client cannot
choose either value.

This design selects no numeric duration. Before runtime representation for a
profile is approved, that profile and publisher policy model must define
bounded values, units, comparison behavior, arithmetic limits, and exact edge
inclusion.

### Post-freeze latency

There is no independent post-freeze local-to-server latency field. Without UTC
or another protected marker, such a value would be unverifiable. The publisher
challenge window bounds the full proof-creation, transport, and verifier-receipt
path after freeze. Later representation work must not invent a claimed
post-freeze duration.

### Skew

No client clock is compared with publisher time, so the accepted wall-clock
skew is not a configurable tolerance; it is inapplicable. The verifier applies
the existing zero-leeway challenge window only in its own authoritative domain.
Introducing a local UTC timestamp or skew allowance requires a new architecture,
threat, privacy, profile, and conformance decision.

### Future-time behavior

Evidence time contains no globally comparable timestamp. A local UTC value,
challenge-derived timestamp, verifier-derived timestamp, result time, permit
time, zero, maximum sentinel, or always-valid marker is malformed or
unsupported according to shape/profile support and can never be clamped into
acceptance.

A protected monotonic value is not classified as past or future relative to
publisher UTC. Its validity comes from protected-source safety, same-epoch
ordering, finite interval duration, strict sequence increase, non-overlap, and
challenge-bounded receipt. An unsafe or discontinuous protected source fails
closed.

### Claim observation versus claim event time

The collection interval states when the complete claim snapshot was assembled,
revalidated, and frozen. It does not claim that every underlying event occurred
during that interval. A boot measurement can describe an earlier boot event;
the registered producer must validate during collection that the measurement
still identifies the current boot and live subject.

This design does not add per-claim timestamps. A future profile that requires a
claim-specific age must define that meaning inside the closed profile vocabulary
and receive separate M1-012 vocabulary, privacy, representation, and versioning
review. It cannot smuggle arbitrary timestamps into evidence time.

## Verifier ordering and temporal state

The later verifier design must preserve this semantic order:

1. receive challenge, expected context, profile carrier, and publisher time;
2. authenticate the complete challenge;
3. perform ADR-0005 authoritative-time, exact-context, and atomic nonce-claim
   behavior;
4. resolve the immutable evidence profile, collection-authority contract,
   effective duration policy, and active protected-session association;
5. independently reconstruct the complete candidate transcript;
6. validate profile coverage and the protected authority statement needed to
   trust evidence-time components;
7. atomically check epoch equality, strict sequence increase, interval order,
   non-overlap, duration, and current temporal high-water;
8. advance temporal high-water for every valid protected temporal statement,
   even if later claim or policy appraisal rejects;
9. validate claim provenance and current-subject relationships; and
10. perform policy appraisal and emit only an existing coarse result.

High-water advancement before later appraisal prevents a policy or claim
rejection from hiding an observed valid sequence and enabling rollback on a
subsequent renewal. Invalid or unauthenticated coverage does not grant authority
to candidate temporal values and cannot advance high-water.

The temporal compare-and-advance operation must be atomic for one active
protected session. Two concurrent valid-looking collections cannot both pass
from the same prior high-water. Local collection serialization is required but
does not replace verifier atomicity.

## Rollback, restart, and recovery

### Local authority rollback or restart

The current protected session ends if:

- the collection authority restarts;
- its protected source restarts, resets, rolls back, or becomes unsafe;
- the publisher/session-scoped epoch relation changes;
- sequence is reused or decreases;
- an interval overlaps accepted history;
- collection ordering becomes impossible; or
- authority continuity cannot be established.

The session key/handle lifecycle is invalidated under the existing local session
contract. Recovery requires a new protected session, new actual key and handle,
fresh challenge, new scoped epoch relation, and initial appraisal. Same-session
renewal cannot bridge the discontinuity.

### Verifier state loss

Missing, corrupt, rolled-back, or contradictory temporal high-water means
continuity is lost and protected mode fails closed. There is no stateless
fallback, client-supplied repair value, inferred sequence, or acceptance of a
new epoch inside the old session.

A temporary store or authority outage may map to retry/unavailable only when
the implementation can prove that authoritative state still exists unchanged
and will be observed when service returns. It must not advance, release, or
reconstruct high-water from untrusted evidence during the outage. The consumed
challenge remains consumed and retry requires a fresh challenge.

### Forward discontinuity

Sequence gaps are allowed for unobserved collections, but protected-source
continuity still must validate under the profile contract. A gap is not a
license to accept an epoch reset, unsafe clock state, interval reversal, or
source discontinuity. Exact mechanism-specific evidence for that distinction is
deferred to each profile and M2/M3 review.

## Failure semantics

This design adds no `Decision`, `ReasonCode`, denial variant, verifier state, or
disciplinary outcome. Later implementation uses existing coarse M1-011 classes:

| Condition | Existing mapping or required behavior |
| --- | --- |
| Missing, duplicate, aliased, contradictory, or structurally invalid candidate shape before protected authority validation | `Malformed` |
| Unregistered profile, authority contract, critical temporal semantic, or protected source kind | `Unsupported` |
| Challenge not yet valid, expired, replayed, or context-mismatched | Existing challenge freshness/context mapping |
| Authority statement or transcript coverage cannot be validated | `EvidenceInvalid` |
| Effective collection-duration policy fails while protected continuity remains valid | `EvidenceInvalid` |
| Temporary authority/store outage with intact recoverable continuity | `Retry` with `AttestationUnavailable` |
| A validated authority statement proves start after end, epoch change, rollback, restart, reused/decreased sequence, overlap, source discontinuity, or lost high-water | `ProtectedSessionLost` and terminal session invalidation |
| Evidence-time contract or profile-specific finite limits are absent | Implementation blocked; no runtime fallback |

Every failure after ADR-0005 atomic nonce claim leaves the challenge consumed.
No failure proves cheating. Operational unavailability, unsupported hardware,
rollback detection, malformed transport, and policy rejection remain distinct
for coarse reporting and internal remediation without exposing private values.

## Privacy, retention, and diagnostics

Evidence time is correlation-sensitive authorization data. The semantic value,
protected source statement, and proof are confidential by default.

### Scope and disclosure

- The exposed epoch relation is opaque and scoped to one publisher and
  protected session.
- Raw boot identifiers, boot seeds, reset/restart counters, TPM clock values,
  daemon uptime, host wall-clock time, and device-wide epoch identifiers are not
  transcript values.
- Cross-publisher or cross-session equality must not be observable from the
  evidence-time representation unless a separately approved claim already
  requires that identity for a declared purpose.
- Evidence time cannot become an analytics identifier, player identifier,
  anti-cheat score, discipline record, or general host telemetry.

### Verifier retention

The verifier retains only the authority contract reference, scoped epoch
relation, greatest validated sequence, and latest validated end needed for the
active protected session. It deletes that temporal high-water at terminal
session end after any atomic in-flight operation is resolved. Existing challenge
replay retention remains separately governed by ADR-0005 and is not extended by
this design.

No backup, replica, disaster-recovery, or migration behavior is authorized by
this semantic decision. Any production persistence design must preserve atomic
high-water, anti-rollback, finite active-session retention, deletion, and
publisher/session scoping under separate review.

### Local retention

The collection authority retains only active-operation state and the minimum
same-session continuity state required for serialization and protected-source
validation. Frozen claim snapshots and proof material follow the separately
approved evidence-carrier lifecycle and cannot be retained merely for temporal
analytics or cross-challenge reuse.

### Diagnostics

Ordinary `Debug`, `Display`, errors, logs, traces, metrics, crash reports, audit
events, support bundles, and test assertion messages must exclude:

- authority contract identifiers when they reveal deployment detail;
- epoch relations;
- sequences;
- interval start, end, and duration;
- temporal high-water;
- raw protected-source values or state;
- complete challenge or expected-context values;
- session key/handle values; and
- proof or carrier bytes.

Diagnostics report only coarse redacted class and operational disposition. An
explicit accessor inside trusted functional code is not an approved diagnostic
sink.

## Threat analysis

### Stale snapshot relabeled as fresh

Threat: collect cached claim values after receiving a nonce and claim that
snapshot collection makes the underlying state current.

Required response: every profile registers how each claim is newly obtained or
revalidated against the current live subject during the interval. Collection
time never overrides claim provenance or current-state validation.

### Challenge substitution or snapshot reuse

Threat: create one snapshot for challenge A and cover, submit, or replay it under
challenge B, another publisher, session, key, profile, or renewal.

Required response: the complete exact challenge and all M1-012 semantics are
covered together; evidence is single-challenge; context and key/session
relationships are checked independently.

### Clock confusion

Threat: copy challenge `issued_at`, challenge expiry, verifier `now`, result
time, permit time, host UTC, or process uptime into evidence time.

Required response: those domains are structurally and semantically excluded.
No skew, clamping, normalization, or fallback converts them into protected local
collection semantics.

### Rollback and restart

Threat: restart or roll back the collection authority, protected source, or
verifier state, then bind a fresh nonce to old local state.

Required response: same-session epoch continuity, strict sequence increase,
non-overlap, atomic verifier high-water, and terminal session loss on continuity
failure. New-session recovery requires a new key/handle and scoped epoch.

### Concurrent collection

Threat: race two renewals from one temporal state and obtain two accepted
snapshots.

Required response: one active local collection plus atomic verifier temporal
compare-and-advance. Challenge replay atomicity remains independently required.

### Forward jump and duration abuse

Threat: use extreme values, arithmetic overflow, an unbounded interval, or an
unsafe protected source to bypass freshness.

Required response: finite profile ceiling, policy tightening only, bounded later
representation, checked arithmetic, source-safety validation, and no UTC or
sentinel interpretation. Sequence gaps alone do not authorize source
discontinuity.

### Diagnostic and correlation leakage

Threat: expose raw epoch, clock, sequence, timing, challenge, session, or proof
values through errors or retained telemetry, enabling cross-context tracking.

Required response: publisher/session-scoped opacity, minimum active-session
state, terminal deletion, fixed redaction, and no telemetry purpose.

## Required validation

### Positive semantic cases

- Initial appraisal opens after receiving the exact challenge, collects every
  current required claim, freezes within effective duration policy, reaches the
  verifier before challenge expiry, and establishes temporal high-water.
- Same-session renewal uses a fresh challenge, same epoch relation, greater
  sequence, non-overlapping interval, current complete snapshot, and updated
  high-water.
- A sequence gap caused by an unobserved failed collection remains eligible when
  protected continuity, strict increase, non-overlap, and all other checks hold.
- A boot-origin claim remains eligible only when its registered producer
  revalidates that it identifies the current boot during collection.
- A temporary unavailable result can retry with a fresh challenge after the
  intact authoritative state becomes available.

### Negative semantic cases

- collection opened before the covered challenge is received;
- challenge A snapshot or proof submitted for challenge B;
- reuse across publisher, session, key/handle, profile authority, or renewal;
- second concurrent collection for one protected session;
- missing, duplicated, invented, aliased, or contradictory temporal component;
- UTC, challenge time, verifier time, result time, permit time, uptime, zero, or
  always-valid substitution;
- start after end or duration beyond effective policy;
- proof arrives at exact challenge expiry or later;
- same or lower sequence;
- changed epoch inside one protected session;
- new start before prior validated end;
- local authority or protected source restart/rollback/unsafe state;
- missing, corrupt, rolled-back, unavailable, or non-atomic verifier high-water;
- stale cached claim accepted solely because collection is recent;
- policy rejection hiding a validated sequence from later high-water;
- invalid proof advancing candidate temporal high-water;
- profile transition resetting sequence or epoch;
- old session epoch accepted after new-session recovery;
- raw temporal value emitted by any diagnostic surface; and
- temporal state retained after terminal session end without approved purpose.

### Property and mutation strategy

Task 13 abstract fixtures and later model tests must establish:

- equality only when every semantic component and scope relation is equal;
- any one-component mutation prevents equivalent transcript coverage;
- accepted sequences strictly increase but need not be contiguous;
- accepted intervals never overlap within one session epoch;
- no accepted renewal crosses an epoch or terminal session boundary;
- no challenge validates more than one evidence instance;
- high-water never decreases, resets, or disappears while the session is live;
- later appraisal failure cannot undo a validated temporal observation;
- temporary unavailability cannot create authority or stateless fallback;
- no wall-clock skew parameter influences evidence-time acceptance; and
- every generated diagnostic remains value-independent and redacted.

Finite model work should include arbitrary histories of collection open,
freeze, drop, submit, validate, reject, renew, concurrent submit, authority
outage, verifier outage, rollback, restart, terminal session end, and deletion.
Mutation counts are selected only after the semantic inventory is frozen.

No byte fuzz target is justified by this documentation-only design. M2 parser
work must add bounded fuzzing and differential validation after representation
is selected.

## Documentation delivery

An implementation plan for this documentation-only contract should consider:

- a canonical planning issue for M1-012F;
- `CONTEXT.md` terminology;
- `docs/ARCHITECTURE.md` authority, flow, restart, and state lifetime;
- `docs/PROTOCOL.md` evidence-time semantics and time-domain separation;
- `docs/ROADMAP.md` resolution of the M1-012 prerequisite before task 13;
- `docs/TRUST_MODEL.md` local authority and verifier responsibilities;
- `docs/PRIVACY_MODEL.md` scoped epoch, retention, and diagnostics;
- `docs/THREAT_MODEL.md` stale collection, rollback, concurrency, and leakage;
- `docs/TEST_STRATEGY.md` positive, negative, property, and mutation matrices;
- `docs/SECURITY_INVARIANTS.md` only if existing evidence freshness, restart,
  renewal, privacy, and fail-closed invariants prove insufficient;
- one ADR because authority placement, nonce-plus-monotonic design, session
  termination on restart, and no-UTC semantics are hard to reverse; and
- schema-valid attack scenarios expressible without inventing representation.

The documentation task adds no Rust, dependency, parser, serializer,
cryptography, persistence implementation, privilege, networking, or production
configuration.

## Alternatives considered

### Challenge-anchored protected collection interval

Selected. It combines RFC 9334 nonce freshness with a protected local snapshot
interval and same-session continuity. It avoids client UTC while exposing enough
semantics for bounded collection, renewal ordering, rollback detection, and
abstract fixtures.

### Trusted synchronized UTC plus monotonic continuity

Rejected for this phase. It could quantify absolute evidence age directly, but
would add synchronization endorsements, skew policy, future-time behavior,
wall-clock rollback, and a larger local trust boundary. RFC 9334 explicitly
recognizes that a trustworthy synchronized clock may be unavailable.

### Nonce-only rough epoch

Rejected as incomplete. It establishes that covered evidence follows nonce
generation but cannot express collection duration, snapshot freeze, local
rollback, serialized renewal, or same-session temporal continuity.

### Per-claim timestamps

Rejected. They expand the closed vocabulary and privacy surface, multiply clock
authorities, and do not provide one coherent snapshot boundary. Claim-specific
event age requires separate profile vocabulary review.

### Profile-specific unconstrained temporal union

Rejected. Allowing arbitrary instant, interval, sequence, UTC, or epoch shapes
would make verifier behavior profile-fragmented and unknown-critical handling
ambiguous. Profiles may vary mechanism and limits while preserving this common
semantic contract.

### Evidence mechanism proof-completion time

Rejected. Defining interval end as proof completion creates self-reference if
that end must be covered by the proof. The snapshot freezes first; challenge
expiry bounds proof creation and transport afterward.

### Verifier-assigned evidence time

Rejected. Receipt time is publisher authority for evaluation, not evidence
creation. It cannot prove when local claims were collected and would collapse
the time-domain separation required by ADR-0010.

### Contiguous accepted sequences

Rejected. A locally created collection can be lost before verifier observation.
Arithmetic succession would make ordinary loss appear as rollback. Strict
increase plus epoch continuity and non-overlap detects reuse without requiring
the verifier to observe every failed collection.

### Resume the same protected session after authority restart

Rejected. Safe continuation would require separately designed durable local
epoch transition, anti-rollback, key lifetime, recovery, migration, and verifier
state. Existing local session capabilities are process-local. Recovery therefore
starts a new protected session with a new key/handle and epoch scope.

### Retain raw boot or TPM epoch values

Rejected. Raw device-wide values enable cross-publisher/session correlation and
freeze TPM-specific representation before M3 review. The semantic relation is
opaque and scoped.

## Compatibility and migration

No stable evidence-time runtime representation or wire artifact exists, so this
decision requires no compatibility parser or persisted-data migration.

M1-012 currently marks evidence-time authority unresolved. Once this design and
its documentation plan are approved, project text must replace that blocker
with this normative contract rather than preserve both as alternatives.

Task 13 may then define abstract JSON conformance fixtures for the semantic
value and its relationships without claiming those fixture fields are the M2
wire format. M2 may design representation and coverage only if it preserves the
authority, scoping, ordering, single-challenge validity, and privacy rules here.
M3 remains responsible for proving any TPM-specific mapping.

Changing the common tuple, allowing UTC, enabling cross-challenge reuse,
permitting same-session epoch transition, or broadening retention after fixtures
exist requires explicit versioning and renewed architecture, threat, privacy,
and conformance review.

## Residual risks

- A compromised registered collection authority can misstate collection
  boundaries or coordinate dishonest producers while producing structurally
  valid evidence.
- A compromised claim producer can provide dishonest current-state data within
  its trust class; collection timing does not establish claim truth.
- A compromised publisher verifier or profile registry remains inside the TCB.
- Full-session relay and post-appraisal state change remain outside this
  temporal contract.
- The challenge window bounds total proof/transport latency but does not measure
  the post-freeze portion independently.
- Exact production duration limits, protected-source mechanisms, proof strength,
  persistence, replication, backup, and secure deletion remain later profile
  and implementation decisions.
- A new session after restart intentionally loses continuity with the old
  session; its security relies on new key/handle creation, fresh challenge, and
  old-session invalidation.

These are explicit residual risks, not permission for fallback or inflated
assurance claims.

## Acceptance criteria

The evidence-time authority design is complete only when:

- evidence time describes one complete frozen collection snapshot;
- one immutable profile registers the trusted local collection authority and
  protected monotonic semantics;
- the generic attester and local client remain non-authoritative;
- the semantic value contains authority contract, scoped epoch relation,
  sequence, start, and end meanings without selecting representation;
- collection opens only for the exact challenge later covered and authenticated;
- snapshot freeze precedes proof creation without self-reference;
- evidence is valid for one challenge only and arrives before challenge expiry;
- profile finite duration is mandatory and publisher policy only tightens it;
- no separate unverifiable post-freeze latency field is introduced;
- UTC, skew, challenge time, verifier time, result time, permit time, uptime,
  zero, and always-valid substitution are excluded;
- renewal uses a fresh challenge, same uninterrupted epoch, strictly greater
  sequence, and non-overlapping interval;
- sequence gaps are allowed only because unobserved collections may be lost;
- verifier temporal high-water advances atomically for validated temporal
  statements before later appraisal and never from invalid proof;
- authority restart, rollback, epoch change, reuse/decrease, overlap, protected-
  source discontinuity, or lost high-water terminates the session;
- temporary unavailability is retryable only with intact recoverable state and
  a fresh challenge;
- new-session recovery requires new key/handle and scoped epoch;
- cached or boot-origin claims require current-subject revalidation during
  collection;
- epoch and timing values are publisher/session scoped, confidential, redacted,
  minimally retained, and deleted at terminal session end;
- failure mappings remain coarse, fail closed, and non-disciplinary;
- positive, negative, property, mutation, concurrency, rollback, restart, and
  privacy cases are explicitly enumerable;
- task 13 ownership of abstract fixtures and M2/M3 ownership of representation,
  cryptography, parser, and TPM mapping remain intact;
- no runtime API, wire, crypto, TPM, persistence implementation, dependency,
  privilege, or production limit enters scope; and
- the human decision owner reviews and approves the exact written candidate
  before implementation planning or DCO certification.

## Deferred implementation prerequisites

This design resolves the common semantic evidence-time authority prerequisite.
It does not by itself authorize runtime implementation.

Before one profile can be represented or validated at runtime, later approved
work must define:

- the profile's protected monotonic source and source-safety semantics;
- publisher/session-scoped epoch construction and validation;
- sequence and interval representation with checked bounds;
- exact finite profile and publisher-policy duration values;
- atomic local collection and verifier high-water storage behavior;
- evidence mechanism coverage and authority-statement validation;
- canonical encoding, parsing, algorithms, and literal purpose labels;
- production retention, deletion, replication, backup, recovery, and migration;
  and
- TPM-specific mapping where applicable.

No placeholder may bypass those profile and M2/M3 gates.
