# M1-012F: Define challenge-anchored evidence-time authority
<!-- labels: type: architecture,type: documentation,area: model,area: verifier,area: agent,area: session,area: privacy,risk: trusted-computing-base,risk: privacy,status: ready -->
<!-- milestone: M1 Domain Model -->

## Problem

M1-012 requires every evidence-binding transcript to contain one evidence-time
semantic, but intentionally blocked representation and proof work until a
separately approved authority contract defined its producer, clock or epoch,
validity, skew, rollback, restart, renewal, and privacy behavior.

OGIR now selects one challenge-anchored protected local collection interval for
one complete frozen claim snapshot. An immutable `EvidenceProfile` registers
one Evidence Collection Authority and protected monotonic contract. The
publisher verifier authenticates the challenge and remains the sole acceptance
authority. Client UTC and every other protocol time domain remain excluded.

On 2026-09-01, the decision owner approved design SHA-256
`6d0c2f5f9625a584dba06468bf9b7016ef3223ddcaa3336ad168f299abe89bd4`
and certified exact signed design commit
`2bc3a6d4f9a3edeee829e3a8e620daa3df7d3f85` under DCO 1.1. That approval
authorizes documentation planning only. Runtime code, representation,
cryptography, a live issue, publication, and further commits remain separate
human gates.

## Security invariants

- Evidence time describes when one complete current claim snapshot was
  collected, revalidated, and frozen; it does not claim every underlying event
  occurred during that interval.
- One immutable profile registers exactly one collection-authority contract,
  protected monotonic source semantics, and finite duration ceiling.
- The semantic value contains authority contract, opaque publisher/session
  epoch relation, protected sequence, protected start, and protected freeze end.
- The exact complete challenge is received before collection opens and is later
  authenticated and covered; one evidence instance is valid only for that
  challenge.
- Snapshot freeze precedes proof creation. Challenge expiry bounds proof,
  transport, and verifier receipt after freeze.
- Client UTC is absent and no wall-clock skew tolerance can authorize evidence.
- Accepted same-session sequences strictly increase but need not be contiguous;
  accepted intervals never overlap.
- Validated temporal high-water advances atomically before later appraisal and
  cannot be reset by a later rejection.
- Continuity loss terminates the protected session without implying cheating.
- Temporal values are confidential, minimally retained, and redacted.

## In scope

- Canonical Evidence Collection Authority, Frozen evidence snapshot, Protected
  epoch relation, Collection sequence, Collection interval, and Temporal
  high-water terminology.
- Immutable profile registration of one local collection authority, protected
  monotonic source semantics, and finite hard duration ceiling.
- The evidence-time semantic tuple and its publisher/session/key/profile scope.
- Initial receive, open, collect/revalidate, freeze, proof, verifier validation,
  and high-water lifecycle.
- Same-session renewal, sequence gaps, non-overlap, profile transitions, and
  terminal continuity loss.
- Exact challenge relation, single-challenge validity, challenge-expiry receipt,
  collection duration, no-UTC/skew behavior, and post-freeze boundary.
- Verifier ordering, atomic temporal high-water, rollback, restart,
  unavailability, and recovery behavior.
- Existing M1-011 coarse failure mappings and non-disciplinary semantics.
- Publisher/session-scoped epoch privacy, minimum retention, terminal deletion,
  and diagnostic exclusion.
- Documentation, one ADR, deterministic validation strategy, and machine-
  readable attack scenarios.

## Out of scope

- Rust types, traits, methods, state machines, storage adapters, or APIs.
- Integer widths, clock units, exact production duration values, arithmetic
  representation, or serialization.
- JSON, CBOR, wire fields, numeric tags, parser, canonical encoding, or media
  type.
- Synchronized client UTC, time service, skew tolerance, or local-to-publisher
  time conversion.
- TPM clock/counter structures, reset/restart fields, commands, PCRs, quote
  layout, or hardware profile mapping.
- Hash, signature, MAC, KDF, commitment, key, proof format, or literal domain-
  separation label.
- Protected Attestation Result, permit, or renewal-authorization validity.
- Permit renewal, revocation, admission, proof of possession, or matchmaking.
- Per-claim timestamp vocabulary or arbitrary profile timestamp extensions.
- Production persistence, replication, backup, migration, deletion enforcement,
  networking, telemetry, or dependency selection.

## Trust sources

| Authority | Exact responsibility |
| --- | --- |
| Publisher challenge issuer and verifier | Challenge time, authentication, freshness, and final acceptance |
| Immutable profile registry | Collection-authority contract, protected source semantics, and hard duration ceiling |
| Evidence Collection Authority | Protected local collection interval, scoped epoch, sequence, and snapshot freeze |
| Registered claim producers | Claim truth within the profile's exact registered provenance |
| Generic attester | Collection request, candidate transcript construction, proof invocation, and transport only |
| Profile evidence mechanism | Complete frozen transcript coverage |
| Publisher verifier | Protected authority-statement validation, atomic high-water, provenance validation, and appraisal |
| Relying party | Independent `ExpectedContext`, outside transcript evidence |
| Future protected-result issuer | Result validity and integrity, outside this issue |

The game, bridge, generic attester, local client, process uptime, host UTC,
challenge timestamps, verifier evaluation time, result time, permit time, and
caller-supplied repair state are not evidence-time authorities.

## Required interfaces

The interface is semantic rather than a Rust or wire API:

```text
Evidence time
  registered collection-authority contract
  opaque publisher/session-scoped protected epoch relation
  protected collection sequence
  protected collection start
  protected snapshot-freeze end
```

The authority contract must define the trusted local component, protected
source semantics, scoped epoch continuity, sequence/interval protection,
snapshot freeze, finite duration ceiling, restart/rollback/unavailability
behavior, and verifier validation path. A profile or authority-contract change
requires explicit versioning or a new profile identity.

The profile ceiling is finite. Publisher policy may impose an equal or stricter
limit but cannot loosen it. This issue selects no numeric value or unit.

## Required relationships

### Initial appraisal

1. The generic attester receives one complete challenge.
2. The collection authority rejects a second active operation for the same
   protected session.
3. It opens one operation for the challenge publisher, protected session,
   actual key/`SessionPublicKeyId` association, and registered profile.
4. It establishes the publisher/session-scoped epoch and assigns a protected
   sequence.
5. It records protected start.
6. Every required claim is newly collected or revalidated for the current live
   appraisal subject through its exact registered producer/provenance path.
7. It records protected end and atomically freezes the complete snapshot.
8. No claim or temporal value can change after freeze.
9. The attester constructs the exact M1-012 transcript and invokes profile
   coverage after freeze.
10. The publisher verifier authenticates and atomically claims the challenge,
    reconstructs the transcript, validates coverage and authority statement,
    and atomically establishes temporal high-water before later appraisal.

### Same-session renewal

Renewal creates new evidence. It uses a fresh complete challenge, current frozen
claims, and a new interval. Publisher, protected `SessionId`, live subject, and
key/handle lifecycle remain unchanged under ADR-0010. The epoch relation is the
same, the sequence is strictly greater than the greatest validated sequence,
`new.start >= prior.end`, collection duration satisfies effective policy, and
the proof reaches the verifier before challenge expiry.

Profile identity and exact selected-policy identity need not remain unchanged.
A profile transition must prove continuity with the same protected epoch and
cannot reset sequence or interval high-water. If it cannot, the session cannot
renew.

A local collection can be dropped or rejected before the publisher verifier
observes it. Contiguous accepted sequences would misclassify ordinary message
loss as rollback. Strict increase permits unobserved gaps while reuse, decrease,
epoch change, overlap, and protected-source discontinuity remain terminal.

## Validity and time domains

- Evidence is valid only for the exact complete challenge it covers.
- The challenge must authenticate and pass ADR-0005 freshness; evidence received
  at exact expiry or later fails.
- RFC 9334 nonce freshness supplies a rough external epoch. The protected local
  interval supplies snapshot duration and continuity, not global time.
- Collection start is not after freeze end, and elapsed duration satisfies the
  effective profile/publisher ceiling.
- Snapshot freeze occurs before proof creation. No independently unverifiable
  post-freeze latency field is introduced; challenge expiry bounds the remaining
  proof/transport/receipt path.
- No client clock is compared with publisher time, so wall-clock skew is
  inapplicable rather than configurable.
- UTC, challenge time, verifier time, result time, permit time, uptime, zero,
  maximum sentinel, and always-valid values are never normalized into evidence
  time.
- Boot-origin or cached source facts may predate collection only when the
  registered producer revalidates that they still identify the current live
  subject during collection.

## Verifier temporal state

The verifier retains the authority contract reference, scoped epoch relation,
greatest validated sequence, and latest validated freeze end only for the active
protected session. Temporal compare-and-advance is atomic.

After challenge authentication/freshness, profile resolution, exact transcript
reconstruction, coverage validation, and protected authority-statement
validation, the verifier checks epoch, strict sequence increase, interval order,
non-overlap, duration, and existing high-water. It advances high-water for every
valid protected temporal statement before later claim/provenance/policy
appraisal. Later rejection cannot erase that observation. Invalid or
unauthenticated coverage never advances candidate time.

## Rollback, restart, unavailability, and recovery

The protected session terminates if the collection authority or protected
source restarts, resets, rolls back, or becomes unsafe; if epoch changes; if
sequence is reused/decreased; if an interval overlaps or proves impossible; or
if authoritative high-water is missing, corrupt, rolled back, or contradictory.

Same-session repair is forbidden. Recovery creates a new protected session, new
actual key and handle, fresh challenge, and new scoped epoch relation.

A temporary authority/store outage is retryable only when the implementation
can prove authoritative continuity state remains intact and recoverable. It
cannot advance, release, or reconstruct state from client evidence. Any consumed
challenge remains consumed; retry uses a fresh challenge.

## Failure semantics

This issue adds no result variant, reason code, verifier state, accusation, or
disciplinary outcome.

| Condition | Existing mapping or required behavior |
| --- | --- |
| Structurally invalid candidate shape | `Malformed` |
| Unregistered profile, authority contract, or source kind | `Unsupported` |
| Challenge freshness or context failure | Existing challenge/context mapping |
| Authority statement or transcript coverage invalid | `EvidenceInvalid` |
| Duration exceeds policy with valid continuity | `EvidenceInvalid` |
| Temporary outage with intact recoverable continuity | `Retry` with `AttestationUnavailable` |
| Validated rollback, restart, epoch change, reuse/decrease, overlap, impossible interval, source discontinuity, or lost high-water | `ProtectedSessionLost` and terminal invalidation |
| Missing semantic contract or finite profile limit | Implementation blocked |

Every failure after ADR-0005 atomic nonce claim leaves that challenge consumed.
No temporal failure is evidence that a player cheated.

## Positive tests

- Initial collection receives one exact challenge, freezes a complete current
  snapshot within effective duration, arrives before expiry, and establishes
  high-water.
- Renewal uses a fresh challenge, same epoch, strictly greater sequence, non-
  overlapping interval, current snapshot, and advanced high-water.
- A valid sequence gap after an unobserved dropped collection remains eligible.
- A boot-origin claim passes only after current-boot revalidation during the
  interval.
- A temporary outage retries with a fresh challenge after unchanged
  authoritative state returns.

## Negative tests

- Collection opens before receiving the challenge later covered.
- Challenge A evidence is submitted for challenge B or another publisher,
  session, key/handle, profile authority, or renewal.
- A second collection is active concurrently for one protected session.
- Authority, epoch, sequence, start, or freeze end is omitted, duplicated,
  invented, aliased, or contradictory.
- UTC, challenge/verifier/result/permit time, uptime, zero, maximum, or always-
  valid values substitute for evidence time.
- Start is after end or duration exceeds effective policy.
- Proof arrives at exact challenge expiry or later.
- Sequence is reused or decreased; epoch changes; interval overlaps.
- Authority/protected source restarts, rolls back, becomes unsafe, or loses
  continuity.
- Verifier high-water is missing, corrupt, rolled back, unavailable, non-atomic,
  or repaired from client data.
- A stale cached claim is accepted solely because collection is recent.
- A later appraisal rejection erases a validated sequence.
- Invalid proof advances candidate temporal high-water.
- Profile transition resets sequence or epoch.
- Old session epoch is accepted after new-session recovery.
- Any diagnostic surface emits a temporal, challenge, key/handle, or proof
  value.
- Temporal state survives terminal session end without approved purpose.

## Fuzz/property tests

- Equal semantics compare equal only when every component and scope relation is
  equal; mutating any one component prevents equivalent coverage.
- Accepted sequences strictly increase but need not be contiguous.
- Accepted intervals never overlap within one session epoch.
- No accepted renewal crosses epoch or terminal session boundaries.
- High-water never decreases, resets, disappears, or rolls back while live.
- Later appraisal failure cannot undo a validated temporal observation.
- Invalid proof and temporary unavailability cannot create authority.
- No wall-clock skew parameter influences evidence-time acceptance.
- Every generated diagnostic is value-independent and redacted.

Later finite model work covers arbitrary histories of open, freeze, drop,
submit, validate, reject, renew, concurrent submit, outage, rollback, restart,
terminal end, and deletion. This documentation task adds no byte parser or fuzz
target; M2 owns bounded parser fuzzing after representation exists.

## Privacy impact

The authority contract, scoped epoch, sequence, interval, duration, temporal
high-water, protected-source statement, and proof are confidential. The exposed
epoch is opaque and scoped to one publisher/protected session. Raw boot IDs,
boot seeds, reset/restart counters, TPM clock, daemon uptime, host UTC, and
device-wide epochs are prohibited.

Verifier state is retained only for the active protected session and deleted at
terminal end after atomic in-flight resolution. Existing challenge replay
retention remains separately governed by ADR-0005. No backup, replication,
migration, telemetry, or secure-deletion implementation is selected.

Ordinary debug, display, error, log, trace, metric, crash, audit, support, and
test assertion output contains only coarse redaction and operational disposition,
never temporal or correlation values.

## Dependency impact

Documentation and existing JSON scenario fixtures only. No manifest, lockfile,
Rust, clock, storage, crypto, parser, network, unsafe-code, TPM, runtime TCB, or
license dependency changes.

## Acceptance criteria

- The canonical terms and authority split are consistent repository-wide.
- One complete frozen collection snapshot is the evidence-time subject.
- One immutable profile registers exactly one authority/source contract and
  finite ceiling.
- The exact five semantic components and all scope relations are explicit.
- Collection begins only after exact challenge receipt and freeze precedes proof.
- Evidence is single-challenge and received before challenge expiry.
- Profile ceiling is finite and publisher policy only tightens it.
- UTC/skew and every unrelated time domain remain excluded.
- Renewal requires fresh challenge, same epoch, strictly greater non-contiguous
  sequence, and non-overlap.
- Atomic high-water advances before later appraisal and never from invalid proof.
- Rollback/restart/epoch/reuse/overlap/discontinuity/lost state terminates the
  session; temporary intact-state outage alone is retryable.
- New-session recovery uses new key/handle/epoch.
- Cached claims require current-subject revalidation.
- Privacy, active-session retention, terminal deletion, and diagnostics are
  explicit.
- Failure mappings remain coarse, fail closed, and non-disciplinary.
- ADR and scenario coverage trace every threat and test family.
- Task 13, M2, and M3 ownership remains exact.
- No runtime API, representation, cryptography, TPM mapping, persistence
  implementation, dependency, or production limit enters scope.

## Primary sources

- [RFC 9334 Section 10](https://www.rfc-editor.org/rfc/rfc9334.html#section-10),
  including nonce freshness in Section 10.2 and claim-age responsibility in
  Section 10.4.
- [RFC 9711 Section 4.3.1](https://www.rfc-editor.org/rfc/rfc9711.html#section-4.3.1)
  for token creation versus older observations.
- [RFC 9711 Section 6.3.11](https://www.rfc-editor.org/rfc/rfc9711.html#section-6.3.11)
  and [Section 9.3](https://www.rfc-editor.org/rfc/rfc9711.html#section-9.3)
  for profile-defined mandatory freshness.
- ADR-0005 through ADR-0010.
- [Approved M1-012F design](../../docs/superpowers/specs/2026-09-01-m1-012f-evidence-time-authority-design.md).
- `docs/SECURITY_INVARIANTS.md`, `docs/THREAT_MODEL.md`,
  `docs/ARCHITECTURE.md`, `docs/PROTOCOL.md`, `docs/PRIVACY_MODEL.md`,
  `docs/TEST_STRATEGY.md`, `docs/ROADMAP.md`, and
  `docs/AI_DEVELOPMENT_POLICY.md`.
