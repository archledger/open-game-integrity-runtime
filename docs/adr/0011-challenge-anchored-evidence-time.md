# ADR-0011: Use challenge-anchored protected collection intervals for evidence time

- Status: Accepted
- Date: 2026-09-01
- Owners: Initial maintainer
- Related issues: [M1-012F](../../planning/issues/012f-evidence-time-authority.md)
- Supersedes: None
- Superseded by: None

## Context

ADR-0010 requires one evidence-time semantic in every Evidence-binding
transcript and deliberately blocked runtime representation until a separately
approved contract defined its producer, clock or epoch, validity, skew,
rollback, restart, renewal, and privacy behavior.

Challenge issuance, publisher-verifier evaluation, evidence collection,
protected-result validity, permit validity, and renewal authorization are
different events controlled by different authorities. Copying challenge or
verifier time into evidence would not establish when local claims were
collected. Trusting client UTC would add synchronization, skew, future-time, and
rollback assumptions that OGIR cannot currently justify.

The transcript combines claims from hardware-certified, measured-log-derived,
and trusted-agent-observed producers. Some underlying events, such as boot
measurements, occur before an appraisal attempt. Evidence time therefore needs
to identify when one complete current snapshot was assembled and frozen while
preserving separate current-state/provenance validation for older source facts.

Same-session renewal also needs local temporal continuity. The design must
distinguish ordinary dropped collections from sequence rollback, reject
concurrent/overlapping collections, define authority restart behavior, and avoid
exposing raw boot, TPM clock, reset, or device-wide identifiers.

## Decision drivers

- Only the publisher verifier may accept evidence or authorize protected mode.
- The local game, bridge, generic attester, and client clock are untrusted.
- Evidence must be fresh for one exact unpredictable challenge without trusting
  synchronized client UTC.
- One complete claim snapshot needs an explicit start-to-freeze boundary.
- Snapshot freeze must precede proof creation to avoid self-reference.
- Same-session renewal needs rollback/restart/concurrency behavior that fails
  closed without treating ordinary message loss as rollback.
- Temporal values must not become stable cross-publisher/session identifiers.
- The decision must remain semantic and defer representation, cryptography,
  persistence implementation, numeric production limits, and TPM mapping.
- Failure must remain coarse, non-disciplinary, and compatible with M1-011.

## Options considered

### Challenge-anchored protected collection interval

Selected. An immutable profile registers one trusted local collection authority
and protected monotonic semantics. A publisher nonce supplies the rough external
epoch described by RFC 9334, while the local interval identifies snapshot
duration and same-session continuity without pretending to be global time.

### Trusted synchronized UTC plus monotonic continuity

Rejected. It could quantify absolute age directly but adds clock trust,
synchronization endorsements, skew policy, future-time ambiguity, wall-clock
rollback, and a larger local TCB. RFC 9334 explicitly recognizes deployments
without trustworthy synchronized attester clocks.

### Nonce-only rough epoch

Rejected as incomplete. It proves covered evidence follows nonce generation but
cannot express collection duration, snapshot freeze, local rollback, serialized
renewal, or same-session temporal continuity.

### Per-claim timestamps

Rejected. They expand the closed M1-012 vocabulary and privacy surface, multiply
clock authorities, and do not define one coherent complete-snapshot boundary.
Claim-specific event age needs separate profile vocabulary review.

### Unconstrained profile-specific temporal union

Rejected. Allowing arbitrary instant, interval, sequence, UTC, or epoch shapes
would fragment verifier behavior and make unknown-critical handling ambiguous.
Profiles may vary protected mechanism and limits while preserving one common
semantic contract.

### Evidence mechanism proof-completion time

Rejected. If proof completion determines the value covered by that proof, the
definition is self-referential. The complete snapshot freezes first; the
challenge window bounds proof creation, transport, and receipt afterward.

### Verifier-assigned evidence time

Rejected. Receipt/evaluation time is publisher authority but cannot establish
when local claims were collected. It would collapse the time-domain separation
required by ADR-0010.

### Contiguous accepted collection sequences

Rejected. A local collection receives a sequence before the remote verifier can
observe it. Network loss, malformed transport, challenge rejection, or invalid
proof can leave an unobserved gap. Requiring arithmetic succession would turn
ordinary loss into false session termination. Strict increase plus protected
epoch/source continuity and non-overlap rejects reuse without requiring every
failed collection to reach the verifier.

### Resume the same protected session after authority restart

Rejected. Safe continuation requires durable local epoch transitions, anti-
rollback, key lifetime, migration, recovery, and verifier-state design. Existing
local session capabilities are process-local. Recovery therefore creates a new
session, key/handle, challenge, and scoped epoch.

### Retain raw boot or TPM epoch values

Rejected. Raw device-wide values create cross-publisher/session correlation and
prematurely select TPM-specific representation before M3 review.

## Decision

Each immutable `EvidenceProfile` registers exactly one trusted local **Evidence
Collection Authority** contract. The contract defines the local component,
protected monotonic source semantics, publisher/session-scoped epoch relation,
sequence and interval protection, atomic complete-snapshot freeze, finite hard
collection-duration ceiling, restart/rollback/unavailability behavior, and
publisher-verifier validation path.

The Evidence Collection Authority is authoritative only for one protected local
collection interval. Registered claim producers retain authority for claim
truth within their provenance classes. The generic attester requests collection,
constructs the candidate transcript, invokes proof, and transports the external
carrier without authority to choose or rewrite temporal values. The publisher
verifier authenticates challenge/policy, validates the protected temporal
statement, maintains high-water, appraises claims, and remains the sole
acceptance authority.

One evidence-time semantic contains exactly:

1. the immutable registered collection-authority contract identity;
2. one opaque publisher/session-scoped protected epoch relation;
3. one protected collection sequence;
4. one protected collection start; and
5. one protected snapshot-freeze end.

This is semantic shape, not a wire or Rust type. Later representation may avoid
literal duplication of scope already carried by the profile, challenge,
session, key, or handle, but it must preserve exact equality and domain
separation.

For initial appraisal, the attester receives the complete challenge before the
authority opens collection. The authority rejects a second active operation,
establishes publisher/session scope and epoch, assigns a sequence, records
start, obtains or revalidates every required current claim through its registered
producer/provenance path, and atomically freezes the complete snapshot at end.
No value changes after freeze. The attester then constructs the exact transcript
and invokes profile coverage.

The local authority need not authenticate publisher trust roots. It covers the
exact challenge it receives, and the publisher verifier later authenticates and
claims that challenge through ADR-0005. A fake local request can consume bounded
work but cannot authorize protected mode.

Evidence is valid only for that exact challenge and must reach the verifier
before its existing half-open expiry boundary. It cannot be cached or reused
for another challenge, publisher, session, key/handle, profile authority, or
renewal.

The profile's collection-duration ceiling is finite. Publisher policy may apply
an equal or stricter limit but cannot loosen the profile. This ADR selects no
numeric duration or unit. There is no independent post-freeze latency claim;
challenge expiry bounds proof, transport, and receipt after freeze.

Client UTC is absent. No local time is compared with publisher time, so wall-
clock skew is inapplicable rather than configurable. Challenge issuance,
verifier evaluation, result/permit time, process uptime, zero, maximum sentinel,
and always-valid values cannot substitute or be normalized into evidence time.

Initial appraisal establishes verifier **Temporal high-water** for the active
session: authority contract, scoped epoch relation, greatest validated sequence,
and latest validated freeze end. Same-session renewal is serialized and requires
a fresh challenge, unchanged publisher/protected-session/live-subject/key
lifecycle, same uninterrupted epoch, a strictly increasing sequence, and
`new.start >= prior.end`. Accepted sequences may have gaps for collections the
verifier never observed. Profile or selected-policy identity may change only if
the new profile contract proves the same epoch continuity and preserves sequence
and end high-water.

After challenge freshness, profile resolution, independent transcript
reconstruction, coverage validation, and protected authority-statement
validation, the verifier atomically checks epoch, strict sequence increase,
interval order, non-overlap, duration, and current high-water. It advances high-
water before later claim/provenance/policy appraisal. Later rejection cannot
erase the valid observation. Invalid or unauthenticated proof cannot advance
candidate time. Local collection serialization does not replace atomic verifier
compare-and-advance.

Authority or protected-source restart, reset, rollback, unsafe state, epoch
change, reused/decreased sequence, overlap, impossible interval, protected-
source discontinuity, or missing/corrupt/rolled-back/contradictory verifier
high-water terminates the current protected session. Same-session repair is not
permitted. Recovery requires a new session, actual key and handle, challenge,
scoped epoch, and initial appraisal.

A temporary authority/store outage maps to retry/unavailable only when the
implementation can prove the same authoritative continuity state remains intact
and recoverable. It cannot advance, release, or reconstruct high-water from
client evidence. A consumed challenge remains consumed and retry uses a fresh
challenge. No stateless fallback exists.

Boot-origin or cached facts can predate collection only when the registered
producer revalidates during the interval that they still identify the current
live subject. Recent collection never promotes stale data or grants provenance.

This ADR selects no bytes, field names, integer widths, clock units, numeric
limits, parser, serialization, synchronized UTC, TPM structures/commands,
cryptographic mechanisms, proof format, literal labels, persistence adapter,
networking, telemetry, protected-result/permit validity, renewal authorization,
revocation, proof of possession, admission, or dependency.

## Consequences

The design gives task 13 one stable temporal semantic for abstract fixtures and
gives M2 explicit representation/validation obligations. It makes stale-
snapshot, cross-challenge, sequence/epoch, restart, concurrency, duration,
unavailability, and privacy attacks independently testable without coupling M1
to UTC or TPM details.

The costs are a new trusted local authority contract, profile-specific protected
source/limit work, active-session verifier high-water, atomic local/verifier
ordering, terminal sessions after continuity loss, and later persistence/
recovery design. Sequence gaps require protected source validation rather than
simple arithmetic succession.

Task 13 may now define abstract semantic fixtures. Runtime implementation still
requires an approved profile mechanism/limit plus M2 representation,
cryptography, parser, and storage design. M3 remains responsible for TPM
mapping.

## Threat-model impact

Affected assets are evidence appraisal integrity, verifier temporal state,
protected-session authorization, session key binding, and player privacy.
Affected trust boundaries are publisher challenge to local collection request;
registered producers to collection authority; collection authority to attester
and evidence mechanism; attester/carrier to publisher verifier; profile registry
and publisher policy to verifier; and verifier temporal storage.

This decision narrows A0/A1 replay/substitution, A4 trusted-component/source
confusion, A5 faulty/compromised verifier or state, A6 profile drift, and A8
privacy/correlation risk. Failures remain coarse and non-disciplinary.

Residual risks remain: a compromised registered producer or collection
authority can emit dishonest but structurally valid evidence; a compromised
verifier remains in the TCB; full-session relay and post-appraisal state change
remain; challenge expiry does not separately measure post-freeze latency; exact
mechanisms, limits, persistence, backups, and deletion enforcement remain later
decisions.

## Privacy impact

The authority contract, scoped epoch relation, sequence, start, end, duration,
temporal high-water, protected-source statement, and proof are confidential.
The exposed epoch relation is opaque and scoped to one publisher/protected
session. Raw boot IDs, boot seeds, reset/restart counters, TPM clocks, daemon
uptime, host UTC, and device-wide epochs are prohibited.

Verifier high-water exists only for the active protected session and is deleted
at terminal end after atomic in-flight resolution. Existing challenge replay
retention is separate. Local state is limited to one active collection and the
minimum continuity state. No backup, replication, recovery, migration,
telemetry, or secure-deletion implementation is authorized here.

Ordinary diagnostics reveal only coarse redacted class and operational
disposition, never temporal, challenge/context, key/handle, carrier, proof, or
raw protected-source values. Explicit trusted functional access is not an
approved diagnostic sink.

## Dependency and license impact

This is a documentation-only semantic decision. It adds no dependency,
manifest, lockfile, runtime TCB implementation, unsafe code, clock service,
storage adapter, TPM library, cryptographic primitive, or license boundary.
Future implementation dependencies require separate purpose, maintenance,
security, and license review.

## Validation

Repository documentation and abstract fixtures must cover:

- valid initial collection and same-session renewal;
- valid strictly increasing sequence gaps after unobserved collections;
- current-state revalidation of boot-origin/cached facts;
- challenge/time-domain/cross-context substitution;
- missing/duplicate/aliased temporal components;
- start/end order and effective duration limits;
- exact challenge expiry;
- reused/decreased sequence, epoch change, overlap, restart, rollback, and
  source discontinuity;
- concurrent local collection and atomic verifier high-water races;
- temporary intact-state unavailability versus missing/corrupt/rolled-back
  state;
- high-water advancement before later appraisal and no advancement from invalid
  proof;
- profile transitions and terminal new-session recovery; and
- diagnostics, retention, deletion, and correlation boundaries.

Finite model work must cover arbitrary collection/open/freeze/drop/submit/
validate/reject/renew/outage/rollback/restart/end/delete histories. M2 parser
work adds bounded fuzzing only after representation exists. The ADR/index gate,
scenario gate, full repository check, primary-source review, and exact human
approval are required.

## Rollback

Changing this accepted contract requires a superseding ADR, explicit versioning,
profile/compatibility analysis, threat/privacy review, and new deterministic
fixtures. Accepted history is retained.

Disabling protected mode is a safe operational fallback. Removing epoch,
sequence, interval, challenge binding, active-session high-water, or terminal
continuity loss; substituting UTC/challenge/verifier time; accepting stateless
fallback; or resuming the same session after restart is not an acceptable
rollback.

## Primary sources

- [RFC 9334 Section 10](https://www.rfc-editor.org/rfc/rfc9334.html#section-10)
  defines synchronized-clock, nonce, and epoch freshness approaches.
- [RFC 9334 Section 10.2](https://www.rfc-editor.org/rfc/rfc9334.html#section-10.2)
  defines verifier nonce freshness as rough epoch without trusted client UTC.
- [RFC 9334 Section 10.4](https://www.rfc-editor.org/rfc/rfc9334.html#section-10.4)
  assigns responsibility for older claim values remaining fresh.
- [RFC 9711 Section 4.3.1](https://www.rfc-editor.org/rfc/rfc9711.html#section-4.3.1)
  distinguishes token creation from older claim observations.
- [RFC 9711 Section 6.3.11](https://www.rfc-editor.org/rfc/rfc9711.html#section-6.3.11)
  and [Section 9.3](https://www.rfc-editor.org/rfc/rfc9711.html#section-9.3)
  require profile-defined freshness.
- [ADR-0005](0005-verifier-authoritative-challenge-freshness.md) defines
  publisher challenge time and durable nonce freshness.
- [ADR-0006](0006-local-session-lifecycle-capabilities.md) defines process-local
  session lifetime and terminal cleanup.
- [ADR-0007](0007-verifier-flow-capabilities.md) defines ordered verifier
  authority and restart limitations.
- [ADR-0008](0008-session-public-key-id-is-not-authority.md) defines key/handle
  lifetime and non-authority.
- [ADR-0009](0009-capability-gated-appraisal-results.md) separates unsigned
  appraisal semantics from protected results.
- [ADR-0010](0010-semantic-evidence-binding-transcript.md) defines the transcript
  and evidence-time prerequisite.
- [M1-012F](../../planning/issues/012f-evidence-time-authority.md), the
  [approved design](../superpowers/specs/2026-09-01-m1-012f-evidence-time-authority-design.md),
  security invariants, architecture, protocol, roadmap, trust model, privacy
  model, threat model, test strategy, and AI development policy are project
  authorities.
