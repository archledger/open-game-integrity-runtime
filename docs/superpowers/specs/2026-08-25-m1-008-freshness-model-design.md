# M1-008 challenge freshness and replay design

- Status: Approved for implementation
- Date: 2026-08-25
- Related issue: [M1-008](../../../planning/issues/008-freshness-model.md)
- Decision owner: Initial maintainer

## Summary

OGIR protected-mode challenges use a publisher-controlled, verifier-authoritative
clock, a strict half-open validity interval, and a fresh 32-byte random nonce.
The publisher namespace and nonce form a globally single-use replay key within
that publisher. Issued and consumed replay records plus a verifier-time
high-water mark are durable state. Missing, corrupt, unavailable, rolled-back,
or capacity-exhausted freshness state fails closed and never falls back to
stateless validation.

The pure model defines typed time, window, and limit invariants. The verifier
owns one deep freshness boundary that performs the atomic replay transition and
returns an unforgeable proof that freshness checks completed. No client clock,
database product, wire format, async runtime, TPM clock, or permit-renewal
behavior is selected here.

## Context

The scaffold currently carries `issued_at_unix_seconds` and
`expires_at_unix_seconds` as independent integers and compares them directly in
the verifier. A unique nonce alone proves neither that evidence is recent nor
that a previously accepted challenge cannot be replayed. Wall clocks can move
backward, process restarts can erase volatile replay state, and a check followed
by a separate state update admits concurrent double use.

Freshness is an authorization prerequisite, not evidence that a player cheated.
Every failure in this design either rejects malformed/stale/replayed input or
reports an operationally unavailable protected mode.

## Goals

- Define the authoritative issuer and evaluator for challenge time.
- Make exact validity boundaries and zero skew unambiguous.
- Prevent the same publisher nonce from authorizing twice in any context.
- Define crash-safe registration, atomic claim, restart, rollback, and garbage
  collection semantics independently of a database.
- Bound state exhaustion without evicting live security records.
- Make skipped freshness gates unrepresentable at the verifier boundary.
- Provide deterministic tests for boundaries, replay, failure, and arbitrary
  operation sequences.

## Non-goals

- Selecting a production database, consensus system, or clock service.
- Defining CBOR, JSON, COSE, JOSE, or another wire encoding.
- Using the TPM clock, TPM counters, or a hardware monotonic counter.
- Implementing permit renewal, permit signing, or production authorization.
- Choosing numeric production lifetimes, quotas, or rate limits.
- Defining `SessionPublicKeyId`, `RevocationTarget`, or the M1 verifier state
  machine beyond its freshness input.

## Primary-source basis

- [RFC 9334 Section 10](https://www.rfc-editor.org/rfc/rfc9334.html#section-10)
  identifies freshness provisioning as an early architectural decision.
- [RFC 9334 Section 10.2](https://www.rfc-editor.org/rfc/rfc9334.html#section-10.2)
  places nonce-based timekeeping on the verifier or relying party and requires
  per-nonce state.
- [RFC 9711 Section 9.3](https://www.rfc-editor.org/rfc/rfc9711.html#section-9.3)
  requires every EAT use to provide a replay-resistant freshness mechanism.
- [RFC 9711 Section 6.4](https://www.rfc-editor.org/rfc/rfc9711.html#section-6.4)
  requires a new single unique nonce for every token request in its constrained
  profile.
- [RFC 9711 Section 4.1](https://www.rfc-editor.org/rfc/rfc9711.html#section-4.1)
  requires at least 64 bits of nonce entropy and bounds encoded nonce size.
  OGIR's existing 32-byte nonce exceeds that entropy floor without inventing a
  new primitive.
- [RFC 7519 Sections 4.1.4–4.1.6](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4)
  define expiration, not-before, and issued-at boundaries. Its clock leeway is
  optional; OGIR deliberately selects zero acceptance leeway.
- Rust documents [`SystemTime`](https://doc.rust-lang.org/std/time/struct.SystemTime.html)
  as non-monotonic, so a persisted high-water guard is required if wall time is
  used across authorization operations and restarts.

## Trust and authority

### Challenge issuer

The publisher-controlled challenge issuer is authoritative for:

- generating a fresh nonce with an operating-system or reviewed cryptographic
  random-number generator;
- selecting `issued_at` and `expires_at` under local freshness policy;
- durably registering the challenge before signing or returning it; and
- authenticating the challenge with a publisher key.

The issuer never accepts a nonce or authoritative timestamp from the game,
Wine/Proton bridge, local agent, or other client-controlled component.

### Verifier

The publisher-controlled verifier is authoritative for the current time used
to evaluate a challenge. It authenticates the challenge, compares every typed
context field with independently supplied relying-party context, and performs
the atomic replay claim. Client-reported time is ignored.

### Attester and client

The attester copies the challenge nonce into evidence so it is covered by the
future evidence authenticity mechanism. Neither the attester nor the game can
extend, reinterpret, or consume a challenge authoritatively.

## Time model

### Types

The pure `ogir-model` crate owns the following conceptual types:

- `UnixTime(u64)`: whole seconds since the Unix epoch;
- `ChallengeLifetime(NonZeroU64)`: the maximum permitted window duration for
  the active local policy;
- `ChallengeWindow`: private `issued_at` and `expires_at` values constructed
  only after validation; and
- `FreshnessLimits`: explicit nonzero lifetime and state-exhaustion limits with
  no `Default` implementation.

### Construction

`ChallengeWindow` construction must:

1. reject `expires_at <= issued_at`;
2. compute duration with checked subtraction;
3. reject a duration greater than the explicit `ChallengeLifetime`; and
4. retain the two original integer values without normalization or leeway.

There is no global hard-coded challenge lifetime. Every caller supplies a
reviewed, finite, nonzero policy limit. A challenge close to `u64::MAX` may be
structurally ordered but cannot be accepted at a realistic verifier time; an
expiry chosen to create an excessive duration is rejected during construction.

### Evaluation

A challenge is valid only when:

```text
issued_at <= verifier_now < expires_at
```

Consequently:

- before issuance: `NotYetValid`;
- exact issuance: eligible for subsequent replay/context checks;
- the final representable second before expiry: eligible;
- exact expiry and every later time: `Expired`.

Acceptance leeway is exactly zero. Clock disagreement is an availability fault,
not permission to widen the signed window.

## Nonce and replay identity

The challenge nonce remains exactly 32 bytes. Generation occurs at the
publisher issuer using an approved CSPRNG; the model does not implement random
number generation.

Replay identity is:

```text
ReplayKey = (PublisherId, Nonce)
```

Game, build, account, match, policy, and policy-version values are stored as the
record's binding, never as replay-key components. Under one authenticated
publisher, a nonce is globally single-use across every context. Reusing it with
the same or a different binding is `ReplayDetected`. The same random bytes in a
different authenticated publisher namespace are independent.

The binding stored with the replay record contains:

- `GameId`;
- `BuildId`;
- `AccountScope`;
- `MatchId`;
- `PolicyId`; and
- `PolicyVersion`.

No replay-cache log or public error includes the nonce or account-scoped
binding.

## Replay lifecycle and transaction boundaries

### Issuance

The logical issuance transaction is:

1. observe the publisher-authoritative time source shared by issuer and
   verifier, and reject rollback;
2. construct and policy-check the challenge window;
3. generate the nonce;
4. atomically enforce uniqueness, lifetime, capacity, and issuance-rate limits;
5. durably insert an `Issued` replay record and advance the time high-water
   mark; and
6. only after the transaction commits, sign and return the challenge.

Signing failure after registration may leave an unreachable issued record. It
is harmless and expires normally. Returning a challenge whose registration did
not commit is forbidden.

### Verification and claim

Verification order is:

1. bounded parse and structural checks;
2. publisher authentication of the challenge;
3. durably check/advance the authoritative-time high-water mark, then apply
   strict window evaluation;
4. exact comparison with relying-party publisher/game/build/account/match/
   policy context;
5. one atomic replay-store operation that rechecks the time floor, record
   binding, window, and state, then changes `Issued` to `Consumed`; and
6. expensive evidence, platform, and policy appraisal.

The claim is irreversible. Denial, unavailable evidence, verifier crash, or any
later transient error leaves the nonce consumed. The caller obtains a new
challenge to retry. This permits a holder to burn its own challenge, but it
prevents ambiguous replay after a crash or unknown downstream result.

Only the ordered verifier transition constructs a `FreshnessChecked`
capability with private fields after context comparison and atomic claim. The
public raw claim operation consumes state but returns no capability, so a
downstream caller cannot bypass verifier ordering. Later verifier-state work
may advance toward an allow result only while holding this capability; the
current research scaffold still performs no publisher authentication and never
returns `Allow`.

## Persistent state, restart, and rollback

Replay records and the authoritative-time high-water mark are security state
and must survive process restart. A protected-mode process cannot issue or
verify challenges until the store is opened and its integrity is validated.

Every authoritative issuance or verification observation, claim, and
garbage-collection transaction observes a current authoritative `UnixTime`.
The time-floor check/advance commits before later window rejection, so an
expired or not-yet-valid request cannot hide a forward observation:

- `now >= persisted_high_water`: operation may proceed and the high-water mark
  advances to `now` if needed;
- `now < persisted_high_water`: `ClockRollback`, fail closed; and
- unavailable, missing, or corrupt high-water/replay state:
  `StateUnavailable`, fail closed.

There is no automatic empty-cache recovery. Recovery requires one of:

1. restoring known-good durable state; or
2. an operator-controlled issuer/signing-key epoch rotation that invalidates
   every outstanding challenge before new state is initialized.

The operational runbook and production key-rotation mechanism are future
reviewed work. Restart never silently chooses the second option.

## Retention and garbage collection

Both `Issued` and `Consumed` records remain through their challenge expiry.
Garbage collection may delete a record only when the persisted time high-water
mark is greater than or equal to that record's `expires_at`. If time state is
unavailable or rolled back, garbage collection stops.

Issuance-rate events remain only while they can affect enforcement. Each event
records its finite configured rate-window duration and is deleted when the
persisted high-water mark reaches the end of that window. Reference
snapshot/reopen handles refer to one authoritative durable state generation,
not detached copies, so garbage collection is visible through every handle.
Production backup copies require a separately approved finite retention,
deletion, access-control, and anti-rollback lifecycle.

Unexpired records are never evicted to make space. Audit retention after expiry
requires a separately approved purpose, access policy, and finite retention
period; it is outside the minimum replay-safety contract.

## Denial-of-service bounds

`FreshnessLimits` and the deployment boundary require finite, nonzero values
for:

- maximum challenge lifetime;
- maximum total outstanding challenges;
- maximum outstanding challenges per publisher;
- maximum outstanding challenges per `(PublisherId, AccountScope)`;
- issuance-rate window duration; and
- maximum challenge issuances per publisher within that window.

The model provides no permissive defaults. Exceeding any outstanding or rate
limit returns `CapacityExceeded` and refuses issuance. It never evicts an
unexpired record, reuses a nonce, widens a validity window, or switches to
stateless verification.

Exact production values and distributed enforcement topology require workload
evidence and a separate deployment review. Tests use explicit small fixture
limits.

## Privacy and state minimization

Replay records contain account- and match-scoped binding data. They are
privacy-sensitive authorization state, not telemetry. A production adapter
must apply least-privilege access, protection at rest appropriate to publisher
policy, and expiry/rate-window-driven deletion. Logs, metrics, and replay-state
`Debug` implementations use aggregate counts, explicit redaction markers, or
an internal opaque record reference; they never include nonce bytes,
publisher/game/build/account/match/policy bindings, policy versions, or window
timestamps. Default `Debug` is redacted on those identifier/time leaves and on
challenge, expected-context, verification-request, replay-state, guard, store,
and durable-handle aggregates. Explicit value accessors remain necessary for
trusted verification/storage behavior and are not diagnostic interfaces.

The store retains only the fields required for replay identity, exact binding,
window evaluation, state, and recovery. Adding player profile, device identity,
or unrelated session data requires a separate privacy review.

## Module boundaries

### `ogir-model`

Owns pure, dependency-free types and invariants:

- time/window/lifetime/limit newtypes;
- checked window construction and strict evaluation;
- replay key and typed binding values if they are shared across verifier
  interfaces; and
- structural `FreshnessError` variants that require no I/O knowledge.

It does not read a clock, persist state, perform random generation, or call an
async runtime.

### `ogir-verifier::freshness`

Owns one deep freshness boundary:

- issuance registration semantics;
- time-floor observation;
- atomic replay claim semantics;
- mapping storage failures to typed operational errors; and
- the private-constructor `FreshnessChecked` capability.

The M1 implementation defines a synchronous, database-neutral `ReplayStore`
contract consistent with the current deterministic verifier. It exposes
atomic time-floor observation, register, claim, and expiry-GC operations. It
must not expose separate
`contains` and `mark_consumed` operations, select a database, or add a database
dependency. A future async service may adapt this boundary without moving
freshness rules into transport code.

### Application/storage adapter

Owns the real authoritative clock, durable transaction mechanism, rate limiter,
state-integrity checks, and operator recovery. It must implement the specified
atomic behavior; a read-then-write replay check is nonconforming.

## Error taxonomy and external mapping

Internal freshness errors are:

- `InvalidWindow`;
- `LifetimeExceeded`;
- `NotYetValid`;
- `Expired`;
- `ReplayDetected`;
- `ClockRollback`;
- `StateUnavailable`; and
- `CapacityExceeded`.

They do not contain raw nonce, account, match, or context values in `Debug` or
`Display` output.

External mapping remains non-disciplinary:

| Internal error | Existing external class |
| --- | --- |
| `InvalidWindow`, `LifetimeExceeded` | `Malformed` |
| `NotYetValid` | `NotYetValid` |
| `Expired` | `Expired` |
| `ReplayDetected` | `ReplayDetected` |
| `ClockRollback`, `StateUnavailable`, `CapacityExceeded` | retry/unavailable protected mode |

No error is evidence of cheating and no error directly triggers a player ban.
M1-010 owns the final verifier outcome/state-machine representation.

## Test design

### Window boundaries

- before issuance;
- exact issuance;
- one second before expiry;
- exact expiry;
- after expiry;
- equal/reversed endpoints;
- lifetime exactly at and one second over the configured maximum;
- an extreme-future window evaluated against the current verifier time;
- values near `u64::MAX`; and
- arithmetic mutations that would wrap or saturate.

### Clock authority and rollback

- client time is absent from the freshness API;
- equal/high verifier time advances or retains the high-water mark;
- a rejected future-time window still persists its observation, including
  across snapshot/reopen, and a later lower time fails rollback;
- a later in-window context mismatch persists its observation before rejection,
  including across reopen, without consuming the original issued record;
- any lower verifier time fails `ClockRollback`;
- a forward jump may create an operational outage but never restores expired
  validity; and
- unavailable/corrupt time state fails closed.

### Replay and binding

- first claim succeeds exactly once;
- repeat claim in the same context is replay;
- repeat nonce under the same publisher with any changed game/build/account/
  match/policy binding is replay;
- rejecting an altered same-key binding/window does not consume the original
  issued record;
- the same nonce bytes under a different authenticated publisher are
  independent;
- missing registration fails closed; and
- identifier/time leaves and challenge/expected-context/request/replay-key/
  binding/registration/guard/store/snapshot debug plus errors reveal no raw
  binding, nonce, policy-version, or window-timestamp context.

### Atomicity, restart, and failure

- two simultaneous claims produce exactly one `FreshnessChecked` capability;
- the public raw claim API cannot return or construct `FreshnessChecked`;
- crash after claim leaves the replay record consumed;
- snapshot/reopen preserves issued and consumed records plus the time floor,
  while a handle reopened before garbage collection observes that later
  authoritative deletion;
- restart with unavailable, missing, or corrupt state cannot issue or verify;
- explicit epoch/key recovery invalidates old challenges before reset; and
- no error path releases a consumed nonce.

### Capacity and garbage collection

- every configured boundary is accepted at its exact limit and rejected one
  over;
- full state refuses issuance without evicting live records;
- records persist immediately before expiry;
- records become GC-eligible at exact expiry only when the time floor reaches
  expiry;
- issuance events become GC-eligible at the exact end of their configured rate
  window through every durable-state handle; and
- rollback/unavailable time blocks GC.

### Property and mutation tests

Deterministic arbitrary sequences of issue, claim, time-advance, rollback,
restart, unavailable, and GC actions must preserve:

- at most one freshness capability per replay key;
- no capability before issuance or at/after expiry;
- monotonic persisted time;
- no authorization from unavailable state; and
- no loss of an unexpired replay record.

Mutations that widen either time boundary, split check from consume, scope the
replay key by game/match, clear state on restart, release a consumed nonce,
evict an unexpired record, skip time-before-window/context observation, retain
expired rate history, detach state during reopen, or expose any binding/time
leaf or challenge/request/replay aggregate through default debug must make at
least one test fail.

Every machine-readable freshness attack scenario must also satisfy the shared
scenario schema's required accountable `owner` and
`required_assurance_profile`. These freshness controls use
`all-protected-modes` because replay, state integrity, and diagnostic privacy
apply independently of the attestation backend or hardware assurance class.

## Alternatives considered

### Timestamp-only stateless validation

Rejected. It reduces state and round trips but trusts synchronized timestamp
claims and cannot detect replay within the accepted window.

### Signed nonce challenge without replay state

Rejected. Authenticity prevents modification, not reuse. A signed challenge can
still be replayed until expiry.

### Context-scoped replay key

Rejected. Including game, match, account, or policy in the key would allow the
same publisher nonce to authorize a second context and violate global
single-use semantics.

### Permissive clock-skew leeway

Rejected. It would accept before the signed issuance boundary or after the
signed expiry boundary, contradicting OGIR's invariant. Clock disagreement is
handled as availability failure.

### Volatile cache with restart reset

Rejected. A restart would make previously issued challenges appear unused and
clock rollback could extend acceptance.

### Epoch-ID freshness

Deferred. RFC 9334 describes state-efficient epoch identifiers, but they do not
provide per-challenge single use and require a trusted epoch distributor plus
transition-window semantics that M1 does not need.

## Migration and sequencing

1. The M1-007 typed identifier model is a prerequisite. M1-008 implementation
   begins only from a verified `main` descendant containing that model.
2. The implementation replaces the two raw challenge timestamp fields with a
   typed `ChallengeWindow` and updates verifier call sites/tests.
3. A new ADR, expected to be ADR-0005, records the nonce-first,
   verifier-authoritative, durable replay decision and alternatives.
4. Production storage/time adapters, numeric limits, and operational recovery
   remain separately reviewed follow-ups.

## Acceptance-criteria traceability

| Issue requirement | Design provision |
| --- | --- |
| Issuer/evaluator authority | Publisher challenge issuer and publisher verifier roles are explicit; client time is absent. |
| Inclusive/exclusive boundaries and skew | Strict `[issued_at, expires_at)` with zero leeway. |
| Replay-cache key | `(PublisherId, Nonce)` globally single-use within publisher scope. |
| Persistence/restart | Durable records/time floor; no empty fallback; explicit recovery only. |
| Denial-of-service bounds | Explicit nonzero lifetime, capacity, account, and rate limits; fail closed at capacity. |
| Database-independent semantics | Logical atomic operations and module contracts do not select a datastore. |
| Boundary tests | Exact issue/expiry, invalid/extreme/overflow cases enumerated. |
| Duplicate nonce tests | Same/different context and publisher behavior specified. |
| Cache failure tests | Unavailable/corrupt/restart states fail closed. |
| No client-authoritative time | Only publisher-controlled authoritative time enters evaluation. |

## Residual risks and follow-up obligations

- Zero skew can reduce availability during clock disagreement; monitoring and
  time-source operations are required before production.
- Durable replay state becomes authorization-critical infrastructure and needs
  its own threat model, backup, integrity, and availability review.
- A valid challenge holder can burn its own nonce by initiating verification
  that later fails; bounded reissuance is the recovery path.
- Advancing the time floor far into the future can cause a fail-closed outage;
  explicit operator recovery must never re-enable old challenge keys.
- This design narrows replay and time risk but does not implement evidence
  authenticity, policy appraisal, permits, renewal, or revocation.
