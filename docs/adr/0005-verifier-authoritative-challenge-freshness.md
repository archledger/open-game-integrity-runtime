# ADR-0005: Verifier-authoritative nonce freshness with durable replay state

- Status: Accepted
- Date: 2026-08-25
- Owners: Initial maintainer
- Related issues: [M1-008](../../planning/issues/008-freshness-model.md)
- Supersedes: None
- Superseded by: None

## Context

Independent challenge timestamps and a unique nonce do not by themselves
prevent replay. A challenge can be reused inside its accepted window, two
concurrent verifications can both observe unused state, a restart can erase a
volatile cache, and a wall-clock rollback can extend apparent validity.

Freshness is an authorization prerequisite rather than evidence that a player
cheated. The design therefore needs exact authority, transaction, persistence,
capacity, privacy, and error semantics without selecting a database or wire
format.

## Decision drivers

- Fail closed without trusting client time or client-maintained nonce state.
- Make one publisher nonce single-use across every game/account/match/policy
  context.
- Survive concurrent claims, verifier restart, and clock rollback.
- Bound state and issuance pressure without evicting a live security record.
- Retain only the privacy-sensitive context needed for exact claim validation.
- Keep the pure model and verifier contract deterministic and database-neutral.
- Make each security boundary falsifiable through literal and adversarial tests.

## Options considered

### Timestamp-only stateless validation

Rejected. It avoids replay state but permits reuse throughout the accepted
window and depends on timestamp trust alone.

### Signed nonce challenge without replay state

Rejected. Authentication prevents alteration; it does not prevent a valid
signed challenge from being submitted more than once.

### Context-scoped replay keys

Rejected. Adding game, account, match, policy, or window data to the key would
let one publisher nonce authorize a second context. Those values belong in the
stored binding, not in replay identity.

### Permissive clock-skew leeway

Rejected. Leeway would accept outside the signed half-open interval. Clock
disagreement is an availability fault, not authority to widen the window.

### Volatile replay cache reset on restart

Rejected. Restart would make an issued or consumed challenge appear unused and
could combine with clock rollback to extend acceptance.

### Epoch identifiers

Deferred. Epoch IDs reduce per-nonce state but do not provide per-challenge
single use and introduce a trusted distributor plus transition-window rules
that M1 does not need.

## Decision

The publisher-controlled issuer generates the challenge nonce, chooses its
window under explicit local policy, and durably registers the challenge before
signing or returning it. The publisher-controlled verifier supplies the only
authoritative evaluation time. The game, bridge, attester, and local client do
not supply authoritative time or nonce state.

Challenge validity is exactly:

```text
issued_at <= verifier_now < expires_at
```

Acceptance leeway is zero. Replay identity is exactly
`(PublisherId, Nonce)`. Game, build, account scope, match, policy, and policy
version are stored as the binding and never become key components.

Issued and consumed records plus the authoritative-time high-water mark are
durable security state. Registration atomically rechecks time/window/lifetime,
uniqueness, total/publisher/account capacity, and per-publisher issuance rate
before insertion. Verification checks the strict window and relying-party
context, then one atomic operation rechecks the time floor, window, binding,
and state before irreversibly changing `Issued` to `Consumed`. Expensive
evidence and policy appraisal follows the claim; later denial or failure never
releases it.

Records may be deleted only when the persisted high-water mark is at or after
their expiry. Missing, corrupt, unavailable, rolled-back, or capacity-exhausted
state fails closed without stateless fallback or unexpired-record eviction.
Every lifetime/capacity/account/rate limit is explicit, finite, nonzero, and
has no permissive default.

`ogir-model` owns pure time/window/limit/error types. The synchronous,
database-neutral `ogir-verifier` boundary exposes only atomic register, claim,
and expiry-GC operations. No production storage adapter, clock source, random
generator, serializer, async runtime, or cryptographic primitive is selected.

## Consequences

One publisher nonce cannot yield two freshness capabilities, including across
context substitution, concurrent requests, or process restart. Time rollback
and state loss become explicit operational failures instead of silent replay
windows.

The replay store and authoritative clock become availability-critical publisher
infrastructure. A valid holder can burn its own challenge by starting a claim
that later fails, so recovery is bounded issuance of a new challenge. A forward
clock jump can cause a fail-closed outage. Production limit values, distributed
enforcement, monitoring, backups, and operator recovery require deployment
evidence and separate review.

## Threat-model impact

The decision narrows A0/A1 replay and cross-context substitution and makes
check-then-consume races mechanically nonconforming. It adds the replay store,
time high-water mark, and publisher-authoritative clock to the publisher trust
boundary. A5 compromise can still forge time/state or signing behavior and
remains an explicit residual risk.

Rollback, missing/corrupt state, lock/store failure, and capacity pressure are
mapped to unavailable protected mode. They are not cheating evidence and do
not directly trigger discipline.

## Privacy impact

Replay state contains publisher/account/match-scoped binding data. It is
authorization state, not telemetry. Store only replay identity, exact binding,
window, state, issuance-rate data, and recovery time floor. Delete records at
expiry unless a separately approved finite audit purpose exists.

Nonce bytes, `AccountScope`, `MatchId`, and raw replay bindings must not appear
in errors, logs, metrics, or derived `Debug` output. Aggregate counts or opaque
internal references are the permitted diagnostic shape.

## Dependency and license impact

The implementation uses the Rust standard library only and adds no package,
database, serializer, async runtime, clock, RNG, or cryptographic dependency.
All affected Rust, documentation, and attack-lab paths remain Apache-2.0.

## Validation

- Literal before/exact issue/last-second/exact-and-after-expiry tests.
- Equal/reversed/excessive/near-`u64::MAX` construction tests.
- Same-key same/different-context replay and cross-publisher independence.
- Missing/unavailable/corrupt state, restart, and high-water rollback tests.
- Exact lifetime, total, publisher, account, and rate-window limits.
- Issued/consumed retention and exact-expiry garbage collection.
- Two simultaneous claims yielding exactly one capability.
- 16,384 fixed-seed operations checked against an independent literal oracle.
- Redaction tests for registration, snapshot, nonce, account, match, and errors.
- Isolated mutations for both window edges, key scope, claim atomicity, restart,
  rollback, capacity eviction, claim release, arithmetic, and privacy.

## Rollback

Changing these semantics requires a superseding ADR and an explicit state/API
migration. Disabling protected mode is safe; resetting replay state while an
old issuer/signing-key epoch can still authenticate challenges is not. Recovery
must restore known-good state or first rotate the issuer/signing-key epoch so
every outstanding challenge is invalidated.

## Primary sources

- [RFC 9334 Section 10](https://www.rfc-editor.org/rfc/rfc9334.html#section-10)
  treats freshness provisioning as an early architectural decision.
- [RFC 9334 Section 10.2](https://www.rfc-editor.org/rfc/rfc9334.html#section-10.2)
  places nonce-based timekeeping on the verifier/relying party and requires
  per-nonce state.
- [RFC 9711 Section 4.1](https://www.rfc-editor.org/rfc/rfc9711.html#section-4.1)
  defines EAT nonce entropy and size bounds.
- [RFC 9711 Section 9.3](https://www.rfc-editor.org/rfc/rfc9711.html#section-9.3)
  requires an EAT use to provide a freshness mechanism.
- [RFC 7519 Sections 4.1.4–4.1.6](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4)
  define expiration, not-before, and issued-at boundaries; its optional leeway
  is deliberately not selected.
- [Rust `SystemTime`](https://doc.rust-lang.org/std/time/struct.SystemTime.html)
  documents that wall-clock measurements are not monotonic.
