# ADR-0013: Isolate a bounded volatile mock replay cache

- Status: Proposed
- Date: 2026-09-04
- Owners: Initial maintainer
- Related issues: [Approved local M1-014 issue](../../planning/issues/014-isolated-mock-replay-cache.md); [approved M1-014 design](../superpowers/specs/2026-09-04-m1-014-isolated-mock-replay-cache-design.md)
- Supersedes: None
- Superseded by: None

## Context

Roadmap item 14 calls for an in-memory replay cache and tests. The repository's
existing freshness boundary has a different purpose: ADR-0005 requires the
publisher verifier's issued/consumed replay records and authoritative-time
high-water mark to be durable, atomic, and available across restart.
`ReplayStore` and `FreshnessGuard` embody that trusted boundary.

The approved M1-014 design instead scopes a reusable research model. It needs
literal, bounded replay behavior for direct callers without implying durable
freshness authority, authorizing a verifier flow, or changing production
recovery requirements. The existing integration-test `ReferenceReplayStore`
remains an independent test support implementation; its in-process shared
snapshot behavior is not crash recovery evidence.

## Decision drivers

- Preserve ADR-0005 and security invariants 7--9 as the authoritative
  durable publisher-verifier contract.
- Make replay identity, exact binding checks, half-open windows, time-floor
  behavior, capacity, retention, and races independently testable.
- Bound retained research data and prevent sensitive values from becoming
  diagnostics or telemetry.
- Model terminal state loss honestly instead of presenting an empty volatile
  cache as restart recovery.
- Avoid a storage, recovery, cryptographic, clock-source, network, or
  production-admission dependency in this research slice.

## Options considered

### A bounded, opt-in isolated mock replay cache

Proposed. A feature-gated research module owns synchronized, fixed-policy,
fixed-capacity volatile state. It does not implement `ReplayStore`, convert to
it, produce `FreshnessChecked` or another verifier capability, or enable either
daemon. It gives research callers direct operations whose results are mock
state transitions only.

This keeps the durable interface authoritative while making the new behavior
reusable and falsifiable. Its limits are that it cannot support production
freshness, a verifier's protected result, or recovery after process exit.

### A durable replay backend now

Rejected for this roadmap item. A real backend could satisfy `ReplayStore` and
survive restart, but it requires separate decisions for transactions, durable
time-floor persistence, corruption, backups, retention, deployment, and
operator recovery. Those decisions exceed the approved in-memory research
scope.

### Relax the durable store contract to admit volatile reset

Rejected. Direct mock integration would be convenient, but a reset could make
an issued or consumed nonce appear unused and could combine with clock rollback
to create a replay window. This conflicts with ADR-0005 and invariants 7--9
and would require an explicit security-contract migration rather than a
research implementation.

## Decision

This ADR proposes option A. Under a non-default `research-mock-replay` feature,
`ogir-verifier` may expose an explicitly named mock replay cache for isolated
research runs. The cache has immutable limits, bounded record and issuance-event
slots, and one shared mutex covering every public operation. Clones share the
same state; a clone does not create a detached snapshot.

The cache is opt-in, volatile, and unable to satisfy the durable store
interface. It must not implement `ReplayStore`, dereference or convert to a
store, or mint `FreshnessChecked`, `VerifiedAttestation`, an appraisal result,
a permit, or a recovery capability. ADR-0005 remains authoritative for every
publisher-controlled freshness or protected-session path.

Within an available research run, the model follows the approved direct
operation order for time observation, half-open window evaluation, exact
`(PublisherId, Nonce)` identity, stored binding comparison, bounded admission,
and atomic `Issued`-to-`Consumed` claim. Records and issuance events are
collected only at their declared retention boundaries by an eligible registration
or explicit purge using the observed modeled time. No background clock, I/O, real-time deletion guarantee, live
record eviction, permanent nonce set, or stateless fallback is provided.

`simulate_state_loss` makes the complete shared state terminally unavailable
and drops its retained data. Every old handle then fails closed; it cannot be
reopened, restored, reset, serialized, or made available again. A newly
constructed cache is a distinct research run, not continuation of an
authenticated issuer or crash recovery. Process exit similarly destroys this
volatile model. Production recovery remains ADR-0005 durable state or a
separately approved invalidation of outstanding authority.

## Consequences

Research callers gain a bounded, concurrency-safe model with explicit state
loss and a stable direct testing surface. The model can demonstrate only local
mock semantics. It cannot be used as evidence of production replay protection,
durability, freshness authority, protected admission, or crash recovery.

Implementation must retain the existing `ReferenceReplayStore` and its tests
as an independent comparison baseline where the new cache's additional limits
do not bind. Any future durable adapter, production integration, policy change,
or recovery design requires a separate approved decision.

## Threat-model impact

The proposal supplies a testable model for same-key replay, context
substitution, clock rollback, capacity/rate pressure, and concurrent claim
races inside one research run. A simulated loss, poisoned state, unavailable
state, and post-loss operation fail closed rather than becoming authorization.

It does not reduce the production risks from A0/A1 replay or A5 compromise and
does not alter the publisher clock/durable-store trust boundary. Volatile data
loss remains an intentional, explicit limitation; interpreting it as recovery
would be a security defect.

## Privacy impact

The cache retains only bounded replay registrations and bounded issuer-rate
events for their declared modeled windows. Deletion drops owned data, but this
does not claim secure erasure, allocator residency control, or deletion of
caller-held copies.

All cache diagnostics and `Debug` output must use fixed redacted strings.
Nonce bytes, identifiers, bindings, windows, time floors, paths, and
synchronization identities must not be emitted through logging, metrics,
errors, panic text, or test failures. Aggregate retained-record and
retained-event counts are the only proposed inspection surface.

## Dependency and license impact

The proposal uses only the Rust standard library and introduces no storage,
serializer, clock, network, cryptographic, or runtime dependency. It adds a
feature-gated research module to `ogir-verifier`; the repository's Apache-2.0
license boundary remains unchanged.

## Validation

- Confirm default builds expose no mock module and feature builds expose only
  the declared research surface; neither daemon opts in.
- Use compile probes to show the cache cannot satisfy `ReplayStore` or produce
  verifier capabilities.
- Test exact key/binding/window edges, common time ordering, rejection side
  effects, capacity/rate/global-event limits, expiry collection, and stats
  without hidden purge behavior.
- Run real concurrent claim, registration, capacity/rate, and loss races, with
  exactly the documented linearization results.
- Test terminal loss and poisoned state for every public operation, with no
  restoration path and an explicitly distinct new research run.
- Compare compatible traces with the unchanged reference store and use
  separate literal expectations for the new cache's stricter limits.
- Inspect actual diagnostic output and `Debug` rendering for redaction, then
  execute physical mutation cases for replay scope, atomicity, time/window,
  capacity, rate history, reset, and redaction regressions.

## Rollback

Before acceptance or implementation, this proposal can be withdrawn by
removing the proposed ADR and index row. After implementation, disable the
opt-in feature and remove only the research module after its callers have been
updated. Replacing it with durable authority, weakening the durable contract,
or adding recovery requires a superseding ADR and any necessary API/state
migration; resetting a live production replay state is not a safe rollback.

## Primary sources

- [ADR-0005](0005-verifier-authoritative-challenge-freshness.md) and
  [security invariants 7--9 and 37--38](../SECURITY_INVARIANTS.md) are the
  controlling repository contracts for durable freshness, fail-closed loss,
  diagnostics, and retention.
- [Approved M1-014 design](../superpowers/specs/2026-09-04-m1-014-isolated-mock-replay-cache-design.md)
  defines this proposed cache's scope, terminal-loss behavior, bounds, privacy
  rules, and required verification.
- [Rust 1.98.0 `Mutex` source](https://github.com/rust-lang/rust/blob/1.98.0/library/std/src/sync/poison/mutex.rs)
  documents that mutex poisoning is advisory; the proposed model therefore
  fails closed rather than treating poisoning as complete corruption detection.
