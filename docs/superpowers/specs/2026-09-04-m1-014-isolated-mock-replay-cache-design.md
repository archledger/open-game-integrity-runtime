# M1-014: Isolated mock replay cache

- Status: Written design approved by the human in the Codex task on 2026-09-04; local implementation candidate awaits final human review.
- Agent: codex
- Scope: roadmap item 14, research-only in-memory replay behavior.
- Related issue: [local M1-014 proposal](../../../planning/issues/014-isolated-mock-replay-cache.md).
- Baseline: `96de87efa2df1fec35fb1f173b0d8eb96be31a92`, tree `ee6d8c50a0b20f4eb82b7193c4677e2b196471be`.
- Integration prerequisite satisfied: PR #28 was human-merged on 2026-09-04 as `78fe4b911f13c1d19366fdb3822c5b6bf49962f8`; its verified tree equals the baseline candidate tree above.

## 1. Objective and authority

Provide a reusable, bounded, synchronized replay model for research callers.
One retained challenge registration can be consumed at most once within a
cache instance, including when calls race. Exact binding, time, capacity, retention
and terminal-loss semantics must be independently testable.

This component is not a durable replay adapter. A successful operation reports
only a mock state transition. It does not establish freshness authority,
produce `FreshnessChecked`, drive a verifier flow, or authorize a session.

[ADR-0005](../../adr/0005-verifier-authoritative-challenge-freshness.md),
[security invariants 7–9 and 37–38](../../SECURITY_INVARIANTS.md), `ReplayStore`,
`FreshnessGuard`, and existing verifier capability boundaries remain unchanged.
They continue to require durable publisher-controlled infrastructure. This
design scopes an additional research surface; it does not supersede their
security contract or change production recovery rules.

## 2. Existing components and compatibility

`ogir-model` already supplies canonical identifiers, `UnixTime`,
`ChallengeWindow`, `FreshnessLimits`, and `FreshnessError`.
`ogir-verifier` already supplies `ReplayKey`, `ChallengeBinding`, and
`ReplayRegistration`. Replay identity is exactly `(PublisherId, Nonce)`;
game/build/account/match/policy fields and the window are compared as stored
context, never incorporated into a wider replay key.

The existing integration-test `ReferenceReplayStore` remains an independent
reference. Its `Snapshot` shares an `Arc<Mutex<State>>`; reopening it models
shared state within a process, not crash recovery. Do not move its algorithm
into the new implementation, replace it with the candidate, or change its
established tests to agree with new behavior.

The new cache intentionally adds two restrictions relative to that reference:
policy is immutable per instance, and retained issuance events have an explicit
global cap. Differential comparisons apply only where those added limits do
not bind. Separate literal tests cover the additional restrictions.

## 3. Packaging and proposed public API

Add an opt-in Cargo feature `research-mock-replay = []` to `ogir-verifier`.
It has no external dependency and is absent from default builds. Under that
feature, expose `ogir_verifier::mock_replay`, implemented in
`crates/ogir-verifier/src/mock_replay.rs`. Do not re-export its types at the
crate root or enable the feature in either daemon.

The following is API signature notation, not a compile-ready Rust example.
The local implementation candidate supplies these interfaces:

```rust,ignore
pub struct MockReplayLimits { /* private fields */ }
impl MockReplayLimits {
    pub const fn new(
        freshness: FreshnessLimits,
        max_retained_issuances: NonZeroUsize,
    ) -> Self;
    pub const fn freshness(&self) -> FreshnessLimits;
    pub const fn max_retained_issuances(&self) -> NonZeroUsize;
}

pub struct MockReplayCache { /* private shared state */ }
impl MockReplayCache {
    pub fn new_research_run(limits: MockReplayLimits)
        -> Result<Self, FreshnessError>;
    pub fn observe_time(&self, now: UnixTime) -> Result<(), FreshnessError>;
    pub fn register(&self, now: UnixTime, registration: &ReplayRegistration)
        -> Result<(), FreshnessError>;
    pub fn claim(&self, now: UnixTime, registration: &ReplayRegistration)
        -> Result<(), FreshnessError>;
    pub fn purge_expired(&self, now: UnixTime) -> Result<usize, FreshnessError>;
    pub fn simulate_state_loss(&self) -> Result<(), FreshnessError>;
    pub fn stats(&self) -> Result<MockReplayStats, FreshnessError>;
}

pub struct MockReplayStats { /* private aggregate counts */ }
impl MockReplayStats {
    pub const fn retained_records(&self) -> usize;
    pub const fn retained_issuances(&self) -> usize;
}
```

`MockReplayLimits` is `Copy + Clone`; it has no `Default`, mutation API or
policy-replacement operation. `MockReplayCache` is `Clone + Send + Sync`;
cloning shares state and immutable policy rather than copying records.
`MockReplayStats` is `Copy + Clone + PartialEq + Eq`. All three types have
manual, fixed redacted `Debug` output as specified in section 8.

Do not implement `ReplayStore`, `Deref` to a store, store conversion, or a
capability-producing adapter for the cache. Do not add such adapters in tests.
Use direct operation comparison with the existing reference instead. No
public operation returns `FreshnessChecked`, `VerifiedAttestation`, an
`AppraisalResult`, a permit, or a recovery capability.

A downstream author can still write a dishonest wrapper implementing the
public trusted `ReplayStore` trait; this design does not claim to prevent
arbitrary downstream code from making false durability assertions. The
repository supplies no such wrapper or implicit conversion.

## 4. State and synchronization

One `Arc` owns immutable limits and one `Mutex` protecting the complete state.
State is either `Available` or `Lost`. An available state owns:

- an optional highest observed `UnixTime`, initially absent;
- fixed-length slots for replay records, each vacant or containing the exact
  registration and an `Issued`/`Consumed` tag;
- fixed-length slots for issuance events, each vacant or containing only the
  publisher identifier and accepted issuance-observation time.

Slot lengths are the configured total record cap and global issuance-event cap.
No independent per-publisher maps, snapshots, append-only logs or background
queues are retained. Publisher/account/rate counts are computed by scanning
these bounded slots. Performance optimization is not part of this task.

Acquire the single mutex once for each complete public operation. Hold it
through all checks and state updates, including time observation and expiry
cleanup. No public callback, user-supplied closure, sleep, I/O, clock read,
async work, or second lock occurs inside that operation. Claim checks and the
`Issued` to `Consumed` transition are never separate operations.

Poisoned locks return `StateUnavailable`. A helper may use the poisoned guard
only to replace state with `Lost` and drop owned data; it must not resume an
operation, clear poison, reconstruct a time floor or restore availability.
Rust poisoning is advisory, so the implementation must also avoid fallible
work after committing half a registration. It must not rely on poisoning as
a universal detector of every interruption or corruption.

## 5. Exact operation order and rejection side effects

Every time-taking operation first acquires the lock and rejects `Lost` or
poisoned state as `StateUnavailable`. If `now` is below an existing floor,
return `ClockRollback` without changing records, events or the floor. Otherwise
set the floor to `now`, including equality. The first observation in a newly
constructed research run establishes its floor.

This time update precedes later rejection. A rejected expired challenge,
binding mismatch, duplicate or full-capacity registration must not erase a
future observation. These are in-memory side effects, not durable writes.

### `observe_time`

Perform only the common time steps and return success. It does not purge.

### `register`

After the common time steps, use this order:

1. Recheck positive window duration using checked subtraction; return
   `InvalidWindow` for invalid duration, then `LifetimeExceeded` if it exceeds
   the cache's fixed lifetime policy.
2. Evaluate the supplied window exactly as `[issued_at, expires_at)`, returning
   `NotYetValid` or `Expired` before any registration cleanup.
3. Purge records and issuance events whose enforcement windows have ended at
   the floor, using section 6. This cleanup remains applied if a later check
   rejects the registration.
4. Reject an existing publisher/nonce key as `ReplayDetected`, regardless of
   its stored binding or whether it is issued or consumed.
5. Check total retained records, publisher retained records, and retained
   records for the publisher/account pair, in that order. Both issued and
   consumed records count. Reject a reached cap as `CapacityExceeded`.
6. Check retained events for that publisher against the fixed per-publisher
   issuance cap, then all retained events against the global event cap.
   Return `CapacityExceeded` when either is reached.
7. Prepare the owned registration and publisher event before changing occupied
   slots. Commit exactly one `Issued` record and one issuance event at `now`
   under the same lock; no fallible allocation or callback may separate those
   two slot writes. Then return success.

Rejected issuance creates no event and consumes no quota. There is no live
record eviction, stateless fallback or policy override. Later rejection may
leave only the documented time-floor and eligible-cleanup side effects.

### `claim`

After the common time steps, evaluate the supplied window, then locate the
exact key. A missing key returns `StateUnavailable`. A different stored binding,
different stored window, or consumed record returns `ReplayDetected`. Otherwise
change `Issued` to `Consumed` and return `Ok(())`. This return is a mock result,
not a verifier capability. Claim does not purge or remove the consumed record.

No cancellation, release, reset, or downstream-failure callback changes a
consumed record back to issued. At/after expiry the supplied matching window
fails before lookup; at an unexpired missing key lookup fails closed.

### `purge_expired`

After the common time steps, apply section 6 and return the number of removed
replay records; removed issuance events do not increase this count.

### `stats`

Acquire the same lock and reject lost/poisoned state. Return counts of occupied
record and event slots only. This operation does not read a clock, observe time
or purge, so counts include any expired entries not yet explicitly collected.
Do not expose a record iterator, membership query, time floor, binding, pointer,
allocation identity or strong-reference count.

## 6. Retention, bounds and allocation

Records are eligible for deletion only when `expires_at <= floor`. Issuance
events are eligible when `floor - observed_at >= rate_window_seconds`, using
checked subtraction rather than potentially overflowing timestamp addition.
The immutable rate-window policy applies to every event in the instance.
Deletion drops owned payloads; every shared handle sees the same deletion.

An impossible retained event later than the floor is an internal-state failure:
transition to `Lost`, drop state, and return `StateUnavailable` before normal
cleanup. It is not corrected by inventing a new timestamp.

Time and cleanup are explicitly driven by research callers. No call means no
automatic time observation or expiry cleanup. The harness must call purge at
modeled expiry boundaries; this model makes no real-time deletion SLA. Terminal
loss or dropping the last handle releases the remaining owned records. Neither
logical deletion nor drop proves secure erasure, and allocator residency and
caller-retained input copies are outside the retention claim.

After expiry cleanup, the cache has no tombstone for the deleted key. The exact
old registration still fails its expired window. A newly valid registration
using the same publisher/nonce can be inserted once the old record is gone;
the mock does not prove nonce uniqueness across all time. Trusted research
issuance must model fresh nonces. There is no hidden permanent nonce set or
new nonce generator. This matches bounded expiry retention and prevents a
false lifetime-uniqueness claim; it does not relax production issuer duties.

Let `R` be `max_outstanding_total` and `E` be `max_retained_issuances`. The
cache retains at most `R` registrations and `E` events, independent of the
number of publisher names supplied. The global event cap is essential even
when short-lived records are repeatedly collected for new publishers.

Each registration has six canonical text identifiers of at most 128 bytes
(publisher plus game/build/account/match/policy). An event has one such publisher
identifier. Thus retained identifier payload is bounded by `768*R + 128*E`
bytes, plus the fixed-size nonce, times, policy version and state metadata.
This is a logical payload bound, not an exact heap or RSS bound.

Preallocate fixed-length `Vec<Option<...>>` slot collections during construction
using checked products and sums for both slot storage and the identifier-payload
formula, then `try_reserve_exact`; reject overflow before allocation and fill
only the requested slot counts. Never use allocator-provided spare capacity as authorization to
admit additional records. Reject capacity arithmetic/reservation errors with
`CapacityExceeded`, returning no cache. No collection grows after construction.
The allocator may reserve more bytes than requested; do not claim that
`try_reserve_exact` yields an exact allocation size.

Typed string cloning and `Arc` allocation use the standard library's ordinary
allocation behavior. Process-wide allocation failure/abort is not promised to
be converted into a `FreshnessError`. Construction or registration cannot
return success with only half its required state committed. If implementation
needs extra retained indexes, unbounded scratch copies, a custom allocator or
an allocation-failure recovery mechanism, revise this design before adding it.

Scans and initialization are finite functions of configured `R` and `E`.
Callers must select practical research limits. This design promises neither
constant-time lookup, bounded lock-wait latency, fairness, nor measured speed.

## 7. Terminal loss and distinct research runs

`simulate_state_loss` replaces `Available` with `Lost` while holding the lock
and drops records, events and the floor. On an already lost, unpoisoned instance
it returns `Ok(())` idempotently. Poison cleanup returns `StateUnavailable`.
It never creates a replacement available state.

After loss, every old clone returns `StateUnavailable` from time observation,
registration, claim, purge and stats. Repeating loss remains harmless. No
`reopen`, restore, reset, availability toggle, serialization or snapshot API is
provided. A concurrent claim linearized before loss may return its mock success;
a claim after loss must fail. Loss does not retract a result already returned.

`new_research_run` creates an independent experiment. A new cache can accept the
same synthetic registration once, because it is a different run. It is never
presented as continuing the old authenticated issuer or recovering its state.
Process exit destroys this model's volatile data. Production recovery still
requires ADR-0005's durable state or separately approved invalidation of all
outstanding authority; Task 14 implements neither mechanism.

## 8. Diagnostics and privacy

Fixed `Debug` strings are `MockReplayLimits([REDACTED])`,
`MockReplayCache([REDACTED])` and `MockReplayStats([REDACTED])`, independent of
values, phase and lock state. Formatting must not lock or enumerate state.
Use the existing field-free `FreshnessError` diagnostics unchanged.

Explicit aggregate-count getters are functional test interfaces, not telemetry.
No logging, error source chain, metrics, tracing, panic message, test failure
or diagnostic helper may expose nonce bytes, identifiers, bindings, windows,
floor values, paths or synchronization identities. Assertions over sensitive
values use fixed messages or predicate results, not operand-printing equality
assertions. Fault probes must inspect actual stdout/stderr as well as formatting.

The research caller supplies already validated synthetic domain values and
trusted modeled time. This is not a parser, issuer-authentication service or
mechanism for making caller data authoritative.

## 9. Required verification

| Area | Required observable evidence |
| --- | --- |
| Packaging | Default build has no mock module; feature build exposes only the declared research surface; daemons do not opt in. |
| Authority | Valid feature-enabled code constructs/uses the cache; separate compile-fail cases reject direct `ReplayStore` use and assignment of raw claim to `FreshnessChecked`; failures must be due to those intended type boundaries, not missing imports. |
| Key and context | Same publisher/nonce duplicates across each changed context and window; independent publishers; exact mismatched claim leaves original unconsumed. |
| Time | Before/exact issue, last valid second, exact/after expiry, equal/rollback observations, large timestamps, rejected future observations followed by lower time. |
| Capacity | Each record/rate/global-event boundary at and over limit; consumed records count; no unexpired eviction; many publishers cannot bypass the global event cap. |
| Policy | Fixed policy across clones; no setter/per-call override; current lifetime rechecked at registration even if a registration was constructed under a looser policy. |
| Side effects | Literal checks of floor and cleanup effects for every rejection stage; no rejected issuance event; no partial record/event insertion. |
| Retention | Exact record/rate expiry, independent windows, zero/all removals, old handles observe deletion; stats do not secretly purge. |
| Forgotten keys | Exact old registration stays expired after purge; a same-key newly valid registration follows ordinary register rules after deletion, documenting the trusted fresh-nonce issuance assumption. |
| Concurrency | Real competing threads: exactly one same-key claim and one same-key registration succeed; capacity/rate races cannot overfill; loss races obey linearization. |
| Loss and poison | All operations on old handles fail after loss; repeated loss is idempotent; ordinary poison fails closed and drops state; no restoration path; new independent run is explicitly distinguished. |
| Independent model | Preserve M1-008 reference tests; compare compatible traces against the unchanged reference and new policies against separately written literal expectations. No expected result derived from candidate helpers. |
| Privacy | Complete type/error debug and actual failure-output probes; source checks alone do not establish output redaction. |
| Mutation | Physically exercise key-scope, atomicity, clock/window, capacity, rate-history, release/reset and redaction regressions with observed first cause and restored passing runs. No kill credit for setup/compile errors. |

Compile-pass controls accompany compile-fail tests. Independent/private test
helpers may inspect internal counts, state and drop behavior for verification;
none is exported or installed as a durable-store adapter. Concurrency tests use
coordinated starts and require deterministic outcome invariants, not a chosen
winner or timing-dependent sleeps. Test-only hooks may force an interleaving
for a deliberately broken mutant but cannot replace correct-source competing
thread coverage.

The implementation plan must inventory exact cases and mutations before code
changes. This document does not assert a test count or completed test result.
Run the existing full default/all-feature Rust and release checks, rustfmt,
Clippy, rustdoc, metadata/ADR gates and relevant aggregate/Python regression
gates from the final implementation state. Do not weaken pre-existing gates.
Use existing CI all-feature commands for the opt-in Rust tests. Python workflow
expansion is a separately scoped concern, not silently bundled into this task.

## 10. Proposed change surface and exclusions

Implementation may add `mock_replay.rs` and focused internal/external Rust tests;
change only the feature/module declarations in the verifier manifest and root;
and update scoped architecture, threat, test-strategy, roadmap and lessons text.
An ADR documenting the isolated research boundary and its index entry must be
reviewed before implementation is accepted; it must not supersede ADR-0005.
The issue and this design are documentation deliverables first.

No production daemon feature activation, verifier flow/freshness contract
rewrite, persistence adapter, serializer, randomness, signer, network service,
database, external package, unsafe Rust, public snapshot or copied reference
implementation is in scope. Existing reference/model tests remain independent.
Do not change the M1-013 certified source or rewrite its completed lessons.

## 11. Sources and verified limits of evidence

- [ADR-0005](../../adr/0005-verifier-authoritative-challenge-freshness.md) and
  [M1-008](../../../planning/issues/008-freshness-model.md) control durable
  freshness, context, error-order and retention compatibility.
- [Replay contract](../../../crates/ogir-verifier/src/freshness.rs),
  [domain limits](../../../crates/ogir-model/src/freshness.rs), and
  [reference implementation](../../../crates/ogir-verifier/tests/support/reference_replay_store.rs)
  were read at the baseline above.
- [RFC 9334 sections 10.2–10.3](https://www.rfc-editor.org/rfc/rfc9334.html#section-10.2)
  place nonce freshness timekeeping on the appraiser and describe per-nonce
  state. OGIR's durable-transition requirement is its own accepted decision.
- Official Rust 1.98.0 tagged source was retrieved and inspected for
  [Mutex](https://github.com/rust-lang/rust/blob/1.98.0/library/std/src/sync/poison/mutex.rs),
  [Vec](https://github.com/rust-lang/rust/blob/1.98.0/library/alloc/src/vec/mod.rs),
  and [Arc](https://github.com/rust-lang/rust/blob/1.98.0/library/alloc/src/sync.rs).
  Mutex poisoning is advisory; Vec reservation may exceed requested capacity;
  ordinary allocation and Arc clone overflow do not promise recoverable errors.
  Retrieved source hashes are retained in the local design review evidence.

Versioned rustdoc URLs could not be opened by the web tool. The exact tagged
upstream source was obtained through GitHub instead; no different-version API
documentation was substituted. No performance, persistence, secure-erasure or
production-readiness result is inferred from this design.

## 12. Acceptance and next gate

The human approved approach A and this written design on 2026-09-04. The
implementation plan was written and self-reviewed, and implementation began
only after verification of PR #28's human merge. Status and integration notes
have been refreshed without changing the approved behavior requirements.
The original approved bytes and hashes remain recorded in the design review
evidence.

The local implementation candidate now requires final human line review,
acceptance of Proposed ADR-0013, DCO certification and separate commit
and publication authorization. M1-013 certification does not transfer to new
content. No Task 14 live issue, push or PR publication is authorized by design
approval alone. This research model remains non-authoritative and volatile.
