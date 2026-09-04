# Isolated Mock Replay Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a reusable bounded mock replay cache without representing volatile state as durable freshness authority.

**Architecture:** A default-off research module in `ogir-verifier` owns fixed-length record/event slots and an immutable policy behind one shared mutex. It exposes raw mock operations and aggregate counts, never `ReplayStore` or verifier capabilities. Existing M1-008 reference code remains independent.

**Tech Stack:** Rust 1.98.0, edition 2024, standard library and existing workspace dependencies; current Cargo/rustfmt/Clippy/rustdoc gates.

**Spec:** [Approved written design](../specs/2026-09-04-m1-014-isolated-mock-replay-cache-design.md), SHA-256 `385f7bb4bd0b09f4545dc15014e622c03e5a8d74fe56471fc686cf95ab38b1f9`. [Approved local issue](../../../planning/issues/014-isolated-mock-replay-cache.md), SHA-256 `c8f2f62cb135593581f4b4768ba41a49d5dfbac4d7b2a3e0366407885b6ca01d`. Human written-spec approval was received on 2026-09-04. These hashes identify the original approved documents. During implementation, status/merge notes and issue-tool metadata were refreshed; the original approval evidence remains recorded separately and the behavior requirements are unchanged.

## Global constraints

- `research-mock-replay = []` is opt-in and absent from default builds. No daemon opts in.
- Do not implement `ReplayStore`, `Deref` to a store, store conversion, or a capability-producing adapter for the cache. Do not add such adapters in tests.
- `MockReplayLimits` is `Copy + Clone`; it has no `Default`, mutation API or policy-replacement operation.
- `MockReplayCache` is `Clone + Send + Sync`; cloning shares state and immutable policy rather than copying records.
- `MockReplayStats` is `Copy + Clone + PartialEq + Eq`.
- Replay identity is exactly `(PublisherId, Nonce)`. All existing durable/verifier contracts remain unchanged.
- Time and cleanup are explicitly driven by research callers. No call means no automatic time observation or expiry cleanup.
- A new cache is a separate research run, never recovery of an outstanding authenticated challenge. No permanent nonce-history claim.
- Fixed Debug outputs, no raw sensitive diagnostics, no secure-erasure claim, no external dependency, lockfile change, unsafe Rust or production service expansion.
- Approved spec sections 3–8 define the API, exact error order and side effects. The executable cases below supplement that authority; they do not override it.
- Tests and mutations use synthetic data only. A missing symbol may establish initial API RED, but import/compile/setup failures never count as behavioral mutation kills.
- Checkpoint after each material change. Frequent local checkpoints replace automatic commits: every signed commit requires its own exact human line review/DCO and authorization. Earlier M1-013 certification does not transfer.

## Starting state and deliverable boundary

At plan preparation, PR #28 is OPEN/ready, head `96de87efa2df1fec35fb1f173b0d8eb96be31a92`; remote main is `9a04b055d9e978b5e4ff01adce72f0915c122532`. The certified candidate tree is `ee6d8c50a0b20f4eb82b7193c4677e2b196471be`. This plan does not invent a merge SHA. Task 1 must verify the human web merge before implementation starts. Do not merge on the human's behalf.

Plan creation changes documentation only. No proposed Rust below has been installed or tested by writing this plan. Case and mutation counts are planned inventory counts, not execution results.

## File ownership

| File | Responsibility |
| --- | --- |
| `crates/ogir-verifier/Cargo.toml` | Empty research feature declaration only. |
| `crates/ogir-verifier/src/lib.rs` | Feature-gated public `mock_replay` module only. |
| `crates/ogir-verifier/src/mock_replay.rs` | Public types, fixed redaction, private shared state and operations. |
| `crates/ogir-verifier/src/mock_replay/tests.rs` | Private-state, literal, concurrency, loss and privacy tests. |
| `crates/ogir-verifier/tests/support/mock_replay_reference.rs` | Feature-gated external differential test against the unchanged reference store. |
| `crates/ogir-verifier/tests/support/reference_replay_store.rs` | Read-only independent reference; not moved or rewritten. |
| `crates/ogir-verifier/tests/freshness.rs` | Existing integration suite; add only a feature-gated path-module declaration for X08, preserving every existing test body. |
| `docs/adr/0013-isolated-mock-replay-cache.md` and `docs/adr/index.md` | Proposed research-boundary ADR and consistent index entry. Recheck number availability first. |
| `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/TEST_STRATEGY.md`, `docs/ROADMAP.md`, `docs/LESSONS_LEARNED.md` | Focused mock boundary, evidence, limits and append-only lessons. |
| `planning/issues/014-isolated-mock-replay-cache.md` and approved spec | Preserve reviewed content; add implementation evidence only through a reviewed documentation change. |
| `.superpowers/sdd/2026-09-04-m1-014-isolated-mock-replay-cache/` | Ignored commands/results, source snapshots, compile probes, mutation artifacts, reviews and freeze manifest. |

No workspace restructuring or new helper crate. Private tests may be split later only if needed for readability without expanding public APIs or changing selectors; record any such mechanical move in the checkpoint.

## Task 1: Verify integration baseline and document the research boundary

**Files:** Read the approved issue/spec, invariants, threat model, architecture, roadmap, AI policy, ADR-0005 and ADR-0007. Create the proposed ADR above and its index entry only after the merge gate. Record ignored `baseline.json` and `progress.md`.

**Interfaces:** Consumes GitHub PR #28 and the certified tree. Produces a verified merged starting commit, unchanged spec/issue hashes and a proposed research-boundary ADR. No runtime interface changes.

- [ ] Read shared-memory index and project handoff first. Recheck the two approved document hashes and record existing untracked files. Preserve `scripts/__pycache__/`.
- [ ] Query PR #28 and remote main. If still open, stop implementation and hand the GitHub web merge back to the human; local planning work may remain.

```bash
gh pr view 28 --repo archledger/open-game-integrity-runtime --json state,headRefOid,baseRefOid,mergeCommit,mergedAt
git ls-remote origin refs/heads/main
```

Require MERGED and the certified PR head. Fetch the observed main ref without resetting any occupied worktree. Inspect the actual squash commit: expected sole parent is the observed premerge main if it remained unchanged; require its tree to equal the certified tree, valid signature metadata, and both reviewed contributor sign-offs preserved. If main advanced, inspect the additional commits and tree differences rather than assuming equality or discarding them. Do not infer certification for added content.

- [ ] Choose an isolated Task 14 checkout at the verified merged baseline using the worktree skill and existing user preferences. Do not repoint another worktree or amend the M1-013 branch. Copy only the three reviewed Task 14 documents into it and compare hashes. Record checkout path and actual branch/OID, not a guessed resumption state.
- [ ] Run `cargo test --workspace --all-features` and `bash scripts/check.sh` as the starting gates with captured exits. Inspect failures rather than accepting a dirty baseline. Preserve prior Task 10 evidence separately.
- [ ] Write ADR-0013 with Status Proposed, Date 2026-09-04, owner Initial maintainer, this issue/spec as references, Supersedes None. Decision text: the mock is opt-in, volatile, bounded and unable to satisfy the durable store interface; ADR-0005 remains authoritative. Include three considered approaches, terminal loss, no crash recovery, privacy/retention and planned verification from the spec. Add an index row with identical status; do not mark Accepted without the human decision.
- [ ] Verify metadata/ADR checks against a disposable index containing the proposed documentation, preserve the real index, and checkpoint. No automatic commit.

## Task 2: Feature, immutable limits, shared state and terminal loss

**Files:** Modify verifier manifest/root; create `mock_replay.rs` and `mock_replay/tests.rs`.

**Interfaces:** Produces all three public types, limits constructor/getters, `new_research_run`, `Clone`, `stats`, `simulate_state_loss`, manual Debug and private `lock_state`. Public signature authority is spec section 3. Subsequent tasks add the four time-taking methods.

- [ ] Add A01–A06 and private-state P01/P02 formatting tests from the inventory. Defer A07/A08 until Task 4 and the full X loss/poison sequences until Task 6. First establish missing-API RED, then keep tests for behavior RED as the types are introduced. Run selectors with the feature enabled; do not count a zero-test run as passing.

```bash
cargo test -p ogir-verifier --features research-mock-replay --lib mock_replay::tests::case_a01 -- --exact
```

- [ ] Add only these declarations to existing files:

```toml
[features]
research-mock-replay = []
```

```rust
#[cfg(feature = "research-mock-replay")]
pub mod mock_replay;
```

- [ ] Use the following private layout and implement the approved public fields/getters without exposing storage. Public structs keep fields private. `MockReplayLimits` stores `freshness: FreshnessLimits` and `max_retained_issuances: NonZeroUsize`; `MockReplayStats` stores `retained_records: usize` and `retained_issuances: usize`.

```rust
use std::fmt;
use std::mem::size_of;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard};
use ogir_model::{FreshnessError, FreshnessLimits, PublisherId, UnixTime};
use crate::ReplayRegistration;

#[derive(Clone)]
pub struct MockReplayCache { shared: Arc<Shared> }
struct Shared { limits: MockReplayLimits, state: Mutex<State> }
enum State { Available(Active), Lost }
struct Active {
    floor: Option<UnixTime>,
    records: Vec<Option<Record>>,
    events: Vec<Option<Event>>,
}
struct Record { registration: ReplayRegistration, consumed: bool }
struct Event { publisher: PublisherId, observed_at: UnixTime }

fn slots<T>(n: usize) -> Result<Vec<Option<T>>, FreshnessError> {
    let mut result = Vec::new();
    result.try_reserve_exact(n).map_err(|_| FreshnessError::CapacityExceeded)?;
    result.resize_with(n, || None);
    Ok(result)
}
```

- [ ] Before calling `slots`, check products/sums for `R*size_of::<Option<Record>>() + E*size_of::<Option<Event>>()` and `768*R + 128*E`, using checked arithmetic and `CapacityExceeded` on overflow. Initialize no occupied slot and no floor. Construct the Arc only after both collections are available. Ordinary Arc/String allocation aborts are not promised to become recoverable errors.

```rust
fn checked_budget(r: usize, e: usize) -> Result<(), FreshnessError> {
    let storage = r.checked_mul(size_of::<Option<Record>>())
        .and_then(|a| e.checked_mul(size_of::<Option<Event>>())
            .and_then(|b| a.checked_add(b)));
    let payload = r.checked_mul(768)
        .and_then(|a| e.checked_mul(128).and_then(|b| a.checked_add(b)));
    match (storage, payload) {
        (Some(_), Some(_)) => Ok(()),
        _ => Err(FreshnessError::CapacityExceeded),
    }
}
```

- [ ] Implement `lock_state(&self) -> Result<MutexGuard<'_, State>, FreshnessError>` as below. `stats` matches Available, counts occupied slots and returns only aggregates; Lost returns StateUnavailable. `simulate_state_loss` takes that guard and assigns Lost, so the old Active is dropped and repeated loss remains Ok.

```rust
fn lock_state(&self) -> Result<MutexGuard<'_, State>, FreshnessError> {
    match self.shared.state.lock() {
        Ok(guard) => Ok(guard),
        Err(poisoned) => {
            *poisoned.into_inner() = State::Lost;
            Err(FreshnessError::StateUnavailable)
        }
    }
}
```

- [ ] Implement Debug with `formatter.write_str("MockReplayCache([REDACTED])")` and the exact analogous Limits/Stats strings. Never acquire the lock during formatting. Do not derive Debug on sensitive private state or introduce Display.
- [ ] Run implemented A/P selectors, then the feature-enabled library suite and rustfmt/Clippy. Record counts/exits and review the default-off/type boundary. Checkpoint without committing.

### Shared test fixtures for Tasks 2–6

Put these helpers inside `mock_replay/tests.rs`; the parent uses `#[cfg(test)] mod tests;`. No helper becomes a public mock-to-store adapter. The existing nonce fixture pattern is synthetic and not a random generator.

```rust
use super::*;
use std::num::NonZeroU64;
use ogir_model::{AccountScope, BuildId, ChallengeLifetime, ChallengeWindow,
    GameId, IdentifierError, MatchId, Nonce, PolicyId, PolicyVersion,
    ProtocolVersion, PublisherChallenge};

fn take<T>(result: Result<T, FreshnessError>) -> T {
    match result { Ok(value) => value, Err(_) => panic!("mock fixture failed") }
}
fn nz(n: usize) -> NonZeroUsize {
    match NonZeroUsize::new(n) { Some(n) => n, None => panic!("invalid fixture limit") }
}
fn nz64(n: u64) -> NonZeroU64 {
    match NonZeroU64::new(n) { Some(n) => n, None => panic!("invalid fixture limit") }
}
fn id<T>(text: &str) -> T
where for<'a> T: TryFrom<&'a str, Error = IdentifierError> {
    match T::try_from(text) { Ok(value) => value, Err(_) => panic!("invalid fixture id") }
}
fn policy(total: usize, publisher: usize, account: usize, rate: usize) -> FreshnessLimits {
    FreshnessLimits::new(ChallengeLifetime::new(nz64(100)), nz(total),
        nz(publisher), nz(account), nz64(60), nz(rate))
}
fn cache(total: usize, publisher: usize, account: usize, rate: usize, events: usize)
    -> MockReplayCache {
    take(MockReplayCache::new_research_run(MockReplayLimits::new(
        policy(total, publisher, account, rate), nz(events))))
}
fn challenge(publisher: &str, seed: u8, issue: u64, expiry: u64) -> PublisherChallenge {
    PublisherChallenge {
        version: ProtocolVersion { major: 0, minor: 1 },
        publisher_id: id::<PublisherId>(publisher), game_id: id::<GameId>("example.game"),
        build_id: id::<BuildId>("build-1"), account_scope: id::<AccountScope>("account-1"),
        match_id: id::<MatchId>("match-1"), policy_id: id::<PolicyId>("research-v0"),
        policy_version: PolicyVersion::new(1),
        nonce: Nonce::from_bytes(std::array::from_fn(|i| seed ^ i as u8)),
        window: take(ChallengeWindow::new(UnixTime::new(issue), UnixTime::new(expiry),
            ChallengeLifetime::new(nz64(u64::MAX)))),
    }
}
fn reg(publisher: &str, seed: u8, issue: u64, expiry: u64) -> ReplayRegistration {
    ReplayRegistration::from_challenge(&challenge(publisher, seed, issue, expiry))
}
fn counts(cache: &MockReplayCache) -> (usize, usize) {
    let stats = take(cache.stats());
    (stats.retained_records(), stats.retained_issuances())
}
#[test]
fn case_a01() {
    let model = cache(4, 4, 4, 4, 8);
    assert!(counts(&model) == (0, 0), "new cache retained state");
}
```

Use fixed predicate messages for all input-dependent assertions. Binding/window mismatch cases use substituted windows valid at the operation time (for example 100..199 at time150), so an earlier window error cannot mask the intended replay check. Fixtures with different context fields modify a constructed `PublisherChallenge`, then call `ReplayRegistration::from_challenge`; do not fabricate access to private replay fields.

## Task 3: Authoritative modeled time and expiry collection

**Files:** `mock_replay.rs`, private tests.

**Interfaces:** Consumes Shared/State/Active and `lock_state`. Produces `observe_time`, `purge_expired`, private `advance(&mut Active, UnixTime)` and `collect(&mut Active, NonZeroU64)`; register reuses both, claim only advance. `collect` returns `Result<usize, FreshnessError>`.

- [ ] Add T01–T03, T06–T07 and G01–G07 tests. Defer registration-dependent T04/T08 to Task 4 and claim-dependent T05/G08 to Task 5. Before register exists, private tests install explicitly constructed Record/Event values in known vacant slots; do not pretend those setup paths test registration.

```rust
#[test]
fn case_t03() {
    let model = cache(4, 4, 4, 4, 8);
    take(model.observe_time(UnixTime::new(150)));
    assert!(model.observe_time(UnixTime::new(149)) == Err(FreshnessError::ClockRollback),
        "rollback was accepted");
    take(model.observe_time(UnixTime::new(150)));
}
fn advance(active: &mut Active, now: UnixTime) -> Result<(), FreshnessError> {
    if active.floor.is_some_and(|floor| now < floor) {
        return Err(FreshnessError::ClockRollback);
    }
    active.floor = Some(now);
    Ok(())
}
```

- [ ] `observe_time`: lock, reject Lost, call advance, return without cleanup. Never call a system clock.
- [ ] `collect`: require a floor; validate every occupied event has `observed_at <= floor` before deleting anything. Count record removals while replacing only records with `expires_at <= floor` with None. Remove events with checked age at least the fixed rate window. Return record removals only.

```rust
let floor = active.floor.ok_or(FreshnessError::StateUnavailable)?;
if active.events.iter().flatten().any(|event| event.observed_at > floor) {
    return Err(FreshnessError::StateUnavailable);
}
let mut removed = 0;
for slot in &mut active.records {
    if slot.as_ref().is_some_and(|r| r.registration.window().expires_at() <= floor) {
        *slot = None;
        removed += 1;
    }
}
for slot in &mut active.events {
    if slot.as_ref().is_some_and(|event| {
        floor.seconds().checked_sub(event.observed_at.seconds())
            .is_some_and(|age| age >= rate_window.get())
    }) { *slot = None; }
}
Ok(removed)
```

- [ ] `purge_expired`: hold the state guard through advance and collect; if collect reports impossible state, replace the whole State with Lost and return StateUnavailable. Rollback must return before cleanup/loss. This distinction prevents a normal missing-registration error in a later task from invalidating an otherwise healthy cache.
- [ ] Run implemented time/collection cases and the feature suite; verify the stored floor after later failure using a subsequent lower-time call and private state assertions. Checkpoint.

## Task 4: Registration with immutable policy and bounded issuance history

**Files:** `mock_replay.rs`, private tests.

**Interfaces:** Adds `register(&self, UnixTime, &ReplayRegistration) -> Result<(), FreshnessError>`. Consumes immutable limits, advance, collect and fixed slot storage.

- [ ] Write A07/A08, T04/T08 and R01–R12 RED tests (A07 covers insert/purge now and adds consumption in Task 5), including global event exhaustion after expired records from several publishers are purged. Example:

```rust
#[test]
fn case_r11() {
    let model = cache(1, 1, 1, 4, 2);
    take(model.register(UnixTime::new(100), &reg("publisher-one", 1, 100, 101)));
    take(model.register(UnixTime::new(101), &reg("publisher-two", 2, 101, 102)));
    assert!(model.register(UnixTime::new(102), &reg("publisher-three", 3, 102, 103))
        == Err(FreshnessError::CapacityExceeded), "global event bound bypassed");
    assert!(counts(&model) == (0, 2), "rejection side effects differ");
}
```

- [ ] Implement spec section 5's exact order under one guard: advance; checked positive duration; lifetime; window; collect; key duplicate; total/publisher/account records; publisher events; global events; prepare; insert. Use the same immutable `FreshnessLimits` for every clone/call.

```rust
let lifetime = registration.window().expires_at().seconds()
    .checked_sub(registration.window().issued_at().seconds())
    .filter(|duration| *duration != 0)
    .ok_or(FreshnessError::InvalidWindow)?;
if lifetime > limits.freshness().max_lifetime().seconds().get() {
    return Err(FreshnessError::LifetimeExceeded);
}
registration.window().evaluate(now)?;
```

Scan occupied records using `r.registration.key()` and `.binding()` for exact typed equality; consumed records count. Counts compare using `>=`. A publisher/account count includes both publisher equality and account equality. Publisher-rate count reads occupied Event publishers; no input can supply a larger per-call policy.

- [ ] Locate one vacant record slot and one vacant event slot only after capacity checks. Clone registration and publisher into owned temporary Record/Event before either slot assignment. Then move them into those two slots under the same lock; there is no allocation, callback or recheck between assignments.

```rust
let record_index = active.records.iter().position(Option::is_none)
    .ok_or(FreshnessError::StateUnavailable)?;
let event_index = active.events.iter().position(Option::is_none)
    .ok_or(FreshnessError::StateUnavailable)?;
let record = Record { registration: registration.clone(), consumed: false };
let event = Event { publisher: registration.key().publisher_id().clone(), observed_at: now };
active.records[record_index] = Some(record);
active.events[event_index] = Some(event);
Ok(())
```

`active` and `limits` above are the available state and shared policy while the single guard is held. If collect fails, mark Lost before returning, as in Task 3. Do not treat policy, window, duplicate or capacity rejection as loss.

- [ ] For R03/R09 consumed variants before claim exists, set the private consumed tag explicitly; C tests later verify the public transition. Run every R row and implemented A/T/G rows. Verify that rejected issuance leaves no new event and only the specified floor/expiry-cleanup side effects. Checkpoint.

## Task 5: Irreversible raw mock claim

**Files:** `mock_replay.rs`, private tests.

**Interfaces:** Adds `claim(&self, UnixTime, &ReplayRegistration) -> Result<(), FreshnessError>`. It neither purges nor returns a capability.

- [ ] Add T05, C01–C08 and G08 RED tests; extend A07 through the public claim transition. Explicitly show that a wrong binding leaves the original issued registration claimable and that a missing registration leaves unrelated state available.

```rust
#[test]
fn case_c02() {
    let model = cache(4, 4, 4, 4, 8);
    let input = reg("example.publisher", 1, 100, 200);
    take(model.register(UnixTime::new(100), &input));
    take(model.claim(UnixTime::new(150), &input));
    assert!(model.claim(UnixTime::new(150), &input) == Err(FreshnessError::ReplayDetected),
        "consumed registration was reusable");
    assert!(counts(&model) == (1, 1), "claim removed enforcement state");
}
```

- [ ] Under one guard, reject Lost; advance; evaluate the supplied window; find exact key; check binding, window and consumed flag; set consumed. Implement the core transition exactly:

```rust
registration.window().evaluate(now)?;
let record = active.records.iter_mut().flatten()
    .find(|r| r.registration.key() == registration.key())
    .ok_or(FreshnessError::StateUnavailable)?;
if record.registration.binding() != registration.binding()
    || record.registration.window() != registration.window()
    || record.consumed {
    return Err(FreshnessError::ReplayDetected);
}
record.consumed = true;
Ok(())
```

- [ ] Run all C rows; then every implemented row together. Check raw success type and ensure no release, rollback or verifier integration method was added. Checkpoint.

## Task 6: Concurrency, model independence, loss and real diagnostics

**Files:** private tests, `crates/ogir-verifier/tests/support/mock_replay_reference.rs`; candidate only for test-demonstrated corrections. Existing reference source remains read-only.

**Interfaces:** Consumes the complete mock API. Produces X/P evidence and private fault controls, not an adapter. X08 is an external integration test in `tests/support/mock_replay_reference.rs`, included by a feature-gated path module in the existing `tests/freshness.rs` target; import `crate::support` instead of compiling support again. Import `support::ReferenceReplayStore`, `ogir_verifier::ReplayStore` and the public mock types. This preserves the reference file’s existing external-crate imports; do not include it as a nested module inside the library. Reuse the fixture constructor code above in this external test with public imports. Compare direct reference trait operations, never implement that trait for the candidate.

- [ ] Complete X01–X08/P01–P05. Coordinated correct-source concurrency uses real threads. Each worker owns a Clone of the cache and its registration; a Barrier coordinates the start, not an expected winner.

```rust
let model = cache(4, 4, 4, 4, 8);
let input = reg("example.publisher", 1, 100, 200);
take(model.register(UnixTime::new(100), &input));
let start = Arc::new(std::sync::Barrier::new(3));
let mut workers = Vec::new();
for _ in 0..2 {
    let model = model.clone(); let input = input.clone(); let start = start.clone();
    workers.push(std::thread::spawn(move || {
        start.wait(); model.claim(UnixTime::new(150), &input)
    }));
}
start.wait();
let results: Vec<_> = workers.into_iter().map(|worker| match worker.join() {
    Ok(result) => result, Err(_) => panic!("mock worker failed"),
}).collect();
assert!(results.iter().filter(|r| r.is_ok()).count() == 1, "claim winner count differs");
assert!(results.iter().filter(|r| **r == Err(FreshnessError::ReplayDetected)).count() == 1,
    "claim loser classification differs");
```

- [ ] For X08, use direct `ReplayStore` calls on the unchanged reference and direct candidate calls with the same immutable policy. Keep global event capacity nonbinding. Compare the literal action sequence specified below, not candidate-generated expected results. The existing 16,384-operation M1-008 suite still runs unchanged; do not rename it as new candidate coverage.
The external X08 test imports the same public fixture types, defines the fixture helpers above with public imports rather than `super::*`, and uses this literal comparison body. This is the entire action/expected-result sequence; no candidate helper computes an expectation.

```rust
#[test]
fn case_x08() {
    let model = cache(4, 4, 4, 4, 8);
    let reference = support::ReferenceReplayStore::available();
    let fixed = policy(4, 4, 4, 4);
    let first = reg("example.publisher", 1, 100, 200);
    let second = reg("example.publisher", 2, 100, 200);
    let mut changed = challenge("example.publisher", 1, 100, 200);
    changed.game_id = id::<GameId>("other.game");
    let wrong = ReplayRegistration::from_challenge(&changed);
    macro_rules! compare {
        ($candidate:expr, $reference:expr, $expected:expr, $records:expr, $events:expr) => {{
            let observed = $candidate;
            let reference_observed = $reference;
            assert!(observed == $expected && reference_observed == $expected,
                "literal replay result differs");
            assert!(counts(&model) == ($records, $events), "mock counts differ");
            assert!(reference.record_count() == Ok($records), "reference record count differs");
            assert!(reference.issuance_event_count() == Ok($events), "reference event count differs");
        }};
    }
    compare!(model.observe_time(UnixTime::new(100)),
        reference.observe_time(UnixTime::new(100)), Ok(()), 0, 0);
    compare!(model.register(UnixTime::new(100), &first),
        reference.register(UnixTime::new(100), &first, fixed), Ok(()), 1, 1);
    compare!(model.claim(UnixTime::new(150), &wrong),
        reference.claim(UnixTime::new(150), &wrong), Err(FreshnessError::ReplayDetected), 1, 1);
    compare!(model.observe_time(UnixTime::new(149)),
        reference.observe_time(UnixTime::new(149)), Err(FreshnessError::ClockRollback), 1, 1);
    compare!(model.claim(UnixTime::new(150), &first),
        reference.claim(UnixTime::new(150), &first), Ok(()), 1, 1);
    compare!(model.claim(UnixTime::new(150), &first),
        reference.claim(UnixTime::new(150), &first), Err(FreshnessError::ReplayDetected), 1, 1);
    compare!(model.register(UnixTime::new(150), &second),
        reference.register(UnixTime::new(150), &second, fixed), Ok(()), 2, 2);
    compare!(model.purge_expired(UnixTime::new(160)),
        reference.purge_expired(UnixTime::new(160)), Ok(0), 2, 1);
    compare!(model.purge_expired(UnixTime::new(200)),
        reference.purge_expired(UnixTime::new(200)), Ok(2), 0, 1);
    compare!(model.claim(UnixTime::new(200), &first),
        reference.claim(UnixTime::new(200), &first), Err(FreshnessError::Expired), 0, 1);
}
```

- [ ] Private poison probes panic with a fixed message while holding the mutex and join the worker. After the next operation, inspect State::Lost privately and require every operation to return the appropriate loss result. Never clear poison. An internal future-event injection must also cause whole-state loss through collect.
- [ ] Actual output probe P04: use a populated cache with distinctive synthetic canonical text and a large distinctive time value, not common substrings such as `100`. Define a child-only test branch selected by an exact test-specific environment variable. The child intentionally formats the model/limits/stats/errors and runs a failing fixed-message predicate under libtest. A parent invokes `std::env::current_exe()` with only the P04 selector plus `--exact --nocapture`, sets the child variable, captures both streams, and requires the expected child failure exit with no synthetic identifier/nonce/time sentinel. The parent must not print captured streams on failure. P05 covers poison-worker panic output in the same parent/child pattern with a distinct selector and variable, so it cannot recurse.
- [ ] Use only non-sensitive result summaries and hashes in permanent evidence. Run all X/P rows and the feature suite; preserve real-thread evidence even when mutation-only barriers are later used. Checkpoint.

## Exact runtime test inventory

There are **57 planned named test functions**: 56 library tests and one external integration test. Each ID except X08 maps to `mock_replay::tests::case_<lowercase-id>`, for example A01 to `mock_replay::tests::case_a01`. X08 maps to `mock_replay_reference::case_x08` in integration target `freshness`. Each row defines one test function; explicitly enumerated variants inside a row are additional assertions, not extra named tests. Helper/child branches do not inflate the count. Avoid a catch-all test which silently omits rows.

Default fixture: window `[100,200)`, lifetime 100, rate window 60, four records per global/publisher/account cap, publisher-rate cap 4 and global-event cap 8. Override only values named in the row. Every isolated subcase gets a fresh cache unless sharing is the behavior under test.

| ID | Required inputs/actions and expected result |
| --- | --- |
| A01 | New run has counts (0,0) and no floor. |
| A02 | Clone then lose state through one; both stats calls return StateUnavailable. Shared registration counts are also checked in R01 after registration exists. |
| A03 | Limits constructor/getters preserve all six FreshnessLimits values and global event cap; Copy of limits cannot change an existing cache. |
| A04 | Stats Copy/Clone/equality preserve aggregate counts; no hidden mutation. |
| A05 | Total record cap `usize::MAX`: checked arithmetic rejects CapacityExceeded before allocation. |
| A06 | Event cap `usize::MAX`: same rejection; no huge allocation probe. |
| A07 | Configured slot lengths are exactly R/E throughout insert/consume/purge; vacant slots are reused and collections do not grow. |
| A08 | Extra reserved Vec capacity is not used as additional admission slots; artificially reserve spare capacity privately and still reject at policy limits. |
| T01 | First observation 100 establishes floor; counts unchanged. |
| T02 | Equal observation 100 succeeds and preserves floor. |
| T03 | 150 then 149 rejects ClockRollback without record/event mutation. |
| T04 | Expired register at 250 rejects Expired; subsequent observe 249 rejects rollback. |
| T05 | Claim with mismatched binding at 150 rejects replay; subsequent observe 149 rejects rollback. |
| T06 | Observe alone at 200 retains previously installed expired slots; stats does not collect. |
| T07 | Observe `u64::MAX` succeeds; `u64::MAX-1` then rejects rollback. |
| T08 | Before-issue register at 99 establishes floor then NotYetValid; observe 98 rejects rollback. |
| R01 | Valid register at 100 adds one issued record/event at floor 100; an earlier clone observes the same (1,1) counts. |
| R02 | Window 100..201 created under loose fixture lifetime rejects LifetimeExceeded under cache max 100; no event. |
| R03 | Same-key duplicate, both issued and consumed variants, rejects replay and creates no event. |
| R04 | Same-key registration with each game/build/account/match/policy/policy-version/window variant rejects replay; key unchanged. |
| R05 | Same nonce under two different publishers registers independently. |
| R06 | R=2: accept two distinct keys; third rejects capacity and preserves both live records. |
| R07 | Global=4, publisher=2: third same-publisher key rejects while another publisher can register. |
| R08 | Global/publisher=4, account=1: second same-publisher/account rejects; a new account or another publisher succeeds. |
| R09 | A consumed unexpired record continues to count against account, publisher and total limits, in that order (three isolated cap settings). |
| R10 | Publisher-rate=2: accept at 100/100, third at 159 rejects; at 160 old events expire and registration succeeds if record caps permit. |
| R11 | Global-event=2, R=1: short-lived registrations across three publishers at 100/101/102 reject the third with (0,2), despite record cleanup. |
| R12 | Expired unrelated record/event cleanup persists when a later duplicate or cap rejection occurs; no event for the failed attempt. |
| C01 | Exact registered input at 150 changes issued to consumed once. |
| C02 | Second exact claim at 150 rejects replay; retained counts unchanged. |
| C03 | Seven binding/window substitutions each reject replay; exact original subsequently succeeds at the same floor. |
| C04 | Missing key at a valid window returns StateUnavailable; unrelated issued record remains usable. |
| C05 | Claim at exact issue succeeds; isolated cache at 199 succeeds; at 200 and 201 rejects Expired before lookup. |
| C06 | On a fresh cache with no registered input or floor, claim for 100..200 at 99 rejects NotYetValid before lookup; observe 98 then rejects ClockRollback. Registering at 100 first would instead make claim99 a rollback. |
| C07 | After a valid raw claim, unrelated later mock failure never releases the consumed record. |
| C08 | Claim does no GC: unrelated expired record/event slots remain until explicit purge or eligible registration cleanup. |
| G01 | Record retained at 199; at 200 removed with count 1; repeated purge returns 0. |
| G02 | Issued and consumed records both removed only at expiry (isolated variants). |
| G03 | Event at 100 retained at 159 and removed at 160; record remains until 200; return counts exclude events. |
| G04 | Shared handle created before purge sees deletions afterward. |
| G05 | Purge at lower time rejects rollback and deletes nothing. |
| G06 | Near-maximum timestamp event: checked subtraction avoids addition overflow; exact age boundary behavior. |
| G07 | Mixed expired/live slots: remove only eligible ones and return exact record count; slots reused. |
| G08 | After purge, old exact input remains Expired; same publisher/nonce with newly valid 200..300 window follows normal registration and can be consumed once. |
| X01 | Two concurrent claims produce exactly one Ok and one ReplayDetected. |
| X02 | Two concurrent same-key registrations produce exactly one Ok, one replay and one retained event. |
| X03 | Two concurrent distinct-key registrations at final total/publisher/account/rate/global-event slot: exactly one succeeds for each isolated limiting policy. |
| X04 | Loss drops records/events/floor; every old clone's observe/register/claim/purge/stats returns StateUnavailable. |
| X05 | Repeated loss is Ok on unpoisoned Lost; fresh independent run can use same synthetic input but cannot restore old clones. |
| X06 | Poisoned mutex then each operation fails closed; future-event internal corruption on cleanup becomes Lost before deletion; no resumed state. |
| X07 | Real claim/loss race permits only claim-before-loss success or StateUnavailable; afterward all old handles unavailable; deterministic ordered cases cover both sides. |
| X08 | Independent reference trace: observe100, register key1, mismatched claim150, observe149, exact claim150, duplicate claim150, register key2 at150, purge160, purge200, old exact claim200. Compare errors/counts where exposed; expected sequence has rollback/replay/expiry at the named actions. |
| P01 | Limits/Cache/Stats Debug are their exact three fixed redacted strings for empty/populated/consumed state. |
| P02 | Debug of Lost and poisoned cache is fixed, never locks, and does not leak identifiers or floor. |
| P03 | Every FreshnessError Debug/Display remains field-free; no new source-chain diagnostic surface. |
| P04 | Captured real child-test formatting/failure output contains only approved fixed diagnostics and no synthetic value sentinel. |
| P05 | Captured actual poison-thread failure output uses a fixed message and does not dump state, inputs or pointers. |

Rows referring to invalid/reversed windows cannot use a nonexistent invalid public constructor. Positive-duration validation is tested through the approved typed constructor and the candidate lifetime recheck. Do not forge private model fields to manufacture an unreachable external input.

## Task 7: Compile-time authority and feature probes

**Files:** rustdoc examples in `mock_replay.rs`; ignored standalone probe crates under SDD. No external dependency or tracked probe package.

**Interfaces:** Produces three explicit compile probes F01–F03 plus compile-pass controls; these are not part of the 57 runtime functions.

- [ ] F01: build a temporary standalone Cargo project with an absolute path dependency on the execution checkout's `ogir-verifier`, `default-features = false`, without the research feature. A source containing `use ogir_verifier::mock_replay::MockReplayCache; fn main() {}` must fail because the module is feature-gated. A control importing `ogir_verifier::ReplayStore` and an empty main must compile. Construct the TOML path with a proper serializer, not shell substitution.
- [ ] F02: enable `research-mock-replay` in the path dependency; compile-pass import and type-use controls precede the following expected trait-bound failure:

```rust
use ogir_verifier::{ReplayStore, mock_replay::MockReplayCache};
fn requires_durable<T: ReplayStore>() {}
fn main() { requires_durable::<MockReplayCache>(); }
```

- [ ] F03: with the feature enabled and the existing model path dependency, require an expected return-type mismatch. A companion returning `Result<(), FreshnessError>` must compile.

```rust
use ogir_model::{FreshnessError, UnixTime};
use ogir_verifier::{FreshnessChecked, ReplayRegistration, mock_replay::MockReplayCache};
fn forged(cache: &MockReplayCache, registration: &ReplayRegistration)
    -> Result<FreshnessChecked, FreshnessError> {
    cache.claim(UnixTime::new(100), registration)
}
fn main() {}
```

- [ ] Capture cargo JSON diagnostics and require the intended E0432 missing-module, E0277 trait-bound or E0308 mismatched-type error naming the involved API; reject missing dependencies, syntax errors, unrelated compiler failures and zero compile-pass controls. Mirror F02/F03 in documented compile-fail examples under the feature. Run `cargo test -p ogir-verifier --features research-mock-replay --doc` and default/all-feature workspace builds. Record controls and failures separately; do not fabricate a runtime success count for compiler rejection.

## Task 8: Documentation, ADR review and complete regression

**Files:** approved issue, scoped docs listed above, ADR/index; no security-invariant/production-protocol changes.

**Interfaces:** Produces accurate implementation evidence tied to the actual code, an independently reviewed research-boundary ADR and fresh complete gate results.

- [ ] Add a test-strategy section separating 57 planned runtime rows, actual named tests, F01–F03 probes, literal/differential/concurrent checks and mutation detections. Replace planned counts only with observed counts after reconciling all names. Cite existing M1-008 tests as unchanged reference evidence, not new mock coverage.
- [ ] Document the default-off module, no durable trait implementation, fixed policies, event-cap and payload-versus-heap distinction, lazy purge and terminal loss. Record old-registration expiry versus newly valid same-key reuse; do not promise lifetime nonce uniqueness.
- [ ] Append a new dated lesson, preserving every earlier completed entry: forgetting an expired key cannot support a permanent uniqueness claim; exact-old-window rejection and issuer responsibility are distinct.
- [ ] Keep the ADR Proposed until the human accepts it. Obtain independent implementation review on authority, operation order, resource/retention/privacy, and model/CI coverage; a reviewer must see the candidate and approved spec, not just a controller summary. Fix confirmed findings with targeted RED/GREEN and record every disposition.
- [ ] Run fresh gates after final edits, preserving command output, exit, tool version and source hashes:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --no-default-features
cargo test --workspace --all-features
cargo test --workspace --all-features --release
cargo doc --workspace --no-deps --all-features
python3 -Werror scripts/check-m1-013-plan-registry.py
python3 -Werror scripts/test-m1-013-plan-registry.py
python3 -Werror scripts/test-bounded-json.py
python3 -Werror scripts/test-abstract-conformance.py
python3 -Werror scripts/test-history-conformance.py
python3 -Werror scripts/test-attack-scenario-parity.py
python3 -Werror scripts/test-conformance-accounting.py
python3 -Werror scripts/test-conformance-accounting-reference.py
python3 -Werror scripts/test-conformance-documentation.py
bash scripts/check.sh
```

Set `PYTHONDONTWRITEBYTECODE=1` and `RUSTDOCFLAGS=-D warnings` through the runner. Do not change HOME or other system variables. Metadata/ADR checks on new files use a temporary candidate index; preserve the real index until staging is authorized. Run `cargo deny check` explicitly if the aggregate gate reports it unavailable; tool absence is a limitation, not a pass.

- [ ] Reconcile runtime selectors: the 56 expected library names appear exactly once in `cargo test -p ogir-verifier --features research-mock-replay --lib -- --list`; `mock_replay_reference::case_x08` appears exactly once in `cargo test -p ogir-verifier --features research-mock-replay --test freshness -- --list`. Their union is the 57-row inventory, with no missing or duplicate IDs. Confirm every intended row ran in the final suite. Additional necessary regressions receive explicit new IDs and an updated reviewed count, not silent row replacement. Checkpoint.

## Task 9: Mutation evidence, final review and freeze

**Files:** ignored SDD mutation harness/copies/manifests/reports; source corrections only for validated findings.

**Interfaces:** Consumes passing runtime/probe inventory. Produces exact variant patches, first-cause detector failures, restored passes, final scope report and frozen candidate tree/patch/file hashes.

The following **24 planned semantic variants** each require one separately saved physical source change, an intended detector and verified restoration. The selector is `mock_replay::tests::case_<id>` unless F01/F02/F03. Record full commands and source SHA-256 before mutation, after mutation and after restoration. Source-only compile breakage is never a successful detector.

| Mutation | Exact behavioral change | Primary detector |
| --- | --- | --- |
| M01 | In `advance`, remove the lower-than-floor rejection. | T03 |
| M02 | In `register`, move advance after the window rejection. | T04 |
| M03 | In `claim`, move advance after the binding rejection. | T05 |
| M04 | In `register`, omit the fixed maximum-lifetime comparison. | R02 |
| M05 | In duplicate registration lookup, include binding equality so same-key altered bindings no longer collide. | R04 |
| M06 | In the publisher/account record-cap count, exclude consumed records. | R09 |
| M07 | Omit the total-record cap comparison. Preserve source validity; select a test-only backing spare slot so the intended cap, not a missing slot, rejects. | R06 |
| M08 | Omit publisher-record cap comparison. | R07 |
| M09 | Scope account count without publisher equality, causing cross-publisher over-rejection. | R08 |
| M10 | Omit per-publisher issuance-event cap comparison. | R10 |
| M11 | Omit global event cap comparison; use one extra test-only backing slot to expose policy enforcement rather than storage exhaustion. | R11 |
| M12 | Add an issuance event on capacity rejection when a vacant event slot exists. | R06 |
| M13 | In `claim`, omit stored binding comparison. | C03 |
| M14 | In `claim`, omit stored window comparison, retaining supplied-window evaluation. | C03 |
| M15 | In `claim`, omit the consumed-flag rejection. | C02 |
| M16 | In `claim`, omit `record.consumed = true`. | C02 |
| M17 | Split claim validation and consumption across two locks with no revalidation; mutation-only barrier forces both validations first. | X01 |
| M18 | Record purge predicate changes expiry `<= floor` to `< floor`. | G01 |
| M19 | Event purge age comparison changes `>= window` to `> window`. | G03 |
| M20 | `observe_time` additionally collects expired state. | T06 |
| M21 | `simulate_state_loss` becomes an Ok no-op, retaining available state. | X04 |
| M22 | `lock_state` returns the poisoned inner guard and resumes operations instead of losing state. | X06 |
| M23 | Cache Debug appends one retained publisher identifier. | P04 |
| M24 | Add a public `impl ReplayStore for MockReplayCache` delegating observe/register/claim/purge to mock methods; registration ignores the supplied per-call limits. | F02 |

M07/M11 patches explicitly include a private test-only extra backing slot so a missing slot cannot mask the policy mutant. Correct-source A08 independently proves spare allocation capacity is not additional logical storage. These are controlled semantic variants, not production storage-layout changes. Capture both patch hunks and label the extra slot as detector setup.

M17's mutation alone inserts a synchronization call between releasing the validation lock and acquiring the mutation lock. The same mutation patch introduces this private unit-test helper; it is absent from correct source and only the selected X01 mutation invokes it:

```rust
pub(super) fn wait_between_check_and_commit() {
    static BETWEEN: std::sync::OnceLock<std::sync::Barrier> = std::sync::OnceLock::new();
    BETWEEN.get_or_init(|| std::sync::Barrier::new(2)).wait();
}
```

Call it as `tests::wait_between_check_and_commit()` at the split-lock point in the mutant. Correct-source X01 still uses its real start Barrier and never invokes this helper. Run only its exact selector, with an outer deadline; timeout/deadlock is an invalid attempt rather than an assertion kill. Save the full split-lock method replacement and the helper before running; a marker comment alone is not a distinct mutant.

M24's expected failure is F02 unexpectedly compiling after its compile-pass control succeeds. This is a compile-boundary detector, recorded separately from runtime assertion-RED counts. P04 is an actual captured-output detector. Do not sum these into fictitious assertion counts or claim each variant proves every related guard.

- [ ] Freeze the pre-campaign candidate bytes and exact mutation patches. For each variant, run a normal-source detector first, apply in an isolated copy, establish the intended runtime/probe violation, restore exact bytes, rerun GREEN and verify hashes. No parallel mutation of shared candidate files.
- [ ] Invalid attempts retain logs and are rerun only after correcting the harness; never overwrite their history. Record selected subtests and actual first cause, not just nonzero exit. No broad suite crash counts as intended failure.
- [ ] Independently review the campaign, full change and spec compliance. Close every Critical/Important finding and disposition Minor findings. Re-run affected gates after fixes; repeat the campaign rows whose source/detector meaning changed.
- [ ] Run final Task 8 gates on the exact final source after every correction. Use a temporary index to include only the reviewed paths, run metadata/ADR/diff checks, write the candidate tree and binary patch, save all file hashes, and prove the real index unchanged. Record implementation limits and all external changes in shared memory. Stop for exact candidate line review/DCO before Task 10.

## Task 10: Guarded commit and publication handoff

**Files:** ignored acceptance/freeze/publication evidence and shared memory. No source changes after certification without renewed review.

**Interfaces:** Consumes exact human-certified candidate and separate Git/publication authorization. Produces a signed local commit, then only separately authorized remote artifacts.

- [ ] Obtain exact human line review/DCO certification for the frozen Task 14 candidate. Prior M1-013 certification is insufficient. Reverify identity, exact trailer, candidate tree/patch/file hashes and current branch before staging.
- [ ] Only when authorized, stage the reviewed paths and create the signed local commit. Verify parent/tree, signature, author/committer, exact message/trailer and DCO range. No automatic amend or rebase.
- [ ] Only when authorized, ordinary non-force push and exact remote readback.
- [ ] Prepare concrete issue/PR bodies with observed evidence, synthetic-data scope, feature boundary, AI disclosure and remaining limits. Publish only with authorization; verify remote body hashes and exact head/base/author. A push alone authorizes neither issue nor PR creation.
- [ ] Read CI/DCO/CodeQL results accurately. Final line review and web-only merge remain human actions. Refresh shared memory and keep completed records append-only.

## Coverage and completion ledger

| Approved spec area | Plan task / evidence |
| --- | --- |
| Sections 1–2: authority and compatibility | Tasks 1, 7, 8; unchanged durable/reference contracts, F01–F03 |
| Section 3: API/feature/traits | Tasks 2, 7; A01–A08, compile-pass controls |
| Section 4: state/atomicity | Tasks 2, 4–6; X01–X07, M17 |
| Section 5: exact ordering/side effects | Tasks 3–5; T/R/C rows |
| Section 6: bounds/retention/allocation | Tasks 2–4; A05–A08, R06–R12, G01–G08 |
| Section 7: loss/distinct runs | Tasks 2, 6; X04–X07, G08 |
| Section 8: diagnostics/privacy | Tasks 2, 6; P01–P05, M23 |
| Section 9: independent tests/mutations/gates | Tasks 6–9; X08, F01–F03, 24 mutations |
| Sections 10–11: scope/source evidence | Tasks 1, 8; ADR, source hashes, focused docs |
| Section 12: approval/integration | Tasks 1, 10; merge prerequisite, exact DCO/publication gates |

A plan-review pass means the specification maps to concrete tasks and inventories; it is not evidence that a compiler, runtime test, mutation or GitHub gate has run. Implementation may start only from the verified merged baseline with the user's execution direction. Use the chosen SDD or inline executing-plans workflow; the planning self-review itself requires no subagent.

## Execution refinements recorded 2026-09-04

Task 1 verified human merge `78fe4b911f13c1d19366fdb3822c5b6bf49962f8`
with the exact certified tree and preserved sign-offs. The original approved
issue and original plan hashes remain in the scoping review evidence. The
implementation issue adds canonical labels/milestone metadata consumed by
bootstrap tooling; this does not change the behavior specification.

The existing root-source authority inventory requires a narrow test-only
update in `crates/ogir-verifier/src/verification/tests.rs` for the approved
feature-gated module. Its exact-equality scanner stays strict, with additional
negative feature/exposure probes and the existing sibling macro audit applied
to the new module.

X08 belongs to the existing external `freshness` target. A separate integration
target compiled the entire unchanged reference support again with unused items
and failed Clippy. Sharing that existing target preserves reference independence
without lint suppressions, dummy calls, extra public visibility or changes to
any existing test body. Final inventory remains 56 library tests plus one new
external test; its exact selector is `mock_replay_reference::case_x08`.

Final review also required refreshing the issue/spec's mutable status and
integration notes: written-design approval and the human merge are complete;
local code now exists. The original approval hashes identify the earlier
reviewed bytes, while final candidate hashes include these factual updates.
