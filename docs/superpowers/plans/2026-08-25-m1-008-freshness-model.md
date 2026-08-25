# M1-008 Challenge Freshness Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace ad hoc challenge timestamps with a typed strict validity window and a database-neutral, atomic, durable replay-state contract that fails closed across replay, clock rollback, restart, and capacity failure.

**Architecture:** `ogir-model` owns dependency-free time, window, limit, and error value types. `ogir-verifier::freshness` owns replay identity/binding types and one deep synchronous guard over an atomic `ReplayStore` contract; that guard is the only constructor of `FreshnessChecked`, and the existing research verifier uses it before evidence appraisal. A test-only reference store proves persistence, concurrency, restart, garbage-collection, and capacity semantics without selecting a production database.

**Tech Stack:** Rust 1.98.0, edition 2024, standard library only, Cargo workspace tests, rustfmt, Clippy, rustdoc, shell-based repository gates.

**Spec:** `docs/superpowers/specs/2026-08-25-m1-008-freshness-model-design.md`

## Global Constraints

- Begin from verified `main` commit `883f8adb4672b8748365b6a254ff9626d8773399` or a later reviewed descendant containing M1-007.
- Read the spec, `docs/SECURITY_INVARIANTS.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, and issue #8 before editing.
- Use strict `issued_at <= verifier_now < expires_at`; acceptance leeway is exactly zero.
- The game, bridge, attester, and local client never supply authoritative time or nonce state.
- Replay identity is exactly `(PublisherId, Nonce)`; context never becomes part of the key.
- Register replay state durably before returning a challenge; claim it atomically and irreversibly before expensive appraisal.
- Missing, corrupt, unavailable, rolled-back, or capacity-exhausted freshness state fails closed without stateless fallback.
- Retain every issued/consumed record through expiry; never evict an unexpired record.
- Every lifetime, capacity, account, and issuance-rate limit is explicit, finite, nonzero, and has no default.
- Do not add a database, clock, random-number, async, serialization, cryptographic, or unsafe-code dependency.
- Start every new Rust source/test file with `// SPDX-License-Identifier: Apache-2.0` and document every new public item.
- Errors and debug output never include nonce bytes, `AccountScope`, `MatchId`, or raw replay bindings.
- Freshness failures are non-disciplinary and never prove cheating or trigger a ban.
- Write negative tests first and observe the expected RED result before production behavior in Tasks 1–5.
- Commit each task as one independently reviewable unsigned slice under `Wisbendji Fimerlus <archledger236@gmail.com>`; DCO sign-off requires a later explicit human certification of the final frozen range.

## File and Responsibility Map

- Create `crates/ogir-model/src/freshness.rs`: pure time/window/limit types and `FreshnessError`.
- Modify `crates/ogir-model/src/lib.rs`: expose freshness types and replace raw challenge timestamps with `ChallengeWindow`.
- Create `crates/ogir-model/tests/freshness.rs`: independent literal boundary and overflow contracts.
- Create `crates/ogir-verifier/src/freshness.rs`: `ReplayStore`, `FreshnessGuard`, replay registration, and private-constructor `FreshnessChecked`.
- Modify `crates/ogir-verifier/src/lib.rs`: export freshness interfaces and require an atomic freshness claim in `verify_research_structure`.
- Create `crates/ogir-verifier/tests/support/mod.rs`: test-support module boundary.
- Create `crates/ogir-verifier/tests/support/reference_replay_store.rs`: mutex-protected reference implementation used only by integration tests.
- Create `crates/ogir-verifier/tests/freshness.rs`: registration, replay, rollback, restart, capacity, GC, concurrency, and arbitrary-sequence tests.
- Create `docs/adr/0005-verifier-authoritative-challenge-freshness.md`: accepted decision and alternatives.
- Modify `docs/adr/index.md`: register ADR-0005.
- Modify `docs/SECURITY_INVARIANTS.md`: replace the scaffold freshness invariants with the accepted strict-window, durable-state rules.
- Modify `docs/ARCHITECTURE.md`: current freshness/replay flow and authority.
- Modify `docs/THREAT_MODEL.md`: replay/clock/store threats and responses.
- Modify `docs/TEST_STRATEGY.md`: new deterministic and mutation coverage.
- Create `lab/scenarios/challenge-replay.yml`: executable attacker narrative for same-key reuse across contexts/restart.
- Create `lab/scenarios/freshness-state-failure.yml`: fail-closed rollback/unavailable-state narrative.
- Modify `planning/issues/008-freshness-model.md`: keep sources/metadata synchronized with live issue #8; change workflow status only through the triage process.

---

### Task 0: Advance the Approved Research Issue to Ready

**Files:**
- Modify: `planning/issues/008-freshness-model.md:2`
- External write after local commit: GitHub issue #8 body and workflow label

**Interfaces:**
- Consumes: the committed approved design and maintainer approval recorded before this plan.
- Produces: one local/live canonical issue source at `status: ready` before implementation begins.

- [ ] **Step 1: Reconfirm the exact precondition**

```bash
test "$(git rev-parse main)" = 883f8adb4672b8748365b6a254ff9626d8773399
test "$(git rev-parse origin/main)" = 883f8adb4672b8748365b6a254ff9626d8773399
test "$(sed -n '2p' planning/issues/008-freshness-model.md)" = '<!-- labels: type: architecture,area: protocol,risk: cryptography,status: needs-research -->'
test "$(gh api repos/archledger/open-game-integrity-runtime/issues/8 --template '{{.body}}' | sha256sum | cut -d' ' -f1)" = "$(sha256sum planning/issues/008-freshness-model.md | cut -d' ' -f1)"
test "$(gh issue view 8 --repo archledger/open-game-integrity-runtime --json labels --jq '[.labels[].name] | sort | join("|")')" = 'area: protocol|risk: cryptography|status: needs-research|type: architecture'
```

Expected: all checks pass. If main moved or the live issue changed, stop and
rebase/review or reconcile the external change before editing metadata.

- [ ] **Step 2: Apply and verify the policy-defined transition**

Change only line 2 to:

```markdown
<!-- labels: type: architecture,area: protocol,risk: cryptography,status: ready -->
```

Then run:

```bash
./scripts/test-repository-metadata.sh
./scripts/check-repository-metadata.sh
git diff --check
git diff -- planning/issues/008-freshness-model.md
```

Expected: both metadata gates pass and the diff contains only the workflow
label transition.

- [ ] **Step 3: Commit locally, then synchronize the live issue**

```bash
git add planning/issues/008-freshness-model.md
git diff --cached --check
git commit -m "chore: mark M1-008 ready"
gh issue edit 8 --repo archledger/open-game-integrity-runtime \
  --body-file planning/issues/008-freshness-model.md \
  --remove-label 'status: needs-research' \
  --add-label 'status: ready'
gh api repos/archledger/open-game-integrity-runtime/issues/8 --template '{{.body}}' | sha256sum
sha256sum planning/issues/008-freshness-model.md
gh issue view 8 --repo archledger/open-game-integrity-runtime \
  --json labels,milestone,state \
  --jq '{labels: [.labels[].name] | sort, milestone: .milestone.title, state}'
```

Expected: body hashes match; the issue is open in `M1 Domain Model` with
exactly `area: protocol`, `risk: cryptography`, `status: ready`, and
`type: architecture`.

If post-write verification fails, restore the known prior body and workflow
label before stopping:

```bash
gh issue edit 8 --repo archledger/open-game-integrity-runtime \
  --body-file <(git show HEAD^:planning/issues/008-freshness-model.md) \
  --remove-label 'status: ready' \
  --add-label 'status: needs-research'
```

---

### Task 1: Add Pure Time, Window, and Limit Types

**Files:**
- Create: `crates/ogir-model/src/freshness.rs`
- Modify: `crates/ogir-model/src/lib.rs:1-35`
- Test: `crates/ogir-model/tests/freshness.rs`

**Interfaces:**
- Consumes: standard-library `NonZeroU64` and `NonZeroUsize` only.
- Produces: `UnixTime`, `ChallengeLifetime`, `ChallengeWindow`, `FreshnessLimits`, and `FreshnessError` with the exact signatures below.

- [ ] **Step 1: Write the failing pure-model boundary tests**

Create `crates/ogir-model/tests/freshness.rs` with literal expectations independent of production constants:

```rust
// SPDX-License-Identifier: Apache-2.0

use std::num::{NonZeroU64, NonZeroUsize};

use ogir_model::{
    ChallengeLifetime, ChallengeWindow, FreshnessError, FreshnessLimits, UnixTime,
};

fn nonzero_u64(value: u64) -> NonZeroU64 {
    match NonZeroU64::new(value) {
        Some(value) => value,
        None => panic!("fixture must be nonzero"),
    }
}

fn nonzero_usize(value: usize) -> NonZeroUsize {
    match NonZeroUsize::new(value) {
        Some(value) => value,
        None => panic!("fixture must be nonzero"),
    }
}

fn window(issued: u64, expires: u64, maximum: u64) -> ChallengeWindow {
    match ChallengeWindow::new(
        UnixTime::new(issued),
        UnixTime::new(expires),
        ChallengeLifetime::new(nonzero_u64(maximum)),
    ) {
        Ok(window) => window,
        Err(error) => panic!("valid fixture rejected: {error:?}"),
    }
}

#[test]
fn half_open_window_has_zero_leeway() {
    let window = window(100, 200, 100);
    assert_eq!(window.evaluate(UnixTime::new(99)), Err(FreshnessError::NotYetValid));
    assert_eq!(window.evaluate(UnixTime::new(100)), Ok(()));
    assert_eq!(window.evaluate(UnixTime::new(199)), Ok(()));
    assert_eq!(window.evaluate(UnixTime::new(200)), Err(FreshnessError::Expired));
    assert_eq!(window.evaluate(UnixTime::new(201)), Err(FreshnessError::Expired));
}

#[test]
fn invalid_and_excessive_windows_fail_without_overflow() {
    let maximum = ChallengeLifetime::new(nonzero_u64(100));
    assert_eq!(
        ChallengeWindow::new(UnixTime::new(100), UnixTime::new(100), maximum),
        Err(FreshnessError::InvalidWindow)
    );
    assert_eq!(
        ChallengeWindow::new(UnixTime::new(101), UnixTime::new(100), maximum),
        Err(FreshnessError::InvalidWindow)
    );
    assert_eq!(
        ChallengeWindow::new(UnixTime::new(100), UnixTime::new(201), maximum),
        Err(FreshnessError::LifetimeExceeded)
    );
    let extreme = match ChallengeWindow::new(
        UnixTime::new(u64::MAX - 1),
        UnixTime::new(u64::MAX),
        maximum,
    ) {
        Ok(window) => window,
        Err(error) => panic!("ordered near-maximum window rejected: {error:?}"),
    };
    assert_eq!(extreme.issued_at().seconds(), u64::MAX - 1);
    assert_eq!(extreme.expires_at().seconds(), u64::MAX);
    assert_eq!(
        extreme.evaluate(UnixTime::new(150)),
        Err(FreshnessError::NotYetValid)
    );
}

#[test]
fn limits_are_explicit_and_nonzero() {
    let limits = FreshnessLimits::new(
        ChallengeLifetime::new(nonzero_u64(120)),
        nonzero_usize(1_000),
        nonzero_usize(100),
        nonzero_usize(4),
        nonzero_u64(60),
        nonzero_usize(20),
    );
    assert_eq!(limits.max_lifetime().seconds().get(), 120);
    assert_eq!(limits.max_outstanding_total().get(), 1_000);
    assert_eq!(limits.max_outstanding_per_publisher().get(), 100);
    assert_eq!(limits.max_outstanding_per_account().get(), 4);
    assert_eq!(limits.issuance_rate_window_seconds().get(), 60);
    assert_eq!(limits.max_issuances_per_publisher().get(), 20);
}
```

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
cargo test -p ogir-model --test freshness
```

Expected: compilation fails only because the five new public freshness types do not exist.

- [ ] **Step 3: Implement the minimal pure types**

Create `crates/ogir-model/src/freshness.rs` with these exact public contracts:

```rust
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fmt;
use std::num::{NonZeroU64, NonZeroUsize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(u64);

impl UnixTime {
    #[must_use]
    pub const fn new(seconds: u64) -> Self { Self(seconds) }

    #[must_use]
    pub const fn seconds(self) -> u64 { self.0 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeLifetime(NonZeroU64);

impl ChallengeLifetime {
    #[must_use]
    pub const fn new(seconds: NonZeroU64) -> Self { Self(seconds) }

    #[must_use]
    pub const fn seconds(self) -> NonZeroU64 { self.0 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeWindow {
    issued_at: UnixTime,
    expires_at: UnixTime,
}

impl ChallengeWindow {
    pub fn new(
        issued_at: UnixTime,
        expires_at: UnixTime,
        maximum: ChallengeLifetime,
    ) -> Result<Self, FreshnessError> {
        let duration = expires_at
            .seconds()
            .checked_sub(issued_at.seconds())
            .ok_or(FreshnessError::InvalidWindow)?;
        if duration == 0 {
            return Err(FreshnessError::InvalidWindow);
        }
        if duration > maximum.seconds().get() {
            return Err(FreshnessError::LifetimeExceeded);
        }
        Ok(Self { issued_at, expires_at })
    }

    pub fn evaluate(self, now: UnixTime) -> Result<(), FreshnessError> {
        if now < self.issued_at {
            return Err(FreshnessError::NotYetValid);
        }
        if now >= self.expires_at {
            return Err(FreshnessError::Expired);
        }
        Ok(())
    }

    #[must_use]
    pub const fn issued_at(self) -> UnixTime { self.issued_at }

    #[must_use]
    pub const fn expires_at(self) -> UnixTime { self.expires_at }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessLimits {
    max_lifetime: ChallengeLifetime,
    max_outstanding_total: NonZeroUsize,
    max_outstanding_per_publisher: NonZeroUsize,
    max_outstanding_per_account: NonZeroUsize,
    issuance_rate_window_seconds: NonZeroU64,
    max_issuances_per_publisher: NonZeroUsize,
}

impl FreshnessLimits {
    #[must_use]
    pub const fn new(
        max_lifetime: ChallengeLifetime,
        max_outstanding_total: NonZeroUsize,
        max_outstanding_per_publisher: NonZeroUsize,
        max_outstanding_per_account: NonZeroUsize,
        issuance_rate_window_seconds: NonZeroU64,
        max_issuances_per_publisher: NonZeroUsize,
    ) -> Self {
        Self {
            max_lifetime,
            max_outstanding_total,
            max_outstanding_per_publisher,
            max_outstanding_per_account,
            issuance_rate_window_seconds,
            max_issuances_per_publisher,
        }
    }

    #[must_use]
    pub const fn max_lifetime(self) -> ChallengeLifetime { self.max_lifetime }

    #[must_use]
    pub const fn max_outstanding_total(self) -> NonZeroUsize {
        self.max_outstanding_total
    }

    #[must_use]
    pub const fn max_outstanding_per_publisher(self) -> NonZeroUsize {
        self.max_outstanding_per_publisher
    }

    #[must_use]
    pub const fn max_outstanding_per_account(self) -> NonZeroUsize {
        self.max_outstanding_per_account
    }

    #[must_use]
    pub const fn issuance_rate_window_seconds(self) -> NonZeroU64 {
        self.issuance_rate_window_seconds
    }

    #[must_use]
    pub const fn max_issuances_per_publisher(self) -> NonZeroUsize {
        self.max_issuances_per_publisher
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessError {
    InvalidWindow,
    LifetimeExceeded,
    NotYetValid,
    Expired,
    ReplayDetected,
    ClockRollback,
    StateUnavailable,
    CapacityExceeded,
}

impl fmt::Display for FreshnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidWindow => "challenge window is invalid",
            Self::LifetimeExceeded => "challenge lifetime exceeds policy",
            Self::NotYetValid => "challenge is not yet valid",
            Self::Expired => "challenge is expired",
            Self::ReplayDetected => "challenge nonce was already consumed",
            Self::ClockRollback => "authoritative clock moved backward",
            Self::StateUnavailable => "freshness state is unavailable",
            Self::CapacityExceeded => "freshness state capacity is exhausted",
        })
    }
}

impl Error for FreshnessError {}
```

Add `mod freshness;` and explicit `pub use freshness::{...};` in `crates/ogir-model/src/lib.rs`. Do not expose the module's private fields.

- [ ] **Step 4: Run focused model verification**

Run:

```bash
cargo fmt --all
cargo test -p ogir-model --test freshness
cargo clippy -p ogir-model --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc -p ogir-model --no-deps
```

Expected: all commands exit 0; three new tests pass.

- [ ] **Step 5: Commit the pure model slice**

```bash
git add crates/ogir-model/src/freshness.rs crates/ogir-model/src/lib.rs crates/ogir-model/tests/freshness.rs
git diff --cached --check
git commit -m "feat: add typed challenge freshness window"
```

---

### Task 2: Migrate Publisher Challenge and Verifier Time Inputs

**Files:**
- Modify: `crates/ogir-model/src/lib.rs:287-430`
- Modify: `crates/ogir-model/tests/identifiers.rs:230-275`
- Modify: `crates/ogir-verifier/src/lib.rs:1-230`
- Test: `crates/ogir-model/tests/freshness.rs`
- Test: existing verifier unit tests in `crates/ogir-verifier/src/lib.rs`

**Interfaces:**
- Consumes: `ChallengeWindow`, `ChallengeLifetime`, `UnixTime`, and `FreshnessError` from Task 1.
- Produces: `PublisherChallenge::window: ChallengeWindow` and `VerificationRequest::now: UnixTime`; removes raw public challenge timestamps and obsolete `ModelError` time validation.

- [ ] **Step 1: Add failing public migration tests**

Extend `crates/ogir-model/tests/freshness.rs` with a `PublisherChallenge` fixture using `window: ChallengeWindow`; update the verifier tests to construct `VerificationRequest { now: UnixTime::new(...) }`. Add the missing exact-issuance and just-before-expiry assertions:

```rust
#[test]
fn verifier_accepts_freshness_boundaries_before_failing_closed_on_evidence() {
    for now in [100, 199] {
        let request = VerificationRequest {
            challenge: challenge(),
            evidence: evidence(),
            expected: expected(),
            now: UnixTime::new(now),
        };
        let outcome = verify_research_structure(&request);
        assert_eq!(outcome.reason, ReasonCode::EvidenceInvalid);
    }
}
```

- [ ] **Step 2: Run model/verifier tests and verify RED**

```bash
cargo test -p ogir-model --test freshness
cargo test -p ogir-verifier
```

Expected: compile failures show raw `issued_at_unix_seconds`, `expires_at_unix_seconds`, and `now_unix_seconds` fields still exist while `window`/`now` do not.

- [ ] **Step 3: Replace raw fields and remove obsolete validation**

Change `PublisherChallenge` to:

```rust
pub struct PublisherChallenge {
    pub version: ProtocolVersion,
    pub publisher_id: PublisherId,
    pub game_id: GameId,
    pub build_id: BuildId,
    pub account_scope: AccountScope,
    pub match_id: MatchId,
    pub policy_id: PolicyId,
    pub policy_version: PolicyVersion,
    pub nonce: Nonce,
    pub window: ChallengeWindow,
}
```

Delete `PublisherChallenge::validate_structure`, `ModelError`, its `Display`/`Error` implementations, and the obsolete time-window unit tests from `lib.rs`. Window construction now makes invalid ordering/lifetime unrepresentable.

Change `VerificationRequest` to:

```rust
pub struct VerificationRequest {
    pub challenge: PublisherChallenge,
    pub evidence: EvidenceBundle,
    pub expected: ExpectedContext,
    pub now: UnixTime,
}
```

Replace current time checks with the typed evaluator and introduce the final
non-disciplinary mapping now, so no intermediate commit maps an operational
freshness failure to `Decision::Deny`:

```rust
if let Err(error) = request.challenge.window.evaluate(request.now) {
    return freshness_failure(error);
}

fn freshness_failure(error: FreshnessError) -> VerificationOutcome {
    match error {
        FreshnessError::InvalidWindow | FreshnessError::LifetimeExceeded => {
            denied(ReasonCode::Malformed)
        }
        FreshnessError::NotYetValid => denied(ReasonCode::NotYetValid),
        FreshnessError::Expired => denied(ReasonCode::Expired),
        FreshnessError::ReplayDetected => denied(ReasonCode::ReplayDetected),
        FreshnessError::ClockRollback
        | FreshnessError::StateUnavailable
        | FreshnessError::CapacityExceeded => VerificationOutcome {
            decision: Decision::Retry,
            reason: ReasonCode::AttestationUnavailable,
        },
    }
}
```

Update every `PublisherChallenge` and `VerificationRequest` fixture found by:

```bash
rg -n 'issued_at_unix_seconds|expires_at_unix_seconds|now_unix_seconds|PublisherChallenge \{|VerificationRequest \{' crates apps
```

- [ ] **Step 4: Verify migration and absence of raw time fields**

```bash
cargo fmt --all
cargo test -p ogir-model -p ogir-verifier
cargo clippy --workspace --all-targets --all-features -- -D warnings
if rg -n 'pub (issued_at_unix_seconds|expires_at_unix_seconds|now_unix_seconds):' crates apps; then exit 1; fi
if rg -n '\bModelError\b|validate_structure\(' crates apps; then exit 1; fi
```

Expected: all tests/Clippy pass and both obsolete-API scans return no matches.

- [ ] **Step 5: Commit the migration slice**

```bash
git add crates/ogir-model/src/lib.rs crates/ogir-model/tests/freshness.rs crates/ogir-model/tests/identifiers.rs crates/ogir-verifier/src/lib.rs
git diff --cached --check
git commit -m "refactor: type challenge freshness inputs"
```

---

### Task 3: Define Replay Identity and the Atomic Store Contract

**Files:**
- Create: `crates/ogir-verifier/src/freshness.rs`
- Modify: `crates/ogir-verifier/src/lib.rs:1-20`
- Create: `crates/ogir-verifier/tests/support/mod.rs`
- Create: `crates/ogir-verifier/tests/support/reference_replay_store.rs`
- Create: `crates/ogir-verifier/tests/freshness.rs`

**Interfaces:**
- Consumes: typed challenge/context/window/limit/error values from Tasks 1-2.
- Produces: `ReplayKey`, `ChallengeBinding`, `ReplayRegistration`, `ReplayStore`, `FreshnessGuard`, and private-constructor `FreshnessChecked`.

- [ ] **Step 1: Write failing replay identity and lifecycle tests**

Create `crates/ogir-verifier/tests/freshness.rs` with `mod support;` and these initial contracts:

```rust
// SPDX-License-Identifier: Apache-2.0

mod support;

use std::fmt::Debug;
use std::num::{NonZeroU64, NonZeroUsize};

use ogir_model::{
    AccountScope, BuildId, ChallengeLifetime, ChallengeWindow, FreshnessError,
    FreshnessLimits, GameId, IdentifierError, MatchId, Nonce, PolicyId, PolicyVersion,
    ProtocolVersion, PublisherChallenge, PublisherId, UnixTime,
};
use ogir_verifier::FreshnessGuard;
use support::ReferenceReplayStore;

#[test]
fn same_publisher_nonce_is_single_use_across_bindings() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits());
    let first = challenge("example.game", [7; 32]);
    let changed = challenge("other.game", [7; 32]);

    assert_eq!(guard.register(UnixTime::new(100), &first), Ok(()));
    assert_eq!(
        guard.register(UnixTime::new(100), &changed),
        Err(FreshnessError::ReplayDetected)
    );
    assert!(guard.claim(UnixTime::new(100), &first).is_ok());
    assert_eq!(
        guard.claim(UnixTime::new(100), &changed),
        Err(FreshnessError::ReplayDetected)
    );
}

#[test]
fn identical_nonce_bytes_are_independent_across_publishers() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits());
    let first = challenge_for_publisher("publisher-one", [9; 32]);
    let second = challenge_for_publisher("publisher-two", [9; 32]);

    assert_eq!(guard.register(UnixTime::new(100), &first), Ok(()));
    assert_eq!(guard.register(UnixTime::new(100), &second), Ok(()));
    assert!(guard.claim(UnixTime::new(100), &first).is_ok());
    assert!(guard.claim(UnixTime::new(100), &second).is_ok());
}

#[test]
fn unavailable_store_never_returns_freshness_capability() {
    let store = ReferenceReplayStore::unavailable();
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(
        guard.register(UnixTime::new(100), &challenge("example.game", [3; 32])),
        Err(FreshnessError::StateUnavailable)
    );
}
```

Define these fixture helpers in the test file; they use literal values and do
not call production code to compute expected outcomes:

```rust
fn identifier<T>(value: &str) -> T
where
    T: Debug,
    for<'a> T: TryFrom<&'a str, Error = IdentifierError>,
{
    match T::try_from(value) {
        Ok(value) => value,
        Err(error) => panic!("valid fixture rejected: {error:?}"),
    }
}

fn nonzero_u64(value: u64) -> NonZeroU64 {
    match NonZeroU64::new(value) {
        Some(value) => value,
        None => panic!("fixture must be nonzero"),
    }
}

fn nonzero_usize(value: usize) -> NonZeroUsize {
    match NonZeroUsize::new(value) {
        Some(value) => value,
        None => panic!("fixture must be nonzero"),
    }
}

fn limits() -> FreshnessLimits {
    FreshnessLimits::new(
        ChallengeLifetime::new(nonzero_u64(100)),
        nonzero_usize(16),
        nonzero_usize(8),
        nonzero_usize(2),
        nonzero_u64(60),
        nonzero_usize(8),
    )
}

fn valid_window(issued_at: u64, expires_at: u64) -> ChallengeWindow {
    match ChallengeWindow::new(
        UnixTime::new(issued_at),
        UnixTime::new(expires_at),
        ChallengeLifetime::new(nonzero_u64(100)),
    ) {
        Ok(window) => window,
        Err(error) => panic!("valid window rejected: {error:?}"),
    }
}

fn challenge_for_publisher(publisher: &str, nonce: [u8; 32]) -> PublisherChallenge {
    PublisherChallenge {
        version: ProtocolVersion { major: 0, minor: 1 },
        publisher_id: identifier::<PublisherId>(publisher),
        game_id: identifier::<GameId>("example.game"),
        build_id: identifier::<BuildId>("build-1"),
        account_scope: identifier::<AccountScope>("account-1"),
        match_id: identifier::<MatchId>("match-1"),
        policy_id: identifier::<PolicyId>("research-v0"),
        policy_version: PolicyVersion::new(1),
        nonce: Nonce::from_bytes(nonce),
        window: valid_window(100, 200),
    }
}

fn challenge(game: &str, nonce: [u8; 32]) -> PublisherChallenge {
    let mut challenge = challenge_for_publisher("example.publisher", nonce);
    challenge.game_id = identifier::<GameId>(game);
    challenge
}

fn challenge_for_account(
    publisher: &str,
    account: &str,
    nonce: [u8; 32],
) -> PublisherChallenge {
    let mut challenge = challenge_for_publisher(publisher, nonce);
    challenge.account_scope = identifier::<AccountScope>(account);
    challenge
}

fn challenge_with_window(
    publisher: &str,
    nonce: [u8; 32],
    issued_at: u64,
    expires_at: u64,
) -> PublisherChallenge {
    let mut challenge = challenge_for_publisher(publisher, nonce);
    challenge.window = valid_window(issued_at, expires_at);
    challenge
}
```

- [ ] **Step 2: Run the test and verify RED**

```bash
cargo test -p ogir-verifier --test freshness
```

Expected: compile failure for missing freshness module interfaces and test support.

- [ ] **Step 3: Add the production contract**

Create `crates/ogir-verifier/src/freshness.rs` with these public shapes:

```rust
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use ogir_model::{
    AccountScope, BuildId, ChallengeWindow, FreshnessError, FreshnessLimits, GameId, MatchId,
    Nonce, PolicyId, PolicyVersion, PublisherChallenge, PublisherId, UnixTime,
};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ReplayKey {
    publisher_id: PublisherId,
    nonce: Nonce,
}

impl fmt::Debug for ReplayKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayKey")
            .field("publisher_id", &self.publisher_id)
            .field("nonce", &self.nonce)
            .finish()
    }
}

impl ReplayKey {
    #[must_use]
    pub fn publisher_id(&self) -> &PublisherId { &self.publisher_id }

    #[must_use]
    pub const fn nonce(&self) -> Nonce { self.nonce }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeBinding {
    game_id: GameId,
    build_id: BuildId,
    account_scope: AccountScope,
    match_id: MatchId,
    policy_id: PolicyId,
    policy_version: PolicyVersion,
}

impl ChallengeBinding {
    #[must_use]
    pub fn game_id(&self) -> &GameId { &self.game_id }

    #[must_use]
    pub fn build_id(&self) -> &BuildId { &self.build_id }

    #[must_use]
    pub fn account_scope(&self) -> &AccountScope { &self.account_scope }

    #[must_use]
    pub fn match_id(&self) -> &MatchId { &self.match_id }

    #[must_use]
    pub fn policy_id(&self) -> &PolicyId { &self.policy_id }

    #[must_use]
    pub const fn policy_version(&self) -> PolicyVersion { self.policy_version }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRegistration {
    key: ReplayKey,
    binding: ChallengeBinding,
    window: ChallengeWindow,
}

impl ReplayRegistration {
    #[must_use]
    pub fn from_challenge(challenge: &PublisherChallenge) -> Self {
        Self {
            key: ReplayKey {
                publisher_id: challenge.publisher_id.clone(),
                nonce: challenge.nonce,
            },
            binding: ChallengeBinding {
                game_id: challenge.game_id.clone(),
                build_id: challenge.build_id.clone(),
                account_scope: challenge.account_scope.clone(),
                match_id: challenge.match_id.clone(),
                policy_id: challenge.policy_id.clone(),
                policy_version: challenge.policy_version,
            },
            window: challenge.window,
        }
    }

    #[must_use]
    pub fn key(&self) -> &ReplayKey { &self.key }

    #[must_use]
    pub fn binding(&self) -> &ChallengeBinding { &self.binding }

    #[must_use]
    pub const fn window(&self) -> ChallengeWindow { self.window }
}

pub trait ReplayStore: fmt::Debug + Send + Sync {
    fn register(
        &self,
        now: UnixTime,
        registration: &ReplayRegistration,
        limits: FreshnessLimits,
    ) -> Result<(), FreshnessError>;

    fn claim(
        &self,
        now: UnixTime,
        registration: &ReplayRegistration,
    ) -> Result<(), FreshnessError>;

    fn purge_expired(&self, now: UnixTime) -> Result<usize, FreshnessError>;
}

/// Proof that one registered challenge passed the atomic freshness claim.
///
/// ```compile_fail
/// use ogir_verifier::FreshnessChecked;
///
/// let forged = FreshnessChecked { _private: () };
/// ```
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub struct FreshnessChecked {
    _private: (),
}

#[derive(Debug)]
pub struct FreshnessGuard<'store, Store: ?Sized> {
    store: &'store Store,
    limits: FreshnessLimits,
}

impl<'store, Store: ReplayStore + ?Sized> FreshnessGuard<'store, Store> {
    #[must_use]
    pub const fn new(store: &'store Store, limits: FreshnessLimits) -> Self {
        Self { store, limits }
    }

    pub fn register(
        &self,
        now: UnixTime,
        challenge: &PublisherChallenge,
    ) -> Result<(), FreshnessError> {
        challenge.window.evaluate(now)?;
        self.store.register(
            now,
            &ReplayRegistration::from_challenge(challenge),
            self.limits,
        )
    }

    pub fn claim(
        &self,
        now: UnixTime,
        challenge: &PublisherChallenge,
    ) -> Result<FreshnessChecked, FreshnessError> {
        challenge.window.evaluate(now)?;
        self.store.claim(now, &ReplayRegistration::from_challenge(challenge))?;
        Ok(FreshnessChecked { _private: () })
    }

    pub fn purge_expired(&self, now: UnixTime) -> Result<usize, FreshnessError> {
        self.store.purge_expired(now)
    }
}
```

Implement all getters and constructors fully; do not expose mutation, raw nonce logging, a public `FreshnessChecked` constructor, or split contains/consume methods. Add `mod freshness;` plus explicit re-exports in verifier `lib.rs`.

- [ ] **Step 4: Build the reference test store just far enough for initial tests**

Create `tests/support/reference_replay_store.rs` with:

```rust
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ogir_model::{ChallengeWindow, FreshnessError, FreshnessLimits, PublisherId, UnixTime};
use ogir_verifier::{ChallengeBinding, ReplayKey, ReplayRegistration, ReplayStore};

#[derive(Debug, Clone)]
pub struct ReferenceReplayStore {
    state: Arc<Mutex<State>>,
}

#[derive(Debug, Clone)]
struct State {
    availability: Availability,
    high_water: Option<UnixTime>,
    records: HashMap<ReplayKey, StoredRecord>,
    issuance_events: Vec<(UnixTime, PublisherId)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Availability { Available, Unavailable }

#[derive(Debug, Clone, PartialEq, Eq)]
enum StoredState { Issued, Consumed }

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredRecord {
    binding: ChallengeBinding,
    window: ChallengeWindow,
    state: StoredState,
}

impl ReferenceReplayStore {
    fn with_availability(availability: Availability) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                availability,
                high_water: None,
                records: HashMap::new(),
                issuance_events: Vec::new(),
            })),
        }
    }

    pub fn available() -> Self {
        Self::with_availability(Availability::Available)
    }

    pub fn unavailable() -> Self {
        Self::with_availability(Availability::Unavailable)
    }
}
```

Use these private helpers; `observe_time` runs while the one method-wide lock is
held, and its high-water update remains durable even when a later check returns
another error:

```rust
fn with_state<T>(
    &self,
    operation: impl FnOnce(&mut State) -> Result<T, FreshnessError>,
) -> Result<T, FreshnessError> {
    let mut state = self
        .state
        .lock()
        .map_err(|_| FreshnessError::StateUnavailable)?;
    if state.availability != Availability::Available {
        return Err(FreshnessError::StateUnavailable);
    }
    operation(&mut state)
}

fn observe_time(state: &mut State, now: UnixTime) -> Result<(), FreshnessError> {
    if state.high_water.is_some_and(|high_water| now < high_water) {
        return Err(FreshnessError::ClockRollback);
    }
    state.high_water = Some(now);
    Ok(())
}

fn is_unexpired(record: &StoredRecord, now: UnixTime) -> bool {
    record.window.expires_at() > now
}
```

Implement `ReplayStore` with exactly one mutex critical section per trait
method and these ordered semantics:

1. `register` calls `observe_time`; recomputes the window duration with
   `checked_sub`; rejects zero/reversed duration as `InvalidWindow`, a duration
   above `limits.max_lifetime()` as `LifetimeExceeded`, and a window that does
   not contain `now` with its boundary error. It then performs the same safe GC
   as `purge_expired`, deleting only records already expired at the high-water,
   and rejects any still-existing `(PublisherId, Nonce)` as `ReplayDetected`.
2. Still under the same lock, retain successful issuance events whose age is
   strictly less than `issuance_rate_window_seconds`—an event exactly one full
   window old is outside the sliding window. Count all unexpired `Issued` and
   `Consumed` records for the total, publisher, and
   `(PublisherId, AccountScope)` boundaries. If adding one would exceed any
   boundary, or the publisher already has the maximum successful events in the
   sliding window, return `CapacityExceeded` without deleting an unexpired
   record. Because registration first removes every GC-eligible record, the
   total counter also bounds the record map rather than allowing expired state
   to accumulate between explicit GC calls.
3. Only after all checks pass, insert `StoredRecord { binding, window,
   state: StoredState::Issued }` and append the issuance event. Events are
   appended only for successful registrations.
4. `claim` calls `observe_time`, re-evaluates the stored registration window,
   obtains the record by the exact replay key, and returns `StateUnavailable`
   if it is missing. A binding mismatch, window mismatch, or `Consumed` state
   returns `ReplayDetected`. Otherwise change `Issued` to `Consumed` before
   releasing the lock.
5. `purge_expired` calls `observe_time`, then removes only records whose
   `expires_at <= state.high_water`; it returns the exact removed count.

Use `checked_sub` for both lifetime and event age. A subtraction failure in
window validation maps to `InvalidWindow`; a subtraction failure after
`observe_time` while aging events maps to `ClockRollback`. Never call `unwrap`,
`expect`, recover a poisoned lock, expose split contains/consume methods, or
log a key/binding. Add constructors `available()` and `unavailable()` now;
Task 5 adds restart snapshots and corrupt/missing-state constructors.
`available()` is explicitly a test fixture for a newly initialized issuer/key
epoch with no outstanding challenges; it is not an automatic production
empty-cache recovery path.

Export it from `tests/support/mod.rs`:

```rust
// SPDX-License-Identifier: Apache-2.0

mod reference_replay_store;
pub use reference_replay_store::ReferenceReplayStore;
```

- [ ] **Step 5: Run focused tests and verify GREEN**

```bash
cargo fmt --all
cargo test -p ogir-verifier --test freshness
cargo clippy -p ogir-verifier --all-targets -- -D warnings
```

Expected: initial replay/store tests pass and Clippy is clean.

- [ ] **Step 6: Commit the replay-contract slice**

```bash
git add crates/ogir-verifier/src/freshness.rs crates/ogir-verifier/src/lib.rs crates/ogir-verifier/tests/freshness.rs crates/ogir-verifier/tests/support
git diff --cached --check
git commit -m "feat: define atomic challenge replay contract"
```

---

### Task 4: Require Freshness Claim in the Research Verifier

**Files:**
- Modify: `crates/ogir-verifier/src/lib.rs:45-230`
- Modify: `crates/ogir-verifier/tests/freshness.rs`
- Modify: `crates/ogir-verifier/tests/support/reference_replay_store.rs`

**Interfaces:**
- Consumes: `FreshnessGuard<ReplayStore>` and `FreshnessChecked` from Task 3.
- Produces: `verify_research_structure(request, freshness)` that checks time, exact relying-party context, and atomic replay claim before returning its existing fail-closed evidence result.

- [ ] **Step 1: Add failing verifier integration cases**

Add these helpers and tests to `crates/ogir-verifier/tests/freshness.rs`:

```rust
use ogir_model::{Decision, EvidenceProfile, ReasonCode};
use ogir_protocol::EvidenceBundle;
use ogir_verifier::{
    ExpectedContext, VerificationRequest, verify_research_structure,
};

fn expected() -> ExpectedContext {
    ExpectedContext {
        publisher_id: identifier::<PublisherId>("example.publisher"),
        game_id: identifier::<GameId>("example.game"),
        build_id: identifier::<BuildId>("build-1"),
        account_scope: identifier::<AccountScope>("account-1"),
        match_id: identifier::<MatchId>("match-1"),
        policy_id: identifier::<PolicyId>("research-v0"),
        policy_version: PolicyVersion::new(1),
    }
}

fn request_with_expected(
    challenge: PublisherChallenge,
    now: u64,
    expected: ExpectedContext,
) -> VerificationRequest {
    VerificationRequest {
        challenge,
        evidence: EvidenceBundle {
            profile_id: identifier::<EvidenceProfile>("mock-v0"),
            payload: Vec::new(),
        },
        expected,
        now: UnixTime::new(now),
    }
}

fn request(challenge: PublisherChallenge, now: u64) -> VerificationRequest {
    request_with_expected(challenge, now, expected())
}

#[test]
fn first_fresh_request_reaches_fail_closed_evidence_result() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits());
    let challenge = challenge("example.game", [1; 32]);
    assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));
    let outcome = verify_research_structure(&request(challenge, 100), &guard);
    assert_eq!(outcome.reason, ReasonCode::EvidenceInvalid);
}

#[test]
fn second_request_with_same_nonce_is_replay() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits());
    let challenge = challenge("example.game", [2; 32]);
    assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));
    let first = verify_research_structure(
        &request(challenge.clone(), 100),
        &guard,
    );
    let second = verify_research_structure(
        &request(challenge, 100),
        &guard,
    );
    assert_eq!(first.reason, ReasonCode::EvidenceInvalid);
    assert_eq!(second.reason, ReasonCode::ReplayDetected);
}

#[test]
fn every_context_mismatch_rejects_without_consuming_registered_nonce() {
    let mut mismatches = Vec::new();
    let mut mismatch = expected();
    mismatch.publisher_id = identifier::<PublisherId>("other.publisher");
    mismatches.push(mismatch);
    let mut mismatch = expected();
    mismatch.game_id = identifier::<GameId>("other.game");
    mismatches.push(mismatch);
    let mut mismatch = expected();
    mismatch.build_id = identifier::<BuildId>("build-2");
    mismatches.push(mismatch);
    let mut mismatch = expected();
    mismatch.account_scope = identifier::<AccountScope>("account-2");
    mismatches.push(mismatch);
    let mut mismatch = expected();
    mismatch.match_id = identifier::<MatchId>("match-2");
    mismatches.push(mismatch);
    let mut mismatch = expected();
    mismatch.policy_id = identifier::<PolicyId>("research-v1");
    mismatches.push(mismatch);
    let mut mismatch = expected();
    mismatch.policy_version = PolicyVersion::new(2);
    mismatches.push(mismatch);

    for (index, mismatch) in mismatches.into_iter().enumerate() {
        let store = ReferenceReplayStore::available();
        let guard = FreshnessGuard::new(&store, limits());
        let challenge = challenge("example.game", [(index as u8) + 3; 32]);
        assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));
        assert_eq!(
            verify_research_structure(
                &request_with_expected(challenge.clone(), 100, mismatch),
                &guard,
            )
            .reason,
            ReasonCode::SessionBindingMismatch
        );
        assert_eq!(
            verify_research_structure(&request(challenge, 100), &guard).reason,
            ReasonCode::EvidenceInvalid
        );
    }
}

#[test]
fn unavailable_state_returns_retry_without_allow() {
    let store = ReferenceReplayStore::unavailable();
    let guard = FreshnessGuard::new(&store, limits());
    let outcome = verify_research_structure(
        &request(challenge("example.game", [10; 32]), 100),
        &guard,
    );
    assert_eq!(outcome.decision, Decision::Retry);
    assert_eq!(outcome.reason, ReasonCode::AttestationUnavailable);
}

#[test]
fn clock_rollback_returns_retry_without_allow() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits());
    let challenge = challenge("example.game", [5; 32]);
    assert_eq!(guard.register(UnixTime::new(150), &challenge), Ok(()));
    let outcome = verify_research_structure(
        &request(challenge, 140),
        &guard,
    );
    assert_eq!(outcome.decision, Decision::Retry);
    assert_eq!(outcome.reason, ReasonCode::AttestationUnavailable);
}
```

- [ ] **Step 2: Run verifier tests and verify RED**

```bash
cargo test -p ogir-verifier
```

Expected: compile errors show the verifier has not yet accepted a guard or claimed replay state.

- [ ] **Step 3: Integrate the guard in the exact security order**

Change the public function to:

```rust
pub fn verify_research_structure<Store: ReplayStore + ?Sized>(
    request: &VerificationRequest,
    freshness: &FreshnessGuard<'_, Store>,
) -> VerificationOutcome
```

The function body order must be:

1. `request.challenge.window.evaluate(request.now)` and map boundary errors;
2. exact expected/challenge publisher/game/build/account/match/policy/version comparison;
3. `freshness.claim(request.now, &request.challenge)` and bind the returned value to `_freshness_checked`;
4. return the existing `EvidenceInvalid` denial because evidence authentication/policy remain deferred.

Keep the function documentation explicit that publisher-signature
authentication is not implemented in this research scaffold and it therefore
never authorizes. The production pipeline specified by the ADR must place
bounded parsing and publisher authentication before this implemented window /
context / claim segment; M1-008 does not invent an authentication capability or
signature format.

The `#[cfg(test)]` module currently embedded in verifier `lib.rs` cannot use an
integration-test support store. Move its boundary and binding cases into
`tests/freshness.rs` (the tests above subsume them), then delete that embedded
module. Do not leave a second bypassing verifier entry point for unit tests.

Use this mapping:

```rust
fn freshness_failure(error: FreshnessError) -> VerificationOutcome {
    match error {
        FreshnessError::InvalidWindow | FreshnessError::LifetimeExceeded => {
            denied(ReasonCode::Malformed)
        }
        FreshnessError::NotYetValid => denied(ReasonCode::NotYetValid),
        FreshnessError::Expired => denied(ReasonCode::Expired),
        FreshnessError::ReplayDetected => denied(ReasonCode::ReplayDetected),
        FreshnessError::ClockRollback
        | FreshnessError::StateUnavailable
        | FreshnessError::CapacityExceeded => VerificationOutcome {
            decision: Decision::Retry,
            reason: ReasonCode::AttestationUnavailable,
        },
    }
}
```

Do not claim before context matching and do not release a claim after later denial.

- [ ] **Step 4: Run integration and full workspace tests**

```bash
cargo fmt --all
cargo test -p ogir-verifier
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: all commands exit 0; replay/context/operational mapping tests pass; no test produces `Decision::Allow`.

- [ ] **Step 5: Commit verifier integration**

```bash
git add crates/ogir-verifier/src/lib.rs crates/ogir-verifier/tests/freshness.rs crates/ogir-verifier/tests/support/reference_replay_store.rs
git diff --cached --check
git commit -m "feat: require atomic freshness claim in verifier"
```

---

### Task 5: Prove Restart, Rollback, Capacity, GC, Concurrency, and Properties

**Files:**
- Modify: `crates/ogir-verifier/tests/freshness.rs`
- Modify: `crates/ogir-verifier/tests/support/mod.rs`
- Modify: `crates/ogir-verifier/tests/support/reference_replay_store.rs`

**Interfaces:**
- Consumes: stable production interfaces from Tasks 1-4.
- Produces: mutation-resistant contract tests; no new production API.

- [ ] **Step 1: Add failing state-resilience tests**

Add the following helper next to the Task 3 fixtures:

```rust
use ogir_verifier::ReplayRegistration;
use support::Snapshot;

fn limits_for(
    total: usize,
    publisher: usize,
    account: usize,
    rate_window: u64,
    rate_maximum: usize,
) -> FreshnessLimits {
    FreshnessLimits::new(
        ChallengeLifetime::new(nonzero_u64(100)),
        nonzero_usize(total),
        nonzero_usize(publisher),
        nonzero_usize(account),
        nonzero_u64(rate_window),
        nonzero_usize(rate_maximum),
    )
}

fn limits_with_lifetime(seconds: u64) -> FreshnessLimits {
    FreshnessLimits::new(
        ChallengeLifetime::new(nonzero_u64(seconds)),
        nonzero_usize(16),
        nonzero_usize(16),
        nonzero_usize(16),
        nonzero_u64(60),
        nonzero_usize(16),
    )
}

fn snapshot(store: &ReferenceReplayStore) -> Snapshot {
    match store.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("available reference store did not snapshot: {error:?}"),
    }
}
```

Then add exact restart, rollback, failure, capacity, rate, GC, privacy, and
concurrency tests:

```rust
#[test]
fn clock_rollback_and_restart_never_reset_security_state() {
    let store = ReferenceReplayStore::available();
    let challenge = challenge("example.game", [20; 32]);
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(guard.register(UnixTime::new(150), &challenge), Ok(()));

    let reopened = ReferenceReplayStore::reopen(snapshot(&store));
    let reopened_guard = FreshnessGuard::new(&reopened, limits());
    assert_eq!(
        reopened_guard.claim(UnixTime::new(149), &challenge),
        Err(FreshnessError::ClockRollback)
    );
    assert_eq!(reopened.high_water(), Ok(Some(UnixTime::new(150))));
}

#[test]
fn consumed_state_survives_snapshot_and_reopen() {
    let store = ReferenceReplayStore::available();
    let challenge = challenge("example.game", [21; 32]);
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));
    assert!(guard.claim(UnixTime::new(100), &challenge).is_ok());

    let reopened = ReferenceReplayStore::reopen(snapshot(&store));
    let reopened_guard = FreshnessGuard::new(&reopened, limits());
    assert_eq!(
        reopened_guard.claim(UnixTime::new(100), &challenge),
        Err(FreshnessError::ReplayDetected)
    );
}

#[test]
fn issuance_rate_state_survives_snapshot_and_reopen() {
    let store = ReferenceReplayStore::available();
    let rate_limits = limits_for(8, 8, 8, 60, 2);
    let guard = FreshnessGuard::new(&store, rate_limits);
    for nonce in [42, 43] {
        assert_eq!(
            guard.register(
                UnixTime::new(100),
                &challenge("example.game", [nonce; 32]),
            ),
            Ok(())
        );
    }

    let reopened = ReferenceReplayStore::reopen(snapshot(&store));
    let reopened_guard = FreshnessGuard::new(&reopened, rate_limits);
    assert_eq!(
        reopened_guard.register(
            UnixTime::new(100),
            &challenge("example.game", [44; 32]),
        ),
        Err(FreshnessError::CapacityExceeded)
    );
}

#[test]
fn missing_or_corrupt_snapshot_fails_closed() {
    let challenge = challenge("example.game", [22; 32]);
    for store in [
        ReferenceReplayStore::missing(),
        ReferenceReplayStore::corrupt(),
    ] {
        let guard = FreshnessGuard::new(&store, limits());
        assert_eq!(
            guard.register(UnixTime::new(100), &challenge),
            Err(FreshnessError::StateUnavailable)
        );
        assert_eq!(
            guard.claim(UnixTime::new(100), &challenge),
            Err(FreshnessError::StateUnavailable)
        );
        assert_eq!(
            guard.purge_expired(UnixTime::new(200)),
            Err(FreshnessError::StateUnavailable)
        );
    }
}

#[test]
fn capacity_refuses_issuance_without_evicting_unexpired_records() {
    let store = ReferenceReplayStore::available();
    let limits = limits_for(2, 2, 1, 60, 2);
    let guard = FreshnessGuard::new(&store, limits);
    let first = challenge_for_publisher("publisher-one", [23; 32]);
    let second = challenge_for_publisher("publisher-two", [24; 32]);
    let rejected = challenge_for_publisher("publisher-three", [25; 32]);
    let first_key = ReplayRegistration::from_challenge(&first).key().clone();
    let second_key = ReplayRegistration::from_challenge(&second).key().clone();

    assert_eq!(guard.register(UnixTime::new(100), &first), Ok(()));
    assert_eq!(guard.register(UnixTime::new(100), &second), Ok(()));
    assert_eq!(
        guard.register(UnixTime::new(100), &rejected),
        Err(FreshnessError::CapacityExceeded)
    );
    assert_eq!(store.record_count(), Ok(2));
    assert_eq!(store.contains(&first_key), Ok(true));
    assert_eq!(store.contains(&second_key), Ok(true));
}

#[test]
fn consumed_unexpired_records_still_count_toward_capacity() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits_for(2, 2, 1, 60, 2));
    let first = challenge("example.game", [45; 32]);
    let second = challenge("example.game", [46; 32]);
    assert_eq!(guard.register(UnixTime::new(100), &first), Ok(()));
    assert!(guard.claim(UnixTime::new(100), &first).is_ok());
    assert_eq!(
        guard.register(UnixTime::new(100), &second),
        Err(FreshnessError::CapacityExceeded)
    );
}

#[test]
fn registration_reclaims_only_records_expired_at_the_time_floor() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits_for(1, 1, 1, 60, 2));
    let old = challenge("example.game", [47; 32]);
    let replacement = challenge_with_window("example.publisher", [48; 32], 200, 300);
    let old_key = ReplayRegistration::from_challenge(&old).key().clone();
    let replacement_key = ReplayRegistration::from_challenge(&replacement)
        .key()
        .clone();

    assert_eq!(guard.register(UnixTime::new(100), &old), Ok(()));
    assert_eq!(guard.register(UnixTime::new(200), &replacement), Ok(()));
    assert_eq!(store.contains(&old_key), Ok(false));
    assert_eq!(store.contains(&replacement_key), Ok(true));
}

#[test]
fn registration_rechecks_active_lifetime_policy_atomically() {
    let challenge = challenge("example.game", [41; 32]);

    let exact_store = ReferenceReplayStore::available();
    let exact_guard = FreshnessGuard::new(&exact_store, limits_with_lifetime(100));
    assert_eq!(exact_guard.register(UnixTime::new(100), &challenge), Ok(()));

    let over_store = ReferenceReplayStore::available();
    let over_guard = FreshnessGuard::new(&over_store, limits_with_lifetime(99));
    assert_eq!(
        over_guard.register(UnixTime::new(100), &challenge),
        Err(FreshnessError::LifetimeExceeded)
    );
    assert_eq!(over_store.record_count(), Ok(0));
}

#[test]
fn publisher_account_and_rate_limits_accept_limit_and_reject_one_over() {
    let publisher_store = ReferenceReplayStore::available();
    let publisher_guard = FreshnessGuard::new(
        &publisher_store,
        limits_for(4, 2, 2, 60, 4),
    );
    for (account, nonce) in [("account-one", 26), ("account-two", 27)] {
        let challenge = challenge_for_account("publisher-one", account, [nonce; 32]);
        assert_eq!(publisher_guard.register(UnixTime::new(100), &challenge), Ok(()));
    }
    let publisher_over =
        challenge_for_account("publisher-one", "account-three", [28; 32]);
    assert_eq!(
        publisher_guard.register(UnixTime::new(100), &publisher_over),
        Err(FreshnessError::CapacityExceeded)
    );

    let account_store = ReferenceReplayStore::available();
    let account_guard = FreshnessGuard::new(&account_store, limits_for(4, 4, 2, 60, 4));
    for nonce in [29, 30] {
        let challenge = challenge("example.game", [nonce; 32]);
        assert_eq!(account_guard.register(UnixTime::new(100), &challenge), Ok(()));
    }
    assert_eq!(
        account_guard.register(
            UnixTime::new(100),
            &challenge("example.game", [31; 32]),
        ),
        Err(FreshnessError::CapacityExceeded)
    );

    let rate_store = ReferenceReplayStore::available();
    let rate_guard = FreshnessGuard::new(&rate_store, limits_for(4, 4, 4, 60, 2));
    for nonce in [32, 33] {
        let challenge = challenge("example.game", [nonce; 32]);
        assert_eq!(rate_guard.register(UnixTime::new(100), &challenge), Ok(()));
    }
    let after_limit = challenge("example.game", [34; 32]);
    assert_eq!(
        rate_guard.register(UnixTime::new(100), &after_limit),
        Err(FreshnessError::CapacityExceeded)
    );
    assert_eq!(
        rate_guard.register(UnixTime::new(160), &after_limit),
        Ok(())
    );
}

#[test]
fn gc_keeps_record_before_expiry_and_removes_it_at_expiry() {
    let store = ReferenceReplayStore::available();
    let challenge = challenge("example.game", [35; 32]);
    let key = ReplayRegistration::from_challenge(&challenge).key().clone();
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));
    assert!(guard.claim(UnixTime::new(100), &challenge).is_ok());
    assert_eq!(guard.purge_expired(UnixTime::new(199)), Ok(0));
    assert_eq!(store.contains(&key), Ok(true));
    assert_eq!(guard.purge_expired(UnixTime::new(200)), Ok(1));
    assert_eq!(store.contains(&key), Ok(false));
    assert_eq!(
        guard.claim(UnixTime::new(200), &challenge),
        Err(FreshnessError::Expired)
    );
}

#[test]
fn rollback_or_unavailable_state_blocks_gc() {
    let store = ReferenceReplayStore::available();
    let challenge = challenge("example.game", [36; 32]);
    let key = ReplayRegistration::from_challenge(&challenge).key().clone();
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(guard.register(UnixTime::new(150), &challenge), Ok(()));
    assert_eq!(
        guard.purge_expired(UnixTime::new(149)),
        Err(FreshnessError::ClockRollback)
    );
    assert_eq!(store.contains(&key), Ok(true));

    let unavailable = ReferenceReplayStore::unavailable();
    let unavailable_guard = FreshnessGuard::new(&unavailable, limits());
    assert_eq!(
        unavailable_guard.purge_expired(UnixTime::new(200)),
        Err(FreshnessError::StateUnavailable)
    );
}

#[test]
fn missing_registration_fails_closed() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(
        guard.claim(
            UnixTime::new(100),
            &challenge("example.game", [37; 32]),
        ),
        Err(FreshnessError::StateUnavailable)
    );
}

#[test]
fn replay_identity_ignores_every_context_and_window_field() {
    let baseline = challenge("example.game", [38; 32]);
    let mut variants = Vec::new();

    let mut changed = baseline.clone();
    changed.game_id = identifier::<GameId>("other.game");
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.build_id = identifier::<BuildId>("build-2");
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.account_scope = identifier::<AccountScope>("account-2");
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.match_id = identifier::<MatchId>("match-2");
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.policy_id = identifier::<PolicyId>("research-v1");
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.policy_version = PolicyVersion::new(2);
    variants.push(changed);
    variants.push(challenge_with_window(
        "example.publisher",
        [38; 32],
        100,
        199,
    ));

    for changed in variants {
        let store = ReferenceReplayStore::available();
        let guard = FreshnessGuard::new(&store, limits());
        assert_eq!(guard.register(UnixTime::new(100), &baseline), Ok(()));
        assert!(guard.claim(UnixTime::new(100), &baseline).is_ok());
        assert_eq!(
            guard.claim(UnixTime::new(100), &changed),
            Err(FreshnessError::ReplayDetected)
        );
    }
}

#[test]
fn replay_debug_and_errors_redact_nonce_account_and_match() {
    let challenge = challenge("example.game", [39; 32]);
    let debug = format!("{:?}", ReplayRegistration::from_challenge(&challenge));
    assert!(debug.contains("Nonce([REDACTED; 32])"));
    assert!(!debug.contains("account-1"));
    assert!(!debug.contains("match-1"));
    assert!(!debug.contains("39, 39"));

    for error in [
        FreshnessError::ReplayDetected,
        FreshnessError::ClockRollback,
        FreshnessError::StateUnavailable,
        FreshnessError::CapacityExceeded,
    ] {
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("account-1"));
        assert!(!rendered.contains("match-1"));
        assert!(!rendered.contains("39, 39"));
    }
}

#[test]
fn two_concurrent_claims_produce_exactly_one_capability() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let store = ReferenceReplayStore::available();
    let challenge = challenge("example.game", [40; 32]);
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));

    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let thread_store = store.clone();
        let thread_challenge = challenge.clone();
        let thread_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let thread_guard = FreshnessGuard::new(&thread_store, limits());
            thread_barrier.wait();
            thread_guard.claim(UnixTime::new(100), &thread_challenge)
        }));
    }
    barrier.wait();

    let mut successes = 0;
    let mut replays = 0;
    for handle in handles {
        match handle.join() {
            Ok(Ok(_capability)) => successes += 1,
            Ok(Err(FreshnessError::ReplayDetected)) => replays += 1,
            Ok(Err(error)) => panic!("unexpected claim error: {error:?}"),
            Err(_) => panic!("claim worker panicked"),
        }
    }
    assert_eq!(successes, 1);
    assert_eq!(replays, 1);
}
```

- [ ] **Step 2: Add a deterministic arbitrary-action property test**

Use 64 fixed seeds and 256 actions per seed (16,384 operations total). The
generator and action selection are exactly:

```rust
#[derive(Debug, Clone, Copy)]
enum Action {
    Register { publisher: u8, nonce: u8 },
    Claim { publisher: u8, nonce: u8 },
    Advance(u8),
    Rollback(u8),
    Restart,
    SetUnavailable,
    Purge,
}

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn action(&mut self) -> Action {
        let value = self.next();
        let publisher = (value >> 8) as u8;
        let nonce = (value >> 16) as u8;
        let delta = ((value >> 24) as u8 % 16) + 1;
        match value % 7 {
            0 => Action::Register { publisher, nonce },
            1 => Action::Claim { publisher, nonce },
            2 => Action::Advance(delta),
            3 => Action::Rollback(delta),
            4 => Action::Restart,
            5 => Action::SetUnavailable,
            6 => Action::Purge,
            _ => unreachable!("modulo seven is exhaustive"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OracleRecordState {
    Issued,
    Consumed,
}

#[derive(Debug, Clone, Copy)]
struct OracleRecord {
    issued_at: u64,
    expires_at: u64,
    state: OracleRecordState,
}

fn property_challenge(publisher: u8, nonce: u8, now: u64) -> PublisherChallenge {
    let publisher_id = format!("publisher-{publisher}");
    let account = format!("account-{publisher}");
    let expires_at = match now.checked_add(100) {
        Some(value) => value,
        None => panic!("property clock overflowed"),
    };
    let mut challenge =
        challenge_for_account(&publisher_id, &account, [nonce; 32]);
    challenge.window = valid_window(now, expires_at);
    challenge
}
```

The test driver starts each seed at time `100`, uses
`limits_for(65_535, 65_535, 65_535, 1, 65_535)`, and maintains these values
separately from the store: `available: bool`, `high_water: Option<u64>`, a
`HashMap<(u8, u8), OracleRecord>`, a set of keys that have ever been issued,
the corresponding invocation `PublisherChallenge` values, per-key capability
counts, and the last known-good snapshot plus clone of the oracle.

For `Register`, combine the two action bytes into a `u16` and scan that entire
16-bit keyspace with wrapping addition until finding a key outside the
ever-issued set; 16,384 total actions cannot exhaust 65,536 keys. Split the
chosen value back into publisher/nonce bytes. Construct its challenge with
literal `[now, now + 100)` and binding strings produced only from those two
bytes. This keeps the property inside the issuer contract
that generated nonces are fresh; duplicate-key behavior remains covered by the
named replay tests. Derive expected results without calling `ChallengeWindow`
evaluation or any store helper:

- unavailable state -> `StateUnavailable`;
- `now < high_water` -> `ClockRollback`;
- otherwise advance high-water, remove only records with
  `expires_at <= high_water` (registration's safe-GC step), insert literal
  `{ issued_at: now, expires_at: now + 100, state: Issued }`, and succeed.

For `Claim`, use the saved challenge when the key exists, otherwise construct a
literal in-window challenge for the requested missing key. Apply this oracle
order: before issue -> `NotYetValid`; at/after expiry -> `Expired`; unavailable
-> `StateUnavailable`; below high-water -> `ClockRollback`; missing record ->
`StateUnavailable`; consumed record -> `ReplayDetected`; otherwise mark it
consumed, increment exactly one capability count, and return success. Any
store-level attempt that reaches an available non-rollback operation advances
the oracle high-water even when missing or replayed.

`Advance(delta)` uses checked addition and fails the test on overflow;
`Rollback(delta)` uses `saturating_sub`; neither observes store time by itself.
`Purge` first applies unavailable/rollback rules, then removes exactly records
with `expires_at <= high_water`. `Restart` snapshots and reopens the available
store and proves field-equivalent observable state; after
`SetUnavailable`, it restores only the last known-good snapshot and matching
oracle clone. This models the one recovery path approved by the spec and never
creates an empty store. After every action, if `snapshot()` succeeds, refresh
the last-known-good pair even when the action returned replay/missing/capacity:
those errors may still have durably advanced the time floor.

After every action, when state is inspectable, assert:

- no key has more than one successful capability;
- high-water time never decreases;
- unavailable state never returns success;
- no capability exists before issuance or at/after expiry;
- no unexpired record disappears; and
- expired records become removable only at/after exact expiry.

Compare the exact `Result` variant from the store/guard with the independent
oracle for every `Register`, `Claim`, and `Purge`. Include seed and action index
in assertion messages so a failure is reproducible.

- [ ] **Step 3: Run tests and verify RED against incomplete reference store**

```bash
cargo test -p ogir-verifier --test freshness
```

Expected: failures identify missing snapshot/reopen, high-water, capacity, GC, or atomic-concurrency behavior in the test reference store.

- [ ] **Step 4: Complete only the test reference implementation**

Extend `Availability` with `Missing` and `Corrupt`, export `Snapshot` from
`tests/support/mod.rs`, and add these exact test-support surfaces:

```rust
mod reference_replay_store;
pub use reference_replay_store::{ReferenceReplayStore, Snapshot};
```

```rust
#[derive(Debug, Clone)]
pub struct Snapshot {
    high_water: Option<UnixTime>,
    records: HashMap<ReplayKey, StoredRecord>,
    issuance_events: Vec<(UnixTime, PublisherId)>,
}

impl ReferenceReplayStore {
    pub fn missing() -> Self {
        Self::with_availability(Availability::Missing)
    }

    pub fn corrupt() -> Self {
        Self::with_availability(Availability::Corrupt)
    }

    pub fn reopen(snapshot: Snapshot) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                availability: Availability::Available,
                high_water: snapshot.high_water,
                records: snapshot.records,
                issuance_events: snapshot.issuance_events,
            })),
        }
    }

    pub fn snapshot(&self) -> Result<Snapshot, FreshnessError> {
        self.with_state(|state| {
            Ok(Snapshot {
                high_water: state.high_water,
                records: state.records.clone(),
                issuance_events: state.issuance_events.clone(),
            })
        })
    }

    pub fn set_unavailable(&self) -> Result<(), FreshnessError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| FreshnessError::StateUnavailable)?;
        state.availability = Availability::Unavailable;
        Ok(())
    }

    pub fn high_water(&self) -> Result<Option<UnixTime>, FreshnessError> {
        self.with_state(|state| Ok(state.high_water))
    }

    pub fn record_count(&self) -> Result<usize, FreshnessError> {
        self.with_state(|state| Ok(state.records.len()))
    }

    pub fn contains(&self, key: &ReplayKey) -> Result<bool, FreshnessError> {
        self.with_state(|state| Ok(state.records.contains_key(key)))
    }
}
```

Keep the atomic method algorithms and error precedence from Task 3. Calculate
total/publisher/account counts before insertion, filter per-publisher issuance
events using the exact age rule, and delete records only when
`expires_at <= high_water`. `Snapshot` is an in-memory test image, not a
production serialization format or durability claim.

Never recover mutex poisoning, reset unavailable state automatically, release consumed records, or evict an unexpired record.

- [ ] **Step 5: Verify and commit resilience tests**

```bash
cargo fmt --all
cargo test -p ogir-model --test freshness
cargo test -p ogir-verifier --test freshness
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
git add crates/ogir-verifier/tests/freshness.rs crates/ogir-verifier/tests/support/mod.rs crates/ogir-verifier/tests/support/reference_replay_store.rs
git commit -m "test: pin freshness and replay invariants"
```

- [ ] **Step 6: Mutation-prove the committed critical tests**

For each row below, create a new detached disposable worktree at Task 5 Step 5
`HEAD`, use `apply_patch` inside only that worktree to make the one mutation,
run the two focused commands, record the named failure, then remove that exact
temporary worktree before starting the next row:

| Mutation | Test that must fail |
| --- | --- |
| Remove the `now < issued_at` rejection. | `half_open_window_has_zero_leeway` |
| Change exact-expiry rejection from `now >= expires_at` to `now > expires_at`. | `half_open_window_has_zero_leeway` |
| Add `GameId` or `MatchId` to `ReplayKey`. | `same_publisher_nonce_is_single_use_across_bindings` or `replay_identity_ignores_every_context_and_window_field` |
| Split claim into a check lock and later write lock, with a disposable two-party `Barrier` between them to force the race. | `two_concurrent_claims_produce_exactly_one_capability` |
| Reopen with an empty record map. | `consumed_state_survives_snapshot_and_reopen` |
| Permit `now < high_water`. | `clock_rollback_and_restart_never_reset_security_state` |
| Evict one unexpired record when total capacity is full. | `capacity_refuses_issuance_without_evicting_unexpired_records` |
| Leave an issued record unchanged after a successful claim. | `second_request_with_same_nonce_is_replay` |
| Replace checked window subtraction with wrapping subtraction. | `invalid_and_excessive_windows_fail_without_overflow` |
| Render nonce bytes in `Nonce::Debug`. | `replay_debug_and_errors_redact_nonce_account_and_match` |
| Render `AccountScope` or `MatchId` text in `Debug`. | `replay_debug_and_errors_redact_nonce_account_and_match` |

Use this lifecycle for every row:

```bash
mutation_parent=$(mktemp -d)
mutation_worktree="$mutation_parent/repo"
git worktree add --detach "$mutation_worktree" HEAD
cargo test -p ogir-model --test freshness --manifest-path "$mutation_worktree/Cargo.toml"
cargo test -p ogir-verifier --test freshness --manifest-path "$mutation_worktree/Cargo.toml"
git worktree remove --force "$mutation_worktree"
rmdir "$mutation_parent"
```

Expected: at least the named regression test fails for each mutation. If a
mutation passes, remove the disposable worktree, add a focused failing test in
the primary worktree, commit it as `test: close freshness mutation gap`, and
repeat that mutation. Never copy a mutated file back to the primary worktree.

- [ ] **Step 7: Prove mutation work left the branch unchanged**

```bash
git worktree list --porcelain
git status --porcelain=v1
cargo test -p ogir-model --test freshness
cargo test -p ogir-verifier --test freshness
```

Expected: only intentional long-lived worktrees remain, primary status is
empty, and both focused suites pass.

---

### Task 6: Record ADR-0005 and Update Architecture/Threat/Test Documentation

**Files:**
- Create: `docs/adr/0005-verifier-authoritative-challenge-freshness.md`
- Modify: `docs/adr/index.md`
- Modify: `docs/SECURITY_INVARIANTS.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/THREAT_MODEL.md`
- Modify: `docs/TEST_STRATEGY.md`
- Create: `lab/scenarios/challenge-replay.yml`
- Create: `lab/scenarios/freshness-state-failure.yml`
- Modify: `planning/issues/008-freshness-model.md` from `status: ready` to `status: needs-review` after deterministic evidence exists
- Modify: `docs/superpowers/plans/2026-08-25-m1-008-freshness-model.md` only to keep executable gate commands correct

**Interfaces:**
- Consumes: completed behavior and verified tests from Tasks 1-5.
- Produces: accepted ADR-0005 and timeless documentation matching implemented semantics.

- [ ] **Step 1: Write ADR-0005 from the approved spec**

Create the ADR with exact metadata:

```markdown
# ADR-0005: Verifier-authoritative nonce freshness with durable replay state

- Status: Accepted
- Date: 2026-08-25
- Owners: Initial maintainer
- Related issues: [M1-008](../../planning/issues/008-freshness-model.md)
- Supersedes: None
- Superseded by: None
```

Populate every template heading with these exact decisions:

- **Context:** raw independent timestamps and nonce uniqueness alone do not
  prevent replay, concurrent double claim, restart reset, or clock rollback.
- **Decision drivers:** fail-closed authorization, exact publisher authority,
  cross-context single use, bounded durable state, privacy minimization,
  database independence, and deterministic testing.
- **Options considered:** timestamp-only stateless validation, signed nonce
  without replay state, context-scoped keys, skew leeway, volatile restart
  reset, and epoch IDs; retain each approved rejection rationale.
- **Decision:** zero skew; strict `[issued_at, expires_at)`; replay key exactly
  `(PublisherId, Nonce)`; durable registration and high-water; irreversible
  atomic claim; expiry-only GC; explicit nonzero limits; no stateless fallback.
- **Consequences:** stronger single-use/restart guarantees at the cost of an
  availability-critical store, possible self-burned challenges, and bounded
  reissuance; production values/adapters/recovery remain follow-up work.
- **Threat-model impact:** replay store and authoritative clock enter the
  publisher TCB; rollback, missing/corrupt state, races, and capacity pressure
  fail closed.
- **Privacy impact:** store only replay identity, typed binding, window, state,
  and recovery fields; redact nonce/account/match and delete at expiry.
- **Dependency and license impact:** standard library only; no new package,
  database, serializer, async runtime, or license boundary.
- **Validation:** name the boundary, binding, restart, rollback, capacity, GC,
  concurrency, arbitrary-sequence, privacy, and mutation tests from Tasks 1–5.
- **Rollback:** only a superseding ADR plus migration/issuer-key epoch rotation
  may replace the decision; never reset state while old challenges remain valid.
- **Primary sources:** cite the exact RFC 9334, RFC 9711, RFC 7519, and Rust
  `SystemTime` links already recorded in the approved spec.

Do not copy transient branch or PR history into the ADR.

- [ ] **Step 2: Add the exact ADR index row**

Append:

```markdown
| [ADR-0005](0005-verifier-authoritative-challenge-freshness.md) | Accepted | Publisher-verifier time and durable single-use nonce state define challenge freshness. | None | None |
```

- [ ] **Step 3: Update current architecture and threat text**

Replace freshness invariants 7–10 in `docs/SECURITY_INVARIANTS.md` without
renumbering later sections:

```markdown
7. The publisher-controlled issuer generates a fresh cryptographically random nonce and durably registers its challenge before returning it.
8. A challenge is eligible only during its exact publisher-verifier window `[issued_at, expires_at)`, and `(PublisherId, Nonce)` can yield at most one freshness capability in any context.
9. Issued/consumed replay state and the verifier-time high-water mark survive restart; rollback, missing/corrupt/unavailable state, or capacity exhaustion fails closed without stateless fallback or unexpired-record eviction.
10. Evidence and permits have explicit issued-at and expiry values; renewal requires a fresh challenge and cannot silently downgrade policy.
```

In `docs/ARCHITECTURE.md`, document the issuance/claim order, strict interval, durable time floor, and operational-unavailable mapping in the protocol-object/verifier sections.

In `docs/THREAT_MODEL.md`, extend the replay threat response with atomic publisher-scoped nonce claim, durable restart state, and rollback detection. Add the replay store and authoritative clock as security-critical publisher infrastructure; do not make the client clock trusted.

In `docs/TEST_STRATEGY.md`, list boundary, replay-context, restart, rollback, capacity, GC, concurrent claim, arbitrary-sequence, and mutation tests under pure-model/property/integration coverage.

Create the two schema-conforming attack scenarios with exact content:

```yaml
id: OGIR-PROTOCOL-REPLAY-002
title: Reuse one publisher challenge across context or restart
attacker: A1
assets:
  - protected_session_authorization
preconditions:
  - a publisher challenge was durably registered and claimed once
steps:
  - resubmit the signed challenge with the same or altered game, account, match, or policy binding
  - repeat after the verifier reopens its durable freshness state
expected:
  decision: deny
  reason: replay-detected
  automatic_ban: false
invariants:
  - one publisher-scoped nonce yields at most one freshness capability in every context
  - restart preserves issued and consumed replay state
residual_risk:
  - a valid holder can burn its own challenge and must request a bounded reissuance
```

```yaml
id: OGIR-PROTOCOL-FRESHNESS-001
title: Roll back time or remove verifier freshness state
attacker: A5
assets:
  - protected_session_authorization
  - verifier_freshness_state
preconditions:
  - the verifier persisted a challenge record and authoritative-time high-water mark
steps:
  - present a lower authoritative time or make replay state missing, corrupt, or unavailable
  - submit an otherwise in-window challenge
expected:
  decision: retry
  reason: attestation-unavailable
  automatic_ban: false
invariants:
  - clock rollback never extends validity
  - unavailable security state never falls back to stateless validation
residual_risk:
  - a forward clock jump can cause a fail-closed protected-mode outage
```

After all implementation/tests above are complete, change only the issue
source workflow label from `status: ready` to `status: needs-review`:

```markdown
<!-- labels: type: architecture,area: protocol,risk: cryptography,status: needs-review -->
```

- [ ] **Step 4: Run documentation gates**

```bash
git add docs/adr/0005-verifier-authoritative-challenge-freshness.md docs/adr/index.md docs/SECURITY_INVARIANTS.md docs/ARCHITECTURE.md docs/THREAT_MODEL.md docs/TEST_STRATEGY.md lab/scenarios/challenge-replay.yml lab/scenarios/freshness-state-failure.yml planning/issues/008-freshness-model.md docs/superpowers/plans/2026-08-25-m1-008-freshness-model.md
./scripts/test-adr-index.sh
./scripts/check-adr-index.sh
./scripts/test-repository-metadata.sh
./scripts/check-repository-metadata.sh
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
if rg -n 'TBD|TODO|FIXME|PLACEHOLDER' docs/adr/0005-verifier-authoritative-challenge-freshness.md docs/SECURITY_INVARIANTS.md docs/ARCHITECTURE.md docs/THREAT_MODEL.md docs/TEST_STRATEGY.md; then exit 1; fi
python3 -c 'import pathlib, yaml; required={"id","title","attacker","assets","preconditions","steps","expected","invariants","residual_risk"}; [(required <= set(yaml.safe_load(path.read_text()))) or (_ for _ in ()).throw(SystemExit(f"missing attack-scenario key: {path}")) for path in pathlib.Path("lab/scenarios").glob("*.yml")]'
git diff --check
```

Expected: ADR tests/check pass, rustdoc exits 0, placeholder search returns no matches, diff check passes.

- [ ] **Step 5: Commit documentation**

```bash
git add docs/adr/0005-verifier-authoritative-challenge-freshness.md docs/adr/index.md docs/SECURITY_INVARIANTS.md docs/ARCHITECTURE.md docs/THREAT_MODEL.md docs/TEST_STRATEGY.md lab/scenarios/challenge-replay.yml lab/scenarios/freshness-state-failure.yml planning/issues/008-freshness-model.md docs/superpowers/plans/2026-08-25-m1-008-freshness-model.md
git diff --cached --check
git commit -m "docs: record challenge freshness decision"
```

---

### Task 7: Completion, Adversarial Review, Live Issue Sync, and Publication Handoff

**Files:**
- Review range: verified implementation base through final local head
- Potentially modify only files required by evidence-backed review findings
- External read/write: GitHub issue #8 body/labels only after local source is committed

**Interfaces:**
- Consumes: every prior task and the repository Definition of Done.
- Produces: clean reviewed unsigned branch ready for explicit human DCO certification; publication occurs only after certification/rewrite/reverification.

- [ ] **Step 1: Run the complete local matrix**

```bash
./scripts/check.sh
bash -n scripts/*.sh
shellcheck scripts/*.sh
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
python3 -c 'import pathlib, yaml; [yaml.safe_load(path.read_text()) for path in pathlib.Path(".github/workflows").glob("*.yml")]'
gcc -std=c17 -Wall -Wextra -Werror -fsyntax-only -x c -I. - <<'EOF'
#include "sdk/include/ogir.h"
int main(void) {
    ogir_session *session = 0;
    (void)session;
    return 0;
}
EOF
git diff 883f8adb4672b8748365b6a254ff9626d8773399..HEAD --check
git fsck --full --no-dangling
git status --porcelain=v1
```

Expected: every command exits 0 and status is empty. If `main` changes before execution starts, stop, verify/rebase onto the new main, and revise every recorded base OID in this plan before continuing.

- [ ] **Step 2: Run acceptance scans**

```bash
if rg -n 'pub (issued_at_unix_seconds|expires_at_unix_seconds|now_unix_seconds):' crates apps; then exit 1; fi
if rg -n '\bModelError\b|validate_structure\(' crates apps; then exit 1; fi
if git diff --name-only 883f8adb4672b8748365b6a254ff9626d8773399..HEAD -- Cargo.lock Cargo.toml 'crates/*/Cargo.toml' 'apps/*/Cargo.toml' | rg .; then exit 1; fi
if git diff 883f8adb4672b8748365b6a254ff9626d8773399..HEAD | rg -n '(BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})'; then exit 1; fi
```

Expected: no raw time fields, dependency changes, or sensitive patterns.

- [ ] **Step 3: Dispatch a fresh-context read-only adversarial reviewer**

Provide exact base/head plus issue #8 and the approved spec. Require attacks against boundary widening, context-scoped replay, check-then-consume races, restart clearing, rollback acceptance, capacity eviction, claim release, error/privacy leakage, and tests that pass under those mutations. Fix every Critical/Important finding test-first and rerun this task from Step 1 until independent verdict is Yes.

The final issue taxonomy includes `risk: trusted-computing-base` and
`risk: privacy`; obtain explicit fresh-context TCB and privacy specialist Yes
verdicts on the final head before Step 4.

- [ ] **Step 4: Synchronize live issue #8**

After all issue-source edits are committed:

```bash
issue_ready_commit=eec0150ee8b522e6adff93146077f0bb100efaaf
test "$(gh api repos/archledger/open-game-integrity-runtime/issues/8 --template '{{.body}}' | sha256sum | cut -d' ' -f1)" = "$(git show "$issue_ready_commit:planning/issues/008-freshness-model.md" | sha256sum | cut -d' ' -f1)"
test "$(gh issue view 8 --repo archledger/open-game-integrity-runtime --json labels --jq '[.labels[].name] | sort | join("|")')" = 'area: protocol|risk: cryptography|status: ready|type: architecture'
gh issue edit 8 --repo archledger/open-game-integrity-runtime \
  --body-file planning/issues/008-freshness-model.md \
  --remove-label 'status: ready' \
  --add-label 'status: needs-review' \
  --add-label 'area: model' \
  --add-label 'area: verifier' \
  --add-label 'risk: privacy' \
  --add-label 'risk: trusted-computing-base'
gh api repos/archledger/open-game-integrity-runtime/issues/8 --template '{{.body}}' | sha256sum
sha256sum planning/issues/008-freshness-model.md
gh issue view 8 --repo archledger/open-game-integrity-runtime \
  --json labels,milestone,state \
  --jq '{labels: [.labels[].name] | sort, milestone: .milestone.title, state}'
```

Expected: hashes match; the issue is open in `M1 Domain Model` with exactly
`area: model`, `area: protocol`, `area: verifier`, `risk: cryptography`,
`risk: privacy`, `risk: trusted-computing-base`, `status: needs-review`, and
`type: architecture`.

If post-write verification fails, restore the verified ready-state body and
label before stopping:

```bash
gh issue edit 8 --repo archledger/open-game-integrity-runtime \
  --body-file <(git show "$issue_ready_commit:planning/issues/008-freshness-model.md") \
  --remove-label 'status: needs-review' \
  --remove-label 'area: model' \
  --remove-label 'area: verifier' \
  --remove-label 'risk: privacy' \
  --remove-label 'risk: trusted-computing-base' \
  --add-label 'status: ready'
```

- [ ] **Step 5: Freeze the unsigned range for human certification**

```bash
test "$(git config user.name)" = 'Wisbendji Fimerlus'
test "$(git config user.email)" = 'archledger236@gmail.com'
git rev-list --count 883f8adb4672b8748365b6a254ff9626d8773399..HEAD
git log --reverse --format='%H%x09%T%x09%s' 883f8adb4672b8748365b6a254ff9626d8773399..HEAD
./scripts/check-dco.sh 883f8adb4672b8748365b6a254ff9626d8773399 HEAD
```

Expected before certification: identity checks pass; DCO fails for exactly every unsigned branch commit and requests only `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>`.

Stop and request explicit human certification of that exact base/head range. Do not add a trailer based on plan approval, code review, or generic publication authorization.

- [ ] **Step 6: After certification, back up and rewrite metadata only**

Capture immutable comparisons, create a timestamped backup ref and complete
verified bundle, then rewrite only commit metadata:

```bash
freshness_base=883f8adb4672b8748365b6a254ff9626d8773399
freshness_backup_stamp=$(date -u +%Y%m%dT%H%M%SZ)
freshness_backup_ref="refs/backup/pre-m1-008-dco/$freshness_backup_stamp/tip"
freshness_bundle="../backups/ogir-m1-008-pre-dco-$freshness_backup_stamp.bundle"
freshness_old_count=$(git rev-list --count "$freshness_base"..HEAD)
freshness_old_sequence=$(git log --reverse --format='%T%x09%s' "$freshness_base"..HEAD)
git update-ref "$freshness_backup_ref" HEAD
git bundle create "$freshness_bundle" --all
git bundle verify "$freshness_bundle"
sha256sum "$freshness_bundle"
git rebase --force-rebase --signoff 883f8adb4672b8748365b6a254ff9626d8773399
```

Prove count/tree/subject equivalence, whole-tree equivalence, linear topology,
the exact one allowed trailer per commit, DCO, repository integrity, clean
status, and unchanged main:

```bash
test "$(git rev-list --count "$freshness_base"..HEAD)" = "$freshness_old_count"
test "$(git log --reverse --format='%T%x09%s' "$freshness_base"..HEAD)" = "$freshness_old_sequence"
git diff --exit-code "$freshness_backup_ref" HEAD
test "$(git rev-list --count --merges "$freshness_base"..HEAD)" -eq 0
while IFS= read -r freshness_commit; do
    test "$(git show -s --format=%B "$freshness_commit" | git interpret-trailers --parse | rg '^Signed-off-by:')" = 'Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>'
done < <(git rev-list "$freshness_base"..HEAD)
./scripts/check-dco.sh "$freshness_base" HEAD
git fsck --full --no-dangling
git status --porcelain=v1
test "$(git rev-parse main)" = "$freshness_base"
test "$(git rev-parse origin/main)" = "$freshness_base"
```

Expected: every command passes and status output is empty. Rerun the complete
matrix from Step 1 and obtain a fresh independent rewritten-SHA audit before
publication.

- [ ] **Step 7: Publish only after rewritten audit Yes**

Verify remote main still equals `883f8adb4672b8748365b6a254ff9626d8773399` and no same-name branch/PR exists, then non-force push and create the issue-linked PR from `.github/pull_request_template.md`. Leave `Human-Reviewed-Every-Line` and responsibility unchecked until the human actually completes them. Watch CI, CodeQL, and both DCO checks to terminal success; preserve the worktree for review feedback.

---

## Adversarial Review Amendments

The fresh-context review of `883f8ad..2eb6b9a` returned No with two Important
findings. The following amendments supersede earlier Task 3–5 snippets:

1. `ReplayStore` also exposes atomic durable `observe_time(now)`. The verifier
   calls `FreshnessGuard::evaluate_window`, which commits/checks the time floor
   before strict window evaluation. `register` and raw `claim` call their store
   operations directly because those operations already observe time first.
2. A rejected future-time request must leave its time floor durable across
   snapshot/reopen; any later lower request is `ClockRollback`/retry rather than
   becoming eligible again.
3. Public `FreshnessGuard::claim` returns `Result<(), FreshnessError>` and can
   consume but cannot mint `FreshnessChecked`. Only crate-private
   `claim_checked`, called after the verifier's context comparison, constructs
   the capability. The research verifier still lacks publisher authentication
   and therefore never authorizes.
4. The arbitrary-sequence oracle applies unavailable → rollback → durable
   high-water advance → window → replay-state precedence, independently of the
   implementation.
5. Add a failing future-observation/restart regression and a compile-fail raw
   capability-bypass test before the fixes. Mutation-probe both fixes, rerun the
   complete matrix, and obtain a fresh independent Yes verdict before live
   issue sync or DCO freeze.
6. Re-review requires an altered-first raw-claim test: reject a same-key changed
   binding/window, then prove the original challenge still claims exactly once.
   Mutation-probe a premature `Consumed` write before binding/window validation.
   Record both confirmed defects in `docs/LESSONS_LEARNED.md` as required by the
   AI development policy.
7. Final standards review requires issue taxonomy for model/verifier,
   trusted-computing-base, and privacy scope plus all mandatory AI-task sections.
   Obtain targeted TCB and privacy specialist Yes verdicts before live sync.
8. `ReplayDetected` is produced for duplicate registration, altered binding/
   window, and consumed state. Its context-free `Display` must describe
   "already registered or consumed"; pin that wording in a model regression and
   record the diagnostic defect in `docs/LESSONS_LEARNED.md`.

---

## Approved-Spec Coverage Map

| Approved design obligation | Implemented/proved in |
| --- | --- |
| Publisher issuer/verifier authority; no client clock or RNG implementation | Tasks 1–3 APIs; Task 6 architecture/ADR; Task 7 raw-field/dependency scans |
| Checked construction and strict zero-leeway `[issued_at, expires_at)` | Task 1 model tests and exact-expiry/before-issue mutation probes |
| Replay key exactly `(PublisherId, Nonce)` across every context | Task 3 key contract; Task 5 changed-binding/window, cross-publisher, and mutation tests |
| Durable registration before return and irreversible atomic claim before appraisal | Task 3 store contract; Task 4 verifier order; repeated-request and forced-race tests |
| Restart survival, monotonic time floor, rollback/missing/corrupt/unavailable fail-closed behavior | Task 5 snapshot, reopen, rollback, unavailable, property, and mutation tests |
| Expiry-only GC with no live eviction | Task 3 atomic algorithms; Task 5 exact-expiry GC/capacity/property/mutation tests |
| Explicit finite lifetime, total/publisher/account/rate limits with no defaults | Task 1 nonzero types/getters; Task 5 exact-limit, one-over, rate-window, and restart tests |
| Privacy-minimal state and redacted errors/debug output | Task 3 private fields/getters; Task 5 redaction test; Task 6 ADR/threat/invariant text |
| Non-disciplinary external error mapping and no `Allow` | Tasks 2 and 4 mapping/tests; Task 7 acceptance review |
| Database-neutral synchronous boundary; no new dependency or unsafe/async/serialization choice | Task 3 `ReplayStore`; Task 6 dependency ADR; Task 7 manifest and full-matrix scans |
| Deterministic arbitrary sequences and mutation resistance | Task 5 fixed-seed oracle and fourteen isolated mutation probes after review remediation |
| Repository governance, issue state, independent review, DCO, and publication | Tasks 0, 6, and 7 |

---

## Plan Self-Review Checklist

- [x] Every approved design section maps to at least one task and named test.
- [x] Type/method/field names are consistent across tasks.
- [x] No task adds a production dependency, unsafe code, database, async runtime, serializer, clock source, or RNG implementation.
- [x] No unresolved drafting marker, elided code body, analogy-only instruction, or unspecified error-handling step remains.
- [x] Every production behavior has a preceding failing test and expected RED reason.
- [x] Each source-changing task includes scoped verification and an atomic commit before publication.
- [x] Final publication remains gated on independent review and explicit human DCO certification.
