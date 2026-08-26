# M1-010 Fail-Closed Verifier State Machine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement one deterministic, fail-closed publisher-verifier flow whose exact attempt-bound gates are the only path to a non-forgeable `VerifiedAttestation` capability.

**Architecture:** Add one focused `ogir-verifier::verification` module that owns the request, private allocation-identity binding, checked runtime graph, terminal mappings, opaque gate capabilities, and authority-bearing final capability. Keep durable freshness atomicity in the existing `freshness` module, make the unauthenticated research scaffold use raw claim without minting authority, and redact the adjacent protocol evidence aggregate. Private child tests exercise trusted fixtures without shipping fake production capability constructors.

**Tech Stack:** Rust 1.98.0, edition 2024, Rust standard library (`Arc::ptr_eq`), existing `ogir-model`, `ogir-protocol`, and `ogir-verifier` workspace crates, Cargo tests/doctests/Clippy/rustdoc, Bash/Git disposable mutation worktrees, GitHub CLI, and the existing dependency-free attack-scenario validator.

**Spec:** `docs/superpowers/specs/2026-08-26-m1-010-verifier-state-machine-design.md`

## Global Constraints

- Before every task, read the approved spec plus `docs/SECURITY_INVARIANTS.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, and `docs/AI_DEVELOPMENT_POLICY.md` sections named by that task.
- Work only in `/home/wisbfime/Open Game Intergrity Runtime  - Github Project/open-game-integrity-runtime-m1-010` on `research/m1-010-verifier-state-machine`; preserve every other worktree.
- Keep `#![forbid(unsafe_code)]`; add no `unsafe`, C, FFI, parser, serializer, network, async runtime, database, filesystem operation, clock source, random generator, cryptographic primitive, TPM operation, policy language, signer, permit, production key, or privileged behavior.
- Add no Cargo dependency, feature, crate, or build script. Do not modify any `Cargo.toml`, `Cargo.lock`, or `rust-toolchain.toml`.
- `Decision`, `ReasonCode`, and `VerificationOutcome` are report-only. No authority consumer may accept them in place of `VerifiedAttestation`.
- `VerifierFlow`, all seven gate capabilities, and `VerifiedAttestation` remain non-`Clone`, non-`Copy`, privately bound, and manually redacted.
- `VerificationOutcome` fields remain private. All five decisions and twelve reasons arise only through the exact approved mapping.
- Every capability transition checks phase first, allocation identity second, and mutates last. A submitted capability is consumed on success or rejection.
- Both full and restricted success require every gate. Restricted is a separately selected/satisfied relying-party policy, never fallback after full-policy failure.
- Every terminal transition releases the owned request without claiming memory zeroization. Every terminal rejects every later action and cannot issue another capability.
- The public research scaffold remains fail closed, preserves all M1-008 time/context/atomic-claim behavior, uses raw claim, and never constructs `FreshnessChecked` or `VerifiedAttestation`.
- No production gate factory is added merely for tests. `verification::tests` uses child-module privacy; the freshness module may expose a `#[cfg(test)] pub(crate)` fixture constructor used only by that test build.
- `Debug`/`Display` may expose only fixed type names, redaction markers, and approved safe enums. They never expose request values, evidence, replay registration, `Arc` address/count, or caller-controlled text.
- Every public type, variant, safe public field, function, and method has specific rustdoc; code sketches below omit repeated prose only where this global requirement supplies it.
- Every public fallible method documents its exact `# Errors` contract and uses checked intra-doc links.
- Production code uses no `unwrap`, `expect`, `panic`, `todo`, `unimplemented`, permissive default, or swallowed error.
- Write each negative test first and run it to the specified RED result before production changes. If RED fails for a different reason, correct the test before implementing.
- After every task commit, a fresh reviewer checks both repository standards and the task/spec diff. Do not start the next task with an unresolved finding.
- The controller owns Shared Memory, live GitHub mutation, DCO rewrite, publication, and final review state. A worker returns exact facts; the controller refreshes `/home/wisbfime/Agent Shared Memory/project-open-game-integrity-runtime.md` and `index.md` before the next dispatch.
- Keep every commit unsigned until the user certifies one exact frozen range. Never add `Signed-off-by: archledger <archledger236@gmail.com>`. The only permitted eventual trailer is `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>` after exact human certification.
- Do not push, open a PR, rewrite commit metadata, move the issue to `needs-review`, or imply production readiness before Tasks 10-11 authorize the exact action.

## File Map

**Create:**

- `crates/ogir-verifier/src/verification.rs` — request/report contract, private attempt binding, checked graph, gate/final capabilities, terminal/error/diagnostic logic.
- `crates/ogir-verifier/src/verification/tests.rs` — private fixtures, independent oracle, exhaustive/permutation/property/binding/privacy/structural tests.
- `crates/ogir-verifier/tests/verification_public.rs` — downstream-visible begin/phase/outcome/redaction contract.
- `lab/scenarios/verifier-gate-skip.scenario.json` — mandatory-gate omission trace.
- `lab/scenarios/verifier-capability-substitution.scenario.json` — equal-request cross-flow substitution trace.
- `lab/scenarios/verifier-terminal-immutability.scenario.json` — terminal re-entry/reclassification trace.
- `lab/scenarios/verifier-unknown-gate.scenario.json` — unknown required gate fail-closed trace.
- `lab/scenarios/verifier-diagnostics-privacy.scenario.json` — request/evidence/binding diagnostic disclosure trace.
- `docs/adr/0007-verifier-flow-capabilities.md` — durable verifier state/capability/outcome decision.

**Modify:**

- `crates/ogir-protocol/src/lib.rs` — replace derived `EvidenceBundle::Debug` with fixed redaction.
- `crates/ogir-protocol/tests/evidence_profile.rs` — direct non-vacuous evidence diagnostic regression.
- `crates/ogir-verifier/src/lib.rs` — declare/re-export the reviewed verification module contract.
- `crates/ogir-verifier/src/freshness.rs` — remove unauthenticated checked minting; bind `FreshnessChecked` to one verification attempt; preserve raw claim.
- `crates/ogir-verifier/tests/freshness.rs` — use read-only outcome accessors and retain every M1-008 behavior/error assertion.
- `docs/ARCHITECTURE.md` — verifier report-versus-authority boundary, exact graph, process-local binding, deferred claims/signer.
- `docs/ROADMAP.md` — distinguish pure appraisal proof from later result/permit/renewal lifecycle.
- `docs/THREAT_MODEL.md` — gate skip, equal-data substitution, terminal mutation, unknown gate, diagnostics, residual trusted-producer compromise.
- `docs/TEST_STRATEGY.md` — exact 182-pair/permutation/million-action/compile-fail/mutation evidence.
- `docs/adr/index.md` — exact ADR-0007 Accepted row.
- `planning/issues/010-verifier-state-machine.md` — implementation evidence and status transition only after proof/review.
- `docs/LESSONS_LEARNED.md` — append only for a concrete durable implementation/review lesson.

**Intentionally unchanged:**

- `ogir-model`, `ogir-agent`, application binaries, all Cargo manifests/lockfiles/toolchain files, and current public identifier/freshness-store semantics.
- Attack-scenario schema/validator and owner/profile registries unless a concrete independently reviewed defect is reproduced.
- Any real challenge/evidence/identity/session/revocation/policy adapter, result signer, permit, wire format, or network service.

---

### Task 1: Guardedly Publish the Reviewed Ready Issue and Freeze Preconditions

**Files:**

- Read: `planning/issues/010-verifier-state-machine.md`
- Read: `scripts/create-initial-issues.sh`
- External: one GitHub issue only; no repository file change

**Interfaces:**

- Consumes: approved issue body at local `status: ready`, approved plan commit, exact remote main `b3a8f1431258a41d38df88c3724ab384dab1272a`.
- Produces: one open live issue with exact title/body/labels/milestone and a stable issue number discoverable by exact title.

- [ ] **Step 1: Revalidate immutable local and remote preconditions**

Run each command separately:

```bash
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
git ls-remote origin refs/heads/main
git ls-remote --heads origin refs/heads/research/m1-010-verifier-state-machine
gh issue list --repo archledger/open-game-integrity-runtime --state all --limit 500 --json number,title,state,url
gh pr list --repo archledger/open-game-integrity-runtime --state open --limit 100 --json number,title,state,url
sha256sum planning/issues/010-verifier-state-machine.md
m1_010_existing_count="$(gh issue list --repo archledger/open-game-integrity-runtime --state all --limit 500 --json title --jq '[.[] | select(.title == "M1-010: Implement the fail-closed verifier state machine")] | length')"
test "${m1_010_existing_count}" -eq 0
```

Expected:

- clean local M1-010 branch at the exact approved plan head;
- local/remote main both equal `b3a8f1431258a41d38df88c3724ab384dab1272a`;
- no remote M1-010 branch and no open PR;
- zero issue titles equal to `M1-010: Implement the fail-closed verifier state machine`;
- local issue SHA-256 equals the plan-reviewed hash recorded in Shared Memory.

If main, the issue title, or any canonical body/metadata precondition differs, stop without writing GitHub and obtain review of the new state.

- [ ] **Step 2: Create exactly the reviewed M1-010 issue**

Run:

```bash
m1_010_issue_title='M1-010: Implement the fail-closed verifier state machine'
m1_010_issue_url="$(gh issue create --repo archledger/open-game-integrity-runtime --title "${m1_010_issue_title}" --body-file planning/issues/010-verifier-state-machine.md --milestone 'M1 Domain Model' --label 'type: implementation' --label 'area: model' --label 'area: verifier' --label 'area: privacy' --label 'risk: trusted-computing-base' --label 'risk: privacy' --label 'status: ready')"
printf '%s' "${m1_010_issue_url}"
```

Expected: one GitHub issue URL ending in the decimal issue number. Do not guess or hard-code that number.

- [ ] **Step 3: Read back exact live bytes and metadata**

Run:

```bash
m1_010_issue_number="$(gh issue list --repo archledger/open-game-integrity-runtime --state all --limit 500 --search 'M1-010: Implement the fail-closed verifier state machine in:title' --json number,title --jq '.[] | select(.title == "M1-010: Implement the fail-closed verifier state machine") | .number')"
m1_010_issue_count="$(gh issue list --repo archledger/open-game-integrity-runtime --state all --limit 500 --json title --jq '[.[] | select(.title == "M1-010: Implement the fail-closed verifier state machine")] | length')"
test "${m1_010_issue_count}" -eq 1
test -n "${m1_010_issue_number}"
m1_010_local_body="$(base64 -w0 planning/issues/010-verifier-state-machine.md)"
m1_010_live_body="$(gh issue view "${m1_010_issue_number}" --repo archledger/open-game-integrity-runtime --json body --jq '.body | @base64')"
test "${m1_010_live_body}" = "${m1_010_local_body}"
gh issue view "${m1_010_issue_number}" --repo archledger/open-game-integrity-runtime --json number,title,state,milestone,labels,url
```

Expected metadata:

```text
state: OPEN
milestone: M1 Domain Model
labels (sorted): area: model,area: privacy,area: verifier,risk: privacy,risk: trusted-computing-base,status: ready,type: implementation
```

If body bytes or metadata differ, do not continue to code. Preserve the returned issue number, diagnose the exact mismatch, and use a guarded correction only after review.

- [ ] **Step 4: Record external state and rollback**

Refresh Shared Memory with the exact issue number/URL, live body hash, labels, milestone, local HEAD, remote main, and absence of remote branch/PR. Rollback before implementation is to close only this issue after explicit authorization; never delete or rewrite unrelated issues.

No repository commit is created in this task.

---

### Task 2: Redact `EvidenceBundle` Diagnostics Test-First

**Files:**

- Modify: `crates/ogir-protocol/tests/evidence_profile.rs`
- Modify: `crates/ogir-protocol/src/lib.rs`

**Interfaces:**

- Consumes: existing public `EvidenceBundle { profile_id, payload }` shape and `fmt` import.
- Produces: unchanged construction/equality/ownership plus exact `Debug` output `EvidenceBundle([REDACTED])`.

- [ ] **Step 1: Add the direct failing privacy regression**

Append to `crates/ogir-protocol/tests/evidence_profile.rs`:

```rust
#[test]
fn evidence_bundle_debug_redacts_profile_and_payload() {
    let profile_sentinel = "private-profile-sentinel";
    let payload_sentinel = b"private-evidence-payload-sentinel";
    let profile = match EvidenceProfile::try_from(profile_sentinel) {
        Ok(value) => value,
        Err(error) => panic!("valid evidence profile rejected: {error:?}"),
    };
    let evidence = EvidenceBundle {
        profile_id: profile,
        payload: payload_sentinel.to_vec(),
    };

    let diagnostic = format!("{evidence:?}");
    assert_eq!(diagnostic, "EvidenceBundle([REDACTED])");
    assert!(!diagnostic.contains(profile_sentinel));
    assert!(!diagnostic.contains("private-evidence-payload-sentinel"));
}
```

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
cargo test -p ogir-protocol --test evidence_profile evidence_bundle_debug_redacts_profile_and_payload -- --exact
```

Expected: FAIL at `assert_eq!` because derived `Debug` prints the struct fields. The synthetic sentinel may appear only in this expected local RED output; no real evidence is used.

- [ ] **Step 3: Replace derived `Debug` with the fixed implementation**

In `crates/ogir-protocol/src/lib.rs`, change the derive and add the implementation exactly:

```rust
#[derive(Clone, PartialEq, Eq)]
pub struct EvidenceBundle {
    /// Evidence profile identifier.
    pub profile_id: EvidenceProfile,
    /// Encoded payload owned by the selected attestation profile.
    pub payload: Vec<u8>,
}

impl fmt::Debug for EvidenceBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EvidenceBundle([REDACTED])")
    }
}
```

Do not change field visibility, `Clone`, equality, profile validation, payload ownership, or framing limits.

- [ ] **Step 4: Run focused GREEN and crate gates**

Run:

```bash
cargo test -p ogir-protocol --test evidence_profile evidence_bundle_debug_redacts_profile_and_payload -- --exact
cargo test -p ogir-protocol --all-features
cargo clippy -p ogir-protocol --all-targets --all-features -- -D warnings
cargo doc -p ogir-protocol --no-deps
git diff --check
```

Expected: all commands exit 0; the focused test reports one pass.

- [ ] **Step 5: Commit the isolated privacy hardening**

```bash
git add crates/ogir-protocol/src/lib.rs crates/ogir-protocol/tests/evidence_profile.rs
git diff --cached --check
git commit -m "fix: redact evidence bundle diagnostics"
```

Expected: one unsigned two-file commit. Refresh Shared Memory, then obtain a fresh task review before Task 3.

---

### Task 3: Seal Reporting Outcomes and Remove Unauthenticated Capability Minting

**Files:**

- Create: `crates/ogir-verifier/src/verification.rs`
- Modify: `crates/ogir-verifier/src/lib.rs`
- Modify: `crates/ogir-verifier/src/freshness.rs`
- Modify: `crates/ogir-verifier/tests/freshness.rs`

**Interfaces:**

- Consumes: current `ExpectedContext`, `VerificationRequest`, `VerificationOutcome`, `verify_research_structure`, `FreshnessGuard::claim`, and all M1-008 tests.
- Produces: unchanged top-level imports for the moved request/report types and function; private outcome fields with `decision()`/`reason()`; research raw claim with no `FreshnessChecked` minting.

- [ ] **Step 1: Change integration assertions to the required read-only API**

In `crates/ogir-verifier/tests/freshness.rs`, replace every report field read:

```rust
outcome.decision
outcome.reason
```

with:

```rust
outcome.decision()
outcome.reason()
```

Keep every expected `Decision` and `ReasonCode` unchanged. Add this regression:

```rust
#[test]
fn research_scaffold_reports_without_authority() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits());
    let challenge = challenge("example.game", [91; 32]);
    assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));

    let outcome = verify_research_structure(&request(challenge, 100), &guard);
    assert_eq!(outcome.decision(), Decision::Deny);
    assert_eq!(outcome.reason(), ReasonCode::EvidenceInvalid);
}
```

- [ ] **Step 2: Run focused verification and observe RED**

Run:

```bash
cargo test -p ogir-verifier --test freshness research_scaffold_reports_without_authority -- --exact
```

Expected: compile failure `no method named decision` and/or `no method named reason` on `VerificationOutcome`. Do not add temporary public fields or extension traits.

- [ ] **Step 3: Move the request/report contract into `verification.rs`**

Create `crates/ogir-verifier/src/verification.rs` by moving the existing request/context/research function and using this outcome shape:

```rust
// SPDX-License-Identifier: Apache-2.0

//! Checked verifier-flow and report-only outcome contracts.

use std::fmt;

use ogir_model::{
    AccountScope, BuildId, Decision, FreshnessError, GameId, MatchId, PolicyId,
    PolicyVersion, PublisherChallenge, PublisherId, ReasonCode, UnixTime,
};
use ogir_protocol::EvidenceBundle;

use crate::freshness::{FreshnessGuard, ReplayStore};

#[derive(Clone, PartialEq, Eq)]
pub struct ExpectedContext {
    pub publisher_id: PublisherId,
    pub game_id: GameId,
    pub build_id: BuildId,
    pub account_scope: AccountScope,
    pub match_id: MatchId,
    pub policy_id: PolicyId,
    pub policy_version: PolicyVersion,
}

impl fmt::Debug for ExpectedContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedContext([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VerificationRequest {
    pub challenge: PublisherChallenge,
    pub evidence: EvidenceBundle,
    pub expected: ExpectedContext,
    pub now: UnixTime,
}

impl fmt::Debug for VerificationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerificationRequest([REDACTED])")
    }
}

/// Report-only view of a verifier terminal.
///
/// ```compile_fail
/// use ogir_model::{Decision, ReasonCode};
/// use ogir_verifier::VerificationOutcome;
///
/// let forged = VerificationOutcome {
///     decision: Decision::Allow,
///     reason: ReasonCode::None,
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationOutcome {
    decision: Decision,
    reason: ReasonCode,
}

impl VerificationOutcome {
    #[must_use]
    pub const fn decision(self) -> Decision {
        self.decision
    }

    #[must_use]
    pub const fn reason(self) -> ReasonCode {
        self.reason
    }
}

const fn denied(reason: ReasonCode) -> VerificationOutcome {
    VerificationOutcome {
        decision: Decision::Deny,
        reason,
    }
}

const fn retry_unavailable() -> VerificationOutcome {
    VerificationOutcome {
        decision: Decision::Retry,
        reason: ReasonCode::AttestationUnavailable,
    }
}
```

Move `freshness_failure` unchanged in meaning, using `retry_unavailable()` for rollback/unavailable/capacity. Move `verify_research_structure` and replace its checked claim block with raw claim:

```rust
if let Err(error) = freshness.claim(request.now, &request.challenge) {
    return freshness_failure(error);
}

denied(ReasonCode::EvidenceInvalid)
```

The function still performs durable window observation before exact expected-context comparison and raw irreversible claim. It never creates or mentions a local `FreshnessChecked` value.

- [ ] **Step 4: Declare/re-export the module and remove old definitions**

Reduce `crates/ogir-verifier/src/lib.rs` to module declarations/re-exports plus the crate docs:

```rust
mod freshness;
mod verification;

pub use freshness::{
    ChallengeBinding, FreshnessChecked, FreshnessGuard, ReplayKey,
    ReplayRegistration, ReplayStore,
};
pub use verification::{
    ExpectedContext, VerificationOutcome, VerificationRequest,
    verify_research_structure,
};
```

Remove the moved imports, structs, function, and helper mappings from `lib.rs`.

In `crates/ogir-verifier/src/freshness.rs`, delete only the crate-private `claim_checked` method. Keep public raw `claim`, the opaque `FreshnessChecked` type/doctests, registration, and store semantics unchanged until Task 4 binds the type.

- [ ] **Step 5: Run focused GREEN and preservation gates**

Run:

```bash
cargo test -p ogir-verifier --test freshness
cargo test -p ogir-verifier --doc
cargo clippy -p ogir-verifier --all-targets --all-features -- -D warnings
cargo doc -p ogir-verifier --no-deps
rg -n 'claim_checked' crates/ogir-verifier/src crates/ogir-verifier/tests
git diff --check
```

Expected:

- 30 verifier integration tests pass after adding the regression;
- verifier doctests pass, including external outcome construction failure;
- Clippy/rustdoc exit 0;
- `rg` exits 1 with no `claim_checked` occurrence;
- all M1-008 result mappings and replay effects remain unchanged.

- [ ] **Step 6: Commit the report/freshness boundary**

```bash
git add crates/ogir-verifier/src/lib.rs crates/ogir-verifier/src/verification.rs crates/ogir-verifier/src/freshness.rs crates/ogir-verifier/tests/freshness.rs
git diff --cached --check
git commit -m "refactor: seal verifier reporting outcomes"
```

Expected: one unsigned four-file commit. Refresh Shared Memory and obtain fresh task review before Task 4.

---

### Task 4: Implement the Attempt-Bound Success Graph Test-First

**Files:**

- Modify: `crates/ogir-verifier/src/verification.rs`
- Create: `crates/ogir-verifier/src/verification/tests.rs`
- Create: `crates/ogir-verifier/tests/verification_public.rs`
- Modify: `crates/ogir-verifier/src/freshness.rs`
- Modify: `crates/ogir-verifier/src/lib.rs`

**Interfaces:**

- Consumes: `VerificationRequest`, `VerificationOutcome`, `ReplayRegistration`, public raw freshness, and the exact approved graph.
- Produces: `VerifierFlow::begin/phase/outcome`, seven opaque bound gate types, `VerifiedAttestation`, eight success transitions, `VerificationPhase`, `VerificationAction`, `DenialReason`, and `TransitionError` at top-level `ogir_verifier` imports.

- [ ] **Step 1: Add public and private RED contract tests**

Create `crates/ogir-verifier/tests/verification_public.rs` with the SPDX header and these complete synthetic fixture helpers:

```rust
use std::fmt::Debug;
use std::num::NonZeroU64;

use ogir_model::{
    AccountScope, BuildId, ChallengeLifetime, ChallengeWindow, EvidenceProfile,
    GameId, IdentifierError, MatchId, Nonce, PolicyId, PolicyVersion,
    ProtocolVersion, PublisherChallenge, PublisherId, UnixTime,
};
use ogir_protocol::EvidenceBundle;
use ogir_verifier::{ExpectedContext, VerificationRequest};

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

fn request_fixture() -> VerificationRequest {
    let maximum = match NonZeroU64::new(100) {
        Some(value) => ChallengeLifetime::new(value),
        None => panic!("fixture maximum must be nonzero"),
    };
    let window = match ChallengeWindow::new(UnixTime::new(100), UnixTime::new(200), maximum) {
        Ok(value) => value,
        Err(error) => panic!("valid window rejected: {error:?}"),
    };
    VerificationRequest {
        challenge: PublisherChallenge {
            version: ProtocolVersion { major: 0, minor: 1 },
            publisher_id: identifier::<PublisherId>("example.publisher"),
            game_id: identifier::<GameId>("example.game"),
            build_id: identifier::<BuildId>("build-1"),
            account_scope: identifier::<AccountScope>("account-1"),
            match_id: identifier::<MatchId>("match-1"),
            policy_id: identifier::<PolicyId>("research-v0"),
            policy_version: PolicyVersion::new(1),
            nonce: Nonce::from_bytes([7; 32]),
            window,
        },
        evidence: EvidenceBundle {
            profile_id: identifier::<EvidenceProfile>("mock-v0"),
            payload: b"synthetic-public-fixture".to_vec(),
        },
        expected: ExpectedContext {
            publisher_id: identifier::<PublisherId>("example.publisher"),
            game_id: identifier::<GameId>("example.game"),
            build_id: identifier::<BuildId>("build-1"),
            account_scope: identifier::<AccountScope>("account-1"),
            match_id: identifier::<MatchId>("match-1"),
            policy_id: identifier::<PolicyId>("research-v0"),
            policy_version: PolicyVersion::new(1),
        },
        now: UnixTime::new(100),
    }
}
```

Then add this external contract:

```rust
use ogir_verifier::{VerificationPhase, VerifierFlow};

#[test]
fn new_flow_exposes_only_received_phase_and_no_outcome() {
    let flow = VerifierFlow::begin(request_fixture());
    assert_eq!(flow.phase(), VerificationPhase::EvidenceReceived);
    assert_eq!(flow.outcome(), None);
    assert_eq!(format!("{flow:?}"), "VerifierFlow { phase: EvidenceReceived, outcome: None }");
}
```

The fixture uses no new dependency, clock, random input, or real identity.

Create `crates/ogir-verifier/src/verification/tests.rs` with these private fixture helpers before the first tests:

```rust
use std::fmt::Debug;
use std::num::NonZeroU64;

use ogir_model::{
    AccountScope, BuildId, ChallengeLifetime, ChallengeWindow, Decision,
    EvidenceProfile, GameId, IdentifierError, MatchId, Nonce, PolicyId,
    PolicyVersion, ProtocolVersion, PublisherChallenge, PublisherId,
    ReasonCode, UnixTime,
};
use ogir_protocol::EvidenceBundle;

use super::*;

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

fn request_fixture(seed: u8) -> VerificationRequest {
    let maximum = match NonZeroU64::new(100) {
        Some(value) => ChallengeLifetime::new(value),
        None => panic!("fixture maximum must be nonzero"),
    };
    let window = match ChallengeWindow::new(UnixTime::new(100), UnixTime::new(200), maximum) {
        Ok(value) => value,
        Err(error) => panic!("valid window rejected: {error:?}"),
    };
    VerificationRequest {
        challenge: PublisherChallenge {
            version: ProtocolVersion { major: 0, minor: 1 },
            publisher_id: identifier::<PublisherId>("example.publisher"),
            game_id: identifier::<GameId>("example.game"),
            build_id: identifier::<BuildId>("build-1"),
            account_scope: identifier::<AccountScope>("account-1"),
            match_id: identifier::<MatchId>("match-1"),
            policy_id: identifier::<PolicyId>("research-v0"),
            policy_version: PolicyVersion::new(1),
            nonce: Nonce::from_bytes([seed; 32]),
            window,
        },
        evidence: EvidenceBundle {
            profile_id: identifier::<EvidenceProfile>("mock-v0"),
            payload: vec![seed; 8],
        },
        expected: ExpectedContext {
            publisher_id: identifier::<PublisherId>("example.publisher"),
            game_id: identifier::<GameId>("example.game"),
            build_id: identifier::<BuildId>("build-1"),
            account_scope: identifier::<AccountScope>("account-1"),
            match_id: identifier::<MatchId>("match-1"),
            policy_id: identifier::<PolicyId>("research-v0"),
            policy_version: PolicyVersion::new(1),
        },
        now: UnixTime::new(100),
    }
}

fn flow_fixture(seed: u8) -> VerifierFlow {
    VerifierFlow::begin(request_fixture(seed))
}

fn advance_to_policy_ready(flow: &mut VerifierFlow, allowed: AllowedClass) {
    let binding = flow.binding.clone();
    assert_eq!(flow.record_challenge_authenticated(ChallengeAuthenticated { binding: binding.clone() }), Ok(()));
    assert_eq!(flow.record_freshness_checked(crate::freshness::test_freshness_checked(binding.clone())), Ok(()));
    assert_eq!(flow.record_identity_checked(IdentityChecked { binding: binding.clone() }), Ok(()));
    assert_eq!(flow.record_evidence_appraised(EvidenceAppraised { binding: binding.clone() }), Ok(()));
    assert_eq!(flow.record_session_bound(SessionBound { binding: binding.clone() }), Ok(()));
    assert_eq!(flow.record_revocation_checked(RevocationChecked { binding: binding.clone() }), Ok(()));
    assert_eq!(flow.record_policy_satisfied(PolicySatisfied { binding, allowed }), Ok(()));
}

fn policy_ready_flow(seed: u8, allowed: AllowedClass) -> VerifierFlow {
    let mut flow = flow_fixture(seed);
    advance_to_policy_ready(&mut flow, allowed);
    flow
}
```

Then add these first tests:

```rust
#[test]
fn canonical_full_path_returns_one_bound_verified_capability() {
    let mut flow = flow_fixture(7);
    let binding = flow.binding.clone();
    assert_eq!(flow.record_challenge_authenticated(ChallengeAuthenticated { binding: binding.clone() }), Ok(()));
    assert_eq!(flow.record_freshness_checked(crate::freshness::test_freshness_checked(binding.clone())), Ok(()));
    assert_eq!(flow.record_identity_checked(IdentityChecked { binding: binding.clone() }), Ok(()));
    assert_eq!(flow.record_evidence_appraised(EvidenceAppraised { binding: binding.clone() }), Ok(()));
    assert_eq!(flow.record_session_bound(SessionBound { binding: binding.clone() }), Ok(()));
    assert_eq!(flow.record_revocation_checked(RevocationChecked { binding: binding.clone() }), Ok(()));
    assert_eq!(flow.record_policy_satisfied(PolicySatisfied { binding, allowed: AllowedClass::Full }), Ok(()));

    let verified = match flow.complete() {
        Ok(value) => value,
        Err(error) => panic!("canonical path rejected: {error:?}"),
    };
    assert_eq!(flow.phase(), VerificationPhase::Verified);
    assert_eq!(flow.outcome().map(VerificationOutcome::decision), Some(Decision::Allow));
    assert_eq!(flow.outcome().map(VerificationOutcome::reason), Some(ReasonCode::None));
    assert_eq!(format!("{verified:?}"), "VerifiedAttestation([REDACTED])");
}

#[test]
fn complete_before_policy_satisfaction_rejects_without_releasing_request() {
    let mut flow = flow_fixture(8);
    assert_eq!(
        flow.complete(),
        Err(TransitionError::InvalidTransition {
            phase: VerificationPhase::EvidenceReceived,
            action: VerificationAction::Complete,
        })
    );
    assert_eq!(flow.phase(), VerificationPhase::EvidenceReceived);
    assert!(flow.request.is_some());
}

#[test]
fn equal_request_from_another_flow_rejects_challenge_capability() {
    let source = flow_fixture(8);
    let mut target = flow_fixture(8);
    assert_eq!(source.request.as_ref(), target.request.as_ref());
    let before_phase = target.phase();
    let before_request = target.request.clone();

    assert_eq!(
        target.record_challenge_authenticated(ChallengeAuthenticated {
            binding: source.binding.clone(),
        }),
        Err(TransitionError::CapabilityRejected {
            action: VerificationAction::RecordChallengeAuthenticated,
        })
    );
    assert_eq!(target.phase(), before_phase);
    assert_eq!(target.request, before_request);
}

#[test]
fn restricted_success_uses_the_same_complete_gate() {
    let mut flow = policy_ready_flow(9, AllowedClass::Restricted);
    assert!(flow.complete().is_ok());
    assert_eq!(flow.outcome().map(VerificationOutcome::decision), Some(Decision::AllowRestricted));
    assert_eq!(flow.outcome().map(VerificationOutcome::reason), Some(ReasonCode::None));
}
```

At the bottom of `verification.rs`, declare:

```rust
#[cfg(test)]
mod tests;
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```bash
cargo test -p ogir-verifier --test verification_public
cargo test -p ogir-verifier --lib verification::tests
```

Expected: compile failures for missing `VerifierFlow`, `VerificationPhase`, gate capabilities, and transition methods. The failures must originate from the intended missing contract, not fixture syntax.

- [ ] **Step 3: Add the exact public views and private attempt/state types**

In `verification.rs`, add imports:

```rust
use std::error::Error;
use std::sync::Arc;

use crate::freshness::{FreshnessChecked, ReplayRegistration};
```

Add the exact public enums:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationPhase {
    EvidenceReceived,
    ChallengeAuthenticated,
    FreshnessChecked,
    IdentityChecked,
    EvidenceAppraised,
    SessionBound,
    RevocationChecked,
    PolicySatisfied,
    Verified,
    Malformed,
    Unsupported,
    Retryable,
    Denied,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationAction {
    RecordChallengeAuthenticated,
    RecordFreshnessChecked,
    RecordIdentityChecked,
    RecordEvidenceAppraised,
    RecordSessionBound,
    RecordRevocationChecked,
    RecordPolicySatisfied,
    Complete,
    MarkMalformed,
    MarkUnsupported,
    MarkRetryable,
    Deny,
    MarkRevoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenialReason {
    NotYetValid,
    Expired,
    ReplayDetected,
    SessionBindingMismatch,
    EvidenceInvalid,
    PolicyDenied,
    ProtectedSessionLost,
}
```

Add the private attempt identity:

```rust
struct AttemptRecord {
    _registration: ReplayRegistration,
}

#[derive(Clone)]
pub(crate) struct VerificationBinding(Arc<AttemptRecord>);

impl VerificationBinding {
    fn new(challenge: &PublisherChallenge) -> Self {
        Self(Arc::new(AttemptRecord {
            _registration: ReplayRegistration::from_challenge(challenge),
        }))
    }

    fn matches(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for VerificationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerificationBinding([REDACTED])")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AllowedClass {
    Full,
    Restricted,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VerificationState {
    EvidenceReceived,
    ChallengeAuthenticated,
    FreshnessChecked,
    IdentityChecked,
    EvidenceAppraised,
    SessionBound,
    RevocationChecked,
    PolicySatisfied(AllowedClass),
    Verified(AllowedClass),
}
```

The underscore on `_registration` suppresses a speculative-unused-field warning while retaining the exact redacted context required by the approved binding. Do not add an unused getter or lint suppression.

- [ ] **Step 4: Add explicit opaque capabilities and redacted diagnostics**

Define each authority field explicitly:

```rust
#[must_use]
pub struct ChallengeAuthenticated {
    binding: VerificationBinding,
}

#[must_use]
pub struct IdentityChecked {
    binding: VerificationBinding,
}

#[must_use]
pub struct EvidenceAppraised {
    binding: VerificationBinding,
}

#[must_use]
pub struct SessionBound {
    binding: VerificationBinding,
}

#[must_use]
pub struct RevocationChecked {
    binding: VerificationBinding,
}

#[must_use]
pub struct PolicySatisfied {
    binding: VerificationBinding,
    allowed: AllowedClass,
}

#[must_use]
pub struct VerifiedAttestation {
    binding: VerificationBinding,
    allowed: AllowedClass,
}
```

Use one private diagnostic macro only for repetitive formatting; do not generate the authority fields themselves:

```rust
macro_rules! impl_redacted_debug {
    ($type_name:ty, $text:literal) => {
        impl fmt::Debug for $type_name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($text)
            }
        }
    };
}

impl_redacted_debug!(ChallengeAuthenticated, "ChallengeAuthenticated([REDACTED])");
impl_redacted_debug!(IdentityChecked, "IdentityChecked([REDACTED])");
impl_redacted_debug!(EvidenceAppraised, "EvidenceAppraised([REDACTED])");
impl_redacted_debug!(SessionBound, "SessionBound([REDACTED])");
impl_redacted_debug!(RevocationChecked, "RevocationChecked([REDACTED])");
impl_redacted_debug!(PolicySatisfied, "PolicySatisfied([REDACTED])");

impl fmt::Debug for VerifiedAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _redacted_binding = &self.binding;
        let _redacted_allowed = self.allowed;
        formatter.write_str("VerifiedAttestation([REDACTED])")
    }
}
```

The local reads prevent dead-field lint suppression without exposing either value. Do not derive `Clone`, `Copy`, `Default`, serialization, or equality on an authority-bearing public type.

- [ ] **Step 5: Bind `FreshnessChecked` without a production constructor**

In `freshness.rs`, import the binding and replace the zero-sized type:

```rust
use crate::verification::VerificationBinding;

#[must_use]
pub struct FreshnessChecked {
    binding: VerificationBinding,
}

impl FreshnessChecked {
    pub(crate) fn binding(&self) -> &VerificationBinding {
        &self.binding
    }
}

impl fmt::Debug for FreshnessChecked {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FreshnessChecked([REDACTED])")
    }
}

#[cfg(test)]
pub(crate) fn test_freshness_checked(binding: VerificationBinding) -> FreshnessChecked {
    FreshnessChecked { binding }
}
```

Update its construction doctest to fail on the private `binding` field. Keep the raw-claim-to-capability compile-fail example. There is no non-test constructor in this task.

- [ ] **Step 6: Implement transition errors and the eight success edges**

Add:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    InvalidTransition {
        phase: VerificationPhase,
        action: VerificationAction,
    },
    CapabilityRejected {
        action: VerificationAction,
    },
}

impl fmt::Display for TransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { .. } => {
                formatter.write_str("verifier transition is not allowed")
            }
            Self::CapabilityRejected { .. } => {
                formatter.write_str("verifier capability was rejected")
            }
        }
    }
}

impl Error for TransitionError {}

#[must_use]
pub struct VerifierFlow {
    binding: VerificationBinding,
    request: Option<VerificationRequest>,
    state: VerificationState,
}
```

Implement `begin`, `phase`, `outcome`, `invalid_transition`, and `ensure_binding`. `outcome()` returns `None` for all active states and maps `Verified(Full|Restricted)` through private exact `VerificationOutcome::allowed_full()` / `allowed_restricted()` helpers.

`begin` is exactly:

```rust
pub fn begin(request: VerificationRequest) -> Self {
    let binding = VerificationBinding::new(&request.challenge);
    Self {
        binding,
        request: Some(request),
        state: VerificationState::EvidenceReceived,
    }
}
```

`ensure_binding(action, candidate)` compares only `self.binding.matches(candidate)` and returns `CapabilityRejected { action }` on false. It neither mutates nor inspects request values.

Every ordinary gate method must use this explicit pattern:

```rust
pub fn record_identity_checked(
    &mut self,
    capability: IdentityChecked,
) -> Result<(), TransitionError> {
    if self.state != VerificationState::FreshnessChecked {
        return Err(self.invalid_transition(VerificationAction::RecordIdentityChecked));
    }
    self.ensure_binding(VerificationAction::RecordIdentityChecked, &capability.binding)?;
    self.state = VerificationState::IdentityChecked;
    Ok(())
}
```

Implement every edge explicitly according to this table; no wildcard/shared permissive state set is allowed:

| Method | Required state | Capability binding accessor | Next state | Public action |
| --- | --- | --- | --- | --- |
| `record_challenge_authenticated` | `EvidenceReceived` | `&capability.binding` | `ChallengeAuthenticated` | `RecordChallengeAuthenticated` |
| `record_freshness_checked` | `ChallengeAuthenticated` | `capability.binding()` | `FreshnessChecked` | `RecordFreshnessChecked` |
| `record_identity_checked` | `FreshnessChecked` | `&capability.binding` | `IdentityChecked` | `RecordIdentityChecked` |
| `record_evidence_appraised` | `IdentityChecked` | `&capability.binding` | `EvidenceAppraised` | `RecordEvidenceAppraised` |
| `record_session_bound` | `EvidenceAppraised` | `&capability.binding` | `SessionBound` | `RecordSessionBound` |
| `record_revocation_checked` | `SessionBound` | `&capability.binding` | `RevocationChecked` | `RecordRevocationChecked` |
| `record_policy_satisfied` | `RevocationChecked` | `&capability.binding` | `PolicySatisfied(capability.allowed)` | `RecordPolicySatisfied` |
| `complete` | `PolicySatisfied(allowed)` | no submitted capability | `Verified(allowed)` | `Complete` |

`complete()` sets `request = None` before returning exactly one `VerifiedAttestation { binding: self.binding.clone(), allowed }`. Every other edge retains the request.

Implement manual `Debug` for `VerifierFlow`:

```rust
impl fmt::Debug for VerifierFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifierFlow")
            .field("phase", &self.phase())
            .field("outcome", &self.outcome())
            .finish()
    }
}
```

Document `# Errors` on all eight public transitions.

- [ ] **Step 7: Re-export the complete reviewed surface**

Update `lib.rs`:

```rust
pub use verification::{
    ChallengeAuthenticated, DenialReason, EvidenceAppraised, ExpectedContext,
    IdentityChecked, PolicySatisfied, RevocationChecked, SessionBound,
    TransitionError, VerificationAction, VerificationOutcome,
    VerificationPhase, VerificationRequest, VerifiedAttestation, VerifierFlow,
    verify_research_structure,
};
```

Keep `FreshnessChecked` in the explicit freshness re-export list.

- [ ] **Step 8: Run focused GREEN and crate gates**

Run:

```bash
cargo test -p ogir-verifier --lib verification::tests
cargo test -p ogir-verifier --test verification_public
cargo test -p ogir-verifier --test freshness
cargo test -p ogir-verifier --doc
cargo clippy -p ogir-verifier --all-targets --all-features -- -D warnings
cargo doc -p ogir-verifier --no-deps
git diff --check
```

Expected: canonical full/restricted paths pass, early complete rejects unchanged, all existing freshness tests pass, doctests prove raw construction fails, and Clippy/rustdoc report no warning.

- [ ] **Step 9: Commit the bound success graph**

```bash
git add crates/ogir-verifier/src/verification.rs crates/ogir-verifier/src/verification/tests.rs crates/ogir-verifier/tests/verification_public.rs crates/ogir-verifier/src/freshness.rs crates/ogir-verifier/src/lib.rs
git diff --cached --check
git commit -m "feat: add attempt-bound verifier success gates"
```

Expected: one unsigned five-file commit. Refresh Shared Memory and obtain fresh task review before Task 5.

---

### Task 5: Add Immutable Failure Terminals and Exhaust the Finite Graph

**Files:**

- Modify: `crates/ogir-verifier/src/verification.rs`
- Modify: `crates/ogir-verifier/src/verification/tests.rs`

**Interfaces:**

- Consumes: Task 4 success graph, safe public phases/actions, private request/state, and report-only outcome.
- Produces: five typed failure methods, exact decision/reason mapping, permanent terminals, 182-pair independent oracle, seven gate omissions, and all 5,040 permutations.

- [ ] **Step 1: Write failure/outcome/terminal tests before implementation**

Add to `verification/tests.rs`:

```rust
#[test]
fn every_failure_class_is_terminal_and_releases_the_request() {
    for (action, expected_phase, expected_decision, expected_reason) in [
        (TestAction::MarkMalformed, VerificationPhase::Malformed, Decision::Deny, ReasonCode::Malformed),
        (TestAction::MarkUnsupported, VerificationPhase::Unsupported, Decision::Unsupported, ReasonCode::UnsupportedVersion),
        (TestAction::MarkRetryable, VerificationPhase::Retryable, Decision::Retry, ReasonCode::AttestationUnavailable),
        (TestAction::Deny(DenialReason::PolicyDenied), VerificationPhase::Denied, Decision::Deny, ReasonCode::PolicyDenied),
        (TestAction::MarkRevoked, VerificationPhase::Revoked, Decision::Deny, ReasonCode::Revoked),
    ] {
        let mut flow = flow_fixture(31);
        let other_binding = flow_fixture(31).binding;
        assert_eq!(
            apply_action(&mut flow, &other_binding, action),
            Ok(ActionResult::NoCapability)
        );
        assert_eq!(flow.phase(), expected_phase);
        assert_eq!(flow.outcome().map(VerificationOutcome::decision), Some(expected_decision));
        assert_eq!(flow.outcome().map(VerificationOutcome::reason), Some(expected_reason));
        assert!(flow.request.is_none());
        assert_every_action_rejected(&mut flow);
    }
}

#[test]
fn every_denial_reason_has_its_only_valid_reporting_mapping() {
    for (index, (reason, expected)) in [
        (DenialReason::NotYetValid, ReasonCode::NotYetValid),
        (DenialReason::Expired, ReasonCode::Expired),
        (DenialReason::ReplayDetected, ReasonCode::ReplayDetected),
        (DenialReason::SessionBindingMismatch, ReasonCode::SessionBindingMismatch),
        (DenialReason::EvidenceInvalid, ReasonCode::EvidenceInvalid),
        (DenialReason::PolicyDenied, ReasonCode::PolicyDenied),
        (DenialReason::ProtectedSessionLost, ReasonCode::ProtectedSessionLost),
    ]
    .into_iter()
    .enumerate()
    {
        let mut flow = flow_fixture(32 + index as u8);
        assert_eq!(flow.deny(reason), Ok(()));
        assert_eq!(flow.outcome().map(VerificationOutcome::decision), Some(Decision::Deny));
        assert_eq!(flow.outcome().map(VerificationOutcome::reason), Some(expected));
    }
}

#[test]
fn unknown_mandatory_gate_maps_to_unsupported() {
    let mut flow = flow_fixture(44);
    assert_eq!(flow.mark_unsupported(), Ok(()));
    assert_eq!(flow.phase(), VerificationPhase::Unsupported);
    assert_eq!(flow.outcome().map(VerificationOutcome::reason), Some(ReasonCode::UnsupportedVersion));
}
```

Define `ActionResult` so the harness discards but distinguishes the real authority token:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionResult {
    NoCapability,
    Verified,
}
```

`TestAction` has all 13 public action kinds; `Policy` carries one `AllowedClass` and `Deny` carries one `DenialReason`. `apply_action` maps `complete()` to `ActionResult::Verified` only after receiving and dropping the real `VerifiedAttestation`; the harness never substitutes a report.

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```bash
cargo test -p ogir-verifier --lib every_failure_class_is_terminal_and_releases_the_request -- --exact
cargo test -p ogir-verifier --lib every_denial_reason_has_its_only_valid_reporting_mapping -- --exact
```

Expected: compile failures for missing failure methods/private terminal state variants. Correct any test-helper error before implementation.

- [ ] **Step 3: Add private failure states and exact outcome constructors**

Extend `VerificationState`:

```rust
enum VerificationState {
    EvidenceReceived,
    ChallengeAuthenticated,
    FreshnessChecked,
    IdentityChecked,
    EvidenceAppraised,
    SessionBound,
    RevocationChecked,
    PolicySatisfied(AllowedClass),
    Verified(AllowedClass),
    Malformed,
    Unsupported,
    Retryable,
    Denied(DenialReason),
    Revoked,
}
```

Add only mapping-specific private constructors:

```rust
impl VerificationOutcome {
    const fn allowed_full() -> Self {
        Self { decision: Decision::Allow, reason: ReasonCode::None }
    }

    const fn allowed_restricted() -> Self {
        Self { decision: Decision::AllowRestricted, reason: ReasonCode::None }
    }

    const fn malformed() -> Self {
        Self { decision: Decision::Deny, reason: ReasonCode::Malformed }
    }

    const fn unsupported() -> Self {
        Self { decision: Decision::Unsupported, reason: ReasonCode::UnsupportedVersion }
    }

    const fn retryable() -> Self {
        Self { decision: Decision::Retry, reason: ReasonCode::AttestationUnavailable }
    }

    const fn revoked() -> Self {
        Self { decision: Decision::Deny, reason: ReasonCode::Revoked }
    }

    const fn denied(reason: DenialReason) -> Self {
        Self { decision: Decision::Deny, reason: reason.as_reason_code() }
    }
}
```

Implement `DenialReason::as_reason_code()` as one exhaustive `match` over its seven variants. Delete the generic `denied(ReasonCode)` helper from Task 3 entirely. Refactor the research scaffold to use only the mapping-specific constructors:

```rust
fn freshness_failure(error: FreshnessError) -> VerificationOutcome {
    match error {
        FreshnessError::InvalidWindow | FreshnessError::LifetimeExceeded => {
            VerificationOutcome::malformed()
        }
        FreshnessError::NotYetValid => {
            VerificationOutcome::denied(DenialReason::NotYetValid)
        }
        FreshnessError::Expired => {
            VerificationOutcome::denied(DenialReason::Expired)
        }
        FreshnessError::ReplayDetected => {
            VerificationOutcome::denied(DenialReason::ReplayDetected)
        }
        FreshnessError::ClockRollback
        | FreshnessError::StateUnavailable
        | FreshnessError::CapacityExceeded => VerificationOutcome::retryable(),
    }
}
```

Context mismatch uses `VerificationOutcome::denied(DenialReason::SessionBindingMismatch)` and the final opaque-evidence result uses `VerificationOutcome::denied(DenialReason::EvidenceInvalid)`. No function accepts an arbitrary `ReasonCode` together with a decision.

Expand `phase()` and `outcome()` with one explicit match arm per state. Do not use a wildcard arm.

- [ ] **Step 4: Implement the five failure transitions with one private helper**

Add:

```rust
fn is_terminal(&self) -> bool {
    matches!(
        self.state,
        VerificationState::Verified(_)
            | VerificationState::Malformed
            | VerificationState::Unsupported
            | VerificationState::Retryable
            | VerificationState::Denied(_)
            | VerificationState::Revoked
    )
}

fn enter_failure(
    &mut self,
    action: VerificationAction,
    next: VerificationState,
) -> Result<(), TransitionError> {
    if self.is_terminal() {
        return Err(self.invalid_transition(action));
    }
    self.request = None;
    self.state = next;
    Ok(())
}
```

Public methods map exactly:

```rust
pub fn mark_malformed(&mut self) -> Result<(), TransitionError> {
    self.enter_failure(VerificationAction::MarkMalformed, VerificationState::Malformed)
}

pub fn mark_unsupported(&mut self) -> Result<(), TransitionError> {
    self.enter_failure(VerificationAction::MarkUnsupported, VerificationState::Unsupported)
}

pub fn mark_retryable(&mut self) -> Result<(), TransitionError> {
    self.enter_failure(VerificationAction::MarkRetryable, VerificationState::Retryable)
}

pub fn deny(&mut self, reason: DenialReason) -> Result<(), TransitionError> {
    self.enter_failure(VerificationAction::Deny, VerificationState::Denied(reason))
}

pub fn mark_revoked(&mut self) -> Result<(), TransitionError> {
    self.enter_failure(VerificationAction::MarkRevoked, VerificationState::Revoked)
}
```

Document exact `# Errors`. Ensure `complete` and every capability transition also reject all six terminal states through their exact phase checks.

- [ ] **Step 5: Add the independent 182-pair literal oracle**

In `verification/tests.rs`, define an independent model that does not call production phase, outcome, or transition helpers:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingMode {
    Matching,
    OtherFlow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestAction {
    Challenge(BindingMode),
    Freshness(BindingMode),
    Identity(BindingMode),
    Evidence(BindingMode),
    Session(BindingMode),
    Revocation(BindingMode),
    Policy(AllowedClass, BindingMode),
    Complete,
    MarkMalformed,
    MarkUnsupported,
    MarkRetryable,
    Deny(DenialReason),
    MarkRevoked,
}

impl TestAction {
    fn public(self) -> VerificationAction {
        match self {
            Self::Challenge(_) => VerificationAction::RecordChallengeAuthenticated,
            Self::Freshness(_) => VerificationAction::RecordFreshnessChecked,
            Self::Identity(_) => VerificationAction::RecordIdentityChecked,
            Self::Evidence(_) => VerificationAction::RecordEvidenceAppraised,
            Self::Session(_) => VerificationAction::RecordSessionBound,
            Self::Revocation(_) => VerificationAction::RecordRevocationChecked,
            Self::Policy(_, _) => VerificationAction::RecordPolicySatisfied,
            Self::Complete => VerificationAction::Complete,
            Self::MarkMalformed => VerificationAction::MarkMalformed,
            Self::MarkUnsupported => VerificationAction::MarkUnsupported,
            Self::MarkRetryable => VerificationAction::MarkRetryable,
            Self::Deny(_) => VerificationAction::Deny,
            Self::MarkRevoked => VerificationAction::MarkRevoked,
        }
    }

    fn binding_mode(self) -> Option<BindingMode> {
        match self {
            Self::Challenge(mode)
            | Self::Freshness(mode)
            | Self::Identity(mode)
            | Self::Evidence(mode)
            | Self::Session(mode)
            | Self::Revocation(mode)
            | Self::Policy(_, mode) => Some(mode),
            Self::Complete
            | Self::MarkMalformed
            | Self::MarkUnsupported
            | Self::MarkRetryable
            | Self::Deny(_)
            | Self::MarkRevoked => None,
        }
    }

    fn required_phase(self) -> Option<VerificationPhase> {
        match self {
            Self::Challenge(_) => Some(VerificationPhase::EvidenceReceived),
            Self::Freshness(_) => Some(VerificationPhase::ChallengeAuthenticated),
            Self::Identity(_) => Some(VerificationPhase::FreshnessChecked),
            Self::Evidence(_) => Some(VerificationPhase::IdentityChecked),
            Self::Session(_) => Some(VerificationPhase::EvidenceAppraised),
            Self::Revocation(_) => Some(VerificationPhase::SessionBound),
            Self::Policy(_, _) => Some(VerificationPhase::RevocationChecked),
            Self::Complete => Some(VerificationPhase::PolicySatisfied),
            Self::MarkMalformed
            | Self::MarkUnsupported
            | Self::MarkRetryable
            | Self::Deny(_)
            | Self::MarkRevoked => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlowSnapshot {
    phase: VerificationPhase,
    outcome: Option<VerificationOutcome>,
    has_request: bool,
}

fn flow_snapshot(flow: &VerifierFlow) -> FlowSnapshot {
    FlowSnapshot {
        phase: flow.phase(),
        outcome: flow.outcome(),
        has_request: flow.request.is_some(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateKind {
    Challenge,
    Freshness,
    Identity,
    Evidence,
    Session,
    Revocation,
    Policy,
}

const ALL_7_GATE_KINDS: [GateKind; 7] = [
    GateKind::Challenge,
    GateKind::Freshness,
    GateKind::Identity,
    GateKind::Evidence,
    GateKind::Session,
    GateKind::Revocation,
    GateKind::Policy,
];

impl GateKind {
    fn action(self) -> VerificationAction {
        match self {
            Self::Challenge => VerificationAction::RecordChallengeAuthenticated,
            Self::Freshness => VerificationAction::RecordFreshnessChecked,
            Self::Identity => VerificationAction::RecordIdentityChecked,
            Self::Evidence => VerificationAction::RecordEvidenceAppraised,
            Self::Session => VerificationAction::RecordSessionBound,
            Self::Revocation => VerificationAction::RecordRevocationChecked,
            Self::Policy => VerificationAction::RecordPolicySatisfied,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModelState {
    EvidenceReceived,
    ChallengeAuthenticated,
    FreshnessChecked,
    IdentityChecked,
    EvidenceAppraised,
    SessionBound,
    RevocationChecked,
    PolicySatisfied(AllowedClass),
    Verified(AllowedClass),
    Malformed,
    Unsupported,
    Retryable,
    Denied(DenialReason),
    Revoked,
}

const ALL_13_MATRIX_ACTIONS: [TestAction; 13] = [
    TestAction::Challenge(BindingMode::Matching),
    TestAction::Freshness(BindingMode::Matching),
    TestAction::Identity(BindingMode::Matching),
    TestAction::Evidence(BindingMode::Matching),
    TestAction::Session(BindingMode::Matching),
    TestAction::Revocation(BindingMode::Matching),
    TestAction::Policy(AllowedClass::Full, BindingMode::Matching),
    TestAction::Complete,
    TestAction::MarkMalformed,
    TestAction::MarkUnsupported,
    TestAction::MarkRetryable,
    TestAction::Deny(DenialReason::PolicyDenied),
    TestAction::MarkRevoked,
];

const ALL_14_MODEL_STATES: [ModelState; 14] = [
    ModelState::EvidenceReceived,
    ModelState::ChallengeAuthenticated,
    ModelState::FreshnessChecked,
    ModelState::IdentityChecked,
    ModelState::EvidenceAppraised,
    ModelState::SessionBound,
    ModelState::RevocationChecked,
    ModelState::PolicySatisfied(AllowedClass::Full),
    ModelState::Verified(AllowedClass::Full),
    ModelState::Malformed,
    ModelState::Unsupported,
    ModelState::Retryable,
    ModelState::Denied(DenialReason::PolicyDenied),
    ModelState::Revoked,
];

fn model_transition(state: ModelState, action: TestAction) -> Option<ModelState> {
    match (state, action) {
        (ModelState::EvidenceReceived, TestAction::Challenge(BindingMode::Matching)) => Some(ModelState::ChallengeAuthenticated),
        (ModelState::ChallengeAuthenticated, TestAction::Freshness(BindingMode::Matching)) => Some(ModelState::FreshnessChecked),
        (ModelState::FreshnessChecked, TestAction::Identity(BindingMode::Matching)) => Some(ModelState::IdentityChecked),
        (ModelState::IdentityChecked, TestAction::Evidence(BindingMode::Matching)) => Some(ModelState::EvidenceAppraised),
        (ModelState::EvidenceAppraised, TestAction::Session(BindingMode::Matching)) => Some(ModelState::SessionBound),
        (ModelState::SessionBound, TestAction::Revocation(BindingMode::Matching)) => Some(ModelState::RevocationChecked),
        (ModelState::RevocationChecked, TestAction::Policy(class, BindingMode::Matching)) => Some(ModelState::PolicySatisfied(class)),
        (ModelState::PolicySatisfied(class), TestAction::Complete) => Some(ModelState::Verified(class)),
        (state, TestAction::MarkMalformed) if model_is_nonterminal(state) => Some(ModelState::Malformed),
        (state, TestAction::MarkUnsupported) if model_is_nonterminal(state) => Some(ModelState::Unsupported),
        (state, TestAction::MarkRetryable) if model_is_nonterminal(state) => Some(ModelState::Retryable),
        (state, TestAction::Deny(reason)) if model_is_nonterminal(state) => Some(ModelState::Denied(reason)),
        (state, TestAction::MarkRevoked) if model_is_nonterminal(state) => Some(ModelState::Revoked),
        _ => None,
    }
}

fn model_is_nonterminal(state: ModelState) -> bool {
    matches!(
        state,
        ModelState::EvidenceReceived
            | ModelState::ChallengeAuthenticated
            | ModelState::FreshnessChecked
            | ModelState::IdentityChecked
            | ModelState::EvidenceAppraised
            | ModelState::SessionBound
            | ModelState::RevocationChecked
            | ModelState::PolicySatisfied(_)
    )
}

fn model_phase(state: ModelState) -> VerificationPhase {
    match state {
        ModelState::EvidenceReceived => VerificationPhase::EvidenceReceived,
        ModelState::ChallengeAuthenticated => VerificationPhase::ChallengeAuthenticated,
        ModelState::FreshnessChecked => VerificationPhase::FreshnessChecked,
        ModelState::IdentityChecked => VerificationPhase::IdentityChecked,
        ModelState::EvidenceAppraised => VerificationPhase::EvidenceAppraised,
        ModelState::SessionBound => VerificationPhase::SessionBound,
        ModelState::RevocationChecked => VerificationPhase::RevocationChecked,
        ModelState::PolicySatisfied(_) => VerificationPhase::PolicySatisfied,
        ModelState::Verified(_) => VerificationPhase::Verified,
        ModelState::Malformed => VerificationPhase::Malformed,
        ModelState::Unsupported => VerificationPhase::Unsupported,
        ModelState::Retryable => VerificationPhase::Retryable,
        ModelState::Denied(_) => VerificationPhase::Denied,
        ModelState::Revoked => VerificationPhase::Revoked,
    }
}

fn model_denial_reason(reason: DenialReason) -> ReasonCode {
    match reason {
        DenialReason::NotYetValid => ReasonCode::NotYetValid,
        DenialReason::Expired => ReasonCode::Expired,
        DenialReason::ReplayDetected => ReasonCode::ReplayDetected,
        DenialReason::SessionBindingMismatch => ReasonCode::SessionBindingMismatch,
        DenialReason::EvidenceInvalid => ReasonCode::EvidenceInvalid,
        DenialReason::PolicyDenied => ReasonCode::PolicyDenied,
        DenialReason::ProtectedSessionLost => ReasonCode::ProtectedSessionLost,
    }
}

fn model_report(state: ModelState) -> Option<(Decision, ReasonCode)> {
    match state {
        ModelState::Verified(AllowedClass::Full) => Some((Decision::Allow, ReasonCode::None)),
        ModelState::Verified(AllowedClass::Restricted) => {
            Some((Decision::AllowRestricted, ReasonCode::None))
        }
        ModelState::Malformed => Some((Decision::Deny, ReasonCode::Malformed)),
        ModelState::Unsupported => Some((Decision::Unsupported, ReasonCode::UnsupportedVersion)),
        ModelState::Retryable => Some((Decision::Retry, ReasonCode::AttestationUnavailable)),
        ModelState::Denied(reason) => Some((Decision::Deny, model_denial_reason(reason))),
        ModelState::Revoked => Some((Decision::Deny, ReasonCode::Revoked)),
        ModelState::EvidenceReceived
        | ModelState::ChallengeAuthenticated
        | ModelState::FreshnessChecked
        | ModelState::IdentityChecked
        | ModelState::EvidenceAppraised
        | ModelState::SessionBound
        | ModelState::RevocationChecked
        | ModelState::PolicySatisfied(_) => None,
    }
}
```

Define `ALL_13_MATRIX_ACTIONS` with matching binding mode for each gate, one `Policy(AllowedClass::Full, BindingMode::Matching)`, and one `Deny(DenialReason::PolicyDenied)` value; parameter choices do not create extra public action kinds. Test restricted success and all denial reasons separately. Define `ALL_14_MODEL_STATES` with `PolicySatisfied(Full)` and `Verified(Full)` as the representative public phases.

Implement `flow_for_model_state` by starting from `flow_fixture`, applying only the canonical public transitions needed to reach the requested state, and using the corresponding public failure method for each failure terminal. Implement `apply_action(flow, other_binding, action)` as one exhaustive match over all `TestAction` variants; each gate chooses `flow.binding` for `Matching` or `other_binding` for `OtherFlow`, and successful `complete()` maps to unit `ActionResult::Verified` after consuming the returned capability.

The required helper signatures and contracts are:

```rust
fn flow_for_model_state(state: ModelState, seed: u8) -> VerifierFlow;
fn apply_action(
    flow: &mut VerifierFlow,
    other_binding: &VerificationBinding,
    action: TestAction,
) -> Result<ActionResult, TransitionError>;
fn assert_flow_matches_model(flow: &VerifierFlow, state: ModelState);
fn assert_every_action_rejected(flow: &mut VerifierFlow);
```

`flow_for_model_state` uses zero through seven matching gate actions for the eight nonterminals, adds `Complete` for `Verified`, or invokes exactly one matching public failure method for the five failure terminals. `assert_flow_matches_model` compares public phase, report decision/reason, and private request presence against literal `model_phase`, `model_report`, and `model_is_nonterminal` matches. `assert_every_action_rejected` applies all 13 matrix actions with a distinct other binding and requires exact `InvalidTransition { phase: current_phase, action: action.public() }` plus an unchanged snapshot.

Add:

```rust
#[test]
fn all_182_phase_action_pairs_match_the_independent_model() {
    let mut succeeded = 0usize;
    let mut rejected = 0usize;
    for state in ALL_14_MODEL_STATES {
        for action in ALL_13_MATRIX_ACTIONS {
            let mut flow = flow_for_model_state(state, 53);
            let before = flow_snapshot(&flow);
            let expected = model_transition(state, action);
            let other_binding = flow_fixture(54).binding;
            let actual = apply_action(&mut flow, &other_binding, action);
            match expected {
                Some(next) => {
                    assert!(actual.is_ok(), "allowed pair rejected: {state:?} {action:?}");
                    assert_flow_matches_model(&flow, next);
                    succeeded += 1;
                }
                None => {
                    assert_eq!(
                        actual,
                        Err(TransitionError::InvalidTransition {
                            phase: model_phase(state),
                            action: action.public(),
                        })
                    );
                    assert_eq!(flow_snapshot(&flow), before);
                    rejected += 1;
                }
            }
        }
    }
    assert_eq!(succeeded, 48);
    assert_eq!(rejected, 134);
}
```

Do not count a mismatched binding as a separate phase/action pair; Task 6 covers it orthogonally.

- [ ] **Step 6: Add seven omissions and all 5,040 permutations**

Generate permutations without a dependency:

```rust
fn permute_gates(gates: &mut [GateKind], start: usize, visit: &mut impl FnMut(&[GateKind])) {
    if start == gates.len() {
        visit(gates);
        return;
    }
    for index in start..gates.len() {
        gates.swap(start, index);
        permute_gates(gates, start + 1, visit);
        gates.swap(start, index);
    }
}
```

Add tests that:

- omit each one of `Challenge`, `Freshness`, `Identity`, `Evidence`, `Session`, `Revocation`, `Policy` and prove completion rejects;
- enumerate exactly 5,040 permutations;
- allow only `[Challenge, Freshness, Identity, Evidence, Session, Revocation, Policy]` to reach `PolicySatisfied`; and
- prove every other ordering remains non-verified and never releases the request unless it deliberately enters a failure terminal.

Assert counters `permutations == 5_040`, `canonical == 1`, and `noncanonical == 5_039`.

- [ ] **Step 7: Run focused and full verifier GREEN**

Run:

```bash
cargo test -p ogir-verifier --lib all_182_phase_action_pairs_match_the_independent_model -- --exact
cargo test -p ogir-verifier --lib gate_permutations_require_the_one_canonical_order -- --exact
cargo test -p ogir-verifier --lib
cargo test -p ogir-verifier --test verification_public
cargo test -p ogir-verifier --test freshness
cargo test -p ogir-verifier --doc
cargo clippy -p ogir-verifier --all-targets --all-features -- -D warnings
git diff --check
```

Expected: 48/134 and 1/5,039 counters match exactly; every command exits 0.

- [ ] **Step 8: Commit immutable terminal/exhaustive behavior**

```bash
git add crates/ogir-verifier/src/verification.rs crates/ogir-verifier/src/verification/tests.rs
git diff --cached --check
git commit -m "feat: add fail-closed verifier terminals"
```

Expected: one unsigned two-file commit. Refresh Shared Memory and obtain fresh task review before Task 6.

---

### Task 6: Prove Cross-Flow Authority, Long Histories, and Diagnostic Privacy

**Files:**

- Modify: `crates/ogir-verifier/src/verification.rs`
- Modify: `crates/ogir-verifier/src/verification/tests.rs`
- Modify: `crates/ogir-verifier/src/freshness.rs`
- Modify: `crates/ogir-verifier/tests/verification_public.rs`

**Interfaces:**

- Consumes: complete 14-phase/13-action graph, private test fixtures, explicit authority fields, and bound `FreshnessChecked`.
- Produces: seven equal-data cross-flow regressions, exact million-action oracle, non-vacuous coverage counters, compile-fail downstream authority proof, per-field structural proof, and exact diagnostic allowlists.

- [ ] **Step 1: Prove every gate rejects an equal-data different flow**

Add a private helper that constructs two flows from `request_fixture(seed).clone()` and advances both to the phase expected by one selected gate. Mint the tested capability with flow A's private binding, submit it to flow B, and snapshot flow B first.

Add:

```rust
#[test]
fn every_capability_rejects_an_equal_request_from_another_flow() {
    for gate in ALL_7_GATE_KINDS {
        let (source, mut target) = equal_flows_at_gate(gate, 71);
        let before = flow_snapshot(&target);
        let result = apply_capability_from_other_flow(gate, &source, &mut target);
        assert_eq!(
            result,
            Err(TransitionError::CapabilityRejected { action: gate.action() })
        );
        assert_eq!(flow_snapshot(&target), before);
    }
}

#[test]
fn mismatched_capabilities_preserve_phase_before_binding_error_precedence() {
    for state in ALL_14_MODEL_STATES {
        for gate in ALL_7_GATE_KINDS {
            let source = flow_fixture(72);
            let mut target = flow_for_model_state(state, 72);
            let before = flow_snapshot(&target);
            let actual = apply_capability_from_other_flow(gate, &source, &mut target);
            let expected = if gate.required_phase() == model_phase(state) {
                TransitionError::CapabilityRejected { action: gate.action() }
            } else {
                TransitionError::InvalidTransition {
                    phase: model_phase(state),
                    action: gate.action(),
                }
            };
            assert_eq!(actual, Err(expected));
            assert_eq!(flow_snapshot(&target), before);
        }
    }
}
```

`flow_snapshot` contains only `phase`, `outcome`, and `request.is_some()`. The fixture must assert source and target requests are equal before moving them into their distinct flows. This makes an `Arc::ptr_eq` → value-equality mutation observable.

Implement the helpers with these exact signatures:

```rust
fn equal_flows_at_gate(gate: GateKind, seed: u8) -> (VerifierFlow, VerifierFlow);
fn apply_capability_from_other_flow(
    gate: GateKind,
    source: &VerifierFlow,
    target: &mut VerifierFlow,
) -> Result<(), TransitionError>;
```

`equal_flows_at_gate` creates two equal cloned request values, begins two distinct flows, asserts their private requests compare equal and their bindings do not match, then advances both with matching fixtures through the prefix before `gate`. `apply_capability_from_other_flow` exhaustively matches `GateKind`, constructs only that capability with `source.binding.clone()`, and calls the corresponding target transition; policy uses `AllowedClass::Full`.

Add `GateKind::required_phase()` as an exhaustive match returning the seven phases in success order. The 14 × 7 precedence test is mandatory: correct phase yields generic capability rejection; every other phase, including every terminal, yields invalid transition without inspecting the binding.

- [ ] **Step 2: Add exact diagnostics and request-retention coverage**

Use distinct canonical identifier sentinels, a nonce byte sentinel, distinct times, profile text, and payload bytes. Add:

```rust
#[test]
fn every_flow_capability_outcome_and_error_diagnostic_is_redacted() {
    let mut flow = flow_with_private_sentinels();
    let diagnostics = diagnostics_for_every_surface(&mut flow);
    let forbidden = [
        "private.publisher", "private.game", "private-build",
        "private-account", "private-match", "private-policy",
        "private-profile", "private-evidence-payload", "/home/",
        "::error::", "\n", "0x",
    ];

    for diagnostic in diagnostics {
        for sentinel in forbidden {
            assert!(!diagnostic.contains(sentinel), "diagnostic leaked {sentinel:?}: {diagnostic:?}");
        }
    }
}

#[test]
fn request_exists_only_while_flow_is_nonterminal() {
    for state in ALL_14_MODEL_STATES {
        let flow = flow_for_model_state(state, 83);
        assert_eq!(flow.request.is_some(), model_is_nonterminal(state));
    }
}
```

`diagnostics_for_every_surface` must include active and every terminal `VerifierFlow`, all seven gate capabilities, `VerifiedAttestation`, both `TransitionError` variants, every `VerificationOutcome`, `VerificationBinding`, `VerificationRequest`, and direct `EvidenceBundle` formatting. Compare fixed expected strings where the type contract specifies one; omission-only checks are supplemental.

The exact fixed strings are:

```text
VerificationBinding([REDACTED])
ChallengeAuthenticated([REDACTED])
FreshnessChecked([REDACTED])
IdentityChecked([REDACTED])
EvidenceAppraised([REDACTED])
SessionBound([REDACTED])
RevocationChecked([REDACTED])
PolicySatisfied([REDACTED])
VerifiedAttestation([REDACTED])
VerificationRequest([REDACTED])
EvidenceBundle([REDACTED])
verifier transition is not allowed
verifier capability was rejected
```

`VerifierFlow` uses only the literal shape `VerifierFlow { phase: EvidenceReceived, outcome: None }` or the corresponding approved phase/outcome enum names; `VerificationOutcome` uses only its safe decision/reason enums. Implement `diagnostics_for_every_surface` by formatting each listed object once, then each of the 14 flow phases and 13 reporting outcomes from the mapping table.

Use these exact helper contracts:

```rust
fn flow_with_private_sentinels() -> VerifierFlow;
fn diagnostics_for_every_surface(flow: &mut VerifierFlow) -> Vec<String>;
```

`flow_with_private_sentinels` constructs publisher `private.publisher`, game `private.game`, build `private-build`, account `private-account`, match `private-match`, policy `private-policy`, nonce `[0xA5; 32]`, window `[4_242, 4_342)`, profile `private-profile`, and payload `private-evidence-payload`; expected context uses the same identifiers and authoritative time is 4,242. `diagnostics_for_every_surface` uses private fixture constructors to format each authority object before consumption, drives separate flows to every terminal, formats both errors, and returns all strings without logging them.

- [ ] **Step 3: Add external compile-pass and single-cause compile-fail proofs**

Document this compile-pass public-surface example on `VerifierFlow`:

```rust
/// ```
/// use ogir_verifier::{
///     ChallengeAuthenticated, DenialReason, EvidenceAppraised,
///     FreshnessChecked, IdentityChecked, PolicySatisfied,
///     RevocationChecked, SessionBound, TransitionError,
///     VerificationAction, VerificationOutcome, VerificationPhase,
///     VerificationRequest, VerifiedAttestation, VerifierFlow,
/// };
///
/// fn assert_public<T>() {}
/// assert_public::<ChallengeAuthenticated>();
/// assert_public::<FreshnessChecked>();
/// assert_public::<IdentityChecked>();
/// assert_public::<EvidenceAppraised>();
/// assert_public::<SessionBound>();
/// assert_public::<RevocationChecked>();
/// assert_public::<PolicySatisfied>();
/// assert_public::<VerifiedAttestation>();
/// assert_public::<VerifierFlow>();
/// assert_public::<VerificationRequest>();
/// assert_public::<VerificationOutcome>();
/// assert_public::<VerificationPhase>();
/// assert_public::<VerificationAction>();
/// assert_public::<DenialReason>();
/// assert_public::<TransitionError>();
///
/// fn inspect(flow: &VerifierFlow) {
///     let _phase = flow.phase();
///     let _outcome = flow.outcome();
/// }
/// ```
```

Add separate `compile_fail` blocks, one prohibited operation per block, for:

```text
construct ChallengeAuthenticated
construct FreshnessChecked
construct IdentityChecked
construct EvidenceAppraised
construct SessionBound
construct RevocationChecked
construct PolicySatisfied
construct VerifiedAttestation
clone VerifierFlow
clone each of the seven gate capabilities
clone VerifiedAttestation
read/replace VerifierFlow.binding
read/replace VerifierFlow.request
read/replace VerifierFlow.state
read each capability binding
read PolicySatisfied.allowed
read VerifiedAttestation binding/allowed
construct or mutate VerificationOutcome fields
pass Decision where VerifiedAttestation is required
pass VerificationOutcome where VerifiedAttestation is required
obtain FreshnessChecked from public FreshnessGuard::claim
```

Use these exact expressions so every authority type/field has its own block:

| Type | Construction block expression | Clone block expression | Field-read block expressions |
| --- | --- | --- | --- |
| `VerifierFlow` | construction remains public only through `begin(request)`; no raw-field literal block | `let _ = value.clone();` | `value.binding`, `value.request`, `value.state` in three blocks |
| `ChallengeAuthenticated` | `ChallengeAuthenticated::new()` | `let _ = value.clone();` | `value.binding` |
| `FreshnessChecked` | `FreshnessChecked::new()` | `let _ = value.clone();` | `value.binding` |
| `IdentityChecked` | `IdentityChecked::new()` | `let _ = value.clone();` | `value.binding` |
| `EvidenceAppraised` | `EvidenceAppraised::new()` | `let _ = value.clone();` | `value.binding` |
| `SessionBound` | `SessionBound::new()` | `let _ = value.clone();` | `value.binding` |
| `RevocationChecked` | `RevocationChecked::new()` | `let _ = value.clone();` | `value.binding` |
| `PolicySatisfied` | `PolicySatisfied::new()` | `let _ = value.clone();` | `value.binding`, `value.allowed` in separate blocks |
| `VerifiedAttestation` | `VerifiedAttestation::new()` | `let _ = value.clone();` | `value.binding`, `value.allowed` in separate blocks |
| `VerificationOutcome` | struct literal with `Decision::Allow`/`ReasonCode::None` | copy is allowed because it is report-only | `value.decision`, `value.reason` in separate blocks |

Add two dedicated nonexistent-shortcut blocks: `VerifiedAttestation::from_decision(Decision::Allow)` and `VerifiedAttestation::from_outcome(outcome)`. Mutation `A01` adds exactly the forbidden `from_decision` shortcut and must make its compile-fail doctest unexpectedly compile; the second block permanently proves report-object substitution is also absent.

Use concrete Rust for every block. Example forms:

```rust
/// ```compile_fail
/// use ogir_verifier::VerifierFlow;
/// fn clone_flow(flow: VerifierFlow) { let _copy = flow.clone(); }
/// ```
```

```rust
/// ```compile_fail
/// use ogir_model::Decision;
/// use ogir_verifier::VerifiedAttestation;
/// fn consume(_: VerifiedAttestation) {}
/// consume(Decision::Allow);
/// ```
```

Do not combine two prohibited operations in one block; the compiler failure must have one intended cause.

- [ ] **Step 4: Pin every authority field structurally**

In the private test module, read source with `include_str!("../verification.rs")` and `include_str!("../freshness.rs")`. Assert exact private declarations for:

```text
VerifierFlow: binding, request, state
ChallengeAuthenticated: binding
FreshnessChecked: binding
IdentityChecked: binding
EvidenceAppraised: binding
SessionBound: binding
RevocationChecked: binding
PolicySatisfied: binding, allowed
VerifiedAttestation: binding, allowed
VerificationOutcome: decision, reason
```

Also assert none of those exact field lines begins with `pub`, `pub(crate)`, or `pub(super)`. Normalize only CRLF to LF; do not strip arbitrary whitespace that could hide a visibility change.

- [ ] **Step 5: Add the exact 1,048,576-action oracle**

Add constants:

```rust
const TOTAL_ACTIONS: usize = 1_048_576;
const SCHEDULED_ACTIONS: usize = 2_048;
const ARBITRARY_ACTIONS: usize = TOTAL_ACTIONS - SCHEDULED_ACTIONS;
```

Use a dependency-free LCG:

```rust
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        self.0
    }

    fn action(&mut self) -> TestAction {
        let action_index = (self.next() % 13) as usize;
        let selector = self.next();
        arbitrary_action_from_index(action_index, selector)
    }
}

fn seed_for_index(index: usize) -> u8 {
    (index % 200) as u8 + 1
}

fn arbitrary_action_from_index(index: usize, selector: u64) -> TestAction {
    let mode = if selector & 1 == 0 {
        BindingMode::Matching
    } else {
        BindingMode::OtherFlow
    };
    let denial_reasons = [
        DenialReason::NotYetValid,
        DenialReason::Expired,
        DenialReason::ReplayDetected,
        DenialReason::SessionBindingMismatch,
        DenialReason::EvidenceInvalid,
        DenialReason::PolicyDenied,
        DenialReason::ProtectedSessionLost,
    ];
    match index {
        0 => TestAction::Challenge(mode),
        1 => TestAction::Freshness(mode),
        2 => TestAction::Identity(mode),
        3 => TestAction::Evidence(mode),
        4 => TestAction::Session(mode),
        5 => TestAction::Revocation(mode),
        6 => TestAction::Policy(
            if selector & 2 == 0 { AllowedClass::Full } else { AllowedClass::Restricted },
            mode,
        ),
        7 => TestAction::Complete,
        8 => TestAction::MarkMalformed,
        9 => TestAction::MarkUnsupported,
        10 => TestAction::MarkRetryable,
        11 => TestAction::Deny(
            denial_reasons[(selector % denial_reasons.len() as u64) as usize],
        ),
        12 => TestAction::MarkRevoked,
        _ => panic!("arbitrary action index outside fixed domain: {index}"),
    }
}
```

Represent scheduled sequences explicitly so test-setup resets are not counted as state-machine actions:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScheduledStep {
    reset_before: bool,
    action: TestAction,
}

fn push_sequence(schedule: &mut Vec<ScheduledStep>, actions: &[TestAction]) {
    for (index, action) in actions.iter().copied().enumerate() {
        schedule.push(ScheduledStep {
            reset_before: index == 0,
            action,
        });
    }
}

const MATCHING_GATE_PREFIX: [TestAction; 7] = [
    TestAction::Challenge(BindingMode::Matching),
    TestAction::Freshness(BindingMode::Matching),
    TestAction::Identity(BindingMode::Matching),
    TestAction::Evidence(BindingMode::Matching),
    TestAction::Session(BindingMode::Matching),
    TestAction::Revocation(BindingMode::Matching),
    TestAction::Policy(AllowedClass::Full, BindingMode::Matching),
];

fn canonical_completion(allowed: AllowedClass) -> [TestAction; 8] {
    let mut actions = [TestAction::Complete; 8];
    actions[..6].copy_from_slice(&MATCHING_GATE_PREFIX[..6]);
    actions[6] = TestAction::Policy(allowed, BindingMode::Matching);
    actions[7] = TestAction::Complete;
    actions
}
```

Build `scheduled_actions() -> Vec<ScheduledStep>` deterministically. It must append complete reset-delimited sequences for:

- at least 16 full and 16 restricted completions;
- all 8 nonterminal phases × 5 failure actions;
- all 8 nonterminal phases × 7 denial reasons;
- all seven matching gate transitions;
- all seven equal-data cross-flow rejections, followed by `MarkMalformed` so each sequence terminates;
- all 6 terminals × 13 rejected actions; and
- one unknown-gate-to-unsupported sequence.

For each of eight nonterminal phases, the sequence prefix is `&MATCHING_GATE_PREFIX[..phase_index]`; append the selected failure/denial action. For each cross-flow gate, append the matching prefix before that gate, the same gate with `BindingMode::OtherFlow`, then `MarkMalformed`. For each terminal/action pair, construct that terminal in the same reset-delimited sequence and append the rejected action.

After all named sequences exist, append alternating full/restricted canonical sequences while another eight actions fit. Fill any final remainder with one-action reset-delimited `MarkMalformed` sequences. Assert both `schedule.len() == 2_048` and every named schedule counter before running.

The fixed arithmetic is:

```text
32 canonical completions × 8 actions                         = 256
8 nonterminal phases × 5 failures with prefixes             = 180
8 nonterminal phases × 7 denial reasons with prefixes       = 252
7 cross-flow gates with prefixes + rejection + termination  = 35
6 terminals × 13 attempted actions with construction        = 247
dedicated unknown-gate sequence                              = 1
named subtotal                                               = 971
134 alternating canonical completions × 8                    = 1,072
five one-action terminal sequences                           = 5
total                                                        = 2,048
```

Define non-vacuous coverage storage:

```rust
#[derive(Default)]
struct Coverage {
    full_completions: usize,
    restricted_completions: usize,
    failure_edges: [[usize; 5]; 8],
    denial_reasons: [usize; 7],
    matching_gates: [usize; 7],
    mismatched_gates: [usize; 7],
    terminal_rejections: [[usize; 13]; 6],
    unknown_gate: usize,
}

impl Coverage {
    fn assert_non_vacuous(&self) {
        assert!(self.full_completions >= 16);
        assert!(self.restricted_completions >= 16);
        assert!(self.failure_edges.iter().flatten().all(|count| *count > 0));
        assert!(self.denial_reasons.iter().all(|count| *count > 0));
        assert!(self.matching_gates.iter().all(|count| *count > 0));
        assert!(self.mismatched_gates.iter().all(|count| *count > 0));
        assert!(self.terminal_rejections.iter().flatten().all(|count| *count > 0));
        assert!(self.unknown_gate > 0);
    }
}
```

Implement `Coverage::observe(before, action, expected, actual)` using exhaustive test-only phase/action/reason index matches. Increment a counter only after `actual` matches `expected`; `unknown_gate` increments when `EvidenceReceived + MarkUnsupported` reaches the unsupported terminal.

Add a literal history-result classifier so phase-first error precedence is independent of production code:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedAction {
    Allowed(ModelState),
    InvalidTransition,
    CapabilityRejected,
}

fn model_is_terminal(state: ModelState) -> bool {
    !model_is_nonterminal(state)
}

fn expected_history_action(state: ModelState, action: TestAction) -> ExpectedAction {
    if let Some(next) = model_transition(state, action) {
        return ExpectedAction::Allowed(next);
    }
    if action.binding_mode() == Some(BindingMode::OtherFlow)
        && action.required_phase() == Some(model_phase(state))
    {
        return ExpectedAction::CapabilityRejected;
    }
    ExpectedAction::InvalidTransition
}
```

`binding_mode`, `required_phase`, and `public` are exhaustive test-only matches over `TestAction`; they must not call production transition helpers.

Add:

```rust
#[test]
fn one_million_actions_match_the_independent_verifier_model() {
    let schedule = scheduled_actions();
    assert_eq!(schedule.len(), SCHEDULED_ACTIONS);
    let mut rng = Lcg(0x4f47_4952_4d31_3031);
    let mut coverage = Coverage::default();
    let mut flow = flow_fixture(101);
    let mut other_binding = flow_fixture(101).binding;
    let mut model = ModelState::EvidenceReceived;

    for index in 0..TOTAL_ACTIONS {
        let (reset_before, action) = if index < SCHEDULED_ACTIONS {
            let step = schedule[index];
            (step.reset_before, step.action)
        } else {
            (model_is_terminal(model), rng.action())
        };
        if reset_before {
            let seed = seed_for_index(index);
            flow = flow_fixture(seed);
            other_binding = flow_fixture(seed).binding;
            model = ModelState::EvidenceReceived;
        }
        let model_before = model;
        let expected = expected_history_action(model, action);
        let before = flow_snapshot(&flow);
        let actual = apply_action(&mut flow, &other_binding, action);
        assert_action_matches_model(index, action, expected, before, &flow, &actual);
        if let ExpectedAction::Allowed(next) = expected {
            model = next;
        }
        coverage.observe(model_before, action, expected, &actual);
    }

    assert_eq!(TOTAL_ACTIONS - SCHEDULED_ACTIONS, ARBITRARY_ACTIONS);
    coverage.assert_non_vacuous();
}
```

`Coverage::assert_non_vacuous()` requires at least 16 full and 16 restricted completions and at least one observation for every other named scheduled class. Failure output includes only fixed seed/action index/safe enums, never request fields.

- [ ] **Step 6: Run the proof suite and verify all public docs**

Run:

```bash
cargo test -p ogir-verifier --lib every_capability_rejects_an_equal_request_from_another_flow -- --exact
cargo test -p ogir-verifier --lib one_million_actions_match_the_independent_verifier_model -- --exact
cargo test -p ogir-verifier --lib every_flow_capability_outcome_and_error_diagnostic_is_redacted -- --exact
cargo test -p ogir-verifier --all-features
cargo test -p ogir-verifier --doc
cargo test -p ogir-protocol --all-features
cargo clippy -p ogir-verifier -p ogir-protocol --all-targets --all-features -- -D warnings
cargo doc -p ogir-verifier -p ogir-protocol --no-deps
git diff --check
```

Expected: exact million-action count, non-vacuous counters, every compile-fail block, privacy allowlists, all prior tests, Clippy, and rustdoc pass.

- [ ] **Step 7: Commit the authority proof suite**

```bash
git add crates/ogir-verifier/src/verification.rs crates/ogir-verifier/src/verification/tests.rs crates/ogir-verifier/src/freshness.rs crates/ogir-verifier/tests/verification_public.rs
git diff --cached --check
git commit -m "test: prove verifier authority boundaries"
```

Expected: one unsigned four-file commit. Refresh Shared Memory and obtain fresh task review before Task 7.

---

### Task 7: Add Five Machine-Readable Verifier Attack Scenarios

**Files:**

- Create: `lab/scenarios/verifier-gate-skip.scenario.json`
- Create: `lab/scenarios/verifier-capability-substitution.scenario.json`
- Create: `lab/scenarios/verifier-terminal-immutability.scenario.json`
- Create: `lab/scenarios/verifier-unknown-gate.scenario.json`
- Create: `lab/scenarios/verifier-diagnostics-privacy.scenario.json`

**Interfaces:**

- Consumes: implemented/tested verifier graph, unchanged scenario schema, registered `initial-maintainer` owner and `all-protected-modes` assurance profile.
- Produces: five unique accountable scenario IDs covering every new threat class without claiming real crypto/adapters.

- [ ] **Step 1: Create the gate-skip scenario**

Create `lab/scenarios/verifier-gate-skip.scenario.json`:

```json
{
  "id": "OGIR-VERIFIER-GATE-SKIP-001",
  "title": "Skip a mandatory verifier appraisal gate",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["protected_session_authorization"],
  "preconditions": ["one verifier flow received hostile or opaque evidence"],
  "steps": [
    "omit one of challenge authentication, freshness, identity, evidence, session binding, revocation, or policy satisfaction",
    "request completion or present a report-only allow decision"
  ],
  "expected": {
    "decision": "deny",
    "reason": "invalid-transition",
    "automatic_ban": false
  },
  "invariants": [
    "only the canonical seven-gate path can create VerifiedAttestation",
    "Decision and VerificationOutcome are reporting views rather than authority"
  ],
  "residual_risk": ["a deliberately compromised trusted gate producer remains inside the verifier TCB"]
}
```

- [ ] **Step 2: Create the equal-request substitution scenario**

Create `lab/scenarios/verifier-capability-substitution.scenario.json`:

```json
{
  "id": "OGIR-VERIFIER-CAPABILITY-SUBSTITUTION-001",
  "title": "Use a gate capability on an equal but distinct verifier flow",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["protected_session_authorization", "verifier_freshness_state"],
  "preconditions": ["two verifier flows contain equal cloned request data"],
  "steps": [
    "obtain a valid opaque gate capability bound to flow-A",
    "submit that capability to flow-B at the otherwise correct phase"
  ],
  "expected": {
    "decision": "deny",
    "reason": "capability-rejected",
    "automatic_ban": false
  },
  "invariants": [
    "capability identity uses the exact process-local attempt allocation rather than request equality",
    "rejection preserves phase outcome and request ownership"
  ],
  "residual_risk": ["trusted producer code can still lie about which operation it performed"]
}
```

- [ ] **Step 3: Create the terminal-immutability scenario**

Create `lab/scenarios/verifier-terminal-immutability.scenario.json`:

```json
{
  "id": "OGIR-VERIFIER-TERMINAL-IMMUTABILITY-001",
  "title": "Mutate a verifier terminal or issue success twice",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["protected_session_authorization"],
  "preconditions": ["a verifier flow entered Verified or one failure terminal"],
  "steps": [
    "request another gate transition terminal reclassification or completion",
    "attempt to obtain another VerifiedAttestation"
  ],
  "expected": {
    "decision": "deny",
    "reason": "invalid-transition",
    "automatic_ban": false
  },
  "invariants": [
    "all six terminals reject all thirteen actions",
    "one flow can issue at most one non-cloneable VerifiedAttestation"
  ],
  "residual_risk": ["future result signing must consume rather than duplicate the verified capability"]
}
```

- [ ] **Step 4: Create the unknown-gate scenario**

Create `lab/scenarios/verifier-unknown-gate.scenario.json`:

```json
{
  "id": "OGIR-VERIFIER-UNKNOWN-GATE-001",
  "title": "Ignore an unknown mandatory verifier gate",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["protected_session_authorization"],
  "preconditions": ["the selected protocol or profile requires a gate this verifier does not understand"],
  "steps": ["treat the unknown gate as optional", "continue toward verifier completion"],
  "expected": {
    "decision": "unsupported",
    "reason": "unsupported-version",
    "automatic_ban": false
  },
  "invariants": ["unknown mandatory gate state terminates Unsupported and cannot be skipped"],
  "residual_risk": ["later protocol parsing must preserve unknown-critical-field detection before this mapping"]
}
```

- [ ] **Step 5: Create the diagnostic privacy scenario**

Create `lab/scenarios/verifier-diagnostics-privacy.scenario.json`:

```json
{
  "id": "OGIR-PRIVACY-VERIFIER-DIAGNOSTICS-001",
  "title": "Disclose verifier request evidence or attempt identity through diagnostics",
  "attacker": "A8",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["player_privacy", "verifier_freshness_state"],
  "preconditions": ["a verifier flow owns privacy-sensitive request and evidence data"],
  "steps": [
    "format the request flow capabilities errors outcomes binding and final capability",
    "format EvidenceBundle directly",
    "search output for identifiers nonce time evidence payload pointer values paths or control text"
  ],
  "expected": {
    "decision": "deny",
    "reason": "privacy-boundary",
    "automatic_ban": false
  },
  "invariants": [
    "default aggregate diagnostics contain only fixed redaction markers and approved safe enums",
    "terminal entry releases owned raw request data without claiming allocator zeroization"
  ],
  "residual_risk": ["explicit trusted value accessors and future operator telemetry require separate privacy review"]
}
```

- [ ] **Step 6: Validate scenarios and exact aggregate count**

Run:

```bash
python3 ./scripts/check-attack-scenario-traceability.py --self-test
python3 ./scripts/check-attack-scenario-traceability.py
rg -n 'OGIR-VERIFIER-GATE-SKIP-001|OGIR-VERIFIER-CAPABILITY-SUBSTITUTION-001|OGIR-VERIFIER-TERMINAL-IMMUTABILITY-001|OGIR-VERIFIER-UNKNOWN-GATE-001|OGIR-PRIVACY-VERIFIER-DIAGNOSTICS-001' lab/scenarios
git diff --check
```

Expected: validator reports 14 scenarios total, self-tests pass, and each new ID occurs exactly once.

- [ ] **Step 7: Commit executable scenarios**

```bash
git add lab/scenarios/verifier-gate-skip.scenario.json lab/scenarios/verifier-capability-substitution.scenario.json lab/scenarios/verifier-terminal-immutability.scenario.json lab/scenarios/verifier-unknown-gate.scenario.json lab/scenarios/verifier-diagnostics-privacy.scenario.json
git diff --cached --check
git commit -m "test: add verifier state-machine attack scenarios"
```

Expected: one unsigned five-file commit. Refresh Shared Memory and obtain fresh task review before Task 8.

---

### Task 8: Align Architecture, Roadmap, and Threat Model

**Files:**

- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/ROADMAP.md`
- Modify: `docs/THREAT_MODEL.md`

**Interfaces:**

- Consumes: implemented graph/proof and five passing scenarios.
- Produces: durable prose that distinguishes verifier appraisal proof from report data, signed results, permits, and relying-party admission without overstating unimplemented adapters.

- [ ] **Step 1: Update the roadmap graph precisely**

In M1's verifier state-machine subsection of `docs/ROADMAP.md`, replace the ambiguous permit lifecycle graph with:

```text
Verifier appraisal attempt:

EvidenceReceived
 -> ChallengeAuthenticated
 -> FreshnessChecked
 -> IdentityChecked
 -> EvidenceAppraised
 -> SessionBound
 -> RevocationChecked
 -> PolicySatisfied
 -> Verified

any nonterminal phase
 -> Malformed | Unsupported | Retryable | Denied | Revoked

All six terminals are permanent. Verified yields one process-local
VerifiedAttestation capability; it is not a signed AttestationResult, permit,
or game admission. Renewal starts a new appraisal attempt with a fresh
challenge. Result construction, permit issuance, expiry, renewal, and
revocation lifecycle are later domain/protocol issues.
```

Keep M1's original deliverable list, but state that `Decision`/`ReasonCode` are report-only and both `Allow` classes require all seven gates.

- [ ] **Step 2: Add the verifier-flow authority subsection to architecture**

Under the publisher-verifier/challenge-freshness architecture, add these exact facts in prose:

```markdown
#### Verifier appraisal-flow authority

One `VerifierFlow` owns one exact request while active. Seven opaque,
non-cloneable gate capabilities advance one private checked graph. Every
capability carries one private `Arc` allocation identity plus the redacted
replay registration; `Arc::ptr_eq` rejects a capability from an equal but
distinct flow. Phase and binding checks precede mutation.

Only `PolicySatisfied -> Verified` emits one non-cloneable
`VerifiedAttestation`. `Decision`, `ReasonCode`, and `VerificationOutcome` are
reporting views and cannot substitute for that capability. Restricted success
is a separately selected and satisfied relying-party policy, never fallback
after full-policy failure.

The capability currently carries only the attempt binding and allowed class.
It is process-local, nonserializable, and not restart-durable. Future result
work must add typed verified claims under the same binding and consume the
capability; raw request fields cannot be refilled into an unrelated signed
result. M1-010 adds no signature, evidence, identity, session-key, revocation,
policy, result-signing, permit, network, or persistence adapter.
```

Also state that active request ownership ends at every terminal without making a secure-erasure claim.

- [ ] **Step 3: Add two threat responses and explicit residual risk**

In `docs/THREAT_MODEL.md`, add:

```markdown
### Verifier gate skipping or cross-attempt substitution

Threat: Hostile/equal requests or faulty orchestration skip an appraisal gate,
reuse a gate result from another attempt, treat opaque evidence or report-only
Allow as authority, or issue success twice.

Required response: Keep progress in one private checked graph. Require all
seven exact-attempt capabilities in order, compare allocation identity rather
than request equality, make completion single-use, and keep every terminal
permanent. Unknown required gates terminate Unsupported. Only a future trusted
consumer of `VerifiedAttestation` may construct an attestation result.

### Verifier diagnostic disclosure or over-retention

Threat: Default formatting exposes request identifiers, freshness context,
evidence payload, pointer identity, or retains the raw request after a terminal.

Required response: Use fixed aggregate redaction for requests, flows,
capabilities, errors, outcomes, bindings, and `EvidenceBundle`; release request
ownership on terminal entry; expose no allocation address/count. This is a
retention bound, not secure memory erasure.
```

Add the residual statement: deliberate malicious behavior in a trusted gate producer/verifier remains A5 risk; the pure graph narrows external/API misuse but cannot make compromised TCB code honest.

- [ ] **Step 4: Verify documentation is precise and non-duplicative**

Run:

```bash
rg -n 'EvidenceReceived|VerifiedAttestation|reporting views|Arc::ptr_eq|Restricted|Malformed.*Unsupported.*Retryable.*Denied.*Revoked' docs/ROADMAP.md docs/ARCHITECTURE.md docs/THREAT_MODEL.md
rg -n 'signed AttestationResult|permit|admission|process-local|nonserializable|secure memory erasure' docs/ROADMAP.md docs/ARCHITECTURE.md docs/THREAT_MODEL.md
git diff --check
./scripts/check-repository-metadata.sh .
```

Expected: every required distinction is present, no text claims a real validator/signer/permit, and checks exit 0.

- [ ] **Step 5: Commit architecture/threat traceability**

```bash
git add docs/ARCHITECTURE.md docs/ROADMAP.md docs/THREAT_MODEL.md
git diff --cached --check
git commit -m "docs: define verifier flow authority"
```

Expected: one unsigned three-file commit. Refresh Shared Memory and obtain fresh task review before Task 9.

---

### Task 9: Record ADR-0007 and the Exact Test Contract

**Files:**

- Create: `docs/adr/0007-verifier-flow-capabilities.md`
- Modify: `docs/adr/index.md`
- Modify: `docs/TEST_STRATEGY.md`
- Modify only on a concrete lesson: `docs/LESSONS_LEARNED.md`

**Interfaces:**

- Consumes: implemented behavior, passing code/scenarios, approved design, primary sources, and task-review findings.
- Produces: accepted durable decision, indexed navigation, exact executable evidence contract, and append-only lessons only where a real mistaken assumption occurred.

- [ ] **Step 1: Update the test strategy with exact implemented numbers**

Add a verifier subsection to `docs/TEST_STRATEGY.md` containing these exact facts:

```markdown
Verifier-flow tests exhaust 14 phases × 13 actions = 182 pairs against an
independent literal model: exactly 48 succeed and 134 reject unchanged. Seven
gate omissions and all 7! = 5,040 orderings prove that only one canonical order
can reach `PolicySatisfied`. All seven capabilities reject an equal cloned
request in a different flow through allocation identity.

The fixed action budget is exactly 1,048,576: 2,048 scheduled actions guarantee
at least 16 full and 16 restricted completions plus every failure/reason,
binding, and terminal class; 1,046,528 fixed-seed actions exercise arbitrary
histories against the same independent oracle. A new flow is test setup after
terminal entry and is not counted as one of the 13 actions.

Single-cause compile-fail and structural tests cover every authority-bearing
type/field, outcome construction, raw-claim exclusion, and report/capability
substitution. Exact diagnostic tests cover the request, flow, all gates,
binding, errors, outcomes, final capability, and direct `EvidenceBundle`.
```

Extend the mutation subsection with the per-gate/per-field expansion rule and the exact plan-frozen probe table from Task 10. State explicitly that no parser/fuzzer is added in M1-010.

- [ ] **Step 2: Create complete Accepted ADR-0007**

Create `docs/adr/0007-verifier-flow-capabilities.md` with every template section and this metadata:

```markdown
# ADR-0007: Attempt-bound fail-closed verifier flow

- Status: Accepted
- Date: 2026-08-26
- Owners: Initial maintainer
- Related issues: [M1-010](../../planning/issues/010-verifier-state-machine.md)
- Supersedes: None
- Superseded by: None
```

The section content must record these decisions verbatim in substance:

```text
Context:
- report fields are currently constructible and progress is implicit;
- seven future validation results arrive dynamically;
- exact request separation and terminal failure must be testable;
- permit/signing/admission are out of scope.

Decision drivers:
- no authority from Decision/ReasonCode/outcome;
- all seven gates mandatory for full/restricted;
- exact in-process attempt binding without RNG/hash/counter;
- finite exhaustive graph and non-vacuous history proof;
- minimal request retention and fixed diagnostics;
- no new dependency/I/O/unsafe/crypto.

Options considered:
- checked runtime graph selected;
- typestate and dual APIs rejected;
- monolithic verify success path rejected;
- public/unbound capabilities rejected;
- value-equality/random/hash/counter IDs rejected;
- serializable/restart-durable capabilities deferred;
- report-only Allow rejected as authority.

Decision:
- exact EvidenceReceived -> ... -> Verified graph;
- five failure terminals plus Verified permanent;
- one Arc allocation identity plus ReplayRegistration;
- phase-before-binding-before-mutation;
- one non-cloneable VerifiedAttestation carrying binding/allowed class only;
- exact outcome mapping and restricted-no-fallback rule;
- active-only request ownership;
- no production gate producer except future real adapters;
- raw research claim without FreshnessChecked minting;
- EvidenceBundle fixed Debug redaction.

Consequences:
- cross-flow/reordered/terminal misuse fails deterministically;
- allocator identity is process-local and cannot cross restart;
- future result model must add bound verified claims and consume capability;
- trusted producer compromise remains residual.

Threat-model impact:
- narrows A1 hostile request/API misuse and accidental TCB orchestration bugs;
- A5 deliberate verifier compromise remains residual;
- failures are non-disciplinary and never authorize fallback.

Privacy impact:
- request retained only while active;
- binding retains redacted replay registration until capability drop;
- no secure-erasure claim;
- all aggregate and EvidenceBundle diagnostics fixed/redacted.

Dependency/license impact:
- standard library Arc only;
- no new package/unsafe/parser/crypto/I/O;
- Apache-2.0 boundary unchanged.

Validation:
- 182 matrix, 5,040 permutations, seven omissions/substitutions;
- exact million-action budget/counters;
- compile-fail/structural/privacy evidence;
- five scenarios;
- named disposable mutations and TCB/privacy review.

Rollback:
- disabling protected mode safe;
- changing graph/binding/authority/mapping/retention/privacy requires ADR update
  or superseding ADR and matching migrations/tests;
- gate bypass/report authority/raw diagnostic restoration are not rollback.

Primary sources:
- approved design and project security/architecture/threat/roadmap docs;
- RFC 9334;
- Rust 1.98 visibility/privacy, Arc::ptr_eq, ownership;
- Rust API Guidelines.
```

Write complete prose under each required heading; do not leave the labels above as shorthand in the ADR.

- [ ] **Step 3: Index ADR-0007 atomically**

Add exactly one row to `docs/adr/index.md`:

```markdown
| [ADR-0007](0007-verifier-flow-capabilities.md) | Accepted | One attempt-bound checked graph is the only path to verifier appraisal authority. | None | None |
```

No existing row changes.

- [ ] **Step 4: Append a lesson only for a reproduced durable mistake**

If implementation or review has established a concrete mistaken assumption, append one new `docs/LESSONS_LEARNED.md` entry containing symptom, root cause, correction, and prevention plus the regression/mutation name. If no such defect occurred, leave the file byte-identical; do not manufacture a lesson to satisfy process.

- [ ] **Step 5: Verify ADR/test traceability and full local gates**

Stage the required documentation paths first because the ADR checker validates Git-index bytes:

```bash
git add docs/adr/0007-verifier-flow-capabilities.md docs/adr/index.md docs/TEST_STRATEGY.md
./scripts/check-adr-index.sh .
python3 ./scripts/check-attack-scenario-traceability.py
rg -n 'ADR-0007|182|48|134|5,040|1,048,576|2,048|1,046,528|VerifiedAttestation|Arc::ptr_eq' docs/adr/0007-verifier-flow-capabilities.md docs/adr/index.md docs/TEST_STRATEGY.md
./scripts/check.sh
cargo test --workspace --all-features --release
git diff --cached --check
git diff --check
```

If Task 9 Step 4 changed `docs/LESSONS_LEARNED.md`, stage it immediately after the first `git add` and before running any checker.

Expected: seven ADRs, fourteen scenarios, all full/release tests, Clippy, rustdoc, cargo-deny, metadata, and traceability pass.

- [ ] **Step 6: Commit durable decision/test documentation**

Commit the already verified index:

```bash
git diff --cached --check
git commit -m "docs: record verifier flow decision"
```

If and only if Step 4 added a real lesson, include `docs/LESSONS_LEARNED.md` in the same documentation commit and name the lesson in the commit body. Expected: one unsigned documentation commit. Refresh Shared Memory and obtain fresh task review before Task 10.

---

### Task 10: Prove 88 Mutations, Obtain Independent Review, and Move to `needs-review`

**Files:**

- Modify only for mutation-surviving regressions/fixes: verifier/protocol files named in Tasks 2-6
- Modify after clean review: `planning/issues/010-verifier-state-machine.md`
- Modify only for a concrete new lesson: `docs/LESSONS_LEARNED.md`
- External after local commit: exact live M1-010 issue body/status label only

**Interfaces:**

- Consumes: clean Task 9 head, complete tests/docs/scenarios, live ready issue.
- Produces: 88/88 killed mutation evidence, full/release green exact head, clean independent TCB/privacy verdicts, committed implementation evidence, and exact live `needs-review` synchronization.

- [ ] **Step 1: Freeze the clean pre-mutation head and topology**

Run:

```bash
git status --short --branch
m1_010_mutation_head="$(git rev-parse HEAD)"
printf '%s' "${m1_010_mutation_head}"
git rev-parse origin/main
git worktree list --porcelain
git fsck --no-dangling
./scripts/check.sh
cargo test --workspace --all-features --release
```

Record the exact head as `m1_010_mutation_head` in the task report and Shared Memory. Expected: clean worktree, full/release pass, remote main unchanged, no mutation worktree exists.

- [ ] **Step 2: Run one disposable worktree per exact mutation**

Create ignored `.superpowers/sdd/2026-08-26-m1-010-verifier-state-machine/mutation-report.md` with `apply_patch`. Give it one table row per probe: ID, exact base head, mutated path/semantic, focused command, exit code, intended failing assertion/compiler cause, cleanup verification. Do not store request sentinels, credentials, or raw model output.

For each probe below:

1. create a new temporary directory with `mktemp -d`;
2. add a detached worktree at exact `m1_010_mutation_head`;
3. apply only the named single-cause mutation with `apply_patch`;
4. run the named focused regression command;
5. require nonzero exit caused by the intended assertion/compile failure;
6. record probe name, mutated path, command, exit, and intended failure in the ignored task report;
7. remove that exact temporary worktree; and
8. verify primary HEAD/status did not change.

Use this shell structure for each probe, substituting the exact probe ID and focused command from the table/report:

```bash
m1_010_probe_id='P01'
m1_010_mutation_head="$(git rev-parse HEAD)"
m1_010_probe_root="$(mktemp -d)"
m1_010_probe_path="${m1_010_probe_root}/${m1_010_probe_id}"
git worktree add --detach "${m1_010_probe_path}" "${m1_010_mutation_head}"
```

Apply the single mutation with `apply_patch` inside `m1_010_probe_path`, run its focused test, and require the intended nonzero result. Then:

```bash
git worktree remove --force "${m1_010_probe_path}"
rmdir "${m1_010_probe_root}"
git rev-parse HEAD
git status --short --branch
```

Never use a workspace root, home directory, unresolved glob, or unresolved environment variable as a removal target.

The exact table is 88 probes:

| Group | Probe IDs | Exact mutation | Required detector |
| --- | --- | --- | --- |
| Phase guards (9) | `P01` challenge, `P02` freshness, `P03` identity, `P04` evidence, `P05` session, `P06` revocation, `P07` policy, `P08` early full completion, `P09` early restricted completion | delete/widen one expected-phase comparison; each completion mutation chooses only its named allowed class | 182-pair oracle, omission/permutation, and full/restricted early-completion tests |
| Binding (8) | `B01` challenge, `B02` freshness, `B03` identity, `B04` evidence, `B05` session, `B06` revocation, `B07` policy, `B08` allocation identity | bypass only that capability comparison; for `B08`, replace `Arc::ptr_eq` with replay-registration/request equality | seven equal-data cross-flow test |
| Authority production (3) | `A01` accept `Decision`, `A02` raw claim returns/mints `FreshnessChecked`, `A03` issue a second `VerifiedAttestation` | add one forbidden authority shortcut | single-cause compile-fail or repeated-completion test |
| Terminality (7) | `T01` Verified, `T02` Malformed, `T03` Unsupported, `T04` Retryable, `T05` Denied, `T06` Revoked, `T07` reclassification | permit one action from that terminal or allow failure terminal to change class/reason | terminal × 13 matrix and terminal-class test |
| Unknown gate (1) | `U01` | continue progress instead of `mark_unsupported` | unknown-gate regression/scenario |
| Outcome mapping (7) | `M01` full, `M02` restricted, `M03` malformed, `M04` unsupported, `M05` retryable, `M06` revoked, `M07` denial-reason map | change one decision or reason mapping | complete outcome table test |
| Request retention (6) | `R01` Verified, `R02` Malformed, `R03` Unsupported, `R04` Retryable, `R05` Denied, `R06` Revoked | omit request release for exactly one terminal | request-exists-only-while-nonterminal test |
| Clone/copy (9) | `C01` flow, `C02` challenge, `C03` freshness, `C04` identity, `C05` evidence, `C06` session, `C07` revocation, `C08` policy, `C09` verified | add `Clone` (or `Copy` where compilable) to exactly one authority type | matching single-cause compile-fail doctest |
| Private fields (17) | `F01` flow binding, `F02` flow request, `F03` flow state, `F04` attempt registration, `F05` binding Arc, `F06` challenge binding, `F07` freshness binding, `F08` identity binding, `F09` evidence binding, `F10` session binding, `F11` revocation binding, `F12` policy binding, `F13` policy allowed, `F14` verified binding, `F15` verified allowed, `F16` outcome decision, `F17` outcome reason | make exactly one field externally or crate visible | per-field structural assertion plus corresponding compile-fail block |
| Public construction (8) | `K01` challenge, `K02` freshness, `K03` identity, `K04` evidence, `K05` session, `K06` revocation, `K07` policy, `K08` verified | add one public constructor/factory | corresponding external construction compile-fail block |
| Diagnostics (13) | `D01` flow, `D02` binding, `D03` challenge, `D04` freshness, `D05` identity, `D06` evidence, `D07` session, `D08` revocation, `D09` policy, `D10` verified, `D11` transition error, `D12` request, `D13` evidence bundle | expose one private sentinel/address/count/payload through default formatting | exact diagnostic privacy tests |

Count assertion: `9 + 8 + 3 + 7 + 1 + 7 + 6 + 9 + 17 + 8 + 13 = 88`.

Focused commands are the smallest test named in the detector column. For a compile-fail mutation run `cargo test -p ogir-verifier --doc`; for structural/privacy groups run the exact named unit/integration test; for `D13` run the protocol diagnostic test. Do not accept a failure caused by syntax, formatting, or an unrelated compile error.

- [ ] **Step 3: Handle a surviving or wrong-cause mutation test-first**

If any probe passes or fails for the wrong reason:

1. remove its disposable worktree;
2. return to the clean primary worktree;
3. write one focused regression that passes on current correct code;
4. re-run the mutation in a fresh worktree and require the intended failure;
5. commit only the regression (and minimal production correction if a real defect exists) unsigned;
6. refresh `m1_010_mutation_head`; and
7. restart all 88 probes at the new exact head.

Never copy mutated source into the primary worktree.

- [ ] **Step 4: Prove cleanup and run final exact-head gates**

Run:

```bash
git status --short --branch
git rev-parse HEAD
git worktree list --porcelain
git fsck --no-dangling
git diff --check
./scripts/check.sh
cargo test --workspace --all-features --release
```

Expected: primary branch clean; no mutation worktrees/branches; 88/88 report complete; at least 71 runtime/integration tests (66 baseline plus the new protocol/public/private verifier coverage), all doctests/scenarios/ADRs and quality gates pass. Record actual counts rather than retaining this lower bound.

- [ ] **Step 5: Obtain separate fresh TCB and privacy reviews**

Prepare a review package with:

```text
base: b3a8f1431258a41d38df88c3724ab384dab1272a
head: exact current unsigned HEAD
spec: docs/superpowers/specs/2026-08-26-m1-010-verifier-state-machine-design.md
issue: planning/issues/010-verifier-state-machine.md
plan: docs/superpowers/plans/2026-08-26-m1-010-verifier-state-machine.md
mutation report: exact 88/88 names/commands/results
```

Dispatch two independent fresh-context reviewers:

- TCB reviewer: authority construction, phase/binding order, equal-flow substitution, freshness integration, outcome mapping, terminality, report/capability confusion, missing negative tests.
- Privacy reviewer: request retention, every diagnostic surface, evidence bundle, Arc details, sentinels, paths/control text, false non-disciplinary claims.

Require each to report only concrete Critical/Important/Minor findings and a final readiness Yes/No. Fix findings test-first, rerun affected mutations/full gates, and repeat fresh review until both verdicts are Yes with no unresolved finding.

- [ ] **Step 6: Add exact implementation evidence and move local status**

Before editing, capture the current live body/metadata and prove it still equals the committed ready issue source. Then use `apply_patch` on `planning/issues/010-verifier-state-machine.md` to:

- change only `status: ready` to `status: needs-review` in metadata;
- append `## Implementation evidence` with the exact time-bounded pre-DCO review checkpoint (base, unsigned head, tree, commit count), actual test/doctest/scenario/ADR counts, 182/48/134, 5,040/5,039, 1,048,576/2,048/1,046,528, 88/88 mutations, compile-pass/fail counts, cross-flow coverage, request/diagnostic proof, full/release commands, review verdicts, limitations, and deferred adapters;
- state explicitly that, at that recorded checkpoint, every commit was unsigned and publication/DCO/human review remained pending; later metadata-only SHA equivalence is recorded in Shared Memory and the PR rather than rewriting this historical sentence; and
- avoid any production-readiness or cheating-detection claim.

Run:

```bash
./scripts/check.sh
cargo test --workspace --all-features --release
git diff --check
git add planning/issues/010-verifier-state-machine.md
git diff --cached --check
git commit -m "docs: record M1-010 implementation evidence"
```

Expected: one unsigned issue-evidence commit on a clean exact head.

- [ ] **Step 7: Guardedly synchronize only the live issue body/status label**

Resolve the exact issue number by title. Preconditions:

- live body equals the prior committed ready body captured before Step 6;
- live state remains OPEN;
- milestone is `M1 Domain Model`;
- labels equal the exact ready taxonomy;
- no duplicate exact title exists.

Then run:

```bash
gh issue edit "${m1_010_issue_number}" --repo archledger/open-game-integrity-runtime --body-file planning/issues/010-verifier-state-machine.md --remove-label 'status: ready' --add-label 'status: needs-review'
```

Read back body base64 and complete metadata. Require exact new local/live body equality, unchanged non-status labels/milestone/state, and only `status: needs-review`. Refresh Shared Memory with rollback: restore the previous reviewed body and label only through another guarded edit if a concrete review requires it.

---

### Task 11: Freeze DCO, Publish Non-Force, and Hand Off for Human Review

**Files:**

- Read only: complete repository and exact unsigned history
- Create outside the repository: immutable backup ref/bundle/hash manifest
- Create ignored review/PR body files only: `.superpowers/sdd/2026-08-26-m1-010-verifier-state-machine/`
- External: remote feature branch and one non-draft PR; no merge

**Interfaces:**

- Consumes: clean independently reviewed unsigned branch, exact live `needs-review` issue, human DCO certification.
- Produces: metadata-only DCO-clean equivalent range, verified rollback bundle, non-force published branch, green reviewable PR, and human handoff.

- [ ] **Step 1: Freeze and print the exact unsigned certification range**

Run:

```bash
git status --short --branch
m1_010_base='b3a8f1431258a41d38df88c3724ab384dab1272a'
m1_010_unsigned_tip="$(git rev-parse HEAD)"
git rev-list --reverse "${m1_010_base}..${m1_010_unsigned_tip}"
git log --reverse --format='commit=%H%ncommitter=%cn <%ce>%nsubject=%s%ntrailers=%(trailers:key=Signed-off-by,valueonly)%n---' "${m1_010_base}..${m1_010_unsigned_tip}"
./scripts/check-dco.sh "${m1_010_base}" "${m1_010_unsigned_tip}"
```

Expected: clean branch, exact immutable commit count/list, and DCO exit 1 only because each unsigned commit lacks `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>`. Any existing/mismatched/forbidden trailer is a blocker.

Stop and ask the user to certify the exact printed commit range. Required substance:

```text
I certify that I authored or otherwise have the right to submit every commit
in the exact range b3a8f1431258a41d38df88c3724ab384dab1272a..${m1_010_unsigned_tip}
under DCO 1.1, and I authorize adding exactly:
Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>
to those commits.
```

Before showing this sentence to the user, replace the shell expression with the exact printed 40-hex unsigned tip; never ask the user to certify an unresolved variable.

Do not infer certification from design approval, plan approval, execution permission, GitHub identity, or prior M1 ranges.

- [ ] **Step 2: After exact certification, create immutable rollback evidence**

Run with the certified frozen tip:

```bash
m1_010_base='b3a8f1431258a41d38df88c3724ab384dab1272a'
m1_010_unsigned_tip="$(git rev-parse HEAD)"
m1_010_backup_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
m1_010_backup_ref="refs/backup/pre-m1-010-dco/${m1_010_backup_stamp}/tip"
m1_010_backup_bundle="/home/wisbfime/Open Game Intergrity Runtime  - Github Project/backups/ogir-m1-010-pre-dco-${m1_010_backup_stamp}.bundle"
git update-ref "${m1_010_backup_ref}" "${m1_010_unsigned_tip}"
git bundle create "${m1_010_backup_bundle}" "${m1_010_backup_ref}" refs/heads/main
git bundle verify "${m1_010_backup_bundle}"
sha256sum "${m1_010_backup_bundle}"
git fsck --no-dangling
```

Write the exact SHA-256 to the sibling `.bundle.sha256` manifest with `apply_patch`, then run `sha256sum -c` on it. Record ref, bundle path/hash, certified range, and exact restore command `git fetch "${m1_010_backup_bundle}" "${m1_010_backup_ref}:${m1_010_backup_ref}"` in Shared Memory. Never delete the ref/bundle during this task.

- [ ] **Step 3: Rewrite metadata only and prove equivalence**

Run:

```bash
m1_010_base='b3a8f1431258a41d38df88c3724ab384dab1272a'
m1_010_backup_ref="$(git for-each-ref --count=1 --sort=-creatordate --format='%(refname)' 'refs/backup/pre-m1-010-dco/*/tip')"
test -n "${m1_010_backup_ref}"
git rebase --force-rebase --exec 'git commit --amend --no-edit --signoff' "${m1_010_base}"
m1_010_signed_tip="$(git rev-parse HEAD)"
./scripts/check-dco.sh "${m1_010_base}" "${m1_010_signed_tip}"
git log --reverse --format='%T%x09%s' "${m1_010_base}..${m1_010_backup_ref}"
git log --reverse --format='%T%x09%s' "${m1_010_base}..${m1_010_signed_tip}"
git range-diff "${m1_010_base}..${m1_010_backup_ref}" "${m1_010_base}..${m1_010_signed_tip}"
git log --format='%(trailers:key=Signed-off-by,valueonly)' "${m1_010_base}..${m1_010_signed_tip}"
git status --short --branch
```

Expected:

- same commit count/order/tree/subject/author as the certified unsigned range;
- only commit IDs/committer metadata and one exact permitted trailer differ;
- DCO passes every commit;
- no `Signed-off-by: archledger <archledger236@gmail.com>` or duplicate trailer;
- clean worktree.

- [ ] **Step 4: Re-run all gates and obtain fresh rewritten-SHA review**

Run:

```bash
m1_010_base='b3a8f1431258a41d38df88c3724ab384dab1272a'
m1_010_signed_tip="$(git rev-parse HEAD)"
./scripts/check.sh
cargo test --workspace --all-features --release
git diff "${m1_010_base}..${m1_010_signed_tip}" --check
git fsck --no-dangling
git status --short --branch
```

Dispatch a fresh exact-SHA reviewer to compare certified unsigned backup range with rewritten range, then review the whole rewritten head against issue/spec/plan. Publication requires equivalence Yes and no Critical/Important/Minor finding.

- [ ] **Step 5: Guardedly publish without force**

Immediately before push, run:

```bash
m1_010_signed_tip="$(git rev-parse HEAD)"
m1_010_issue_number="$(gh issue list --repo archledger/open-game-integrity-runtime --state all --limit 500 --json number,title --jq '.[] | select(.title == "M1-010: Implement the fail-closed verifier state machine") | .number')"
test -n "${m1_010_issue_number}"
git ls-remote origin refs/heads/main
git ls-remote --heads origin refs/heads/research/m1-010-verifier-state-machine
gh pr list --repo archledger/open-game-integrity-runtime --state all --head research/m1-010-verifier-state-machine --json number,state,url
gh issue view "${m1_010_issue_number}" --repo archledger/open-game-integrity-runtime --json state,milestone,labels,url
```

Require remote main still `b3a8f1431258a41d38df88c3724ab384dab1272a`, no remote feature branch/PR, and exact open `needs-review` issue. Then:

```bash
git push -u origin research/m1-010-verifier-state-machine
git ls-remote --heads origin refs/heads/research/m1-010-verifier-state-machine
```

No force flag is permitted. Verify remote head equals `m1_010_signed_tip`.

- [ ] **Step 6: Create and verify the non-draft PR**

Use `apply_patch` to create ignored `.superpowers/sdd/2026-08-26-m1-010-verifier-state-machine/pr-body.md` from `.github/pull_request_template.md`, filling every section with exact final evidence. Insert the exact issue number discovered in Task 1; do not leave a generic issue-number marker.

Required body facts:

```text
Problem: verifier appraisal progress/report fields do not encode authority.
Invariants: 1, 2, 5, 6, 8-10, 20-21, 25-26, 37, 39-40.
In scope: pure attempt-bound graph, report boundary, proof suite, docs/scenarios.
Out of scope: every deferred validator/signer/permit/network/crypto item.
Primary sources: RFC 9334, Rust 1.98 visibility/Arc/ownership, API Guidelines.
Trust boundary: Verifier/relying party checked.
Verification: exact final commands/counts and 88/88 mutations.
Privacy: no new disclosed claim/log field; model/redaction tests updated.
Dependencies: no dependency added or changed; SPDX boundary reviewed.
AI-Assisted: yes
AI-System: OpenAI Codex
AI-Use: research | implementation | tests | review | docs
Human-Reviewed-Every-Line: no
Primary-Sources-Verified: yes
Closes followed by `#` and the exact decimal issue number discovered in Task 1.
Contributor certification: DCO checked; responsibility remains unchecked.
```

Create:

```bash
m1_010_pr_url="$(gh pr create --repo archledger/open-game-integrity-runtime --base main --head research/m1-010-verifier-state-machine --title 'M1-010: Implement the fail-closed verifier state machine' --body-file .superpowers/sdd/2026-08-26-m1-010-verifier-state-machine/pr-body.md)"
m1_010_pr_number="$(gh pr list --repo archledger/open-game-integrity-runtime --state open --head research/m1-010-verifier-state-machine --json number --jq '.[0].number // empty')"
test -n "${m1_010_pr_number}"
```

Read back PR head/base/body/state/draft/mergeability/commits. Require exact signed head, base `main`, non-draft OPEN state, issue-closing linkage, AI disclosure, DCO certification checked, and human review/responsibility still `no`/unchecked.

- [ ] **Step 7: Watch remote checks and hand off; never merge autonomously**

Run:

```bash
m1_010_pr_number="$(gh pr list --repo archledger/open-game-integrity-runtime --state open --head research/m1-010-verifier-state-machine --json number --jq '.[0].number // empty')"
test -n "${m1_010_pr_number}"
gh pr checks --repo archledger/open-game-integrity-runtime --watch "${m1_010_pr_number}"
gh pr view "${m1_010_pr_number}" --repo archledger/open-game-integrity-runtime --json state,isDraft,mergeable,mergeStateStatus,reviews,comments,commits,url
gh api "repos/archledger/open-game-integrity-runtime/pulls/${m1_010_pr_number}/comments"
gh api "repos/archledger/open-game-integrity-runtime/code-scanning/alerts?state=open&pr=${m1_010_pr_number}"
```

Resolve only evidence-backed findings through new test-first unsigned commits, followed by their own human DCO certification/rewrite and non-force/lease-safe publication. Never dismiss a real alert to make checks green.

When checks/reviews are clean, refresh Shared Memory and hand the exact PR URL/head to the user. Stop for explicit line-by-line review, responsibility acceptance, and merge authorization. Do not mark those human-only fields, click merge, delete the branch, or remove any worktree without explicit user direction.

---

## Spec-to-Task Coverage

| Approved requirement | Implemented/proved by |
| --- | --- |
| Report-only decisions versus authority capability | Tasks 3-6, mutations `A01`, `K08`, `F16-F17` |
| Exact seven-gate/eight-edge success graph | Tasks 4-5, `P01-P09`, omissions/permutations |
| Five failure classes and six immutable terminals | Task 5, `T01-T07`, 182-pair oracle |
| Full/restricted no-fallback outcomes | Tasks 4-5, `P08-P09`, `M01-M02` |
| Seven denial reasons and all decision/reason mappings | Task 5, `M03-M07` |
| Arc allocation identity plus replay registration | Tasks 4 and 6, `B01-B08` |
| Equal-data cross-flow rejection | Tasks 4 and 6, scenario 2, `B01-B08` |
| Active-only request ownership | Tasks 4-6, `R01-R06` |
| No unauthenticated freshness capability | Task 3, raw-claim compile proof, `A02` |
| Non-cloneable/private authority surface | Tasks 4 and 6, `C01-C09`, `F01-F17`, `K01-K08` |
| Exact diagnostic redaction and EvidenceBundle hardening | Tasks 2 and 6, scenario 5, `D01-D13` |
| 182 pairs, 5,040 permutations, exact million histories | Tasks 5-6 |
| Five machine-readable scenarios | Task 7 |
| Architecture/roadmap/threat/test/ADR traceability | Tasks 8-9 |
| Independent TCB/privacy review and evidence status | Task 10 |
| Human DCO, non-force PR, human-only merge | Task 11 |
| No dependency/unsafe/parser/crypto/I/O/production adapter | Global constraints plus every task's file/command gate |

---

## Plan Self-Review Checklist

- [x] Every issue/spec requirement maps to at least one task and executable command.
- [x] File map matches every create/modify path used by tasks; no task touches an intentionally unchanged path.
- [x] All seven gate types, eight success edges, five failure actions, six terminals, seven denial reasons, five decisions, and twelve reasons are named consistently.
- [x] Matrix arithmetic is `14 × 13 = 182`, `48 + 134 = 182`; permutations are `5,040 = 1 + 5,039`; action budget is `2,048 + 1,046,528 = 1,048,576`; mutation groups sum to 88.
- [x] Task 3 removes unauthenticated `claim_checked`; Task 4 adds no production replacement constructor.
- [x] Every code-producing task has a focused RED command before implementation and focused/full GREEN commands after.
- [x] Every authority field/type and diagnostic surface has both compile/structural/privacy coverage and a named mutation.
- [x] Restricted success is never described as fallback; report-only values are never accepted as authority.
- [x] Request release is tested for all six terminals without a zeroization claim.
- [x] Five scenario IDs/filenames are unique and validator-compatible; total becomes fourteen.
- [x] ADR-0007, architecture, roadmap, threat, test strategy, issue evidence, and conditional lessons are sequenced after executable behavior.
- [x] No task adds a dependency, unsafe/crypto/parser/I/O/adapter, production claim, or automatic disciplinary behavior.
- [x] GitHub writes are guarded/read back; DCO requires exact new human certification; push is non-force; merge remains human-only.
- [x] No unresolved marker, vague “handle errors,” undefined type/function, or cross-task shortcut remains.
