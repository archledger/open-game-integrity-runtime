# M1-011 Appraisal Result Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one opaque, capability-gated, unsigned `AppraisalResult` with exact context, allow-only accepted claims, and a complete phase-eligible five-decision/fifteen-reason taxonomy.

**Architecture:** Keep the semantic result beside `VerifierFlow` in `ogir-verifier`, where private capability payloads and whole-state terminal replacement can preserve exact-attempt association without a reverse dependency or public factory. Success consumes `VerifiedAttestation`; eligible failure transitions emit one failure result directly. The value is reportable but has no intrinsic validity, cryptographic payload provenance, trusted failure provenance, generic signer, wire representation, permit, proof, or admission authority.

**Tech Stack:** Rust 1.98.0, edition 2024, Rust standard library ownership and privacy, existing `ogir-model`, `ogir-protocol`, and `ogir-verifier` crates, Cargo tests/doctests/Clippy/rustdoc, Bash/Git disposable mutation worktrees, GitHub CLI behind explicit authorization, and the existing dependency-free scenario validator.

**Spec:** `docs/superpowers/specs/2026-08-28-m1-011-appraisal-result-design.md`

## Global Constraints

- Base implementation work on `main` commit `955c88e372cffa13f15953085f15887165be62b5`; preserve the approved dirty design tree `bc015648a08f10de543b764d8333baaf6e423114` and the separately approved plan commit used to create the implementation branch.
- Before each task, read the approved spec and the task-relevant portions of `docs/SECURITY_INVARIANTS.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `docs/AI_DEVELOPMENT_POLICY.md`, the canonical issue, ADR-0007, and ADR-0009.
- At execution time, use `superpowers:using-git-worktrees` before implementation and retain every existing worktree, backup ref, bundle, manifest, and report. Never clean another task's worktree or rollback evidence.
- No GitHub issue exists for M1-011. Creating or editing an issue, branch, PR, label, milestone, comment, review, alert, or other GitHub object requires fresh explicit user authorization for that exact mutation.
- Keep `#![forbid(unsafe_code)]`; add no dependency, feature, crate, build script, parser, serializer, encoding, wire discriminant, cryptographic primitive, signer, validator, network, filesystem, database, clock, RNG, persistence, privileged behavior, or `unsafe` code.
- Do not modify any `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, historical plan, or historical spec.
- `AppraisalResult` is unsigned semantic data. It is not the protected `AttestationResult`, a permit, proof of possession, admission decision, disciplinary assertion, or generic input to a signer.
- The types prove valid result shape, exact-flow capability association, context movement, and one-use allow conversion. They do not prove cryptographic provenance of `EvidenceProfile` or `SessionPublicKeyId`, trusted provenance of failures, intrinsic result validity, freshness at result emission, expiry, deletion, or secure erasure.
- `AppraisalResult`, `AcceptedClaims`, `VerifiedAttestation`, `VerifierFlow`, and authority capabilities have no public construction shortcut. `AppraisalResult` and `VerifiedAttestation` are neither `Clone` nor `Copy`; `AppraisalResult` has no `Default`, builder, setter, report conversion, signing conversion, or public fields.
- The only allowed allow conversion is `VerifiedAttestation::into_appraisal_result(self) -> AppraisalResult`. It accepts no argument and is infallible.
- Every failure method validates phase and typed input before mutation, replaces the whole active state with a terminal first, then infallibly assembles one returned `AppraisalResult`. A repeated terminal action returns `InvalidTransition` and emits no second result.
- Every capability transition checks phase, allocation binding, and only then moves payload/state. Allocation identity proves flow association, not payload truth.
- `EvidenceAppraised` carries `EvidenceProfile`; `SessionBound` carries `SessionPublicKeyId`; `PolicySatisfied` carries the selected `AllowedClass`. Active state accumulates these values without unrelated `Option` slots.
- Full and restricted results retain the exact policy already in `ExpectedContext`. Restricted is not a second policy and is never fallback after full-policy denial.
- Failure results retain exact `ExpectedContext` and no accepted claims. Allows retain exact context, accepted profile, session-key handle, and class, with no failure reason.
- `verify_research_structure` remains a non-authoritative report-only scaffold and never constructs `VerifiedAttestation`, `AcceptedClaims`, or `AppraisalResult`.
- Default diagnostics never expose identifiers, timestamps, durations, nonce, evidence, profile sentinels, key bytes, binding/allocation details, paths, control text, or CI commands. Explicit getters are trusted functional interfaces, not logging surfaces.
- Write every negative test and capture its independent runtime/compiler RED before the corresponding production edit. A wrong-cause RED must be corrected before implementation.
- Execute every `bash` fence in a fresh Bash process with `set -euo pipefail` prepended. A `text` fence containing RED selectors is a command list: execute each line as its own fresh fail-fast Bash invocation and record its expected nonzero status. Values never persist across fences or tasks: rediscover them from exact state or read them from a reviewed ignored evidence file, then validate them. A failed producer or empty command substitution is never evidence of absence.
- If two proposed tests make one Rust target uncompilable, add and run only one test, remove that exact hunk, restore baseline GREEN, then repeat for the next test. After all isolated RED records exist, add the complete set and implement; never claim selector-specific causality while another uncompilable test is present.
- Keep commits unsigned until the user certifies one exact frozen range under DCO 1.1. The only eventually permitted trailer is `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>` after exact certification.
- After each implementation task, obtain a fresh requirements review and a fresh code-quality/security review. Resolve findings test-first before the next task.
- Do not implement this plan, commit, publish, push, open a PR, or merge while writing or reviewing the plan.

## File Map

**Modify runtime and tests:**

- `crates/ogir-model/src/lib.rs:529-571` - retain five decisions; replace the twelve-value reason enum with exactly fifteen failure reasons and no absence sentinel.
- `crates/ogir-verifier/src/lib.rs:9-17` - re-export `AppraisalResult`, `AppraisalResultView`, `AcceptedClaims`, `RetryReason`, and updated verifier types.
- `crates/ogir-verifier/src/verification.rs:61-139` - make report reason optional and add exact mapping helpers.
- `crates/ogir-verifier/src/verification.rs:205-343` - expand typed causes, claim-bearing capabilities, result types, and private state.
- `crates/ogir-verifier/src/verification.rs:415-988` - update authority doctests, whole-state transitions, completion, failures, and diagnostics.
- `crates/ogir-verifier/src/verification.rs:1000-1049` - update only report taxonomy in the non-authoritative research scaffold.
- `crates/ogir-verifier/src/verification/tests.rs:1-2034` - fixtures, independent model, result tests, 336-pair oracle, history schedule, structural and privacy proof.
- `crates/ogir-verifier/tests/verification_public.rs:1-73` - downstream read-only result/view/accessor behavior.
- `crates/ogir-verifier/tests/freshness.rs:240-518` - `Option<ReasonCode>` assertions while preserving all freshness effects.
- `crates/ogir-verifier/src/freshness.rs:202-247` - only update authority documentation if the new whole-state wording requires it; do not alter raw freshness semantics.

**Modify durable documentation:**

- `docs/ARCHITECTURE.md:177-196, 251-374, 459-472, 625-642` - semantic result seam, retained values, validity/protection deferral, taxonomy.
- `docs/THREAT_MODEL.md:140-167, 217-221, 223-250, 269-279` - result forgery, claim substitution/discard, impossible-phase reasons, residual TCB and privacy risks.
- `docs/ROADMAP.md:83-193, 724-735, 764-778` - M1-011 completion and M1-012/M2 ownership boundaries.
- `docs/TEST_STRATEGY.md:43-67, 109-157, 271-279` - frozen `336/50/286`, history schedule, 154 mutations, and scenario claims.
- `docs/PRIVACY_MODEL.md:5-42` - context/allow-claim retention, failure discard, no intrinsic expiry, trusted getters.
- `docs/TRUST_MODEL.md:3-30` - capability association versus payload truth and protected issuer responsibilities.
- `docs/PROTOCOL.md:24-51` - semantic Appraisal Result precedes transcript/protection; no wire or signing shortcut.
- `docs/LESSONS_LEARNED.md` - append only when implementation or review confirms a concrete mistake with a permanent regression.
- `docs/adr/0007-verifier-flow-capabilities.md:88-149, 190-220` - refine all-failure eligibility and update executable evidence.
- `docs/adr/0009-capability-gated-appraisal-results.md:69-168` - record implemented evidence without changing the accepted decision.
- `docs/adr/index.md:18-28` - verify ADR-0009 remains one Accepted row; change only if checker evidence exposes real drift.
- `planning/issues/011-result-reason-code-taxonomy.md:1-292` - append exact time-bounded implementation evidence and move local status only after all reviews.

**Modify the existing five verifier scenarios; create no sixth duplicate family:**

- `lab/scenarios/verifier-gate-skip.scenario.json:1-23` - result-forgery and only-complete-path language.
- `lab/scenarios/verifier-capability-substitution.scenario.json:1-23` - wrong-flow claims versus correctly bound dishonest payload residual risk.
- `lab/scenarios/verifier-terminal-immutability.scenario.json:1-23` - one result emission and all 24 semantic actions.
- `lab/scenarios/verifier-unknown-gate.scenario.json:1-17` - `unsupported-critical-requirement` mapping and phase eligibility.
- `lab/scenarios/verifier-diagnostics-privacy.scenario.json:1-24` - result/view/claims diagnostics and failure claim discard.

**Intentionally unchanged:**

- All historical plans/specs, scenario schema/validator/registries, protocol/model crates other than `ReasonCode`, manifests/lockfile/toolchain, agent/session code, application binaries, freshness storage behavior, and every production adapter.

---

### Task 1: Guard Local/Live Setup and Freeze the Complete Action Domain

**Files:**
- Read: `planning/issues/011-result-reason-code-taxonomy.md:1-292`
- Read: `docs/superpowers/specs/2026-08-28-m1-011-appraisal-result-design.md:1-511`
- Read: `crates/ogir-verifier/src/verification/tests.rs:117-454, 942-1411, 1684-2034`
- External only after explicit authorization: one GitHub issue; no runtime edit

**Interfaces:**
- Consumes: exact base `955c88e372cffa13f15953085f15887165be62b5`, approved design tree `bc015648a08f10de543b764d8333baaf6e423114`, approved plan commit, no existing M1-011 live issue.
- Produces: retained implementation worktree/branch, one exact live ready issue only if authorized, and reviewed constants `24`, `336`, `50`, `286`, `2_048`, `1_046_528`, and `1_048_576` before runtime edits.

- [ ] **Step 1: Stop for explicit external-mutation authorization**

Ask the user to authorize exactly: creating one live issue titled `M1-011: Define the Appraisal Result and reason-code taxonomy` from the canonical local body and creating/publishing no branch or PR. If authorization is absent, record the local preconditions and stop Task 1 before every `gh` write.

- [ ] **Step 2: Verify local topology and retained artifacts**

Run separately in the implementation worktree:

```bash
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
git worktree list --porcelain
git for-each-ref --format='%(refname) %(objectname)' 'refs/backup/*'
git fsck --no-dangling
```

Expected: the isolated branch descends from the approved planning head whose base is `955c88e`; all retained worktrees and backup refs remain present; no unrelated dirty path exists. Any missing retained artifact or changed base blocks execution.

- [ ] **Step 3: If authorized, prove no live issue collision and create exactly one issue**

```bash
set -euo pipefail
m1_011_title='M1-011: Define the Appraisal Result and reason-code taxonomy'
m1_011_count="$(gh api --paginate --slurp 'repos/archledger/open-game-integrity-runtime/issues?state=all&per_page=100' --jq '[.[][] | select(.pull_request == null) | select(.title == "M1-011: Define the Appraisal Result and reason-code taxonomy")] | length')"
test "${m1_011_count}" -eq 0
m1_011_url="$(gh issue create --repo archledger/open-game-integrity-runtime --title "${m1_011_title}" --body-file planning/issues/011-result-reason-code-taxonomy.md --milestone 'M1 Domain Model' --label 'type: architecture' --label 'area: model' --label 'area: verifier' --label 'area: privacy' --label 'risk: trusted-computing-base' --label 'risk: privacy' --label 'status: ready')"
printf '%s\n' "${m1_011_url}"
m1_011_number="${m1_011_url##*/}"
test "$(gh issue view "${m1_011_number}" --repo archledger/open-game-integrity-runtime --json title --jq '.title')" = "${m1_011_title}"
test "$(gh issue view "${m1_011_number}" --repo archledger/open-game-integrity-runtime --json state --jq '.state')" = 'OPEN'
test "$(gh issue view "${m1_011_number}" --repo archledger/open-game-integrity-runtime --json milestone --jq '.milestone.title')" = 'M1 Domain Model'
test "$(gh issue view "${m1_011_number}" --repo archledger/open-game-integrity-runtime --json labels --jq '[.labels[].name] | sort | join(",")')" = 'area: model,area: privacy,area: verifier,risk: privacy,risk: trusted-computing-base,status: ready,type: architecture'
live_ready_body="$(gh issue view "${m1_011_number}" --repo archledger/open-game-integrity-runtime --json body --jq '.body | @base64')"
local_ready_body="$(base64 -w0 planning/issues/011-result-reason-code-taxonomy.md)"
test -n "${live_ready_body}"
test -n "${local_ready_body}"
test "${live_ready_body}" = "${local_ready_body}"
```

Expected: one URL and five successful exact readback guards. The paginated preflight covers every open and closed issue instead of truncating at 500; the issue number comes only from the returned URL.

Using `apply_patch`, record the exact issue URL/number and the one-line `base64 -w0` ready-body value in ignored Task 1 evidence, including `.superpowers/sdd/2026-08-28-m1-011-appraisal-result/live-ready-body.b64`. Later issue guards read this reviewed evidence rather than ambient variables.

- [ ] **Step 4: Freeze the 24 semantic actions in a review note before runtime edits**

Record this exact enumeration in the Task 1 report and later test constants:

```text
01 Challenge(Matching)
02 Freshness(Matching)
03 Identity(Matching)
04 Evidence(Matching)
05 Session(Matching)
06 Revocation(Matching)
07 Policy(Full, Matching)
08 Policy(Restricted, Matching)
09 Complete
10 MarkMalformed
11 MarkUnsupported(VersionOrProfile)
12 MarkUnsupported(Platform)
13 MarkUnsupported(UnknownCriticalRequirement)
14 MarkRetryable(AttestationUnavailable)
15 MarkRetryable(TransientFailure)
16 Deny(ChallengeAuthenticationFailed)
17 Deny(NotYetValid)
18 Deny(Expired)
19 Deny(ReplayDetected)
20 Deny(ContextBindingMismatch)
21 Deny(EvidenceInvalid)
22 Deny(PolicyDenied)
23 Deny(ProtectedSessionLost)
24 MarkRevoked
```

The seven public gate action names become eight semantic variants only because `PolicySatisfied` has separate Full and Restricted payloads. Binding mismatch is tested in a separate seven-gate matrix and is not a 25th semantic action.

- [ ] **Step 5: Freeze the 41 eligible failure edges and arithmetic**

Record the exact rows:

```text
EvidenceReceived (5): malformed; challenge-authentication-failed; attestation-unavailable; transient-failure; unknown-critical-requirement
ChallengeAuthenticated (8): version-or-profile; not-yet-valid; expired; replay-detected; context-binding-mismatch; attestation-unavailable; transient-failure; unknown-critical-requirement
FreshnessChecked (4): context-binding-mismatch; attestation-unavailable; transient-failure; unknown-critical-requirement
IdentityChecked (5): platform; evidence-invalid; attestation-unavailable; transient-failure; unknown-critical-requirement
EvidenceAppraised (5): context-binding-mismatch; protected-session-lost; attestation-unavailable; transient-failure; unknown-critical-requirement
SessionBound (5): revoked; protected-session-lost; attestation-unavailable; transient-failure; unknown-critical-requirement
RevocationChecked (5): policy-denied; protected-session-lost; attestation-unavailable; transient-failure; unknown-critical-requirement
PolicySatisfied (4): protected-session-lost; attestation-unavailable; transient-failure; unknown-critical-requirement
```

Freeze these equations:

```text
5 + 8 + 4 + 5 + 5 + 5 + 5 + 4 = 41 eligible failure edges
6 ordinary pre-policy gate edges + 2 policy-class edges + 1 completion edge = 9 success-graph edges
14 phases × 24 semantic actions = 336 pairs
41 + 9 = 50 successful pairs
336 - 50 = 286 state-preserving rejections
```

- [ ] **Step 6: Freeze the exact long-history schedule**

Use these constants and allocation, without changing the million-action budget:

```rust
const TOTAL_ACTIONS: usize = 1_048_576;
const SCHEDULED_ACTIONS: usize = 2_048;
const ARBITRARY_ACTIONS: usize = 1_046_528;
const ACTIVE_PAIR_ACTIONS: usize = 864;
const TERMINAL_PAIR_ACTIONS: usize = 576;
const CROSS_FLOW_ACTIONS: usize = 35;
const EXTRA_COMPLETION_ACTIONS: usize = 312;
const FILLER_ACTIONS: usize = 5;
```

Derivation:

```text
32 canonical completions × 8 actions = 256
sum over active prefixes: 24 × (1 + 2 + 3 + 4 + 5 + 6 + 7 + 8) = 864
terminal/action proof: Verified 24 × 9 + Malformed 24 × 2 + Unsupported 24 × 2 + Retryable 24 × 2 + Denied 24 × 2 + Revoked 24 × 7 = 576
seven wrong-flow sequences: 2 + 3 + 4 + 5 + 6 + 7 + 8 = 35
39 extra canonical completions × 8 = 312
five one-action eligible malformed fillers = 5
256 + 864 + 576 + 35 + 312 + 5 = 2,048
2,048 + 1,046,528 = 1,048,576
```

The scheduled minimum completion counters are exactly 61 full and 35 restricted: initial `16/16`, active-pair `1/0`, terminal-constructor `24/0`, and extra-completion `20/19`. Freeze `MIN_FULL_COMPLETIONS = 61` and `MIN_RESTRICTED_COMPLETIONS = 35`.

- [ ] **Step 7: Obtain two read-only Task 1 reviews**

Reviewer A independently recomputes all enumerations/arithmetic without reading the derivation first. Reviewer B checks issue/spec/ADR consistency, GitHub preconditions, and retained-artifact safety. Both must report no unresolved finding before Task 2. Task 1 creates no repository commit.

---

### Task 2: Replace the Taxonomy and Make Report Reasons Optional, RED-GREEN

**Files:**
- Modify: `crates/ogir-model/src/lib.rs:529-571`
- Modify: `crates/ogir-verifier/src/verification.rs:61-139, 205-245, 1000-1049`
- Modify: `crates/ogir-verifier/src/lib.rs:12-17`
- Modify: `crates/ogir-verifier/tests/freshness.rs:240-518`
- Test: `crates/ogir-verifier/src/verification/tests.rs:405-454, 1637-1682`

**Interfaces:**
- Consumes: `Decision`, report-only `VerificationOutcome`, `FreshnessError`, and Task 1 taxonomy.
- Produces: exact fifteen-variant `ReasonCode`; `VerificationOutcome::reason(self) -> Option<ReasonCode>`; exported `UnsupportedRequirement`, `RetryReason`, and `DenialReason` exact variants.

- [ ] **Step 1: Capture each failing report-taxonomy test in isolation**

Add the first exact test only, run its selector, record the absence-sentinel failure, remove that exact hunk, and restore baseline GREEN. Then add the second test only, run its selector, record the missing variants/mappings, remove it, and restore baseline GREEN. Patch both tests back immediately before Step 3. The exact tests are:

```rust
#[test]
fn report_reason_is_absent_only_for_allows() {
    assert_eq!(VerificationOutcome::allowed_full().reason(), None);
    assert_eq!(VerificationOutcome::allowed_restricted().reason(), None);
    assert_eq!(VerificationOutcome::malformed().reason(), Some(ReasonCode::Malformed));
}

#[test]
fn every_failure_reason_has_one_report_mapping() {
    let mappings = [
        (Decision::Deny, ReasonCode::Malformed),
        (Decision::Deny, ReasonCode::ChallengeAuthenticationFailed),
        (Decision::Deny, ReasonCode::NotYetValid),
        (Decision::Deny, ReasonCode::Expired),
        (Decision::Deny, ReasonCode::ReplayDetected),
        (Decision::Deny, ReasonCode::ContextBindingMismatch),
        (Decision::Deny, ReasonCode::EvidenceInvalid),
        (Decision::Deny, ReasonCode::PolicyDenied),
        (Decision::Deny, ReasonCode::Revoked),
        (Decision::Deny, ReasonCode::ProtectedSessionLost),
        (Decision::Unsupported, ReasonCode::UnsupportedVersionOrProfile),
        (Decision::Unsupported, ReasonCode::UnsupportedPlatform),
        (Decision::Unsupported, ReasonCode::UnsupportedCriticalRequirement),
        (Decision::Retry, ReasonCode::AttestationUnavailable),
        (Decision::Retry, ReasonCode::TransientFailure),
    ];
    assert_eq!(mappings.len(), 15);
}
```

In a third isolated patch, update freshness expectations to `Some(...)`, run only the named freshness selector, record the `Option` mismatch, and revert that hunk. Patch those assertions back with both unit tests immediately before Step 3.

- [ ] **Step 2: Capture independent RED**

```text
cargo test -p ogir-verifier --lib verification::tests::report_reason_is_absent_only_for_allows -- --exact
cargo test -p ogir-verifier --lib verification::tests::every_failure_reason_has_one_report_mapping -- --exact
cargo test -p ogir-verifier --test freshness first_fresh_request_reaches_fail_closed_evidence_result -- --exact
```

Expected: each selector is the only proposed failure in an otherwise compiling target. The first fails on `reason()`/`ReasonCode::None`, the second on missing variants/private mappings, and freshness only on the `Option` mismatch. A combined crate compile error is not independent RED evidence.

- [ ] **Step 3: Replace `ReasonCode` exactly**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReasonCode {
    Malformed,
    ChallengeAuthenticationFailed,
    NotYetValid,
    Expired,
    ReplayDetected,
    ContextBindingMismatch,
    EvidenceInvalid,
    PolicyDenied,
    Revoked,
    ProtectedSessionLost,
    UnsupportedVersionOrProfile,
    UnsupportedPlatform,
    UnsupportedCriticalRequirement,
    AttestationUnavailable,
    TransientFailure,
}
```

Retain the exact `Debug, Clone, Copy, PartialEq, Eq, Hash` derives and add specific rustdoc to the enum and every variant. Do not add numeric discriminants, `#[non_exhaustive]`, strings, nested data, aliases, or `None`.

- [ ] **Step 4: Add exact typed causes and mappings**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnsupportedRequirement {
    VersionOrProfile,
    Platform,
    UnknownCriticalRequirement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetryReason {
    AttestationUnavailable,
    TransientFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenialReason {
    ChallengeAuthenticationFailed,
    NotYetValid,
    Expired,
    ReplayDetected,
    ContextBindingMismatch,
    EvidenceInvalid,
    PolicyDenied,
    ProtectedSessionLost,
}
```

Retain those exact derives and add specific rustdoc to all three enums and every variant. Implement exhaustive private `as_reason_code` matches. `Malformed` and `Revoked` appear in neither input enum.

- [ ] **Step 5: Change report storage and accessors**

```rust
pub struct VerificationOutcome {
    decision: Decision,
    reason: Option<ReasonCode>,
}

impl VerificationOutcome {
    #[must_use]
    pub const fn decision(self) -> Decision { self.decision }

    #[must_use]
    pub const fn reason(self) -> Option<ReasonCode> { self.reason }
}
```

Allow constructors store `None`; every failure constructor stores `Some(reason)`. Change the private constructors to `unsupported(requirement: UnsupportedRequirement)` and `retryable(reason: RetryReason)` and map through their exhaustive `as_reason_code` methods; keep `malformed()`, `revoked()`, and `denied(reason: DenialReason)` exact. Update `verify_research_structure` mappings only: old session mismatch becomes `ContextBindingMismatch`; unsupported/retry meanings remain report-only and no result is constructed.

Add `RetryReason` to the existing `pub use verification::{...}` list in `crates/ogir-verifier/src/lib.rs`; `mark_retryable` is a public method in Task 6, so downstream callers must be able to name its argument type and variants.

- [ ] **Step 6: Run GREEN and absence scans**

```bash
cargo test -p ogir-model --all-features
cargo test -p ogir-verifier --test freshness
cargo test -p ogir-verifier --lib verification::tests::report_reason_is_absent_only_for_allows -- --exact
if rg -n 'ReasonCode::None|UnsupportedVersion\b|SessionBindingMismatch|UnknownMandatoryGate' crates/ogir-model crates/ogir-verifier; then exit 1; else test "$?" -eq 1; fi
git diff --check
```

Expected: tests pass; `rg` exits 1; no runtime result API exists yet.

- [ ] **Step 7: Commit and review**

```bash
git add crates/ogir-model/src/lib.rs crates/ogir-verifier/src/lib.rs crates/ogir-verifier/src/verification.rs crates/ogir-verifier/src/verification/tests.rs crates/ogir-verifier/tests/freshness.rs
git diff --cached --check
git commit -m "feat: define appraisal reason taxonomy"
```

Expected: one unsigned commit. Fresh taxonomy and privacy reviewers verify all 15 variants and report-only semantics.

---

### Task 3: Add the Opaque Result API and Public Privacy Proof, RED-GREEN

**Files:**
- Modify: `crates/ogir-verifier/src/verification.rs:338-654`
- Modify: `crates/ogir-verifier/src/lib.rs:9-17`
- Modify: `crates/ogir-verifier/tests/verification_public.rs:1-73`

**Interfaces:**
- Consumes: exact `ReasonCode`, `Decision`, `ExpectedContext`, `EvidenceProfile`, `SessionPublicKeyId`.
- Produces: `AppraisalResult`, `AcceptedClaims`, `AppraisalResultView<'a>`, and exact read-only accessor names.

- [ ] **Step 1: Add public compile-pass and compile-fail contracts first**

Add a public compile-pass test importing:

```rust
use ogir_model::{Decision, ReasonCode};
use ogir_verifier::{AcceptedClaims, AppraisalResult, AppraisalResultView, ExpectedContext};

#[test]
fn appraisal_result_public_accessors_type_check() {
    fn inspect_claims(claims: &AcceptedClaims) {
        let _ = claims.accepted_profile();
        let _ = claims.session_public_key_id();
    }

    fn inspect(result: &AppraisalResult) {
        let _: &ExpectedContext = result.context();
        let _: Decision = result.decision();
        let _: Option<ReasonCode> = result.reason();
        match result.view() {
            AppraisalResultView::Allow(claims)
            | AppraisalResultView::AllowRestricted(claims) => inspect_claims(claims),
            AppraisalResultView::Failure { decision, reason } => {
                let _: Decision = decision;
                let _: ReasonCode = reason;
            }
        }
    }

    let _: fn(&AppraisalResult) = inspect;
    let _: fn(&AcceptedClaims) = inspect_claims;
}
```

Add these complete isolated doctest blocks. Keep each as a separate `compile_fail` fence so one forbidden surface cannot mask another:

```compile_fail
use ogir_verifier::{AppraisalResult, ExpectedContext};
fn forbidden(context: ExpectedContext) {
    let _ = AppraisalResult::new(context);
}
```

```compile_fail
use ogir_verifier::AppraisalResult;
fn forbidden() {
    let _ = AppraisalResult::builder();
}
```

```compile_fail
use ogir_verifier::AppraisalResult;
fn forbidden() {
    let _ = AppraisalResult::default();
}
```

```compile_fail
use ogir_verifier::AppraisalResult;
fn forbidden(result: AppraisalResult) {
    let _ = result.clone();
}
```

```compile_fail
use ogir_model::{EvidenceProfile, SessionPublicKeyId};
use ogir_verifier::AcceptedClaims;
fn forbidden(profile: EvidenceProfile, key_id: SessionPublicKeyId) {
    let _ = AcceptedClaims::new(profile, key_id);
}
```

```compile_fail
use ogir_verifier::{AppraisalResult, VerificationOutcome};
fn forbidden(outcome: VerificationOutcome) {
    let _ = AppraisalResult::from_outcome(outcome);
}
```

```compile_fail
use ogir_verifier::{AppraisalResult, AppraisalResultView};
fn forbidden(view: AppraisalResultView<'_>) {
    let _: AppraisalResult = view.into();
}
```

```compile_fail
use ogir_model::Decision;
use ogir_verifier::AppraisalResult;
fn forbidden() {
    let _ = AppraisalResult::from_decision(Decision::Allow);
}
```

```compile_fail
use ogir_verifier::AppraisalResult;
struct TestSigner;
fn forbidden(result: AppraisalResult, signer: TestSigner) {
    let _ = result.sign(signer);
}
```

```compile_fail
use ogir_verifier::AppraisalResult;
struct ValidatedPermit;
fn forbidden(result: AppraisalResult) -> ValidatedPermit {
    result.into_permit()
}
```

```compile_fail
use ogir_verifier::AppraisalResult;
struct Admission;
fn forbidden(result: AppraisalResult) -> Admission {
    result.admit()
}
```

```compile_fail
use ogir_verifier::{AppraisalResult, ExpectedContext};
fn forbidden(context: ExpectedContext) {
    let _ = AppraisalResult { context, payload: unreachable!() };
}
```

```compile_fail
use ogir_model::{EvidenceProfile, SessionPublicKeyId};
use ogir_verifier::AcceptedClaims;
fn forbidden(profile: EvidenceProfile, session_public_key_id: SessionPublicKeyId) {
    let _ = AcceptedClaims { accepted_profile: profile, session_public_key_id };
}
```

```compile_fail
use ogir_verifier::AppraisalResult;
fn forbidden(result: AppraisalResult) {
    let _ = result.context;
}
```

```compile_fail
use ogir_verifier::AppraisalResult;
fn forbidden(result: AppraisalResult) {
    let _ = result.payload;
}
```

```compile_fail
use ogir_verifier::AcceptedClaims;
fn forbidden(claims: AcceptedClaims) {
    let _ = claims.accepted_profile;
}
```

```compile_fail
use ogir_verifier::AcceptedClaims;
fn forbidden(claims: AcceptedClaims) {
    let _ = claims.session_public_key_id;
}
```

- [ ] **Step 2: Capture RED**

```text
cargo test -p ogir-verifier --test verification_public
cargo test -p ogir-verifier --doc
```

Expected: the public test fails for missing result types. Doctests must not be accepted as evidence until the types exist and each forbidden expression is the isolated failure.

- [ ] **Step 3: Add the exact private shape and borrowed view**

```rust
#[must_use]
pub struct AppraisalResult {
    context: ExpectedContext,
    payload: AppraisalPayload,
}

enum AppraisalPayload {
    Allow(AcceptedClaims),
    AllowRestricted(AcceptedClaims),
    Failure(FailurePayload),
}

#[must_use]
pub struct AcceptedClaims {
    accepted_profile: EvidenceProfile,
    session_public_key_id: SessionPublicKeyId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FailurePayload {
    decision: FailureDecision,
    reason: ReasonCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FailureDecision {
    Deny,
    Unsupported,
    Retry,
}

impl FailureDecision {
    const fn as_decision(self) -> Decision {
        match self {
            Self::Deny => Decision::Deny,
            Self::Unsupported => Decision::Unsupported,
            Self::Retry => Decision::Retry,
        }
    }
}

pub enum AppraisalResultView<'a> {
    Allow(&'a AcceptedClaims),
    AllowRestricted(&'a AcceptedClaims),
    Failure { decision: Decision, reason: ReasonCode },
}
```

Do not derive `Clone`, `Copy`, `Default`, equality, serialization, or hashing for result/claims/view. The freely constructible failure view remains report data only.

- [ ] **Step 4: Implement the exact accessor API**

```rust
impl AppraisalResult {
    #[must_use]
    pub const fn context(&self) -> &ExpectedContext { &self.context }

    #[must_use]
    pub const fn decision(&self) -> Decision {
        match &self.payload {
            AppraisalPayload::Allow(_) => Decision::Allow,
            AppraisalPayload::AllowRestricted(_) => Decision::AllowRestricted,
            AppraisalPayload::Failure(failure) => failure.decision.as_decision(),
        }
    }

    #[must_use]
    pub const fn reason(&self) -> Option<ReasonCode> {
        match &self.payload {
            AppraisalPayload::Allow(_) | AppraisalPayload::AllowRestricted(_) => None,
            AppraisalPayload::Failure(failure) => Some(failure.reason),
        }
    }

    #[must_use]
    pub const fn view(&self) -> AppraisalResultView<'_> {
        match &self.payload {
            AppraisalPayload::Allow(claims) => AppraisalResultView::Allow(claims),
            AppraisalPayload::AllowRestricted(claims) => {
                AppraisalResultView::AllowRestricted(claims)
            }
            AppraisalPayload::Failure(failure) => AppraisalResultView::Failure {
                decision: failure.decision.as_decision(),
                reason: failure.reason,
            },
        }
    }
}

impl AcceptedClaims {
    #[must_use]
    pub const fn accepted_profile(&self) -> &EvidenceProfile { &self.accepted_profile }

    #[must_use]
    pub const fn session_public_key_id(&self) -> &SessionPublicKeyId {
        &self.session_public_key_id
    }
}
```

These names are frozen: `context`, `decision`, `reason`, `view`, `accepted_profile`, and `session_public_key_id`.

- [ ] **Step 5: Add fixed aggregate diagnostics and exports**

`Debug` outputs are exactly:

```text
AppraisalResult([REDACTED])
AcceptedClaims([REDACTED])
AppraisalResultView([REDACTED])
```

Re-export the three public result types from `lib.rs`; retain Task 2's `RetryReason` export. Do not re-export private payload/decision types.

- [ ] **Step 6: Run GREEN and forbidden-surface scans**

```bash
cargo test -p ogir-verifier --test verification_public
cargo test -p ogir-verifier --doc
cargo clippy -p ogir-verifier --all-targets --all-features -- -D warnings
cargo doc -p ogir-verifier --no-deps
if rg -n 'pub (context|payload|accepted_profile|session_public_key_id):|impl (Clone|Copy|Default) for (AppraisalResult|AcceptedClaims)|fn (sign|into_permit|admit)' crates/ogir-verifier/src; then exit 1; else test "$?" -eq 1; fi
git diff --check
```

Expected: tests/docs pass and `rg` exits 1.

- [ ] **Step 7: Commit and obtain API/security reviews**

```bash
git add crates/ogir-verifier/src/verification.rs crates/ogir-verifier/src/lib.rs crates/ogir-verifier/tests/verification_public.rs
git diff --cached --check
git commit -m "feat: add opaque appraisal result API"
```

Reviewers independently check public construction, contradictory shapes, getters, result naming, and absence of signing/validity authority.

---

### Task 4: Replace Split Flow State and Carry Cumulative Claims, RED-GREEN

**Files:**
- Modify: `crates/ogir-verifier/src/verification.rs:247-368, 654-861`
- Modify: `crates/ogir-verifier/src/verification/tests.rs:26-115, 202-215, 615-725, 1917-1990`

**Interfaces:**
- Consumes: existing exact-attempt binding and seven gate methods.
- Produces: one private `VerificationState` owning request/cumulative claims; claim-bearing `EvidenceAppraised`, `SessionBound`, `PolicySatisfied`.

- [ ] **Step 1: Add failing claim-transfer and structural tests**

Use non-vacuous fixtures:

```rust
fn accepted_profile() -> EvidenceProfile { identifier("accepted-profile-v1") }

fn session_key_id(seed: u8) -> SessionPublicKeyId {
    SessionPublicKeyId::from_bytes(std::array::from_fn(|index| seed ^ index as u8))
}

#[test]
fn claim_capabilities_move_payload_only_after_phase_and_binding_checks() {
    let mut flow = flow_fixture(7);
    advance_to_identity_checked(&mut flow);
    let other = flow_fixture(7);
    let before = flow_snapshot(&flow);
    assert_eq!(
        flow.record_evidence_appraised(EvidenceAppraised {
            binding: other.binding.clone(),
            accepted_profile: accepted_profile(),
        }),
        Err(TransitionError::CapabilityRejected {
            action: VerificationAction::RecordEvidenceAppraised,
        })
    );
    assert_eq!(flow_snapshot(&flow), before);
}
```

Make `FlowSnapshot` inspect private active request/context/profile/key/class presence by exact state match, not unrelated options.

- [ ] **Step 2: Capture RED**

```text
cargo test -p ogir-verifier --lib verification::tests::claim_capabilities_move_payload_only_after_phase_and_binding_checks -- --exact
cargo test -p ogir-verifier --lib verification::tests::authority_fields_remain_private_by_structure -- --exact
```

Expected: compile failure for missing payload fields and structural failure because `VerifierFlow` still has `request: Option<VerificationRequest>` plus flat `VerificationState`.

- [ ] **Step 3: Replace the private state exactly**

```rust
enum VerificationState {
    EvidenceReceived { request: VerificationRequest },
    ChallengeAuthenticated { request: VerificationRequest },
    FreshnessChecked { request: VerificationRequest },
    IdentityChecked { request: VerificationRequest },
    EvidenceAppraised { request: VerificationRequest, accepted_profile: EvidenceProfile },
    SessionBound { request: VerificationRequest, accepted_profile: EvidenceProfile, session_public_key_id: SessionPublicKeyId },
    RevocationChecked { request: VerificationRequest, accepted_profile: EvidenceProfile, session_public_key_id: SessionPublicKeyId },
    PolicySatisfied { request: VerificationRequest, accepted_profile: EvidenceProfile, session_public_key_id: SessionPublicKeyId, allowed: AllowedClass },
    Verified { outcome: VerificationOutcome },
    Malformed { outcome: VerificationOutcome },
    Unsupported { outcome: VerificationOutcome },
    Retryable { outcome: VerificationOutcome },
    Denied { outcome: VerificationOutcome },
    Revoked { outcome: VerificationOutcome },
}

pub struct VerifierFlow {
    binding: VerificationBinding,
    state: VerificationState,
}
```

No active variant may omit its exact request; no terminal variant may retain request/profile/key/class.

Because the new state owns non-`Copy` values, replace the existing by-value accessor matches with borrowed matches. `phase()` matches `&self.state` exhaustively across all fourteen variants; `outcome()` matches `&self.state`, returns `Some(*outcome)` for the six terminal variants, and `None` for all eight active variants. Matching `self.state` by value through `&self` is forbidden.

Add `request_fixture_with_context_tag(seed: u8, tag: u8)`. It starts from `request_fixture(seed)` and replaces all six identifier fields with valid tag-bearing values plus `PolicyVersion::new(u32::from(tag) + 1)`. Add matching `flow_fixture_with_context_tag` and `policy_ready_flow_with_context_tag` helpers. C07/C13 use tag `1` and must assert its expected policy version differs from `PolicyVersion::new(u32::MAX)` before mutation execution; different nonce/evidence with equal context is not a valid detector.

- [ ] **Step 4: Add claim fields to capabilities and move them explicitly**

```rust
pub struct EvidenceAppraised {
    binding: VerificationBinding,
    accepted_profile: EvidenceProfile,
}

pub struct SessionBound {
    binding: VerificationBinding,
    session_public_key_id: SessionPublicKeyId,
}

pub struct PolicySatisfied {
    binding: VerificationBinding,
    allowed: AllowedClass,
}
```

Each method first matches the one required active variant by shared reference, then checks binding. After those fallible checks, replace the whole state with the fail-closed terminal `Retryable { outcome: VerificationOutcome::retryable(RetryReason::TransientFailure) }`, destructure the returned old active variant, construct the next active variant infallibly, and assign it. No caller-controlled operation occurs between replacement and assignment; if a destructor unexpectedly unwinds, the flow is already terminal rather than request-less active. For example, evidence appraisal uses this exact order:

```rust
if !matches!(&self.state, VerificationState::IdentityChecked { .. }) {
    return Err(self.invalid_transition(VerificationAction::RecordEvidenceAppraised));
}
self.ensure_binding(
    VerificationAction::RecordEvidenceAppraised,
    &capability.binding,
)?;
let previous = std::mem::replace(
    &mut self.state,
    VerificationState::Retryable {
        outcome: VerificationOutcome::retryable(RetryReason::TransientFailure),
    },
);
let VerificationState::IdentityChecked { request } = previous else {
    unreachable!("phase was checked before active-state replacement")
};
self.state = VerificationState::EvidenceAppraised {
    request,
    accepted_profile: capability.accepted_profile,
};
Ok(())
```

On phase or binding rejection, the capability is consumed but the flow is byte-for-byte logically unchanged. Add a focused unwind-safety structural test that requires the replacement terminal to precede extraction and forbids an `Option<VerificationState>` take pattern.

- [ ] **Step 5: Update private test fixtures and seven substitutions**

Construct exact profile/key values in private fixtures. For evidence/session wrong-flow tests, use a different payload as well as a different binding and assert rejection; separately document that a dishonest payload in a correctly bound capability is TCB risk, not mechanically detectable provenance fraud.

- [ ] **Step 6: Run GREEN**

```bash
cargo test -p ogir-verifier --lib verification::tests::claim_capabilities_move_payload_only_after_phase_and_binding_checks -- --exact
cargo test -p ogir-verifier --lib verification::tests::every_capability_rejects_an_equal_request_from_another_flow -- --exact
cargo test -p ogir-verifier --lib verification::tests::mismatched_capabilities_preserve_phase_before_binding_error_precedence -- --exact
cargo test -p ogir-verifier --lib verification::tests::authority_fields_remain_private_by_structure -- --exact
cargo clippy -p ogir-verifier --all-targets --all-features -- -D warnings
git diff --check
```

Expected: all pass; structural test pins one state field and every cumulative variant.

- [ ] **Step 7: Commit and review**

```bash
git add crates/ogir-verifier/src/verification.rs crates/ogir-verifier/src/verification/tests.rs
git diff --cached --check
git commit -m "refactor: make verifier claims state-owned"
```

Fresh reviewers focus on move ordering, wrong-flow rejection, payload-provenance honesty, and absence of nonterminal request-less states.

---

### Task 5: Emit Allowed Appraisal Results by Consuming Completion, RED-GREEN

**Files:**
- Modify: `crates/ogir-verifier/src/verification.rs:338-368, 842-880`
- Modify: `crates/ogir-verifier/src/verification/tests.rs:1459-1581`
- Modify: `crates/ogir-verifier/tests/verification_public.rs:64-73`

**Interfaces:**
- Consumes: claim-complete `PolicySatisfied` state and opaque result API.
- Produces: `complete() -> Result<VerifiedAttestation, TransitionError>` carrying exact context/claims/class and `VerifiedAttestation::into_appraisal_result(self)` as the sole allow constructor.

- [ ] **Step 1: Capture baseline preservation, then each allow RED in isolation**

Run `completed_flow_rejects_second_complete_without_result` before adding either compile-breaking result test and record baseline GREEN. Add only the full test, run its exact selector, record missing capability fields/conversion, remove it, and restore baseline GREEN. Repeat with only the restricted test. Then add both tests plus the already-green repetition detector immediately before Step 3.

```rust
#[test]
fn completed_capability_converts_once_to_exact_full_result() {
    let expected_context = request_fixture_with_context_tag(7, 1).expected;
    let expected_profile = accepted_profile();
    let expected_key = session_key_id(7);
    let mut flow = policy_ready_flow_with_context_tag(7, 1, expected_profile.clone(), expected_key, AllowedClass::Full);
    let verified = flow.complete().expect("canonical test path must complete");
    let result = verified.into_appraisal_result();
    assert_eq!(result.context(), &expected_context);
    assert_eq!(result.decision(), Decision::Allow);
    assert_eq!(result.reason(), None);
    match result.view() {
        AppraisalResultView::Allow(claims) => {
            assert_eq!(claims.accepted_profile(), &expected_profile);
            assert_eq!(claims.session_public_key_id(), &expected_key);
        }
        _ => panic!("full completion returned the wrong view"),
    }
}
```

Add the restricted counterpart:

```rust
#[test]
fn restricted_success_uses_the_same_complete_gate() {
    let expected_context = request_fixture_with_context_tag(9, 1).expected;
    let expected_profile = accepted_profile();
    let expected_key = session_key_id(9);
    let mut flow = policy_ready_flow_with_context_tag(
        9,
        1,
        expected_profile.clone(),
        expected_key,
        AllowedClass::Restricted,
    );
    let verified = flow.complete().expect("restricted test path must complete");
    let result = verified.into_appraisal_result();
    assert_eq!(result.context(), &expected_context);
    assert_eq!(result.decision(), Decision::AllowRestricted);
    assert_eq!(result.reason(), None);
    match result.view() {
        AppraisalResultView::AllowRestricted(claims) => {
            assert_eq!(claims.accepted_profile(), &expected_profile);
            assert_eq!(claims.session_public_key_id(), &expected_key);
        }
        _ => panic!("restricted completion returned the wrong view"),
    }
}
```

Add the completion repetition detector:

```rust
#[test]
fn completed_flow_rejects_second_complete_without_result() {
    let mut flow = policy_ready_flow(
        8,
        accepted_profile(),
        session_key_id(8),
        AllowedClass::Full,
    );
    let first = flow.complete().expect("canonical test path must complete");
    drop(first);
    assert!(matches!(
        flow.complete(),
        Err(TransitionError::InvalidTransition {
            phase: VerificationPhase::Verified,
            action: VerificationAction::Complete,
        })
    ));
}
```

- [ ] **Step 2: Capture RED**

Run the preservation selector before adding either isolated RED:

```bash
set -euo pipefail
cargo test -p ogir-verifier --lib verification::tests::completed_flow_rejects_second_complete_without_result -- --exact
```

Then run each isolated RED as a separate fresh invocation:

```text
cargo test -p ogir-verifier --lib verification::tests::completed_capability_converts_once_to_exact_full_result -- --exact
cargo test -p ogir-verifier --lib verification::tests::restricted_success_uses_the_same_complete_gate -- --exact
```

Expected: each of the first two selectors was captured alone in an otherwise compiling target and failed because `VerifiedAttestation` lacks context/claims and conversion. The repetition selector ran before either proposed test and is baseline GREEN because current `complete()` already enters `Verified`; it must remain green throughout Task 5 and is not new RED evidence.

- [ ] **Step 3: Extend the private completed capability**

```rust
pub struct VerifiedAttestation {
    binding: VerificationBinding,
    context: ExpectedContext,
    accepted_profile: EvidenceProfile,
    session_public_key_id: SessionPublicKeyId,
    allowed: AllowedClass,
}
```

All fields remain private and the type remains non-cloneable/non-copyable.

- [ ] **Step 4: Implement terminal-first completion**

Borrow-match `PolicySatisfied` to derive the safe terminal report without moving the non-`Copy` state, return the exact current-phase transition error for every other variant, replace `self.state` with `VerificationState::Verified { outcome }`, then destructure the returned old state and move exact values into `VerifiedAttestation`. No fallible operation occurs after replacement.

```rust
pub fn complete(&mut self) -> Result<VerifiedAttestation, TransitionError> {
    let outcome = match &self.state {
        VerificationState::PolicySatisfied {
            allowed: AllowedClass::Full,
            ..
        } => VerificationOutcome::allowed_full(),
        VerificationState::PolicySatisfied {
            allowed: AllowedClass::Restricted,
            ..
        } => VerificationOutcome::allowed_restricted(),
        _ => return Err(self.invalid_transition(VerificationAction::Complete)),
    };
    let previous = std::mem::replace(
        &mut self.state,
        VerificationState::Verified { outcome },
    );
    let VerificationState::PolicySatisfied {
        request,
        accepted_profile,
        session_public_key_id,
        allowed,
    } = previous else {
        unreachable!("phase was checked before terminal replacement")
    };
    Ok(VerifiedAttestation {
        binding: self.binding.clone(),
        context: request.expected,
        accepted_profile,
        session_public_key_id,
        allowed,
    })
}
```

The `unreachable!` is justified only by the immediately preceding exhaustive check and must be mutation-tested; production still contains no caller-triggerable panic path.

- [ ] **Step 5: Implement the only allow conversion**

```rust
impl VerifiedAttestation {
    #[must_use]
    pub fn into_appraisal_result(self) -> AppraisalResult {
        let Self {
            binding,
            context,
            accepted_profile,
            session_public_key_id,
            allowed,
        } = self;
        drop(binding);
        let claims = AcceptedClaims {
            accepted_profile,
            session_public_key_id,
        };
        let payload = match allowed {
            AllowedClass::Full => AppraisalPayload::Allow(claims),
            AllowedClass::Restricted => AppraisalPayload::AllowRestricted(claims),
        };
        AppraisalResult { context, payload }
    }
}
```

The complete destructuring deliberately consumes and drops the private binding without exposing it. Add a compile-fail moved-value doctest proving repeat conversion fails.

- [ ] **Step 6: Run GREEN and one-use proofs**

```bash
cargo test -p ogir-verifier --lib verification::tests::completed_capability_converts_once_to_exact_full_result -- --exact
cargo test -p ogir-verifier --lib verification::tests::restricted_success_uses_the_same_complete_gate -- --exact
cargo test -p ogir-verifier --lib verification::tests::gate_permutations_require_the_one_canonical_order -- --exact
cargo test -p ogir-verifier --doc
git diff --check
```

Expected: exact claims/context/class pass; 5,040 permutations and moved-value compile failure remain intact.

- [ ] **Step 7: Commit and review**

```bash
git add crates/ogir-verifier/src/verification.rs crates/ogir-verifier/src/verification/tests.rs crates/ogir-verifier/tests/verification_public.rs
git diff --cached --check
git commit -m "feat: emit capability-gated appraisal allows"
```

Reviewers verify the sole allow path, terminal-first ordering, exact policy retention, and no signer/validity shortcut.

---

### Task 6: Enforce Phase-Eligible Failure Emission, RED-GREEN

**Files:**
- Modify: `crates/ogir-verifier/src/verification.rs:882-988`
- Modify: `crates/ogir-verifier/src/verification/tests.rs:1583-1735`

**Interfaces:**
- Consumes: Task 1's exact eligibility table and private terminal result constructor.
- Produces: a compatible typed test-action/result harness, five failure methods returning one `AppraisalResult`, exact phase eligibility, and failure claim discard.

- [ ] **Step 0: Migrate only the test harness and prove baseline GREEN**

Before adding a failure-result test, change `TestAction::MarkRetryable` to `MarkRetryable(RetryReason)`, `ActionResult::NoCapability` to `NoResult`, and add `FailureResult { decision: Decision, reason: ReasonCode }`. Update `public`, `binding_mode`, `required_phase`, fixture builders, and `apply_action` exhaustively. Until production signatures change, existing failure arms consume `()` and return `NoResult`; fixture builders drop successful `()` instead of comparing it. Add all Task 1 typed failure action variants, but leave `ALL_13_MATRIX_ACTIONS` unchanged. Make the old `model_transition` compile by explicitly predicting state-preserving rejection for every new failure variant. Run the complete verifier library target and require baseline GREEN; this intentionally stale model becomes Task 7's runtime RED.

- [ ] **Step 1: Capture every new RED selector independently, then add the complete set**

For each of Step 2's eight selectors, add only that test and its local table/helper, run it, verify its named failure, remove its exact hunk, and restore baseline GREEN before the next selector. After all eight records exist, add the complete set below together. This prevents one accessor call on current `()` from masking every other test.

```rust
#[test]
fn failure_after_session_binding_discards_all_accepted_claims() {
    let mut flow = flow_at_session_bound_with_context_tag(41, 1);
    let expected_context = request_fixture_with_context_tag(41, 1).expected;
    let result = flow.mark_revoked().expect("revocation is eligible at SessionBound");
    assert_eq!(result.context(), &expected_context);
    assert_eq!(result.decision(), Decision::Deny);
    assert_eq!(result.reason(), Some(ReasonCode::Revoked));
    assert!(matches!(result.view(), AppraisalResultView::Failure { .. }));
    assert_eq!(flow.phase(), VerificationPhase::Revoked);
}

#[test]
fn policy_denial_before_revocation_check_is_rejected_unchanged() {
    let mut flow = flow_for_model_state(ModelState::IdentityChecked, 42);
    let before = flow_snapshot(&flow);
    assert_eq!(
        flow.deny(DenialReason::PolicyDenied),
        Err(TransitionError::InvalidTransition {
            phase: VerificationPhase::IdentityChecked,
            action: VerificationAction::Deny,
        })
    );
    assert_eq!(flow_snapshot(&flow), before);
}
```

Add `all_41_phase_eligible_failure_edges_emit_exact_results` as a table-driven test enumerating all 41 eligible failure pairs from Task 1. For every row, build the phase from a request whose exact expected context is retained separately, invoke the typed action, and assert `result.context() == &expected_context` in addition to exact decision/reason/view/terminal checks. Add `all_phase_ineligible_failures_reject_without_mutation` by taking the Cartesian product of the eight active phases and fifteen failure actions, excluding those exact 41 rows, and requiring the exact `InvalidTransition` plus byte-for-byte-equal `FlowSnapshot` for all 79 remaining pairs. Add `every_result_accessor_and_view_mapping_is_exact`, covering full allow, restricted allow, and all fifteen failure results; assert each exact `decision()`, `reason()`, and exhaustive `view()` payload.

Add this explicit all-claim-bearing-phase proof:

```rust
#[test]
fn failure_terminals_store_no_claims_from_every_claim_bearing_phase() {
    for (state, action) in [
        (
            ModelState::EvidenceAppraised,
            TestAction::Deny(DenialReason::ProtectedSessionLost),
        ),
        (ModelState::SessionBound, TestAction::MarkRevoked),
        (
            ModelState::RevocationChecked,
            TestAction::Deny(DenialReason::PolicyDenied),
        ),
        (
            ModelState::PolicySatisfied(AllowedClass::Full),
            TestAction::Deny(DenialReason::ProtectedSessionLost),
        ),
    ] {
        let mut flow = flow_for_model_state(state, 43);
        let other_binding = flow_fixture(44).binding;
        let actual = apply_action(&mut flow, &other_binding, action);
        assert!(matches!(actual, Ok(ActionResult::FailureResult { .. })));
        let snapshot = flow_snapshot(&flow);
        assert!(!snapshot.has_request);
        assert!(!snapshot.has_profile);
        assert!(!snapshot.has_session_key);
        assert!(!snapshot.has_allowed_class);
        assert!(matches!(&flow.state, VerificationState::Denied { .. } | VerificationState::Revoked { .. }));
    }
}
```

The structural test separately rejects `accepted_profile`, `session_public_key_id`, `allowed`, or `AcceptedClaims` fields in every terminal state and in `FailurePayload`; borrowed-view matching alone is not accepted as no-claim-storage proof.

- [ ] **Step 2: Capture RED**

```text
cargo test -p ogir-verifier --lib verification::tests::failure_after_session_binding_discards_all_accepted_claims -- --exact
cargo test -p ogir-verifier --lib verification::tests::policy_denial_before_revocation_check_is_rejected_unchanged -- --exact
cargo test -p ogir-verifier --lib verification::tests::all_41_phase_eligible_failure_edges_emit_exact_results -- --exact
cargo test -p ogir-verifier --lib verification::tests::all_phase_ineligible_failures_reject_without_mutation -- --exact
cargo test -p ogir-verifier --lib verification::tests::failure_terminals_store_no_claims_from_every_claim_bearing_phase -- --exact
cargo test -p ogir-verifier --lib verification::tests::every_failure_terminal_rejects_repeat_emission -- --exact
cargo test -p ogir-verifier --lib verification::tests::every_failure_reason_has_its_only_valid_reporting_mapping -- --exact
cargo test -p ogir-verifier --lib verification::tests::every_result_accessor_and_view_mapping_is_exact -- --exact
```

Expected: every selector was the sole proposed failure in an otherwise GREEN target and fails for its named contract: result selectors fail because methods return `()`; the ineligible matrix exposes the permissive rule; claim-discard/result-repetition tests cannot observe a returned result; and the mapping test lacks typed mappings. A zero-test run, combined uncompilable set, or unrelated failure is not RED evidence.

- [ ] **Step 3: Implement exact eligibility without a permissive wildcard**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Private normalized failure action used only for eligibility and terminal mapping.
enum FailureKind {
    /// Malformed evidence.
    Malformed,
    /// A typed unsupported requirement.
    Unsupported(UnsupportedRequirement),
    /// A typed retryable failure.
    Retry(RetryReason),
    /// A typed denial.
    Deny(DenialReason),
    /// Revocation discovered at the approved phase.
    Revoked,
}

fn failure_is_eligible(phase: VerificationPhase, failure: FailureKind) -> bool {
    match failure {
        FailureKind::Malformed => phase == VerificationPhase::EvidenceReceived,
        FailureKind::Unsupported(UnsupportedRequirement::VersionOrProfile) => phase == VerificationPhase::ChallengeAuthenticated,
        FailureKind::Unsupported(UnsupportedRequirement::Platform) => phase == VerificationPhase::IdentityChecked,
        FailureKind::Unsupported(UnsupportedRequirement::UnknownCriticalRequirement) => is_active_phase(phase),
        FailureKind::Retry(_) => is_active_phase(phase),
        FailureKind::Deny(DenialReason::ChallengeAuthenticationFailed) => phase == VerificationPhase::EvidenceReceived,
        FailureKind::Deny(DenialReason::NotYetValid | DenialReason::Expired | DenialReason::ReplayDetected) => phase == VerificationPhase::ChallengeAuthenticated,
        FailureKind::Deny(DenialReason::ContextBindingMismatch) => matches!(phase, VerificationPhase::ChallengeAuthenticated | VerificationPhase::FreshnessChecked | VerificationPhase::EvidenceAppraised),
        FailureKind::Deny(DenialReason::EvidenceInvalid) => phase == VerificationPhase::IdentityChecked,
        FailureKind::Deny(DenialReason::PolicyDenied) => phase == VerificationPhase::RevocationChecked,
        FailureKind::Deny(DenialReason::ProtectedSessionLost) => matches!(phase, VerificationPhase::EvidenceAppraised | VerificationPhase::SessionBound | VerificationPhase::RevocationChecked | VerificationPhase::PolicySatisfied),
        FailureKind::Revoked => phase == VerificationPhase::SessionBound,
    }
}
```

`is_active_phase` explicitly names all eight active phases and no terminal.

- [ ] **Step 4: Change all five signatures**

```rust
pub fn mark_malformed(&mut self) -> Result<AppraisalResult, TransitionError>;
pub fn mark_unsupported(&mut self, requirement: UnsupportedRequirement) -> Result<AppraisalResult, TransitionError>;
pub fn mark_retryable(&mut self, reason: RetryReason) -> Result<AppraisalResult, TransitionError>;
pub fn deny(&mut self, reason: DenialReason) -> Result<AppraisalResult, TransitionError>;
pub fn mark_revoked(&mut self) -> Result<AppraisalResult, TransitionError>;
```

Each delegates to `emit_failure` with exactly one `FailureKind`. No method accepts raw `Decision` or `ReasonCode`:

```rust
pub fn mark_malformed(&mut self) -> Result<AppraisalResult, TransitionError> {
    self.emit_failure(FailureKind::Malformed)
}

pub fn mark_unsupported(
    &mut self,
    requirement: UnsupportedRequirement,
) -> Result<AppraisalResult, TransitionError> {
    self.emit_failure(FailureKind::Unsupported(requirement))
}

pub fn mark_retryable(
    &mut self,
    reason: RetryReason,
) -> Result<AppraisalResult, TransitionError> {
    self.emit_failure(FailureKind::Retry(reason))
}

pub fn deny(&mut self, reason: DenialReason) -> Result<AppraisalResult, TransitionError> {
    self.emit_failure(FailureKind::Deny(reason))
}

pub fn mark_revoked(&mut self) -> Result<AppraisalResult, TransitionError> {
    self.emit_failure(FailureKind::Revoked)
}
```

- [ ] **Step 5: Implement terminal-first failure replacement**

Implement an exhaustive action mapping and one consuming helper. Eligibility and all mappings are checked before mutation; only copyable safe terminal/report values are built before replacement. The match over the returned state moves the request from every one of the eight active variants and drops every profile, key handle, and allowed class through `..`:

```rust
impl FailureKind {
    const fn action(self) -> VerificationAction {
        match self {
            Self::Malformed => VerificationAction::MarkMalformed,
            Self::Unsupported(_) => VerificationAction::MarkUnsupported,
            Self::Retry(_) => VerificationAction::MarkRetryable,
            Self::Deny(_) => VerificationAction::Deny,
            Self::Revoked => VerificationAction::MarkRevoked,
        }
    }
}

impl VerifierFlow {
    fn emit_failure(
        &mut self,
        failure: FailureKind,
    ) -> Result<AppraisalResult, TransitionError> {
        let action = failure.action();
        if !failure_is_eligible(self.phase(), failure) {
            return Err(self.invalid_transition(action));
        }

        let (decision, reason, terminal) = match failure {
            FailureKind::Malformed => (
                FailureDecision::Deny,
                ReasonCode::Malformed,
                VerificationState::Malformed {
                    outcome: VerificationOutcome::malformed(),
                },
            ),
            FailureKind::Unsupported(requirement) => (
                FailureDecision::Unsupported,
                requirement.as_reason_code(),
                VerificationState::Unsupported {
                    outcome: VerificationOutcome::unsupported(requirement),
                },
            ),
            FailureKind::Retry(retry_reason) => (
                FailureDecision::Retry,
                retry_reason.as_reason_code(),
                VerificationState::Retryable {
                    outcome: VerificationOutcome::retryable(retry_reason),
                },
            ),
            FailureKind::Deny(denial_reason) => (
                FailureDecision::Deny,
                denial_reason.as_reason_code(),
                VerificationState::Denied {
                    outcome: VerificationOutcome::denied(denial_reason),
                },
            ),
            FailureKind::Revoked => (
                FailureDecision::Deny,
                ReasonCode::Revoked,
                VerificationState::Revoked {
                    outcome: VerificationOutcome::revoked(),
                },
            ),
        };

        let previous = std::mem::replace(&mut self.state, terminal);
        let request = match previous {
            VerificationState::EvidenceReceived { request }
            | VerificationState::ChallengeAuthenticated { request }
            | VerificationState::FreshnessChecked { request }
            | VerificationState::IdentityChecked { request }
            | VerificationState::EvidenceAppraised { request, .. }
            | VerificationState::SessionBound { request, .. }
            | VerificationState::RevocationChecked { request, .. }
            | VerificationState::PolicySatisfied { request, .. } => request,
            VerificationState::Verified { .. }
            | VerificationState::Malformed { .. }
            | VerificationState::Unsupported { .. }
            | VerificationState::Retryable { .. }
            | VerificationState::Denied { .. }
            | VerificationState::Revoked { .. } => {
                unreachable!("eligibility excluded terminal state before replacement")
            }
        };

        Ok(AppraisalResult {
            context: request.expected,
            payload: AppraisalPayload::Failure(FailurePayload { decision, reason }),
        })
    }
}
```

No fallible operation occurs after replacement. No failure payload or terminal contains `AcceptedClaims` or claim fields. The `unreachable!` is justified by the exhaustive active-phase eligibility guard and must be mutation-tested.

- [ ] **Step 6: Run GREEN for eligibility, discard, repetition, and mappings**

```bash
cargo test -p ogir-verifier --lib verification::tests::all_41_phase_eligible_failure_edges_emit_exact_results -- --exact
cargo test -p ogir-verifier --lib verification::tests::all_phase_ineligible_failures_reject_without_mutation -- --exact
cargo test -p ogir-verifier --lib verification::tests::failure_after_session_binding_discards_all_accepted_claims -- --exact
cargo test -p ogir-verifier --lib verification::tests::failure_terminals_store_no_claims_from_every_claim_bearing_phase -- --exact
cargo test -p ogir-verifier --lib verification::tests::every_failure_terminal_rejects_repeat_emission -- --exact
cargo test -p ogir-verifier --lib verification::tests::every_failure_reason_has_its_only_valid_reporting_mapping -- --exact
cargo test -p ogir-verifier --lib verification::tests::every_result_accessor_and_view_mapping_is_exact -- --exact
git diff --check
```

Expected: 41 eligible edges each retain exact context, 79 active-phase ineligible failure pairs reject unchanged, every claim-bearing phase reaches a terminal with no claim storage, mappings are exact, and no second result is emitted.

- [ ] **Step 7: Commit and review**

```bash
git add crates/ogir-verifier/src/verification.rs crates/ogir-verifier/src/verification/tests.rs
git diff --cached --check
git commit -m "feat: emit phase-eligible appraisal failures"
```

Reviewers independently compare every match arm with the approved table and inspect claim discard/terminal ordering.

---

### Task 7: Rebuild the Finite Oracle, History, Permutation, and Substitution Proof

**Files:**
- Modify: `crates/ogir-verifier/src/verification/tests.rs:117-1411, 1684-2034`

**Interfaces:**
- Consumes: complete result-emitting transition surface.
- Produces: exact `336/50/286` oracle, 5,040 permutations, seven omissions, phase-before-binding matrix, seven substitutions, and exactly 1,048,576 checked history actions.

- [ ] **Step 1: Replace only the matrix action constant with all 24 variants**

Name it `ALL_24_MATRIX_ACTIONS` and copy Task 1's enumeration exactly. Task 6 already made `TestAction`, `ActionResult`, and `apply_action` compile against the result-returning API; change no model expectation yet. `apply_action` consumes and inspects real returned results and never substitutes a report.

- [ ] **Step 2: Capture stale-oracle RED before changing model expectations**

```bash
cargo test -p ogir-verifier --lib verification::tests::all_336_phase_action_pairs_match_the_independent_model -- --exact
```

Expected: the test compiles and runs, then fails on an eligible failure pair because Task 6's intentionally stale model still predicts rejection for every newly added failure action. A compile failure is the wrong RED cause.

- [ ] **Step 3: Implement the independent literal model**

Use a test-only model whose terminal states retain exact report reason, while active states retain modeled claim-presence booleans. `model_transition` explicitly encodes the nine success edges and 41 failure edges; no production eligibility helper is called.

- [ ] **Step 4: Freeze matrix arithmetic in executable assertions**

```rust
assert_eq!(ALL_14_MODEL_STATES.len(), 14);
assert_eq!(ALL_24_MATRIX_ACTIONS.len(), 24);
assert_eq!(succeeded, 50);
assert_eq!(rejected, 286);
assert_eq!(succeeded + rejected, 336);
```

Every rejected pair compares complete private snapshot: phase, outcome, active request, profile, key, and class presence.

Add the exact retained-state detector used by the terminal replacement mutations:

```rust
#[test]
fn request_and_claims_exist_only_in_active_states() {
    for state in ALL_14_MODEL_STATES {
        let flow = flow_for_model_state(state, 83);
        let snapshot = flow_snapshot(&flow);
        assert_eq!(snapshot.has_request, model_is_nonterminal(state));
        assert_eq!(snapshot.has_profile, model_has_profile(state));
        assert_eq!(snapshot.has_session_key, model_has_session_key(state));
        assert_eq!(snapshot.has_allowed_class, model_has_allowed_class(state));
    }
}
```

The independent `model_has_*` functions use exhaustive literal matches and never inspect production state helpers.

- [ ] **Step 5: Implement the exact 2,048-action schedule from Task 1**

Build in this order: 32 canonical completions; every active phase/action sequence; every representative terminal/action sequence; seven wrong-flow sequences terminated by phase-eligible `TransientFailure`; 39 alternating extra completions beginning Full; five malformed fillers. Assert each subtotal `256, 864, 576, 35, 312, 5` and cumulative total `2_048`.

- [ ] **Step 6: Update coverage counters concretely**

```rust
struct Coverage {
    full_completions: usize,
    restricted_completions: usize,
    success_edges: [usize; 9],
    eligible_failures: [[usize; 15]; 8],
    ineligible_failures: [[usize; 15]; 8],
    matching_gates: [usize; 7],
    mismatched_gates: [usize; 7],
    terminal_rejections: [[usize; 24]; 6],
}
```

Require `full_completions >= 61`, `restricted_completions >= 35`, every success edge nonzero, exactly 41 nonzero eligible cells, exactly 79 nonzero ineligible cells, every gate/substitution nonzero, and every one of 144 terminal cells nonzero. Counters increment only after actual result equals the independent expectation.

- [ ] **Step 7: Update arbitrary generation and execute exact history**

Change modulo `13` to `24`, map every index explicitly, keep seed `0x4f47_4952_4d31_3031`, and retain terminal-reset behavior. Assert:

```rust
assert_eq!(executed, 1_048_576);
assert_eq!(SCHEDULED_ACTIONS, 2_048);
assert_eq!(ARBITRARY_ACTIONS, 1_046_528);
```

- [ ] **Step 8: Preserve omission, permutation, and phase-before-binding detectors**

```bash
cargo test -p ogir-verifier --lib verification::tests::omitting_each_gate_prevents_completion -- --exact
cargo test -p ogir-verifier --lib verification::tests::gate_permutations_require_the_one_canonical_order -- --exact
cargo test -p ogir-verifier --lib verification::tests::every_capability_rejects_an_equal_request_from_another_flow -- --exact
cargo test -p ogir-verifier --lib verification::tests::mismatched_capabilities_preserve_phase_before_binding_error_precedence -- --exact
```

Expected: omissions `7`; permutations `5,040 = 1 canonical + 5,039 rejected`; substitutions `7`; all 14 phases check phase before binding.

- [ ] **Step 9: Run full proof GREEN, commit, and review**

```bash
cargo test -p ogir-verifier --lib verification::tests::all_336_phase_action_pairs_match_the_independent_model -- --exact
cargo test -p ogir-verifier --lib verification::tests::one_million_actions_match_the_independent_verifier_model -- --exact
cargo test -p ogir-verifier --all-features
git diff --check
git add crates/ogir-verifier/src/verification/tests.rs
git commit -m "test: exhaust appraisal result transitions"
```

Independent model and test-quality reviewers recompute the 24 actions, 41/9 split, schedule subtotals, and coverage dimensions.

---

### Task 8: Prove Authority, Privacy, and Whole-State Structure

**Files:**
- Modify: `crates/ogir-verifier/src/verification.rs:415-654`
- Modify: `crates/ogir-verifier/src/verification/tests.rs:683-912, 1870-1990`
- Modify: `crates/ogir-verifier/tests/verification_public.rs:64-73`
- Modify only if its wording contradicts the implemented API: `crates/ogir-verifier/src/freshness.rs:202-247`

**Interfaces:**
- Consumes: final public/private result and flow shapes.
- Produces: isolated compile-fail, structural, one-use, redaction, and non-overclaim evidence.

- [ ] **Step 1: Add isolated compile-fail cases before any proof helper**

Retain and rerun every exact isolated block from Task 3. Add the following exact remaining blocks; no block may depend on a local from another fence:

```compile_fail
use ogir_verifier::AppraisalResult;
fn forbidden(result: AppraisalResult) {
    let _first = result;
    let _second = result;
}
```

```compile_fail
use ogir_model::{EvidenceProfile, SessionPublicKeyId};
use ogir_verifier::{AcceptedClaims, AppraisalResultView};
fn forbidden(profile: EvidenceProfile, session_public_key_id: SessionPublicKeyId) {
    let claims = AcceptedClaims { accepted_profile: profile, session_public_key_id };
    let _ = AppraisalResultView::Allow(&claims);
}
```

```compile_fail
use ogir_verifier::{AppraisalResult, VerificationOutcome};
fn forbidden(report: VerificationOutcome) {
    let _: AppraisalResult = report.into();
}
```

```compile_fail
use ogir_verifier::{AppraisalResult, VerificationRequest};
fn forbidden(request: VerificationRequest) {
    let _: AppraisalResult = request.into();
}
```

```compile_fail
use ogir_verifier::{AppraisalResult, ExpectedContext};
fn forbidden(mut result: AppraisalResult, replacement: ExpectedContext) {
    result.set_context(replacement);
}
```

```compile_fail
use ogir_verifier::VerifiedAttestation;
fn forbidden(verified: VerifiedAttestation) {
    let _first = verified.into_appraisal_result();
    let _second = verified.into_appraisal_result();
}
```

```compile_fail
use ogir_verifier::VerifiedAttestation;
fn forbidden(verified: VerifiedAttestation) {
    let _ = verified.clone();
}
```

```compile_fail
use ogir_verifier::AppraisalResult;
struct ProtectedResult;
fn forbidden(result: AppraisalResult) -> ProtectedResult {
    result.into_protected_result()
}
```

```compile_fail
use ogir_verifier::AppraisalResult;
struct ProofOfPossession;
fn forbidden(result: AppraisalResult) -> ProofOfPossession {
    result.into_proof_of_possession()
}
```

```compile_fail
use ogir_verifier::{AppraisalResult, ExpectedContext};
fn forbidden(result: &AppraisalResult, replacement: ExpectedContext) {
    *result.context() = replacement;
}
```

Each block has all symbols and locals defined in that fence and one intended cause: absent trait/constructor/conversion/method, private fields, moved value, or immutable borrowed access. Keep the `VerificationOutcome` input named `report` as the report-only-to-authoritative-result prohibition; do not invent a nonexistent report type.

- [ ] **Step 2: Add exact structural declarations**

The CRLF-normalized structural test pins private result/claims/capability fields and requires `VerifierFlow` to contain only `binding` and `state`. It rejects `request: Option`, `accepted_profile: Option`, `session_public_key_id: Option`, public constructors, `fn builder`, `impl From<VerificationOutcome>`, `impl From<AppraisalResultView<'_>> for AppraisalResult`, and any `sign`, `permit`, `proof`, or `admit` method. It also pins that both `complete` and `emit_failure` call `std::mem::replace(&mut self.state, terminal)` before destructuring or extracting the returned active state, and that the four claim-moving active gate methods retain the fail-closed replacement-before-extraction order from Task 4.

- [ ] **Step 3: Extend non-vacuous diagnostic tests**

Use distinct sentinels for all seven context identifiers, policy version, two times, evidence payload/profile, session-key bytes, and allocation. Format result, claims, view, flow in every phase, all capabilities, verified capability, outcome, transition errors, binding, request, expected context, and evidence bundle. Exact aggregate outputs are fixed markers; safe fieldless decision/reason/phase/action names may appear.

- [ ] **Step 4: Add explicit provenance-limit tests/documentation assertions**

Private tests may construct two correctly bound `EvidenceAppraised` capabilities with different profiles and prove the state machine accepts whichever trusted producer supplied. The test name is `correct_binding_does_not_claim_cryptographic_payload_provenance`; it must not call this a vulnerability or claim payload truth. A separate failure test states public failure emission is valid shape but not trusted signing provenance.

- [ ] **Step 5: Run all authority/privacy detectors**

```bash
cargo test -p ogir-verifier --doc
cargo test -p ogir-verifier --test verification_public
cargo test -p ogir-verifier --lib verification::tests::authority_fields_remain_private_by_structure -- --exact
cargo test -p ogir-verifier --lib verification::tests::every_flow_result_claim_view_and_error_diagnostic_is_redacted -- --exact
cargo test -p ogir-verifier --lib verification::tests::correct_binding_does_not_claim_cryptographic_payload_provenance -- --exact
cargo clippy -p ogir-verifier --all-targets --all-features -- -D warnings
cargo doc -p ogir-verifier --no-deps
git diff --check
```

Expected: all pass; compile-fail cases fail for intended causes; sentinels never appear in test failure text.

- [ ] **Step 6: Commit and obtain separate authority/privacy reviews**

```bash
git add crates/ogir-verifier/src/verification.rs crates/ogir-verifier/src/verification/tests.rs crates/ogir-verifier/tests/verification_public.rs crates/ogir-verifier/src/freshness.rs
git diff --cached --check
git commit -m "test: prove appraisal result authority boundaries"
```

Stage `freshness.rs` only if it changed. Authority and privacy reviewers are different fresh contexts.

---

### Task 9: Synchronize Scenarios, Architecture, Trust, Privacy, Protocol, and ADR Evidence

**Files:**
- Modify: all five `lab/scenarios/verifier-*.scenario.json` files listed in File Map
- Modify: `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/ROADMAP.md`, `docs/TEST_STRATEGY.md`, `docs/PRIVACY_MODEL.md`, `docs/TRUST_MODEL.md`, `docs/PROTOCOL.md`
- Modify: `docs/adr/0007-verifier-flow-capabilities.md`, `docs/adr/0009-capability-gated-appraisal-results.md`, `docs/adr/index.md`
- Modify only for a confirmed defect: `docs/LESSONS_LEARNED.md`

**Interfaces:**
- Consumes: reviewed executable behavior and exact counts.
- Produces: one consistent documentary boundary assigning semantics to M1-011, transcript inputs to M1-012, and commitment/protection/wire/validation to M2.

- [ ] **Step 1: Update existing scenarios without adding a duplicate family**

Make exact semantic changes:

```text
gate-skip: report-only Allow and freely built failure view cannot construct AppraisalResult; only completed capability conversion allows.
capability-substitution: wrong-flow profile/key capabilities reject; correctly bound dishonest payload remains trusted-producer residual risk.
terminal-immutability: all six terminals reject all 24 semantic actions; one terminal emits at most one result.
unknown-gate: expected reason becomes unsupported-critical-requirement and is eligible at each active phase.
diagnostics-privacy: include AppraisalResult, AppraisalResultView, AcceptedClaims, profile, key handle, and failure claim discard.
```

- [ ] **Step 2: Update architecture and roadmap with exact seam ownership**

State: M1-011's unsigned `AppraisalResult` retains context and allow claims; M1-012 defines semantic transcript inputs; later M2 chooses commitment representation, algorithm identifiers, signature/integrity, wire, parser, validation, issued-at/expiry, and trusted issuer. Replace the superseded M1-010 statement that `VerifiedAttestation` carries only binding/class.

- [ ] **Step 3: Update threat/trust/privacy documents without overclaiming**

Record exact-flow association versus payload truth, public failure shape versus trusted failure provenance, no intrinsic validity, failure claim discard, correlation-sensitive retained context/key handle, and future finite retention/confidentiality/deletion obligations. State no automatic cheating conclusion.

- [ ] **Step 4: Update protocol and test strategy**

`PROTOCOL.md` must say `AppraisalResult` is not a wire object or generic signer input. `TEST_STRATEGY.md` records `14 × 24 = 336`, `41 + 9 = 50`, `286`, `5,040`, seven omissions/substitutions, schedule `256 + 864 + 576 + 35 + 312 + 5 = 2,048`, arbitrary `1,046,528`, total `1,048,576`, and mutation count `154`.

- [ ] **Step 5: Refine ADR-0007 and add implementation evidence to ADR-0009**

ADR-0007 keeps the factual M1-010 evidence `182/48/134` unchanged and explicitly labels it historical M1-010 evidence. Add a separate refinement note that M1-011 replaces the earlier all-failure rule with phase eligibility; do not rewrite history or characterize the historical count as erroneous. ADR-0009 remains Accepted and gains the current M1-011 implementation evidence `336/50/286`, explicitly labeled the refinement/current evidence. The index remains exactly one Accepted ADR-0009 row.

- [ ] **Step 6: Append a lesson only for a confirmed durable mistake**

If a concrete implementation/review defect occurred, append symptom, root cause, correction, permanent regression, and prevention rule. If none occurred, leave `docs/LESSONS_LEARNED.md` byte-identical.

- [ ] **Step 7: Validate and commit docs/scenarios**

Stage ADR files before the index-based checker:

```bash
git add lab/scenarios/verifier-gate-skip.scenario.json lab/scenarios/verifier-capability-substitution.scenario.json lab/scenarios/verifier-terminal-immutability.scenario.json lab/scenarios/verifier-unknown-gate.scenario.json lab/scenarios/verifier-diagnostics-privacy.scenario.json docs/ARCHITECTURE.md docs/THREAT_MODEL.md docs/ROADMAP.md docs/TEST_STRATEGY.md docs/PRIVACY_MODEL.md docs/TRUST_MODEL.md docs/PROTOCOL.md docs/adr/0007-verifier-flow-capabilities.md docs/adr/0009-capability-gated-appraisal-results.md docs/adr/index.md
python3 ./scripts/check-attack-scenario-traceability.py --self-test
python3 ./scripts/check-attack-scenario-traceability.py
./scripts/check-adr-index.sh .
./scripts/check-repository-metadata.sh .
git diff --cached --check
git commit -m "docs: define appraisal result boundary"
```

Include `LESSONS_LEARNED.md` only if Step 6 changed it. Fresh architecture and documentation reviewers check every deferred-owner statement.

---

### Task 10: Kill the Frozen 154 One-Cause Mutations and Obtain Separate Reviews

**Files:**
- Modify only for surviving-regression fixes: runtime/test/docs files from Tasks 2-9
- Create ignored evidence: `.superpowers/sdd/2026-08-28-m1-011-appraisal-result/mutation-report.md`

**Interfaces:**
- Consumes: clean reviewed Task 9 head.
- Produces: exactly 154/154 intended-cause kills plus separate fresh TCB and privacy verdicts.

- [ ] **Step 1: Freeze exact mutation head and baseline gates**

```bash
git status --short --branch
m1_011_mutation_head="$(git rev-parse HEAD)"
git worktree list --porcelain
git fsck --no-dangling
./scripts/check.sh
cargo test --workspace --all-features --release
```

Expected: clean branch, retained worktrees/backups unchanged, full/release green.

Using `apply_patch`, write the observed exact 40-hex head plus one newline to ignored `.superpowers/sdd/2026-08-28-m1-011-appraisal-result/mutation-head`. Every probe reads and validates that file; `m1_011_mutation_head` does not persist from the prior fence.

- [ ] **Step 2: Use one disposable worktree and one mutation per probe**

For each row below: set `m1_011_mutation_head="$(tr -d '\n' < .superpowers/sdd/2026-08-28-m1-011-appraisal-result/mutation-head)"`, validate it is 40 hex and equals the reviewed Task 9 head, add a detached worktree at that OID, apply only the named change with `apply_patch`, run the exact command, require nonzero exit from the named detector, record head/path/command/exit/cause, remove only that worktree, and verify primary HEAD/status. Syntax errors, zero-test runs, timeouts, and unrelated compiler failures do not count.

Command keys:

```text
ELIG = cargo test -p ogir-verifier --lib verification::tests::all_41_phase_eligible_failure_edges_emit_exact_results -- --exact
MAP = cargo test -p ogir-verifier --lib verification::tests::every_failure_reason_has_its_only_valid_reporting_mapping -- --exact
VIEW = cargo test -p ogir-verifier --lib verification::tests::every_result_accessor_and_view_mapping_is_exact -- --exact
CLAIM = cargo test -p ogir-verifier --lib verification::tests::completed_capability_converts_once_to_exact_full_result -- --exact
RESTRICT = cargo test -p ogir-verifier --lib verification::tests::restricted_success_uses_the_same_complete_gate -- --exact
DISCARD = cargo test -p ogir-verifier --lib verification::tests::failure_after_session_binding_discards_all_accepted_claims -- --exact
NO_CLAIMS = cargo test -p ogir-verifier --lib verification::tests::failure_terminals_store_no_claims_from_every_claim_bearing_phase -- --exact
STATE = cargo test -p ogir-verifier --lib verification::tests::authority_fields_remain_private_by_structure -- --exact
TERMINAL_STATE = cargo test -p ogir-verifier --lib verification::tests::request_and_claims_exist_only_in_active_states -- --exact
DOC = cargo test -p ogir-verifier --doc
ONE = cargo test -p ogir-verifier --lib verification::tests::every_failure_terminal_rejects_repeat_emission -- --exact
COMPLETE_ONCE = cargo test -p ogir-verifier --lib verification::tests::completed_flow_rejects_second_complete_without_result -- --exact
PRIV = cargo test -p ogir-verifier --lib verification::tests::every_flow_result_claim_view_and_error_diagnostic_is_redacted -- --exact
MATRIX = cargo test -p ogir-verifier --lib verification::tests::all_336_phase_action_pairs_match_the_independent_model -- --exact
INELIG = cargo test -p ogir-verifier --lib verification::tests::all_phase_ineligible_failures_reject_without_mutation -- --exact && cargo test -p ogir-verifier --lib verification::tests::all_336_phase_action_pairs_match_the_independent_model -- --exact
BIND = cargo test -p ogir-verifier --lib verification::tests::every_capability_rejects_an_equal_request_from_another_flow -- --exact
```

Exact eligibility-removal probes, each changing only its named approved pair from eligible to ineligible and detected by `ELIG` plus `MATRIX`:

```text
E01 EvidenceReceived malformed
E02 EvidenceReceived challenge-authentication-failed
E03 EvidenceReceived attestation-unavailable
E04 EvidenceReceived transient-failure
E05 EvidenceReceived unknown-critical-requirement
E06 ChallengeAuthenticated version-or-profile
E07 ChallengeAuthenticated not-yet-valid
E08 ChallengeAuthenticated expired
E09 ChallengeAuthenticated replay-detected
E10 ChallengeAuthenticated context-binding-mismatch
E11 ChallengeAuthenticated attestation-unavailable
E12 ChallengeAuthenticated transient-failure
E13 ChallengeAuthenticated unknown-critical-requirement
E14 FreshnessChecked context-binding-mismatch
E15 FreshnessChecked attestation-unavailable
E16 FreshnessChecked transient-failure
E17 FreshnessChecked unknown-critical-requirement
E18 IdentityChecked platform
E19 IdentityChecked evidence-invalid
E20 IdentityChecked attestation-unavailable
E21 IdentityChecked transient-failure
E22 IdentityChecked unknown-critical-requirement
E23 EvidenceAppraised context-binding-mismatch
E24 EvidenceAppraised protected-session-lost
E25 EvidenceAppraised attestation-unavailable
E26 EvidenceAppraised transient-failure
E27 EvidenceAppraised unknown-critical-requirement
E28 SessionBound revoked
E29 SessionBound protected-session-lost
E30 SessionBound attestation-unavailable
E31 SessionBound transient-failure
E32 SessionBound unknown-critical-requirement
E33 RevocationChecked policy-denied
E34 RevocationChecked protected-session-lost
E35 RevocationChecked attestation-unavailable
E36 RevocationChecked transient-failure
E37 RevocationChecked unknown-critical-requirement
E38 PolicySatisfied protected-session-lost
E39 PolicySatisfied attestation-unavailable
E40 PolicySatisfied transient-failure
E41 PolicySatisfied unknown-critical-requirement
```

Exact widening probes, each changing only its named rejected pair from ineligible to eligible by adding that one pair to the named arm; each is detected by `INELIG`:

```text
W01 Malformed at ChallengeAuthenticated
W02 ChallengeAuthenticationFailed at ChallengeAuthenticated
W03 NotYetValid at EvidenceReceived
W04 Expired at EvidenceReceived
W05 ReplayDetected at EvidenceReceived
W06 ContextBindingMismatch at IdentityChecked
W07 EvidenceInvalid at FreshnessChecked
W08 PolicyDenied at IdentityChecked
W09 Revoked at EvidenceAppraised
W10 ProtectedSessionLost at IdentityChecked
W11 VersionOrProfile at FreshnessChecked
W12 Platform at FreshnessChecked
W13 UnknownCriticalRequirement at Verified
W14 AttestationUnavailable at Verified
W15 TransientFailure at Verified
```

Exact mapping probes. M01-M15 change one typed failure-reason mapping and are detected by `MAP`; M16-M27 change one result decision/reason/view arm and are detected by `VIEW`:

```text
M01 Malformed
M02 ChallengeAuthenticationFailed
M03 NotYetValid
M04 Expired
M05 ReplayDetected
M06 ContextBindingMismatch
M07 EvidenceInvalid
M08 PolicyDenied
M09 Revoked
M10 ProtectedSessionLost
M11 UnsupportedVersionOrProfile
M12 UnsupportedPlatform
M13 UnsupportedCriticalRequirement
M14 AttestationUnavailable
M15 TransientFailure
M16 FailureDecision Deny arm
M17 FailureDecision Unsupported arm
M18 FailureDecision Retry arm
M19 AppraisalResult decision Allow arm
M20 AppraisalResult decision AllowRestricted arm
M21 AppraisalResult decision Failure arm
M22 AppraisalResult reason Allow arm
M23 AppraisalResult reason AllowRestricted arm
M24 AppraisalResult reason Failure arm
M25 AppraisalResult view Allow arm
M26 AppraisalResult view AllowRestricted arm
M27 AppraisalResult view Failure arm
```

Replacement values are deterministic. For M01-M15, replace the mapped `ReasonCode` with the next code in the listed M01-M15 order, wrapping M15 to `Malformed`. M16 changes Deny to Unsupported; M17 Unsupported to Retry; M18 Retry to Deny. M19 changes Allow decision to AllowRestricted; M20 AllowRestricted to Deny; M21 the failure decision arm to Allow. M22 and M23 return `Some(ReasonCode::Malformed)` instead of `None`; M24 returns `None` instead of the stored failure reason. M25 returns `AllowRestricted(claims)` from the Allow arm; M26 returns `Allow(claims)` from the restricted arm; M27 keeps the failure reason but returns `decision: Decision::Allow` in the failure view. No worker may choose a different wrong value under these probe IDs.

Exact claim probes:

```text
C01 store request evidence profile instead of EvidenceAppraised payload - CLAIM
C02 replace the accumulated profile during EvidenceAppraised-to-SessionBound transfer - CLAIM
C03 store an all-zero key handle instead of SessionBound payload - CLAIM
C04 replace the accumulated key during SessionBound-to-RevocationChecked transfer - CLAIM
C05 flip Full to Restricted in VerifiedAttestation only - CLAIM
C06 flip Restricted to Full in VerifiedAttestation only - RESTRICT
C07 before success result assembly, set moved `context.policy_version` to `PolicyVersion::new(u32::MAX)` while the tag-1 fixture expects another value - CLAIM
C08 add `accepted_profile: Option<EvidenceProfile>` to the `Denied` terminal and retain `Some` from claim-bearing denial paths - NO_CLAIMS
C09 add `session_public_key_id: Option<SessionPublicKeyId>` to the `Denied` terminal and retain `Some` from key-bearing denial paths - NO_CLAIMS
C10 replace the policy inside restricted context - RESTRICT
C11 bypass EvidenceAppraised binding while preserving payload - BIND
C12 bypass SessionBound binding while preserving payload - BIND
C13 before failure result assembly, set moved `request.expected.policy_version` to `PolicyVersion::new(u32::MAX)` while the tag-1 fixture expects another value - ELIG
```

Exact whole-state/terminal probes, detected by `STATE`, `MATRIX`, and the named terminal request/discard tests:

```text
R01 complete extracts before Verified replacement - STATE
R02 shared `emit_failure` extracts request before terminal replacement - STATE
R03 evidence-appraisal gate extracts before fail-closed replacement - STATE
R04 session-binding gate extracts before fail-closed replacement - STATE
R05 revocation-check gate extracts before fail-closed replacement - STATE
R06 policy-satisfaction gate extracts before fail-closed replacement - STATE
```

Exact authority probes, each adding only the named forbidden surface and detected by the exact command shown. Non-`Copy` remains a compile-fail/type-structure proof rather than a mutation: making this owned result `Copy` cannot be a compiling one-cause patch because its context/profile payloads are non-`Copy`.

```text
A01 public AppraisalResult constructor - DOC
A02 public `AppraisalResult::builder()` returning an `AppraisalResultBuilder` - DOC
A03 AppraisalResult Default - DOC
A04 AppraisalResult Clone - DOC
A05 public AcceptedClaims constructor - DOC
A06 public AcceptedClaims fields - DOC
A07 public AppraisalResult context field - DOC
A08 public AppraisalResult payload field - DOC
A09 public VerifierFlow state field - STATE
A10 public context refill setter - DOC
A11 From<VerificationOutcome> for AppraisalResult - DOC
A12 From<Decision> for AppraisalResult - DOC
A13 generic sign method - DOC
A14 result-to-permit shortcut - DOC
A15 result-to-admission shortcut - DOC
A16 `impl From<AppraisalResultView<'_>> for AppraisalResult` - DOC
A17 public VerifiedAttestation constructor - STATE
A18 public EvidenceAppraised payload field - STATE
A19 public SessionBound payload field - STATE
```

Exact one-use probes:

```text
O01 permit second complete emission - COMPLETE_ONCE
O02 permit second failure emission - ONE
O03 make into_appraisal_result borrow instead of consume - DOC moved-value case
O04 add Clone to VerifiedAttestation - DOC
```

Exact diagnostic probes, each exposing one real sentinel and detected by `PRIV`:

```text
D01 AppraisalResult
D02 AcceptedClaims
D03 AppraisalResultView
D04 VerifierFlow
D05 EvidenceAppraised
D06 SessionBound
D07 PolicySatisfied
D08 VerifiedAttestation
D09 ExpectedContext
D10 VerificationRequest
D11 VerificationBinding allocation/registration
D12 TransitionError Debug
D13 TransitionError Display
D14 VerificationOutcome
D15 EvidenceBundle
```

Exact preserved gate/binding probes:

```text
G01 challenge phase guard - MATRIX
G02 freshness phase guard - MATRIX
G03 identity phase guard - MATRIX
G04 evidence phase guard - MATRIX
G05 session phase guard - MATRIX
G06 revocation phase guard - MATRIX
G07 policy phase guard - MATRIX
G08 challenge binding check - BIND
G09 freshness binding check - BIND
G10 identity binding check - BIND
G11 evidence binding check - BIND
G12 session binding check - BIND
G13 revocation binding check - BIND
G14 policy binding check - BIND
```

Count assertion:

```text
41 eligibility removals + 15 widening probes + 27 mappings + 13 claims + 6 replacements + 19 authority + 4 one-use + 15 diagnostics + 14 gate/binding = 154
41 + 15 + 27 + 13 + 6 + 19 + 4 + 15 + 14 = 154
```

- [ ] **Step 3: Handle any survivor test-first and restart the entire campaign**

Remove its mutation worktree, add one focused correct-code regression in the primary worktree, capture the mutation-specific RED in a fresh disposable worktree, commit the regression/minimal correction unsigned, set a new exact mutation head, and rerun all 154 probes. Never copy mutated source into the primary worktree.

- [ ] **Step 4: Run exact-head gates and verify cleanup**

```bash
git status --short --branch
git worktree list --porcelain
git fsck --no-dangling
./scripts/check.sh
cargo test --workspace --all-features --release
git diff --check
```

Expected: 154/154 intended-cause report, no mutation worktree, all retained worktrees/backups intact, clean full/release head.

- [ ] **Step 5: Obtain separate fresh TCB and privacy reviews**

TCB review covers allow provenance, terminal-first state, 41 eligibility edges, mappings, claims, exact-flow binding, one-use conversion, and no signer/permit shortcut. Privacy review covers retained context/claims, failure discard, all diagnostics/getters, no validity claim, and future retention obligations. Require no unresolved Critical/Important/Minor finding and readiness Yes from both; fixes restart affected tests/mutations and both reviews.

---

### Task 11: Record Time-Bounded Evidence and Guard Local/Live `needs-review` Sync

**Files:**
- Modify: `planning/issues/011-result-reason-code-taxonomy.md:1-292`
- External only after fresh explicit authorization: existing live M1-011 issue body/status label

**Interfaces:**
- Consumes: clean 154/154 exact head and two clean reviews.
- Produces: one unsigned evidence commit and, only if authorized, exact local/live `needs-review` synchronization.

- [ ] **Step 1: Capture exact evidence without claiming future validity**

Record base/head/tree/commit count, actual runtime/integration/doctest/scenario/ADR counts, `336/50/286`, `5,040/5,039`, seven omissions/substitutions, `1,048,576/2,048/1,046,528`, scheduled subtotals, compile-pass/fail count, `154/154`, full/release commands, review verdicts, limitations, and unsigned/publication-pending state.

- [ ] **Step 2: Patch only issue status/evidence and verify**

Change local metadata `status: ready` to `status: needs-review`; append `## Implementation evidence` with the captured facts. Explicitly state no cryptographic payload provenance, trusted failure provenance, intrinsic validity, signer, protected result, permit, PoP, admission, parser, crypto, I/O, or production adapter.

```bash
set -euo pipefail
./scripts/check.sh
cargo test --workspace --all-features --release
git diff --check
git add planning/issues/011-result-reason-code-taxonomy.md
git diff --cached --check
git commit -m "docs: record M1-011 implementation evidence"
```

- [ ] **Step 3: Stop for separate issue-edit authorization**

If not authorized, leave live issue at ready and record the exact divergence. If authorized, require live body equals the prior ready body, state OPEN, milestone exact, no duplicate title, and exact ready labels before:

```bash
set -euo pipefail
m1_011_title='M1-011: Define the Appraisal Result and reason-code taxonomy'
m1_011_issue_number="$(gh api --paginate --slurp 'repos/archledger/open-game-integrity-runtime/issues?state=all&per_page=100' --jq '[.[][] | select(.pull_request == null) | select(.title == "M1-011: Define the Appraisal Result and reason-code taxonomy")] | if length == 1 then .[0].number else error("expected exactly one M1-011 issue") end')"
case "${m1_011_issue_number}" in ''|*[!0-9]*) exit 1 ;; esac
expected_ready_body="$(tr -d '\n' < .superpowers/sdd/2026-08-28-m1-011-appraisal-result/live-ready-body.b64)"
live_ready_body="$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json body --jq '.body | @base64')"
test "${live_ready_body}" = "${expected_ready_body}"
test "$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json title --jq '.title')" = "${m1_011_title}"
test "$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json state --jq '.state')" = 'OPEN'
test "$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json milestone --jq '.milestone.title')" = 'M1 Domain Model'
test "$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json labels --jq '[.labels[].name] | sort | join(",")')" = 'area: model,area: privacy,area: verifier,risk: privacy,risk: trusted-computing-base,status: ready,type: architecture'
gh issue edit "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --body-file planning/issues/011-result-reason-code-taxonomy.md --remove-label 'status: ready' --add-label 'status: needs-review'
live_review_body="$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json body --jq '.body | @base64')"
local_review_body="$(base64 -w0 planning/issues/011-result-reason-code-taxonomy.md)"
test "${live_review_body}" = "${local_review_body}"
test "$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json state --jq '.state')" = 'OPEN'
test "$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json milestone --jq '.milestone.title')" = 'M1 Domain Model'
test "$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json labels --jq '[.labels[].name] | sort | join(",")')" = 'area: model,area: privacy,area: verifier,risk: privacy,risk: trusted-computing-base,status: needs-review,type: architecture'
```

Read back exact body/metadata and require only the reviewed body/status change. Rollback is another explicitly authorized guarded edit restoring the prior body/label.

- [ ] **Step 4: Obtain final evidence-commit reviews**

One reviewer checks time-bounded factual accuracy; another checks no production/provenance/validity overclaim. No unresolved finding proceeds to DCO.

---

### Task 12: Freeze Human DCO Certification, Back Up, Rewrite Metadata, and Reverify

**Files:**
- Read only: exact unsigned history
- Create outside repository: immutable backup ref, bundle, and hash manifest

**Interfaces:**
- Consumes: exact clean unsigned range and explicit human DCO certification.
- Produces: retained verified pre-rewrite backup and metadata-only signed equivalent range.

- [ ] **Step 1: Print the exact unsigned range and stop for certification**

```bash
set -euo pipefail
m1_011_base='955c88e372cffa13f15953085f15887165be62b5'
m1_011_unsigned_tip="$(git rev-parse HEAD)"
git rev-list --reverse "${m1_011_base}..${m1_011_unsigned_tip}"
git log --reverse --format='commit=%H%ncommitter=%cn <%ce>%nsubject=%s%ntrailers=%(trailers:key=Signed-off-by,valueonly)%n---' "${m1_011_base}..${m1_011_unsigned_tip}"
./scripts/check-dco.sh "${m1_011_base}" "${m1_011_unsigned_tip}"
```

Expected: DCO fails solely for missing trailers. Ask the user to certify the printed concrete range under DCO 1.1 and authorize exactly `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>`. Never infer this from earlier approvals.

After certification, use `apply_patch` to create ignored `.superpowers/sdd/2026-08-28-m1-011-appraisal-result/dco-certified-tip` containing exactly the certified 40-hex OID plus one newline. Every later DCO block reads and validates this file; ambient shell state is forbidden.

- [ ] **Step 2: Create immutable backup evidence after certification**

```bash
set -euo pipefail
m1_011_unsigned_tip="$(tr -d '\n' < .superpowers/sdd/2026-08-28-m1-011-appraisal-result/dco-certified-tip)"
test "${#m1_011_unsigned_tip}" -eq 40
test "$(git rev-parse HEAD)" = "${m1_011_unsigned_tip}"
m1_011_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
m1_011_backup_ref="refs/backup/pre-m1-011-dco/${m1_011_stamp}/tip"
m1_011_bundle="/home/wisbfime/Open Game Intergrity Runtime  - Github Project/backups/ogir-m1-011-pre-dco-${m1_011_stamp}.bundle"
git update-ref "${m1_011_backup_ref}" "${m1_011_unsigned_tip}"
git bundle create "${m1_011_bundle}" "${m1_011_backup_ref}" refs/heads/main
git bundle verify "${m1_011_bundle}"
sha256sum "${m1_011_bundle}"
```

Create the sibling manifest with `apply_patch`, verify `sha256sum -c`, and retain exact restore command.

- [ ] **Step 3: Perform metadata-only rewrite and prove equivalence**

```bash
set -euo pipefail
m1_011_base='955c88e372cffa13f15953085f15887165be62b5'
m1_011_unsigned_tip="$(tr -d '\n' < .superpowers/sdd/2026-08-28-m1-011-appraisal-result/dco-certified-tip)"
test "$(git rev-list --count "${m1_011_base}..${m1_011_unsigned_tip}")" -gt 0
backup_ref_list="$(git for-each-ref --format='%(refname)' --points-at "${m1_011_unsigned_tip}" 'refs/backup/pre-m1-011-dco/*/tip')"
test -n "${backup_ref_list}"
mapfile -t m1_011_backup_refs <<<"${backup_ref_list}"
test "${#m1_011_backup_refs[@]}" -eq 1
m1_011_backup_ref="${m1_011_backup_refs[0]}"
test "$(git config --get user.name)" = 'Wisbendji Fimerlus'
test "$(git config --get user.email)" = 'archledger236@gmail.com'
old_trailers="$(git log --format='%(trailers:only)' "${m1_011_base}..${m1_011_unsigned_tip}")"
test -z "${old_trailers}"
GIT_COMMITTER_NAME='Wisbendji Fimerlus' GIT_COMMITTER_EMAIL='archledger236@gmail.com' GIT_SEQUENCE_EDITOR=: git -c commit.gpgSign=false rebase --force-rebase --signoff --no-gpg-sign "${m1_011_base}"
m1_011_signed_tip="$(git rev-parse HEAD)"
./scripts/check-dco.sh "${m1_011_base}" "${m1_011_signed_tip}"
old_commit_list="$(git rev-list --reverse "${m1_011_base}..${m1_011_backup_ref}")"
new_commit_list="$(git rev-list --reverse "${m1_011_base}..${m1_011_signed_tip}")"
test -n "${old_commit_list}"
test -n "${new_commit_list}"
mapfile -t m1_011_old_commits <<<"${old_commit_list}"
mapfile -t m1_011_new_commits <<<"${new_commit_list}"
test "${#m1_011_old_commits[@]}" -eq "${#m1_011_new_commits[@]}"
for index in "${!m1_011_old_commits[@]}"; do
  old_commit="${m1_011_old_commits[${index}]}"
  new_commit="${m1_011_new_commits[${index}]}"
  old_parent="$(git rev-parse "${old_commit}^")"
  new_parent="$(git rev-parse "${new_commit}^")"
  if test "${index}" -eq 0; then
    test "${old_parent}" = "${m1_011_base}"
    test "${new_parent}" = "${m1_011_base}"
  else
    previous_index="$((index - 1))"
    test "${old_parent}" = "${m1_011_old_commits[${previous_index}]}"
    test "${new_parent}" = "${m1_011_new_commits[${previous_index}]}"
  fi
  old_tree="$(git show -s --format='%T' "${old_commit}")"
  new_tree="$(git show -s --format='%T' "${new_commit}")"
  old_author="$(git show -s --format='%an%x09%ae%x09%aI' "${old_commit}")"
  new_author="$(git show -s --format='%an%x09%ae%x09%aI' "${new_commit}")"
  old_subject="$(git show -s --format='%s' "${old_commit}")"
  new_subject="$(git show -s --format='%s' "${new_commit}")"
  test -n "${old_tree}" && test -n "${new_tree}"
  test "${old_tree}" = "${new_tree}"
  test "${old_author}" = "${new_author}"
  test "${old_subject}" = "${new_subject}"
  test "$(git show -s --format='%cn <%ce>' "${new_commit}")" = 'Wisbendji Fimerlus <archledger236@gmail.com>'
  test "$(git show -s --format='%(trailers:only)' "${new_commit}")" = 'Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>'
  old_message="$(git show -s --format='%B' "${old_commit}")"
  new_message="$(git show -s --format='%B' "${new_commit}")"
  expected_message="$(printf '%s\n\nSigned-off-by: Wisbendji Fimerlus <archledger236@gmail.com>\n' "${old_message}")"
  test "${new_message}" = "${expected_message}"
  old_raw_commit="$(git cat-file commit "${old_commit}")"
  new_raw_commit="$(git cat-file commit "${new_commit}")"
  if rg -q '^gpgsig ' <<<"${old_raw_commit}"; then exit 1; fi
  if rg -q '^gpgsig ' <<<"${new_raw_commit}"; then exit 1; fi
done
git range-diff "${m1_011_base}..${m1_011_backup_ref}" "${m1_011_base}..${m1_011_signed_tip}"
git diff "${m1_011_backup_ref}^{tree}" "${m1_011_signed_tip}^{tree}" --exit-code
git fsck --no-dangling
```

Expected: same count/order/tree/author/date/subject, exactly one canonical trailer per commit, no forbidden trailer, empty final tree diff.

After the verified rewrite, use `apply_patch` to write the exact 40-hex `m1_011_signed_tip` plus one newline to ignored `.superpowers/sdd/2026-08-28-m1-011-appraisal-result/dco-signed-tip`. Push and PR tasks must read and validate this file immediately before each external write.

- [ ] **Step 4: Re-run gates and fresh signed-SHA reviews**

```bash
set -euo pipefail
m1_011_base='955c88e372cffa13f15953085f15887165be62b5'
m1_011_signed_tip="$(git rev-parse HEAD)"
./scripts/check.sh
cargo test --workspace --all-features --release
git diff "${m1_011_base}..${m1_011_signed_tip}" --check
git status --short --branch
```

Require equivalence Yes and no findings from a fresh exact-SHA reviewer before publication.

---

### Task 13: Guard an Ordinary Non-Force Push

**Files:**
- External only after fresh explicit authorization: remote branch `research/m1-011-appraisal-result`

**Interfaces:**
- Consumes: signed reviewed exact head, exact live needs-review issue, explicit push authorization.
- Produces: one remote feature branch at the exact local head; no PR.

- [ ] **Step 1: Stop for exact push authorization**

Authorization must name the branch and signed head. It does not authorize PR creation or merge.

- [ ] **Step 2: Revalidate remote and issue preconditions**

```bash
set -euo pipefail
m1_011_signed_tip="$(tr -d '\n' < .superpowers/sdd/2026-08-28-m1-011-appraisal-result/dco-signed-tip)"
test "${#m1_011_signed_tip}" -eq 40
test "$(git rev-parse HEAD)" = "${m1_011_signed_tip}"
remote_main_line="$(git ls-remote origin refs/heads/main)"
test -n "${remote_main_line}"
read -r m1_011_remote_main _ <<<"${remote_main_line}"
test "${m1_011_remote_main}" = '955c88e372cffa13f15953085f15887165be62b5'
remote_feature="$(git ls-remote --heads origin refs/heads/research/m1-011-appraisal-result)"
test -z "${remote_feature}"
test "$(gh pr list --repo archledger/open-game-integrity-runtime --state all --head research/m1-011-appraisal-result --json number --jq 'length')" -eq 0
m1_011_issue_number="$(gh api --paginate --slurp 'repos/archledger/open-game-integrity-runtime/issues?state=all&per_page=100' --jq '[.[][] | select(.pull_request == null) | select(.title == "M1-011: Define the Appraisal Result and reason-code taxonomy")] | if length == 1 then .[0].number else error("expected exactly one M1-011 issue") end')"
test "$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json state --jq '.state')" = 'OPEN'
test "$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json milestone --jq '.milestone.title')" = 'M1 Domain Model'
test "$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json labels --jq '[.labels[].name] | sort | join(",")')" = 'area: model,area: privacy,area: verifier,risk: privacy,risk: trusted-computing-base,status: needs-review,type: architecture'
live_issue_body="$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json body --jq '.body | @base64')"
local_issue_body="$(base64 -w0 planning/issues/011-result-reason-code-taxonomy.md)"
test "${live_issue_body}" = "${local_issue_body}"
```

Require remote main still the reviewed base lineage, no feature branch/PR, and exact open needs-review issue. Drift blocks push.

- [ ] **Step 3: Push ordinarily and read back exact OID**

```bash
set -euo pipefail
m1_011_signed_tip="$(tr -d '\n' < .superpowers/sdd/2026-08-28-m1-011-appraisal-result/dco-signed-tip)"
test "$(git rev-parse HEAD)" = "${m1_011_signed_tip}"
local_branch_tip="$(git rev-parse refs/heads/research/m1-011-appraisal-result)"
test "${local_branch_tip}" = "${m1_011_signed_tip}"
remote_main_line="$(git ls-remote origin refs/heads/main)"
test -n "${remote_main_line}"
read -r m1_011_remote_main _ <<<"${remote_main_line}"
test "${m1_011_remote_main}" = '955c88e372cffa13f15953085f15887165be62b5'
remote_feature="$(git ls-remote --heads origin refs/heads/research/m1-011-appraisal-result)"
test -z "${remote_feature}"
test "$(gh pr list --repo archledger/open-game-integrity-runtime --state all --head research/m1-011-appraisal-result --json number --jq 'length')" -eq 0
m1_011_issue_number="$(gh api --paginate --slurp 'repos/archledger/open-game-integrity-runtime/issues?state=all&per_page=100' --jq '[.[][] | select(.pull_request == null) | select(.title == "M1-011: Define the Appraisal Result and reason-code taxonomy")] | if length == 1 then .[0].number else error("expected exactly one M1-011 issue") end')"
test "$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json state --jq '.state')" = 'OPEN'
test "$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json milestone --jq '.milestone.title')" = 'M1 Domain Model'
test "$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json labels --jq '[.labels[].name] | sort | join(",")')" = 'area: model,area: privacy,area: verifier,risk: privacy,risk: trusted-computing-base,status: needs-review,type: architecture'
live_issue_body="$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json body --jq '.body | @base64')"
local_issue_body="$(base64 -w0 planning/issues/011-result-reason-code-taxonomy.md)"
test "${live_issue_body}" = "${local_issue_body}"
git push -u origin refs/heads/research/m1-011-appraisal-result:refs/heads/research/m1-011-appraisal-result
m1_011_local_tip="$(git rev-parse HEAD)"
remote_tip_line="$(git ls-remote --heads origin refs/heads/research/m1-011-appraisal-result)"
test -n "${remote_tip_line}"
read -r m1_011_remote_tip _ <<<"${remote_tip_line}"
test "${m1_011_remote_tip}" = "${m1_011_local_tip}"
```

No force or force-with-lease flag is permitted. Remote OID must equal signed local head.

---

### Task 14: Guard PR Creation and Complete Requesting-Code-Review Gates

**Files:**
- Create ignored: `.superpowers/sdd/2026-08-28-m1-011-appraisal-result/pr-body.md`
- External only after fresh explicit authorization: one non-draft PR

**Interfaces:**
- Consumes: exact remote branch, live needs-review issue, explicit PR authorization.
- Produces: one exact non-draft PR with disclosures and green checks; no merge.

- [ ] **Step 1: Invoke `superpowers:requesting-code-review` and run whole-branch reviews**

Provide base, signed head, spec, issue, plan, 154-probe report, full/release outputs, DCO equivalence, and scenario/docs evidence. Require separate whole-branch requirements, code-quality/security, TCB, and privacy reviews with no unresolved finding.

- [ ] **Step 2: Stop for exact PR authorization**

Authorization must name base `main`, head `research/m1-011-appraisal-result`, title, and issue. It does not authorize merge.

- [ ] **Step 3: Create an exact PR body from the repository template**

Validate the already-discovered issue number before writing the body:

```bash
set -euo pipefail
m1_011_issue_number="$(gh api --paginate --slurp 'repos/archledger/open-game-integrity-runtime/issues?state=all&per_page=100' --jq '[.[][] | select(.pull_request == null) | select(.title == "M1-011: Define the Appraisal Result and reason-code taxonomy")] | if length == 1 then .[0].number else error("expected exactly one M1-011 issue") end')"
case "${m1_011_issue_number}" in
  ''|*[!0-9]*) exit 1 ;;
esac
test "${m1_011_issue_number}" -gt 0
printf 'Closes #%s\n' "${m1_011_issue_number}"
```

Fill every field with final evidence. Required statements include AI assistance; exact primary sources; `336/50/286`; `154/154`; no dependency/parser/serializer/crypto/I/O/unsafe; no payload/failure provenance or intrinsic validity claim; human-reviewed-every-line `no`; and responsibility unchecked. Using `apply_patch`, insert the command's printed `Closes` line as a concrete decimal literal in `pr-body.md`; the body must contain neither a shell variable nor a placeholder.

- [ ] **Step 4: Create and read back the PR**

```bash
set -euo pipefail
m1_011_signed_tip="$(tr -d '\n' < .superpowers/sdd/2026-08-28-m1-011-appraisal-result/dco-signed-tip)"
test "$(git rev-parse HEAD)" = "${m1_011_signed_tip}"
remote_main_line="$(git ls-remote origin refs/heads/main)"
test -n "${remote_main_line}"
read -r m1_011_remote_main _ <<<"${remote_main_line}"
test "${m1_011_remote_main}" = '955c88e372cffa13f15953085f15887165be62b5'
remote_tip_line="$(git ls-remote --heads origin refs/heads/research/m1-011-appraisal-result)"
test -n "${remote_tip_line}"
read -r m1_011_remote_tip _ <<<"${remote_tip_line}"
test "${m1_011_remote_tip}" = "${m1_011_signed_tip}"
m1_011_issue_number="$(gh api --paginate --slurp 'repos/archledger/open-game-integrity-runtime/issues?state=all&per_page=100' --jq '[.[][] | select(.pull_request == null) | select(.title == "M1-011: Define the Appraisal Result and reason-code taxonomy")] | if length == 1 then .[0].number else error("expected exactly one M1-011 issue") end')"
test "$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json state --jq '.state')" = 'OPEN'
test "$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json milestone --jq '.milestone.title')" = 'M1 Domain Model'
test "$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json labels --jq '[.labels[].name] | sort | join(",")')" = 'area: model,area: privacy,area: verifier,risk: privacy,risk: trusted-computing-base,status: needs-review,type: architecture'
live_issue_body="$(gh issue view "${m1_011_issue_number}" --repo archledger/open-game-integrity-runtime --json body --jq '.body | @base64')"
local_issue_body="$(base64 -w0 planning/issues/011-result-reason-code-taxonomy.md)"
test "${live_issue_body}" = "${local_issue_body}"
test "$(rg -c "^Closes #${m1_011_issue_number}$" .superpowers/sdd/2026-08-28-m1-011-appraisal-result/pr-body.md)" -eq 1
test "$(gh pr list --repo archledger/open-game-integrity-runtime --state all --base main --head research/m1-011-appraisal-result --json number --jq 'length')" -eq 0
m1_011_pr_url="$(gh pr create --repo archledger/open-game-integrity-runtime --base main --head research/m1-011-appraisal-result --title 'M1-011: Define the Appraisal Result and reason-code taxonomy' --body-file .superpowers/sdd/2026-08-28-m1-011-appraisal-result/pr-body.md)"
m1_011_pr_number="${m1_011_pr_url##*/}"
case "${m1_011_pr_number}" in
  ''|*[!0-9]*) exit 1 ;;
esac
test "${m1_011_pr_number}" -gt 0
test "$(gh pr list --repo archledger/open-game-integrity-runtime --state open --base main --head research/m1-011-appraisal-result --json number --jq 'length')" -eq 1
test "$(gh pr list --repo archledger/open-game-integrity-runtime --state open --base main --head research/m1-011-appraisal-result --json number --jq '.[0].number')" -eq "${m1_011_pr_number}"
test "$(gh pr view "${m1_011_pr_number}" --repo archledger/open-game-integrity-runtime --json state --jq '.state')" = 'OPEN'
test "$(gh pr view "${m1_011_pr_number}" --repo archledger/open-game-integrity-runtime --json isDraft --jq '.isDraft')" = 'false'
test "$(gh pr view "${m1_011_pr_number}" --repo archledger/open-game-integrity-runtime --json baseRefName --jq '.baseRefName')" = 'main'
test "$(gh pr view "${m1_011_pr_number}" --repo archledger/open-game-integrity-runtime --json headRefName --jq '.headRefName')" = 'research/m1-011-appraisal-result'
live_head_oid="$(gh pr view "${m1_011_pr_number}" --repo archledger/open-game-integrity-runtime --json headRefOid --jq '.headRefOid')"
local_head_oid="$(git rev-parse HEAD)"
test "${live_head_oid}" = "${local_head_oid}"
live_pr_body="$(gh pr view "${m1_011_pr_number}" --repo archledger/open-game-integrity-runtime --json body --jq '.body | @base64')"
local_pr_body="$(base64 -w0 .superpowers/sdd/2026-08-28-m1-011-appraisal-result/pr-body.md)"
test "${live_pr_body}" = "${local_pr_body}"
test "$(gh pr view "${m1_011_pr_number}" --repo archledger/open-game-integrity-runtime --json url --jq '.url')" = "${m1_011_pr_url}"
```

Require the returned URL to contain a positive decimal PR number, exactly one matching open base/head PR, OPEN, non-draft, exact base/head/OID/body/linkage, and human-only boxes still false.

- [ ] **Step 5: Watch checks and inspect all review surfaces**

```bash
set -euo pipefail
m1_011_pr_number="$(gh pr list --repo archledger/open-game-integrity-runtime --state open --base main --head research/m1-011-appraisal-result --json number --jq 'if length == 1 then .[0].number else error("expected exactly one M1-011 PR") end')"
case "${m1_011_pr_number}" in ''|*[!0-9]*) exit 1 ;; esac
test "${m1_011_pr_number}" -gt 0
gh pr checks --repo archledger/open-game-integrity-runtime --watch "${m1_011_pr_number}"
gh pr view "${m1_011_pr_number}" --repo archledger/open-game-integrity-runtime --json reviews,comments,commits,mergeable,mergeStateStatus,url
gh api "repos/archledger/open-game-integrity-runtime/pulls/${m1_011_pr_number}/comments"
gh api "repos/archledger/open-game-integrity-runtime/code-scanning/alerts?state=open&pr=${m1_011_pr_number}"
```

Resolve findings only through new negative-test-first commits, separately certified DCO, non-force publication, rerun 154 mutations when semantics/proof change, and fresh reviews. Never dismiss a real alert to obtain green.

---

### Task 15: Human-Only Merge Handoff and Post-Merge Verification

**Files:**
- Read only: PR, issue, repository, retained backups/worktrees
- External only after explicit human actions: PR disclosure update and merge

**Interfaces:**
- Consumes: green exact PR, human line review and responsibility acceptance, separate merge authorization.
- Produces: human-controlled merge handoff; post-merge evidence only after the human authorizes merge.

- [ ] **Step 1: Hand off exact facts and stop**

Give the user PR URL, signed head/tree, exact checks, 154/154 report, review verdicts, issue state, and retained backup restore command. Ask the human to review every line, verify primary sources, accept responsibility, and separately authorize merge.

- [ ] **Step 2: Do not mark human attestations autonomously**

Only after the user explicitly states line-by-line review and responsibility may the PR disclosure be updated by exactly those fields. Read back exact body afterward.

- [ ] **Step 3: Do not merge without a separate exact authorization**

Before an authorized merge, re-read head OID, approvals, checks, mergeability, issue linkage, DCO, and open alerts. Any changed head invalidates prior merge authorization.

- [ ] **Step 4: Require the exact web squash/sign-off mode, preserve rollback artifacts, and verify**

The only permitted mode is **Squash and merge through the GitHub.com web interface**, performed by the authorized human with the repository's compulsory **Sign off and commit** control enabled for the newly created `main` commit. Merge commits, rebase merges, CLI/API merge commands, bypasses, disabled web sign-off, and autonomous agent merge actions are prohibited. If GitHub does not present or retain the compulsory web sign-off, stop without merging.

Do not delete the local worktree, backup ref, bundle, manifest, or reports. After the human reports the web squash merge, read back `main`, update local `main` by fast-forward only, and run:

```bash
./scripts/check.sh
cargo test --workspace --all-features --release
git diff --check
git fsck --no-dangling
```

Verify the squash commit has exactly one parent equal to the reviewed base lineage, its tree equals the reviewed feature-head tree, and its trailers include the compulsory canonical web sign-off for the authenticated human who created that squash commit. Verify issue closure, CI/CodeQL, and no open alert. Report facts without production-readiness claims.

---

## Spec-to-Task Coverage

| Approved requirement | Implemented/proved by |
| --- | --- |
| Exact 15-reason taxonomy and optional report reason | Tasks 1-2, mutations `M01-M15` |
| Opaque discriminated result and borrowed view | Task 3, `A01-A16` |
| Exact accessor names and allow-only claims | Tasks 3 and 5, `C01-C10` |
| Whole-state active request/cumulative claims | Task 4, `R01-R06`, structural proof |
| Evidence/profile, session/key, policy/class payloads | Tasks 4-5, `C01-C12` |
| Sole consuming allow conversion | Task 5, `O01-O04` |
| Five result-emitting failure methods | Task 6 |
| 41 phase-eligible failure edges | Tasks 1, 6-7, `E01-E41` |
| 336 pairs, 50 successes, 286 rejections | Tasks 1 and 7 |
| 5,040 permutations and seven omissions | Task 7 |
| Phase-before-binding and seven substitutions | Tasks 4 and 7, `G08-G14` |
| Exactly 1,048,576 history actions | Tasks 1 and 7 |
| Failure claim discard and terminal-first replacement | Tasks 6 and 8, `C08-C09`, `R01-R06` |
| No cryptographic payload/trusted failure provenance claim | Tasks 4, 8-9, TCB review |
| No intrinsic validity or generic signer | Tasks 3, 8-9, `A13-A15` |
| Report-only research scaffold remains non-authoritative | Tasks 2 and 8 |
| Fixed diagnostics and privacy retention limits | Tasks 3, 8-9, `D01-D15` |
| Existing five scenarios extended | Task 9 |
| Architecture/threat/roadmap/test/privacy/trust/protocol/ADR synchronization | Task 9 |
| Exact 154-probe mutation campaign and separate TCB/privacy reviews | Task 10 |
| Time-bounded evidence and guarded issue sync | Task 11 |
| Human DCO with retained backup/equivalence | Task 12 |
| Guarded ordinary push and separate PR authorization | Tasks 13-14 |
| Requesting-code-review and human-only merge | Tasks 14-15 |
| No dependency/parser/serializer/crypto/I/O/unsafe | Global constraints and all gate commands |

---

## Plan Self-Review Checklist

- [x] The approved spec, canonical issue, ADR-0007, ADR-0009, mandatory project documents, current source/tests, five scenarios, and M1-010 precedent are mapped to exact tasks and paths.
- [x] The action domain is exactly 24 semantic variants: 8 gate/class variants, Complete, Malformed, 3 Unsupported, 2 Retry, 8 Denial, and Revoked.
- [x] Eligibility arithmetic is explicit: `5 + 8 + 4 + 5 + 5 + 5 + 5 + 4 = 41`; success graph is 9; `14 × 24 = 336`; `41 + 9 = 50`; rejections are 286.
- [x] Schedule arithmetic is explicit: `256 + 864 + 576 + 35 + 312 + 5 = 2,048`; `2,048 + 1,046,528 = 1,048,576`; minimum completions are `61/35`.
- [x] All seven gate permutations/omissions/substitutions and phase-before-binding checks remain independent detectors.
- [x] Public API names are type-consistent across tasks: `context`, `decision`, `reason`, `view`, `accepted_profile`, `session_public_key_id`, and `into_appraisal_result`.
- [x] All five failure signatures return `Result<AppraisalResult, TransitionError>` and exact typed inputs; malformed/revoked are dedicated actions.
- [x] Every code-producing task captures a focused negative RED before production and gives focused/full GREEN commands.
- [x] Whole-state terminal replacement, claim transfer/discard, exact policy retention, and one-use conversion have direct tests and mutations.
- [x] The mutation inventory is closed and sums exactly to 154; every probe names one cause, command key, and intended detector.
- [x] Result shape is not described as cryptographic payload provenance, trusted failure provenance, intrinsic validity, protected result, signer input, permit, PoP, admission, or discipline.
- [x] Historical plans/specs, dependencies, parser/serializer/crypto/I/O/unsafe, scenario schema/registries, and unrelated worktrees/backups remain unchanged.
- [x] Documentation ownership remains exact: M1-011 semantic result, M1-012 transcript inputs, later M2 commitment/protection/wire/validation/validity.
- [x] GitHub writes each require explicit authorization, guarded preconditions, exact readback, and rollback; push and PR are separate gates.
- [x] DCO requires a concrete frozen range, exact human certification, immutable backup, metadata-only equivalence proof, and fresh signed-SHA review.
- [x] Final review uses `superpowers:requesting-code-review`; line review, responsibility, merge, and cleanup remain human-only.
- [x] Placeholder scan found no unresolved planning marker, shorthand implementation instruction, undefined public signature, or vague error-handling step.
