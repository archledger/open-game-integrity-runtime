# M1-009 Local Protected-Session State Machine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement one deterministic, fail-closed local protected-session state machine whose typed, session-bound gates prevent skipped admission/renewal steps and whose terminal states retain an explicit cleanup obligation.

**Architecture:** Add one private `ogir-agent::session` feature module and selectively re-export its reviewed public views and opaque types. The module owns one non-cloneable `LocalSession`, a private discriminated state, non-cloneable session-bound completion capabilities, structured redacted errors, and cleanup bookkeeping; it performs no I/O. Private child-module tests provide fixtures without shipping speculative constructors, while future trusted sibling adapters will add crate-confined factories when their real validation/cleanup operations exist.

**Tech Stack:** Rust 1.98.0, edition 2024, Rust standard library, existing `ogir-model::SessionId`, Cargo tests/doctests/Clippy/rustdoc, Bash/Git disposable mutation worktrees, existing dependency-free attack-scenario validator.

**Spec:** `docs/superpowers/specs/2026-08-26-m1-009-local-session-state-machine-design.md`

## Global Constraints

- Read the approved spec and `docs/SECURITY_INVARIANTS.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, and `docs/AI_DEVELOPMENT_POLICY.md` before changing code.
- Keep `#![forbid(unsafe_code)]`; add no `unsafe`, C, FFI, parser, I/O, async, TPM, process, filesystem, policy-enforcement, signature, transport, or serialization behavior.
- Add no Cargo dependency and do not modify any `Cargo.toml` or `Cargo.lock` file.
- `LocalSession`, all authority-bearing gate/cleanup types, and their fields remain non-`Clone`, non-`Copy`, private to construction, and redacted by default.
- Do not ship an unused production constructor merely to support tests. `session::tests`, as a child module, constructs private fixtures directly. A later trusted-adapter task may add the reviewed `pub(crate)` factories.
- Public fieldless phase/action/cleanup enums are deliberately exhaustive because they define the fixed audited graph. Adding a variant is a reviewed security-contract change, not a silent minor extension.
- No state transition may mutate before phase and (when applicable) session-binding checks succeed.
- `Display` uses fixed lowercase context-free messages. `Debug` contains only type names, explicit redaction markers, and safe fieldless enums.
- Every recoverable misuse returns `Result`; production code uses no `unwrap`, `expect`, `panic`, `todo`, or `unimplemented`.
- Every public fallible method documents its exact `# Errors` contract and uses checked intra-doc links.
- Write the negative test before each implementation slice and observe the expected RED failure. Never weaken an invariant to make a test pass.
- After every material code, test, design, Git-topology, or GitHub change, refresh `/home/wisbfime/Agent Shared Memory/project-open-game-integrity-runtime.md`, append a factual `agent: codex` checkpoint, and update its index row before continuing or handing off.
- Keep commits unsigned until the user certifies one exact immutable range. Never add `Signed-off-by: archledger <archledger236@gmail.com>`. The only permitted eventual trailer is `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>` after exact human certification.
- Do not push, open a PR, or rewrite sign-offs until final tests/reviews and the explicit DCO gate in Task 7.

## File Map

**Create:**

- `crates/ogir-agent/src/session.rs` — public lifecycle contract, private state, capabilities, transitions, redacted diagnostics.
- `crates/ogir-agent/src/session/tests.rs` — private-fixture unit tests, independent finite-state oracle, arbitrary sequences, privacy assertions.
- `lab/scenarios/local-session-skip-permit.scenario.json` — activation-gate attack trace.
- `lab/scenarios/local-session-cross-capability.scenario.json` — cross-session capability substitution trace.
- `lab/scenarios/local-session-terminal-cleanup.scenario.json` — cleanup/reactivation trace.
- `docs/adr/0006-local-session-lifecycle-capabilities.md` — durable lifecycle/capability/cleanup decision.

**Modify:**

- `crates/ogir-agent/src/lib.rs` — private module declaration and selective public re-exports only.
- `planning/issues/009-local-session-state-machine.md` — complete AI task contract, corrected renewal graph, evidence/status.
- `docs/ROADMAP.md` — explicit initial, renewal, and terminal lifecycle edges.
- `docs/ARCHITECTURE.md` — local capability authority and orthogonal cleanup status.
- `docs/THREAT_MODEL.md` — skipped gate, cross-session capability, reactivation, and stranded cleanup responses.
- `docs/TEST_STRATEGY.md` — exhaustive matrix, arbitrary sequence, compile-fail, privacy, and mutation coverage.
- `docs/adr/index.md` — exact ADR-0006 row.
- `docs/LESSONS_LEARNED.md` — append only if implementation/review uncovers a durable new lesson.

**Intentionally unchanged:**

- Every `Cargo.toml` and `Cargo.lock`.
- `ogir-model`, `ogir-protocol`, `ogir-verifier`, application binaries, and existing freshness behavior.
- `scripts/check-attack-scenario-traceability.py` and its schema unless a concrete independently reviewed defect is reproduced.

---

### Task 1: Make the M1-009 Issue Contract Implementation-Ready

**Files:**

- Modify: `planning/issues/009-local-session-state-machine.md`

**Interfaces:**

- Consumes: approved M1-009 spec and existing label/milestone taxonomy.
- Produces: one canonical local/live issue body with exact scope, trust authority, graph, tests, privacy, dependencies, and acceptance criteria.

- [ ] **Step 1: Record the current immutable baseline**

Run:

```bash
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
sha256sum planning/issues/009-local-session-state-machine.md
gh issue list --repo archledger/open-game-integrity-runtime --state all \
  --limit 100 --json number,title,state,url
```

Expected:

- clean `research/m1-009-local-session-state-machine` at the approved-plan base;
- local `origin/main` remains `34ce07e7e0433ed9ef34fdcb08d8d0cac7117c43` unless a separately reviewed upstream change is reported;
- no existing issue titled `M1-009: Implement the local protected-session state machine`.

- [ ] **Step 2: Replace the short issue body with the complete reviewed contract**

Use `apply_patch` so the file contains these sections and facts verbatim in substance:

```markdown
# M1-009: Implement the local protected-session state machine
<!-- labels: type: implementation,area: model,area: agent,area: session,risk: trusted-computing-base,risk: privacy,status: ready -->
<!-- milestone: M1 Domain Model -->

## Problem

A protected session must not skip challenge validation, caller binding, policy
preparation, evidence creation, verifier-permit receipt, activation, renewal,
or terminal cleanup. Independent booleans admit contradictory combinations and
make skipped gates difficult to audit.

## Security invariants

- Evidence-created state is unreachable before caller binding and session preparation.
- Active state is unreachable without a matching session-bound validated permit.
- Renewal requires a fresh validated permit and reuses the permit-received gate.
- Ended and invalidated sessions never renew, reactivate, or change terminal disposition.
- Every terminal entry records cleanup required until trusted completion is acknowledged.
- A capability for one `SessionId` never advances another session.
- Diagnostics expose no session, challenge, account, evidence, permit, key, process, or path value.

## Threats addressed

- A1 modified client skips local admission gates or reuses another session's capability.
- A1 or buggy orchestration attempts activation without verifier authorization.
- A1 or a local failure attempts renewal/reactivation after terminal entry.
- A4/local-service failure strands session restrictions after end or invalidation.
- A8 overreaching diagnostics disclose session-scoped authorization context.

## In scope

- One pure deterministic checked runtime state machine in `ogir-agent`.
- Private discriminated lifecycle state and safe public phase/cleanup/action views.
- Non-cloneable opaque session-bound completion capabilities.
- Initial, renewal, terminal, cleanup-request, and cleanup-completion transitions.
- Structured deterministic state-preserving errors and redacted diagnostics.
- Exhaustive finite-state, deterministic arbitrary-sequence, compile-fail, privacy, mutation, and machine-readable scenario evidence.

## Out of scope

- Concrete permit or `AttestationResult` fields, signatures, keys, or validation.
- Cgroup/process/Wine/Proton/filesystem/policy-enforcement operations.
- TPM evidence, networking, serialization, storage, async, retry scheduling, or actual cleanup I/O.
- M1-010 verifier state machine and public trusted-adapter factories.

## Trust sources

- `SessionId` and lifecycle creation: trusted local portal/agent, never the game.
- Gate completion capabilities: future trusted sibling adapters after their real operation succeeds.
- Validated permit capability: future trusted local verifier-result validator.
- Cleanup completion capability: future trusted idempotent cleanup adapter.
- Phase ordering and exact session comparison: this pure state machine.

## Required interfaces

- Public fieldless `SessionPhase`, `CleanupStatus`, and `SessionAction` enums.
- Non-cloneable public opaque `LocalSession`, five gate capabilities, `CleanupRequest`, and `CleanupCompleted`.
- Eight initial/renewal progression methods, `end`, `invalidate`, `cleanup_request`, and `record_cleanup_completed`.
- `TransitionError::{InvalidTransition, CapabilityRejected}` with no caller-controlled diagnostic field.
- No public or unused production constructor; private child tests construct fixtures directly.

## Positive tests

- All eight initial/renewal progression edges.
- End and invalidate from every nonterminal phase.
- Cleanup request/reissue/completion for both terminal dispositions.
- Repeated successful renewal through a fresh validated permit.

## Negative tests

- All 94 disallowed pairs in the 12-state × 10-action matrix.
- Mismatched `SessionId` for every capability-bearing allowed edge.
- Direct renewal activation, terminal reactivation, duplicate cleanup completion, and cleanup completion outside terminal-required state.
- Compile-fail external construction, field access, cloning, copying, and direct state mutation.
- Exact redacted diagnostics with non-vacuous private session sentinels.

## Fuzz/property tests

- Exhaust all 120 state/action pairs against an independent literal model.
- Execute at least 4,096 fixed-seed sequences of 256 actions (1,048,576 actions) and compare after every action.
- No byte fuzzer is added because this task introduces no parser and the finite action domain is exhaustively covered.

## Privacy impact

The machine stores only private `SessionId` plus lifecycle state. It stores no
challenge, account, evidence, permit, key, process, or path payload. Default
diagnostics expose only approved enum names and redaction markers. Adding any
raw field requires a separate privacy review.

## Dependency impact

No new crate or package. The session module uses only the Rust standard library
and existing `ogir_model::SessionId`; all affected source remains Apache-2.0.

## Acceptance criteria

- The initial graph, explicit renewal loop, and terminal cleanup status match the approved design, architecture, and roadmap.
- Exactly 26 state/action pairs succeed and 94 fail unchanged.
- No sequence reaches initial or renewed Active without the required matching permit gate.
- Every terminal path reports cleanup Required until matching completion, and no terminal lifecycle transition succeeds.
- Public authority-bearing objects are non-forgeable/non-cloneable through safe external Rust.
- Errors and default diagnostics reveal no private binding or caller-controlled value.
- All named mutation probes fail a specific regression test.
- `./scripts/check.sh` passes without dependency or unsafe-code changes.

## Primary sources

- Approved design: `docs/superpowers/specs/2026-08-26-m1-009-local-session-state-machine-design.md`.
- Project authority: `docs/SECURITY_INVARIANTS.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `docs/THREAT_MODEL.md`, and `docs/AI_DEVELOPMENT_POLICY.md`.
- Rust 1.98 visibility: https://doc.rust-lang.org/1.98.0/reference/visibility-and-privacy.html
- Rust 1.98 ownership: https://doc.rust-lang.org/1.98.0/book/ch04-01-what-is-ownership.html
- Rust 1.98 `must_use`: https://doc.rust-lang.org/1.98.0/core/attribute.must_use.html
```

- [ ] **Step 3: Verify the local issue contract**

Run:

```bash
./scripts/check-repository-metadata.sh .
git diff --check
rg -n '^## (Problem|Security invariants|Threats addressed|In scope|Out of scope|Trust sources|Required interfaces|Positive tests|Negative tests|Fuzz/property tests|Privacy impact|Dependency impact|Acceptance criteria|Primary sources)$' planning/issues/009-local-session-state-machine.md
rg -n '1,048,576|Exactly 26|94 fail|status: ready|No new crate|No public or unused production constructor' planning/issues/009-local-session-state-machine.md
```

Expected: repository metadata passes, diff is clean, every required heading occurs exactly once, and all fixed security/test terms are present. If `pub(crate)` appears only in a source URL and not an interface sentence, correct the issue before committing.

- [ ] **Step 4: Commit the local issue contract without a sign-off trailer**

```bash
git add planning/issues/009-local-session-state-machine.md
git diff --cached --check
git commit -m "docs: make M1-009 implementation-ready"
```

Expected: one unsigned documentation commit; `git log -1 --format=%B` contains no `Signed-off-by:` line.

- [ ] **Step 5: Guardedly create the one live ready issue**

Run read-only preconditions first:

```bash
issue_title='M1-009: Implement the local protected-session state machine'
existing_count="$(gh issue list --repo archledger/open-game-integrity-runtime \
  --state all --limit 100 --json title \
  --jq "[.[] | select(.title == \"${issue_title}\")] | length")"
test "${existing_count}" -eq 0
test "$(git ls-remote origin refs/heads/main | cut -f1)" = \
  "$(git rev-parse origin/main)"
```

Then create only this issue:

```bash
gh issue create --repo archledger/open-game-integrity-runtime \
  --title "${issue_title}" \
  --body-file planning/issues/009-local-session-state-machine.md \
  --milestone 'M1 Domain Model' \
  --label 'type: implementation' \
  --label 'area: model' \
  --label 'area: agent' \
  --label 'area: session' \
  --label 'risk: trusted-computing-base' \
  --label 'risk: privacy' \
  --label 'status: ready'
```

Read back the created issue and record its number/URL/body hash in Shared Memory. Do not run `scripts/create-initial-issues.sh`; it would create unrelated backlog issues.

---

### Task 2: Implement the Initial Session Admission Gates Test-First

**Files:**

- Create: `crates/ogir-agent/src/session.rs`
- Create: `crates/ogir-agent/src/session/tests.rs`
- Modify: `crates/ogir-agent/src/lib.rs`

**Interfaces:**

- Consumes: `ogir_model::SessionId`; no raw `PublisherChallenge`, `AccountScope`, `EvidenceBundle`, or permit type.
- Produces: `SessionPhase`, `CleanupStatus`, `SessionAction`, `TransitionError`, `LocalSession`, five opaque gate types, and `New -> ChallengeValidated -> CallerBound -> SessionPrepared -> EvidenceCreated -> PermitReceived -> Active`.

- [ ] **Step 1: Add the private module and failing initial-path tests**

In `crates/ogir-agent/src/lib.rs`, add only:

```rust
mod session;

pub use session::{
    BoundCaller, CleanupStatus, CreatedEvidence, LocalSession, PreparedSession, SessionAction,
    SessionPhase, TransitionError, ValidatedChallenge, ValidatedPermit,
};
```

Create `crates/ogir-agent/src/session.rs` with the SPDX header, module-level contract, and:

```rust
#[cfg(test)]
mod tests;
```

Create `crates/ogir-agent/src/session/tests.rs` with private fixture helpers and these RED tests:

```rust
use super::*;

fn session_id(value: &str) -> SessionId {
    match SessionId::try_from(value) {
        Ok(value) => value,
        Err(error) => panic!("valid test session identifier rejected: {error:?}"),
    }
}

fn binding(value: &str) -> SessionBinding {
    SessionBinding(session_id(value))
}

fn session(value: &str) -> LocalSession {
    LocalSession {
        session_id: session_id(value),
        state: SessionState::New,
    }
}

#[test]
fn new_session_starts_without_cleanup() {
    let session = session("session-a");
    assert_eq!(session.phase(), SessionPhase::New);
    assert_eq!(session.cleanup_status(), CleanupStatus::NotRequired);
}

#[test]
fn initial_path_requires_every_gate_in_order() {
    let mut session = session("session-a");

    assert_eq!(
        session.record_challenge_validated(ValidatedChallenge {
            binding: binding("session-a"),
        }),
        Ok(())
    );
    assert_eq!(session.phase(), SessionPhase::ChallengeValidated);
    assert_eq!(
        session.record_caller_bound(BoundCaller {
            binding: binding("session-a"),
        }),
        Ok(())
    );
    assert_eq!(session.phase(), SessionPhase::CallerBound);
    assert_eq!(
        session.record_session_prepared(PreparedSession {
            binding: binding("session-a"),
        }),
        Ok(())
    );
    assert_eq!(session.phase(), SessionPhase::SessionPrepared);
    assert_eq!(
        session.record_evidence_created(CreatedEvidence {
            binding: binding("session-a"),
        }),
        Ok(())
    );
    assert_eq!(session.phase(), SessionPhase::EvidenceCreated);
    assert_eq!(
        session.record_permit_received(ValidatedPermit {
            binding: binding("session-a"),
        }),
        Ok(())
    );
    assert_eq!(session.phase(), SessionPhase::PermitReceived);
    assert_eq!(session.activate(), Ok(()));
    assert_eq!(session.phase(), SessionPhase::Active);
}

#[test]
fn skipped_gate_returns_exact_error_without_mutation() {
    let mut session = session("session-a");
    let error = session.activate();
    assert_eq!(
        error,
        Err(TransitionError::InvalidTransition {
            phase: SessionPhase::New,
            cleanup_status: CleanupStatus::NotRequired,
            action: SessionAction::Activate,
        })
    );
    assert_eq!(session.phase(), SessionPhase::New);
}

#[test]
fn cross_session_capability_is_rejected_without_mutation() {
    let mut session = session("session-a");
    let error = session.record_challenge_validated(ValidatedChallenge {
        binding: binding("session-b"),
    });
    assert_eq!(
        error,
        Err(TransitionError::CapabilityRejected {
            action: SessionAction::RecordChallengeValidated,
        })
    );
    assert_eq!(session.phase(), SessionPhase::New);
}
```

- [ ] **Step 2: Run the focused test to verify RED**

Run:

```bash
cargo test -p ogir-agent session::tests --all-features
```

Expected: compile failure naming missing `SessionId`, `SessionBinding`, `LocalSession`, and transition types/methods. A passing or zero-test result is a harness failure.

- [ ] **Step 3: Implement the minimal initial state/capability/error core**

In `session.rs`, import only:

```rust
use std::error::Error;
use std::fmt;

use ogir_model::SessionId;
```

Define the public views exactly as fieldless enums deriving `Debug, Clone,
Copy, PartialEq, Eq, Hash`. Add a `///` comment to every enum and variant. Do
not use `#[non_exhaustive]`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionPhase {
    New,
    ChallengeValidated,
    CallerBound,
    SessionPrepared,
    EvidenceCreated,
    PermitReceived,
    Active,
    RenewalPending,
    Ended,
    Invalidated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CleanupStatus {
    NotRequired,
    Required,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionAction {
    RecordChallengeValidated,
    RecordCallerBound,
    RecordSessionPrepared,
    RecordEvidenceCreated,
    RecordPermitReceived,
    Activate,
    BeginRenewal,
    End,
    Invalidate,
    RecordCleanupCompleted,
}
```

Define the initial private state:

```rust
#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionState {
    New,
    ChallengeValidated,
    CallerBound,
    SessionPrepared,
    EvidenceCreated,
    PermitReceived,
    Active,
}

struct SessionBinding(SessionId);

impl SessionBinding {
    fn matches(&self, session_id: &SessionId) -> bool {
        self.0.eq(session_id)
    }
}
```

Define each capability explicitly—do not generate the public API with a macro:

```rust
#[must_use = "validated challenge capability must be consumed by its session transition"]
pub struct ValidatedChallenge {
    binding: SessionBinding,
}

#[must_use = "caller binding capability must be consumed by its session transition"]
pub struct BoundCaller {
    binding: SessionBinding,
}

#[must_use = "prepared-session capability must be consumed by its session transition"]
pub struct PreparedSession {
    binding: SessionBinding,
}

#[must_use = "created-evidence capability must be consumed by its session transition"]
pub struct CreatedEvidence {
    binding: SessionBinding,
}

#[must_use = "validated permit capability must be consumed by its session transition"]
pub struct ValidatedPermit {
    binding: SessionBinding,
}
```

Implement custom `Debug` for each capability using exactly its type name and
`([REDACTED])`. Do not implement `Clone`, `Copy`, `PartialEq`, a constructor, or
a binding getter.

Define the exact error:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    InvalidTransition {
        phase: SessionPhase,
        cleanup_status: CleanupStatus,
        action: SessionAction,
    },
    CapabilityRejected {
        action: SessionAction,
    },
}

impl fmt::Display for TransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { .. } => {
                formatter.write_str("local session transition is not allowed")
            }
            Self::CapabilityRejected { .. } => {
                formatter.write_str("local session capability rejected")
            }
        }
    }
}

impl Error for TransitionError {}
```

Define `LocalSession` without derives:

```rust
#[must_use = "local session lifecycle state must be retained by its trusted owner"]
pub struct LocalSession {
    session_id: SessionId,
    state: SessionState,
}
```

Implement `phase`, `cleanup_status`, one private `invalid_transition` helper,
one private `ensure_binding` helper, and the six initial transition methods.
Every phase mapping must list every private variant explicitly. Every
capability-bearing method must check phase first, binding second, and assign
state last. `record_permit_received` accepts only `EvidenceCreated` in this
task; Task 3 adds the renewal origin.

Use this exact method pattern for each capability-bearing edge:

```rust
pub fn record_challenge_validated(
    &mut self,
    capability: ValidatedChallenge,
) -> Result<(), TransitionError> {
    if self.state != SessionState::New {
        return Err(self.invalid_transition(SessionAction::RecordChallengeValidated));
    }
    self.ensure_binding(
        SessionAction::RecordChallengeValidated,
        &capability.binding,
    )?;
    self.state = SessionState::ChallengeValidated;
    Ok(())
}
```

Repeat the same literal order for caller, preparation, evidence, and permit.
`activate` checks only `SessionState::PermitReceived`, then assigns `Active`.

Implement `LocalSession` debug without formatting the identifier as a field:

```rust
impl fmt::Debug for LocalSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalSession")
            .field("phase", &self.phase())
            .field("cleanup_status", &self.cleanup_status())
            .finish()
    }
}
```

Add `///` documentation for every public type/variant/method and a `# Errors`
section for every transition. Explain that trusted production construction is
deferred; do not add an unused factory or lint suppression.

- [ ] **Step 4: Run focused GREEN and public documentation checks**

```bash
cargo fmt --all --check
cargo test -p ogir-agent session::tests --all-features
cargo clippy -p ogir-agent --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc -p ogir-agent --no-deps
```

Expected: four tests pass, no warning, no broken link, and no constructor is
present in normal rustdoc.

- [ ] **Step 5: Commit the initial gate slice**

```bash
git add crates/ogir-agent/src/lib.rs crates/ogir-agent/src/session.rs \
  crates/ogir-agent/src/session/tests.rs
git diff --cached --check
git commit -m "feat: enforce local session admission gates"
```

---

### Task 3: Add Renewal and Explicit Terminal Cleanup Test-First

**Files:**

- Modify: `crates/ogir-agent/src/session.rs`
- Modify: `crates/ogir-agent/src/session/tests.rs`
- Modify: `crates/ogir-agent/src/lib.rs`

**Interfaces:**

- Consumes: Task 2 `LocalSession`, private `SessionState`, `ValidatedPermit`, `TransitionError`.
- Produces: `Active -> RenewalPending -> PermitReceived -> Active`, terminal entry from every nonterminal phase, retryable `CleanupRequest`, and capability-gated `CleanupCompleted` acknowledgement.

- [ ] **Step 1: Write renewal and terminal-cleanup tests before implementation**

Add private helpers that advance a session through the initial path without
using `unwrap` or `expect`; use `assert_eq!(transition, Ok(()))` after each
step. Add these RED tests:

```rust
#[test]
fn renewal_requires_a_fresh_matching_permit_before_reactivation() {
    let mut session = active_session("session-a");
    assert_eq!(session.begin_renewal(), Ok(()));
    assert_eq!(session.phase(), SessionPhase::RenewalPending);
    assert_eq!(
        session.activate(),
        Err(TransitionError::InvalidTransition {
            phase: SessionPhase::RenewalPending,
            cleanup_status: CleanupStatus::NotRequired,
            action: SessionAction::Activate,
        })
    );
    assert_eq!(
        session.record_permit_received(ValidatedPermit {
            binding: binding("session-a"),
        }),
        Ok(())
    );
    assert_eq!(session.activate(), Ok(()));
    assert_eq!(session.phase(), SessionPhase::Active);
}

#[test]
fn every_nonterminal_phase_can_end_with_cleanup_required() {
    for phase in NONTERMINAL_PHASES {
        let mut session = session_at("session-a", phase);
        let request = session.end();
        assert!(request.is_ok(), "end failed from {phase:?}: {request:?}");
        assert_eq!(session.phase(), SessionPhase::Ended);
        assert_eq!(session.cleanup_status(), CleanupStatus::Required);
    }
}

#[test]
fn every_nonterminal_phase_can_invalidate_with_cleanup_required() {
    for phase in NONTERMINAL_PHASES {
        let mut session = session_at("session-a", phase);
        let request = session.invalidate();
        assert!(
            request.is_ok(),
            "invalidation failed from {phase:?}: {request:?}"
        );
        assert_eq!(session.phase(), SessionPhase::Invalidated);
        assert_eq!(session.cleanup_status(), CleanupStatus::Required);
    }
}

#[test]
fn matching_cleanup_completion_preserves_terminal_disposition() {
    let mut session = active_session("session-a");
    assert!(session.invalidate().is_ok());
    assert!(session.cleanup_request().is_some());
    assert_eq!(
        session.record_cleanup_completed(CleanupCompleted {
            binding: binding("session-a"),
        }),
        Ok(())
    );
    assert_eq!(session.phase(), SessionPhase::Invalidated);
    assert_eq!(session.cleanup_status(), CleanupStatus::Complete);
    assert!(session.cleanup_request().is_none());
}

#[test]
fn terminal_sessions_reject_every_lifecycle_action() {
    for phase in [SessionPhase::Ended, SessionPhase::Invalidated] {
        for cleanup_complete in [false, true] {
            let mut session = terminal_session("session-a", phase, cleanup_complete);
            assert_all_lifecycle_actions_rejected(&mut session);
            assert_eq!(session.phase(), phase);
        }
    }
}
```

Define `NONTERMINAL_PHASES` as the exact eight fieldless phases. Implement
`session_at`, `active_session`, `terminal_session`, and
`assert_all_lifecycle_actions_rejected` in the same test module with explicit
matches—no wildcard over owned enums.

- [ ] **Step 2: Run focused test to verify RED**

```bash
cargo test -p ogir-agent session::tests --all-features
```

Expected: compile failures for missing `RenewalPending` private state,
`begin_renewal`, `CleanupRequest`, `CleanupCompleted`, terminal methods, and
cleanup query.

- [ ] **Step 3: Implement renewal and terminal cleanup minimally**

Add private state:

```rust
#[derive(Clone, Copy, PartialEq, Eq)]
enum TerminalCleanup {
    Required,
    Complete,
}
```

Extend `SessionState` with:

```rust
RenewalPending,
Ended(TerminalCleanup),
Invalidated(TerminalCleanup),
```

Update `phase()` and `cleanup_status()` with exhaustive matches. Define
non-cloneable `CleanupRequest` and `CleanupCompleted`, each holding private
`SessionBinding` and each with a fixed redacted custom `Debug`. Mark
`CleanupRequest` with:

```rust
#[must_use = "terminal session cleanup remains required until acknowledged"]
```

Because the actual cleanup adapter is out of scope and therefore does not yet
read `CleanupRequest.binding`, its custom `Debug` deliberately reads and
discards only the reference before emitting the fixed marker. This proves the
field is intentionally retained/redacted without suppressing `dead_code`:

```rust
impl fmt::Debug for CleanupRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _redacted_binding = &self.binding;
        formatter.write_str("CleanupRequest([REDACTED])")
    }
}
```

Modify `record_permit_received` so only `EvidenceCreated` or
`RenewalPending` are accepted. Add `begin_renewal`, accepting only `Active`.

Implement terminal methods with phase check before assignment:

```rust
pub fn end(&mut self) -> Result<CleanupRequest, TransitionError> {
    if self.state.is_terminal() {
        return Err(self.invalid_transition(SessionAction::End));
    }
    self.state = SessionState::Ended(TerminalCleanup::Required);
    Ok(CleanupRequest {
        binding: SessionBinding(self.session_id.clone()),
    })
}

pub fn invalidate(&mut self) -> Result<CleanupRequest, TransitionError> {
    if self.state.is_terminal() {
        return Err(self.invalid_transition(SessionAction::Invalidate));
    }
    self.state = SessionState::Invalidated(TerminalCleanup::Required);
    Ok(CleanupRequest {
        binding: SessionBinding(self.session_id.clone()),
    })
}
```

`SessionState::is_terminal` must explicitly classify every variant. Implement
`cleanup_request` by matching only both terminal-required variants and cloning
only the private `SessionId` into a new non-cloneable request.

Implement cleanup completion using a computed next state so assignment occurs
after both checks:

```rust
pub fn record_cleanup_completed(
    &mut self,
    capability: CleanupCompleted,
) -> Result<(), TransitionError> {
    let next_state = match self.state {
        SessionState::Ended(TerminalCleanup::Required) => {
            SessionState::Ended(TerminalCleanup::Complete)
        }
        SessionState::Invalidated(TerminalCleanup::Required) => {
            SessionState::Invalidated(TerminalCleanup::Complete)
        }
        SessionState::New
        | SessionState::ChallengeValidated
        | SessionState::CallerBound
        | SessionState::SessionPrepared
        | SessionState::EvidenceCreated
        | SessionState::PermitReceived
        | SessionState::Active
        | SessionState::RenewalPending
        | SessionState::Ended(TerminalCleanup::Complete)
        | SessionState::Invalidated(TerminalCleanup::Complete) => {
            return Err(self.invalid_transition(SessionAction::RecordCleanupCompleted));
        }
    };
    self.ensure_binding(
        SessionAction::RecordCleanupCompleted,
        &capability.binding,
    )?;
    self.state = next_state;
    Ok(())
}
```

Document retry/idempotency obligations and every error condition. Selectively
re-export `CleanupRequest` and `CleanupCompleted` from `lib.rs`.

- [ ] **Step 4: Run GREEN and crate-quality gates**

```bash
cargo fmt --all --check
cargo test -p ogir-agent session::tests --all-features
cargo clippy -p ogir-agent --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc -p ogir-agent --no-deps
```

Expected: all initial, renewal, terminal, and cleanup tests pass with no
warning or broken documentation link.

- [ ] **Step 5: Commit renewal and cleanup**

```bash
git add crates/ogir-agent/src/lib.rs crates/ogir-agent/src/session.rs \
  crates/ogir-agent/src/session/tests.rs
git diff --cached --check
git commit -m "feat: model renewal and terminal cleanup"
```

---

### Task 4: Exhaust the Finite Graph and Long Action Histories

**Files:**

- Modify: `crates/ogir-agent/src/session.rs`
- Modify: `crates/ogir-agent/src/session/tests.rs`

**Interfaces:**

- Consumes: complete Task 3 state/action API.
- Produces: independent coverage of all 120 state/action pairs, exact 26/94 success/failure counts, 1,048,576 deterministic history actions, capability substitution checks, compile-fail authority checks, and complete diagnostic redaction.

- [ ] **Step 1: Add an independent literal model and exhaustive matrix**

In `session/tests.rs`, define test-only enums independent of private
`SessionState`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModelState {
    New,
    ChallengeValidated,
    CallerBound,
    SessionPrepared,
    EvidenceCreated,
    PermitReceived,
    Active,
    RenewalPending,
    EndedRequired,
    EndedComplete,
    InvalidatedRequired,
    InvalidatedComplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestAction {
    Challenge,
    Caller,
    Preparation,
    Evidence,
    Permit,
    Activate,
    Renewal,
    End,
    Invalidate,
    CleanupComplete,
}

const MODEL_STATES: [ModelState; 12] = [
    ModelState::New,
    ModelState::ChallengeValidated,
    ModelState::CallerBound,
    ModelState::SessionPrepared,
    ModelState::EvidenceCreated,
    ModelState::PermitReceived,
    ModelState::Active,
    ModelState::RenewalPending,
    ModelState::EndedRequired,
    ModelState::EndedComplete,
    ModelState::InvalidatedRequired,
    ModelState::InvalidatedComplete,
];

const TEST_ACTIONS: [TestAction; 10] = [
    TestAction::Challenge,
    TestAction::Caller,
    TestAction::Preparation,
    TestAction::Evidence,
    TestAction::Permit,
    TestAction::Activate,
    TestAction::Renewal,
    TestAction::End,
    TestAction::Invalidate,
    TestAction::CleanupComplete,
];
```

Implement `ModelState::phase`, `cleanup_status`, and `is_nonterminal` with
exhaustive matches. Implement `TestAction::public` and `uses_capability`
exactly. The independent transition oracle is:

```rust
fn model_transition(state: ModelState, action: TestAction) -> Option<ModelState> {
    match (state, action) {
        (ModelState::New, TestAction::Challenge) => Some(ModelState::ChallengeValidated),
        (ModelState::ChallengeValidated, TestAction::Caller) => {
            Some(ModelState::CallerBound)
        }
        (ModelState::CallerBound, TestAction::Preparation) => {
            Some(ModelState::SessionPrepared)
        }
        (ModelState::SessionPrepared, TestAction::Evidence) => {
            Some(ModelState::EvidenceCreated)
        }
        (ModelState::EvidenceCreated | ModelState::RenewalPending, TestAction::Permit) => {
            Some(ModelState::PermitReceived)
        }
        (ModelState::PermitReceived, TestAction::Activate) => Some(ModelState::Active),
        (ModelState::Active, TestAction::Renewal) => Some(ModelState::RenewalPending),
        (state, TestAction::End) if state.is_nonterminal() => {
            Some(ModelState::EndedRequired)
        }
        (state, TestAction::Invalidate) if state.is_nonterminal() => {
            Some(ModelState::InvalidatedRequired)
        }
        (ModelState::EndedRequired, TestAction::CleanupComplete) => {
            Some(ModelState::EndedComplete)
        }
        (ModelState::InvalidatedRequired, TestAction::CleanupComplete) => {
            Some(ModelState::InvalidatedComplete)
        }
        (
            ModelState::New
            | ModelState::ChallengeValidated
            | ModelState::CallerBound
            | ModelState::SessionPrepared
            | ModelState::EvidenceCreated
            | ModelState::PermitReceived
            | ModelState::Active
            | ModelState::RenewalPending
            | ModelState::EndedRequired
            | ModelState::EndedComplete
            | ModelState::InvalidatedRequired
            | ModelState::InvalidatedComplete,
            TestAction::Challenge
            | TestAction::Caller
            | TestAction::Preparation
            | TestAction::Evidence
            | TestAction::Permit
            | TestAction::Activate
            | TestAction::Renewal
            | TestAction::End
            | TestAction::Invalidate
            | TestAction::CleanupComplete,
        ) => None,
    }
}
```

Implement `apply_action(&mut LocalSession, TestAction, &str) ->
Result<(), TransitionError>` by matching every action and normalizing terminal
results with `.map(|_request| ())`. Capability actions construct the exact
private capability with `binding(capability_session)`.

Add:

```rust
#[test]
fn all_120_state_action_pairs_match_the_independent_model() {
    let mut allowed = 0usize;
    let mut rejected = 0usize;

    for state in MODEL_STATES {
        for action in TEST_ACTIONS {
            let mut session = session_for_model_state("session-a", state);
            let before_phase = session.phase();
            let before_cleanup = session.cleanup_status();
            let expected = model_transition(state, action);
            let actual = apply_action(&mut session, action, "session-a");

            match expected {
                Some(next) => {
                    allowed += 1;
                    assert_eq!(actual, Ok(()), "state={state:?} action={action:?}");
                    assert_eq!(session.phase(), next.phase());
                    assert_eq!(session.cleanup_status(), next.cleanup_status());
                }
                None => {
                    rejected += 1;
                    assert_eq!(
                        actual,
                        Err(TransitionError::InvalidTransition {
                            phase: before_phase,
                            cleanup_status: before_cleanup,
                            action: action.public(),
                        }),
                        "state={state:?} action={action:?}"
                    );
                    assert_eq!(session.phase(), before_phase);
                    assert_eq!(session.cleanup_status(), before_cleanup);
                }
            }
        }
    }

    assert_eq!(allowed, 26);
    assert_eq!(rejected, 94);
}

#[test]
fn cleanup_request_exists_for_exactly_the_two_required_terminal_states() {
    let count = MODEL_STATES
        .into_iter()
        .filter(|state| {
            session_for_model_state("session-a", *state)
                .cleanup_request()
                .is_some()
        })
        .count();
    assert_eq!(count, 2);
}
```

`session_for_model_state` must reach every configuration through public
transitions and matching private test capabilities. It must not assign private
`SessionState` directly after initial fixture construction; this prevents the
matrix from testing impossible handcrafted production states.

- [ ] **Step 2: Run the exhaustive model**

```bash
cargo test -p ogir-agent session::tests::all_120_state_action_pairs_match_the_independent_model -- --exact
cargo test -p ogir-agent session::tests::cleanup_request_exists_for_exactly_the_two_required_terminal_states -- --exact
```

Expected: both pass with literal counts 26, 94, and 2. If they fail, treat the
approved spec and independent model as authority until a concrete contradiction
is reviewed.

- [ ] **Step 3: Add deterministic arbitrary sequences with binding substitution**

Add a dependency-free generator:

```rust
fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
```

For seeds `1..=4_096`, create one new actual session and `ModelState::New`.
Execute 256 actions per seed. Select `TEST_ACTIONS[random % 10]`; for every
capability action, use `session-b` when the next random bit is one and
`session-a` otherwise.

Before applying, call `model_transition`. Phase-invalid actions expect
`InvalidTransition` regardless of binding. An otherwise allowed capability
action with `session-b` expects `CapabilityRejected` and unchanged model state.
All other allowed actions update the model. Compare actual result, phase, and
cleanup status after every action.

Track these independent history facts:

```rust
struct GateHistory {
    initial_mask: u8,
    renewal_pending: bool,
    renewal_permit: bool,
}

const CHALLENGE_GATE: u8 = 1 << 0;
const CALLER_GATE: u8 = 1 << 1;
const PREPARATION_GATE: u8 = 1 << 2;
const EVIDENCE_GATE: u8 = 1 << 3;
const PERMIT_GATE: u8 = 1 << 4;
const ALL_INITIAL_GATES: u8 = CHALLENGE_GATE
    | CALLER_GATE
    | PREPARATION_GATE
    | EVIDENCE_GATE
    | PERMIT_GATE;
```

Set each bit only after its matching successful initial transition. On a
successful `Renewal`, set `renewal_pending = true` and
`renewal_permit = false`. On a successful permit whose prior model state was
`RenewalPending`, set `renewal_permit = true`. On successful activation:

- assert `initial_mask == ALL_INITIAL_GATES`;
- if `renewal_pending`, assert `renewal_permit`; and
- then clear `renewal_pending`.

Name the exact 4,096-seed × 256-action implementation
`one_million_deterministic_actions_preserve_session_invariants`.

Failure messages include only `seed`, `action_index`, model state, action, and
safe error enums—never a private identifier.

- [ ] **Step 4: Add exact capability and diagnostic privacy tests**

For every allowed capability-bearing edge (challenge, caller, preparation,
evidence, initial permit, renewal permit, and cleanup completion), add a
mismatched-session case to one table-driven test named
`every_capability_rejects_a_different_session_without_mutation`. Assert the
exact `CapabilityRejected` action plus unchanged phase/status for every row.

Add one test that constructs distinct `private-session-a` and
`private-session-b` sentinels inside the machine, every gate capability,
cleanup types, and both error variants. Format every value through `Debug` and
every error through `Display`. Assert:

- neither sentinel occurs;
- output contains only the expected type/redaction/enum vocabulary;
- no `\n`, `\r`, escape byte, `/home/`, `::error`, or `::warning` occurs; and
- `TransitionError` display is exactly one of the two approved lowercase fixed
  messages.

Name the test:

```rust
#[test]
fn every_session_diagnostic_is_context_free_and_redacted() {
    let session = session("private-session-a");
    let values = [
        format!("{session:?}"),
        format!(
            "{:?}",
            ValidatedChallenge {
                binding: binding("private-session-a"),
            }
        ),
        format!(
            "{:?}",
            BoundCaller {
                binding: binding("private-session-a"),
            }
        ),
        format!(
            "{:?}",
            PreparedSession {
                binding: binding("private-session-a"),
            }
        ),
        format!(
            "{:?}",
            CreatedEvidence {
                binding: binding("private-session-a"),
            }
        ),
        format!(
            "{:?}",
            ValidatedPermit {
                binding: binding("private-session-a"),
            }
        ),
        format!(
            "{:?}",
            CleanupRequest {
                binding: binding("private-session-a"),
            }
        ),
        format!(
            "{:?}",
            CleanupCompleted {
                binding: binding("private-session-b"),
            }
        ),
        format!(
            "{:?}",
            TransitionError::InvalidTransition {
                phase: SessionPhase::New,
                cleanup_status: CleanupStatus::NotRequired,
                action: SessionAction::Activate,
            }
        ),
        format!(
            "{:?}",
            TransitionError::CapabilityRejected {
                action: SessionAction::RecordPermitReceived,
            }
        ),
        TransitionError::InvalidTransition {
            phase: SessionPhase::New,
            cleanup_status: CleanupStatus::NotRequired,
            action: SessionAction::Activate,
        }
        .to_string(),
        TransitionError::CapabilityRejected {
            action: SessionAction::RecordPermitReceived,
        }
        .to_string(),
    ];

    let expected = [
        "LocalSession { phase: New, cleanup_status: NotRequired }",
        "ValidatedChallenge([REDACTED])",
        "BoundCaller([REDACTED])",
        "PreparedSession([REDACTED])",
        "CreatedEvidence([REDACTED])",
        "ValidatedPermit([REDACTED])",
        "CleanupRequest([REDACTED])",
        "CleanupCompleted([REDACTED])",
        "InvalidTransition { phase: New, cleanup_status: NotRequired, action: Activate }",
        "CapabilityRejected { action: RecordPermitReceived }",
        "local session transition is not allowed",
        "local session capability rejected",
    ];
    assert_eq!(values, expected);

    for value in values {
        for forbidden in [
            "private-session-a",
            "private-session-b",
            "\n",
            "\r",
            "\u{1b}",
            "/home/",
            "::error",
            "::warning",
        ] {
            assert!(!value.contains(forbidden), "forbidden diagnostic value: {forbidden:?}");
        }
    }
}
```

Also run this structural boundary scan; it is non-vacuous because the
production module must import `SessionId` but none of the forbidden payload
types:

```bash
rg -n '^use ogir_model::SessionId;$' crates/ogir-agent/src/session.rs
! rg -n -P '^use (ogir_model|ogir_protocol)::.*\b(PublisherChallenge|AccountScope|EvidenceBundle|AttestationResult|Nonce|Path|PathBuf|Process)\b|(?<!Validated)\bPermit\b' \
  crates/ogir-agent/src/session.rs
! rg -n -P '^\s+[a-z_][a-z0-9_]*:\s*.*\b(PublisherChallenge|AccountScope|EvidenceBundle|AttestationResult|Nonce|Path|PathBuf|Process)\b|(?<!Validated)\bPermit\b' \
  crates/ogir-agent/src/session.rs
```

Verify the `Permit` negative-lookbehind positive control before recording evidence:

```bash
printf '%s\n' 'Permit' | rg -q -P '(?<!Validated)\bPermit\b'
! printf '%s\n' 'ValidatedPermit' | rg -q -P '(?<!Validated)\bPermit\b'
```

- [ ] **Step 5: Add compile-fail public authority proofs**

Add `compile_fail` doctests to the relevant public items. Include each complete
external snippet:

```rust
use ogir_agent::LocalSession;
use ogir_model::SessionId;

let id = SessionId::try_from("session-a")?;
let _session = LocalSession::new(id);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Attach a separate clone compile-fail block to every authority-bearing public
type; do not group them because one compiler error could hide later types. The
exact function bodies are:

| Type | Compile-fail body |
| --- | --- |
| `LocalSession` | `fn duplicate(value: LocalSession) { let _copy = value.clone(); }` |
| `ValidatedChallenge` | `fn duplicate(value: ValidatedChallenge) { let _copy = value.clone(); }` |
| `BoundCaller` | `fn duplicate(value: BoundCaller) { let _copy = value.clone(); }` |
| `PreparedSession` | `fn duplicate(value: PreparedSession) { let _copy = value.clone(); }` |
| `CreatedEvidence` | `fn duplicate(value: CreatedEvidence) { let _copy = value.clone(); }` |
| `ValidatedPermit` | `fn duplicate(value: ValidatedPermit) { let _copy = value.clone(); }` |
| `CleanupRequest` | `fn duplicate(value: CleanupRequest) { let _copy = value.clone(); }` |
| `CleanupCompleted` | `fn duplicate(value: CleanupCompleted) { let _copy = value.clone(); }` |

Each block imports only its named type from `ogir_agent` before the function.
Because Rust requires `Clone` for `Copy`, these also prevent adding `Copy`.

For each of `ValidatedChallenge`, `BoundCaller`, `PreparedSession`,
`CreatedEvidence`, `ValidatedPermit`, `CleanupRequest`, and
`CleanupCompleted`, add its own block that imports only the named type and uses
this body:

```rust
fn reveal(value: TYPE) {
    let _binding = value.binding;
}
```

Each must fail only with private-field error E0616. Add separate `LocalSession`
blocks for direct session-ID read, session-ID replacement, and state read:

```rust
use ogir_agent::LocalSession;

fn reveal_session_id(session: &LocalSession) -> &str {
    session.session_id.as_str()
}
```

```rust
use ogir_agent::LocalSession;
use ogir_model::SessionId;

fn replace_session_id(session: &mut LocalSession, replacement: SessionId) {
    session.session_id = replacement;
}
```

```rust
use ogir_agent::LocalSession;

fn reveal_state(session: &LocalSession) {
    let _state = &session.state;
}
```

Retain one external compile-pass block that names every public authority type.
Add `every_authority_field_is_structurally_private` to pin all seven binding
fields plus `LocalSession.session_id` and `LocalSession.state` as private. This
separate runtime assertion is required because a private supporting type can
keep a compile-fail snippet green after its field becomes public. Ensure every
import resolves before the intended privacy/trait error; deleting a type must
not make a compile-fail test vacuously pass.

- [ ] **Step 6: Verify the complete model/property/privacy contract**

```bash
cargo fmt --all --check
cargo test -p ogir-agent --all-features
cargo test -p ogir-agent --doc
cargo clippy -p ogir-agent --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc -p ogir-agent --no-deps
```

Expected: the exhaustive test reports 26/94 internally, the arbitrary test
executes 1,048,576 actions, every doctest passes as compile-fail, and all
privacy/Clippy/rustdoc checks pass.

- [ ] **Step 7: Commit the proof suite**

```bash
git add crates/ogir-agent/src/session.rs crates/ogir-agent/src/session/tests.rs
git diff --cached --check
git commit -m "test: exhaust local session lifecycle invariants"
```

---

### Task 5: Add Attack Scenarios and Durable Documentation

**Files:**

- Create: `lab/scenarios/local-session-skip-permit.scenario.json`
- Create: `lab/scenarios/local-session-cross-capability.scenario.json`
- Create: `lab/scenarios/local-session-terminal-cleanup.scenario.json`
- Create: `docs/adr/0006-local-session-lifecycle-capabilities.md`
- Modify: `docs/adr/index.md`
- Modify: `docs/ROADMAP.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/THREAT_MODEL.md`
- Modify: `docs/TEST_STRATEGY.md`

**Interfaces:**

- Consumes: passing Task 4 executable graph and existing attack-scenario schema/registries.
- Produces: machine-readable threat mapping and human-reviewable authoritative lifecycle documentation.

- [ ] **Step 1: Add three machine-readable scenarios**

Create `local-session-skip-permit.scenario.json`:

```json
{
  "id": "OGIR-SESSION-GATE-SKIP-001",
  "title": "Skip permit receipt before local session activation",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["protected_session_authorization"],
  "preconditions": ["a local session has not consumed a matching validated permit capability"],
  "steps": ["skip one or more admission gates", "request transition to Active"],
  "expected": {
    "decision": "deny",
    "reason": "invalid-transition",
    "automatic_ban": false
  },
  "invariants": [
    "Active is reachable only after challenge, caller, preparation, evidence, and permit gates",
    "transition rejection does not mutate the local session"
  ],
  "residual_risk": ["a compromised trusted local adapter can violate its capability-minting contract"]
}
```

Create `local-session-cross-capability.scenario.json`:

```json
{
  "id": "OGIR-SESSION-CAPABILITY-SUBSTITUTION-001",
  "title": "Use one local session capability on another session",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["protected_session_authorization", "local_session_identity"],
  "preconditions": ["a valid completion capability exists for local session-A"],
  "steps": ["present the session-A capability to the state machine for session-B"],
  "expected": {
    "decision": "deny",
    "reason": "capability-rejected",
    "automatic_ban": false
  },
  "invariants": [
    "every authority-bearing capability is bound to exactly one local SessionId",
    "capability rejection preserves phase and cleanup status"
  ],
  "residual_risk": ["the trusted local owner must avoid creating multiple authoritative machines for one SessionId"]
}
```

Create `local-session-terminal-cleanup.scenario.json`:

```json
{
  "id": "OGIR-SESSION-TERMINAL-CLEANUP-001",
  "title": "Reactivate a terminal session or abandon required cleanup",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["protected_session_authorization", "host_policy_noninterference"],
  "preconditions": ["a local session entered Ended or Invalidated"],
  "steps": [
    "request renewal, permit receipt, or activation after terminal entry",
    "drop one cleanup request and request a retry while cleanup remains required",
    "acknowledge cleanup with a capability from another session"
  ],
  "expected": {
    "decision": "deny",
    "reason": "terminal-session-cleanup-required",
    "automatic_ban": false
  },
  "invariants": [
    "terminal lifecycle disposition never changes",
    "cleanup remains Required until matching trusted completion",
    "cleanup request retry never permits reactivation"
  ],
  "residual_risk": ["actual idempotent cleanup and crash recovery require a later trusted adapter"]
}
```

- [ ] **Step 2: Verify scenarios before documentation claims**

```bash
python3 scripts/check-attack-scenario-traceability.py
git diff --check
```

Expected: validator passes for nine scenarios with no schema/registry change.

- [ ] **Step 3: Commit executable scenarios**

```bash
git add lab/scenarios/local-session-*.scenario.json
git diff --cached --check
git commit -m "test: trace local session lifecycle attacks"
```

- [ ] **Step 4: Correct roadmap and architecture graph text**

Replace the ambiguous local-session roadmap graph with:

```text
New
 -> ChallengeValidated
 -> CallerBound
 -> SessionPrepared
 -> EvidenceCreated
 -> PermitReceived
 -> Active

Active -> RenewalPending -> PermitReceived -> Active

any nonterminal phase -> Ended | Invalidated
Ended | Invalidated: lifecycle-terminal; cleanup Required -> Complete
```

In `docs/ARCHITECTURE.md`, add a `Local session lifecycle authority` subsection
after `LocalSessionDescriptor`. State exactly:

- trusted local adapters mint opaque completion capabilities;
- every capability is privately bound to one `SessionId` and consumed once;
- the pure state machine owns ordering but no raw operation payload or I/O;
- renewal reuses the permit-received/activation gates; and
- terminal cleanup status is orthogonal and cannot reactivate lifecycle state.

- [ ] **Step 5: Add threat and test traceability**

In `docs/THREAT_MODEL.md`, add a principal threat titled `Local session gate
bypass or stranded cleanup`. Its required response must name the private
checked graph, session-bound capability rejection, fresh renewal permit,
permanent terminality, cleanup Required/Complete status, idempotent retry
obligation, and non-disciplinary failure.

In `docs/TEST_STRATEGY.md`:

- add the 12 × 10 = 120 matrix with 26 success/94 rejection under unit tests;
- add 4,096 × 256 fixed-seed sequences under property tests;
- add capability/constructor compile-fail and diagnostic allowlist coverage;
- add the named gate/binding/terminal/cleanup/redaction mutations; and
- list all three scenario IDs in the attack-scenario mapping.

Do not claim actual process-policy cleanup or production adapter coverage.

- [ ] **Step 6: Write ADR-0006 and index it atomically**

Create `docs/adr/0006-local-session-lifecycle-capabilities.md` from the template
with:

- Status `Accepted`, date `2026-08-26`, owners `Initial maintainer`, related
  issue link to local M1-009, no supersession.
- Context: boolean drift, dynamic runtime events, missing renewal-success edge,
  and implicit-cleanup failure.
- Drivers: fail-closed authorization, exact session binding, runtime
  orchestration, terminal cleanup, privacy, no dependencies, exhaustive tests.
- Options: checked private runtime enum selected; pure typestate, dual API,
  concrete permit, public/unbound capability, implicit/one-shot cleanup, and
  new crate rejected with the spec's reasons.
- Decision: exact initial/renewal/terminal graph, crate-confined trusted
  construction authority, opaque non-cloneable session-bound capabilities,
  state-preserving errors, and cleanup Required/Complete.
- Consequences: clear finite audit surface and retryable cleanup; trusted
  adapters remain TCB and actual I/O remains future work.
- Threat impact: A1 gate/substitution/reactivation narrowed; A4 adapter
  compromise and cleanup crash remain residual; failures non-disciplinary.
- Privacy: only private SessionId plus enums; fixed redacted diagnostics; no raw
  challenge/account/evidence/permit/key/process/path fields.
- Dependencies: standard library plus existing `SessionId`; no package or
  license change.
- Validation: exact 120/26/94 counts, one-million actions, compile-fail,
  diagnostics, scenarios, mutations, full gate, independent review.
- Rollback: disable protected mode or supersede ADR; never bypass gates or mark
  cleanup implicitly complete.
- Primary sources: approved spec/project authority and exact Rust 1.98 URLs.

Append this exact index row:

```markdown
| [ADR-0006](0006-local-session-lifecycle-capabilities.md) | Accepted | A private checked runtime graph and session-bound capabilities govern local lifecycle and cleanup. | None | None |
```

- [ ] **Step 7: Verify and commit durable documentation**

```bash
./scripts/check-adr-index.sh
python3 scripts/check-attack-scenario-traceability.py
git diff --check
rg -n 'RenewalPending -> PermitReceived -> Active|120|26|94|1,048,576|CleanupStatus' \
  docs/ROADMAP.md docs/ARCHITECTURE.md docs/THREAT_MODEL.md docs/TEST_STRATEGY.md \
  docs/adr/0006-local-session-lifecycle-capabilities.md
git add docs/ROADMAP.md docs/ARCHITECTURE.md docs/THREAT_MODEL.md \
  docs/TEST_STRATEGY.md docs/adr/0006-local-session-lifecycle-capabilities.md \
  docs/adr/index.md
git diff --cached --check
git commit -m "docs: record local session lifecycle decision"
```

---

### Task 6: Prove Mutation Resistance, Review, and Move the Issue to Review

**Files:**

- Modify if gaps are found: `crates/ogir-agent/src/session.rs`
- Modify if gaps are found: `crates/ogir-agent/src/session/tests.rs`
- Modify if a durable lesson is found: `docs/LESSONS_LEARNED.md`
- Modify after all evidence passes: `planning/issues/009-local-session-state-machine.md`

**Interfaces:**

- Consumes: complete implementation, tests, scenarios, ADR, and ready live issue.
- Produces: mutation evidence, independent TCB/privacy review closure, full-gate evidence, and exact local/live `needs-review` issue state.

- [ ] **Step 1: Freeze a clean pre-mutation head**

```bash
git status --short --branch
mutation_base="$(git rev-parse HEAD)"
mutation_parent="$(mktemp -d)"
printf 'mutation_base=%s\nmutation_parent=%s\n' "${mutation_base}" "${mutation_parent}"
```

Expected: clean branch. Record `mutation_parent` exactly; never substitute the
repository root, `$HOME`, or an unresolved variable into removal commands.

- [ ] **Step 2: Run one isolated disposable worktree per named mutation**

For each row below:

1. assign the table row's two-digit probe number to `probe_index`, create
   `probe="${mutation_parent}/probe-${probe_index}"`, and run
   `git worktree add --detach "${probe}" "${mutation_base}"`;
2. use `apply_patch` only inside that explicit probe path;
3. run the named focused test, require at least one test to execute, and require
   nonzero status for the intended assertion or diagnostic;
4. record the failing test/output summary; and
5. run `git worktree remove --force "${probe}"` before the next row.

| Probe | Mutation | Required failing test |
| --- | --- | --- |
| `01` | Allow `record_evidence_created` from `CallerBound` | `all_120_state_action_pairs_match_the_independent_model` |
| `02` | Allow `record_permit_received` from `SessionPrepared` | exhaustive matrix and early-Active history assertion |
| `03` | Allow `activate` from `EvidenceCreated` | exhaustive matrix and initial gate history |
| `04` | Allow `activate` from `RenewalPending` | renewal test and arbitrary history |
| `05` | Make `SessionBinding::matches` always true | `every_capability_rejects_a_different_session_without_mutation` |
| `06` | In `record_challenge_validated`, assign `ChallengeValidated` before `ensure_binding` | `every_capability_rejects_a_different_session_without_mutation` |
| `07` | Permit renewal outside `Active` | exhaustive matrix |
| `08` | Permit `activate` from `Ended(TerminalCleanup::Required)` | `all_120_state_action_pairs_match_the_independent_model` |
| `09` | Make `end` set `TerminalCleanup::Complete` | `every_nonterminal_phase_can_end_with_cleanup_required` |
| `10` | Make `cleanup_request` return `None` for `Ended(TerminalCleanup::Required)` | `cleanup_request_exists_for_exactly_the_two_required_terminal_states` |
| `11` | Accept duplicate or nonterminal cleanup completion | exhaustive matrix |
| `12` | Change `Ended(Required)` cleanup completion to `Active` | `matching_cleanup_completion_preserves_terminal_disposition` and arbitrary property |
| `13` | Derive `Clone` for `LocalSession`, `ValidatedPermit`, and `CleanupRequest` | the three clone compile-fail doctests |
| `14` | Make `ValidatedPermit.binding` public | `every_authority_field_is_structurally_private` |
| `15` | Make `LocalSession.state` public | `every_authority_field_is_structurally_private` |
| `16` | Add raw `self.session_id.as_str()` to `LocalSession` `Debug` | `every_session_diagnostic_is_context_free_and_redacted` |
| `17` | Allow `record_caller_bound` from `New` | exhaustive matrix |
| `18` | Allow `record_session_prepared` from `ChallengeValidated` | exhaustive matrix |
| `19` | Allow `record_evidence_created` from `ChallengeValidated` | exhaustive matrix |
| `20` | Make `invalidate` set `TerminalCleanup::Complete` | `every_nonterminal_phase_can_invalidate_with_cleanup_required` |
| `21` | Make `LocalSession.session_id` public | structural privacy test plus external session-ID read/write compile-fail doctests |
| `22` | Make `CleanupCompleted.binding` public | `every_authority_field_is_structurally_private` |
| `23` | Make `ValidatedChallenge.binding` public | `every_authority_field_is_structurally_private` |
| `24` | Make `BoundCaller.binding` public | `every_authority_field_is_structurally_private` |
| `25` | Make `PreparedSession.binding` public | `every_authority_field_is_structurally_private` |
| `26` | Make `CreatedEvidence.binding` public | `every_authority_field_is_structurally_private` |
| `27` | Make `CleanupRequest.binding` public | `every_authority_field_is_structurally_private` |

The table contains exactly 27 probes. The external compile-pass doctest proves
all authority-bearing types remain nameable, separate compile-fail doctests
prove each private binding cannot be read and the session ID cannot be read or
replaced, and the structural privacy test prevents a private supporting type
from masking a public-field mutation.

If any mutation passes, remove the disposable worktree, add a focused RED
regression in the primary worktree, implement only the needed correction, run
GREEN/full focused gates, append a factual lesson if durable, and commit the
gap separately before restarting the complete mutation table.

- [ ] **Step 3: Prove mutation cleanup did not alter the branch**

```bash
test "$(git rev-parse HEAD)" = "${mutation_base}"
git status --short
git worktree list --porcelain
rmdir "${mutation_parent}"
```

Expected: primary branch unchanged/clean; no probe worktree remains; the empty
explicit temp parent is removed.

- [ ] **Step 4: Run full final verification**

```bash
./scripts/check.sh
cargo test --workspace --all-features --release
git diff --check 34ce07e7e0433ed9ef34fdcb08d8d0cac7117c43..HEAD
git fsck --no-dangling
git status --short --branch
```

Expected: full gate and optimized workspace tests pass, no diff whitespace,
repository object graph valid, and worktree clean.

- [ ] **Step 5: Obtain fresh independent standards/spec and TCB/privacy review**

Invoke the `requesting-code-review` skill with exact base
`34ce07e7e0433ed9ef34fdcb08d8d0cac7117c43`, exact current head, M1-009 local
issue, and approved spec. Require reviewers to attack:

- every skipped/duplicated gate and renewal shortcut;
- cross-session and same-ID lifecycle duplication assumptions;
- state mutation before rejection;
- terminal reactivation and cleanup completion bypass;
- dropped/reissued cleanup requests and idempotency obligation;
- public construction, cloning, private-field access, and diagnostic leakage;
- model/oracle coupling, vacuous compile-fail/privacy tests, and surviving
  mutations; and
- documentation/scenario/ADR drift.

Fix every Critical/Important finding test-first. Rerun Tasks 4–6 after any
source/semantic change until the verdict is Yes with no findings.

- [ ] **Step 6: Move the local issue to needs-review only after evidence**

Change only the issue metadata comment from `status: ready` to
`status: needs-review`. Add a concise `## Implementation evidence` section with
exact test counts, commands, scenario IDs, mutation count, ADR, review verdict,
and residual trusted-adapter/actual-cleanup scope.

```bash
git add planning/issues/009-local-session-state-machine.md
git diff --cached --check
git commit -m "chore: mark M1-009 ready for review"
```

- [ ] **Step 7: Guardedly synchronize the exact live issue**

Derive the issue number by exact title, require exactly one match, and compare
the live ready body to the parent of the needs-review commit:

```bash
issue_title='M1-009: Implement the local protected-session state machine'
issue_json="$(gh issue list --repo archledger/open-game-integrity-runtime \
  --state all --limit 100 --json number,title,state,labels,milestone \
  --jq "[.[] | select(.title == \"${issue_title}\")]")"
test "$(jq 'length' <<<"${issue_json}")" -eq 1
issue_number="$(jq -r '.[0].number' <<<"${issue_json}")"
test "$(jq -r '.[0].state' <<<"${issue_json}")" = 'OPEN'
test "$(jq -r '.[0].milestone.title' <<<"${issue_json}")" = 'M1 Domain Model'

ready_body="/tmp/ogir-m1-009-ready-body-${issue_number}.md"
live_body="/tmp/ogir-m1-009-live-body-${issue_number}.md"
git show HEAD^:planning/issues/009-local-session-state-machine.md >"${ready_body}"
gh api "repos/archledger/open-game-integrity-runtime/issues/${issue_number}" \
  | jq -j '.body' >"${live_body}"
test "$(sha256sum "${ready_body}" | cut -d' ' -f1)" = \
  "$(sha256sum "${live_body}" | cut -d' ' -f1)"
test "$(git ls-remote origin refs/heads/main | cut -f1)" = \
  "$(git rev-parse origin/main)"
```

Then write only the reviewed body/status transition:

```bash
gh issue edit "${issue_number}" --repo archledger/open-game-integrity-runtime \
  --body-file planning/issues/009-local-session-state-machine.md \
  --remove-label 'status: ready' \
  --add-label 'status: needs-review'
```

Read back exact body hash and require it equals the working-tree file. Require
exactly the six non-status labels plus `status: needs-review`, milestone
`M1 Domain Model`, state `OPEN`, and unchanged remote main. Record the old/new
hashes and exact restore command (parent body plus ready/needs-review label
swap) in Shared Memory.

---

### Task 7: Freeze DCO, Publish, and Hand Off for Human Review

**Files:**

- No source change unless review/check feedback requires a new test-first commit.

**Interfaces:**

- Consumes: clean final unsigned range, all green checks, exact issue needs-review state.
- Produces: human-certified metadata-only rewrite, remote branch, reviewable PR, and exact rollback evidence.

- [ ] **Step 1: Freeze and print the exact unsigned certification range**

```bash
base=34ce07e7e0433ed9ef34fdcb08d8d0cac7117c43
head="$(git rev-parse HEAD)"
count="$(git rev-list --count "${base}..${head}")"
git status --short --branch
git log --reverse --format='%H %s' "${base}..${head}"
printf 'I certify the %s commits in %s..%s under the DCO.\n' \
  "${count}" "${base:0:7}" "${head:0:7}"
```

Stop and obtain that exact human sentence. Generic approval is not DCO
certification. Do not add any trailer before it.

- [ ] **Step 2: After certification, create immutable rollback evidence**

```bash
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_ref="refs/backup/pre-m1-009-dco/${stamp}/tip"
backup_dir='/home/wisbfime/Open Game Intergrity Runtime  - Github Project/backups'
bundle="${backup_dir}/ogir-m1-009-pre-dco-${stamp}.bundle"
manifest="${bundle}.sha256"
old_sequence="/tmp/ogir-m1-009-${stamp}-old-tree-subjects.tsv"

test "$(git rev-parse HEAD)" = "${head}"
test -d "${backup_dir}"
test ! -e "${bundle}"
git update-ref "${backup_ref}" "${head}"
git log --reverse --format='%T%x09%s' "${base}..${backup_ref}" >"${old_sequence}"
git bundle create "${bundle}" "${backup_ref}" refs/heads/main
git bundle verify "${bundle}"
sha256sum "${bundle}" >"${manifest}"
sha256sum --check "${manifest}"
test "$(git rev-parse "${backup_ref}")" = "${head}"
```

Record the exact ref, bundle, manifest, and hash in Shared Memory before
rewriting. These task-specific explicit paths are the rollback boundary.

- [ ] **Step 3: Rewrite commit metadata only with the one permitted identity**

Set author/committer identity to:

```text
Wisbendji Fimerlus <archledger236@gmail.com>
```

Rebase the exact frozen range with `--signoff` and command-scoped identity:

```bash
git -c user.name='Wisbendji Fimerlus' \
  -c user.email='archledger236@gmail.com' \
  rebase --exec "git -c user.name='Wisbendji Fimerlus' -c user.email='archledger236@gmail.com' commit --amend --no-edit --signoff" \
  "${base}"
```

Never use `archledger <archledger236@gmail.com>`. Verify every rewritten
commit and immutable sequence:

```bash
new_head="$(git rev-parse HEAD)"
new_sequence="/tmp/ogir-m1-009-${stamp}-new-tree-subjects.tsv"
git log --reverse --format='%T%x09%s' "${base}..${new_head}" >"${new_sequence}"
diff -u "${old_sequence}" "${new_sequence}"
test "$(git rev-list --count "${base}..${new_head}")" -eq "${count}"
test "$(git rev-list --min-parents=2 "${base}..${new_head}" | wc -l)" -eq 0

while IFS= read -r commit; do
  test "$(git show -s --format='%cn <%ce>' "${commit}")" = \
    'Wisbendji Fimerlus <archledger236@gmail.com>'
  test "$(git show -s --format=%B "${commit}" | \
    rg -x -c 'Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>')" -eq 1
  ! git show -s --format=%B "${commit}" | \
    rg -x 'Signed-off-by: archledger <archledger236@gmail.com>'
done < <(git rev-list --reverse "${base}..${new_head}")

./scripts/check-dco.sh "${base}" "${new_head}"
```

This must prove:

- same ordered subject;
- same ordered tree;
- same linear topology/no merge commits;
- exact one `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>`;
- no forbidden trailer identity; and
- local DCO gate passes the complete range.

- [ ] **Step 4: Re-run all gates on rewritten SHAs and obtain fresh review**

```bash
./scripts/check.sh
cargo test --workspace --all-features --release
git fsck --no-dangling
git status --short --branch
```

Compare the new range against the backup tree/subject sequence and request a
fresh exact-SHA review. Metadata equivalence does not replace rerunning tests.

- [ ] **Step 5: Guardedly publish without force**

Require remote main unchanged, remote feature branch absent, exact local DCO
pass, clean status, and issue needs-review. Then:

```bash
git push -u origin research/m1-009-local-session-state-machine
```

Create `/tmp/ogir-m1-009-pr.md` with `apply_patch`, using the repository PR
template headings. Include exact issue, spec, ADR, graph, 120/26/94 counts,
one-million-action property, mutation/scenario/review evidence, dependencies
unchanged, and human review/responsibility boxes left unchecked. Then:

```bash
gh pr create --repo archledger/open-game-integrity-runtime \
  --base main \
  --head research/m1-009-local-session-state-machine \
  --title 'M1-009: Implement the local protected-session state machine' \
  --body-file /tmp/ogir-m1-009-pr.md
pr_number="$(gh pr view --repo archledger/open-game-integrity-runtime \
  --json number --jq '.number')"
test -n "${pr_number}"
```

- [ ] **Step 6: Watch and diagnose every remote check**

```bash
gh pr checks --watch --repo archledger/open-game-integrity-runtime "${pr_number}"
```

For failures, use `gh-fix-ci`: inspect exact GitHub Actions logs, propose the
minimal test-first fix, and obtain explicit approval before source changes. For
review comments, use `gh-address-comments`: classify each technically, resolve
only after an exact fix or evidence-backed response, and verify zero unresolved
threads.

- [ ] **Step 7: Hand the exact PR to the human; do not merge autonomously**

Report PR URL/head/tree, issue URL/state, checks, unresolved thread/alert count,
backup ref/bundle/hash, exact test evidence, residual risks, and the fact that
actual trusted adapters/cleanup I/O remain out of scope. Merge only after the
user's explicit line-by-line responsibility and merge approval.

---

## Plan Self-Review Checklist

- [x] Every approved spec section maps to at least one task and one executable check.
- [x] The eight progression edges, 16 terminal-entry pairs, and two cleanup-completion pairs total exactly 26 successes; the other 94 of 120 reject.
- [x] All type/method/action names are identical across Tasks 2–7.
- [x] No task adds a dependency, parser, serializer, I/O, async, TPM, process, policy, signature, or public construction authority.
- [x] Every capability/session/cleanup authority is non-cloneable and redacted; safe enums alone are `Copy`.
- [x] Tests avoid `unwrap`/`expect`, construct private fixtures only as a child module, and do not depend on production factories.
- [x] Compile-fail and privacy tests have positive existence/private-sentinel controls and are not vacuous.
- [x] Every mutation has an exact target and named failing regression.
- [x] Live issue writes have exact read-only preconditions and readback/rollback evidence.
- [x] Every planned commit omits `-s`; DCO rewrite is gated on exact human certification and exact permitted identity.
- [x] Placeholder scan, staged diff check, full repository gate, and clean status run before committing this plan.
