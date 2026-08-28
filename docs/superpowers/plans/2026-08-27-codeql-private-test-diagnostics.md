# Privacy-Test Assertion Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure OGIR privacy/redaction tests cannot print the private value they are testing when an assertion fails, while preserving every existing privacy expectation.

**Architecture:** Keep the correction entirely in existing tests and documentation. Convert only privacy-bearing equality and containment checks to boolean assertions with fixed generic panic text; retain CodeQL alerts #43/#44 as the scanner RED evidence and use existing crate tests plus full repository gates as behavioral preservation evidence.

**Tech Stack:** Rust 1.98.0, Cargo workspace tests, GitHub CodeQL 2.26.4, repository shell gates.

**Spec:** `docs/superpowers/specs/2026-08-27-codeql-private-test-diagnostics-design.md`

## Global Constraints

- Exact base: merged `main` commit `25030e1af6a437472e27c5e842f4251222d4c6fe`.
- Assigned issue: #18, `https://github.com/archledger/open-game-integrity-runtime/issues/18`.
- Change only planning, test, `docs/TEST_STRATEGY.md`, and `docs/LESSONS_LEARNED.md` files.
- Preserve production source bytes, public APIs, expected redaction strings, forbidden fixture sets, loops, fixtures, and functional assertions.
- Add no dependency, workflow, CodeQL configuration, suppression, exclusion, dismissal, scenario, macro, helper crate, `unsafe`, cryptography, I/O, or trust-boundary change.
- Do not mechanically rewrite assertions whose operands cannot carry private fixture data.
- Assertion failure text may name the privacy-check class but must not format either operand, a forbidden fixture, or the diagnostic under test.
- Keep all implementation commits unsigned until the human certifies the exact frozen range under DCO 1.1.
- Stop before DCO rewriting, push, pull-request creation, alert dismissal, or merge.

---

### Task 1: Freeze Planning And Scanner RED Evidence

**Files:**
- Create: `planning/issues/codeql-private-test-diagnostics.md`
- Create: `docs/superpowers/specs/2026-08-27-codeql-private-test-diagnostics-design.md`
- Create: `docs/superpowers/plans/2026-08-27-codeql-private-test-diagnostics.md`

**Interfaces:**
- Consumes: merged `main` at `25030e1a`, open CodeQL alerts #43/#44, approved design.
- Produces: exact local/live issue #18, implementation spec, and this executable plan.

- [ ] **Step 1: Verify exact branch base and clean isolation**

Run:

```bash
test "$(git rev-parse HEAD)" = 25030e1af6a437472e27c5e842f4251222d4c6fe
test "$(git branch --show-current)" = fix/codeql-private-test-diagnostics
git status --short
```

Expected: both guards return zero; status lists only the three planning files.

- [ ] **Step 2: Verify the live issue is exact and correctly classified**

Run:

```bash
local_body=$(base64 -w0 planning/issues/codeql-private-test-diagnostics.md)
live_body=$(gh issue view 18 --repo archledger/open-game-integrity-runtime --json body --jq '.body|@base64')
test "$local_body" = "$live_body"
gh issue view 18 --repo archledger/open-game-integrity-runtime \
  --json state,labels,milestone \
  --jq '{state,labels:[.labels[].name]|sort,milestone:.milestone.title}'
```

Expected: exact body equality; issue is `OPEN`, milestone is `M1 Domain Model`, and labels are exactly `area: privacy`, `risk: privacy`, `status: needs-review`, and `type: test`.

- [ ] **Step 3: Reconfirm scanner RED without mutating alert state**

Run:

```bash
gh api 'repos/archledger/open-game-integrity-runtime/code-scanning/alerts?state=open&ref=refs/heads/main' \
  --jq 'map(select(.number == 43 or .number == 44) | {number,rule:.rule.id,state,dismissed_at,location:.most_recent_instance.location})'
```

Expected: alerts #43/#44 are open `rust/cleartext-logging` results in `freshness.rs`, with `dismissed_at: null`.

- [ ] **Step 4: Reproduce the assertion behavior outside the repository tree**

Run:

```bash
rustc --edition=2024 -o /tmp/opencode/ogir-assert-custom-repro - <<'RS'
fn main() {
    let sensitive = "private-account";
    assert!(false, "debug output exposed {sensitive}");
}
RS
! /tmp/opencode/ogir-assert-custom-repro 2> /tmp/opencode/ogir-assert-custom.stderr

rustc --edition=2024 -o /tmp/opencode/ogir-assert-eq-repro - <<'RS'
fn main() {
    let diagnostic = "AccountScope(private-account)";
    assert_eq!(diagnostic, "AccountScope([REDACTED])");
}
RS
! /tmp/opencode/ogir-assert-eq-repro 2> /tmp/opencode/ogir-assert-eq.stderr

rustc --edition=2024 -o /tmp/opencode/ogir-assert-safe-repro - <<'RS'
fn main() {
    let diagnostic = "AccountScope(private-account)";
    assert!(
        diagnostic == "AccountScope([REDACTED])",
        "private diagnostic mismatch"
    );
}
RS
! /tmp/opencode/ogir-assert-safe-repro 2> /tmp/opencode/ogir-assert-safe.stderr

rg -F 'private-account' /tmp/opencode/ogir-assert-custom.stderr
rg -F 'AccountScope(private-account)' /tmp/opencode/ogir-assert-eq.stderr
rg -F 'private diagnostic mismatch' /tmp/opencode/ogir-assert-safe.stderr
! rg -F 'private-account' /tmp/opencode/ogir-assert-safe.stderr
```

Expected: the first prints `private-account`, the second prints `AccountScope(private-account)`, and the third prints only `private diagnostic mismatch`. This is characterization evidence, not a committed test or production change.

- [ ] **Step 5: Check planning files and commit them unsigned**

Run:

```bash
git diff --check
git diff -- planning/issues/codeql-private-test-diagnostics.md \
  docs/superpowers/specs/2026-08-27-codeql-private-test-diagnostics-design.md \
  docs/superpowers/plans/2026-08-27-codeql-private-test-diagnostics.md
git add planning/issues/codeql-private-test-diagnostics.md \
  docs/superpowers/specs/2026-08-27-codeql-private-test-diagnostics-design.md \
  docs/superpowers/plans/2026-08-27-codeql-private-test-diagnostics.md
git commit --no-gpg-sign -m "test: plan private diagnostic hardening"
```

Expected: one unsigned planning-only commit; no source or test file is staged.

---

### Task 2: Harden Model And Protocol Privacy Assertions

**Files:**
- Modify: `crates/ogir-model/src/lib.rs:627-630`
- Modify: `crates/ogir-model/tests/identifiers.rs:202-240,243-252,261-286`
- Modify: `crates/ogir-model/tests/session_public_key_id.rs:1577-1610`
- Modify: `crates/ogir-protocol/tests/evidence_profile.rs:21-37`

**Interfaces:**
- Consumes: existing formatted `String` diagnostics and literal redaction expectations.
- Produces: unchanged privacy predicates with fixed generic failure text and no operand-printing equality macro.

- [ ] **Step 1: Record the RED and behavioral baseline**

Run:

```bash
gh api repos/archledger/open-game-integrity-runtime/code-scanning/alerts/43 --jq '{number,state,dismissed_at,rule:.rule.id}'
cargo test -p ogir-model tests::debug_output_redacts_nonce_bytes -- --exact
cargo test -p ogir-model --test identifiers privacy_sensitive_debug_output_is_redacted -- --exact
cargo test -p ogir-model --test identifiers validation_errors_never_echo_hostile_input -- --exact
cargo test -p ogir-model --test identifiers publisher_challenge_uses_typed_ids_and_redacts_complete_binding -- --exact
cargo test -p ogir-model --test session_public_key_id debug_is_exact_fixed_redaction_for_real_sentinel_bytes -- --exact
cargo test -p ogir-protocol --test evidence_profile evidence_bundle_debug_redacts_profile_and_payload -- --exact
```

Expected: alert #43 remains open/undismissed as scanner RED; all existing behavioral tests pass before edits.

- [ ] **Step 2: Replace the model unit-test equality sink**

Use exactly:

```rust
assert!(
    format!("{nonce:?}") == "Nonce([REDACTED; 32])",
    "private diagnostic mismatch"
);
```

- [ ] **Step 3: Replace identifier exact-redaction equality sinks**

Use fixed-message boolean assertions for the ten formatted values:

```rust
assert!(format!("{publisher:?}") == "PublisherId([REDACTED])", "private diagnostic mismatch");
assert!(format!("{game:?}") == "GameId([REDACTED])", "private diagnostic mismatch");
assert!(format!("{build:?}") == "BuildId([REDACTED])", "private diagnostic mismatch");
assert!(format!("{account:?}") == "AccountScope([REDACTED])", "private diagnostic mismatch");
assert!(format!("{match_id:?}") == "MatchId([REDACTED])", "private diagnostic mismatch");
assert!(format!("{session:?}") == "SessionId([REDACTED])", "private diagnostic mismatch");
assert!(format!("{policy:?}") == "PolicyId([REDACTED])", "private diagnostic mismatch");
assert!(format!("{policy_version:?}") == "PolicyVersion([REDACTED])", "private diagnostic mismatch");
assert!(format!("{:?}", window.issued_at()) == "UnixTime([REDACTED])", "private diagnostic mismatch");
assert!(format!("{window:?}") == "ChallengeWindow([REDACTED])", "private diagnostic mismatch");
```

Leave the two message-free hostile-input containment assertions unchanged: their panic text contains only the source expression, not either runtime value. Replace the challenge aggregate comparison with:

```rust
assert!(
    debug == "PublisherChallenge([REDACTED])",
    "private diagnostic mismatch"
);
```

- [ ] **Step 4: Replace session-key and evidence equality sinks**

Use:

```rust
assert!(
    format!("{identifier:?}") == "SessionPublicKeyId([REDACTED; 32])",
    "private diagnostic mismatch"
);
```

```rust
assert!(
    diagnostic == "SessionPublicKeyId([REDACTED; 32])",
    "private diagnostic mismatch"
);
```

```rust
assert!(
    diagnostic == "EvidenceBundle([REDACTED])",
    "private diagnostic mismatch"
);
```

Keep the existing message-free containment checks unchanged.

- [ ] **Step 5: Format and run affected model/protocol tests**

Run:

```bash
cargo fmt --all -- --check
cargo test -p ogir-model tests::debug_output_redacts_nonce_bytes -- --exact
cargo test -p ogir-model --test identifiers privacy_sensitive_debug_output_is_redacted -- --exact
cargo test -p ogir-model --test identifiers validation_errors_never_echo_hostile_input -- --exact
cargo test -p ogir-model --test identifiers publisher_challenge_uses_typed_ids_and_redacts_complete_binding -- --exact
cargo test -p ogir-model --test session_public_key_id all_8192_position_value_cases_round_trip_without_normalization -- --exact
cargo test -p ogir-model --test session_public_key_id debug_is_exact_fixed_redaction_for_real_sentinel_bytes -- --exact
cargo test -p ogir-protocol --test evidence_profile evidence_bundle_debug_redacts_profile_and_payload -- --exact
```

Expected: formatting and all seven tests pass without warnings.

- [ ] **Step 6: Review and commit the model/protocol change unsigned**

Run:

```bash
git diff --check
git diff -- crates/ogir-model/src/lib.rs crates/ogir-model/tests/identifiers.rs \
  crates/ogir-model/tests/session_public_key_id.rs crates/ogir-protocol/tests/evidence_profile.rs
git add crates/ogir-model/src/lib.rs crates/ogir-model/tests/identifiers.rs \
  crates/ogir-model/tests/session_public_key_id.rs crates/ogir-protocol/tests/evidence_profile.rs
git commit --no-gpg-sign -m "test: redact model assertion failures"
```

Expected: one unsigned test-only commit preserving all compared values.

---

### Task 3: Harden Agent And Verifier Privacy Assertions

**Files:**
- Modify: `crates/ogir-agent/src/session/tests.rs:847-879`
- Modify: `crates/ogir-verifier/src/verification/tests.rs:1828-1865`
- Modify: `crates/ogir-verifier/tests/freshness.rs:752-849`
- Modify: `crates/ogir-verifier/tests/verification_public.rs:64-73`

**Interfaces:**
- Consumes: existing arrays and strings for session, verifier-flow, replay, and public-flow diagnostics.
- Produces: identical equality/containment predicates with fixed generic panic text.

- [ ] **Step 1: Record affected behavioral baseline**

Run:

```bash
cargo test -p ogir-agent session::tests::every_session_diagnostic_is_context_free_and_redacted -- --exact
cargo test -p ogir-verifier verification::tests::every_flow_capability_outcome_and_error_diagnostic_is_redacted -- --exact
cargo test -p ogir-verifier --test freshness replay_debug_and_errors_redact_every_binding_and_timestamp -- --exact
cargo test -p ogir-verifier --test verification_public new_flow_exposes_only_received_phase_and_no_outcome -- --exact
```

Expected: all four existing behavioral tests pass before edits; alerts #43/#44 remain external RED evidence.

- [ ] **Step 2: Replace the agent diagnostic sinks**

Replace the array equality and custom forbidden message with:

```rust
assert!(values == expected, "private diagnostic mismatch");
```

```rust
assert!(
    !value.contains(forbidden),
    "private diagnostic exposed a forbidden value"
);
```

Do not alter either array or either loop.

- [ ] **Step 3: Replace the verifier-flow custom failure message**

Use:

```rust
assert!(
    !diagnostic.contains(sentinel),
    "private diagnostic exposed a forbidden value"
);
```

Keep all forbidden sentinel literals and both loops unchanged.

- [ ] **Step 4: Replace the freshness privacy sinks**

Replace the two exact-redaction comparisons with:

```rust
assert!(
    format!("{private_expected:?}") == "ExpectedContext([REDACTED])",
    "private diagnostic mismatch"
);
assert!(
    format!("{verification_request:?}") == "VerificationRequest([REDACTED])",
    "private diagnostic mismatch"
);
```

Replace the two custom loop messages with:

```rust
assert!(
    debug.contains("REDACTED"),
    "private diagnostic missing redaction marker"
);
```

```rust
assert!(
    !debug.contains(sensitive),
    "private diagnostic exposed a forbidden value"
);
```

Leave the error loop's message-free assertion unchanged.

- [ ] **Step 5: Replace the public-flow exact diagnostic sink**

Keep the phase/outcome assertions unchanged because those operands cannot carry the request. Replace only the formatted flow comparison:

```rust
assert!(
    format!("{flow:?}") == "VerifierFlow { phase: EvidenceReceived, outcome: None }",
    "private diagnostic mismatch"
);
```

- [ ] **Step 6: Format and run affected agent/verifier tests**

Run:

```bash
cargo fmt --all -- --check
cargo test -p ogir-agent session::tests::every_session_diagnostic_is_context_free_and_redacted -- --exact
cargo test -p ogir-verifier verification::tests::every_flow_capability_outcome_and_error_diagnostic_is_redacted -- --exact
cargo test -p ogir-verifier --test freshness replay_debug_and_errors_redact_every_binding_and_timestamp -- --exact
cargo test -p ogir-verifier --test verification_public new_flow_exposes_only_received_phase_and_no_outcome -- --exact
```

Expected: all four tests pass without warnings.

- [ ] **Step 7: Review and commit the agent/verifier change unsigned**

Run:

```bash
git diff --check
git diff -- crates/ogir-agent/src/session/tests.rs \
  crates/ogir-verifier/src/verification/tests.rs \
  crates/ogir-verifier/tests/freshness.rs \
  crates/ogir-verifier/tests/verification_public.rs
git add crates/ogir-agent/src/session/tests.rs \
  crates/ogir-verifier/src/verification/tests.rs \
  crates/ogir-verifier/tests/freshness.rs \
  crates/ogir-verifier/tests/verification_public.rs
git commit --no-gpg-sign -m "test: redact verifier assertion failures"
```

Expected: one unsigned test-only commit; production implementations remain byte-identical to base.

---

### Task 4: Record The Durable Test Rule

**Files:**
- Modify: `docs/TEST_STRATEGY.md:250-272`
- Modify: `docs/LESSONS_LEARNED.md` at end of file

**Interfaces:**
- Consumes: issue #18 root cause and selected fixed-message assertion shape.
- Produces: durable guidance for future privacy tests and an append-only lesson entry.

- [ ] **Step 1: Add the test-strategy rule**

After the freshness privacy-scenario paragraph, add:

```markdown
Privacy/redaction tests must not repeat the value under test in their own
failure diagnostics. Exact comparisons and forbidden-value checks use boolean
assertions with fixed generic messages rather than `assert_eq!` or interpolated
panic text, because Rust equality assertions print unequal operands. CodeQL
`rust/cleartext-logging` remains the sink-model regression gate; do not dismiss
or suppress a repository-controlled finding when the test assertion can be made
non-disclosing.
```

- [ ] **Step 2: Append the lesson entry**

Append:

```markdown
## 2026-08-27 — Privacy tests must not disclose the regression they detect

- **Context:** Post-merge CodeQL 2.26.4 review of verifier freshness privacy
  diagnostics.
- **Mistaken assumption:** Synthetic fixtures and test-only assertions made it
  harmless to include the forbidden value or complete diagnostic in failure
  output, and message-free `assert_eq!` comparisons were safe.
- **Observed failure:** Alerts #43/#44 traced private account data into custom
  assertion messages; Rust 1.98.0 also prints both operands for every failed
  `assert_eq!`, creating same-root-cause variants across privacy tests.
- **Security or quality impact:** A redaction regression could copy the private
  value into local or CI logs through the test intended to catch it, while
  repeated scanner noise reduced the value of full-branch analysis.
- **Permanent regression test:** Existing exact redaction and forbidden-value
  tests now fail with fixed generic text; CodeQL alerts #43/#44 provide the
  scanner RED and must be fixed by analysis with null dismissal metadata.
- **New prevention rule:** Privacy assertions may compare or search sensitive
  diagnostics, but their panic path must not format either operand, the
  forbidden fixture, or the diagnostic under test. Prefer boolean `assert!`
  with fixed generic text over `assert_eq!` for privacy-bearing values.
- **Documentation or agent-policy updates:** Issue #18, its design/plan, and the
  test strategy record the assertion rule; no production or threat-model change
  is implied.
```

- [ ] **Step 3: Check documentation and commit unsigned**

Run:

```bash
git diff --check
git diff -- docs/TEST_STRATEGY.md docs/LESSONS_LEARNED.md
./scripts/check.sh
git add docs/TEST_STRATEGY.md docs/LESSONS_LEARNED.md
git commit --no-gpg-sign -m "docs: prevent private test failure output"
```

Expected: documentation gate passes and one unsigned documentation commit is created.

---

### Task 5: Verify Scope, Variants, And Full Gates

**Files:**
- Modify only if evidence is factual: `planning/issues/codeql-private-test-diagnostics.md`
- Review: every file changed in Tasks 1-4

**Interfaces:**
- Consumes: all prior task commits.
- Produces: frozen unsigned head with reproducible evidence, no unresolved review findings, and no publication-side effects.

- [ ] **Step 1: Prove production and configuration scope are unchanged**

Run:

```bash
git diff --name-only 25030e1af6a437472e27c5e842f4251222d4c6fe..HEAD
test -z "$(git diff --name-only 25030e1af6a437472e27c5e842f4251222d4c6fe..HEAD -- \
  ':(glob)crates/*/src/**/*.rs' ':(exclude)crates/ogir-model/src/lib.rs' \
  ':(exclude)crates/ogir-agent/src/session/tests.rs' \
  ':(exclude)crates/ogir-verifier/src/verification/tests.rs' \
  '.github/**' Cargo.toml Cargo.lock)"
git diff 25030e1af6a437472e27c5e842f4251222d4c6fe..HEAD -- crates/ogir-model/src/lib.rs
```

Expected: only approved planning/test/docs paths appear. The model diff is confined to its existing `#[cfg(test)]` module; the other two allowed `src/` paths are dedicated test modules. No production item changes.

- [ ] **Step 2: Perform the focused variant review**

Inspect every changed privacy test and confirm:

```text
no assert_eq!/assert_ne! has a privacy-bearing diagnostic operand
no custom assert!/panic message formats a tested diagnostic or forbidden fixture
every original expected string and forbidden fixture remains present
unrelated functional/state-machine assertions remain unchanged
```

Use `git diff --word-diff=porcelain` and targeted `rg` searches over the eight test locations. Do not add a source-text regression test.

- [ ] **Step 3: Run formatting and targeted crate suites**

Run:

```bash
cargo fmt --all -- --check
cargo test -p ogir-model --all-features
cargo test -p ogir-protocol --all-features
cargo test -p ogir-agent --all-features
cargo test -p ogir-verifier --all-features
```

Expected: all crate suites pass with no warnings.

- [ ] **Step 4: Run full normal and optimized gates**

Run:

```bash
./scripts/check.sh
cargo test --workspace --all-features --release
git diff --check
git status --short --branch
```

Expected: full repository gate and release suite pass; worktree is clean after any evidence commit.

- [ ] **Step 5: Obtain independent privacy-focused review**

Review the exact base-to-head diff for behavioral weakening, missed value-emitting variants, production changes, misleading threat claims, dependency/configuration changes, and inadequate evidence.

Expected: no unresolved Critical, Important, or Minor finding. Correct findings test-first and rerun affected/full gates before continuing.

- [ ] **Step 6: Record exact pre-DCO evidence only after verification**

Update the issue's `Implementation evidence` section with the exact base/head, changed paths, RED evidence, targeted/full/release results, variant-review result, limitations, and explicit statement that DCO/publication/CodeQL GREEN remain pending. Sync the exact live issue body only if separately authorized by the existing issue-creation scope.

Commit the factual evidence update unsigned:

```bash
git add planning/issues/codeql-private-test-diagnostics.md
git commit --no-gpg-sign -m "docs: record private diagnostic evidence"
```

- [ ] **Step 7: Freeze and stop at the human gate**

Run:

```bash
git log --format='%H%x09%s%x09%(trailers:key=Signed-off-by,valueonly)' \
  25030e1af6a437472e27c5e842f4251222d4c6fe..HEAD
git status --short --branch
gh api repos/archledger/open-game-integrity-runtime/code-scanning/alerts/43 --jq '{state,dismissed_at}'
gh api repos/archledger/open-game-integrity-runtime/code-scanning/alerts/44 --jq '{state,dismissed_at}'
```

Expected: exact unsigned range is clean and frozen; alerts remain open/undismissed because no branch has been pushed. Stop and request human review plus exact DCO certification. Do not rewrite, push, create a PR, dismiss an alert, or merge.
