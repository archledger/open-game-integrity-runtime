# Harden privacy-test assertion diagnostics
<!-- labels: type: test,area: privacy,risk: privacy,status: needs-review -->
<!-- milestone: M1 Domain Model -->

## Problem

The full `main` CodeQL 2.26.4 scan opened test-classified
`rust/cleartext-logging` alerts #43 and #44 in
`crates/ogir-verifier/tests/freshness.rs`. The affected privacy regression
correctly checks that diagnostic output excludes private account and binding
fixtures, but its own failure message interpolates the forbidden fixture and
the complete diagnostic. A redaction regression would therefore print the
private synthetic value while reporting the failure.

This is not a production vulnerability: the values are synthetic test fixtures
and no production logging path is involved. It is nevertheless a real
test-diagnostic hygiene defect. Exact-version CodeQL source and Rust 1.98.0
behavior also show that `assert_eq!` prints both unequal operands, so changing
only the two reported custom messages would leave equivalent disclosure paths
inside the repository's privacy/redaction tests.

## Security requirements

- Preserve privacy invariant 37: default diagnostics remain redacted and do not
  expose private account, binding, nonce, evidence, or session fixtures.
- Enforce invariant 47: the confirmed test-diagnostic defect receives durable
  scanner and behavioral regression evidence.
- Enforce invariant 48: this AI-assisted test-only correction receives normal
  source, test, review, DCO, and publication scrutiny.
- A privacy regression may make a test fail, but the assertion failure itself
  must not format the private actual value or forbidden fixture.

## Trust boundaries touched

None. The correction changes failure-only test diagnostics. It does not alter
runtime code, public APIs, trust decisions, protocol data, persistence,
privileges, or release behavior.

## In scope

- Replace value-emitting assertion forms inside existing privacy/redaction tests
  with boolean assertions whose panic text is fixed and generic.
- Cover exact-redaction comparisons currently expressed with `assert_eq!`,
  because Rust prints both operands when those comparisons fail.
- Cover forbidden-value checks whose custom messages interpolate either the
  forbidden fixture or the diagnostic under test.
- Preserve every existing expected redaction string, forbidden-value set,
  loop, fixture, and functional assertion.
- Record the test-strategy rule and root-cause lesson.
- Verify alerts #43/#44 are fixed by analysis rather than dismissal.

## Out of scope

- Production source or public API changes.
- Changes to `Debug`, `Display`, identifier, freshness, session, verifier, or
  protocol behavior.
- New dependencies, helper crates, macros, workflows, CodeQL configuration,
  suppressions, exclusions, severity changes, or alert dismissals.
- Rewriting unrelated assertions whose values cannot carry private data.
- Real credentials, account data, publisher material, secrets, or production
  logs.

## Required assertion shape

Exact privacy comparisons use a boolean condition and fixed message:

```rust
assert!(actual == expected, "private diagnostic mismatch");
```

Forbidden-value checks likewise use a fixed message:

```rust
assert!(
    !diagnostic.contains(forbidden),
    "private diagnostic exposed a forbidden value"
);
```

The fixed text may identify the class of failed privacy assertion but must not
format either operand, the forbidden fixture, or the diagnostic under test.
The implementation must not require adding a `Debug` bound merely to report a
failed comparison.

## Positive tests

- Every existing exact redaction expectation remains unchanged and passes.
- Every existing forbidden-value check remains unchanged in meaning and passes.
- The targeted verifier freshness privacy test passes.
- Model, protocol, agent, and verifier privacy/redaction tests pass.
- Full normal and optimized all-feature workspace suites pass.

## Negative and scanner evidence

- Alerts #43/#44 are the pre-change scanner RED cases.
- An isolated Rust 1.98.0 characterization proves the old custom `assert!`
  prints an interpolated private value and old `assert_eq!` prints both unequal
  operands.
- The same characterization proves a fixed-message boolean `assert!` prints no
  operand.
- Repository variant review finds no remaining value-emitting assertion form in
  the changed privacy/redaction tests.
- Post-publication CodeQL reports alerts #43/#44 fixed with null dismissal
  metadata and no same-root-cause replacement alert.

## Fuzz/property tests

No parser, untrusted byte surface, or input domain changes. No fuzz target or
new property generator is warranted. Existing exhaustive and deterministic
privacy-adjacent tests remain unchanged.

## Privacy impact

The change reduces data emitted when a privacy test fails. Passing-test output
and production diagnostics are unchanged. The fixtures remain synthetic, and
the issue makes no claim about secure erasure.

## Dependency impact

None. No dependency, feature, license boundary, workflow permission, action pin,
or toolchain version changes.

## Acceptance criteria

- Only planning, test, test-strategy, and lessons-learned files change.
- Production source bytes and public APIs remain unchanged.
- Exact redaction and forbidden-value coverage are preserved.
- Failure messages in the affected privacy/redaction tests cannot print tested
  values or forbidden fixtures.
- `cargo fmt --all -- --check`, targeted privacy tests, `./scripts/check.sh`,
  `cargo test --workspace --all-features --release`, `git diff --check`, and
  independent privacy-focused review pass.
- Published commits carry only human-certified DCO trailers.
- Alerts #43/#44 are fixed without dismissal; no same-root-cause alert replaces
  them.
- Work stops before DCO rewriting, push, pull request, dismissal, or merge
  unless each later action is separately authorized.

## Primary sources

- CodeQL query help for `rust/cleartext-logging`:
  https://codeql.github.com/codeql-query-help/rust/rust-cleartext-logging/
- Exact CodeQL 2.26.4 query:
  https://github.com/github/codeql/blob/1d123a2caa0e4e6256a49d963bfcbd51a01617e8/rust/ql/src/queries/security/CWE-312/CleartextLogging.ql
- Exact sensitive-data heuristics:
  https://github.com/github/codeql/blob/1d123a2caa0e4e6256a49d963bfcbd51a01617e8/shared/concepts/codeql/concepts/internal/SensitiveDataHeuristics.qll
- Exact upstream Rust assertion-sink tests:
  https://github.com/github/codeql/blob/1d123a2caa0e4e6256a49d963bfcbd51a01617e8/rust/ql/test/query-tests/security/CWE-312/test_logging.rs
- Rust 1.98.0 `assert!` documentation:
  https://doc.rust-lang.org/1.98.0/std/macro.assert.html
- Rust 1.98.0 `assert_eq!` documentation:
  https://doc.rust-lang.org/1.98.0/std/macro.assert_eq.html
- GitHub code-scanning alerts #43 and #44:
  https://github.com/archledger/open-game-integrity-runtime/security/code-scanning/43
  https://github.com/archledger/open-game-integrity-runtime/security/code-scanning/44

## Implementation evidence

- Verified base: `25030e1af6a437472e27c5e842f4251222d4c6fe`.
- Verified implementation head before this evidence-only update:
  `19eaefb082de3bf627a5525b5aa3bb633ac61156`.
- The base-to-implementation-head diff contains 13 approved planning, test, and
  documentation paths: the eight test locations named by the plan,
  `docs/TEST_STRATEGY.md`, `docs/LESSONS_LEARNED.md`, this issue, the approved
  design, and the implementation plan. It contains 956 insertions and 31
  deletions. The production/configuration path guard passed; the only model
  source diff is inside its existing `#[cfg(test)]` module, the agent and
  verifier `src/` diffs are dedicated test modules, and `.github/**`,
  `Cargo.toml`, and `Cargo.lock` are unchanged.
- Scanner RED remains reproducible without mutation: alerts #43/#44 are open
  `rust/cleartext-logging` results at `freshness.rs:828` and `freshness.rs:833`,
  both with `dismissed_at: null`. The Rust 1.98.0 characterization recorded in
  Task 1 proved that the old custom and equality assertion forms print private
  operands while the selected fixed-message boolean assertion does not.
- `cargo fmt --all -- --check` passed. The four targeted all-feature crate
  suites passed with no warnings: model 54 runtime tests plus 20 doctests,
  protocol 4 runtime tests, agent 17 runtime tests plus 20 doctests, and
  verifier 48 runtime tests plus 40 doctests.
- `./scripts/check.sh` passed with 123 runtime/integration tests, 80 doctests,
  14 attack scenarios, and 8 ADRs. Repository metadata, GitHub bootstrap, DCO
  fixtures, formatting, Clippy, rustdoc, and cargo-deny also passed.
  `cargo test --workspace --all-features --release` passed with the same 123
  runtime/integration tests and 80 doctests. `git diff --check` passed.
- Focused word-diff review confirmed 19 new fixed mismatch messages, three new
  fixed forbidden-value messages, and one new fixed missing-marker message;
  the edited predicates, expected strings, forbidden sets, fixtures, loops,
  and unrelated functional/state-machine assertions remain unchanged.
- The focused variant acceptance criterion is not yet satisfied.
  `diagnostics_for_every_surface`, called before the changed forbidden-value
  loop in `every_flow_capability_outcome_and_error_diagnostic_is_redacted`,
  still uses privacy-bearing `assert_eq!` comparisons for binding, capability,
  request, expected-context, evidence, and private-flow diagnostics. A
  redaction regression can therefore print an actual private diagnostic before
  the fixed-message containment checks execute. These same-root-cause variants
  are at `crates/ogir-verifier/src/verification/tests.rs:733-839` and require a
  separately authorized correction before this work can pass final privacy
  review.
- Before this section was appended, the local issue body was byte-equal to live
  issue #18. This local evidence update is intentionally not synchronized;
  GitHub issue state, labels, milestone, body, and alerts remain unchanged.
- Limitations and pending gates: the normal and release suites exercise passing
  behavior, not assertion-failure confidentiality. No independent reviewer was
  dispatched under the Task 5 controller ruling. Controller review, correction
  and re-verification of the unresolved variants, exact DCO certification and
  rewrite, publication, and post-publication CodeQL GREEN all remain pending.
