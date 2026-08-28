# Privacy-Test Assertion Diagnostics Design

**Status:** Approved for implementation planning on 2026-08-27

## Context

CodeQL alerts #43/#44 identify private synthetic account data flowing into
custom assertion panic messages in the verifier freshness privacy test. The
runtime does not log these values. The defect exists solely in failure-only test
diagnostics: if redaction regresses, the test intended to detect that regression
can repeat the private fixture in its panic output.

Primary-source review established that this is a pattern rather than a two-line
special case. CodeQL 2.26.4 models Rust panic/assertion formatting as a logging
sink, and Rust 1.98.0 `assert_eq!` prints both unequal operands. Existing exact
redaction tests therefore have the same failure-mode risk even where no custom
message is present.

## Decision

Harden only existing privacy/redaction tests. Replace comparisons and
containment assertions that can emit tested private diagnostics with boolean
`assert!` conditions and fixed generic messages. Preserve the compared values,
expected strings, forbidden fixture sets, and all test control flow.

Representative transformations:

```rust
assert_eq!(diagnostic, "Type([REDACTED])");
```

becomes:

```rust
assert!(
    diagnostic == "Type([REDACTED])",
    "private diagnostic mismatch"
);
```

and:

```rust
assert!(
    !diagnostic.contains(forbidden),
    "diagnostic leaked {forbidden:?}: {diagnostic:?}"
);
```

becomes:

```rust
assert!(
    !diagnostic.contains(forbidden),
    "private diagnostic exposed a forbidden value"
);
```

No reusable production helper is introduced. The expressions are short and
local, and direct fixed-message assertions make the no-formatting property
visible at each failure site without adding a `Debug` bound or cross-crate test
infrastructure.

## Scope

The implementation may update privacy/redaction assertions in these existing
test locations where an operand or custom message can carry private fixture
data:

- `crates/ogir-model/src/lib.rs`
- `crates/ogir-model/tests/identifiers.rs`
- `crates/ogir-model/tests/session_public_key_id.rs`
- `crates/ogir-protocol/tests/evidence_profile.rs`
- `crates/ogir-agent/src/session/tests.rs`
- `crates/ogir-verifier/src/verification/tests.rs`
- `crates/ogir-verifier/tests/freshness.rs`
- `crates/ogir-verifier/tests/verification_public.rs`

The implementation also updates `docs/TEST_STRATEGY.md` and
`docs/LESSONS_LEARNED.md` with the durable rule. Planning documents may record
the issue and execution evidence.

## Boundaries

- No production implementation, public API, dependency, workflow, scenario,
  CodeQL configuration, suppression, exclusion, or alert-state change.
- Do not mechanically rewrite unrelated `assert_eq!` calls. State-machine and
  functional assertions whose values are not privacy-bearing remain unchanged.
- Do not weaken exact expected redaction strings or forbidden-value coverage.
- Do not print tested operands to improve debuggability; the privacy boundary
  intentionally takes precedence in these tests.
- Do not add a source-text grep test. The repository's CodeQL scan tests the
  actual sink model, while source-text checks would be brittle change detectors.

## Verification Strategy

1. Retain alerts #43/#44 as external scanner RED evidence.
2. Preserve the isolated Rust 1.98.0 characterization output showing the old
   forms leak values and the selected form does not.
3. Run each affected crate's privacy/redaction tests after its minimal change.
4. Search the named test functions for remaining interpolated panic messages or
   equality macros that can print privacy-bearing values.
5. Run formatting, full normal checks, optimized all-feature tests, diff checks,
   and independent privacy-focused review.
6. After separately authorized publication, require CodeQL to mark alerts
   #43/#44 fixed with no dismissal and no replacement variant.

## Rejected Alternatives

### Change only the two alerted lines

Rejected because `assert_eq!` prints unequal operands, leaving equivalent
failure-only disclosure paths in privacy tests.

### Dismiss or suppress the alerts

Rejected because the repository controls the sink and can remove it without
weakening coverage. Dismissal would hide useful scanner evidence.

### Add a shared test-helper crate or production helper

Rejected as disproportionate for local assertion expressions spanning multiple
crate test layouts. It would add interface and maintenance surface without
improving the fixed-message property.

### Add a source-text regression scanner

Rejected because it would test spelling rather than panic behavior and would
produce broad false positives. CodeQL remains the authoritative sink-model
regression gate.

## Residual Risk

Rust assertions outside the reviewed privacy/redaction tests may still print
their operands by design. They are not changed unless their values can carry a
private fixture under the same root cause. Final CodeQL evidence depends on a
separately authorized push and GitHub analysis.
