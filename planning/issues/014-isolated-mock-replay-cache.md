# M1-014: Implement an isolated mock replay cache and tests
<!-- labels: type: implementation,area: verifier,area: privacy,risk: trusted-computing-base,risk: privacy,risk: compatibility,status: ready -->
<!-- milestone: M1 Domain Model -->

Status: design approved; local implementation candidate awaiting final human review and DCO.

## Problem

Roadmap item 14 calls for an in-memory replay cache. The existing public
`ReplayStore` contract instead requires atomic durable records and a durable
time floor. Supplying a volatile implementation of that contract would falsely
assert restart protection. Existing `ReferenceReplayStore` is integration-test
support whose shared-memory snapshots simulate reopen; it is not a reusable
runtime adapter or process-crash recovery implementation.

Build a reusable research-only cache with an explicit type boundary and bounded
state. The proposed exact API, operation ordering and tests are in the
[M1-014 design](../../docs/superpowers/specs/2026-09-04-m1-014-isolated-mock-replay-cache-design.md).
That document is the behavior specification; this issue summarizes scope.

## Security invariants

- Preserve security invariants 7–9 and ADR-0005's durable replay requirement.
  The mock does not implement or convert to `ReplayStore`.
- One retained registration is consumed at most once per instance; context/window
  substitution cannot create another key or release a retained consumed record.
  Expiry deletion does not imply a permanent nonce-uniqueness history; modeled
  issuance remains responsible for fresh nonces.
- Observe time before later rejection; rollback and lost/poisoned state fail
  closed. A mock success grants no verifier capability or session authority.
- Preserve privacy invariants 37–38 through fixed diagnostics, bounded retained
  state and shared deletion, with no persistence or secure-erasure claim.

## Threats addressed

Replay and context substitution; concurrent double consume or quota bypass;
clock rollback; permissive expiry edges; live-record eviction; unbounded retained
rate history across publishers; reset after loss; accidental use of a volatile
model as durable infrastructure; privacy leaks in output and retained copies.

## In scope

- An opt-in, default-off `research-mock-replay` module in `ogir-verifier`.
- Fixed per-instance policy, finite record slots and a global issuance-event
  cap, one synchronized state, atomic registration/claim, expiry cleanup and
  aggregate-only observations.
- Terminal simulated state loss across shared handles; no reopen/reset API.
- Independent model/literal, concurrent, boundary, compile-fail and actual
  diagnostic-output tests, with meaningful mutation/restoration evidence.
- An ADR clarifying the research boundary without superseding ADR-0005, plus
  focused documentation and test-strategy updates.

## Out of scope

Durable storage or crash recovery, daemon activation, a `ReplayStore` wrapper,
verifier capability/flow changes, issuer/signing-key epoch recovery, database,
serialization, parser, crypto, nonce generator, wall clock, network, TPM,
production permit/admission, external dependencies and unsafe Rust.
No unrelated CI expansion or refactoring of the existing reference model.

## Primary sources

- [Security invariants](../../docs/SECURITY_INVARIANTS.md),
  [ADR-0005](../../docs/adr/0005-verifier-authoritative-challenge-freshness.md),
  [M1-008](008-freshness-model.md), and the source references in the design.
- [RFC 9334 sections 10.2–10.3](https://www.rfc-editor.org/rfc/rfc9334.html#section-10.2).
- Official Rust 1.98.0 tagged Mutex, Vec and Arc sources linked in the design.

## Required interfaces

Feature-gated `MockReplayLimits`, `MockReplayCache` and `MockReplayStats` in
`ogir_verifier::mock_replay`. Use existing validated domain/replay inputs and
`FreshnessError`; no new capability or durable-store implementation. Public
signatures and exact failure side effects are defined in design sections 3–7.

## Positive tests

Valid registration/one consume; equal-time observations; independent publishers;
exact policy boundaries; shared-handle observations and expiry deletion;
independent new research runs. Default and feature-enabled builds both work.

## Negative tests

Same-key/context/window substitutions, replay after consumption, lifetime and
half-open window failures, clock rollback, missing registration, quota/rate/global
event exhaustion, loss/poison, old-handle reuse, and authority-boundary misuse.
Check exact documented floor/cleanup effects after rejected operations.

## Fuzz/property tests

Preserve existing M1-008 tests as an independent baseline. Add deterministic
operation traces with a separate oracle, real competing-thread invariants, and
physical semantic mutations with intended detector failures and verified
restoration. No parser or new fuzzing dependency is introduced. Exact cases,
selectors and mutation counts belong in the reviewed implementation plan.

## Privacy impact

Use synthetic canonical identifiers and nonces only. Retain bounded necessary
registration/event data in one shared state; no snapshot export, log, telemetry,
pointer or time-floor exposure. Explicit purge drives modeled expiry deletion;
there is no wall-clock deletion SLA or secure-erasure guarantee. Default Debug
and actual failing-test output must redact sensitive values.

## Dependency impact

Use the standard library and existing workspace dependencies. Add one empty
opt-in Cargo feature, no default activation, package, lockfile or license change.
Existing Apache-2.0 and safe-Rust requirements apply. Any new dependency or
broader memory-management mechanism requires revisiting the design.

## Acceptance criteria

- The human approves the written design before implementation planning.
- No API claims volatile state is durable or produces freshness authority.
- All exact operation-order, bounds, concurrency, loss, retention and privacy
  requirements in the design have independent observable tests.
- Existing replay/model/verifier tests and behavior remain unchanged.
- Required default/all-feature, release, format, lint, docs, metadata, ADR and
  regression gates pass on the final candidate; no gate is weakened.
- Reviews disposition every finding and record actual limitations. The final
  change remains small enough for coherent human review.
- Verify PR #28's human web merge before the implementation checkout. New
  content receives its own line review, DCO and commit/publication authorization.

## Current status and authorization

The human approved approach A and the written design on 2026-09-04. PR #28
was subsequently human-merged as `78fe4b911f13c1d19366fdb3822c5b6bf49962f8`;
its tree matches the certified M1-013 candidate. M1-014 now has a local,
uncommitted implementation on that merged baseline.

The candidate contains the feature-gated mock module, direct behavior and
concurrency tests, an independent reference comparison, compiler-boundary
probes and scoped documentation. ADR-0013 remains Proposed pending human
acceptance. Final evidence belongs to the implementation review/freeze report;
passing tests are not production-readiness or durability evidence.

No Task 14 live issue, commit, signature, push or PR has been created. The new
candidate requires its own exact human line review, DCO certification and
commit/publication authorization; earlier M1-013 certification does not apply.
