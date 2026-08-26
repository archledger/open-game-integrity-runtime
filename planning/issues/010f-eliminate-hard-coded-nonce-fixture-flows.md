# M1-010F: Eliminate hard-coded nonce fixture flows
<!-- labels: type: security-hardening,area: verifier,risk: trusted-computing-base,risk: cryptography,status: ready -->
<!-- milestone: M1 Domain Model -->

## Problem

The first M1-010 pull-request scan reported one newly introduced hard-coded
nonce fixture. Replacing only that literal made the pull request green, but the
subsequent full `main` scan opened CodeQL alert #38 at another existing call to
the same fixture API. Four private test builders still accept raw `[u8; 32]`
values through parameters named `nonce`, and dozens of callers pass repeated
literal or scalar-derived arrays into those sinks.

This is a test-only security-scanning defect, not evidence that production
cryptographic key or nonce material is hard coded. Nevertheless, fixing only
the currently reported line leaves the shared source-to-sink boundary intact,
allows the same alert to move again, and reduces the usefulness of the
repository's full-branch security signal.

## Security invariants

- Preserve invariant 8: identical publisher/nonce fixture values still model
  one exact replay identity, while different fixture values remain distinct.
- Preserve invariant 37: fixture bytes remain absent from default diagnostics.
- Enforce invariants 45 and 47: security automation remains actionable and a
  confirmed defect receives a permanent regression.
- Enforce invariant 48: the AI-assisted correction receives the same source,
  test, review, and DCO scrutiny as production-facing work.

## Threats addressed

- A symptom-only patch removes one reported source while equivalent literal
  nonce flows remain behind the same helper boundary.
- Future tests reintroduce raw repeated-byte arrays because the fixture API
  continues to accept them.
- A mechanical refactor changes replay equality, cross-publisher independence,
  capacity, rollback, or arbitrary-history semantics while making CodeQL green.
- A maintainer dismisses or suppresses a real scanner result instead of fixing
  the repository-controlled source-to-sink pattern.

## In scope

- Change the four private freshness-test builders to accept one `u8` fixture
  seed rather than raw `[u8; 32]` nonce bytes.
- Make the existing deterministic helper derive all 32 bytes using the
  per-index XOR operation recognized as a barrier by the exact CodeQL 2.26.3
  query, and return `Nonce` directly.
- Migrate every freshness-test call site to the scalar-seed API.
- Prove all 256 seed values are deterministic and pairwise distinct.
- Preserve every existing freshness/verifier assertion and action budget.
- Record the root-cause lesson and applicable test-strategy guidance.
- Obtain fresh local gates, independent review, DCO certification, pull-request
  checks, and full-`main` CodeQL evidence without dismissing either alert.

## Out of scope

- Production nonce generation, cryptography, key material, or protocol fields.
- Changes under `crates/ogir-verifier/src/` or any other production source.
- CodeQL query configuration, suppression, exclusion, dismissal, or severity.
- Dependencies, serialization, networking, persistence, RNG, or `unsafe` code.
- M1-011 session-public-key design or any result, permit, or admission behavior.
- Treating a test-fixture alert as player cheating or a production vulnerability.

## Trust sources

- The exact CodeQL 2.26.3 query defines literal/array-repeat expressions as
  sources, exact credential-named call parameters including `nonce` as
  heuristic sinks, and binary arithmetic/bitwise operands as barriers.
- Repository-controlled scalar seeds are test inputs only and carry no
  production randomness or authorization claim.
- Existing independent freshness/replay oracles define the behavior that the
  fixture-only refactor must preserve.
- GitHub's full-branch CodeQL analysis, not an alert dismissal, supplies the
  final external regression evidence.

## Required interfaces

- `test_nonce(seed: u8) -> Nonce` deterministically derives 32 bytes through
  `seed ^ index` and performs the sole `Nonce::from_bytes` construction.
- `challenge_for_publisher`, `challenge`, `challenge_for_account`, and
  `challenge_with_window` accept `nonce_seed: u8` and never accept raw nonce
  arrays.
- Property-history helpers likewise name their scalar input `nonce_seed`, so no
  private function retains the CodeQL query's exact `nonce` parameter sink.
- No public API is added or changed.

## Positive tests

- Each seed in `0..=255` produces the same nonce on repeated construction.
- All 256 generated nonces are pairwise distinct.
- Same-seed replay and same-seed/different-publisher tests retain their exact
  outcomes.
- All 30 freshness tests and the verifier's existing exhaustive/history proofs
  remain green.

## Negative tests

- Passing `[value; 32]` to any of the four fixture builders no longer compiles
  because their input type is `u8`.
- Different seeds never collapse to one replay identity.
- No raw fixture nonce appears in diagnostics.
- No raw repeated-array call remains at the freshness fixture boundary.
- CodeQL alert #38 is fixed and no equivalent open
  `rust/hard-coded-cryptographic-value` alert remains on the final full `main`
  scan; no dismissal field is populated.

## Fuzz/property tests

The refactor adds no parser or untrusted byte surface, so no fuzz target is
added. Exhausting the complete 256-value seed domain is the appropriate finite
property proof. Existing fixed-budget arbitrary freshness and verifier histories
remain unchanged.

## Privacy impact

No claim, identifier, log field, or diagnostic is added. Synthetic nonce bytes
remain redacted. The correction does not assert secure erasure or change replay
retention.

## Dependency impact

No dependency, feature, license boundary, workflow permission, or action pin is
added or changed. The implementation uses only the Rust standard library and
existing model types.

## Acceptance criteria

- The issue changes tests/documentation only and preserves all production
  source bytes.
- All four freshness fixture builders accept scalar seeds and all callers use
  the new interface.
- The complete 256-seed property proof and every existing freshness assertion
  pass.
- `cargo fmt`, Clippy, full workspace tests, rustdoc, cargo-deny, repository
  checks, and optimized all-feature tests pass.
- Fresh independent review reports no unresolved Critical, Important, or Minor
  finding.
- Every published commit has the exact human-certified DCO trailer.
- PR and post-merge CodeQL checks pass; alert #38 is fixed, no next equivalent
  main alert is open, and no alert is dismissed.
- `docs/TEST_STRATEGY.md` and `docs/LESSONS_LEARNED.md` record the durable
  prevention rule; an attack scenario is explicitly not added because no
  runtime or protocol threat behavior changes.

## Primary sources

- GitHub CodeQL Rust query help for `rust/hard-coded-cryptographic-value`:
  https://codeql.github.com/codeql-query-help/rust/rust-hard-coded-cryptographic-value/
- Exact CodeQL 2.26.3 Rust source/sink/barrier model:
  https://github.com/github/codeql/blob/codeql-cli/v2.26.3/rust/ql/lib/codeql/rust/security/HardcodedCryptographicValueExtensions.qll
- GitHub code-scanning alert #38:
  https://github.com/archledger/open-game-integrity-runtime/security/code-scanning/38
