# Plan: M2-018 mock verifier and permit

- Status: Executed in the `research/m2-018-mock-verifier-and-permit`
  worktree; all local gates green; awaiting human review, signed commit,
  and separately authorized publication.
- Date: 2026-09-06.
- Baseline: merged `79e2410ccd4a8bf8c8960179179652ee5cb5cc4e`.
- Authority: M2-018 charter in the approved M2-016 design record; ADR-0013
  (replay cache), ADR-0014 (permit validity), ADR-0015/0016 (substrate);
  [local issue](../../../planning/issues/018-mock-verifier-and-permit.md).

## Tasks

1. `ogir-mock-keys`: session-key registry in `MockKeyDirectory`
   (`register_session`, `session_material_by_handle`) as the trusted mock
   channel for relying-party proof validation; directory is `Clone` for
   per-party trust views.
2. `ogir-mock-protocol::policy`: the verifier policy interface
   (`MockPolicy` trait, `PolicyRequest` of verified objects only,
   `MockDecision` admit/deny with `ReasonCode`) plus the exact-context
   `ContextMatchPolicy` implementation mirroring `ExpectedContext`
   authority.
3. `ogir-mock-protocol::service`: `MockVerifierService` wiring the
   ADR-0015 signed objects, the ADR-0016 directory, the verifier crate's
   opt-in ADR-0013 replay cache (feature `research-mock-replay`) through
   `ReplayRegistration::from_challenge` on a reconstructed typed
   `PublisherChallenge`, the half-open window evaluation, and the policy
   into the challenge -> evidence -> permit path with deterministic
   non-disciplinary denials.
4. `ogir-mock-protocol::admission`: `MockRelyingParty` admitting only a
   verifier-signed, unexpired permit with a session key registered in its
   own directory and a proof of possession valid under that exact key and
   those exact permit bytes (`verify_pop_under_material` shares the
   canonical parser and the ADR-0016 formula); one-use initial admission
   per permit with ADR-0014 redelivery semantics noted.
5. Plan record and local issue.

## Test inventory (executed, all green)

- Policy: matching context admits; every single context-field mismatch
  (game, build, account, match, policy id, policy version) denies
  `ContextBindingMismatch`.
- Service happy path: permit issued with exact times, handle binding.
- Hosted attack categories: patched client (no proof, impostor session
  key, forged permit all reject), evidence replay (second submission
  `ReplayDetected` via the ADR-0013 cache), expired challenge (`Expired`
  at the boundary and after; `NotYetValid` before issuance), permit replay
  at the relying party (`PermitReplay`), expired permit (`PermitExpired`
  at and after the exclusive boundary), verifier key mismatch
  (`UnknownKey` against a stranger directory), unknown session key
  (`UnknownSession`).
- Binding: evidence embedding a different challenge object denies
  `ContextBindingMismatch`; non-canonical challenge text denies
  `Malformed` at model reconstruction.
- Regression: all M2-017 suites still green; full workspace 444 tests.

## Local gates

`cargo fmt --all --check` clean; `cargo clippy --workspace --all-targets`
zero warnings; `RUSTDOCFLAGS="-D warnings" cargo doc --workspace
--no-deps` clean (the gate missed in M2-017, now standard); `cargo test
--workspace` 444 tests all green; isolation script PASS (mock-on-production
dependency direction only; the `research-mock-replay` feature is the
documented ADR-0013 opt-in, not a production default).

## Deliberately not done

Renewal/revocation lifecycles beyond one-use initial admission (ADR-0014
fencing for successors is M2-019 scope with the conformance vectors); the
CLI demo; deterministic hex conformance vectors; the independent second
encoder. No production crate changed.
