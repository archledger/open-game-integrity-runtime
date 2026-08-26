# M1-009: Implement the local protected-session state machine
<!-- labels: type: implementation,area: model,area: agent,area: session,risk: trusted-computing-base,risk: privacy,status: needs-review -->
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

## Implementation evidence

- `ogir-agent` now contains the pure initial, renewal, terminal, and cleanup-
  acknowledgement state machine, with no production factory, dependency, or
  I/O boundary added.
- The independent model exhausts all 120 state/action pairs: 26 are allowed
  and 94 reject without mutation. The cleanup query returns a request for
  exactly two terminal-required states.
- Fixed-seed histories execute exactly 1,048,576 actions: 80 scheduled and
  1,048,496 pseudo-random. The exact deep counters are 8 initial permits, 8
  initial activations, 12 renewal entries, 10 renewal permits, and 10 renewed
  activations.
- All eight capability-bearing edges reject a different session without
  mutation. Exact diagnostic allowlists remain context-free and omit the raw
  private session binding.
- External authority proof includes one compile-pass and 19 single-cause
  compile-fail doctests, plus a focused structural privacy test for every
  authority, session-ID, and state field.
- The final exact-head mutation run killed all 27 named mutations. The mutation
  loop closed four proof-gap regressions test-first and recorded durable
  lessons.
- Scenarios `OGIR-SESSION-GATE-SKIP-001`,
  `OGIR-SESSION-CAPABILITY-SUBSTITUTION-001`, and
  `OGIR-SESSION-TERMINAL-CLEANUP-001` pass within nine total validated attack
  scenarios.
- [ADR-0006](../../docs/adr/0006-local-session-lifecycle-capabilities.md) is
  accepted, and roadmap, architecture, threat-model, and test-strategy
  documentation reflect the implemented and deferred boundaries.
- Final `./scripts/check.sh` and optimized release verification pass 66
  runtime/integration tests plus 23 doctests with no failures; range whitespace,
  repository object-graph, and clean-worktree checks also pass.
- Task-scoped reviews are clean. The final whole-branch scoped re-review found
  all five findings addressed with no new breakage.
- Trusted factories and operation adapters, real cleanup I/O, and persistence/
  process-restart durability remain future work. The original 19-commit range
  certified as 34ce07e..024eccd was metadata-only rewritten DCO-clean as
  34ce07e..305546f; any later content commit requires its own DCO
  certification. Publication and line-by-line human review remain pending.
