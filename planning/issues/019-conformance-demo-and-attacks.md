# M2-019: Conformance vectors, CLI demonstration, attack suite, and renewal fencing
<!-- labels: type: implementation,area: protocol,area: verifier,type: test,risk: trusted-computing-base,status: needs-review -->
<!-- milestone: M2 Mock End-to-End Proof -->

Status: Local integration candidate; no live GitHub issue yet. Implements the M2-019 charter; on merge it completes Milestone M2.

## Problem

M2-017/018 built the mock substrate and the verifier-to-admission path,
but the milestone exit criteria still lack their executable proof:
frozen conformance vectors with independent-encoder agreement, the CLI
demonstration that never returns a trusted local boolean, the full
twelve-category attack suite, and renewal fencing per ADR-0014.

## Scope

- `renewal.rs`: mock session owner with one-pending, one-successor
  fencing, idempotent exact redelivery, and pending-grants-nothing.
- `examples/mock-demo.rs`: deterministic end-to-end demonstration with
  digest/redacted output and server-side-only admission.
- `tests/conformance.rs`: four frozen hex vectors plus the independent
  second encoder (byte-for-byte agreement for all four classes).
- `tests/attack_suite.rs`: all twelve roadmap attack-test categories,
  each deterministic non-allow.
- Plan record, this issue, and the roadmap M2 completion boundary.

## Acceptance criteria

- All local gates green: fmt, clippy, rustdoc under `-D warnings`, 462
  workspace tests, isolation script.
- All twelve attack categories reject deterministically; the demo runs
  end to end with no trusted local boolean.
- Frozen vectors reproduce byte for byte and verify as live objects.
- No production crate changed; no dependency added.

## Current state

- 2026-09-06: Implemented in `research/m2-019-conformance-demo-and-attacks`
  from `c5bdb88`; awaiting human review and the signed-commit gate.
