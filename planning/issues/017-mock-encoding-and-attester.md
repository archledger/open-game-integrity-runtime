# M2-017: Implement the mock encoding and attester
<!-- labels: type: implementation,area: protocol,area: verifier,risk: trusted-computing-base,status: needs-review -->
<!-- milestone: M2 Mock End-to-End Proof -->

Status: Local integration candidate; no live GitHub issue yet. Implements the ADR-0015/ADR-0016 obligations under the approved M2-017 charter.

## Problem

ADR-0015 and ADR-0016 specify the mock substrate but no encoder, parser,
key primitive, or signed object exists. Every later M2 slice (verifier
policy, permits, proof of possession wiring, conformance vectors, the
attack suite) needs this substrate to exist and to fail closed under
adversarial input before any of it can be reviewed against real behavior.

## Scope

- `crates/ogir-mock-keys`: in-repo SHA-256 and HMAC-SHA256 with FIPS 180-4
  and RFC 4231 vectors, three ephemeral key classes with deterministic
  derivation and `OGIRMOCK`-namespaced ids, a mock key directory modeling
  the ADR-0016 compromise boundary, full Debug redaction.
- `crates/ogir-mock-protocol`: ADR-0015 record encoding and parsing with
  fail-closed structural rejection, the four signed object classes with
  frozen registries, the ADR-0016 proof-of-possession construction, and
  the test-only 16-byte frame header with downgrade rejection.
- `ogir-protocol`: `MessageKind` 5 through 8 allocation with a
  reserved-range-aware `from_u16`.
- `scripts/test-mock-substrate.py`: production-graph exclusion gate.
- Plan and issue records.

## Acceptance criteria

- All local gates green: fmt, clippy (workspace-deny lints), full
  workspace tests, isolation script.
- FIPS 180-4 and RFC 4231 vectors pass; derivation is reproducible.
- Every single-bit flip of a signed challenge rejects; cross-class
  substitution rejects; duplicate, unknown, out-of-order, truncated,
  oversized, and trailing inputs reject deterministically.
- No production crate depends on a mock crate; `ogir-model` unchanged;
  no dependency added.

## Current state

- 2026-09-05: Implemented in `research/m2-017-mock-encoding-and-attester`
  from `c90c3d70`; 371 workspace tests green; awaiting human review and
  the signed-commit gate.
