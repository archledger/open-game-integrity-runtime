# Plan: M3-020 attestation backend seam

- Status: Executed in the `research/m3-020-attestation-backend`
  worktree; local gates green; awaiting human review, signed commit, and
  separately authorized publication.
- Date: 2026-09-06.
- Baseline: merged `22491f356e9afa94779dcbea6d049717bfc3486d` (M2
  complete).
- Authority: approved M3 entry scoping (recommendations R1-R4 accepted
  2026-09-06); roadmap Milestone M3; [local issue](../../../planning/issues/020-attestation-backend-seam.md);
  [ADR-0017](../../../docs/adr/0017-attestation-backend-boundary.md).

## Tasks

1. `crates/ogir-attest` (new, dependency-free, production): trait,
   class taxonomy, request/statement shapes, error taxonomy, class gate.
2. `ogir-mock-protocol::attest`: the labeled test backend implementing
   the seam over the M2 mock attester key.
3. ADR-0017 + index row; architecture placement note; roadmap M3-020
   boundary record carrying the accepted recommendations (including the
   discrete-TPM fixture deferral); local issue; this plan.
4. Isolation gate: `ogir-attest` joins the production manifest list.

## Test inventory (executed, all green)

- Seam unit: 3x3 strict-equality gate matrix; statement shape
  rejections (empty/oversized backend id and payload); request bounds
  (empty, over-max, at-max accepted); redacted Debug; stable class
  labels.
- Test backend: deterministic key-sensitive qualifying binding; distinct
  data yields distinct digest and payload; empty request fails closed;
  test statements rejected under software and hardware expectations.

## Deliberately not done

No TPM dependency, no PCR selection, no cancellation surface: those
arrive with M3-021 (software-TPM backend) against this provisional
contract, with any trait hardening as a reviewed ADR-0017 amendment.
