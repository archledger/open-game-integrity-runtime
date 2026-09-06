# M3-020: Attestation backend seam and assurance classes
<!-- labels: type: architecture,type: implementation,area: tpm,area: agent,risk: trusted-computing-base,status: needs-review -->
<!-- milestone: M3 TPM Backend -->

Status: Local integration candidate; no live GitHub issue yet. Implements the first M3 slice under the approved entry-scoping recommendations (R1-R4 accepted 2026-09-06, including the discrete-TPM fixture deferral record).

## Problem

Milestone M3 replaces the mock attester with TPM-backed freshness and key
possession while the system stays backend-agnostic. Before the first
external production dependency decision (tss-esapi, M3-021), the seam
that every backend will implement must exist, be reviewed, and carry the
assurance-class enforcement that the M3 exit criteria demand; otherwise
the dependency choice lands against an unreviewed contract.

## Scope

- `crates/ogir-attest`: the `AttestationBackend` trait, `AssuranceClass`
  taxonomy with stable labels, bounded `QuoteRequest`,
  shape-invariant `AttestationStatement` with redacted Debug, fail-closed
  `BackendError`, and the strict-equality `accept_class` gate.
- The M2 mock attester behind the seam as the labeled test backend
  (`MockAttestationBackend`, class `test`, id
  `ogir-mock-attester-v1`), with deterministic, key-sensitive
  qualifying-data binding.
- ADR-0017 with the boundary decision and the no-raw-TPM-command rule;
  the isolation gate extended to treat `ogir-attest` as a production
  manifest; roadmap boundary record including the accepted R1-R4
  recommendations.
- Zero new dependencies; `ogir-model` untouched.

## Acceptance criteria

- The 3x3 class-pair matrix proves strict equality is the only admitting
  comparison; test statements are rejected under software and hardware
  expectations.
- Statement construction rejects invalid shapes; requests enforce
  bounds; Debug redacts payloads.
- All local gates green (fmt, clippy, rustdoc `-D warnings`, full
  workspace tests, isolation script).
- Signed commit verified per house flow.

## Current state

- 2026-09-06: Implemented in `research/m3-020-attestation-backend` from
  `22491f3`; awaiting human review and the signed-commit gate.
