# M3-022: AK enrollment records and semantic quote validation
<!-- labels: type: implementation,area: tpm,area: verifier,risk: trusted-computing-base,status: needs-review -->
<!-- milestone: M3 TPM Backend -->

Status: Local integration candidate; no live GitHub issue yet. Delivers the enrollment/validation half of the original M3-022 charter; the remainder is re-chartered to M3-023 per ADR-0019.

## Problem

M3-021 lands real TPM quotes but nothing validates them verifier-side
and no enrollment exists: any right-backend statement would pass
eyeball checks, and the unenrolled-AK and cross-publisher-reuse attack
categories have no host.

## Scope

- Statement contract v2: the AK public modulus as the fourth payload
  field plus the `ak_modulus()` accessor (ADR-0018 contract amendment).
- `enrollment`: publisher-scoped `AkEnrollment` records and the
  `EnrollmentRegistry` with one-modulus-one-scope enforcement and
  fail-closed record validation.
- `validation::validate_quote`: strict class gate, known-backend
  check, v2 payload structure, exact publisher-scope enrollment match,
  TPM-echoed qualifying-data equality, and digest/payload consistency,
  returning a `ValidatedQuote` that is policy input, never authority.
- ADR-0019 (with the cryptographic-verification deferral and its
  unsafe-policy blocker), roadmap re-charter note, local issue, plan.

## Acceptance criteria

- All house gates green, with twelve real-swtpm integration tests
  (backend v2 suite plus seven validation scenarios) and three
  enrollment unit tests.
- Every rejection path deterministic: unenrolled scope, foreign AK,
  wrong qualifying data, class mismatch, tampered payload, unknown
  backend.
- No new dependencies; the 53-crate allowlist unchanged.

## Current state

- 2026-09-06: Implemented in `research/m3-022-enrollment-and-validation`
  from `507b925`; awaiting human review and the signed-commit gate.
