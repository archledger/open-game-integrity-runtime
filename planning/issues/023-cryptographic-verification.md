# M3-023: Cryptographic quote verification via the audited marshaling boundary
<!-- labels: type: implementation,area: tpm,area: verifier,risk: trusted-computing-base,status: needs-review -->
<!-- milestone: M3 TPM Backend -->

Status: Local integration candidate; no live GitHub issue yet. Executes the human Option A unsafe-policy decision.

## Problem

ADR-0019 left the copied-public-AK forgery exposure open: the semantic
validator cannot tell a TPM-signed quote from a crafted payload, and
the M3-024 attack suite must demonstrate the difference. Closing it
needs the raw signed bytes, whose only marshaling path requires unsafe.

## Scope

- The audited marshaling boundary: `ogir-attest-tpm` adopts its own
  lint table (`unsafe_code = "deny"`) with exactly one
  `#[allow(unsafe_code)]` block around `Tss2_MU_TPMS_ATTEST_Marshal`;
  the isolation gate enforces the one-block policy and that no other
  crate overrides the workspace posture.
- Statement contract v3: fifth payload field = marshaled TPMS_ATTEST
  bytes.
- SHA-256 promoted to production `ogir-attest` (FIPS vectors retained
  as production gates; the mock crate re-exports).
- `QuoteVerifier`: verifier-side TPM verifies RSASSA-SHA256 over the
  SHA-256 digest of the attest bytes against the ENROLLED public key;
  `validate_quote_cryptographic` = full semantic set + crypto.
- ADR-0020, index row, roadmap boundary, local issue, plan.

## Acceptance criteria

- Real quotes verify cryptographically; tampered attest bytes and
  forged signatures reject `SignatureInvalid`; all prior semantic
  rejections unchanged.
- All house gates green incl. the extended isolation gate; the
  53-crate allowlist unchanged (`tss-esapi-sys` direct but already
  admitted).

## Current state

- 2026-09-06: Implemented in `research/m3-023-cryptographic-verification`
  from `64e0299`; awaiting human review and the signed-commit gate.
