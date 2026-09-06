# Plan: M3-023 cryptographic verification

- Status: Executed in `research/m3-023-cryptographic-verification`; all
  local gates green; awaiting human review, signed commit, and
  separately authorized publication.
- Date: 2026-09-06.
- Baseline: merged `64e02999603371607c77f3c6cc82b3376559745f`.
- Authority: human Option A decision (2026-09-06);
  [ADR-0020](../../../docs/adr/0020-audited-unsafe-marshaling-and-cryptographic-verification.md);
  [local issue](../../../planning/issues/023-cryptographic-verification.md).

## Tasks

1. SHA-256 promotion: module moved to `ogir-attest`; `ogir-mock-keys`
   re-exports (mock crate gains a production-crate dependency edge,
   direction allowed by the isolation gate).
2. The lint carve-out: own `[lints]` table mirroring the workspace
   except `unsafe_code = "deny"`; `marshal.rs` with the single
   audited block; isolation-gate enforcement (deny posture present,
   no other crate overrides, exactly one allow-block).
3. Statement contract v3 (fifth field = marshaled attest bytes).
4. `QuoteVerifier` + `validate_quote_cryptographic`:
   `load_external_public` of the ENROLLED key into the verifier TPM
   (Null hierarchy), `verify_signature` over the SHA-256 digest of the
   attest bytes, deterministic `SignatureInvalid` on failure.
5. Three cryptographic tests (valid verifies; tampered bytes reject;
   garbage-signature forgery rejects) plus the updated semantic suite;
   ADR-0020, index row, roadmap boundary, issue, plan.

## Test inventory (executed, all green)

- Eighteen ogir-attest-tpm tests: 3 enrollment, 5 backend v3 (fifth
  field asserted), 10 validation (7 semantic scenarios updated to v3
  plus the 3 cryptographic ones).
- Isolation gate extended and green (one-block unsafe policy).

## Deliberately not done

The EK-bound credential-activation enrollment prototype and the
identity/privacy and recovery ADRs remain the next slice before the
M3-024 attack suite and exit audit.
