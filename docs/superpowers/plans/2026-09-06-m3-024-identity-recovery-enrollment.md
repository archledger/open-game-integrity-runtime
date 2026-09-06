# Plan: M3-024 identity, recovery, and enrollment prototype

- Status: Executed in `research/m3-024-identity-recovery-enrollment`;
  all local gates green; awaiting human review, signed commit, and
  separately authorized publication.
- Date: 2026-09-06.
- Baseline: merged `4b583bf8d23413b5814fd28d43273c749e9d84b6`.
- Authority: roadmap M3 spikes 3-5;
  [ADR-0021](../../../docs/adr/0021-publisher-scoped-identity-and-privacy.md),
  [ADR-0022](../../../docs/adr/0022-recovery-after-tpm-state-loss.md);
  [local issue](../../../planning/issues/024-identity-recovery-enrollment.md).

## Tasks

1. `activation.rs`: EK (restricted-decryption RSA, AES-256-CFB) and AK
   (restricted-signing RSA, RSASSA-SHA256) primaries under Endorsement
   with empty auth; `ActivationRequest` (marshaled EK public via the
   `Marshall` trait + AK name from `read_public`);
   `seal_credential` (verifier `load_external_public` of the EK +
   `make_credential`); `activate` (dual password sessions; both the AK
   and the EK must be authorized); `ak_modulus` for enrollment.
2. ADR-0021 and ADR-0022 with options and honest limitations; index
   rows; roadmap boundary; local issue; this plan.
3. Three integration tests against real per-test swtpm instances.

## Test inventory (executed, all green)

- Genuine holder: seal -> activate -> exact token recovery; AK modulus
  available (256 bytes).
- Foreign client on a different swtpm: activation fails.
- Corrupted AK name (EK/AK confusion): activation fails.

## Development lessons

ReadPublic and other non-authed commands fail with 0x98B ("handle not
correct for the use, session 1") when a context carries a leftover
password session - clear sessions after authed batches.
ActivateCredential requires BOTH session 1 (AK) and session 2 (EK)
authorizations; the EK template uses the standard
restricted-decryption form. `Public::marshall` comes from the
`tss_esapi::traits::Marshall` trait.

## Deliberately not done

Endorsement-certificate authentication of the EK (future work, recorded
in ADR-0022 option C); registry integration of the activation token
(the prototype stands alone); the M3-025 attack suite and exit audit.
