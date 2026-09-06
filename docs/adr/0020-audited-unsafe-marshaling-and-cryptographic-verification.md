# ADR-0020: The audited unsafe marshaling boundary and cryptographic quote verification

- Status: Accepted
- Date: 2026-09-06
- Owners: Initial maintainer
- Related issues: [Local M3-023 issue](../../planning/issues/023-cryptographic-verification.md); [M3-023 plan](../superpowers/plans/2026-09-06-m3-023-cryptographic-verification.md)
- Supersedes: None
- Superseded by: None

## Context

ADR-0019 deferred cryptographic signature verification because the only
path to the raw, signed TPMS_ATTEST bytes is
`Tss2_MU_TPMS_ATTEST_Marshal` through `tss-esapi-sys`, which requires
`unsafe`, and the workspace forbids unsafe outright. The human selected
Option A on 2026-09-06: a reviewed, audited, single-block lint carve-out
rather than a new dependency.

## Decision drivers

- Close the copied-public-AK forgery exposure: a forger with the
  enrolled modulus but no private key must not be able to produce an
  acceptable statement.
- Keep the unsafe surface minimal, enumerated, and mechanically
  enforced; the workspace forbid posture stays intact everywhere else.
- No new external dependencies; the 53-crate signed inventory is
- unchanged.
- The verifier must check the signature against the ENROLLED key, never
  key material from the statement.

## Options considered

### A: One audited `#[allow(unsafe_code)]` block (selected)

The crate-level posture becomes `unsafe_code = "deny"` (overridable)
instead of the inherited `forbid`, admitting exactly one
`#[allow(unsafe_code)]` function wrapping the single
`Tss2_MU_TPMS_ATTEST_Marshal` call, with a written safety argument.

### B: Admit a marshaling-safe or RSA dependency

Rejected by the human decision: extends the signed inventory and admits
crypto code without the scrutiny the design gate reserves.

### C: Keep the deferral

Rejected: the copied-public-AK exposure would persist into the M3-024
attack suite, which must demonstrate its closure.

## Decision

- `crates/ogir-attest-tpm` replaces `[lints] workspace = true` with its
  own table mirroring every workspace lint except `unsafe_code`, which
  is `deny`. The isolation gate enforces: the deny posture exists, no
  other crate overrides the unsafe posture, and exactly ONE
  `#[allow(unsafe_code)]` block exists in the crate's sources.
- `marshal.rs` holds that single block around the marshal call, with a
  function-level safety argument (initialized struct from the safe
  `From` conversion, live correctly-sized buffer, zero-based offset
  bounded by the MU layer, no escaping pointers).
- Statement contract v3: the payload gains a fifth length-prefixed
  field, the marshaled TPMS_ATTEST bytes.
- The in-repo SHA-256 implementation moves from the test-only
  `ogir-mock-keys` into production `ogir-attest` (this ADR authorizes
  that promotion; the HMAC authenticator remains test-only per
  ADR-0016), keeping the FIPS 180-4 vector tests as production gates.
  `ogir-mock-keys` re-exports it; no behavior changes.
- `validation::QuoteVerifier` connects to a verifier-side swtpm,
  loads the ENROLLED public key via `load_external_public` (Null
  hierarchy; never statement material), and asks the TPM to verify the
  RSASSA-SHA256 signature over the SHA-256 digest of the marshaled
  bytes. `validate_quote_cryptographic` runs the full ADR-0019 semantic
  set first, then this check. Failure is `SignatureInvalid`,
  deterministic and non-disciplinary.

## Consequences

The copied-public-AK forgery class is closed for swtpm-class
statements: without the enrolled AK's private key no acceptable
signature exists. Costs: the workspace has exactly one unsafe block
whose justification is now permanent review surface, the verifier
needs a TPM context (swtpm today, fTPM in M3-023's remainder), and the
statement payload grows by the attestation size.

## Threat-model impact

Closes: copied public AK without TPM possession; tampered attestation
bytes (signature no longer covers them); crafted signatures. The M3-024
attack suite will demonstrate each.

## Privacy impact

None. The digest computation is local; verifier contexts redact Debug;
no new identifiers.

## Dependency and license impact

None external. `tss-esapi-sys` becomes a direct dependency of
`ogir-attest-tpm` (already in the 53-crate allowlist); the allowlist
itself is unchanged.

## Validation

Eighteen tests: the three enrollment unit tests; the five-test backend
suite asserting the v3 fifth field; ten validation tests including
end-to-end cryptographic verification of a real quote, tampered
attestation bytes rejecting with `SignatureInvalid`, and a
garbage-signature forgery rejecting with `SignatureInvalid`. The
isolation gate enforces the one-block unsafe policy.

## Rollback

Revert the slice: the crate returns to `[lints] workspace = true`
(forbid restored workspace-wide), SHA-256 returns to the mock crate,
contract v2 resumes, and the ADR-0019 deferral exposure reopens.

## Primary sources

- tss-esapi-sys 0.6.0 bindings (`Tss2_MU_TPMS_ATTEST_Marshal`
  signature: `size_t` buffer and offset); tss-esapi 7.7.0
  (`load_external_public`, `verify_signature`, `From<Attest> for
  TPMS_ATTEST`).
- ADR-0019 (the deferral and blocker), ADR-0016 (promotion clause),
  ADR-0017/0018 (seam, backend, contract lineage).
- The human Option A decision, 2026-09-06.
