# M3 exit-criteria audit

- agent: zcode
- timestamp: 2026-09-06T11:45:00-04:00
- audited ref: branch `research/m3-025-attack-suite-and-exit-audit` from merged main `3660cc1` (all M3 engineering slices live).
- method: executed-test evidence against the roadmap's four M3 exit criteria; static review of the API surface for the non-exportability criterion.

## Criterion 1: "Hardware and software assurance classes cannot be confused."

**PASS.** The strict-equality class gate (`ogir_attest::accept_class`,
ADR-0017) admits exact matches only; the 3x3 class-pair matrix is
unit-tested, and the attack suite's software-as-hardware category
re-executes it against a real swtpm quote through the full
cryptographic chain. Every backend labels every statement with its
class at construction; no constructor accepts a class parameter.

## Criterion 2: "The verifier validates AK enrollment and quote binding."

**PASS.** Enrollment is exact-per-scope with one-modulus-one-scope
(ADR-0019); quote binding is enforced at three layers: the TPM-echoed
qualifying data must equal the request byte for byte, the statement
digest must match the payload's PCR digest, and - since ADR-0020 - the
RSASSA-SHA256 signature over the marshaled TPMS_ATTEST bytes must
verify against the ENROLLED public key inside a verifier-side TPM. The
attack suite demonstrates every layer rejecting its category
(unenrolled AK, wrong qualifying data, copied public AK, stale quote,
malformed structures).

## Criterion 3: "Private AK/session material is not exportable through OGIR APIs."

**PASS (static).** No OGIR type exposes private key material: the
statement carries only public fields (echo, digest, signature, modulus,
attest bytes); the enrollment record carries a public modulus; the
activation flow moves only sealed blobs; the mock HMAC keys are
test-only by ADR-0016 and isolated by the gate. The only unsafe block
in the workspace (ADR-0020, gate-enforced to exactly one) marshals a
public structure. The swtpm and fTPM key material lives in the TPMs;
the workspace's Rust API surface has no private-key type to export.
(Caveat: this is a static audit of the API surface, not a formal
proof.)

## Criterion 4: "All TPM errors fail closed for protected mode and remain diagnosable."

**PASS.** `map_tss_error`/`map_error` map every TSS-layer condition to
the seam's fail-closed diagnosable taxonomy (`InvalidRequest`,
`Unavailable`, `Unsupported`, `Busy`, `Internal`); the attack suite's
resource-exhaustion and daemon-killed categories demonstrate the
behavior against a real TPM: no panic, no hang, diagnosable errors,
and the exhaustion did not corrupt the TPM (it resumed quoting or
failed closed).

## Verdict

All four M3 exit criteria hold by executed-test or verified-static
evidence. With the ten attack categories green, Milestone M3 is
COMPLETE pending human acceptance of this audit. Not carried into M3's
record: the fTPM hardware-class backend remains future work (the
discrete-TPM fixture is deferred per the accepted M3 entry
recommendation; the assurance-class taxonomy, seam, and validator are
class-agnostic and ready for it), and endorsement-certificate
authentication of the EK is ADR-0022 option C future work.
