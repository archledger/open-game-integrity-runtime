# ADR-0019: Enrollment records and semantic quote validation

- Status: Accepted
- Date: 2026-09-06
- Owners: Initial maintainer
- Related issues: [Local M3-022 issue](../../planning/issues/022-enrollment-and-validation.md); [M3-022 plan](../superpowers/plans/2026-09-06-m3-022-enrollment-and-validation.md)
- Supersedes: None
- Superseded by: None

## Context

M3-021 lands real TPM quotes behind the seam, but nothing validates
them verifier-side and no enrollment exists: any statement from the
right backend would pass eyeball checks, and the unenrolled-AK and
cross-publisher-reuse attack categories have no host. M3 originally
chartered enrollment, identity, and recovery together; this decision
delivers the enrollment record model and full semantic validation now,
and explicitly re-charters the remainder (see Consequences).

## Decision drivers

- A verifier must only accept quotes from an AK enrolled for the exact
  publisher scope, under an exact assurance class.
- The TPM-echoed qualifying data is the honest binding point between a
  request and a quote; the statement digest and payload must agree.
- Cryptographic signature verification requires the raw marshaled
  TPMS_ATTEST bytes; the only available marshaling path
  (`Tss2_MU_TPMS_ATTEST_Marshal` through `tss-esapi-sys`) needs
  `unsafe`, which the workspace forbids outright. Policy coherence
  beats feature completeness in this repository.

## Options considered

### A: Semantic validation with AK-modulus binding now, cryptographic
verification deferred behind a documented blocker (selected)

Every check that does not require re-deriving the signature: strict
class equality, known-backend identity, v2 payload structure, exact
publisher-scope enrollment match on the AK modulus, echoed
qualifying-data equality, and digest/payload consistency. The deferral
and its precise blocker are recorded here and in the roadmap.

### B: Carve a lint exception and verify signatures now

Rejected for this slice: the workspace-wide `unsafe_code = "forbid"` is
a standing security posture; punching a hole in it for convenience
deserves its own reviewed decision (with a marshaling audit), not a
rider on a feature slice.

### C: Add a pure-Rust marshaling/RSA dependency to avoid unsafe

Rejected: extends the 53-crate signed inventory mid-slice and admits
crypto code without the scrutiny the design gate reserves for it.

## Decision

- Statement contract v2: the swtpm backend's payload gains a fourth
  length-prefixed field, the AK public modulus, and exposes
  `ak_modulus()` for enrollment. Fields: [echoed qualifying data,
  attested PCR digest, RSA signature, AK modulus].
- `enrollment`: `AkEnrollment` (publisher scope, AK modulus, assurance
  class) and `EnrollmentRegistry` with one-modulus-one-scope
  enforcement (the cross-publisher AK-reuse guard) and fail-closed
  record validation.
- `validation::validate_quote`: strict class gate; known-backend
  check; v2 payload structure; enrollment match on the exact publisher
  scope and modulus; echoed qualifying data must equal the request;
  the statement digest must equal the payload's PCR digest. Returns a
  `ValidatedQuote` (class, modulus, digest) that is policy input,
  never authority.
- Deliberately deferred, with blocker: cryptographic verification of
  the RSA-2048/RSASSA-SHA256 signature (the copied-public-AK forgery
  class remains uncovered until it lands), the EK-bound
  credential-activation enrollment protocol, and the publisher-scoped
  identity/privacy and recovery ADRs.

## Consequences

The unenrolled-AK, wrong-qualifying-data, cross-publisher-reuse, and
class-confusion categories are now hosted and deterministic. The
signature-forgery-by-copied-modulus category is NOT covered and is
documented as an open exposure. The roadmap M3-022 boundary re-charters
the deferred work into M3-023 (cryptographic verification plus the
enrollment protocol and identity/recovery ADRs, starting with the
unsafe-policy decision) ahead of the M3-024 attack suite.

## Threat-model impact

Within M3's mock threat model this closes the unenrolled-AK quote and
cross-publisher AK reuse classes at the validator. Residual and open:
a forger who copies an enrolled modulus and crafts payload fields
defeats this validator's semantic checks (the signature field is not
yet verified); the class gate still binds real TPM classes exactly.

## Privacy impact

None. Enrollment records carry a publisher scope string, a public
modulus, and a class label; no private key material exists OGIR-side
by construction.

## Dependency and license impact

None. No new crates; the 53-crate allowlist is unchanged.

## Validation

Fifteen tests: three enrollment unit tests (roundtrip, one-modulus-
one-scope, invalid records) and twelve integration tests against real
per-test swtpm instances (the five-test backend suite extended to the
v2 fourth field, plus seven validation scenarios: end-to-end valid,
unenrolled scope, foreign AK, wrong qualifying data, class mismatch,
tampered payload/digest, unknown backend).

## Rollback

Revert the slice; the statement contract returns to v1 (three fields)
and the enrollment/validation modules are removed. ADR-0018's backend
is otherwise unaffected.

## Primary sources

- ADR-0017 (seam and class gate), ADR-0018 (backend and contract v1).
- tss-esapi-sys 0.6.0 bindings (`Tss2_MU_TPMS_ATTEST_Marshal`
  availability), the workspace `deny.toml`/lint posture.
- Roadmap Milestone M3 attack-test categories (unenrolled AK,
  cross-publisher AK reuse, EK/AK confusion).
