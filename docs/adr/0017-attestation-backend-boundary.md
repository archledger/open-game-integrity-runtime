# ADR-0017: AttestationBackend boundary and assurance classes

- Status: Accepted
- Date: 2026-09-06
- Owners: Initial maintainer
- Related issues: [Local M3-020 issue](../../planning/issues/020-attestation-backend-seam.md); [M3 entry scoping](../superpowers/plans/2026-09-06-m3-020-attestation-backend-seam.md)
- Supersedes: None
- Superseded by: None

## Context

Milestone M3 replaces the mock attester with TPM-backed freshness and key
possession while keeping the rest of the system backend-agnostic. The
roadmap requires an `AttestationBackend` trait, three backends labeled by
assurance class (test, software TPM, hardware/firmware TPM), and the exit
criterion that the classes cannot be confused. The approved M3 entry
scoping recommended the seam land first, with zero new dependencies,
before the first external production dependency decision (tss-esapi,
M3-021).

## Decision drivers

- Assurance classes must be disjoint at an enforcement point, not by
  convention or configuration.
- The core stays backend-agnostic; no raw physical-TPM command may be
  exposed outside a backend's own boundary.
- Statements are candidate inputs, never authority (standing trust
  model).
- Errors fail closed and remain diagnosable without disclosing key
  material or statement bytes.
- The seam must exist and be reviewed before the TPM dependency arrives,
  so the dependency decision is made against a stable contract.

## Options considered

### A: A dedicated production crate `ogir-attest` holding the trait,
class taxonomy, statement shape, and acceptance gate

Selected. The seam is attester-side infrastructure used by every
backend; giving it its own dependency-free crate keeps `ogir-verifier`
publisher-side, keeps the trait out of the mock crates, and lets the
M3-021 isolation analysis reason about exactly one production surface.
Costs: one more crate; the contract is provisional until a real backend
exercises it.

### B: Define the trait inside `ogir-verifier`

Rejected. The verifier is the publisher-side appraisal authority; the
backend is the client-side attester seam. Placing the trait there would
couple every backend to the verifier crate and blur the trust boundary
the roadmap keeps explicit.

### C: Defer the trait until the TPM backend exists

Rejected. The first external dependency decision would then be made
against an unreviewed contract, and the M2 mock attester would need an
ad-hoc retrofit instead of becoming the labeled test backend now.

## Decision

- `ogir-attest` (dependency-free, `publish = false` until the workspace
  decides otherwise) defines: `AssuranceClass` (`Test`, `SoftwareTpm`,
  `HardwareFirmwareTpm`) with stable public labels; the
  `AttestationBackend` trait (`assurance_class`, `backend_id`, `quote`);
  `QuoteRequest` with bounded qualifying data; `AttestationStatement`
  with private fields, shape-invariant construction, and redacted
  `Debug`; fail-closed `BackendError`; and `accept_class`, the
  strict-equality class gate that enforces the exit criterion.
- The qualifying digest is backend-defined (each class documents its
  derivation; the mock uses a labeled hash folded with its key id);
  correspondence between a statement's digest and the verifier's own
  derivation of the request is the verifier's check, never assumed.
- The trait is a provisional contract: M3-021 (software-TPM backend) may
  harden it (for example PCR selection inputs), and any change is a
  reviewed amendment to this ADR, not a silent break.
- The labeled test backend is the M2 mock attester behind the seam
  (`ogir-mock-protocol::attest::MockAttestationBackend`, class `Test`,
  id `ogir-mock-attester-v1`).
- No implementation may expose raw physical-TPM commands through the
  seam; the isolation gate covers `ogir-attest` as a production manifest
  from this slice on.

## Consequences

Every backend lands behind one reviewed contract with a single
enforcement point for class confusion. The costs: the contract will
likely need amendment when the first TPM backend arrives (recorded as an
obligation, not a surprise), and the acceptance gate is deliberately
strict equality, which forbids any future silent class-lattice (a
verifier wanting multiple classes must enumerate them explicitly at its
own boundary).

## Threat-model impact

Within M3's mock threat model this closes the software-as-hardware
substitution class at the seam: a test or software statement can never
satisfy a hardware expectation because admission compares exact class
equality. No production trust boundary changes yet; the TPM-era threats
(quote forgery, AK confusion, resource exhaustion) arrive with M3-021+
and are hosted there.

## Privacy impact

None. Labels are non-disciplinary class strings; statements redact
payloads from `Debug`; no new claims or identifiers.

## Dependency and license impact

None. `ogir-attest` has zero dependencies. The first external production
dependency (tss-esapi route per the approved recommendation) remains the
M3-021 ADR and its human-signed `cargo-deny` policy event.

## Validation

Unit: the 3x3 class-pair gate matrix; statement shape-invariant
rejections (empty or oversized ids and payloads); request bounds;
redacted Debug. Integration: the mock backend labels every statement
`Test`, binds qualifying data deterministically and key-sensitively, and
its statements are rejected under software and hardware expectations.

## Rollback

Before acceptance, revise or discard. After acceptance, incompatible
changes require an explicit superseding ADR; the class taxonomy may only
grow through amendment with the strict-equality gate preserved.

## Primary sources

- Roadmap Milestone M3 (objective, deliverables, exit criteria) at
  `22491f3`.
- Approved M3 entry scoping: spike report and decomposition
  (`ogir/task-18-scoping/`, intake provenance) with recommendations
  R1-R4 accepted by the human on 2026-09-06.
- ADR-0003 (compatibility/attestation separation), ADR-0010/0015
  (evidence binding), the M2-019 attack-suite pattern.
