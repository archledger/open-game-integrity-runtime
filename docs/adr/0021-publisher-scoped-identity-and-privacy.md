# ADR-0021: Publisher-scoped attestation identity and privacy

- Status: Accepted
- Date: 2026-09-06
- Owners: Initial maintainer
- Related issues: [Local M3-024 issue](../../planning/issues/024-identity-recovery-enrollment.md)
- Supersedes: None
- Superseded by: None

## Context

Roadmap spike 4 (from the approved M3 entry scoping) asks OGIR to define
publisher-scoped identity and its privacy behavior before enrollment
becomes operational. Without a written rule, an AK could become a
cross-publisher tracking handle, contradicting the privacy model's
"no universal ranked-match authorization" and "no global device ID"
commitments.

## Decision drivers

- No identifier may link a player's sessions across publishers.
- A publisher may see only the identities scoped to it.
- Key rotation within a publisher must be possible without implying
  anything about other publishers.
- The model must hold on the swtpm class now and the fTPM class later
  without redesign.

## Options considered

### A: Per-publisher key sets with scope-bound names (selected)

Each publisher scope owns its own AKs; the enrollment registry (ADR-0019)
already enforces one-modulus-one-scope, so a key cannot serve two
publishers. Names exposed to a publisher are scope-bound
(`<scope>/<key-id>` forms); nothing in a statement or enrollment record
names a device globally.

### B: One device-wide AK with per-publisher policy

Rejected: a single modulus is a cross-publisher correlation handle, and
revoking it for one publisher affects all.

### C: Anonymous credentials with unlinkable proofs

Rejected for now: OGIR has no zero-knowledge machinery, and the TPM
quote model is inherently linkable per-key; documenting this honestly
is better than pretending unlinkability.

## Decision

- Attestation identity is PER PUBLISHER SCOPE: a scope's AKs are
  created under that scope, enrolled only for it (ADR-0019 guard), and
  rotated independently.
- Statements and enrollment records carry no cross-scope identifier:
  the modulus, the backend id, and the assurance class are the only
  identity material, and the modulus is scope-unique.
- Privacy behavior: diagnostics never log moduli or names (existing
  redaction); a compromised publisher learns nothing about the player's
  other publishers; the EK remains the privacy-sensitive root and is
  never exposed in statements (the activation flow uses it only inside
  the client TPM and the verifier's transient load).
- Linkability within one scope is accepted and documented: a publisher
  can link its own sessions by design (that is what scoping permits);
  cross-scope linkability is structurally absent.

## Consequences

Simple, enforceable model today; honest limitation: intra-scope
linkability remains until any future unlinkable-credential work, which
would require its own ADR and machinery.

## Threat-model impact

Removes the cross-publisher tracking class at the identity layer.
Residual: a publisher with a stolen statement still sees its own scope's
identifiers - inherent to scoped attestation.

## Privacy impact

Definitional: this ADR IS the privacy behavior for attestation
identity. No new disclosure; existing redaction obligations extend to
activation material.

## Dependency and license impact

None.

## Validation

The one-modulus-one-scope registry tests (ADR-0019) enforce the core
invariant; the activation suite proves the EK never leaves the TPMs.

## Rollback

A superseding ADR would be required to change the scoping rule; the
registry guard makes silent violations fail closed.

## Primary sources

- Roadmap M3 spike 4; `docs/PRIVACY_MODEL.md`; ADR-0019; the approved
  M3 entry scoping (R1-R4).
