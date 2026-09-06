# ADR-0022: Recovery after TPM state loss

- Status: Accepted
- Date: 2026-09-06
- Owners: Initial maintainer
- Related issues: [Local M3-024 issue](../../planning/issues/024-identity-recovery-enrollment.md)
- Supersedes: None
- Superseded by: None

## Context

Roadmap spike 5 requires defining recovery after TPM clear, motherboard
replacement, firmware update, or agent reinstallation. A TPM clear
destroys the endorsement and attestation key material; any enrollment
and any outstanding authorization predicated on the old keys must fail
closed, never silently recover.

## Decision drivers

- Loss of TPM key material must never resurrect old authorization.
- Recovery must be an explicit re-enrollment, not a state migration.
- Each loss event has a distinct cause and a distinct operator path;
  the MODEL must distinguish them even where the mechanism is shared.
- No recovery path may bypass the enrollment validation chain.

## Options considered

### A: Fail-closed re-enrollment with per-cause procedures (selected)

All four events end the affected keys: enrollment lookups miss (new
modulus), quotes fail activation/verification, permits based on them
expire naturally per ADR-0014. Recovery = fresh enrollment of the new
keys with the same publisher scope, with the event recorded.

### B: Key backup/migration (duplicated keys)

Rejected: TPM-bound keys are the root of trust; duplicating them
outside the TPM defeats the assurance class and creates a new attack
surface.

### C: Automatic recovery via platform attestation of the new TPM

Deferred: technically attractive (prove the new TPM's provenance and
re-enroll automatically) but requires endorsement-certificate
validation machinery OGIR has not built; documented as future work.

## Decision

- TPM clear: all endorsement-hierarchy keys are destroyed. Every
  enrollment for the old moduli becomes inert (registry entries may
  remain as tombstones); statements from pre-clear keys fail
  cryptographic verification (ADR-0020). Recovery: new
  `ActivationKeys::create` + fresh enrollment; the event is logged as
  `tpm-clear`.
- Motherboard replacement: equivalent to TPM clear plus a new EK; the
  endorsement certificate changes, so future automated provenance
  checks (option C) would treat it as a new device identity. Recovery
  path: re-enrollment; event `hardware-replacement`.
- Firmware update: if the TPM survives with keys intact (common for
  fTPM with preserved state), nothing changes; if state is reset, the
  TPM-clear path applies. The client detects which case by testing AK
  presence; event `firmware-update-reset` or no event.
- Agent reinstallation: TPM keys persist (they live in the TPM, not the
  agent); the agent reloads key handles. Only if the agent recreated
  keys does re-enrollment apply; event `agent-key-recreation`.
- No recovery flow may copy key material, mint permits, or extend old
  validity. Recovery is always: create keys, enroll, then proceed
  through normal validation.

## Consequences

Recovery is deliberately mundane and auditable. Cost: users re-attest
after clears; no silent continuity. Option C remains the future
improvement.

## Threat-model impact

Closes the "resurrected authorization after state loss" class: old
statements cannot validate (wrong modulus), old sealed credentials
cannot activate (wrong EK), and registry tombstones preserve audit.

## Privacy impact

Tombstones retain only scope + modulus + class (already public);
per-cause events are operational metadata, not player data.

## Dependency and license impact

None.

## Validation

The activation suite's foreign-client rejection demonstrates the core
property: a new TPM's keys cannot activate material sealed to the old
keys.

## Rollback

A superseding ADR would be required to add any migration path; the
fail-closed default cannot be silently weakened.

## Primary sources

- Roadmap M3 spike 5; ADR-0014 (finite validity, no resurrection),
  ADR-0019 (registry), ADR-0020 (verification); TPM 2.0 clear
  semantics (Part 1).
