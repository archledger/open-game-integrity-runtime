# ADR-0048: The M10 exit audit

- Status: Accepted
- Date: 2026-09-09
- Owners: Initial maintainer
- Related issues: [Local M10-052 issue](../../planning/issues/052-exit-audit.md)
- Supersedes: None
- Superseded by: None

## Context

M10 (Wine TPM compatibility) delivered five slices: the
per-prefix vTPM manager (ADR-0044), the TBS compatibility layer
(ADR-0045), the API-layer attack families (ADR-0046), and the
WoW64 ABI tests (ADR-0047). The milestone closes only against
its roadmap exit criteria, audited here.

## Decision drivers

- The M10 exit criteria, verbatim from the roadmap: physical
  TPM isolation is mechanically tested; compatibility claims
  are not reused as trust claims; the patch is suitable for
  upstream review or remains clearly experimental.
- The audit is EXECUTED, not argued: every criterion cites a
  gate or an artifact that exists and runs.
- M11 (publisher pilot) and M12 (production candidate) are
  beyond M10: closing M10 ends the standing authorization's
  scope.

## Decision

### Criterion 1: Physical TPM isolation is mechanically tested - PASS

- `wine/tests/run-all-gates.py` (new) sweeps EVERY non-gate
  wine/ source for host-TPM references (/dev/tpm, /dev/tpmrm,
  tpm2_) and runs the whole suite in one fail-closed command;
  executed on the dev host 2026-09-09: PASS.
- The manager gate (ADR-0044) greps vtpm-manager.sh and proves
  per-prefix state/socket separation, reset-wipes, and cleanup.
- The functional gate (ADR-0045) greps tbs.c and tbs.h; the
  layer's only transport is the per-prefix socket pair - there
  is no host path to remove because none was ever written.
- The attack gate (ADR-0046) proves cross-prefix no-reach: a
  stopped prefix fails closed while another keeps serving.

### Criterion 2: Compatibility claims are not reused as trust claims - PASS

- The capability contract (wine/README.md, ADR-0044) pins the
  vTPM to ADR-0017's software-tpm class, rejected wherever
  hardware is required (invariant 17).
- The layer CANNOT emit an assurance claim at all: it returns
  TPM bytes and TBS codes only; device info reports only the
  version fields with reserved zeros.
- The attack family "vTPM-presented-as-hardware" executes the
  check: the vendor identity through the layer is the software
  emulator's own (ADR-0046), and the WoW64 gate re-asserts the
  reserved zeros from both PE widths (ADR-0047).
- The registry maps invariants 17/18/20 to executable scenarios;
  the coverage gate holds 48/48 and the security dashboard
  reports gate: pass (67 scenarios at closure).
- Residual (declared): within-prefix publisher separation is
  out of the compat layer's scope by design - the vTPM has no
  publisher concept; trust decisions stay in the attest/verifier
  crates where the class gate lives.

### Criterion 3: The patch is suitable for upstream review or remains clearly experimental - VERDICT: CLEARLY EXPERIMENTAL

`wine/tbs/UPSTREAM-NOTES.md` (new) is the honest delta record:
the upstreamable core (the five entry points, the transport
design, the spec promotions) is identified, and so are the four
things that keep the patch experimental today - getenv-based
prefix discovery (a Wine-tree version derives the prefix from
Wine internals), the unlocked context registry (no shared-
context serialization story yet), cancel bounded to swtpm's
inability to interrupt in-flight commands, and the open design
question of a Wine dll depending on swtpm at runtime. No
submission is made; nothing here presents itself as upstream
ready.

### Deliverables audit (roadmap list -> evidence)

- Research of current Wine tbs.dll coverage: upstream master is
  stubs (recorded in ADR-0045 with sources). DONE.
- Per-prefix virtual TPM manager (swtpm): ADR-0044. DONE.
- Selected TBS semantics against the vTPM: ADR-0045. DONE.
- Isolation/persistence/reset/cleanup policy: ADR-0044 (+ the
  discovery symlink, ADR-0045). DONE.
- WoW64 ABI tests: ADR-0047. DONE.
- Explicit capability flag: wine/README.md (ADR-0044). DONE.
- The seven required attack tests: ADR-0046 (+ 0044/0045/0047
  gates); identity-leakage residual declared above. DONE.

## Consequences

- MILESTONE M10 IS COMPLETE on merge; M0 through M10 are all
  closed. M11 (publisher pilot) requires new, explicit
  authorization - it is outside the standing one.
- The whole wine/ compat surface is reproducibly auditable with
  one command (`wine/tests/run-all-gates.py`), which is the
  artifact future slices extend.

## Threat-model impact

None new: the audit adds no product behavior; it consolidates
evidence.

## Privacy impact

None: all executed gates use ephemeral per-prefix state under
their own tmp trees.

## Dependency and license impact

`wine/tests/run-all-gates.py` and `wine/tbs/UPSTREAM-NOTES.md`
are LGPL-2.1-or-later under wine/ (existing boundaries; the
notes file is .md so the source-license gate ignores it, and it
carries the LGPL notice in the ADR for clarity).

## Validation

Executed on the dev host (2026-09-09): the full suite PASS
(`wine/tests/run-all-gates.py`: isolation sweep + manager +
functional + attacks + wow64); scripts/
check-attack-scenario-traceability.py (67 scenarios) and
scripts/check-invariant-coverage.py (48/48) PASS;
scripts/check-adr-index.sh and the metadata gate PASS.

## Rollback

Revert the commit; the audit artifacts disappear and the
milestone record reverts to four-slices-in (the underlying
slices are independently reverted by their own commits).

## Primary sources

- The M10 roadmap section (deliverables, attack tests, exit
  criteria); ADRs 0044-0047; the executed gate outputs
  (2026-09-09, dev host).
