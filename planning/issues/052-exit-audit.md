# M10-052: The M10 exit audit
<!-- labels: type: implementation,area: wine-tpm,status: needs-review -->
<!-- milestone: M10 Wine TPM Compatibility -->


## Problem

M10's five slices must be audited against the roadmap's exit
criteria before the milestone closes: physical TPM isolation
mechanically tested; compatibility claims not reused as trust
claims; the patch suitable for upstream review or clearly
experimental.

## What this slice delivers

1. `wine/tests/run-all-gates.py` (LGPL): the whole wine/ suite in
   one fail-closed command - the repo-wide isolation sweep (no
   non-gate wine/ source references the host TPM) plus the
   manager, functional, attack-family, and WoW64 gates.
2. `wine/tbs/UPSTREAM-NOTES.md` (LGPL): the honest upstream
   delta - the upstreamable core and the four blockers that keep
   the patch experimental.
3. ADR-0048: the audit record - all three criteria PASS/PASS/
   CLEARLY EXPERIMENTAL, the deliverables audit (all six
   deliverables and seven attack families mapped to executed
   evidence), and the milestone-closing statement.
4. ROADMAP boundary (ON MERGE, MILESTONE M10 IS COMPLETE); the
   ADR index row; this issue.

## Executed evidence (dev host)

- The full suite PASS via run-all-gates.py; traceability (67
  scenarios) + coverage (48/48) PASS; ADR + metadata gates PASS.

## Security invariants

- 16/17: the isolation claim is enforced by the sweep + gates,
  not asserted.
- 20: the trust-claim separation is executed (identity through
  the layer is the emulator's; reserved zeros from both widths).

## Out of scope

- Any M11/M12 work (outside the standing authorization); an
  actual upstream submission.
