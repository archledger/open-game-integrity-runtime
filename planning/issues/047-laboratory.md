# M9-047: The invariant-coverage gate, the registry completion, and the dashboard
<!-- labels: type: test,area: attack-lab,status: needs-review -->
<!-- milestone: M9 Attack Laboratory -->


## Problem

M9's exit criterion demands every security invariant maps to at
least one executable scenario; the mapping and the dashboard were
missing.

## What this slice delivers

1. scripts/check-invariant-coverage.py (ADR-0043): the mechanical
   gate over all 48 invariants, CI-enforced.
2. 21 registry scenarios mapping the previously-unmapped
   invariants to their already-executed suite legs (registry: 61
   scenarios, 48/48).
3. scripts/security-dashboard.py: per-invariant counts and gate
   status - test status, not marketing scores.
4. The M9 exit audit (criteria 1-3 satisfied; the bare-metal
   physical-TPM leg recorded as the open follow-up).

## Executed evidence (dev host)

- The coverage gate PASS (48/48); the dashboard renders.

## Out of scope

- The physical-TPM bare-metal leg (recorded); M10.
