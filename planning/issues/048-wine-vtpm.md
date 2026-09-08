# M10-048: The per-prefix virtual TPM
<!-- labels: type: implementation,area: wine-tpm,status: needs-review -->
<!-- milestone: M10 Wine TPM Compatibility -->


## Problem

M10 improves ordinary Windows TPM API compatibility under Wine
without conflating it with physical-host attestation; the
per-prefix vTPM manager is the deliverable everything else lands
on.

## What this slice delivers

1. `wine/vtpm/vtpm-manager.sh` (LGPL, ADR-0044): one swtpm per
   prefix - state under <prefix>/vtpm/, runtime-dir sockets keyed
   by a hash of the prefix path (structural isolation),
   start/stop/reset/status, idempotent start, wipe-on-reset.
2. `wine/tests/test-vtpm-manager.py` (LGPL): the mechanical
   four-family gate - NO host TPM reference in the manager,
   per-prefix state/socket separation, reset wipes
   (mtime-checked), cleanup removes sockets.
3. THE CAPABILITY CONTRACT (wine/README.md + ADR-0044): the vTPM
   is the software-tpm class - ordinary Windows TPM compatibility,
   never hardware-host attestation (invariant 17).
4. ADR-0044 + index row; ROADMAP boundary; this issue; the plan.

## Executed evidence (dev host)

- The manager smoke (start/status/state/stop/status) and the
  four-family gate PASS.

## Security invariants

- The manager has NO physical TPM path (mechanically checked).
- Prefix isolation is structural (path-hash sockets, per-prefix
  state).
- LGPL-2.1-or-later for the Wine-targeted source.

## Out of scope

- The TBS implementation against the per-prefix socket; WoW64 ABI
  tests; exhaustion/malformed/cancel/leakage API-layer families;
  the M10 exit audit.
