# M10-050: The TBS API-layer attack families
<!-- labels: type: implementation,area: wine-tpm,status: needs-review -->
<!-- milestone: M10 Wine TPM Compatibility -->


## Problem

The M10 roadmap requires API-layer attack tests against the TBS
compatibility layer (M10-049): exhaustion, malformed buffers,
cancellation races, cross-prefix/identity leakage, and
vTPM-presented-as-hardware. M10-048 covers the manager-level
families; the layer's own surface was functional-tested only.

## What this slice delivers

1. `wine/tests/tbs_harness.c` (extended): exhaustion, fd
   stability, bad-tag and size-mismatch transparency, cancel
   storm, stdin-synchronized dead-vTPM cancel, submit/cancel
   loops for the cross-process race, and the vendor-identity
   query through the layer.
2. `wine/tests/test-tbs-attacks.py` (LGPL): the attack gate -
   the five families executed against the REAL layer and a REAL
   per-prefix swtpm, plus gate-controlled fake data sockets for
   the malformed-RESPONSE legs (EOF, sub-header size,
   0xffffffff, trailing garbage).
3. Registry scenarios (66 total): tbs-context-exhaustion (23),
   tbs-malformed-buffers (23, 26), tbs-cancel-races (23, 40),
   tbs-cross-prefix-isolation (17, 18), tbs-vtpm-not-hardware
   (17, 20); coverage stays 48/48.
4. ADR-0046 + index row; ROADMAP boundary; this issue.

## Executed evidence (dev host)

- The attack gate PASS; the M10-049 functional gate and the
  M10-048 manager gate PASS (regression); the traceability (66
  scenarios) and coverage (48/48) gates PASS.

## Security invariants

- 16/17: no physical-TPM path (inherited; the layer is
  untouched by this slice).
- 23/26: the fixed limits hold under attack.
- 18: per-prefix identity isolation at the API layer.

## Out of scope

- WoW64 ABI tests (next slice); the M10 exit audit; upstream
  submission.
