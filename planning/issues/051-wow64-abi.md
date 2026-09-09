# M10-051: The WoW64 ABI tests
<!-- labels: type: implementation,area: wine-tpm,status: needs-review -->
<!-- milestone: M10 Wine TPM Compatibility -->


## Problem

The M10 roadmap requires WoW64 ABI tests for the Wine TPM
compatibility track: evidence that the TBS layer's documented
ABI works from real Windows-shaped callers - both 64-bit and
32-bit (WoW64) - against the per-prefix vTPM.

## What this slice delivers

1. `wine/tbs/tbs.c` + `wine/tbs/include/tbs.h`: the PE build
   mode (-DOGIR_TBS_PE) - the same five transport primitives
   behind winsock (AF_UNIX through ws2_32, probed; lazy
   WSAStartup; DWORD-ms timeouts), all TBS logic shared verbatim
   with the unchanged POSIX path; header guards where mingw's
   winerror.h already defines the same TBS_E_* values.
2. `wine/tests/test-tbs-wow64.py` (LGPL): the dev-host gate -
   builds the layer + harness as PE binaries for x86_64 and
   i686, asserts the object-level symbol shapes (i386 stdcall
   decorations with exact argument-byte counts; x64 undecorated),
   and runs the TBS behavior matrix under Wine for both
   architectures (i686 via WoW64), including distinct
   per-architecture random payloads and fail-closed after the
   vTPM stops.
3. `wine/tests/tbs_harness.c`: guarded fd-count helper (POSIX
   only; PE reports -1 and the gate skips that scenario).
4. Registry scenario OGIR-M10-TBS-WOW64 (invariants 28, 17; 67
   scenarios, coverage 48/48); ADR-0047 + index row; ROADMAP
   boundary; this issue.

## Executed evidence (dev host)

- wine/tests/test-tbs-wow64.py PASS; the POSIX regression set
  (test-tbs.py, test-tbs-attacks.py, test-vtpm-manager.py) PASS
  unchanged; traceability + coverage gates PASS.

## Security invariants

- 28: the boundary discipline (validation before use) holds for
  32-bit and 64-bit callers alike (executed).
- 17: PE callers terminate at the same isolated per-prefix
  vTPM; no new transport surface.

## Out of scope

- The M10 exit audit (next slice); upstream submission (a
  Wine-tree integration would derive the prefix from Wine
  internals - the recorded integration point).
