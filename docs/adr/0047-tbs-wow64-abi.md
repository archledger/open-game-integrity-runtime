# ADR-0047: The TBS PE transport and the WoW64 ABI tests

- Status: Accepted
- Date: 2026-09-09
- Owners: Initial maintainer
- Related issues: [Local M10-051 issue](../../planning/issues/051-wow64-abi.md)
- Supersedes: None
- Superseded by: None

## Context

The M10 roadmap requires "WoW64 ABI tests" for the Wine TPM
compatibility track. The TBS layer (ADR-0045) existed in two
build modes (POSIX standalone for the gates; windef.h for a
future Wine tree), but no PE build and no evidence that the
documented ABI works from 32-bit callers - the thing WoW64
applications actually are.

## Decision drivers

- The layer must be reachable the way a real Windows
  application reaches it: PE entry points with the exact
  stdcall shapes Windows import libs expect.
- Invariant 28: no raw Windows pointer or unchecked length
  crosses the Wine/Unix boundary - the boundary discipline must
  hold for 32-bit and 64-bit callers alike.
- Invariant 17: PE callers terminate at the same isolated
  per-prefix vTPM; the WoW64 leg introduces no new transport
  surface.
- The dev host has Wine 11 with WoW64 and both mingw
  cross-compilers, but no 32-bit unix libs - so a winelib 32-bit
  build is impossible and a PE build is the honest path.

## Options considered

1. **A PE build with the winsock transport** (`-DOGIR_TBS_PE`):
   the same AF_UNIX sockets through ws2_32, probed first (Wine
   passes AF_UNIX through to the host; a 12-byte GetRandom
   round-trips from both a 64-bit PE and a 32-bit PE under
   Wine).
2. A 32-bit winelib build. Impossible here (no 32-bit wine unix
   libs on the dev host) and less honest as ABI evidence: a PE
   caller is what real applications are.
3. ABI declaration without execution (header review only).
   Rejected: the M10 posture is executed evidence.

## Decision

Adopt option 1. `wine/tbs/tbs.c` gains the PE transport as a
third build mode sharing ALL TBS logic verbatim: winsock
socket/connect/send/recv/closesocket behind the same five
transport primitives (the POSIX path is unchanged and the
existing gates still cover it), a lazily-initialized WSAStartup,
and DWORD-millisecond socket timeouts (30 s -> TBS_E_IOERROR
unchanged). `wine/tbs/include/tbs.h` gains the PE base-type
branch (winsock2.h before windows.h; PCBYTE defined - Windows
SDKs spell it LPCBYTE) and per-define guards where mingw's
winerror.h already carries the same TBS_E_* values.

`wine/tests/test-tbs-wow64.py` (LGPL) builds the layer + harness
as PE binaries for x86_64 and i686 and:

- asserts the OBJECT-LEVEL SYMBOL SHAPES: i386 stdcall
  decorations with the exact argument-byte counts
  (_Tbsip_Submit_Command@28 = 7 four-byte args; _Tbsi_Context_Create@8;
  _Tbsip_Cancel_Commands@4; _Tbsip_Context_Close@4;
  _Tbsi_GetDeviceInfo@8) and the undecorated x64 names;
- runs the TBS behavior matrix under Wine for BOTH
  architectures (the i686 leg through WoW64): fail-closed
  presence, the documented validation codes, close semantics,
  a real GetRandom round-trip (28-byte response, real bytes),
  insufficient-buffer, cancel, device info with reserved zeros,
  five create/close cycles, and two interleaved contexts;
- asserts the two architectures received DISTINCT random
  payloads (no caller is served another's bytes);
- stops the vTPM and asserts both architectures fail closed.

## Consequences

- The layer is now reachable from real Windows-shaped callers;
  the WoW64 ABI criterion is EXECUTED evidence (a 32-bit stdcall
  caller exercising every documented entry point).
- The discovery path under PE is the WINEPREFIX environment
  variable (getenv works in Wine processes; the gate sets it).
  A real Wine-tree integration would derive the prefix from
  Wine internals instead - that is the one integration point a
  future upstream submission would replace, recorded here and
  in the code comment.
- The gate is dev-host-only (CI has no Wine), like the other
  wine/ gates.

## Threat-model impact

Positive: the ABI boundary is now exercised from both widths -
the layer's validation (registry before dereference, length
checks before use) demonstrably holds for 32-bit and 64-bit
callers. No new surface: the PE transport speaks to the same
per-prefix sockets.

## Privacy impact

None: the gate runs against an ephemeral per-prefix vTPM under
its own tmp tree.

## Dependency and license impact

The gate adds mingw cross-compilers and wine as DEV-HOST
gate tooling (not project dependencies; CI unaffected). All
changed files stay LGPL-2.1-or-later under wine/.

## Validation

Executed on the dev host (2026-09-09):
wine/tests/test-tbs-wow64.py PASS; the POSIX regression set -
wine/tests/test-tbs.py, wine/tests/test-tbs-attacks.py,
wine/tests/test-vtpm-manager.py - PASS unchanged; the
traceability (67 scenarios) and coverage (48/48) gates PASS.

## Rollback

Revert the commit; the PE transport branch, the header guards,
the harness guards, and the gate disappear together (the POSIX
behavior is bit-identical before and after - the gates prove
it).

## Primary sources

- The executed probes (spike notes, task-18-scoping/m10-051):
  ws2_32 AF_UNIX passthrough under Wine for both PE widths.
- Microsoft Learn tbs.h (unchanged prototypes); mingw headers
  (winerror.h TBS_E_* values; PCBYTE spelling).
