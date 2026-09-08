# M5-033: The ogir-client prototype
<!-- labels: type: implementation,area: agent,area: proton-bridge,status: needs-review -->
<!-- milestone: M5 Proton Bridge -->


## Problem

M5 needs the minimal Windows PE DLL with the stable C ABI
(sdk/include/ogir.h) that a game under Wine/Proton uses to reach the
unprivileged local portal without trusting Windows-provided identity
fields - and mainline wine's ws2_32 has no AF_UNIX, so the transport
must cross the boundary inside the wine process.

## What this slice delivers

1. `wine/ogir-client/pe/ogir_client.c` - the real mingw PE DLL
   (AMD64 + i386): the public C ABI with strict argument validation
   (null out pointers, null-data-with-length, blobs over 4096,
   capacity checks, null-tolerant close) and transport open/close
   dispatched through ntdll's `__wine_unix_call` (bound via a
   dlltool import library for the two wine-private data exports).
2. `wine/ogir-client/ogir_client_dll.c` + `ogir_client.spec` - the
   winegcc unixlib: spec-bound ms_abi exports AND initialized
   dispatch tables (an uninitialized table attaches nothing), the
   AF_UNIX transport with the bounded frame codec mirroring the
   portal's, and the fail-closed Hello handshake.
3. `abi_test.c` (both architectures) - the ABI-layer attack legs;
   `build.sh` - the reproducible build incl. the 32-bit PE variant;
   `scripts/test-ogir-client-build.py` - the fail-closed structural
   gate (loader-contract symbols, initialized tables, PE export
   surfaces, machine checks); `examples/portal-serve.rs` - the
   development portal host.
4. ADR-0029 with the six-point executed loader map and the honest
   deployment constraint (the unixlib must live in wine's
   machine-unix directory); ROADMAP boundary; this issue; the plan
   doc with every hard-won loader lesson.

## Executed evidence (dev host; logs in task-18-scoping/m5-033/)

- The 64-bit harness under wine against the LIVE Rust portal:
  13/13 PASS including "open succeeded against the portal"; the
  portal logged the wine process's kernel credentials
  (pid/uid/gid), pinned the caller (CallerBinding alive), and
  served the connection.
- The 32-bit (WoW64) harness: every ABI check PASS; open fails
  CLOSED (UNAVAILABLE) per the recorded layout-mismatch defense.
- The build gate PASS (loader contract, initialized tables,
  exports, architectures).

## Security invariants

- No TPM call, no privileged operation, no raw TBS forwarding
  anywhere in the bridge (wine/README.md rules).
- The ABI layer fails closed on malformed arguments; identity
  remains kernel-derived at the portal.
- No Rust dependency changes; the bridge is Apache-2.0 OGIR code,
  not an upstream Wine patch.

## Out of scope

- The wine/Proton transport executions on other hosts (archhost's
  GE-Proton) and the correlation work (M5-034); redacted tracing;
  the game/runtime manifest; the replaced-DLL and related attack
  categories (M5-035); a proper wow64 conversion layer for full
  32-bit transport support.
