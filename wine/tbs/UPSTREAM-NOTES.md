# Upstream notes for the TBS compatibility layer (M10-052)

Status: EXPERIMENTAL. This directory is OGIR's Wine TPM
compatibility research, not a submission. This note is the honest
delta record the M10 exit audit (ADR-0048) relies on: what a
future upstream contribution would keep, change, and answer.

## What is here

- `tbs.c` implements the five documented TBS entry points
  (Tbsi_Context_Create, Tbsip_Submit_Command,
  Tbsip_Cancel_Commands, Tbsip_Context_Close, Tbsi_GetDeviceInfo)
  against a per-prefix software TPM (swtpm) exposed as unix
  sockets; upstream's dlls/tbs/tbs.c is stubs (two functions
  return TBS_E_TPM_NOT_FOUND, the rest unimplemented).
- `include/tbs.h` extends upstream's minimal header with the
  documented return codes, TBS_CONTEXT_PARAMS2, the
  locality/priority enums, and TPM_DEVICE_INFO (values from
  Microsoft's documented API).
- `tbs.spec` records the three promoted entries a patch would
  carry (Submit/Cancel/Close from @stub to @stdcall).

## Design facts a reviewer would care about

- One connection per command: swtpm serves ONE persistent data
  client at a time (a second client's connection is accepted and
  never served), so the manager starts the data channel in
  server `disconnect` mode and every submit is
  connect/send/receive/close. Probed on swtpm 0.10.2.
- Transparent transport: TPM-level errors arrive in the response
  buffer; the layer returns TBS_SUCCESS for transport success
  and never synthesizes TPM outcomes.
- Validation is exactly the documented surface (locality ZERO
  only; the five priorities; the 10-byte TPM2 header minimum;
  the swtpm 4096-byte buffer cap; TBS_CONTEXT_PARAMS2
  includeTpm20; the insufficient-buffer contract with the
  required size returned; in-place buffers).
- Handles are validated against a bounded registry BEFORE any
  dereference (a bogus handle is TBS_E_INVALID_CONTEXT, not a
  crash); close zeroes the context per the documented semantics.
- Cancel is compatibility surface only: swtpm cannot interrupt a
  synchronous in-flight command (its control channel says so),
  so Tbsip_Cancel_Commands reports what the vTPM reports.

## What a submission would have to change

1. PREFIX DISCOVERY: the layer resolves
   `$WINEPREFIX/vtpm/sockets/...` via getenv. A Wine-tree
   version would derive the prefix from Wine internals instead -
   this is THE integration point, deliberately isolated in
   build_paths().
2. BUILD MODES: the dev-host gates compile the file standalone
   (-DOGIR_TBS_STANDALONE, POSIX) and as a PE (-DOGIR_TBS_PE,
   winsock; Wine passes AF_UNIX through ws2_32 - probed). A
   Wine-tree build would drop the standalone shim block and use
   the winsock path (Wine DLLs may use winsock); the ogir_
   prefixed gate scaffolding stays out of any submission.
3. CONCURRENCY: the context registry is unlocked (documented
   single-threaded callers per context). Upstream review would
   demand a serialization story for shared contexts.
4. PROCESS: license (LGPL-2.1-or-later is already correct),
   Wine coding conventions, and the upstream community's patch
   process are respected here; swtpm as a runtime dependency of
   a Wine dll is a design question upstream would weigh
   (detection, error mapping to TBS_E_SERVICE_NOT_RUNNING vs
   TBS_E_TPM_NOT_FOUND, and whether such a dll belongs in tree
   at all).

## Evidence that the behavior matrix holds

wine/tests/run-all-gates.py executes the whole suite in one
command: the manager gate (isolation/reset/cleanup), the TBS
functional gate (fail-closed, validation matrix, round-trips),
the attack-family gate (exhaustion, malformed, races, cross-
prefix, capability contract), and the WoW64 ABI gate (i386
stdcall shapes; both widths under Wine). CI runs the registry
and Rust gates; the wine gates are dev-host by nature.
