# ADR-0045: The TBS compatibility layer over the per-prefix vTPM

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M10-049 issue](../../planning/issues/049-tbs-layer.md)
- Supersedes: None
- Superseded by: None

## Context

M10's compat deliverable is the TBS API itself. Upstream Wine's
tbs.dll is stubs: Tbsi_Context_Create and Tbsi_GetDeviceInfo
return TBS_E_TPM_NOT_FOUND, and Tbsip_Submit_Command,
Tbsip_Cancel_Commands, and Tbsip_Context_Close are unimplemented
spec stubs, so ordinary Windows TPM applications see no TPM under
Wine. The per-prefix vTPM (ADR-0044) provides the isolated
backend; this slice implements the five documented entry points
against its sockets.

## Decision drivers

- The M10 roadmap: "Implement selected TBS
  context/device/submit/close/cancel semantics against the vTPM."
- Invariant 17: raw Windows TPM compatibility terminates at the
  ISOLATED VIRTUAL TPM; the layer must have no physical path.
- Semantics must match the DOCUMENTED Windows API (Microsoft
  Learn, tbs.h): signatures, parameter validation, error codes,
  and the insufficient-buffer contract.
- Wine-targeted source is LGPL-2.1-or-later under wine/ with
  Wine conventions, aiming at the "suitable for upstream review
  or clearly experimental" exit criterion.

## Options considered

1. **One connection per submit over the data socket** (connect,
   send, receive, close), with the manager starting the data
   channel in server `disconnect` mode.
2. **A persistent per-context data connection.** Probed and
   rejected: swtpm serves ONE data client at a time - a second
   concurrent context's submit HANGS (the connection is accepted
   but never served). Windows allows concurrent TBS contexts;
   this design would deadlock them.
3. **Forwarding raw TBS commands to the host TPM.** Prohibited
   by invariant 17 and the wine/README rules; not an option.

The probed facts behind option 1 (swtpm 0.10.2, dev host):
with the server `disconnect` option (documented for TCP;
empirically effective for unixio) a second client is served and
the idle first client is closed, so per-submit connections both
avoid the single-client lockup and tolerate interleaving; the
ctrl channel's CMD_CANCEL_TPM_CMD is a BE u32 command (9) with
a BE u32 ptm_res response, and reports success even when no
command is in flight.

## Decision

Adopt option 1. `wine/tbs/tbs.c` (LGPL, Wine-shaped drop-in
candidate for dlls/tbs/tbs.c) implements the five entry points:

- Tbsi_Context_Create validates parameters per the documented
  tables (NULL output pointer, NULL params, unknown version,
  1.2-only requests, missing includeTpm20) and probes the
  per-prefix data socket; no vTPM means TBS_E_TPM_NOT_FOUND -
  the same code the upstream stub returns, now with honest
  presence semantics. Live contexts are registered in a
  bounded table (64) validated BEFORE any pointer dereference,
  so bogus handles are error returns, not crashes; the table
  full case returns TBS_E_TOO_MANY_TBS_CONTEXTS.
- Tbsip_Submit_Command validates locality (only locality ZERO
  is documented as supported on Windows), the five documented
  priorities, command shape (>= the 10-byte TPM2 header), and
  the swtpm buffer cap (4096; TBS_E_BUFFER_TOO_LARGE above),
  then transports the command transparently: TPM-level errors
  come back in the response buffer, never synthesized. The
  too-small output buffer sets the required size and returns
  TBS_E_INSUFFICIENT_BUFFER (draining the response). In-place
  buffers are allowed (the command is fully sent before the
  response is read). IO is bounded by a 30-second socket
  timeout surfacing as TBS_E_IOERROR.
- Tbsip_Cancel_Commands opens a transient ctrl connection and
  sends CMD_CANCEL_TPM_CMD. Honest limitation: swtpm's own ctrl
  channel notes the TPM would need a polling thread to
  interrupt an in-flight command, so cancel is compatibility
  surface, not interruption.
- Tbsip_Context_Close unregisters, zeroes, and frees (the
  documented zeroing semantics; reuse fails closed).
- Tbsi_GetDeviceInfo fills TPM_DEVICE_INFO (structVersion 2,
  tpmVersion 2, reserved fields 0) when the vTPM is present;
  TBS_E_TPM_NOT_FOUND otherwise.

`wine/tbs/include/tbs.h` extends upstream's minimal header with
the documented definitions (return codes, TBS_CONTEXT_PARAMS2,
locality/priority enums, TPM_DEVICE_INFO); values are from
Microsoft Learn. `wine/tbs/tbs.spec` records the three promoted
spec entries for the upstream patch. Discovery: the manager
creates `<prefix>/vtpm/sockets` as a symlink into the per-prefix
runtime dir, so no runtime-dir layout knowledge (and no hashing)
lives in C.

## Consequences

- Ordinary Windows TPM applications gain a working TBS surface
  against the per-prefix vTPM; prefixes without a vTPM see the
  documented not-found behavior.
- The manager now starts the data channel with `disconnect` (a
  behavioral choice recorded here and in the manager comments).
- Known limitations (for the M10 exit audit): the context
  registry is plain storage without locking (single-threaded
  callers per context; a Wine-side submission adds
  serialization); cancel cannot interrupt in-flight commands
  (swtpm constraint); a too-small output buffer consumes the
  response (the required size is still reported).
- The API-layer attack families (exhaustion, malformed buffers,
  cancellation races, cross-prefix leakage,
  vTPM-presented-as-hardware) and WoW64 ABI tests remain open
  M10 slices against this layer.

## Threat-model impact

Positive: the layer is transparent transport with no physical
TPM path (grep-gated mechanically); bogus handles fail closed.
Neutral-to-positive: the bounded context table bounds per-process
handle growth. Residual: a wedged vTPM surfaces as IOERROR after
the 30-second bound rather than hanging forever.

## Privacy impact

None beyond ADR-0044: the layer follows the calling prefix's own
sockets; nothing is logged and no identity material is created
or exposed by the layer itself.

## Dependency and license impact

No new dependencies (POSIX sockets only). All new Wine-targeted
files are LGPL-2.1-or-later under wine/ (the metadata gate's
existing boundary).

## Validation

Executed on the dev host (2026-09-08):
wine/tests/test-tbs.py compiles the layer standalone with
-Wall -Wextra -Werror and runs the scenario gate against a REAL
per-prefix swtpm: no-vtpm fail-closed, the parameter matrix,
handle misuse, the GetRandom round-trip with real random bytes,
the insufficient-buffer contract, in-place buffers, TPM-error
transparency, cancel, device info, five create/close cycles, two
interleaved contexts, and the source-level host-TPM grep - PASS.
The extended M10-048 manager gate (data socket + discovery
symlink) - PASS.

## Rollback

Revert the commit; the layer, harness, gate, and the manager's
data-channel addition disappear together (the M10-048 manager
surface reverts with it - the four-family gate covers that
state).

## Primary sources

- Microsoft Learn: Tbsi_Context_Create, Tbsip_Submit_Command,
  Tbsip_Cancel_Commands, Tbsip_Context_Close,
  Tbsi_GetDeviceInfo, TBS_CONTEXT_PARAMS2, TPM_DEVICE_INFO
  (2026-09-08).
- Upstream Wine master: dlls/tbs/tbs.c, tbs.spec,
  include/tbs.h (stub surface).
- swtpm 0.10.2: man pages; include/swtpm/tpm_ioctl.h (CMD_*
  enum); src/swtpm/ctrlchannel.c (wire format and the cancel
  comment); executed probes on the dev host.
