# M10-049: The TBS compatibility layer over the per-prefix vTPM
<!-- labels: type: implementation,area: wine-tpm,status: needs-review -->
<!-- milestone: M10 Wine TPM Compatibility -->


## Problem

M10's compat deliverable is the TBS API itself: context/device/
submit/close/cancel semantics against the per-prefix vTPM socket
(the M10-048 manager). Upstream Wine's tbs.dll is stubs, so
ordinary Windows TPM applications see no TPM under Wine at all.

## What this slice delivers

1. `wine/tbs/tbs.c` + `wine/tbs/include/tbs.h` +
   `wine/tbs/tbs.spec` (LGPL, ADR-0045): the five documented TBS
   entry points over the per-prefix sockets - documented
   validation and error codes, transparent transport (TPM
   errors verbatim, never synthesized), the insufficient-buffer
   contract, in-place buffers, zeroing close, TPM_DEVICE_INFO,
   bogus handles failing closed via a bounded registry.
2. `wine/vtpm/vtpm-manager.sh` (extended): the data channel
   (`--server type=unixio,disconnect` - one client per command,
   concurrent contexts cannot deadlock on the probed
   one-persistent-client-at-a-time behavior), the
   `<prefix>/vtpm/sockets` discovery symlink, `pwd -P` hashing
   exactness, stop removing the data socket and symlink.
3. `wine/tests/tbs_harness.c` + `wine/tests/test-tbs.py` (LGPL):
   the dev-host scenario gate - negative tests first (no-vtpm,
   parameter matrix, handle misuse), then the GetRandom
   round-trip, insufficient-buffer, in-place, TPM-error
   transparency, cancel, device info, cycling, interleaved
   contexts, and the source-level host-TPM grep.
4. ADR-0045 + index row; ROADMAP boundary; this issue.

## Executed evidence (dev host)

- wine/tests/test-tbs.py PASS; wine/tests/test-vtpm-manager.py
  (extended for the data socket and symlink) PASS.

## Security invariants

- No physical TPM path exists in the layer (grep-gated; the
  socket pair is the only transport).
- The vTPM stays the software-tpm class (invariant 17); nothing
  here presents it as hardware.
- Per-prefix isolation is inherited structurally (the layer only
  resolves sockets under its own prefix's vtpm/ tree).

## Out of scope

- WoW64 ABI tests; the API-layer attack families (exhaustion,
  malformed buffers, cancellation races, cross-prefix leakage,
  vTPM-presented-as-hardware); the M10 exit audit; upstream
  submission of the patch.
