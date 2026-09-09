# Wine integration workstream

This directory is reserved for research and patches intended for Wine-compatible integration.

Rules:

- Code intended for upstream Wine must use `LGPL-2.1-or-later` and Wine conventions.
- Physical OGIR attestation remains a separate high-level API.
- Raw Windows TBS commands must not be forwarded to the physical host TPM.
- Future Windows TPM compatibility should use an isolated per-prefix virtual TPM.
- Prefer upstreamable Wine changes over a permanent private Proton fork.
- Do not copy Apache-licensed core implementation code into Wine-targeted source without license review.

## The per-prefix virtual TPM (M10)

`vtpm/vtpm-manager.sh` runs ONE swtpm per wine prefix: state under
`<prefix>/vtpm/`, sockets under `$XDG_RUNTIME_DIR/ogir-vtpm/<hash>`
(hash of the prefix path - two prefixes can never collide), 0700
permissions, `start|stop|reset|status`. The manager NEVER
references the host TPM (mechanically checked by
`wine/tests/test-vtpm-manager.py` together with prefix isolation,
reset-wipes, and cleanup).

THE CAPABILITY CONTRACT: the per-prefix vTPM is ordinary Windows
TPM API compatibility, NOT hardware-host attestation. In OGIR's
assurance classes (ADR-0017) a swtpm-backed TPM is exactly the
`software-tpm` class, and the class gate rejects it wherever
hardware is required; the capability is never presented, ranked,
or accepted as hardware assurance (invariant 17).

## The TBS compatibility layer (M10-049)

`tbs/tbs.c` (+ `tbs/include/tbs.h`, `tbs/tbs.spec`) implements
the DOCUMENTED TBS surface - context create, submit, cancel,
close, and device info - against the per-prefix vTPM's sockets
(upstream Wine's tbs.dll is stubs). One connection per submit:
the manager starts the data channel in server `disconnect` mode
because swtpm serves one persistent data client at a time.
Discovery is the manager-maintained `<prefix>/vtpm/sockets`
symlink - no runtime-dir layout knowledge in C. The layer
returns TPM errors VERBATIM (compat transport, never synthesis),
validates per the documented tables, and has NO physical TPM
path (grep-gated by `wine/tests/test-tbs.py` together with the
fail-closed, parameter, lifecycle, and transparency scenarios).
The capability contract above is unchanged by this layer.

## The TBS attack families (M10-050)

`tests/test-tbs-attacks.py` executes the M10 roadmap's API-layer
attack families against the layer: exhaustion (registry cap,
recovery, no descriptor growth), malformed requests and responses
(the vTPM's own errors verbatim; a fake-socket matrix for
malformed responses - IOERROR or bounded exactly), cancellation
races (storm, cross-process submit/cancel race, dead-vTPM
fail-closed), cross-prefix no-reach, and the vTPM-as-hardware
check (the vendor identity served through the layer is the
SOFTWARE emulator's). Registry scenarios
`tbs-*` map the families to invariants 17, 18, 20, 23, 26, 40.

## The WoW64 ABI evidence (M10-051)

`tbs/tbs.c` builds in three modes: the POSIX standalone gate, a
future Wine tree, and PE (-DOGIR_TBS_PE - the same AF_UNIX
transport through ws2_32; probed: Wine passes it through).
`tests/test-tbs-wow64.py` builds the layer as PE binaries for
x86_64 and i686 and runs the behavior matrix under Wine (the
i686 leg through WoW64): the i386 stdcall symbol shapes are
asserted at the object level and both callers reach only their
own prefix's vTPM.

## The M10 exit audit (M10-052)

`tests/run-all-gates.py` runs the whole wine/ suite in one
fail-closed command (the repo-wide isolation sweep, the manager
gate, the TBS functional gate, the attack-family gate, and the
WoW64 ABI gate). `tbs/UPSTREAM-NOTES.md` records the upstream
delta honestly: the patch is EXPERIMENTAL, with the upstreamable
core and its blockers identified. The milestone record is
ADR-0048.
