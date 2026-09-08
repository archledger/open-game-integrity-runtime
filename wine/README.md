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
