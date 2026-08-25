# Wine integration workstream

This directory is reserved for research and patches intended for Wine-compatible integration.

Rules:

- Code intended for upstream Wine must use `LGPL-2.1-or-later` and Wine conventions.
- Physical OGIR attestation remains a separate high-level API.
- Raw Windows TBS commands must not be forwarded to the physical host TPM.
- Future Windows TPM compatibility should use an isolated per-prefix virtual TPM.
- Prefer upstreamable Wine changes over a permanent private Proton fork.
- Do not copy Apache-licensed core implementation code into Wine-targeted source without license review.
