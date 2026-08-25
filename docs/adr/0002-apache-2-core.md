# ADR-0002: Apache-2.0 for the default OGIR core

- Status: Accepted
- Date: 2026-08-24
- Owners: Initial maintainer

## Context

OGIR must be auditable and reusable by proprietary games and publisher infrastructure while retaining an explicit patent grant.

## Decision

License the default Rust core, SDK, verifier, documentation, and attack lab under Apache-2.0. License Wine-upstream work under LGPL-2.1-or-later and BPF/kernel-facing program source under a GPL-compatible identifier appropriate to that boundary.

## Consequences

- Per-file SPDX identifiers are required.
- Implementation code cannot be copied casually across license boundaries.
- Trademark and certification rights remain separate.
