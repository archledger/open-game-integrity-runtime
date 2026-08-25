# ADR-0002: Apache-2.0 for the default OGIR core

- Status: Accepted
- Date: 2026-08-24
- Owners: Initial maintainer
- Related issues: None recorded
- Supersedes: None
- Superseded by: None

## Context

OGIR must be auditable and reusable by proprietary games and publisher infrastructure while retaining an explicit patent grant.

## Decision drivers

- Permit inspection, reuse, and integration by open and proprietary game
  ecosystems.
- Retain an explicit patent grant for the default trusted core.
- Respect Wine and Linux upstream license boundaries.
- Make file-level license obligations mechanically reviewable.

## Options considered

### Apache-2.0 core with boundary-specific upstream licenses

Selected because it combines broad reuse with an explicit patent grant while
preserving the licenses required at Wine and kernel-facing boundaries.

### MIT- or BSD-style licensing for the default core

Rejected because those licenses do not provide the explicit patent grant that
the project requires for its default trusted core.

### One copyleft license for every repository path

Rejected because it would unnecessarily restrict default-core reuse and would
not remove the need to respect distinct Wine and kernel upstream obligations.

## Decision

License the default Rust core, SDK, verifier, documentation, and attack lab under Apache-2.0. License Wine-upstream work under LGPL-2.1-or-later and BPF/kernel-facing program source under a GPL-compatible identifier appropriate to that boundary.

## Consequences

- Per-file SPDX identifiers are required.
- Implementation code cannot be copied casually across license boundaries.
- Trademark and certification rights remain separate.

## Threat-model impact

This decision primarily affects attacker class A6 and the source-to-release
supply-chain boundary: explicit license provenance reduces accidental or
malicious mixing of code across incompatible boundaries. It does not change
runtime authorization, evidence assurance, or attacker capabilities.

## Privacy impact

No evidence claim, identifier, retention period, or disclosure changes. License
policy does not authorize collection of additional user or platform data.

## Dependency and license impact

Every new source file and dependency must remain compatible with its path's
declared license. Rust core, SDK, verifier, documentation, and attack-lab source
default to Apache-2.0; Wine-upstream work uses LGPL-2.1-or-later; BPF and
kernel-facing program source uses the reviewed GPL-compatible identifier.

## Validation

- Require exact SPDX declarations on staged source blobs.
- Keep the repository license map current.
- Preserve byte-identical official license texts.
- Run cargo-deny for dependency licenses and sources.
- Review any code movement across Apache, LGPL, or GPL boundaries.

## Rollback

Relicensing requires a superseding ADR, legal and contributor-rights review,
and an explicit migration. Existing third-party and contributed code cannot be
silently relicensed. If compatibility is uncertain, reject the dependency or
isolate it behind its existing boundary.

## Primary sources

- [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.txt)
- [GNU LGPL 2.1](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.txt)
- [GNU GPL 2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt)
- [OGIR license map](../../LICENSES.md)
- [OGIR security invariants](../SECURITY_INVARIANTS.md), especially invariants
  44–48
