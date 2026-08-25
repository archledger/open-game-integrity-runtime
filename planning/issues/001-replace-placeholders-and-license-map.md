# M0-001: Replace repository placeholders and verify license boundaries
<!-- labels: type: implementation,area: supply-chain,status: ready -->
<!-- milestone: M0 Repository Foundation -->

## Problem

The bootstrap contains `YOUR-GITHUB-ACCOUNT` and `YOUR_GITHUB_USERNAME` placeholders. The repository also crosses Apache-2.0, LGPL-2.1-or-later, and GPL-2.0-only boundaries. These must be explicit before accepting contributions.

## Security invariants

- A contributor and reviewer can determine the license of every source path.
- Wine-targeted and BPF-targeted code cannot silently inherit the Apache-2.0 default.
- Repository security links resolve to the real repository.

## In scope

- Replace all owner and username placeholders.
- Verify `LICENSE`, `LICENSES/`, `LICENSES.md`, `NOTICE`, and SPDX identifiers.
- Decide the initial copyright notice form without claiming ownership of future contributions.
- Add a CI-friendly placeholder scan.

## Out of scope

- Trademark registration.
- Contributor license agreement.
- Relicensing any upstream Wine or kernel code.

## Primary sources

- Apache License 2.0: https://www.apache.org/licenses/LICENSE-2.0
- SPDX license list: https://spdx.org/licenses/
- REUSE specification: https://reuse.software/spec/
- Wine license: https://github.com/wine-mirror/wine/blob/master/LICENSE

## Required tests

- Repository search returns no unresolved owner placeholders.
- Every C, Rust, shell, and future BPF source has an SPDX identifier.
- A deliberate source file without licensing metadata is detected by the chosen check.

## Acceptance criteria

- All placeholders are replaced with verified values.
- License boundaries match `LICENSES.md`.
- The check runs locally and in CI or is recorded as a follow-up with an explicit owner.
- No source is copied across license boundaries in this issue.
