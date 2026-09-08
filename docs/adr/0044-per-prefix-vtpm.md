# ADR-0044: The per-prefix virtual TPM

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M10-048 issue](../../planning/issues/048-wine-vtpm.md)
- Supersedes: None
- Superseded by: None

## Context

M10 improves ordinary Windows TPM API compatibility under Wine
WITHOUT conflating it with physical-host attestation. The
deliverables start with the research and the per-prefix vTPM
manager; the TBS implementation lands on it in later slices.

## Decision drivers

- Invariant 17: raw Windows TPM compatibility terminates at an
  ISOLATED VIRTUAL TPM - never the physical one.
- Invariant 29 posture: everything runs unprivileged.
- One prefix must never touch another's TPM state.
- LGPL-2.1-or-later for Wine-targeted source (the wine/ boundary
  the metadata gate already enforces).

## Options considered

1. **swtpm per prefix** (state under the prefix, sockets under
   the runtime dir keyed by a hash of the prefix path).
2. **A shared system swtpm** with per-prefix NV naming.
   Cross-prefix correlation surface; rejected.
3. **A single multi-TPM emulator.** New dependency, new trust
   surface; rejected.

## Decision

Adopt option 1: `wine/vtpm/vtpm-manager.sh` (LGPL) with
start/stop/reset/status; state at `<prefix>/vtpm/` (0700),
sockets at `$XDG_RUNTIME_DIR/ogir-vtpm/<sha256-16-of-path>` (two
prefixes can never collide - the isolation is structural, not
configurable), idempotent start, kill-escalating stop, and a
reset that WIPEs the state. The manager NEVER references the
host TPM - mechanically checked by
`wine/tests/test-vtpm-manager.py` together with per-prefix
state/socket separation, reset-wipes (mtime-checked), and
cleanup-removes-sockets. THE CAPABILITY CONTRACT: the vTPM is
ordinary Windows TPM API compatibility, not hardware-host
attestation - in ADR-0017's assurance classes it is exactly
`software-tpm`, the class gate rejects it wherever hardware is
required, and the capability is never presented as hardware
(invariant 17). This is recorded in wine/README.md.

## Consequences

- The TBS implementation (the next slices) targets the per-prefix
  socket; no physical path exists to implement against.
- The M10 attack families the manager owns are covered
  mechanically (physical isolation, prefix isolation, reset,
  cleanup); exhaustion/malformed/cancel land with the TBS layer.

## Threat-model impact

Positive: the compat track gains a surface that CANNOT reach the
physical TPM (no path, mechanically checked).

## Privacy impact

Per-prefix state isolation prevents persistent identity leakage
across prefixes (each prefix's EK lives only in its own state
dir); reset destroys it.

## Dependency and license impact

swtpm (already the house TPM emulator, ADR-0018 posture); the
manager and tests are LGPL-2.1-or-later under wine/.

## Validation

Executed on the dev host: the manager smoke (start/status/state
exists/stop/status) and the four-family gate PASS.

## Rollback

Revert the commit; the manager, tests, and README updates
disappear together.

## Primary sources

- Invariant 17 and the M10 roadmap section; the executed smoke
  and gate runs (2026-09-08).
