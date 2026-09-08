# M5-035: The runtime manifest, the attack suite, and the M5 exit audit
<!-- labels: type: test,area: agent,area: attack-lab,status: needs-review -->
<!-- milestone: M5 Proton Bridge -->


## Problem

M5's remaining deliverables are the game/runtime manifest
derivation and the thirteen required attack tests, closing the
milestone with its exit audit.

## What this slice delivers

1. `ogir_agent::manifest` (ADR-0031) - the REDACTED runtime
   manifest of a PINNED caller from procfs: executable digest and
   size, bounded module digests (max 64, malformed maps fail
   closed), and the mount-namespace digest (the substitution
   anchor). Derivation requires the pin; reference data only.
2. `crates/ogir-agent/tests/m5_attack_suite.rs` - all thirteen
   roadmap categories in the house inventory pattern, deterministic
   and non-allow: replaced bridge (identical files, distinct
   callers), copied environment (same prefix digest, different
   caller and manifest), PID reuse, exit-during-binding, prefix
   substitution (different digest), mount-namespace substitution
   (environment-honest under EPERM: anchor stability asserted),
   parent/child distinctness, oversized requests, layout-mismatch
   shapes, invalid frames, socket impersonation, request flood,
   and the no-privileged-operation-is-expressible proof. Wine-side
   legs anchor to their executed dev-host evidence.
3. The M5 exit audit: criteria 1, 2, and 4 satisfied by executed
   work; criterion 3 partial with the fuzz-target remainder
   recorded for the M6 SDK slice.
4. ADR-0031 + index row; the ROADMAP M5-035 boundary declaring M5
   COMPLETE; this issue; the plan doc with the environment
   lessons.

## Executed evidence (dev host)

- Manifest tests: 3/3 (derivation, cross-process distinction, dead
  processes cannot have manifests).
- The thirteen-category suite: 13/13 across three consecutive runs
  under parallel load.

## Security invariants

- The manifest reads procfs of the pinned, same-UID process only;
  digests and sizes never leak paths.
- No caller-supplied input reaches the manifest or the binding.
- No new dependencies.

## Out of scope

- Fuzz/sanitizer targets for the C ABI (M6 SDK slice, recorded in
  the exit audit); full wow64 transport support; permit issuance
  (M6).
