# M3-025: The M3 attack suite and exit audit
<!-- labels: type: test,area: tpm,area: verifier,risk: trusted-computing-base,status: needs-review -->
<!-- milestone: M3 TPM Backend -->

Status: Local integration candidate; no live GitHub issue yet. The milestone-closing slice; on merge, Milestone M3 is complete.

## Problem

M3's exit criteria require executed proof: every roadmap attack
category must return a deterministic non-allow result, and the four
exit criteria need an evidence-backed audit before the milestone can
close.

## Scope

- The ten-category attack suite as one named inventory (real swtpm,
  full enrollment/validation/cryptographic chain), including the new
  categories: resource exhaustion (live AKs accumulate until the TPM's
  loaded-object slots exhaust; every failure is the fail-closed
  Internal error), daemon killed during quote (the swtpm process dies
  mid-session; the backend fails closed), stale quote (a prior
  challenge's statement replayed for a new challenge rejects), and
  malformed TPM structures (garbage attest bytes fail cryptographic
  verification).
- The M3 exit-criteria audit (executed-test or verified-static
  evidence for all four criteria).
- Roadmap M3 completion boundary; local issue; plan.

## Acceptance criteria

- All ten categories green; all house gates green.
- The audit's verdict: all four M3 exit criteria hold.

## Current state

- 2026-09-06: Implemented in `research/m3-025-attack-suite-and-exit-audit`
  from `3660cc1`; awaiting human review and the signed-commit gate.
