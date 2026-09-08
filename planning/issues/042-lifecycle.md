# M7-042: The session registry and the lifecycle cleanup matrix
<!-- labels: type: implementation,area: agent,status: needs-review -->
<!-- milestone: M7 Session Observation -->


## Problem

M7's exit criteria demand reliable session cleanup after normal
exit, crash, agent restart, and system shutdown; the observation
core (ADR-0037) produces the record but nothing owns the
lifecycle.

## What this slice delivers

1. `ogir_agent::registry::SessionRegistry` (ADR-0038): admission
   (pin+observe+register; duplicates reject; dead callers fail
   closed), exact-liveness state, tombstoned cleanup, the fleet
   crash sweep, live-session refresh (the drift input), and the
   executable after-registry-loss posture.
2. The four-scenario cleanup matrix as tests: normal exit, crash,
   agent restart (fails closed - no persistence; re-establishment
   only), system shutdown (startup empty; indistinguishable from
   restart by design).
3. ADR-0038 + index row; ROADMAP boundary; this issue; the plan.

## Executed evidence (dev host)

- Nine registry tests green across ten consecutive runs, including
  multi-session independence (one crashes; only it sweeps) and the
  live-refresh contract.

## Security invariants

- Crash detection is the pidfd (exact, not polling).
- Restart/shutdown fail closed; nothing persists.
- Dead identities never re-animate as themselves.

## Out of scope

- The event stream + renewal invalidation (M7-043); the
  noninterference suite + exit audit (M7-044); OS-session
  integration (rejected in the ADR).
