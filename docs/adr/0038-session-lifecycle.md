# ADR-0038: The session registry and the lifecycle cleanup matrix

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M7-042 issue](../../planning/issues/042-lifecycle.md)
- Supersedes: None
- Superseded by: None

## Context

M7's exit criteria demand reliable session cleanup after normal
exit, crash, agent restart, and system shutdown. The observation
core (ADR-0037) produces the record; nothing yet owns the
lifecycle.

## Decision drivers

- Crash detection must be exact (the pidfd, not polling).
- Agent restart and system shutdown FAIL CLOSED (the ADR-0022
  posture): observation state is deliberately NOT persisted; every
  session re-establishes.
- Dead identities must never re-animate as themselves.
- NO ENFORCEMENT CLAIM.

## Options considered

1. **Persist the registry across agent restarts** (a state file):
   reintroduces exactly the recovery ambiguity ADR-0022 rejected
   for keys - a stale observation is worse than none.
2. **An in-memory registry with tombstones and an explicit
   after-loss semantic**; restart and shutdown are the SAME
   behavior (the registry is simply gone).
3. **OS-session integration (sd-session/logind).** A new
   dependency and a desktop-specific surface; the cgroup digest in
   the identity already carries the deployment scope.

## Decision

Adopt option 2. `ogir_agent::registry::SessionRegistry`:
- `admit()` pins + observes + registers under the identity digest;
  duplicate admission is a protocol error; dead callers fail
  closed;
- `state()` reports Active/Terminated from the PIN (exact
  liveness);
- `cleanup()` ends a session and TOMBSTONES the identity (never
  re-registered as itself);
- `sweep_dead()` is the crash path for a fleet (each entry whose
  pin no longer holds is collected);
- `refresh()` re-observes a live session (the M7-043 drift input),
  failing closed on death;
- `after_registry_loss()` makes the restart/shutdown posture
  EXECUTABLE: any prior identity is unknown; re-establishment is
  the only path, and a still-live process re-admits to the SAME
  identity (deterministic observation) as a FRESH registration.

The four-scenario cleanup matrix is the test set: normal exit
(cleanup + tombstone), crash (state flips Terminated; the sweep
collects; the refresh refuses), agent restart (registry dropped;
prior identities unknown; re-admission works), and system shutdown
(startup empty; any ghost identity unknown - by design
indistinguishable from restart, which is the honest boundary of
what the registry can know).

## Consequences

- The M7 event stream (next slice) attaches to registry entries.
- A crashed session's tombstone persists for the registry's
  lifetime; a restart clears tombstones too (nothing carries).
- The registry is host-side state; nothing here is
  publisher-facing.

## Threat-model impact

No new privilege; the registry reads only what the observation
already reads. Fail-closed on every boundary: dead callers, dead
sessions, lost registries.

## Privacy impact

None beyond the observation's own redaction.

## Dependency and license impact

None.

## Validation

Executed on the dev host: nine registry tests green across ten
consecutive runs - the full four-scenario matrix plus duplicate
admission, dead admission, multi-session independence (one
crashes, only it sweeps), and the live-refresh contract.

## Rollback

Revert the commit; the registry and its matrix disappear together.

## Primary sources

- ADR-0022 (fail-closed recovery posture), ADR-0028 (the pin),
  ADR-0037 (the observation), and the executed matrix runs
  (2026-09-08).
