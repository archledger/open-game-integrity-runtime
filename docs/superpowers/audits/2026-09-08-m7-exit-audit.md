# M7 exit audit: protected-session observation

Date: 2026-09-08
Agent: zcode
Scope: the four M7 exit criteria from docs/ROADMAP.md, audited
against delivered, merged work plus this slice's executed
evidence.

## Criterion 1: evidence is bound to the actual launched process
tree

DELIVERED. The observation core (ADR-0037) composes the pidfd pin
(ADR-0028 - exact liveness, race-resistant), the correlation
(ADR-0030), and the manifest (ADR-0031) into ObservedSession whose
ObservedTree IS the launched process's ancestor chain (pid +
kernel start time per hop, bounded, identity-checked on refresh: a
restarted same-pid process is a different session). The registry
(ADR-0038) admits only kernel-derived identities.

## Criterion 2: session cleanup is reliable after normal exit,
crash, agent restart, and system shutdown

DELIVERED and EXECUTED. The four-scenario matrix (ADR-0038) and
its consolidation in this suite: normal exit (cleanup +
tombstone), crash (exact pidfd detection -> Terminated -> sweep ->
refresh refuses), agent restart (the registry is deliberately not
persisted - fail closed, re-establishment only), and system
shutdown (startup empty; indistinguishable from restart by
design).

## Criterion 3: observation does not expose unrelated process
inventory to the publisher

DELIVERED, STRUCTURALLY and EXECUTED. Noninterference is
structural: the observation reads ONLY the pinned process's
procfs; the tree is walked upward from the pin; no global
enumeration exists in any code path. The suite executes it: an
unrelated sibling never appears in any tree (and killing it does
not move the state digest); same-prefix unrelated processes stay
isolated (matching prefix digests, disjoint trees, distinct
identities); the redacted view carries no inventory surface (no
path, name, or command material); per-session event logs never
reference another session; and observation itself is
noninterfering (a sibling's observation does not change the lone
process's state digest).

## Criterion 4: no enforcement claim is made

DELIVERED. The public surface is records, gates, and errors: the
renewal gate returns MayReverify/MustReestablish (a gate, never a
grant); no method blocks, kills, or instructs the host to act on a
process. The suite pins it compile-time (no observation type
implements an Enforcement trait) and runtime (a drifting refresh
returns a record, never an instruction).

## Deliverables coverage

| Roadmap deliverable | Status |
| --- | --- |
| Dedicated cgroup/session identity | M7-041, merged |
| Process tree and start-time tracking | M7-041, merged |
| Runtime and loaded-component manifest | M7-041 (composes ADR-0031) |
| Policy-state digest | M7-041 (the StateDigest) |
| Session lifecycle and cleanup | M7-042, merged |
| Event stream for integrity changes | M7-043, merged |
| Renewal invalidation on observed change | M7-043, merged |
| Explicit noninterference tests | This slice: 7/7 x3 runs |

## Honest limitations (recorded, not gaps in the criteria)

- The event stream is host-side Rust API; no wire route until a
  consumer composes (recorded in ADR-0039).
- Event sequences reset with the registry (deliberate).
- The tree walk stops at the first unreadable hop (deep trees on
  restricted hosts observe shallower - fail-visible, not silent).

## Verdict

All four M7 exit criteria are satisfied by delivered, executed,
and reviewed work. With this slice merged, Milestone M7 is
COMPLETE: M0 through M7 are closed; the next milestone is M8
(scoped protected-session enforcement).
