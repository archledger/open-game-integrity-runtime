# ADR-0039: The integrity event stream and renewal invalidation

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M7-043 issue](../../planning/issues/043-event-stream.md)
- Supersedes: None
- Superseded by: None

## Context

M7's remaining deliverables are the event stream for relevant
integrity changes and renewal invalidation when observed state
changes. The registry (ADR-0038) refreshes; nothing records what
changed or gates renewal on it.

## Decision drivers

- Events are the REDACTED layer only (ADR-0037): digests, pids,
  start times - never observations.
- The stream is bounded (a rolling diagnostic, not a ledger).
- Renewal invalidation is a GATE, never a grant: a quiet stream
  permits re-verification; anything else demands re-establishment.
- NO ENFORCEMENT CLAIM.

## Options considered

1. **A global event bus** (all sessions, one stream). Couples
   unrelated sessions; a publisher-side reader could correlate -
   an interference risk.
2. **Per-session bounded logs** with a sequence-based renewal
   gate.
3. **A persistent audit ledger.** Beyond M7 (the registry itself
   is deliberately volatile per ADR-0038).

## Decision

Adopt option 2. `ogir_agent::events`:
- `EventKind` (process-exited, manifest-drift, cgroup-moved,
  tree-changed) with stable wire spellings;
- `IntegrityEvent` (kind, session digest, sequence, BEFORE/AFTER
  state digests - nothing else);
- `EventLog`: per-session, bounded (default 64, oldest drops),
  monotonic sequence;
- `diagnose()`: the change kind between two observations with a
  fixed precedence (exit > manifest > cgroup > tree);
- `renewal_gate(log, permit_sequence)`: MayReverify when the
  stream is quiet since the permit, MustReestablish otherwise.

The registry integration (ADR-0038's refresh): every refresh
diffs the state digest; drift emits the diagnosed event; the
process exiting emits the terminal event before the fail-closed
error; cleanup and sweeps drop the logs with the sessions; and
`SessionRegistry::renewal_gate()` gates renewal on BOTH the quiet
stream AND live liveness (a dead session fails closed - stronger
than MustReestablish, there is nothing to renew). The M6 service's
renewal route can consume this gate through the agent seam when
the authoritative backend composes.

## Consequences

- The M7-044 suite asserts the full invalidation story.
- The gate is deliberately weak where it should be: MayReverify
  still requires full re-verification (the M6 renewal chain).
- Event sequences are per-session and reset with the registry.

## Threat-model impact

No new privilege; events are derived from the observation's own
redacted digests. Per-session isolation prevents cross-session
correlation through the stream.

## Privacy impact

Positive: events carry two digests and an enum - less than the
already-redacted observation.

## Dependency and license impact

None.

## Validation

Executed on the dev host: ogir-agent 59 tests green across six
consecutive runs - the event-log unit set (sequencing, bounding,
the renewal gate, quiet logs, the stable spellings) plus the
registry integration set (quiet sessions emit nothing; exit emits
the terminal event and closes renewal; the full invalidation
flow). Full house gates in the slice record.

## Rollback

Revert the commit; the events module and registry integration
disappear together.

## Primary sources

- ADR-0037/0038 (the observation and registry this composes) and
  the executed runs (2026-09-08).
