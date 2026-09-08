# M7-043: The integrity event stream and renewal invalidation
<!-- labels: type: implementation,area: agent,area: privacy,status: needs-review -->
<!-- milestone: M7 Session Observation -->


## Problem

M7's remaining deliverables are the event stream for relevant
integrity changes and renewal invalidation when observed state
changes; the registry refreshes but nothing records what changed
or gates renewal on it.

## What this slice delivers

1. `ogir_agent::events` (ADR-0039): EventKind (stable spellings),
   IntegrityEvent (kind + session digest + sequence + BEFORE/AFTER
   state digests ONLY), the per-session bounded EventLog,
   diagnose() with fixed precedence, and renewal_gate() - a GATE,
   never a grant.
2. The registry integration: refresh diffs the state digest and
   emits the diagnosed event; exit emits the terminal event before
   the fail-closed error; cleanup/sweeps drop logs; renewal_gate()
   demands BOTH a quiet stream AND live liveness.
3. ADR-0039 + index row; ROADMAP boundary; this issue; the plan.

## Executed evidence (dev host)

- ogir-agent 59 tests green across six consecutive runs: quiet
  sessions emit nothing; exit emits the terminal event and closes
  renewal; the full invalidation flow; the log unit set.

## Security invariants

- Events are digest-only (less than the already-redacted
  observation); per-session isolation prevents cross-session
  correlation.
- The gate never grants: MayReverify still requires full
  re-verification.
- NO ENFORCEMENT CLAIM.

## Out of scope

- The noninterference suite + exit audit (M7-044); a persistent
  audit ledger (rejected); the M6 service route wiring (composes
  when the authoritative backend does).
