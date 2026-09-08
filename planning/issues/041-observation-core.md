# M7-041: The observation core
<!-- labels: type: implementation,area: agent,area: privacy,status: needs-review -->
<!-- milestone: M7 Protected Session Observation -->


## Problem

M7 binds attestation to the live game process tree before any
enforcement; the M5 chain (pin, correlation, manifest) is the
substrate but no composed observation record, session identity, or
state digest exists.

## What this slice delivers

1. `ogir_agent::observation` (ADR-0037): ObservedSession composing
   the pin + correlation + manifest; ObservedTree (the bounded
   upward walk, pid+start per hop); SessionIdentity (the
   cgroup-digest+pid+start hash); StateDigest (one order-
   independent comparable value over everything observed);
   RedactedObservation (digests/pids/start-times/counts only);
   observe/observe_pinned/refresh/same_state with identity-checked
   refresh (a restarted same-pid process is a DIFFERENT session).
2. Two production fixes from the stability chase: bounded retries
   for manifest module reads (transient failures are not drift)
   and maps-order-independent state material.
3. ADR-0037 + index row; ROADMAP boundary; this issue; the plan
   with the mid-exec finding.

## Executed evidence (dev host)

- Nine observation tests green across FIFTEEN consecutive parallel
  runs (the stability bar), including the quiet-stability contract.

## Security invariants

- Noninterference is structural: only the pinned process's procfs;
  no global enumeration exists in the code path.
- NO enforcement claim (M7 exit criterion posture).

## Out of scope

- The lifecycle cleanup matrix (M7-042); the event stream +
  renewal invalidation (M7-043); the noninterference suite + exit
  audit (M7-044).
