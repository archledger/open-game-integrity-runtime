# M8-045: The enforcement seam, the first property, and the bypass suite
<!-- labels: type: implementation,area: agent,status: needs-review -->
<!-- milestone: M8 Scoped Enforcement -->


## Problem

M8 adds only the minimum game-scoped controls for one defined
threat class; the first property needs a mechanism-independent
interface, activation/immutability semantics, loss events, renewal
failure, and bypass + noninterference tests per blocked interface.

## What this slice delivers

1. `ogir_agent::enforcement` (ADR-0041): the MemoryAccessControl
   seam; the SessionPolicy (activation with the M7 observation,
   immutability, loss event, renewal closure); the SimulatedBackend
   (CI); MemoryInterface with stable spellings.
2. The bypass/noninterference suite: all three interfaces deny
   against the ACTIVE target; unrelated processes keep access
   (OutOfScope + the executed mem-open leg).
3. ADR-0041 + index row; ROADMAP boundary; this issue; the plan.

## Executed evidence (dev host)

- Five enforcement unit tests + three suite tests green.

## Security invariants

- Enforcement is game-scoped; unrelated processes keep every
  right (tested).
- The policy fails closed; loss closes renewal.

## Out of scope

- The real kernel backends (LSM/ptrace-blocking) - their own
  dev-host slices; the disclosure doc; the M8 exit audit.
