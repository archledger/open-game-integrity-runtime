# M7-044: The noninterference suite and the M7 exit audit
<!-- labels: type: test,area: agent,area: privacy,status: needs-review -->
<!-- milestone: M7 Session Observation -->


## Problem

M7 closes with its noninterference criterion made executable and
its exit audit of the four criteria.

## What this slice delivers

1. The five-leg noninterference suite (ADR-0040): unrelated
   siblings never appear (and their death does not move the state
   digest); same-prefix processes stay isolated; the redacted view
   has no inventory surface; event logs never cross-reference;
   observation itself is noninterfering.
2. The four-scenario cleanup matrix consolidated.
3. The no-enforcement-claim pin (compile-time + runtime).
4. The M7 exit audit: all four criteria satisfied; honest
   limitations recorded.

## Executed evidence (dev host)

- 7/7 across three consecutive runs.

## Security invariants

- Noninterference is structural AND executed.
- No enforcement claim.

## Out of scope

- M8+ (enforcement onward).
