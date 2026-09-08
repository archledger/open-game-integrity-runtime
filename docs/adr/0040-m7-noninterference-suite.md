# ADR-0040: The M7 noninterference suite and the milestone close

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M7-044 issue](../../planning/issues/044-suite-and-audit.md)
- Supersedes: None
- Superseded by: None

## Context

M7 closes with its noninterference criterion made executable and
its exit audit. The observation, registry, and event stream
(ADR-0037..0039) are live; the suite consolidates.

## Options considered

1. **Assert noninterference only structurally (code review).**
   Not executable; refactors could regress it silently.
2. **Execute it: five targeted legs over real processes** (the
   sibling tree disjointness, the same-prefix isolation, the
   redacted-shape inspection, the log isolation, and the
   noninterference-of-observation property), plus the claim pin.
3. **A system-wide sweep comparison** (enumerate all processes,
   diff against the record). The test itself would violate the
   no-enumeration posture it protects.

## Decision drivers

- Noninterference must be EXECUTED, not just claimed structural.
- The no-enforcement-claim criterion needs a pin that survives
  refactors.

## Decision

`crates/ogir-agent/tests/m7_noninterference_suite.rs`: five
noninterference legs (an unrelated sibling never appears in any
tree and killing it does not move the state digest; same-prefix
unrelated processes stay isolated; the redacted view carries no
inventory surface; per-session event logs never cross-reference;
observation itself is noninterfering), the four-scenario cleanup
matrix consolidated, and the no-enforcement-claim pin (compile-
time: no observation type implements an Enforcement trait; runtime:
a drifting refresh returns a record, never an instruction). The
exit audit finds all four M7 criteria satisfied.

## Consequences

- M7 closes with the criterion executable; M8's enforcement work
  inherits the suite as its noninterference baseline.
- The claim pin is runtime (the compile-time note documents trait
  absence; a dead-code-clean form).

## Threat-model impact

The suite hardens the observation boundary against regressions:
any future enumeration or inventory leak fails the build.

## Privacy impact

Positive: the redacted-shape leg fails on any path-valued or
name-valued field.

## Dependency and license impact

None.

## Validation

7/7 across three consecutive runs; the full house gates in the
slice record.

## Rollback

Revert the commit; the suite and audit disappear together.

## Primary sources

ADR-0037..0039 and the executed runs (2026-09-08).
