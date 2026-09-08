# ADR-0043: The invariant-coverage gate and the security dashboard

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M9-047 issue](../../planning/issues/047-laboratory.md)
- Supersedes: None
- Superseded by: None

## Context

M9 turns the threat model into executable, repeatable adversarial
testing. The scenario schema, the traceability gate, the
per-family corpus (the milestone suites), and the fuzz crate
already exist from M1-M8; the missing pieces are the
invariant-to-scenario MAPPING (the exit criterion) and the
dashboard.

## Decision drivers

- The exit criterion must be MECHANICAL, not an audit document.
- The registry records mappings to ALREADY-EXECUTED suites; it
  does not duplicate tests.
- The dashboard must not invent scores the roadmap does not claim.

## Options considered

1. **Manual audit of the mapping.** Decays silently; not a gate.
2. **A mechanical coverage gate** (every numbered invariant must
   appear in at least one scenario's invariants array) plus a
   status-only dashboard.
3. **Full family-to-corpus automation** (each of the 14 attack
   families mapped to runnable suites). Over-engineering at this
   stage; the families are covered through the invariants.

## Decision

Adopt option 2. scripts/check-invariant-coverage.py fail-closes on
any unmapped invariant (wired into CI); the 21 previously-executed
but unmapped invariants gain registry scenarios pointing at their
existing suite legs (the steps reference running the suite; the
expected decision is the deny-family shape; the notes cite the
executed evidence). scripts/security-dashboard.py prints
per-invariant scenario counts and the gate status - test status,
not marketing scores.

## Consequences

- The invariant list and the scenario registry cannot drift apart
  silently: adding an invariant without a scenario fails CI.
- The dashboard is deliberately dumb: counts and pass/fail, no
  scoring.

## Threat-model impact

Positive: the release gate now proves the invariant coverage the
threat model claims.

## Privacy impact

None.

## Dependency and license impact

None (stdlib Python).

## Validation

48/48 invariants mapped across 61 scenarios; the gate and
dashboard PASS; the traceability gate unchanged at 61 scenarios.

## Rollback

Revert the commit; the gate, dashboard, and 21 scenarios disappear
together.

## Primary sources

The M9 exit criteria and the 48-invariant SECURITY_INVARIANTS.md.
