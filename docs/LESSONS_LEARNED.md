# Lessons learned

This file records durable process and design lessons from confirmed defects, failed experiments, incorrect assumptions, and security reviews.

Each entry must include:

```text
Date
Context
Mistaken assumption
Observed failure
Security or quality impact
Permanent regression test
New prevention rule
Documentation or agent-policy updates
```

Do not use this document to expose embargoed vulnerability details before coordinated disclosure.

## 2026-08-25 — Rejected windows must still persist authoritative time

- **Context:** M1-008 challenge freshness adversarial review.
- **Mistaken assumption:** Returning `NotYetValid` or `Expired` before entering
  the replay store was safe because the request was already fail-closed.
- **Observed failure:** An expired request observed at time 300 left the durable
  floor at 100; after restart, time 150 could claim the same `[100, 200)`
  challenge instead of failing rollback.
- **Security or quality impact:** A rejected request could hide a forward clock
  observation and let later rolled-back time escape the monotonicity contract.
- **Permanent regression test:**
  `rejected_future_time_persists_floor_across_restart`, plus a mutation that
  deletes pre-window `observe_time`.
- **New prevention rule:** Treat authoritative time observation as a durable
  security transition. Check/advance its floor before any later window error,
  and recheck it inside atomic state-changing operations.
- **Documentation or agent-policy updates:** ADR-0005, the freshness design and
  implementation plan, architecture, invariants, threat model, test strategy,
  and freshness-state attack scenario now record store-first observation.

## 2026-08-25 — Audit every capability-producing API, not only constructors

- **Context:** M1-008 `FreshnessChecked` adversarial review.
- **Mistaken assumption:** Private capability fields and a compile-fail struct
  literal were sufficient to make skipped verifier gates unrepresentable.
- **Observed failure:** Public `FreshnessGuard::claim` returned
  `FreshnessChecked` using only challenge/time/store inputs, so downstream code
  could obtain it without independently supplied context or the ordered
  verifier entry point.
- **Security or quality impact:** Future verifier-state code could accidentally
  treat a raw replay claim as proof that all preceding gates ran.
- **Permanent regression test:** A compile-fail doctest requires raw public
  claim to return `Result<(), FreshnessError>`; a mutation restoring the
  capability return makes that doctest fail.
- **New prevention rule:** For every typestate or authorization capability,
  enumerate and restrict all functions that can return or construct it. A
  private field alone is not a complete issuance boundary.
- **Documentation or agent-policy updates:** ADR-0005, the freshness design and
  implementation plan, architecture, invariants, threat model, and test
  strategy now distinguish raw consumption from crate-internal capability
  creation.
