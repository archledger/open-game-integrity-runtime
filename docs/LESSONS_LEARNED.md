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

## 2026-08-25 — Triage metadata must follow the implemented review surface

- **Context:** Final M1-008 standards review after implementation.
- **Mistaken assumption:** The original architecture/protocol/cryptography
  taxonomy and concise research issue remained sufficient after the issue
  gained model code, verifier acceptance logic, and privacy-sensitive durable
  binding state.
- **Observed failure:** The canonical issue omitted model/verifier areas,
  trusted-computing-base/privacy risks, and seven mandatory AI-task sections,
  so required specialist routing and the complete implementation contract were
  absent at needs-review.
- **Security or quality impact:** A verifier/retention change could reach human
  review without the specialist signals and explicit privacy/dependency/test
  obligations required by repository policy.
- **Permanent regression test:** Repository metadata/live-state verification
  requires the exact expanded label set, while final review checks the issue's
  threats, interfaces, positive/negative/property tests, privacy, and dependency
  sections.
- **New prevention rule:** Reconcile issue taxonomy and mandatory task sections
  against the actual changed files/trust boundaries before implementation and
  again before advancing to needs-review.
- **Documentation or agent-policy updates:** M1-008's canonical issue source and
  executable live-sync plan now carry the complete review surface; targeted TCB
  and privacy reviews are required before DCO freeze.

## 2026-08-25 — Error text must describe every producing state

- **Context:** Final M1-008 standards review of freshness diagnostics.
- **Mistaken assumption:** `ReplayDetected` meant the stored nonce had already
  been consumed.
- **Observed failure:** Duplicate registration and altered binding/window claims
  also returned `ReplayDetected` while the legitimate record remained issued,
  but `Display` stated that it was already consumed.
- **Security or quality impact:** Operator diagnostics contradicted actual state
  and could mislead incident triage even though authorization still failed
  closed.
- **Permanent regression test:**
  `replay_error_describes_registered_or_consumed_state` pins accurate,
  context-free wording.
- **New prevention rule:** Before finalizing a shared error message, enumerate
  every branch that produces the variant and describe their common condition
  without claiming a narrower internal state.
- **Documentation or agent-policy updates:** `FreshnessError::ReplayDetected`
  documentation and display wording now both cover registered or consumed
  nonce state without including replay identity or binding values.
