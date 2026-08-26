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

## 2026-08-25 — Gate-order claims need distinct-time regressions

- **Context:** M1-008 targeted trusted-computing-base review.
- **Mistaken assumption:** A context-mismatch test at the existing time floor
  proved that durable time observation occurred before context rejection.
- **Observed failure:** Moving context comparison ahead of window evaluation
  would leave the floor unchanged, yet the same-time test would still pass.
- **Security or quality impact:** The suite did not prove the documented gate
  order that prevents a rejected request from hiding a later authoritative time.
- **Permanent regression test:**
  `context_mismatch_observes_time_before_rejection_and_preserves_issued_state`
  uses time 150 above the registration floor, reopens state, rejects time 140
  as rollback, and proves the original record remains claimable at time 150.
- **New prevention rule:** Tests for ordered durable transitions must use inputs
  that make each intermediate state change independently observable.
- **Documentation or agent-policy updates:** The freshness design, ADR, issue,
  invariants, test strategy, and mutation plan now name time-before-context
  ordering explicitly.

## 2026-08-25 — Retention applies to rate history and every durable copy

- **Context:** M1-008 targeted privacy review.
- **Mistaken assumption:** Purging expired replay records was sufficient to
  satisfy expiry-driven deletion for the complete freshness store.
- **Observed failure:** Issuance events survived explicit garbage collection
  until a later registration, and detached test snapshots retained replay
  bindings after the live store purged them.
- **Security or quality impact:** Publisher and binding state could outlive its
  enforcement purpose through rate history or an ordinary restart copy.
- **Permanent regression test:**
  `gc_bounds_rate_history_and_scrubs_every_durable_state_handle` proves exact
  rate-window deletion and exact-expiry record deletion through handles created
  before both purges.
- **New prevention rule:** Enumerate every retained field and every persistence
  copy when defining deletion; a live-table TTL alone is not end-to-end
  retention control.
- **Documentation or agent-policy updates:** The reference adapter now stores a
  finite lifetime per issuance event and aliases one authoritative durable state
  generation for reopen; production exports require separate retention and
  anti-rollback review.

## 2026-08-25 — Redaction must cover the entire derived object graph

- **Context:** M1-008 targeted privacy review of replay-state diagnostics.
- **Mistaken assumption:** Redacting nonce, account, and match leaf types kept
  parent replay objects safe to derive `Debug`.
- **Observed failure:** Parent debug output still exposed publisher, game,
  build, policy, version, and issuance/expiry timestamps, while the store trait
  unnecessarily required every adapter to implement `Debug`.
- **Security or quality impact:** Lower-access diagnostic sinks could receive a
  nearly complete authorization binding despite leaf-level redaction.
- **Permanent regression test:**
  `replay_debug_and_errors_redact_every_binding_and_timestamp` checks replay
  keys, bindings, registrations, guards, stores, durable-state handles, and
  errors against distinct values for every binding and timestamp field.
- **New prevention rule:** Audit formatted roots and all recursively reachable
  fields; use explicit redacted implementations and do not impose diagnostic
  trait bounds on security-state adapters without a functional need.
- **Documentation or agent-policy updates:** ADR-0005, the design, architecture,
  issue, threat model, test strategy, and privacy scenario now define the full
  replay diagnostic boundary.

## 2026-08-25 — Redacted parents do not make raw-debuggable children safe

- **Context:** M1-008 final privacy re-review.
- **Mistaken assumption:** Redacting replay-state aggregate roots was sufficient
  because callers would normally format those roots rather than their public
  children or the surrounding verifier request.
- **Observed failure:** Public accessors returned publisher/game/build/policy/
  version/window leaves with raw `Debug`, while `PublisherChallenge`,
  `ExpectedContext`, and `VerificationRequest` recursively exposed the same
  values. The regression formatted only six already-redacted roots.
- **Security or quality impact:** Ordinary diagnostic formatting could bypass
  the intended replay-binding redaction without deliberately calling explicit
  value accessors.
- **Permanent regression test:** `privacy_sensitive_debug_output_is_redacted`,
  `publisher_challenge_uses_typed_ids_and_redacts_complete_binding`, and
  `replay_debug_and_errors_redact_every_binding_and_timestamp` cover each
  identifier/time child and every challenge/request/replay aggregate.
- **New prevention rule:** Redact safe-by-default formatting at both leaf and
  aggregate layers. Keep explicit value getters for trusted functional logic,
  and document that they are not diagnostic interfaces.
- **Documentation or agent-policy updates:** The model, architecture, ADR,
  design, issue, threat model, test strategy, scenario, and mutation plan now
  define the complete default-debug boundary.

## 2026-08-25 — Shared-state tests must open handles before later mutation

- **Context:** M1-008 final privacy re-review of retention propagation.
- **Mistaken assumption:** Capturing a snapshot before garbage collection and
  reopening it afterward proved that `reopen` preserved shared state.
- **Observed failure:** A mutation that deep-copied the already-purged state
  inside `reopen` would pass; no reopened store remained alive while another
  handle performed later deletion.
- **Security or quality impact:** The suite did not prove the documented rule
  that every ordinary reopen handle observes subsequent authoritative GC.
- **Permanent regression test:**
  `gc_bounds_rate_history_and_scrubs_every_durable_state_handle` now reopens
  before each rate/record purge and inspects that same live handle afterward.
- **New prevention rule:** For aliasing and propagation claims, create every
  observer before the state transition and assert through it after the
  transition.
- **Documentation or agent-policy updates:** The spec, issue, threat/test docs,
  privacy scenario, and mutation plan now say “opened before deletion” rather
  than relying on snapshot-capture timing alone.

## 2026-08-25 — Traceability requirements belong in the scenario schema

- **Context:** M1-008 final trusted-computing-base/standards review.
- **Mistaken assumption:** Naming invariants, tests, and residual risks in each
  attack scenario satisfied the threat-to-test rule even though ownership and
  assurance-profile mappings remained implicit.
- **Observed failure:** All three M1-008 scenarios omitted the rule's mandatory
  owner and required assurance profile, and the shared schema could not reject
  either omission. The pre-existing protocol replay scenario had the same gap.
- **Security or quality impact:** An accepted threat could lose accountable
  maintenance or silently become optional in a weaker assurance profile while
  still passing structural validation.
- **Permanent regression test:** The dependency-free attack-scenario
  traceability self-tests reject missing, malformed, duplicate, or
  schema-optional fields; the repository check and full JSON Schema validation
  accept all scenarios with `owner: initial-maintainer` and
  `required_assurance_profile: all-protected-modes`.
- **New prevention rule:** If the threat model says a traceability attribute is
  mandatory, encode it as a required machine-readable field rather than prose
  or reviewer convention.
- **Documentation or agent-policy updates:** The scenario schema, standard-
  library aggregate gate, attack-lab README, threat model, test strategy, issue,
  ADR, approved spec, implementation plan, and all four existing scenarios now
  carry or enforce the mapping explicitly.
