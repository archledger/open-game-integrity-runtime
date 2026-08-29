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

## 2026-08-25 — Security metadata must be parsed, not line-scanned

- **Context:** M1-008 TCB certification re-review of the new scenario gate.
- **Mistaken assumption:** A strict-looking top-level line matcher was enough to
  enforce two scalar fields in YAML without adding a parser dependency.
- **Observed failure:** The checker accepted a quoted duplicate `owner` key and
  accepted valid mappings in one YAML document followed by an ownerless second
  document because it ignored both syntaxes.
- **Security or quality impact:** The aggregate gate claimed owner/profile
  enforcement while ambiguous or additional scenario content could bypass it.
- **Permanent regression test:** The attack-scenario self-test supplies a
  quoted duplicate key and a second-document separator; parsed validation must
  reject both, along with missing/malformed mappings and unknown fields.
- **New prevention rule:** Do not approximate a security-relevant serialization
  with line matching. Use a real parser with duplicate detection and enforce a
  single canonical document format.
- **Documentation or agent-policy updates:** Scenarios now use one
  `*.scenario.json` document each. The standard-library gate parses with a
  duplicate-key hook, validates every supported shared-schema keyword, rejects
  unsupported future keywords, and remains cross-checked with Draft 2020-12
  validation during final verification.

## 2026-08-25 — “Parsed JSON” still needs strictness, budgets, and safe diagnostics

- **Context:** M1-008 exact-head TCB/privacy certification of the parsed
  scenario validator.
- **Mistaken assumption:** Python's default JSON decoder plus recursive schema
  checks were strict and bounded enough once duplicate keys/documents failed.
- **Observed failure:** Default decoding accepted `NaN`/`Infinity`; `$`-anchored
  mapping patterns accepted a terminal newline; schema dialect drift and nested
  expected fields passed; parser budgets were undeclared; malformed-input
  diagnostics printed the absolute checkout/home path.
- **Security or quality impact:** Repository-controlled input could disagree
  with RFC 8259/downstream parsers, weaken exact role/profile lookup, consume
  unbounded resources, or disclose a contributor/runner home path.
- **Permanent regression test:** The aggregate self-test rejects non-JSON
  constants, terminal-newline mappings, wrong/empty dialects, nested unknown
  fields, oversized/deep/wide/long inputs, and proves malformed absolute-source
  diagnostics omit `/home/`. Final verification additionally cross-checks the
  current schema/scenarios and newline/nested-unknown probes with an external
  Draft 2020-12 implementation; that optional tool is not an aggregate
  dependency.
- **New prevention rule:** A security parser contract includes its exact
  dialect, nonstandard decoder options, closed-object policy, resource budgets,
  and diagnostic data boundary—not only syntax parsing.
- **Documentation or agent-policy updates:** The parser, schema, attack-lab
  README, issue, threat/test docs, ADR, approved spec, and implementation plan
  now state and enforce strict constants, exact dialect, closed expected fields,
  and fixed limits; the later basename-injection entry supersedes its diagnostic
  label rule.

## 2026-08-25 — Validator safety includes schema programs and error arguments

- **Context:** Final M1-008 TCB/privacy certification after strict JSON closure.
- **Mistaken assumption:** Input-size bounds and source-label sanitization made
  every schema operation and error path bounded and private.
- **Observed failure:** Schema-provided backtracking regexes could exceed a
  processing-time budget or raise uncaught overflow; duplicate/property/caller
  names and I/O labels could inject home paths into errors; the scenario
  directory symlink and three limit branches lacked regressions. Separately,
  concurrent-claim and capacity threats had tests but no attack scenarios, and
  an optional external Draft check was described as permanent aggregate proof.
- **Security or quality impact:** Pull-request-controlled metadata could stall
  validation, disclose host paths, redirect the validation boundary, or leave
  accepted threats without required scenario traceability.
- **Permanent regression test:** The validator accepts only two reviewed regex
  patterns; rejects backtracking/oversized-repetition patterns; converts
  unexpected exceptions to context-free failure; tests every parser limit,
  scenario-count boundary, and scenario-directory symlink; and probes parse,
  duplicate, I/O, schema, and instance errors with injected `/home/` values.
  Dedicated race and capacity scenarios complete the threat map.
- **New prevention rule:** Treat schemas as executable input. Whitelist bounded
  pattern programs, make every diagnostic argument context-free, test every
  branch behind a published limit, and distinguish permanent aggregate gates
  from optional final differential checks.
- **Documentation or agent-policy updates:** The validator, threat map, two new
  scenarios, attack-lab/test/spec/ADR/issue/plan text, and corrected differential
  statement now reflect these boundaries.

## 2026-08-25 — A basename is still attacker-controlled diagnostic data

- **Context:** Final M1-008 TCB certification of context-free parser errors.
- **Mistaken assumption:** Reducing an absolute scenario path to its basename
  made the diagnostic source safe and useful.
- **Observed failure:** A PR-controlled filename containing a newline and
  `::error::` produced a second forged GitHub-style annotation line in stderr.
- **Security or quality impact:** Malicious repository metadata could spoof CI
  log structure or annotations even though it no longer disclosed the host path.
- **Permanent regression test:** A malformed parse source containing CR/LF,
  terminal escape, and CI error-command text must yield an error containing none
  of those values; the same helper continues to cover home-path injection across
  parse, duplicate, I/O, schema, and instance failures.
- **New prevention rule:** Do not sanitize an untrusted diagnostic label into a
  different untrusted label. Use a fixed context-free token unless the value has
  a formally encoded safe representation.
- **Documentation or agent-policy updates:** Parser code, attack-lab README,
  threat/test docs, issue, ADR, approved spec, and implementation plan now
  require one fixed label and forbid filenames, controls, and CI commands.

## 2026-08-25 — Review primary sources again when remediation expands scope

- **Context:** M1-008 final standards review after adding a repository JSON/
  schema validator during freshness-review remediation.
- **Mistaken assumption:** The issue's original freshness/time sources remained
  complete because the parser was support tooling rather than protocol code.
- **Observed failure:** The implementation enforced RFC 8259, Draft 2020-12,
  and Python decoder-hook behavior without recording any of those primary
  sources in the issue/spec/ADR/lab contract.
- **Security or quality impact:** Reviewers could not distinguish deliberate
  strictness/limit decisions from ad hoc parser behavior using the canonical
  task source list.
- **Permanent regression test:** Final issue-contract review now includes direct
  official links for JSON syntax/parser limits, JSON Schema core/validation,
  and Python `json` controls alongside the freshness sources.
- **New prevention rule:** Re-run the primary-source inventory whenever review
  remediation adds a new language, parser, format, dependency boundary, or
  security mechanism—even when it is test/repository tooling.
- **Documentation or agent-policy updates:** Issue #8, the approved design,
  ADR-0005, and attack-lab README now record all four parser/schema sources.

## 2026-08-25 — Every named failure mode and sentinel must execute

- **Context:** M1-008 final TCB review of fail-closed and diagnostic tests.
- **Mistaken assumption:** Poisoned-lock behavior was covered by inspection and
  unavailable-state tests, while listing CR/`::warning::` in forbidden output
  was equivalent to injecting them.
- **Observed failure:** No test actually poisoned either replay-store mutex, and
  the hostile filename contained LF/escape/`::error::` but neither CR nor
  `::warning::`.
- **Security or quality impact:** Required fail-closed branches and two claimed
  diagnostic sentinels could regress while the suite stayed green.
- **Permanent regression test:**
  `poisoned_replay_store_locks_fail_closed_without_allow` poisons both locks and
  exercises register/claim/GC/snapshot/verifier mapping. The filename fixture
  now contains CR, LF, escape, `::error::`, and `::warning::`, all forbidden in
  the rendered error.
- **New prevention rule:** For every named branch or forbidden sentinel, make
  the fixture reach or contain it; assertions against absent inputs are vacuous.
- **Documentation or agent-policy updates:** Freshness spec/ADR/test strategy,
  parser self-test, implementation plan, and this ledger record the executable
  coverage.

## 2026-08-26 — Named invalid edges need deterministic execution

- **Context:** M1-009 local-session mutation testing.
- **Mistaken assumption:** One million deterministic actions plus nonzero valid
  renewal counters made the history property sensitive to direct activation
  from `RenewalPending`.
- **Observed failure:** The focused renewal test rejected the shortcut, but the
  history test passed the mutant because its scheduled prefix exercised only
  the valid renewal path and its pseudo-random remainder never attempted that
  invalid edge in a reachable renewal state.
- **Security or quality impact:** A renewal authorization bypass could survive
  the claimed arbitrary-history proof despite the large action count.
- **Permanent regression test:** The fixed deep-history prefix now attempts
  `Activate` immediately after entering `RenewalPending`, requires rejection,
  then continues through a fresh permit and valid renewed activation without
  changing the exact 1,048,576-action budget.
- **New prevention rule:** For every named security-sensitive invalid edge,
  schedule a reachable deterministic attempt; action volume and valid-path
  counters do not prove invalid-edge coverage.
- **Documentation or agent-policy updates:** This ledger and the Task 6
  mutation report record the gap, RED mutant, and corrected exact history.

## 2026-08-26 — Compile-fail tests must fail for the intended privacy boundary

- **Context:** M1-009 opaque-capability and private-state mutation testing.
- **Mistaken assumption:** The external construction and state-mutation
  compile-fail doctests would fail if their target fields became public.
- **Observed failure:** Both doctests remained green after the fields became
  public because the compiler instead rejected the still-private
  `SessionBinding` or `SessionState` type inferred by the generic fixture.
- **Security or quality impact:** Public authority/state fields could survive
  the named focused proof while the test appeared to enforce field privacy.
- **Permanent regression test:** `ValidatedPermit` and `LocalSession` locally
  deny Rust's `private_interfaces` lint. The exact public-field mutations now
  fail compilation at the boundary, while the existing doctests continue to
  cover construction or mutation if both the field and its type become public.
- **New prevention rule:** Inspect the compiler error for every compile-fail
  test and mutation. When a private supporting type can mask the target
  visibility failure, add an independent compile-time or structural guard for
  the public interface itself.
- **Documentation or agent-policy updates:** This ledger and the Task 6
  mutation report record both masked failures and their compile-time guards.

## 2026-08-26 — A mutation must reach its test, not only fail compilation

- **Context:** M1-009 whole-branch review of authority-field mutation proof.
- **Mistaken assumption:** Denying `private_interfaces` on two opaque structs
  was sufficient evidence because a public private-typed field made the focused
  Cargo command nonzero.
- **Observed failure:** The compiler stopped before rustdoc or a runtime test
  executed; the same pattern left `CleanupCompleted.binding` unguarded, and no
  external proof covered reading or replacing `LocalSession.session_id`.
- **Security or quality impact:** Mutation closure was overstated and several
  authority-bearing fields lacked a test whose intended failure was their own
  privacy boundary.
- **Permanent regression test:** One external compile-pass proves the public
  opaque types exist; 19 separate compile-fail doctests produce field-privacy
  errors for every binding plus session-ID read/replacement and state access;
  and `every_authority_field_is_structurally_private` runs as one focused test
  and rejects each exact public-field mutation.
- **New prevention rule:** A named mutation command must execute at least one
  test and fail its intended assertion or diagnostic. Use a structural guard
  when a private supporting type would otherwise mask field visibility.
- **Documentation or agent-policy updates:** The approved spec, implementation
  plan, test strategy, ADR-0006, 27-probe table, and Task 6 report record the
  layered proof and supersede the earlier lint-only closure.

## 2026-08-26 — A focused Cargo success must execute the named test

- **Context:** M1-010 immutable verifier-terminal verification.
- **Mistaken assumption:** `cargo test --lib <bare-test-name> -- --exact` would
  match a nested unit test whose real name begins with
  `verification::tests::`.
- **Observed failure:** The command exited zero while reporting `running 0
  tests` and filtering every verifier test. Exit status alone looked green even
  though the named terminal regression never executed.
- **Security or quality impact:** Terminal immutability or a later mutation
  probe could be reported as covered without exercising its detector.
- **Permanent regression test:** Focused verifier commands use the fully
  qualified name, including
  `verification::tests::every_failure_class_is_terminal_and_releases_the_request`,
  `verification::tests::all_182_phase_action_pairs_match_the_independent_model`,
  and
  `verification::tests::one_million_actions_match_the_independent_verifier_model`,
  and their evidence records the expected `running 1 test`/`1 passed` count.
  Each M1-010 mutation report row must likewise name the intended assertion or
  compiler cause rather than accepting any nonzero result.
- **New prevention rule:** A focused command is evidence only when its output
  confirms the expected test count and intended assertion/compiler boundary;
  zero-test success and wrong-cause failure are both invalid.
- **Documentation or agent-policy updates:** The verifier mutation contract in
  `TEST_STRATEGY.md`, this ledger, and the live execution handoff record the
  count-and-cause requirement.

## 2026-08-26 — Test the authority payload and every retained diagnostic state

- **Context:** M1-010 independent TCB/privacy review after the initial mutation
  campaign.
- **Mistaken assumption:** Correct public flow outcomes, one sentinel-bearing
  active flow, and exact redaction labels were sufficient proof for the
  returned authority token and every phase-specific diagnostic surface.
- **Observed failure:** Three terminal/error/outcome diagnostic mutants and
  three wrong-binding/wrong-class `VerifiedAttestation` mutants all survived
  their existing focused tests. The unknown-gate test also invoked only a
  generic no-argument failure method rather than modeling an unknown required
  gate.
- **Security or quality impact:** A future result consumer could receive
  restricted authority labeled full or a token bound to another allocation;
  terminal-only retained state, error Debug, outcome Debug, decimal counts, or
  unknown mandatory requirements could evade claimed proof.
- **Permanent regression test:** Canonical full/restricted tests inspect the
  returned capability's exact allocation and class. Every phase is formatted
  from the private sentinel request, complete flow/outcome/error Debug strings
  are asserted, decimal digits are forbidden, and unknown mandatory gates use
  typed `UnsupportedRequirement` input. The mutation table expands with
  `V01-V03`, `D14`, and `D15`, and the entire 93-probe campaign restarts.
- **New prevention rule:** Assert the contents of an authority-bearing return
  value directly; public container state is not a proxy. Privacy fixtures must
  carry real private context through every retained phase, and mutations must
  disclose the named data class rather than merely alter a label.
- **Documentation or agent-policy updates:** ADR-0007, architecture, threat
  model, roadmap wording, approved design/plan amendment, test strategy,
  mutation report, and this ledger record the expanded proof.

## 2026-08-26 — Fix scanner dataflow boundaries, not one reported source

- **Context:** M1-010 pull-request and post-merge CodeQL analysis of synthetic
  freshness nonce fixtures.
- **Mistaken assumption:** Replacing the one newly reported hard-coded nonce
  literal meant the underlying test-fixture dataflow was closed.
- **Observed failure:** The pull-request scan became green, but the subsequent
  full `main` scan opened alert #38 on another existing literal passed through
  the same raw `[u8; 32]` `nonce` helper boundary. Dozens of equivalent callers
  remained.
- **Security or quality impact:** A symptom-only fix let a critical-severity
  scanner alert move to another line after merge and weakened confidence that a
  green pull-request delta represented the complete repository state.
- **Permanent regression test:** Freshness fixture builders accept only scalar
  seeds, one helper derives the typed nonce behind the reviewed bitwise barrier,
  and the complete 256-seed domain is deterministic and pairwise distinct. The
  final evidence requires a full default-branch scan with no equivalent open
  alert and no dismissal.
- **New prevention rule:** Trace a security-scanner result to the shared
  source/sink API, inventory every equivalent caller, and fix that boundary.
  Never infer full-repository closure from one pull-request-selected result.
- **Documentation or agent-policy updates:** Issue #14, the test strategy, and
  this ledger record the root cause and full-branch closure requirement; no
  attack scenario is added because the issue accepts no new runtime/protocol
  threat. Process-quality failures remain traceable through the issue, finite
  regression, independent review, and full-main scanner gate.

## 2026-08-26 — Make shell evidence fail closed before printing success

- **Context:** M1-007F live-issue body reconciliation after intermittent GitHub
  API failures.
- **Mistaken assumption:** A shell command that ran an equality `test` and then
  printed `body_bytes_equal=yes` established equality without explicit
  fail-fast shell options.
- **Observed failure:** The final `printf` could execute and return success even
  if an earlier equality `test` failed, so the printed success line was not
  valid evidence. Review also found that the durable report omitted the live
  body's SHA-256.
- **Security or quality impact:** A live issue body could be reported as
  byte-identical to the reviewed local source without a fail-closed comparison,
  weakening provenance for the authorized implementation scope.
- **Permanent regression test:** External byte-equality evidence uses
  `set -euo pipefail`, computes and records both local and live SHA-256 values,
  requires the equality check to pass, and only then emits success evidence.
- **New prevention rule:** Never treat a command's final successful print as
  proof that earlier checks succeeded. Make multi-step evidence commands fail
  closed and preserve the compared values or hashes in the durable report.
- **Documentation or agent-policy updates:** The corrected Task 1 report
  explicitly invalidates the earlier apparent success and records the matching
  fail-closed hashes; this ledger preserves the rule for future external-state
  reconciliation.

## 2026-08-27 — Privacy tests must not disclose the regression they detect

- **Context:** Post-merge CodeQL 2.26.4 review of verifier freshness privacy
  diagnostics.
- **Mistaken assumption:** Synthetic fixtures and test-only assertions made it
  harmless to include the forbidden value or complete diagnostic in failure
  output, and message-free `assert_eq!` comparisons were safe.
- **Observed failure:** Alerts #43/#44 traced private account data into custom
  assertion messages; Rust 1.98.0 also prints both operands for every failed
  `assert_eq!`, creating same-root-cause variants across privacy tests.
- **Security or quality impact:** A redaction regression could copy the private
  value into local or CI logs through the test intended to catch it, while
  repeated scanner noise reduced the value of full-branch analysis.
- **Permanent regression test:** Existing exact redaction and forbidden-value
  tests now fail with fixed generic text; CodeQL alerts #43/#44 provide the
  scanner RED and must be fixed by analysis with null dismissal metadata.
- **New prevention rule:** Privacy assertions may compare or search sensitive
  diagnostics, but their panic path must not format either operand, the
  forbidden fixture, or the diagnostic under test. Prefer boolean `assert!`
  with fixed generic text over `assert_eq!` for privacy-bearing values.
- **Documentation or agent-policy updates:** Issue #18, its design/plan, and the
  test strategy record the assertion rule; no production or threat-model change
  is implied.

## 2026-08-28 — Source-token authority proofs need closed expansion boundaries

- **Context:** M1-011 Task 8 review of Appraisal Result authority and privacy
  structure.
- **Mistaken assumption:** Inspecting direct root declarations and
  authority-named tokens was sufficient to prove the complete construction and
  method surface of opaque result types.
- **Observed failure:** Nested modules, aliases, imports, generic macros,
  `include!`, declaration attributes, parent-module expansion, relative `std`
  macro paths, and crate-local `std` bindings could create or redirect an
  authority-bearing path outside the inspected inventory.
- **Security or quality impact:** A source change could expand result
  construction, conversion, failure issuance, or diagnostic behavior while the
  claimed structural proof stayed green. Runtime behavior was not shown to be
  exploitable; the defect was in the completeness of the test evidence.
- **Permanent regression test:** The recursive literal-preserving authority
  inventory rejects unapproved module sources, aliases, imports, definitions,
  invocations, attributes, and reserved bindings; pins the complete parent
  module inventory; and requires exact absolute `::std::matches!` and
  `::std::unreachable!` calls. Isolated physical mutations exercise each layer.
- **New prevention rule:** A source-token proof must enumerate every source and
  expansion mechanism in scope, establish an otherwise-valid positive baseline
  before each negative probe, and fail closed on uninspected mechanisms. It must
  also state that it is not a Rust parser, macro-expansion engine,
  cryptographic proof, or secure-erasure proof.
- **Documentation or agent-policy updates:** ADR-0009 and the M1-011 Task 8
  report record the closed inventory, layered regressions, and explicit proof
  limits.

## 2026-08-28 — Terminal state shape does not prove allocation release

- **Context:** M1-011 Task 10 independent privacy review.
- **Mistaken assumption:** Replacing the request-bearing active state with a
  claim-free terminal was sufficient to prove all attempt-private data was
  released.
- **Observed failure:** `VerifierFlow.binding` lived outside the state enum, so
  failures retained its `AttemptRecord` and `ReplayRegistration`; success cloned
  the binding and left a second owner in the terminal flow.
- **Security or quality impact:** Privacy evidence claimed terminal retention
  bounds that the real allocation lifetime contradicted.
- **Permanent regression test:** Test-only `Weak<AttemptRecord>` probes keep the
  terminal flow alive and prove failure release before return plus sole success
  ownership by `VerifiedAttestation`; one-cause physical mutations remove the
  release and restore the clone.
- **New prevention rule:** Retention reviews must test allocation lifetime, not
  infer it from state shape. Registered owner `initial-maintainer` must gate
  privacy review before result fields, diagnostics, wire adapters, storage or
  backups, logging, or telemetry expand.
- **Documentation or agent-policy updates:** Invariant 38, architecture,
  threat/privacy models, roadmap, issue, ADR-0009, test strategy, and scenario
  `OGIR-PRIVACY-VERIFIER-DIAGNOSTICS-001` now state the ownership bound and gate
  without claiming secure erasure.

## 2026-08-28 — Mutation kills must match their declared detector

- **Context:** M1-011 Task 10 whole-branch mutation-evidence review.
- **Mistaken assumption:** A nonzero focused test exit after one test executed
  proved that each mutant was killed by the row's declared authority or
  whole-state detector.
- **Observed failure:** `R03`-`R06` added generic `unreachable!` invocations and
  `A17` added `panic!`; the shared `STATE` test rejected those new macros before
  reaching `validate_active_state_replacement` or the
  `VerifiedAttestation` method/construction inventories. The archive therefore
  supported 149, not 154, intended-cause kills.
- **Security or quality impact:** Campaign completion and review readiness were
  overstated even though no runtime authority bypass was found.
- **Permanent regression test:** Redesign all five mutants to compile without
  adding a macro invocation, prove their focused failures name the declared
  detector, then restart and audit the complete 154-row campaign from E01.
- **New prevention rule:** A mutation row passes only when its raw output names
  the declared assertion or compiler boundary. Treat earlier aggregate guards,
  collateral failures, syntax failures, and zero-test runs as invalid evidence.
- **Documentation or agent-policy updates:** The test strategy records the
  corrected 149-row support and requires a 154-row cause audit before closure.
