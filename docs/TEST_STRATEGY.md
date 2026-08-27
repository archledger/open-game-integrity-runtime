# Test and attack-simulation strategy

## Test pyramid

### Unit tests

Pure domain invariants, length checks, state transitions, policy evaluation,
redaction, expiry, identifier validation, and fail-closed behavior. Challenge
freshness includes checked window construction and literal before/exact issue,
last-second, exact/after expiry, excessive lifetime, and near-`u64::MAX`
boundaries.

Local-session tests exhaust the 12 reachable state configurations × 10 actions
= 120 pairs against an independent literal model: exactly 26 succeed and 94
reject without state mutation. The cleanup query returns a request for exactly
the two terminal states whose `CleanupStatus` is `Required`. One external
compile-pass doctest and 19 separate compile-fail doctests cover public type
availability, session construction, cloning, every private capability/request
binding, private session-ID read/replacement, and private-state access. A
focused structural test prevents private supporting types from masking public
authority/state fields. Exact diagnostic allowlists use non-vacuous private
session sentinels and exclude raw authorization, process, and path values.

#### Verifier flow

Verifier-flow tests exhaust 14 phases × 13 actions = 182 pairs against an
independent literal model: exactly 48 succeed and 134 reject unchanged. Seven
gate omissions and all 7! = 5,040 orderings prove that only one canonical order
can reach `PolicySatisfied`. All seven capabilities reject an equal cloned
request in a different flow through allocation identity.
Full and restricted success tests also inspect the returned capability's exact
allocation identity and private allowed class; flow outcome alone is not used
as a proxy for authority payload correctness.

The fixed action budget is exactly 1,048,576: 2,048 scheduled actions guarantee
at least 16 full and 16 restricted completions plus every failure/reason,
binding, and terminal class; 1,046,528 fixed-seed actions exercise arbitrary
histories against the same independent oracle. A new flow is test setup after
terminal entry and is not counted as one of the 13 actions.

One public compile-pass, 39 single-cause compile-fail doctests, and structural
tests cover every authority-bearing type/field, outcome construction, raw-claim
exclusion, and report/capability substitution. Exact diagnostic tests cover the
request, flow, all gates, binding, errors, outcomes, final capability, and
direct `EvidenceBundle` formatting. Every phase is built from the same private
sentinel request, both error Display/Debug variants and every outcome Debug are
exact, and decimal counts/times are forbidden.

### Property tests

Examples:

- changing any bound challenge field changes the binding digest;
- a permit for match A never validates for match B;
- an expired or revoked object never produces `Allow`;
- malformed or unknown critical input never produces `Allow`;
- encode/decode round trips preserve one canonical representation;
- renewal never lowers the active policy;
- disclosure output is a subset of the profile's allowed claims;
- fixed-seed register/claim/time-advance/rollback/restart/unavailable/GC
  sequences preserve at most one freshness capability, monotonic persisted
  time, no success from unavailable state, and no loss of an unexpired record.
- 4,096 fixed-seed local-session sequences of 256 actions execute exactly
  1,048,576 actions and compare implementation state and results after every
  action. The fixed budget contains 80 scheduled deep-path actions and
  1,048,496 pseudo-random actions. The final exact counters are initial permit
  8, initial activation 8, renewal entry 12, renewal permit 10, and renewed
  activation 10; every required deep path is therefore reached at least eight
  times.

### Fuzz tests

Every untrusted parser:

- Wine/Unix bridge frame;
- local IPC frame;
- publisher challenge;
- evidence bundle;
- TPM quote wrapper;
- measured-boot log;
- IMA log;
- policy and reference manifest;
- Attestation Result and permit;
- update metadata.

### Differential tests

At least two independent decoders/verifiers must agree on valid and invalid conformance vectors before the signed production format is frozen.

### Mutation tests

Freshness tests must fail when either time edge is widened, replay identity is
scoped by context, check and consume are split, restart clears records, clock
rollback is accepted, capacity evicts a live record, a successful claim remains
issued, future-time or context-mismatch rejection skips durable observation,
raw claim returns a capability, binding/window failure consumes the original
issued record, checked arithmetic wraps, rate history survives its window,
an already-reopened handle retains later-purged state, or any binding/time leaf
or challenge/request/replay aggregate debug output is unredacted. Each
mutation runs in a disposable worktree; mutated source never returns to the
primary branch.

The exact 27-probe local-session mutation table must kill deleted or widened
challenge/caller/preparation/evidence/permit/activation/renewal gates, evidence
before caller binding or preparation, activation without `PermitReceived`,
direct `RenewalPending -> Active`, cross-session capability acceptance,
cloneable authority objects, every public authority/state field, lifecycle
progress from a terminal state, omitted cleanup-required state on either
terminal path, mismatched or duplicate cleanup completion, cleanup completion
that changes terminal disposition, and raw private-session diagnostic
disclosure.

M1-010 expands every verifier gate, authority type, terminal, mapping, retained
field, constructor, and diagnostic into its own single-cause probe. A grouped
mutation cannot stand in for a per-gate or per-field result. The frozen table is
exactly 93 probes:

| Group | Probe IDs | Exact mutation | Required detector |
| --- | --- | --- | --- |
| Phase guards (9) | `P01` challenge, `P02` freshness, `P03` identity, `P04` evidence, `P05` session, `P06` revocation, `P07` policy, `P08` early full completion, `P09` early restricted completion | Delete or widen one expected-phase comparison; each completion probe changes only its named allowed class. | 182-pair oracle, omission/permutation, and full/restricted early-completion tests |
| Binding (8) | `B01` challenge, `B02` freshness, `B03` identity, `B04` evidence, `B05` session, `B06` revocation, `B07` policy, `B08` allocation identity | Bypass only that capability comparison; for `B08`, replace `Arc::ptr_eq` with replay-registration/request equality. | Seven equal-data cross-flow test |
| Authority production (3) | `A01` accept `Decision`, `A02` raw claim returns/mints `FreshnessChecked`, `A03` issue a second `VerifiedAttestation` | Add one forbidden authority shortcut. | Single-cause compile-fail or repeated-completion test |
| Verified capability payload (3) | `V01` returned binding, `V02` full allowed class, `V03` restricted allowed class | Return a distinct allocation with equal registration, or flip exactly one returned allowed class while leaving the flow report unchanged. | Direct private assertions on the returned `VerifiedAttestation` binding and allowed class |
| Terminality (7) | `T01` Verified, `T02` Malformed, `T03` Unsupported, `T04` Retryable, `T05` Denied, `T06` Revoked, `T07` reclassification | Permit one action from that terminal or allow a failure terminal to change class/reason. | Terminal × 13 matrix and terminal-class test |
| Unknown gate (1) | `U01` | Continue progress instead of `mark_unsupported`. | Unknown-gate regression/scenario |
| Outcome mapping (7) | `M01` full, `M02` restricted, `M03` malformed, `M04` unsupported, `M05` retryable, `M06` revoked, `M07` denial-reason map | Change one decision or reason mapping. | Complete outcome table test |
| Request retention (6) | `R01` Verified, `R02` Malformed, `R03` Unsupported, `R04` Retryable, `R05` Denied, `R06` Revoked | Omit request release for exactly one terminal. | Request-exists-only-while-nonterminal test |
| Clone/copy (9) | `C01` flow, `C02` challenge, `C03` freshness, `C04` identity, `C05` evidence, `C06` session, `C07` revocation, `C08` policy, `C09` verified | Add `Clone`, or `Copy` where compilable, to exactly one authority type. | Matching single-cause compile-fail doctest |
| Private fields (17) | `F01` flow binding, `F02` flow request, `F03` flow state, `F04` attempt registration, `F05` binding Arc, `F06` challenge binding, `F07` freshness binding, `F08` identity binding, `F09` evidence binding, `F10` session binding, `F11` revocation binding, `F12` policy binding, `F13` policy allowed, `F14` verified binding, `F15` verified allowed, `F16` outcome decision, `F17` outcome reason | Make exactly one field externally or crate visible. | Per-field structural assertion plus corresponding compile-fail block |
| Public construction (8) | `K01` challenge, `K02` freshness, `K03` identity, `K04` evidence, `K05` session, `K06` revocation, `K07` policy, `K08` verified | Add one public constructor/factory. | Corresponding external construction compile-fail block |
| Diagnostics (15) | `D01` flow, `D02` binding, `D03` challenge, `D04` freshness, `D05` identity, `D06` evidence, `D07` session, `D08` revocation, `D09` policy, `D10` verified, `D11` transition error Display, `D12` request, `D13` evidence bundle, `D14` transition error Debug, `D15` outcome Debug | Expose a real private sentinel/address/count/payload through exactly one default formatting surface. A harmless label-only change is not acceptable mutation evidence. | Exact per-phase sentinel diagnostic privacy tests over every Debug/Display surface |

The count is `9 + 8 + 3 + 3 + 7 + 1 + 7 + 6 + 9 + 17 + 8 + 15 = 93`.
Each probe runs in a disposable worktree at one frozen head and must fail its
named assertion or compiler boundary. A nonzero command that executes zero
tests, fails syntax, or stops on an unrelated compiler error is not mutation
evidence. M1-010 adds no parser or fuzzer because it adds no untrusted byte or
wire surface; the finite typed action domain is exhausted directly.

### Security-scanning regressions

Repository-owned security fixtures must remove a reported dataflow at its
shared source/sink boundary rather than only editing the line selected by one
pull-request scan. Freshness challenge builders accept scalar synthetic seeds,
construct one typed nonce through the reviewed per-index transformation, and
do not accept raw repeated-byte arrays. The complete 256-seed domain proves
determinism and pairwise distinction while the existing replay tests preserve
same-seed and different-seed behavior.

A green pull-request delta scan is not closure for a confirmed shared fixture
pattern. The correction must also pass the full default-branch CodeQL scan with
no next equivalent alert, and no alert may be dismissed or excluded to obtain
that result. This scanner-only fixture issue accepts no new runtime or protocol
threat, so the threat-to-test rule does not require a new attack-lab scenario.
Its process-quality failures instead map to the issue, finite regression, full
repository checks, independent review, and this durable rule. Any scanner
finding that does represent an accepted threat still requires the complete
scenario/owner/profile/residual-risk mapping.

### Integration tests

- mock attester -> verifier -> permit;
- software TPM -> quote -> verifier;
- hardware TPM -> quote -> verifier;
- Proton sample client -> portal -> agent;
- measured boot evidence replay;
- session-key proof of possession;
- renewal and expiry;
- revocation propagation;
- challenge first/repeat claim, same-key changed context, and cross-publisher
  nonce independence;
- replay-state restart, rollback, missing/corrupt/unavailable failure,
  poisoned availability/state locks, rejected-future observation persistence,
  capacity/rate limits, exact-expiry GC, rate-history GC propagated to handles
  opened before deletion, complete leaf/aggregate diagnostic redaction,
  simultaneous atomic claims, and raw-claim capability exclusion.

### Bare-metal tests

- accepted and unaccepted UKI/kernel profiles;
- Secure Boot enabled/disabled;
- hardware TPM, firmware TPM, vTPM, and no TPM;
- firmware and kernel updates;
- module-signing and lockdown variations;
- file and process races;
- supported GPU/runtime variations where relevant.

## Attack scenario format

Every security claim receives a scenario under `lab/scenarios/`:

```json
{
  "id": "OGIR-PROTOCOL-REPLAY-001",
  "title": "Reuse a permit in another match",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["protected_session_authorization"],
  "preconditions": ["a valid permit exists for match-A"],
  "steps": ["submit the permit to match-B"],
  "expected": {
    "decision": "deny",
    "reason": "session-binding-mismatch",
    "automatic_ban": false
  },
  "invariants": ["permit match binding is exact"],
  "residual_risk": ["full-session relay requires a separate scenario"]
}
```

Challenge replay, concurrent claim, freshness-state failure, capacity
exhaustion, and freshness-state privacy are represented by
`OGIR-PROTOCOL-REPLAY-002`, `OGIR-PROTOCOL-FRESHNESS-RACE-001`,
`OGIR-PROTOCOL-FRESHNESS-001`, `OGIR-PROTOCOL-FRESHNESS-CAPACITY-001`, and
`OGIR-PRIVACY-FRESHNESS-001`. They preserve publisher-authoritative time,
atomic single-use nonce, live-record retention, bounded state, and redacted
diagnostics without turning failure into disciplinary evidence.
Local-session gate skipping, cross-session capability substitution, and
terminal reactivation or stranded cleanup are represented by
`OGIR-SESSION-GATE-SKIP-001`,
`OGIR-SESSION-CAPABILITY-SUBSTITUTION-001`, and
`OGIR-SESSION-TERMINAL-CLEANUP-001`. These scenarios exercise only the pure
lifecycle contract; trusted production adapters and actual idempotent cleanup
I/O remain future coverage.
Verifier gate skipping, equal-request capability substitution, terminal
immutability, unknown mandatory gates, and diagnostic disclosure are represented
by `OGIR-VERIFIER-GATE-SKIP-001`,
`OGIR-VERIFIER-CAPABILITY-SUBSTITUTION-001`,
`OGIR-VERIFIER-TERMINAL-IMMUTABILITY-001`,
`OGIR-VERIFIER-UNKNOWN-GATE-001`, and
`OGIR-PRIVACY-VERIFIER-DIAGNOSTICS-001`. These scenarios cover only the pure
appraisal graph; trusted gate producers, signed results, permits, networking,
and persistence remain future coverage.
Scenarios use one duplicate-free JSON document per `*.scenario.json` file. The
aggregate dependency-free validator rejects duplicate keys, extra documents,
unknown fields, unsupported schema keywords, and every schema violation. Its
self-tests pin owner/assurance omissions, parser-bypass regressions, non-JSON
constants, terminal-newline mappings, schema-dialect drift, nested unknown
fields, every resource-limit branch, scenario-directory symlinks, unapproved
backtracking/repetition patterns, and context-free parse/duplicate/I/O/schema/
instance diagnostics, including newline/escape/CI-command injection through a
scenario filename. Cross-file checks also reject duplicate scenario IDs and
unregistered owner/profile values.

## Release gates by maturity

### Scaffold

- formatting;
- Clippy;
- unit tests;
- documentation build;
- attack-scenario owner/assurance traceability;
- dependency and license policy.

### End-to-end prototype

Adds:

- parser fuzz targets;
- replay and binding property tests;
- software-TPM integration;
- protocol conformance corpus;
- sanitizer coverage for C boundaries.

### Hardware alpha

Adds:

- hardware-TPM matrix;
- measured-boot replay tests;
- power interruption and TPM resource-pressure tests;
- process identity and PID-reuse stress;
- fault injection and daemon restart tests.

### Protected-session alpha

Adds:

- same-user memory-access attack corpus;
- cgroup migration and namespace races;
- debugger, perf, uprobe, and BPF attachment attempts;
- policy cleanup verification;
- unrelated-process noninterference tests.

### Production candidate

Adds:

- independent audit;
- white-box and black-box red team;
- supply-chain compromise exercises;
- key rotation and revocation drills;
- reproducible-build verification by independent builders;
- public conformance suite;
- private then public bug bounty.

## Mandatory failure behavior

A test failure cannot be resolved by weakening the invariant, skipping the test, broadening an allowlist, or suppressing a warning without a reviewed explanation and threat-model update.
