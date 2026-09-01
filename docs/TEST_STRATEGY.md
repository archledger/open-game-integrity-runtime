# Test and attack-simulation strategy

## Test pyramid

### Unit tests

Pure domain invariants, length checks, state transitions, policy evaluation,
redaction, expiry, identifier validation, and fail-closed behavior. Challenge
freshness includes checked window construction and literal before/exact issue,
last-second, exact/after expiry, excessive lifetime, and near-`u64::MAX`
boundaries.

#### Session public-key lookup handle

M1-007F runs seven dedicated runtime/structural tests. Six value/privacy tests
cover exact 32-byte round trip, all-zero/all-`0xff`/alternating/ascending/
descending controls, copy/equality/inequality/hash behavior, a non-vacuous
private diagnostic sentinel, and runtime type distinction from `Nonce` and
`SessionId`. The finite matrix executes exactly 32 positions × 256 byte values
= 8,192 cases without normalization or rejection. A CRLF-normalized structural
test pins the exact private tuple field, derive list, two public methods, fixed
Debug implementation, and absence of convenience or authority interfaces.

One positive rustdoc and eighteen separate compile-fail doctests added by this
slice cover direct field construction, 31/33-byte arrays, `Nonce`/`SessionId`
substitution, `Default`, `Display`, string parsing, implicit array conversion,
`AsRef`, mutable access, serialization, validity, decision conversion, and
independent verified-attestation, validated-permit, proof-of-possession, and
admission shortcuts.
Each block imports a real public type before its one intended failure.

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

Historical M1-010 verifier-flow evidence exhausts 14 phases × 13 actions = 182
pairs against its independent literal model: exactly 48 succeeded and 134
rejected unchanged. That evidence describes the M1-010 action domain before
phase-eligible M1-011 result emission.

M1-011 re-freezes the current domain at 14 phases × 24 semantic actions = 336
pairs. The independent model contains 9 successful gate/completion edges and 41
phase-eligible failure edges, for exactly `41 + 9 = 50` successes and 286
state-preserving rejections. The fifteen failure observations across eight
active phases contain exactly 41 eligible and 79 ineligible cells. Every
successful failure action compares the direct typed result's exact context,
decision, reason, and view; every rejection compares the complete unchanged
active state. All six terminals reject all 24 actions.

Seven gate omissions and all 7! = 5,040 orderings prove that only one canonical
order can reach `PolicySatisfied`. All seven capabilities reject equal cloned
request data from a different flow through allocation identity. Full and
restricted tests inspect exact result context, profile, key handle, and allowed
class; flow outcome alone is not used as a proxy for authority payload
correctness. Correct binding proves association with the flow, not
cryptographic payload provenance.

M1-011 retains all 5,040 gate permutations, seven omissions, seven equal-data
capability substitutions, and phase-before-binding checks. The fixed schedule
is exactly `256 + 864 + 576 + 35 + 312 + 5 = 2,048` actions; another 1,046,528
fixed-seed actions exercise arbitrary histories, for exactly 1,048,576 checked
actions. Coverage updates only after exact result and complete state equality.
A new flow is test setup after terminal entry and is not counted as one of the
24 semantic actions.

The frozen M1-011 mutation inventory contains exactly 154 one-cause probes for
mapping, phase eligibility, claim transfer/discard, authority fields, terminal
replacement, one-use paths, and diagnostic redaction. The initial Task 10
campaign ran all 154 rows, but complete raw failure-cause review invalidated
`R03`-`R06`, `A08`, and `A17`. Generic macro-inventory checks rejected syntax
introduced by `R03`-`R06` and `A17` before their declared detectors ran, while
`A08` failed crate compilation before rustdoc because its supporting payload
type remained private. That archive therefore supports 148 intended-cause
kills. Correction requires redesigned compiling mutants and
a complete restart from E01 at the first documentation-correction head; only a
154-row audit with 154 intended-cause kills, zero collateral/invalid/surviving
rows, and 154 cleanup records closes the campaign.

The current verifier documentation suite contains one ordinary public
compile-pass and 70 single-cause compile-fail doctests. Structural tests cover
every inventoried authority-bearing type/field, result construction, raw-claim
exclusion, and report/capability substitution. Exact diagnostic tests cover the
request, flow, all gates, binding, errors, outcomes, completed capability,
`AppraisalResult`, `AppraisalResultView`, `AcceptedClaims`, and direct
`EvidenceBundle` formatting. Every phase uses distinct private sentinels; fixed
redaction markers are exact, and semantic values, allocation details, paths,
control text, and decimal private values are forbidden.

Test-only `Weak<AttemptRecord>` probes verify physical ownership: failures
release the attempt allocation before returning while the terminal flow remains
alive; success leaves it owned only by `VerifiedAttestation` and releases it on
conversion. Physical mutations remove the failure release and restore a success
clone to prove both tests fail for retained strong ownership.

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

The M1-007F minimum mutation contract is expanded to 19 isolated probes so no
combined convenience-interface or diagnostic mutation can mask another:

| Group | Probe IDs | Exact mutation | Required detector |
| --- | --- | --- | --- |
| Width (2) | `L01`, `L02` | Change the public length constant to 31 or 33. | Exact constant/runtime compile contract |
| Field privacy (1) | `F01` | Make the tuple field public. | Structural test plus private-constructor doctest |
| Byte preservation (2) | `A01`, `A02` | Normalize one constructor byte; return a promoted zero array from `as_bytes`. | Round-trip and 8,192-case matrix |
| Diagnostics (2) | `D01`, `D02` | Format all raw bytes; append one real byte to the redaction marker. | Exact sentinel Debug tests and matrix |
| Convenience interfaces (6) | `T01`-`T06` | Add `Default`, `Display`, `From<[u8; 32]>`, `FromStr`, `AsRef<[u8; 32]>`, or `serialize`. | Matching single-cause doctest plus structural test |
| Authority shortcuts (5) | `K01`-`K05` | Add `is_valid`, `verified_attestation`, `validated_permit`, `proof_of_possession`, or `admit`. | Matching single-cause doctest plus structural test |
| Type distinction (1) | `N01` | Replace the newtype with a `Nonce` alias while preserving compilation. | TypeId, Debug, and structural tests |

Every probe runs from one frozen exact head in a disposable worktree, executes
the named detector, and fails for the intended cause. Syntax failure, zero-test
success, an unrelated compiler failure, or a grouped mutation is not evidence.
No parser fuzz target or attack scenario is added because this type accepts one
compile-time fixed array and implements no runtime threat control.

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

## Evidence-binding transcript validation

This section defines future semantic validation, not implemented runtime tests.
It selects no transcript representation, bytes, cryptographic mechanism,
algorithm, literal domain-separation label, or proof format.

### Positive reconstruction

| Case | Required semantic result |
| --- | --- |
| Initial appraisal | Independently constructed attester and verifier semantics match for the complete fresh challenge, registered profile, actual-key and `SessionPublicKeyId` association, evidence time, exact claims, and provenance. |
| Same-session renewal | A new Evidence-binding transcript uses a fresh complete challenge, current claims, and a new evidence-time value accepted under the future evidence-time authority. The same actual key and `SessionPublicKeyId` may repeat only when the publisher, protected `SessionId`, and live subject are unchanged; renewal belongs to the existing session lifecycle; policy is not silently weakened; current claims describe current live state; and the future evidence-time authority accepts the new evidence. A new publisher or protected session requires a new key and handle. Profile identity and exact selected-policy identity need not remain unchanged. The purpose remains fixed to OGIR evidence binding; renewal authorization is separate. |
| Profile with only Base claims | The profile requires and reconstructs exactly all eight Base claims and no profile-specific claim. |
| Profile with additional registered claims | The profile requires all eight Base claims plus only its declared subset of attestation identity and runtime measurement identity. |
| Hardware-certified provenance | A claim registered as `hardware-certified` is reconstructed exactly once under that provenance class. |
| Measured-log-derived provenance | A claim registered as `measured-log-derived` is reconstructed exactly once under that provenance class. |
| Trusted-agent-observed provenance | A claim registered as `trusted-agent-observed` is reconstructed exactly once under that provenance class. |

### Single-change negative matrix

Each row starts from one valid semantic fixture and changes only the named leaf
or relationship.

| Mutation | Expected result |
| --- | --- |
| Change one `PublisherChallenge` field | reject before successful appraisal. |
| Change `ProtocolVersion` | reject before successful appraisal. |
| Change `EvidenceProfile` | reject before successful appraisal. |
| Omit one required claim | reject before successful appraisal. |
| Duplicate one claim meaning | reject before successful appraisal. |
| Inject one undeclared claim | reject before successful appraisal. |
| Alias one meaning under two names | reject before successful appraisal. |
| claim-provenance substitution: change one claim's provenance class | reject before successful appraisal. |
| Change Attesting agent identity semantic value | reject before successful appraisal. |
| Change Platform identity semantic value | reject before successful appraisal. |
| Change Boot measurement identity semantic value | reject before successful appraisal. |
| Change Runtime manifest identity semantic value | reject before successful appraisal. |
| Change Game manifest identity semantic value | reject before successful appraisal. |
| Change Process binding identity semantic value | reject before successful appraisal. |
| Change Protected-session identity semantic value | reject before successful appraisal. |
| Change Enforcement policy state semantic value | reject before successful appraisal. |
| Change Attestation identity semantic value under a profile that declares it | reject before successful appraisal. |
| Change Runtime measurement identity semantic value under a profile that declares it | reject before successful appraisal. |
| Change actual session public key | reject before successful appraisal. |
| Change `SessionPublicKeyId` | reject before successful appraisal. |
| Change only the actual-key-to-handle association | reject before successful appraisal. |
| Change protected-session subject | reject before successful appraisal. |
| Change publisher | reject before successful appraisal. |
| Change manifest identity namespace | reject before successful appraisal. |
| Change manifest identity algorithm | reject before successful appraisal. |
| Change manifest identity value | reject before successful appraisal. |
| Change evidence-time producer/source | reject before successful appraisal. |
| Change evidence-time clock/epoch | reject before successful appraisal. |
| Change evidence-time creation value | reject before successful appraisal. |
| Change evidence validity semantics | reject before successful appraisal. |
| Reuse for another account/game/match/policy/session | reject before successful appraisal. |
| Reuse for another build | reject before successful appraisal. |
| Reuse initial evidence as renewal authorization | reject before successful appraisal. |
| Reuse prior renewal evidence for a fresh challenge | reject before successful appraisal. |
| Reuse the same actual key and `SessionPublicKeyId` after the publisher changes | reject before successful appraisal. |
| Reuse the same actual key and `SessionPublicKeyId` after the protected `SessionId` changes | reject before successful appraisal. |
| Reuse the same actual key and `SessionPublicKeyId` after the live subject changes | reject before successful appraisal. |
| Reuse the same actual key and `SessionPublicKeyId` outside the existing session lifecycle, including after terminal end or invalidation | reject before successful appraisal. |
| Reuse the same actual key and `SessionPublicKeyId` while silently weakening policy | reject before successful appraisal. |
| Reuse the same actual key and `SessionPublicKeyId` when current claims do not describe current live state | reject before successful appraisal. |
| Reuse evidence binding as protected Attestation Result integrity | reject before successful appraisal. |
| Reuse evidence binding as permit authorization | reject before successful appraisal. |
| Reuse evidence binding as session proof of possession | reject before successful appraisal. |
| Reuse evidence binding as renewal authorization | reject before successful appraisal. |
| Duplicate one semantically set-valued element | reject before successful appraisal. |
| Add one unknown critical semantic | reject before successful appraisal. |
| Use a known claim under a profile that did not declare it | reject before successful appraisal. |
| Accept the complete `EvidenceBundle` payload as a transcript input | reject before successful appraisal. |
| Accept an attester-supplied transcript without independent reconstruction | reject before successful appraisal. |
| Accept only `EvidenceProfile` without the evidence instance claims | reject before successful appraisal. |
| Use rolled-back evidence time | design-blocking until the evidence-time authority defines accepted temporal behavior; no runtime acceptance case is authorized. |
| Reuse or substitute evidence across a trusted evidence-producer restart | design-blocking until the evidence-time authority defines restart behavior; no runtime acceptance case is authorized. |
| Reuse or substitute evidence across a protected-session restart | design-blocking until the evidence-time authority defines restart behavior; no runtime acceptance case is authorized. |
| Reuse the same actual key and `SessionPublicKeyId` without acceptance of the new evidence under the future evidence-time authority | design-blocking until the evidence-time authority defines renewal acceptance; no runtime accepted-time behavior is authorized. |

These expected results preserve the existing M1-011 coarse, non-disciplinary
failure mappings. M1-012 adds no failure code, runtime validator, or permissive
fallback.

The generic `EvidenceProfile`, challenge-field, and policy mutation rows compare
one candidate transcript with its independently reconstructed expected current
transcript. They do not require a renewal to retain the prior profile identity
or exact selected-policy identity.

### Shape and domain exclusions

| Boundary | Required assertion |
| --- | --- |
| Evidence carrier | The whole `EvidenceBundle` is not a transcript semantic; it externally carries claims and proof material. |
| Independent context | `ExpectedContext` is not transcript evidence and is never copied from candidate claims. |
| Diagnostic exclusion | Ordinary diagnostics exclude all `ExpectedContext` values, all complete challenge-context values, all publisher/build/account/game/match/policy bindings, and all protected-session context values, as well as all transcript and proof material. |
| Appraisal and protected result | `Decision`, `ReasonCode`, `VerificationOutcome`, `VerifiedAttestation`, `AcceptedClaims`, `AppraisalResult`, and protected-result identity, validity, commitment, and integrity are excluded. |
| Permit and proof of possession | Permit contents and validity plus proof-of-possession challenges and responses are excluded and remain separate domains. |
| Time authority | Verifier evaluation time, challenge issuance or expiry time, future protected-result validity, and placeholders do not replace evidence creation or validity time. The unresolved evidence-time authority remains a blocker. |
| Key material | Private session keys are excluded; only the actual public key and its `SessionPublicKeyId` association are transcript semantics. |
| Semantic identity | Raw digest bytes or a marker cannot replace a semantic manifest or measurement identity. |
| Representation and mechanism | Literal byte, canonical representation, algorithm, domain-label, and proof-coverage expectations cannot be tested until M2 selects them. |

The future property strategy keeps three assertions independent so one stage
cannot mask another:

1. Independently reconstruct the verifier transcript and assert exact semantic
   equality with the valid attester transcript before coverage or appraisal.
2. Mutate exactly one semantic leaf, assert reconstruction inequality, and
   require profile proof-coverage rejection for every mutation without using an
   appraisal result as the coverage oracle.
3. Separately appraise claim values and provenance on coverage-valid fixtures,
   including fixtures whose covered claim or provenance is unacceptable, so
   coverage success cannot substitute for appraisal.

A separate generated-claim-set strategy enforces the exact eight Base plus two
profile-specific vocabulary: isolated value binding for every required meaning,
required membership, no undeclared members, and exactly-once meanings.
Membership and shape assertions remain separate from value mutations. These are
future executable strategies; no runtime test or validator is implemented by
M1-012. Evidence-time rollback and restart cases remain design-blocking and do
not define accepted temporal behavior.

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
Privacy/redaction tests must not repeat the value under test in their own
failure diagnostics. Exact comparisons and forbidden-value checks use boolean
assertions with fixed generic messages rather than `assert_eq!` or interpolated
panic text, because Rust equality assertions print unequal operands. CodeQL
`rust/cleartext-logging` remains the sink-model regression gate; do not dismiss
or suppress a repository-controlled finding when the test assertion can be made
non-disclosing.
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
