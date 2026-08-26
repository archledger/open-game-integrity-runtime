# ADR-0007: Attempt-bound fail-closed verifier flow

- Status: Accepted
- Date: 2026-08-26
- Owners: Initial maintainer
- Related issues: [M1-010](../../planning/issues/010-verifier-state-machine.md)
- Supersedes: None
- Superseded by: None

## Context

The research verifier previously exposed constructible `VerificationOutcome`
fields while its implemented freshness/context scaffold represented progress
only implicitly. A report containing `Decision::Allow` is not proof that the
publisher challenge, freshness, identity, evidence, live session, revocation,
and policy gates all completed for one exact attempt.

Those seven future validation results arrive dynamically, so a verifier must
represent invalid orderings and reject them deterministically. Equal request
values must still identify distinct attempts, failure must become permanent,
and tests must be able to inspect public phase/report state without gaining
authority. Signed results, permits, relying-party admission, and every real
validation adapter remain outside M1-010.

## Decision drivers

- `Decision`, `ReasonCode`, and `VerificationOutcome` must never carry
  appraisal authority.
- Both full and restricted success require all seven gates in the same order;
  restricted success is not fallback after full-policy failure.
- Capabilities must bind to one exact in-process attempt without adding a
  random identifier, hash, or counter.
- The finite graph must support exhaustive state/action, ordering,
  substitution, and non-vacuous long-history proofs.
- Raw request retention must end at terminals and default diagnostics must
  reveal no request, evidence, timing, or allocation identity.
- The pure model must add no dependency, I/O, `unsafe`, parser, serializer, or
  cryptographic choice.

## Options considered

### Checked private runtime graph

Selected. One private discriminated state supports dynamic orchestration while
making every allowed edge, invalid edge, and terminal action observable to an
independent finite oracle. Public phase and report views remain read-only.

### Pure typestate API

Rejected for this slice. Typestate makes many invalid actions unnameable, but
runtime gate results arrive dynamically and M1-010 requires exhaustive testing
of every invalid action and arbitrary action history. An erased runtime graph
would still be required.

### Parallel typestate and runtime APIs

Rejected. Two authoritative graphs could drift and would enlarge the trusted
review surface without improving the dynamic contract.

### Monolithic `verify()` success path

Rejected. Hiding every gate inside one call would make dynamic failure
terminals, cross-attempt substitution, phase-first rejection, and exhaustive
action-history testing materially harder to represent and audit.

### Public or unbound capabilities

Rejected. Public constructors would let callers assert validation work they
did not perform. Unbound capabilities could advance an unrelated flow.

### Value, random, hash, or counter attempt identity

Rejected. Request equality intentionally does not identify an attempt, random
identity would add a generator/failure surface, hashes add collision and input
selection questions, and counters add global state. One unique `Arc`
allocation already gives the required process-local identity.

### Serializable or restart-durable capabilities

Deferred. Persistence would require a separately authenticated durable format,
anti-rollback semantics, keying, migration, retention, and recovery policy.

### Report-only Allow as authority

Rejected. A copyable reporting enum or outcome object cannot substitute for a
non-cloneable proof emitted only after the complete graph.

## Decision

The exact success graph is:

```text
EvidenceReceived
 -> ChallengeAuthenticated
 -> FreshnessChecked
 -> IdentityChecked
 -> EvidenceAppraised
 -> SessionBound
 -> RevocationChecked
 -> PolicySatisfied
 -> Verified
```

Every nonterminal may instead enter `Malformed`, `Unsupported`, `Retryable`,
`Denied`, or `Revoked`. Those five failure states and `Verified` are permanent.
Each ordinary transition checks the exact required phase, then the capability
binding, and mutates only after both checks succeed.

One `VerifierFlow` owns one request and one `VerificationBinding`. That binding
contains a unique standard-library `Arc<AttemptRecord>` allocation and the
redacted `ReplayRegistration`. Gate capabilities carry a clone of the private
binding; `Arc::ptr_eq` compares allocation identity, so equal cloned request
data in another flow cannot satisfy a gate.

Only `PolicySatisfied -> Verified` returns one non-cloneable,
non-`Copy` `VerifiedAttestation`. It carries only the attempt binding and the
privately selected full or restricted allowed class. `Decision`, `ReasonCode`,
and `VerificationOutcome` remain copyable reporting views with private fields
and cannot be converted into the capability. Full and restricted policies use
the same seven gates; restricted is selected by a satisfied policy, never by a
failed full-policy path.

The flow owns the raw request only while nonterminal. Successful completion or
any failure terminal releases that ownership while retaining the minimal
binding and outcome state. M1-010 makes no secure-memory-erasure claim.

No production gate producer is added. Future trusted validation adapters must
perform their real operation before constructing the corresponding capability.
The existing research scaffold uses the raw irreversible freshness claim and
does not mint `FreshnessChecked`. `EvidenceBundle` uses the fixed diagnostic
`EvidenceBundle([REDACTED])` rather than derived field formatting.

M1-010 does not define or implement signatures, verified claim contents,
evidence validation, identity validation, session-key proof, revocation data,
policy evaluation, signed result construction, permits, admission, networking,
persistence, or restart recovery.

## Consequences

Gate reordering, omission, cross-flow substitution, early completion, terminal
reclassification, and double completion fail deterministically without state
or request mutation. One successful attempt produces at most one
`VerifiedAttestation`, and report-only values cannot fabricate another.

Allocation identity is deliberately process-local, nonserializable, and not
restart-durable. The final capability currently proves graph completion, not a
set of typed verified claims. Future result work must add those claims under
the same binding and consume the capability so raw request fields cannot be
refilled into an unrelated signed result.

A trusted gate producer remains part of the verifier trusted computing base. A
deliberately compromised producer can lie about its own validation work; the
pure graph prevents external/API misuse and accidental orchestration errors but
cannot make compromised trusted code honest.

## Threat-model impact

The decision narrows A1 hostile-request and same-user API misuse against
`protected_session_authorization` and `verifier_freshness_state`. It also makes
accidental trusted orchestration bugs observable through explicit phase,
binding, terminal, and mapping failures. Unknown mandatory gates terminate
`Unsupported`; no failure grants fallback authorization or becomes automatic
cheating evidence.

Deliberate compromise of a trusted gate producer, policy service, verifier, or
online verifier key remains A5 risk. The new boundaries do not address a
malicious verifier that fabricates its own trusted inputs.

## Privacy impact

The exact request remains owned only during the eight nonterminal phases and is
released at all six terminals. The attempt binding retains a redacted replay
registration until the flow and final capability are dropped. This is a finite
ownership/retention rule, not an allocator-zeroization guarantee.

Default diagnostics for the request, flow, all seven capabilities, binding,
errors, outcomes, final capability, and `EvidenceBundle` are fixed redaction
markers or approved fieldless enums. They expose no identifier, nonce, time,
evidence payload, home path, control text, pointer address, reference count, or
allocation identity. Explicit value access inside trusted functional code is
not an approved diagnostic sink.

## Dependency and license impact

The implementation adds only `std::sync::Arc`; it introduces no package,
transitive dependency, parser, serializer, cryptographic primitive, I/O,
network, persistence, or `unsafe` boundary. Existing Apache-2.0 source and
documentation boundaries are unchanged.

## Validation

Completed executable evidence compares 14 phases × 13 actions = 182 pairs
against an independent literal model, with exactly 48 successes and 134
state-preserving rejections. Seven omissions and all 7! = 5,040 gate orderings
admit exactly one canonical ordering. All seven capability types reject equal
request data from another flow, and a 14 × 7 matrix proves phase checks precede
binding checks. Full and restricted completion tests inspect the returned
capability's exact allocation identity and allowed class rather than inferring
them from the flow report.

The fixed history executes exactly 1,048,576 actions: 2,048 scheduled actions
cover both allowed classes, all failure/reason classes, every matching and
mismatched gate, every terminal/action pair, and unknown-gate mapping;
1,046,528 fixed-seed actions exercise arbitrary histories. Coverage counters
are incremented only after actual results match the independent oracle and are
required to be non-vacuous.

One public-surface compile-pass and 39 single-cause compile-fail doctests cover
construction, cloning, private fields, report construction/substitution,
nonexistent authority shortcuts, and raw-claim exclusion. A CRLF-only-
normalized structural test pins all 17 authority/report fields. Exact private
sentinels cover every diagnostic surface in every phase, including manual
transition-error Debug and exact outcome Debug; request presence is checked in
all 14 phases. A typed unknown-mandatory-gate observation is exercised
separately from ordinary version/profile unsupported state. Five verifier
scenarios are part of the 14-scenario validated aggregate.

Completion of M1-010 additionally requires the exact 93 disposable-worktree
mutations and separate fresh trusted-computing-base and privacy reviews. Those
Task 10 gates are required validation and are not claimed complete by this ADR.

## Rollback

Disabling protected mode is safe. Any change to the graph, binding identity,
authority type, outcome mapping, request retention, or privacy boundary
requires an ADR update or superseding ADR plus matching code, migration,
mutation, architecture, threat, and privacy tests.

Bypassing a gate, treating a report as authority, restoring public/unbound
capability construction, or restoring raw diagnostic output is not an
acceptable rollback.

## Primary sources

- The [approved M1-010 design](../superpowers/specs/2026-08-26-m1-010-verifier-state-machine-design.md)
  defines the project-specific graph, authority, privacy, and proof boundary.
- The project [security invariants](../SECURITY_INVARIANTS.md),
  [architecture](../ARCHITECTURE.md), [roadmap](../ROADMAP.md), and
  [threat model](../THREAT_MODEL.md) define authorization, freshness, privacy,
  failure, and residual-risk requirements.
- [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html) defines the IETF RATS
  appraisal/result role separation used by the broader architecture.
- [Rust 1.98 visibility and privacy](https://doc.rust-lang.org/1.98.0/reference/visibility-and-privacy.html)
  defines the private-field boundary.
- [Rust 1.98 `Arc::ptr_eq`](https://doc.rust-lang.org/1.98.0/std/sync/struct.Arc.html#method.ptr_eq)
  defines allocation-identity comparison.
- [Rust 1.98 ownership](https://doc.rust-lang.org/1.98.0/book/ch04-01-what-is-ownership.html)
  defines the by-value moves used for non-cloneable capabilities.
- The [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) inform
  the explicit public types, private invariants, and documentation contract.
