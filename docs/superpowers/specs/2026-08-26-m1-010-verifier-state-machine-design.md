# M1-010 fail-closed verifier state-machine design

- Status: Approved for implementation planning
- Date: 2026-08-26
- Related issue: [M1-010](../../../planning/issues/010-verifier-state-machine.md)
- Decision owner: Initial maintainer

## Summary

OGIR will model one publisher-verifier attempt as a non-cloneable checked
runtime state machine in `ogir-verifier`. The machine owns the exact
`VerificationRequest` while active, exposes only safe redacted phase and
reporting views, and accepts seven opaque non-cloneable gate capabilities bound
to one exact in-process attempt. Only the canonical completed path returns one
opaque `VerifiedAttestation` capability. A report-only `Decision` or
`VerificationOutcome` is never authority and cannot replace that capability.

The success graph is:

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

Every nonterminal phase may instead enter one of five immutable failure
terminals: `Malformed`, `Unsupported`, `Retryable`, `Denied`, or `Revoked`.
Every terminal rejects every later action. Renewal is a new verification
attempt using a fresh challenge; permit issuance, serialization, signing, and
admission remain later work.

M1-010 implements ordering, capability ownership, failure classification,
outcome privacy, and proof evidence only. It deliberately ships no publisher
signature validator, evidence appraiser, identity enrollment, session-key
validator, revocation backend, policy evaluator, attestation-result signer, or
permit adapter. Those operations may later mint their gate capability inside
the trusted verifier crate only after the real operation succeeds.

## Approval record

On 2026-08-26, the decision owner approved, in sequence:

- a non-forgeable non-cloneable `VerifiedAttestation` as the authority-bearing
  success value while `Decision` and `ReasonCode` remain reporting views;
- one checked private runtime graph instead of a consuming typestate pipeline
  or monolithic hidden verifier function;
- the exact eight-edge success graph and five immutable failure terminals;
- exact request ownership plus allocation-identity capability binding;
- typed valid decision/reason mappings, state-preserving errors, and fixed
  diagnostic redaction;
- the exhaustive matrix, permutation, omission, property, compile-fail,
  mutation, scenario, and independent-review proof strategy;
- direct `EvidenceBundle` diagnostic hardening discovered during inspection;
  and
- the module, documentation, worktree, review, DCO, and publication sequence.

The decision owner also authorized evidence-backed refinements inside this
approved issue and security scope. Any refinement that changes authority,
trust boundaries, scope, dependencies, cryptography, I/O, GitHub publication,
or a human-only certification remains an explicit review point.

The decision owner reviewed exact written-spec commit
`3f3a1e3ab01f3b3f69af171acb8166bd4bce36e0` and explicitly approved it on
2026-08-26 with no requested change. This status follow-up records that human
review; it changes no approved design requirement and does not authorize
implementation, DCO certification, or publication.

## Security objective

The verifier must make it mechanically difficult to create an authoritative
success without every required gate for one exact request. Specifically:

- no client-controlled boolean, `Decision`, outcome field, or opaque evidence
  payload authorizes a protected mode;
- challenge authentication precedes freshness authority;
- freshness retains ADR-0005's time-observation, exact relying-party context,
  and irreversible atomic claim order;
- identity, evidence, session binding, revocation, and policy are distinct
  mandatory gates rather than mutable flags;
- each gate result belongs to one process-local attempt and cannot advance an
  equal-but-distinct attempt;
- terminal failure is non-disciplinary, state preserving, and irreversible;
  and
- successful appraisal produces a capability for future trusted result
  construction, not a local admission decision or signed permit.

This follows the RATS separation in RFC 9334: a verifier appraises evidence and
produces attestation results, while a relying party applies its own result
policy to make an application decision. M1-010 stops before constructing or
signing that attestation result.

## Non-goals

M1-010 does not:

- validate a publisher signature or select keys/algorithms;
- parse, authenticate, or appraise an evidence profile or TPM quote;
- enroll or validate an attestation identity;
- define a session public-key type or proof transcript;
- load revocation/reference/policy data or evaluate a policy language;
- define or sign an `AttestationResult` or permit;
- serialize or transmit a state, capability, result, or request;
- persist or restore a flow across process restart;
- add a clock, random-number generator, hash, crypto primitive, network,
  database, filesystem, async runtime, privileged operation, or dependency;
- implement renewal, permit expiry, or permit revocation lifecycle; or
- change the M1-009 local-session lifecycle/capability contract.

## Authority model

### Report versus authority

`Decision`, `ReasonCode`, and `VerificationOutcome` are safe reporting data.
They allow logging, metrics, tests, and later API mapping, but possession of an
allow-shaped report proves nothing. `VerificationOutcome` therefore has
private fields and read-only accessors, but it may remain `Clone`/`Copy`
because it carries no authority.

`VerifiedAttestation` is the authority-bearing value. It is opaque, has private
fields, implements neither `Clone` nor `Copy`, has no public constructor, and
is returned only by the final transition. Future trusted result construction
must consume it by value. M1-010 provides no such consumer and does not claim
that the capability is a signed result or an admission permit.

The M1-010 capability carries only the private attempt binding and allowed
class. It intentionally does not yet contain the evidence digest, accepted
claims, session public key, verifier identity, validity interval, or signature
needed by a real attestation result. A later reviewed result-model issue must
add typed verified claims under the same binding and consume the capability;
it may not refill result fields from an unrelated raw request.

### Trusted capability producers

The seven successful gate capabilities are:

1. `ChallengeAuthenticated`
2. `FreshnessChecked`
3. `IdentityChecked`
4. `EvidenceAppraised`
5. `SessionBound`
6. `RevocationChecked`
7. `PolicySatisfied`

Each is opaque, non-`Clone`, non-`Copy`, and bound to one flow. Future trusted
operations mint them only after their corresponding operation succeeds. M1-010
does not add a public `mark_passed(bool)`, generic gate constructor, builder,
trait implementable downstream, or unused production factory. Private child
tests may construct fixtures through module privacy. The existing implemented
freshness path remains trusted, but it cannot create a completed flow while
challenge authentication and later gate producers are absent.

A compromised crate-internal gate producer can still lie or bind the wrong
operation to a flow. That code is part of the publisher-verifier trusted
computing base and requires its own implementation review. This state machine
prevents external safe-Rust forgery, cross-flow substitution, skipped ordering,
and terminal re-entry; it does not defend against deliberately malicious code
inside its own crate.

## Attempt identity and request ownership

### Active request ownership

`VerifierFlow::begin(VerificationRequest)` takes ownership of one exact request
and starts in `EvidenceReceived`. Creating a flow is not authority; an external
caller still cannot construct any gate capability. Owning the request gives
future crate-internal validators one canonical input and avoids a separate
caller passing request A while asking to mint a capability for flow B.

The active request is private and absent from default diagnostics. On every
successful or failed terminal transition, the flow releases its request
ownership. Tests prove the private request slot is empty after each terminal.
This is a retention bound, not a claim that Rust's allocator overwrites freed
memory. Evidence remains privacy-sensitive, and secure erasure is neither
implemented nor claimed by this pure research model.

### Process-local binding

Each call to `begin` creates one private immutable attempt allocation behind
`std::sync::Arc`. That record retains the exact `ReplayRegistration` derived
from the request challenge. `VerificationBinding` is a private wrapper around
the shared allocation.

Every gate capability and `VerifiedAttestation` contains a private clone of
that wrapper. Matching uses `Arc::ptr_eq`, not inner-value equality. Therefore:

- a capability for flow A matches flow A;
- a separately begun flow B never matches, even if A and B use equal requests;
- a capability keeps its allocation alive until consumed or dropped, so an
  address cannot be reused while that capability exists; and
- no random ID, global counter, hash collision, secret, serialized token, or
  restart epoch is invented.

The retained `ReplayRegistration` connects the successful capability to the
publisher/nonce replay key, exact challenge binding, and window without copying
the full evidence payload into every capability. Its existing `Debug` contract
is redacted. The process-local allocation identity is deliberately not exposed,
serialized, persisted, logged, or treated as a protocol identifier.

## State model

### Public phase view

`VerificationPhase` is a public fieldless enum:

```text
EvidenceReceived
ChallengeAuthenticated
FreshnessChecked
IdentityChecked
EvidenceAppraised
SessionBound
RevocationChecked
PolicySatisfied
Verified
Malformed
Unsupported
Retryable
Denied
Revoked
```

The first eight phases are nonterminal. The final six phases are terminal.
`Verified` means the state machine completed and issued its one
`VerifiedAttestation`; it does not mean that a relying party admitted a game.

### Public action view

`VerificationAction` is a public fieldless enum:

```text
RecordChallengeAuthenticated
RecordFreshnessChecked
RecordIdentityChecked
RecordEvidenceAppraised
RecordSessionBound
RecordRevocationChecked
RecordPolicySatisfied
Complete
MarkMalformed
MarkUnsupported
MarkRetryable
Deny
MarkRevoked
```

These 14 phases and 13 actions form the exact finite matrix used by the
independent oracle.

### Success transitions

The only successful progression edges are:

| Current phase | Action/capability | Next phase |
| --- | --- | --- |
| `EvidenceReceived` | `ChallengeAuthenticated` | `ChallengeAuthenticated` |
| `ChallengeAuthenticated` | `FreshnessChecked` | `FreshnessChecked` |
| `FreshnessChecked` | `IdentityChecked` | `IdentityChecked` |
| `IdentityChecked` | `EvidenceAppraised` | `EvidenceAppraised` |
| `EvidenceAppraised` | `SessionBound` | `SessionBound` |
| `SessionBound` | `RevocationChecked` | `RevocationChecked` |
| `RevocationChecked` | `PolicySatisfied` | `PolicySatisfied` |
| `PolicySatisfied` | `complete()` | `Verified` |

`PolicySatisfied` privately carries `Full` or `Restricted`. Both require the
same preceding gates. Restricted success represents a separately selected and
satisfied relying-party policy; it is never an automatic downgrade or fallback
after full-policy failure. `complete()` atomically changes the flow to
`Verified`, releases the raw request, and returns one `VerifiedAttestation`
carrying the same private binding and allowed class. Calling it again rejects.

### Capability transition order

Every capability transition takes its capability by value and performs this
order:

1. inspect only the safe current phase;
2. reject an invalid phase without inspecting the private binding;
3. compare the capability and flow allocation identities;
4. return generic `CapabilityRejected` on mismatch; and
5. mutate only after phase and binding both succeed.

Because the value was moved into the method, it is consumed on success and on
rejection. Rejection preserves phase, terminal outcome, request ownership, and
all other flow state. Phase-before-binding keeps invalid-order behavior
deterministic and avoids turning the error taxonomy into a binding oracle.

### Failure transitions

Each of these actions is valid from every one of the eight nonterminal phases:

- `mark_malformed()`
- `mark_unsupported(UnsupportedRequirement)`
- `mark_retryable()`
- `deny(DenialReason)`
- `mark_revoked()`

A failure transition atomically records its immutable terminal class and safe
reason, releases the raw request, and never returns authority. Allowing an
external orchestrator to fail its own flow is safe: failure can reduce
availability but cannot grant protected-mode authority.

No failure or progression action succeeds from any terminal phase. A terminal
cannot change reason, switch class, re-enter progress, or issue a capability.
`UnsupportedRequirement` distinguishes a version/profile failure from a typed
`UnknownMandatoryGate` observation. Either maps to `Unsupported`; omission is
not a compatibility strategy.

## Outcome taxonomy

`DenialReason` is a public typed subset containing exactly:

```text
NotYetValid
Expired
ReplayDetected
SessionBindingMismatch
EvidenceInvalid
PolicyDenied
ProtectedSessionLost
```

The complete valid reporting map is:

| Terminal | `Decision` | `ReasonCode` |
| --- | --- | --- |
| `Verified(Full)` | `Allow` | `None` |
| `Verified(Restricted)` | `AllowRestricted` | `None` |
| `Malformed` | `Deny` | `Malformed` |
| `Unsupported` | `Unsupported` | `UnsupportedVersion` |
| `Retryable` | `Retry` | `AttestationUnavailable` |
| `Revoked` | `Deny` | `Revoked` |
| `Denied(NotYetValid)` | `Deny` | `NotYetValid` |
| `Denied(Expired)` | `Deny` | `Expired` |
| `Denied(ReplayDetected)` | `Deny` | `ReplayDetected` |
| `Denied(SessionBindingMismatch)` | `Deny` | `SessionBindingMismatch` |
| `Denied(EvidenceInvalid)` | `Deny` | `EvidenceInvalid` |
| `Denied(PolicyDenied)` | `Deny` | `PolicyDenied` |
| `Denied(ProtectedSessionLost)` | `Deny` | `ProtectedSessionLost` |

This covers all five existing decisions and all twelve existing reasons.
Contradictory pairs such as `Retry + PolicyDenied`, `Allow + Revoked`, or
`Deny + None` have no constructor. M1-011 may extend/refine public result and
reason taxonomy, but it must preserve this authority split and update this
design/ADR/tests before changing observable mappings.

`VerifierFlow::outcome()` returns `None` while active and a copy of the safe
reporting outcome after terminal entry. `VerificationOutcome` fields become
private; `decision()` and `reason()` are the only public reads. External code
can still construct a raw `Decision::Allow`, but no OGIR authority consumer may
accept it in place of `VerifiedAttestation`.

## Error and diagnostic contract

`TransitionError` contains only:

```rust
InvalidTransition {
    phase: VerificationPhase,
    action: VerificationAction,
}
CapabilityRejected {
    action: VerificationAction,
}
```

`InvalidTransition` reports only the safe public state/action view.
`CapabilityRejected` deliberately does not distinguish a different attempt,
wrong request, stale future capability, evidence mismatch, or another private
binding fault. `Display` messages are fixed and context-free.

Manual `Debug` implementations for `VerifierFlow`, `VerificationBinding`, all
gate capabilities, `VerifiedAttestation`, and transition errors expose only
type names, fixed redaction markers, and approved public enums. They never
include:

- publisher/game/build/account/match/policy/session identifiers;
- nonce bytes, issued/expiry/current time, or replay registration fields;
- evidence profile or payload;
- `Arc` address, reference count, pointer formatting, or allocation metadata;
- expected context or the owned request;
- caller-controlled strings, control characters, home paths, or CI annotation
  prefixes; or
- private full/restricted state before it becomes a safe reporting decision.

Inspection found a pre-existing adjacent gap: `EvidenceBundle` derives `Debug`,
which prints its `profile_id` and raw `payload`. M1-010 replaces that derived
implementation with fixed `EvidenceBundle([REDACTED])` formatting and adds a
non-vacuous sentinel test. `Clone` and equality behavior remain unchanged.

## Conceptual public API

The reviewed surface is conceptually:

```rust
pub struct VerifierFlow { /* private */ }
pub struct ChallengeAuthenticated { /* private */ }
pub struct FreshnessChecked { /* private */ }
pub struct IdentityChecked { /* private */ }
pub struct EvidenceAppraised { /* private */ }
pub struct SessionBound { /* private */ }
pub struct RevocationChecked { /* private */ }
pub struct PolicySatisfied { /* private */ }
pub struct VerifiedAttestation { /* private */ }

impl VerifierFlow {
    pub fn begin(request: VerificationRequest) -> Self;
    pub fn phase(&self) -> VerificationPhase;
    pub fn outcome(&self) -> Option<VerificationOutcome>;

    pub fn record_challenge_authenticated(
        &mut self,
        capability: ChallengeAuthenticated,
    ) -> Result<(), TransitionError>;
    pub fn record_freshness_checked(
        &mut self,
        capability: FreshnessChecked,
    ) -> Result<(), TransitionError>;
    pub fn record_identity_checked(
        &mut self,
        capability: IdentityChecked,
    ) -> Result<(), TransitionError>;
    pub fn record_evidence_appraised(
        &mut self,
        capability: EvidenceAppraised,
    ) -> Result<(), TransitionError>;
    pub fn record_session_bound(
        &mut self,
        capability: SessionBound,
    ) -> Result<(), TransitionError>;
    pub fn record_revocation_checked(
        &mut self,
        capability: RevocationChecked,
    ) -> Result<(), TransitionError>;
    pub fn record_policy_satisfied(
        &mut self,
        capability: PolicySatisfied,
    ) -> Result<(), TransitionError>;
    pub fn complete(&mut self) -> Result<VerifiedAttestation, TransitionError>;

    pub fn mark_malformed(&mut self) -> Result<(), TransitionError>;
    pub fn mark_unsupported(
        &mut self,
        requirement: UnsupportedRequirement,
    ) -> Result<(), TransitionError>;
    pub fn mark_retryable(&mut self) -> Result<(), TransitionError>;
    pub fn deny(&mut self, reason: DenialReason) -> Result<(), TransitionError>;
    pub fn mark_revoked(&mut self) -> Result<(), TransitionError>;
}

impl VerificationOutcome {
    pub const fn decision(self) -> Decision;
    pub const fn reason(self) -> ReasonCode;
}
```

This is a contract sketch, not implementation text. The implementation plan
may adjust names for established Rust style only if it updates this spec first
and preserves all approved semantics. No alternate authority-producing API is
permitted.

## Existing freshness and research scaffold

ADR-0005 remains authoritative. Freshness still performs:

1. durable publisher-authoritative time observation;
2. exact half-open window evaluation;
3. exact independently supplied publisher/game/build/account/match/policy
   comparison;
4. atomic irreversible replay claim; and
5. capability construction only inside the crate-confined checked path.

`FreshnessChecked` changes from a zero-sized private proof to an attempt-bound
capability. The public raw `FreshnessGuard::claim` remains incapable of
returning it. A checked producer must bind the capability to the same flow that
owns the exact request and can only be recorded after
`ChallengeAuthenticated`.

The public `verify_research_structure` entry point remains explicitly
fail-closed. It continues to preserve every M1-008 time/context/claim mapping
and never treats the opaque `EvidenceBundle` as appraised. M1-010 changes this
unauthenticated compatibility scaffold to use the public raw irreversible claim
operation, which returns no capability; it must not construct or transiently
hold `FreshnessChecked` before challenge authentication. Because signature,
identity, evidence, session, revocation, and policy producers are absent, no
production call path in M1-010 can create the bound freshness capability or
reach `VerifiedAttestation`. Tests may drive the complete graph only through
private module fixtures.

## Module boundaries

### `ogir-verifier::verification`

Owns:

- `ExpectedContext`, `VerificationRequest`, and private/redacted request use;
- `VerifierFlow`, private binding/attempt/state, phases, actions, terminal
  storage, and request release;
- six new gate capabilities (including `PolicySatisfied`) plus the existing
  now-bound `FreshnessChecked` and final `VerifiedAttestation`;
- `DenialReason`, `VerificationOutcome`, and `TransitionError`;
- exact transition and mapping logic; and
- unit, independent-model, permutation, ownership, privacy, and structural
  authority tests.

Existing top-level `ogir_verifier::...` imports remain stable through explicit
re-exports from `lib.rs`. Wildcard re-exports are not required.

### `ogir-verifier::freshness`

Continues to own replay identity, registration, store, guard, atomic claim, and
freshness errors. It upgrades `FreshnessChecked` to carry the private attempt
binding without exposing that binding or relaxing raw-claim exclusion. All
existing freshness/restart/race/capacity/privacy tests remain passing.

### `ogir-protocol`

Changes only `EvidenceBundle` diagnostic formatting and its focused privacy
test. The payload shape, ownership, equality, framing, and profile type do not
change. No parser or wire format is introduced.

### Other crates and future adapters

- `ogir-model` continues to own `Decision`, `ReasonCode`, identifiers, and
  freshness primitives. `DenialReason` stays verifier-specific so M1-010 does
  not preempt M1-011's broader domain-taxonomy work.
- `ogir-agent` and its local session machine do not change.
- applications gain no success adapter, permit, signer, network, or policy
  implementation.
- future trusted sibling verifier modules add crate-confined capability
  producers only alongside their real validators.

No new crate or dependency is added.

## Test design

### Exhaustive finite-state matrix

The model has 14 reachable phases and 13 actions, for 182 exact pairs.

Allowed pairs are:

- the seven capability progression edges;
- `complete` from `PolicySatisfied`; and
- five failure actions from each of eight nonterminal phases.

Exactly 48 pairs succeed. The remaining 134 return the expected
`InvalidTransition` and preserve phase, outcome, request-presence, and private
binding. Tests construct each reachable state through public transitions,
never by assigning production state directly. A separate literal model defines
expected behavior without calling production transition helpers.

Every terminal phase rejects all 13 actions. Both successful policy classes
reach `Verified`, return exactly one non-cloneable capability, release the
request, and report the correct safe outcome.

### Gate omission and permutation

Tests independently omit each of the seven capabilities and prove `complete`
cannot succeed. A dependency-free permutation generator enumerates all 7! =
5,040 capability orderings. Only the one canonical ordering may reach
`PolicySatisfied`; all 5,039 alternatives remain non-verified and preserve the
literal model after each attempted action.

### Attempt binding

For each of seven capability-bearing edges:

- a capability bound to the same flow succeeds exactly once;
- a capability from a different flow returns `CapabilityRejected`;
- two flows created from equal cloned requests still reject substitution;
- the target phase/outcome/request-presence state remains unchanged; and
- neither flow's binding, request, or sentinel appears in any diagnostic.

The substitution fixtures use equal cloned requests. Therefore, a production
regression from `Arc::ptr_eq` to replay-registration or request-value equality
would accept the wrong capability and fail the test rather than passing only
because fixture values differ.

### Outcome and terminal mapping

Tests cover both full and restricted success, the four fixed failure mappings,
all seven denial reasons, and therefore every existing `Decision` and
`ReasonCode`. Structural/API tests prove no contradictory mapping constructor
exists. Every failure class is entered from each nonterminal phase. Attempts to
change a terminal class/reason, reactivate, or complete again fail unchanged.

### Public authority proof

One external compile-pass doctest proves every intended public type is
nameable. Separate single-cause compile-fail doctests prove external safe Rust
cannot:

- construct any gate capability or `VerifiedAttestation`;
- read any capability/verified binding or allowed class;
- clone or copy a capability, `VerifiedAttestation`, or `VerifierFlow`;
- read or replace flow request, binding, or private state;
- directly construct or mutate `VerificationOutcome` fields;
- call a crate-private trusted producer;
- use a raw `Decision` or `VerificationOutcome` where
  `VerifiedAttestation` is required; or
- use public raw replay claim to obtain `FreshnessChecked`.

A focused source-structure test pins every authority-bearing field as private.
It prevents a compile-fail proof from passing for an incidental private
supporting type while the authority field itself accidentally becomes public.
Every authority field receives its own single-cause proof rather than one
representative mutation.

### Deterministic arbitrary histories

A dependency-free fixed-seed harness executes exactly 1,048,576 actions and
compares production behavior with an independent oracle after every action.
Exactly 2,048 actions are reserved inside the budget for scheduled paths that
guarantee:

- repeated full and restricted canonical completion;
- every nonterminal-to-failure-class edge;
- every denial reason;
- all seven same-flow capability successes;
- all seven equal-data cross-flow capability rejections;
- repeated actions from every terminal; and
- unknown-gate unsupported termination.

The remaining 1,046,528 actions are fixed-seed arbitrary histories. Before the
next generated mutating action after any terminal, the harness creates a new
independent flow as test setup; flow creation is not counted among the 13
state-machine actions. This prevents the budget from degenerating into repeated
terminal rejection. The scheduled prefix produces at least 16 full and 16
restricted completions, and explicit counters for every other scheduled deep
path must meet plan-frozen nonzero minimums. A test may not claim a property
through vacuous random coverage.

### Request retention and diagnostics

Private unit tests place distinct non-vacuous sentinels into every request
identifier, nonce/time, expected context, evidence profile, and evidence
payload. They format active/terminal flows, every capability,
`VerifiedAttestation`, outcomes, and errors through every implemented
`Debug`/`Display` surface.

Output must match an allowlisted context-free shape and omit all sentinels,
pointer/address forms, reference counts, line breaks, escape/control text,
absolute/home paths, and CI annotation prefixes. Separate protocol tests format
`EvidenceBundle` directly and require exactly its fixed redaction marker.

Private state tests verify the owned request is present through valid and
rejected nonterminal actions, then absent after all six terminal classes. No
test claims memory zeroization after `drop`.

### Mutation evidence

Every mutation runs in a disposable detached worktree, must make its named
regression fail, and is removed before the next probe. Mutated source never
returns to the primary M1-010 worktree.

The implementation plan freezes an exact table covering at least:

- deletion/widening of each of seven phase guards and the final completion
  guard;
- deletion/widening of each of seven binding comparisons;
- replacement of allocation identity with inner-value equality;
- early full or restricted success;
- second success-capability issuance;
- progress from each terminal class and terminal reclassification;
- ignoring an unknown mandatory gate;
- each invalid decision/reason pairing;
- retention of the raw request after every terminal class;
- clone/copy derivation on each authority-bearing type;
- public exposure of every individual authority/request/state/outcome field;
- raw public construction of each capability and verified result;
- unbound or raw-claim `FreshnessChecked` construction;
- diagnostic disclosure from every flow/capability/outcome/error surface; and
- direct `EvidenceBundle` profile/payload disclosure.

If implementation introduces another authority field or diagnostic surface,
the table expands one-for-one. Representative coverage is insufficient. A
surviving mutation first adds a focused failing regression in the primary
worktree; production changes follow only after that RED evidence.

### Machine-readable attack scenarios

Add five single-document scenarios under `lab/scenarios/`:

1. `OGIR-VERIFIER-GATE-SKIP-001`
2. `OGIR-VERIFIER-CAPABILITY-SUBSTITUTION-001`
3. `OGIR-VERIFIER-TERMINAL-IMMUTABILITY-001`
4. `OGIR-VERIFIER-UNKNOWN-GATE-001`
5. `OGIR-PRIVACY-VERIFIER-DIAGNOSTICS-001`

They use registered owner `initial-maintainer` and assurance profile
`all-protected-modes`, produce non-disciplinary denial/unsupported results,
and record residual risk from compromised trusted gate producers. The existing
bounded schema and validator are reused unchanged unless a new scenario proves
a concrete validator defect.

### Fuzz and differential impact

M1-010 introduces no parser, serializer, wire object, foreign ABI, or untrusted
byte interpretation. The finite action domain is exhaustively enumerated and
long histories are oracle-checked. Adding a byte fuzzer would add no semantic
coverage and would create unnecessary tool/dependency surface. Future evidence,
attestation-result, and permit parsers receive separate fuzz/differential
review before their formats are frozen.

### Completion gates and review

The exact implementation head must pass:

- `./scripts/check.sh`;
- `cargo test --workspace --all-features --release`;
- all implementation-plan acceptance scans;
- every isolated named mutation;
- clean diff/whitespace/object/worktree checks; and
- separate fresh-context trusted-computing-base and privacy reviews.

No live issue moves to `needs-review`, DCO range freezes, branch publishes, or
PR opens with an unresolved finding.

## Documentation and traceability

Implementation updates, in reviewed increments:

- `planning/issues/010-verifier-state-machine.md` with evidence and
  `status: needs-review` only after proof exists;
- `docs/ARCHITECTURE.md` with verifier flow authority, binding, and explicit
  report-versus-capability separation;
- `docs/ROADMAP.md` so M1's verifier graph distinguishes the pure appraisal
  proof from later permit/renewal lifecycle;
- `docs/THREAT_MODEL.md` with gate skipping, equal-data cross-flow
  substitution, terminal mutation, unknown gates, and diagnostic disclosure;
- `docs/TEST_STRATEGY.md` with the exact matrix/permutation/property/mutation
  evidence;
- a new accepted ADR-0007 recording runtime state,
  attempt allocation identity, capability authority, terminal mapping, and
  deferred validators/result signing;
- the ADR index and machine-readable scenarios; and
- `docs/LESSONS_LEARNED.md` for every durable mistake or review-discovered gap.

Primary sources recorded in the design/ADR include:

- [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html) for verifier,
  evidence appraisal, attestation-result, and relying-party roles;
- [Rust 1.98 visibility and privacy](https://doc.rust-lang.org/1.98.0/reference/visibility-and-privacy.html)
  for private fields and crate-confined authority;
- [Rust 1.98 `Arc::ptr_eq`](https://doc.rust-lang.org/1.98.0/std/sync/struct.Arc.html#method.ptr_eq)
  for same-allocation identity;
- [Rust 1.98 ownership](https://doc.rust-lang.org/1.98.0/book/ch04-01-what-is-ownership.html)
  for by-value one-use capabilities; and
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) for
  private structs, newtypes, custom typed arguments, and boundary validation.

## Alternatives considered

### Public mutable flags or state enum

Rejected. Callers could create contradictory combinations, mark a gate true,
construct a terminal/verified state, or mutate progress without the
corresponding trusted operation.

### Consuming typestate pipeline

Rejected for this task. Typestate prevents many invalid calls at compile time,
but verifier results arrive dynamically and the issue requires every invalid
action and terminal history to be represented and tested. An erased runtime
wrapper would still be necessary, producing two graphs that could drift.

### Parallel typestate and runtime APIs

Rejected. Two authority surfaces double the review burden without narrowing
the trusted boundary.

### One monolithic `verify()` function

Rejected as the M1-010 contract. It provides a small call surface but hides
progress and makes gate omission, unknown state, terminal immutability, and
arbitrary histories less directly falsifiable. The existing research function
remains as a fail-closed compatibility scaffold, not an alternate success path.

### Public capability constructors or `mark_passed(bool)`

Rejected. Either lets an external caller forge trusted completion.

### Unbound zero-sized capabilities

Rejected. A valid capability could advance another request. The existing
zero-sized freshness proof is upgraded to exact attempt binding.

### Binding only by request equality

Rejected. Two equal requests are still two orchestration attempts, and an
evidence operation from one must not silently advance the other. Allocation
identity distinguishes them without inventing protocol identity.

### Random, hashed, or global-counter attempt IDs

Rejected. Random IDs require an RNG and collision policy; hashes introduce
algorithm/collision/canonicalization semantics and could accidentally become a
protocol field; a global counter adds mutable process state, wraparound, and
restart meaning. A private `Arc` allocation already provides the exact
in-process identity required by this issue.

### Storing the full request in every capability

Rejected. It duplicates bounded but privacy-sensitive evidence and invites
value-equality comparison. The flow owns one request; capabilities share a
minimal private attempt record.

### Treating `Decision::Allow` as authority

Rejected. Public enum variants are constructible by design. Authority is the
opaque non-cloneable `VerifiedAttestation`; reports remain copyable views.

### Serializable or restart-durable verifier capabilities

Rejected. That would require an authenticated format, key/epoch management,
anti-replay rules, storage, and recovery semantics outside M1-010. A restart
begins a fresh verification flow and challenge.

### Adding result signing or permit issuance now

Rejected. It would preempt later result/crypto/protocol issues and falsely turn
a pure research model into an authorization artifact.

### Leaving derived `EvidenceBundle::Debug`

Rejected after inspection showed that it prints the opaque raw payload. Fixed
redaction is the smallest change consistent with the existing privacy
invariant and introduces no semantic/dependency expansion.

## Migration and execution sequence

1. Create isolated branch `research/m1-010-verifier-state-machine` and sibling
   worktree from exact reviewed main `b3a8f143`.
2. Run clean baseline build and full repository checks before editing.
3. Expand the local issue and commit this design specification only; do not
   publish a live issue or change runtime behavior.
4. Self-review for placeholders, contradictions, ambiguity, scope, authority,
   privacy, and source accuracy; run full documentation/repository gates.
5. Commit the documentation atomically without a DCO trailer and hand the exact
   commit to the decision owner for review.
6. After written-spec approval, invoke the required writing-plans workflow and
   create a negative-test-first implementation plan; commit and review it
   before runtime changes.
7. Publish the reviewed local issue through the guarded GitHub workflow with
   exact labels/milestone/body readback before implementation begins.
8. Implement in small ordered commits: public/compile-fail RED contract,
   independent finite oracle RED, minimal graph, binding/terminal/outcome
   behavior, property/privacy proof, scenarios/docs/ADR, then mutations and
   fresh independent reviews.
9. Move the issue to `needs-review` only after exact evidence passes.
10. Freeze the unsigned range and request explicit human DCO certification;
    preserve a verified backup before any metadata-only rewrite.
11. Publish non-force, create a non-draft PR, wait for checks/reviews, and merge
    only after human line-by-line responsibility and explicit approval.

The retained M1-009 worktree, branch, refs, and bundles remain untouched unless
the user separately requests cleanup.

## Acceptance-criteria traceability

| Issue requirement | Design provision |
| --- | --- |
| No early authority | Seven ordered opaque gates plus final single-use completion; report values are non-authoritative. |
| Exact attempt binding | One private `Arc` allocation per flow; `Arc::ptr_eq`; equal-data cross-flow tests. |
| Expected context authority | ADR-0005 order and relying-party `ExpectedContext` remain mandatory before claim. |
| Deterministic progress | One private runtime graph with 14 public phases and 13 explicit actions. |
| Valid outcomes only | Private outcome construction and exact complete decision/reason table. |
| Unknown/missing state fails closed | Missing gates reject; unknown required gates terminate `Unsupported`. |
| Terminal immutability | Six terminal phases reject all 13 actions and cannot reclassify or reissue success. |
| No opaque-evidence authorization | No production later-gate producers; research entry point remains evidence-invalid. |
| Exhaustive proof | 182-pair oracle, 5,040 permutations, seven omissions, exact million-action history. |
| Non-forgeable API | Compile-fail plus per-field structural/mutation proof. |
| Privacy | Active-only request ownership, fixed aggregate redaction, direct bundle hardening, sentinel tests. |
| Dependency-light | Existing crates and standard library only; no unsafe, crypto, parser, serializer, or I/O. |
| Traceability | Five scenarios, ADR-0007, architecture/threat/roadmap/test/lessons updates. |

## Rollback and change control

Before implementation, rollback is deletion/reversion of this unimplemented
design and local branch/worktree. After local implementation but before
publication, revert the relevant atomic commits or remove the unpublished
worktree/branch only with explicit direction. No current action rewrites shared
`main` or alters GitHub.

After merge, changing gate order, attempt identity, capability authority,
terminal classification, decision/reason mapping, request-retention behavior,
or diagnostic disclosure requires an ADR update or superseding ADR plus
matching model, compile-fail, mutation, privacy, threat, and scenario changes.

Disabling protected mode is a safe operational response. Skipping a gate,
accepting a capability from another attempt, treating a report as authority,
reactivating a terminal, silently ignoring an unknown gate, or restoring raw
evidence diagnostics is not an acceptable rollback.
