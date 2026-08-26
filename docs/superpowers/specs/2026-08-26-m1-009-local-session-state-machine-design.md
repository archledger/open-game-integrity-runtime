# M1-009 local protected-session state-machine design

- Status: Approved for implementation planning
- Date: 2026-08-26
- Related issue: [M1-009](../../../planning/issues/009-local-session-state-machine.md)
- Decision owner: Initial maintainer

## Summary

OGIR will model each local protected session as one non-cloneable, deterministic
runtime state machine in `ogir-agent`. The machine exposes a safe public phase
view but keeps construction, session identity, and internal state confined to
the trusted crate boundary. Explicit
transition methods consume opaque, non-cloneable completion capabilities bound
to the same `SessionId`. Capability constructors remain confined to the crate,
so future trusted local adapters can mint them only after their corresponding
operation succeeds without exposing protocol, cryptographic, process, or policy
payloads through the lifecycle API.

The initial path is:

```text
New
 -> ChallengeValidated
 -> CallerBound
 -> SessionPrepared
 -> EvidenceCreated
 -> PermitReceived
 -> Active
```

Renewal reuses the same permit gate:

```text
Active -> RenewalPending -> PermitReceived -> Active
```

Every nonterminal phase can end or invalidate. Terminal entry atomically marks
cleanup required. Cleanup completion is tracked separately and never permits a
terminal session to reactivate. The state machine performs no I/O, async work,
TPM interaction, signature validation, networking, process inspection, or
policy enforcement.

## Approval record

On 2026-08-26, the decision owner approved, in sequence:

- an opaque validated-permit capability instead of a concrete permit or
  `AttestationResult` type;
- one checked runtime graph instead of pure typestate or duplicate runtime and
  typestate APIs;
- the explicit successful-renewal loop through `PermitReceived`;
- the `ogir-agent::session` module and crate-confined capability boundary;
- the exact nonterminal data and transition contract;
- explicit terminal cleanup status and structured redacted errors; and
- exhaustive finite-state, arbitrary-sequence, compile-fail, mutation,
  privacy, and attack-scenario validation.

The decision owner then approved the written specification captured in commit
`fc9acbbe01714a8c8337555efb101f1d592e7428`; this status-only follow-up records
that review.

Evidence-backed refinements may proceed inside this approved task and trust
scope when their source, rationale, and falsifying test are recorded. Any
change to scope, trust authority, or the approved security semantics requires a
new explicit review rather than a silent implementation change.

## Context

The current `ogir-agent` crate defines a local `SessionIdentity`, an
`EvidenceRequest`, an `AttestationBackend`, and high-level errors. It does not
model lifecycle progress. As a result, future orchestration could accumulate
independent booleans for caller binding, policy preparation, evidence, permit,
renewal, and termination. Such flags admit contradictory combinations and make
skipped gates difficult to audit.

The roadmap names the phases but omits the successful exit from
`RenewalPending`. The architecture requires renewal to bind a fresh nonce to
the existing session key and active policy. The approved graph therefore
returns a successfully renewed session through the existing permit-receipt and
activation gates instead of creating a second authorization path.

Cleanup is also not represented by a terminal phase alone. The security
invariants require session policy removal at end and prohibit restrictions from
persisting beyond the protected session. A terminal enum says that lifecycle
progress stopped; it does not prove cleanup is still required or completed.
Cleanup status is therefore an orthogonal, explicitly observable part of each
terminal state.

## Goals

- Encode the approved local-session graph in one deterministic implementation.
- Reject every skipped, repeated, cross-session, or terminal lifecycle action.
- Require an opaque verifier-validated permit result before every activation.
- Keep gate capabilities single-use, session-bound, non-forgeable outside the
  crate, and redacted by default.
- Prevent external callers from manufacturing a lifecycle machine from a raw
  `SessionId`; trusted local adapter code owns construction.
- Keep invalid transitions state-preserving and errors deterministic.
- Make cleanup required on every terminal path, retryable after interruption,
  and separately acknowledgeable without terminal reactivation.
- Exhaustively test the finite transition space and compare it with an
  independent model.
- Add no production dependency, parser, serializer, async runtime, or I/O.

## Non-goals

- Defining concrete permit or `AttestationResult` fields.
- Signature, certificate, or verifier-key validation.
- Publisher challenge signature validation.
- TPM evidence generation or appraisal.
- Cgroup, process, Wine/Proton, filesystem, or policy-enforcement operations.
- Network transport or protocol serialization.
- Session public-key generation or proof of possession.
- Implementing the M1-010 verifier state machine.
- Selecting production cleanup retry timing, persistence, or crash recovery.
- Preventing arbitrary untrusted application code from invoking unrelated
  backend APIs; later trusted orchestration must make this state machine the
  sole lifecycle path.

## Primary-source basis

### Project authority

- [`docs/SECURITY_INVARIANTS.md`](../../SECURITY_INVARIANTS.md) requires an
  accepted verifier result and session-key binding before authorization,
  kernel-derived caller/session identity, policy limited to the intended
  process tree, policy removal at session end, fail-closed renewal after
  enforcement loss, redacted diagnostics, and no restrictions after the
  protected session.
- [`docs/ARCHITECTURE.md`](../../ARCHITECTURE.md) defines the locally derived
  `LocalSessionDescriptor`, signed `AttestationResult`, fresh renewal binding,
  and local-to-verifier trust boundaries.
- [`docs/ROADMAP.md`](../../ROADMAP.md) defines the M1 local-session phases,
  deterministic property-tested exit criterion, and dependency-free pure
  model boundary.
- [`docs/THREAT_MODEL.md`](../../THREAT_MODEL.md) requires verifier-signed
  authorization, race-resistant caller identity, session-key binding, scoped
  session policy, fail-closed enforcement loss, and non-disciplinary failure.
- [`planning/issues/009-local-session-state-machine.md`](../../../planning/issues/009-local-session-state-machine.md)
  defines this task's exact scope and acceptance criteria.

No external standard defines OGIR's local lifecycle graph. The repository's
reviewed security and architecture documents are therefore the normative
semantic sources.

### Rust 1.98 language/toolchain basis

- The [Rust 1.98 Reference visibility rules](https://doc.rust-lang.org/1.98.0/reference/visibility-and-privacy.html)
  define private fields and `pub(crate)` visibility. They support public opaque
  capability types whose construction and binding fields remain confined to
  `ogir-agent`.
- [The Rust 1.98 Programming Language ownership chapter](https://doc.rust-lang.org/1.98.0/book/ch04-01-what-is-ownership.html)
  documents by-value moves. A capability that implements neither `Copy` nor
  `Clone` is consumed by a by-value transition call.
- Rust 1.98's [`must_use` documentation](https://doc.rust-lang.org/1.98.0/core/attribute.must_use.html)
  states that the attribute produces a warning and can be explicitly
  discarded. `#[must_use]` improves diagnostics but cannot enforce cleanup;
  the terminal state must retain `CleanupStatus::Required` until trusted
  completion is recorded.

## Trust and authority

### Local session identity

`SessionId` comes from the trusted local portal/agent boundary already defined
by the architecture. The game, bridge, environment, PID text, path, App ID, or
publisher cannot supply the authoritative local session identity.

`LocalSession` owns one `SessionId`, is not `Clone` or `Copy`, and has no public
constructor. A crate-confined constructor is reserved for future trusted local
portal/agent code after it derives the authoritative session identity. This
prevents external safe Rust callers from manufacturing or directly copying a
lifecycle machine. The trusted local owner remains responsible for creating at
most one authoritative machine per `SessionId`; M1-009 adds no global registry
or persistence layer.

### Gate capabilities

The trusted adapter that owns a real operation is authoritative for completing
that operation and minting its capability inside `ogir-agent`. The lifecycle
machine is authoritative only for ordering and exact session binding. It does
not reinterpret raw operation results.

The five input capabilities are:

- `ValidatedChallenge`;
- `BoundCaller`;
- `PreparedSession`;
- `CreatedEvidence`; and
- `ValidatedPermit`.

Each capability contains only a private local session binding. It contains no
raw challenge, account, evidence, policy, permit, key, signature, process, or
path payload. It is public only so boundary APIs may name and pass it;
construction is `pub(crate)`, and the binding is never publicly readable.

`ValidatedPermit` means a trusted future local permit-validation adapter has
accepted a verifier result for this session. It deliberately does not define
the later signed result's fields, encoding, algorithms, or verification
process.

### Cleanup authority

The state machine authorizes cleanup by producing a session-bound
`CleanupRequest`. A future trusted cleanup adapter is authoritative for
removing or confirming the absence of session-scoped controls. Only that
adapter may mint `CleanupCompleted` inside the crate.

Cleanup requests may be reissued while cleanup remains required. This supports
crash and transient-failure retry, so the future cleanup operation must be
idempotent. M1-009 models the obligation and acknowledgement, not the actual
operation or retry scheduler.

## State representation

### Public views

`SessionPhase` is a public, fieldless enum with exactly:

```text
New
ChallengeValidated
CallerBound
SessionPrepared
EvidenceCreated
PermitReceived
Active
RenewalPending
Ended
Invalidated
```

`CleanupStatus` is a public, fieldless enum with exactly:

```text
NotRequired
Required
Complete
```

`SessionAction` is a public, fieldless enum used only for structured errors and
test/model traceability. It names the ten mutating actions:

```text
RecordChallengeValidated
RecordCallerBound
RecordSessionPrepared
RecordEvidenceCreated
RecordPermitReceived
Activate
BeginRenewal
End
Invalidate
RecordCleanupCompleted
```

These enums contain no user-controlled strings or identifiers and are safe to
include in diagnostics.

### Private state

The implementation uses one private discriminated enum rather than independent
writable phase and cleanup fields. Nonterminal variants carry no cleanup
status. `Ended` and `Invalidated` carry a private terminal cleanup variant of
`Required` or `Complete`.

This makes invalid combinations unrepresentable inside the implementation:

- a nonterminal phase cannot have required or complete cleanup;
- a terminal phase cannot have `NotRequired` cleanup; and
- cleanup completion cannot change terminal disposition.

The twelve reachable public state configurations are:

- eight nonterminal phases with `CleanupStatus::NotRequired`;
- `Ended` with cleanup `Required` or `Complete`; and
- `Invalidated` with cleanup `Required` or `Complete`.

`LocalSession::phase()` and `LocalSession::cleanup_status()` derive their views
from the private state. There is no public state setter or raw state field.

## Nonterminal transition contract

The eight allowed nonterminal edges are:

| Current phase | Method and required input | Next phase |
| --- | --- | --- |
| `New` | `record_challenge_validated(ValidatedChallenge)` | `ChallengeValidated` |
| `ChallengeValidated` | `record_caller_bound(BoundCaller)` | `CallerBound` |
| `CallerBound` | `record_session_prepared(PreparedSession)` | `SessionPrepared` |
| `SessionPrepared` | `record_evidence_created(CreatedEvidence)` | `EvidenceCreated` |
| `EvidenceCreated` | `record_permit_received(ValidatedPermit)` | `PermitReceived` |
| `PermitReceived` | `activate()` | `Active` |
| `Active` | `begin_renewal()` | `RenewalPending` |
| `RenewalPending` | `record_permit_received(ValidatedPermit)` | `PermitReceived` |

Every method mutates through `&mut self` and returns
`Result<(), TransitionError>`. Capability-bearing methods consume their input
by value.

The deterministic validation order is:

1. verify that the current private state permits the requested action;
2. when the action carries a capability, compare its private `SessionId` with
   the machine's private `SessionId`; and
3. only after both checks succeed, replace the private state.

An action invalid for the current state returns `InvalidTransition` without
consulting or exposing the capability binding. An otherwise allowed action
with a mismatched capability returns `CapabilityRejected`. The capability is
dropped on every success or failure and cannot be reused through safe Rust.
Every failure leaves the state unchanged.

`activate()` needs no second capability because the private `PermitReceived`
phase is itself reachable only by consuming a matching `ValidatedPermit`.
Renewal must consume a fresh `ValidatedPermit`; an earlier capability was
already moved and the machine cannot jump directly from `RenewalPending` to
`Active`.

## Terminal and cleanup contract

`end()` and `invalidate()` are valid from every one of the eight nonterminal
phases. Uniform terminal handling prevents a partial startup failure from
bypassing cleanup merely because a future implementation has already acquired
some local resource not represented in this pure model.

On success, each method atomically:

1. changes the private state to the selected terminal disposition with cleanup
   `Required`; and
2. returns a `#[must_use]` session-bound `CleanupRequest`.

Calling either method from `Ended` or `Invalidated` returns
`InvalidTransition` and leaves cleanup status unchanged.

`cleanup_request()` is a non-mutating query:

- it returns a new session-bound request only for terminal states whose cleanup
  is `Required`; and
- it returns `None` for all nonterminal or cleanup-complete states.

Explicit reissue is permitted so a dropped request or interrupted cleanup does
not strand the session. Multiple requests cannot authorize or reactivate a
session. The future adapter must make repeated removal safe and idempotent.

`record_cleanup_completed(CleanupCompleted)` is valid only for `Ended` or
`Invalidated` with cleanup `Required`. It validates the private session binding
and changes only the terminal cleanup value to `Complete`. Duplicate,
nonterminal, or mismatched completion fails without mutation.

Cleanup acknowledgement is an orthogonal bookkeeping transition, not a
lifecycle transition. Both terminal phases reject challenge, caller,
preparation, evidence, permit, activation, renewal, end, and invalidation
actions before and after cleanup completion.

## Public API shape

The conceptual public surface is:

```rust
pub struct LocalSession { /* private */ }

impl LocalSession {
    pub(crate) fn new(session_id: SessionId) -> Self;
    pub fn phase(&self) -> SessionPhase;
    pub fn cleanup_status(&self) -> CleanupStatus;

    pub fn record_challenge_validated(
        &mut self,
        capability: ValidatedChallenge,
    ) -> Result<(), TransitionError>;
    pub fn record_caller_bound(
        &mut self,
        capability: BoundCaller,
    ) -> Result<(), TransitionError>;
    pub fn record_session_prepared(
        &mut self,
        capability: PreparedSession,
    ) -> Result<(), TransitionError>;
    pub fn record_evidence_created(
        &mut self,
        capability: CreatedEvidence,
    ) -> Result<(), TransitionError>;
    pub fn record_permit_received(
        &mut self,
        capability: ValidatedPermit,
    ) -> Result<(), TransitionError>;
    pub fn activate(&mut self) -> Result<(), TransitionError>;
    pub fn begin_renewal(&mut self) -> Result<(), TransitionError>;

    pub fn end(&mut self) -> Result<CleanupRequest, TransitionError>;
    pub fn invalidate(&mut self) -> Result<CleanupRequest, TransitionError>;
    pub fn cleanup_request(&self) -> Option<CleanupRequest>;
    pub fn record_cleanup_completed(
        &mut self,
        capability: CleanupCompleted,
    ) -> Result<(), TransitionError>;
}
```

This is a contract sketch, not implementation text. The implementation plan
may adjust names for established Rust style only if it updates this spec and
preserves all approved semantics before code is written.

The crate-confined constructor is shown to make authority explicit; it is not a
public consumer API. A future trusted portal/agent factory may return
`LocalSession` after authenticating and deriving session identity without
exposing raw construction.

`LocalSession`, all five gate capabilities, `CleanupRequest`, and
`CleanupCompleted` implement neither `Clone` nor `Copy`. Public phase/action/
cleanup enums may implement `Clone`, `Copy`, equality, and hashing because they
contain no authority or secret data.

## Error and diagnostic contract

`TransitionError` has two structured variants:

```rust
InvalidTransition {
    phase: SessionPhase,
    cleanup_status: CleanupStatus,
    action: SessionAction,
}
CapabilityRejected {
    action: SessionAction,
}
```

`InvalidTransition` reports only the safe public state/action view.
`CapabilityRejected` deliberately does not distinguish a wrong session,
expired future capability, or another internal capability fault. M1-009 has no
time-bearing capability, but the generic wording avoids creating a later
binding oracle.

`Display` uses fixed, context-free messages. `Debug` for `LocalSession`, gate
capabilities, cleanup types, and errors contains only type names, approved
redaction markers, and the safe public enums. It never includes:

- `SessionId` text;
- publisher, game, build, account, match, or policy identifiers;
- a challenge, nonce, evidence bundle, permit, signature, or key;
- process, prefix, cgroup, home, or filesystem paths; or
- caller-controlled strings.

The state machine stores none of those raw values except its private redacted
`SessionId`, so most disclosure classes are excluded structurally rather than
filtered after formatting.

Transition errors are local orchestration failures. They are not cheating
evidence, do not map directly to discipline, and never authorize a fallback
protected mode.

## Module boundary

### `ogir-agent::session`

Owns:

- `LocalSession` and its private state;
- public phase, cleanup, action, and error views;
- opaque capability and cleanup types;
- crate-confined session and capability constructors;
- exact transition logic; and
- unit, model, privacy, and compile-fail documentation tests.

The module uses only the Rust standard library and `ogir_model::SessionId`. It
does not use `EvidenceBundle`, `PublisherChallenge`, `AccountScope`, async,
clock, random, transport, storage, TPM, process, filesystem, or policy APIs.

`crates/ogir-agent/src/lib.rs` declares the module and explicitly re-exports
the reviewed public contract. No wildcard public re-export is required.

### Future trusted adapters

Future sibling modules may use crate-visible constructors only after their
operation succeeds. They remain responsible for validating raw inputs and for
not minting a completion capability early. The state machine cannot protect
against a compromised trusted adapter that deliberately violates this
contract; such a compromise is inside the local trusted computing base.

### Other crates

- `ogir-model` continues to own shared pure identifier and decision types. It
  does not absorb agent-specific lifecycle capability types.
- `ogir-protocol` continues to own protocol object framing and gains no M1-009
  lifecycle dependency.
- `ogir-verifier` remains separate; M1-010 owns its state machine.
- applications gain no process, cleanup, permit, or TPM implementation in this
  task.

No new crate or dependency is added.

## Test design

### Exhaustive finite-state matrix

The reachable model has twelve state configurations and ten mutating actions,
for 120 state/action pairs.

Allowed pairs are:

- the eight nonterminal progression/renewal edges;
- `end` and `invalidate` from each of eight nonterminal phases (16 pairs); and
- cleanup completion from each terminal disposition while cleanup is required
  (two pairs).

Exactly 26 pairs succeed. The remaining 94 return the expected structured
error and preserve phase and cleanup status. `cleanup_request()` is tested as a
separate query: it returns `Some` for exactly the two terminal-required states
and `None` for the other ten.

Tests construct each reachable state through public transitions rather than
direct private-state assignment. A separate literal reference model defines
expected phase, cleanup, and error results without calling production
transition helpers.

### Capability binding and ownership

For each allowed capability-bearing edge:

- a capability for the same session succeeds once;
- a capability for another session returns `CapabilityRejected`;
- the exact phase and cleanup status remain unchanged on rejection; and
- no error or object diagnostic exposes either session sentinel.

Compile-fail doctests prove that external code cannot:

- construct `LocalSession` directly from a raw `SessionId`;
- construct any gate capability or `CleanupCompleted`;
- read a capability's session binding;
- clone or copy a capability, `CleanupRequest`, `CleanupCompleted`, or
  `LocalSession`; or
- write the private lifecycle state directly.

### Initial and renewal safety

- `Active` is unreachable when any initial gate is omitted.
- `EvidenceCreated` is unreachable before both caller binding and preparation.
- Initial activation requires a matching `ValidatedPermit` after evidence.
- Renewal can begin only from `Active`.
- `RenewalPending` cannot activate directly or reuse an earlier permit
  capability.
- A matching fresh `ValidatedPermit` returns renewal to `PermitReceived`, and
  only the separate activation edge returns it to `Active`.
- Repeated renewal cycles preserve the same rules.

### Terminal cleanup

- `end` and `invalidate` succeed from each nonterminal phase.
- Every successful terminal entry returns a must-use cleanup request and
  reports `CleanupStatus::Required`.
- Cleanup request reissue succeeds only while required.
- Matching cleanup completion preserves terminal disposition and reports
  `Complete`.
- Mismatched, duplicate, and nonterminal cleanup completion fails unchanged.
- Every lifecycle action fails from both terminal dispositions before and
  after cleanup completion.

### Deterministic arbitrary sequences

A dependency-free fixed-seed generator executes at least 4,096 sequences of
256 actions (1,048,576 total actions). After every action, the implementation
is compared with an independent model that tracks:

- current phase and cleanup status;
- successful initial gate history;
- whether a fresh permit was accepted after entering renewal;
- terminal disposition; and
- the exact expected error class.

The property assertions include:

- no `Active` state before all initial gates;
- no renewed `Active` state without a post-renewal validated permit;
- no cross-session capability success;
- no state mutation after a rejected action;
- no lifecycle exit from a terminal phase; and
- no terminal state without required-or-complete cleanup.

The seed and action index are printed only on failure. They are test metadata,
not session data.

### Diagnostic privacy

Tests place distinct non-vacuous private session sentinels inside the machine
and every capability, then format every object and error through both `Debug`
and `Display`. Output must match an allowlisted structure and omit all
sentinels, line breaks, escape/control sequences, home paths, and CI annotation
prefixes.

Challenge and account data cannot enter the module's state or capability
fields. Their absence is established by the public/private type contract and
reviewed module imports rather than a vacuous runtime string assertion.

### Mutation evidence

Each mutation runs only in a disposable detached worktree and is removed after
the named test fails. Mutations must cover at least:

- deleting or widening each initial progression gate;
- allowing evidence before caller binding or preparation;
- allowing activation without `PermitReceived`;
- allowing direct `RenewalPending -> Active`;
- accepting a cross-session capability;
- making a capability or `LocalSession` cloneable/constructible;
- allowing any lifecycle action from a terminal state;
- omitting cleanup-required status from either terminal path;
- accepting mismatched or duplicate cleanup completion;
- changing cleanup completion into a nonterminal phase; and
- exposing the private session binding through a default diagnostic.

Every mutation maps to a named regression. If a mutation survives, add a
focused failing test in the primary worktree before changing implementation.
Mutated source is never copied back.

### Machine-readable attack scenarios

Add distinct scenarios for:

1. skipping permit receipt and attempting activation;
2. presenting a capability from another local session; and
3. attempting renewal/reactivation after terminal entry or leaving terminal
   cleanup unacknowledged.

Each scenario uses the existing registered `initial-maintainer` owner and
`all-protected-modes` assurance profile, returns a non-disciplinary rejection
or cleanup-required outcome, and records residual trusted-adapter risk. The
existing bounded strict scenario validator is reused unchanged unless a
reviewed scenario exposes a concrete schema defect.

### Fuzz/property impact

No parser or untrusted byte surface is introduced. The action/state domain is
finite and exhaustively enumerated, while long deterministic sequences cover
history. A fuzzing dependency or target would add nondeterminism and supply-
chain surface without covering a larger semantic domain. Future raw permit or
challenge parsing receives its own bounded parser/fuzzer review.

## Documentation and traceability

Implementation must update, in reviewed increments:

- `planning/issues/009-local-session-state-machine.md` with the complete
  required AI-task sections, trust sources, exact graph, positive/negative/
  property/mutation/privacy/dependency coverage, and `status: needs-review`
  only after evidence exists;
- `docs/ARCHITECTURE.md` with the successful renewal loop, capability authority,
  and orthogonal terminal cleanup status;
- `docs/ROADMAP.md` so the local graph does not retain the ambiguous missing
  renewal-success edge;
- `docs/TEST_STRATEGY.md` with the exhaustive model, arbitrary sequences,
  compile-fail, mutation, privacy, and attack-scenario mapping;
- `docs/THREAT_MODEL.md` with skipped-gate, cross-session capability, terminal
  reactivation, and stranded-cleanup responses;
- a new ADR, expected to be ADR-0006, recording checked runtime state,
  crate-confined capabilities, renewal reuse of the permit gate, and explicit
  cleanup obligation; and
- the ADR decision index and public lessons when review discovers a durable
  gap.

## Alternatives considered

### Ad hoc booleans

Rejected. Independent flags admit contradictory states, skipped gates, and
terminal reactivation, and make exhaustive review harder.

### Pure typestate API

Rejected for this task. It makes many invalid calls unnameable at compile time,
but local session events arrive dynamically and the issue explicitly requires
every invalid one-step action plus arbitrary action sequences. An erased
runtime wrapper would still be required.

### Parallel typestate and runtime APIs

Rejected. Two observable graphs can drift and double the trusted audit surface.

### Public runtime enum with writable state

Rejected. It would let callers construct `Active`, terminal-without-cleanup, or
other invalid combinations directly.

### Concrete permit or `AttestationResult` in M1-009

Rejected. It would invent not-yet-approved protocol fields, signature
semantics, and validation authority and overlap M1-010/later protocol work.

### Public capability constructors

Rejected. Any caller could forge gate completion. Crate-confined construction
keeps the future adapter boundary explicit.

### Public `LocalSession::new(SessionId)`

Rejected. It would let an external caller manufacture parallel lifecycle
machines for an identifier whose authority belongs to the trusted local
portal/agent. Construction remains crate-confined until that trusted factory is
implemented.

### Unbound zero-sized capabilities

Rejected. A capability accepted for one local session could advance another.
Every capability is privately bound to the exact `SessionId`.

### Separate renewal-permit state or direct renewal activation

Rejected. A parallel gate could diverge from initial authorization; a direct
edge could skip permit receipt. Renewal reuses `PermitReceived` and `activate`.

### Terminal enum with implicit cleanup

Rejected. It cannot distinguish cleanup pending from complete, and
`#[must_use]` alone is explicitly discardable under Rust semantics.

### One-shot cleanup request

Rejected. Losing the token during a crash or transient failure could strand
session restrictions. Explicit request reissue plus an idempotent future
adapter supports retry without permitting lifecycle progress.

### New state-machine crate

Rejected. The local lifecycle belongs to `ogir-agent`, needs only the existing
`SessionId`, and benefits from crate-confined trusted adapter constructors. A
new crate would add a boundary without reducing authority or dependencies.

## Migration and sequencing

1. Commit and human-review this design specification.
2. Expand and review the local M1-009 issue body; publish/synchronize a live
   issue only through the guarded repository workflow.
3. Write and human-review a test-first implementation plan.
4. Add compile-fail/public-contract tests before capability implementation.
5. Add the independent finite-state oracle and verify its expected RED state.
6. Implement the smallest private state/capability transition core.
7. Add terminal cleanup tracking, arbitrary sequences, diagnostics, scenarios,
   documentation, ADR, and mutation evidence in separate reviewable commits.
8. Obtain fresh independent TCB/privacy review, then move the issue to
   `needs-review` only after all evidence passes.
9. Freeze the exact unsigned commit range for human DCO certification before
   any sign-off rewrite or publication.

M1-010 may consume the established concepts but must not weaken or bypass this
local capability boundary. Concrete permit validation and actual cleanup remain
future adapters with separately reviewed failure semantics.

## Acceptance-criteria traceability

| Issue requirement | Design provision |
| --- | --- |
| Pure deterministic typed transitions | Crate-confined construction, one private discriminated state, ten explicit actions, no I/O or dependency addition. |
| Evidence after caller binding/preparation only | Only ordered `CallerBound -> SessionPrepared -> EvidenceCreated`; exhaustive and mutation tests reject skipped gates. |
| Active only after verifier permit | Session-bound unforgeable `ValidatedPermit`, `PermitReceived`, then separate `activate`; same gate reused for renewal. |
| Ended/invalidated terminal | Every lifecycle action rejected from both terminal dispositions before and after cleanup. |
| Cleanup every terminal path | Every nonterminal end/invalidate atomically records `Required`; retryable request and capability-gated completion are explicit. |
| Structured transition errors | Safe phase/status/action enums only; invalid phase and capability rejection are deterministic and state-preserving. |
| All allowed transitions | Exact 26 successful state/action pairs enumerated. |
| Every one-step invalid transition | Remaining 94 finite pairs rejected against an independent oracle. |
| Random sequences never reach early Active | At least 1,048,576 deterministic actions checked after every step. |
| Terminal states remain terminal | Exhaustive terminal matrix, arbitrary sequences, and terminal-guard mutations. |
| Redacted errors | Raw challenge/account data excluded structurally; private session sentinels tested non-vacuously across every diagnostic. |
| Dependency-light, side-effect free | Existing `ogir-agent` crate, standard library plus existing `SessionId`; no new dependency or operation adapter. |
| Graph matches architecture/roadmap | Initial graph preserved; missing renewal success edge explicitly corrected; cleanup is orthogonal rather than a new lifecycle phase. |

## Rollback and change control

Before implementation, rollback is deletion/reversion of this unimplemented
design and local branch. After implementation, changing a gate, capability
authority, terminal rule, or cleanup obligation requires an ADR update or
superseding ADR plus corresponding model, mutation, privacy, architecture, and
threat-model changes.

Disabling protected mode is a safe operational response. Bypassing a gate,
reactivating a terminal session, treating cleanup as implicitly complete, or
adding a public capability constructor is not an acceptable rollback.
