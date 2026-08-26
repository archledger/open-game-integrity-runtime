# ADR-0006: Local session lifecycle capabilities

- Status: Accepted
- Date: 2026-08-26
- Owners: Initial maintainer
- Related issues: [M1-009](../../planning/issues/009-local-session-state-machine.md)
- Supersedes: None
- Superseded by: None

## Context

Independent booleans for challenge validation, caller binding, session
preparation, evidence creation, permit receipt, activation, renewal, and
termination can drift into contradictory combinations and hide a skipped
authorization gate. Local orchestration also receives dynamic runtime events,
so invalid actions must be representable and rejected deterministically.

The roadmap's original linear graph did not contain a successful exit from
`RenewalPending`. A terminal lifecycle enum alone also cannot distinguish
cleanup still required from cleanup already completed. Treating cleanup as
implicit, or relying only on a discardable `#[must_use]` warning, can strand
session-scoped restrictions after a dropped request, crash, or transient
failure.

## Decision drivers

- Fail closed before initial or renewed protected-session authorization.
- Bind every authority-bearing completion to exactly one local session.
- Support dynamic runtime orchestration and deterministic rejection.
- Make terminality permanent while keeping cleanup explicit and retryable.
- Keep identifiers and raw authorization or process data out of diagnostics.
- Add no crate, package, parser, serializer, async runtime, or I/O boundary.
- Make the finite graph exhaustive and mutation-testable.

## Options considered

### Checked private runtime enum

Selected. One private discriminated state makes invalid phase/cleanup
combinations unrepresentable inside the implementation while keeping every
runtime action explicit, rejectable, and available to an exhaustive oracle.

### Pure typestate API

Rejected. Typestate can make invalid calls unnameable at compile time, but
session events arrive dynamically and this issue requires every invalid
one-step action and arbitrary action history to be exercised. An erased runtime
wrapper would still be necessary.

### Parallel typestate and runtime APIs

Rejected. Two observable graphs could drift and would double the trusted audit
surface without adding authority.

### Concrete permit or `AttestationResult`

Rejected. M1-009 must not invent protocol fields, signatures, encodings, or
validation authority owned by the later verifier and protocol work.

### Public or unbound capabilities

Rejected. Public constructors would let callers forge gate completion, while
an unbound capability could advance a different local session. Construction
authority remains crate-confined and every capability is privately bound to an
exact `SessionId`.

### Implicit or one-shot cleanup

Rejected. A terminal enum with implicit cleanup cannot distinguish pending
from complete, `#[must_use]` can be explicitly discarded, and a one-shot
request lost during failure could strand session restrictions. Reissuable
requests require the future cleanup adapter to be idempotent.

### New state-machine crate

Rejected. The lifecycle belongs to `ogir-agent`, uses only the existing
`SessionId`, and must keep future trusted adapter construction in that crate. A
new crate would add a boundary without reducing authority or dependencies.

## Decision

`ogir-agent` owns one non-cloneable `LocalSession` with a private `SessionId`
and private discriminated lifecycle state. Its exact initial path is:

```text
New
 -> ChallengeValidated
 -> CallerBound
 -> SessionPrepared
 -> EvidenceCreated
 -> PermitReceived
 -> Active
```

Renewal reuses the same permit and activation gates:

```text
Active -> RenewalPending -> PermitReceived -> Active
```

Every nonterminal phase may enter `Ended` or `Invalidated`. Both dispositions
are permanently lifecycle-terminal and atomically set
`CleanupStatus::Required`; a matching trusted cleanup completion changes only
that status to `CleanupStatus::Complete`.

Trusted local adapters own completion authority. M1-009 exposes opaque,
non-cloneable, session-bound capability types but no public or unused
production constructor. Future real adapters may add crate-confined factories
only alongside their validated operation. Transition methods consume
capabilities by value, check phase before binding, compare the exact private
session binding, and mutate only after both checks succeed. Invalid transitions
and rejected capabilities return structured, state-preserving errors.

The machine owns ordering only. It stores no raw operation payload and performs
no challenge, permit, evidence, process, policy, cleanup, persistence, network,
filesystem, cryptographic, or other I/O operation.

## Consequences

The finite state surface is small enough for complete state/action review, and
initial plus renewed activation share one authorization gate. Terminal cleanup
remains visible and requests can be reissued after interruption without opening
a lifecycle path.

Trusted adapters remain part of the local trusted computing base: a
compromised adapter can mint a capability early or create multiple
authoritative machines for one `SessionId`. Production construction,
capability minting, retry scheduling, persistence, and actual idempotent cleanup
I/O remain future work with separate review.

## Threat-model impact

The decision narrows A1 gate skipping, cross-session capability substitution,
and terminal reactivation against `protected_session_authorization`,
`local_session_identity`, and `host_policy_noninterference`. A4 compromise of a
trusted local adapter and crashes during future cleanup remain residual risks.
Transition rejection, unavailable cleanup, and other lifecycle failures are
non-disciplinary and never create protected-session authorization.

The affected boundaries are the future trusted local adapter-to-state-machine
capability boundary and the state-machine-to-cleanup-adapter request boundary.
The pure M1 implementation adds no IPC, privilege, process, or wire boundary.

## Privacy impact

The machine stores only a private `SessionId` and private lifecycle state whose
public views are fieldless phase, action, and `CleanupStatus` enums. Fixed
redacted diagnostics expose only approved enum names and redaction markers.
No raw challenge, account, evidence, permit, key, process, prefix, cgroup,
home, or path field enters the lifecycle machine or capability objects.

## Dependency and license impact

The implementation uses the Rust standard library plus the existing
`ogir_model::SessionId`. It adds no crate, package, transitive dependency, or
license-boundary change; the affected source and documentation remain
Apache-2.0.

## Validation

Completed executable evidence covers all 12 reachable configurations × 10
actions = 120 pairs, with exactly 26 successes and 94 state-preserving
rejections. The cleanup query returns a request for exactly two states. The
fixed-seed history executes exactly 1,048,576 actions: 80 scheduled deep-path
actions and 1,048,496 pseudo-random actions, with all five deep authorization
counters reaching eight. All eight capability-bearing allowed edges reject a
mismatched session without mutation.

One external compile-pass doctest and 13 separate compile-fail doctests cover
the public opaque contract, construction, non-cloneability, private bindings,
and private state. Exact diagnostic allowlists with private sentinels cover the
redaction contract. The three lifecycle attack scenarios are part of the nine
scenarios accepted by the unchanged aggregate validator. The Task 4 fix round
received scoped re-review with all four findings addressed and no new finding.

Final M1-009 completion additionally requires the named disposable-worktree
gate, binding, terminal, cleanup, and redaction mutations; a passing full
`./scripts/check.sh`; and fresh independent branch review. This ADR records
those as validation gates and does not claim the Task 6 mutation table or final
review is already complete.

## Rollback

Disabling protected mode is safe. Changing the graph, capability authority,
terminal rule, or cleanup obligation requires a superseding ADR and matching
model, mutation, privacy, architecture, and threat updates. Bypassing a gate,
reactivating a terminal session, or marking cleanup implicitly complete is not
an acceptable rollback.

## Primary sources

- [Approved M1-009 design](../superpowers/specs/2026-08-26-m1-009-local-session-state-machine-design.md)
  defines the project-specific graph and authority boundary.
- [Security invariants](../SECURITY_INVARIANTS.md),
  [architecture](../ARCHITECTURE.md), [roadmap](../ROADMAP.md), and
  [threat model](../THREAT_MODEL.md) are the project authority for
  authorization, session identity, renewal, cleanup, privacy, and failure
  semantics.
- [Rust 1.98 visibility and privacy](https://doc.rust-lang.org/1.98.0/reference/visibility-and-privacy.html)
  defines private fields and crate-confined visibility.
- [Rust 1.98 ownership](https://doc.rust-lang.org/1.98.0/book/ch04-01-what-is-ownership.html)
  defines by-value moves used for one-use non-`Copy`/non-`Clone` capabilities.
- [Rust 1.98 `must_use`](https://doc.rust-lang.org/1.98.0/core/attribute.must_use.html)
  documents the discardable warning and why cleanup must remain state-tracked.
