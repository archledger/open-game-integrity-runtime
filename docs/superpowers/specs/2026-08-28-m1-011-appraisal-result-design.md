# M1-011 Appraisal Result and reason-code taxonomy design

- Status: Approved for implementation planning
- Date: 2026-08-28
- Related issue: [M1-011](../../../planning/issues/011-result-reason-code-taxonomy.md)
- Decision owner: Initial maintainer

## Summary

M1-011 will add one pure, unsigned `AppraisalResult` at the in-process seam
between completed verifier appraisal and future protected Attestation Result
work. The name preserves `AttestationResult` for the signed verifier output
already defined by `docs/ARCHITECTURE.md`.

An allowed Appraisal Result can be created only by consuming the exact non-
cloneable `VerifiedAttestation` returned by the seven-gate verifier path. Every
Appraisal Result carries relying-party `ExpectedContext`. Allowed outcomes
additionally carry the accepted `EvidenceProfile` and `SessionPublicKeyId`.
Unsuccessful outcomes carry no accepted claims and exactly one coarse,
phase-eligible, non-disciplinary reason.

The evidence commitment is deferred. M1-012 defines binding-transcript inputs
without choosing cryptography; later M2 protocol work selects commitment,
integrity, and wire behavior. An Appraisal Result is not signable or
serializable as an OGIR Attestation Result by this issue.

## Approval record

On 2026-08-28, the decision owner approved the conversation-level direction:

- a pure semantic outcome boundary with no signing, serialization, permit, or
  admission behavior;
- one coarse reason for each unsuccessful outcome and no reason for allows;
- a discriminated payload where only allows expose accepted claims;
- result validity deferred to the future protected-result issuer because M1
  has no authoritative terminal-time boundary;
- terminal-emission failures and capability-consumed allows;
- an opaque result with cumulative typed claim state;
- one exact selected policy for both full and restricted outcomes;
- deferral of evidence commitment rather than opaque bytes or a marker;
- `AppraisalResult` terminology preserving protected `AttestationResult`; and
- phase-to-reason eligibility that refines ADR-0007 and requires new frozen
  finite-model counts.

An adversarial review of the first written translation found and prompted the
last three refinements plus validity deferral, honest payload-provenance limits,
and whole-state terminal replacement.

On 2026-08-28, the decision owner approved exact candidate tree
`bc015648a08f10de543b764d8333baaf6e423114` with no requested change. This
approval authorizes implementation planning only. It does not authorize runtime
implementation, publication, DCO certification, or GitHub mutation.

## Security objective

The module must prevent public safe Rust from creating an allowed semantic
outcome without the completed exact-attempt verifier capability. It must make
contradictory Appraisal Result shapes impossible and reject reason observations
that do not belong to the current gate:

- no report-only allow becomes allowed-result provenance;
- no raw request is refilled after terminal request release;
- no capability crosses from an equal distinct flow;
- no failure retains accepted claims;
- no allow carries a failure reason;
- no unsuccessful outcome omits its reason;
- no reason falsely claims a check from another phase;
- no restricted outcome substitutes policy; and
- no Appraisal Result is mistaken for protected result, permit, PoP, or
  admission.

RFC 9334 assigns Evidence appraisal and Attestation Result production to the
Verifier, then assigns application-specific result appraisal to the Relying
Party. RFC 9711 says result claims are governed by verifier policy and
distinguishes attestation used with PoP from the PoP transaction. M1-011 follows
those role separations without selecting an EAT or other wire representation.

## Scope

### Included

- `AppraisalResult`, accepted claims, and a borrowed discriminated view;
- exact relying-party context;
- exact-attempt-associated accepted profile and session-key handle;
- consuming conversion from `VerifiedAttestation` to allow;
- one Appraisal Result returned by each eligible failure transition;
- complete five-decision/fifteen-reason mapping and phase eligibility;
- removal of `ReasonCode::None` and optional reason reporting;
- one private state that owns active request and cumulative claims;
- fixed redaction, finite model evidence, mutation contracts, and docs.

### Excluded

- evidence commitment, verifier identity, signature, protected
  `AttestationResult`, signing/validation interface, and key material;
- encoding, parser, serializer, canonicalization, protocol discriminants, or
  conformance corpus;
- permit, key resolution, PoP, admission, renewal, or revocation lifecycle;
- clock adapter, persistence, retention enforcement, production gate or result-
  issuance adapters, I/O, `unsafe`, dependencies, privilege, or crypto;
- cryptographic provenance of copyable profile/key-handle payloads; and
- trusted unsuccessful-result provenance suitable for a future signer.

Result issued-at/expiry, maximum lifetime, and authoritative issuance-time
observation are also excluded. The future protected Attestation Result issuer
must bind those fields with commitment, identity, and integrity protection.

M1-012 specifies binding-transcript inputs without selecting algorithms. Later
M2 work must decide commitment representation, algorithm identification,
integrity protection, and wire coverage before a protected result exists.

## Domain model

### Common fields and policy binding

Every Appraisal Result owns exact `ExpectedContext`, independently supplied by
the relying party at flow start. Result construction accepts no replacement
correlation.

The selected policy in `ExpectedContext` is the accepted policy after success.
Restricted means that exact preselected policy defined restricted gameplay. It
does not carry a second policy or permit fallback after a full-policy failure.

### Discriminated payload

Conceptual private shape:

```rust
pub struct AppraisalResult {
    context: ExpectedContext,
    payload: AppraisalPayload,
}

enum AppraisalPayload {
    Allow(AcceptedClaims),
    AllowRestricted(AcceptedClaims),
    Failure(FailurePayload),
}

pub struct AcceptedClaims {
    accepted_profile: EvidenceProfile,
    session_public_key_id: SessionPublicKeyId,
}

struct FailurePayload {
    decision: FailureDecision,
    reason: ReasonCode,
}
```

`FailureDecision` is private and limited to deny, unsupported, and retry.
`AppraisalResult` has no public constructor, builder, setter, `Default`,
`Clone`, `Copy`, or conversion from a report.

A borrowed public view is report-only:

```rust
pub enum AppraisalResultView<'a> {
    Allow(&'a AcceptedClaims),
    AllowRestricted(&'a AcceptedClaims),
    Failure { decision: Decision, reason: ReasonCode },
}
```

Its failure variant is freely constructible. Its allow variants require opaque
`AcceptedClaims` borrowed from an existing result because accepted-claim
construction remains private. The enforced invariant is not that arbitrary
report pairs are globally unconstructible. It is that accessors on an opaque
Appraisal Result can expose only one valid mapping. Constructing a view cannot
construct or mutate the outer result.

### Commitment deferral

A protected Attestation Result eventually needs a commitment to the exact
appraised evidence or binding transcript. M1-011 cannot define that value
without representation, bounds, canonical input, algorithm identification,
and integrity-coverage decisions. Opaque bytes freeze observable behavior
without meaning; a marker is not a commitment.

M1-012 determines the semantic transcript inputs without choosing crypto. A
later M2 protocol issue selects the commitment and protected representation.
Until then, Appraisal Result is deliberately not an Attestation Result basis
that a generic signer may accept.

## Authority, provenance, and module seam

`AppraisalResult` belongs in `ogir-verifier`, beside `VerifierFlow`. Construction
must inspect verifier-private capabilities; placing it in `ogir-model` would
require a public factory or reverse dependencies.

Dependencies are entirely in-process. There is one implementation and no
varying external dependency, so no trait, port, or adapter is justified.

### What the types prove

- An allowed Appraisal Result came through one completed flow capability.
- A claim-bearing capability was accepted only by its exact flow allocation.
- Context was bound before terminal completion.
- Result shape and reason mapping are valid by construction.

### What the types do not prove

`EvidenceProfile` is cloneable and `SessionPublicKeyId` is copyable. A trusted
producer can place a copied or dishonest payload into a correctly bound
capability. Allocation binding proves capability association, not cryptographic
payload provenance. Future appraiser/session producers are verifier-TCB code
and must establish payload truth before minting capabilities.

Public callers can begin a flow and choose an eligible failure. Therefore an
unsuccessful Appraisal Result is a valid report shape, not sufficient trusted
provenance for a future signer. Protected-result issuance must introduce a
trusted issuer boundary for all outcomes rather than trusting failure
provenance solely from this type.

## Private state and atomic terminal replacement

The current split `state` plus `request: Option<_>` cannot express the stronger
invariant without coordination. M1-011 replaces it conceptually with one private
state that owns all phase-specific data:

```text
Active phase + exact request + cumulative claims
or
Terminal phase + safe outcome only
```

Claim-bearing transitions check phase, then allocation identity, then move the
payload into the next active state. No flat unrelated `Option` claim slots are
added.

A terminal transition validates all fallible inputs first, then replaces the
whole active state with its terminal state before extracting/moving context and
claims from the old state. Result assembly after replacement is infallible.
If unwinding occurs during later drops, the flow is already fail-closed and
terminal. Structural tests prohibit a nonterminal state without its exact
request and cumulative claims.

## Successful completion

The interface becomes:

```rust
impl VerifierFlow {
    pub fn complete(&mut self)
        -> Result<VerifiedAttestation, TransitionError>;
}

impl VerifiedAttestation {
    pub fn into_appraisal_result(self) -> AppraisalResult;
}
```

`complete` is valid only from `PolicySatisfied`. After every fallible check, it
replaces the whole active state with `Verified`, then infallibly moves exact
context, accepted profile, key handle, attempt binding, and allowed class from
the returned old state into `VerifiedAttestation`. Conversion accepts no caller
input and is infallible.

`VerifiedAttestation` and `AppraisalResult` remain non-cloneable and non-copyable.
The Appraisal Result is still not relying-party admission authority; one-use
provenance prepares safe later design rather than creating a permit.

## Unsuccessful completion

Failure actions return the Appraisal Result caused by terminal entry:

```text
mark_malformed()
mark_unsupported(requirement)
mark_retryable(cause)
deny(reason)
mark_revoked()
```

`deny` accepts exactly `ChallengeAuthenticationFailed`, `NotYetValid`,
`Expired`, `ReplayDetected`, `ContextBindingMismatch`, `EvidenceInvalid`,
`PolicyDenied`, or `ProtectedSessionLost`. `Malformed` and `Revoked` are not
denial inputs; only their dedicated actions emit those reasons. Unsupported and
retry reasons likewise remain confined to their typed actions.

Each action first checks phase eligibility and any typed input without mutation.
It then terminal-first replaces the whole active state, drops staged accepted
claims, releases raw request fields other than moved context, and returns one
unsuccessful Appraisal Result. Repetition returns `InvalidTransition` and cannot
issue another result.

## Decision, reason, and phase taxonomy

`Decision` remains allow, allow restricted, deny, unsupported, or retry.
`ReasonCode::None` is removed. `VerificationOutcome::reason()` returns `None`
for either allow and `Some(reason)` for every unsuccessful outcome.

| Decision | Reason codes |
| --- | --- |
| `Allow` | none |
| `AllowRestricted` | none |
| `Deny` | `Malformed`, `ChallengeAuthenticationFailed`, `NotYetValid`, `Expired`, `ReplayDetected`, `ContextBindingMismatch`, `EvidenceInvalid`, `PolicyDenied`, `Revoked`, `ProtectedSessionLost` |
| `Unsupported` | `UnsupportedVersionOrProfile`, `UnsupportedPlatform`, `UnsupportedCriticalRequirement` |
| `Retry` | `AttestationUnavailable`, `TransientFailure` |

Reasons contain no strings, raw evidence, nested details, or accusation.
`ContextBindingMismatch` intentionally avoids disclosing which context leaf
differed. Enums remain exhaustive and select no wire values.

Phase eligibility is:

| Current phase | Eligible observations |
| --- | --- |
| `EvidenceReceived` | malformed; challenge authentication failed; unavailable; transient; unknown critical requirement |
| `ChallengeAuthenticated` | unsupported version/profile; not yet valid; expired; replay; context mismatch; unavailable; transient; unknown critical requirement |
| `FreshnessChecked` | identity/context mismatch; unavailable; transient; unknown critical requirement |
| `IdentityChecked` | unsupported platform; evidence invalid; unavailable; transient; unknown critical requirement |
| `EvidenceAppraised` | session/context mismatch; protected-session lost; unavailable; transient; unknown critical requirement |
| `SessionBound` | revoked; protected-session lost; unavailable; transient; unknown critical requirement |
| `RevocationChecked` | policy denied; protected-session lost; unavailable; transient; unknown critical requirement |
| `PolicySatisfied` | protected-session lost; unavailable; transient; unknown critical requirement |

This intentionally refines ADR-0007's rule that every failure action succeeds
from every nonterminal. Existing terminal permanence and fail-closed behavior
remain. The finite oracle must use new independently derived counts.

## Errors and diagnostics

Existing transition errors remain structurally accurate:

```text
InvalidTransition { safe phase, safe action }
CapabilityRejected { safe action }
```

Phase-ineligible reason actions return `InvalidTransition` without mutation.
No generic result-construction error exists because there is no public result
constructor.

Default diagnostics for result, claims, view, flow, capabilities, and errors
are fixed/redacted where values are sensitive.
Fieldless decision, reason, phase, and action names remain safe.

## Privacy and retention

An active state owns the request only until terminal replacement. On success,
exact context and allowed claims move into `VerifiedAttestation`; on failure,
only exact context moves into the returned Appraisal Result. Staged accepted
claims are discarded at every failure. Success also moves the flow's sole
attempt binding into `VerifiedAttestation`; failure releases it before return.
Terminal flows retain no binding, replay registration, or attempt allocation.

An Appraisal Result retains correlation and, for allows, profile and key handle.
It has no intrinsic expiry and cannot enforce deletion or secure erasure. Future
protected-result transport/storage work must define finite retention,
confidentiality, deletion, and backup behavior.

Default diagnostics exclude identifier values, timestamps, policy duration,
profile sentinels, key bytes, evidence, binding identity, allocation details,
paths, control text, and CI commands. Explicit accessors are trusted functional
interfaces, not logging surfaces.

Registered scenario owner `initial-maintainer` is the accountable privacy-review
gate before expanding any result context/claim field, diagnostic surface,
serializer/wire adapter, persistence/storage/backup path, or logging/telemetry
path.

## Verification design

### Re-frozen finite model

Phase eligibility changes the M1-010 action semantics. The implementation plan
must independently enumerate the complete typed action set, then freeze exact
phase/action success and rejection counts before runtime edits. It must also
re-freeze the deterministic history schedule and coverage counters. The old
`48/134` counts cannot be copied forward.

The seven-gate canonical ordering, 5,040 permutations, seven omissions,
phase-before-binding behavior, and equal-flow capability rejection remain
required and should retain their existing independent detectors.

### Result and eligibility evidence

- Both allows carry exact context, profile, key handle, and class.
- Every reason appears only under its permitted decision and phases.
- Every ineligible reason preserves the entire active state.
- Every failure after claim-bearing phases exposes no accepted claims.
- Public reports/views cannot construct or mutate an Appraisal Result.
- Mixed payload/right-binding substitution is recorded as TCB risk, while
  wrong-binding capability substitution remains mechanically rejected.

### Compile-time, structural, and mutation evidence

Separate compile-fail cases reject result literals, private fields, cloning,
copying, accepted-claim construction, report conversion, refill methods,
repeat conversion, and result-to-permit/admission shortcuts.

Structural tests pin whole-state ownership so no nonterminal can lack request or
cumulative claims. Exact non-vacuous sentinels cover every diagnostic aggregate.

Before implementation, freeze one-cause mutations for every mapping,
eligibility guard, claim payload/transfer/discard, terminal replacement,
authority field, one-use path, and redaction surface. Only
an intended semantic detector failure counts; syntax, zero-test, timeout-only,
or unrelated failures do not.

No parser fuzzer or differential decoder is added because this issue creates no
wire or untrusted byte surface.

### Scenarios and reviews

Implementation extends existing gate-skip, capability-substitution, and
verifier-diagnostics scenarios for result forgery, wrong-capability
substitution, claim discard, phase-ineligible reporting, and redaction. It does
not duplicate those threat families.

Normal and optimized workspace checks, every frozen mutation, and fresh
separate trusted-computing-base and privacy reviews must pass before publication.

## Documentation and traceability

Implementation updates architecture, threat model, roadmap, test strategy,
ADR-0007's refined failure rule, ADR-0009 status/index, existing scenarios, and
lessons learned for confirmed defects. The roadmap must keep responsibilities
accurate:

- M1-011 defines Appraisal Result shape and taxonomy.
- M1-012 defines binding-transcript inputs without choosing cryptography.
- M2 protocol issues choose commitment, protection, wire, and validation.

The local issue is the canonical scope/acceptance source. This approved design
is the interface/rationale artifact. The implementation plan owns exact edit
order, new oracle counts, mutation inventory, and commands.

## Alternatives considered

### Reuse `AttestationResult` for the semantic value

Rejected. Architecture already uses that name for a signed output containing an
evidence digest, verifier identity, and signature. Reuse creates incompatible
meanings at the future protection seam.

### Public builder or flat optional structure

Rejected. It redistributes validation to callers and permits contradictory
shapes, unrelated refill, missing claims, and claims on failure.

### Generic extensible claims

Rejected. Maps, strings, arbitrary bytes, or downstream traits expand the
fixed privacy vocabulary and preempt protocol versioning.

### Pull result after terminal entry

Rejected. A later `take` adds not-terminal/already-taken states and separates
failure from the transition that caused it.

### Issued-at and expiry in Appraisal Result

Rejected after adversarial review. M1 has no fresh authoritative terminal-time
observation or trusted issuance policy boundary. Supplying a window during
completion merely moves stale refresh to `PolicySatisfied`; deriving it from
the earlier freshness observation mislabels appraisal time as issuance time.
The future protected-result issuer must bind validity with commitment, verifier
identity, and integrity protection.

### Every reason from every nonterminal

Rejected after adversarial review. It permits semantically false histories.
Typed phase eligibility refines ADR-0007 and requires new oracle counts.

### Separate accepted policy

Rejected. `ExpectedContext` authorizes one policy. A second value is redundant
or permits substitution; restricted is a class under the selected policy.

### Commitment bytes or marker in M1-011

Rejected. Bytes require meaning and bounds; a marker is not a commitment.
M1-012 defines transcript inputs and later M2 work chooses protection details.

### Claim payload provenance from capability binding

Rejected as an overclaim. Binding proves capability association. Copyable claim
truth remains a trusted-producer obligation until cryptographic commitment and
protected result validation exist.

### Cloneable Appraisal Result

Rejected. The future protection design should start from one-use success
provenance. Protected serialized results may later be copied under their own
replay/validity rules.

## Primary sources

- [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html), especially sections
  3, 4.2, 5.1, and 11, defines verifier result production, separate relying-
  party appraisal, transport-format separation, and privacy risk.
- [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html), especially sections
  1.3.1 and 10.5, makes result claims verifier-policy-governed and distinguishes
  attestation accompanying PoP from the PoP transaction.
- [Rust 1.98 visibility and privacy](https://doc.rust-lang.org/1.98.0/reference/visibility-and-privacy.html)
  supports opaque public structs, private fields, and confined helpers.
- [Rust 1.98 ownership](https://doc.rust-lang.org/1.98.0/book/ch04-01-what-is-ownership.html)
  supports by-value one-use capability consumption.
- Project security invariants, architecture, threat model, roadmap, ADR-0004,
  ADR-0005, ADR-0007, and ADR-0008 define OGIR-specific authority, freshness,
  policy, key-handle, and privacy obligations.

These sources were freshly retrieved from the RFC Editor and Rust 1.98
documentation on 2026-08-28 before this candidate was prepared.

## Review and execution gate

The decision owner approved this file, local issue, glossary, and Proposed ADR
as exact candidate tree `bc015648a08f10de543b764d8333baaf6e423114` on
2026-08-28. The required writing-plans workflow may now produce a separately
reviewed implementation plan. No runtime edit begins until that plan is approved.

The plan must be negative-test-first, derive and freeze new finite-model counts
and mutation probes before runtime implementation, preserve retained
worktrees/backups, and stop at human gates for issue publication, DCO, push, PR,
and merge.
