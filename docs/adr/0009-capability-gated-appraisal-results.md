# ADR-0009: Capability-gated Appraisal Results

- Status: Accepted
- Date: 2026-08-28
- Owners: Initial maintainer
- Related issues: [M1-011](../../planning/issues/011-result-reason-code-taxonomy.md)
- Supersedes: None
- Superseded by: None

## Context

ADR-0007 leaves one process-local `VerifiedAttestation` after the complete
verifier graph, but defines no semantic outcome or verified-claim payload.
Public `Decision`, `ReasonCode`, and `VerificationOutcome` values are reports and
cannot prove appraisal occurred. Later work must not combine an allow report
with raw fields from an unrelated request.

`docs/ARCHITECTURE.md` reserves `AttestationResult` for the future signed
verifier output containing an evidence digest, verifier identity, and signature.
The pure M1 semantic value needs a distinct name and must remain explicitly
outside that protected-result contract.

The current all-failure-actions-from-all-nonterminals rule also allows reasons
to claim checks that cannot occur in the current phase. M1 has no authoritative
terminal-time issuance boundary, so protected-result validity must remain later.

## Decision drivers

- Preserve exact-attempt seven-gate success authority from ADR-0007.
- Make contradictory outcome shapes impossible rather than caller-validated.
- Keep relying-party context authoritative and prevent post-terminal refill.
- Keep restricted success bound to the preselected policy.
- Make reason observations consistent with verifier gate order.
- Distinguish failure classes without raw evidence or accusation.
- Defer commitment/protected-result behavior to its actual roadmap owners.
- Add no crypto, encoding, parser, adapter, dependency, I/O, or `unsafe`.

## Options considered

### Opaque discriminated Appraisal Result with capability-gated allow

Selected. It centralizes context movement, typed claim accumulation, valid
mappings, phase eligibility, claim exclusion, and redaction.

### Reuse `AttestationResult`

Rejected. That name already denotes the protected signed architecture object.

### Public builder or flat optional fields

Rejected. These require every caller to recheck authority, completeness,
context provenance, mapping, and claim exclusion.

### Generic claim map

Rejected. It expands the fixed claim vocabulary and chooses extension behavior.

### Every reason from every nonterminal

Rejected. It permits false gate histories and ambiguous diagnostics.

### Evidence commitment as bytes or marker

Rejected. Bytes require representation/algorithm semantics; a marker is not a
commitment. M1-012 defines only semantic binding-transcript inputs. Later M2
work selects commitment representation, algorithms, integrity protection, and
wire behavior.

## Decision

`ogir-verifier` owns one opaque, non-cloneable, non-copyable
`AppraisalResult`. Every value contains exact relying-party `ExpectedContext`
and one private discriminated payload.

Full and restricted allow payloads contain exact-attempt-associated accepted
`EvidenceProfile` and `SessionPublicKeyId` values. They have no reason.
Unsuccessful payloads contain no accepted claims and exactly one valid,
phase-eligible `Decision`/`ReasonCode` mapping.

`VerifierFlow::complete()` terminal-first replaces the whole active state and
returns `VerifiedAttestation`. Consuming
`VerifiedAttestation::into_appraisal_result()` accepts no refill input and is
the only allow path. Eligible failure actions use the same terminal-first whole-
state replacement and return one unsuccessful Appraisal Result. Every terminal
remains permanent and issues at most once.

The exact policy in `ExpectedContext` binds both allow classes. Restricted means
that policy selected restricted gameplay, not a replacement policy or fallback.

Reason absence is structural: `ReasonCode::None` is removed. Allowed reports
return no reason; unsuccessful reports return one of fifteen coarse reasons.
The denial action accepts only challenge-authentication failure, time-window,
replay, context-binding, evidence, policy, and protected-session-loss reasons;
malformed and revoked remain confined to their dedicated actions.
Reason eligibility follows the gate where the observation can occur, refining
ADR-0007's prior all-failures-from-all-phases contract. New finite-model counts
must be independently derived before implementation.

Capability allocation identity proves exact-flow association, not
cryptographic truth of cloneable/copyable claim payloads. Trusted producers
remain responsible for payload truth. Publicly produced unsuccessful Appraisal
Results are report shapes, not sufficient provenance for a future signer.

An Appraisal Result has no issued-at/expiry and is unsigned. It grants no
protected Attestation Result, permit, proof, admission, or disciplinary
authority. M1-012 defines transcript inputs without choosing crypto; later M2
work selects commitment, signature, wire, and validation behavior.

## Consequences

Future work receives a small semantic outcome interface with valid shape and
one-use allow construction. Phase-specific reasons cannot be emitted from
unrelated gates, and failure paths retain no accepted claims.

The change is source-breaking for `ReasonCode::None`, reason access,
failure-transition results, claim-bearing capabilities, flow-private state, and
the old finite oracle. OGIR is a research scaffold; resolving these semantics
before stable wire/API commitments is deliberate.

The pure types do not establish cryptographic payload provenance, trusted
failure provenance, signer behavior, intrinsic expiry, deletion, secure
erasure, or operational policy selection. Those remain explicit later
obligations.

## Threat-model impact

This narrows A1/API misuse and accidental orchestration paths that forge an
allow shape, refill context, substitute a wrong-flow
capability, retain claims on failure, or report a reason from an impossible
phase. It narrows A8 diagnostic disclosure through fixed redaction and coarse
reasons.

A deliberately compromised gate producer, verifier, policy service, or future
issuer remains A5 residual risk. A producer can copy or lie about claim payloads
inside a correctly bound capability. This decision adds no signature,
commitment, key resolution, PoP, or admission validation.

## Privacy impact

Every Appraisal Result retains context; allows also retain profile and a
correlation-sensitive key handle. Default diagnostics redact those values.
Explicit accessors remain trusted functional interfaces.

Unsuccessful outcomes discard staged accepted claims. Reasons are fixed,
coarse, non-disciplinary values with no free text or evidence details. The type
has no intrinsic expiry and does not enforce deletion or secure erasure. Future
protected-result transport/storage work must define confidentiality and finite
retention.

## Dependency and license impact

The decision uses existing workspace types and standard Rust ownership/privacy.
It adds no package, transitive dependency, feature, parser, serializer,
cryptographic primitive, I/O, network, persistence, `unsafe`, or license change.
Existing Apache-2.0 boundaries remain unchanged.

## Validation

### Current M1-011 implementation evidence

The implemented independent model exhausts 14 phases × 24 semantic actions =
336 pairs. Nine gate/completion edges plus 41 phase-eligible failure edges give
exactly 50 successes and 286 state-preserving rejections; the complementary
failure table contains exactly 79 ineligible cells. Direct typed failure results
are compared by exact context, decision, reason, and borrowed view. Successful
completion compares exact context, accepted profile, session-key handle, and
full or restricted class before consuming the sole allow capability.

All 7! = 5,040 gate permutations, seven omissions, seven equal-data wrong-flow
capability substitutions, phase-before-binding behavior, and all six terminal ×
24 action cells remain covered. The deterministic history schedule is exactly
`256 + 864 + 576 + 35 + 312 + 5 = 2,048`, followed by 1,046,528 arbitrary
fixed-seed actions, for exactly 1,048,576 oracle-checked actions. Complete result
and state equality is required before coverage counters advance.

Structural and compile-fail evidence pins whole active-state ownership,
terminal-first replacement, sole consuming allow construction, exact failure
entry points, fixed redaction, and the distinction between flow association and
payload provenance. These source-token proofs intentionally enforce a closed
current inventory and do not claim Rust-parser completeness, macro-expansion
semantics, cryptographic authenticity, or secure erasure.

The implementation plan freezes exactly 154 one-cause mutations for authority,
eligibility, mapping, claim transfer/discard, terminal, one-use, and redaction
paths. That Task 10 campaign and its separate fresh TCB/privacy reviews remain
required; this ADR does not claim they are complete.

Normal and optimized all-feature checks plus fresh independent TCB and privacy
reviews must pass before publication. No byte fuzzer is added because there is
no wire/parser.

## Rollback

Before implementation, reversal requires the decision owner to reject or
supersede this Accepted ADR and update the matching design artifacts. After
merge, changing outcome authority, context
binding, claim shape, policy binding, phase eligibility, terminal replacement,
mapping, or diagnostics requires an ADR update or superseding ADR plus matching
model, mutation, privacy, threat, and scenario tests.

A public allow builder, claims on failure,
policy substitution, impossible-phase reasons, or value-less commitment is not
an acceptable rollback.

## Primary sources

- [Approved M1-011 design](../superpowers/specs/2026-08-28-m1-011-appraisal-result-design.md)
  records the approved project-specific boundary.
- [RFC 9334 sections 3, 4.2, 5.1, and 11](https://www.rfc-editor.org/rfc/rfc9334.html)
  define verifier result production, relying-party appraisal, serialization
  separation, and privacy risk.
- [RFC 9711 sections 1.3.1 and 10.5](https://www.rfc-editor.org/rfc/rfc9711.html)
  define verifier-policy-governed result claims and separate attestation from
  an accompanying PoP transaction.
- [Rust 1.98 visibility and privacy](https://doc.rust-lang.org/1.98.0/reference/visibility-and-privacy.html)
  supports opaque public types with private construction state.
- [Rust 1.98 ownership](https://doc.rust-lang.org/1.98.0/book/ch04-01-what-is-ownership.html)
  supports by-value one-use capability consumption.
- ADR-0004, ADR-0005, ADR-0007, and ADR-0008 define publisher authority,
  freshness, exact-attempt capability, and key-handle boundaries.
