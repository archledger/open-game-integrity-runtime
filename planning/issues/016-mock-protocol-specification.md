# M2-016: Specify the mock end-to-end attestation protocol
<!-- labels: type: architecture,area: protocol,area: verifier,risk: trusted-computing-base,status: needs-review -->
<!-- milestone: M2 Mock Protocol -->

Status: Local integration candidate; no live GitHub issue yet. Human design approval received on 2026-09-05, including the default resolutions recorded in the approved design.

## Problem

Milestone M1 is complete at `62fe2584` (static exit-criteria audit recorded
with this slice's scoping evidence). M2 must prove challenge, evidence,
verifier, permit, and session-key binding with test-only software keys
before any production serialization or signature library is selected (M2
design gate). The workspace has the semantic substrate (ADRs 0010-0014, the
verifier capability flow, the replay cache) but no concrete
binding-transcript encoding, no abstract schemas for signed challenge, mock
evidence, and permit, no specified test-only key hierarchy, and no home for
the twelve required M2 attack-test categories. Implementation slices cannot
be reviewed against a stable contract until that specification exists.

The approved specification is recorded in the
[mock protocol design](../../docs/superpowers/specs/2026-09-05-m2-016-mock-protocol-specification-design.md),
[ADR-0015](../../docs/adr/0015-mock-binding-transcript-encoding.md), and
[ADR-0016](../../docs/adr/0016-test-only-ephemeral-key-hierarchy.md). Those
documents are the detailed scope authority for review; this issue summarizes
them.

## Security invariants

- Enforce the design gate: no production serialization or signature library
  selection occurs in this slice or is implied by its artifacts.
- Preserve M1 exit criterion 1: `ogir-model` gains no dependencies, types,
  or authority changes.
- Every specified field carries an explicit trust source consistent with
  the trust model; no client-supplied field becomes authoritative.
- Domain separation is explicit per message class (challenge, evidence,
  permit, proof, revocation view) so no transcript bytes are valid in
  another role.
- The test-only key hierarchy is labeled and structured so it can never be
  confused with production attestation identity (M3 remains the earliest
  point where TPM-backed identity appears).

## Threats addressed

None directly. This slice produces specifications only and changes no
runtime trust boundary or attacker capability. It exists to prevent by
construction the M2 failure modes of transcript substitution between message
classes, unspecified field trust, and premature production-library
commitment.

## In scope

- ADR-0015: concrete test-only binding-transcript format with explicit
  domain separation (field order, encoding rules, per-class separation
  tags, ambiguity analysis, frozen per-class field registries).
- ADR-0016: test-only ephemeral software key hierarchy (verifier test
  signing key, test attester key, ephemeral session key; generation,
  deterministic derivation, lifetime, non-production labeling) and the
  in-repo-shim-versus-test-dependency decision recorded against `deny.toml`
  policy.
- Protocol document extension: abstract schemas for signed challenge, mock
  evidence, and permit messages, the proof-of-possession contract, and the
  `MessageKind` allocation plan (values, framing bounds,
  unknown-critical-field rule).
- Attack-test placement mapping each of the twelve roadmap attack-test
  categories to the M2-017 through M2-019 implementation slices that will
  host it.
- Slice charters for M2-017/018/019 sufficient for later scoped issues.
- Static M1 exit-criteria audit summary referenced from the design record.

## Out of scope

- Any change under `crates/`, `apps/`, or `scripts/` (including
  `MessageKind` itself; this slice only plans its extension).
- Any new dependency, crate, feature, or workspace manifest change,
  including `ogir-mock-keys` itself (specified here, implemented in M2-017).
- Any production serialization or signature library selection (design
  gate).
- Permit, proof-of-possession, policy-interface, conformance-vector, or CLI
  implementation (later slices).
- Any change to the replay cache beyond naming its M2-018 integration
  points.
- Lab scenario JSONs: the M1-013 checker validates closed scenario
  inventories, not protocol prose, and no encoder exists yet to check
  against; encoding properties become machine-checkable in M2-017.

## Primary sources

- `docs/ROADMAP.md` Milestone M2 (objective, deliverables, attack tests,
  exit criteria, design gate) at the baseline.
- ADRs 0005, 0007-0014 for the authority, transcript, temporal, replay,
  and renewal/revocation semantics the format must express.
- `docs/TRUST_MODEL.md` evidence-binding transcript authorities.
- `crates/ogir-protocol/src/lib.rs` framing primitives and
  `crates/ogir-verifier/src/verification.rs` `ExpectedContext`.
- `deny.toml` dependency policy for the key-hierarchy options analysis.

## Required interfaces

- None changed. This slice adds documentation and ADRs only. The ADRs
  state, not imply, every interface obligation they create for
  M2-017/018/019.

## Positive tests

- Documentation consistency gates: every schema field in the ADR/protocol
  extension maps to exactly one named trust source; every domain-separation
  tag is enumerated; every attack-test category maps to exactly one owning
  slice; both ADRs carry every template section; the ADR index rows are
  added.
- Mechanical gates: zero em dashes, balanced code fences, no trailing
  whitespace in new sections, valid relative links.

## Negative tests

- The ADR must show, by construction, that transcript bytes from one
  message class fail validation in every other class (domain-separation
  proof obligation written into ADR-0015's validation section for M2-017
  to later verify mechanically).
- No example, diagram, or normative sentence may present a client-supplied
  value as authoritative or a local boolean as trusted.

## Fuzz/property tests

- None in this slice (no code). The design record specifies the properties
  the later slices hold fixed: transcript determinism, separation-tag
  disjointness, replay-cache key derivation stability under ADR-0013.

## Privacy impact

- None. Specifications only; no data handling changes. The ADRs restate the
  redaction rules (nonce, key, and claim-value debug redaction) as
  obligations on the implementing slices.

## Dependency impact

- None. Zero manifest changes. ADR-0016 recommends an in-repo test-only
  shim precisely to keep it that way until the post-M2 production
  selection ADR.

## Acceptance criteria

- ADR-0015 and ADR-0016 accepted by the human reviewer with no open
  findings and merged via the standard SDD publication flow.
- The protocol document extension and the attack-test-to-slice mapping
  accepted in the same review.
- The M1 completion record (static exit-criteria audit) is referenced from
  the design record so M1 closes formally with M2-016.

## Current state

- 2026-09-05: Approved design integrated as documentation-only candidate in
  the `docs/m2-016-mock-protocol-specification` worktree: ADR-0015,
  ADR-0016, ADR index rows, protocol extension, threat/privacy/test/
  architecture/roadmap cross-links, lessons entry, this issue, and the
  design record. Awaiting human contribution review, signed commit
  authorization, and separately authorized publication.
