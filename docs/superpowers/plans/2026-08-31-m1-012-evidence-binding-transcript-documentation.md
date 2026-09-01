# M1-012 Evidence-binding Transcript Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the approved M1-012 semantic evidence-binding transcript contract as repository documentation, one accepted ADR, and machine-readable attack scenarios without selecting a representation, cryptographic mechanism, or runtime API.

**Architecture:** Keep `EvidenceBundle` as the external profile-specific carrier and define one closed semantic transcript reconstructed independently by the verifier from authenticated challenge semantics, registered profile semantics, decoded claims and provenance, the actual session public key plus its lookup handle, and profile-required evidence-time semantics. Record this as a documentation-only contract now; runtime representation, coverage verification, protected-result issuance, and all cryptographic choices remain blocked by explicit prerequisites.

**Tech Stack:** Markdown, JSON Schema draft 2020-12 scenario documents, Bash repository gates, Cargo workspace verification.

**Spec:** `docs/superpowers/specs/2026-08-31-m1-012-evidence-binding-transcript-design.md`

## Global Constraints

- Delivery is documentation-only: do not modify Rust source, Cargo manifests, lockfiles, shell gates, CI workflows, dependencies, generated artifacts, or wire formats.
- `EvidenceBundle` remains outside the evidence-binding transcript as the profile-specific carrier of claims and proof material.
- The complete typed `PublisherChallenge` semantics are one transcript input; no challenge digest, copied subset, or second challenge structure is introduced.
- `ExpectedContext` remains outside the transcript as an independent relying-party comparator.
- The actual session public key and `SessionPublicKeyId` are both transcript inputs; the private key is never an input or disclosed value.
- Every profile requires all eight Base claim meanings and may add only the two profile-specific claim meanings defined by the spec.
- Every required claim appears semantically exactly once with exactly one registered provenance class.
- Manifest and measurement identities are semantic algorithm-and-value identities, not opaque commitment markers or untyped digest bytes.
- The attester constructs and covers one transcript; the verifier independently reconstructs it from trusted and received sources before checking coverage and appraising claims.
- Initial appraisal and same-session renewal each create a fresh evidence-binding transcript; renewal authorization remains separate. Key/handle reuse is allowed only for an unchanged publisher, protected session, and live subject in the existing lifecycle, with non-weakened policy, current claims, and accepted new evidence time. Profile identity and exact selected-policy identity need not remain unchanged.
- Semantic domain separation is mandatory, but literal labels, numeric tags, canonical bytes, and cryptographic algorithms are deferred to later M2 work.
- The evidence-time producer, clock/epoch, validity, rollback, restart, renewal, and privacy contract is an unresolved prerequisite; do not imply that `PublisherChallenge.issued_at`, verifier evaluation time, or client wall-clock time satisfies it.
- Do not create a branch, commit, issue, pull request, release, DCO certification, publication, remote mutation, or GitHub mutation without separate explicit authorization.
- Preserve the detached worktree base at exact `origin/main` commit `a82bdbc3e84963b0958cdf215a60dbd5d2d3d685`; do not reconcile the intentionally divergent local `main`.

---

### Task 1: Canonical M1-012 Planning Issue Contract

**Files:**
- Create: `planning/issues/012-evidence-binding-transcript-inputs.md`
- Reference: `docs/superpowers/specs/2026-08-31-m1-012-evidence-binding-transcript-design.md`

**Interfaces:**
- Consumes: the approved semantic definitions, trust-source matrix, exclusions, validation matrix, and evidence-time prerequisite from the spec.
- Produces: the canonical local M1-012 issue contract that later documentation and scenario tasks cite; it creates no live GitHub issue.

- [ ] **Step 1: Write the issue-contract review assertions before creating the issue**

Run this source assertion and retain its expected failure as the red checkpoint:

```bash
test -f planning/issues/012-evidence-binding-transcript-inputs.md
```

Expected: exit status `1` because the local issue contract does not yet exist.

- [ ] **Step 2: Create the issue heading, repository metadata comments, and problem statement**

Create `planning/issues/012-evidence-binding-transcript-inputs.md` beginning with exactly this metadata and semantic problem statement:

```markdown
# M1-012: Define evidence-binding transcript inputs without choosing cryptography
<!-- labels: type: architecture,type: documentation,area: model,area: verifier,area: privacy,risk: trusted-computing-base,risk: privacy,status: ready -->
<!-- milestone: M1 Domain Model -->

## Problem

OGIR has typed challenge, evidence-profile, evidence-carrier, expected-context,
and session-key-handle values, but it does not yet define the complete semantic
claim set that one evidence mechanism must cover for one appraisal attempt.
Without that contract, an implementation can underbind a challenge field,
accept an incomplete or invented claim set, lose claim provenance, substitute a
manifest identity, treat a lookup handle as key authority, or silently reuse
evidence for another protocol purpose.

The canonical domain term is **Evidence-binding transcript**. It is a closed
semantic value, not a byte serialization. `EvidenceBundle` remains the external
profile-specific carrier of claims and proof material. The attester constructs
and covers one transcript; the verifier independently reconstructs the expected
transcript before checking profile coverage and appraising claims.

On 2026-08-31, the decision owner approved candidate specification SHA-256
`60fb29682e939d1b259b84033c113b3096a9e734541b5a0634e8733deebfe591`
without a requested semantic change. That approval permits this
documentation-only contract and plan; it does not authorize runtime code,
cryptographic selection, a commit, or a live GitHub mutation.
```

- [ ] **Step 3: Add exact invariants, scope, and trust-source sections**

Add `## Security invariants`, `## In scope`, `## Out of scope`, and `## Trust sources` sections. They must state all of the following as normative bullets:

```markdown
- Changing any transcript semantic causes profile coverage validation to fail.
- The complete authenticated `PublisherChallenge` is bound as one typed
  semantic aggregate, including its `ProtocolVersion`.
- `ExpectedContext` is an independent comparator and is never copied into the
  transcript as evidence.
- Both the actual session public key and `SessionPublicKeyId` are bound; the
  handle alone is not key authority.
- Every registered profile requires all Base claims and may add only declared
  profile-specific claims from the fixed OGIR vocabulary.
- Every required claim appears semantically exactly once with one registered
  provenance class.
- Manifest and measurement identities include their semantic namespace,
  algorithm identity, and value.
- Initial appraisal and same-session renewal each use the fixed evidence-binding
  purpose; renewal authorization is a separate semantic purpose.
- A transcript is evidence input, not an Appraisal Result, protected result,
  permit, admission decision, or disciplinary signal.
- Transcript values and proof material are confidential by default and absent
  from ordinary diagnostics.
```

The scope must include terminology, the external carrier relationship, the complete input set, fixed claim vocabulary, provenance, semantic manifest identity, construction/reconstruction, lifecycle relationships, validation cases, ADR, and scenarios. The exclusions must name Rust types, serializers, canonical bytes, numeric discriminants, hash/signature/MAC/KDF algorithms, TPM command layouts, public-key encodings, proof formats, protected-result signing, permits, telemetry, networking, storage, and dependencies.

The trust-source section must assign authenticated challenge semantics to the publisher challenge issuer and verifier, expected context to the relying party, private-key ownership to the trusted local key owner, profile claims to registered trusted evidence producers, transcript construction to the attester, reconstruction and appraisal to the publisher verifier, and protected-result validity to a future issuer.

- [ ] **Step 4: Add the closed claim vocabulary and required relationship contract**

Add one `## Required interfaces` section, treating “interfaces” as semantic contracts rather than Rust APIs. Include the exact Base claim names:

```text
Attesting agent identity
Platform identity
Boot measurement identity
Runtime manifest identity
Game manifest identity
Process binding identity
Protected-session identity
Enforcement policy state
```

Include the exact profile-specific vocabulary:

```text
Attestation identity
Runtime measurement identity
```

State that profiles may add these meanings only through an immutable registered contract, cannot rename or redefine them, cannot make required claims optional at runtime, and cannot use an arbitrary extension map.

Add `## Required relationships` with separate subsections for initial appraisal and same-session renewal. Initial appraisal binds one challenge, one profile, one actual public key and handle, one evidence-time statement, and one complete claim/provenance set. Renewal constructs a fresh transcript with a fresh complete challenge, current claims, and accepted new evidence time; conditional key/handle reuse follows the unchanged publisher/session/live-subject, existing-lifecycle, non-weakened-policy, current-claims, and accepted-time rules, while profile identity and exact selected-policy identity need not remain unchanged. Old evidence never becomes new-context authorization.

Add `## Failure semantics` stating that M1-012 adds no decision, reason code, denial variant, or verifier state. Map malformed transcript shape to `Malformed`, unsupported profiles or unknown critical semantics to `Unsupported`, challenge/context disagreement and key/session association disagreement to coarse `ContextBindingMismatch`, coverage or provenance failure to `EvidenceInvalid`, trusted-authority unavailability to `Retry` or `AttestationUnavailable`, and session loss to `ProtectedSessionLost`. State that an absent evidence-time contract blocks implementation and has no permissive runtime mapping. Every failure remains non-disciplinary, and a failure after atomic freshness claim consumes the challenge.

- [ ] **Step 5: Add evidence-time blocker, required tests, acceptance criteria, and references**

Add an explicit `## Evidence-time prerequisite` section with this boundary:

```markdown
The producer, authority, clock or epoch, validity model, skew rule, rollback and
restart behavior, renewal behavior, and privacy treatment for evidence creation
time are not yet approved. No runtime transcript representation or coverage
validator may be designed as final until that prerequisite is resolved.
`PublisherChallenge.issued_at`, verifier evaluation time, and client wall-clock
time are not substitutes.
```

Add `## Required tests` listing the positive reconstruction cases and every single-change negative family from the spec: challenge field/version, profile, claim omission/duplication/invention, provenance, actual key, key handle, manifest namespace/algorithm/value, evidence-time field, cross-context reuse, renewal-purpose confusion, result/permit domain confusion, and time-source substitution.

Add `## Acceptance criteria` requiring exact challenge coverage, closed claim sets, exact-once claim semantics, dual key binding, semantic manifest identities, independent verifier reconstruction, domain separation, M1-011-compatible non-disciplinary failure mapping, diagnostics exclusion, scenario coverage, ADR traceability, and an explicit unresolved evidence-time prerequisite.

Add `## Primary sources` citing ADR-0005, ADR-0007, ADR-0008, ADR-0009, the M1-012 design spec, [IETF RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html) for RATS roles and appraisal boundaries, and [IETF RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html) for profile-governed claims, freshness, and proof-of-possession separation. Cite `docs/SECURITY_INVARIANTS.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, and `docs/AI_DEVELOPMENT_POLICY.md` as project authorities; state that M1-012 adopts no TPM wire or algorithm choice.

- [ ] **Step 6: Verify the issue contract independently**

Run:

```bash
test -f planning/issues/012-evidence-binding-transcript-inputs.md
grep -F 'status: ready' planning/issues/012-evidence-binding-transcript-inputs.md
grep -F 'Evidence-time prerequisite' planning/issues/012-evidence-binding-transcript-inputs.md
grep -F 'actual session public key' planning/issues/012-evidence-binding-transcript-inputs.md
grep -F 'arbitrary extension map' planning/issues/012-evidence-binding-transcript-inputs.md
git diff --check -- planning/issues/012-evidence-binding-transcript-inputs.md
```

Expected: every `grep` prints one matching line, and both `test` and `git diff --check` exit `0`.

- [ ] **Step 7: Record a non-mutating review checkpoint**

Run:

```bash
git diff -- planning/issues/012-evidence-binding-transcript-inputs.md
git status --short
```

Expected: only an uncommitted local documentation artifact is added by this task. Treat the file as the exact proposed live-issue body; live issue creation and post-creation body comparison remain a separate authorization gate. Do not commit or create the issue without separate authorization.

---

### Task 2: Domain, Architecture, Protocol, Trust, and Roadmap Alignment

**Files:**
- Modify: `CONTEXT.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/PROTOCOL.md`
- Modify: `docs/TRUST_MODEL.md`
- Modify: `docs/ROADMAP.md`
- Reference: `planning/issues/012-evidence-binding-transcript-inputs.md`

**Interfaces:**
- Consumes: the canonical semantic terms and trust assignments from Task 1.
- Produces: one repository-wide domain and authority description used by threat, testing, ADR, and scenario documentation.

- [ ] **Step 1: Capture the missing-term red checkpoint**

Run:

```bash
grep -F 'Evidence-binding transcript' CONTEXT.md
```

Expected: exit status `1` before the canonical term is introduced.

- [ ] **Step 2: Add the semantic transcript to canonical context**

In `CONTEXT.md`, add `Evidence-binding transcript`, `Evidence carrier`, `Profile contract`, `Semantic identity`, `Coverage`, and `Key association` to the canonical domain language. Define this conceptual shape without assigning a Rust type or serialization:

```text
Evidence-binding transcript
  purpose: OGIR evidence binding
  complete PublisherChallenge semantics
  registered EvidenceProfile semantics
  actual session public key
  SessionPublicKeyId
  profile-required evidence creation and validity semantics
  exact closed profile-required claims
  exact provenance class for every claim
  semantic manifest and measurement identities
```

State directly below the shape:

```markdown
`EvidenceBundle` carries profile-specific claims and proof material but is not
inside the transcript. `ExpectedContext` remains independently supplied by the
relying party. Transcript equality is semantic equality; no byte encoding,
field order, digest, or cryptographic algorithm is selected here.
```

State that initial appraisal and same-session renewal each create a new evidence-binding transcript with a fresh complete challenge; evidence binding remains distinct from renewal authorization. Add a concise Base/profile-specific claim table using the exact claim meanings from Task 1. Add the provenance classes `hardware-certified`, `measured-log-derived`, and `trusted-agent-observed`, and require the profile contract to register exactly one permitted class for each claim.

- [ ] **Step 3: Add construction, reconstruction, and boundary flow to architecture**

In `docs/ARCHITECTURE.md`, add a subsection named `### Evidence-binding transcript boundary` in the verifier/evidence flow. Include this exact directional model:

```text
publisher challenge issuer -> authenticated PublisherChallenge
relying party -> independent ExpectedContext
trusted local key owner -> actual session public key + SessionPublicKeyId
trusted evidence producers -> registered claims + provenance
attester -> constructed semantic transcript + external EvidenceBundle
publisher verifier -> independently reconstructed transcript
publisher verifier -> coverage validation, then claim appraisal
future protected-result issuer -> separately protected result
```

State that the verifier must reject before successful appraisal if any required semantic is absent, duplicated, invented, reclassified, or unequal. State that carrier parsing, transcript reconstruction, coverage validation, claim appraisal, expected-context comparison, and protected-result issuance are separate architectural operations.

Add the five distinct semantic purposes from the spec: evidence binding, protected Attestation Result integrity, permit authorization, session proof of possession, and renewal authorization. State that challenge authentication is a separate verifier operation and admission is downstream, so neither belongs to the closed purpose set. Require later representations to domain-separate these purposes, while explicitly deferring literal labels.

- [ ] **Step 4: Replace protocol underbinding and align trust authorities**

In `docs/PROTOCOL.md`, replace the undefined `challenge digest` input list with the complete typed `PublisherChallenge` semantic and external-carrier contract. State that M2 still owns canonical source representations, algorithms and identifiers, literal domain-separation labels, proof coverage, encoding, parsing, and conformance vectors.

In `docs/TRUST_MODEL.md`, assign authenticated challenge semantics to the publisher challenge issuer and verifier, `ExpectedContext` to the relying party, actual-key ownership and handle association to the trusted local key owner, claims and provenance to registered evidence producers, construction to the attester, reconstruction/coverage/appraisal to the publisher verifier, and later validity/integrity to the protected-result issuer. State that received claims are candidate inputs rather than authority and that valid coverage does not prove claim truth.

- [ ] **Step 5: Add sharp definitions and roadmap limits**

In `CONTEXT.md`, add definitions with these exact boundaries:

```markdown
**Coverage:** The profile-specific property that changing any evidence-binding
transcript semantic causes profile validation to fail. Coverage does not name a
cryptographic mechanism.

**Evidence carrier:** The external profile-specific `EvidenceBundle` that
transports claims and proof material. The carrier is not itself a transcript
semantic.

**Evidence-binding transcript:** The closed semantic claim set one evidence
mechanism covers for one appraisal attempt. It is not a serialization, digest,
result, permit, or admission decision.

**Profile contract:** The immutable semantic definition named by an
`EvidenceProfile`: exact required claims, permitted provenance, coverage,
assurance meaning, disclosure class, and evidence-time requirements.

**Semantic identity:** An identity whose namespace, algorithm identity, and
value are explicit after profile selection; not an untyped digest or opaque
commitment marker.
```

Update existing related terms only as needed to cross-link these boundaries; do not broaden their authority. In `docs/ROADMAP.md`, mark M1-012 complete only at the semantic documentation boundary. Name evidence-time authority as an earlier blocking design for runtime transcript work and preserve M2 ownership of representation/cryptography and M3 ownership of TPM-specific coverage.

- [ ] **Step 6: Verify terminology and boundary consistency**

Run:

```bash
grep -F 'Evidence-binding transcript' CONTEXT.md docs/ARCHITECTURE.md docs/PROTOCOL.md
grep -F 'EvidenceBundle' CONTEXT.md docs/ARCHITECTURE.md docs/PROTOCOL.md
grep -F 'ExpectedContext' CONTEXT.md docs/ARCHITECTURE.md docs/TRUST_MODEL.md
grep -F 'actual session public key' CONTEXT.md docs/ARCHITECTURE.md docs/TRUST_MODEL.md
grep -F 'not a serialization' CONTEXT.md
grep -F 'evidence-time' docs/ROADMAP.md
git diff --check -- CONTEXT.md docs/ARCHITECTURE.md docs/PROTOCOL.md docs/TRUST_MODEL.md docs/ROADMAP.md
```

Expected: each concept appears in the named files, and `git diff --check` exits `0`.

- [ ] **Step 7: Record a non-mutating review checkpoint**

Run:

```bash
git diff -- CONTEXT.md docs/ARCHITECTURE.md docs/PROTOCOL.md docs/TRUST_MODEL.md docs/ROADMAP.md
```

Expected: documentation-only semantic changes with no representation or cryptographic choice. Do not commit without separate authorization.

---

### Task 3: Threat, Privacy, and Validation Contract

**Files:**
- Modify: `docs/THREAT_MODEL.md`
- Modify: `docs/TEST_STRATEGY.md`
- Modify: `docs/PRIVACY_MODEL.md`
- Modify only if review finds a genuine invariant gap: `docs/SECURITY_INVARIANTS.md`
- Reference: `planning/issues/012-evidence-binding-transcript-inputs.md`

**Interfaces:**
- Consumes: the domain boundaries from Task 2.
- Produces: explicit attack families, disclosure limits, and a validation matrix consumed by Task 5 scenarios.

- [ ] **Step 1: Capture missing validation families as the red checkpoint**

Run:

```bash
grep -F 'claim-provenance substitution' docs/TEST_STRATEGY.md
```

Expected: exit status `1` before the M1-012 matrix is added.

- [ ] **Step 2: Add evidence-transcript threats and residual risks**

In `docs/THREAT_MODEL.md`, add a subsection named `### Evidence-binding transcript substitution and underbinding`. Map the following threats to existing attacker classes without inventing a new class:

```text
authenticated challenge field or protocol-version omission/substitution
profile substitution or profile-contract drift
required-claim omission, duplication, aliasing, or undeclared claim injection
claim-provenance reclassification
actual session-public-key or SessionPublicKeyId substitution
manifest namespace, algorithm, or value substitution
cross-account, game, match, policy, session, or purpose replay
evidence-time source, epoch, validity, rollback, restart, or renewal confusion
transcript/result/permit domain confusion
diagnostic or telemetry disclosure of transcript or proof material
```

State mitigations as independent verifier reconstruction, closed profile contracts, exact-once claim semantics, dual key association, semantic identities, purpose separation, independent `ExpectedContext`, and confidentiality by default.

Record residual risks precisely: compromised trusted producers can emit dishonest but correctly classified claims; cryptographic strength depends on later profile mechanisms; evidence-time soundness remains unresolved; verifier or issuer compromise remains inside the TCB; privacy still depends on profile minimization and retention policy.

- [ ] **Step 3: Add the privacy classification and disclosure boundary**

In `docs/PRIVACY_MODEL.md`, classify the complete transcript, decoded claims, provenance, actual public key, key handle, semantic manifest identities, evidence-time statement, and proof material as confidential-by-default attestation data. Add these rules:

```markdown
- Ordinary `Debug`, error, tracing, metric, crash, and audit output must not
  contain transcript contents, proof bytes, claim values, manifest identities,
  key bytes, key handles, account/game/match/policy bindings, or evidence time.
- `EvidenceProfile` alone is not permission to log the profile's claims.
- Profiles must declare disclosure class and data minimization expectations.
- Retention, deletion, and protected audit disclosure remain separately
  governed and are not selected by M1-012.
- The private session key is never evidence, transcript input, or telemetry.
```

State that documentation examples use semantic names, never realistic account identifiers, key material, proof bytes, or biometric/device fingerprints.

- [ ] **Step 4: Add a complete semantic validation matrix**

In `docs/TEST_STRATEGY.md`, add `## Evidence-binding transcript validation` with three tables.

The positive table must include exact reconstruction for initial appraisal, same-session renewal under the conditional context/key/time rules without requiring profile or exact-policy identity stability, a profile with only Base claims, a profile with additional registered claims, and each provenance class.

The single-change negative table must include one row for each of these mutations and an expected `reject before successful appraisal` result:

```text
change one PublisherChallenge field
change ProtocolVersion
change EvidenceProfile
omit one required claim
duplicate one claim meaning
inject one undeclared claim
alias one meaning under two names
change one claim's provenance class
change actual session public key
change SessionPublicKeyId
change only the actual-key-to-handle association
change protected-session subject
change publisher
change manifest identity namespace
change manifest identity algorithm
change manifest identity value
change evidence-time producer/source
change evidence-time clock/epoch
change evidence-time creation value
change evidence validity semantics
reuse for another account/game/match/policy/session
reuse initial evidence as renewal authorization
reuse transcript under result or permit purpose
duplicate one semantically set-valued element
add one unknown critical semantic
use a known claim under a profile that did not declare it
accept the complete EvidenceBundle payload as a transcript input
accept an attester-supplied transcript without independent reconstruction
accept only EvidenceProfile without the evidence instance claims
```

The shape/domain table must assert that the whole `EvidenceBundle` is not a transcript semantic, `ExpectedContext` is not transcript evidence, verifier evaluation time and challenge issuance time do not replace evidence time, private keys are excluded, and literal byte/canonical/algorithm expectations cannot be tested until M2.

Add a property strategy: start from a valid semantic fixture, mutate exactly one semantic leaf, and require coverage validation or equality to reject; separately generate claim sets to enforce required-membership, no undeclared members, and exactly-once meanings. Mark this as a future executable strategy, not an implemented runtime test.

- [ ] **Step 5: Verify threat/privacy/test coverage**

Run:

```bash
grep -F 'Evidence-binding transcript substitution and underbinding' docs/THREAT_MODEL.md
grep -F 'confidential-by-default' docs/PRIVACY_MODEL.md
grep -F 'claim-provenance substitution' docs/TEST_STRATEGY.md
grep -F 'SessionPublicKeyId' docs/TEST_STRATEGY.md
grep -F 'evidence-time clock/epoch' docs/TEST_STRATEGY.md
grep -F 'reject before successful appraisal' docs/TEST_STRATEGY.md
git diff --check -- docs/THREAT_MODEL.md docs/PRIVACY_MODEL.md docs/TEST_STRATEGY.md docs/SECURITY_INVARIANTS.md
```

Expected: each required boundary is present and `git diff --check` exits `0`.

- [ ] **Step 6: Record a non-mutating review checkpoint**

Run:

```bash
git diff -- docs/THREAT_MODEL.md docs/PRIVACY_MODEL.md docs/TEST_STRATEGY.md docs/SECURITY_INVARIANTS.md
```

Expected: no claim of implemented runtime enforcement or selected cryptography. Do not commit without separate authorization.

---

### Task 4: Durable Architecture Decision

**Files:**
- Create: `docs/adr/0010-semantic-evidence-binding-transcript.md`
- Modify: `docs/adr/index.md`
- Reference: `docs/adr/template.md`
- Reference: `planning/issues/012-evidence-binding-transcript-inputs.md`

**Interfaces:**
- Consumes: Tasks 1-3 and the repository ADR lifecycle.
- Produces: accepted ADR-0010 and its exact decision-index row.

- [ ] **Step 1: Capture the ADR-index red checkpoint**

Run:

```bash
./scripts/check-adr-index.sh
test ! -f docs/adr/0010-semantic-evidence-binding-transcript.md
```

Expected: the ADR gate currently passes, and the second command exits `0`, proving ADR-0010 is not already present.

- [ ] **Step 2: Create ADR-0010 metadata and context**

Create `docs/adr/0010-semantic-evidence-binding-transcript.md` with this exact metadata:

```markdown
# ADR-0010: Use a semantic evidence-binding transcript with an external carrier

- Status: Accepted
- Date: 2026-08-31
- Owners: Initial maintainers
- Related issues: [M1-012](../../planning/issues/012-evidence-binding-transcript-inputs.md)
- Supersedes: None
- Superseded by: None
```

Retain every required template heading as rendered Markdown. Under `## Context`, explain that an undefined transcript permits challenge underbinding, profile/claim/provenance drift, key-handle authority confusion, semantic-manifest substitution, cross-purpose reuse, and privacy leakage; record that the decision is needed before representation or cryptography can be selected safely.

- [ ] **Step 3: Record drivers and options without selecting representation**

Under `## Decision drivers`, include complete semantic binding, independent verifier reconstruction, profile extensibility without open maps, key-handle non-authority, privacy minimization, representation neutrality, and future M2 compatibility.

Under `## Options considered`, analyze and reject each of these alternatives with the stated reason:

```text
include complete EvidenceBundle payload: binds transport accidents and unstable envelope fields
bind only EvidenceProfile: underbinds concrete claims and key association
trust attester-supplied transcript: removes independent reconstruction
verifier-only construction: does not define what evidence covered
bind only SessionPublicKeyId: handle is not authority under ADR-0008
bind only actual public key: loses protocol correlation handle
opaque manifest commitment markers: fail to identify appraised subject
raw digest bytes: omit namespace and algorithm semantics
one universal claim set: cannot express profile assurance differences safely
arbitrary claim maps: permit omission, invention, aliasing, and provenance drift
freeze literal labels now: prematurely selects representation
defer all purpose separation: permits cross-protocol reuse
equate evidence time with challenge time: conflates different events and authorities
```

- [ ] **Step 4: Record the selected decision, consequences, and impacts**

Under `## Decision`, state the complete approved architecture: external carrier, complete typed challenge, registered profile contract, actual key plus handle, all Base claims plus closed profile additions, exact provenance, semantic manifest identities, profile-required evidence-time semantics, attester construction, verifier reconstruction, and semantic purpose separation.

Under `## Consequences`, state both benefits and costs. Costs include more profile-registry governance, explicit claim/provenance handling, later canonicalization work, and an evidence-time prerequisite. State that no runtime behavior exists from this ADR alone.

Under `## Threat-model impact` and `## Privacy impact`, mirror the bounded threats and confidentiality rules from Task 3. Under `## Dependency and license impact`, state that no dependency, TCB package, or license boundary changes in this documentation-only decision.

- [ ] **Step 5: Add validation, rollback, and primary sources**

Under `## Validation`, require the documentation matrix, machine-readable scenarios, ADR gate, full repository gate, and later mutation/property/conformance tests after representation choices are approved.

Under `## Rollback`, state that changing this accepted semantic contract requires a superseding ADR, profile migration analysis, compatibility analysis, and corresponding issue/model/threat/test/scenario updates; deleting history is forbidden.

Under `## Primary sources`, cite ADR-0005, ADR-0007, ADR-0008, ADR-0009, RFC 9334, RFC 9711, and the project authorities named in Task 1 with the same TPM non-adoption caveat.

- [ ] **Step 6: Add the exact ADR index row**

Append this row after ADR-0009 in `docs/adr/index.md`:

```markdown
| [ADR-0010](0010-semantic-evidence-binding-transcript.md) | Accepted | Evidence mechanisms cover one closed semantic transcript reconstructed independently by the verifier while EvidenceBundle remains external. | None | None |
```

- [ ] **Step 7: Verify the ADR as an independent deliverable**

Run:

```bash
./scripts/check-adr-index.sh
grep -F 'Status: Accepted' docs/adr/0010-semantic-evidence-binding-transcript.md
grep -F 'EvidenceBundle remains external' docs/adr/index.md
grep -F 'evidence-time prerequisite' docs/adr/0010-semantic-evidence-binding-transcript.md
git diff --check -- docs/adr/0010-semantic-evidence-binding-transcript.md docs/adr/index.md
```

Expected: ADR consistency passes, all required text is present, and `git diff --check` exits `0`.

- [ ] **Step 8: Record a non-mutating review checkpoint**

Run:

```bash
git diff -- docs/adr/0010-semantic-evidence-binding-transcript.md docs/adr/index.md
```

Expected: one accepted ADR and one matching index row. Do not commit without separate authorization.

---

### Task 5: Machine-readable Attack Scenarios

**Files:**
- Create: `lab/scenarios/evidence-transcript-underbinding.scenario.json`
- Create: `lab/scenarios/evidence-transcript-claim-shape.scenario.json`
- Create: `lab/scenarios/evidence-transcript-provenance-substitution.scenario.json`
- Create: `lab/scenarios/evidence-transcript-key-substitution.scenario.json`
- Create: `lab/scenarios/evidence-transcript-manifest-substitution.scenario.json`
- Create: `lab/scenarios/evidence-transcript-context-reuse.scenario.json`
- Create: `lab/scenarios/evidence-transcript-purpose-confusion.scenario.json`
- Create: `lab/scenarios/evidence-transcript-time-authority-confusion.scenario.json`
- Create: `lab/scenarios/evidence-transcript-diagnostics-privacy.scenario.json`
- Reference: `lab/scenarios/schema.json`
- Reference: `docs/TEST_STRATEGY.md`

**Interfaces:**
- Consumes: the validation families from Task 3 and JSON shape enforced by the existing scenario schema.
- Produces: nine schema-valid M1-012 regression scenarios; no runtime harness or schema extension.

- [ ] **Step 1: Capture the scenario-count red checkpoint**

Run:

```bash
test -z "$(compgen -G 'lab/scenarios/evidence-transcript-*.scenario.json')"
```

Expected: exit status `0` before the scenarios are created.

- [ ] **Step 2: Create the challenge/profile underbinding scenario**

Create `lab/scenarios/evidence-transcript-underbinding.scenario.json` with this exact content:

```json
{
  "id": "OGIR-EVIDENCE-TRANSCRIPT-UNDERBINDING-001",
  "title": "Omit or substitute one authenticated transcript semantic",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["protected_session_authorization", "evidence_appraisal_integrity"],
  "preconditions": ["one profile mechanism covers an otherwise valid independently reconstructed evidence-binding transcript"],
  "steps": [
    "establish an accepted baseline with equal complete PublisherChallenge and EvidenceProfile semantics",
    "repeat the mutation independently for every PublisherChallenge semantic including ProtocolVersion",
    "independently substitute the EvidenceProfile while retaining the original carrier proof"
  ],
  "expected": {"decision": "deny", "reason": "evidence-invalid", "automatic_ban": false},
  "invariants": [
    "the complete typed PublisherChallenge is one semantic input without a copied subset or challenge digest",
    "the verifier reconstructs the expected transcript independently from authenticated and registered semantics",
    "changing any transcript semantic causes profile coverage validation to fail before successful appraisal"
  ],
  "residual_risk": ["coverage strength depends on a later approved profile mechanism and representation"]
}
```

- [ ] **Step 3: Create the claim shape and provenance scenario**

Create `lab/scenarios/evidence-transcript-claim-shape.scenario.json`:

```json
{
  "id": "OGIR-EVIDENCE-TRANSCRIPT-CLAIM-SHAPE-001",
  "title": "Alter the registered transcript claim shape or provenance",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["evidence_appraisal_integrity", "player_privacy"],
  "preconditions": ["one registered profile defines all eight Base claims and any required profile-specific claims with exact provenance"],
  "steps": [
    "independently omit one required claim or duplicate one singleton meaning",
    "independently alias one meaning inject one undeclared claim or add one unknown critical semantic",
    "independently duplicate one set element or use a known claim under a profile that did not declare it"
  ],
  "expected": {"decision": "deny", "reason": "malformed", "automatic_ban": false},
  "invariants": [
    "every profile requires all eight Base claims and only declared profile-specific claims",
    "every required claim appears semantically exactly once",
    "the immutable profile contract rejects missing duplicate aliased and undeclared claim meanings"
  ],
  "residual_risk": ["a compromised trusted producer can emit a dishonest value with the registered claim shape"]
}
```

- [ ] **Step 4: Create the claim provenance substitution scenario**

Create `lab/scenarios/evidence-transcript-provenance-substitution.scenario.json`:

```json
{
  "id": "OGIR-EVIDENCE-TRANSCRIPT-PROVENANCE-SUBSTITUTION-001",
  "title": "Reclassify one evidence claim provenance",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["evidence_appraisal_integrity", "protected_session_authorization"],
  "preconditions": ["one registered profile assigns exactly one provenance class to every required claim"],
  "steps": [
    "retain one claim meaning and value while changing hardware-certified to measured-log-derived",
    "independently relabel a measured-log-derived claim as trusted-agent-observed",
    "supply a declared provenance label through a validation path that does not satisfy that class"
  ],
  "expected": {"decision": "deny", "reason": "evidence-invalid", "automatic_ban": false},
  "invariants": [
    "each required claim binds exactly one profile-registered provenance class",
    "provenance classes describe origin and assurance limits rather than interchangeable strength labels",
    "the verifier rejects a claim whose actual validation path does not satisfy its declared provenance"
  ],
  "residual_risk": ["a compromised trusted producer can emit dishonest claim content through an otherwise accepted provenance path"]
}
```

- [ ] **Step 5: Create the session-key association substitution scenario**

Create `lab/scenarios/evidence-transcript-key-substitution.scenario.json`:

```json
{
  "id": "OGIR-EVIDENCE-TRANSCRIPT-KEY-SUBSTITUTION-001",
  "title": "Substitute the covered session public key or lookup handle",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["protected_session_authorization", "session_key_binding"],
  "preconditions": ["one trusted key owner associated an actual session public key and SessionPublicKeyId with one publisher and protected session"],
  "steps": [
    "independently replace the actual session public key while retaining the covered SessionPublicKeyId",
    "independently replace the SessionPublicKeyId while retaining the covered actual key",
    "pair one session actual key with another session lookup handle"
  ],
  "expected": {"decision": "deny", "reason": "context-binding-mismatch", "automatic_ban": false},
  "invariants": [
    "the transcript binds both the actual public key and SessionPublicKeyId",
    "SessionPublicKeyId remains a non-authoritative lookup handle under ADR-0008",
    "the verifier checks one trusted-owner key handle publisher and protected-session association"
  ],
  "residual_risk": ["proof of possession and concrete key representation remain later protocol work"]
}
```

- [ ] **Step 6: Create the semantic manifest substitution scenario**

Create `lab/scenarios/evidence-transcript-manifest-substitution.scenario.json`:

```json
{
  "id": "OGIR-EVIDENCE-TRANSCRIPT-MANIFEST-SUBSTITUTION-001",
  "title": "Substitute one semantic manifest identity component",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["evidence_appraisal_integrity", "reference_value_integrity"],
  "preconditions": ["one accepted profile identifies an exact appraised boot runtime game or protected-session semantic object"],
  "steps": [
    "independently replace the semantic identity namespace",
    "independently replace the algorithm identity",
    "independently replace the value or substitute raw digest bytes or an opaque commitment marker"
  ],
  "expected": {"decision": "deny", "reason": "evidence-invalid", "automatic_ban": false},
  "invariants": [
    "manifest and measurement identities bind explicit semantic namespace algorithm identity and value",
    "raw bytes and opaque commitment markers do not identify the appraised semantic object",
    "each isolated identity change causes semantic inequality and future coverage failure"
  ],
  "residual_risk": ["canonical source objects algorithms and compact commitments remain deferred to M2"]
}
```

- [ ] **Step 7: Create the cross-context reuse scenario**

Create `lab/scenarios/evidence-transcript-context-reuse.scenario.json`:

```json
{
  "id": "OGIR-EVIDENCE-TRANSCRIPT-CONTEXT-REUSE-001",
  "title": "Reuse covered evidence across relying-party or session context",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["protected_session_authorization", "verifier_freshness_state"],
  "preconditions": ["one evidence carrier was created for one authenticated challenge and one live appraisal subject"],
  "steps": [
    "independently reuse the carrier under another publisher game build account match or policy",
    "independently reuse one session key or handle under another protected session",
    "replay prior evidence for renewal or renew after terminal end under changed publisher session or silently weakened policy semantics"
  ],
  "expected": {"decision": "deny", "reason": "context-binding-mismatch", "automatic_ban": false},
  "invariants": [
    "ExpectedContext remains independently supplied rather than attester-originated evidence",
    "overlapping challenge claim key and session meanings agree before successful appraisal",
    "same-session renewal preserves the publisher protected session and live subject while applying conditional key reuse non-weakened policy current claims and accepted new evidence time"
  ],
  "residual_risk": ["a valid full-session relay remains outside evidence transcript binding alone"]
}
```

- [ ] **Step 8: Create the cross-purpose confusion scenario**

Create `lab/scenarios/evidence-transcript-purpose-confusion.scenario.json`:

```json
{
  "id": "OGIR-EVIDENCE-TRANSCRIPT-PURPOSE-CONFUSION-001",
  "title": "Reuse evidence coverage as another protocol authority",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["protected_session_authorization", "permit_integrity"],
  "preconditions": ["one mechanism establishes coverage for the OGIR evidence-binding semantic purpose"],
  "steps": [
    "present evidence coverage as protected Attestation Result integrity",
    "present evidence coverage as permit authorization",
    "present evidence coverage as session proof of possession",
    "present an initial-appraisal transcript as same-session renewal authorization"
  ],
  "expected": {"decision": "deny", "reason": "evidence-invalid", "automatic_ban": false},
  "invariants": [
    "the five distinct purposes are evidence binding protected Attestation Result integrity permit authorization session proof of possession and renewal authorization",
    "an evidence-binding transcript is not a protected Attestation Result permit session proof of possession renewal authorization or disciplinary signal",
    "later representation work must domain-separate all five purposes"
  ],
  "residual_risk": ["literal domain labels and cryptographic enforcement remain deferred to M2"]
}
```

- [ ] **Step 9: Create the evidence-time authority blocker scenario**

Create `lab/scenarios/evidence-transcript-time-authority-confusion.scenario.json`:

```json
{
  "id": "OGIR-EVIDENCE-TRANSCRIPT-TIME-AUTHORITY-001",
  "title": "Substitute an unapproved time source for evidence time",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["evidence_appraisal_integrity", "verifier_freshness_state"],
  "preconditions": ["runtime evidence-time producer clock validity rollback restart renewal and privacy semantics are unresolved"],
  "steps": [
    "copy challenge issued_at or expires_at into evidence creation or expiry semantics",
    "substitute verifier evaluation time or client wall-clock time",
    "omit evidence time or use an always-valid or zero-valued placeholder"
  ],
  "expected": {"decision": "blocked", "reason": "evidence-time-authority-unresolved", "automatic_ban": false},
  "invariants": [
    "evidence creation and validity time are distinct from challenge verifier result permit and renewal time domains",
    "no implicit source clock ordering or accepted interval is authorized",
    "runtime transcript representation proof implementation and protected-result issuance remain blocked"
  ],
  "residual_risk": ["accepted positive temporal behavior requires a separately approved evidence-time authority design"]
}
```

- [ ] **Step 10: Create the transcript diagnostics privacy scenario**

Create `lab/scenarios/evidence-transcript-diagnostics-privacy.scenario.json`:

```json
{
  "id": "OGIR-PRIVACY-EVIDENCE-TRANSCRIPT-DIAGNOSTICS-001",
  "title": "Disclose transcript claims proof or correlation data through diagnostics",
  "attacker": "A8",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["player_privacy", "session_key_binding"],
  "preconditions": ["an attester or verifier handles transcript semantics an EvidenceBundle or profile proof material"],
  "steps": [
    "request formatting logging tracing metrics crash output or audit output for transcript processing",
    "search output for claims provenance manifest identities evidence time public key key handle proof bytes or challenge context",
    "attempt to treat EvidenceProfile visibility as permission to disclose profile claims"
  ],
  "expected": {"decision": "deny", "reason": "privacy-boundary", "automatic_ban": false},
  "invariants": [
    "future aggregate diagnostics use one fixed complete redaction marker",
    "ordinary diagnostic surfaces reveal no transcript value proof material or correlation identifier",
    "private session-key material is never a transcript input evidence claim diagnostic value or fixture"
  ],
  "residual_risk": ["future explicit access storage transport retention deletion and protected audit disclosure require separate privacy review"]
}
```

- [ ] **Step 11: Validate all scenarios through the existing repository gate**

Run:

```bash
python3 ./scripts/check-attack-scenario-traceability.py --self-test
python3 ./scripts/check-attack-scenario-traceability.py
git diff --check -- lab/scenarios/evidence-transcript-*.scenario.json
```

Expected: the scenario checker reports all existing and nine new scenarios valid, and `git diff --check` exits `0`.

- [ ] **Step 12: Record a non-mutating review checkpoint**

Run:

```bash
git diff -- lab/scenarios/evidence-transcript-*.scenario.json
```

Expected: nine documentation fixtures and no schema or executable-code change. Do not commit without separate authorization.

---

### Task 6: Traceability, Scope Audit, and Full Verification

**Files:**
- Modify only if a traceability gap is found: `planning/issues/012-evidence-binding-transcript-inputs.md`
- Modify only if a traceability gap is found: `CONTEXT.md`
- Modify only if a traceability gap is found: `docs/ARCHITECTURE.md`
- Modify only if a traceability gap is found: `docs/PROTOCOL.md`
- Modify only if a traceability gap is found: `docs/TRUST_MODEL.md`
- Modify only if a traceability gap is found: `docs/ROADMAP.md`
- Modify only if a traceability gap is found: `docs/THREAT_MODEL.md`
- Modify only if a traceability gap is found: `docs/PRIVACY_MODEL.md`
- Modify only if a traceability gap is found: `docs/TEST_STRATEGY.md`
- Modify only if a traceability gap is found: `docs/SECURITY_INVARIANTS.md`
- Modify only if a traceability gap is found: `docs/adr/0010-semantic-evidence-binding-transcript.md`
- Modify only if a traceability gap is found: `docs/adr/index.md`
- Modify only if a traceability gap is found: `lab/scenarios/evidence-transcript-*.scenario.json`

**Interfaces:**
- Consumes: all preceding documentation artifacts.
- Produces: a verified, internally consistent, uncommitted documentation-only M1-012 change set ready for decision-owner review and separate commit authorization.

- [ ] **Step 1: Build a spec-to-artifact traceability checklist**

Use this exact checklist during review; every item must point to at least one repository artifact and no item may rely only on the design spec:

```text
external EvidenceBundle carrier
complete typed PublisherChallenge
independent ExpectedContext
registered immutable EvidenceProfile contract
all eight Base claims
both profile-specific claims
exactly-once claim semantics
registered provenance class per claim
actual public key plus SessionPublicKeyId
semantic manifest namespace plus algorithm plus value
attester construction plus verifier reconstruction
initial appraisal semantics
same-session renewal semantics
five-way semantic purpose separation
confidential-by-default handling
single-change negative validation
evidence-time authority prerequisite
representation and cryptography deferral
protected-result and permit exclusions
TPM-specific deferral
```

If an item is absent, add the smallest missing normative statement to the artifact responsible for that concern; do not create new runtime or representation requirements.

- [ ] **Step 2: Scan for forbidden placeholders and premature choices**

Run:

```bash
grep -R -n -E 'TO''DO|T''BD|implement[[:space:]]+later|fill[[:space:]]+in|appropriate[[:space:]]+error[[:space:]]+handling|choose[[:space:]]+(SHA|RSA|ECDSA|EdDSA|HMAC|KDF)|canonical[[:space:]]+(CBOR|JSON|bytes)|numeric[[:space:]]+discriminant' planning/issues/012-evidence-binding-transcript-inputs.md CONTEXT.md docs/ARCHITECTURE.md docs/PROTOCOL.md docs/TRUST_MODEL.md docs/ROADMAP.md docs/THREAT_MODEL.md docs/PRIVACY_MODEL.md docs/TEST_STRATEGY.md docs/SECURITY_INVARIANTS.md docs/adr/0010-semantic-evidence-binding-transcript.md lab/scenarios/evidence-transcript-*.scenario.json
```

Expected: exit status `1` with no matches. The named evidence-time prerequisite is not a placeholder; it must remain explicit and bounded.

- [ ] **Step 3: Confirm the change set is documentation-only**

Run:

```bash
git status --short
git diff --name-only
```

Expected: paths are limited to the approved spec status/approval record, this plan, `planning/issues/012-evidence-binding-transcript-inputs.md`, the named Markdown documents, ADR-0010/index, and nine scenario JSON files. No `crates/`, `Cargo.toml`, `Cargo.lock`, `scripts/`, `.github/`, or generated path appears.

- [ ] **Step 4: Run focused documentation gates**

Run:

```bash
./scripts/check-adr-index.sh
python3 ./scripts/check-attack-scenario-traceability.py --self-test
python3 ./scripts/check-attack-scenario-traceability.py
git diff --check
```

Expected: every command exits `0`; the ADR count increases from 9 to 10 and the scenario count increases from 14 to 23.

- [ ] **Step 5: Run the complete repository gate**

Run:

```bash
./scripts/check.sh
```

Expected: formatting, Clippy, rustdoc, metadata, dependency policy, runtime/integration tests, doctests, ADR validation, and scenario validation all pass. Expected unchanged executable-test counts are 225 runtime/integration tests and 111 doctests; expected documentation fixture counts are 10 ADRs and 23 scenarios.

- [ ] **Step 6: Inspect the final diff and record hashes**

Run:

```bash
git diff --stat
git diff
sha256sum docs/superpowers/specs/2026-08-31-m1-012-evidence-binding-transcript-design.md docs/superpowers/plans/2026-08-31-m1-012-evidence-binding-transcript-documentation.md
git status --short
```

Expected: one coherent documentation-only diff. Record both final hashes in the project handoff because the spec hash changes when its approval record is appended. Do not claim that the approved candidate hash changed retroactively; retain `60fb29682e939d1b259b84033c113b3096a9e734541b5a0634e8733deebfe591` as the hash of the exact reviewed candidate.

- [ ] **Step 7: Update the canonical archledger handoff after execution**

Update `/home/wisbfime/archledger-gp/project-open-game-integrity-runtime.md` and `/home/wisbfime/archledger-gp/index.md` with the exact detached worktree state, changed files, verification output, final hashes, absence of commit/remote mutation, evidence-time blocker, and next authorization gate. Append a factual checkpoint using `/home/wisbfime/archledger-gp/session-summary-template.md`; do not edit prior completed checkpoints.

- [ ] **Step 8: Stop at the authorization boundary**

Present the verified diff for review. Do not create a branch, commit, DCO certification, GitHub issue, pull request, or remote mutation until the decision owner separately authorizes that exact next action.
