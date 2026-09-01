# M1-012F Evidence-time Authority Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the approved M1-012F challenge-anchored evidence-time authority contract as aligned repository documentation, one accepted ADR, and machine-readable attack scenarios without selecting a runtime representation, clock implementation, cryptographic mechanism, or production duration.

**Architecture:** Register one trusted local Evidence Collection Authority per immutable profile. It creates one publisher/session-scoped protected epoch relation, strictly increasing collection sequence, and bounded start-to-freeze interval for each exact fresh challenge; the publisher verifier authenticates the challenge, validates coverage and temporal continuity, and retains only active-session temporal high-water. UTC, skew, cross-challenge reuse, and same-session restart recovery are excluded.

**Tech Stack:** Markdown, JSON Schema draft 2020-12 scenario documents, Bash repository gates, Cargo workspace verification.

**Spec:** `docs/superpowers/specs/2026-09-01-m1-012f-evidence-time-authority-design.md`

## Global Constraints

- Execute inline with `superpowers:executing-plans`; the user has explicitly requested no subagents for this work.
- Delivery is documentation-only: do not modify Rust source, Cargo manifests, lockfiles, shell gates, CI workflows, dependencies, generated artifacts, runtime APIs, wire formats, parsers, persistence adapters, or production configuration.
- The approved spec is signed commit `2bc3a6d4f9a3edeee829e3a8e620daa3df7d3f85`; its file SHA-256 is `6d0c2f5f9625a584dba06468bf9b7016ef3223ddcaa3336ad168f299abe89bd4`.
- Work from branch `docs/m1-012f-evidence-time-authority` based on exact `origin/main` `f97e3a77f5e4521888d9f136f506d23aa857d367`; never reconcile, reset, merge, or rewrite the intentionally divergent local `main`.
- One immutable `EvidenceProfile` registers exactly one Evidence Collection Authority contract, protected monotonic source semantics, publisher/session-scoped epoch relation, and finite collection-duration ceiling.
- The generic attester, game, bridge, client, process uptime, host UTC, challenge timestamps, verifier time, result time, and permit time are not evidence-time authorities.
- One evidence-time semantic contains authority-contract identity, opaque scoped epoch relation, protected collection sequence, protected start, and protected snapshot-freeze end.
- Collection opens only after receiving the exact complete challenge later covered by evidence; the local authority does not need publisher trust roots, and the publisher verifier authenticates the challenge.
- The complete claim snapshot freezes before proof creation. No proof-completion timestamp or separately unverifiable post-freeze latency value is introduced.
- Evidence is single-challenge and must arrive before the existing half-open publisher challenge expiry boundary. No snapshot, interval, sequence, carrier, or proof is reusable across challenges.
- UTC is absent. There is no evidence-time wall-clock skew tolerance or local-to-publisher time conversion.
- Initial appraisal establishes active-session temporal high-water. Renewal is serialized and requires a fresh challenge, same uninterrupted epoch, strictly greater but not necessarily contiguous sequence, and non-overlapping interval.
- A validated authority restart, rollback, epoch change, reused/decreased sequence, overlap, impossible interval, protected-source discontinuity, or lost high-water terminates the protected session with coarse non-disciplinary `ProtectedSessionLost` behavior.
- Temporary unavailability is retryable only when authoritative continuity state remains intact and recoverable; retry uses a fresh challenge and has no stateless fallback.
- The verifier atomically advances high-water for every valid protected temporal statement before later claim/policy appraisal; invalid or unauthenticated proof never advances it.
- Epoch, sequence, interval, duration, high-water, challenge, key/handle, and proof values are confidential and absent from ordinary diagnostics. Epoch representation is publisher/session scoped and never exposes raw boot, TPM clock, reset/restart, or device-wide identity.
- Task 13 may consume the completed semantic contract for abstract fixtures. M2 still owns representation, encoding, parser, algorithms, literal labels, proof coverage, and runtime validation; M3 owns TPM mapping.
- No task may create a commit, issue, pull request, push, remote branch, DCO certification, or other GitHub/remote mutation without a separate explicit human authorization for the exact candidate.
- OGIR DCO policy overrides generic frequent-commit guidance: preserve task checkpoints uncommitted, freeze the final candidate, obtain exact human certification, then create only the separately authorized signed commit history.

---

### Task 1: Canonical M1-012F Planning Issue Contract

**Files:**
- Create: `planning/issues/012f-evidence-time-authority.md`
- Reference: `docs/superpowers/specs/2026-09-01-m1-012f-evidence-time-authority-design.md`
- Reference: `planning/issues/012-evidence-binding-transcript-inputs.md`

**Interfaces:**
- Consumes: the approved authority, tuple, lifecycle, failure, privacy, and validation contract from the spec.
- Produces: one canonical local issue body cited by every later documentation task; it does not create a live GitHub issue.

- [ ] **Step 1: Capture the missing issue-contract red checkpoint**

Run:

```bash
test -f planning/issues/012f-evidence-time-authority.md
```

Expected: exit status `1` because the canonical issue contract does not exist.

- [ ] **Step 2: Create exact issue heading, metadata, problem, and approval provenance**

Create the file with this opening:

```markdown
# M1-012F: Define challenge-anchored evidence-time authority
<!-- labels: type: architecture,type: documentation,area: model,area: verifier,area: agent,area: session,area: privacy,risk: trusted-computing-base,risk: privacy,status: ready -->
<!-- milestone: M1 Domain Model -->

## Problem

M1-012 requires every evidence-binding transcript to contain one evidence-time
semantic, but intentionally blocked representation and proof work until a
separately approved authority contract defined its producer, clock or epoch,
validity, skew, rollback, restart, renewal, and privacy behavior.

OGIR now selects one challenge-anchored protected local collection interval for
one complete frozen claim snapshot. An immutable EvidenceProfile registers one
Evidence Collection Authority and protected monotonic contract. The publisher
verifier authenticates the challenge and remains the sole acceptance authority.
Client UTC and every other protocol time domain remain excluded.

On 2026-09-01, the decision owner approved design SHA-256
`6d0c2f5f9625a584dba06468bf9b7016ef3223ddcaa3336ad168f299abe89bd4`
and certified exact signed design commit
`2bc3a6d4f9a3edeee829e3a8e620daa3df7d3f85` under DCO 1.1. That approval
authorizes documentation planning only. Runtime code, representation,
cryptography, a live issue, publication, and further commits remain separate
human gates.
```

- [ ] **Step 3: Add security invariants, scope, and trust boundaries**

Add `## Security invariants`, `## In scope`, `## Out of scope`, and
`## Trust sources`. Include these exact normative requirements:

```markdown
- Evidence time describes when one complete current claim snapshot was
  collected, revalidated, and frozen; it does not claim every underlying event
  occurred during that interval.
- One immutable profile registers exactly one collection-authority contract,
  protected monotonic source semantics, and finite duration ceiling.
- The semantic value contains authority contract, opaque publisher/session
  epoch relation, protected sequence, protected start, and protected freeze end.
- The exact complete challenge is received before collection opens and is later
  authenticated and covered; one evidence instance is valid only for that
  challenge.
- Snapshot freeze precedes proof creation. Challenge expiry bounds proof,
  transport, and verifier receipt after freeze.
- Client UTC is absent and no wall-clock skew tolerance can authorize evidence.
- Accepted same-session sequences strictly increase but need not be contiguous;
  accepted intervals never overlap.
- Validated temporal high-water advances atomically before later appraisal and
  cannot be reset by a later rejection.
- Continuity loss terminates the protected session without implying cheating.
- Temporal values are confidential, minimally retained, and redacted.
```

The in-scope list must cover terminology, authority registration, semantic
tuple, initial/renewal lifecycle, challenge relation, duration policy, verifier
ordering/high-water, rollback/restart/unavailability, failure mapping, privacy,
retention, diagnostics, ADR, test strategy, and attack scenarios.

The out-of-scope list must name Rust types/APIs, integer widths, clock units,
wire fields, serialization, parsers, persistence adapters, synchronized UTC,
TPM structures/commands, crypto, literal labels, production duration values,
result/permit validity, renewal authorization, revocation, admission, and
per-claim timestamp vocabulary.

Assign authority as follows:

```text
Publisher issuer/verifier -> challenge time, authentication, freshness, acceptance
Immutable profile registry -> collection-authority contract and hard ceiling
Evidence Collection Authority -> protected local collection interval and freeze
Registered claim producers -> claim truth within registered provenance
Generic attester -> request, candidate construction, proof invocation, transport
Profile evidence mechanism -> complete transcript coverage
Publisher verifier -> protected statement validation, high-water, appraisal
Relying party -> ExpectedContext, outside transcript evidence
```

- [ ] **Step 4: Add required semantic interfaces and lifecycle**

Under `## Required interfaces`, define the semantic tuple exactly as:

```text
Evidence time
  registered collection-authority contract
  opaque publisher/session-scoped protected epoch relation
  protected collection sequence
  protected collection start
  protected snapshot-freeze end
```

State that this is semantic shape, not a serializer or runtime type. Add
`## Required relationships` with `### Initial appraisal` and
`### Same-session renewal` subsections. Initial appraisal must describe receive,
open, start, collect/revalidate, freeze, cover, authenticate, validate, and
establish-high-water order. Renewal must require fresh challenge, unchanged
publisher/session/live subject/key lifecycle, same epoch, strictly greater
sequence, `new.start >= prior.end`, effective duration, current frozen claims,
and receipt before expiry.

Explain sequence gaps exactly:

```markdown
A local collection can be dropped or rejected before the publisher verifier
observes it. Contiguous accepted sequences would misclassify ordinary message
loss as rollback. Strict increase permits unobserved gaps while reuse, decrease,
epoch change, overlap, and protected-source discontinuity remain terminal.
```

- [ ] **Step 5: Add failure, privacy, tests, dependency, and acceptance sections**

Use the issue format required by `docs/AI_DEVELOPMENT_POLICY.md`. Add:

- `## Positive tests` covering initial appraisal, valid renewal, a valid
  unobserved sequence gap, current-boot revalidation, and recovered temporary
  outage with fresh challenge;
- `## Negative tests` covering every family from the spec's negative semantic
  cases;
- `## Fuzz/property tests` covering strict increase, non-overlap, epoch/session
  boundaries, high-water monotonicity, appraisal-rejection ordering,
  unavailability, and diagnostics;
- `## Privacy impact` requiring scoped opacity, active-session-only high-water,
  terminal deletion, and fixed redaction;
- `## Dependency impact` stating standard repository documentation only and no
  manifest, lockfile, runtime, crypto, clock, storage, or TPM dependency;
- `## Acceptance criteria` reproducing every spec acceptance family; and
- `## Primary sources` linking RFC 9334 Sections 10, 10.2, and 10.4; RFC 9711
  Sections 4.3.1, 6.3.11, and 9.3; ADRs 0005-0010; the approved spec; and the
  mandatory project authorities.

Use this failure table:

```markdown
| Condition | Existing mapping or required behavior |
| --- | --- |
| Structurally invalid candidate shape | `Malformed` |
| Unregistered profile, authority contract, or source kind | `Unsupported` |
| Challenge freshness or context failure | Existing challenge/context mapping |
| Authority statement or transcript coverage invalid | `EvidenceInvalid` |
| Duration exceeds policy with valid continuity | `EvidenceInvalid` |
| Temporary outage with intact recoverable continuity | `Retry` with `AttestationUnavailable` |
| Validated rollback, restart, epoch change, reuse/decrease, overlap, impossible interval, source discontinuity, or lost high-water | `ProtectedSessionLost` and terminal invalidation |
| Missing semantic contract or finite profile limit | Implementation blocked |
```

- [ ] **Step 6: Verify and checkpoint Task 1**

Run:

```bash
test -f planning/issues/012f-evidence-time-authority.md
grep -F 'status: ready' planning/issues/012f-evidence-time-authority.md
grep -F 'strictly increase but need not be contiguous' planning/issues/012f-evidence-time-authority.md
grep -F 'ProtectedSessionLost' planning/issues/012f-evidence-time-authority.md
grep -F 'RFC 9334' planning/issues/012f-evidence-time-authority.md
git diff --check -- planning/issues/012f-evidence-time-authority.md
git diff -- planning/issues/012f-evidence-time-authority.md
git status --short
```

Expected: all assertions and `git diff --check` exit `0`; only local
documentation is changed. Do not commit or create the live issue.

---

### Task 2: Domain, Protocol, Architecture, and Roadmap Alignment

**Files:**
- Modify: `CONTEXT.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/PROTOCOL.md`
- Modify: `docs/ROADMAP.md`
- Modify: `planning/issues/012-evidence-binding-transcript-inputs.md`
- Reference: `planning/issues/012f-evidence-time-authority.md`
- Reference: `docs/superpowers/specs/2026-09-01-m1-012f-evidence-time-authority-design.md`

**Interfaces:**
- Consumes: canonical M1-012F issue terminology and authority relationships.
- Produces: one repository-wide domain and verifier-flow contract consumed by trust, privacy, threat, test, ADR, and scenario tasks.

- [ ] **Step 1: Capture unresolved-contract red assertions**

Run:

```bash
grep -F 'Evidence Collection Authority' CONTEXT.md
grep -F 'strictly increasing collection sequence' docs/PROTOCOL.md
grep -F 'M1-012F' docs/ROADMAP.md
```

Expected: each command exits `1` before the contract is integrated.

- [ ] **Step 2: Add canonical domain terms to `CONTEXT.md`**

Add these terms without representation leakage:

```markdown
- **Evidence Collection Authority**: the immutable-profile-registered trusted
  local component that opens one exact-challenge collection, controls protected
  local start and freeze semantics, and coordinates current claim collection;
  it does not authenticate publisher policy or appraise claims.
- **Frozen evidence snapshot**: the complete immutable profile-required claim
  and provenance set at protected collection end, before proof creation.
- **Protected epoch relation**: an opaque publisher/session-scoped proof of one
  uninterrupted local collection-authority lifetime; it is not UTC or a raw
  boot, clock, or reset identifier.
- **Temporal high-water**: active-session verifier authorization state holding
  accepted epoch relation, greatest validated sequence, and latest validated
  freeze end; it is not telemetry.
```

Cross-link `Evidence-binding transcript` to these terms and preserve
`EvidenceBundle`, `ExpectedContext`, profile, key/handle, and result boundaries.

- [ ] **Step 3: Add the collection and verifier flow to `docs/ARCHITECTURE.md`**

Add an `### Evidence-time collection authority` subsection adjacent to the
evidence-binding transcript architecture. Include:

1. exact challenge receipt before local collection open;
2. one active collection per protected session;
3. protected scope/epoch/sequence/start;
4. complete current claim collection or revalidation;
5. atomic snapshot freeze at end before proof creation;
6. independent publisher challenge authentication and freshness claim;
7. exact transcript reconstruction and coverage validation;
8. atomic temporal high-water compare/advance before later appraisal; and
9. active-session deletion or terminal invalidation behavior.

Add explicit architecture paragraphs stating that sequence is strictly
increasing rather than contiguous, valid gaps represent unobserved collections,
and local/verifier serialization are both required. State that authority restart
or protected-source restart terminates the current protected session and
requires new session/key/handle/epoch.

- [ ] **Step 4: Replace the unresolved protocol blocker in `docs/PROTOCOL.md`**

Keep the evidence-time semantic inside the M1-012 transcript shape, then define:

```text
evidence time:
  registered collection-authority contract
  opaque publisher/session protected epoch relation
  strictly increasing collection sequence
  protected collection start
  protected snapshot-freeze end
```

State single-challenge validity, freeze-before-proof, challenge-expiry receipt,
effective profile/publisher duration, no UTC/skew, renewal non-overlap, sequence
gaps, terminal continuity failure, and coarse failure mappings. Do not add JSON,
CBOR, bytes, field tags, numeric limits, or TPM semantics.

- [ ] **Step 5: Update roadmap ownership and M1-012 prerequisite status**

In `docs/ROADMAP.md`, replace “separately approved evidence-time authority
design is an earlier blocker” with a completed semantic boundary:

```markdown
M1-012F resolves the common evidence-time semantic prerequisite with one
challenge-anchored protected collection interval, registered local authority,
publisher/session-scoped epoch relation, strictly increasing sequence,
freeze-before-proof boundary, and terminal continuity loss. Task 13 may define
abstract semantic fixtures. Runtime representation and profile validation remain
M2 work, and TPM mapping remains M3 work.
```

Do not renumber the first 30 issues. Add M1-012F as an inserted prerequisite
annotation between roadmap tasks 12 and 13, not a new numbered issue.

In `planning/issues/012-evidence-binding-transcript-inputs.md`, preserve the
historical M1-012 contract but add a `## Evidence-time prerequisite resolution`
section linking M1-012F. State that the common semantic blocker is resolved only
at documentation level; M2/profile prerequisites remain.

- [ ] **Step 6: Verify and checkpoint Task 2**

Run:

```bash
grep -F 'Evidence Collection Authority' CONTEXT.md
grep -F 'Temporal high-water' CONTEXT.md
grep -F 'strictly increasing' docs/ARCHITECTURE.md docs/PROTOCOL.md
grep -F 'freeze-before-proof' docs/ROADMAP.md
grep -F 'Evidence-time prerequisite resolution' planning/issues/012-evidence-binding-transcript-inputs.md
grep -R -n 'evidence-time authority.*unresolved\|evidence-time prerequisite.*unresolved' CONTEXT.md docs planning/issues/012-evidence-binding-transcript-inputs.md
git diff --check -- CONTEXT.md docs/ARCHITECTURE.md docs/PROTOCOL.md docs/ROADMAP.md planning/issues/012-evidence-binding-transcript-inputs.md
git diff -- CONTEXT.md docs/ARCHITECTURE.md docs/PROTOCOL.md docs/ROADMAP.md planning/issues/012-evidence-binding-transcript-inputs.md
git status --short
```

Expected: positive assertions print matches; the stale-unresolved search prints
no active claim and exits `1` after reviewed historical/spec references are
excluded or reworded; `git diff --check` exits `0`. Do not commit.

---

### Task 3: Trust, Privacy, Threat, and Validation Contract

**Files:**
- Modify: `docs/TRUST_MODEL.md`
- Modify: `docs/PRIVACY_MODEL.md`
- Modify: `docs/THREAT_MODEL.md`
- Modify: `docs/TEST_STRATEGY.md`
- Modify if required by demonstrated gap: `docs/SECURITY_INVARIANTS.md`
- Reference: `planning/issues/012f-evidence-time-authority.md`

**Interfaces:**
- Consumes: Task 2 domain and flow contract.
- Produces: authority, disclosure, attack, and deterministic-validation rules consumed by ADR and scenarios.

- [ ] **Step 1: Capture missing trust/privacy/test red assertions**

Run:

```bash
grep -F 'Evidence Collection Authority' docs/TRUST_MODEL.md
grep -F 'temporal high-water' docs/PRIVACY_MODEL.md
grep -F 'sequence gaps' docs/TEST_STRATEGY.md
```

Expected: each exits `1` before alignment.

- [ ] **Step 2: Update `docs/TRUST_MODEL.md` with exact authority limits**

Under evidence-binding authorities, add:

- immutable profile registry owns authority contract and hard duration ceiling;
- collection authority owns only protected local interval/freeze semantics;
- claim producers retain provenance truth authority;
- generic attester cannot choose or rewrite temporal values;
- profile mechanism covers the complete frozen transcript;
- publisher verifier owns challenge auth, temporal validation/high-water, and
  acceptance;
- relying party remains authoritative for `ExpectedContext`; and
- protected-result issuer remains separate.

Add explicit “does not trust” bullets for client UTC, copied challenge time,
process uptime, raw boot/reset/TPM clock values, sequence supplied outside the
registered authority path, and client repair of missing high-water.

- [ ] **Step 3: Update `docs/PRIVACY_MODEL.md` with scoped epoch and retention**

Add these controls:

```markdown
- Evidence-time authority contract, scoped epoch relation, sequence, interval,
  duration, high-water, protected-source statement, and proof are confidential.
- The transcript exposes no raw boot identifier, boot seed, reset/restart
  counter, TPM clock, daemon uptime, host UTC, or device-wide epoch.
- Epoch equality is scoped to one publisher and protected session and is not a
  telemetry or analytics identifier.
- Verifier high-water is retained only for the active protected session and is
  deleted at terminal end after atomic in-flight resolution.
- Ordinary diagnostics reveal only fixed coarse redaction and operational
  disposition, never temporal values.
```

Preserve existing challenge replay retention as separate ADR-0005 state. State
that backup, replication, recovery, migration, and secure deletion enforcement
remain separately approved production work.

- [ ] **Step 4: Update `docs/THREAT_MODEL.md`**

Add or expand threats for:

- stale snapshot relabeled by recent collection;
- challenge/snapshot substitution and cross-context reuse;
- UTC/challenge/verifier/result/permit time confusion;
- local authority/protected-source/verifier-state rollback or restart;
- concurrent collection and atomic high-water race;
- forward discontinuity, unbounded duration, and arithmetic abuse;
- profile transition attempting to reset epoch/sequence;
- unavailable state causing stateless fallback; and
- temporal diagnostic/correlation leakage.

For each, state the exact response from the spec and retain residual risks:
compromised trusted producer/authority/verifier, full-session relay,
post-appraisal state change, no separately measured post-freeze latency, and
later mechanism/storage choices.

- [ ] **Step 5: Add the deterministic matrix to `docs/TEST_STRATEGY.md`**

Add a table with these rows and required outcomes:

| Case | Expected |
| --- | --- |
| valid initial collection | establish high-water |
| valid renewal | same epoch, greater sequence, non-overlap |
| dropped unobserved collection | later sequence gap remains valid |
| reused/decreased sequence | terminal `ProtectedSessionLost` |
| changed epoch/restart/rollback | terminal `ProtectedSessionLost` |
| overlapping/concurrent interval | exactly one atomic advance; other terminal |
| duration over effective ceiling | `EvidenceInvalid` |
| proof received at/after challenge expiry | existing challenge expiry failure |
| stale cached claim | current-state validation fails |
| UTC or other time substitution | malformed/unsupported, never normalized |
| temporary intact-state outage | retry/unavailable with fresh challenge |
| missing/corrupt/rolled-back high-water | terminal continuity loss |
| later appraisal rejection | validated temporal high-water remains advanced |
| invalid proof | candidate temporal values never advance high-water |
| terminal session end | temporal state deleted and old epoch cannot recover |
| diagnostics | no temporal or correlation value appears |

Require finite arbitrary-history modeling of open, freeze, drop, submit,
validate, reject, renew, concurrent submit, outage, rollback, restart, terminal
end, and deletion. State that mutation count follows the frozen inventory and no
byte fuzz target is added before M2 representation.

- [ ] **Step 6: Decide whether security invariants need a minimal amendment**

Compare existing invariants 9, 10, 37, 38, 41, and 42 against the approved
contract. Modify `docs/SECURITY_INVARIANTS.md` only if they do not already force:

- evidence single-challenge validity;
- protected interval/continuity behavior; or
- terminal loss on collection-authority restart.

If modification is required, add one concise invariant after current freshness
invariant 10:

```markdown
Evidence collection is bound to one fresh challenge and one uninterrupted
publisher/session-scoped protected epoch; rollback, restart, reused/decreased
sequence, overlap, or lost temporal high-water terminates the protected session.
```

Renumber later invariants and all references only if this line is added. If the
existing invariant set already covers the contract through documented
specialization, leave the file untouched and record that finding in Task 6.

- [ ] **Step 7: Verify and checkpoint Task 3**

Run:

```bash
grep -F 'Evidence Collection Authority' docs/TRUST_MODEL.md
grep -F 'temporal high-water' docs/PRIVACY_MODEL.md
grep -F 'sequence gaps' docs/TEST_STRATEGY.md
grep -F 'stale snapshot' docs/THREAT_MODEL.md
grep -F 'invalid proof' docs/TEST_STRATEGY.md
git diff --check -- docs/TRUST_MODEL.md docs/PRIVACY_MODEL.md docs/THREAT_MODEL.md docs/TEST_STRATEGY.md docs/SECURITY_INVARIANTS.md
git diff -- docs/TRUST_MODEL.md docs/PRIVACY_MODEL.md docs/THREAT_MODEL.md docs/TEST_STRATEGY.md docs/SECURITY_INVARIANTS.md
git status --short
```

Expected: all positive assertions and `git diff --check` pass; no runtime
enforcement claim, raw temporal fixture, or production mechanism is introduced.
Do not commit.

---

### Task 4: Durable Architecture Decision

**Files:**
- Create: `docs/adr/0011-challenge-anchored-evidence-time.md`
- Modify: `docs/adr/index.md`
- Modify: `docs/adr/0010-semantic-evidence-binding-transcript.md`
- Reference: `docs/adr/template.md`

**Interfaces:**
- Consumes: Tasks 1-3 authority, lifecycle, threat, privacy, and validation language.
- Produces: one accepted durable decision and an explicit resolution link from ADR-0010.

- [ ] **Step 1: Capture ADR/index red checkpoints**

Run:

```bash
test -f docs/adr/0011-challenge-anchored-evidence-time.md
grep -F 'ADR-0011' docs/adr/index.md
```

Expected: both commands exit `1`.

- [ ] **Step 2: Create ADR metadata and context**

Start with:

```markdown
# ADR-0011: Use challenge-anchored protected collection intervals for evidence time

- Status: Accepted
- Date: 2026-09-01
- Owners: Initial maintainer
- Related issues: [M1-012F](../../planning/issues/012f-evidence-time-authority.md)
- Supersedes: None
- Superseded by: None
```

Follow every `docs/adr/template.md` section exactly once. Context and drivers
must cover the M1-012 blocker, mixed claim-event times, unavailable trustworthy
client UTC, snapshot coherence, renewal continuity, rollback/restart, privacy,
and representation deferral.

- [ ] **Step 3: Record options and exact decision**

Record and disposition all options from the spec:

- challenge-anchored protected collection interval: selected;
- synchronized UTC plus monotonic: rejected for expanded trust/skew/rollback;
- nonce-only rough epoch: rejected as insufficient for interval/continuity;
- per-claim timestamps: rejected for vocabulary/privacy/authority expansion;
- unconstrained profile-specific union: rejected for fragmentation;
- proof-completion time: rejected for self-reference;
- verifier-assigned evidence time: rejected for authority confusion;
- contiguous accepted sequence: rejected because unobserved drops create gaps;
- same-session restart resume: rejected pending durable recovery design; and
- raw boot/TPM epoch: rejected for correlation and premature TPM coupling.

The Decision section must state the semantic tuple, authority split, complete
initial/renewal order, strict non-contiguous increase, high-water timing,
terminal continuity loss, temporary outage condition, privacy/retention, and
all non-goals.

- [ ] **Step 4: Complete consequences, threat, privacy, dependency, validation, rollback, and sources**

Use the approved spec as the exhaustive checklist. The Rollback section must
state that removing epoch/sequence/interval semantics, substituting UTC, or
allowing same-session restart is not an acceptable rollback; reversal requires
a superseding ADR, versioning, threat/privacy review, and new conformance cases.

Dependency impact must state no dependency, manifest, lockfile, runtime TCB
implementation, TPM, crypto, or license change. Primary sources must link the
exact RFC sections and ADRs 0005-0010.

- [ ] **Step 5: Index ADR-0011 and link ADR-0010 resolution**

Append this exact index row in numeric order:

```markdown
| [ADR-0011](0011-challenge-anchored-evidence-time.md) | Accepted | Evidence time is one challenge-anchored protected collection interval with scoped epoch and monotonic same-session continuity. | None | None |
```

Add a final `## Follow-up resolution` section to ADR-0010, without rewriting its
historical decision:

```markdown
## Follow-up resolution

[ADR-0011](0011-challenge-anchored-evidence-time.md) resolves the common
evidence-time semantic prerequisite with a challenge-anchored protected
collection interval. Representation, cryptography, profile mechanisms, numeric
limits, persistence implementation, and TPM mapping remain deferred.
```

- [ ] **Step 6: Verify and checkpoint Task 4**

Run:

```bash
./scripts/check-adr-index.sh
grep -F 'ADR-0011' docs/adr/index.md
grep -F 'strictly increase' docs/adr/0011-challenge-anchored-evidence-time.md
grep -F 'Follow-up resolution' docs/adr/0010-semantic-evidence-binding-transcript.md
git diff --check -- docs/adr/0010-semantic-evidence-binding-transcript.md docs/adr/0011-challenge-anchored-evidence-time.md docs/adr/index.md
git diff -- docs/adr/0010-semantic-evidence-binding-transcript.md docs/adr/0011-challenge-anchored-evidence-time.md docs/adr/index.md
git status --short
```

Expected: ADR gate reports 11 decision records, all assertions pass, and only
documentation changes remain. Do not commit.

---

### Task 5: Machine-readable Evidence-time Attack Scenarios

**Files:**
- Modify: `lab/scenarios/evidence-transcript-time-authority-confusion.scenario.json`
- Modify: `lab/scenarios/evidence-transcript-diagnostics-privacy.scenario.json`
- Create: `lab/scenarios/evidence-time-stale-snapshot.scenario.json`
- Create: `lab/scenarios/evidence-time-temporal-reuse.scenario.json`
- Create: `lab/scenarios/evidence-time-authority-restart.scenario.json`
- Create: `lab/scenarios/evidence-time-concurrent-collection.scenario.json`
- Create: `lab/scenarios/evidence-time-duration-expiry.scenario.json`
- Create: `lab/scenarios/evidence-time-high-water-loss.scenario.json`
- Create: `lab/scenarios/evidence-time-state-unavailable.scenario.json`
- Reference: `lab/scenarios/schema.json`

**Interfaces:**
- Consumes: Task 3 threat/test matrix and Task 4 accepted decision.
- Produces: nine schema-valid temporal attack scenarios with existing registry owner/profile identifiers and no schema change.

- [ ] **Step 1: Capture scenario red checkpoints**

Run:

```bash
test -f lab/scenarios/evidence-time-stale-snapshot.scenario.json
grep -F 'strictly increasing' lab/scenarios/evidence-transcript-time-authority-confusion.scenario.json
```

Expected: both exit `1` before scenario delivery.

- [ ] **Step 2: Replace unresolved time-authority scenario with resolved confusion attacks**

Keep ID `OGIR-EVIDENCE-TRANSCRIPT-TIME-AUTHORITY-001`, owner
`initial-maintainer`, profile `all-protected-modes`, and `automatic_ban: false`.
Replace the unresolved precondition/expected state with:

```json
{
  "preconditions": ["a registered profile requires challenge-anchored protected collection time"],
  "steps": [
    "copy challenge issued_at expires_at verifier now result time permit time client UTC or process uptime into evidence time",
    "omit authority epoch sequence start or freeze end or replace one with zero maximum or always-valid data",
    "ask the verifier to apply skew clamp or normalize the substituted value"
  ],
  "expected": {"decision": "deny", "reason": "evidence-invalid", "automatic_ban": false},
  "invariants": [
    "only the registered collection-authority statement supplies evidence-time semantics",
    "client UTC and every other protocol time domain have no evidence-time skew allowance",
    "malformed or unsupported temporal semantics never normalize into acceptance"
  ],
  "residual_risk": ["a compromised registered collection authority remains inside the trusted computing base"]
}
```

Preserve all required top-level fields and use the arrays above as field
replacements, not a nested object.

- [ ] **Step 3: Expand the existing diagnostics scenario**

Keep its existing ID and add epoch relation, collection sequence, start, freeze
end, duration, temporal high-water, protected-source state, raw boot/TPM/reset
values, and authority contract detail to the attempted disclosure and invariant
lists. Require active-session-only state and terminal deletion. Do not place
realistic timestamp, identity, key, or proof values in the fixture.

- [ ] **Step 4: Add stale-snapshot and temporal-reuse scenarios**

Create `evidence-time-stale-snapshot.scenario.json` with:

```json
{
  "id": "OGIR-EVIDENCE-TIME-STALE-SNAPSHOT-001",
  "title": "Relabel stale cached claims with a recent collection interval",
  "attacker": "A1",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": ["evidence_appraisal_integrity", "protected_session_authorization"],
  "preconditions": ["the collection authority can access cached boot manifest or enforcement observations"],
  "steps": [
    "receive a fresh publisher challenge and open a valid protected collection interval",
    "reuse an old claim without current-subject revalidation",
    "present recent snapshot freeze as proof that the old claim still describes current state"
  ],
  "expected": {"decision": "deny", "reason": "evidence-invalid", "automatic_ban": false},
  "invariants": [
    "snapshot time never replaces registered claim provenance or current-state validation",
    "every bound claim is newly collected or revalidated for the live appraisal subject"
  ],
  "residual_risk": ["a compromised registered producer can provide dishonest but structurally current evidence"]
}
```

Create `evidence-time-temporal-reuse.scenario.json` with ID
`OGIR-EVIDENCE-TIME-TEMPORAL-REUSE-001`, attacker `A1`, assets
`protected_session_authorization` and `verifier_temporal_high_water`. Steps must
attempt same/lower sequence, prior interval, prior challenge, cross-session
epoch, and old-session recovery. Expected decision is `deny`, reason
`protected-session-lost`, automatic ban false. Invariants require strictly
greater non-contiguous sequences, same epoch, non-overlap, single-challenge
evidence, and new key/handle/epoch after terminal loss.

- [ ] **Step 5: Add restart and concurrency scenarios**

Create `evidence-time-authority-restart.scenario.json` with ID
`OGIR-EVIDENCE-TIME-AUTHORITY-RESTART-001`, attacker `A4`, assets
`protected_session_authorization` and `evidence_appraisal_integrity`. Steps must
restart/rollback the authority or source, bind a fresh nonce under changed or
old epoch state, and request same-session renewal. Expected decision is `deny`,
reason `protected-session-lost`, automatic ban false. Invariants require
terminal session loss and new session/key/handle/epoch recovery.

Create `evidence-time-concurrent-collection.scenario.json` with ID
`OGIR-EVIDENCE-TIME-CONCURRENT-COLLECTION-001`, attacker `A1`, assets
`verifier_temporal_high_water` and `protected_session_authorization`. Steps race
two collections from one prior high-water and submit both. Expected decision is
`deny`, reason `protected-session-lost`, automatic ban false. Invariants require
one active local collection, atomic verifier compare/advance, and no two
successful transitions from one prior high-water.

- [ ] **Step 6: Add duration/expiry and unavailable-state scenarios**

Create `evidence-time-duration-expiry.scenario.json` with ID
`OGIR-EVIDENCE-TIME-DURATION-EXPIRY-001`, attacker `A1`, assets
`evidence_appraisal_integrity` and `verifier_freshness_state`. Steps exceed the
effective collection ceiling, delay proof/transport to exact challenge expiry,
and request post-freeze latency normalization. Expected decision is `deny`,
reason `evidence-invalid`, automatic ban false. Invariants require finite
profile ceiling, publisher tightening only, existing challenge half-open expiry,
and no invented post-freeze field.

Create `evidence-time-state-unavailable.scenario.json` with ID
`OGIR-EVIDENCE-TIME-STATE-UNAVAILABLE-001`, attacker `A5`, assets
`verifier_temporal_high_water` and `protected_session_authorization`. Steps make
intact authoritative state temporarily inaccessible, request stateless fallback
or client repair, and retry after the same state becomes available. Expected
decision is `retry`, reason `attestation-unavailable`, automatic ban false.
Invariants require unchanged authoritative state, no high-water mutation during
the outage, no fallback, and a fresh challenge for retry.

Create `evidence-time-high-water-loss.scenario.json` with ID
`OGIR-EVIDENCE-TIME-HIGH-WATER-LOSS-001`, attacker `A5`, assets
`verifier_temporal_high_water` and `protected_session_authorization`. Steps make
active-session high-water missing, corrupt, contradictory, or rolled back, ask
the verifier to reconstruct it from client evidence, and request same-session
renewal. Expected decision is `deny`, reason `protected-session-lost`, automatic
ban false. Invariants require terminal continuity loss, no client repair or
stateless fallback, and new session/key/handle/epoch recovery.

- [ ] **Step 7: Validate exact scenario inventory and privacy**

Run:

```bash
./scripts/check-attack-scenario-traceability.py
test "$(find lab/scenarios -maxdepth 1 -type f -name '*.scenario.json' | wc -l)" -eq 30
grep -R -n 'evidence-time-authority-unresolved' lab/scenarios
grep -R -n 'Signed-off-by\|PRIVATE KEY\|BEGIN .* KEY' lab/scenarios
git diff --check -- lab/scenarios
git diff -- lab/scenarios
git status --short
```

Expected: validator reports 30 scenarios; both forbidden searches print nothing
and exit `1`; `git diff --check` exits `0`. No schema, registry, executable, or
runtime source changes. Do not commit.

---

### Task 6: Traceability, Scope Audit, and Full Verification

**Files:**
- Modify as needed for factual consistency only: every Task 1-5 file
- Create ignored progress/report artifacts under the active `.superpowers/sdd/` execution directory if the executing workflow uses them
- Reference: approved spec and this plan

**Interfaces:**
- Consumes: the complete uncommitted Tasks 1-5 candidate.
- Produces: one internally consistent, fully verified documentation candidate ready for exact human review and separate publication authorization.

- [ ] **Step 1: Build a requirement-to-artifact matrix**

Record each row in the execution report and verify at least these destinations:

| Requirement | Required artifacts |
| --- | --- |
| authority registration and limits | issue, context, trust, protocol, ADR |
| tuple and scope | issue, context, protocol, architecture, ADR |
| receive/open/collect/freeze/proof order | issue, architecture, protocol, ADR, tests |
| single-challenge validity | issue, protocol, threat, tests, scenarios |
| no UTC/skew | issue, protocol, privacy, threat, ADR, scenario |
| strict non-contiguous sequence | issue, architecture, protocol, test, ADR, scenario |
| atomic high-water before appraisal | architecture, protocol, threat, test, ADR |
| rollback/restart terminal behavior | issue, architecture, threat, ADR, scenarios |
| temporary outage distinction | issue, architecture, failure table, test, scenario |
| stale claim revalidation | issue, architecture, threat, test, scenario |
| privacy/retention/diagnostics | privacy, trust, threat, ADR, scenario |
| task 13/M2/M3 boundaries | roadmap, issue, ADR, M1-012 resolution |

Any missing row is a defect; make the smallest factual correction before
continuing.

- [ ] **Step 2: Search for stale blocker and semantic contradictions**

Run focused searches:

```bash
grep -R -n 'evidence-time.*unresolved\|time authority.*unresolved' CONTEXT.md docs planning lab/scenarios
grep -R -n 'contiguous.*sequence\|exact next sequence' CONTEXT.md docs planning lab/scenarios
grep -R -n 'client.*UTC.*authoritative\|challenge.*issued_at.*evidence time\|verifier.*now.*evidence time' CONTEXT.md docs planning lab/scenarios
grep -R -n 'resume.*same.*session.*restart\|reuse.*snapshot.*challenge' CONTEXT.md docs planning lab/scenarios
grep -R -n 'raw TPM clock\|raw boot.*epoch\|device-wide epoch' CONTEXT.md docs planning lab/scenarios
```

Expected: no active text contradicts the approved contract. Historical design
discussion and explicit rejected/prohibited statements are allowed only after
manual context inspection.

- [ ] **Step 3: Audit scope and repository state**

Run:

```bash
git status --short
git diff --name-only 2bc3a6d4f9a3edeee829e3a8e620daa3df7d3f85
git diff --stat 2bc3a6d4f9a3edeee829e3a8e620daa3df7d3f85
git diff --check
```

Expected tracked paths are limited to:

```text
CONTEXT.md
docs/ARCHITECTURE.md
docs/PRIVACY_MODEL.md
docs/PROTOCOL.md
docs/ROADMAP.md
docs/SECURITY_INVARIANTS.md (only if Task 3 proves required)
docs/TEST_STRATEGY.md
docs/THREAT_MODEL.md
docs/TRUST_MODEL.md
docs/adr/0010-semantic-evidence-binding-transcript.md
docs/adr/0011-challenge-anchored-evidence-time.md
docs/adr/index.md
docs/superpowers/plans/2026-09-01-m1-012f-evidence-time-authority-documentation.md
lab/scenarios/evidence-transcript-diagnostics-privacy.scenario.json
lab/scenarios/evidence-transcript-time-authority-confusion.scenario.json
lab/scenarios/evidence-time-authority-restart.scenario.json
lab/scenarios/evidence-time-concurrent-collection.scenario.json
lab/scenarios/evidence-time-duration-expiry.scenario.json
lab/scenarios/evidence-time-high-water-loss.scenario.json
lab/scenarios/evidence-time-stale-snapshot.scenario.json
lab/scenarios/evidence-time-state-unavailable.scenario.json
lab/scenarios/evidence-time-temporal-reuse.scenario.json
planning/issues/012-evidence-binding-transcript-inputs.md
planning/issues/012f-evidence-time-authority.md
```

The approved spec is already committed in the base and should be unchanged.
Rust, Cargo, shell, workflow, schema, dependency, generated, and binary changes
are scope violations.

- [ ] **Step 4: Run the complete repository gate**

Run:

```bash
./scripts/check.sh
git diff --check
```

Expected after this plan: 225 runtime/integration tests, 111 doctests, 30 attack
scenarios, 11 ADRs, formatting, Clippy, rustdoc, metadata, bootstrap, DCO test
suite, scenario negative suite, and dependency policy all pass. Report actual
counts from output rather than copying expected counts if they differ.

- [ ] **Step 5: Perform the final AI self-review**

Inspect the entire candidate for:

- fail-open fallback;
- challenge/snapshot cross-context replay;
- client-controlled authority;
- sequence-gap confusion versus rollback detection;
- high-water update ordering and atomicity;
- restart or profile-transition continuity bypass;
- interval arithmetic or boundary ambiguity;
- stale claims relabeled by collection time;
- UTC/skew or other time-domain substitution;
- post-freeze self-reference or unverifiable latency;
- privacy/correlation leakage and unbounded retention;
- disciplinary interpretation of failure;
- accidental runtime, representation, crypto, TPM, or production-limit claims;
- missing negative tests or scenario ownership; and
- stale M1-012/task-13/M2/M3 ownership text.

Fix only evidence-backed defects and rerun the affected focused checks plus the
full gate.

- [ ] **Step 6: Freeze and report the exact candidate without mutation**

Run:

```bash
git diff --binary 2bc3a6d4f9a3edeee829e3a8e620daa3df7d3f85 > /tmp/ogir-m1-012f-documentation.patch
sha256sum /tmp/ogir-m1-012f-documentation.patch
candidate_index="$(mktemp)"
rm -f "$candidate_index"
GIT_INDEX_FILE="$candidate_index" git read-tree HEAD
GIT_INDEX_FILE="$candidate_index" git add -- \
  CONTEXT.md \
  docs/ARCHITECTURE.md \
  docs/PRIVACY_MODEL.md \
  docs/PROTOCOL.md \
  docs/ROADMAP.md \
  docs/SECURITY_INVARIANTS.md \
  docs/TEST_STRATEGY.md \
  docs/THREAT_MODEL.md \
  docs/TRUST_MODEL.md \
  docs/adr/0010-semantic-evidence-binding-transcript.md \
  docs/adr/0011-challenge-anchored-evidence-time.md \
  docs/adr/index.md \
  lab/scenarios/evidence-transcript-diagnostics-privacy.scenario.json \
  lab/scenarios/evidence-transcript-time-authority-confusion.scenario.json \
  lab/scenarios/evidence-time-authority-restart.scenario.json \
  lab/scenarios/evidence-time-concurrent-collection.scenario.json \
  lab/scenarios/evidence-time-duration-expiry.scenario.json \
  lab/scenarios/evidence-time-high-water-loss.scenario.json \
  lab/scenarios/evidence-time-stale-snapshot.scenario.json \
  lab/scenarios/evidence-time-state-unavailable.scenario.json \
  lab/scenarios/evidence-time-temporal-reuse.scenario.json \
  planning/issues/012-evidence-binding-transcript-inputs.md \
  planning/issues/012f-evidence-time-authority.md
GIT_INDEX_FILE="$candidate_index" git write-tree
rm -f "$candidate_index"
git status --short --branch
```

Record the exact patch hash, candidate tree, changed paths, test commands,
actual counts, limitations, residual risks, and review findings in the execution
report and canonical archledger handoff.

The temporary index is command-scoped rather than exported. Do not run tests
with `GIT_INDEX_FILE` set: repository fixture tests create nested Git stores and
must observe their own indexes. If Task 3 leaves `docs/SECURITY_INVARIANTS.md`
unchanged, it is still safe to add its unchanged path to the candidate index.

Do not create a commit, live issue, push, remote branch, PR, DCO certification,
or merge. Present the exact verified candidate for human decision-owner review.
Any later authorization applies only to that exact frozen candidate; if content
changes, refreeze, reverify, and obtain new certification.

---

## Execution Handoff

This project has already selected inline execution without subagents. After the
decision owner approves and certifies the exact plan candidate, invoke
`superpowers:executing-plans` in this isolated worktree and execute Tasks 1-6 in
order with review checkpoints. Do not dispatch subagents and do not perform any
remote or GitHub mutation unless separately authorized.
