# M1-015 Renewal and Revocation Semantics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Integrate the approved renewal/revocation semantic design as a coherent documentation and attack-scenario contract, with every one of its 34 acceptance criteria traceable.

**Architecture:** Finite permits and authenticated revocation views bound authorization; known applicable revocation is rejected at the next protected decision. One logical session-authorization owner orders successor commitment, installation and terminal state across all relying-party replicas. This change specifies those obligations without implementing runtime authority or choosing deployment mechanisms.

**Tech Stack:** Markdown, the existing bounded JSON attack-scenario schema and Python standard-library validator, current Git metadata/ADR gates. The existing Rust 1.98.0 workspace and dependency set remain unchanged.

**Spec:** [Approved semantic design](../specs/2026-09-04-m1-015-renewal-revocation-semantics-design.md), SHA-256 `2e1969abef5f6348caf787ee965875d0f831eb508366e3fb1851e2d983d525ba`. [Local issue proposal](../../../planning/issues/015-renewal-revocation-semantics.md), SHA-256 `cb37ea854955ea1c5e844645f7d249c66396b4ed078fe7297440b854c76aaa02`. Human approval received 2026-09-04 and recorded in [approval provenance](../specs/2026-09-04-m1-015-renewal-revocation-semantics-design.md#12-approval-and-scope). Task 1 carries the approved spec into the execution checkout so this plan does not depend on external memory after integration.

## Global Constraints

These quoted constraints come from the approved spec; the full spec remains authoritative.

- “The following are semantic relationships, **not proposed wire fields or Rust types**” (section 3).
- “Equality with any exclusive deadline is already too late. There is no grace period or timer reset on retry, reconnect, replay, refresh failure or process restart.” (section 4.2).
- “Starting renewal grants nothing and extends nothing.” (section 5.3).
- “One local pending phase may contain such bounded attempts; it cannot return to Active using the old permit.” (section 5.3).
- “No account-ban, global device fingerprint or universal player revocation identifier is introduced.” (section 6.1).
- “Do not edit prior accepted ADR decisions or completed checkpoint history.” (section 10).
- “No runtime implementation plan is authorized by this design-only task.” (section 10).

Preserve ADRs 0005–0013, all 48 invariants, local/verifier graphs, phase-restricted failure APIs, five purpose domains, allowed profile transitions, M1-013 corpus/schema/checker and registry semantics and M1-014 isolated research cache. No Rust, Cargo, dependency, CI, checker or schema edits. The approved compatibility correction may update only the closed scenario inventory/count/expected normal output in `validators.json`, its root shard hash, and the three count assertions/canonical root hash in `m1_013_plan_registry.py`; the checker, schema, limits and rejection semantics remain unchanged. No timers, codec, signature scheme, service, numeric TTL, database or production guarantee. An actual conflict with accepted authority requires a separately approved superseding design, not silent edits.

Use `initial-maintainer` and `all-protected-modes`, already registered in `scripts/check-attack-scenario-traceability.py`. All scenario examples are synthetic semantic text; `automatic_ban` is always false. Planned examples and schema validation are not runtime tests.

Checkpoint after each material change. Automatic per-task commits from a generic skill are replaced by local checkpoints: a new contribution needs exact human line review/DCO certification before a signed commit. This plan neither reuses old certification nor authorizes remote issue/PR publication.

## Starting State and File Ownership

Fresh GitHub main query at plan preparation returned `5f6d96dedfe20141bafb0de7af84ef534298e9c4`; tree `d4d446238196693e8ea5825ceace1251d26914cd`. Retained Task14 checkout is at `a230f19532e600365291f2da6d6def9feab5ee98`, with the same tree. Only this untracked planning document is added there. Do not repoint or reuse that branch for Task15 execution. The plan itself is not an executed task or proof that any future check passes.

At the verified baseline there are 13 ADRs and 30 attack scenarios. ADR-0014 and the ten scenario IDs below were free when planning; recheck against the execution baseline before creating them. If a name was taken, choose the next unused identifier and update this plan, all mappings and the checkpoint together; do not overwrite another task.

| Action | Exact repository path | Responsibility |
| --- | --- | --- |
| Create | `docs/superpowers/specs/2026-09-04-m1-015-renewal-revocation-semantics-design.md` | Approved semantic authority and 34 unchanged criteria, with integration provenance. |
| Create | `planning/issues/015-renewal-revocation-semantics.md` | Canonical local issue and acceptance/validation scope. |
| Carry | `docs/superpowers/plans/2026-09-04-m1-015-renewal-revocation-semantics.md` | This execution plan, then completed-task evidence links. |
| Create | `docs/adr/0014-renewal-revocation-semantics.md` | Proposed durable decision using the existing template. |
| Modify | `docs/adr/index.md` | Matching Proposed index entry; no earlier ADR mutation. |
| Modify | `docs/ARCHITECTURE.md` | Sections 7.5/7.6 and precise role/authority links. |
| Modify | `docs/PROTOCOL.md` | Semantic renewal/revocation requirements and deferred M2 encoding/mechanisms. |
| Modify | `docs/THREAT_MODEL.md` | Authority/replica/time boundaries, ten scenario mappings and residual risks. |
| Modify | `docs/PRIVACY_MODEL.md` | Bounded live state versus separately governed negative history. |
| Modify | `docs/ROADMAP.md` | Item 15/M1 specification evidence; maintain M2 mechanism gates. |
| Modify | `docs/TEST_STRATEGY.md` | All 34 criterion mappings, positive/negative controls and evidence limits. |
| Modify | `docs/LESSONS_LEARNED.md` | Append the two observed design-review ambiguities and their prevention. |
| Create | Ten exact `lab/scenarios/*.scenario.json` paths in Task 4 | Machine-readable attack specifications under unchanged schema. |
| Modify | `docs/superpowers/plans/m1-013-format-v1/validators.json` | Extend the closed source inventory from the exact 30-file baseline to the exact 40-file candidate; update only its count and normal CLI expected output. |
| Modify | `docs/superpowers/plans/2026-09-02-m1-013-format-v1-registry.json` | Update only the validators-shard SHA-256. |
| Modify | `scripts/m1_013_plan_registry.py` | Update only three admitted-inventory count assertions and the canonical root-registry SHA-256. |

No new glossary is necessary; define the owner, committed successor, installed generation and view freshness together in architecture, then link to those definitions. Keep completed evidence sections intact. Excluding ignored verification artifacts, the approved corrected scope is 25 paths: 12 documents, ten scenarios and three closed planning-authority inventory files.

## Task 1: Isolate the Verified Baseline and Carry Approved Inputs

**Files:** Create the formal spec/local issue and carry this plan. Read project instructions and existing checks. Store local execution evidence in ignored `.superpowers/sdd/2026-09-04-m1-015-renewal-revocation-semantics/` only after checking that directory is ignored; otherwise keep evidence in canonical external task15-scoping.

**Interfaces:** Consumes the two exact approved source hashes and verified merge. Produces an isolated execution checkout with recorded actual branch/HEAD, baseline source inventory and repository-relative spec/issue/plan links. No runtime interface.

- [x] Read canonical `index.md`, OGIR handoff and the chosen checkout's `AGENTS.md`; follow its mandatory reading order, then read the approved issue/design and relevant ADRs.
- [x] Recheck source hashes and fresh main. Inspect any advancement and its effect on this scope; preserve unrelated work and do not assume tree equality after an advance.

```bash
gh api repos/archledger/open-game-integrity-runtime/git/ref/heads/main --jq .object.sha
git status --porcelain=v1
git rev-parse HEAD 'HEAD^{tree}' origin/main
git worktree list --porcelain
```

- [x] Use `superpowers:using-git-worktrees` to create an isolated Task15 checkout at the verified merged baseline. Record its actual location, branch, HEAD/tree and clean initial state. Take SHA-256 inventory of all baseline tracked files before edits; include accepted ADRs, Cargo inputs, runtime, scripts, schema and old scenarios. No network mutation is needed.
- [x] Copy the approved design/issue and this plan to their specified repository paths. Preserve design sections 2–9 and 11 semantic/source text exactly. Change only title/status/provenance, section 1 from a pending decision to the human-approved choice, and section 10 from pending approval to this integration stage. Keep historical source-access and review limitations factual; replace external evidence references with self-contained provenance and repo links rather than broken local paths.
- [x] The formal spec states “Human-approved semantic design; documentation integration candidate; production mechanisms unimplemented.” The issue states “Local integration candidate; no live GitHub issue yet.” Keep canonical labels/milestone from the approved issue; link its design to `../../docs/superpowers/specs/2026-09-04-m1-015-renewal-revocation-semantics-design.md`. Change this plan's spec/issue Markdown links to the repository destinations. Preserve the original approval hashes as provenance, not as hashes of normalized copies.
- [x] Confirm all 34 criterion IDs/texts survived, relative links resolve, source sections are semantically unchanged and the execution source baseline is still unchanged. Run the existing scenario checker and ADR gate to capture starting counts (expected 30/13 only if baseline unchanged). Capture exits, then checkpoint. No commit.

## Task 2: Record the Durable Decision

**Files:** Create `docs/adr/0014-renewal-revocation-semantics.md`; update `docs/adr/index.md`.

**Interfaces:** Consumes formal spec sections 1–8 and 10–11. Produces a Proposed ADR with a matching index row and clear future mechanism obligations.

- [x] Recheck ID availability. Use every heading in `docs/adr/template.md`. Set title `ADR-0014: Specify renewal and revocation semantics`, Status `Proposed`, actual date, Owners `Initial maintainer`, Related issues links to the local issue and formal spec, Supersedes `None`, Superseded by `None`. Human design approval is recorded in Context; the new ADR remains Proposed as agreed for integration, not automatically Accepted.
- [x] Context/drivers explain the gap between existing local/verifier capability ordering and permit/revocation semantics. Options record A finite authorization/view freshness selected, B synchronous checks as a possible stricter implementation, and C honoring known-revoked permits rejected under invariant 6.
- [x] Decision carries the approved clock/deadline contracts, complete ordered views, independent revocation authority, coherent owner, distinct pending/committed/installed states, precommit retry versus exact committed redelivery, terminality, explicit non-weakening transitions and bounded state. Cross-reference full spec rather than inventing fields. State that late callbacks/deliveries cannot erase a logically expired terminal gap.
- [x] Consequences/Threat-model/Privacy sections state availability costs, finite propagation premises, dependency coverage, source compromise residual risk and retention prerequisites. Dependency/license impact: no new dependency or boundary change; future trusted mechanisms require their own review. Validation points to all 34 criteria and Task 4 mappings, explicitly labeling execution status. Rollback: before integration discard/revise the proposal; after acceptance use a superseding decision and separately reviewed revert, never delete accepted history. Primary sources retain the exact approved RFC references and their informative scope.
- [x] Add the index row `Proposed`, with the same filename/number and both supersession columns `None`. Run candidate-index ADR/metadata checks using Task 6's isolated-index procedure; verify prior ADR bytes unchanged and checkpoint.

## Task 3: Align Architecture, Protocol and Roadmap

**Files:** Modify `docs/ARCHITECTURE.md`, `docs/PROTOCOL.md`, `docs/ROADMAP.md`.

**Interfaces:** Consumes Proposed ADR and formal spec. Produces mutually consistent normative semantic requirements with explicit unimplemented mechanisms. Task 4 and Task 5 link here.

- [x] Expand architecture sections 7.5/7.6 with owner and consumer roles, fresh challenge/evidence and complete target classes. Explain that all RP replicas require coherent current owner state and fail unavailable when it cannot be established. Distinguish one uncommitted attempt, one committed undelivered successor and current installed generation; no independent owner or migration in the first profile.
- [x] Describe commit and installation fences against current predecessor, terminal state, policy and accepted revocation updates. Installation invalidates predecessor authorization for subsequent decisions across replicas; prior committed decisions are not rewritten, and continuous activity has a finite reevaluation contract. Redelivery never changes bytes/deadlines or issues another successor.
- [x] In protocol, add a linked semantic section covering exact exclusive deadlines, comparable clock requirements and conservative bounded uncertainty, authenticated complete views, source order/conflict handling, refresh of live state, local knowledge versus remote propagation, and distinct issuer/admission checks. A valid new view may move the current freshness limit within immutable permit expiry; invalid candidates cannot revoke or extend a valid current view. A gap cannot resurrect a terminal session.
- [x] State the fresh initial-session recovery boundary and explicit publisher-approved non-weakening profile/policy transition relation. Preserve the existing valid-profile-transition fixture as temporal evidence only. Keep the five semantic purpose domains unchanged and do not introduce protocol fields, signing algorithms, endpoints, timers or numeric production defaults.
- [x] Update roadmap item 15 and M1 deliverables to link the specification candidate and evidence. Mark only specification work actually completed; do not claim operational renewal/revocation or M1/M2 milestone completion. List remaining M2 permit/result representation, possession, trusted time, view/source authentication, owner coordination, durable recovery and bounded retention gates. M3 TPM work stays separate.
- [x] Cross-read architecture/protocol/spec for differences in deadline equality, old-permit use, new-view refresh, profile changes, owner unavailable behavior and recovery. Check links and diff whitespace; compare runtime/Cargo/accepted ADR baseline hashes and checkpoint.

## Task 4: Encode Attack Scenarios and All Criterion Mappings

**Files:** Create exactly the ten scenario files below. Modify `docs/THREAT_MODEL.md` and `docs/TEST_STRATEGY.md`.

**Interfaces:** Consumes the unchanged schema and approved criterion IDs. Produces ten single JSON documents plus a 34-row documentation traceability table. Uses no new schema fields, registry values or executable runtime model.

- [x] Confirm global ID/path uniqueness and existing limits. With the current baseline, total scenario count becomes 40, within the existing limit of 128. Do not change that limit to accommodate a collision or scope growth.
- [x] For each row below, create `lab/scenarios/<stem>.scenario.json` using the shown schema example. Use its exact ID/attacker/expected disposition, semantic assets, preconditions, attack steps and residual risk. Include each assigned criterion as an `invariants` string of the form `M1-015 R01: <exact criterion text>` from the mapping table. These task-local labels are prose within an existing schema field, not global invariant renumbering or new API reason codes.
- [x] The negative event sequence must actually reach the selected outcome. Distinguish candidate rejection preserving a valid current view from authoritative conflict making state unavailable; a scenario with multiple branches describes each separately. `expected.reason` is descriptive scenario text, not an invented Rust enum variant. Add the positive control and each criterion's distinguishing examples to the test-strategy table. Label every new row “specified; runtime proof deferred”.

### S01: renewal-pending-expiry

- **File/ID:** `lab/scenarios/renewal-pending-expiry.scenario.json` / `OGIR-RENEWAL-PENDING-EXPIRY-001`.
- **Attacker / criteria / existing invariants:** A1; R01 R02 R03 R04 R05 R12; 3,5,7–10,41–42.
- **Negative sequence:** Start renewal with a still-valid current permit, then delay the successor until the exact effective expiry. Attempt to install it after terminal invalidation.
- **Expected:** `deny` / `expired`; `automatic_ban: false`.
- **Positive control:** Before expiry, a fresh complete renewal may succeed; an intact transient attempt failure grants nothing but may preserve independently valid old authorization.
- **Residual risk:** Trusted time and timely reevaluation remain deployment prerequisites.

### S02: renewal-generation-race

- **File/ID:** `lab/scenarios/renewal-generation-race.scenario.json` / `OGIR-RENEWAL-GENERATION-RACE-001`.
- **Attacker / criteria / existing invariants:** A1; R06 R07 R08 R13 R14; 3–5,9–10,15,41–43.
- **Negative sequence:** Race two fresh renewal attempts against one predecessor; lose a committed response; try cancellation and a second grant. Install the exact successor, then replay the predecessor at another replica or deliver success after termination.
- **Expected:** `deny` / `stale-or-terminal-session`; `automatic_ban: false`.
- **Positive control:** Only one successor commits; bounded redelivery is byte-identical, and installation is coherent across replicas. An unavailable owner grants nothing.
- **Residual risk:** The scenario specifies required ordering; it does not supply a distributed transaction or liveness proof.

### S03: renewal-policy-transition

- **File/ID:** `lab/scenarios/renewal-policy-transition.scenario.json` / `OGIR-RENEWAL-POLICY-TRANSITION-001`.
- **Attacker / criteria / existing invariants:** A1; R09 R10 R11; 5–6,10,41–42.
- **Negative sequence:** Request same-session renewal under a numerically higher policy with weaker or unproven assurance. Attempt client repair after continuity/high-water loss.
- **Expected:** `deny` / `policy-or-continuity-requirement-failed`; `automatic_ban: false`.
- **Positive control:** An explicit non-weakening transition preserves epoch and high-water; increasing noncontiguous sequences remain admissible.
- **Residual risk:** Publisher approval and continuity proofs require later trusted mechanisms.

### S04: revocation-view-rollback

- **File/ID:** `lab/scenarios/revocation-view-rollback.scenario.json` / `OGIR-REVOCATION-VIEW-ROLLBACK-001`.
- **Attacker / criteria / existing invariants:** A0; V03 V04 V10 V11; 6,9–10,25–26,40.
- **Negative sequence:** Replay an older authentic view with a new receipt time; present conflicting equal-revision content; offer client-controlled recovery of rolled-back state or a terminal session.
- **Expected:** `unavailable` / `revocation-state-unusable`; `automatic_ban: false`.
- **Positive control:** Identical same-revision redelivery is idempotent without expiry extension; a newer authentic complete view refreshes a still-live session. Invalid candidates preserve independently usable current state.
- **Residual risk:** Authenticity, ordered persistence and trusted recovery are prerequisites; freshness cannot repair an expired terminal gap.

### S05: revocation-issuance-race

- **File/ID:** `lab/scenarios/revocation-issuance-race.scenario.json` / `OGIR-REVOCATION-ISSUANCE-RACE-001`.
- **Attacker / criteria / existing invariants:** A0; V02 V06; 3–6,10,40–42.
- **Negative sequence:** Arrange an applicable trusted revocation accepted after appraisal but before issuer commit; separately arrange one known at relying-party admission before permit expiry. Attempt authorization from the earlier check.
- **Expected:** `deny` / `revoked`; `automatic_ban: false`.
- **Positive control:** An unrelated publisher or namespace target does not revoke this candidate; a current unrevoked candidate passes this gate only.
- **Residual risk:** Not-yet-observed remote revocation remains bounded by trusted view age, time error and reevaluation; no zero-delay guarantee.

### S06: revoked-verifier-key

- **File/ID:** `lab/scenarios/revoked-verifier-key.scenario.json` / `OGIR-REVOCATION-VERIFIER-KEY-001`.
- **Attacker / criteria / existing invariants:** A5; V07; 2,4,6,46.
- **Negative sequence:** Use a revoked verifier key to sign a permit and certify its own unrevoked status or replacement root.
- **Expected:** `deny` / `revoked-verifier-key`; `automatic_ban: false`.
- **Positive control:** An independently authorized unrevoked issuer can pass its key check when all other requirements hold.
- **Residual risk:** Compromise of the independent revocation/root authority remains a separate TCB risk.

### S07: revocation-target-coverage

- **File/ID:** `lab/scenarios/revocation-target-coverage.scenario.json` / `OGIR-REVOCATION-TARGET-COVERAGE-001`.
- **Attacker / criteria / existing invariants:** A1; V01 V05 V08; 6,23,25–26,40.
- **Negative sequence:** Omit one required target class or source from dependency coverage while every included view appears current; supply an unauthenticated view as an empty success.
- **Expected:** `unavailable` / `incomplete-revocation-coverage`; `automatic_ban: false`.
- **Positive control:** All seven target classes have declared namespace, authority, match and retention contracts; nonapplicable targets have no effect.
- **Residual risk:** Trusted complete dependency derivation and safe bounded retention are prerequisite mechanisms.

### S08: revocation-outage-time

- **File/ID:** `lab/scenarios/revocation-outage-time.scenario.json` / `OGIR-REVOCATION-OUTAGE-TIME-001`.
- **Attacker / criteria / existing invariants:** A0; V09 F01; 3,6,9–10,39–42.
- **Negative sequence:** Delay required revocation updates until a view expires; substitute client UTC or an incomparable evidence interval for trusted decision time; continue protected activity past the effective bound.
- **Expected:** `unavailable` / `revocation-freshness-unavailable`; `automatic_ban: false`.
- **Positive control:** Before every exclusive bound, all conjunctive requirements may hold; bounded clock uncertainty must fit wholly inside the validity window.
- **Residual risk:** The proposed propagation bound assumes an honest authority and validated error/reevaluation bounds; unavailable is not proof of cheating.

### S09: revocation-retention-privacy

- **File/ID:** `lab/scenarios/revocation-retention-privacy.scenario.json` / `OGIR-PRIVACY-REVOCATION-STATE-001`.
- **Attacker / criteria / existing invariants:** A8; P01 P02 P03; 18–19,23,34–38,43.
- **Negative sequence:** Retain active authorization state after terminal cleanup, disclose complete dependencies or timing in diagnostics, or discard negative state while an old target can still authorize.
- **Expected:** `deny` / `privacy-or-retention-contract-violation`; `automatic_ban: false`.
- **Positive control:** Finite active-session state is deleted after in-flight resolution; negative history retires only after dependent expiry plus trusted non-reuse guarantees, without global identifiers.
- **Residual risk:** Safe bounded deletion and confidentiality are required later; this scenario does not prove secure erasure.

### S10: renewal-authority-confusion

- **File/ID:** `lab/scenarios/renewal-authority-confusion.scenario.json` / `OGIR-RENEWAL-AUTHORITY-CONFUSION-001`.
- **Attacker / criteria / existing invariants:** A1; F02 F03 C01 C02 C03; 1–5,15,39–43,48.
- **Negative sequence:** Treat an unsigned appraisal, key handle, research-cache success or cleanup acknowledgement as permit/admission authority; claim schema validation proves runtime renewal.
- **Expected:** `deny` / `missing-authorization-authority`; `automatic_ban: false`.
- **Positive control:** Only the existing fresh validated-permit path can activate; matching cleanup acknowledgement changes cleanup status only. Documentation checks prove traceability, not runtime security.
- **Residual risk:** Existing graphs and mock boundaries remain unchanged; M2 representation, factories, cryptography and services remain unimplemented.

### Exact schema example and traceability

```json
{
  "id": "OGIR-REVOCATION-VERIFIER-KEY-001",
  "title": "A revoked verifier key cannot certify its own recovery",
  "attacker": "A5",
  "owner": "initial-maintainer",
  "required_assurance_profile": "all-protected-modes",
  "assets": [
    "protected_session_authorization",
    "publisher_verifier_signing_authority"
  ],
  "preconditions": [
    "an independent publisher-authorized revocation view identifies the verifier key as revoked"
  ],
  "steps": [
    "present a permit signed by the revoked key",
    "present a self-issued assertion that this key is unrevoked or can authorize a replacement trust root"
  ],
  "expected": {
    "decision": "deny",
    "reason": "revoked-verifier-key",
    "automatic_ban": false
  },
  "invariants": [
    "M1-015 V07: Verifier-key revocation is independently enforced by the relying party; the revoked key cannot certify its own recovery"
  ],
  "residual_risk": [
    "Compromise of the independent revocation/root authority remains a separate TCB risk.",
    "Specified attack requirement only; runtime implementation and proof remain deferred."
  ]
}
```

Each criterion appears exactly once in this primary mapping; secondary scenario references may be added without changing the required set. “Invariant” numbers below refer to the existing `docs/SECURITY_INVARIANTS.md`; they are not a new registry. C01–C03 include documentation/compatibility evidence linked to the authority-confusion scenario, not runtime assertions that the scenario validator can enforce.

| Criterion | Primary scenario | Existing invariants | Required distinguishing example |
| --- | --- | --- | --- |
| R01 | S01 | 3,5,7–10,41–42 | Successful same-context renewal uses a new registered challenge, new current claims, same key/epoch, increasing sequence and every verifier/permit/activation gate |
| R02 | S01 | 3,5,7–10,41–42 | Reusing a nonce/evidence/old renewal cannot authorize; later rejection never releases its consumed nonce |
| R03 | S01 | 3,5,7–10,41–42 | Starting/retrying renewal never changes the old permit's expiry or revocation-view deadline |
| R04 | S01 | 3,5,7–10,41–42 | With intact continuity and still-valid trusted views, a transient attempt failure grants nothing but may leave independently valid existing authorization usable |
| R05 | S01 | 3,5,7–10,41–42 | Exact permit/view expiry stops authorization; a reply arriving after terminal invalidation cannot revive the session |
| R12 | S01 | 3,5,7–10,41–42 | Expired challenge, profile-duration violation or late evidence cannot become fresh through permit/result/client timestamps |
| R06 | S02 | 3–5,9–10,15,41–43 | Session termination racing renewal commit/installation prevents activation and cannot recreate deleted active state |
| R07 | S02 | 3–5,9–10,15,41–43 | Two attempts using the same predecessor yield at most one committed successor; retries cannot roll back temporal high-water |
| R08 | S02 | 3–5,9–10,15,41–43 | Delayed predecessor delivery after successor installation cannot restore older rights; duplicate current-artifact delivery cannot extend time |
| R13 | S02 | 3–5,9–10,15,41–43 | After owner installation/termination, another RP replica cannot authorize from stale local state; inability to consult coherent owner state is unavailable |
| R14 | S02 | 3–5,9–10,15,41–43 | Committed successor response loss permits only exact-artifact redelivery before deadlines; cancellation cannot mint another successor from its predecessor |
| R09 | S03 | 5–6,10,41–42 | Allowed policy/profile transition proves non-weakening and same epoch/high-water; retain existing valid temporal-profile-transition semantics |
| R10 | S03 | 5–6,10,41–42 | Higher policy version alone, weaker assurance or absent transition authorization cannot authorize same-session migration |
| R11 | S03 | 5–6,10,41–42 | Restart, lost high-water, epoch/sequence rollback and interval overlap terminate; sequence gaps alone do not |
| V03 | S04 | 6,9–10,25–26,40 | Source revision rollback is rejected; equal-revision identical redelivery is idempotent; conflicting content fails closed |
| V04 | S04 | 6,9–10,25–26,40 | Old authentic view replay or receipt after network delay cannot renew its freshness deadline |
| V10 | S04 | 6,9–10,25–26,40 | Source/trust recovery cannot resurrect terminal sessions or roll back revocation state from a client-provided artifact |
| V11 | S04 | 6,9–10,25–26,40 | A newer authentic complete view can refresh a still-live session within its unchanged permit expiry; invalid candidate views preserve usable current state and cannot revive an expired/terminal gap |
| V02 | S05 | 3–6,10,40–42 | Known applicable revocation blocks an unexpired permit; an unrelated publisher/namespace target does not |
| V06 | S05 | 3–6,10,40–42 | Revocation between ordinary appraisal and issuance must be rechecked/fenced at issuance; after issuance it is checked at the relying party |
| V07 | S06 | 2,4,6,46 | Verifier-key revocation is independently enforced by the relying party; the revoked key cannot certify its own recovery |
| V01 | S07 | 6,23,25–26,40 | Every architectural target class has one declared authority/scope/match/retention rule; omission of a required class fails closed |
| V05 | S07 | 6,23,25–26,40 | Unknown, expired, unauthenticated or incomplete view is unavailable/unsupported, never an empty success or fabricated revocation |
| V08 | S07 | 6,23,25–26,40 | Staleness of any required view defeats authorization even if every other view is current |
| V09 | S08 | 3,6,9–10,39–42 | Strictest effective deadline and finite reevaluation contract bound stale acceptance; no claim of zero cross-service propagation delay |
| F01 | S08 | 3,6,9–10,39–42 | Revoked, expired, continuity-lost, unsupported and temporarily unavailable cases remain distinct and non-disciplinary |
| P01 | S09 | 18–19,23,34–38,43 | Every new retained semantic value has scope, finite retention purpose, deletion condition and diagnostic exclusion |
| P02 | S09 | 18–19,23,34–38,43 | Safe revocation GC cannot re-enable retired targets; generation/non-reuse constraints do not become a global device identifier |
| P03 | S09 | 18–19,23,34–38,43 | Full-state and synthetic diagnostic examples contain no unapproved context, identity, proof or timing values |
| F02 | S10 | 1–5,15,39–43,48 | Cleanup failures preserve Required; a later matching completion changes only cleanup status, never lifecycle terminality |
| F03 | S10 | 1–5,15,39–43,48 | Raw reports, mock-cache success and key handles never substitute for possession, validated permits or issuer authority |
| C01 | S10 | 1–5,15,39–43,48 | Existing Rust graphs, failure eligibility, dependency/lockfile, M1-013 corpus/schema and M1-014 research boundary remain unchanged |
| C02 | S10 | 1–5,15,39–43,48 | Final documentation/ADR/scenario links, owner/profile registry and semantic traceability are checked on the reviewed candidate |
| C03 | S10 | 1–5,15,39–43,48 | Deployment prerequisites are explicit gates, and no unimplemented mechanism is described as proven or production-ready |

- [x] Add a threat-model subsection for renewal/revocation boundary attacks and ten ID/owner/profile mappings. Include A0 replay/delay, A1 hostile caller/races, A5 compromised issuer and A8 privacy abuse without claiming these controls defeat a compromised trusted source. Link each family to existing invariants and residual risks.
- [x] Add the full criterion mapping, positive controls and evidence status to test strategy. Future properties include monotonic generation/temporal state, exact single successor commitment, no terminal resurrection, deadline strictness and value-independent diagnostics. Representation fuzzing and runtime schedule exploration are later work, not invented executables in this documentation change.
- [x] Run the real checker and its self-tests, followed by compatibility tests. Expected: exit zero; real scenario count 40 at unchanged baseline, exact existing parity expectations preserved. Capture actual counts. A passing checker verifies shape/registrations only; independently read the semantics and inspect the parsed mapping for all 34 IDs.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-attack-scenario-traceability.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-attack-scenario-traceability.py
PYTHONDONTWRITEBYTECODE=1 python3 -W error scripts/test-attack-scenario-parity.py
```

- [x] Compare every old scenario, schema, checker, M1-013 fixture and registry against the baseline inventory. Inspect any mismatch; do not update pinned outcomes to make new scenarios fit. Checkpoint exact new scenario hashes and validation results.

## Task 5: Document Retention and Review Lessons

**Files:** Modify `docs/PRIVACY_MODEL.md`, append to `docs/LESSONS_LEARNED.md`; align the Task 4 privacy/threat rows.

**Interfaces:** Consumes spec sections 7–8, S09/S10 and original review findings D1/D2. Produces declared finite retention/deletion/disclosure obligations and truthful design-review lessons.

- [x] Add a retention-purpose table for live owner/generation/attempt state, exact committed successor awaiting redelivery, per-session evidence high-water, challenge replay state and revocation authority/negative history. Each row states owner/scope, eligibility or deletion condition, finite policy requirement and diagnostic exclusion. Preserve ADR-0005 replay retention and active-session-only evidence-time cleanup.
- [x] Explain capacity exhaustion without eviction of required negative state; negative history can retire only after all dependent artifacts expire and trusted non-reuse/generation rules preclude reauthorization. No enabled class without safe bounded retention, no indefinite attestation identity archive and no global correlation key. Numeric retention and implementation mechanisms remain future work.
- [x] Cover diagnostics consistently across Debug/Display/errors/logs/traces/metrics/crash/support/test output: no raw complete context, identity, source revision, permit, proof or session timing. Keep public trust distribution's separate approved disclosure contract; do not treat that as game or diagnostic disclosure permission.
- [x] Append two dated lessons using all existing template fields. D1 records the original ambiguity about cross-replica generation ownership and prevention via one coherent owner plus R13/R14. D2 records overbroad global-immediacy wording and prevention via known-local-revocation versus bounded propagation, V02/V06/V09. “Permanent regression test” states the linked scenario/design criterion and that runtime tests remain deferred; do not falsely report an exploit or runtime regression test. No historical lesson edits.
- [x] Inspect synthetic examples for identity/key/timing material, confirm server denial does not await client cleanup acknowledgement, and verify all retention rows have finite eligibility and deletion prerequisites. Check links/whitespace and checkpoint.

## Approved execution correction (2026-09-04)

The human approved two evidence-backed corrections after Task 4 exposed the
closed 30-file inventory and independent review found the installation TOCTOU.
Maintain the exact closed inventory at 40 through the three files above; do not
weaken or bypass it. Fence relying-party final validation and owner installation
against every issuer-authority, policy, revocation and required-dependency
update accepted before installation. This refines existing V02/V06 behavior and
does not select a runtime mechanism. Approval does not authorize DCO signing or
publication.

## Task 6: Verify the Complete Candidate and Prepare Human Review

**Files:** Candidate's 25 scoped paths; ignored or external evidence only. No extra production/test-source changes.

**Interfaces:** Consumes completed Tasks 1–5. Produces exact candidate tree/hash inventory, command/exit evidence, independent semantic review, limitation report and a reviewable uncommitted candidate.

- [x] Inspect `git diff` and every untracked candidate file. Compare all baseline files outside the 25-path allowlist byte-for-byte; ensure earlier ADRs and complete history remain unchanged. Inspect actual file modes, links and JSON parsed structure. Require exactly 34 unique criterion mappings and ten unique new scenario IDs, matching owner/profile and `automatic_ban: false`.
- [x] Run the aggregate gate in the ordinary checkout environment, with no temporary `GIT_INDEX_FILE` inherited by its fixture self-tests. Also run the candidate documentation/parity checks and CI's warnings-as-errors rustdoc setting. Expected exits are zero; record observed counts and any unavailable tool explicitly.

```bash
PYTHONDONTWRITEBYTECODE=1 bash scripts/check.sh
PYTHONDONTWRITEBYTECODE=1 python3 -W error scripts/test-conformance-documentation.py
PYTHONDONTWRITEBYTECODE=1 python3 -W error scripts/test-attack-scenario-parity.py
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
```

The aggregate already runs formatter, Clippy, workspace all-feature tests, rustdoc, metadata/ADR self-tests, scenario and abstract-corpus checks. Its ordinary index-only metadata/ADR checks do not include new untracked documents. Therefore the following separate candidate-index check is mandatory. Do not claim a 13-ADR ordinary-index pass validates the new 14th ADR. No extra release/mutation/fuzz campaign is justified by this documentation-only scope unless a concrete failure calls for it.

- [x] Prepare a disposable Git index from HEAD, add only the allowlisted candidate paths, and run index-aware gates with a per-process environment. Do not export that index to unrelated Git fixture tests. Preserve the real index unchanged. Run this Python fragment from the isolated execution repository root; it stores no source edits:

```python
from pathlib import Path
import hashlib, json, os, subprocess, tempfile

paths = [
    "docs/superpowers/specs/2026-09-04-m1-015-renewal-revocation-semantics-design.md",
    "planning/issues/015-renewal-revocation-semantics.md",
    "docs/superpowers/plans/2026-09-04-m1-015-renewal-revocation-semantics.md",
    "docs/adr/0014-renewal-revocation-semantics.md", "docs/adr/index.md",
    "docs/ARCHITECTURE.md", "docs/PROTOCOL.md", "docs/THREAT_MODEL.md",
    "docs/PRIVACY_MODEL.md", "docs/ROADMAP.md", "docs/TEST_STRATEGY.md",
    "docs/LESSONS_LEARNED.md",
    "docs/superpowers/plans/m1-013-format-v1/validators.json",
    "docs/superpowers/plans/2026-09-02-m1-013-format-v1-registry.json",
    "scripts/m1_013_plan_registry.py",
]
paths += [f"lab/scenarios/{stem}.scenario.json" for stem in (
    "renewal-pending-expiry", "renewal-generation-race",
    "renewal-policy-transition", "revocation-view-rollback",
    "revocation-issuance-race", "revoked-verifier-key",
    "revocation-target-coverage", "revocation-outage-time",
    "revocation-retention-privacy", "renewal-authority-confusion",
)]
assert len(paths) == len(set(paths)) == 25
assert "GIT_INDEX_FILE" not in os.environ
real_index = Path(subprocess.check_output(
    ["git", "rev-parse", "--git-path", "index"], text=True).strip())
index_before = real_index.read_bytes() if real_index.exists() else None
with tempfile.TemporaryDirectory(prefix="ogir-task15-index-") as directory:
    env = dict(os.environ, GIT_INDEX_FILE=str(Path(directory) / "index"))
    subprocess.run(["git", "read-tree", "HEAD"], env=env, check=True)
    subprocess.run(["git", "add", "--", *paths], env=env, check=True)
    subprocess.run(["git", "diff", "--cached", "--check"], env=env, check=True)
    for checker in ("scripts/check-repository-metadata.sh", "scripts/check-adr-index.sh"):
        subprocess.run(["bash", checker], env=env, check=True)
    tree = subprocess.check_output(["git", "write-tree"], env=env, text=True).strip()
    print(json.dumps({"candidate_tree": tree, "sha256": {
        path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in paths
    }}, indent=2))
assert (real_index.read_bytes() if real_index.exists() else None) == index_before
```

Expected: both candidate gates exit zero, 14 ADRs at unchanged baseline, real index identical and a recorded candidate tree. The disposable index may add unreferenced Git objects; it does not create a commit/ref. Capture the JSON output in local evidence. If a collision forced an approved identifier adjustment, update this exact list before running it.

- [x] Under AI development policy sections 7–8, request an independent adversarial reviewer of the actual candidate and approved spec. Supply paths, scope and requirements; do not provide the author's hidden reasoning. Ask for concrete bypass/ambiguity findings in deadline equality, old-permit use, source refresh and authority loss, multi-replica ordering, committed-response loss, policy transition, revocation applicability, retention and claims of implemented behavior. Have the reviewer report reviewed hashes and severity/evidence. Review is not human approval.
- [x] Address concrete in-scope findings. Rerun the affected checks, then confirm final candidate hashes match the review and gate evidence. Any required change to approved semantics is a new design decision and must be surfaced before adoption. Avoid repeated optional review/test campaigns when no concrete risk remains.
- [x] Final report names baseline/branch/tree, all changed paths, executed commands/results, scoped review findings and resolutions, 34 criterion mappings, ten scenario requirements, no runtime behavior change, and later M2 gates. Refresh issue/spec evidence status truthfully; any edit after freeze invalidates that freeze and requires refreshed identity checks.
- [x] Refresh shared memory/index, append the factual checkpoint and present the exact candidate for human every-line review/DCO and signed-commit authority if contribution is next. Do not sign, publish, mark the Proposed ADR Accepted or merge from this plan alone. A live issue/PR requires explicit publication authority; prepared local bodies are reversible work.

## Self-Review and Execution Handoff

Plan review must confirm every approved criterion maps to one scenario family and existing invariants; all spec sections have a task; every referenced existing path/command was inspected; and all future paths are explicitly marked as creations. The approved 34 rows remain the semantic authority. This plan's scenario grouping neither expands them into a runtime implementation nor drops positive controls.

Recommended execution is inline with `superpowers:executing-plans`, using checkpoints at the six deliverables and a separate final adversarial reviewer required by project policy. Subagent-driven task execution is an available alternative if the user selects it. Planning does not start Task 1 automatically. No further semantic approval is needed for routine work within this approved design; report only material changes to its scope or security decisions.


## Local execution evidence (2026-09-04)

Tasks 1–6 have local validation and review evidence. The unchanged aggregate
check passed, including its original 30-second conformance/accounting limits,
formatter, Clippy, 282 Rust runtime/integration tests, 114 doctests and dependency
policy. Separate checks passed: planning registry 58 tests, abstract conformance
445, attack parity 54, documentation 16, and warnings-as-errors rustdoc. The
aggregate accounting suites passed 34 and 23 tests respectively. Scenario
validation covers 40 files; the disposable candidate index validates 14 ADRs.
All 34 criteria map to ten new scenario specifications. Existing runtime tests
provide compatibility evidence, not implementation proof for those scenarios.

The earlier aggregate timeout did not reproduce: the unchanged abstract
self-test passed in 4.23 seconds, and the full gate later passed with the same
limits. The historical slowdown's exact environmental cause is unresolved. An
initial sandbox run reached the dependency check but could not lock its
advisory cache; an authorized rerun passed all dependency-policy checks. No
checker, timeout, validation or test was weakened to obtain these results.

Independent semantic rereview closed the installation-fence finding and the
registry-scope wording finding, with no open findings in its reviewed candidate.
Final contribution evidence records the exact tree, patch and file hashes,
status-only review reconciliation, command exits and limitations. All baseline
files outside the 25-path scope remain unchanged; the real index is preserved.
The contribution remains uncommitted, ADR-0014 remains Proposed, and human
every-line review, DCO certification, signing and publication remain separate.
