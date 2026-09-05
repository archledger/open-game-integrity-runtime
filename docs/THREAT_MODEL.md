# OGIR threat model

## 1. Security objective

OGIR aims to let a publisher distinguish a freshly attested Linux game session satisfying an explicit policy from common forms of client patching, replay, unaccepted boot/runtime state, and protected-session tampering—without granting the game broad visibility or control over the user's Linux system.

OGIR does not claim to detect every cheat or resist every unknown vulnerability.

## 2. Protected assets

- ranked or otherwise protected session authorization;
- publisher verifier signing keys;
- publisher challenge replay records and authoritative-time high-water state;
- TPM attestation identities and ephemeral session keys;
- integrity-policy definitions and reference values;
- agent, bridge, verifier, and update supply chain;
- privacy of unrelated user activity and files;
- availability and stability of the Linux host;
- accuracy and explainability of attestation outcomes;
- project and certification reputation.

## 3. Attacker classes

| Class | Capability |
|---|---|
| A0 | Remote network attacker without local code execution |
| A1 | Modified game, bridge DLL, Wine prefix, or same-user process |
| A2 | Local administrator/root using normal supported interfaces |
| A3 | Custom kernel, bootloader, firmware configuration, or platform image |
| A4 | Exploit against an accepted kernel, agent, dependency, TPM stack, or firmware |
| A5 | Compromised publisher verifier, policy service, or online signing key |
| A6 | Malicious maintainer, compromised dependency, CI runner, package repository, or release process |
| A7 | Physical, DMA, peripheral, TPM, CPU, or firmware-level attacker |
| A8 | Malicious or overreaching publisher attempting privacy abuse or global host control |

Each assurance profile must state which attacker classes and techniques it meaningfully addresses.

## 4. Initial assumptions

The first hardware-backed prototype assumes:

- the TPM behaves according to its supported assurance class;
- the accepted boot measurement chain is meaningful and verifiable;
- the publisher verifier and its keys are not compromised;
- the accepted local agent and kernel have no successful unknown exploit during the session;
- the publisher challenge issuer's nonce generation, authoritative clock, and
  durable replay adapter satisfy
  [ADR-0005](adr/0005-verifier-authoritative-challenge-freshness.md);
- the game server correctly validates the permit and session-key proof;
- the user understands that a protected mode may reject custom or unrecognized platform profiles.

These assumptions must become narrower as evidence and enforcement mature.

## 5. Trust boundaries

1. Windows game -> bridge DLL.
2. Bridge DLL -> unprivileged portal.
3. Portal -> privileged session/attestation service.
4. Agent -> TPM and kernel evidence sources.
5. Agent -> publisher verifier over the network.
6. Verifier -> reference-value/revocation data.
7. Verifier -> matchmaking relying party.
8. Source repository -> CI and release artifacts.
9. Publisher policy -> local privacy and enforcement constraints.
10. Publisher issuer/verifier -> authoritative clock and durable replay store.

Every boundary requires explicit authentication, authorization, framing, limits, error handling, and adversarial tests.

## 6. Principal threats and required responses

### Client patching

Threat: The game or bridge returns success without performing attestation.

Required response: Match authorization depends only on a verifier-signed permit and session-key proof.

### Fake caller

Threat: Another process presents copied App IDs, paths, or environment variables.

Required response: Derive caller and process-tree identity through kernel credentials, process handles, cgroups, and independently computed manifests.

### Local session gate bypass or stranded cleanup

Threat: A modified client skips challenge, caller, preparation, evidence, or
permit gates; substitutes a capability from another session; reactivates a
terminal session; or abandons required cleanup after end or invalidation.

Required response: Keep lifecycle state in one private checked graph, reject a
capability not bound to the exact local session without mutation, and require a
fresh validated permit for every renewal through the permit-received and
activation gates. `Ended` and `Invalidated` remain permanently terminal, while
orthogonal `CleanupStatus::Required`/`CleanupStatus::Complete` state preserves
the cleanup obligation. Cleanup requests remain reissuable, and the future
cleanup adapter must make the actual operation idempotent. Every rejection or
cleanup failure is non-disciplinary and never authorizes protected-mode
fallback.

### Replay

Threat: Reuse a prior challenge, quote, evidence bundle, permit, or renewal.

Required response: Strict zero-leeway challenge windows; a replay key exactly
`(PublisherId, Nonce)` across all contexts; durable issued/consumed records; an
atomic irreversible claim after exact binding checks; and transcript-bound
session-key proof for later permits. Same-key reuse returns a non-disciplinary
replay result.

### Freshness-state rollback or loss

Threat: Roll back publisher time, race two claims, clear replay state on
restart, corrupt the time floor, exhaust capacity, or make the store
unavailable so an old or duplicate challenge is accepted.

Required response: Persist the authoritative-time high-water mark and every
unexpired issued/consumed record; durably check/advance the floor before window
evaluation so rejection cannot hide a future observation; reject lower time;
perform register/claim/GC as atomic durable operations; construct the freshness
capability only inside the ordered verifier context/claim path; retain records
through expiry; enforce explicit finite limits without live eviction; and fail
closed without a stateless fallback. Operational failures map to
retry/unavailable protected mode and are not cheating evidence.

### Freshness-state disclosure or over-retention

Threat: An overreaching publisher exposes replay bindings through diagnostic
formatting, retains expired replay records or stale issuance-rate history, or
uses a detached restart copy to preserve data after garbage collection.

Required response: Redact binding/time leaves and every challenge,
expected-context, verification-request, replay-key, binding, registration,
guard, store, and durable-state debug surface; treat explicit value accessors as
trusted functional interfaces rather than diagnostic sinks; retain replay
records only through challenge expiry and rate events only through their
enforcement window; make all reopen handles refer to the same authoritative
state generation so a handle opened before purge observes later deletion.
Exported backups require a separately approved finite retention, deletion,
access-control, and anti-rollback policy.

### Verifier gate skipping or cross-attempt substitution

Threat: Hostile/equal requests or faulty orchestration skip an appraisal gate,
reuse a profile-bearing or key-bearing result from another attempt, treat opaque
evidence, a report-only Allow, or a freely built failure view as result
authority, retain accepted claims on failure, report a reason before its gate,
or issue a terminal result twice.

Required response: Keep progress in one private checked graph. Require all
seven exact-attempt capabilities in order, compare allocation identity rather
than request equality, accumulate accepted profile and key-handle claims only
after those checks, and consume the completed capability as the sole allow
construction path. Eligible failure actions return one typed unsigned
`AppraisalResult` directly; terminal-first whole-state replacement discards all
staged claims, and all six terminals reject all twenty-four semantic actions. A
typed `UnsupportedRequirement::UnknownCriticalRequirement` observation is
eligible at every active phase and maps to Unsupported with
`UnsupportedCriticalRequirement`.

Every unsigned Appraisal Result retains exact relying-party context, and only
allows retain accepted claims. Allocation identity proves exact-flow
association, not payload truth: a correctly bound dishonest profile or key
handle remains trusted-producer A5 risk. Public failure construction proves
valid report shape, not trusted provenance for future signing. A later trusted
issuer must separately establish provenance, validity, commitment, and
protection before producing a protected Attestation Result.

### Verifier diagnostic disclosure or over-retention

Threat: Default formatting exposes request identifiers, freshness context,
evidence payload, accepted profile, session-key handle, Appraisal Result
context, accepted claims, or pointer identity, or a failure retains claims or
the raw request after a terminal.

Required response: Use fixed aggregate redaction for requests, flows,
capabilities, errors, outcomes, bindings, `EvidenceBundle`, `AppraisalResult`,
`AppraisalResultView`, and `AcceptedClaims`; terminal-first replacement releases
request ownership and discards staged accepted claims on failure; success moves
the sole attempt binding into `VerifiedAttestation`, while failure releases it
before return, so terminal flows retain no binding, replay registration, or
attempt allocation; expose no allocation address/count. Retained context and allowed key handles remain
correlation-sensitive. The unsigned value has no intrinsic expiry or deletion
enforcement, so future transport/storage requires finite retention,
confidentiality, deletion, and backup policy. None of these ownership rules
claims secure memory erasure.

Registered scenario owner `initial-maintainer` is the required privacy-review
gate before any result context/claim field, diagnostic surface, serializer/wire
adapter, persistence/storage/backup path, or logging/telemetry path expands.

### Evidence-binding transcript substitution and underbinding

Threat: An attacker or faulty trusted component changes, omits, duplicates,
reclassifies, or reuses a semantic input while presenting evidence as if it
covered the verifier's expected Evidence-binding transcript.

The accepted attack families map to existing attacker classes:

| Attack family | Attacker classes |
| --- | --- |
| Authenticated challenge field or protocol-version omission/substitution | A0, A1, A5 |
| Profile substitution or profile-contract drift | A1, A5, A6 |
| Required-claim omission, duplication, aliasing, or undeclared claim injection | A1, A4, A5 |
| Claim-provenance reclassification | A4, A5 |
| Actual session-public-key or `SessionPublicKeyId` substitution | A1, A4, A5 |
| Manifest namespace, algorithm, or value substitution | A1, A4, A5, A6 |
| Cross-account, game, match, policy, or session replay | A0, A1, A5 |
| Evidence-time source, epoch, validity, rollback, restart, or renewal confusion | A1, A4, A5 |
| Cross-purpose reuse of evidence binding as protected Attestation Result integrity, permit authorization, session proof of possession, or renewal authorization | A1, A5 |
| Diagnostic or telemetry disclosure of transcript, proof, `ExpectedContext`, complete challenge context, or protected-session context material | A1, A5, A8 |

Required response: The publisher verifier independently reconstructs the
expected transcript from authenticated, registered, resolved, and candidate
inputs and establishes semantic equality independently of later checks. Profile
proof coverage must then reject every semantic mutation independently of claim
and provenance appraisal; appraisal cannot mask defective coverage. Immutable
closed profile contracts require every Base claim and only declared profile-
specific claims, with each required meaning present exactly once under its
registered provenance. Both the actual session public key and its handle
association are checked. Manifest and measurement identities retain their
semantic namespace, algorithm identity, and value. Exactly five semantic
purposes remain distinct: evidence binding, protected Attestation Result
integrity, permit authorization, session proof of possession, and renewal
authorization. Challenge authentication remains a separate verifier operation,
and admission remains downstream; neither expands the closed five-purpose set.
`ExpectedContext` remains independently supplied relying-party authority.
Evidence time uses the immutable profile's registered local collection
authority, one publisher/session-scoped protected epoch relation, a strictly
increasing sequence, and a bounded start-to-freeze interval for the exact fresh
challenge. All transcript and proof material, all `ExpectedContext` and complete
challenge-context values, all publisher/build/account/game/match/policy
bindings, and all protected-session context values remain confidential by
default.

Residual risks: A compromised trusted producer can emit dishonest but correctly
classified claims. Cryptographic strength depends on later profile mechanisms.
Verifier or issuer compromise remains inside the TCB. Privacy continues to
depend on profile minimization and separately governed production persistence.
Runtime representation, exact profile mechanisms/limits, cryptography, and TPM
mapping remain later work.

### Evidence-time collection, continuity, and privacy attacks

Threat: An attacker or faulty trusted component relabels stale cached claims
with a recent interval, substitutes another challenge/time domain, reuses old
epoch/sequence/interval state, races two collections, rolls back or restarts an
authority/store, exceeds duration/expiry, or leaks temporal correlation data.

Required response:

- The collection authority opens only after receiving the exact challenge later
  covered, and evidence is valid only for that authenticated challenge before
  its half-open expiry boundary.
- Every required claim is newly collected or revalidated for the current live
  subject before the complete snapshot freezes. Recent collection never grants
  claim truth or provenance to stale data.
- Client UTC, challenge time, verifier time, result/permit time, uptime, zero,
  maximum, and always-valid values have no evidence-time authority or skew
  normalization path.
- One local collection is active at a time. The verifier atomically checks and
  advances epoch, greatest validated sequence, and latest end after coverage/
  authority validation and before later appraisal.
- Accepted sequences strictly increase but may have gaps for unobserved dropped
  collections. Reuse/decrease, epoch change, overlap, impossible intervals,
  source discontinuity, restart, rollback, or lost/corrupt high-water terminates
  the current session and requires new session/key/handle/epoch recovery.
- Temporary unavailability is retryable only with intact recoverable authority
  state and a fresh challenge. No stateless or client-repaired fallback exists.
- The profile ceiling is finite and publisher policy only tightens it. Challenge
  expiry bounds proof/transport after freeze; no unverifiable post-freeze field
  is accepted.
- Epoch and temporal state are publisher/session scoped, active-session only,
  terminally deleted, and absent from ordinary diagnostics.

Residual risks: A compromised registered producer or collection authority may
emit dishonest but structurally valid current evidence. A compromised verifier
remains in the TCB. Full-session relay and post-appraisal state change remain.
The challenge window bounds total proof/transport latency but does not measure
post-freeze latency independently. Exact mechanisms, limits, persistence,
backup, and deletion enforcement require later approval.

### Cuckoo or relay

Threat: A cheating machine relays attestation to a separate clean machine.

Required response: Bind evidence to an ephemeral session key and bind proof of possession to the live game transport. Full-session relay remains a residual risk requiring network and behavioral controls.

### TOCTOU file replacement

Threat: Verify clean files and replace them before or during execution.

Required response: Race-resistant file identity, immutable/verity-backed files where practical, verified open descriptors, mount-namespace checks, and continuous or event-driven session invalidation.

### Same-user memory modification

Threat: Use `ptrace`, `process_vm_writev`, `/proc/<pid>/mem`, uprobes, perf, or equivalent interfaces.

Required response: Protect the security property across all equivalent interfaces with scoped LSM/session policy, not one syscall-specific block.

### Custom or compromised kernel

Threat: Boot a kernel that lies to the agent or disables enforcement.

Required response: Verify an accepted measured boot profile and trusted signing hierarchy. An exploit against an accepted kernel is residual A4 risk and requires rapid revocation, renewal, hardening, and server-side detection.

### Evidence-log forgery

Threat: Modify or truncate measured boot or IMA logs.

Required response: Replay the log and compare its rolling state with TPM-certified PCR values; validate policy completeness separately.

### Malformed protocol input

Threat: Trigger memory corruption, parser disagreement, resource exhaustion, or fail-open behavior.

Required response: memory-safe parsers where possible, canonical encoding, strict bounds, fuzzing, differential tests, and fail-closed handling.

### Privileged daemon exploitation

Threat: Abuse local IPC to read files, run commands, load BPF, access raw TPM functionality, or escalate privileges.

Required response: smallest possible operation set, privilege separation, no generic plugins or scripting, service sandboxing, fuzzing, and independent review.

### Supply-chain compromise

Threat: Malicious source, dependency, action, CI runner, build, package, update, or reference value.

Required response: review gates, pinned workflows, dependency policy, reproducible builds, signed provenance, SBOMs, compromise-resilient updates, transparency, separated approvals, and revocation exercises.

### Malicious publisher

Threat: Request unrelated process/file data, persistent identifiers, arbitrary policy code, or global monitoring.

Required response: fixed local claim vocabulary, publisher-scoped identity, session-scoped controls, explicit user-visible policy, local maximum privacy policy, and protocol rejection of unsupported requests.

### False-positive enforcement

Threat: Firmware update, crash, version mismatch, or unsupported configuration is interpreted as cheating.

Required response: structured non-disciplinary outcome classes and separation of eligibility from ban decisions.

An unsigned Appraisal Result, including a deny, unsupported, or retry result, is
not by itself evidence that a player cheated and grants no automatic discipline.

## 7. Explicit residual risks

- unknown exploits in accepted kernels, firmware, TPM stacks, agents, or verifiers;
- sophisticated full-session relay attacks;
- external computer-vision or hardware-assisted cheats;
- server vulnerabilities and non-authoritative game logic;
- DMA or physical attacks outside the selected profile;
- dynamic/JIT code that cannot be fully represented by file measurement alone;
- incomplete IMA or enforcement policies that omit a relevant object or interface;
- compromised publisher infrastructure;
- deliberate malicious behavior in a trusted gate producer or verifier remains
  A5 risk; the pure graph narrows external/API misuse but cannot make
  compromised TCB code honest;
- replay-store/clock outage or a forward time jump causing fail-closed
  protected-mode unavailability;
- collection-authority or verifier temporal-state outage causing fail-closed
  protected-session loss or retry according to whether continuity remains
  intact;
- social engineering and account abuse.

## 8. Threat-to-test rule

Every accepted threat must map to:

- one or more security invariants;
- a machine-readable attack scenario;
- positive and negative tests;
- an owner;
- a required assurance profile;
- a documented residual risk;
- a regression test after every confirmed defect.

Scenario `owner` names the role accountable for maintaining the mitigation and
regressions. `required_assurance_profile: all-protected-modes` means the threat
control is mandatory for every protected mode regardless of evidence backend;
any narrower value requires a separately documented assurance-profile
definition and validator-registry update. The attack-scenario schema requires
both fields, while the aggregate gate requires registered values and globally
unique scenario IDs.
Attack scenarios are single, duplicate-free JSON documents validated against
the supported shared-schema contract in the aggregate gate; text scanning is
not considered parsed enforcement. Repository-controlled scenario parsing has
explicit byte, file-count, nesting, object-field, array-item, string, and total-
node bounds plus a numeric-token/finite-value bound; rejects non-JSON constants
and schema-dialect drift; executes only reviewed bounded regexes; rejects a
symlinked scenario boundary; and emits context-free diagnostics without raw
filenames, keys, properties, host paths, control characters, or CI annotation
commands.

M1-008 freshness threat mapping:

| Accepted threat | Scenario | Owner | Required assurance profile |
| --- | --- | --- | --- |
| Sequential same/altered-context replay | `OGIR-PROTOCOL-REPLAY-002` | `initial-maintainer` | `all-protected-modes` |
| Concurrent double claim | `OGIR-PROTOCOL-FRESHNESS-RACE-001` | `initial-maintainer` | `all-protected-modes` |
| Time rollback, restart loss, or unavailable state | `OGIR-PROTOCOL-FRESHNESS-001` | `initial-maintainer` | `all-protected-modes` |
| Capacity/rate exhaustion and live-record eviction | `OGIR-PROTOCOL-FRESHNESS-CAPACITY-001` | `initial-maintainer` | `all-protected-modes` |
| Diagnostic disclosure or over-retention | `OGIR-PRIVACY-FRESHNESS-001` | `initial-maintainer` | `all-protected-modes` |

M1-012F evidence-time threat mapping:

| Accepted threat | Scenario | Owner | Required assurance profile |
| --- | --- | --- | --- |
| Time-domain or authority substitution | `OGIR-EVIDENCE-TRANSCRIPT-TIME-AUTHORITY-001` | `initial-maintainer` | `all-protected-modes` |
| Stale snapshot relabeling | `OGIR-EVIDENCE-TIME-STALE-SNAPSHOT-001` | `initial-maintainer` | `all-protected-modes` |
| Sequence, interval, challenge, or epoch reuse | `OGIR-EVIDENCE-TIME-TEMPORAL-REUSE-001` | `initial-maintainer` | `all-protected-modes` |
| Authority/protected-source restart or rollback | `OGIR-EVIDENCE-TIME-AUTHORITY-RESTART-001` | `initial-maintainer` | `all-protected-modes` |
| Concurrent collection/high-water race | `OGIR-EVIDENCE-TIME-CONCURRENT-COLLECTION-001` | `initial-maintainer` | `all-protected-modes` |
| Duration or challenge-expiry abuse | `OGIR-EVIDENCE-TIME-DURATION-EXPIRY-001` | `initial-maintainer` | `all-protected-modes` |
| Temporary intact-state unavailability | `OGIR-EVIDENCE-TIME-STATE-UNAVAILABLE-001` | `initial-maintainer` | `all-protected-modes` |
| Missing, corrupt, or rolled-back high-water | `OGIR-EVIDENCE-TIME-HIGH-WATER-LOSS-001` | `initial-maintainer` | `all-protected-modes` |
| Diagnostic/correlation disclosure | `OGIR-PRIVACY-EVIDENCE-TRANSCRIPT-DIAGNOSTICS-001` | `initial-maintainer` | `all-protected-modes` |

The threat model is updated in the same pull request as any changed trust boundary, privilege, protocol field, evidence claim, policy control, or signing/update path.

## M1-013 local implementation evidence

Tasks 2–8 implement the test-only corpus boundary described in
[ADR-0012](adr/0012-abstract-json-conformance-corpus.md), using the
[admitted JSON planning registry](superpowers/plans/2026-09-02-m1-013-format-v1-registry.json).
A1/A6 repository-controlled paths and bytes cross a shared bounded loader;
manifest inventory and executable-table bijection are checked before fixture
expectations are consumed. The normal pipeline stops at the earliest failure.
Independent reconstruction, exact abstract coverage, and appraisal/lifecycle
checks address A5 oracle-design mistakes without trusting candidate pass labels.
Focused calls rebuild prerequisites independently. History tests cover temporal
high-water, concurrent advancement, terminality, and retention semantics.

A8 diagnostic disclosure is addressed by fixed consumer/checkpoint/error-class
labels, suppressed unexpected-exception details, hostile-argument tests, and
value-independent diagnostic cases. The attack consumer retains its reviewed
compatibility formatter, including bounded numeric locations. The accounting
reference also admits bounded stable files before inspecting them. See the
[test evidence](TEST_STRATEGY.md#m1-013-local-implementation-evidence) and
[regression lessons](LESSONS_LEARNED.md#m1-013-local-implementation-evidence).

Residual risks remain: a compromised maintainer or CI runner can change both
fixtures and checks; a jointly wrong oracle and fixture can agree; synthetic
histories are finite; and correctly bound dishonest claims remain trusted-
producer risk. Abstract coverage proves no cryptographic mechanism, and modeled
high-water/deletion proves no durable storage or secure erasure. No production
representation, parser, persistence, privilege, or authorization is added.
This uncommitted test-only candidate is prepared for Task 10 final local
verification and freeze. The freeze handoff will identify the exact candidate
and completed checks. Human line review, DCO certification, and separately
authorized Task 11 commit and publication remain pending.

## M1-014 mock replay boundary

The [isolated mock design](superpowers/specs/2026-09-04-m1-014-isolated-mock-replay-cache-design.md)
models replay, substitution, rollback, quota races and loss within one research
run. The boundary is a trusted synthetic research caller invoking a volatile
library model; it is not publisher authentication, parser admission, or the
authoritative clock/durable-store boundary. Neither daemon opts in, and raw
success cannot satisfy a verifier gate.

Fixed policy and bounded record/global-event slots prevent a sequence of new
publishers and short-lived challenges from accumulating unlimited rate history.
All operations share one lock; both issued and consumed records count until
expiry. Missing registration returns unavailable without resetting unrelated
healthy state. Poison or impossible future-event state causes terminal loss,
with no recovery toggle. A downstream author could still write a dishonest
`ReplayStore` wrapper; the repository supplies none and does not claim to make
arbitrary downstream trust assertions safe.

Remaining risks include caller-selected impractical limits, lock contention,
forward modeled-time jumps, lazy retention when callers stop purging, ordinary
allocation failure, and loss on process exit. These are research limitations,
not production availability or recovery guarantees. Forgetting an expired key
cannot establish nonce uniqueness across all time. Diagnostics stay fixed and
redacted; aggregate functional counters are not telemetry. Production A0/A1
replay and A5 compromise still require the unchanged authoritative mechanisms.


## M1-015 renewal and revocation threats

The [approved design](superpowers/specs/2026-09-04-m1-015-renewal-revocation-semantics-design.md)
and Proposed [ADR-0014](adr/0014-renewal-revocation-semantics.md) specify future
controls across revocation source to issuer/relying party, issuer/replicas to
session-authorization owner, trusted time to decision, and retained state to
diagnostics. The source supplies authenticated complete scope/order/freshness;
every consumer retains its own current decision responsibility. One owner
orders current generation and terminal state across all enforcing replicas.

A0 may replay/delay authentic material, A1 may race hostile renewal or stale
permit requests, A5 may misuse a compromised verifier key, and A8 may seek
unauthorized disclosure or retention. The schema records one primary attacker
per family; it is not a claim of complete resistance to that attacker class.
An authentic contradiction requires faulty/compromised authority behavior, not
an assumed network ability to forge signatures. A dishonest required authority,
incomplete trusted dependency derivation, full-session relay or post-appraisal
state change remains residual risk.

Known applicable revocation rejects at the next protected decision. Unobserved
remote changes remain bounded only under honest source freshness/publication,
immutable downstream age, trusted clock error and finite reevaluation premises.
Owner incoherence, required view loss and incomparable clocks fail unavailable;
none authorizes stale-local fallback or a cheating accusation. Relying-party
final validation and installation form one fence against every applicable
issuer-authority, policy, revocation and required-dependency update accepted
before installation; preliminary validation cannot cross that boundary. A valid view
refresh cannot erase terminal expiry, and a lost committed renewal response
cannot produce another successor from the same predecessor.

The following are machine-readable specifications, not executed runtime attack
proofs. All owners are `initial-maintainer`; every required assurance profile
is `all-protected-modes`. Each scenario includes residual risk and the exact
assigned criterion text. [Validation mappings](TEST_STRATEGY.md#m1-015-renewal-and-revocation-validation)
contain positive controls and compatibility-evidence obligations.

| Family / attacker | Scenario | Existing invariants | Owner | Required assurance profile |
| --- | --- | --- | --- | --- |
| S01 / A1 | [OGIR-RENEWAL-PENDING-EXPIRY-001](../lab/scenarios/renewal-pending-expiry.scenario.json) | 3,5,7–10,41–42 | `initial-maintainer` | `all-protected-modes` |
| S02 / A1 | [OGIR-RENEWAL-GENERATION-RACE-001](../lab/scenarios/renewal-generation-race.scenario.json) | 3–5,9–10,15,41–43 | `initial-maintainer` | `all-protected-modes` |
| S03 / A1 | [OGIR-RENEWAL-POLICY-TRANSITION-001](../lab/scenarios/renewal-policy-transition.scenario.json) | 5–6,10,41–42 | `initial-maintainer` | `all-protected-modes` |
| S04 / A0 | [OGIR-REVOCATION-VIEW-ROLLBACK-001](../lab/scenarios/revocation-view-rollback.scenario.json) | 6,9–10,25–26,40 | `initial-maintainer` | `all-protected-modes` |
| S05 / A0 | [OGIR-REVOCATION-ISSUANCE-RACE-001](../lab/scenarios/revocation-issuance-race.scenario.json) | 3–6,10,40–42 | `initial-maintainer` | `all-protected-modes` |
| S06 / A5 | [OGIR-REVOCATION-VERIFIER-KEY-001](../lab/scenarios/revoked-verifier-key.scenario.json) | 2,4,6,46 | `initial-maintainer` | `all-protected-modes` |
| S07 / A1 | [OGIR-REVOCATION-TARGET-COVERAGE-001](../lab/scenarios/revocation-target-coverage.scenario.json) | 6,23,25–26,40 | `initial-maintainer` | `all-protected-modes` |
| S08 / A0 | [OGIR-REVOCATION-OUTAGE-TIME-001](../lab/scenarios/revocation-outage-time.scenario.json) | 3,6,9–10,39–42 | `initial-maintainer` | `all-protected-modes` |
| S09 / A8 | [OGIR-PRIVACY-REVOCATION-STATE-001](../lab/scenarios/revocation-retention-privacy.scenario.json) | 18–19,23,34–38,43 | `initial-maintainer` | `all-protected-modes` |
| S10 / A1 | [OGIR-RENEWAL-AUTHORITY-CONFUSION-001](../lab/scenarios/renewal-authority-confusion.scenario.json) | 1–5,15,39–43,48 | `initial-maintainer` | `all-protected-modes` |
