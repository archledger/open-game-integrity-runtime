# OGIR implementation roadmap

## 1. Execution strategy

Build OGIR as a sequence of independently falsifiable proofs. Do not begin with kernel enforcement, a general anti-cheat, a Wine fork, or broad distribution support.

The order is:

```text
repository and security process
    -> pure domain model
    -> mock end-to-end protocol
    -> real TPM evidence
    -> measured boot
    -> Proton bridge and caller binding
    -> publisher verifier and sample game
    -> protected-session observation
    -> scoped enforcement
    -> Wine TPM compatibility track
    -> audits and publisher pilot
```

Every milestone has an exit gate. Later work does not begin merely because code exists; the prior security claim must be demonstrated by tests and attack scenarios.

## 2. Product maturity states

| State | Meaning | Permitted use |
|---|---|---|
| Research scaffold | Architecture and interfaces are changing | Local development only |
| Protocol prototype | End-to-end flow with test keys and mock evidence | Demonstrations and conformance work |
| Hardware alpha | Real TPM and one measured boot profile | Dedicated test machines |
| Protected-session alpha | Game-scoped observation/enforcement | Invite-only non-disciplinary tests |
| Publisher pilot | Self-hosted verifier and one sample integration | Controlled test accounts; no automatic bans |
| Production candidate | Audited, reproducible, revocable, operated | Limited launch after publisher risk acceptance |
| Stable profile | Versioned protocol and supported lifecycle | Explicitly supported games/platforms |

Do not publish a production date during the research phase.

---

# Milestone M0 — Repository and security foundation

## Objective

Create a public, reviewable project where unsafe process choices are difficult from the first commit.

## Deliverables

- Apache-2.0 default license and SPDX policy.
- Separate license boundaries for Wine and BPF work.
- README with experimental disclaimer and non-goals.
- Architecture, trust, privacy, threat, AI-development, and test documents.
- DCO sign-off requirement.
- GitHub issue and pull-request templates.
- Pinned Rust toolchain and minimal compiling workspace.
- CI for formatting, linting, unit tests, and documentation.
- Dependabot for Cargo and GitHub Actions.
- Private vulnerability reporting and `SECURITY.md`.
- Initial security invariants.
- Architecture decision record process.

## Exit criteria

- A clean clone can run the documented checks.
- The default branch cannot merge changes that fail CI.
- No production claim appears in the repository.
- No secret or real TPM identity is present.
- Every initial component has an owner and license boundary.
- The first ten GitHub issues have acceptance criteria and threat/test fields.

## Do not add yet

- TPM dependency;
- CBOR/COSE dependency;
- async/web framework;
- Wine patch;
- BPF program;
- root daemon installer;
- production keys.

---

# Milestone M1 — Domain model and state machine

## Objective

Define what OGIR means before deciding how bytes are encoded or which libraries implement it.

## Deliverables

### Domain types

- `ProtocolVersion`
- `PublisherId`
- `GameId`
- `BuildId`
- `AccountScope`
- `MatchId`
- `PolicyId` and `PolicyVersion`
- `Nonce`
- `ChallengeWindow`
- `SessionId`
- `SessionPublicKeyId`
- `EvidenceProfile`
- `AppraisalResult`
- `ReasonCode`
- `RevocationTarget`

`SessionPublicKeyId` is completed as M1-007F, a bounded identifier follow-up to
task 7. It is a non-authoritative lookup handle only. Task 11 defines the
unsigned semantic `AppraisalResult` and reason-code taxonomy that later consume
a key reference as an accepted claim. M2 separately owns protected
`AttestationResult` issuance, integrity protection, and validity.

### State machines

Local session:

```text
New
 -> ChallengeValidated
 -> CallerBound
 -> SessionPrepared
 -> EvidenceCreated
 -> PermitReceived
 -> Active

Active -> RenewalPending -> PermitReceived -> Active

any nonterminal phase -> Ended | Invalidated
Ended | Invalidated: lifecycle-terminal; cleanup Required -> Complete
```

Verifier appraisal attempt:

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

any nonterminal phase
 -> Malformed | Unsupported | Retryable | Denied | Revoked
```

All six terminals are permanent. `Verified` yields one process-local
`VerifiedAttestation`; consuming it is the sole path to an allowed, unsigned
`AppraisalResult`. Every Appraisal Result retains exact `ExpectedContext`, while
only allows retain the accepted profile and session public-key handle. Eligible
failure transitions return direct typed results with one coarse reason and no
accepted claims. `Decision`, `ReasonCode`, `VerificationOutcome`, and borrowed
result views remain report-only. Both full and restricted classes require all
seven gates and use the exact selected policy.

Every terminal flow retains no attempt binding, replay registration, or attempt
allocation. Success moves the sole binding into `VerifiedAttestation` until
conversion; failure releases it before return. Registered owner
`initial-maintainer` gates privacy review before any result field, diagnostic,
wire/serializer, storage/backup, logging, or telemetry expansion.

The unsigned semantic value is distinct from a future protected
`AttestationResult` and grants no permit, proof, admission, or discipline.
M1-012 is complete only at the semantic documentation boundary: it defines the
Evidence-binding transcript, external `EvidenceBundle`, complete challenge,
closed eight-Base-plus-two-profile-specific claim vocabulary, provenance,
actual-key and handle association, and independent reconstruction without
choosing representation or cryptography. M1-012F resolves the common evidence-
time semantic prerequisite with one challenge-anchored protected collection
interval, registered local authority, publisher/session-scoped epoch relation,
strictly increasing sequence, freeze-before-proof boundary, and terminal
continuity loss. Task 13 may define abstract semantic fixtures. Runtime
representation and profile validation remain M2 work, and TPM mapping remains
M3 work. Challenge time, verifier time, result time, client UTC, and placeholders
cannot substitute for the registered protected local semantics.

Later M2 work owns canonical source representations, commitment and protection
algorithms and identifiers, literal domain-separation labels, proof coverage,
wire format and parsing, validation, issued-at/expiry, trusted issuance, and
conformance vectors. M3 owns TPM-specific coverage, including qualifying-data
mapping and quote validation. Permit lifecycle, renewal authorization,
revocation, retention, proof of possession, and admission remain with their
later roadmap issues.

### Failure taxonomy

- malformed;
- unsupported version/profile;
- invalid publisher signature;
- expired/not-yet-valid;
- replay;
- caller mismatch;
- platform unsupported;
- evidence invalid;
- policy denied;
- revoked;
- transient unavailable;
- protected session lost.

## Tests

- invalid or empty identifiers rejected;
- nonce length exact;
- session public-key handle length/type distinction and all 8,192 byte-position/value cases are exact;
- constructible/copyable key handles expose no result, permit, proof, or admission authority;
- session public-key handle diagnostics fully redact the complete value;
- expiry ordering enforced;
- state transitions cannot skip security gates;
- freely constructible `Decision`/`ReasonCode` reports grant no authority;
- `VerifiedAttestation` cannot be constructed without a completed verifier path;
- only consuming `VerifiedAttestation` creates an allowed `AppraisalResult`;
- failures return phase-eligible typed results and discard accepted claims;
- terminal flows release the attempt binding, replay registration, and attempt allocation;
- reason codes remain non-disciplinary;
- debug output redacts nonce/evidence identifiers where needed.

## Exit criteria

- Domain crate has no network, TPM, filesystem, serialization, or async dependency.
- State machine is deterministic and property-tested.
- Every field has a documented trust source.
- No field supplied by the client is marked authoritative by default.

---

# Milestone M2 — Mock end-to-end attestation protocol

## Objective

Prove challenge, evidence, verifier, permit, and session-key binding without involving TPM complexity.

## Architecture

```text
sample-server
  -> signed test challenge
sample-client
  -> local agent using test attester
agent
  -> signed mock evidence
verifier
  -> policy evaluation and short permit
sample-server
  -> permit validation and session-key proof
```

## Deliverables

- Abstract challenge and evidence schemas.
- Binding-transcript specification with explicit domain separation.
- Test-only attestation backend using ephemeral software keys.
- Replay cache.
- Verifier policy interface.
- Permit signing and validation.
- Ephemeral session-key proof of possession.
- Deterministic conformance vectors.
- A CLI demonstration that never returns a trusted local boolean.

## Required attack tests

- patch client to return success;
- alter each challenge field;
- replay evidence;
- replay permit;
- cross-match, cross-game, cross-account, and cross-policy reuse;
- expired challenge and permit;
- unknown critical field;
- oversized and truncated message;
- duplicate security-critical field;
- protocol downgrade;
- verifier key mismatch;
- session-key mismatch.

## Exit criteria

- The server admits only a verifier-signed permit with valid proof of possession.
- Every attack above returns a deterministic non-allow result.
- The client cannot locally mint or extend authorization.
- A second implementation or independent validator agrees on the conformance corpus.

## Design gate

Only after this milestone should OGIR select the production serialization and signature libraries.

---

# Milestone M3 — TPM backend and attestation identity

## Objective

Replace the mock attester with real TPM-backed freshness and key possession while keeping the rest of the system backend-agnostic.

## Deliverables

- `AttestationBackend` trait.
- Test backend, software-TPM backend, and hardware-TPM backend clearly labeled by assurance class.
- Publisher-scoped Attestation Key creation/loading.
- Attestation-key enrollment/credential activation prototype.
- TPM quote over selected experimental PCRs.
- Challenge/session binding in qualifying data.
- TPM resource and concurrency management.
- Cancellation, timeout, restart, and cleanup handling.
- No raw physical-TPM command exposed outside the backend.
- Integration fixtures from at least one discrete/fTPM and one software TPM.

## Research spikes before dependency selection

1. Evaluate `tss-esapi` API coverage, unsafe boundary, supported TPM2-TSS versions, cancellation, context lifecycle, and testability.
2. Compare direct TPM2-TSS usage with adapting Keylime's Rust agent or verifier evidence interfaces.
3. Decide whether enrollment is OGIR-native, Keylime-compatible, or delegated.
4. Define publisher-scoped identity and privacy behavior.
5. Define recovery after TPM clear, motherboard replacement, firmware update, or agent reinstallation.

## Required attack tests

- software TPM presented as hardware profile;
- quote from an unenrolled AK;
- quote with wrong nonce or qualifying data;
- copied public AK without TPM possession;
- stale quote;
- TPM resource exhaustion;
- daemon killed during quote;
- malformed TPM structures;
- EK/AK confusion;
- cross-publisher AK reuse when policy forbids it.

## Exit criteria

- Hardware and software assurance classes cannot be confused.
- The verifier validates AK enrollment and quote binding.
- Private AK/session material is not exportable through OGIR APIs.
- All TPM errors fail closed for protected mode and remain diagnosable.

---

# Milestone M4 — One measured Linux boot profile

## Objective

Prove one narrow, documented Linux platform profile rather than claiming generic Linux trust.

## Recommended first target

A dedicated test image using:

- UEFI Secure Boot;
- a signed Unified Kernel Image;
- predictable PCR 11 measurements;
- TPM 2.0;
- known kernel command line;
- module-signature policy;
- kernel lockdown;
- no production user data.

## Deliverables

- Platform-profile schema.
- Measured-boot event-log ingestion.
- PCR replay/validation.
- UKI and boot-phase reference policy.
- Accepted signing-root representation.
- Secure Boot and custom-key distinction.
- Static signed reference manifest for the test profile.
- Revocation and minimum-version fixture.
- User-facing explanation of accepted and unsupported states.

## Required attack tests

- Secure Boot disabled;
- modified UKI;
- modified initramfs or command line;
- user-enrolled custom key;
- unapproved kernel with valid signature;
- forged/truncated/reordered event log;
- event log that does not reproduce quoted PCRs;
- revoked boot component;
- firmware update producing an unknown profile;
- no TPM or cleared TPM.

## Exit criteria

- The verifier reconstructs or validates measured state against the quote.
- `Secure Boot enabled` alone is never treated as sufficient.
- Unsupported and malicious-looking states remain distinguishable.
- Updating the accepted profile requires signed, reviewed reference data.

---

# Milestone M5 — Proton bridge and race-resistant caller binding

## Objective

Allow a Windows sample game under stock Proton to invoke OGIR without trusting Windows-provided identity fields.

## Implementation order

1. Native Linux sample client to local portal.
2. Minimal Windows PE DLL with stable C ABI.
3. Wine/Proton transport prototype.
4. Kernel-derived peer credentials.
5. pidfd/process-start-time binding.
6. Wine server, prefix, process tree, and cgroup correlation.
7. Game/runtime manifest derivation.
8. Fault and race testing.

## Deliverables

- `ogir-client.dll` prototype.
- Bounded request/response ABI.
- Unprivileged local portal.
- Authenticated Unix-domain IPC.
- Process-handle passing rather than caller-supplied PID trust.
- Sample Windows console client running under stock Proton.
- Redacted tracing for development.
- No physical TPM call or privileged operation in the bridge.

## Required attack tests

- replaced/patched DLL;
- fake process with copied App ID/environment;
- PID reuse;
- process exits during binding;
- prefix substitution;
- mount namespace substitution;
- parent/child race;
- oversized WoW64 request;
- 32/64-bit layout mismatch;
- invalid pointer/length combinations;
- local socket impersonation;
- request flood;
- attempt to invoke unsupported privileged operations.

## Exit criteria

- A fake local process cannot obtain evidence for the sample game merely by copying identifiers.
- Replacing the bridge cannot fabricate a permit.
- The C/FFI surface is sanitizer-tested and fuzzed.
- The portal remains unprivileged and the agent sees only normalized bounded messages.

---

# Milestone M6 — Publisher verifier and sample-game SDK

## Objective

Make the integration experience credible for a game studio while retaining publisher control.

## Deliverables

- Self-hostable verifier service.
- Stable C SDK surface.
- C++ wrapper and sample Unreal-facing design, without committing to a full plugin yet.
- Sample server integration.
- Challenge issuance, evidence submission, permit issuance, renewal, and revocation APIs.
- Structured result and diagnostic API.
- Local developer mode using test keys and simulated profiles.
- CI conformance kit for publisher integration.
- Documentation for casual fallback and no-ban semantics.

## Integration target

The sample game should need only to:

```text
request challenge from its server
pass challenge to OGIR
submit opaque permit and session proof
handle allow / restricted / unsupported / retry / deny
```

It must not parse TPM logs or make the final local trust decision.

## Required attack tests

- server neglects signature validation;
- wrong expected match/account/policy;
- stale verifier key;
- compromised or revoked policy fixture;
- permit parser confusion;
- missing proof of possession;
- verifier time skew;
- duplicate/non-idempotent submission;
- outage and retry behavior;
- publisher accidentally treats unsupported as cheating.

## Exit criteria

- A fresh publisher can run the conformance kit and integrate the sample flow without Linux kernel knowledge.
- The verifier is deterministic and self-hostable.
- Insecure integration patterns are difficult or impossible through the public SDK.

---

# Milestone M7 — Protected-session observation

## Objective

Bind the attestation report to the actual live game process tree before enforcing restrictions.

## Deliverables

- Dedicated cgroup/session identity.
- Process tree and start-time tracking.
- Runtime and loaded-component manifest.
- Policy-state digest.
- Session lifecycle and cleanup.
- Event stream for relevant integrity changes.
- Renewal invalidation when observed state changes.
- Explicit noninterference tests for unrelated processes.

## Exit criteria

- Evidence is bound to the actual launched process tree.
- Session cleanup is reliable after normal exit, crash, agent restart, and system shutdown.
- Observation does not expose unrelated process inventory to the publisher.
- No enforcement claim is made yet.

---

# Milestone M8 — Scoped protected-session enforcement

## Objective

Add only the minimum game-scoped controls needed for a clearly defined threat class.

## Start with one property

First protected property:

> An unrelated same-user process cannot modify the protected game's memory through standard Linux process-memory interfaces while the ranked session is active.

Do not attempt every anti-cheat property at once.

## Deliverables

- Enforcement interface independent of one kernel mechanism.
- LSM-based controls for the first property.
- Tests covering equivalent memory-access paths.
- Session-policy activation and immutability.
- Policy-loss event and permit-renewal failure.
- Cleanup and noninterference tests.
- User-visible policy disclosure.

## Later experimental controls

- debugger attachment;
- perf/uprobe attachment;
- unapproved BPF attachment;
- executable mapping policy;
- immutable game/runtime files;
- IMA appraisal or fs-verity;
- module and lockdown profile;
- device/IOMMU policy.

BPF-LSM may be evaluated only after the property and verifier claim are defined independently of BPF.

## Exit criteria

- Every blocked interface has a bypass test and an unrelated-process noninterference test.
- Losing enforcement prevents renewal.
- Controls disappear at session end.
- The evidence accurately states what was enforced, not a broader claim.

---

# Milestone M9 — Continuous attack laboratory

## Objective

Turn the threat model into executable, repeatable adversarial testing.

This work begins in M1 and becomes a dedicated gate here.

## Deliverables

- Machine-readable attack scenario schema.
- Virtual and bare-metal test orchestration.
- Corpus for protocol, TPM, boot, process, and supply-chain attacks.
- Fuzzing for every untrusted parser.
- Property and mutation testing.
- Protocol state-machine model.
- Race/TOCTOU stress runner.
- Independent verifier differential testing.
- White-box and black-box red-team playbooks.
- Security dashboard containing test status, not marketing scores.

## Attack families

- client/bridge patching;
- fake caller and identity confusion;
- replay and cross-context substitution;
- relay/cuckoo;
- file replacement and namespace races;
- memory modification and instrumentation;
- custom/compromised kernel;
- log forgery and policy incompleteness;
- daemon exploitation and denial of service;
- parser ambiguity and resource exhaustion;
- verifier/policy/reference compromise;
- CI, dependency, release, update, and key compromise;
- malicious-publisher privacy abuse;
- false-positive and recovery behavior.

## Exit criteria

- Every security invariant maps to at least one executable scenario.
- Every confirmed defect adds a permanent scenario/regression.
- Critical attack scenarios run before protected releases.
- Bare-metal coverage is reproducible and documented.

---

# Milestone M10 — Wine TPM compatibility track

## Objective

Improve ordinary Windows TPM API compatibility under Wine without conflating it with physical-host attestation.

## Separate license and upstream strategy

- Develop Wine-targeted source under `LGPL-2.1-or-later`.
- Follow Wine coding and test conventions.
- Prefer upstreamable changes over a permanent Proton fork.
- Keep OGIR's physical attestation API separate.

## Deliverables

- Research current Wine `tbs.dll` coverage and tests.
- Per-prefix virtual TPM manager using `swtpm` or equivalent.
- Implement selected TBS context/device/submit/close/cancel semantics against the vTPM.
- Isolation, persistence, reset, and cleanup policy.
- WoW64 ABI tests.
- Explicit capability flag stating that the vTPM is not hardware-host attestation.

## Required attack tests

- raw TBS command reaches physical TPM;
- one prefix accesses another prefix's TPM state;
- resource exhaustion;
- malformed command buffers;
- cancellation races;
- persistent identity leakage across publishers/prefixes;
- vTPM presented as hardware-ranked assurance.

## Exit criteria

- Physical TPM isolation is mechanically tested.
- Compatibility claims are not reused as trust claims.
- The patch is suitable for upstream review or remains clearly experimental.

---

# Milestone M11 — Security assurance and publisher pilot

## Objective

Earn justified trust rather than asking publishers to trust project reputation alone.

## Deliverables

- OpenSSF OSPS Baseline assessment.
- OpenSSF Best Practices badge work.
- SBOM for releases.
- Signed build provenance and artifact attestations.
- Reproducible-build process with independent rebuild.
- Compromise-resilient update design.
- External protocol/cryptography review.
- External local-agent and verifier audit.
- White-box red team.
- Private bug bounty.
- Key rotation and revocation exercise.
- One publisher-controlled pilot verifier.
- One narrow supported Linux platform profile.
- No automatic player bans during pilot.

## Exit criteria

- Critical/high audit findings are resolved and regression-tested.
- Release artifacts can be independently tied to reviewed source and build process.
- Emergency revocation is demonstrated.
- Publisher and player privacy documentation matches observed network data.
- Pilot results do not depend on hidden exceptions or manual allowlisting.

---

# Milestone M12 — Production candidate

## Objective

Offer one supportable, versioned profile with explicit lifecycle and residual risk.

## Required conditions

- stable versioned protocol;
- supported agent/verifier/platform matrix;
- independent audits and red-team results;
- public conformance suite;
- public vulnerability disclosure and safe-harbor policy;
- funded security response and bounty reserve;
- multi-party release and root-key controls;
- reference-value transparency and revocation;
- operational monitoring without player privacy leakage;
- documented fallback and appeal path;
- publisher integration guide and incident playbook;
- neutral governance plan if multiple organizations depend on OGIR.

A production candidate still does not claim universal cheat prevention.

---

# 3. Parallel workstreams

## Workstream A — Protocol and verifier

Starts immediately. Owns domain types, binding transcript, conformance vectors, verifier, permit, renewal, and revocation.

## Workstream B — Local attestation

Starts after domain model. Owns backend trait, TPM integration, boot evidence, and agent-observed claims.

## Workstream C — Proton bridge

Starts after the local request shape is stable. Owns Windows ABI, Wine/Unix transport, portal, and caller binding.

## Workstream D — Protected session

Starts only after evidence and process identity are trustworthy. Owns cgroups, lifecycle, policy, and scoped enforcement.

## Workstream E — Attack lab

Starts with M1 and runs continuously. It must remain organizationally capable of challenging other workstreams.

## Workstream F — Publisher experience

Starts with the mock protocol. Owns sample server, SDK, conformance tooling, diagnostics, and integration guidance.

## Workstream G — Supply chain and governance

Starts in M0. Owns GitHub controls, dependency policy, releases, provenance, updates, incident response, and future funding/certification boundaries.

---

# 4. First 30 GitHub issues

## Foundation

1. Replace repository placeholders and establish SPDX map.
2. Configure GitHub ruleset and security features.
3. Verify scaffold on Rust 1.98.0 and commit `Cargo.lock`.
4. Add DCO check and contribution sign-off documentation.
5. Add ADR template and decision index.
6. Define project labels, milestones, and triage policy.

## Domain and protocol

7. Define identifier validation rules; use M1-007F for the missing fixed-width session public-key handle.
8. Define challenge time/freshness model.
9. Define local session state machine.
10. Define verifier state machine.
11. Define result and reason-code taxonomy.
12. Define binding-transcript inputs without choosing crypto.
    M1-012F resolves its evidence-time semantic prerequisite before fixtures.
13. Define abstract JSON conformance fixtures.
14. Implement an opt-in isolated mock replay cache and tests under the
    [M1-014 design](superpowers/specs/2026-09-04-m1-014-isolated-mock-replay-cache-design.md):
    immutable finite policy, shared atomic mock operations, bounded rate history,
    terminal state loss, and independent tests. It must not implement the durable
    `ReplayStore` contract or issue verifier authority. Durable storage and
    restart recovery remain separately scoped work.
15. Specify renewal and revocation semantics: human-approved [M1-015 design](superpowers/specs/2026-09-04-m1-015-renewal-revocation-semantics-design.md), Proposed [ADR-0014](adr/0014-renewal-revocation-semantics.md), and [scenario requirements](TEST_STRATEGY.md#m1-015-renewal-and-revocation-validation).

## Mock proof

16. Implement test-only challenge signer.
17. Implement test-only attestation backend.
18. Implement verifier policy interface.
19. Implement short-lived test permit.
20. Implement ephemeral session-key proof-of-possession test flow.
21. Add replay and cross-context attack scenarios.
22. Add malformed/oversized protocol corpus.

## Research spikes

23. Evaluate EAT/CBOR/COSE Rust libraries and canonical behavior.
24. Evaluate `tss-esapi` and Keylime reuse boundaries.
25. Prototype AF_UNIX peer credentials and pidfd passing.
26. Research one UKI-based measured-boot test profile.
27. Map all same-user game-memory modification interfaces.
28. Research stock Proton bridge options and Wine Unixlib upstream path.

## Security process

29. Add parser fuzzing harness design and CI resource policy.
30. Create first threat-to-test traceability matrix.

Each issue must be small enough for a human to review in one coherent pull request.

---

# 5. Definition of done for each issue

- Security requirement restated.
- Trust boundaries identified.
- Primary sources recorded.
- Scope and non-scope respected.
- Positive and negative tests added.
- Fuzz/property impact considered.
- Privacy and logging reviewed.
- Dependency/license impact reviewed.
- Formatting, linting, tests, and docs pass.
- Threat model/ADR/protocol updated where needed.
- AI assistance disclosed.
- Human reviewer can explain every changed line.
- No unsupported security claim added.

---

# 6. What not to build first

Do not start with:

- an eBPF anti-cheat scanner;
- a privileged always-on monitor;
- a `.sys` translator;
- a custom kernel module;
- a fork of all Proton/Wine;
- a universal Linux distribution allowlist;
- a proprietary verifier;
- a `bool IsSystemTrusted()` API;
- direct physical TPM forwarding from TBS;
- AI-designed cryptography;
- automatic player bans;
- a public bug bounty before triage and response capability exists.

The first credible achievement is a narrow end-to-end protocol that survives replay, patching, cross-session substitution, and malformed input.

## M1-013 local implementation evidence

Tasks 2–8 are accepted for continued local development: the shared bounded
loader, abstract snapshot/history corpus, ordered independent validation
oracles, attack-consumer parity, operation accounting, and aggregate integration
are implemented and remain uncommitted. The
[admitted JSON planning registry](superpowers/plans/2026-09-02-m1-013-format-v1-registry.json)
is the format authority; the
[test strategy](TEST_STRATEGY.md#m1-013-local-implementation-evidence) records
observed evidence without duplicating normative case inventories.

Task 9 documents this test-only implementation.

This uncommitted test-only candidate is prepared for Task 10 final local
verification and freeze. The freeze handoff will identify the exact candidate
and completed checks. Human line review, DCO certification, and separately
authorized Task 11 commit and publication remain pending.
No live issue, remote branch, or pull request was created for this work.

JSON remains repository fixture notation. M2 still owns production transcript
representation, canonical encoding, parser and differential/fuzz validation,
cryptographic mechanism and protected-result work. M3 owns TPM-specific mapping.
Production persistence, permit, proof-of-possession, renewal authorization,
and protected-session admission remain separately governed work. The local
conformance result grants no publisher authorization or production readiness.


## M1-015 semantic specification boundary

Task 15 integrates the approved renewal/revocation design, a Proposed ADR and
34 criteria mapped to ten machine-readable attack specifications. Finite permit
and authenticated view validity, one coherent authorization owner, single
successor commitment, terminal recovery, explicit non-weakening transitions and
bounded retention are specified requirements. They are not operational permit
or revocation services, and this does not declare M1 or M2 complete.

M2 must separately prove result/permit representation, protection and validity;
proof of possession; trusted source/time authentication and comparison;
complete dependency coverage; coherent issuer/replica ordering; finite limits;
durable recovery and safe bounded deletion. Representation-specific fuzzing and
runtime schedule/property/mutation evidence belong to those implementations.
M3 retains TPM mapping. The M1-013 corpus and M1-014 research boundaries remain
unchanged. See the [local issue](../planning/issues/015-renewal-revocation-semantics.md)
for integration status and [test strategy](TEST_STRATEGY.md#m1-015-renewal-and-revocation-validation)
for the distinction between executed compatibility checks and planned behavior.

## M2-016 mock specification boundary

Task M2-016 integrates the approved mock protocol specification: the
test-only transcript encoding with explicit domain separation (ADR-0015),
the test-only ephemeral software key hierarchy (ADR-0016), the abstract
mock message schemas and framing plan, and the placement of all twelve M2
attack-test categories onto the M2-017/018/019 implementation slices. The
static M1 exit-criteria audit recorded with this slice found all four M1
exit criteria holding at `62fe2584`; M1 closes formally with this
acceptance.

These are specifications, not mechanisms: no encoder, parser, key, permit,
proof, or demo exists, and this does not declare M2 underway operationally.
The M2 design gate holds (no production serialization or signature library
is selected), `ogir-model` remains dependency-free, and the experimental
namespaces are permanently non-production. See the
[local issue](../planning/issues/016-mock-protocol-specification.md) for
integration status, the [approved design](superpowers/specs/2026-09-05-m2-016-mock-protocol-specification-design.md)
for the decision record, and [test strategy](TEST_STRATEGY.md#m2-016-mock-specification-validation)
for the executed-versus-planned validation boundary.

## M2-019 completion boundary

Task M2-019 closes Milestone M2's executable obligations: frozen hex
conformance vectors for all four mock object classes with an independent
second encoder agreeing byte for byte (ADR-0015's validation obligation),
the CLI demonstration whose admission decision comes only from
relying-party validation of signed artifacts with no trusted local
boolean anywhere, the full twelve-category attack suite returning
deterministic non-allow results, and the ADR-0014 renewal fence (one
pending, one committed successor per predecessor, idempotent exact
redelivery, pending grants nothing). All exit criteria are demonstrated
by executed tests; the design gate holds (no production serialization or
signature library selected, permanent experimental namespaces), and the
mock substrate stays excluded from production graphs by the structural
gate. M3 owns TPM mapping; production library selection remains a
separate post-M2 ADR decision. See the
[local issue](../planning/issues/019-conformance-demo-and-attacks.md) and
[plan](superpowers/plans/2026-09-06-m2-019-conformance-demo-and-attacks.md)
for the executed inventory.

## M3-020 attestation seam boundary

Task M3-020 lands the backend-agnostic seam per the approved M3 entry
scoping (recommendations R1-R4 accepted 2026-09-06, including the
discrete-TPM fixture deferral record): the `AttestationBackend` trait,
the three disjoint assurance classes, and the strict-equality class gate
(ADR-0017), with the M2 mock attester as the labeled test backend and
zero new dependencies. The first external production dependency
decision (tss-esapi via upstream crates.io 7.7.0) belongs to M3-021 and
its own ADR plus `cargo-deny` policy event. See the
[local issue](../planning/issues/020-attestation-backend-seam.md) and
[ADR-0017](adr/0017-attestation-backend-boundary.md).

## M3-021 dependency and swtpm backend boundary

Task M3-021 executes the approved dependency recommendation: upstream
crates.io tss-esapi 7.7.0 becomes the workspace's first external
production dependency, recorded as a signed 53-crate cargo-deny
allowlist and permissive SPDX license set (ADR-0018). The software-TPM
backend creates a restricted-signing attestation key primary under the
Owner hierarchy and issues real TPM2_Quote calls over experimental PCR
slot 16 with caller qualifying data, behind the ADR-0017 seam as
assurance class `software-tpm`. CI installs the TPM toolchain and runs
the real-quote suite on swtpm; the development host runs the same suite
locally. Verifier-side quote validation, AK enrollment, and the
publisher-scoped identity design belong to M3-022. See the
[local issue](../planning/issues/021-swtpm-backend.md) and
[ADR-0018](adr/0018-tss-esapi-dependency-and-swtpm-backend.md).

## M3-022 enrollment and validation boundary

Task M3-022 delivers the publisher-scoped AK enrollment record model
(one modulus, one scope, one assurance class - the cross-publisher
reuse guard) and full semantic validation of swtpm statements under
contract v2 (ADR-0019): strict class gate, known backend, payload
structure, exact enrollment match, TPM-echoed qualifying-data equality,
and digest consistency. Cryptographic signature verification is
explicitly deferred: the only marshaling path for the raw attestation
bytes requires `unsafe`, which the workspace forbids, so the
copied-public-AK forgery class remains an open exposure until the
unsafe-policy decision lands. The roadmap re-charters the deferred
work - signature verification, the EK-bound credential-activation
enrollment protocol, and the publisher-scoped identity/privacy and
recovery ADRs (spikes 3-5) - into M3-023, ahead of the M3-024 attack
suite. See the
[local issue](../planning/issues/022-enrollment-and-validation.md) and
[ADR-0019](adr/0019-enrollment-records-and-quote-validation.md).

## M3-023 cryptographic verification boundary

Task M3-023 executes the human Option A decision: a single audited
`#[allow(unsafe_code)]` marshaling block (the workspace's only unsafe
exception, mechanically enforced to exactly one block by the isolation
gate) serializes the signed TPMS_ATTEST bytes into statement contract
v3; the in-repo SHA-256 moves to production `ogir-attest`; and the
verifier-side TPM cryptographically verifies each quote's RSASSA-SHA256
signature against the ENROLLED AK public key (ADR-0020). This closes
the copied-public-AK exposure ADR-0019 documented: real quotes verify,
tampered attestation bytes and forged signatures reject
deterministically. Remaining in M3-023's original charter, now the next
slice: the EK-bound credential-activation enrollment prototype and the
publisher-scoped identity/privacy and recovery ADRs (roadmap spikes
3-5), then the M3-024 attack suite and exit audit. See the
[local issue](../planning/issues/023-cryptographic-verification.md) and
[ADR-0020](adr/0020-audited-unsafe-marshaling-and-cryptographic-verification.md).

## M3-024 identity, recovery, and enrollment boundary

Task M3-024 completes the roadmap's three remaining M3 research-spike
decisions: publisher-scoped attestation identity and privacy (ADR-0021:
per-scope keys, no cross-publisher linkability, documented intra-scope
linkability), fail-closed recovery after TPM state loss (ADR-0022: TPM
clear, motherboard replacement, firmware update, and agent
reinstallation all end affected keys; recovery is always explicit
re-enrollment), and the EK-bound credential-activation enrollment
prototype (spike 3): the verifier seals an enrollment token with
TPM2_MakeCredential to the client's EK public and AK name, and the
client recovers it with TPM2_ActivateCredential, proving possession of
both keys in one operation; foreign clients and EK/AK-confused
requests reject. With spikes 1-5 now executed, the remaining M3 work is
the M3-025 attack suite and exit audit. See the
[local issue](../planning/issues/024-identity-recovery-enrollment.md).

## M3-025 completion boundary

Task M3-025 closes Milestone M3: the ten roadmap attack-test categories
execute green as one named suite against real swtpm and the full
enrollment/validation/cryptographic chain (software-as-hardware
substitution, unenrolled-AK quote, wrong qualifying data, copied public
AK without possession, stale quote, resource exhaustion, daemon killed
during quote, malformed TPM structures, EK/AK confusion, and
cross-publisher AK reuse), and the exit audit finds all four M3 exit
criteria satisfied by executed-test or verified-static evidence
(classes cannot be confused; the verifier validates AK enrollment and
quote binding; private AK/session material is not exportable through
OGIR APIs; all TPM errors fail closed and remain diagnosable). With
M0, M1, M2, and M3 closed, the next milestone is M4 (one measured
Linux boot profile). Recorded as future work, not M3 gaps: the fTPM
hardware-class backend (class-agnostic seam ready; discrete fixture
deferred per the accepted M3 entry recommendation) and
endorsement-certificate EK authentication (ADR-0022 option C). See the
[local issue](../planning/issues/025-attack-suite-and-exit-audit.md),
[exit audit](superpowers/audits/2026-09-06-m3-exit-audit.md), and
[plan](superpowers/plans/2026-09-06-m3-025-attack-suite-and-exit-audit.md).

## M4-026 ingestion boundary

Task M4-026 delivers the M4 foundation per the accepted entry
recommendations (in-repo parser, EFI-phase-first scope): the
dependency-free ogir-bootlog crate with the TCG2 event-log parser
(Spec ID Event03 + TCG_PCR_EVENT2, total and fail-closed), PCR replay
with exact TPM semantics (EV_NO_ACTION exclusion and
StartupLocality-3 all-FF PCR 0 initialization), exact and
subset-matching comparison modes, and the platform-profile schema
carrying the ADR-0014 non-weakening successor relation. The REAL
development-host fixture (a 116-event firmware log from this machine's
Secure-Boot-enabled LNL boot) ships in-tree: PCRs 2 and 7 replay
exactly to the live readback; PCR 0 is recorded as a known
firmware-log fidelity gap - the roadmap's own log-does-not-reproduce
category seen in the wild, documented rather than papered over. Next:
M4-027 (replay validation against live quotes) per the entry
decomposition. See the
[local issue](../planning/issues/026-profile-schema-and-log-ingestion.md)
and [ADR-0023](adr/0023-platform-profile-and-log-ingestion.md).

## M4-027 log-quote validation boundary

Task M4-027 connects the M4-026 ingestion to the M3 quote chain: the
log-quote bridge extends a parsed event log's per-bank digests into a
live swtpm PCR (reproducing the replay's extension sequence exactly),
quotes it through the SwtpmBackend, and validates that the log's
replayed value agrees with the quote - with the TPM2 semantic that
Quote's pcrDigest is the hash of the selected PCR values, so the
verifier reconstructs the value from the log, hashes it, and compares.
The measured triangle (event log, live TPM bank, quoted digest) is
proven end to end on the real host fixture: the replayed PCR 7 value
equals the live extended bank, and the quote validates against it. The
mismatching-log attack (a different bank's events behind the quote)
rejects deterministically - the roadmap's log-does-not-reproduce
category hosted. Next: M4-028 (the QEMU/OVMF + swtpm test image with
UKI/PCR 11). See the
[local issue](../planning/issues/027-replay-quote-validation.md).

## M4-028a image-build boundary

Task M4-028a delivers the dedicated test image's BUILD per the
accepted M4-028 entry recommendations (UKI-only minimal image;
in-repo tooling under image/; committed TEST-ONLY signing keys for
deterministic fixtures; the distro kernel as payload): the
key-generation script (self-signed keys branded
OGIR TEST-ONLY DO NOT TRUST), the build script (ukify assembles
kernel + initramfs + the known command line + systemd-stub into the
UKI; sbsign signs it; mtools packs it into a FAT ESP - no rootfs),
and the static verification script scripts/test-image-build.py (PE
magic, sbverify against the committed key, the TEST-ONLY subject
branding, the .linux/.initrd/.uname/.cmdline sections, the exact
known command line, and the ESP boot entry - all fail closed). The
built UKI measures its sections into PCR 11 (and 9) when OVMF loads
it; M4-028b boots the ESP under QEMU/OVMF + swtpm and exports the
event-log fixture. See the
[local issue](../planning/issues/028a-image-build.md) and
[image/README.md](../image/README.md).

## M4-028b boot-harness boundary (partial: chassis + findings)

Task M4-028b delivers the QEMU/OVMF/swtpm boot harness chassis and
the honest blocker finding: the harness boots the built UKI (with
secboot OVMF, the test-key UKI is correctly rejected by Secure Boot;
with non-secboot OVMF, the kernel boots and the serial log confirms
the known command line), and the swtpm state persists. THE BLOCKER:
Fedora's edk2-ovmf-20260812 ships NO TCG2/TPM2 measurement support
in any OVMF_CODE variant (zero Tcg2Dxe/TCG2/TPM2 strings in the
firmware volumes), so the TPM PCRs remain zero regardless of the boot
outcome - the measurements never happen. The documented fixes (any
one): build edk2 from source with TCG2 enabled; use Debian/Ubuntu's
ovmf package (which includes TCG2Dxe); or use a TCG2-enabled
prebuilt. The harness needs only the OGIR_OVMF_CODE override - see
image/boot-findings.md and image/boot-test.sh. The PCR 11 replay
validation and the event-log export follow once the blocker clears.

## M4-028c boundary (the measured capture: TCG2 OVMF + UKI fixture + the triangle)

Task M4-028c closes the measured-boot proof the TCG2 blocker held
back. The blocker was re-verified EMPIRICALLY (a traced swtpm shows
zero firmware TPM2_Extend traffic under Fedora's OVMF; a full guest
boot leaves PCRs 0-9 and 11 at zero with no event log; the observed
PCR 10 activity is the kernel's IMA, not firmware - and compressed
firmware volumes mean strings alone can never prove either side).
The fix: image/fetch-ovmf-tcg2.sh pins Ubuntu's hash-verified
TCG2-enabled ovmf-generic (ADR-0024). image/boot-capture.sh builds a
SECOND TEST-ONLY-signed UKI with the capture init embedded (sd-stub
measures it into PCR 11 through the firmware TCG2 protocol), boots
it under the TCG2 OVMF + swtpm with an IDE evidence disk, and the
guest exports the binary event log, the live PCR values, and a
createek/createak TPM2 quote with the recorded nonce.
scripts/test-measured-capture.py gates the artifacts; the committed
fixture is validated durably by the Rust triangle test: the
ogir-bootlog replay equals the live PCR read (PCR 11 included), the
quote's pcrDigest equals SHA256 of the concatenated replayed values
and echoes the nonce, and the QuoteVerifier cryptographically
verifies the signature (tamper rejects). A production parser fix
landed with it: the TCG EFI Spec ID digestSize field is u16 (the
multi-bank log the single-bank host fixture could never exercise).
Open deliberately: the test-key-enrolled varstore and SB enforcement
of the capture image (M4-030 territory), and CI boots (the committed
evidence is what CI validates). See the
[local issue](../planning/issues/028c-measured-capture.md),
[ADR-0024](../adr/0024-tcg2-ovmf-acquisition-and-measured-capture.md),
and [image/boot-findings.md](../image/boot-findings.md).

## M4-029 boundary (the signed reference manifest and revocation fixtures)

Task M4-029 delivers the reference-data half of M4's fourth exit
criterion: updating the accepted profile requires signed, reviewed
reference data. ADR-0025 defines the canonical line-oriented
manifest (profile identity, Secure Boot state, SHA-256 PCR
expectations, component minimum versions, accepted signing roots as
DER fingerprints, revocations, and one RSASSA-SHA256 signature over
the exact payload bytes) parsed fail-closed by ogir-bootlog and
verified against a verifier-PINNED anchor through the audited TPM
path (ogir-attest-tpm; no new dependencies, no self-declared
signers). The committed fixtures pin the M4-028c capture truth:
manifest.txt (revision 1, expectations generated from the committed
pcrs.txt and asserted equal to the event-log replay; the accepted
root is the committed TEST-ONLY image key) and manifest-revoked.txt
(revision 2, retiring test-uki v1 by revocation plus a floor rise -
a non-weakening successor). Update semantics are explicit: floors
compare as dotted-numeric segments (refining ADR-0023's lexical
compare), revocations persist, added signing roots and changed
expectations are fresh acceptances, never successor bumps.
docs/PROFILE_STATES.md is the user-facing explanation of accepted,
unsupported (unknown profile, firmware update, below floor,
revoked, custom key, absent TPM), and attack-indicating states, with
the reason each reports and the principle that unsupported is never
an accusation. Open deliberately: the Secure Boot enforcement boot
(the enrolled varstore) joins the M4-030 attack categories, which
consume these fixtures. See the
[local issue](../planning/issues/029-reference-manifest.md) and
[ADR-0025](../adr/0025-signed-reference-manifest.md).
## M4-030 boundary (the attack suite, the enrolled varstore, and the M4 exit audit; M4 COMPLETE)

Task M4-030 closes Milestone M4. ogir_bootlog::admission::admit_boot
is the production decision point: profile identity, Secure Boot
state, an EXPLICITLY accepted component signing root, then every
manifest PCR expectation - no leg alone admits (ADR-0026, with three
new distinguishable reasons: SecureBootDisabled, SigningRootRejected,
SigningRootNotValidated). The enrolled varstore closes the last
deferred M4-028b deliverable: image/enroll-test-key.sh derives it
deterministically with virt-fw-vars (PK = KEK = db = the committed
TEST-ONLY key, from the ADR-0024 template), and
scripts/test-sb-boot.py proves enforcement both ways on the dev host:
the good UKI boots under Secure Boot with kernel lockdown reported,
and a one-byte-modified UKI is rejected by the firmware. The
measured attack suite
(crates/ogir-attest-tpm/tests/measured_attack_suite.rs) hosts all
ten roadmap categories as the named milestone inventory - Secure
Boot disabled, modified UKI, modified initramfs/cmdline,
user-enrolled custom key, unapproved kernel with valid signature,
forged/truncated/reordered log, log-does-not-reproduce-quote (live,
through the M4-027 bridge), revoked component, firmware-update
unknown profile (distinguishable as unsupported, not attack), and
no-TPM/cleared-TPM fail-closed - plus the SB-alone-is-never-
sufficient exit negative; 12/12 green against real swtpm, with
mutations made on the parsed log structure so each is exactly the
measurement change it claims. The M4 exit audit
(docs/superpowers/audits/2026-09-07-m4-exit-audit.md) finds all four
criteria satisfied by executed work and records the honest
limitations (the emulated profile; no hardware fixture). ON MERGE,
MILESTONE M4 IS COMPLETE: M0-M4 closed; next is M5 (the Proton
bridge and race-resistant caller binding). See the
[local issue](../planning/issues/030-attack-suite-and-exit-audit.md)
and [ADR-0026](../adr/0026-sb-varstore-and-measured-admission.md).
## M5-031 boundary (the unprivileged local portal and the native sample client)

Task M5-031 opens Milestone M5 with implementation-order step 1
(ADR-0027). ogir_agent::portal is the unprivileged local endpoint:
same-UID Unix-domain socket (0600; freshly created parents 0700,
pre-existing directories never re-permissioned), credentials read
from SO_PEERCRED BEFORE any payload parses (the kernel-derived
identity the M5 entry spike proved crosses the wine bridge), frames
bounded by a 1024-byte ceiling that rejects without reading the
body, connections bounded to 16 frames, fail-closed decoding into
normalized responses, and a deliberately minimal v1 message set
(Hello/HelloAck - the ack reports the OBSERVED credentials; Rejected).
The audited-block posture extends: ogir-agent joins ogir-attest-tpm
as the second carved-out crate with exactly one audited unsafe
block (the getsockopt shim), enforced by the amended isolation gate.
The native sample client is
crates/ogir-agent/examples/portal-client.rs. The credential,
flood, oversized, and malformed legs are integration-tested against
real sockets. Open deliberately: the pidfd/process-start-time
binding (M5-032), the PE DLL and transport (M5-033/034), and the
richer message set those slices bring. See the
[local issue](../planning/issues/031-portal.md) and
[ADR-0027](../adr/0027-local-portal-and-peer-cred-shim.md).
## M5-032 boundary (race-resistant caller binding)

Task M5-032 delivers implementation-order step 5 (ADR-0028):
ogir_agent::binding pins the process behind the portal's
kernel-derived credentials by pairing the /proc start time with a
pidfd opened at bind time. Either observation failing means the
process is gone and the binding fails closed (the
exit-during-binding category); still_pins() probes the pinned
process exactly (a reused pid is unreachable through the fd); and
matches() reconciles fresh credentials by pid AND start time (the
PID-reuse defense). The audited surface consolidates into
ogir_agent::audited - the crate's single gate-enforced
#[allow(unsafe_code)] attribute on the module declaration, one libc
call per function with written safety arguments (getsockopt from
ADR-0027; pidfd_open, pidfd_send_signal(0), close new here). Open
deliberately: wiring the binding into the portal's accept path and
the session seam (M5-034), and the live parent/child and reuse
executions (the M5-035 suite). See the
[local issue](../planning/issues/032-caller-binding.md) and
[ADR-0028](../adr/0028-race-resistant-caller-binding.md).
## M5-033 boundary (the ogir-client prototype)

Task M5-033 delivers implementation-order steps 2 and 3 (ADR-0029):
the stable C ABI from sdk/include/ogir.h as a real mingw PE DLL
(strict argument validation; transport open/close via ntdll's
unix-call dispatch) plus the winegcc unixlib carrying real
spec-bound ms_abi exports AND initialized dispatch tables, so
either loader role works. The executed loader map (six traced
points, wine-11.0 Staging) is recorded in the ADR: WINEDLLPATH dead
for imports, LoadLibrary never resolves winelib artifacts, the
attach runs only in the unforced n,b phase, and the deployment is
native-PE-beside-the-app + unixlib in wine's machine-unix
directory. PROVEN LIVE: the 64-bit harness under wine against the
Rust portal - 13/13 PASS, the portal observing and pinning the
wine process's kernel credentials (CallerBinding alive). The WoW64
32-bit leg fails closed by design (custom arg structs need a proper
wow64 conversion layer - future work; the fail-closed behavior IS
the layout-mismatch defense). Session functions return UNSUPPORTED
until the M5-034/035 message set. Open deliberately: the
wine/Proton transport executions on other hosts incl. archhost's
GE-Proton (M5-034), the wine server/prefix/process-tree/cgroup
correlation, redacted tracing, and the game/runtime manifest
(M5-035 with the thirteen-category suite). See the
[local issue](../planning/issues/033-ogir-client.md) and
[ADR-0029](../adr/0029-ogir-client-prototype.md).
## M5-034 boundary (the wine/Proton transport and redacted correlation)

Task M5-034 delivers implementation-order steps 3-6 (ADR-0030):
the transport EXECUTED on a second machine (archhost, the user's
designated target) under BOTH system wine 11.17 mainline (13/13
harness PASS with the portal pinning the caller) and REAL
GE-Proton10-34 via headless `proton run` (exit 0, a second pinned
connection) - the mainline recipe is per-prefix: the PE in the
WINEPREFIX system32 plus the unixlib in the installation's
machine-unix directory; under Proton the unixlib lives in the
Proton build's own wine tree and the PE in the compat prefix.
ogir_agent::correlation derives the REDACTED wine context of a
pinned caller (WINEPREFIX and loader value DIGESTS, bounded
process-tree depth, cgroup controllers and path digest) and the
development portal host demonstrates the redacted tracing; the two
deployments on archhost are distinguishable by prefix digest
without learning the user's paths. build.sh is self-contained
(generates its dispatch import libraries; builds the 64-bit PE).
Open deliberately: the game/runtime manifest derivation and the
thirteen-category attack suite with the M5 exit audit (M5-035).
See the [local issue](../planning/issues/034-transport.md) and
[ADR-0030](../adr/0030-wine-transport-and-correlation.md).
## M5-035 boundary (the runtime manifest, the attack suite, and the M5 exit audit; M5 COMPLETE)

Task M5-035 closes Milestone M5 (ADR-0031).
ogir_agent::manifest derives the REDACTED runtime manifest of a
PINNED caller from procfs: the executable's digest and size,
bounded module digests from file-backed executable mappings, and
the mount-namespace digest - the substitution anchor; derivation
requires the pin, and malformed maps fail closed. The
thirteen-category attack suite
(crates/ogir-agent/tests/m5_attack_suite.rs) consolidates the
milestone's required attack tests in the house inventory pattern:
replaced bridge, copied environment, PID reuse, exit-during-
binding, prefix substitution, mount-namespace substitution
(environment-honest under EPERM), parent/child distinctness,
oversized requests, layout-mismatch shapes, invalid frames,
socket impersonation, request flood, and the
no-privileged-operation-is-expressible proof; the wine-side legs
anchor to their executed evidence (ADR-0029/0030). The M5 exit
audit (docs/superpowers/audits/2026-09-08-m5-exit-audit.md) finds
criteria 1, 2, and 4 satisfied by executed work and criterion 3
partial with the fuzz-target remainder recorded for the M6 SDK
slice. ON MERGE, MILESTONE M5 IS COMPLETE: M0-M5 closed; next is
M6 (publisher verifier and sample-game SDK). See the
[local issue](../planning/issues/035-manifest-and-suite.md) and
[ADR-0031](../adr/0031-runtime-manifest-and-m5-suite.md).
## M6-036 boundary (the verifier service shell and the developer-mode daemon)

Task M6-036 opens Milestone M6 (ADR-0032).
ogir-verifier gains the production shell: bjson (a strict bounded
JSON codec for flat string/hex objects with fixed ceilings and
total fail-closed rejection), http (a bounded HTTP/1.1 endpoint:
4KB header ceiling, capped required Content-Length, one request
per connection, fixed statuses, no TLS - the authority's transport
protection is the deployment's documented duty), and service (the
routes /v1/challenge, /v1/dev/evidence, /v1/evidence over
trait-injected semantics with decision time as a parameter).
crates/ogir-dev-verifierd is the developer-mode deliverable: the
mock substrate (MockVerifierService, exact-context policy,
deterministic seed keys) composed into the shell, rebuilt per
challenge issuance so the three-step flow exercises the full
verify-replay-policy-permit chain; it is mock-tier by construction
(the isolation gate asserts its existence and keeps it out of the
production graph). PROVEN over real TCP: the full flow ADMITS with
a permit, duplicates deny ReplayDetected, premature submissions
deny cleanly, malformed bodies and unknown routes 400, oversized
bodies are refused unread. Open deliberately: renewal/revocation
and the structured diagnostic API (M6-037), the stable SDK and
fuzz targets (M6-038), the sample backend + conformance kit
(M6-039), and the ten-category suite + exit audit (M6-040). See
the [local issue](../planning/issues/036-service-shell.md) and
[ADR-0032](../adr/0032-verifier-service-shell.md).
## M6-037 boundary (renewal, revocation, and the structured result API)

Task M6-037 completes the lifecycle deliverable (ADR-0033). The
wire verdict becomes a STRUCTURED shape: the VerdictKind families
the integration target requires (allow / restricted / unsupported
/ retry / deny) with stable reason codes from the M1 taxonomy and
retry guidance - unsupported states are never denials, transient
failures carry retry, and the permit rides only on admissions, so
"publisher accidentally treats unsupported as cheating" becomes a
wire-shape impossibility rather than a documentation hope. Two new
trait-injected routes complete the five-route lifecycle:
/v1/renew (verify + unexpired + unrevoked, then a FRESH challenge
for the permit's policy context and full reprocessing - stale
evidence denies) and /v1/revoke (the exact target bytes become
the denylist key; nothing is parsed, so parser confusion is
structurally impossible; idempotent). The developer-mode daemon
implements both and honors revocations at re-admission and
renewal. Executed: NINE HTTP integration tests green - the
lifecycle roundtrip, permit-parser confusion (clean Malformed),
verifier time skew (NotYetValid under injected decision time),
plus the M6-036 six. Open deliberately: the stable C SDK surface
and fuzz targets (M6-038), the sample backend + conformance kit +
no-ban docs (M6-039), and the ten-category suite + exit audit
(M6-040). See the
[local issue](../planning/issues/037-lifecycle.md) and
[ADR-0033](../adr/0033-lifecycle-and-structured-results.md).
## M6-038 boundary (the v1 SDK freeze, the C++ wrapper, and the fuzz targets)

Task M6-038 delivers the SDK deliverables and the recorded fuzz
remainder (ADR-0034). sdk/include/ogir.h becomes the FROZEN v1
ABI: OGIR_ABI_VERSION macros, the ogir_verdict enum mirroring
ADR-0033's five families, the structured ogir_result (verdict,
retryable, stable reason_code, borrowed permit view),
ogir_abi_version(), and ogir_session_get_result() - eight exports
pinned by the fail-closed scripts/test-sdk-surface.py gate (the
pre-freeze disclaimer is gone; the M6-039 conformance kit builds
on the freeze). The header-only C++ wrapper
(sdk/cpp/include/ogir/client.hpp) mirrors it with RAII
Client/Session, a Verdict enum class whose unknown families fail
closed to Deny, and Result as a value type COPYING the permit out
of session memory. docs/UNREAL_INTEGRATION_DESIGN.md is the
Unreal-facing design (plugin boundary, USTRUCT mirror, no-ban
family mapping, lifetime, Proton deployment recap) - deliberately
not a plugin. The fuzz crate (fuzz/, workspace-excluded,
gitignored corpus) closes the recorded M5+M6-036 remainder with
three targets: bjson_decode (codec never panics; decoded inputs
re-encode bounded), portal_frame_decode (the v1 decoder admits
only Hello), and service_route (the full HTTP router with null
backends never panics) - smoke-executed 3000/3000/800 runs clean.
CI compile-checks BOTH the C header and the C++ wrapper per push.
Open deliberately: the sample backend + conformance kit + no-ban
docs (M6-039), and the ten-category suite + exit audit (M6-040).
See the [local issue](../planning/issues/038-stable-sdk.md) and
[ADR-0034](../adr/0034-stable-sdk-and-fuzzing.md).
## M6-039 boundary (the sample backend, the conformance kit, and the no-ban documentation)

Task M6-039 delivers the integration deliverables (ADR-0035).
scripts/conformance-kit.py is the standalone publisher kit: 15
fail-closed checks over plain HTTP in five groups - the five-step
flow (issuance, simulation, submission with the structured verdict
and permit), the lifecycle (stale-evidence renewal never admits;
revocation confirms and is idempotent), freshness (duplicates
never re-admit; the taxonomy reason rides the wire), and the wire
bounds (malformed/unknown/missing 400; oversized refused unread -
the reset close is the expected refusal shape). --self-test
validates the kit offline and runs in CI. The sample backend
(examples/sample-game-server.rs) demonstrates the roadmap's five
steps against a running daemon with the publisher's policy table
in full view: verdict families map to gameplay states (Admit,
AdmitRestricted, CasualFallback, RetryLater, EndGracefully) - THE
PUBLISHER'S choice, with the documented intended mapping incl.
casual fallback (unsupported: full game, no protected extras, no
flag) and the graceful end. docs/CASUAL_FALLBACK.md is the
integration contract: the one rule (an attestation result is never
a cheating accusation), the family table, the fallback path, the
never-list, and the local quickstart. Executed: the kit 15/15
against the running daemon; the sample completes the flow with the
lifecycle demo. Open deliberately: the ten-category M6 attack
suite + exit audit (M6-040) closing the milestone. See the
[local issue](../planning/issues/039-sample-and-kit.md) and
[ADR-0035](../adr/0035-sample-backend-and-conformance-kit.md).
## M6-040 boundary (the attack suite and the M6 exit audit; M6 COMPLETE)

Task M6-040 closes Milestone M6 (ADR-0036). The ten-category
attack suite (crates/ogir-dev-verifierd/tests/m6_attack_suite.rs)
runs over REAL TCP against the production shell with the
developer-mode backend, consolidating the focused legs and adding
the remaining ones: unsigned evidence never admits (signature
validation cannot be neglected - the backend validates before any
verdict); wrong-expected-context submissions deny; a
corrupted-signature challenge (the stale-key shape) rejects; a
revoked permit never reanimates (renewal denies Revoked); permit
parser confusion denies Malformed; permit-only renewal without
fresh evidence denies; verifier time skew denies NotYetValid under
injected decision time; duplicates never re-admit; outage is a
loud client error while transient taxonomy codes map to the Retry
family (never punitive); and unsupported is never deny - asserted
at the wire family, retryability, spelling, and permit-absence
levels, plus a compile-time service-trait completeness check.
11/11 green across three consecutive runs. The M6 exit audit
(docs/superpowers/audits/2026-09-08-m6-exit-audit.md) finds all
three criteria satisfied by executed work: the fresh-publisher
kit criterion (15/15, stdlib Python, three-command quickstart),
the deterministic-and-self-hostable criterion (injected decision
time; single binary; documented TLS posture), and the
insecure-patterns-impossible criterion (the frozen SDK's distinct
verdict families; the kit's wire-bounds group). Honest limitations
recorded: developer-mode end-to-end (the production backend
composes the real chain later), restricted not yet emitted,
wow64 fail-closed, CI self-test rather than fuzzing. ON MERGE,
MILESTONE M6 IS COMPLETE: M0-M6 closed; next is M7
(protected-session observation). See the
[local issue](../planning/issues/040-suite-and-audit.md) and
[ADR-0036](../adr/0036-m6-attack-suite.md).
## M7-041 boundary (the observation core)

Task M7-041 opens Milestone M7 (ADR-0037).
ogir_agent::observation composes the M5 chain into ONE tracked
record: the ObservedTree (the bounded upward walk - pid + kernel
start time per hop, max 64, the pinned node first), the
SessionIdentity (SHA-256 over the cgroup-path digest + pid + start
time - stable while the process lives, never reused after a
restart), the StateDigest (SHA-256 over everything observed with
module digests ORDER-INDEPENDENT - a change means the observed
world changed and renewal must re-verify), the RedactedObservation
(the trust-boundary view: digests, pids, start times, structural
counts ONLY), and observe/observe_pinned/refresh/same_state (the
refresh is identity-checked: a restarted same-pid process is a
DIFFERENT session). NONINTERFERENCE IS STRUCTURAL: only the pinned
process's procfs is read, the tree is walked upward from the pin,
nothing is enumerated globally. Two production fixes landed from
the stability chase: manifest module reads retry a bounded budget
(a transient read failure must not become false drift) and the
state material is maps-order independent. Nine tests green across
FIFTEEN consecutive parallel runs, including the quiet-stability
contract and the mid-exec finding (exe changes at exec; the loader
maps libc moments later - observations settle first). NO
ENFORCEMENT CLAIM. Open deliberately: the lifecycle cleanup matrix
(M7-042), the event stream + renewal invalidation (M7-043), and
the noninterference suite + exit audit (M7-044). See the
[local issue](../planning/issues/041-observation-core.md) and
[ADR-0037](../adr/0037-observation-core.md).
## M7-042 boundary (the session registry and the lifecycle cleanup matrix)

Task M7-042 delivers the lifecycle deliverable (ADR-0038).
ogir_agent::registry::SessionRegistry: admit() pins+observes+
registers under the identity digest (duplicates are protocol
errors; dead callers fail closed); state() reports from the PIN
(exact liveness); cleanup() ends and TOMBSTONES (a dead identity
never re-registers as itself); sweep_dead() is the crash path for
a fleet; refresh() re-observes a live session (the M7-043 drift
input); and after_registry_loss() makes the restart/shutdown
posture EXECUTABLE - the registry is deliberately NOT persisted
(ADR-0022 fail-closed), prior identities are unknown, and
re-establishment is the only path (a still-live process re-admits
to the same identity as a FRESH registration). The
four-scenario cleanup matrix is the test set: normal exit
(cleanup + tombstone), crash (Terminated -> sweep -> refresh
refuses), agent restart (registry dropped -> re-admission works),
system shutdown (startup empty; ghost identities unknown - by
design indistinguishable from restart, the honest boundary of
what the registry can know). Nine tests green across ten
consecutive runs, plus multi-session independence. Open
deliberately: the event stream + renewal invalidation (M7-043)
and the noninterference suite + exit audit (M7-044). See the
[local issue](../planning/issues/042-lifecycle.md) and
[ADR-0038](../adr/0038-session-lifecycle.md).
## M7-043 boundary (the integrity event stream and renewal invalidation)

Task M7-043 delivers the stream deliverables (ADR-0039).
ogir_agent::events: EventKind with stable wire spellings
(process-exited, manifest-drift, cgroup-moved, tree-changed);
IntegrityEvent carrying ONLY the kind, session digest, sequence,
and BEFORE/AFTER state digests; the per-session bounded EventLog
(default 64, oldest drops); diagnose() with fixed precedence; and
renewal_gate(log, permit_sequence) - MayReverify when quiet,
MustReestablish otherwise; A GATE, NEVER A GRANT. The registry
integration: every refresh diffs the state digest, drift emits the
diagnosed event, exit emits the terminal event before the
fail-closed error, cleanup/sweeps drop logs with sessions, and
SessionRegistry::renewal_gate() demands BOTH a quiet stream AND
live liveness (a dead session fails closed - stronger than
MustReestablish). Executed: quiet sessions emit nothing; exit
emits the terminal event and closes renewal; the full
invalidation flow; 59 tests green across six consecutive runs. NO
ENFORCEMENT CLAIM. Open deliberately: the noninterference suite +
exit audit (M7-044) closing the milestone. See the
[local issue](../planning/issues/043-event-stream.md) and
[ADR-0039](../adr/0039-event-stream.md).
## M7-044 boundary (the noninterference suite and the M7 exit audit; M7 COMPLETE)

Task M7-044 closes Milestone M7 (ADR-0040). The
noninterference suite (crates/ogir-agent/tests/
m7_noninterference_suite.rs) executes the criterion five ways:
an unrelated sibling NEVER appears in any observed tree (and
killing it does not move the state digest); same-prefix unrelated
processes stay isolated (matching prefix digests, disjoint trees,
distinct identities); the redacted view carries no inventory
surface (no path, name, or command material by type shape AND
runtime inspection); per-session event logs never reference
another session; and observation itself is noninterfering (a
sibling's observation does not change the lone process's state
digest). The four-scenario cleanup matrix is consolidated and the
NO-ENFORCEMENT-CLAIM pin lands (compile-time: no observation type
implements an Enforcement trait; runtime: a drifting refresh
returns a record, never an instruction). 7/7 across three
consecutive runs. The M7 exit audit
(docs/superpowers/audits/2026-09-08-m7-exit-audit.md) finds all
four criteria satisfied by executed work with honest limitations
recorded (the stream is host-side API; sequences reset with the
registry; the tree walk stops at unreadable hops - fail-visible).
ON MERGE, MILESTONE M7 IS COMPLETE: M0-M7 closed; next is M8
(scoped protected-session enforcement). See the
[local issue](../planning/issues/044-suite-and-audit.md) and
[ADR-0040](../adr/0040-m7-noninterference-suite.md).
## M8-045 boundary (the enforcement seam, the first property, and the bypass/noninterference suite)

Task M8-045 opens Milestone M8 (ADR-0041).
ogir_agent::enforcement delivers the FIRST PROPERTY through a
mechanism-INDEPENDENT seam: MemoryInterface (ptrace,
process_vm_writev, proc-mem-write - stable disclosure spellings),
the MemoryAccessControl trait (activate/decide/deactivate + a
mechanism name; nothing mechanism-specific leaks), the
SessionPolicy composed with the M7 observation (activation;
IMMUTABILITY while active - re-activation and target swaps
reject; deactivation emitting the policy-loss event onto the
session stream and closing permit renewal), and the
SimulatedBackend (the property's logic for CI; the LSM and
ptrace-blocking backends are their own dev-host slices). The
bypass/noninterference suite: every covered interface DENIES an
unrelated same-user process against the ACTIVE target; the SAME
access against an UNPROTECTED process is OutOfScope - and,
EXECUTED on the dev host, an unrelated process's /proc/pid/mem
stays openable while protection is active for the game
(enforcement is game-scoped only; the innocent process is
deliberately not corrupted - the open proves the OS permission
the policy must not touch). Cleanup restores the no-claim state.
Five enforcement unit tests + three suite tests green. Open
deliberately: the real kernel backends (LSM/ptrace-blocking) as
dev-host slices, the session-policy disclosure doc, and the M8
exit audit. See the
[local issue](../planning/issues/045-enforcement-seam.md) and
[ADR-0041](../docs/../adr/0041-scoped-enforcement.md).
## M8-046 boundary (the pr-set-dumpable backend, the kernel-real bypass test, the disclosure, and the M8 exit audit; M8 COMPLETE)

Task M8-046 closes Milestone M8 (ADR-0042).
ogir_agent::dumpable_backend::DumpableBackend is the FIRST REAL
kernel mechanism behind the seam (mechanism name
pr-set-dumpable): the prctl lives in the audited module as its
second integer-only shim (the single-attribute posture holds). The
kernel-real bypass test EXECUTES the property: a double-forked,
ancestor-free protected process (stdio detached, setsid, dumpable
cleared, NO EXEC - execve RESETS the flag, the suite's first
empirical discovery) refuses a same-user unrelated process's
/proc/pid/mem open (the kernel's own EACCES, live) while an
unprotected unrelated process's mem stays openable in the same
run; readiness is the kernel's own observable (/proc/pid/stat
becomes root-owned). The second discovery: the kernel's dumpable
check EXEMPTS ANCESTORS - disclosed as the mechanism's honest
limitation and deferred to the LSM backend.
docs/ENFORCEMENT_DISCLOSURE.md is the user-visible policy
disclosure (the one property, the covered spellings, the
mechanism and its limits, and the explicit never-list). The M8
exit audit finds the bypass/noninterference criterion satisfied
for the first property; the LSM backend and the later
experimental controls remain future work behind the same seam per
the roadmap's own sequencing rule. ON MERGE, MILESTONE M8 IS
COMPLETE: M0-M8 closed; next is M9 (continuous attack
laboratory). See the
[local issue](../planning/issues/046-kernel-backend.md) and
[ADR-0042](../adr/0042-pr-set-dumpable-backend.md).
## M9-047 boundary (the invariant-coverage gate, the registry completion, and the dashboard; M9 COMPLETE)

Task M9-047 closes Milestone M9 (ADR-0043). The laboratory's
pre-existing pieces (the 40-scenario schema + traceability gate
run every slice since M1; the per-family corpus IS the milestone
attack suites M2-M8; the fuzz crate from M6-038) gain the missing
mapping layer: scripts/check-invariant-coverage.py fail-closes on
any of docs/SECURITY_INVARIANTS.md's 48 numbered invariants
unmapped in the scenario registry (CI-enforced); the 21
invariants that were executed inside the milestone suites but
unmapped gain registry scenarios pointing at their existing suite
legs (registry: 61 scenarios, 48/48 mapped); and
scripts/security-dashboard.py prints per-invariant scenario counts
and gate status - test status, not marketing scores. The M9 exit
audit: criteria 1-3 satisfied (the mapping is mechanical; the
defect->regression record holds; the critical scenarios run in
the rust CI job before every merge); criterion 4 PARTIAL - the
dev-host and archhost legs are reproducible and documented, but
true bare-metal (physical TPM) coverage has NOT been executed
(the M4 profile is the emulated one by design); recorded as the
open follow-up. ON MERGE, MILESTONE M9 IS COMPLETE: M0-M9 closed;
next is M10 (Wine TPM compatibility). See the
[local issue](../planning/issues/047-laboratory.md) and
[ADR-0043](../adr/0043-attack-laboratory.md).
## M10-048 boundary (the per-prefix virtual TPM; M10 opened)

Task M10-048 opens Milestone M10 (ADR-0044).
wine/vtpm/vtpm-manager.sh (LGPL-2.1-or-later) runs ONE swtpm per
wine prefix: state under <prefix>/vtpm/ (0700), sockets under
$XDG_RUNTIME_DIR/ogir-vtpm/<sha256-16-of-path> (two prefixes can
never collide - structural isolation), idempotent start,
kill-escalating stop, and a reset that WIPES the state. The
manager NEVER references the host TPM - mechanically checked by
wine/tests/test-vtpm-manager.py (LGPL) together with per-prefix
state/socket separation, reset-wipes (mtime-checked), and
cleanup-removes-sockets. THE CAPABILITY CONTRACT: the vTPM is
ordinary Windows TPM API compatibility, NOT hardware-host
attestation - ADR-0017's software-tpm class, gate-rejected
wherever hardware is required (invariant 17); recorded in
wine/README.md. Executed: the manager smoke and the four-family
gate PASS on the dev host. Open deliberately: the TBS
context/device/submit/close/cancel implementation against the
per-prefix socket, the WoW64 ABI tests, the remaining attack
families (exhaustion, malformed buffers, cancellation races,
cross-prefix leakage at the API layer, vTPM-presented-as-hardware),
and the M10 exit audit. See the
[local issue](../planning/issues/048-wine-vtpm.md) and
[ADR-0044](../adr/0044-per-prefix-vtpm.md).
## M10-049 boundary (the TBS compatibility layer)

Task M10-049 delivers M10's compat core (ADR-0045): the
DOCUMENTED TBS surface - Tbsi_Context_Create,
Tbsip_Submit_Command, Tbsip_Cancel_Commands,
Tbsip_Context_Close, Tbsi_GetDeviceInfo - over the per-prefix
vTPM (upstream Wine's tbs.dll is stubs; these five are the
slice's implemented set). wine/tbs/tbs.c (LGPL-2.1-or-later,
Wine-shaped, standalone-compilable for the gate) +
wine/tbs/include/tbs.h (the documented types and codes) +
wine/tbs/tbs.spec (the promoted entries for the upstream patch).
Transport: ONE connection per submit over the data socket - the
manager (extended here) starts the data channel in server
disconnect mode, because swtpm serves one persistent data client
at a time and a second context would hang (probed); discovery is
the manager-maintained <prefix>/vtpm/sockets symlink, so no
runtime-dir layout knowledge lives in C. The layer validates per
the Microsoft Learn tables (locality ZERO only, the five
priorities, the 10-byte TPM2 header, the 4096 swtpm buffer cap,
TBS_CONTEXT_PARAMS2 includeTpm20), honors the
insufficient-buffer contract and in-place buffers, returns TPM
errors VERBATIM in the response buffer (compat transport, never
synthesis), fails bogus handles closed via a bounded registry
(no dereference before validation), and bounds IO at 30s ->
TBS_E_IOERROR. Cancel is honest-bounded: swtpm cannot interrupt
a synchronous in-flight command. THE CAPABILITY CONTRACT is
unchanged: software-tpm class compatibility, never
hardware-host attestation (invariant 17); the layer has NO
physical TPM path (grep-gated mechanically). Executed: the
scenario gate (wine/tests/test-tbs.py - no-vtpm fail-closed,
parameter matrix, handle misuse, a real GetRandom round-trip,
insufficient-buffer, in-place, TPM-error transparency, cancel,
device info, cycling, interleaved contexts, source grep) and the
extended manager gate PASS on the dev host. Open deliberately:
the WoW64 ABI tests, the API-layer attack families (exhaustion,
malformed buffers, cancellation races, cross-prefix leakage,
vTPM-presented-as-hardware), the M10 exit audit, and upstream
submission of the patch. See the
[local issue](../planning/issues/049-tbs-layer.md) and
[ADR-0045](../adr/0045-tbs-compat-layer.md).
## M10-050 boundary (the TBS API-layer attack families)

Task M10-050 executes the M10 roadmap's API-layer attack tests
against the TBS layer (ADR-0046): EXHAUSTION (the 64-slot
context registry fills to TBS_E_TOO_MANY_TBS_CONTEXTS and
recovers after close-all; a 50-submit loop leaks no
descriptors), MALFORMED (unknown tag and header/length mismatch
answered by the vTPM's OWN errors verbatim with transport
success; a gate-controlled fake-socket matrix serves immediate
EOF, responseSize below the header, responseSize 0xffffffff, and
trailing garbage past the declared size - IOERROR or bounded
exactly at 16 bytes), CANCELLATION RACES (a 25-cancel storm
recovers; a 60-submit process and a 40-cancel process race the
same live prefix concurrently with nothing lost and no hang;
cancel after the vTPM stops fails closed as IOERROR),
CROSS-PREFIX LEAKAGE (prefix A stopped + prefix B live: A fails
closed while B keeps serving - no reach-across, identity
material never crosses), and VTPM-AS-HARDWARE (the vendor
identity served THROUGH the layer is the software emulator's -
manufacturer IBM at PT 0x105, vendor string SW at 0x106; the
research note records TPM_CAP_TPM_PROPERTIES=6 and the PT_FIXED
numbering, verified against tss2 headers and the executed
query). Five registry scenarios map the families to invariants
17, 18, 20, 23, 26, and 40 (66 scenarios; coverage 48/48).
Nothing in the layer needed hardening: the executed attacks
confirmed the M10-049 design. Executed on the dev host: the
attack gate, the M10-049 functional gate, the manager gate, the
traceability gate, and the coverage gate all PASS. Open
deliberately: the WoW64 ABI tests, the M10 exit audit, and
upstream submission. See the
[local issue](../planning/issues/050-tbs-attack-families.md) and
[ADR-0046](../adr/0046-tbs-attack-families.md).
