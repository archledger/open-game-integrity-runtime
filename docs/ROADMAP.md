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
- `AttestationResult`
- `ReasonCode`
- `RevocationTarget`

`SessionPublicKeyId` is completed as M1-007F, a bounded identifier follow-up to
task 7. It is a non-authoritative lookup handle only. Task 11 remains the
separate result/reason-code taxonomy that later consumes a key reference under
the complete signed context.

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
`VerifiedAttestation` capability; it is not a signed `AttestationResult`,
permit, or game admission. Renewal starts a new appraisal attempt with a fresh
challenge. Result construction, permit issuance, expiry, renewal, and
revocation lifecycle are later domain/protocol issues. `Decision` and
`ReasonCode` are report-only views, and both full and restricted Allow classes
require all seven gates.

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
13. Define abstract JSON conformance fixtures.
14. Implement in-memory replay cache and tests.
15. Specify renewal and revocation semantics.

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
