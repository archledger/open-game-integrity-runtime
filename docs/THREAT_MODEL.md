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

## 7. Explicit residual risks

- unknown exploits in accepted kernels, firmware, TPM stacks, agents, or verifiers;
- sophisticated full-session relay attacks;
- external computer-vision or hardware-assisted cheats;
- server vulnerabilities and non-authoritative game logic;
- DMA or physical attacks outside the selected profile;
- dynamic/JIT code that cannot be fully represented by file measurement alone;
- incomplete IMA or enforcement policies that omit a relevant object or interface;
- compromised publisher infrastructure;
- replay-store/clock outage or a forward time jump causing fail-closed
  protected-mode unavailability;
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

The threat model is updated in the same pull request as any changed trust boundary, privilege, protocol field, evidence claim, policy control, or signing/update path.
