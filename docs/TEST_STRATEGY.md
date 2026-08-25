# Test and attack-simulation strategy

## Test pyramid

### Unit tests

Pure domain invariants, length checks, state transitions, policy evaluation,
redaction, expiry, identifier validation, and fail-closed behavior. Challenge
freshness includes checked window construction and literal before/exact issue,
last-second, exact/after expiry, excessive lifetime, and near-`u64::MAX`
boundaries.

### Property tests

Examples:

- changing any bound challenge field changes the binding digest;
- a permit for match A never validates for match B;
- an expired or revoked object never produces `Allow`;
- malformed or unknown critical input never produces `Allow`;
- encode/decode round trips preserve one canonical representation;
- renewal never lowers the active policy;
- disclosure output is a subset of the profile's allowed claims;
- fixed-seed register/claim/time-advance/rollback/restart/unavailable/GC
  sequences preserve at most one freshness capability, monotonic persisted
  time, no success from unavailable state, and no loss of an unexpired record.

### Fuzz tests

Every untrusted parser:

- Wine/Unix bridge frame;
- local IPC frame;
- publisher challenge;
- evidence bundle;
- TPM quote wrapper;
- measured-boot log;
- IMA log;
- policy and reference manifest;
- Attestation Result and permit;
- update metadata.

### Differential tests

At least two independent decoders/verifiers must agree on valid and invalid conformance vectors before the signed production format is frozen.

### Mutation tests

Freshness tests must fail when either time edge is widened, replay identity is
scoped by context, check and consume are split, restart clears records, clock
rollback is accepted, capacity evicts a live record, a successful claim remains
issued, future-time rejection skips durable observation, raw claim returns a
capability, checked arithmetic wraps, or nonce/account/match debug output is
unredacted. Each mutation runs in a disposable worktree; mutated source never
returns to the primary branch.

### Integration tests

- mock attester -> verifier -> permit;
- software TPM -> quote -> verifier;
- hardware TPM -> quote -> verifier;
- Proton sample client -> portal -> agent;
- measured boot evidence replay;
- session-key proof of possession;
- renewal and expiry;
- revocation propagation;
- challenge first/repeat claim, same-key changed context, and cross-publisher
  nonce independence;
- replay-state restart, rollback, missing/corrupt/unavailable failure,
  rejected-future observation persistence, capacity/rate limits, exact-expiry
  GC, simultaneous atomic claims, and raw-claim capability exclusion.

### Bare-metal tests

- accepted and unaccepted UKI/kernel profiles;
- Secure Boot enabled/disabled;
- hardware TPM, firmware TPM, vTPM, and no TPM;
- firmware and kernel updates;
- module-signing and lockdown variations;
- file and process races;
- supported GPU/runtime variations where relevant.

## Attack scenario format

Every security claim receives a scenario under `lab/scenarios/`:

```yaml
id: OGIR-PROTOCOL-REPLAY-001
title: Reuse a permit in another match
attacker: A1
assets:
  - protected_session_authorization
preconditions:
  - a valid permit exists for match-A
steps:
  - submit the permit to match-B
expected:
  decision: deny
  reason: session-binding-mismatch
  automatic_ban: false
invariants:
  - permit match binding is exact
residual_risk:
  - full-session relay requires a separate scenario
```

Challenge replay and freshness-state failure are represented by
`OGIR-PROTOCOL-REPLAY-002` and `OGIR-PROTOCOL-FRESHNESS-001`. Both require
non-disciplinary deny/retry outcomes and preserve the publisher-authoritative
time and durable single-use nonce invariants.

## Release gates by maturity

### Scaffold

- formatting;
- Clippy;
- unit tests;
- documentation build;
- dependency and license policy.

### End-to-end prototype

Adds:

- parser fuzz targets;
- replay and binding property tests;
- software-TPM integration;
- protocol conformance corpus;
- sanitizer coverage for C boundaries.

### Hardware alpha

Adds:

- hardware-TPM matrix;
- measured-boot replay tests;
- power interruption and TPM resource-pressure tests;
- process identity and PID-reuse stress;
- fault injection and daemon restart tests.

### Protected-session alpha

Adds:

- same-user memory-access attack corpus;
- cgroup migration and namespace races;
- debugger, perf, uprobe, and BPF attachment attempts;
- policy cleanup verification;
- unrelated-process noninterference tests.

### Production candidate

Adds:

- independent audit;
- white-box and black-box red team;
- supply-chain compromise exercises;
- key rotation and revocation drills;
- reproducible-build verification by independent builders;
- public conformance suite;
- private then public bug bounty.

## Mandatory failure behavior

A test failure cannot be resolved by weakening the invariant, skipping the test, broadening an allowlist, or suppressing a warning without a reviewed explanation and threat-model update.
