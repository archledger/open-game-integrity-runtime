# Open Game Integrity Runtime (OGIR)

> **Status: experimental research software.** OGIR is not ready for production anti-cheat enforcement, ranked-match authorization, player bans, or production signing keys.

Open Game Integrity Runtime is a proposed privacy-preserving Linux game-integrity platform. Its goal is to let a publisher request a clearly defined integrity policy for a Windows game running through Proton, receive fresh hardware-rooted evidence about the protected Linux game session, and make the final authorization decision on a publisher-controlled verifier.

OGIR does **not** attempt to translate arbitrary Windows kernel anti-cheat drivers into Linux kernel modules. It provides an explicit Linux-native trust path instead.

## Core principles

1. **The local game client is untrusted.** A patched DLL or local `trusted=true` result can never authorize a protected match.
2. **Compatibility and trust are separate planes.** Windows TPM API compatibility may use an isolated virtual TPM; physical TPM attestation uses a narrow policy-controlled API.
3. **The publisher controls authorization.** The publisher verifier evaluates evidence and issues a short-lived session permit.
4. **Evidence is session-bound.** A report is bound to the server nonce, publisher, game, build, policy, match, runtime, and an ephemeral session key.
5. **Minimum disclosure.** OGIR must not expose unrelated process lists, personal files, browser activity, raw biometric data, or a universal hardware identifier.
6. **Failure is not proof of cheating.** Unsupported systems, version mismatches, and hardware faults must not automatically become disciplinary actions.
7. **Security claims are testable.** Every claim requires positive tests, negative tests, adversarial scenarios, and documented residual risk.

## First proof of concept

The initial end-to-end proof is deliberately narrow:

```text
Publisher sample server
    -> issues a fresh signed challenge
Windows sample client under stock Proton
    -> passes challenge through a narrow bridge
Unprivileged OGIR portal
    -> authenticates the actual local caller
Minimal OGIR agent
    -> creates TPM-backed evidence bound to the session
Publisher-controlled verifier
    -> validates evidence and issues a short-lived permit
Sample server
    -> validates the permit and session-key proof
```

The proof must reject:

- a patched Windows bridge;
- a replayed challenge, evidence bundle, or permit;
- a permit used for another match or account;
- a changed game executable or runtime manifest;
- an unaccepted boot profile;
- evidence that is malformed, oversized, ambiguous, expired, or revoked.

## Repository map

```text
crates/                  Rust libraries for the trusted core
apps/                    Runnable agent and verifier prototypes
sdk/                     Stable C ABI and future engine wrappers
wine/                    Separate Wine integration workstream
bpf/                     Future GPL-licensed, session-scoped BPF work
lab/                     Adversarial test scenarios and attack tooling
planning/                Reviewable initial GitHub issue specifications
docs/                    Architecture, roadmap, threat model, and policies
.github/                 Review, issue, dependency, and CI configuration
```

## Build the current scaffold

The repository pins Rust through `rust-toolchain.toml`.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
```

The initial crates intentionally avoid selecting a TPM, CBOR/COSE, web framework, or async runtime. Those choices require architecture decision records and focused security spikes before becoming dependencies of the trusted computing base.

## Read before contributing

1. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
2. [`docs/SECURITY_INVARIANTS.md`](docs/SECURITY_INVARIANTS.md)
3. [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
4. [`docs/ROADMAP.md`](docs/ROADMAP.md)
5. [`docs/AI_DEVELOPMENT_POLICY.md`](docs/AI_DEVELOPMENT_POLICY.md)
6. [`CONTRIBUTING.md`](CONTRIBUTING.md)
7. [`AGENTS.md`](AGENTS.md) for AI coding agents

## Security reporting

Do not open a public issue for a suspected vulnerability. Follow [`SECURITY.md`](SECURITY.md).

## Licensing

The default project license is Apache License 2.0. Wine-upstream code must use `LGPL-2.1-or-later`; BPF-LSM and Linux-kernel-facing source must use a compatible GPL identifier. See [`LICENSES.md`](LICENSES.md).
