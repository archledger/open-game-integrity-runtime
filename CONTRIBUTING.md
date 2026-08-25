# Contributing to OGIR

OGIR is security-sensitive experimental software. Correctness, provenance, reviewability, and clearly bounded claims take priority over development speed.

## Before writing code

1. Read `docs/ARCHITECTURE.md`, `docs/SECURITY_INVARIANTS.md`, and `docs/THREAT_MODEL.md`.
2. Work from a GitHub issue with explicit scope, acceptance criteria, security impact, and test requirements.
3. Research current primary specifications and upstream source before selecting an API or dependency.
4. Create or update an architecture decision record for changes to trust boundaries, protocols, cryptography, privilege, dependencies, or persistent formats.
5. Write the negative tests that demonstrate how the feature must fail.

## Pull-request requirements

A pull request must include:

- the problem and threat addressed;
- the files and trust boundaries changed;
- primary-source references;
- positive and negative tests;
- fuzzing impact;
- privacy impact;
- compatibility and rollback impact;
- whether AI assisted the contribution;
- a `Signed-off-by` trailer certifying the Developer Certificate of Origin.

Example:

```text
Signed-off-by: Contributor Name <contributor@example.com>
AI-Assisted: yes
```

## Security-critical changes

The following require an explicit architecture decision record and an independent human review before a production release:

- cryptographic protocols or parameters;
- TPM commands, object templates, authorization policies, or key enrollment;
- verifier acceptance logic;
- evidence or permit parsing;
- local privileged operations;
- `unsafe` Rust or new C code;
- Wine ABI marshalling;
- BPF/LSM enforcement;
- update, signing, reference-value, or revocation logic;
- privacy claim expansion.

## Coding rules

- Safe Rust is the default. The workspace forbids `unsafe_code`.
- A future FFI crate may permit narrowly scoped `unsafe` only after an ADR and dedicated tests.
- Do not implement cryptographic primitives.
- Do not add dependencies without documenting purpose, maintenance status, license, transitive impact, and security surface.
- Do not log secrets, raw attestation identities, full evidence bundles, personal paths, or unrelated process information.
- Do not treat an attestation failure as proof of cheating.
- Do not silently broaden the protected-session policy.

## Local checks

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
```

Additional dependency, fuzzing, provenance, and bare-metal checks will become release gates as the relevant components are introduced.
