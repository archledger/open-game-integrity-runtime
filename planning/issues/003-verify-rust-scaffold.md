# M0-003: Compile the Rust 1.98 scaffold and commit Cargo.lock
<!-- labels: type: implementation,type: test,area: supply-chain,status: ready -->
<!-- milestone: M0 Repository Foundation -->

## Problem

The bootstrap was structurally validated, but it must be compiled and linted on the pinned Rust toolchain before implementation begins.

## Security invariants

- The verifier scaffold remains fail-closed and cannot return `Decision::Allow`.
- The workspace has no undeclared external dependency.
- Warnings are treated as errors.

## In scope

- Install/use the pinned Rust 1.98.0 toolchain.
- Run formatting, Clippy, tests, and documentation build.
- Fix only scaffold defects revealed by those checks.
- Generate and commit `Cargo.lock`.
- Run `cargo deny check` against `deny.toml`.

## Out of scope

- Adding TPM, serialization, async, crypto, HTTP, or database dependencies.
- Implementing the mock protocol.
- Relaxing lints merely to pass CI.

## Primary sources

- Rust toolchain files: https://rust-lang.github.io/rustup/overrides.html#the-toolchain-file
- Cargo manifest: https://doc.rust-lang.org/cargo/reference/manifest.html
- Clippy: https://doc.rust-lang.org/clippy/
- cargo-deny: https://github.com/EmbarkStudios/cargo-deny

## Required tests

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
cargo deny check
```

Add a test asserting that the research verifier never allows opaque evidence.

## Acceptance criteria

- Every command passes on a clean clone.
- `Cargo.lock` is committed.
- No dependency is added.
- Exact tool versions and command output are recorded in the pull request.
