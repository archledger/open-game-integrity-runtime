# ADR-0001: Rust as the primary trusted-core language

- Status: Accepted
- Date: 2026-08-24
- Owners: Initial maintainer
- Related issues: None recorded
- Supersedes: None
- Superseded by: None

## Context

OGIR contains network, IPC, parser, process, TPM, and policy components that will process hostile input. Memory corruption in a privileged or verifier component would be security-critical.

## Decision drivers

- Prefer memory-safe implementation for hostile parsers and privileged policy
  code.
- Keep unsafe ABI and kernel-facing code narrow enough for focused review.
- Support deterministic builds, linting, tests, and dependency review with a
  pinned toolchain.
- Preserve stable C boundaries for Wine, BPF, and external SDK consumers.

## Options considered

### Rust for the trusted core with narrow C boundaries

Selected because it provides memory-safe defaults while retaining explicit C
ABIs where compatibility requires them.

### C or C++ throughout the trusted core

Rejected because hostile parsing and privileged policy code would expose a
larger memory-corruption surface without providing a necessary compatibility
benefit.

### Split the trusted core across several primary languages

Rejected because additional build systems and cross-language boundaries would
increase review and supply-chain complexity before a demonstrated need exists.

## Decision

Use Rust 2024 as the primary language for the agent, portal, session controller, policy engine, evidence model, verifier, command-line tools, and test infrastructure where practical.

Use C only at necessary Wine and BPF boundaries. Keep C surfaces narrow and move policy and parsing into Rust. Safe Rust is the workspace default; any future `unsafe` crate requires a separate ADR.

## Consequences

- Rust toolchain is pinned in source control.
- Cross-language ABI is a stable C interface.
- The project must still address logic, concurrency, FFI, dependency, and supply-chain vulnerabilities; memory safety is not a complete security model.

## Threat-model impact

This decision reduces memory-corruption exposure in components that process
hostile input, especially across attacker classes A0–A4. It does not mitigate
logic bugs, compromised dependencies, unsafe FFI, malicious maintainers, or an
accepted but vulnerable platform; those remain explicit residual risks.

## Privacy impact

This language choice adds no evidence claim, identifier, retention rule, or log
field. Privacy remains governed by the fixed claim vocabulary and redaction
invariants rather than by implementation language.

## Dependency and license impact

The Rust toolchain and every crate become supply-chain inputs subject to pinning,
license review, advisory checks, and maintenance review. Default Rust source is
Apache-2.0; Wine and kernel-facing C boundaries retain their separate license
rules.

## Validation

- Pin the Rust edition and toolchain in source control.
- Forbid unsafe code by default and require a separate ADR for any exception.
- Run rustfmt, Clippy with warnings denied, workspace tests, rustdoc with warnings
  denied, cargo-deny, and C-header compile checks in CI.
- Review each new dependency before it enters the trusted computing base.

## Rollback

A change of primary trusted-core language requires a superseding ADR and a
reviewed migration plan. If a Rust component proves infeasible, disable or
isolate that component rather than silently expanding C or unsafe code.

## Primary sources

- [Rust Reference](https://doc.rust-lang.org/reference/)
- [Cargo manifest reference](https://doc.rust-lang.org/cargo/reference/manifest.html)
- [OGIR security invariants](../SECURITY_INVARIANTS.md), especially invariants
  23, 28, 32, and 45
- [OGIR primary technical sources](../SOURCES.md#rust-and-supply-chain-tooling)
