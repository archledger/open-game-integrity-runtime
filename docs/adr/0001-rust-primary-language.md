# ADR-0001: Rust as the primary trusted-core language

- Status: Accepted
- Date: 2026-08-24
- Owners: Initial maintainer

## Context

OGIR contains network, IPC, parser, process, TPM, and policy components that will process hostile input. Memory corruption in a privileged or verifier component would be security-critical.

## Decision

Use Rust 2024 as the primary language for the agent, portal, session controller, policy engine, evidence model, verifier, command-line tools, and test infrastructure where practical.

Use C only at necessary Wine and BPF boundaries. Keep C surfaces narrow and move policy and parsing into Rust. Safe Rust is the workspace default; any future `unsafe` crate requires a separate ADR.

## Consequences

- Rust toolchain is pinned in source control.
- Cross-language ABI is a stable C interface.
- The project must still address logic, concurrency, FFI, dependency, and supply-chain vulnerabilities; memory safety is not a complete security model.
