# M3-021: The tss-esapi dependency and the swtpm software-TPM backend
<!-- labels: type: implementation,area: tpm,risk: supply-chain,risk: trusted-computing-base,status: needs-review -->
<!-- milestone: M3 TPM Backend -->

Status: Local integration candidate; no live GitHub issue yet. Executes the approved M3 entry recommendations (R1-R4).

## Problem

M3 needs real TPM-backed quotes behind the ADR-0017 seam. That requires
the workspace's first external production dependency decision (tss-esapi
route per R1) and a software-TPM backend that CI can exercise
deterministically (R4). Until this slice, the workspace admitted zero
external crates by policy.

## Scope

- `crates/ogir-attest-tpm` (production): upstream `tss-esapi` 7.7.0
  (generate-bindings) with the `SwtpmBackend`: restricted-signing AK
  primary under Owner (RSA 2048, RSASSA-SHA256, fixedTPM/fixedParent),
  password session authorization, real TPM2_Quote over experimental PCR
  slot 16, qualifying-data binding, fail-closed error mapping.
- `deny.toml`: the signed 53-crate allowlist (normal + build graphs)
  and the permissive SPDX license set, citing ADR-0018.
- CI: install libclang-dev, libtss2-dev, swtpm; run the real-quote
  integration suite.
- ADR-0018 with the decision record and the development lessons;
  roadmap boundary; local issue and plan.

## Acceptance criteria

- All house gates green locally: fmt, clippy, rustdoc `-D warnings`,
  full workspace tests including five real-swtpm integration tests,
  isolation script, and `cargo deny check` fully green.
- Real TPM 2.0 quotes with qualifying-data echo, 32-byte SHA-256 PCR
  digest, and 256-byte RSA-2048 signatures, verified per test.
- The class gate holds: software statements reject under hardware and
  test expectations.
- Signed commit per house flow.

## Current state

- 2026-09-06: Implemented in `research/m3-021-swtpm-backend` from
  `84fd0a3`; awaiting human review and the signed-commit gate.
