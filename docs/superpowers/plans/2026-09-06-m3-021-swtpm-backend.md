# Plan: M3-021 swtpm backend

- Status: Executed in `research/m3-021-swtpm-backend`; all local gates
  green; awaiting human review, signed commit, and separately
  authorized publication.
- Date: 2026-09-06.
- Baseline: merged `84fd0a3a263001d861c4f9ee1c032046bfcfbaab`.
- Authority: approved M3 entry scoping (R1-R4); [ADR-0018](../../../docs/adr/0018-tss-esapi-dependency-and-swtpm-backend.md);
  [local issue](../../../planning/issues/021-swtpm-backend.md).

## Tasks

1. `crates/ogir-attest-tpm`: upstream tss-esapi 7.7.0 dependency and
   the `SwtpmBackend` (AK primary, quote, qualifying binding, password
   session, fail-closed mapping).
2. `deny.toml`: the signed 53-crate allowlist and SPDX license set.
3. CI: TPM toolchain step; isolation gate extended to cover
   `ogir-attest-tpm` as a production manifest.
4. ADR-0018, index row, roadmap boundary, local issue, this plan.

## Test inventory (executed, all green)

- Five real-swtpm integration tests: real quote with echo and digest
  and 256-byte signature; distinct-data distinct-payload; class gate
  (software rejected under hardware/test); invalid request fails
  closed; unreachable instance fails closed.
- Full workspace suite; all house gates; `cargo deny check` fully
  green.

## Development lessons (also in ADR-0018)

swtpm requires `--flags not-need-init,startup-clear` (else
TPM_RC_INITIALIZE); ESYS CreatePrimary/Quote need a password session
(else TSS2_BASE_RC_BAD_VALUE via the session-feasibility check); the
TCTI handshake needs both server and ctrl ports listening; spawn swtpm
with split argv entries, never `--opt value` as one argument; retry
port allocation against parallel-test collisions.

## Deliberately not done

Verifier-side cryptographic quote validation, AK enrollment, identity
and recovery ADRs (M3-022); fTPM fixture and robustness (M3-023); the
ten M3 attack tests (M3-024).
