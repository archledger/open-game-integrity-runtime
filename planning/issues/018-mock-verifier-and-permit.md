# M2-018: Implement the mock verifier and permit lifecycle
<!-- labels: type: implementation,area: verifier,area: protocol,risk: trusted-computing-base,status: needs-review -->
<!-- milestone: M2 Mock End-to-End Proof -->

Status: Local integration candidate; no live GitHub issue yet. Implements the M2-018 charter from the approved M2-016 design record.

## Problem

The M2-017 substrate can sign and verify objects, but nothing yet appraises
evidence into a permit or admits a session: no policy interface exists, the
ADR-0013 replay cache is unwired, permits have no issuing path, and no
relying party enforces "only a verifier-signed permit with valid proof".
The M2 exit criterion "the server admits only a verifier-signed permit with
valid proof of possession" needs this slice to exist.

## Scope

- Session-key registry in the mock key directory (the trusted mock channel
  for relying-party proof validation).
- `MockPolicy` interface plus `ContextMatchPolicy` exact-context
  implementation over verified objects only.
- `MockVerifierService`: verify challenge and evidence, enforce the
  half-open window, register and claim the nonce in the verifier crate's
  opt-in ADR-0013 replay cache, apply the policy, issue the signed permit
  or a deterministic non-disciplinary denial.
- `MockRelyingParty`: permit verification under its own trusted keys,
  exclusive-expiry check, proof-of-possession validation under the exact
  registered session key and exact permit bytes, one-use initial admission.

## Acceptance criteria

- All local gates green: fmt, clippy, rustdoc under `-D warnings`, 444
  workspace tests, isolation script.
- The five hosted attack categories reject deterministically: patched
  client, evidence replay, permit replay, expired permit, verifier key
  mismatch (plus unknown session key and context mismatch).
- No production crate changed; `ogir-model` untouched; the
  `research-mock-replay` feature stays opt-in per ADR-0013.

## Current state

- 2026-09-06: Implemented in `research/m2-018-mock-verifier-and-permit`
  from `79e2410`; awaiting human review and the signed-commit gate.
