# M1-010: Implement the fail-closed verifier state machine
<!-- labels: type: implementation,area: model,area: verifier,risk: trusted-computing-base,status: ready -->
<!-- milestone: M1 Domain Model -->

## Problem

The verifier must not produce an allow result before freshness, identity, evidence, policy, revocation, and session binding are complete. A linear function with mutable flags is too easy to misuse as the verifier grows.

## Security invariants

- `Allow` is constructible only after every mandatory verification gate succeeds.
- Missing, unsupported, contradictory, or unavailable evidence never fails open.
- Denial reasons remain non-disciplinary.
- Expected context comes from the relying party, not the evidence bundle.

## In scope

- Model verifier states and typed transitions.
- Separate malformed, unsupported, retryable, denied, and revoked outcomes.
- Require independently supplied expected publisher/game/build/account/match/policy context.
- Add exhaustive and property tests.

## Out of scope

- Signature validation.
- TPM quote validation.
- Policy language implementation.
- Permit signing.

## Required tests

- No sequence missing one mandatory gate can produce Allow.
- Cross-game, cross-build, cross-account, cross-match, and cross-policy contexts fail.
- Unknown mandatory gate state fails closed.
- Terminal results cannot be mutated into Allow.
- Structural scaffold still never authorizes opaque evidence.

## Acceptance criteria

- The API encodes verification progress rather than exposing writable booleans.
- An allow result has an auditable proof path through all required gates.
- Tests cover every terminal decision and reason code.
