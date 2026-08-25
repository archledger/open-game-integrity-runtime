# ADR-0004: No authoritative local trust decision

- Status: Accepted
- Date: 2026-08-24
- Owners: Initial maintainer
- Related issues: None recorded
- Supersedes: None
- Superseded by: None

## Context

The Windows game, Wine prefix, bridge, and local user are attacker-controlled in the primary threat model. A local `IsTrusted()` result can be patched.

## Decision drivers

- Prevent attacker-controlled client code from authorizing its own protected
  session.
- Bind authorization to fresh evidence, publisher policy, match/account scope,
  and proof of possession of an ephemeral session key.
- Keep attestation evaluation separate from ordinary matchmaking transport.
- Preserve explicit policy differences for protected, offline, and casual
  modes without silently weakening ranked authorization.

## Options considered

### Authoritative local trust boolean

Rejected because the game, bridge, prefix, or same-user process can patch or
fabricate a local success value.

### Matchmaking service parses and evaluates raw evidence directly

Rejected as the default architecture because it duplicates security-critical
parsing and policy logic across relying parties and expands the verifier trust
surface.

### Publisher-controlled verifier issues a scoped permit

Selected because the client transports evidence but cannot create the
publisher's authorization result, and the relying party can validate a narrow,
short-lived artifact plus session-key proof.

## Decision

The client API returns evidence transport status and an opaque publisher-signed permit. Only a publisher-controlled verifier may issue an accepted Attestation Result, and the relying party verifies both the permit and proof of possession of the bound session key.

## Consequences

No SDK API may expose a local boolean as authoritative. Offline or casual modes may use different publisher policy, but ranked authorization remains server-side.

## Threat-model impact

This decision directly addresses A1 client patching and fake-local-success
threats. Fresh challenge, permit scope, expiry, and proof of possession also
constrain replay and cross-session use. Compromise of the publisher verifier or
its signing key remains an A5 residual risk requiring key separation,
revocation, and independent relying-party validation.

## Privacy impact

The game receives transport status and an opaque permit rather than broad host
inspection results. Evidence sent to the publisher remains bounded by the fixed
claim vocabulary, declared policy, minimal retention, and publisher-scoped
identity requirements.

## Dependency and license impact

This ADR selects no network, cryptographic, or serialization dependency and
does not freeze a wire format. Those choices require later ADRs and dependency
review. Client SDK, verifier, and permit model remain in the Apache-2.0 core.

## Validation

- Keep the scaffold verifier fail closed for unverified evidence.
- Test that local booleans, DLL return values, and client claims cannot produce
  authorization.
- Add negative tests for expiry, replay, match/account/session mismatch, and
  missing session-key proof.
- Verify the relying party checks the publisher signature and exact permit
  bindings independently.

## Rollback

If the verifier or permit path is unavailable, deny the protected mode or use a
separately disclosed non-protected publisher policy. Never fall back to an
authoritative local allow result. Changing authority requires a superseding ADR.

## Primary sources

- [IETF RFC 9334 — RATS Architecture](https://www.rfc-editor.org/rfc/rfc9334.html)
- [OGIR architecture](../ARCHITECTURE.md)
- [OGIR threat model](../THREAT_MODEL.md), especially client patching, replay,
  cuckoo/relay, and supply-chain threats
- [OGIR security invariants](../SECURITY_INVARIANTS.md), especially invariants
  1–10 and 39–42
