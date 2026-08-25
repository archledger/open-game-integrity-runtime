# ADR-0004: No authoritative local trust decision

- Status: Accepted
- Date: 2026-08-24
- Owners: Initial maintainer

## Context

The Windows game, Wine prefix, bridge, and local user are attacker-controlled in the primary threat model. A local `IsTrusted()` result can be patched.

## Decision

The client API returns evidence transport status and an opaque publisher-signed permit. Only a publisher-controlled verifier may issue an accepted Attestation Result, and the relying party verifies both the permit and proof of possession of the bound session key.

## Consequences

No SDK API may expose a local boolean as authoritative. Offline or casual modes may use different publisher policy, but ranked authorization remains server-side.
