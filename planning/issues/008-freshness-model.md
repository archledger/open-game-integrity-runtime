# M1-008: Specify challenge freshness, expiry, and clock behavior
<!-- labels: type: architecture,type: implementation,area: protocol,risk: cryptography,status: needs-research -->
<!-- milestone: M1 Domain Model -->

## Problem

Nonce uniqueness alone does not define challenge freshness. The protocol needs explicit issuance, expiry, replay, clock-skew, restart, and verifier-authority semantics.

## Security invariants

- A challenge cannot be valid before issuance or at/after expiry.
- A consumed nonce cannot authorize a second session.
- The untrusted client does not choose authoritative time.
- Clock rollback cannot extend a permit.

## In scope

- Define which component issues and evaluates time fields.
- Define inclusive/exclusive time boundaries and allowed skew.
- Define replay-cache key, persistence, restart behavior, and denial-of-service bounds.
- Add pure-model tests for time-window boundaries.
- Record unresolved distributed-system choices in an ADR.

## Out of scope

- Production database selection.
- TPM clock/counter use.
- Permit renewal implementation.

## Primary sources

- RFC 9334 RATS architecture: https://www.rfc-editor.org/rfc/rfc9334.html
- RFC 9711 EAT: https://www.rfc-editor.org/rfc/rfc9711.html

## Required tests

- Before issue time, exact issue time, just before expiry, exact expiry, and after expiry.
- Duplicate nonce in the same and different game contexts.
- Verifier restart and cache-unavailable behavior fail closed.
- Extreme future and overflow-prone timestamps are rejected.

## Acceptance criteria

- Freshness semantics are documented independently of any database.
- Model tests reflect the written boundary rules.
- No local-client time claim is authoritative.
