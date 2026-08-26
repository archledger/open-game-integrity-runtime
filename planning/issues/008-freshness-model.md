# M1-008: Specify challenge freshness, expiry, and clock behavior
<!-- labels: type: architecture,area: model,area: protocol,area: verifier,risk: cryptography,risk: privacy,risk: trusted-computing-base,status: needs-review -->
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
- RFC 7519 JWT time boundaries: https://www.rfc-editor.org/rfc/rfc7519.html
- Rust `SystemTime` behavior: https://doc.rust-lang.org/std/time/struct.SystemTime.html

## Threats addressed

- Replay of one publisher nonce in the same or altered context.
- Check-then-consume races that yield two freshness capabilities.
- Restart, state loss, or clock rollback that makes an old challenge reusable.
- Capacity pressure that evicts a live replay record or degrades to stateless validation.
- Nonce/account/match disclosure through errors, debug output, or retained state.

## Required interfaces

- Dependency-free `UnixTime`, `ChallengeLifetime`, `ChallengeWindow`,
  `FreshnessLimits`, and `FreshnessError` model types.
- Synchronous database-neutral `ReplayStore` operations for durable time-floor
  observation, atomic registration, atomic claim, and expiry-only GC.
- `FreshnessGuard` with a public raw claim that returns no capability; only the
  ordered verifier context/claim transition constructs `FreshnessChecked`.
- Non-disciplinary mapping of replay to deny and operational state/time/capacity
  failure to retry/unavailable protected mode.

## Positive tests

- Exact issuance and the final second before expiry reach later appraisal.
- First registered claim succeeds exactly once.
- Identical nonce bytes under different authenticated publishers are independent.
- Issued/consumed records, issuance-rate state, and high-water survive reopen.
- Every configured lifetime/capacity/rate boundary is accepted at its exact limit.

## Negative tests

- Before issue time, exact expiry, and after expiry reject.
- Duplicate nonce in the same or altered game/build/account/match/policy/window rejects without consuming the legitimate issued record.
- Missing, unavailable, corrupt, poisoned, rolled-back, or full state fails closed.
- Later context mismatch advances durable time before rejection without
  consuming the correctly bound issued record.
- Two concurrent claims cannot both succeed; unexpired records are never evicted.
- Expired replay records and out-of-window issuance history are purged through
  handles already reopened on the authoritative durable state.
- Binding/time leaves and challenge, expected-context, request, replay, store,
  guard, and durable-handle debug surfaces expose only redaction markers.
- Attack-scenario validation rejects a freshness threat without an accountable
  owner or required assurance profile.
- Extreme-future and overflow-prone timestamps cannot authorize.
- Raw claim cannot return or construct `FreshnessChecked`.

## Fuzz/property tests

- A fixed-seed independent oracle checks 16,384 register/claim/time/rollback/restart/unavailable/GC operations.
- Twenty-one isolated mutations cover both window edges, key scope, atomicity,
  restart, rollback, capacity, claim release/error side effects, time/context
  observation, capability bypass, arithmetic, bounded retention, shared
  durable-state deletion after reopen, and complete leaf/aggregate privacy
  redaction.
- M1-008 adds no parser or wire format, so it adds no fuzz target; parser fuzzing
  remains required when challenge serialization is selected.

## Privacy impact

Replay records retain exact authorization bindings only through challenge
expiry; issuance events remain only through their configured rate window.
Default debug on binding/time leaves and challenge, expected-context, request,
replay, store, guard, and durable-handle aggregates redacts publisher/game/
build/account/match/policy/version, nonce, and window timestamps. Explicit
accessors remain trusted functional interfaces, not diagnostic sinks. Handles
reopened before purge share the authoritative state generation and observe
later deletion; exported backups need separate finite retention and
anti-rollback review. State is not telemetry and no evidence claim or
cross-publisher identifier is added.

## Dependency impact

Standard library only. No manifest/lockfile change and no database, clock, RNG,
serialization, async, cryptographic, or unsafe-code dependency is selected.

## Acceptance criteria

- Freshness semantics are documented independently of any database.
- Model tests reflect the written boundary rules.
- No local-client time claim is authoritative.
- Every accepted freshness threat has a schema-enforced owner, assurance
  profile, invariants, scenario, tests, and residual risk.
