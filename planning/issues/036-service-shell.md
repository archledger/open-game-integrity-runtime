# M6-036: The verifier service shell and the developer-mode daemon
<!-- labels: type: implementation,area: verifier,area: protocol,status: needs-review -->
<!-- milestone: M6 Publisher SDK and Verifier -->


## Problem

M6 opens with the self-hostable verifier service and the local
developer mode. The M1/M2 machinery and the M2 mock protocol exist
as libraries with no service surface, and no HTTP dependency exists
in the signed inventory.

## What this slice delivers

1. `ogir_verifier::bjson` (ADR-0032) - a strict bounded JSON codec
   for flat string/hex objects: fixed ceilings (64KB wire, 32
   members, 512-char strings, 8192-char hex), no
   numbers/arrays/nesting/duplicates/control characters, trailing
   garbage rejected. Hand-rolled; the fuzz targets land with
   M6-038.
2. `ogir_verifier::http` - a bounded HTTP/1.1 endpoint: 4KB header
   ceiling, capped required Content-Length, one request per
   connection, fixed statuses, no TLS (the documented deployment
   duty).
3. `ogir_verifier::service` - the routes /v1/challenge,
   /v1/dev/evidence, /v1/evidence over trait-injected semantics
   (ChallengeIssuer, EvidenceSimulator, EvidenceProcessor) with
   decision time as a parameter.
4. `crates/ogir-dev-verifierd` - the developer-mode daemon: the
   mock substrate composed into the shell, rebuilt per challenge
   issuance; mock-tier by construction (the isolation gate asserts
   it and keeps the production graph clean). Includes the binary
   (127.0.0.1:8080 default).
5. ADR-0032 + index row; ROADMAP boundary; this issue; the plan.

## Executed evidence (dev host)

- ogir-verifier: 129 lib tests green (7 codec negatives, 4 route
  tests; the authority-inventory pin updated for the new modules).
- The daemon's six HTTP integration tests over REAL TCP on
  ephemeral ports: the full three-step flow ADMITS with a permit;
  duplicate submission denies ReplayDetected; submission before
  issuance denies cleanly; malformed bodies and unknown routes
  400; oversized bodies refused unread.

## Security invariants

- The shell exposes no authority of its own; verdicts come from
  the injected processor; all inputs bounded before parsing.
- No new external dependencies; the production graph stays
  mock-free (gate-enforced).

## Out of scope

- Renewal/revocation + the structured diagnostic API (M6-037); the
  stable SDK + fuzz targets (M6-038); the sample backend +
  conformance kit (M6-039); the ten-category suite + exit audit
  (M6-040).
