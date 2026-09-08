# ADR-0032: The verifier service shell and the developer-mode daemon

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M6-036 issue](../../planning/issues/036-service-shell.md)
- Supersedes: None
- Superseded by: None

## Context

M6 opens with the self-hostable verifier service and the local
developer mode. The M1/M2 machinery (capability-gated verification,
freshness, replay cache) and the M2 mock protocol exist as
libraries with no service surface; no HTTP dependency exists in the
signed inventory.

## Decision drivers

- No new signed-inventory dependencies for a research prototype.
- Bounded, strict, fail-closed everything (the portal philosophy at
  the service layer).
- The production graph must stay free of the mock substrate
  (scripts/test-mock-substrate.py).
- Determinism and testability: decision time is injected, not
  wall-clock.

## Options considered

1. **A web framework (axum/hyper).** Large supply-chain surface;
   rejected for this stage.
2. **The shell in the production crate, substrate injected through
   traits; the developer-mode daemon as a new mock-tier crate.**
3. **The service inside the mock substrate.** Puts protocol code
   in test-only territory; rejected.

## Decision

Adopt option 2. `ogir-verifier::{bjson, http, service}` is the
production shell:

- `bjson`: a strict bounded JSON codec for a FLAT object language -
  string and lowercase-hex members only (`_hex` keys), fixed
  ceilings (64KB wire, 32 members, 512-char strings, 8192-char
  hex), no numbers/arrays/nesting/duplicates/control characters/
  exotic escapes, trailing garbage rejected. Hand-rolled so the
  inventory stays untouched; the fuzz targets land with the M6-038
  SDK slice (the recorded M5 remainder).
- `http`: a bounded HTTP/1.1 endpoint - fixed 4KB header block,
  Content-Length required and capped at 64KB, one request per
  connection (Connection: close), fixed status lines. No TLS: the
  verifier is the authority and transport protection is the
  publisher deployment's documented duty (localhost binding by
  default, or the publisher's reverse proxy fronts it).
- `service`: the routes `POST /v1/challenge` (issuance via the
  `ChallengeIssuer` trait), `POST /v1/dev/evidence` (simulation via
  the optional `EvidenceSimulator` trait - developer mode), and
  `POST /v1/evidence` (processing via the `EvidenceProcessor` trait
  into the wire verdict: allow+permit_hex or deny+reason).
  Decision time is a parameter.

`crates/ogir-dev-verifierd` is the developer-mode daemon (the
"local developer mode using test keys and simulated profiles"
deliverable): it composes the mock substrate
(MockVerifierService, ContextMatchPolicy, deterministic seed keys)
into the shell. The service is rebuilt at each challenge issuance
with the exact expected context of that challenge, so the
three-step flow exercises the full verify-replay-policy-permit
chain per challenge. The daemon is mock-tier by construction; the
isolation gate now asserts its existence, its shell dependency, and
keeps it out of the production graph. The authoritative backend
composes the real M3/M5 chain into the same shell later.

## Consequences

- Renewal/revocation routes, the structured diagnostic API, and
  the remaining lifecycle land with M6-037+ on this shell.
- The wire codec's surface is deliberately tiny; anything richer
  waits for the conformance kit to pin it.
- The bin binds 127.0.0.1:8080 by default and says so at startup.

## Threat-model impact

The shell exposes no authority of its own: verdicts come from the
injected processor. All inputs are bounded before parsing; the
oversized-body leg refuses without reading the body. The dev daemon
signs with TEST-ONLY keys (ADR-0016 posture).

## Privacy impact

The wire carries publisher-chosen identifiers and digests only;
the shell logs nothing.

## Dependency and license impact

None: the codec and endpoint are in-repo; the daemon adds one
in-workspace mock-tier crate.

## Validation

Executed on the dev host: ogir-verifier 129 lib tests green (7
codec negatives + 4 route tests; the authority-inventory pin
updated for the new modules); the daemon's six HTTP integration
tests green against REAL TCP on ephemeral ports - the full
three-step flow ADMITS with a permit, duplicate submission denies
ReplayDetected, submission-before-issuance denies cleanly, malformed
bodies and unknown routes 400, oversized bodies refused. Full house
gates in the slice record.

## Rollback

Revert the commit; the shell modules, daemon crate, and gate
amendment disappear together.

## Primary sources

- The M6 entry scoping (task-18-scoping/m6-entry-scoping.md) and
  the executed integration runs (2026-09-08).
- ADR-0016/0017 (the test substrate posture the daemon composes).
