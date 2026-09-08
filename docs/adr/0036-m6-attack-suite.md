# ADR-0036: The M6 attack suite and the milestone close

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M6-040 issue](../../planning/issues/040-suite-and-audit.md)
- Supersedes: None
- Superseded by: None

## Context

M6's ten required attack tests close the milestone alongside its
exit audit. Five categories were already hosted in focused suites
(M6-036/037/039); the closer consolidates all ten into the house
inventory pattern so the milestone record is self-contained, then
audits the three exit criteria.

## Decision drivers

- The suite must run against the REAL stack (production shell +
  backend over TCP), not mock-route units.
- Each category lands a deterministic non-allow (or, for the
  structural categories, a deterministic impossibility assertion).
- No new dependencies.

## Options considered

1. **Extend the M6-039 kit with attack legs.** The kit is a
   publisher tool; attack suites are house records - different
   audiences.
2. **A Rust integration test in the developer-mode crate** (real
   TCP against serve_one with the full backend), re-hosting the
   already-executed legs.

## Decision

Adopt option 2. `crates/ogir-dev-verifierd/tests/m6_attack_suite.rs`
hosts all ten categories over real TCP: unsigned evidence never
admits (the shell cannot neglect signature validation - the
backend validates before any verdict); wrong-expected-context
submissions deny (a stale match.a pair against a match.b
expectation); a corrupted-signature challenge (the stale-key
shape) rejects; a revoked permit never reanimates (renewal denies
Revoked); permit parser confusion denies Malformed; permit-only
renewal without fresh evidence denies (the PoP-demand shape);
verifier time skew denies NotYetValid under injected decision
time; duplicate submission never re-admits; outage surfaces as a
loud client error while TransientFailure/AttestationUnavailable
map to the Retry family (never punitive); and unsupported is
never deny - asserted at the wire family, retryability, spelling,
and permit-absence levels, plus a compile-time completeness check
that the backend implements every service trait. 11/11 green
across three consecutive runs.

The exit audit finds all three M6 criteria satisfied by executed
work with the honest limitations recorded (developer-mode
end-to-end; restricted not yet emitted; wow64 fail-closed; CI
self-test rather than fuzzing).

## Consequences

- M6 closes: M0-M6 complete; next is M7 (protected-session
  observation).
- The suite's connection-counting discipline (a threaded server
  serves EXACTLY the connections the test makes) is recorded for
  the next environment-sensitive suite.

## Threat-model impact

The named insecure patterns are now executable house records: the
shell cannot skip signature validation, stale keys and revoked
fixtures fail closed, time skew is the server's authority, and
the unsupported/deny collapse is structurally impossible.

## Privacy impact

None.

## Dependency and license impact

None.

## Validation

Executed on the dev host: the eleven-test suite green across
three consecutive runs; the full house gates in the slice record.

## Rollback

Revert the commit; the suite, audit, and closure docs disappear
together.

## Primary sources

- The M6 roadmap categories and the executed runs (2026-09-08).
- ADR-0032..0035 (the stack the suite attacks).
