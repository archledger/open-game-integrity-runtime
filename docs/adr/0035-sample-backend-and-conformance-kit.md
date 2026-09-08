# ADR-0035: The sample backend, the conformance kit, and the no-ban documentation

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M6-039 issue](../../planning/issues/039-sample-and-kit.md)
- Supersedes: None
- Superseded by: None

## Context

The M6 exit criteria ask that a fresh publisher can run the
conformance kit and integrate the sample flow WITHOUT Linux kernel
knowledge, and the roadmap asks for documentation for casual
fallback and no-ban semantics. M6-036..038 shipped the service,
the lifecycle, and the frozen SDK to integrate against.

## Decision drivers

- The kit must exercise exactly the surface a game server
  integrates against: HTTP against the verifier, nothing deeper.
- The sample must demonstrate the five-step target verbatim and
  keep the policy table visible (the mapping is the PUBLISHER'S).
- The no-ban rule must be documented as an integration contract,
  not an aspiration.

## Options considered

1. **A Rust integration test as the kit.** Reachable only by
   Rust-capable studios; the criterion says "a fresh publisher".
2. **A standalone Python kit over HTTP** (the deployment's actual
   surface) plus a Rust sample backend example for the flow.
3. **A curl script.** No assertions discipline.

## Decision

Adopt option 2. `scripts/conformance-kit.py` runs against any
deployment's address (developer mode: the daemon's simulation
route; production: a real client provides the evidence) and
fail-closed checks, in five groups: the five-step flow (challenge
issuance, evidence simulation, submission with the structured
verdict and permit), the lifecycle (renewal-with-stale-evidence
never admits; revocation confirms and is idempotent), freshness
(duplicate submission never re-admits; the taxonomy reason rides
the wire), and the wire bounds (malformed bodies, unknown routes,
and missing members 400; oversized bodies are refused unread - the
reset close IS the expected refusal shape, tolerated by the kit).
`--self-test` validates the kit itself offline and runs in CI.

The sample backend
(`crates/ogir-dev-verifierd/examples/sample-game-server.rs`)
demonstrates the roadmap's five steps against a running daemon,
with the publisher's policy table in full view: the mapping from
verdict families to gameplay states (Admit, AdmitRestricted,
CasualFallback, RetryLater, EndGracefully) is THE PUBLISHER'S
choice, and the demo's table implements the documented intended
mapping - including the casual fallback (unsupported: full game,
no protected extras, no flag) and the graceful end (deny: the
server's own relayed decision, never an accusation).

`docs/CASUAL_FALLBACK.md` is the integration contract: the one
rule (an attestation result is never a cheating accusation), the
family table with intended mappings, the casual-fallback path, the
never-list for publishers, and the local quickstart.

## Consequences

- The M6 exit criterion "a fresh publisher can run the conformance
  kit and integrate the sample flow" is executable today against
  the developer-mode daemon.
- The kit doubles as a CI gate (self-test) and a deployment
  diagnostic.
- The sample backend is developer-mode-only (it uses the
  simulation route); a production sample arrives with a real
  client-side flow in later milestones.

## Threat-model impact

The kit hardens the deployment boundary: wire-bounds and freshness
behavior are now publisher-verifiable, reducing the chance of a
studio integrating against an accidental behavior that later
changes. No new trust boundary opens.

## Privacy impact

None: the kit sends publisher-chosen identifiers to the deployment
under test.

## Dependency and license impact

None (stdlib Python; an existing example target).

## Validation

Executed on the dev host: the kit's 15 checks ALL PASS against the
running developer-mode daemon; the sample backend completes the
five-step flow with the lifecycle demo (allow -> Admit with the
permit on file; stale renewal denies; revocation confirms); the
self-test passes and is wired into CI. Full house gates in the
slice record.

## Rollback

Revert the commit; the kit, sample, and documentation disappear
together.

## Primary sources

- The M6 exit criteria and the executed runs (2026-09-08).
- ADR-0033 (the verdict families the kit asserts), ADR-0034 (the
  frozen SDK the sample integrates against).
