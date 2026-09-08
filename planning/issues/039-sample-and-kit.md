# M6-039: The sample backend, the conformance kit, and the no-ban documentation
<!-- labels: type: implementation,area: verifier,status: needs-review -->
<!-- milestone: M6 Publisher SDK and Verifier -->


## Problem

The M6 exit criteria ask that a fresh publisher can run the
conformance kit and integrate the sample flow without Linux kernel
knowledge; the roadmap asks for casual-fallback and no-ban
documentation.

## What this slice delivers

1. `scripts/conformance-kit.py` (ADR-0035): 15 fail-closed checks
   over plain HTTP - the five-step flow, the lifecycle (stale
   renewal never admits; revocation confirms idempotently),
   freshness (duplicates never re-admit; the taxonomy reason rides
   the wire), and the wire bounds (400s; oversized refused unread
   with the reset close tolerated as the expected refusal).
   --self-test runs in CI.
2. `crates/ogir-dev-verifierd/examples/sample-game-server.rs`: the
   roadmap's five steps against a running daemon, with the
   publisher's policy table in full view - verdict families to
   gameplay states is THE PUBLISHER'S choice; the demo implements
   the documented intended mapping including casual fallback.
3. `docs/CASUAL_FALLBACK.md`: the integration contract - the one
   rule (an attestation result is never a cheating accusation),
   the family table, the fallback path, the never-list, and the
   local quickstart.
4. ADR-0035 + index row; ROADMAP boundary; this issue; the plan.

## Executed evidence (dev host)

- The kit: 15/15 PASS against the running developer-mode daemon.
- The sample backend: the full five-step flow (allow -> Admit,
  permit on file) plus the lifecycle demo (stale renewal denies;
  revocation confirms); the self-test PASS and wired into CI.

## Security invariants

- The kit asserts the wire contract (bounds, freshness, families);
  no new trust boundary.
- No new dependencies (stdlib Python; an existing example target).

## Out of scope

- The ten-category M6 attack suite + exit audit (M6-040); a
  production-side sample (needs a real client flow).
