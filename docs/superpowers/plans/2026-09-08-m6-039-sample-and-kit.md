# M6-039 plan: the sample backend, the conformance kit, and the no-ban documentation

Date: 2026-09-08
Agent: zcode
Authorization: standing publication+merge authorization; all gates
mandatory.

## Objective

Deliver the integration deliverables: the publisher kit, the
five-step sample, and the no-ban contract.

## Steps

1. Worktree research/m6-039-sample-and-kit from 9978ad6.
2. The kit first (the contract to demo), then the sample backend,
   then the documentation; CI gets the kit self-test.
3. Execute both against the running daemon.
4. ADR-0035, index row, ROADMAP boundary, planning issue, plan.
5. House gates, signed commit, publication, CI, merge,
   post-merge verification.

## Development notes

- The oversized-body refusal arrives as ConnectionReset (the
  server closes mid-body): the kit TOLERATES the reset as the
  expected refusal shape and asserts no-200.
- The harness reaps backgrounded daemons between shell calls: the
  daemon, the kit, and the sample must run in ONE invocation.
- The sample maps verdict families to gameplay states explicitly -
  the policy table is the point of the demo, not scaffolding.

## Boundaries

In: kit + CI wiring, sample backend, CASUAL_FALLBACK.md,
ADR-0035, docs.
Out: the ten-category suite + exit audit (M6-040); production-side
sample.
