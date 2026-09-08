# M8-045 plan: the enforcement seam, the first property, the bypass suite

Date: 2026-09-08
Agent: zcode
Authorization: standing authorization EXTENDED through M10; all
gates mandatory.

## Objective

Open M8: the first property behind a mechanism-independent seam
with the full policy semantics and both test kinds.

## Steps

1. Worktree research/m8-entry off 793efcd (the entry scoping
   merged into the slice; the M8 roadmap section IS the scoping -
   one property, no more).
2. enforcement.rs: the seam, the policy, the simulation backend;
   unit tests first.
3. The bypass/noninterference suite incl. the executed mem-open
   leg.
4. ADR-0041, index row, ROADMAP boundary, issue, plan.
5. Gates, commit, publish, CI, merge, verify; dispositions.

## Development notes

- The property is quoted VERBATIM from the roadmap into the
  module docs - the claim must be the roadmap's, not a paraphrase.
- The executed noninterference leg OPENS the innocent process's
  mem but deliberately does not WRITE: corrupting an unrelated
  sleep to prove a point the open already proves is not honest
  testing.

## Boundaries

In: seam + policy + simulation + suite + ADR-0041.
Out: kernel backends (next slices); disclosure doc; audit.
