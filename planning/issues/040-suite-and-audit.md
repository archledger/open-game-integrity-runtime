# M6-040: The attack suite and the M6 exit audit
<!-- labels: type: test,area: verifier,area: attack-lab,status: needs-review -->
<!-- milestone: M6 Publisher SDK and Verifier -->


## Problem

M6's ten required attack tests close the milestone alongside its
exit audit; five categories were already hosted in focused suites
and need consolidation into the house inventory.

## What this slice delivers

1. The ten-category suite (ADR-0036) over REAL TCP against the
   production shell with the developer-mode backend: unsigned
   evidence never admits; wrong expected context denies; the
   stale-key shape (corrupted signature) rejects; revoked permits
   never reanimate; parser confusion denies Malformed;
   permit-only renewal denies; time skew denies NotYetValid;
   duplicates never re-admit; outage is retryable-never-punitive;
   unsupported is never deny (wire + type levels) - plus a
   compile-time service-trait completeness check.
2. The M6 exit audit: all three criteria satisfied by executed
   work, honest limitations recorded.
3. ADR-0036 + index row; the ROADMAP M6-040 boundary declaring M6
   COMPLETE; this issue; the plan.

## Executed evidence (dev host)

- The suite: 11/11 green across three consecutive runs.

## Security invariants

- Every category lands a deterministic non-allow or a
  deterministic impossibility assertion.
- No new dependencies.

## Out of scope

- M7+ (protected-session observation onward); the production-side
  end-to-end (the real-chain backend composes later).
