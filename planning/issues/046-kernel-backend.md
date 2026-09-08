# M8-046: The pr-set-dumpable backend, the kernel-real test, the disclosure, and the M8 exit audit
<!-- labels: type: implementation,area: agent,status: needs-review -->
<!-- milestone: M8 Scoped Enforcement -->


## Problem

M8-045 delivered the seam; the first REAL kernel mechanism, the
kernel-real bypass test, the user-visible disclosure, and the exit
audit remain.

## What this slice delivers

1. `DumpableBackend` (ADR-0042): the prctl in the audited module
   (its second integer-only shim); the seam implementation for all
   three interfaces.
2. The KERNEL-REAL bypass test: the double-forked ancestor-free
   protected process (the execve-reset discovery), readiness via
   the root-owned /proc/pid/stat observable, the live EACCES
   denial, and the noninterference leg in the same run.
3. docs/ENFORCEMENT_DISCLOSURE.md (the one property, the covered
   spellings, the mechanism and its honest limits, the
   never-list).
4. The M8 exit audit (the bypass/noninterference criterion
   satisfied; the ancestor exemption disclosed and deferred to the
   LSM backend).

## Executed evidence (dev host)

- 3/3 kernel suite green + the M8-045 suites unchanged.

## Security invariants

- No new privilege; game-scoped only; the ancestor gap disclosed.

## Out of scope

- The LSM backend and the later experimental controls (future work
  behind the seam, per the sequencing rule); M9+.
