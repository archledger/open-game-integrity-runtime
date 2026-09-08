# ADR-0042: The pr-set-dumpable backend and the kernel-real bypass test

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M8-046 issue](../../planning/issues/046-kernel-backend.md)
- Supersedes: None
- Superseded by: None

## Context

M8-045 delivered the mechanism-independent seam; the first REAL
kernel mechanism was deliberately deferred. The roadmap's BPF
README requires the property, policy semantics, evidence claim,
noninterference requirement, and bypass corpus to exist
independently of any mechanism - they now do.

## Decision drivers

- The backend must be a seam implementation, not a redesign.
- The bypass test must be KERNEL-REAL (the denial observed live),
  not just the simulation.
- One audited-unsafe posture for the crate (the single-attribute
  rule).

## Options considered

1. **A BPF-LSM program.** The sequencing rule's own example of
   what NOT to do first.
2. **PR_SET_DUMPABLE clearing: the kernel's own same-user
   memory-access gate, zero new privilege, per-process.**
3. **ptrace_scope raising (yama).** System-wide semantics; not
   game-scoped; rejected.

## Decision

Adopt option 2. `ogir_agent::dumpable_backend::DumpableBackend`
implements MemoryAccessControl with mechanism name
`pr-set-dumpable`; the prctl lives in the AUDITED module as the
module's second shim (integer-only arguments; the single
module-level allow attribute still covers everything - the
isolation gate's one-attribute posture holds). The directive is
applied by the protected process itself at spawn (see the exec
discovery); the backend records the target and decides all three
interfaces for non-self actors.

The kernel-real bypass test: a C helper double-forks - the
protected grandchild detaches its stdio, setsids, clears the
dumpable flag, and pauses (NO EXEC); the parent prints the pid and
exits so the OPENER is never an ancestor. Readiness is the
kernel's own observable: /proc/pid/stat becomes root-owned. An
unrelated same-user opener's mem-open is DENIED (the kernel's
EACCES) while an unprotected unrelated process's mem stays
openable in the same run - the bypass and noninterference legs
executed against the real kernel.

THE TWO EMPIRICAL DISCOVERIES (recorded, both forced the test
shape): (1) execve RESETS the dumpable flag to the default for
non-setuid binaries - a helper that clears then execs protects
nothing; the protected process must clear after spawn or never
exec. (2) The kernel's dumpable check EXEMPTS ANCESTORS - the
direct parent can still open the child's mem; the opener must be
an unrelated process for the property to be honestly tested (and
the ancestor exemption is an honest limitation of this mechanism,
disclosed and deferred to the LSM backend).

## Consequences

- The first property is enforced by a REAL kernel mechanism and
  tested against the real kernel, both directions.
- The LSM backend remains future work behind the seam, now with
  its property, corpus, and disclosure already published.

## Threat-model impact

No new privilege (prctl on our own spawned processes); the
enforcement stays game-scoped; the ancestor gap is disclosed.

## Privacy impact

None.

## Dependency and license impact

None.

## Validation

Executed on the dev host: 3/3 kernel suite green (the
kernel-real denial + noninterference, the prctl round-trip smoke,
the seam decisions) plus the M8-045 suites unchanged.

## Rollback

Revert the commit; the backend, audited shim, suite, disclosure,
and audit disappear together.

## Primary sources

- prctl(2): PR_SET_DUMPABLE semantics and the execve reset.
- The executed probes on the dev host (2026-09-08), including the
  ancestor-exemption and exec-reset discoveries.
