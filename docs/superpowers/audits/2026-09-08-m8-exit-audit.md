# M8 exit audit: scoped protected-session enforcement

Date: 2026-09-08
Agent: zcode

## Criterion: every blocked interface has a bypass test and an
unrelated-process noninterference test

SATISFIED. All three covered interfaces (ptrace,
process_vm_writev, /proc/pid/mem write) are denied at the seam
against the ACTIVE target (the M8-045 suite), and the
kernel-mechanism suite (M8-046) executes the REAL denial: a
non-dumpable, ancestor-free protected process refuses a same-user
unrelated process's /proc/pid/mem open (the kernel's own EACCES,
observed live), while an unrelated UNPROTECTED process's mem stays
openable in the same test run. The empirical discoveries are
recorded: execve resets the dumpable flag (the protected process
must set it after spawn or never exec), and the kernel exempts
ancestors from the dumpable check (an honest limitation of the
first mechanism, disclosed and deferred to the LSM backend).

## Deliverables coverage

| Deliverable | Status |
| --- | --- |
| Enforcement interface independent of one kernel mechanism | M8-045, merged (the seam) |
| LSM-based controls for the first property | First real backend = pr-set-dumpable (M8-046); the LSM backend is recorded future work - the property, policy semantics, and bypass corpus now exist independently (the BPF-README sequencing rule satisfied) |
| Tests covering equivalent memory-access paths | M8-045 + M8-046 suites |
| Session-policy activation and immutability | M8-045, merged |
| Policy-loss event and permit-renewal failure | M8-045, merged |
| Cleanup and noninterference tests | M8-045 (cleanup restores no-claim) + M8-046 (kernel-real noninterference) |
| User-visible policy disclosure | docs/ENFORCEMENT_DISCLOSURE.md |

## Verdict

The exit criterion is satisfied for the first property. M8 closes
with the LSM backend and the later experimental controls recorded
as future work behind the same seam - by the roadmap's own
sequencing rule (property first, mechanism second). M0-M8 closed.
