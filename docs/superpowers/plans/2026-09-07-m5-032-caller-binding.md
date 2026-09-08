# M5-032 plan: race-resistant caller binding

Date: 2026-09-07
Agent: zcode
Authorization: standing publication+merge authorization; all gates
mandatory.

## Objective

Deliver roadmap step 5: turn the portal's kernel-derived peer
credentials into a binding that survives PID reuse and detects
process exit, by pairing the procfs start time with a pidfd pin.

## Steps

1. Worktree research/m5-032-caller-binding from d9a1c33.
2. Consolidate the audited shims first (ADR-0027's getsockopt plus
   the new pidfd calls) into ogir_agent::audited under the single
   gate-enforced module-level allow attribute; the isolation gate
   still counts exactly one.
3. binding.rs: pin/still_pins/matches with fail-closed errors; the
   stat parser reads after the LAST ')' (comm may contain spaces).
4. Tests: live pin, dead-pin failure, child lifecycle, stale-pin
   mismatch, malformed stat.
5. ADR-0028, index row, ROADMAP boundary, planning issue, this
   plan.
6. House gates, signed commit, publication, CI, merge under the
   standing authorization (REST PUT if the CLI pre-flight balks),
   post-merge verification.

## Development notes

- pidfd_send_signal takes FOUR arguments (pidfd, sig, info, flags):
  a variadic syscall call must materialize every argument the
  syscall reads; a short call left garbage in flags and the probe
  failed for LIVE processes. Confirmed against C and standalone
  Rust probes before blaming the shim.
- pidfd_open/pidfd_send_signal have no glibc wrappers: raw
  syscall() via a local variadic extern; x86_64 numbers 434/424.
- edition-2024 requires `unsafe extern "C"` for declarations that
  will be called from unsafe code.
- The audited attribute belongs on the `mod audited;` DECLARATION in
  lib.rs: one occurrence of the attribute string in the crate, as
  the gate counts, and the module's doc carries the invariant.

## Boundaries

In: audited module consolidation, CallerBinding, tests, docs.
Out: portal-accept wiring (M5-034), live race executions (M5-035),
Windows side (M5-033).
