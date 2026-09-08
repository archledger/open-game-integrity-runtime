# ADR-0028: Race-resistant caller binding with pidfd and process start time

- Status: Accepted
- Date: 2026-09-07
- Owners: Initial maintainer
- Related issues: [Local M5-032 issue](../../planning/issues/032-caller-binding.md)
- Supersedes: None
- Superseded by: None

## Context

M5-031 delivered the portal with kernel-derived peer credentials
(SO_PEERCRED), but a pid alone is a racy identity: the process can
exit and the pid can be reused, so "the process that connected" and
"the process a pid names now" can differ. The roadmap's
implementation order step 5 is exactly this: pidfd/process-start-
time binding, with "process-handle passing rather than
caller-supplied PID trust" as the deliverable and PID reuse,
process-exits-during-binding, and parent/child races as attack
categories.

## Decision drivers

- A binding must fail closed when the process is gone (never bind a
  corpse, never bind whoever reused the pid).
- No new dependencies; the audited-unsafe posture stays minimal and
  gate-enforced (ADR-0027's form).
- Deterministic, non-disciplinary errors.

## Options considered

1. **Start time only** (read /proc/<pid>/stat field 22 at accept;
   compare later). Leaves a read-read TOCTOU window between the two
   procfs reads during which a reused pid with a different start
   time could appear "matching" only if the times collide (they do
   not collide across reboots-in-a-boot, but the check remains
   two-observation rather than pinned).
2. **pidfd only** (pin the process with pidfd_open at bind time;
   probe with pidfd_send_signal(0)). The fd refers to exactly the
   pinned process forever; a reused pid is unreachable through it.
   But a bare fd gives no inspectable identity for correlation.
3. **Both**: start time for identity/correlation, pidfd for the
   pin. The pidfd makes the liveness question exact; the start time
   lets fresh credential reads be reconciled against an old pin.

## Decision

Adopt option 3. `ogir_agent::binding::CallerBinding` pins the
process behind portal-observed credentials by reading
/proc/<pid>/stat field 22 (parsed after the LAST ')' because the
comm field may contain spaces) and opening a pidfd; either read
failing means the process is gone and the binding fails closed
(BindingError::ProcessGone - the exit-during-binding category).
`still_pins()` probes the pidfd with signal 0 (exact liveness for
the pinned process); `matches()` reconciles fresh credentials by
pid AND start time (the PID-reuse defense: a reused pid has a new
start time and never matches). The fd is closed on Drop.

The audited surface consolidates: the crate's single gate-enforced
`#[allow(unsafe_code)]` attribute now sits on the `mod audited`
declaration in lib.rs, housing one libc call per function with an
individual written safety argument - getsockopt (ADR-0027) plus
pidfd_open, pidfd_send_signal(0), and close (ADR-0028). The
isolation gate still counts exactly one attribute.

## Consequences

- The portal's accept path can now hand session code a pinned
  caller instead of a bare pid (M5-034 wires them together).
- The audited module is the crate's entire unsafe surface; any
  addition needs its own ADR and a gate change.
- pidfd requires Linux 5.3+ (the M5 platform is 7.x); the x86_64
  syscall numbers are local constants (434/424).

## Threat-model impact

PID reuse, exit-during-binding, and stale-credential races now fail
closed into named errors. Nothing new trusts caller-supplied data:
binding input is the kernel-derived PeerCredentials.

## Privacy impact

None: the binding reads process metadata (pid, start time) that the
portal already lawfully observes for its own caller; nothing is
logged.

## Dependency and license impact

None.

## Validation

Executed on the dev host: ogir-agent 27 lib tests green including
the new binding tests (pin of the live current process; a dead
process fails to pin; a live child pins, differs from its parent,
and stops pinning after exit; a different process never matches a
stale pin; malformed stat lines reject). The isolation gate PASS
with the consolidated single attribute. Full house gates in the
slice record. Development lesson: pidfd_send_signal takes FOUR
arguments - a variadic syscall call must materialize every argument
the syscall reads, or the garbage flags argument fails the probe.

## Rollback

Revert the commit; the binding module, the consolidated audited
module, and the docs disappear together (portal.rs returns to its
own single-function shim shape).

## Primary sources

- procfs(5): /proc/[pid]/stat field 22 is starttime in clock ticks.
- pidfd_open(2) and pidfd_send_signal(2): semantics of pinned
  process handles and signal-0 liveness probes.
- ADR-0027 (the audited-shim posture this decision consolidates).
