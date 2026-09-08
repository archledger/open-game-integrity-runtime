# M5-032: Race-resistant caller binding
<!-- labels: type: implementation,area: agent,status: needs-review -->
<!-- milestone: M5 Proton Bridge -->


## Problem

The portal's SO_PEERCRED pid is a racy identity: the process can
exit and the pid can be reused, so the process that connected and
the process a pid names now can differ. The roadmap's step 5 asks
for pidfd/process-start-time binding with process-handle pinning
rather than caller-supplied PID trust.

## What this slice delivers

1. `ogir_agent::binding::CallerBinding` (ADR-0028) - pins the
   process behind kernel-derived credentials: /proc/<pid>/stat
   field 22 (parsed after the LAST ')' - comm may contain spaces)
   plus a pidfd opened at bind time; either failing is
   ProcessGone (fail closed). still_pins() probes the pinned
   process with signal 0; matches() reconciles fresh credentials by
   pid AND start time (a reused pid has a new start time and never
   matches). The fd closes on Drop.
2. The consolidated audited module `ogir_agent::audited`: the
   crate's single gate-enforced #[allow(unsafe_code)] attribute
   moves to the module declaration; one libc call per function with
   an individual written safety argument (getsockopt from ADR-0027;
   pidfd_open, pidfd_send_signal(0), close new).
3. ADR-0028 + index row; ROADMAP M5-032 boundary; this issue; the
   plan doc with the variadic-arity lesson.

## Executed evidence (dev host)

- ogir-agent 27 lib tests green: the live process pins (start time
  non-zero, still_pins true); a process that exited fails to pin
  with ProcessGone; a live child pins, is distinct from its parent,
  and stops pinning after exit; a different process never matches a
  stale pin; malformed stat lines reject.
- The isolation gate PASS with the consolidated single attribute.
- A C and a standalone-Rust probe confirmed the syscall semantics
  before the shim was trusted.

## Security invariants

- Binding input is only kernel-derived credentials; nothing
  caller-supplied influences identity.
- Fail closed on exit, on missing procfs state, and on pidfd
  unavailability.
- No new dependencies; unsafe stays one audited, gate-enforced
  module.

## Out of scope

- Wiring the binding into the portal accept path and the session
  seam (M5-034); the live parent/child race and real PID-reuse
  executions (the M5-035 suite); Windows-side anything (M5-033).
