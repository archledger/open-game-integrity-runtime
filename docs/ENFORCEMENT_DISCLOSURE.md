# Enforcement disclosure (M8)

What OGIR's scoped enforcement does, in plain terms - published as
the roadmap's user-visible policy disclosure.

## The one property enforced

While a ranked (protected) session is active:

> An unrelated same-user process cannot modify the protected
> game's memory through standard Linux process-memory interfaces.

That is ALL M8 enforces. Nothing else is blocked, watched, or
restricted.

## The covered interfaces

- `ptrace` attach (PTRACE_ATTACH / PTRACE_SEIZE and the poke
  family)
- `process_vm_writev`
- writes through `/proc/pid/mem`

## The mechanism (and its honest limits)

The first real backend clears the protected process's
`PR_SET_DUMPABLE` flag (`prctl`), which makes the kernel itself
refuse those interfaces for non-ancestor same-user processes. The
enforcement interface is deliberately mechanism-independent: the
policy layer does not know which kernel mechanism is engaged, and
other backends (LSM-based) can replace it without policy changes.

Limits, stated plainly:

- **Ancestors are exempt.** The kernel's dumpable check allows
  ancestors (your own launcher, the session manager). This is a
  real gap of THIS mechanism; an LSM backend closes it later.
- **A new process cannot be protected after the fact.** The flag
  is set by the process itself at spawn (exec resets it); the
  launcher applies the directive. Existing processes cannot be
  flipped.
- **Self-access is always allowed.** The game writing its own
  memory is out of scope by definition.

## What enforcement does NOT do

- It does NOT touch unrelated processes. Every noninterference
  test proves the same access to unprotected processes keeps
  working. Game-scoped means exactly that.
- It does NOT ban, flag, or report anyone. A denied write is
  simply denied; policy loss closes the session's permit renewal;
  no account action exists anywhere in OGIR.
- It does NOT claim anti-cheat completeness. Debugger
  attachment, perf/uprobe, BPF, and the later experimental
  controls are explicitly future work, each behind its own
  property definition first.

## What users see

- The disclosure spellings `ptrace`, `process_vm_writev`, and
  `proc-mem-write` appear in any policy report (stable names).
- The mechanism name `pr-set-dumpable` identifies the engaged
  backend.
- Policy loss is an event on the session's integrity stream, and
  permit renewal fails closed until re-establishment.
