# M8-046 plan: the kernel backend, the kernel-real test, the disclosure, the audit

Date: 2026-09-08
Agent: zcode
Authorization: standing authorization extended through M10.

## Development notes

- execve RESETS PR_SET_DUMPABLE for non-setuid binaries: the
  protected process must clear the flag AFTER spawn or never
  exec - the helper IS the protected process.
- The kernel's dumpable check exempts ANCESTORS: the direct
  parent can still open the child's mem; the opener must be an
  unrelated process (the double-fork + separate-opener shape).
- /proc/pid/stat turning root-owned is the readiness observable
  (CoreDumping is NOT the dumpable flag).
- Command::output() waits for EOF on the inherited pipe: the
  grandchild must detach its stdio or the parent's exit never
  surfaces.

## Boundaries

In: backend + audited shim + kernel suite + disclosure + audit.
Out: LSM backend; M9+.
