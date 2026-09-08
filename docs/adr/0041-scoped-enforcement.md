# ADR-0041: Scoped protected-session enforcement - the first property

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M8-045 issue](../../planning/issues/045-enforcement-seam.md)
- Supersedes: None
- Superseded by: None

## Context

M8 adds ONLY the minimum game-scoped controls for one defined
threat class. The first protected property: an unrelated same-user
process cannot modify the protected game's memory through standard
Linux process-memory interfaces while the ranked session is
active. The active LSM list includes bpf and landlock; the BPF dir
mandates property-first sequencing.

## Decision drivers

- The enforcement interface must be INDEPENDENT of one kernel
  mechanism (an M8 exit criterion).
- Every blocked interface needs a bypass test AND an
  unrelated-process noninterference test (the other exit
  criterion).
- Session-policy activation, immutability, loss events, and
  permit-renewal failure are deliverables around the seam.
- CI cannot exercise kernel LSMs: the design must be testable
  in CI (the policy logic) and executable on the dev host (the
  mechanisms) - the SB-varstore pattern.

## Options considered

1. **A BPF-LSM program first.** The BPF README itself forbids it:
   the property must be defined independently of BPF first.
2. **The mechanism-independent seam + the simulation backend (CI)
   + real backends as their own dev-host slices.**
3. **ptrace-blocking via yama as the only backend.** Mechanism
   lock-in, rejected by the exit criteria.

## Decision

Adopt option 2. `ogir_agent::enforcement`:
- `MemoryInterface` (ptrace, process_vm_writev, proc-mem-write)
  with stable disclosure spellings - the covered interfaces of the
  first property;
- `MemoryAccessControl`: the seam (activate/decide/deactivate +
  a stable mechanism name); NOTHING mechanism-specific leaks;
- `SessionPolicy`: activation composed with the M7 observation;
  IMMUTABLE while active (re-activation and target swaps reject);
  deactivation emits the policy-loss event onto the session's
  stream and closes permit renewal (`renewal_permits()` is false
  after loss);
- `SimulatedBackend`: the property's LOGIC with zero kernel
  dependency (CI); the LSM and ptrace-blocking backends implement
  the same seam as dev-host slices.

The bypass/noninterference suite: every covered interface denies
an unrelated same-user process against the ACTIVE target; the SAME
access against an UNPROTECTED process is OutOfScope - and, executed
on the dev host, an unrelated process's /proc/pid/mem STAYS
openable while protection is active for the game (the innocent
process is deliberately not corrupted; the open proves the OS
permission the policy must not touch). Cleanup restores the
no-claim state.

## Consequences

- The policy layer is mechanism-portable; adding the LSM backend
  is a seam implementation, not a redesign.
- The first property is claimed ONLY through the seam; no
  mechanism claims anything on its own.
- Later experimental controls (debugger attachment, perf/uprobe,
  BPF attachment...) follow the same pattern after their
  properties are defined.

## Threat-model impact

Enforcement is game-scoped: unrelated processes keep every right
(tested). The policy fails closed: a mechanism that cannot engage
blocks session activation, and policy loss closes renewal.

## Privacy impact

None: the seam sees pids and interface enums.

## Dependency and license impact

None (the simulation backend is stdlib; the kernel backends are
their own slices).

## Validation

Executed on the dev host: five enforcement unit tests + three
bypass/noninterference tests green (the property holds in
simulation across all three interfaces; activation is immutable;
policy loss emits the event and closes renewal; inactive policies
claim nothing; the unrelated process's mem stays accessible).

## Rollback

Revert the commit; the seam, policy, simulation backend, and suite
disappear together.

## Primary sources

- The M8 roadmap section (the property verbatim) and the BPF
  README's property-first sequencing rule.
- ADR-0037..0040 (the observation stack the policy composes).
