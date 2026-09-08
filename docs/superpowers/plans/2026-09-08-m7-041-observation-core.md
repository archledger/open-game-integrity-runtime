# M7-041 plan: the observation core

Date: 2026-09-08
Agent: zcode
Authorization: standing publication+merge authorization; all gates
mandatory.

## Objective

Open M7: one composed observation record over the M5 chain with a
stable identity and a drift-detectable state digest.

## Steps

1. Worktree research/m7-entry off 650374d (the entry-scoping
   worktree promoted to the slice).
2. observation.rs: the tree walk, identity, state digest, redacted
   view, observe/refresh/same_state; negative tests first.
3. The stability chase: module-order independence, read retries,
   and the mid-exec settle contract.
4. ADR-0037, index row, ROADMAP boundary, planning issue, plan.
5. House gates, signed commit, publication, CI, merge,
   post-merge verification.

## Development notes (all empirically forced)

- The MAPS ORDER of a live process shifts as mappings come and go:
  the state material must sort module digests (the SET is the
  observed fact).
- A transient read failure of a live process's mapped file under
  parallel load produces FALSE drift: manifest reads retry a
  bounded budget (10 x 10ms) before skipping.
- THE MID-EXEC WINDOW: /proc/pid/exe changes at exec, but the
  dynamic loader maps libc a moment LATER - an observation in that
  window is genuinely unstable (module count 2 vs 3). Observers
  settle first; the test helper waits for the file-backed
  executable mapping count to stabilize across two reads 30ms
  apart. Error capture proved the reads never failed - the maps
  content itself was mid-exec.
- std TcpListener (used later): local_addr, and accept() returns a
  tuple. Deleting a duplicated test by brace-matching can eat a
  neighboring body - diff after any scripted deletion.
- The stability bar for environment-sensitive suites: FIFTEEN
  consecutive parallel runs.

## Boundaries

In: observation module + manifest fixes, ADR-0037, docs.
Out: lifecycle (M7-042), stream (M7-043), suite + audit (M7-044);
persisted observation state (rejected).
