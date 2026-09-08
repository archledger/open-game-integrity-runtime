# M5-035 plan: the runtime manifest, the attack suite, and the M5 exit audit

Date: 2026-09-08
Agent: zcode
Authorization: standing publication+merge authorization; all gates
mandatory.

## Objective

Close Milestone M5: the game/runtime manifest derivation, the
thirteen-category attack suite, and the exit audit.

## Steps

1. Worktree research/m5-035-manifest-and-attack-suite from be6ebaa1.
2. manifest.rs: procfs-derived digests requiring the pin; tests.
3. The thirteen-category suite re-hosting executed legs; iterate
   until deterministic under parallel load.
4. ADR-0031, index row, the M5-closing ROADMAP boundary, the exit
   audit, planning issue, this plan.
5. House gates, signed commit, publication, CI, merge, post-merge
   verification.

## Development notes (environment lessons, all empirically forced)

- The fork-window race: reading a freshly spawned child's
  /proc/pid/environ can serve stale or empty content for ~100-200ms
  AFTER the exe link already shows the new binary. The suite's
  settle helper requires BOTH the expected exe AND an environ
  containing the test marker, and the correlation tests retry
  bounded (~1s). Production correlates long-lived processes.
- Kernel start times have clock granularity: two children spawned
  in the same tick share a start time - pid is the distinguisher;
  never assert start-time inequality for near-simultaneous spawns.
- `unshare -m` without CAP_SYS_ADMIN spawns and then dies
  instantly (EPERM): settle would panic "never exec'd" - the
  environment-honest branch detects the early exit and asserts the
  anchor's stability instead, recording the limitation.
- A probe of kind 'H' with any version is a VALID Hello by design;
  the no-privileged-operation proof must probe non-H kinds.
- Parallel test runs surface all of the above; run new
  environment-sensitive suites three times before trusting green.

## Boundaries

In: manifest module + tests, the suite, exit audit, ADR-0031,
docs.
Out: fuzz/sanitizer targets (M6, recorded), wow64 transport, permit
issuance (M6).
