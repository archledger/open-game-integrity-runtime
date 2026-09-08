# ADR-0037: The observation core

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M7-041 issue](../../planning/issues/041-observation-core.md)
- Supersedes: None
- Superseded by: None

## Context

M7 binds attestation to the live game process tree before any
enforcement (M8). The M5 chain (pin, correlation, manifest) is the
substrate but no composed observation record, session identity, or
state digest exists.

## Decision drivers

- NONINTERFERENCE IS STRUCTURAL (an M7 exit criterion): only the
  pinned process's procfs is read; the tree is walked upward from
  the pin, bounded; nothing is enumerated globally.
- Every field that could cross a trust boundary is a digest, a
  pid, or a start time.
- Drift detection needs one comparable value over everything
  observed.
- M7 makes NO enforcement claim.

## Options considered

1. **Persist observation state for agent-restart continuity.**
   Conflicts with the ADR-0022 fail-closed posture; rejected for
   the core (restart semantics land in the lifecycle slice).
2. **A composed record with derived identity + state digest,
   refreshed by re-observation.**
3. **A kernel-level watcher (proc connectors / eBPF).** A new
   privileged surface and dependency; far beyond the observation
   need.

## Decision

Adopt option 2. `ogir_agent::observation` composes the pin
(ADR-0028), correlation (ADR-0030), and manifest (ADR-0031) into
`ObservedSession`:
- `ObservedTree`: the bounded upward walk (pid + start time per
  hop, max 64; the pinned node first);
- `SessionIdentity`: SHA-256 over the cgroup-path digest + pid +
  start time - stable while the process lives, never reused after
  a restart;
- `StateDigest`: SHA-256 over everything observed in a fixed
  order, with module digests ORDER-INDEPENDENT (the maps order
  shifts during execution; the SET of loaded components is the
  observed fact) - a change means the observed world changed and
  renewal must re-verify;
- `RedactedObservation`: the trust-boundary view - digests, pids,
  start times, structural counts only;
- `observe()` (pin + compose), `observe_pinned()` (the refresh
  path), `refresh()` (identity-checked: a restarted same-pid
  process is a DIFFERENT session), and `same_state()` (the drift
  check).

Two production fixes landed from the stability chase: manifest
module reads retry a bounded budget (a transient read failure of a
live process's mapped file under parallel load must not become
false drift), and the state material sorts module digests
(maps-order independence).

## Consequences

- The M7 lifecycle (next slice) composes this record; the event
  stream and renewal invalidation build on StateDigest.
- A mid-exec observation is genuinely unstable (the loader maps
  libc after exe changes) - consumers observe after settle; the
  test helper demonstrates the contract.

## Threat-model impact

No new privilege: everything reads procfs of the pinned, same-UID
process. Noninterference is structural - no global enumeration
exists in the code path at all.

## Privacy impact

The redacted view cannot carry paths, names, or environment values
by construction (the type has no fields for them).

## Dependency and license impact

None.

## Validation

Executed on the dev host: nine observation tests green across
FIFTEEN consecutive parallel runs (the stability bar after the
chase): current-process observation, child-as-own-session,
dead-process ProcessGone, drift-after-exit, distinct identities,
the redacted-view shape, the bounded walk, the retry budget unit
check, and the quiet-stability contract. Full house gates in the
slice record.

## Rollback

Revert the commit; the module and its manifest fixes disappear
together.

## Primary sources

- ADR-0028/0030/0031 (the composed chain) and the executed
  stability runs (2026-09-08), including the mid-exec maps
  finding (exe changes at exec; libc maps moments later).
