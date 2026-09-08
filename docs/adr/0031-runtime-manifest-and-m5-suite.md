# ADR-0031: The runtime manifest and the M5 attack suite

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M5-035 issue](../../planning/issues/035-manifest-and-suite.md)
- Supersedes: None
- Superseded by: None

## Context

M5's remaining deliverables are the game/runtime manifest
derivation and the thirteen required attack tests, closing the
milestone with its exit audit. The portal (ADR-0027), binding
(ADR-0028), bridge (ADR-0029), and correlation (ADR-0030) are live
on main; what is missing is the independent WHAT-IS-RUNNING
reference data and the consolidated category inventory.

## Decision drivers

- The manifest must be redacted like correlation (ADR-0030):
  digests and sizes, never paths, arguments, or environment.
- Derivation must require the pin: a dead process has no manifest.
- The suite must be deterministic and self-contained, re-hosting
  legs already executed in focused suites.

## Options considered

1. **Manifest from the bridge's self-report.** Caller-supplied;
   rejected - the bridge is untrusted client code.
2. **Manifest from procfs of the pinned process** (executable
   digest+size, module digests, mount-namespace digest).
3. **Full memory hashing.** Out of scope for M5; recorded as a
   future hardening direction.

## Decision

Adopt option 2. `ogir_agent::manifest::derive` reads the pinned
process's procfs: the executable's SHA-256 and size, bounded
module digests from file-backed executable mappings (max 64,
malformed maps fail closed), and the mount-namespace digest
(the substitution anchor). The manifest is reference data for
later verifier decisions, never authority.

The M5 attack suite (tests/m5_attack_suite.rs) hosts all thirteen
roadmap categories in the M2-019/M3-025/M4-030 pattern: replaced
bridge, copied environment, PID reuse, exit-during-binding, prefix
substitution, mount-namespace substitution (environment-honest:
`unshare -m` without CAP_SYS_ADMIN falls back to anchor-stability),
parent/child distinctness, oversized requests, layout-mismatch
shapes, invalid frames, socket impersonation, request flood, and
the no-privileged-operation-is-expressible proof. The wine-side
legs (oversized WoW64 requests, 32/64 mismatch, replaced DLL under
wine) anchor to their executed dev-host evidence (ADR-0029/0030)
and re-assert at the layer this crate owns.

The M5 exit audit finds criteria 1, 2, and 4 satisfied by executed
work and criterion 3 partial with its remainder recorded (fuzz
targets land with the M6 SDK slice where the C surface
stabilizes).

## Consequences

- M5 closes with the manifest as the last reference-data layer;
  M6's verifier integration consumes bindings, contexts, and
  manifests.
- The suite's environment lessons (the fork-window environ race;
  same-clock-tick start times; EPERM unshare) are recorded in the
  plan for the next environment-sensitive suite.

## Threat-model impact

The manifest adds no caller-controlled input; it reads procfs of
the pinned, same-UID process. Digests cannot leak paths, and the
mount-namespace digest anchors substitution detection.

## Privacy impact

Consistent with ADR-0030: digests and sizes only.

## Dependency and license impact

None beyond M5-034's in-workspace edge.

## Validation

Executed on the dev host: ogir-agent manifest tests green (3),
the thirteen-category suite 13/13 across three consecutive runs
under parallel load (with the retrying correlate for the
fork-window environ race). Full house gates in the slice record.

## Rollback

Revert the commit; the manifest module, suite, and docs disappear
together.

## Primary sources

- procfs(5): /proc/[pid]/exe, /maps, /ns/mnt semantics.
- The executed suite runs (2026-09-08) and the environment
  lessons in the plan doc.
