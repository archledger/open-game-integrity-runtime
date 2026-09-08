# M5-034: The wine/Proton transport and redacted correlation
<!-- labels: type: implementation,area: proton-bridge,area: privacy,status: needs-review -->
<!-- milestone: M5 Proton Bridge -->


## Problem

M5-033 proved the bridge on the development host's Staging wine
only. The roadmap's transport deliverable requires a sample Windows
console client under STOCK PROTON and the wine server/prefix/
process-tree/cgroup correlation; the user designated archhost
(Steam + GE-Proton10-34 + system wine 11.17) as a required second
test machine.

## What this slice delivers

1. The EXECUTED cross-host transport (ADR-0030): system wine 11.17
   mainline on archhost - 13/13 harness PASS with the portal
   pinning the caller (the per-prefix recipe: PE in the WINEPREFIX
   system32 + unixlib in the machine-unix directory; the Staging
   app-dir recipe does NOT attach on mainline - recorded); REAL
   GE-Proton10-34 via headless `proton run` (exit 0, a second
   pinned connection; unixlib in the Proton build's wine tree, PE
   in the compat prefix).
2. `ogir_agent::correlation` - the REDACTED wine context of a
   PINNED caller: WINEPREFIX presence, SHA-256 digests of the
   prefix and loader VALUES (never the values), bounded ancestry
   depth (ppid chain, structure only), cgroup controllers and path
   digest. A dead process cannot be correlated because it cannot
   be pinned.
3. Redacted tracing demonstrated by the development portal host
   (digest prefixes and structural counts only).
4. `proton/ogir-client/build.sh` made self-contained (generates
   the dispatch import libraries; builds the 64-bit PE).
5. ADR-0030 + index row; ROADMAP boundary; this issue; the plan
   doc; the cross-host runner scripts and evidence in the scoping
   record.

## Executed evidence (both hosts; task-18-scoping/m5-034/)

- Development host: live bridge 13/13 with the traced portal
  (prefix digest, ancestry 7).
- archhost system wine 11.17: 13/13 PASS, correlated round
  (prefix digest db2ea5fe..., ancestry 4).
- archhost GE-Proton10-34: exit 0 (the harness exits with its
  failure count), a SECOND correlated round under a DIFFERENT
  prefix digest (40e21e6a..., 2 loader vars) - the two deployments
  are distinguishable without learning the user's paths.
- ogir-agent 31 tests green (4 correlation).

## Security invariants

- Correlation reads procfs of the pinned, same-UID process only;
  no caller-controlled input; redaction is structural.
- No new external dependencies (one in-workspace production edge
  on the existing SHA-256).
- The wow64 leg remains fail-closed (ADR-0029).

## Out of scope

- The game/runtime manifest derivation and the thirteen-category
  attack suite with the M5 exit audit (M5-035).
