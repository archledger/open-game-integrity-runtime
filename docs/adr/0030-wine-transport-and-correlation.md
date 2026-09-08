# ADR-0030: The wine/Proton transport and redacted correlation

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M5-034 issue](../../planning/issues/034-transport.md)
- Supersedes: None
- Superseded by: None

## Context

M5-033 proved the bridge on the development host under Fedora's
wine-11.0 (Staging, wow64 build). The roadmap's transport
deliverable asks for a sample Windows console client running under
STOCK PROTON, and the wine server/prefix/process-tree/cgroup
correlation. The user designated archhost - a second machine with
Steam, GE-Proton10-30/34, and system wine 11.17 - as a required
test target.

## Decision drivers

- The bridge must load under MAINLINE wine and REAL Proton, not
  only the development host's Staging build.
- Correlation must be REDACTED by construction: structural facts
  and digests, never environment values, command lines, or paths.
- No new dependencies; CI validates committed evidence (cross-host
  boots stay dev-host gates on both machines).

## Options considered

1. **Replicate the Staging recipe (app-dir PE + install-dir .so,
   unforced) on mainline.** Rejected by execution: mainline
   wine 11.17 loads the app-dir native PE first and never runs the
   builtin phase, so no unixlib attaches; the app-dir .so import
   resolution also fails there.
2. **System-wide PE installation.** Works but needs root and
   touches every prefix.
3. **Per-prefix deployment: the PE into the WINEPREFIX's
   drive_c/windows/system32 + the unixlib into the installation's
   machine-unix directory.** Works on mainline AND under Proton
   (the compat prefix is a wineprefix), needs no system PE, and
   matches how a launcher would provision a game's prefix.

## Decision

Adopt option 3 for mainline wine and Proton (the Staging recipe
from ADR-0029 remains valid where it was proven). Under GE-Proton
the unixlib installs into the Proton build's own
files/lib/wine/x86_64-unix directory and the PE into the
STEAM_COMPAT_DATA_PATH prefix; the headless invocation is
`proton run` with STEAM_COMPAT_DATA_PATH and
STEAM_COMPAT_CLIENT_INSTALL_PATH set.

`ogir_agent::correlation` derives the redacted wine context of a
PINNED caller: WINEPREFIX presence, SHA-256 DIGESTS of the
WINEPREFIX and loader variable values (never the values), the
bounded process-tree depth (ppid chain, structure only), and the
cgroup controller list plus path digest. The record requires a
live pin - a dead process cannot be correlated because it cannot
even be pinned. The development portal host demonstrates the
redacted tracing (digest prefixes, structural counts).

`proton/ogir-client/build.sh` is now self-contained (generates the
ntdll dispatch import libraries for both architectures before the
PE builds, and builds the 64-bit PE itself); the structural build
gate re-verifies.

## Consequences

- Deployment recipes are recorded for THREE environments (Staging
  app-dir, mainline per-prefix, Proton compat-prefix) - all
  executed green.
- The correlation digests are stable per prefix: two deployments
  are distinguishable without learning anything about the user's
  paths.
- The wow64 leg remains fail-closed (ADR-0029).

## Threat-model impact

Correlation reads procfs of the PINNED process only (same UID); it
adds no caller-controlled input. Redaction is structural: the
correlation record cannot leak paths, arguments, or environment
values even into logs.

## Privacy impact

Positive by construction: what would be identifying (prefix paths)
is reduced to digests before it exists as data.

## Dependency and license impact

ogir-agent gains an in-workspace production edge on ogir-attest
(the existing SHA-256); the signed external inventory is unchanged.

## Validation

Executed on BOTH hosts (evidence in task-18-scoping/m5-034/):
development host - the live bridge with the traced portal
(13/13, prefix digest, ancestry 7); archhost system wine 11.17 -
13/13 PASS with the correlated round (prefix digest, ancestry 4);
archhost GE-Proton10-34 - exit 0 (the harness exits with its
failure count) with a SECOND correlated round under a DIFFERENT
prefix digest and loader set, demonstrating deployment
distinguishability. ogir-agent 31 tests green (4 correlation).
Full house gates in the slice record.

## Rollback

Revert the commit; the correlation module, tracing, and build
script fixes disappear together. The archhost staging (~/ogir-m5-034,
the two prefixes, the installed .so copies) is dev-host state.

## Primary sources

- The executed cross-host runs (2026-09-08): the archhost evidence
  logs and the runner scripts committed to the scoping record.
- ADR-0029 (the bridge and the Staging loader map), ADR-0028 (the
  pin correlation requires).
