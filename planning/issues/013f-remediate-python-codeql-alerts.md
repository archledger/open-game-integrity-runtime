# M1-013F: Remediate Python code-scanning alerts on M1-013 scripts
<!-- labels: type: security-hardening,area: model,risk: parser,status: needs-review -->
<!-- milestone: M1 Domain Model -->

Status: Draft for human review and approval; no implementation started.

## Problem

The first CodeQL analysis of the M1-013 Python scripts on `main`, created
2026-09-04T09:00:34Z one minute after PR #28 merged (08:59:32Z), opened four
HIGH-severity code-scanning alerts:

- #45 `py/path-injection` at `scripts/m1_013_plan_registry.py:339`
- #46 `py/path-injection` at `scripts/m1_013_plan_registry.py:343`
- #47 `py/overly-permissive-file` at `scripts/abstract_conformance.py:824-825`
- #48 `py/overly-permissive-file` at
  `scripts/test-abstract-conformance.py:412,421`

All four live in CI and developer conformance-support scripts; none are
production runtime and none implicates an accepted runtime threat. Alerts #47
and #48 are true-positive findings: one literal `0o666` creation mode on the
corpus fixture materializer and one monkeypatch shim whose `mode` parameter
default is the integer literal `0o777` mirroring `os.open`. Alerts #45 and #46
report taint flow from registry-file-derived strings into the hardened
`_read_relative` component walk; the exact CodeQL 2.26.4 barrier model has no
recognized shape for the existing denylist guard, and the analysis in the
approved design proves that no honest restructure of that guard can produce a
modeled barrier without weakening the walk.

Leaving the alerts open breaks the repository's zero-open-alert state, invites
alert migration within the same source-to-sink boundary, and leaves the two
true positives unremediated.

## Security invariants

- Enforce invariant 47: the confirmed #47/#48 defects receive permanent
  regression tests pinning the corrected creation modes.
- Enforce invariant 48: this AI-assisted remediation receives the same source,
  test, review, and DCO scrutiny as production-facing work.
- Preserve the `_read_relative` hardened-reader semantics exactly: segment
  rejection of `""`, `"."`, `".."`, per-component
  `O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC` walking from a dup'd root
  descriptor, final-component regular-file and size checks, and the
  `_stable_metadata` before/after TOCTOU recheck.

## Threats addressed

None. This remediation changes no runtime trust boundary, attacker
capability, protected asset, or protocol response. The scripts are
CI/developer tooling with no network surface.

## Quality failures addressed

- A conformance cache file is created requesting world-readable and
  world-writable permission bits (`0o666`), relying on the process umask for
  restriction.
- A test monkeypatch shim mirrors `os.open`'s default mode with a bare
  integer literal `0o777`, which the scanner correctly observes reaching an
  `os.open` mode parameter.
- Four open alerts on `main` remained untriaged through three subsequent
  merges because post-merge verification checked branch-specific alerts and CI
  conclusions but not the repository-wide open-alert list.
- A scanner finding on an already-hardened reader was initially scoped for a
  guard restructure without first proving the restructure could be recognized;
  the design now records the barrier-model proof and the resulting dismissal
  decision instead.

## In scope

- Change the corpus materialization creation mode in
  `scripts/abstract_conformance.py` from `0o666` to owner-only `0o600`.
- Replace the `replace_before_final_open` shim default
  `mode: int = 0o777` in `scripts/test-abstract-conformance.py` with the
  value-preserving non-literal `stat.S_IMODE(0o777)`, adding the `stat`
  import, and add a value-preservation test proving the default still equals
  `0o777`.
- Add RED-first regression tests: corpus cache files are created with owner
  bits `0o600` only (no group/world bits), and the shim default still mirrors
  `os.open`'s documented default value.
- Dismiss alerts #45 and #46 as false positives with a justification comment
  that references the approved design's barrier-model proof and the hardened
  reader's existing defenses, after the fixes are merged and the fixed alerts
  are confirmed closed by analysis.
- Record the durable prevention rule in `docs/LESSONS_LEARNED.md`: pin the
  CodeQL CLI version and exact query sources before designing a remediation,
  and query the repository-wide open-alert list after every merge.
- Obtain fresh local gates, independent review, DCO certification, PR checks,
  and post-merge repository-wide CodeQL evidence.

## Out of scope

- Any change to `scripts/m1_013_plan_registry.py` bytes, including the
  `_read_relative` walk, its guard, or its flag construction.
- Any production source under `crates/`, Rust behavior, dependencies, or
  protocol semantics.
- CodeQL query packs, model packs, `codeql-models.yml`, default-setup
  configuration files or repository properties, query selection, exclusions,
  or severity changes.
- Directory creation modes in `os.mkdir` calls, which the query does not
  model.
- Dismissing any alert other than #45 and #46.
- Treating these tooling alerts as player cheating or production
  vulnerabilities.

## Trust sources

- The exact CodeQL CLI 2.26.4 sources at tag `codeql-cli/v2.26.4` of
  `github/codeql`: `PathInjection.ql`, `PathInjectionQuery.qll`,
  `PathInjectionCustomizations.qll`, `WeakFilePermissions.ql`,
  `BarrierGuards.qll`, `Stdlib.qll`, and `Concepts.qll`. The CI run for PR
  #32 (`33979868648`) logs `CodeQL CLI version 2.26.4 from toolcache`.
- GitHub code-scanning alert records #45 through #48 and their locations.
- The existing M1-013 test suites (abstract conformance, bounded json,
  planning registry) define the behavior the mode corrections must preserve.

## Required interfaces

- No public API changes. All changes are internal to three Python scripts.
- `_write_history_corpus_document` creates new corpus files with mode
  `0o600`; its existing mismatch-verification read path is unchanged.
- The `replace_before_final_open` shim retains its exact signature and
  forwarded behavior; only the `mode` default expression changes, and its
  evaluated value remains `0o777`.

## Positive tests

- After materialization, `os.stat` on a newly created corpus cache file
  reports permission bits exactly `0o600` (masked with `0o777`).
- The shim's `mode` default evaluates to `0o777`, equal to the documented
  `os.open` default, proving value preservation.
- The full abstract conformance suite (445 tests) and the planning registry
  suite (58 tests) pass unchanged.

## Negative tests

- A corpus file never carries group or world permission bits after creation
  under any umask the test controls.
- The mode corrections do not alter corpus mismatch detection: pre-existing
  identical files are still accepted, and mismatched files still raise
  `_TransformError`.
- The shim still rejects replacement attacks exactly as before; only the
  default-mode expression differs.

## Fuzz/property tests

No parser or untrusted byte surface is added. The existing finite conformance
domains remain the appropriate proof; no fuzz target is added.

## Privacy impact

No claim, identifier, log field, or diagnostic changes. Corpus fixture bytes
remain synthetic test data.

## Dependency impact

No dependency, feature, license boundary, workflow permission, or action pin
changes. The corrections use the Python standard library (`stat.S_IMODE`,
integer literals).

## Acceptance criteria

- Alerts #47 and #48 are fixed by new analysis on the remediation PR head
  (fixed, not dismissed), verified by branch-level code-scanning results.
- Alerts #45 and #46 are dismissed exactly once each with reason
  `false_positive` and a justification comment referencing the approved
  design and the hardened reader's defenses, after the code fixes merge.
- The repository-wide open-alert list is empty after post-merge analysis.
- `scripts/m1_013_plan_registry.py` bytes are identical before and after the
  change.
- `./scripts/check.sh`, the abstract conformance, planning registry, bounded
  json, and remaining Python suites pass.
- Fresh independent review reports no unresolved Critical, Important, or
  Minor finding.
- Every published commit carries the exact human-certified DCO trailer.
- `docs/LESSONS_LEARNED.md` records the prevention rule.

## Primary sources

- `py/path-injection` query at the CI version:
  https://github.com/github/codeql/blob/codeql-cli/v2.26.4/python/ql/src/Security/CWE-022/PathInjection.ql
- `py/overly-permissive-file` query at the CI version:
  https://github.com/github/codeql/blob/codeql-cli/v2.26.4/python/ql/src/Security/CWE-732/WeakFilePermissions.ql
- Barrier guard model at the CI version:
  https://github.com/github/codeql/blob/codeql-cli/v2.26.4/python/ql/lib/semmle/python/dataflow/new/BarrierGuards.qll
- Stdlib path models at the CI version:
  https://github.com/github/codeql/blob/codeql-cli/v2.26.4/python/ql/lib/semmle/python/frameworks/Stdlib.qll
- Alerts:
  https://github.com/archledger/open-game-integrity-runtime/security/code-scanning/45
  https://github.com/archledger/open-game-integrity-runtime/security/code-scanning/46
  https://github.com/archledger/open-game-integrity-runtime/security/code-scanning/47
  https://github.com/archledger/open-game-integrity-runtime/security/code-scanning/48
