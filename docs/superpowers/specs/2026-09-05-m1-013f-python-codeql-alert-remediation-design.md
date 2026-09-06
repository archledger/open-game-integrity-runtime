# M1-013F design: Python code-scanning alert remediation

- Date: 2026-09-05
- Status: Draft for human review and approval
- Issue: `planning/issues/013f-remediate-python-codeql-alerts.md`
- Base: merged `main` `6154ac58c10fe8a830e2db09944fae06e20387d1`
- Branch: `fix/m1-013f-python-codeql-alerts` (worktree
  `ogir/open-game-integrity-runtime-m1-013f`)

## 1. Context and scope

Four HIGH code-scanning alerts opened 2026-09-04T09:00:34Z, one minute after
PR #28 merged the M1-013 Python scripts. The CI uses CodeQL CLI 2.26.4 from
toolcache (PR #32 run `33979868648` log). All query citations below are pinned
to tag `codeql-cli/v2.26.4`; the four path-injection files are byte-identical
to `main` (verified by diff), and `BarrierGuards.qll`, `Stdlib.qll`, and
`Concepts.qll` were fetched at the tag.

This design covers two code corrections (#47, #48) and two evidence-backed
dismissals (#45, #46). It revises the scoping recommendation: the originally
proposed guard restructure for #45/#46 is proven nonviable in section 3.

## 2. Exact query semantics at CodeQL 2.26.4

### 2.1 `py/overly-permissive-file` (`WeakFilePermissions.ql`)

- Modeled calls: `os.chmod(path, mode)` and `os.open(path, flags, mode)`.
- The flagged `mode` value must reach the call parameter as an
  `IntegerLiteral` expression:
  `call.getParameter(2,"mode").getAValueReachingSink().asExpr().(IntegerLiteral)`.
- Permission arithmetic: world bits are `p % 8`; world access is
  `writable` when `p % 4 >= 2`, `readable` when `p % 4 < 2 and p != 0`. An
  alert fires when world bits are nonzero, or when world bits are zero and
  group bits `(p / 8) % 8` are nonzero.
- Consequences: `0o777` (world 7) and `0o666` (world 6) are flagged;
  `0o600` (world 0, group 0) is not flagged. A mode whose reaching
  expression is a function call or binary operation is not an
  `IntegerLiteral` and cannot alert, regardless of value.

### 2.2 `py/path-injection` (`PathInjection.ql` + `PathInjectionQuery.qll`)

- Global taint tracking with a two-state model: `NotNormalized` and
  `NormalizedUnchecked`. Sources are `ActiveThreatModelSource` instances
  (file content and command-line arguments qualify). Sinks are
  `FileSystemAccess` vulnerable path arguments, including `os.open` path
  arguments. Sinks accept both states, so normalization alone never stops a
  flow.
- Flow stops only at:
  1. a stateless `Sanitizer`: `ConstCompareAsSanitizerGuard` in
     `PathInjectionCustomizations.qll`, or
  2. a `Path::PathNormalization` node in `NotNormalized` state, which
     restarts flow from its argument in `NormalizedUnchecked`, followed by a
     `Path::SafeAccessCheck` in `NormalizedUnchecked`, or
  3. a models-as-data barrier, which this repository does not use.

### 2.3 Barrier inventories (`BarrierGuards.qll`, `Stdlib.qll`)

- `ConstCompareBarrier` (`BarrierGuards.qll` lines 6-45): for
  `node == CONST` / `node is CONST` / `node in (CONSTS)` the barrier applies
  on the `true` branch; for `node != CONST` / `node is not CONST` /
  `node not in (CONSTS)` the barrier applies on the `false` branch. In every
  case the barrier applies only on paths where the node equals one of the
  constants. A denylist that rejects matches and continues on non-matches
  can never produce this barrier.
- `Path::PathNormalization::Range` implementations in `Stdlib.qll`:
  exactly `os.path.normpath`, `os.path.abspath`, and `os.path.realpath`.
- `Path::SafeAccessCheck::Range` implementations in `Stdlib.qll`: exactly
  one, `StartswithCall` (`str.startswith(prefix)` with `branch = true`).

## 3. Alerts #45/#46: dismissal decision with proof

### 3.1 What is flagged

`_read_relative(root_fd, relative)` at `scripts/m1_013_plan_registry.py:329`
walks `relative.split("/")` components with `os.open(part, flags,
dir_fd=...)` (lines 339 and 343). Taint sources include registry JSON
content (for example `authority["path"]` at line 1830) and command-line
derived basenames (line 2043), both threat-model sources.

### 3.2 Existing defenses

The function already implements defense in depth: rejection of segments
equal to `""`, `"."`, or `".."` (line 331); per-component opens with
`O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC` anchored at a dup'd root descriptor;
a final-component `O_NOFOLLOW` open restricted to regular files with a size
cap and bounded read; and a `_stable_metadata` before/after equality check
(lines 348-369) that detects concurrent replacement. The alerts are
false positives in effect: the flagged walk is itself the traversal defense.

### 3.3 Why no honest code fix exists

1. Denylist guards cannot barrier (section 2.3, case analysis): the use path
   is exactly the non-matching branch.
2. The recognized safe shape is `normalized = os.path.normpath(x)` followed
   by an affirmative `normalized.startswith(prefix)` guard, with all walked
   segments derived from `normalized`. An affirmative anchor must be
   semantically meaningful, not vacuous:
   - A single constant prefix does not exist across the call-site domain
     (constant registry paths, CLI-supplied basenames, registry-data
     authority paths, scenario basenames).
   - An anchor derived from the checked value itself (for example
     `normalized.startswith(normalized.split("/")[0] + "/")`) is always
     true; that is a deceptive barrier and is rejected.
   - Full-value constant membership (`relative in {literals}`) works only
     for the constant-derived flows; registry-data paths cannot be literal
     sets.
3. Replacing the per-component walk with a single `os.open(relative, flags,
   dir_fd=root_fd)` would remove per-component symlink rejection and weaken
   the reader; scanner-driven security regression is rejected.
4. A models-as-data sanitizer would declare the existing guard a barrier
   honestly, but default-setup code scanning only gained config-file support
   via the 2026-08-04 repository-property changelog, and this repository
   keeps scanner configuration out of remediation scope. Documented as a
   future option should advanced setup ever be adopted.

### 3.4 Dismissal procedure

After the #47/#48 fixes merge and their alerts close by analysis, dismiss
#45 and #46 exactly once each: state `dismissed`, reason `false_positive`,
comment linking this design, the issue, and enumerating the defenses in
section 3.2. Dismissed alerts remain in the audit trail with dismissal
metadata, unlike a silent fix-forward.

## 4. Alert #47 fix: owner-only corpus creation mode

`_write_history_corpus_document` in `scripts/abstract_conformance.py`
creates corpus cache files with `0o666` (line 825). The corpus is a
single-user materialization cache under the repository or a temporary root;
no other-user access requirement exists.

Change: the `os.open` creation mode literal `0o666` becomes `0o600`. The
mismatch-verification branch (lines 826-831) and directory creation calls
are unchanged. `os.mkdir` modes are unmodeled by the query and remain
untouched to keep the diff minimal.

RED test (executable, before the fix): in `scripts/test-history-conformance.py`,
the suite whose `build_task7_corpus` exercises the flagged writer, materialize
the complete corpus under `umask 0` (saved and restored in `try/finally`), then
assert every document under `lab/` has `os.stat(path).st_mode & 0o777 == 0o600`
and no group or world bit. Against `0o666` this fails for every created
document (125 genuine subTest failures observed). GREEN after the fix.

Behavioral risk: none for same-user readers and writers; cross-user sharing
of the cache was never a documented behavior. If a future workflow needs
shared caches, it requires its own issue.

## 5. Alert #48 fix: value-preserving shim default

The `replace_before_final_open` shim in
`scripts/test-abstract-conformance.py` declares `mode: int = 0o777`
(line 412), mirroring `os.open`'s documented default, and forwards it to
the captured original (line 421). The literal reaches `os.open`'s mode
parameter, alerting per section 2.1.

Change: the default becomes `stat.S_IMODE(0o777)` with `import stat` added
to the module. `stat.S_IMODE(0o777)` evaluates to `0o777` exactly, so the
mirrored contract is preserved; the reaching expression is a call, not an
`IntegerLiteral`, so the query cannot alert. This is the same barrier
technique accepted for alert #37 (per-index XOR derivation for nonces),
applied to a mode default.

RED: the external scanner is the RED case (open alert #48), exactly as
alert #38 was for M1-010F; branch CodeQL on the fix PR is the GREEN
evidence. Additionally, a value-preservation test asserts the shim's
evaluated `mode` default equals `0o777` through its `__defaults__` tuple,
pinning the mirror contract against future drift.

## 6. Verification matrix

- `PYTHONDONTWRITEBYTECODE=1 bash scripts/check.sh` aggregate (Rust and
  repository gates, including the conformance checker self-tests and
  accounting suites).
- `python3 -W error scripts/test-abstract-conformance.py` (445 tests),
  `scripts/test-history-conformance.py` (193 tests, including the new
  regression), `scripts/test-m1-013-plan-registry.py` (58),
  `scripts/test-bounded-json.py` (68), and
  `scripts/test-conformance-documentation.py` (16), run as separate
  commands because the unittest suites are outside `check.sh`.
- Byte-identity check: `scripts/m1_013_plan_registry.py` blob unchanged
  from `6154ac5`.
- Branch code-scanning on the PR head: #47 and #48 report `fixed` by
  analysis; #45/#46 remain the only open instances pending post-merge
  dismissal.
- Post-merge: repository-wide `state=open` alert query returns empty; #45
  and #46 show `dismissed` with reason `false_positive` and the
  justification comment.
- Independent review of the exact diff (spec axis and process-quality
  axis), then human DCO certification, publication, and web-only merge per
  the standing repository process.

## 7. Files changed (as implemented)

- `scripts/abstract_conformance.py`: one mode literal.
- `scripts/test-abstract-conformance.py`: one import, one default
  expression, one `__defaults__` pin assertion.
- `scripts/test-history-conformance.py`: one new regression test
  (`test_materialized_corpus_documents_are_created_owner_only`); the
  implemented placement supersedes the draft plan's task6-placement wording
  because only `build_task7_corpus` exercises the flagged writer.
- `docs/LESSONS_LEARNED.md`: prevention rule (pin CodeQL CLI version and
  query sources before remediation design; query repository-wide open
  alerts after each merge).

## 8. Risks and limitations

- The dismissal path records audit metadata but does not prevent the same
  query from alerting if `_read_relative` is ever copied or its guard
  weakened; the lessons-learned entry and this design are the durable
  references.
- The umask-controlled mode test depends on POSIX semantics; the repository
  targets Linux CI only, consistent with the existing suites.
- No production/runtime behavior changes; no new dependencies; no scanner
  configuration changes.
