# M1-013F implementation plan: Python code-scanning alert remediation

- Date: 2026-09-05
- Status: Approved for execution (design and issue approved 2026-09-05)
- Issue: `planning/issues/013f-remediate-python-codeql-alerts.md`
- Design: `docs/superpowers/specs/2026-09-05-m1-013f-python-codeql-alert-remediation-design.md`
- Base: `6154ac58c10fe8a830e2db09944fae06e20387d1`
- Authorization: implementation and local verification only. Staging, DCO
  sign-off, commit, push, live issue or PR creation, merge, and alert
  dismissal each require separate explicit authorization.

## Task 1: RED regression tests

Placement correction discovered during implementation: the flagged
`_write_history_corpus_document` writer is exercised by
`build_task7_corpus` in the history suite; `build_task6_corpus` writes via
`Path.write_bytes`. The mode regression therefore lives in
`scripts/test-history-conformance.py`, not `test-abstract-conformance.py`.

1. In `scripts/test-history-conformance.py` (`HistoryTests`), add
   `test_materialized_corpus_documents_are_created_owner_only`:
   - save `os.umask(0)`, restore in `finally`
   - build the task7 corpus in a `tempfile.TemporaryDirectory`
   - enumerate every non-symlink file under `lab/` (deterministically 125
     documents: 69 snapshots, 55 histories, one corpus manifest)
   - assert each has `st_mode & 0o777 == 0o600` and zero group/world bits
   - expected RED against `0o666`: 125 genuine subTest assertion failures
2. In the existing shim test helper in `scripts/test-abstract-conformance.py`
   that defines `replace_before_final_open`, add the mirror-contract pin:
   `self.assertEqual(replace_before_final_open.__defaults__, (0o777,))`
   - this is a value pin, expected to pass before and after the fix; its
     purpose is preventing default drift, and the scanner alert remains the
     RED evidence for alert #48 exactly as alert #38 was for M1-010F

Run the focused tests; record the exact RED failure.

## Task 2: GREEN minimal fix

1. `scripts/abstract_conformance.py` line 825: creation mode literal
   `0o666` becomes `0o600`. No other change in the function.
2. `scripts/test-abstract-conformance.py`: add `import stat` to the import
   block; change the shim default `mode: int = 0o777` (line 412) to
   `mode: int = stat.S_IMODE(0o777)`.

Run the focused tests; record GREEN.

## Task 3: verification matrix

- `PYTHONDONTWRITEBYTECODE=1 python3 -W error scripts/test-history-conformance.py`
  (192 prior tests plus the new regression)
- `PYTHONDONTWRITEBYTECODE=1 python3 -W error scripts/test-abstract-conformance.py`
  (445 prior tests)
- `PYTHONDONTWRITEBYTECODE=1 python3 -W error scripts/test-m1-013-plan-registry.py`
- `PYTHONDONTWRITEBYTECODE=1 python3 -W error scripts/test-bounded-json.py`
- `PYTHONDONTWRITEBYTECODE=1 bash scripts/check.sh` aggregate (Rust and
  repository gates; the unittest suites above run as separate commands)
- Byte identity: `git diff 6154ac5 -- scripts/m1_013_plan_registry.py` is
  empty; the only changed paths are the three scripts and the docs file

## Task 4: lessons-learned documentation

Append to `docs/LESSONS_LEARNED.md` one dated entry recording: pin the
CodeQL CLI version from the CI toolcache log and the exact query sources
before designing remediations; barrier models accept only the shapes they
model (affirmative constant compares and `startswith` true-branches), so a
denylist-reject guard cannot be made recognizable by restructure; and query
the repository-wide open-alert list after every merge, not only
branch-scoped results.

## Task 5: report and stop

Produce the implementation report with exact commands, outputs, and the
diff summary. Stop. Independent review, DCO certification, signed commit,
publication, and the post-merge dismissal of alerts #45/#46 proceed only
under separate explicit authorization.

## Mutation spot-checks (during Task 3)

- Revert the mode literal to `0o666` mentally verified killed by the new
  owner-only test; also physically verify once: flip `0o600` to `0o666`,
  observe the focused test fail, restore.
- Flip `stat.S_IMODE(0o777)` back to a bare `0o777` literal and confirm the
  mirror pin still passes (value unchanged) while the scanner-contract
  difference is documented by design; this check is informational only and
  its revert is verified by diff.
