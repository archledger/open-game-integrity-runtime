# M1-013 Abstract JSON Conformance Fixtures Implementation Plan

> **For agentic workers:** Use `superpowers:subagent-driven-development` or
> `superpowers:executing-plans` and execute this plan task by task.

**Goal:** Build one test-only, representation-independent JSON conformance corpus
that exercises the approved evidence-binding transcript and evidence-time
contracts through a shared bounded loader and six fail-closed validation layers.

**Architecture:** `scripts/bounded_json.py` owns hostile-file admission behind a
consumer-neutral interface. The abstract-conformance validator validates the
manifest and executable registry before consuming expectations, then applies
independent reconstruction, coverage, and appraisal/lifecycle oracles. The
existing attack-scenario validator adopts only the loader seam through a
behavior-preserving compatibility formatter.

**Tech stack:** Python standard library, JSON fixture notation, Markdown, Bash
aggregate gates, and existing Cargo workspace verification.

**Architectural authorities:**

- `docs/superpowers/specs/2026-09-01-m1-013-abstract-json-conformance-fixtures-design.md`
- `docs/adr/0010-semantic-evidence-binding-transcript.md`
- `docs/adr/0011-challenge-anchored-evidence-time.md`
- `docs/adr/0012-abstract-json-conformance-corpus.md`

**Sole normative format-v1 planning authority:** the closed root index at
`docs/superpowers/plans/2026-09-02-m1-013-format-v1-registry.json` and its four
hash-bound shards. The checker at `scripts/check-m1-013-plan-registry.py` is the
only supported way to admit that registry. This plan intentionally duplicates
no normative IDs, paths, schemas, domains, baselines, transforms, actions,
expectations, coverage arrays, resource constructors, diagnostics, or focused
rows.

## Global Constraints

- Work only from `docs/m1-013-abstract-conformance-fixtures` based on exact
  `origin/main` `9a04b055d9e978b5e4ff01adce72f0915c122532`. Never reconcile,
  reset, merge, or rewrite intentionally divergent local `main`.
- The approved design candidate is temporary-index tree
  `f3326ab93724b583b72601b4c50627ce624c1120`, binary patch SHA-256
  `8c8c4d912a20a107a8fdead0bd15ba18471a4ab4ca37dce7f968caa425ff8d99`.
- The human approval dated 2026-09-02 authorized planning only. It did not
  authorize local issue creation, runtime conformance implementation, corpus
  fixtures, staging, commit, sign-off, push, pull request, or GitHub mutation.
- First obtain exact human approval of the plan, registry, checker, and tests.
  Then freeze and, under separate DCO 1.1 certification, create only a separately
  authorized documentation commit. Only after that commit may the human
  separately authorize Task 1 issue drafting. The human must approve that exact
  issue and separately authorize Tasks 2-10. None of these gates authorizes
  Task 11 publication.
- Use only the Python standard library and existing repository tooling. Add no
  dependency, lockfile change, generated dependency artifact, `unsafe` code,
  cryptographic primitive, TPM library, or production TCB module.
- JSON remains repository fixture notation only. Do not create a runtime
  transcript type, production parser/schema/serializer, canonical bytes, wire
  tag, algorithm, proof, literal cryptographic domain label, TPM mapping,
  persistence adapter, permit, proof-of-possession, renewal authorization, or
  admission path.
- Treat repository JSON and paths as hostile until admitted. Preserve the
  attack-scenario consumer's behavior exactly. New conformance diagnostics may
  contain fixed consumer, checkpoint, and error-class labels only.
- For every implementation case, run one narrow RED-GREEN loop: add one intended
  behavior assertion using the registry's exact baseline and transform, observe
  failure for that behavior, implement the smallest change, rerun the case, and
  rerun all earlier cases in the task. Import errors and grouped first failures
  are not valid per-case RED evidence.
- Do not commit task checkpoints. Retain reviewed checkpoints uncommitted until
  the complete candidate is separately frozen, certified, and authorized.
- Every task ends with focused checks, `git diff --check`, exact changed-path
  review, `git status --short`, and independent review when a security interface
  changes.

## Mandatory Planning Gate

This gate precedes Task 1 and every later task. It does not authorize the task.

```bash
python3 scripts/test-m1-013-plan-registry.py
python3 scripts/check-m1-013-plan-registry.py
python3 -m py_compile \
  scripts/m1_013_plan_registry.py \
  scripts/check-m1-013-plan-registry.py \
  scripts/test-m1-013-plan-registry.py
```

Stop on any nonzero exit or any shard hash, count, order, reference, authority,
transform, coverage, resource, diagnostic, focused-matrix, or operation-budget
contract drift.
Implementation code must consume the admitted JSON values; it must not parse
this Markdown guide or recreate a second normative table in Python.

This planning gate does not execute validator-case semantic adapters and does
not contain or derive aggregate operation totals or per-case operation vectors.
Those are runtime implementation evidence produced later under TDD.

The planning-checker TDD record is:

- the superseded monolithic suite produced a valid RED with 21 tests and 47
  behavior assertion failures; its earlier zero-test import failure is invalid
  evidence;
- before the comprehensive checker change, the current mutation suite produced
  a valid RED with 31 tests, 378 assertion failures, and zero errors; and
- before the second hardening pass, the expanded suite produced a valid RED with
  39 tests, 8 assertion failures, and zero errors; and
- before the final semantic-hardening pass, the same suite produced a valid RED
  with 39 tests, 14 assertion failures, and zero errors; and
- before the final capability and closed-policy pass, the expanded suite produced
  a valid RED with 43 tests, 20 assertion failures, and zero errors; and
- before transformed-schema and physical source-binding enforcement, the
  expanded suite produced a valid RED with 47 tests, 21 assertion failures, and
  zero errors; and
- before the directory-race hardening pass, the expanded suite produced a valid
  RED with 49 tests, 4 assertion failures, and zero errors; and
- before stable-file and constructor-contract hardening, the expanded suite
  produced a valid RED with 52 tests, 17 assertion failures, and zero errors; and
- with those intended mutation contracts retained, the current suite runs 52
  tests GREEN and the checker reports the admitted planning counts.

This record proves only the planning registry checker. Every runtime case still
requires its own narrow RED-GREEN evidence under the task rules below.

## Task 1: Canonical Local Issue

**Authorization gate:** Task 1 starts only after the approved planning-only
documentation commit exists and the human separately authorizes local issue
drafting. Completion stops for approval of the exact local issue. Approval of
Task 1 does not authorize Tasks 2-10.

- Create only `planning/issues/013-abstract-json-conformance-fixtures.md`.
- Include every section required by `docs/AI_DEVELOPMENT_POLICY.md`.
- Reference the admitted JSON registry instead of copying its normative data.
- State the test-only scope and all production-representation deferrals.
- State that implementation requires separate human approval and that no live
  issue, staging, commit, sign-off, push, pull request, or merge is implied.
- Run the mandatory planning gate, issue section checks, diff check, and status;
  then stop for exact human approval.

## Task 2: Shared Bounded JSON Loader

**Authorization gate:** Requires separate explicit authorization for Tasks 2-10.

- Create `scripts/abstract_conformance_registry.py`,
  `scripts/test-bounded-json.py`, and `scripts/bounded_json.py`.
- Consume admitted registry baseline, transform, limit, and resource-constructor
  values. Keep executable implementations free of expected outcomes and
  coverage authority.
- Establish the importable interface first, then run one loader-case RED-GREEN
  loop in registry order.
- Implement descriptor-relative `O_NOFOLLOW` admission, final regular-file
  validation, bounded read, strict UTF-8, duplicate-name/non-finite rejection,
  and bounded structural walking.
- Run loader tests, Python compilation, named mutation checks, planning gate,
  diff check, and status. Do not commit.

## Task 3: Preserve Attack-Scenario Behavior

- Create `scripts/test-attack-scenario-parity.py` before migration and record
  literal pre-migration outputs, errors, and exits.
- Prove parity on the frozen source, force one controlled RED, restore GREEN,
  then replace only JSON/file admission in
  `scripts/check-attack-scenario-traceability.py`.
- Import registry transforms; do not duplicate them in the attack consumer.
- Run loader, parity, attack self-test, normal attack validation, planning gate,
  diff check, and status. Obtain independent compatibility review.

## Task 4: Manifest Bootstrap and Executable Bijection

- Create `scripts/abstract_conformance.py` and
  `scripts/check-abstract-conformance.py`; extend the executable registry.
- Build the complete temporary synthetic canonical corpus from admitted JSON
  recipes before creating real corpus files.
- Run one layer-1 RED-GREEN loop per admitted corpus validator case in exact
  registry order.
- Validate the canonical manifest, inventory, paths, tuple uniqueness,
  executable-table bijection, and coverage before consuming any expected result.
- Run self-tests, mutation checks, compilation, planning gate, diff check, and
  status. Obtain independent trust-order review.

## Task 5: Fixture Admission, Shape, and Baseline Reproduction

- Create the real manifest and only the admitted layer-2/layer-3 fixture files.
- Consume JSON schema/domain/nullability and transform values directly.
- Prove byte-level and complete-document one-change reproduction before semantic
  validation. Expected oracle state remains immutable.
- Run one per-row RED-GREEN loop, earliest-stop mutation checks, compilation,
  planning gate, diff check, and status. Obtain independent earliest-layer
  review.

## Task 6: Snapshot Oracles and Corpus

- Implement separate snapshot reconstruction, exact abstract coverage, and
  appraisal oracles.
- For each admitted snapshot-focused row, run independent layer-4, layer-5, and
  layer-6 RED-GREEN loops with baseline prerequisites rebuilt for each call.
- Create every admitted snapshot file from its registered baseline and transform
  and prove exact reproduction.
- Prove claim-order independence and duplicate preservation.
- Run snapshot checks, focused rows, count checks, compilation, planning gate,
  diff check, and status. Do not claim normal real-corpus GREEN before histories
  exist.

## Task 7: History Lifecycle Oracle and Corpus

- Implement ordered evaluation of the admitted closed action registry.
- Resolve references only from candidate registries and reconstruct observations
  only from keyed trusted inputs. Never resolve from or mutate oracle state.
- For each admitted history-focused row, run independent layer-4, layer-5, and
  layer-6 RED-GREEN loops using literal complete states.
- Create every admitted history file from its registered baseline and transform.
- Run lifecycle mutation checks, normal/self-test validation, exact counts,
  compilation, planning gate, diff check, and status. Obtain separate lifecycle,
  authority, privacy, and retention reviews.

## Task 8: Focused Oracles, Budget, Diagnostics, and Aggregate Gate

- Execute the admitted focused matrix literally in order with three independent
  invocations per row.
- Implement operation charging in the registry's category order, incrementing
  before work, with fresh scope per validation/case/focused invocation. Derive
  each per-case vector and the earliest-stop total from the executable runtime
  tables under TDD. Expected counters may not come from the validator under test,
  and the planning registry supplies no vectors or aggregate total.
- Keep the million-boundary probe private and unregistered.
- Run one RED-GREEN loop per admitted diagnostic case and render only fixed safe
  labels.
- Add the separately admitted aggregate commands without changing attack-command
  timeout behavior.
- Run all Python gates, timeout proof, aggregate gate, planning gate, diff check,
  and status. Obtain independent fail-open/resource/diagnostic review.

## Task 9: Implementation Evidence Documentation

- Add candidate-aware documentation assertions before prose changes.
- Update architecture, threat model, test strategy, lab documentation, roadmap,
  ADR evidence, and the approved local issue from observed implementation
  evidence only.
- Reference the JSON registry; do not copy normative arrays into prose.
- Run documentation assertions, ADR index validation through a temporary index,
  all Python gates, aggregate checks, planning gate, diff check, and status.
  Obtain independent documentation/spec/privacy review.

## Task 10: Mutation Evidence, Final Review, and Freeze

- Physically apply and restore every named mutation from Tasks 2-8. Record the
  command, expected detector, observed first cause, exit, and restoration hash.
- Obtain separate independent reviews for loader/path/resource safety;
  manifest/bijection/coverage/earliest-stop behavior; transcript oracles;
  lifecycle/high-water/concurrency/retention; privacy/diagnostics/attack parity;
  and whole-branch spec compliance.
- Fix every Critical or Important finding test-first and disposition every Minor
  finding explicitly.
- Run fresh complete verification, including the planning gate, all Python
  suites, aggregate gate, release workspace tests, diff check, and status.
- Freeze only authorized paths through a temporary index; verify the real index
  remains untouched. Stop for exact human review and DCO certification. Do not
  stage in the real index, commit, sign, or mutate a remote.

## Task 11: Guarded Commit and Publication Handoff

**Authorization gate:** Task 11 requires exact human DCO certification of the
frozen candidate and separate authorization for each commit or publication
action.

- Reverify candidate tree, patch hash, file hashes, identity, and exact trailer.
- Create only the separately authorized signed local commit. Never amend without
  explicit authorization.
- Stop unless an ordinary non-force push is separately authorized; verify remote
  readback on success.
- Stop unless live issue and pull-request creation are separately authorized.
  Push authorization alone authorizes neither.
- The human performs final line review and web-only merge.

## Completion Contract

Before claiming the plan candidate complete, rerun the mandatory planning gate,
verify the JSON section/count arithmetic directly, inspect the complete diff,
run `git diff --check`, and report exact status. A passing checker is evidence
only for planning-registry consistency. It is not evidence that runtime
conformance code or real corpus fixtures exist, and it grants no authorization.
