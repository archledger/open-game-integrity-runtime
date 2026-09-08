# M9 exit audit: continuous attack laboratory

Date: 2026-09-08
Agent: zcode

## Criterion 1: every security invariant maps to at least one
executable scenario

SATISFIED, mechanically enforced. The new
scripts/check-invariant-coverage.py gate parses all 48 numbered
invariants in docs/SECURITY_INVARIANTS.md and requires each to
appear in the invariants array of at least one
lab/scenarios/*.scenario.json. Before this slice, 21 invariants
were executed inside the milestone suites but unmapped in the
registry; the slice adds 21 registry scenarios - each pointing at
its already-executed suite leg as the executable step - bringing
the registry to 61 scenarios and 48/48 invariants mapped, wired
into CI alongside the traceability gate.

## Criterion 2: every confirmed defect adds a permanent
scenario/regression

SATISFIED by the house record and now pinned by invariant 47's
registry scenario: every CI-caught defect this arc landed with its
regression test in the same merge (the M5 manifest settle race,
the flood-write race, the cleartext-logging remediations, the
kernel exec-reset discovery).

## Criterion 3: critical attack scenarios run before protected
releases

SATISFIED: the critical scenarios live in the per-milestone attack
suites (M2/M3/M4/M5/M6/M7/M8), which run in the rust CI job on
every PR - before any merge to main - and the scenario schema's
registry is now coverage-gated in the same pipeline.

## Criterion 4: bare-metal coverage is reproducible and documented

PARTIAL, recorded honestly. The dev host and archhost legs are
reproducible and documented (the runner scripts in the scoping
record; the archhost evidence); true bare-metal (physical TPM)
coverage has not been executed - the M4 work validated the
emulated profile by design, and physical-hardware validation
remains open. The dashboard reports this as status, not a score.

## The dashboard

scripts/security-dashboard.py prints per-invariant scenario counts
and gate status - test status, not marketing scores, per the
roadmap's own wording.

## Verdict

Criteria 1-3 satisfied; criterion 4 partial with the gap recorded
(the physical-TPM bare-metal leg). The laboratory deliverables
that predate this slice (the schema, the traceability gate, the
per-family corpus in the milestone suites, the fuzz crate) plus
this slice's coverage gate and dashboard constitute the
continuous attack laboratory. M0-M9 closed with the bare-metal
gap as the recorded follow-up.
