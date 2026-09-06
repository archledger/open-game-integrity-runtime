# M4-026: Platform-profile schema and TCG2 log ingestion
<!-- labels: type: implementation,area: measured-boot,area: attack-lab,risk: parser,status: needs-review -->
<!-- milestone: M4 Measured Boot Profile -->

Status: Local integration candidate; no live GitHub issue yet. First M4 slice under the accepted entry recommendations (R1-R4).

## Problem

M4 must prove one narrow, documented Linux platform profile; its
foundation - the profile schema, the event-log parser, and PCR replay -
did not exist, and the milestone's log-forgery attack categories need
an ingestion layer to host against.

## Scope

- `crates/ogir-bootlog` (production, dependency-free except
  in-workspace SHA-256): the total TCG2 parser (Spec ID header with
  the algorithm table; EVENT2 records with digest-count consistency
  and trailing-byte rejection); replay with exact TPM semantics
  (NO_ACTION exclusion, locality-3 initialization); exact and subset
  matching; the platform-profile schema with shape validation and the
  ADR-0014 non-weakening successor relation.
- The real host event-log fixture with live-PCR expectations (PCRs 2
  and 7 exact; PCR 0 documented as the known fidelity gap).
- ADR-0023, index row, roadmap boundary, local issue, plan.

## Acceptance criteria

- All house gates green; the five ingestion tests green including the
  real-fixture replay.
- Zero external dependencies added.

## Current state

- 2026-09-06: Implemented in `research/m4-026-profile-schema-and-log-ingestion`
  from `cc33722`; awaiting human review and the signed-commit gate.
