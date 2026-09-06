# Plan: M4-026 profile schema and log ingestion

- Status: Executed in `research/m4-026-profile-schema-and-log-ingestion`;
  all local gates green; awaiting human review, signed commit, and
  separately authorized publication.
- Date: 2026-09-06.
- Baseline: merged `cc33722308f0996a4905dd95d682788b0d242480`.
- Authority: accepted M4 entry recommendations (R1-R4, 2026-09-06);
  [ADR-0023](../../../docs/adr/0023-platform-profile-and-log-ingestion.md);
  [local issue](../../../planning/issues/026-profile-schema-and-log-ingestion.md).

## Tasks

1. Extract the real host fixture (sudo read of the 116-event log) with
   its live `tpm2_pcrread` expectations captured alongside.
2. `ogir-bootlog`: parser, replay, profile modules as specified in
   ADR-0023; workspace membership.
3. The five-test ingestion suite; ADR-0023, index row, roadmap
   boundary, issue, plan.

## Test inventory (executed, all green)

- Real-fixture parse (115 EVENT2 records, SHA-256-only Spec ID) with
  EXACT replay to live PCRs 2 and 7 (PCR 0 documented gap).
- Profile shape validation; the four non-weakening-successor
  directions (revision, dropped expectation, lowered floor,
  dropped Secure Boot).
- Truncation rejection at seven cut points; trailing-byte and
  foreign-header rejection; corrupted-algorithm-table handling.
- Forged expectations and touched-but-unexpected PCRs detect.

## Development lessons

EV_NO_ACTION events never extend a PCR but StartupLocality=3 changes
PCR 0's initial value to all-FF (TCG PC Client PFP) - without both
semantics the replay diverges; real firmware logs may not reproduce
PCR 0 (early CRTM measurements precede the log), which is the roadmap's
log-does-not-reproduce category in the wild - assert the faithful
subset and document the gap rather than weakening the matcher.

## Deliberately not done

SHA-1/TCG 1.2 legacy logs and other digest banks; replay against live
TPM quotes (M4-027); the test image (M4-028); the signed reference
manifest (M4-029).
