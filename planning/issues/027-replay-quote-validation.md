# M4-027: Log-quote replay validation
<!-- labels: type: implementation,area: measured-boot,area: tpm,risk: parser,status: needs-review -->
<!-- milestone: M4 Measured Boot Profile -->

Status: Local integration candidate; no live GitHub issue yet. Second M4 slice, connecting M4-026 ingestion to the M3 quote chain.

## Problem

The M4 exit criterion "the verifier reconstructs or validates measured
state against the quote" needs the measured triangle proven: event
log, live TPM PCR bank, and quoted digest must agree, and a log whose
replay disagrees must reject.

## Scope

- `ogir_attest_tpm::logbridge`: `LogExtender` (connects to swtpm,
  extends log digests into a live PCR with the empty-auth password
  session, reproducing the replay's extension sequence exactly;
  includes a `read_pcr` diagnostic) and
  `replay_agrees_with_quote` - with the TPM2 semantic that Quote's
  pcrDigest is the hash of the selected PCR values, so the comparison
  is SHA256(replayed value) == quoted digest.
- Three integration tests: the end-to-end triangle on the real host
  fixture (extend PCR-7 events into live PCR 16, quote via the M3
  backend, replay agrees); the mismatching-log attack (PCR-2 events
  behind the quote, PCR-7 replay rejects); truncated-log rejection.

## Acceptance criteria

- All house gates green; the triangle and attack tests green on real
  swtpm.
- No new dependencies.

## Current state

- 2026-09-06: Implemented in `research/m4-027-replay-quote-validation`
  from `d213263`; awaiting human review and the signed-commit gate.
