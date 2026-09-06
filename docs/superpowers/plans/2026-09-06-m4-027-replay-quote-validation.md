# Plan: M4-027 log-quote replay validation

- Status: Executed in `research/m4-027-replay-quote-validation`; all
  local gates green; awaiting human review, signed commit, and
  separately authorized publication.
- Date: 2026-09-06.
- Baseline: merged `d2132635cdef6bcdac31a713e5e62b0095fd58ba`.
- Authority: M4 entry decomposition (M4-027); the M4 exit criterion
  "the verifier reconstructs or validates measured state against the
  quote"; [local issue](../../../planning/issues/027-replay-quote-validation.md).

## Tasks

1. `logbridge.rs` in `ogir-attest-tpm` (new dependency on
   `ogir-bootlog`, production-to-production): LogExtender with the
   PCR-session discipline; the triangle check.
2. Three integration tests against real swtpm and the real fixture.
3. Roadmap boundary; local issue; this plan.

## Test inventory (executed, all green)

- End-to-end triangle: the real fixture's PCR-7 event digests
  extended into live PCR 16; the SwtpmBackend's quote validates
  against the replayed PCR-7 value (SHA256-of-value semantics).
- Mismatch attack: PCR-2 events behind the quote; the PCR-7 replay
  rejects LogQuoteMismatch.
- Truncated log rejects at parse.

## Development lessons

TPM2_Quote's pcrDigest is the hash of the CONCATENATED selected PCR
values (Part 3) - a single-bank quote carries SHA256(pcr_value), not
the value itself; the first triangle run failed exactly because the
comparison treated them as equal. PCR_Extend needs the password
session for the (empty-auth) PCR handle - the M3 session lesson
recurs. Debug digests at all three points (replay, live bank, quote)
isolated the semantic question in one run.

## Deliberately not done

The test image and UKI/PCR-11 (M4-028); the signed manifest (M4-029);
the attack suite and exit audit (M4-030).
