# Plan: M3-022 enrollment records and semantic validation

- Status: Executed in `research/m3-022-enrollment-and-validation`; all
  local gates green; awaiting human review, signed commit, and
  separately authorized publication.
- Date: 2026-09-06.
- Baseline: merged `507b9252462c447c9ec8a22d84e6be759a564d5f`.
- Authority: [ADR-0019](../../../docs/adr/0019-enrollment-records-and-quote-validation.md);
  [local issue](../../../planning/issues/022-enrollment-and-validation.md).

## Tasks

1. Statement contract v2 in `swtpm.rs`: AK-modulus capture at
   `create_primary`, `ak_modulus()`, fourth payload field; the staged
   debug-matches from M3-021's cleanup simplified back to plain
   `map_err` chains.
2. `enrollment.rs`: records and registry (one modulus, one scope).
3. `validation.rs`: `validate_quote` with the seven deterministic
   checks; `ValidatedQuote` as policy input.
4. Shared test fixture `tests/common/mod.rs` (the ADR-0018 swtpm
   lessons in one place); backend suite extended to v2; new
   seven-scenario validation suite.
5. ADR-0019, index row, roadmap re-charter boundary, local issue, plan.

## Test inventory (executed, all green)

- Enrollment unit: roundtrip, one-modulus-one-scope, invalid records.
- Backend v2 suite: the five M3-021 tests, with the fourth payload
  field now asserted against `ak_modulus()` (256 bytes).
- Validation integration (real swtpm): end-to-end valid quote;
  unenrolled scope; foreign-AK statement; wrong qualifying data; class
  mismatch; truncated payload and digest-tamper; unknown backend.

## Deliberately not done

Cryptographic signature verification (blocked: the only marshaling
path requires `unsafe`, forbidden workspace-wide - the unsafe-policy
decision belongs to its own review), the EK-bound credential-activation
protocol, and the identity/privacy and recovery ADRs: all re-chartered
into M3-023 per the roadmap boundary.
