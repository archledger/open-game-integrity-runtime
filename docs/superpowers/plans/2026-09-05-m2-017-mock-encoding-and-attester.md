# Plan: M2-017 mock encoding and attester

- Status: Executed in the `research/m2-017-mock-encoding-and-attester`
  worktree; local gates green; awaiting human review, signed commit, and
  separately authorized publication.
- Date: 2026-09-05.
- Baseline: merged `c90c3d70cbc844db6416aa0546bb9e3f0dadf1e5`.
- Authority: ADR-0015 and ADR-0016 obligations; M2-017 charter in the
  approved M2-016 design record; [local issue](../../../planning/issues/017-mock-encoding-and-attester.md).

## Tasks

1. `crates/ogir-mock-keys`: in-repo SHA-256 (FIPS 180-4) and HMAC-SHA256
   (RFC 2104/4231 shape), three ephemeral key classes with deterministic
   seed derivation, key ids carrying the `OGIRMOCK` namespace, a directory
   that models the key-compromise boundary, and full Debug redaction.
2. `crates/ogir-mock-protocol`: ADR-0015 record encoding (canonical
   ascending unique length-prefixed records under five domain tags,
   fail-closed unknown/duplicate/out-of-order/truncated/oversized parsing),
   the four signed object classes with frozen field registries and the
   32-byte authenticator trailer, the ADR-0016 proof-of-possession
   formula, and the M2-017 test-only 16-byte frame header.
3. `ogir-protocol`: allocate `MessageKind` 5 through 8 with reserved-range
   `from_u16` mapping (unknown kinds reject before payload parse).
4. `scripts/test-mock-substrate.py`: structural production-graph exclusion
   gate for ADR-0016.
5. Local planning issue and this plan record.

## Test inventory (executed, all green)

- SHA-256: four FIPS 180-4 vectors (empty, `abc`, 448-bit two-block,
  one-million-`a`) plus an incremental/one-shot block-boundary equality.
- HMAC: RFC 4231 cases 1, 2, 3, 6, 7 plus a fixed-time-equality control.
- Keys: derivation determinism and seed sensitivity, key-class domain
  separation, `OGIRMOCK` namespace prefix, stable 32-byte session handle,
  directory fail-closed behavior (unknown id, wrong key), Debug redaction.
- Transcript: encode/parse roundtrip with re-encode equality; duplicate,
  out-of-order, unknown (including `0x8001` extension), missing-required,
  trailing, truncated, and wrong-tag rejections; wrong-tag matrix across
  four foreign tags.
- Frame: roundtrip for all eight kinds; bad magic, short header, nonzero
  reserved, length-mismatch, oversized payload; kinds 9 and 64 rejected
  before payload read.
- Objects: sign/verify roundtrips preserving every field across all four
  classes; every-single-bit-flip rejection for the challenge (all bytes,
  all eight bits) and first-bit rejection for evidence, permit, and proof;
  cross-class substitution matrix; per-record-value alteration walk;
  wrong-directory `UnknownKey`; worked example pinning every non-key byte
  of a minimal challenge and the derivation-pinned key id and
  authenticator; temporal-ordering rejection (`issued_at >= expires_at`,
  `start > freeze_end`); proof-of-possession binding to exact permit bytes
  and exact session key; Debug redaction.
- Isolation: `scripts/test-mock-substrate.py` PASS (members, publish
  flags, TEST-ONLY markers, production manifests clean).

## Local gates

`cargo fmt --all --check` clean; `cargo clippy --workspace --all-targets`
zero warnings and zero errors (workspace denies `unwrap`/`expect`/`todo`);
`cargo test --workspace` all green (371 tests including doctests);
isolation script PASS. No dependency added: the two new crates are
`publish = false`, depend only on in-workspace `ogir-model` and each other,
and `ogir-mock-protocol` additionally on `ogir-protocol`.

## Deliberately not done

No verifier policy interface, permit lifecycle enforcement, replay-cache
wiring, conformance vectors, CLI demo, or attack-suite runner: those are
the M2-018 and M2-019 charters. `ogir-model` is untouched. The production
wire format remains unfrozen.
