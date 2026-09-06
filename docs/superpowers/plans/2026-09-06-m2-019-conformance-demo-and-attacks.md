# Plan: M2-019 conformance, demonstration, and the attack suite

- Status: Executed in the `research/m2-019-conformance-demo-and-attacks`
  worktree; all local gates green; awaiting human review, signed commit,
  and separately authorized publication.
- Date: 2026-09-06.
- Baseline: merged `c5bdb88353731ed7cfb306abf41ca36507a270d9`.
- Authority: M2-019 charter in the approved M2-016 design record; ADR-0014
  (renewal fencing), ADR-0015 (validation obligations: worked example and
  independent second encoder), ADR-0016; the roadmap's twelve attack-test
  categories; [local issue](../../../planning/issues/019-conformance-demo-and-attacks.md).

## Tasks

1. `renewal.rs`: the ADR-0014 mock session owner - one pending renewal,
   one committed successor per predecessor, idempotent exact redelivery,
   different-successor rejection, pending-grants-nothing.
2. `examples/mock-demo.rs`: the CLI demonstration running the full flow
   deterministically (signed challenge, evidence, frame transport,
   replay-fenced appraisal, permit, proof of possession, admission, fenced
   renewal); sensitive values print as digests or redacted markers; the
   admission decision comes only from relying-party validation of signed
   artifacts, and no trusted local boolean exists anywhere.
3. `tests/conformance.rs`: four frozen hex vectors for the object classes
   generated from fixed seeds (byte-for-byte reproducible; the frozen
   constants pin them permanently) plus the deliberately independent
   second encoder agreeing byte for byte for all four classes.
4. `tests/attack_suite.rs`: all twelve roadmap attack-test categories,
   each ending in a deterministic non-allow result.
5. Plan record, local issue, and the roadmap M2 completion boundary.

## Test inventory (executed, all green; workspace total 462)

- Renewal: one-successor-then-idempotent-redelivery;
  different-successor rejection; stale-predecessor rejection with unique
  pending; pending grants nothing.
- Conformance: frozen vectors reproduce exactly and verify as live
  objects; independent encoder equality for challenge, evidence (with the
  complete embedded signed challenge), permit, and proof.
- Attack suite (twelve categories): patched client (nothing, assertion
  text, impostor key all reject; honest artifacts admit); alter each
  challenge field (walk over every record value byte, authenticator
  coverage rejects); evidence replay (ADR-0013 cache); permit replay
  (one-use admission); cross-match/game/account/policy reuse with fresh
  nonces so each lands on the context comparison it targets; expired
  challenge and expired permit; unknown critical field; oversized and
  truncated (frame and object layers); duplicate security-critical field;
  protocol downgrade (kinds 9, 64, 0xFFFF); verifier key mismatch;
  session-key mismatch.
- Demo: runs end to end (steps 1-7) with redacted output.

## Local gates

`cargo fmt --all --check`; `cargo clippy --workspace --all-targets` zero
warnings; `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`
clean; `cargo test --workspace` 462 passed, 0 failed; isolation script
PASS; zero em/en dashes in added lines.

## M2 exit-criteria status after this slice

- The server admits only a verifier-signed permit with valid proof of
  possession: demonstrated end to end (demo, attack suite category 1).
- Every attack category returns a deterministic non-allow result: all
  twelve categories execute green.
- The client cannot locally mint or extend authorization: no API path
  exists; forging attempts reject in every suite.
- A second implementation or independent validator agrees on the
  conformance corpus: the independent encoder agrees byte for byte, and
  the frozen hex vectors pin the corpus.

## Deliberately not done

Production serialization/signature selection stays deferred (design gate;
post-M2 ADR). Revocation-view enforcement and revocation-aware admission
remain specified-but-not-mocked (ADR-0014 obligations recorded for M3+
implementation slices). No production crate changed.
