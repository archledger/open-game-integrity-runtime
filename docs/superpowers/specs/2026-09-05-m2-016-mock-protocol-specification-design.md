# M2-016: mock protocol specification

- Status: Human-approved design; locally validated documentation integration candidate awaiting human contribution review; no encoder, parser, key primitive, or runtime mechanism implemented.
- Agent: zcode.
- Date: 2026-09-05.
- Baseline: merged `62fe2584116ef3abbe4cd669c2a521c655cbb231` (post-M1-013F).
- Deliverable: documentation-only mock protocol specification. ADR-0015 (test-only transcript encoding with domain separation), ADR-0016 (test-only ephemeral software key hierarchy), the protocol document's M2 mock message schemas, framing plan, and attack-test placement, plus this design record. No new Rust API, crate, dependency, wire format, commit, or publication.

## 1. Approved approach

The human approved the M2-016 specification-slice approach on 2026-09-05
with default resolutions for the four open questions: the mock key crate is
named `ogir-mock-keys`; the revocation-view domain tag is registered without
a field registry until M2-018; the mock frame-header layout is owned by the
M2-017 implementation plan; and no optional fresh workspace test run is
required for the M1 exit audit, which remains static.

| Decision | Selected | Rejected alternatives |
| --- | --- | --- |
| D1 transcript encoding | Flat canonical length-prefixed records under fixed `OGIR-MOCK-*-1` tags (ADR-0015) | Deterministic CBOR now (violates the design gate); digest-only signing (ambiguous, no parser to attack) |
| D2 mock authenticator | In-repo dependency-free SHA-256 + HMAC in a `publish = false` crate (ADR-0016) | Vetted crypto dev-dependency (premature selection, bans-policy event); toy asymmetric scheme (more code, false realism) |
| D3 challenge-evidence binding | Evidence transcript embeds the full signed challenge object as one opaque record | Binding by digest reference alone (weaker reconstruction duty) |
| D4 permit shape | First-class signed object with finite half-open validity per ADR-0014; denials stay unsigned `ReasonCode` reports | Folding denial into the permit type (grants a denial artifact the client could confuse with authority) |
| D5 proof of possession | Session-key authenticator over exact permit bytes plus a verifier-issued single-use rechallenge nonce | Proof over bare session id (no artifact binding) |
| D6 framing | `MessageKind` 5-8 allocated for mock classes; 9-63 reserved; 64+ rejected before payload parse | Reusing `Response` for all mock messages (no downgrade surface) |

## 2. Existing contracts that remain authoritative

1. The M1-012 Evidence-binding transcript remains a closed semantic value;
   ADR-0015 encodes it for tests only and grants no new authority.
2. ADR-0005 challenge freshness, ADR-0008 handle semantics, ADR-0009
   capability-gated results, ADR-0013 replay-cache isolation, and ADR-0014
   permit/renewal/revocation semantics are unchanged and binding on every
   mock implementation.
3. `ogir-model` stays dependency-free; no M2 machinery enters it.
4. The M2 design gate holds: no production serialization or signature
   library is selected by this slice, and experimental namespaces are never
   reused for production (protocol milestones 5 and 10).
5. The existing `FrameHeader`, `MAX_FRAME_LENGTH`, and `MessageKind` values
   1-4 are unchanged.

## 3. Slice charters for later scoped work

- M2-017 (mock encoding and attester): implement `ogir-mock-keys` (SHA-256,
  HMAC, deterministic derivation, key classes) and the ADR-0015
  encoder/parser with the test-only frame header layout; construct signed
  mock challenges and evidence; host the alter-field, unknown-field,
  duplicate-field, oversized/truncated, downgrade, expiry-boundary, and
  context-mismatch attack surfaces.
- M2-018 (verifier and permit): verifier policy interface, permit
  signing/validation, replay-cache wiring, mock key directory, one-successor
  fencing; host the patched-client, evidence-replay, permit-replay,
  expired-permit, and verifier-key-mismatch attacks.
- M2-019 (proof, vectors, demo): session-key proof of possession,
  deterministic conformance vectors, the CLI demonstration that never
  returns a trusted local boolean, the independent second encoder or
  validator, and the full adversarial attack suite.

Each later slice follows the standard SDD flow with separately authorized
steps; nothing in those charters is implemented or authorized by this
slice.

## 4. Validation executed at acceptance

- Documentation gates: both ADRs carry every template section; the ADR
  index gains rows 0015 and 0016; every registry field in ADR-0015 maps to
  a named trust source; all five domain tags are enumerated; every one of
  the twelve attack-test categories maps to exactly one host slice.
- Mechanical gates: zero em dashes, balanced code fences, no trailing
  whitespace in new sections, valid relative links from the ADRs to the
  local issue, this spec, and the protocol document.
- No runtime claim: no encoder, parser, key, signature, permit, or proof
  exists; the M1 exit audit recorded with this slice is static.

## 5. Residual risks

- The mock authenticator is symmetric; key compromise is modeled only at
  the mock key directory boundary (ADR-0016 records the limitation).
- The encoding gives no confidentiality, non-repudiation, or side-channel
  resistance; all are out of mock scope.
- Documentation consistency is checked by review and mechanical gates, not
  by machine-checkable schemas; the M1-013 scenario checker does not cover
  protocol prose, and no encoder exists yet to check against.

## 6. Primary sources

- `docs/ROADMAP.md` Milestone M2 (objective, deliverables, attack tests,
  exit criteria, design gate).
- ADRs 0005, 0007-0014; `docs/TRUST_MODEL.md`;
  `docs/PROTOCOL.md` M1-012 semantics and design milestones.
- `crates/ogir-protocol/src/lib.rs` framing primitives;
  `crates/ogir-model/src/lib.rs` and `freshness.rs` domain types;
  `crates/ogir-verifier/src/verification.rs` `ExpectedContext`.
- Scoping evidence outside the repository:
  `ogir/task-17-scoping/{m1-exit-audit.md,m2-gap-map.md}` (intake
  directory; referenced for provenance only, not repository content).
