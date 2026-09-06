# ADR-0015: Test-only binding-transcript encoding with explicit domain separation

- Status: Accepted
- Date: 2026-09-05
- Owners: Initial maintainer
- Related issues: [Local M2-016 issue](../../planning/issues/016-mock-protocol-specification.md); [approved design](../superpowers/specs/2026-09-05-m2-016-mock-protocol-specification-design.md)
- Supersedes: None
- Superseded by: None

## Context

M1-012 defined the Evidence-binding transcript as a closed semantic value,
deliberately not bytes, a digest, or a wire object. M2 must prove challenge,
evidence, verifier, permit, and session-key binding end to end with test-only
software keys, which requires some concrete byte construction to cover,
authenticate, and cross-check between two independent implementations. The
protocol design milestones freeze production encoding (deterministic CBOR,
COSE) only after M2 conformance vectors pass, and the M2 design gate forbids
selecting production serialization or signature libraries now. A test-only
encoding is therefore needed that two implementations can agree on byte for
byte without committing to any production format.

The human approved the M2-016 design on 2026-09-05, including this encoding.
Acceptance records the decision; no encoder, parser, or runtime mechanism
exists yet.

## Decision drivers

- Two independent implementations must derive identical bytes from identical
  semantic values, with no canonicalization ambiguity left to the implementer.
- Bytes of one message class must fail validation in every other class
  (substitution between challenge, evidence, permit, and proof roles).
- Duplicate security-critical fields and unknown critical fields must be
  structurally detectable, because two of the twelve required M2 attack-test
  categories depend on them.
- Bounded parsing must hold before any digest or authenticator check.
- Nothing in this encoding may be reusable as, or imply a choice of, the
  production wire format.
- `ogir-model` stays dependency-free and unchanged.

## Options considered

### A: Flat length-prefixed record sequence with fixed domain tags

Selected. Each covered object is a fixed ASCII domain tag followed by
zero or more records `field-id(u16, big-endian) || length(u32, big-endian)
|| value(length bytes)`, records sorted by strictly ascending field-id, each
field-id appearing at most once. Benefits: trivially canonical, bounded by
construction, duplicate and unknown ids are detectable before value parsing,
and nesting stays flat (embedded objects are carried as one opaque record of
already-encoded bytes). Costs: none of the record machinery transfers to
production CBOR, which is acceptable because it is test-only.

### B: Deterministic CBOR now

Rejected. It would select a production serialization during M2, violating the
design gate and milestone ordering, and drags in a dependency or an in-repo
CBOR implementation that production review has not scrutinized.

### C: Digest-only binding without a full encoding (sign semantic digests)

Rejected. Signing a digest list without a fixed construction leaves encoding
ambiguity between implementations, defeats the duplicate-field and
unknown-field attack tests, and provides no bounded parser to attack.

## Decision

### Domain tags

Every covered object begins with exactly one fixed ASCII tag, then the record
sequence. Tags are distinct, ASCII, and versioned:

```text
OGIR-MOCK-CHALLENGE-1   signed test challenge
OGIR-MOCK-EVIDENCE-1    evidence-binding transcript (M1-012 semantics)
OGIR-MOCK-PERMIT-1      short-lived test permit
OGIR-MOCK-POP-1         session-key proof of possession
OGIR-MOCK-REVOKE-1      authenticated test revocation view
```

The `MOCK` component is mandatory and permanent: per protocol milestone 10,
experimental namespaces are never reused for production. Validation of any
object requires the expected tag as an input; a byte string valid under one
tag is rejected under every other tag before any record is read. The
revocation-view tag is registered now without a field registry; ADR-0014
semantics own its fields and M2-018 registers them when first implemented.

### Record rules

- `field-id`: `u16` big-endian. Ids `0x0000..=0x7FFF` are critical; ids
  `0x8000..=0xFFFF` are reserved for future test-only extensions.
- Unknown critical id: reject the object (fail closed). Unknown extension ids
  are also rejected in M2; there is no ignore path.
- Duplicate id within one object: reject, including duplicates with equal
  values.
- `length`: `u32` big-endian. An object's total encoded size is bounded by
  the frame bound minus header overhead; a record whose length exceeds the
  remaining bound is rejected before its value is read.
- Integers are fixed-width big-endian (`u16`, `u32`, `u64`); identifiers are
  opaque bytes whose internal length invariants (for example
  `ogir_model::NONCE_LENGTH`, `SESSION_PUBLIC_KEY_ID_LENGTH`) are checked
  after the record is read; no default values, no maps, no variable-order
  fields, no trailing bytes after the last record.

### Field registries (test-only, frozen for M2)

Challenge (`OGIR-MOCK-CHALLENGE-1`): protocol major/minor, publisher id, game
id, build id, account scope, match id, policy id, policy version, nonce,
window issued-at, window expires-at, requested evidence profile id, issuer
key id. Semantics and trust sources are exactly `PublisherChallenge` plus the
test issuer; the signed form adds issuer key id only.

Evidence transcript (`OGIR-MOCK-EVIDENCE-1`): the complete M1-012 semantic
transcript in fixed order: the encoded challenge object as one opaque record
(binding by construction), evidence profile id, session public key id, the
actual session public key bytes, collection authority contract id, protected
epoch relation, collection sequence, collection start, snapshot-freeze end,
the eight Base claim records, the profile's declared subset of the two
profile-specific claim records, exactly one provenance class per claim, and
the semantic manifest and measurement identities. Claim records carry their
provenance class internally as a one-byte discriminator. Every field's trust
source remains as documented in `docs/TRUST_MODEL.md`; encoding grants none.

Permit (`OGIR-MOCK-PERMIT-1`): protocol major/minor, permit id, session id,
session public key id, the appraised challenge's nonce, policy id, policy
version, issued-at, exclusive expires-at (finite, half-open, per ADR-0014),
issuer key id. Denial is not a permit: unsigned non-disciplinary reports use
the existing `ReasonCode` vocabulary outside this encoding.

Proof of possession (`OGIR-MOCK-POP-1`): session-key authenticator over the
permit object's bytes plus a verifier-issued rechallenge nonce. Construction
and validation rules are owned by ADR-0016.

### Digests and authenticators

Where a digest is needed (permit policy binding, conformance vectors), it is
the SHA-256 of the complete tagged object bytes, computed by the in-repo
test-only primitive selected by ADR-0016. Digests never replace
authentication and never appear inside the object they claim to cover.

### Worked example obligation

The implementing slice must include at least one fully written-out byte-level
example transcript with symbolic digest placeholders, small enough to verify
by hand, plus machine-checked equality between two independently constructed
encoders. Concrete hex vectors arrive with M2-019 conformance work.

### Wire framing

The mock demo's test-only frame header layout is intentionally not specified
here; the M2-017 implementation plan owns it, inside the existing
`FrameHeader` and `MAX_FRAME_LENGTH` bounds and the `MessageKind` allocation
recorded in the protocol document.

## Consequences

M2-017 onward implements parsers and constructors against a fixed,
reviewable contract, and the duplicate-field, unknown-field, truncation, and
substitution attack tests have structural targets. The cost is a parallel
test-only encoding that production will not use; every file implementing it
must carry the test-only marker so no production path depends on it. The
production canonical encoding decision remains open for its own later ADR.

## Threat-model impact

No production trust boundary changes. Within the mock threat model, the
encoding removes transcript substitution, field duplication, ordering
ambiguity, and unbounded-input classes by construction. Residual: the
encoding itself provides no confidentiality, no non-repudiation, and no
protection against a party that holds the mock shared secret (see ADR-0016
limitations).

## Privacy impact

None beyond existing rules. The encoding redacts nothing by itself; debug
printing of any object remains forbidden for nonce, key, and claim values,
and implementing slices must keep the existing redaction allowlists.

## Dependency and license impact

None. No manifest change. SHA-256 arrives only through the ADR-0016 test-only
crate decision, not through this encoding decision.

## Validation

Structural gates in the implementing slice: canonical re-encode equality for
all valid objects; cross-tag rejection matrix (every object under every wrong
tag); duplicate-id, unknown-id, oversized, truncated, and trailing-byte
rejection tables; independent second-encoder byte equality. The M2-019
attack suite exercises the same properties adversarially. Documentation
gates executed at acceptance: every registry field maps to one named trust
source, every tag is enumerated, and every M2 attack-test category maps to
exactly one host slice.

## Rollback

Before acceptance, revise or discard this decision without changing runtime
behavior. After acceptance, preserve this record and use an explicit
superseding ADR for incompatible changes; mock artifacts already issued under
a tag version stay valid only for their declared test lifetime. Grace
acceptance of foreign-tag bytes, duplicate ids, or unknown critical ids is
never a safe fallback.

## Primary sources

- [Protocol](../PROTOCOL.md) M1-012 binding transcript semantics and design
  milestones 2, 4, and 10.
- [Trust model](../TRUST_MODEL.md) evidence-binding transcript authorities.
- ADR-0010, ADR-0011 (transcript semantics, challenge-anchored time),
  ADR-0014 (permit validity and renewal ordering).
- `crates/ogir-model/src/lib.rs` (`PublisherChallenge`, `Nonce`,
  `SessionPublicKeyId`, `ProtocolVersion`) and
  `crates/ogir-model/src/freshness.rs` (`ChallengeWindow`, `UnixTime`).
- `crates/ogir-protocol/src/lib.rs` (`FrameHeader`, `MessageKind`,
  `MAX_FRAME_LENGTH`).
