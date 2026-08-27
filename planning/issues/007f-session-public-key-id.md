# M1-007F: Define the session public-key lookup handle
<!-- labels: type: implementation,area: model,area: privacy,risk: trusted-computing-base,risk: privacy,status: needs-review -->
<!-- milestone: M1 Domain Model -->

## Problem

The M1 roadmap names `SessionPublicKeyId`, but the identifier work delivered by
M1-007 omitted it. Later attestation results and permits must refer to one
ephemeral protected-session key without treating a client-provided label, local
boolean, key ID, or copyable value as proof of possession or admission
authority.

Choosing a text identifier, variable-length generic COSE `kid`, key thumbprint,
or public-key encoding now would either add unnecessary parsing/allocation or
prematurely select cryptographic and wire semantics. Leaving the type undefined
would invite raw byte arrays, strings, or key material to cross future module
boundaries without one documented privacy and trust contract.

This issue defines only a fixed-width, opaque, non-authoritative lookup handle.
It does not implement key generation, key resolution, proof of possession,
attestation results, permits, or session admission.

## Security invariants

- Preserve invariants 1-5: a constructible/copyable key identifier never
  authorizes a protected match or substitutes for a signed result, permit, or
  validated proof of possession.
- Prepare invariant 3's future exact session-public-key binding without
  claiming that this standalone handle supplies the binding.
- Preserve invariant 36: future keys and handles are scoped to one publisher
  and protected session rather than reused as global correlation identifiers.
- Preserve invariant 37: default diagnostics redact the complete handle bytes;
  explicit byte access remains a trusted functional interface.
- Enforce invariants 47-48 through permanent regression, primary-source,
  independent-review, and human/DCO gates.

## Threats addressed

None. This pure vocabulary issue implements no runtime trust decision or threat
control. Cross-session substitution, relay, proof replay, permit validation,
and admission remain later result/protocol threats with their own scenarios.

## Quality and design failures addressed

- A key-selection hint is mistaken for a unique key commitment or current PoP.
- The same handle is reused across sessions or publishers and becomes a stable
  correlation identifier.
- Raw handle bytes enter default diagnostics.
- `SessionPublicKeyId`, `SessionId`, and `Nonce` are interchanged accidentally.
- Variable-length/string parsing or a crypto/hash algorithm is selected before
  the M2 protocol design gate.
- A convenience trait (`Default`, `Display`, serialization, implicit
  conversion) silently broadens the public contract.

## In scope

- Add `SESSION_PUBLIC_KEY_ID_LENGTH: usize = 32` to `ogir-model`.
- Add `SessionPublicKeyId([u8; 32])` with private storage.
- Add only infallible `from_bytes([u8; 32])` and explicit
  `as_bytes(&self) -> &[u8; 32]` methods.
- Derive only `Clone`, `Copy`, `PartialEq`, `Eq`, and `Hash`.
- Implement fixed redacted `Debug`.
- Accept every 32-byte value, including all zero; generation/collision policy is
  not representation validation.
- Document the normative per-session lifecycle and future trust ownership.
- Add compile-fail, finite property, structural, privacy, and mutation proof.
- Add ADR-0008 plus architecture, roadmap, trust, privacy, test, issue/spec, and
  applicable lessons traceability.

## Out of scope

- Public/private key bytes, algorithms, signatures, hashes, thumbprints, or
  canonical key encodings.
- RNG, key generation, key storage, destruction, or zeroization.
- `LocalSession`, verifier flow, evidence, protocol, result, permit, or
  admission changes.
- A composite `SessionKeyBinding` or `SessionKeyReference`.
- PoP challenge, transcript, validator, or authority capability.
- Serialization, string parsing, `Display`, `Default`, `AsRef`, `From`, serde,
  networking, persistence, async, I/O, dependencies, or `unsafe` code.
- Runtime enforcement of the documented lifetime; the bare copyable value
  cannot invalidate its copies.
- Repurposing roadmap M1-011, which remains result/reason-code taxonomy.

## Trust sources

- A future trusted local key owner creates the ephemeral session key and its
  application-specific lookup handle; the game/client is never authoritative.
- The future verifier/result path validates exact session-key binding under the
  complete appraisal context.
- The future relying-party/permit validator resolves the actual key and
  validates fresh proof before minting admission authority.
- This M1 type validates representation width only and supplies no trust.

## Lifecycle contract

- One future-generated key and handle belong to exactly one trusted
  `SessionId` and publisher context.
- The same key/handle persists through that protected session's renewals while
  each renewal uses a fresh challenge.
- `Ended` or `Invalidated` makes future use invalid; the future owner destroys
  or releases short-lived key state under a separately implemented policy.
- A new protected session or different publisher gets a new key and handle.
- Copies of the handle remain plain data; lifecycle validity is checked by the
  future trusted owner and consumers, not encoded by this value type.

## Required interfaces

```rust
pub const SESSION_PUBLIC_KEY_ID_LENGTH: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionPublicKeyId([u8; SESSION_PUBLIC_KEY_ID_LENGTH]);

impl SessionPublicKeyId {
    pub const fn from_bytes(bytes: [u8; SESSION_PUBLIC_KEY_ID_LENGTH]) -> Self;
    pub const fn as_bytes(&self) -> &[u8; SESSION_PUBLIC_KEY_ID_LENGTH];
}
```

`Debug` emits exactly `SessionPublicKeyId([REDACTED; 32])`. No other public
method, constructor, field, trait, or conversion is added.

## Positive tests

- Construction and byte round-trip preserve all 32 bytes exactly.
- Copy, equality, inequality, and hashing behave as plain value data.
- All 32 byte positions × all 256 byte values round-trip without normalization
  or rejection.
- All-zero and all-`0xff` values are representable.
- `Debug` is the exact fixed redaction marker.

## Negative tests

- Arrays of length 31 or 33 fail compilation.
- `SessionPublicKeyId` cannot be passed as `Nonce` or `SessionId`.
- `Default`, `Display`, string parsing, `AsRef`, serialization, and implicit
  conversions are unavailable.
- The field is structurally private and the exact public impl/derive surface is
  pinned.
- Real sentinel bytes never appear in default formatting.
- Constructing, copying, comparing, or hashing the handle produces no decision,
  verified-attestation, validated-permit, PoP, or admission interface.

## Fuzz/property tests

No fuzz target is added because the constructor accepts a fixed compile-time
array and performs no parsing. A deterministic 8,192-case matrix covers every
byte position/value pair; fixed all-zero/all-one/alternating controls cover
representative whole-value patterns.

## Mutation tests

Disposable-worktree probes must kill, at minimum:

- length constant changed to 31 or 33;
- storage field made public;
- raw or partially redacted `Debug`;
- `as_bytes` returning altered data;
- added `Default`, `Display`, string, serialization, or implicit conversion;
- removed type distinction or unapproved authority-like method.

Each mutation must execute its named detector and fail for the intended cause.

## Privacy impact

The handle can correlate activity if reused. Normative scope therefore limits a
future handle to one publisher and protected session, with renewal-only reuse
inside that session. Default `Debug` fully redacts it, there is no `Display`, and
explicit bytes are documented as a trusted functional interface rather than an
approved logging surface. No new disclosed protocol claim exists yet.

## Dependency impact

No dependency, crate, feature, workflow, action, license boundary, I/O, parser,
or `unsafe` code is added. The type uses only the Rust standard library in the
existing Apache-2.0 `ogir-model` crate.

## Acceptance criteria

- Exact API/trait/visibility/redaction contract is implemented and documented.
- All 8,192 position/value cases and fixed whole-value controls pass.
- Required compile-fail and structural negative tests fail for their intended
  boundaries.
- All named mutations are killed with intended-cause evidence and cleanup.
- No production crate except `ogir-model` changes; agent, verifier, and protocol
  source remain byte-identical.
- Architecture, roadmap, trust, privacy, test strategy, ADR-0008, and issue/spec
  traceability agree on non-authority and deferred enforcement.
- No unsupported cryptographic uniqueness, secure erasure, or PoP claim exists.
- Full/release gates and fresh model/privacy/standards reviews pass.
- Live issue and PR use canonical taxonomy, AI disclosure, exact DCO, and human
  review gates.

## Primary sources

- RFC 9052 §3.1, COSE `kid` as a non-unique, structurally opaque lookup hint:
  https://www.rfc-editor.org/rfc/rfc9052.html#section-3.1
- RFC 8747 §§3.1, 3.4-3.5, one PoP key, application-specific `kid`, collision,
  freshness, and proof separation:
  https://www.rfc-editor.org/rfc/rfc8747.html
- RFC 9711, EAT/PoP separation and EAT privacy/profile considerations:
  https://www.rfc-editor.org/rfc/rfc9711.html
- Rust 1.98 visibility/privacy:
  https://doc.rust-lang.org/1.98.0/reference/visibility-and-privacy.html
- Rust 1.98 arrays and primitive array type:
  https://doc.rust-lang.org/1.98.0/std/primitive.array.html
- Rust API Guidelines, validated newtypes and static type distinctions:
  https://rust-lang.github.io/api-guidelines/

## Implementation evidence

This evidence is time-bounded to `2026-08-27T06:19:49-04:00` and the exact
unsigned pre-evidence tree named below. The separate Step 7 evidence commit
follows that tree and changes only this issue source.

### Exact checkpoint and scope

- Base: `9269b570ce83be01c1309469ff85fb79d4fa0c3d`.
- Unsigned pre-evidence head:
  `a63dbfbbb2b4931915c67ba107871fd757f38ad4`.
- Pre-evidence tree: `8307b3f4f510e098dc0b859908461443a436c9bf`.
- Base-to-head feature range: 12 commits, derived by
  `git rev-list --count 9269b570ce83be01c1309469ff85fb79d4fa0c3d..a63dbfbbb2b4931915c67ba107871fd757f38ad4`.
- All 12 feature commits were unsigned at this checkpoint: signature state
  `N`, zero `gpgsig` headers, and zero `Signed-off-by` trailers. DCO
  certification/rewrite, publication, and human line-by-line review remain
  pending.

### Executed tests and gates

- `./scripts/check.sh`: exit 0 with 115 runtime/integration tests, 80 doctests,
  14 unchanged attack scenarios, and 8 ADRs; repository metadata, ADR,
  bootstrap, DCO fixtures, scenario validation, rustfmt, workspace Clippy,
  rustdoc, and cargo-deny passed.
- `cargo test --workspace --all-features --release`: exit 0 with 115
  runtime/integration tests and 80 doctests.
- `cargo test -p ogir-model --test session_public_key_id`: 29/29 passed,
  including exactly 8,192 byte-position/value matrix cases.
- `cargo test -p ogir-model --doc`: one positive doctest and 19 compile-fail
  doctests passed.
- The seven core runtime/structural tests were:
  `exact_length_and_round_trip_are_fixed`,
  `every_fixed_whole_value_control_is_representable`,
  `copy_equality_inequality_and_hashing_are_plain_value_semantics`,
  `all_8192_position_value_cases_round_trip_without_normalization`,
  `debug_is_exact_fixed_redaction_for_real_sentinel_bytes`,
  `runtime_type_identity_is_distinct_from_nonce_and_session_id`, and
  `public_api_surface_is_pinned_to_the_approved_non_authority_contract`.

### Boundary and mutation proof

- Exact width is compiler-checked at 32 bytes; the private-field structural
  assertion and private-constructor compile-fail proof reject public storage.
- The 8,192-case matrix and fixed whole-value controls prove exact construction,
  access, copy, equality, inequality, and hash value semantics without
  normalization. Real sentinel bytes verify exact fixed `Debug` redaction.
- Runtime `TypeId`, compile-fail blocks, recursive source inventory, and exact
  token regions preserve distinction from `Nonce`/`SessionId` and the approved
  derive, constructor, accessor, trait, conversion, and non-authority surface.
- Numeric-literal grammar regressions cover decimal/base digits and suffixes,
  exponents, fractions, trailing-dot floats, `..`/`..=` ranges, field access,
  and non-ASCII identifier starts. Real Rust macro forms prove numeric ranges
  cannot hide target, `path`, `include`, or `trait` policy tokens.
- Round 8 restarted all 19 mutations from zero at the exact pre-evidence head:
  `L01 L02 F01 A01 A02 D01 D02 T01 T02 T03 T04 T05 T06 K01 K02 K03 K04
  K05 N01`. Result: 19/19 intended-cause kills, zero survivor, and zero
  wrong-cause row. Every probe used a detached worktree with a real non-symlink
  local Cargo target; every target, worktree, and temporary root was removed.

### No-drift, review, and claim boundary

- Fresh `git diff --exit-code` checks against the base prove
  `crates/ogir-agent`, `crates/ogir-verifier`, `crates/ogir-protocol`, `apps`,
  `sdk`, `.github/workflows`, all Cargo manifests, `Cargo.lock`,
  `rust-toolchain.toml`, `docs/THREAT_MODEL.md`, `docs/PROTOCOL.md`, and the
  14-file scenario corpus remained byte-identical where required.
- The fresh scoped model/API review reports the numeric finding Addressed, no
  new Critical/Important breakage, equivalence Yes, and readiness Yes. The
  independent privacy/standards review reports the same Addressed/no-new-
  breakage/equivalence-Yes/readiness-Yes verdict. AI review is evidence for the
  human reviewer, never human approval.
- This slice added no runtime threat control or attack scenario and no key
  generation, key resolution, proof of possession, result, permit, admission,
  cryptography, wire format, I/O, dependency, or `unsafe` behavior.
- This evidence makes no production-readiness, identifier-uniqueness,
  secure-erasure, or cheating-detection claim. The handle remains plain,
  non-authoritative lookup data whose future lifecycle and relying-party checks
  are deferred.
