# M1-007F session public-key lookup handle design

- Status: Approved for implementation planning
- Date: 2026-08-26
- Base: `9269b570ce83be01c1309469ff85fb79d4fa0c3d`
- Issue source: `planning/issues/007f-session-public-key-id.md`
- Milestone: M1 Domain Model

## 1. Summary

M1-007F adds one missing pure-domain type: `SessionPublicKeyId`. It is an
exactly 32-byte, copyable, redacted, non-authoritative lookup handle for a
future ephemeral protected-session public key.

The handle is deliberately not the public key, a cryptographic thumbprint, a
digest, a proof of possession, a signed claim, a permit, or admission authority.
Its constructor validates only the Rust array width. Future trusted components
must generate the key/handle, scope it to one publisher/session, resolve the
actual key, validate fresh proof, and enforce lifetime.

This issue closes a missing M1-007 identifier deliverable without consuming the
roadmap's M1-011 identifier. The roadmap explicitly reserves task 11 for result
and reason-code taxonomy; that later task can consume `SessionPublicKeyId` under
the complete signed context.

The decision owner reviewed exact written-spec commit
`22e1181fd9fe6180cb162392655161971fb97f74` and explicitly approved it on
2026-08-26 with no requested change. This status follow-up records that
approval; it changes no approved design requirement and authorizes
implementation planning only. It does not authorize runtime implementation,
DCO certification, GitHub publication, or merge.

## 2. Context

The roadmap lists `SessionPublicKeyId` among M1 domain types, but M1-007 shipped
publisher, game, build, account, match, policy, session, and evidence-profile
identifiers without it. Architecture already requires:

- an ephemeral session public key derived by trusted local components;
- verifier appraisal of exact session-key binding;
- a signed result or permit bound to that key; and
- relying-party validation of proof of possession before admission.

Those later objects do not yet exist. Adding their authority behavior here
would cross the M1/M2 design gate and duplicate the responsibilities of the
future result, permit, and sample-server issues. Leaving the identifier absent,
however, encourages raw `[u8]`, `Vec<u8>`, strings, key bytes, or digests to be
used interchangeably.

The design therefore adds vocabulary only: one strongly typed handle with an
explicit non-authority contract and a documented future lifecycle.

## 3. Evidence and standards interpretation

### 3.1 COSE key identifiers are hints

RFC 9052 §3.1 defines `kid` as a binary string used to help find a key. It says
applications must not assume `kid` values are unique, cannot rely on internal
structure, and must not treat the field as security-critical by itself.

OGIR follows that authority model: `SessionPublicKeyId` can select candidate
key state, but security comes only from successfully validating the actual key
and its proof in the complete signed/audience/session context.

### 3.2 A PoP confirmation identifies one actual key

RFC 8747 defines confirmation methods for one PoP key. A `kid` representation is
valid only when the recipient can obtain the identified key and
cryptographically validate possession. It warns about collisions when the ID
is not cryptographically derived or not every party validates such a
derivation. It intentionally leaves the challenge/proof protocol to the
application and requires freshness/replay protection.

M1-007F implements none of those validation steps. It also does not claim that
32 bytes provide collision resistance. The future M2 profile must define key
resolution, audience, transcript, freshness, and collision handling.

### 3.3 Attestation and PoP remain separate

RFC 9711 allows attestation to accompany a PoP application but does not make an
attestation identifier equivalent to possession. RFC 8747's privacy
considerations warn that reusable PoP keys can become correlation handles.

OGIR therefore scopes the future key/handle to one publisher and protected
session. Renewal may retain that session's key, but another session or
publisher receives a fresh key and handle.

## 4. Goals

- Complete the missing `SessionPublicKeyId` M1 domain vocabulary.
- Make accidental type confusion with `Nonce` or `SessionId` impossible.
- Keep the representation fixed, allocation-free, parser-free, and
  serialization-neutral.
- Make the entire public API and trait surface small enough to pin structurally.
- Redact the complete value from default diagnostics.
- Record explicit future lifecycle and trust ownership without claiming the
  bare type enforces it.
- Prevent the type from resembling or producing authorization authority.
- Preserve roadmap task 11 for result/reason-code taxonomy.

## 5. Non-goals

M1-007F does not:

- generate, store, resolve, rotate, destroy, or zeroize keys;
- select a key type, signature algorithm, hash, RNG, or crypto library;
- define a public key, key encoding, thumbprint, or digest;
- define COSE/CBOR/JWK/CDDL/JSON serialization;
- add a variable-length or text parser;
- change local-session or verifier state machines;
- add a composite session-key binding;
- add evidence, result, permit, renewal, or admission fields;
- validate proof of possession or mint a PoP/admission capability;
- enforce lifecycle on copies of the handle;
- add networking, persistence, I/O, async, dependencies, or `unsafe`; or
- claim production security or secure memory erasure.

## 6. Alternatives considered

### 6.1 Fixed 32-byte opaque newtype — selected

```rust
pub struct SessionPublicKeyId([u8; 32]);
```

Advantages:

- one representation;
- no allocation or parsing;
- compile-time length enforcement;
- easy value semantics and exhaustive byte-position/value testing;
- compatible with a future application-defined binary wire representation;
- no required hash, key encoding, or crypto dependency.

Cost:

- the application profile fixes a 32-byte handle size;
- it cannot directly carry every generic COSE `kid` value;
- later protocol code must map between its canonical wire/key representation
  and this OGIR handle deliberately.

That cost is accepted because OGIR is defining its own bounded profile rather
than a generic COSE container.

### 6.2 Variable-length bounded bytes — rejected

A `Vec<u8>` or boxed slice would more closely model arbitrary COSE `kid`
values. It would also add allocation, empty/maximum-length errors, new parser
limits, more normalization questions, and speculative flexibility before the
protocol profile exists.

### 6.3 Canonical text identifier — rejected

Reusing the M1-007 ASCII text grammar would be simple but would introduce a
textual semantic and future encoding constraint that COSE does not require.
Base64/hex would be serialization, not pure identity.

### 6.4 Key thumbprint or digest — rejected

A thumbprint requires canonical key encoding plus a selected digest algorithm.
Those are M2 protocol/crypto decisions and would incorrectly imply that byte
equality is a validated key commitment.

### 6.5 Actual public-key bytes — rejected

Public-key representation varies by key type and encoding. Carrying it now
would select algorithms and create validation/serialization responsibilities.

### 6.6 Composite `SessionKeyBinding` — rejected

A public tuple of publisher/session/key handle could appear authoritative while
remaining freely constructible and incomplete. The future signed result/permit
has the full publisher/game/build/account/match/session/policy/audience context
and is the correct consumer.

### 6.7 Integrate into `LocalSession` now — rejected

The local lifecycle currently owns ordering only and has no key-owning adapter.
Adding a field or transition would imply enforced generation/lifetime without a
real producer and would unnecessarily reopen the reviewed M1-009 graph.

### 6.8 Add a placeholder PoP capability — rejected

The local agent cannot authoritatively validate its own proof, and the verifier
appraises evidence rather than admitting the game. The future M2 relying-party
permit validator owns the real validation and authority capability.

## 7. Public API

### 7.1 Constant

```rust
/// Session public-key lookup-handle length in bytes.
pub const SESSION_PUBLIC_KEY_ID_LENGTH: usize = 32;
```

The name describes the pure-domain handle, not a key/digest algorithm.

### 7.2 Type

```rust
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionPublicKeyId([u8; SESSION_PUBLIC_KEY_ID_LENGTH]);
```

The field is private. `Copy` and `Hash` are safe because the value is not secret
and grants no authority. Making it non-copyable would falsely suggest that
ownership enforces key use or lifetime.

### 7.3 Methods

```rust
impl SessionPublicKeyId {
    #[must_use]
    pub const fn from_bytes(
        bytes: [u8; SESSION_PUBLIC_KEY_ID_LENGTH],
    ) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(
        &self,
    ) -> &[u8; SESSION_PUBLIC_KEY_ID_LENGTH] {
        &self.0
    }
}
```

No validation error exists because Rust enforces the exact width and every
32-byte value is representable. All-zero is not rejected: generator quality,
collision policy, and reserved values belong to the future producer/profile.
Representation validation must not masquerade as key validity.

### 7.4 Debug

```rust
impl fmt::Debug for SessionPublicKeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionPublicKeyId([REDACTED; 32])")
    }
}
```

No byte, length-derived dynamic content, prefix, suffix, hash, or pointer is
formatted.

### 7.5 Intentionally absent interfaces

The type has no:

- `Default`;
- `Display`;
- `From`/`Into`;
- `AsRef`;
- `FromStr` or string constructor;
- serde or wire encoding;
- ordering traits;
- mutable byte accessor;
- generator;
- validity/authority boolean;
- result/permit/capability conversion; or
- runtime lifetime state.

Every future addition to this list requires a scoped issue and review.

## 8. Authority and trust boundaries

### 8.1 Constructibility is intentional

Any caller can construct any 32-byte handle. Therefore:

- construction proves nothing;
- equality proves only byte equality;
- hashing is only collection behavior;
- the handle cannot authorize a transition;
- the handle cannot validate a key; and
- the handle cannot create a result, permit, PoP, or admission token.

### 8.2 Future trusted producer

A future local key-owning adapter will:

1. create an ephemeral private/public key pair using approved M2 choices;
2. assign the application-specific handle;
3. associate key state with trusted `SessionId` and publisher context;
4. expose only necessary public/handle material;
5. retain the key across renewal for the same protected session; and
6. destroy/release key state when the session terminally ends.

None of these behaviors is implemented or claimed here.

### 8.3 Future verifier/result consumer

The future verifier must validate that appraised evidence binds the actual
public key under the same attempt/context. Result construction must consume the
M1-010 `VerifiedAttestation` capability and typed verified claims; it cannot
refill a client-supplied handle into an unrelated result.

### 8.4 Future relying-party consumer

The relying party must:

- validate the signed result/permit and audience/context;
- resolve the actual key rather than trust ID uniqueness;
- validate a fresh replay-resistant proof over the selected transcript; and
- only then mint or enact admission authority.

The handle alone never reaches that authority boundary.

## 9. Lifecycle contract

### 9.1 Scope

The future key/handle is scoped to exactly one publisher and protected
`SessionId`. Equal bytes in another publisher/session are not evidence of the
same key or valid binding.

### 9.2 Renewal

Renewal uses a fresh challenge while retaining the same ephemeral session key
and handle for that one active protected session. This matches the roadmap and
avoids an unnecessary key handover inside the active-session transition.

### 9.3 Terminal state

After `Ended` or `Invalidated`, trusted consumers must reject future use and the
future key owner must release/destroy ephemeral state. The copyable handle
cannot revoke its copies, so the type makes no enforcement or zeroization
claim.

### 9.4 New session and publisher isolation

A new protected session gets a new key and handle. A different publisher gets
a new key and handle. Reuse outside renewal of the same session violates the
normative privacy contract even though the bare type cannot prevent it.

## 10. Error model

M1-007F adds no runtime error type:

- wrong-length arrays fail at compile time;
- every correctly sized byte array constructs;
- key-generation, resolution, collision, missing state, terminal use, and PoP
  failures belong to future operations and must fail closed there.

Adding a fallible constructor would create representational policy without
improving authority. Adding a `bool is_valid()` would be actively misleading.

## 11. Privacy model

### 11.1 Correlation

The handle is privacy-sensitive even though it is not secret. Reuse can link
activity. Future producers therefore scope it to one publisher/session and
retain it only for that session plus its renewals.

### 11.2 Diagnostics

`Debug` is fixed redaction. `Display` is absent. Tests use actual nontrivial
sentinel bytes and forbid their full representation in diagnostics. The
explicit `as_bytes` method is a trusted functional boundary, not an approved
logging input.

### 11.3 Retention

The type has no storage or erasure behavior. Future owners must define finite
retention and terminal cleanup. M1-007F does not claim allocator zeroization or
that copied IDs disappear.

### 11.4 Disclosure

No protocol claim is added. Future result/permit work decides whether the
handle, actual key, or another canonical confirmation representation is signed
and disclosed.

## 12. Component and file boundaries

### 12.1 Production code

Only `crates/ogir-model/src/lib.rs` changes. The type remains in the existing
pure model crate.

### 12.2 Tests

Add `crates/ogir-model/tests/session_public_key_id.rs` for value, privacy,
finite-domain, type, and structural tests. Compile-fail examples live in the
type documentation where practical.

### 12.3 Documentation

Planned documentation changes:

- `planning/issues/007f-session-public-key-id.md`;
- this design specification;
- `docs/adr/0008-session-public-key-id-is-not-authority.md` plus ADR index;
- `docs/ARCHITECTURE.md` trust-source and protocol-object sections;
- `docs/ROADMAP.md` M1 completion/issue ordering clarification;
- `docs/TRUST_MODEL.md` key-handle trust/non-trust statement;
- `docs/PRIVACY_MODEL.md` per-session/publisher correlation limit;
- `docs/TEST_STRATEGY.md` finite/compile/structural/mutation proof; and
- `docs/LESSONS_LEARNED.md` only if implementation or review confirms a new
  mistaken assumption; no ceremonial lesson is required.

### 12.4 Unchanged components

No source change is permitted in:

- `ogir-agent`;
- `ogir-verifier`;
- `ogir-protocol`;
- applications;
- SDK/FFI;
- workflows; or
- attack-scenario schema/corpus.

## 13. Test design

### 13.1 RED-first sequence

1. Add a test import/use of the absent `SessionPublicKeyId`; confirm compilation
   fails for the missing type.
2. Add fixed API/value/privacy tests and confirm the implementation is absent.
3. Implement the smallest complete type.
4. Keep all later documentation/runtime integration absent.

The RED evidence records exact compiler errors and test counts.

### 13.2 Positive value tests

- `from_bytes`/`as_bytes` exact round trip;
- copied value equals original;
- distinct bytes compare unequal;
- equal values hash to one set entry and distinct controls remain distinct;
- all-zero, all-`0xff`, alternating, ascending, and descending controls;
- `Debug` exact marker.

### 13.3 Finite position/value matrix

For each of 32 positions and each `u8` value 0 through 255:

1. start from a nonuniform fixed baseline array;
2. replace only that position with the selected value;
3. construct and copy the handle;
4. require exact byte round trip;
5. require equality/hash stability; and
6. require fixed Debug redaction without any baseline or changed byte sequence.

This executes exactly 8,192 cases. It is a finite semantic test, not random
fuzzing.

### 13.4 Compile-fail contracts

Single-cause compile-fail examples cover:

- `[u8; 31]` construction;
- `[u8; 33]` construction;
- passing the handle where `Nonce` is required;
- passing the handle where `SessionId` is required;
- `SessionPublicKeyId::default()`;
- `{id}`/`Display` formatting;
- string parsing/construction;
- implicit array conversion; and
- mutable/authority-like methods that do not exist.

Compiler output must be inspected so privacy/type errors are not masked by an
unrelated failure.

### 13.5 Structural API test

A CRLF-normalized source assertion pins:

- exact derive list;
- private tuple field;
- exact constant use;
- only `from_bytes` and `as_bytes` in the public impl;
- exact fixed Debug implementation; and
- absence of `Default`, `Display`, string, serialization, mutable, generator,
  validity, result, permit, or authority interfaces.

The structural guard complements compile-fail tests where Rust cannot directly
assert that a method or trait will never be added.

### 13.6 Privacy mutant

Change `Debug` to emit `REDACTED` plus actual sentinel bytes. The focused
privacy test must execute and fail on the actual full representation, not merely
on a stale literal or missing marker.

### 13.7 Mutation probes

At a frozen exact head, disposable worktrees apply one mutation at a time:

| ID | Mutation | Required detector |
| --- | --- | --- |
| `L01` | length 31 | constant/API/matrix/compile contract |
| `L02` | length 33 | constant/API/matrix/compile contract |
| `F01` | tuple field public | structural privacy test |
| `D01` | raw Debug | actual sentinel privacy test |
| `A01` | accessor returns altered bytes | round-trip/matrix test |
| `T01` | add `Default` | structural/compile surface test |
| `T02` | add `Display` | structural/compile surface test |
| `T03` | add implicit/string/serialization interface | structural surface test |
| `K01` | add authority-like validity/conversion method | structural surface test |

Every command must execute the named detector and fail for the intended cause.
All worktrees are removed after recording output.

### 13.8 No fuzz target

There is no untrusted parser, variable length, allocation, or wire input. The
fixed array and complete position/value matrix are more appropriate than a fuzz
target. Future serialization receives its own bounded parser/fuzz issue.

### 13.9 No attack scenario

This vocabulary slice accepts no new runtime threat and implements no threat
control. It records design/quality failures and preserves existing threat
scenarios. Result/permit/PoP issues must add the cross-context, replay, relay,
and missing-proof scenarios when those behaviors exist.

## 14. Traceability

### 14.1 Invariants

- 1-5: the handle is explicitly non-authoritative and cannot substitute for
  result/permit/PoP.
- 36-37: publisher/session scope and complete diagnostic redaction.
- 47-48: permanent regression and full AI/human/DCO review.

### 14.2 Roadmap

- M1 domain types: supplies the missing `SessionPublicKeyId`.
- M1 tests: adds exact-length/type/privacy proof.
- M1 exit: records the trust source and rejects client authority.
- First-30 issue 7: identifier follow-up.
- First-30 issue 11: unchanged result/reason taxonomy consumer.

### 14.3 ADR

ADR-0008 will record the durable decision that `SessionPublicKeyId` is an
opaque non-authoritative handle and that actual key commitment/PoP/admission
remain later boundaries.

## 15. Implementation and review workflow

1. Work from isolated `research/m1-007f-session-public-key-id` based on exact
   merged main `9269b570ce83be01c1309469ff85fb79d4fa0c3d`.
2. Commit this approved issue/design documentation unsigned.
3. Self-review placeholders, contradictions, ambiguity, scope, sources, and
   file/dependency boundaries.
4. Stop for human written-spec approval.
5. Use the writing-plans skill to create a detailed negative-test-first plan.
6. Stop for plan/execution approval before code.
7. Create the live issue only through guarded exact local/live synchronization
   at the plan's chosen point.
8. Implement in reviewed incremental unsigned commits.
9. Run named mutations, full/release gates, and fresh model/privacy/standards
   reviews.
10. Freeze and print the exact unsigned DCO range; never infer certification.
11. After exact human certification, create immutable backup evidence, rewrite
    metadata only, prove equivalence, rerun gates/review, and publish non-force.
12. Preserve `Human-Reviewed-Every-Line: no` and responsibility unchecked until
    the human actually reviews and authorizes merge.

## 16. Dependencies and license

The design adds no dependency. Implementation uses only the Rust standard
library and existing `ogir-model`. All affected files are Apache-2.0. No Cargo
manifest or lockfile change is permitted.

## 17. Residual risks and deferred decisions

- A compromised future trusted key owner can assign misleading or reused
  handles; this type cannot make its producer honest.
- Handle collisions are possible and must be handled by future key resolution
  and actual cryptographic proof.
- Equal handle bytes do not prove equal keys, sessions, publishers, or validity.
- Copies cannot be revoked or erased by the type.
- The exact key encoding, crypto algorithms, transcript, audience, proof,
  result, permit, and admission contract remain M2/later work.
- Per-session/publisher lifecycle is normative until a real owner enforces it.

## 18. Rollback

Before publication, revert the isolated unsigned commits or discard the branch
only with explicit user direction. After merge, removing or changing the public
type requires a deprecation/migration issue and, if authority semantics change,
a superseding ADR.

It is never an acceptable rollback to:

- expose raw Debug;
- turn the ID into authority;
- reuse it globally;
- infer a hash/key algorithm from its width; or
- add parsing/serialization without the protocol design gate.

## 19. Acceptance summary

M1-007F is complete only when:

- exact API/non-API contract exists;
- finite/compile/structural/privacy tests pass;
- all named mutations are killed for intended causes;
- only `ogir-model` production source changes;
- docs/ADR/trust/privacy/roadmap agree;
- no crypto/wire/authority/lifetime-enforcement claim slips in;
- full/release/dependency/license gates pass;
- independent reviews are clean;
- local/live issue and PR evidence are exact;
- DCO certification is human and range-specific; and
- merge occurs only after line-by-line human review/responsibility.

## 20. Primary sources

- [RFC 9052 §3.1](https://www.rfc-editor.org/rfc/rfc9052.html#section-3.1)
- [RFC 8747](https://www.rfc-editor.org/rfc/rfc8747.html)
- [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html)
- [Rust 1.98 visibility and privacy](https://doc.rust-lang.org/1.98.0/reference/visibility-and-privacy.html)
- [Rust 1.98 arrays](https://doc.rust-lang.org/1.98.0/std/primitive.array.html)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [OGIR security invariants](../../SECURITY_INVARIANTS.md)
- [OGIR architecture](../../ARCHITECTURE.md)
- [OGIR roadmap](../../ROADMAP.md)
- [OGIR trust model](../../TRUST_MODEL.md)
- [OGIR privacy model](../../PRIVACY_MODEL.md)
- [ADR-0006](../../adr/0006-local-session-lifecycle-capabilities.md)
- [ADR-0007](../../adr/0007-verifier-flow-capabilities.md)
