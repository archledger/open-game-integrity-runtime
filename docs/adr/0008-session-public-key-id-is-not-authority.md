# ADR-0008: Session public-key identifiers are not authority

- Status: Accepted
- Date: 2026-08-26
- Owners: Initial maintainer
- Related issues: [M1-007F](../../planning/issues/007f-session-public-key-id.md)
- Supersedes: None
- Superseded by: None

## Context

The M1 roadmap names `SessionPublicKeyId`, but the first identifier slice did
not define it. Later signed results and permits need a bounded way to refer to
one ephemeral protected-session public key. A raw byte array, generic string,
key encoding, thumbprint, or freely constructible composite can blur the line
between a key-selection hint and actual proof or authorization.

The result, permit, wire format, key algorithm, key-owning adapter, and
proof-of-possession validator do not exist yet. This decision therefore adds
only pure domain vocabulary and records the obligations of those future
owners and consumers.

## Decision drivers

- Preserve server-side authorization and proof-of-possession invariants.
- Prevent accidental interchange with `Nonce` or `SessionId`.
- Fix representation width without selecting a key or digest algorithm.
- Keep the model allocation-free, parser-free, serialization-neutral, and
  dependency-free.
- Redact a correlation-sensitive value from default diagnostics.
- Make the complete public and non-public surface mechanically reviewable.
- Preserve roadmap M1-011 for result and reason-code taxonomy.

## Options considered

### Fixed 32-byte opaque newtype

Selected. A private-field `[u8; 32]` newtype gives compile-time width and type
distinction without allocation, parsing, hashing, or cryptographic meaning.

### Variable-length bytes or canonical text

Rejected. Either choice introduces allocation, parsing, bounds, normalization,
or encoding policy before the M2 wire-profile gate.

### Public-key bytes, key thumbprint, or digest

Rejected. These choices require an algorithm and canonical key representation
and would imply a key commitment that byte equality alone does not provide.

### Composite session binding or `LocalSession` integration

Rejected. A freely constructible tuple would still be non-authoritative, while
changing the lifecycle graph before a real key-owning adapter exists would
claim enforcement the current pure model cannot provide.

### Premature proof or admission capability

Rejected. The future relying party must validate a fresh proof over the actual
resolved key and complete signed context. The local model cannot mint that
authority for itself.

## Decision

`ogir-model` defines `SESSION_PUBLIC_KEY_ID_LENGTH` as 32 and exposes
`SessionPublicKeyId` with one private `[u8; 32]` field. It derives only `Clone`,
`Copy`, `PartialEq`, `Eq`, and `Hash`; accepts every exactly sized array through
`from_bytes`; returns exact bytes only through `as_bytes`; and formats only as
`SessionPublicKeyId([REDACTED; 32])` through `Debug`.

The value is a non-authoritative application-specific lookup handle.
Construction, copying, equality, hashing, or byte access proves neither key
identity nor possession and cannot authorize a transition, result, permit, or
admission. No `Default`, `Display`, string, conversion, serialization, mutable,
generation, validity, proof, permit, or authority interface is included.

A future trusted local key owner creates one ephemeral key and handle for one
publisher and protected `SessionId`. The same key/handle may persist only
through renewal of that session. Terminal end/invalidation makes future use
invalid, and another session or publisher receives a new key/handle. Future
verifier/result code validates exact key binding; the relying party resolves
the actual key and validates fresh replay-resistant proof before admission.
The copyable M1 value does not enforce or erase this lifecycle.

## Consequences

The domain receives a small unambiguous type that prevents accidental
`Nonce`/`SessionId` interchange and keeps crypto/wire decisions deferred. The
cost is an OGIR-specific 32-byte profile and explicit mapping work in a future
protocol implementation.

Collisions and malicious/reused values remain possible. Future producers and
consumers must handle them through exact context, actual key resolution, signed
binding, freshness, and proof rather than assuming identifier uniqueness.

## Threat-model impact

No runtime threat is accepted or mitigated by this vocabulary-only decision,
so no attack scenario is added. It prevents design/API confusion but does not
yet stop A1 cross-session substitution, relay, replay, or missing proof. Those
threats remain owned by the future result, permit, and proof-validation paths.
A compromised future trusted local key owner remains A4 residual risk; a
compromised verifier or relying party remains A5 risk. Either can mishandle a
lookup handle despite the pure type contract.

## Privacy impact

The handle is not secret but can correlate activity when reused. Future scope
is therefore one publisher and one protected session, with reuse only for that
session's renewal. `Debug` fully redacts the value, `Display` is absent, and
`as_bytes` is a trusted functional interface rather than an approved logging
sink. M1-007F adds no wire disclosure or retention mechanism and makes no
secure-erasure claim.

## Dependency and license impact

The implementation uses only Rust fixed arrays and standard-library traits in
the existing Apache-2.0 `ogir-model` crate. It adds no dependency, feature,
crate, manifest, lockfile, parser, serializer, I/O, `unsafe`, or license-boundary
change.

## Validation

Validation requires seven dedicated runtime/structural tests, exactly 8,192
position/value cases, fixed whole-value controls, one positive and eighteen
single-cause compile-fail doctests added by this slice, exact diagnostic
sentinels, and all 19 disposable mutation probes. Full/release gates and fresh
model/API plus privacy/standards reviews must pass before issue evidence moves
to `needs-review`. No test may infer authority from constructibility or byte
equality.

## Rollback

Before publication, reverting the isolated feature commits is safe. After
merge, removing or changing the public type requires a deprecation/migration
issue. Any change to non-authority, lifecycle, privacy, or future consumer
obligations requires an ADR update or superseding ADR plus matching tests and
documentation.

Exposing raw diagnostics, adding implicit authority, reusing the handle
globally, or inferring a hash/key algorithm from its width is not an acceptable
rollback.

## Primary sources

- [Approved M1-007F design](../superpowers/specs/2026-08-26-m1-007f-session-public-key-id-design.md)
  defines the project-specific representation and authority boundary.
- [RFC 9052 section 3.1](https://www.rfc-editor.org/rfc/rfc9052.html#section-3.1)
  defines COSE `kid` as a non-unique, structurally opaque lookup hint rather
  than a security-critical field.
- [RFC 8747](https://www.rfc-editor.org/rfc/rfc8747.html) separates key-ID
  lookup from actual PoP validation and records collision, freshness, audience,
  segregation, and correlation obligations.
- [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html) distinguishes an EAT
  used alongside a PoP application from the PoP transaction itself.
- [Rust 1.98 visibility and privacy](https://doc.rust-lang.org/1.98.0/reference/visibility-and-privacy.html),
  [Rust 1.98 arrays](https://doc.rust-lang.org/1.98.0/std/primitive.array.html),
  and the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
  define the private-field, fixed-array, and newtype behavior used here.
