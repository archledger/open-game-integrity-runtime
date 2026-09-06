# ADR-0016: Test-only ephemeral software key hierarchy for the mock protocol

- Status: Accepted
- Date: 2026-09-05
- Owners: Initial maintainer
- Related issues: [Local M2-016 issue](../../planning/issues/016-mock-protocol-specification.md); [approved design](../superpowers/specs/2026-09-05-m2-016-mock-protocol-specification-design.md)
- Supersedes: None
- Superseded by: None

## Context

M2 must exercise signed test challenges, signed mock evidence, permit
signing and validation, and session-key proof of possession without TPM
complexity and without selecting production signature or serialization
libraries (M2 design gate; protocol milestones 5 and 10). The workspace
today contains no key material, no signing, and no digest primitive, and
`deny.toml` denies wildcard dependencies, non-crates-io sources, and every
current external crate (`[bans] allow = []`), so even a dev-dependency would
be a policy event requiring its own review.

The human approved the M2-016 design on 2026-09-05, including this key
hierarchy and the working name `ogir-mock-keys`. Acceptance records the
decision; no crate, primitive, or key exists yet.

## Decision drivers

- The mock backend must generate, label, and use ephemeral software keys with
  deterministic replay for conformance work.
- Mock artifacts must be unmistakably non-production: no namespace, key id,
  or artifact may be reusable as production identity (milestone 10).
- `ogir-model` and all production crates must stay free of the mock key
  machinery and its primitive.
- The M2 attack-test categories that depend on signature or proof behavior
  need deterministic failure modes (wrong key, wrong scope, replay), not
  cryptographic strength.
- Zero new external dependencies.

## Options considered

### A: In-repo test-only crate with SHA-256 and keyed authentication

Selected. A new `publish = false` crate named `ogir-mock-keys` implements
SHA-256 and an HMAC-SHA256-style keyed authenticator from scratch, clearly
labeled test-only, with FIPS 180-4 test vectors for SHA-256. Mock
"signatures" are HMAC tags over `domain-tag || object-bytes` (ADR-0015).
Benefits: dependency-free, deterministic, small auditable surface, honest
about being a protocol-shape tool. Costs: the authenticator is symmetric, so
it is not a signature and must never be treated as one.

### B: Add a vetted crypto library as a dev-dependency (for example an
Ed25519 or HMAC crate)

Rejected for M2. It would either begin production library selection before
the design gate allows it or create a test-only dependency exception to the
bans policy without a security review; either way the decision belongs to the
post-M2 production selection ADR, not to the mock substrate.

### C: Toy asymmetric scheme written in-repo (toy RSA or a toy Edwards curve)

Rejected. Far more code to review, no additional protocol-shape value over a
keyed authenticator, and it creates a false impression of cryptographic
realism that this project's documentation discipline would then have to
continually disclaim.

## Decision

### Key classes (all test-only, all ephemeral)

- Verifier test signing key: issues signed test challenges and test permits.
  Key ids carry the `OGIR-MOCK` namespace.
- Test attester key: constructs signed mock evidence. Distinct key space
  from the verifier key; never interchangeable.
- Ephemeral session key: 32 bytes held only by the mock local key owner;
  its lookup handle is the existing `SessionPublicKeyId`. Never transmitted
  except for test-internal construction; the protocol only ever sees the id
  and proof results, matching ADR-0008.

### Generation, derivation, and lifetime

- Conformance mode: keys derive deterministically from an explicit seed via
  a documented HMAC-based derivation chain, so vectors are reproducible.
- Runtime test mode: keys generate from the test harness's existing seeded
  deterministic PRNG discipline (no ambient randomness, no wall clock).
- Lifetime is the test process. No persistence, no files, no reuse across
  runs unless the seed is explicit. Key material never appears in
  diagnostics; debug output prints only redacted placeholders.

### Authenticator construction

A mock signature is `HMAC-SHA256(key, domain-tag || object-bytes)` per the
ADR-0015 tags. Validation recomputes over the received bytes and compares
constant-time in the implementation slice (a correctness obligation, not a
production-timing claim). The session-key proof of possession is
`HMAC-SHA256(session-key, "OGIR-MOCK-POP-1" || permit-bytes || rechallenge
nonce)` where the rechallenge nonce is verifier-issued and single-use.

### Honest limitations, recorded as obligations

- Symmetric: any party holding the verifier test secret can mint valid
  mock permits. Attack tests therefore model key compromise at the mock key
  directory boundary (key ids, scopes, and the wrong-key mismatch test),
  not as a cryptographic property.
- No non-repudiation, no confidentiality, no side-channel resistance, no
  production fitness. Every public item's rustdoc and the crate root must
  state this and name this ADR.
- The crate must not appear in any production crate's dependency graph; the
  implementation slice adds a review gate (and, if practical, a workspace
  ban note) that `ogir-model`, `ogir-protocol`, `ogir-agent`, and
  `ogir-verifier` never depend on it. Mock protocol code that needs both
  lives in separate test binaries or a mock crate of its own.

### Placement

New crate `crates/ogir-mock-keys`, `publish = false`,
`unsafe_code = "forbid"`, workspace lints, no features. SHA-256 is
self-checked against official FIPS 180-4 vectors at test time.

## Consequences

M2 gains a fully deterministic, dependency-free mock substrate, and the
production selection ADR after M2 starts from a clean slate. The cost is
maintaining a small crypto primitive in-repo and the permanent discipline of
keeping it out of production graphs. The M2-017 slice implements it behind
this contract; the M2-019 conformance vectors depend on its deterministic
derivation.

## Threat-model impact

No production trust boundary changes. Within the mock threat model, the
symmetric-authenticator limitation is the accepted residual risk, mitigated
by directory-boundary modeling of key compromise. No new attacker class
gains any production capability.

## Privacy impact

None. No persistent identifiers, no new claims; key material and proofs are
redacted from diagnostics per existing rules.

## Dependency and license impact

None external. One new internal `publish = false` crate; no manifest
dependency additions; no license-boundary change (Apache-2.0 project code).

## Validation

FIPS 180-4 SHA-256 vectors; RFC 4231 HMAC-SHA256 vectors; deterministic
derivation reproducibility across two constructions; wrong-key, wrong-tag,
and bit-flip rejection tables; the ADR-0015 cross-tag matrix through this
authenticator; a structural check that no production crate depends on the
mock crate.

## Rollback

Before acceptance, revise or discard this decision without changing runtime
behavior. After acceptance, removal requires deleting the mock crate and its
dependents' test paths; nothing production-facing may reference it, so
rollback is a test-only revert. Promoting this primitive or its keys toward
production use is never a safe fallback and requires its own ADR.

## Primary sources

- [Protocol](../PROTOCOL.md) design milestones 5 and 10 (production
  selection deferred; experimental namespaces never reused).
- `deny.toml` `[bans]` policy.
- ADR-0005 (verifier-authoritative challenge freshness), ADR-0008
  (SessionPublicKeyId is a lookup handle), ADR-0013 (isolated mock replay
  cache, whose isolation discipline this crate mirrors), ADR-0014 (permit
  validity semantics the mock issuer applies).
- FIPS 180-4 (SHA-256) and RFC 4231 (HMAC test vectors), used only as test
  vector sources for the in-repo primitive.
