# M1-012 Evidence-binding transcript inputs design

- Status: Approved for implementation planning
- Date: 2026-08-31
- Related roadmap task: M1-012, define binding-transcript inputs without choosing crypto
- Decision owner: Initial maintainer

## Summary

M1-012 defines the semantic inputs that profile-specific evidence must bind for
one OGIR verifier appraisal attempt. It does not define bytes, an ordered wire
transcript, a digest, a signature input, a cryptographic algorithm, or a Rust
runtime type.

The canonical domain term is **Evidence-binding transcript**: the closed
semantic claim set that one evidence mechanism must cover for one appraisal
attempt. The existing `EvidenceBundle` remains outside that transcript as the
profile-specific evidence carrier. This separation avoids making a bundle
containing proof material recursively cover itself.

The attester constructs and covers one semantic transcript. The verifier
independently reconstructs the expected transcript from the authenticated
complete `PublisherChallenge`, the registered evidence-profile contract, the
received profile claims and provenance, and the actual session public key plus
its `SessionPublicKeyId` association. All received material remains untrusted
until structure, coverage, provenance, key association, and appraisal checks
succeed.

`ExpectedContext` remains outside the transcript as the relying party's
independent exact comparator. Evidence creation and validity time remains
distinct from challenge time. Its trusted producer, clock, interval rules, and
rollback behavior require a separately approved design before any transcript
representation or proof implementation is authorized.

## Conversation-level approval record

On 2026-08-31, the decision owner approved the following architectural
directions in sequence:

- define pre-appraisal evidence-binding inputs rather than result-binding or a
  combined evidence/result transcript;
- bind the complete typed `PublisherChallenge` semantics rather than an
  undefined challenge digest or a copied field subset;
- keep M1-012 normative and semantic because actual public-key and manifest-
  commitment representations do not yet exist;
- keep `ExpectedContext` outside the attester-originated transcript as the
  relying party's exact-match comparator;
- keep evidence creation and validity time distinct from challenge time, with
  the unresolved evidence-time authority treated as a blocker rather than a
  permissive default;
- keep `EvidenceBundle` outside the transcript as the profile-specific carrier
  whose evidence covers the transcript;
- bind both the abstract actual session public key and its
  `SessionPublicKeyId` association without treating the handle as a key,
  digest, commitment, or proof;
- use one mandatory core plus a registered profile's closed typed claim set;
- define semantic protocol-purpose separation now while deferring literal
  domain-separation labels and byte encodings;
- require attester construction and independent verifier reconstruction;
- bind exact appraised manifest and measurement identities as semantic values,
  not unspecified digest bytes or value-less commitments; and
- keep M1-012 delivery documentation-only, with no Rust type, dependency,
  serializer, cryptographic primitive, I/O, persistence, or authority path.

This approval authorizes writing this local candidate specification. It does
not authorize a branch, commit, live GitHub issue, implementation plan,
runtime implementation, DCO certification, publication, pull request, or
remote mutation.

On 2026-08-31, the decision owner reviewed and approved the exact written
candidate with SHA-256
`60fb29682e939d1b259b84033c113b3096a9e734541b5a0634e8733deebfe591`
without requesting a change. That approval authorizes documentation-only
implementation planning under the evidence-time prerequisite. It does not
authorize a branch, commit, live GitHub issue, execution, DCO certification,
publication, pull request, or remote mutation.

## Security objective

Future OGIR evidence must be unusable after substitution of any security-
relevant semantic input. An accepted profile mechanism must establish coverage
of one exact challenge, one exact evidence profile, one exact appraised subject,
one exact claim and provenance set, and one actual session-key association.

The design must prevent these classes of semantic ambiguity:

- challenge-field substitution hidden behind an undefined digest;
- profile substitution or downgrade;
- omission, duplication, or invention of evidence claims;
- provenance-class confusion between hardware-certified, measured-log-derived,
  and trusted-agent-observed claims;
- manifest or live-session substitution;
- actual-key substitution while retaining an equal handle;
- handle substitution while retaining an equal actual key;
- cross-publisher, cross-session, cross-match, or cross-policy reuse;
- treating attester-controlled values as relying-party authority;
- treating challenge time as evidence creation or validity time;
- treating proof coverage as successful policy appraisal;
- reusing evidence-binding proof as a protected result, permit, renewal
  authorization, or session proof of possession; and
- expanding the evidence vocabulary or disclosure set through profile payload
  conventions.

The transcript is necessary evidence-binding input. It is not independently
sufficient for an allowed `AppraisalResult`, protected `AttestationResult`,
permit, proof of possession, matchmaking admission, or disciplinary action.

## Scope

### Included

- canonical semantic terminology for an evidence-binding transcript;
- the external relationship between the transcript and `EvidenceBundle`;
- semantic purpose separation from results, permits, renewal authorization, and
  proof of possession;
- the complete mandatory input vocabulary;
- registered profile claim-set and provenance rules;
- actual session-public-key and lookup-handle association semantics;
- exact semantic manifest and measurement identities;
- attester construction and independent verifier reconstruction;
- required cross-input relationships;
- initial-appraisal and same-session-renewal semantics;
- fail-closed error classification consistent with M1-011;
- privacy, disclosure, diagnostic, and future-retention constraints;
- positive, negative, property, mutation, and attack-scenario requirements;
- explicit documentation and ADR synchronization requirements; and
- a named evidence-time authority prerequisite.

### Excluded

- a Rust `EvidenceBindingTranscript` type or any other runtime type;
- changing `EvidenceBundle`, `VerificationRequest`, `PublisherChallenge`,
  `ExpectedContext`, `VerifiedAttestation`, or `AppraisalResult`;
- actual public-key encoding, key algorithm, signature algorithm, or key
  generation;
- manifest canonicalization, digest algorithm, commitment representation, or
  commitment algorithm identifiers;
- literal domain-separation strings, byte labels, field ordering, or framing;
- serialization, parsing, canonical encoding, media types, CBOR, COSE, CDDL,
  JSON conformance objects, or duplicate-wire-field behavior;
- evidence proof generation or validation;
- TPM quote or qualifying-data construction;
- protected-result commitment, verifier identity, result signature, result
  issued-at/expiry, or trusted protected-result issuer behavior;
- permit issuance or validation, session-key resolution adapters, live proof of
  possession, matchmaking admission, renewal permits, or revocation lifecycle;
- a production clock, persistence, storage, retention enforcement, backup,
  networking, async runtime, privilege, `unsafe`, or dependency; and
- production-readiness, cryptographic-security, or universal-assurance claims.

Roadmap task 13 owns abstract JSON conformance fixtures. M2 owns representation,
algorithms, integrity protection, canonical wire behavior, parsing, and
differential validation. M3 owns TPM-specific binding mechanisms.

## Canonical domain language

### Evidence-binding transcript

The closed semantic claim set that one evidence mechanism must cover for one
appraisal attempt. It defines meanings and required relationships, not bytes,
ordering, hashing, signing, or serialization.

### Evidence carrier

The profile-specific `EvidenceBundle` that transports claims and the material
needed for a profile mechanism to establish transcript coverage. The carrier is
not itself a transcript input.

### Profile contract

The immutable semantic definition named by one `EvidenceProfile`: its exact
required claims, allowed provenance for each claim, coverage requirements,
assurance meaning, and disclosure class. Changing those semantics requires an
explicit protocol/profile version transition or a new profile identity.

### Semantic identity

The exact meaning of an appraised boot, runtime, game, process, enforcement, or
session state before any canonical source representation or compact commitment
is selected. A semantic identity is not an arbitrary `Vec<u8>`, a digest with an
unstated algorithm, or a marker that merely claims a commitment exists.

### Coverage

The profile-specific security property that changing any transcript semantic
causes profile validation to fail. M1-012 requires coverage but does not choose
the mechanism that supplies it.

### Key association

The trusted assertion that one `SessionPublicKeyId` identifies one abstract
actual session public key for one publisher and protected session. The handle
is not a commitment to the key and cannot establish this association by byte
equality alone.

## Roles and trust boundaries

### Publisher challenge issuer

The publisher-controlled issuer creates the complete `PublisherChallenge`,
including its nonce and validated window, and durably registers the challenge
under ADR-0005 before returning it. Challenge semantics are untrusted until the
publisher authentication gate succeeds.

### Relying party

The relying party supplies `ExpectedContext` independently of client evidence.
It remains authoritative for publisher, game, build, account scope, match, and
selected policy expectations. It does not supply transcript evidence claims.

### Trusted local key owner

A future trusted local owner creates and retains the actual ephemeral session
key and assigns its `SessionPublicKeyId`. It supplies the key association to the
attester and later trusted verifier/result consumers. The game and client are
never authoritative for this association.

### Trusted evidence producers

Profile-registered collectors produce claims from TPM-certified state,
measured logs, or trusted local observation. Each claim retains its provenance
class. A producer cannot upgrade trusted-software observation into hardware-
certified evidence through a label.

### Attester

The attester obtains the authenticated challenge input, profile selection, key
association, evidence-time input, and exact profile claims. It constructs one
semantic transcript and supplies a profile-specific evidence carrier intended
to establish coverage of that transcript. Its output crosses an untrusted
network and parser boundary in later work.

### Publisher verifier

The verifier authenticates the challenge, checks authoritative freshness and
independent expected context under ADR-0005, resolves the registered profile and
key association, reconstructs the expected semantic transcript, validates
profile coverage and provenance, and separately appraises claims, revocation,
and policy. Profile evidence never authorizes itself merely by being present.

### Future protected-result issuer

The issuer is outside M1-012. It may create a protected `AttestationResult` only
after provenance, appraisal, validity, commitment, and protection contracts are
defined. An evidence-binding transcript is not a generic signer input.

## Selected architecture

### External evidence carrier

`EvidenceBundle` remains outside the semantic transcript. The bundle can carry
the claims and profile-specific proof material needed to establish coverage,
but the complete bundle or payload is not one of the covered semantic inputs.

This avoids the recursive structure in which a bundle containing proof over a
transcript would need to include that same proof inside the transcript it
covers. It also avoids making transport framing, parser behavior, or future
non-semantic envelope fields security-critical by accident.

The exclusion does not mean the evidence instance is unbound. The profile
mechanism must cover the exact semantic claims extracted from that instance,
including their provenance, manifest identities, evidence-time semantics, and
key association.

### Construct and reconstruct

The attester and verifier do not share authority merely because they produce
equal values.

The attester constructs the semantic transcript that its profile evidence is
intended to cover. The verifier independently reconstructs the expected
semantic transcript from:

- the authenticated complete challenge;
- the registered profile contract;
- profile-decoded claims and provenance classifications;
- the resolved actual-key and handle association; and
- the profile-required evidence-time input.

Decoded values remain untrusted candidates while reconstruction occurs.
Coverage validation establishes that the profile mechanism covered those exact
candidates. Separate provenance and appraisal checks establish whether the
claims are acceptable and satisfy policy.

An attester-supplied serialized transcript, if a future profile carries one,
cannot replace independent reconstruction. Later wire work may compare a
decoded representation with the reconstructed semantic value, but equality of
attester-controlled bytes is not authority.

### Semantic purpose separation

M1-012 defines five distinct semantic purposes:

1. evidence binding;
2. protected Attestation Result integrity;
3. permit authorization;
4. session proof of possession; and
5. renewal authorization.

The evidence-binding transcript belongs only to the first purpose. Later
profiles must assign unambiguous representation-level domain separation so that
proof or integrity material from one purpose cannot validate for another.

M1-012 does not select literal labels or bytes. It requires the later M2 design
to provide distinct, versioned, canonical representations for these purposes.

## Closed semantic transcript

The conceptual semantic shape is:

```text
Evidence-binding transcript
  purpose: OGIR evidence binding
  challenge: complete PublisherChallenge
  evidence profile: one registered EvidenceProfile
  session key association:
    actual ephemeral session public key
    SessionPublicKeyId
  evidence time:
    profile-required creation/validity semantics
  claims:
    exact profile-required closed claim set
    exact provenance class for each claim
```

This notation is explanatory. It is not a Rust declaration, field order,
serialized map, signing structure, or canonical encoding.

### Purpose and protocol semantics

The purpose is fixed to OGIR evidence binding. It is not caller-selected.

The complete challenge already contains `ProtocolVersion`; M1-012 does not add
a second potentially divergent protocol-version field. A future representation
must bind the evidence-binding purpose together with the complete challenge
semantics, including its protocol version.

### Complete PublisherChallenge

The transcript binds the complete typed `PublisherChallenge` aggregate as one
semantic input. For the current model, that aggregate contains:

- protocol version;
- publisher identifier;
- game identifier;
- exact build identifier;
- publisher-scoped account binding;
- match or protected-session identifier;
- policy identifier and policy version;
- nonce; and
- validated challenge window.

No `challenge_digest` semantic exists in M1-012. No caller may copy a subset of
challenge fields into a second structure and claim equivalence. If the typed
challenge contract changes, the transcript design and profile versioning must
be reviewed explicitly rather than silently inheriting or omitting fields.

The publisher signature, future verifier identity, and future server channel-
binding material are not current `PublisherChallenge` model semantics and are
not invented by this design. Their future addition requires a separately
reviewed typed challenge change.

### Evidence profile

The transcript binds one exact `EvidenceProfile`. That identifier names a
registered immutable semantic contract. The profile defines:

- its exact required claims;
- the allowed provenance class for each claim;
- whether any claim is a set and its semantic uniqueness rules;
- its assurance meaning and exclusions;
- its disclosure class and local maximum-disclosure compatibility;
- the evidence-time semantics it requires; and
- the future profile-specific coverage-validation obligation.

M1-012 defines no optional arbitrary extension map. A profile may use only the
fixed OGIR claim vocabulary. A semantic profile change requires explicit
versioning or a new identifier; it cannot be hidden behind unchanged profile
text.

### Session key association

The transcript binds both:

- the abstract actual ephemeral session public key; and
- the `SessionPublicKeyId` assigned by the trusted key owner.

Binding only the handle is insufficient because ADR-0008 defines it as a
representation-only lookup identifier, not a key commitment or proof. Binding
only the actual key leaves a later handle-to-key remapping seam. Binding both
makes the asserted relationship part of the evidence semantics while preserving
the requirement that the verifier independently resolve and validate it.

M1-012 does not choose a key algorithm, byte encoding, fingerprint, thumbprint,
or proof mechanism. Every actual key representation remains deferred.

The private key is never a transcript input, evidence claim, diagnostic value,
fixture, or verifier output.

### Profile-required claims

Every profile declares one complete required claim set selected from the
following closed semantic vocabulary:

| Claim | Requirement | Exact semantic meaning |
| --- | --- | --- |
| Attesting agent identity | Base | The exact accepted local attesting-agent implementation or build identity used for this evidence instance. |
| Platform identity | Base | The exact appraised platform-profile identity, including the assurance class the verifier is evaluating. |
| Boot measurement identity | Base | The exact appraised boot state reconstructed or certified under the profile. |
| Runtime manifest identity | Base | The exact appraised Proton/runtime component set and state. |
| Game manifest identity | Base | The exact appraised game executable and component set and state. |
| Process binding identity | Base | The exact race-resistant live game process-tree subject to which evidence applies. |
| Protected-session identity | Base | The exact trusted local protected session and lifecycle subject to which evidence applies. |
| Enforcement policy state | Base | The exact selected local protected-session policy and observed enforcement state. |
| Attestation identity | Profile-specific | The exact publisher-scoped attestation identity under which the profile mechanism is validated. It is never a universal device identifier. |
| Runtime measurement identity | Profile-specific | The exact appraised dynamic/runtime measurement state required by the profile. |

The names above are normative meanings, not wire field names, Rust identifiers,
or commitments. Profile assurance and privacy disclosure class remain part of
the registered profile contract rather than caller-supplied claims.

Every profile requires every Base claim. The registered profile contract may
add any Profile-specific claim, after which that claim is required for that
profile. The contract selects exactly one allowed provenance class for every
required claim. No profile may remove a Base claim, make a required claim
optional at runtime, or define a profile-local claim name or meaning outside
this table. Expanding the table is a fixed-vocabulary and privacy-boundary
change requiring explicit architecture, threat, privacy, profile-version, and
scenario review.

Every required claim must appear semantically exactly once. A set-valued claim
uses the profile's exact uniqueness and equality rules; byte ordering remains a
later representation concern. A profile cannot omit a required claim, duplicate
one meaning through aliases, add undeclared claims, or reclassify provenance.

### Provenance classes

Each claim binds exactly one provenance class:

- **hardware-certified**: directly covered by accepted hardware-backed
  attestation semantics;
- **measured-log-derived**: reconstructed from a measured log and checked
  against certified rolling state; or
- **trusted-agent-observed**: independently observed by trusted local software.

These classes describe evidence origin and assurance limits. They are not
interchangeable strength labels. The verifier must reject a claim whose actual
profile validation path does not satisfy its declared provenance.

### Semantic manifest and measurement identities

M1-012 binds exact appraised meanings for boot, runtime, game, and protected-
session state. It deliberately does not bind an untyped digest field.

Later commitment work must first define:

- the canonical source object or set being identified;
- inclusion, exclusion, ordering, path, namespace, and metadata rules;
- versioning and ambiguity behavior;
- the commitment algorithm and algorithm identifier;
- domain separation between different manifest families; and
- validation against independently derived or approved references.

Only then may a compact commitment represent the semantic identity defined
here. A raw byte vector or a marker named `commitment` cannot satisfy this
contract by itself.

### Evidence creation and validity time

Evidence creation and validity semantics are mandatory transcript input, but
their authority design is intentionally not selected here.

They are distinct from:

- challenge `issued_at` and `expires_at`;
- verifier `now` used for challenge freshness;
- future protected-result `issued_at` and `expires_at`; and
- permit or renewal validity.

M1-012 does not infer equality, ordering, or an allowed interval between these
time domains. It does not copy `ChallengeWindow` into an evidence-time field.

A separately approved design must define:

- the trusted producer of evidence creation time;
- the authoritative clock or freshness mechanism;
- whether evidence has an instant, interval, sequence, or profile-specific
  temporal relation;
- maximum age and future-time behavior;
- rollback, restart, unavailable, and disagreement behavior;
- renewal behavior; and
- privacy and retention implications.

Until that design is approved, no transcript runtime representation, evidence
proof implementation, or protected-result issuer may use a placeholder time or
omit the temporal input.

## Excluded semantic inputs

The following values do not belong in the evidence-binding transcript:

### ExpectedContext

`ExpectedContext` is independently supplied relying-party authority. The
verifier compares it exactly with the authenticated challenge under the
existing freshness path. Including it as attester-originated evidence would
duplicate authority and invite confused-deputy substitution.

### Verifier evaluation time

Verifier `now` is publisher-authoritative input to challenge freshness state.
It is not evidence creation time and is not attester-originated evidence.

### EvidenceBundle payload or complete envelope

The bundle is the evidence carrier. Its covered semantic claims are transcript
inputs; transport framing, proof bytes, and the complete envelope are not.

### Appraisal and result values

`Decision`, `ReasonCode`, `VerificationOutcome`, `VerifiedAttestation`,
`AcceptedClaims`, `AppraisalResult`, and future protected-result values occur
during or after appraisal. They cannot be inputs to the pre-appraisal evidence-
binding transcript.

### Protected-result identity, validity, and protection

Future verifier identity, result issued-at/expiry, evidence commitment,
signature or integrity protection, and protected-result wire semantics belong
to the trusted issuer and M2 design.

### Permit and admission values

Permit fields, permit validity, transport-channel binding, proof-of-possession
challenge/response, and matchmaking admission belong to later relying-party
protocol domains.

### Private or unrelated host data

Private keys, unrelated process lists, personal files, browser or chat data,
biometric material, raw universal device identity, and arbitrary publisher
queries are prohibited by the fixed evidence vocabulary and privacy model.

## Required relationships

Field presence does not establish a valid transcript. These relationships are
mandatory:

1. The challenge must authenticate under publisher policy.
2. Every shared challenge field must equal independent `ExpectedContext` before
   the existing freshness claim path proceeds.
3. The verifier must accept the exact registered `EvidenceProfile` under its
   configured policy.
4. The claim set must equal that profile's complete required claim set.
5. Every claim must use the profile-required provenance class and must be
   supported by the corresponding profile validation path.
6. The actual session public key and `SessionPublicKeyId` must be one trusted-
   owner association for the same publisher and protected session.
7. Game, runtime, process, enforcement, and session claims must describe one
   live appraisal subject.
8. Overlapping build, publisher, policy, match, and session meanings must agree
   with the authenticated challenge.
9. Boot, runtime, game, and protected-session manifest identities must be the
   exact identities appraised under the selected profile.
10. The profile mechanism must cover the exact reconstructed transcript. A
    change to any semantic input must produce coverage failure.
11. Coverage validation and claim appraisal must remain separate. Valid
    coverage cannot turn an unacceptable claim set into policy success.
12. No temporal relationship between challenge time and evidence time is
    accepted until the evidence-time authority prerequisite is resolved.

## Verifier processing contract

M1-012 does not change the current verifier state machine. A later
implementation must preserve this semantic order:

1. Receive the challenge, evidence carrier, independent expected context, and
   verifier-authoritative challenge time.
2. Authenticate the complete challenge.
3. Execute ADR-0005 authoritative-time, strict-window, exact-context, and
   irreversible nonce-claim behavior.
4. Resolve the registered profile contract.
5. Decode or otherwise obtain the profile's candidate claims, provenance, key
   association, and evidence-time semantics under later bounded parser rules.
6. Reject missing, duplicate, undeclared, contradictory, or unsupported-
   critical semantics.
7. Independently reconstruct the expected semantic transcript.
8. Validate profile-specific coverage of that exact transcript.
9. Validate provenance and appraise claims.
10. Validate the actual-key, handle, publisher, and protected-session
    association.
11. Continue revocation and selected-policy gates.
12. Only the completed existing gate path may create `VerifiedAttestation` and
    an allowed `AppraisalResult`.

Steps 5 through 10 may require profile-specific internal sequencing when a
future proof mechanism is selected. That sequencing must preserve all stated
relationships and cannot treat an unvalidated claim as authority.

## Initial appraisal and renewal

### Initial appraisal

One initial appraisal uses:

- one fresh complete publisher challenge;
- one newly created actual session key and lookup handle for the publisher and
  protected session;
- one registered profile contract;
- one complete profile-required claim/provenance set;
- one evidence-time semantic value under the future authority contract; and
- one profile evidence carrier covering the reconstructed transcript.

### Same-session renewal

Renewal creates a new evidence-binding transcript with a fresh complete
challenge. The same actual key and `SessionPublicKeyId` may repeat only when all
of these are true:

- publisher identity is unchanged;
- protected `SessionId` and live session subject are unchanged;
- renewal belongs to the existing session lifecycle;
- selected policy is not silently weakened;
- the new profile claim set describes the current live state; and
- the future evidence-time authority contract accepts the new evidence.

Any new publisher or protected session requires a new key and handle. Renewal
does not authorize replay of the prior evidence carrier or transcript. The
fresh challenge remains irreversibly single-use under ADR-0005.

## Failure semantics

M1-012 adds no new `Decision`, `ReasonCode`, denial variant, or verifier state.
Later implementation maps failures through the existing coarse, non-
disciplinary taxonomy:

| Condition | Existing semantic class |
| --- | --- |
| Missing, duplicate, undeclared, contradictory, or structurally invalid transcript semantics | Malformed |
| Unsupported profile contract or unknown critical semantic | Unsupported |
| Challenge and independent relying-party context disagree | Context binding mismatch |
| Profile mechanism does not cover the exact reconstructed transcript | Evidence invalid |
| Claim does not satisfy its declared provenance or appraisal contract | Evidence invalid |
| Actual key, handle, publisher, or protected-session association disagrees | Session binding mismatch, reported through coarse context binding mismatch |
| Required store, profile validator, key resolver, or trusted authority is unavailable | Retry or attestation unavailable |
| Protected session is lost during the attempt | Protected session lost |
| Evidence-time contract is absent | Implementation remains blocked; no permissive runtime mapping is authorized |

Failures remain non-disciplinary. A coverage or appraisal failure does not prove
cheating. Any failure after the ADR-0005 atomic freshness claim leaves the
challenge consumed and requires a newly issued challenge for retry.

## Privacy and retention

The semantic transcript is correlation-sensitive because it combines complete
challenge context, profile, evidence claims, manifest and session identities,
provenance, actual public key, lookup handle, and evidence time.

Required controls:

- any future aggregate diagnostic emits one fixed complete redaction marker;
- no field-derived `Debug`, free-text diagnostic, log, metric label, trace,
  pointer identity, or panic/assertion message emits transcript values;
- explicit field access is a trusted functional interface, not an approved
  diagnostic sink;
- private session-key material is never present;
- the profile cannot expand the fixed vocabulary or exceed the local maximum-
  disclosure policy;
- accepted public-key material and handles remain session-correlation data even
  when the public key is not secret;
- unsuccessful outcomes retain no accepted claims under M1-011;
- M1-012 adds no persistence, backup, telemetry, or transport behavior; and
- later protected-result and evidence transport/storage work must define finite
  retention, confidentiality, deletion, access control, and backup behavior.

No ownership or redaction rule claims secure memory erasure or allocator
zeroization.

The registered `initial-maintainer` scenario owner remains the accountable
privacy-review gate before expanding a transcript claim, profile disclosure,
diagnostic surface, wire adapter, storage path, backup, logging, or telemetry.

## Threat-model impact

The design narrows:

- A1 client or same-user substitution of challenge, profile, manifests, key,
  handle, or session claims;
- replay and cross-context reuse across publisher, game, build, account, match,
  policy, or session;
- relay setup that relies on presenting evidence for one key while admitting
  another;
- accidental verifier omission of required profile claims;
- provenance-class confusion;
- result/permit/PoP cross-protocol reuse; and
- A8 publisher expansion of evidence claims or diagnostic disclosure.

The design does not eliminate:

- A4 compromise of an accepted agent, kernel, evidence producer, parser,
  profile validator, or key owner;
- A5 compromise of the publisher issuer, verifier, policy, reference service,
  or future protected-result issuer;
- false claims produced deliberately by trusted TCB code;
- full-session relay attacks after valid attestation;
- parser, canonicalization, algorithm, key-management, storage, or transport
  defects that later implementation may introduce; or
- ambiguity in evidence-time authority, which remains a blocking prerequisite.

Coverage proves association with one semantic transcript under the selected
profile mechanism. It does not prove every claim is true, complete beyond the
registered profile, or sufficient for every threat class.

## Validation strategy

M1-012 is documentation-only. Validation therefore focuses on semantic
completeness, contradiction detection, traceability, and executable attack-
scenario registration rather than runtime proof code.

### Positive cases

- An initial appraisal where attester construction and verifier reconstruction
  contain exactly equal challenge, profile, key association, evidence time,
  claims, and provenance.
- A same-session renewal with a fresh challenge, unchanged publisher/session
  key association, current claims, and no policy weakening.
- Two different valid profiles with distinct registered claim sets that both
  satisfy the same mandatory core without arbitrary extensions.

### Single-change negative cases

Starting from one accepted semantic fixture, independently change:

- each complete challenge semantic;
- the evidence profile;
- one required claim;
- one claim's provenance class;
- one manifest or measurement identity;
- the actual session public key;
- the `SessionPublicKeyId`;
- only the key-to-handle association;
- the protected-session subject;
- the publisher;
- the evidence-time semantic value; and
- the semantic purpose.

Every change must produce semantic inequality and future profile coverage
failure. Tests must not infer success from producer-supplied pass labels.

### Shape and vocabulary negative cases

- omit every required input one at a time;
- duplicate every singleton input one at a time;
- duplicate a set element under its semantic equality rules;
- add an undeclared claim;
- add an unknown critical semantic;
- use a known claim under a profile that did not declare it;
- provide a required claim under the wrong provenance class;
- create aliases that duplicate one meaning under two names;
- replace a semantic manifest identity with raw digest bytes or a marker;
- treat the complete bundle payload as a transcript input;
- accept an attester-supplied transcript without independent reconstruction;
  and
- accept only a profile identifier without binding the evidence instance's
  semantic claims.

### Cross-context and lifecycle negative cases

- reuse an evidence carrier with a different challenge;
- reuse across publisher, game, build, account, match, or policy;
- reuse one session's key or handle in another session;
- pair one session's actual key with another session's handle;
- reuse renewal evidence instead of constructing evidence for the fresh
  challenge;
- renew under a different publisher;
- renew after terminal session end or invalidation; and
- silently weaken selected policy during renewal.

### Domain-boundary negative cases

Tests or structural documentation checks must prove that the evidence-binding
transcript excludes:

- `ExpectedContext` as an attester claim;
- verifier challenge-evaluation time;
- `Decision`, `ReasonCode`, and `VerificationOutcome`;
- `VerifiedAttestation`, `AcceptedClaims`, and `AppraisalResult`;
- protected-result verifier identity, validity, commitment, and integrity
  protection;
- permit contents and validity;
- proof-of-possession challenge and response; and
- private session-key material.

### Time-boundary negative cases

- copy challenge `issued_at` as evidence creation time;
- copy challenge `expires_at` as evidence expiry;
- use verifier `now` as attester evidence time;
- use future protected-result validity as evidence validity;
- omit evidence time because challenge freshness passed; and
- introduce an always-valid or zero-valued placeholder.

These cases remain specification blockers until the evidence-time authority
design defines accepted positive temporal behavior.

### Mutation and property strategy

The implementation plan must define a finite semantic inventory before choosing
mutation counts. At minimum, each mandatory input, exclusion, relationship,
provenance rule, and failure mapping receives one isolated one-cause mutation or
equivalent falsification.

Property tests for later semantic fixtures must establish:

- reflexive equality for independently constructed equal semantics;
- inequality after any single semantic mutation;
- profile claim-set closure;
- order independence only for semantically set-valued claims;
- no equality between distinct semantic purposes; and
- no authority gained from a producer-provided success label.

No byte fuzz target is added by M1-012 because no byte parser, encoding, or
runtime transcript exists. Task 13 owns abstract JSON conformance fixtures.
Later M2 parser work must add bounded fuzzing and differential validation.

## Documentation and ADR delivery

The later M1-012 implementation plan is documentation-only and must consider
updates to:

- `CONTEXT.md` for the canonical Evidence-binding transcript, Evidence carrier,
  Profile contract, Semantic identity, Coverage, and Key association terms;
- `docs/ARCHITECTURE.md` for the external-carrier and reconstruction flow;
- `docs/PROTOCOL.md` to replace the undefined challenge-digest list with this
  semantic contract and preserve M2 representation deferrals;
- `docs/ROADMAP.md` for M1-012 completion limits and the evidence-time
  prerequisite;
- `docs/TRUST_MODEL.md` for key owner, evidence producer, attester, verifier,
  and relying-party authority;
- `docs/PRIVACY_MODEL.md` for transcript correlation and disclosure controls;
- `docs/THREAT_MODEL.md` for substitution, provenance, domain-confusion, and
  time-authority risks;
- `docs/TEST_STRATEGY.md` for the semantic mutation and attack matrix;
- `docs/SECURITY_INVARIANTS.md` only if review finds the current invariants do
  not already cover exact session binding, fixed vocabulary, and trusted local
  derivation;
- one new ADR matching the existing `docs/adr/` convention; and
- machine-readable attack scenarios where the existing schema can express the
  accepted threats without inventing wire fields.

The ADR is justified because the external evidence-carrier relationship,
complete challenge binding, actual-key-plus-handle association, closed profile
vocabulary, and semantic-domain separation are hard to reverse, surprising
without rationale, and selected from genuine alternatives.

No live GitHub issue is created by the design-writing step. The later plan must
gate issue creation and exact body synchronization separately.

## Alternatives considered

### External evidence carrier with semantic transcript

Selected. It avoids self-reference, keeps transport/proof bytes outside the
semantic meaning, supports profile-specific mechanisms, and allows independent
verifier reconstruction.

### Include the complete EvidenceBundle payload in the transcript

Rejected. A bundle containing proof over the transcript becomes recursive. It
also freezes transport and proof bytes as semantic inputs before representation
review.

### Bind only EvidenceProfile

Rejected. It binds a profile name but not the actual evidence instance, claim
set, provenance, manifests, key, or live session.

### Trust an attester-supplied transcript

Rejected. Proof over an attester-selected subset does not establish that the
verifier required every semantic input. Independent reconstruction is
mandatory.

### Verifier-only construction without received claims

Rejected. The verifier cannot reconstruct profile evidence meanings that were
never conveyed. Received claims are candidate inputs, not authority.

### Bind only SessionPublicKeyId

Rejected. ADR-0008 defines the handle as neither key commitment nor proof.

### Bind only the actual public key

Rejected. It leaves the future handle-to-key association outside the covered
semantics and permits remapping ambiguity.

### Use opaque manifest commitment markers

Rejected. A marker does not identify the committed semantic object, canonical
source representation, domain, or algorithm.

### Use raw digest bytes

Rejected. Untyped bytes imply no algorithm, domain, canonical source object, or
validation semantics.

### One universal claim set for every profile

Rejected. It forces unsupported placeholders or unnecessary disclosure and
erases assurance-profile distinctions.

### Arbitrary profile claim maps

Rejected. They violate the fixed evidence vocabulary, expand privacy exposure,
and make unknown-critical behavior ambiguous.

### Freeze literal domain-separation labels now

Rejected. Byte labels depend on canonical representation and cryptographic
review. M1-012 fixes semantic purposes only.

### Defer all domain separation

Rejected. Later proof, result, permit, renewal, and PoP work would have no
normative barrier against cross-purpose reuse.

### Equate evidence time with challenge time

Rejected. Challenge issuance, evidence creation, verifier evaluation, result
issuance, and permit validity have different producers and trust semantics.

## Compatibility and migration

M1-012 intentionally changes documentation semantics before a stable wire or
runtime transcript exists. It adds no public Rust API and needs no persisted-
data migration.

The current `docs/PROTOCOL.md` phrase `challenge digest` is superseded by the
complete typed challenge semantic. Current architecture references to manifest
digests remain future representation goals and must not be read as an already
defined M1 type or algorithm.

Once a profile identifier is used by conformance fixtures or wire artifacts,
its claim/provenance contract becomes observable. Semantic changes then require
explicit versioning or a new profile identity rather than silent modification.

No compatibility layer may accept both the complete transcript and a weaker
profile-only, handle-only, or subset transcript as equivalent.

## Acceptance criteria

The M1-012 documentation task is complete only when:

- the canonical terms are defined without representation leakage;
- the transcript and external evidence carrier are unambiguously separated;
- complete typed challenge semantics replace undefined challenge-digest
  language;
- the mandatory core and profile-closed claim rules are complete;
- every input and exclusion has one documented trust source;
- actual key plus handle association is required without promoting the handle
  to commitment or authority;
- exact semantic manifest identities are required without inventing digest
  bytes or algorithms;
- attester construction and verifier reconstruction are both required;
- all cross-input relationships and renewal constraints are explicit;
- semantic purpose separation is explicit while literal labels remain deferred;
- failure mappings remain consistent with M1-011 and non-disciplinary;
- privacy, diagnostics, and future retention obligations are explicit;
- the evidence-time authority prerequisite is named and blocks implementation
  without a permissive placeholder;
- positive and negative semantic cases cover every input, exclusion,
  relationship, and cross-context substitution;
- relevant attack scenarios have accountable owner and assurance profile;
- no Rust, dependency, parser, serializer, crypto, I/O, persistence, privilege,
  or remote/GitHub mutation enters scope;
- architecture, protocol, trust, privacy, threat, test, roadmap, glossary, and
  ADR text are internally consistent;
- repository documentation checks and `git diff --check` pass; and
- the decision owner reviews and explicitly approves the exact written
  candidate before implementation planning begins.

## Deferred prerequisites

### Evidence-time authority

This is a deliberate unresolved prerequisite, not an omitted requirement. A
separately approved design must resolve producer, clock/freshness mechanism,
validity semantics, rollback, restart, unavailability, renewal, and privacy.

No implementation plan may represent or validate the transcript until this
prerequisite is either resolved in the same approved planning scope or made an
explicit earlier blocking task.

### Representation and cryptography

M2 must define canonical source representations, compact commitments,
algorithms and identifiers, literal domain-separation labels, protection
coverage, wire encoding/parsing, validity, trusted issuance, and conformance
vectors under cryptographic review.

### TPM-specific coverage

M3 must map the semantic transcript onto TPM qualifying data, quote validation,
attestation-key enrollment, and assurance-class behavior without weakening the
M1-012 input contract.

## Primary sources and project authorities

- [RFC 9334, Remote ATtestation procedureS Architecture](https://www.rfc-editor.org/rfc/rfc9334.html),
  especially sections 3, 4.1, 4.2, 5.1, 10, and 11 for role separation,
  Evidence and Attestation Result separation, appraisal, freshness, and privacy.
- [RFC 9711, The Entity Attestation Token](https://www.rfc-editor.org/rfc/rfc9711.html),
  especially sections 1.3.1, 4.1, 9.3, and 10.5 for profile-governed claims,
  nonce freshness, and the separation between attestation and accompanying
  proof-of-possession use.
- `docs/SECURITY_INVARIANTS.md` for exact session binding, trusted local
  derivation, fixed evidence vocabulary, fail-closed parsing, privacy, and
  non-disciplinary failure.
- `docs/THREAT_MODEL.md` for replay, relay, verifier-gate, evidence, malicious-
  publisher, and false-positive threats.
- `docs/ARCHITECTURE.md` for RATS roles, complete challenge intent, evidence
  classes, session-key lifecycle, Appraisal Result seam, and later protected
  result.
- `docs/ROADMAP.md` for M1 semantic-first scope, M1-012 ownership, M2 abstract
  protocol work, and later TPM binding.
- `docs/AI_DEVELOPMENT_POLICY.md` for human authority over protocol and
  cryptographic decisions.
- ADR-0005 for publisher-authoritative challenge freshness and irreversible
  nonce claim.
- ADR-0007 for exact-attempt verifier capability authority.
- ADR-0008 for the non-authoritative `SessionPublicKeyId` boundary.
- ADR-0009 for the unsigned semantic `AppraisalResult` and protected-result
  deferral.

## Review gate

This written candidate must be self-reviewed for placeholders, contradictions,
scope drift, ambiguous terms, unsupported security claims, and stale project
language. The decision owner must then review the exact file and approve or
request changes.

Only after exact written-spec approval may implementation planning begin. That
planning remains documentation-only unless a later separately approved design
resolves the evidence-time prerequisite and authorizes representation work.
