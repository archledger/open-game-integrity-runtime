# OGIR domain glossary

This glossary defines domain language only. It does not describe modules, wire
encodings, cryptographic algorithms, implementation status, or delivery order.

## Appraisal Result

The verifier's unsigned semantic outcome for one relying-party-selected
context. It contains either accepted claims for an allowed outcome or one
coarse non-disciplinary reason for an unsuccessful outcome. It is not an
Attestation Result, permit, proof of possession, or protected-session admission.

## Attestation Result

The verifier-protected output consumed by a relying party. A trusted issuer
creates it only after independently establishing the appraisal outcome, then
binds that outcome to the appraised evidence, verifier identity, validity, and
integrity protection required by the selected protocol profile.

## Accepted claims

Claims that the verifier has appraised and is prepared to place in an allowed
outcome. Unsuccessful outcomes contain no accepted claims.

## Decision

The coarse outcome class: allow, allow restricted, deny, unsupported, or retry.
A Decision is a report and grants no authority.

## Reason code

Exactly one coarse, structured, non-disciplinary explanation attached to an
unsuccessful Appraisal Result. Allowed outcomes have no reason code. A reason
code contains no free text, raw evidence, or accusation of cheating.

## Verified Attestation

A proof that every verifier appraisal gate completed for one exact attempt. It
is not a protected Attestation Result or admission decision.

## Expected context

The publisher, game, build, account scope, match, and policy selected by the
relying party independently of client evidence. The same selected policy binds
both full and restricted allowed classes; restricted mode cannot substitute a
different policy after appraisal begins.

## Evidence-binding transcript

The closed semantic claim set one evidence mechanism covers for one appraisal
attempt. It is not a serialization, digest, result, permit, or admission
decision.

Its conceptual shape is:

```text
Evidence-binding transcript
  purpose: OGIR evidence binding
  complete PublisherChallenge semantics
  registered EvidenceProfile semantics
  actual session public key
  SessionPublicKeyId
  profile-required evidence creation and validity semantics
  exact closed profile-required claims
  exact provenance class for every claim
  semantic manifest and measurement identities
```

`EvidenceBundle` carries profile-specific claims and proof material but is not
inside the transcript. `ExpectedContext` remains independently supplied by the
relying party. Transcript equality is semantic equality; no byte encoding,
field order, digest, or cryptographic algorithm is selected here.

Initial appraisal and same-session renewal each create a new evidence-binding
transcript with a fresh complete challenge. The transcript purpose remains
fixed to OGIR evidence binding; same-session renewal authorization is a
separate semantic domain.

Every profile requires all eight Base claims and may add only its declared
subset of the two profile-specific claims:

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

Each required claim appears semantically exactly once. The immutable profile
contract registers exactly one permitted provenance class for each claim:
`hardware-certified`, `measured-log-derived`, or `trusted-agent-observed`.

## Coverage

The profile-specific property that changing any evidence-binding transcript
semantic causes profile validation to fail. Coverage does not name a
cryptographic mechanism.

## Evidence carrier

The external profile-specific `EvidenceBundle` that transports claims and proof
material. The carrier is not itself a transcript semantic.

## Profile contract

The immutable semantic definition named by an `EvidenceProfile`: exact required
claims, permitted provenance, coverage, assurance meaning, disclosure class,
and evidence-time requirements.

## Semantic identity

An identity whose namespace, algorithm identity, and value are explicit after
profile selection; not an untyped digest or opaque commitment marker.

## Key association

The trusted assertion that one `SessionPublicKeyId` identifies one actual
session public key for one publisher and protected session. Handle equality
alone is not a key commitment, proof, or authority.

## Session public-key lookup handle

A non-authoritative reference to an ephemeral protected-session public key.
The relying party must resolve the actual key and validate fresh
transcript-bound proof of possession before admission.
