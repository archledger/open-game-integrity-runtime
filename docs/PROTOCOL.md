# Protocol work plan

No production wire format is frozen yet.

## Required role mapping

OGIR will align with the RATS conceptual roles:

- Attester: local OGIR attestation environment;
- Verifier: publisher-controlled verification service;
- Relying Party: matchmaking or game server;
- Endorser/reference provider: TPM/platform vendors, distributions, OGIR release process, and publisher-approved manifests.

## Candidate format

- EAT-compatible claims;
- deterministic CBOR;
- COSE signatures;
- CDDL schemas;
- explicit OGIR media/profile identifiers;
- detached large measured logs where required, bound by digest;
- canonical, bounded, versioned encoding.

## Protocol design milestones

1. Define semantic domain types without serialization.
2. Define security binding transcript.
3. Define state machine and error taxonomy.
4. Create JSON-readable abstract test vectors.
5. Evaluate CBOR/COSE libraries.
6. Define canonical encoding and duplicate-field behavior.
7. Build two independent decoders or one decoder plus a reference validator.
8. Fuzz and differentially test.
9. Freeze experimental version `0` only after conformance vectors pass.
10. Never reuse an experimental key or identifier namespace for production.

## Semantic appraisal seam

M1-011 defines `AppraisalResult` as an opaque, unsigned, in-process semantic
value. Every result retains exact relying-party context; only allows retain the
accepted profile and session public-key handle. The only allow path consumes
the `VerifiedAttestation` produced by the completed verifier flow. Direct typed
failure results establish a valid phase-eligible shape and discard accepted
claims, but public failure provenance is not sufficient for signing.

`AppraisalResult` is not a wire object, protected `AttestationResult`, or generic
signer input. It has no evidence commitment, algorithm identifier, verifier
identity, signature or integrity protection, issued-at/expiry, parser,
validation contract, permit, or admission authority. M1-012 owns only the
semantic binding-transcript inputs. Later M2 work must choose commitment and
algorithm representation, protection coverage, canonical wire encoding and
parsing, validation, authoritative validity fields, and the trusted issuer
boundary before a protected Attestation Result exists.

## Binding transcript

M1-012 defines the **Evidence-binding transcript** as a closed semantic value,
not bytes, a digest, a result, or a wire object. Its purpose is fixed to OGIR
evidence binding. Initial appraisal and same-session renewal each create a new
transcript with a fresh complete challenge; renewal authorization remains a
separate semantic domain.

The semantic transcript contains:

```text
purpose: OGIR evidence binding
complete typed PublisherChallenge, including ProtocolVersion
one exact registered EvidenceProfile
actual session public key + SessionPublicKeyId association
registered Evidence Collection Authority contract
opaque publisher/session-scoped protected epoch relation
protected collection sequence
protected collection start
protected snapshot-freeze end
all eight Base claims
the profile's declared subset of two profile-specific claims
exactly one registered provenance class for every required claim
semantic manifest and measurement identities
```

The eight Base claims are attesting agent identity, platform identity, boot
measurement identity, runtime manifest identity, game manifest identity,
process binding identity, protected-session identity, and enforcement policy
state. The only profile-specific claims are attestation identity and runtime
measurement identity. Every required claim appears semantically exactly once
with one of the registered `hardware-certified`, `measured-log-derived`, or
`trusted-agent-observed` provenance classes.

`EvidenceBundle` is the external carrier of those claims and profile-specific
proof material; the complete carrier is not inside the transcript.
`ExpectedContext` remains independently supplied relying-party authority and is
not an evidence claim. The attester constructs the semantic transcript, while
the publisher verifier independently reconstructs it before separate coverage,
provenance, and appraisal checks. Received claims remain candidate inputs, and
valid coverage does not prove their truth.

The collection authority opens one operation only after receiving the exact
complete challenge later covered by evidence. It records protected start,
collects or revalidates every required current claim, and atomically freezes the
complete snapshot at protected end before proof creation. The local authority
does not need publisher trust roots: the publisher verifier later authenticates
the challenge through the existing freshness path.

One evidence instance is valid only for that challenge and must reach the
publisher verifier before the challenge's existing half-open expiry boundary.
Each profile defines a finite collection-duration ceiling; publisher policy may
only tighten it. Challenge expiry bounds proof creation, transport, and receipt
after freeze, so there is no separate claimed post-freeze latency.

Evidence time contains no client UTC and has no wall-clock skew allowance.
Challenge issuance, verifier evaluation, result validity, permit validity,
process uptime, zero, and always-valid values cannot substitute for the
registered protected local semantics.

Initial appraisal establishes active-session temporal high-water. Same-session
renewal is serialized and requires a fresh challenge, the same uninterrupted
epoch relation, a strictly increasing collection sequence, and an interval
whose start is not earlier than the latest validated end. Accepted sequences
need not be contiguous because a locally created collection can be lost before
the verifier observes it. Reuse or decrease, epoch change, overlap, rollback,
restart, protected-source discontinuity, or lost high-water terminates the
protected session without implying cheating.

After validating coverage and the protected authority statement, the verifier
atomically compares and advances temporal high-water before later claim and
policy appraisal. Later rejection cannot erase a validated temporal
observation; invalid or unauthenticated proof cannot advance candidate time.
Temporary unavailability is retryable only while authoritative continuity state
remains intact and recoverable, and retry requires a fresh challenge.

M2 still owns canonical source representations, algorithms and identifiers,
literal domain-separation labels, proof coverage, encoding, parsing, and
conformance vectors. It must domain-separate the closed five semantic purposes:
evidence binding; protected Attestation Result integrity; permit authorization;
session proof of possession; and renewal authorization. Challenge
authentication remains a separate verifier operation. Admission remains
downstream and outside the evidence-binding transcript. No representation, byte
order, algorithm, literal label, proof format, or runtime API is selected here.
