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

M1-012 must define the semantic inputs that a future transcript covers. Later
M2 commitment/protection work must at least bind:

```text
protocol version
challenge digest
publisher/game/build/account/match/policy
agent and evidence profile
boot/runtime/game/session manifest digests
ephemeral session public key
issued-at and expiry
```

The exact order, encoding, domain-separation label, and hash algorithm require an ADR and cryptographic review.
