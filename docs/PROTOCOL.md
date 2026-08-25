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

## Binding transcript

The future transcript must at least commit to:

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
