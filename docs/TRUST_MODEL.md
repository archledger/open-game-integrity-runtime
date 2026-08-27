# Trust model

## Publisher trusts

- its own verifier configuration and signing keys;
- accepted TPM/platform roots and attestation-key enrollment;
- accepted local agent and platform measurements;
- signed reference values and revocations;
- its own matchmaking permit validation.
- session-key binding only after verifier appraisal and relying-party validation of the actual key and fresh proof;

## Publisher does not trust

- local game return values;
- client-provided PID, path, build, App ID, or process list;
- unsigned evidence;
- stale evidence;
- software TPM evidence presented as hardware assurance;
- a TPM signature over unverified caller-supplied claims.
- a client-supplied or byte-equal `SessionPublicKeyId` as key commitment, proof of possession, permit, or admission authority;

## Player trusts

- publicly inspectable protocol and source;
- signed and reproducible local packages;
- fixed evidence schema and privacy policy;
- session-scoped controls;
- explicit disclosure and fallback behavior;
- separation between attestation failure and discipline.
- a future session key and lookup handle are scoped to one publisher/protected session, with reuse only for that session's renewal;

## Player does not grant

- arbitrary publisher kernel code;
- unrestricted host-memory or file access;
- raw physical TPM command access;
- global process scanning;
- persistent monitoring outside the game session;
- automatic biometric access.

## OGIR maintainers must not control

- universal ranked-match authorization;
- publisher matchmaking decisions;
- one global device-tracking identity;
- every release, policy, reference, and verifier key through one credential;
- a hidden bypass or private policy weakening.
- a stable session-key handle reused as a cross-session or cross-publisher correlation identity;
