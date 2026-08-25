# Trust model

## Publisher trusts

- its own verifier configuration and signing keys;
- accepted TPM/platform roots and attestation-key enrollment;
- accepted local agent and platform measurements;
- signed reference values and revocations;
- its own matchmaking permit validation.

## Publisher does not trust

- local game return values;
- client-provided PID, path, build, App ID, or process list;
- unsigned evidence;
- stale evidence;
- software TPM evidence presented as hardware assurance;
- a TPM signature over unverified caller-supplied claims.

## Player trusts

- publicly inspectable protocol and source;
- signed and reproducible local packages;
- fixed evidence schema and privacy policy;
- session-scoped controls;
- explicit disclosure and fallback behavior;
- separation between attestation failure and discipline.

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
