# Trust model

## Publisher trusts

- its own verifier configuration and signing keys;
- accepted TPM/platform roots and attestation-key enrollment;
- accepted local agent and platform measurements;
- signed reference values and revocations;
- its own matchmaking permit validation.
- session-key binding only after verifier appraisal and relying-party validation of the actual key and fresh proof;
- allowed Appraisal Result shape only after consuming the exact completed verifier capability;

## Publisher does not trust

- local game return values;
- client-provided PID, path, build, App ID, or process list;
- unsigned evidence;
- stale evidence;
- software TPM evidence presented as hardware assurance;
- a TPM signature over unverified caller-supplied claims.
- a client-supplied or byte-equal `SessionPublicKeyId` as key commitment, proof of possession, permit, or admission authority;
- an unsigned `AppraisalResult`, public failure shape, report-only Allow, or borrowed result view as a protected Attestation Result, generic signer input, permit, proof, admission, or cheating conclusion;

The in-process attempt allocation binds a capability to one exact flow. It does
not establish cryptographic provenance or truth for a copied profile or
session-key-handle payload. Trusted profile, session-binding, policy, failure-
provenance, and future protected-result issuer code remains in the publisher
verifier TCB. Future validity, signing/integrity, wire validation, key
resolution, proof of possession, permit, and admission boundaries must be
validated separately.

## Player trusts

- publicly inspectable protocol and source;
- signed and reproducible local packages;
- fixed evidence schema and privacy policy;
- session-scoped controls;
- explicit disclosure and fallback behavior;
- separation between attestation failure and discipline.
- a future session key and lookup handle are scoped to one publisher/protected session, with reuse only for that session's renewal;
- failures discard staged accepted claims and default result diagnostics redact retained context profile and key-handle values;

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
