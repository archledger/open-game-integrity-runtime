# Privacy model

OGIR applies data minimization at the protocol boundary.

## Allowed information classes

- publisher/game/build/match identifiers already known to the publisher;
- selected integrity policy identifier;
- accepted profile identifiers and digests;
- TPM-backed freshness and measurement evidence;
- publisher-scoped attestation identity;
- game/runtime/session manifest digests;
- structured policy outcomes;
- short-lived session public key.
- opaque session public-key lookup handle scoped to one publisher and protected session;
- exact relying-party context retained in every unsigned Appraisal Result;
- accepted profile and session public-key handle retained only in allowed Appraisal Results;

## Disallowed information classes

- complete system process list;
- names of unrelated applications;
- browser, chat, document, or home-directory content;
- unrelated file paths;
- raw biometric samples or templates;
- universal cross-publisher device identifier;
- raw TPM Endorsement Key as a game identifier;
- arbitrary publisher-selected host queries;
- persistent global monitoring after the game session.
- session-key or key-handle reuse as a stable cross-session/cross-publisher correlation identifier;

## Evidence-binding transcript disclosure boundary

The complete Evidence-binding transcript, decoded claims, provenance, actual
session public key, `SessionPublicKeyId`, semantic manifest and measurement
identities, evidence-time statement, and proof material are
confidential-by-default attestation data.

- Ordinary `Debug`, error, tracing, metric, crash, and audit output must not
  contain transcript contents, proof bytes, claim values, manifest identities,
  key bytes, key handles, or evidence time. It must also exclude
  all `ExpectedContext` values, all complete challenge-context values, all publisher/build/account/game/match/policy bindings, and all protected-session context values.
  This prohibition applies even though `ExpectedContext` is independent
  authority rather than transcript evidence.
- `EvidenceProfile` alone is not permission to log the profile's claims.
- Profiles must declare disclosure class and data minimization expectations.
- Retention, deletion, and protected audit disclosure remain separately
  governed and are not selected by M1-012.
- The private session key is never evidence, transcript input, or telemetry.

The evidence-time authority contract, scoped epoch relation, collection
sequence, interval start and freeze end, duration, temporal high-water,
protected-source statement, and proof are confidential. The transcript exposes
no raw boot identifier, boot seed, reset/restart counter, TPM clock, daemon
uptime, host UTC, or device-wide epoch. Epoch equality is opaque and scoped to
one publisher and protected session; it is not an analytics, telemetry, player,
or discipline identifier.

The publisher verifier retains temporal high-water only for the active
protected session and deletes it at terminal end after resolving any atomic in-
flight operation. Existing challenge replay retention remains separately
governed by ADR-0005. Local collection state is limited to one active operation
and the minimum same-session continuity state. M1-012F selects no backup,
replication, disaster recovery, migration, telemetry, or secure-deletion
implementation.

Ordinary `Debug`, `Display`, errors, logs, traces, metrics, crash reports, audit
events, support bundles, and test assertion messages expose only coarse redacted
class and operational disposition. They never expose authority contract detail,
epoch, sequence, interval, duration, high-water, raw protected-source state,
complete challenge/context, key/handle, carrier, or proof values.

Documentation examples use semantic names, never realistic account identifiers,
key material, proof bytes, or biometric or device fingerprints.

## Controls

- fixed claim schema;
- local maximum-disclosure policy;
- publisher-scoped Attestation Keys;
- hashed or abstracted accepted-profile results where possible;
- redacted local logging;
- short retention periods;
- user-visible policy before protected mode;
- session-scoped enforcement and cleanup;
- privacy tests that fail when forbidden fields appear.
- a fresh future key/handle for every new session or publisher, with renewal-only reuse inside one session;
- fixed `SessionPublicKeyId` Debug redaction and explicit byte access treated as a trusted functional boundary;
- fixed redaction for `AppraisalResult`, `AppraisalResultView`, and `AcceptedClaims`;
- terminal-first failure emission discards every staged accepted profile and key-handle claim;
- terminal flows retain no attempt binding, replay registration, or attempt allocation; success moves the sole binding into `VerifiedAttestation` until conversion and failure releases it before return;

The retained context and allowed-result key handle are correlation-sensitive.
Explicit accessors are trusted functional interfaces, not approved logging
sinks. `AppraisalResult` is unsigned and has no intrinsic expiry, secure-erasure
guarantee, or deletion enforcement. Future protected-result transport and
storage must define finite retention, confidentiality, deletion, and backup
behavior before operational use.

Registered scenario owner `initial-maintainer` is the accountable privacy-review
gate before expanding any result context or claim field, diagnostic surface,
serializer or wire adapter, persistence, storage or backup path, or logging or
telemetry path.
