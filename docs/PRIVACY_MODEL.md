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


## M1-015 authorization-state retention

The [approved design](superpowers/specs/2026-09-04-m1-015-renewal-revocation-semantics-design.md)
and Proposed [ADR-0014](adr/0014-renewal-revocation-semantics.md) specify the
following future retention obligations. No storage, backup, replication,
secure-erasure or production deletion mechanism is implemented by this change.
`initial-maintainer` reviews every retained/disclosed metadata expansion;
`all-protected-modes` requires these controls for every protected mode.

| State and accountable authority | Scope and purpose | Finite lifetime / deletion condition | Diagnostic exclusion |
| --- | --- | --- | --- |
| Live binding, current generation and terminal/attempt state; configured session-authorization owner | One publisher/protected session; coherent admission and at most one pending attempt | Minimum bounded active-session state; resolve/cancel atomic in-flight operations before terminal deletion; absence never reconstructs an old session from a permit | Raw binding, account, key/handle, generation and complete context |
| Exact committed successor awaiting installation; trusted issuer/owner | Same session and predecessor; bounded authenticated redelivery only | Only while active and eligible, before predecessor effective deadline and successor validity; discard when installation/terminal disposition no longer needs redelivery; never a permanent permit archive | Permit bytes, proof and per-session timing |
| Evidence temporal high-water; publisher verifier / trusted collection authority | One publisher/protected session; preserve epoch/sequence/interval continuity | Existing active-session-only rule; delete at terminal end after atomic in-flight resolution; no client repair or reusable archive | Authority detail, epoch, sequence, intervals, high-water, protected-source state |
| Challenge registration, consumption, time floor and issuance-rate accounting; publisher freshness authority | Existing ADR-0005 scopes and replay/rollback purpose | Preserve existing replay-record expiry and issuance-event window rules; trusted time floor follows its authority lifetime, not a new session-retention rule | Complete challenge/replay binding, time/floor and publisher/context values |
| Current revocation views and source order/high-water; authorized source and trusted consumers | Publisher/delegated source generation; current complete applicability and anti-rollback | Finite configured authorities/views/payloads; view expires exclusively without receipt-time reset; retain required order/negative state until trusted retirement rules make old eligible artifacts impossible | Source epoch/revision, sensitive target/dependency identities and correlation metadata |
| Negative revocation history and minimum-version constraints; authorized source | Declared target class/namespace; prevent a retired target regaining rights | Each enabled class needs finite eligibility/retention policy; retirement requires dependent-artifact expiry plus trusted non-reuse/retired-generation rules; never indefinite attestation identity retention | Sensitive targets, full dependency sets and unapproved identifying history |

Finite limits cover authority namespaces, views, target/dependency counts,
pending work, retained artifacts and payload sizes. Capacity exhaustion fails
closed without evicting still-required negative state. No class/profile can be
enabled if safe bounded retention cannot be established. A time-to-live alone
does not prove that a removed target cannot become eligible again. Revocation
source high-water and evidence temporal high-water are different scopes and
purposes; neither is a global device or player identifier.

A trusted publisher applicability path can establish a permit's current
revocation status without exposing raw attestation identities or dependencies
to the game. New sessions and publishers retain the existing fresh key/handle
boundary. Known revocation and unavailable knowledge remain different coarse
outcomes, never automatic disciplinary evidence.

Ordinary Debug/Display/errors/logs/traces/metrics/crash reports/support bundles
and test assertions disclose no complete context, account, raw session/key/
handle, dependency identity, source epoch/revision, permit, proof or per-session
timing. Synthetic examples use semantic categories only. Public trust-
distribution material requires its own approved disclosure contract; this is
not permission to expose sensitive targets in game responses or diagnostics.

Server authorization denial never waits for client cleanup acknowledgement.
Required cleanup is retryable and remains Required until matching trusted
completion; completion cannot revive terminal state. An implementation must
prove its finite deletion and cleanup behavior, not infer it from these tables
or from schema-valid scenarios.
