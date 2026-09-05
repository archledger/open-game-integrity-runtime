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


## M1-015 renewal and revocation contract

The human-approved
[semantic design](superpowers/specs/2026-09-04-m1-015-renewal-revocation-semantics-design.md)
and Proposed [ADR-0014](adr/0014-renewal-revocation-semantics.md) define future
permit/renewal/revocation obligations. They do not add a codec, endpoint, runtime
API or operational service. The five purpose domains above remain unchanged.

1. Establish live-session eligibility through the configured
   [session-authorization owner](ARCHITECTURE.md#75-renewal). Require coherent
   owner state across every enforcing replica, exact independent context and
   either unchanged policy or an approved non-weakening transition preserving
   epoch/high-water. No cached replica state substitutes for owner coherence.
2. Reserve one bounded attempt for the exact current predecessor. Use a fresh
   durably registered challenge and new current evidence under existing
   temporal rules; run all verifier gates. Consumed challenges and valid
   temporal observations are never released by rejection or retry.
3. At issuer commitment, fence predecessor, terminal status, effective validity,
   current policy/transition and applicable revocation against accepted updates.
   Commit at most one successor for a predecessor, bound to the exact attempt,
   context, actual key/handle and approved policy/profile.
4. At relying-party installation, fence final validation and owner installation
   against the current predecessor/terminal state, effective predecessor
   deadline and every issuer-authority, policy, revocation and required-
   dependency update accepted before installation. Within the fence,
   independently revalidate issuer, context, possession, successor validity and
   complete current dependencies, then atomically install the newer generation.
   Earlier validation is insufficient. Later replica decisions cannot authorize
   the predecessor.
5. A trusted local adapter supplies a new validated renewal permit through the
   existing `RenewalPending -> PermitReceived -> Active` edges. A report,
   handle, research mock result or cleanup acknowledgement cannot create it.

Grant commitment and installation are different events. A cancelled uncommitted
attempt may start a fresh-challenge attempt while eligibility survives. A
committed response loss instead permits bounded redelivery of the exact
committed artifact, without re-signing or changing deadlines. Redelivery must
finish within predecessor eligibility and successor validity; otherwise new
initial establishment is required. A duplicate currently installed artifact can
only receive idempotent acknowledgement after current validation.

The current permit has a finite nonempty half-open interval. Required result
validity and all required authenticated view validity are conjunctive. An
exclusive deadline equal to the decision time is too late. A minimum of those
deadlines is valid only in a common trusted time domain; otherwise evaluate
through each approved mapping. For a bounded trusted decision-time interval,
its lower bound must satisfy every not-before/freshness origin and its upper
bound must precede every expiry. Uncertainty is not acceptance leeway. Client
UTC, process uptime and evidence collection time cannot replace those contracts.

A view authenticates the full required scope/coverage, source and continuing
authority, generation/revision and freshness origin/deadline. A partial update
requires complete reconstruction before use. Replaying an authentic old view
or changing its receipt time never extends age. Invalid/older candidates cannot
advance or revoke and leave a usable current view intact. Identical revisions
are idempotent without a changed deadline; authenticated contradictory authority
state is unavailable for the affected scope. Revision exhaustion cannot wrap.
A later complete authentic view may refresh still-live authorization within the
unchanged permit expiry. It cannot erase a prior expired terminal gap.

Known applicable revocation blocks protected decisions, even with an unexpired
permit. Initial/renewal appraisal, issuance and relying-party admission or
continued use each retain their own current checks. Accepted updates are fenced
locally; unobserved remote updates remain subject to the declared finite
propagation assumptions. Revocation of an issuer key is checked through
independent publisher-approved authority, never vouched for by that revoked key.
All applicable target classes and sources must be covered; one stale required
view defeats the conjunction even if others remain current.

A pending attempt grants no new authorization and extends no prior deadline.
Intact transient failure may preserve only independently valid current use.
Expiry without a usable installed successor, continuity loss or known applicable
revocation prevents late resurrection. New initial establishment is required
following terminal loss. A stronger-sounding profile/version cannot bypass an
unproven transition; a restricted alternative uses a separate explicit context.
Semantic failure reasons remain non-disciplinary and do not authorize calls to
phase-ineligible existing failure methods.

Each operational profile must define finite permit/view ceilings, reevaluation,
attempt/work/state bounds, trusted clock error/mappings and safe target retention.
M2 still owes protected result/permit representation and validity, authentication
and proof coverage, bounded parsing, issuer factories, possession, coherent owner
access, durable order/recovery and deletion. No mock or scenario schema check
proves these mechanisms. M3 TPM mapping is unchanged.
