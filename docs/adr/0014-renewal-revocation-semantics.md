# ADR-0014: Specify renewal and revocation semantics

- Status: Proposed
- Date: 2026-09-04
- Owners: Initial maintainer
- Related issues: [Local M1-015 issue](../../planning/issues/015-renewal-revocation-semantics.md); [approved semantic design](../superpowers/specs/2026-09-04-m1-015-renewal-revocation-semantics-design.md)
- Supersedes: None
- Superseded by: None

## Context

Existing ADRs define exact challenge freshness, protected evidence continuity,
ordered verifier gates and terminal local sessions. They do not implement
permit issuance, renewal authorization or a live revocation service.
`AppraisalResult` is unsigned; `RevocationChecked` is attempt-bound; the volatile
mock replay cache cannot supply production authority. Those contracts remain
unchanged.

The human approved the M1-015 semantic design on 2026-09-04. This Proposed ADR
records its integration candidate; semantic approval does not imply that the
operational mechanisms exist or that this contribution has been certified.

## Decision drivers

- Require fresh evidence without extending an old permit on retry or outage.
- Stop known-revoked authorization without claiming globally instantaneous updates.
- Keep time sources, revocation scope and authorization consumers explicit.
- Order successor commitment, installation and termination across all replicas.
- Preserve non-weakening, continuity-proven policy/profile transitions.
- Bound state, work and privacy exposure without unsafe negative-state deletion.
- Preserve coarse non-disciplinary failure and existing capability boundaries.

## Options considered

### A: Finite permits and finite authenticated revocation-view validity

Selected. Consumers reject known applicable revocation at the next protected
decision. Independently usable older knowledge has a finite validity limit;
expiry has no grace. This supports bounded outages but requires trustworthy
source freshness, time comparisons, ordered state and finite reevaluation.

### B: Synchronous authoritative lookup at every protected decision

A possible stricter implementation of A. It makes network availability and
latency part of every decision and still needs ordering between lookup and use.
It is not required by this semantic decision.

### C: Honor permits until expiry despite known applicable revocation

Rejected. It conflicts with invariant 6 and preserves authorization after a
consumer has already established that it is revoked.

## Decision

The [approved design](../superpowers/specs/2026-09-04-m1-015-renewal-revocation-semantics-design.md)
is the detailed semantic contract. This ADR selects no wire fields, Rust types,
cryptography, storage, transport, numerical production settings or new claim.

### Time and current revocation knowledge

Permit validity is finite and half-open. Required result validity and all
applicable revocation-view freshness requirements are conjunctive. Compare
values only through their trusted time contracts; a minimum is meaningful only
in a common validated time domain. Equality with any exclusive expiry is too
late. With bounded time uncertainty, the entire decision-time interval must fit
inside every applicable validity interval. Client UTC or evidence interval
values cannot substitute for server authorization time.

A usable revocation view authenticates source, publisher/delegation and scope,
complete required coverage, authority generation, ordered revision, freshness
origin and exclusive deadline. A delta needs proven complete reconstruction
against its proper base. An older or invalid candidate cannot replace a valid
current view, advance state, extend freshness or invent revocation. Identical
redelivery is idempotent without extending its deadline; authenticated
contradictory state fails closed for its scope. Revision exhaustion cannot wrap.
Later views incorporate committed applicable revocations and cannot silently
remove them or lower minimum versions within the same trust generation.

A newer complete authentic view may refresh a live session within immutable
permit expiry. It cannot erase an expired gap, even if an expiry callback has
not yet run, or revive terminal state. Required knowledge loss denies protected
authorization; effective expiry terminally invalidates the session. Recovery
cannot reconstruct trusted state from client material.

Consumers check every applicable architectural target class and their source's
continuing authority: protocol versions, agent/bridge builds, platform profiles,
policies, attestation identities, verifier keys and game/runtime manifests.
Each needs an authorized scope, namespace, match rule and finite retention
contract. Verifiers derive complete bounded dependencies from authenticated
artifacts and trusted configuration. Relying parties obtain current applicability
through a trusted publisher path without requiring raw dependency disclosure to
the game. Missing mandatory coverage fails unavailable/unsupported.

Known applicable revocation stops affected authorization at the next protected
decision; it does not wait for permit expiry. A revoked signing key cannot
certify its own recovery: the relying party uses independent publisher-approved
revocation/trust authority. Propagation of remote changes remains bounded only
under the approved honest-source, immutable age, trusted comparison and finite
reevaluation premises. No zero-delay guarantee is made.

### Renewal and terminal ordering

One logical session-authorization owner, designated by trusted configuration for
an exact publisher/protected-session context, owns the current admitted
generation, terminal disposition and one pending renewal. Every enforcing
replica consults coherent owner state; an unexpired local cache is insufficient
when coherence cannot be established. Independent active owners and ownership
migration are outside the first profile. This is an obligation, not an
implemented database or consensus mechanism.

Renewal requires a fresh durably registered challenge and current evidence for
the same uninterrupted publisher/session/live subject and actual key/handle.
The protected epoch remains the same, sequence strictly increases with gaps
allowed, and intervals do not overlap. Validated temporal high-water advances
before later appraisal rejection; invalid proof cannot advance it. Nonce
consumption and validated temporal observations never roll back on retry.

Before grant commitment, the issuer fences the exact live predecessor,
validity, current policy/transition and applicable revocation against accepted
updates and terminal state. At most one successor commits per predecessor.
The relying party performs final validation and owner installation as one
fenced operation against the current predecessor/terminal state, predecessor
effective deadline, and every issuer-authority, policy, revocation and required-
dependency update accepted before installation. Within the fence it revalidates
context, issuer, possession, dependencies, successor validity and predecessor
eligibility; validation performed earlier is insufficient. Installation is
ordered through the owner. Subsequent decisions
at any replica cannot authorize the predecessor; already committed decisions
are not rewritten and ongoing activity has bounded reevaluation.

An uncommitted attempt can be cancelled/resolved and retried with a new
challenge while eligibility survives. A committed-but-undelivered successor
cannot be erased to mint another: only bounded authenticated redelivery of the
exact artifact is allowed, without re-signing or changed deadlines, before both
predecessor eligibility and successor validity expire. Otherwise recover through
a new initial session. Duplicate installed artifacts only receive idempotent
acknowledgement after current validation.

Pending renewal grants nothing. The old current permit may remain usable only
while all independent authorization requirements hold. A new validated permit
must traverse `RenewalPending -> PermitReceived -> Active`; there is no fallback
to Active using the old permit. Expiry, terminal continuity loss or established
applicable revocation cannot be repaired by late completion. A new initial
session/key/handle/challenge and appraisal are required after terminal loss.

A policy/profile change needs an explicit publisher-approved non-weakening
transition relation, independently selected context and proven same epoch/high-
water. Numeric versions do not order assurance. Unproven transitions require
new initial establishment. Known revocation or violated minimum versions cannot
be bypassed by migration; a restricted alternative is an explicit new context.

### Failure, cleanup and bounded state

Revoked, expired, continuity-lost, unsupported and temporarily unavailable
conditions remain distinct and non-disciplinary. Existing failure methods keep
their phase restrictions. Server denial does not wait for client cleanup;
`CleanupStatus::Required` persists until matching trusted acknowledgement, which
cannot reactivate a session.

Keep bounded active-session state, one pending attempt or exact committed
successor, and temporal continuity only for its declared lifetime. Resolve
atomic in-flight operations before terminal deletion; absent active state is
not recreated by an old permit. Challenge replay state follows ADR-0005.
Revocation negative history has a separate purpose: delete only after dependent
artifacts expire and trusted non-reuse/retired-generation rules prevent revived
authorization. Every enabled target class needs safe finite retention; indefinite
identity storage is not a workaround. Capacity exhaustion fails closed without
evicting still-required negative state.

## Consequences

Later implementations have explicit decision/expiry, retry, ordering and
retention obligations. The costs are availability loss when authoritative
state is unavailable and required proof of time, source completeness, owner
coherence and recovery. No runtime implementation is supplied. M2 must define
representation, trusted factories, possession, signatures, bounded parsing,
source authentication, time mappings, durable coordination and deletion before
operational use. M3 still owns TPM mapping.

## Threat-model impact

A0 delayed/replayed views, A1 hostile renewal/replica races, A5 compromised
issuer-key claims and A8 over-retention/disclosure are specified in the
[threat model](../THREAT_MODEL.md#m1-015-renewal-and-revocation-threats).
The affected boundaries include revocation source to issuer/RP, issuer/RP to
owner state, trusted time to protected decisions and retention to diagnostics.
A compromised required authority, dishonest source or full-session relay remains
residual risk. Local fencing cannot remove unobserved cross-service propagation.

## Privacy impact

No new evidence vocabulary, global device ID, account ban or raw attestation
identity disclosure to the game. Scope live bindings to publisher/session and
retain only for declared finite purposes. Ordinary diagnostics exclude complete
context, key/handle, identity, source revision, permit/proof and session timing.
Public trust-distribution disclosures have a separately approved contract.
See [retention requirements](../PRIVACY_MODEL.md#m1-015-authorization-state-retention).
No secure-erasure, backup or deletion implementation is claimed.

## Dependency and license impact

No dependency, Rust API, manifest, lockfile, schema, license boundary or runtime
TCB implementation changes. The approved test-only maintenance expands the
M1-013 closed scenario inventory and its registry/checker counts from 30 to 40;
it does not change the scenario schema, attack checker or validation semantics.
Future mechanisms and dependencies require their own security, maintenance,
provenance and license review.

## Validation

The [test strategy](../TEST_STRATEGY.md#m1-015-renewal-and-revocation-validation)
maps all 34 approved criteria to ten machine-readable scenario specifications,
existing invariants, positive controls, negative sequences and residual risks.
Schema/registry validation establishes structure and traceability, not runtime
authorization. Existing runtime regression checks guard compatibility only.
Candidate ADR/metadata/link/scope checks and independent semantic review precede
human contribution review; operational race/property/fuzz/mutation evidence is
required from the later implementations.

## Rollback

Before acceptance, revise or discard this Proposed decision without changing
runtime behavior. After acceptance, preserve this record and use an explicit
superseding decision and separately reviewed revert for incompatible changes.
Grace after expiry, known-revoked authorization, old-permit resurrection or
client-controlled state repair are not safe fallbacks.

## Primary sources

- [RFC 9334 sections 4, 8.4–8.5 and 10](https://datatracker.ietf.org/doc/html/rfc9334): role separation and policy-defined freshness; it does not define an OGIR permit.
- [RFC 7009 section 2.1](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1): informative comparison for propagation and scope, not an adopted OAuth endpoint.
- [RFC 7662 sections 4–5](https://www.rfc-editor.org/rfc/rfc7662.html#section-4): informative cache-staleness/privacy tradeoff, not an adopted introspection or TLS profile.
- Existing [security invariants](../SECURITY_INVARIANTS.md), [decision index](index.md), [protocol](../PROTOCOL.md) and the approved design are the OGIR-specific authorities. No accepted ADR is superseded.
