# M1-015: renewal and revocation semantics

- Status: Human-approved semantic design; locally validated documentation integration candidate awaiting human contribution review; production mechanisms unimplemented.
- Agent: codex.
- Date: 2026-09-04.
- Baseline: merged `5f6d96dedfe20141bafb0de7af84ef534298e9c4`, tree `d4d446238196693e8ea5825ceace1251d26914cd`.
- Deliverable: documentation-only semantic design, acceptance criteria and planned attack coverage. No new Rust API, protocol encoding, production service, dependency, numeric deployment setting, commit or publication.

## 1. Approved semantic approach

The human approved **A: bounded authorization and revocation freshness, with immediate local rejection of known applicable revocation**. Renewal never adds grace to an old permit. Each relying party makes its own current authorization decision using publisher-approved authority and independently supplied context.

| Approach | Benefit | Cost and limitation |
| --- | --- | --- |
| A — finite permit validity plus finite trusted revocation-view validity (recommended) | Gives explicit outage behavior and a finite stale-authorization bound without selecting transport | Requires trustworthy deadline evaluation, rollback protection and final decision checks; revocation is not globally instantaneous |
| B — synchronous authoritative revocation lookup for every authorization decision | Avoids using a cached revocation view for that decision | Makes connectivity/latency part of every decision; still requires race handling between lookup and use |
| C — allow existing permits until expiry even after applicable revocation is known | Simplest implementation and more availability | Reject: contradicts the fail-closed revocation invariant and unnecessarily preserves known-bad authorization |

B can later implement a stricter freshness policy under A. This proposal does not require OAuth, an introspection endpoint, a particular database, or a distributed consensus algorithm.

## 2. Existing contracts that remain authoritative

1. The publisher's challenge issuer durably registers a fresh nonce; the verifier claims it once using exact context and the half-open challenge window. A later rejection does not unconsume it (ADR-0005).
2. Local lifecycle order is `Active -> RenewalPending -> PermitReceived -> Active`. `Ended` and `Invalidated` never reactivate. Terminal entry records required, retryable cleanup (ADR-0006).
3. `RevocationChecked` is an opaque attempt-bound gate. It is not a live revocation service or permanent admission approval. `AppraisalResult` is unsigned and grants no permit or admission authority (ADRs 0007/0009).
4. Renewal uses new evidence for its exact fresh challenge, the same actual session key and associated handle, and an uninterrupted publisher/session/live-subject relationship. Evidence binding and renewal authorization remain different members of the existing five semantic purpose domains (ADRs 0008/0010).
5. Protected evidence time keeps the same scoped epoch, a strictly increasing sequence (gaps allowed), and a non-overlapping interval. Validated high-water advances before later appraisal; loss or contradiction terminates the session (ADR-0011).
6. A profile or selected-policy identity may change if its authority contract proves continuity and preserves high-water. Existing `history-valid-profile-transition` covers temporal admissibility, not a complete renewal authorization decision. M1-015 must not silently rewrite that fixture's meaning.
7. The M1-014 volatile research cache is not a durable store, revocation authority or production authorization adapter (ADR-0013).
8. Existing privacy restrictions, finite retention and non-disciplinary failure meanings remain in force. No new evidence claim family is added.

The first implementation under this task should integrate documentation and planned attack scenarios only. Production mechanisms remain M2 or later work.

## 3. Authority and semantic boundaries

| Actor | Authority in this proposal | Does not establish |
| --- | --- | --- |
| Publisher policy owner | Approved policies, revocation trust sources, target scope, freshness ceilings, permitted policy transitions | A fact merely asserted by a client |
| Publisher-authorized revocation authority | Authenticated, scoped, ordered current revocation state; trustworthy freshness origin | Health of a device, proof of possession, or policy approval outside its delegation |
| Publisher verifier / future trusted result and permit issuers | Fresh appraisal, complete revocation dependency evaluation and final issuance checks | A relying party's future admission decision |
| Relying party | Independent expected context, current permit/possession validation, current revocation and policy decision | Local evidence time, claims or client honesty |
| Registered collection authority and claim producers | Existing protected collection/claim contracts and continuity | Global permit time or permission to extend a deadline |
| Trusted local session/controller adapters | Existing lifecycle transitions and cleanup after validated local events | Server admission, arbitrary clock conversion or a new public capability factory |
| Game, bridge and generic attester | Request, carry and present material | Renewal eligibility, revocation state, authority repair, or expiry extension |

The following are semantic relationships, **not proposed wire fields or Rust types**: current live-session authorization generation; one pending renewal attempt; exact predecessor/successor relationship; applicable dependency set; trusted revocation view and its scope/order/freshness bound; approved policy-transition relation. Later representations must preserve these relationships without enlarging the evidence vocabulary or disclosing unnecessary identities.

## 4. Finite time and freshness contracts

### 4.1 Separate clocks and events

Challenge validity continues to use its existing publisher-verifier authority. Evidence collection uses its registered local protected source. Protected-result validity, permit validity and relying-party deadline evaluation require their own publisher-approved trusted contracts. Client UTC and raw evidence interval values cannot substitute for those contracts.

M1-015 defines comparisons only when the relevant authority contract makes them valid. It does not introduce a local-to-server time conversion, synchronization protocol, skew allowance or numeric TTL. A deployment that cannot prove a required comparison cannot authorize the protected action. If a trusted clock contract provides a bounded interval for the decision time, eligibility must hold for the entire interval: its lower bound must be at or after an applicable not-before/freshness-origin boundary, and its upper bound strictly before every exclusive expiry. Uncertainty is not late-acceptance leeway. Different time domains still require an approved mapping contract.

### 4.2 Effective authorization deadline

A future permit must have a finite, nonempty half-open interval. At a relying-party decision, the current permit must be valid, the required protected result must meet its declared validity contract, and every applicable revocation view must still be usable. All required conditions are conjunctive.

For a common validated decision-time domain, the latest possible authorization deadline is the minimum of permit expiry, any result-validity deadline required by that permit contract, and all applicable revocation-view deadlines. Otherwise evaluate each comparison through its registered authority contract; do not take a mathematical minimum of incomparable clock values. Equality with any exclusive deadline is already too late. There is no grace period or timer reset on retry, reconnect, replay, refresh failure or process restart.

Each operational profile must declare finite maxima for permit validity and revocation-view age, a finite authorization reevaluation interval where decisions cover a continuous activity, and bounded renewal attempts/work/state. Values and time units are deployment/profile decisions requiring later validation, not defaults invented here. Missing or unbounded mandatory limits make the profile ineligible.

### 4.3 What a usable revocation view means

A view must authenticate the authorized publisher/source and delegated scope; cover every required target class; identify one coherent authority generation and ordered revision; and carry a trustworthy freshness origin and exclusive deadline. A consumer checks both the view and the source's continuing authority. Arrival time alone cannot make old information fresh. The first profile consumes complete coherent semantic views; partial/delta transport cannot masquerade as complete coverage. A future delta format must prove reconstruction against the correct base before any resulting view is usable.

Older revisions are rejected without replacing trusted state. An identical revision may be received idempotently but cannot extend its deadline; conflicting content at the same revision is unavailable/contradictory state. Invalid or unauthorized input cannot advance high-water or revoke a session. A higher number is not itself evidence of authenticity or freshness. Rejecting an invalid, unauthenticated or older candidate preserves an independently usable current view. It does not invent a revocation or extend that view. Authenticated conflicting authority state is different: fail closed for the affected scope. Ordered revision exhaustion cannot wrap to old state; recovery requires a separately authenticated trust-generation transition. Missing coverage, an expired view, invalid authority, untrusted time or lost rollback protection cannot be treated as an empty revocation set.

For the first semantic profile, a revocation becomes effective when the publisher-authorized authority commits it as applicable. A later view in that scope must include its effect. Scheduled future revocations and trust-root recovery transitions need separate explicit designs. A newer view cannot silently remove a revocation or reduce a minimum-version constraint within the same trust generation.

A newer authenticated complete view may replace an older view while the session is still live. This can move the current revocation freshness limit forward, but never changes the old view's deadline or the permit's immutable expiry. Refresh alone does not issue a permit, renew session continuity or revive a session that already became terminal during a gap. Invalid refresh attempts leave any still-usable current view unchanged.

### 4.4 Honest propagation bound

A consumer rejects a known applicable revocation at its next protected decision; it does not wait for the current permit to expire. A disconnected consumer may temporarily know only an older still-valid view. The finite view deadline limits that residual interval.

A bound from authority commitment requires all of these premises: the authority's freshness origin predates/includes the committed state it represents; later views incorporate committed effects; old views cannot extend their age downstream; deadline comparison has a declared trustworthy error bound; continuous activity is rechecked within its declared bound. Under those premises, an old view cannot justify authorization beyond its original age ceiling plus the declared time-evaluation and reevaluation bounds. A shorter permit deadline tightens the limit. No numeric or globally instantaneous revocation promise is made. A source that fails to publish the committed state honestly is a TCB failure, not solved by a cache timeout.

## 5. Renewal lifecycle

### 5.1 Eligibility

An authoritative live-session record must exist. It binds the publisher, game/build, account scope, match, protected session/live subject, actual key and handle, selected policy/profile and permitted assurance class. Values are independently validated, not taken from a client-renamed old permit. The current authorization must not be terminal, expired or already affected by a known applicable revocation.

One logical **session-authorization owner**, designated by trusted publisher/relying-party configuration, owns the current admitted generation, terminal disposition and at most one pending renewal for the exact publisher/protected-session context. Every relying-party instance or replica enforcing that context must make its decision against this coherent owner state. Replica-local cached permit state cannot override successor installation or termination at the owner. If coherence cannot be established, protected authorization is unavailable even when the cached permit has not expired. This requirement does not mandate a database or consensus algorithm; it is a prerequisite that the later implementation must prove. Ownership migration or independent active owners for the same context are outside the first profile.

Generation is not the evidence collection sequence; one cannot substitute for the other. The owner distinguishes a pending attempt, a committed-but-not-installed successor and the current admitted generation. These semantic states do not alter the Rust local-session graph. Initial session establishment, key creation and permit construction remain later mechanisms.

### 5.2 Required sequence

1. Validate live-session eligibility and the independently selected context/policy transition; reserve a bounded attempt against the exact current predecessor.
2. Obtain a fresh durably registered challenge. Collect/revalidate and freeze new evidence under the existing protected epoch and temporal rules.
3. Run every existing verifier gate in its required order. An earlier `RevocationChecked` observation cannot be reused as a permanent grant. No raw `AppraisalResult`, report, key handle or mock-cache success can mint a permit.
4. Before the future issuer commits a renewal grant through the session-authorization owner, recheck the live predecessor, authorization deadline, current policy/transition and applicable revocation state. Serialize this commit against terminal invalidation, predecessor replacement and the issuer's accepted policy/revocation updates. This is an abstract atomicity/fencing requirement, not an assertion that a cross-service transaction already exists.
5. Bind the successor to the exact attempt, predecessor, session/key/context and approved policy/profile. At most one successor can commit from a predecessor. No automatic retry creates a second successor from that same predecessor.
6. The relying party performs final successor validation and installation as one fenced operation against the session-authorization owner's current predecessor and terminal state, the predecessor's effective deadline, and every issuer-authority, policy, revocation and required-dependency update accepted before installation. Within that fence it independently validates the successor, its trusted issuer, complete current revocation coverage, exact context and required session-key possession, then installs the newer current generation atomically at the owner. Validation performed before the fence is insufficient. Every enforcing replica observes that ordering; an older/reordered/duplicate delivery cannot roll back or extend authorization.
7. The trusted local adapter supplies a **newly validated renewal permit** through `RenewalPending -> PermitReceived -> Active`. The old permit cannot mint another `ValidatedPermit` completion or bypass that route. No new local lifecycle edge is introduced.

Grant commitment and installation are separate serialized owner events. Once a successor is committed, cancelling delivery or timing out cannot erase that fact and mint another successor from the same predecessor. The first profile permits only bounded authenticated redelivery of that exact committed artifact, followed by complete current validation; it permits no re-signing, changed deadline or new grant disguised as redelivery. If redelivery cannot succeed before the predecessor's effective deadline and the successor's own validity limits, invalidate the session and recover through a new initial session. Before grant commitment, an abandoned attempt may be resolved/cancelled and a bounded fresh-challenge attempt may start while eligibility survives.

Until successor installation, the owner still identifies the predecessor as current and it can only be evaluated under section 5.3. Once installation commits, no later protected decision at any enforcing replica may authorize that predecessor. The later mechanism must prove these event linearization points and coherent owner access. Decisions already committed before replacement are not retroactively rewritten; continuing protected activity remains subject to the bounded reevaluation contract. A duplicate of the currently installed artifact can only receive an idempotent acknowledgement after current validation, never create another renewal or change a deadline.

### 5.3 Pending renewal and transient failure

Starting renewal grants nothing and extends nothing. The local `RenewalPending` phase is orchestration state; it does not itself revoke or prolong an independently valid server permit. A relying party may continue honoring its existing current permit only while **all** of its original validity, possession, policy, revocation and continuity requirements remain satisfied. This permits bounded use of still-valid knowledge, not fallback after expiry or loss.

A transient attempt failure is retryable only while authoritative state is provably intact/recoverable and the session has not reached its effective deadline or a terminal condition. Retry uses a fresh challenge and a new attempt after an uncommitted prior attempt is resolved/cancelled. A committed successor instead follows the exact-artifact redelivery rule in section 5.2. A consumed nonce stays consumed, and a validated temporal observation stays advanced. One local pending phase may contain such bounded attempts; it cannot return to Active using the old permit.

At expiry with no usable successor, stop protected authorization and invalidate the protected session. A late success must not resurrect it. Recovery requires a new initial session/key/handle/challenge and appraisal. A subsequent valid revocation view cannot revive a session already terminally invalidated while its view was stale or unavailable.

### 5.4 Policy/profile changes

Unchanged policy/profile still requires current appraisal and current revocation checks. Changed policy/profile may renew the same session only through an explicit publisher-approved transition relation that preserves all previously required security obligations and assurance, satisfies the relying party's newly selected context, and proves the same protected epoch and retained temporal high-water under the new authority contract.

Numeric policy versions, familiar profile names or a client claim of “stronger” are not that proof. An absent or unproven transition relation cannot authorize same-session migration; use a fresh initial session under independently approved policy instead. Known applicable revocation or a newly violated minimum version terminates the old affected session, rather than being bypassed by migration. A weaker/restricted gameplay alternative is a separate explicit relying-party choice and new protected context, not successful renewal of the original protected mode.

## 6. Revocation applicability and races

### 6.1 Target coverage

Use the existing architectural target classes: protocol versions, agent/bridge builds, platform profiles, policies, attestation identities, verifier keys, and game/runtime manifests. No account-ban, global device fingerprint or universal player revocation identifier is introduced.

Each class requires an approved source/delegation, exact namespace and match rule. Minimum-version ordering must be defined by the registered version contract; a version comparison is not an assurance comparison. A target not applicable to the candidate cannot revoke it merely because a string or version happens to match in another namespace.

The verifier must derive a bounded complete dependency set from authenticated artifacts, registered producers and trusted configuration. The relying party must be able to establish current revocation applicability for its permit through a trusted publisher evaluation path. That does not require disclosing the raw dependency set or attestation identity to the game. Missing classes, unknown mandatory rules or an unresolvable dependency mean unavailable/unsupported protected authorization, never implicit acceptance.

### 6.2 Required consumers

- Challenge admission may reject already-known revoked policy/requirements before expensive work; it cannot replace later checks.
- Every initial and renewal appraisal checks its applicable dependencies.
- Future result/permit issuance checks the current issuer authority and fences against accepted policy/revocation changes before commit.
- The relying party validates issuer-key revocation and all required permit dependencies at admission and subsequent protected decisions, including already-active permits. A valid signature alone is insufficient.
- Revoking a verifier signing key is evaluated using independent publisher-authorized revocation/trust authority. The revoked signing key cannot vouch for its own unrevoked status or authorize a replacement trust root.

If two independent consumer views differ, one party's success does not override the other's current failure. Across services, propagation delay is governed by section 4.4; local fencing does not pretend to eliminate that delay.

### 6.3 Race outcomes

| Race | Required outcome |
| --- | --- |
| Accepted revocation/policy update before issuer commit | Re-evaluate against it; do not issue based only on the earlier checked view |
| Revocation after issuance but before relying-party admission | Current relying-party check rejects when the effect is known; stale knowledge remains bounded by its original deadline |
| Known applicable revocation at the relying party, or expiry, before renewal installation | No renewed admission and no terminal resurrection; a not-yet-observed remote revocation remains subject to the bounded propagation rule |
| Two renewals against one predecessor | At most one committed successor; losers do not refill nonce/temporal state |
| Older permit arrives at any replica after successor installation at the owner | Reject for activation; no replica-local generation rollback or deadline extension |
| Session terminates while an attempt is in flight | Cancellation/fencing prevents activation; late completion cannot recreate missing active-session state |
| One trusted source is current but another required source is stale | Refuse protected authorization; combine requirements conjunctively |
| Source rollback or contradictory revision during normal traffic | Fail closed within the affected scope; do not accept repaired state from the client |

## 7. Failure and cleanup

| Established condition | Semantic disposition | Continuation |
| --- | --- | --- |
| Authenticated, applicable revocation | Revoked, non-disciplinary | Stop affected protected authorization; invalidate live affected session; recover only through a new authorized session after remediation |
| Expired permit / effective deadline | Expired for this authorization | No grace; terminal invalidation if no usable installed successor |
| Lost/contradictory session continuity or authoritative temporal high-water | Protected session lost | New session/key/handle/epoch required |
| Temporary renewal service failure with intact state and still-valid prior authorization | Retry/unavailable attempt | No new grant; prior permit only under section 5.3; fresh-challenge retry within bounds |
| Revocation knowledge stale, unavailable or lacking required coverage | Unavailable, not a claim of revocation | No new authorization; existing use stops when no required valid view remains; terminal invalidation at the effective deadline |
| Unknown critical rule/profile | Unsupported critical requirement | Cannot ignore it or silently select a weaker mode |
| Context, proof, replay or policy validation failure | Existing coarse reason as applicable | No successor; only independently intact existing authorization may survive; terminal findings take priority |

These are semantic outcomes, not new methods or permission to call an existing phase-restricted `VerifierFlow` failure method from any phase. Future adapters must map them through the correct public failure contract. Never relabel unavailable as revoked or an integrity failure as cheating.

Terminal local entry and cleanup remain ADR-0006 behavior: `CleanupStatus::Required` persists until matching trusted acknowledgement, retries are idempotent, and cleanup completion cannot reactivate the session. Server authorization denial does not depend on a client acknowledging cleanup. The trusted local adapter's deadline observation and cleanup liveness need their own validated implementation; client UTC is not enough.

## 8. State, retention and privacy

Keep the minimum bounded live-session binding, current generation, one pending attempt or exact committed successor awaiting installation, and validated temporal state. Authenticated redelivery storage is active-session only and cannot outlive its eligibility/deadline; it is not a permanent permit archive. Configure finite limits on trusted authorities/namespaces, view/target/dependency counts, pending work and retained payloads; capacity exhaustion fails closed without dropping still-needed negative state. Resolve/cancel atomic in-flight operations before terminal deletion. An absent session cannot be re-created by presenting an old permit; new establishment follows its own trusted initial path. Session/key/epoch values remain scoped and confidential.

Challenge replay retention stays governed by ADR-0005. Do not mix it with session authorization or revocation history. Revocation source order/high-water is authority metadata, not the per-session evidence high-water.

Before operational implementation, each revocation target class must define a finite eligibility/retention policy. Negative records cannot be garbage-collected while an old still-eligible target or artifact could regain authorization; retirement needs both expiry of dependent artifacts and a trusted non-reuse/retired-generation rule. Do not solve this by indefinite retention of publisher-scoped attestation identities. If safe bounded retention cannot be established for a class, that class/profile cannot be enabled. Numeric limits, durable storage, recovery, backups and deletion mechanisms need later designs.

Ordinary debug/display/errors/logs/traces/metrics/crash/support/test output expose only coarse disposition. No raw session/key/handle, account, complete context, dependency identity, source epoch/revision, permit, evidence-time, proof or per-session timing is added. Public trust-distribution artifacts may have their separately approved disclosure contract; this does not authorize putting sensitive targets into diagnostics or game responses. Owner `initial-maintainer` reviews any retained or disclosed authorization metadata; required assurance profile is `all-protected-modes` unless a narrower registered definition is explicitly approved.

## 9. Acceptance criteria and planned validation

All rows below are **required design examples / future tests**, not executed runtime results. Documentation integration must attach each to a registered attack scenario and invariant without changing the current abstract-conformance format's meaning.

| ID | Concrete criterion / distinguishing example |
| --- | --- |
| R01 | Successful same-context renewal uses a new registered challenge, new current claims, same key/epoch, increasing sequence and every verifier/permit/activation gate |
| R02 | Reusing a nonce/evidence/old renewal cannot authorize; later rejection never releases its consumed nonce |
| R03 | Starting/retrying renewal never changes the old permit's expiry or revocation-view deadline |
| R04 | With intact continuity and still-valid trusted views, a transient attempt failure grants nothing but may leave independently valid existing authorization usable |
| R05 | Exact permit/view expiry stops authorization; a reply arriving after terminal invalidation cannot revive the session |
| R06 | Session termination racing renewal commit/installation prevents activation and cannot recreate deleted active state |
| R07 | Two attempts using the same predecessor yield at most one committed successor; retries cannot roll back temporal high-water |
| R08 | Delayed predecessor delivery after successor installation cannot restore older rights; duplicate current-artifact delivery cannot extend time |
| R13 | After owner installation/termination, another RP replica cannot authorize from stale local state; inability to consult coherent owner state is unavailable |
| R14 | Committed successor response loss permits only exact-artifact redelivery before deadlines; cancellation cannot mint another successor from its predecessor |
| R09 | Allowed policy/profile transition proves non-weakening and same epoch/high-water; retain existing valid temporal-profile-transition semantics |
| R10 | Higher policy version alone, weaker assurance or absent transition authorization cannot authorize same-session migration |
| R11 | Restart, lost high-water, epoch/sequence rollback and interval overlap terminate; sequence gaps alone do not |
| R12 | Expired challenge, profile-duration violation or late evidence cannot become fresh through permit/result/client timestamps |
| V01 | Every architectural target class has one declared authority/scope/match/retention rule; omission of a required class fails closed |
| V02 | Known applicable revocation blocks an unexpired permit; an unrelated publisher/namespace target does not |
| V03 | Source revision rollback is rejected; equal-revision identical redelivery is idempotent; conflicting content fails closed |
| V04 | Old authentic view replay or receipt after network delay cannot renew its freshness deadline |
| V05 | Unknown, expired, unauthenticated or incomplete view is unavailable/unsupported, never an empty success or fabricated revocation |
| V06 | Revocation between ordinary appraisal and issuance must be rechecked/fenced at issuance; after issuance it is checked at the relying party |
| V07 | Verifier-key revocation is independently enforced by the relying party; the revoked key cannot certify its own recovery |
| V08 | Staleness of any required view defeats authorization even if every other view is current |
| V09 | Strictest effective deadline and finite reevaluation contract bound stale acceptance; no claim of zero cross-service propagation delay |
| V10 | Source/trust recovery cannot resurrect terminal sessions or roll back revocation state from a client-provided artifact |
| V11 | A newer authentic complete view can refresh a still-live session within its unchanged permit expiry; invalid candidate views preserve usable current state and cannot revive an expired/terminal gap |
| F01 | Revoked, expired, continuity-lost, unsupported and temporarily unavailable cases remain distinct and non-disciplinary |
| F02 | Cleanup failures preserve Required; a later matching completion changes only cleanup status, never lifecycle terminality |
| F03 | Raw reports, mock-cache success and key handles never substitute for possession, validated permits or issuer authority |
| P01 | Every new retained semantic value has scope, finite retention purpose, deletion condition and diagnostic exclusion |
| P02 | Safe revocation GC cannot re-enable retired targets; generation/non-reuse constraints do not become a global device identifier |
| P03 | Full-state and synthetic diagnostic examples contain no unapproved context, identity, proof or timing values |
| C01 | Existing Rust graphs, failure eligibility, dependency/lockfile, M1-013 corpus/schema and M1-014 research boundary remain unchanged |
| C02 | Final documentation/ADR/scenario links, owner/profile registry and semantic traceability are checked on the reviewed candidate |
| C03 | Deployment prerequisites are explicit gates, and no unimplemented mechanism is described as proven or production-ready |

Required adversarial scenario families: pending/late renewal; generation/terminal races; policy-transition downgrade; revocation rollback/stale replay; issuance/admission revocation races; verifier-key revocation; missing target coverage; stale-view outage; revocation retention/diagnostic privacy. Reuse established owners/profiles and the existing scenario validator. This proposal reserves no global scenario ID until repository integration checks uniqueness.

## 10. Documentation integration and later work

Human approval was received on 2026-09-04. The documentation integration plan covers:

- canonical local issue `planning/issues/015-renewal-revocation-semantics.md`;
- formal Task15 spec under `docs/superpowers/specs/`;
- a new Proposed ADR and index entry (next available ID must be rechecked; 0013 is currently the latest);
- aligned architecture, protocol, threat/privacy model, roadmap, test strategy and terminology where necessary;
- registered machine-readable attack scenarios and traceability for the accepted semantic rules.

Do not edit prior accepted ADR decisions or completed checkpoint history. Explain how this extends ADRs 0005–0013; if a real contradiction requires changing an invariant, stop and seek explicit superseding design approval.

Later M2 work must separately specify protected-result/permit representation and validity, exact renewal proof coverage and domain separation, bounded parsing, authority factories, trustworthy server-time/deadline mapping, source freshness and ordered state authentication, atomic issuer/RP coordination, multi-party delivery/acknowledgement, durable recovery and retention mechanisms. No mock test can satisfy those deployment gates by itself. M3 still owns TPM mapping. No runtime implementation plan is authorized by this design-only task.

## 11. Evidence and limitations

Repository contracts were inspected at the exact merged tree; the retained Task14 checkout is byte-identical to that tree and remains clean. No renewal authorization service, production permit object or operational revocation feed was found in the inspected runtime paths. Existing local and verifier capabilities are structural research boundaries. This proposal is a design choice, not a claim that those mechanisms already exist.

Primary-source context (external text is informative; OGIR-specific rules above are proposals):

- [RFC 9334 sections 4, 8.4–8.5 and 10](https://datatracker.ietf.org/doc/html/rfc9334): verifier and relying-party appraisals have different owners; freshness is a policy decision with a residual race after appraisal. It does not select OGIR permit validity or a renewal protocol.
- [RFC 7009 section 2.1](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1): its OAuth revocation example recognizes propagation delay and potentially related grants. Used only as an example of why revocation scope and observation must be explicit, not as an OGIR endpoint or response contract.
- [RFC 7662 sections 4–5](https://www.rfc-editor.org/rfc/rfc7662.html#section-4): caching authorization information trades load for staleness, and privacy-sensitive identifiers require care. Informative comparison only; OGIR does not adopt OAuth introspection or its TLS-version text.

The approval provenance and inspected source baseline are recorded below; the integration evidence is summarized in the linked issue and test strategy. No performance, exhaustive scheduling, secure erasure, production TTL or global instantaneous revocation claim is made.

## 12. Approval and scope

The human approved approach A and the written semantics on 2026-09-04, then
authorized the documentation integration plan and its local execution. The
approved source SHA-256 is
`2e1969abef5f6348caf787ee965875d0f831eb508366e3fb1851e2d983d525ba`.
The original local issue SHA-256 is
`cb37ea854955ea1c5e844645f7d249c66396b4ed078fe7297440b854c76aaa02`.
These identify pre-integration sources, not these normalized repository copies.
The inspected source tree is `d4d446238196693e8ea5825ceace1251d26914cd` at the
merged baseline named above. Its relevant authorities are ADRs 0005–0013,
the security invariants, architecture, protocol, privacy/threat models, local
session and verifier implementation, and existing temporal-profile-transition
fixture.

Independent design review closed two wording ambiguities: one coherent owner
must order authorization across replicas, and known local revocation must be
distinguished from bounded remote propagation. The reviewed source above
includes both corrections. Original RFC-editor access for RFC 9334 returned a
rate-limit response; its official IETF datatracker copy was read successfully.

See the [local issue](../../../planning/issues/015-renewal-revocation-semantics.md),
[integration plan](../plans/2026-09-04-m1-015-renewal-revocation-semantics.md)
and [test strategy](../../TEST_STRATEGY.md) for integration scope and evidence.
The approval does not certify a new contribution under DCO or authorize signing
or publication. The resulting ADR remains Proposed during integration review.
