# M1-015: Specify renewal and revocation semantics
<!-- labels: type: architecture,area: protocol,area: verifier,area: privacy,risk: trusted-computing-base,risk: privacy,risk: compatibility,status: needs-review -->
<!-- milestone: M1 Domain Model -->

Status: Local integration candidate; no live GitHub issue yet. Human semantic design approval received on 2026-09-04.

## Problem

OGIR already defines fresh challenges, protected evidence-time continuity,
terminal local sessions and an attempt-bound revocation gate. It does not yet
define how renewal authorizes a successor, how current revocation knowledge
limits an already-issued permit, or how late/concurrent events avoid reviving a
terminal session. Without a shared semantic contract, later permit and server
implementations could disagree about expiry, outage handling or policy changes.

The approved semantic behavior is specified in the
[renewal/revocation design](../../docs/superpowers/specs/2026-09-04-m1-015-renewal-revocation-semantics-design.md). That proposal is the
single detailed scope authority for review; this issue summarizes it.

## Security invariants

- Preserve invariants 1–10: publisher/relying-party authority, context and key
  binding, fresh challenges, current revocation and no silent policy downgrade.
- Preserve protected identity/terminal lifecycle and cleanup requirements in
  invariants 14–15 and ADR-0006.
- Preserve invariants 34–38: fixed disclosure vocabulary, scoped identifiers,
  redaction and bounded purpose-specific retention.
- Preserve invariants 39–43: failure is not cheating, no renewal after loss of
  required protection, and server decisions do not trust local success reports.
- Extend ADRs 0005–0013 without weakening their accepted contracts or treating
  an unsigned report or volatile mock as a permit/production authority.

## Threats addressed

Old permits or evidence replayed as renewal; double successor issuance;
termination/expiry racing delayed success; policy/version/profile downgrade;
revocation-view rollback, age reset and missing target coverage; a revoked
verifier key certifying itself; accepting an unexpired but known-revoked permit;
stale distributed views creating unbounded admission; privacy leakage or unsafe
revocation-record deletion.

## In scope

- Documentation-only semantics for fresh renewal, predecessor/successor
  relations, pending-attempt behavior and terminal races.
- Current revocation applicability at appraisal, issuance and relying-party
  admission/continued protected decisions.
- Trusted finite permit/view validity, no grace, bounded staleness and explicit
  trust/time premises; no invented global-immediacy promise.
- Explicit non-weakening policy/profile transitions that preserve existing
  permitted evidence-time continuity; no numeric assurance ordering.
- Existing target categories, delegated authority, scope, ordered views,
  incomplete/contradictory knowledge and fail-closed recovery boundaries.
- Coarse failure/cleanup relationships and minimum scoped retention.
- Proposed ADR, aligned project documentation and registered attack-scenario
  requirements under the approved design.

## Out of scope

Rust types, methods, factories, state-graph changes, codecs, wire fields,
cryptographic algorithms, literal purpose labels, signer implementations,
production permit construction, a database/replication system, actual trust-root
recovery, an introspection service, timers, numeric production TTLs, new
background monitoring, TPM mapping, dependencies and changes to the M1-013
fixture format. No contribution signing or publication is authorized by this
issue proposal alone.

## Primary sources

- Existing repository invariants, architecture, protocol, threat/privacy model,
  ADRs 0005–0013 and inspected local/verifier source at merged `5f6d96d`.
- [RFC 9334](https://datatracker.ietf.org/doc/html/rfc9334), role separation and
  policy-defined freshness with a residual appraisal-to-use race.
- [RFC 7009 section 2.1](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.1),
  informative example of revocation propagation and related authorization.
- [RFC 7662 sections 4–5](https://www.rfc-editor.org/rfc/rfc7662.html#section-4),
  informative caching/staleness and disclosure tradeoffs.

The OAuth documents are comparisons, not an adopted protocol or transport
profile. See the [approval provenance](../../docs/superpowers/specs/2026-09-04-m1-015-renewal-revocation-semantics-design.md#12-approval-and-scope) for the exact source hashes and inspected baseline.

## Required interfaces

Semantic contracts only: live-session eligibility, one bounded pending renewal,
exact current predecessor and successor, policy-transition authorization,
complete applicable dependency evaluation, trusted ordered revocation views,
finite freshness/validity and final issuer/relying-party checks. No new public
API or evidence claim is specified.

## Positive tests

Planned examples: fresh same-context renewal; increasing noncontiguous evidence
sequence; explicit continuity-preserving non-weakening profile transition;
intact-state transient retry with fresh challenge; independently valid existing
permit during a bounded renewal attempt; exact source-view refresh; unrelated
revocation not matching this publisher/namespace; retryable terminal cleanup.

## Negative tests

Planned examples: replay, expired challenge/permit/view, late successor,
duplicate/out-of-order delivery, two renewals from one predecessor, terminal
invalidation race, source rollback/conflicting revision, missing class/scope,
unauthenticated revocation, known verifier-key revocation, stale cache replay,
policy downgrade and loss of protected continuity. All failures preserve the
existing non-disciplinary meaning and do not manufacture capabilities.

## Fuzz/property tests

The design defines future deterministic interleaving, monotonic-deadline,
single-successor, no-resurrection and namespace-separation properties. It adds
no runtime harness or parser now. Documentation integration must map the 34
acceptance cases to attack families and existing owner/profile registries,
without claiming those cases have executed. Later runtime implementations must
supply their own negative/race/property and mutation evidence.

## Privacy impact

No new raw context or evidence disclosure. Keep minimum bounded live-session
and revocation state with declared scope and safe deletion. Server-side
applicability does not require sending raw attestation identities or dependency
sets to the game. Retired targets must not regain authorization through early
GC, while indefinite identity retention is not an acceptable workaround.
`initial-maintainer` remains the privacy gate for retained/disclosed metadata.

## Dependency impact

None. Existing Rust graphs, dependency versions, Cargo.lock, default features and
M1-014 research cache remain unchanged. The approved test-only maintenance
expands the M1-013 closed scenario inventory and its registry/checker counts
from 30 to 40 while preserving the existing conformance cases, schema, original
30 scenarios, attack checker and validation semantics.

## Acceptance criteria

- Human approved approach A, including outage and policy-transition behavior,
  before documentation integration planning; preserve that semantic scope.
- The design's R01–R14, V01–V11, F01–F03, P01–P03 and C01–C03 cases are complete
  and consistent with existing contracts. These total 34 criteria; counted
  mechanically during review rather than inferred from headings.
- Every authority, rejection side effect, deadline comparison, race outcome,
  scoped retention purpose and explicit deployment prerequisite is stated.
- Final relying-party validation and owner installation are fenced against every
  applicable authority/policy/revocation/dependency update accepted before installation.
- Relevant project documents, a Proposed ADR/index entry and registered
  scenario/traceability records agree once integrated.
- Existing capability/terminal semantics and accepted temporal transition
  fixtures retain their meaning. No production mechanism is implied to exist.
- Review dispositions are recorded; final documentation gates and link/scope
  checks execute on the exact reviewed integration candidate.
- Any later code or wire work, new signed commit and publication receive their
  own applicable design/review/DCO and action authorization.

## Current state

Task14 is merged through PR30 as `5f6d96d`; its recorded post-merge CI and CodeQL
passed. Task15's local documentation/scenario candidate has passed validation
and independent semantic rereview. The unchanged aggregate passed 282 Rust
runtime/integration tests and 114 doctests, formatting, Clippy, conformance and
accounting checks, and dependency policy. Separate registry 58, abstract
conformance 445, attack parity 54 and documentation 16 tests passed, as did
warnings-as-errors rustdoc. Scenario validation covers 40 files; candidate-index
metadata and 14 ADRs passed. All 34 criteria map to the ten new scenarios.

The original 30-second limits remain unchanged. The prior abstract-selftest
timeout did not reproduce; its historical environmental cause is unresolved.
The final local contribution report records exact candidate identities,
commands, exits, review reconciliation and remaining deployment prerequisites.

These are compatibility and specification-traceability results. No renewal
authorization service, production permit or live revocation mechanism is
implemented. Human every-line review and DCO certification remain pending;
ADR-0014 is Proposed. No Task15 commit or publication was performed during
local validation; no live Task15 issue or PR is recorded.
