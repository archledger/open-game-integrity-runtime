# ADR-0033: Renewal, revocation, and the structured result API

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M6-037 issue](../../planning/issues/037-lifecycle.md)
- Supersedes: None
- Superseded by: None

## Context

M6-036 shipped the service shell with challenge issuance, evidence
submission, and permit issuance. The roadmap's lifecycle asks for
renewal and revocation APIs and a structured result and diagnostic
API; the integration target requires a game server to handle
allow / restricted / unsupported / retry / deny without parsing
anything deeper.

## Decision drivers

- The verdict wire shape must make unsupported and retry states
  FIRST-CLASS: the "publisher accidentally treats unsupported as
  cheating" category is a wire-shape problem before it is a policy
  problem.
- Renewal follows ADR-0014: fresh evidence, one coherent session
  owner, no migration.
- Revocation must be parser-proof: no interpretation of the target
  before denylisting.

## Options considered

1. **Keep the flat allow/deny verdict with a reason string.**
   Loses the unsupported/retry distinction into string parsing by
   clients - exactly the confusion the roadmap warns about.
2. **A structured verdict (kind + stable reason code + permit only
   on admission) plus explicit /v1/renew and /v1/revoke routes.**
3. **A generic result-object schema.** Over-design at this stage;
   the conformance kit (M6-039) pins the stable shape later.

## Decision

Adopt option 2. `WireVerdict` becomes a STRUCT: the `VerdictKind`
(allow / restricted / unsupported / retry / deny) with wire
spellings and retry guidance, the stable `reason_code` drawn from
the M1 taxonomy, and `permit_hex` present only for admissions.
`from_reason` maps the taxonomy mechanically: the three Unsupported
codes are never denials; TransientFailure and AttestationUnavailable
carry retry guidance. The verdict encoder emits
`{"verdict":...,"reason_code":...[,permit_hex]}`.

Two new routes with trait-injected semantics:
`POST /v1/renew` (`PermitRenewer`: verify + unexpired + unrevoked,
then a FRESH challenge for the permit's policy context and
processing of the submitted evidence against it - stale evidence
embedding the old challenge denies) and `POST /v1/revoke`
(`RevocationAuthority`: the exact target bytes become the
denylist key; nothing is parsed, so parser confusion is
structurally impossible; revocation is idempotent).

The developer-mode daemon implements both: renewal issues the
renewal challenge and reuses the full verify-replay-policy-permit
chain; revoked permit bytes are honored at re-admission and
renewal.

## Consequences

- The full five-route lifecycle (challenge, evidence, permit,
  renew, revoke) is live on one deterministic shell.
- The structured verdict is the shape the C SDK surfaces
  (M6-038) and the conformance kit pins (M6-039).
- Restricted is defined but not yet produced by the mock policy;
  it arrives with a policy that emits it.

## Threat-model impact

Server-side attack legs now executable: stale evidence renewal
(denies), revoked-permit re-admission (denies), permit parser
confusion (structural impossibility + clean Malformed), verifier
time skew (NotYetValid via injected decision time), duplicate
submission (ReplayDetected, M6-036).

## Privacy impact

None: the wire carries publisher-chosen identifiers and digests.

## Dependency and license impact

None.

## Validation

Executed on the dev host: ogir-verifier 130 lib tests green; the
daemon's NINE HTTP integration tests green - the original six plus
the lifecycle roundtrip (allow -> stale-evidence renewal denies ->
revoke confirms -> re-revoke idempotent), permit-parser confusion
(clean Malformed, never a permit), and verifier time skew
(NotYetValid under injected decision time). Full house gates in
the slice record.

## Rollback

Revert the commit; the structured verdict, routes, and daemon
impls disappear together (M6-036's flat verdict returns).

## Primary sources

- ADR-0014 (renewal/revocation semantics), ADR-0032 (the shell).
- The executed integration runs (2026-09-08).
