# M6-037: Renewal, revocation, and the structured result API
<!-- labels: type: implementation,area: verifier,area: protocol,status: needs-review -->
<!-- milestone: M6 Publisher SDK and Verifier -->


## Problem

The roadmap's lifecycle requires renewal and revocation APIs and a
structured result and diagnostic API; the integration target
requires a game server to handle allow / restricted / unsupported
/ retry / deny without parsing anything deeper.

## What this slice delivers

1. The STRUCTURED verdict (ADR-0033): VerdictKind families with
   wire spellings and retry guidance, stable reason codes from the
   M1 taxonomy, permit only on admissions; from_reason maps the
   taxonomy mechanically (unsupported is never a denial; transient
   failures retry).
2. `POST /v1/renew` (PermitRenewer): verify + unexpired +
   unrevoked, then a fresh challenge for the permit's policy
   context and full reprocessing - stale evidence denies.
3. `POST /v1/revoke` (RevocationAuthority): the exact target bytes
   become the denylist key; nothing is parsed (parser confusion is
   structurally impossible); idempotent.
4. Developer-mode daemon implementations honoring revocations at
   re-admission and renewal.

## Executed evidence (dev host)

- ogir-verifier: 130 lib tests green.
- NINE HTTP integration tests green: the M6-036 six plus the
  lifecycle roundtrip (allow -> stale-evidence renewal denies ->
  revoke confirms -> re-revoke idempotent), permit-parser
  confusion (clean Malformed, never a permit), and verifier time
  skew (NotYetValid under injected decision time).

## Security invariants

- Unsupported is never a denial on the wire; retry guidance is
  structural.
- Revocation is parser-proof and idempotent.
- No new dependencies.

## Out of scope

- The stable C SDK surface + fuzz targets (M6-038); the sample
  backend + conformance kit + no-ban docs (M6-039); the
  ten-category suite + exit audit (M6-040); a Restricted-emitting
  policy (arrives with such a policy).
