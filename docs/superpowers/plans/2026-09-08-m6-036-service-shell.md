# M6-036 plan: the verifier service shell and the developer-mode daemon

Date: 2026-09-08
Agent: zcode
Authorization: standing publication+merge authorization; all gates
mandatory.

## Objective

Open M6: the self-hostable service shell (bounded HTTP + strict
flat JSON + the first three lifecycle routes) and the
developer-mode daemon (test keys, simulated profiles) composing the
mock substrate into it.

## Steps

1. Worktree research/m6-entry off 0f2134f (the entry-scoping
   worktree, promoted to the slice).
2. bjson (the flat-object codec) and http (the bounded endpoint)
   with negative tests first.
3. The service shell with trait-injected semantics and decision
   time as a parameter.
4. The developer-mode daemon as a NEW mock-tier crate; the
   isolation gate amended to allow and assert it.
5. The six HTTP integration tests over real TCP.
6. ADR-0032, index row, ROADMAP boundary, planning issue, plan.
7. House gates, signed commit, publication, CI, merge, post-merge
   verification.

## Development notes

- The authority-inventory test pins lib.rs's module list EXACTLY:
   adding modules means updating the pin (found by test, updated
   faithfully).
- JsonError details are &'static str: accessors must not embed the
  borrowed key (lifetime).
- The codec's hex members exceed the string cap: the VALUE limit
  must be selected by the key BEFORE parsing (MAX_HEX for _hex).
- The service is rebuilt at each challenge issuance so the
  exact-context policy matches what was issued (the first draft
  with an empty expected context denied everything).
- MockVerifierService::new consumes its signing key by value; the
  deterministic seed makes the reconstructed key identical.
- The isolation gate's production-path loop excludes the new
  mock-tier consumer and asserts its existence + shell dependency.

## Boundaries

In: shell modules, daemon crate + bin, gate amendment, ADR-0032,
docs, integration tests.
Out: renewal/revocation + diagnostics (M6-037); SDK + fuzz
(M6-038); sample backend + kit (M6-039); suite + audit (M6-040).
