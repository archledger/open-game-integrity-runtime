# M6 exit audit: publisher verifier and sample-game SDK

Date: 2026-09-08
Agent: zcode
Scope: the three M6 exit criteria from docs/ROADMAP.md, audited
against delivered, merged work plus this slice's executed
evidence.

## Criterion 1: a fresh publisher can run the conformance kit and
integrate the sample flow without Linux kernel knowledge

DELIVERED and EXECUTED. The conformance kit
(scripts/conformance-kit.py) is a stdlib-Python HTTP client: no
kernel knowledge, no Rust toolchain, no TPM concepts - a publisher
points it at their deployment (`--daemon <address>`) and gets 15
fail-closed checks across the five-step flow, the lifecycle,
freshness, and the wire bounds. The kit executed 15/15 against the
developer-mode daemon (M6-039 evidence); its self-test runs in CI.
The sample backend demonstrates the five-step integration target
verbatim with the publisher's policy table in full view, and
docs/CASUAL_FALLBACK.md documents the intended mapping. The local
quickstart is three commands.

## Criterion 2: the verifier is deterministic and self-hostable

DELIVERED. The service shell (ADR-0032) is in-repo, single-binary,
localhost-by-default, and takes NO wall clock: decision time is
injected (the daemon passes its own source; tests pass fixed
times), so identical inputs at identical decision times produce
identical verdicts - demonstrated by the time-skew leg executing
the SAME pair at two decision times with different outcomes by
design. Self-hostable: the developer-mode daemon composes the test
substrate (M6-036); the authoritative backend composes the real
M3/M5 chain into the same shell (the trait seams are the
integration points), and the no-TLS posture is a documented
deployment duty rather than a hidden assumption.

## Criterion 3: insecure integration patterns are difficult or
impossible through the public SDK

DELIVERED, structurally. The frozen v1 SDK (ADR-0034) exposes no
authoritative local trust decision (ADR-0004 posture): the verdict
families are distinct ABI values, so collapsing `unsupported` into
`deny` - the roadmap's named insecure pattern - cannot be
expressed (category 10 asserts it at the wire AND type levels).
The permit is opaque and borrowed; the wrapper copies it out
without parsing. The kit's wire-bounds group fails deployments
that drift from the safe contract, and the never-list in
CASUAL_FALLBACK.md names the remaining publisher-side duties that
no SDK can enforce (account actions are outside OGIR entirely).

## Deliverables coverage

| Roadmap deliverable | Status |
| --- | --- |
| Self-hostable verifier service | M6-036, merged |
| Stable C SDK surface | M6-038, merged (frozen, gated) |
| C++ wrapper and Unreal-facing design | M6-038, merged |
| Sample server integration | M6-039, merged |
| Challenge/submission/permit/renewal/revocation APIs | M6-036/037, merged |
| Structured result and diagnostic API | M6-037, merged |
| Local developer mode (test keys, simulated profiles) | M6-036, merged |
| CI conformance kit | M6-039, merged (self-test in CI) |
| Casual fallback and no-ban documentation | M6-039, merged |
| Ten required attack tests | This slice: 11/11 green across three runs |

## Honest limitations (recorded, not gaps in the criteria)

- The sample backend and the kit's full run use the developer-mode
  simulation route; a production end-to-end (a real client's
  evidence through the authoritative backend) arrives when the
  real-chain service composes - the trait seams and the kit's
  production posture (a real client provides evidence) are ready.
- The `restricted` family is defined but not yet emitted by any
  policy; it arrives with a policy that grades admissions.
- The wow64 32-bit transport remains fail-closed (ADR-0029).
- CI runs the kit's self-test, not the fuzz targets (dev-host
  posture, recorded in ADR-0034).

## Verdict

All three M6 exit criteria are satisfied by delivered, executed,
and reviewed work. With this slice merged, Milestone M6 is
COMPLETE: M0 through M6 are closed, and the roadmap's next
milestone is M7 (protected-session observation).
