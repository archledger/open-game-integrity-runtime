# ADR-0046: The TBS API-layer attack families

- Status: Accepted
- Date: 2026-09-09
- Owners: Initial maintainer
- Related issues: [Local M10-050 issue](../../planning/issues/050-tbs-attack-families.md)
- Supersedes: None
- Superseded by: None

## Context

The M10 roadmap requires API-layer attack tests against the TBS
compatibility layer (M10-049): resource exhaustion, malformed
command buffers, cancellation races, persistent-identity and
cross-prefix leakage at the API layer, and
vTPM-presented-as-hardware. M10-048 covers the manager-level
families; the layer's own surface was functional-tested only.

## Decision drivers

- The five roadmap attack families must be EXECUTED, not argued.
- Invariants 16/17 (no physical TPM path; compatibility
  terminates at the isolated vTPM), 18 (no universal game
  identifier), 20 (claim classes distinguished), 23 (fixed
  parser limits), 26 (malformed never allows), 40 (outcomes
  distinguishable).
- The M9 registry pattern: attack scenarios are recorded as
  executable-evidence registry entries with invariant mappings.

## Options considered

1. **A dedicated attack gate over the real layer plus
   gate-controlled fake data sockets for the response-side
   malformed legs** (a fake unix socket at the same discovery
   path the layer follows).
2. Fuzz-style random mutation of command buffers. Deferred to
   the existing fuzz-crate posture (M9); this slice's families
   are deterministic and each leg asserts a specific documented
   behavior.
3. Testing only against the real swtpm. Rejected for the
   response-side family: swtpm always emits well-formed
   responses, so malformed-RESPONSE handling (early close,
   sub-header size, 0xffffffff size, trailing garbage) is only
   reachable through a substituted socket.

## Decision

Adopt option 1. `wine/tests/test-tbs-attacks.py` (LGPL) plus the
extended scenario harness execute the families:

- EXHAUSTION: the 64-slot context registry fills to
  TBS_E_TOO_MANY_TBS_CONTEXTS and recovers after close-all; a
  50-submit loop leaves the process descriptor count unchanged
  (/proc/self/fd).
- MALFORMED: requests with an unknown tag or a header/length
  mismatch are answered by the vTPM's OWN errors verbatim with
  transport success (compat transparency - the layer never
  synthesizes); the fake-socket matrix serves an immediate EOF,
  a responseSize below the header, a 0xffffffff responseSize,
  and trailing garbage past the declared size - the first three
  fail closed as TBS_E_IOERROR, the last returns EXACTLY the
  declared 16 bytes.
- CANCELLATION RACES: a 25-cancel storm recovers; a submit-loop
  process (60 submits) and a cancel-loop process (40 cancels)
  race the same live prefix concurrently with zero lost submits,
  zero failed cancels, and no hang; cancel on a context whose
  vTPM stopped returns IOERROR (never a hang).
- CROSS-PREFIX LEAKAGE: with prefix A stopped and prefix B live,
  A's layer fails closed (context create and device info
  TPM_NOT_FOUND) while B keeps serving - no reach-across; each
  prefix's identity material stays inside its own vTPM.
- VTPM-AS-HARDWARE: the vendor identity served THROUGH the
  layer is the software emulator's own (PT_MANUFACTURER
  "IBM\0" at 0x105, PT_VENDOR_STRING_1 "SW  " at 0x106); device
  info keeps the reserved fields zero. (Research note recorded:
  TPM_CAP_TPM_PROPERTIES is 6 in the current spec revision, and
  the PT_FIXED property numbering puts MANUFACTURER at 0x105 -
  both verified against tss2 headers and the executed query.)

Five registry scenarios map the families to invariants 17, 18,
20, 23, 26, and 40 (66 scenarios total; coverage stays 48/48).

## Consequences

- The M10 roadmap's API-layer attack families are executed
  evidence, not claims; the M10 exit audit can cite them.
- The fake-socket matrix introduces no product code - it is
  gate-only infrastructure at the same discovery path.
- Nothing in the layer needed hardening: the executed attacks
  confirmed the M10-049 design (cap, per-submit connections,
  responseSize sanity, bounded IO).

## Threat-model impact

Positive: malformed and racing callers cannot crash, hang, or
overrun the layer, and cannot reach another prefix's TPM.

## Privacy impact

None: the gate creates only ephemeral per-prefix state under its
own tmp tree; no identity material is logged.

## Dependency and license impact

None new; the gate uses the standard library, gcc, swtpm, and
the existing manager. New files are LGPL-2.1-or-later under
wine/ (the harness extension) and Apache-2.0 gate/registry
entries elsewhere per the tree's boundaries.

## Validation

Executed on the dev host (2026-09-09):
wine/tests/test-tbs-attacks.py PASS (all five families);
wine/tests/test-tbs.py and wine/tests/test-vtpm-manager.py PASS
(regression); scripts/check-attack-scenario-traceability.py
(66 scenarios) and scripts/check-invariant-coverage.py (48/48)
PASS.

## Rollback

Revert the commit; the attack scenarios, registry entries, and
harness extension disappear together (the layer itself is
untouched).

## Primary sources

- The M10 roadmap's required attack tests; SECURITY_INVARIANTS
  16/17/18/20/23/26/40; the M9 registry schema
  (lab/README.md, scripts/check-attack-scenario-traceability.py).
- tss2_tpm2_types.h (TPM2_CAP_TPM_PROPERTIES = 6) and the
  executed GetCapability query (property 0x105/0x106).
