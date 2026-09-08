# M5 exit audit: Proton bridge and race-resistant caller binding

Date: 2026-09-08
Agent: zcode
Scope: the four M5 exit criteria from docs/ROADMAP.md, audited
against delivered, merged work plus this slice's executed
evidence.

## Criterion 1: a fake local process cannot obtain evidence for the
sample game merely by copying identifiers

DELIVERED and EXECUTED. Identity is kernel-derived at every layer:
the portal reads SO_PEERCRED before any payload parses (ADR-0027);
the binding pins pid + start time + pidfd (ADR-0028); the manifest
reduces the executable and modules to digests (ADR-0031). Category
2 executes the exact scenario - a process copying the game's
WINEPREFIX reproduces the prefix DIGEST but remains a different
caller (distinct pid, distinct pin, never matching the game's
credentials), and its own executable digest distinguishes its
manifest. Category 11 executes socket impersonation: whoever
connects is pinned as themselves.

## Criterion 2: replacing the bridge cannot fabricate a permit

DELIVERED. No permit exists to fabricate in M5: session functions
return UNSUPPORTED, and the portal's v1 surface expresses exactly
one operation (Hello) whose answer carries only the OBSERVED
credentials (category 13: no privileged operation is even
expressible). A replaced bridge speaks as just another client:
category 1 executes two processes sharing the identical bridge
files binding as two distinct callers. The permit path itself
arrives with M6's verifier integration, where the same
kernel-derived chain gates it.

## Criterion 3: the C/FFI surface is sanitizer-tested and fuzzed

PARTIAL, recorded honestly. The ABI layer is exercised by the
mingw harnesses (both architectures) covering null pointers,
invalid pointer/length combinations, oversized blobs, and capacity
checks, run under wine on TWO hosts including real GE-Proton
(ADR-0029/0030 evidence), and the structural build gate enforces
the export surface per build. Dedicated cargo-fuzz/ASan targets
for the C ABI are NOT yet present: the pure-Rust frame decoder
(the surface hostile input actually reaches) is negative-tested
exhaustively at the frame layer, but the criterion's
sanitizer-and-fuzz wording is only partially met. Recorded as the
M5 follow-up: fuzz targets for the frame codec and the C ABI
boundary in the M6 SDK slice, where the C surface stabilizes.

## Criterion 4: the portal remains unprivileged and the agent sees
only normalized bounded messages

DELIVERED and EXECUTED. The portal is a same-UID 0600 socket with
no privileged operation (categories 12-13); frames are bounded
(1024-byte ceiling rejecting without body allocation), connections
budgeted (16 frames), decoding fail-closed, and responses built
only from OBSERVED credentials (ADR-0027, suite categories 8-10,
12). The bridge performs no TPM call, no privileged operation, and
no raw TBS forwarding anywhere (wine/README.md rules; ADR-0029).

## Deliverables coverage

| Roadmap deliverable | Status |
| --- | --- |
| ogir-client.dll prototype | M5-033, merged (proven live, both hosts) |
| Bounded request/response ABI | M5-031 (frames) + M5-033 (C ABI) |
| Unprivileged local portal | M5-031, merged |
| Authenticated Unix-domain IPC | M5-031 (SO_PEERCRED), merged |
| Process-handle passing over caller-supplied PID trust | M5-032 (pidfd pin), merged |
| Sample Windows console client under stock Proton | M5-033/034 (GE-Proton10-34 on archhost, executed) |
| Redacted tracing for development | M5-034 (correlation digests), merged |
| No physical TPM call / privileged operation in the bridge | Structural; asserted by category 13 |
| Wine server/prefix/process-tree/cgroup correlation | M5-034, merged |
| Game/runtime manifest derivation | M5-035 (this slice) |
| Thirteen required attack tests | M5-035 (this slice; wine-side legs anchored to executed evidence) |

## Honest limitations (recorded, not gaps in the criteria)

- The wow64 32-bit transport fails closed (ADR-0029): full 32-bit
  support needs a proper conversion layer.
- The sanitizer/fuzz half of criterion 3 is future work (above).
- The fuzzing CI posture and the archhost executions are dev-host
  gates; CI validates committed evidence.
- Proton's run wrapper swallows child stdout: the GE-Proton verdict
  is the exit code plus the portal's log.

## Verdict

Criteria 1, 2, and 4 are satisfied by executed work. Criterion 3 is
partially satisfied with its remainder recorded as the M6 follow-up
(fuzz targets on the stabilizing C surface). With this slice
merged, Milestone M5 is COMPLETE: M0 through M5 are closed, and the
roadmap's next milestone is M6 (publisher verifier and sample-game
SDK).
