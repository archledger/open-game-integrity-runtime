# ADR-0034: The v1 SDK freeze and the fuzz targets

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M6-038 issue](../../planning/issues/038-stable-sdk.md)
- Supersedes: None
- Superseded by: None

## Context

The M5 exit audit recorded the sanitizer/fuzz remainder; M6-036's
hand-rolled JSON codec repeated it. The roadmap's SDK deliverables
are the stable C ABI, the C++ wrapper, and the Unreal-facing
design. The header was explicitly experimental.

## Decision drivers

- A studio must integrate against a frozen surface: the M6-039
  conformance kit verifies ABI presence per build.
- The verdict surface must carry ADR-0033's families so an
  integration cannot collapse unsupported into deny.
- Fuzzing must cover the hand-rolled parsers that untrusted input
  actually reaches: the JSON codec, the portal frame decoder, and
  the HTTP router.

## Options considered

1. **Freeze the six-function experimental header as-is.** Lacks the
   structured verdict surface - integrations would parse reason
   strings.
2. **Extend then freeze: version macros, ogir_result, the verdict
   enum, and ogir_abi_version(), then pin everything with a
   fail-closed surface gate.**
3. **A generated ABI (idl/ffi).** Overkill; the header is 8 exports.

## Decision

Adopt option 2. sdk/include/ogir.h becomes the frozen v1 ABI:
`OGIR_ABI_VERSION_MAJOR/MINOR` macros, the `ogir_verdict` enum
mirroring ADR-0033's five families, the `ogir_result` struct
(verdict, retryable, stable reason_code, permit view borrowed from
the session), `ogir_abi_version()`, and
`ogir_session_get_result()` joining the existing six exports.
`scripts/test-sdk-surface.py` fail-closes the freeze: the macros,
all five verdict values, all eight exports, the result surface,
and the removal of the pre-freeze disclaimer; the M6-039 kit
builds on it. CI compile-checks both the C header and the C++
wrapper per push.

`sdk/cpp/include/ogir/client.hpp` is the header-only C++ wrapper:
RAII `Client`/`Session` (move-only, raw-pointer owners), `Verdict`
enum class with unknown families failing closed to Deny, `Result`
as a value type that COPIES the permit out of session memory, and
`Error` carrying the status. No policy, no verdict judgment.

`docs/UNREAL_INTEGRATION_DESIGN.md` is the Unreal-facing design
(the plugin boundary, the USTRUCT mirror, the no-ban family
mapping, threading and lifetime, the Proton deployment recap) -
deliberately not a plugin.

The fuzz crate (`fuzz/`, excluded from the workspace, gitignored
corpus): `bjson_decode` (decode never panics; decoded inputs
re-encode within bounds), `portal_frame_decode` (the v1 request
decoder never panics and admits only Hello), and `service_route`
(the full HTTP router with null backends never panics on arbitrary
method/path/body). Smoke-executed: 3000/3000/800 runs clean.

## Consequences

- The recorded M5+M6-036 fuzz remainder is closed for the layers
  untrusted input reaches; the C ABI boundary itself is guarded by
  the M5 harness's negative tests plus the surface gate.
- A future v2 adds a new header; v1 declarations never change.
- The fuzz crate needs nightly-independent libFuzzer; it stays a
  dev-host tool (CI keeps compile-checking the surfaces).

## Threat-model impact

Parser confusion reaches: the codec, frame decoder, and router are
now fuzz-covered against panic/hang/crash; the SDK makes the
unsupported-vs-deny confusion structurally impossible for
integrations, closing the publisher-side category at the client
edge too.

## Privacy impact

None: the SDK surfaces verdict families and opaque bytes.

## Dependency and license impact

The fuzz crate adds libfuzzer-sys as a DEV-ONLY dependency outside
the workspace and the signed inventory (gitignored lock); the
production inventory is unchanged.

## Validation

Executed on the dev host: the C header and C++ wrapper
compile -Wall -Wextra -Werror clean (and now in CI); the surface
gate PASS; all three fuzz targets smoke-run clean (3000/3000/800
runs, zero findings); the full house gates in the slice record.

## Rollback

Revert the commit; the extended header, wrapper, design doc, fuzz
crate, and gates disappear together (the six-export experimental
header returns).

## Primary sources

- ADR-0033 (the verdict families the SDK mirrors), the M5 exit
  audit's recorded remainder, and the executed fuzz runs
  (2026-09-08).
