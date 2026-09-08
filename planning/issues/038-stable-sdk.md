# M6-038: The v1 SDK freeze, the C++ wrapper, and the fuzz targets
<!-- labels: type: implementation,area: verifier,area: supply-chain,status: needs-review -->
<!-- milestone: M6 Publisher SDK and Verifier -->


## Problem

The roadmap's SDK deliverables (stable C ABI, C++ wrapper,
Unreal-facing design) plus the fuzz remainder recorded by the M5
exit audit and repeated for M6-036's hand-rolled codec: the layers
untrusted input reaches must be fuzz-covered.

## What this slice delivers

1. The FROZEN v1 ABI (ADR-0034): version macros, the ogir_verdict
   enum (ADR-0033's five families), the structured ogir_result,
   ogir_abi_version(), ogir_session_get_result() - eight exports
   pinned by scripts/test-sdk-surface.py (fail-closed).
2. The header-only C++ wrapper: RAII Client/Session, a Verdict
   enum class failing closed on unknown families, Result as a
   value type copying the permit out of session memory.
3. docs/UNREAL_INTEGRATION_DESIGN.md: the plugin boundary, USTRUCT
   mirror, no-ban family mapping, lifetime, Proton deployment
   recap - deliberately not a plugin.
4. The fuzz crate (workspace-excluded): bjson_decode,
   portal_frame_decode, service_route - smoke-executed
   3000/3000/800 runs clean; CI compile-checks both headers.

## Executed evidence (dev host)

- The C header and C++ wrapper compile -Wall -Wextra -Werror
  clean; the surface gate PASS; all three fuzz targets clean.

## Security invariants

- Integrations cannot collapse unsupported into deny: the families
  are distinct ABI values.
- No production dependency changes (libfuzzer-sys is dev-only,
  outside the workspace and the signed inventory).

## Out of scope

- The sample backend + conformance kit + no-ban docs (M6-039); the
  ten-category suite + exit audit (M6-040); a full UE plugin.
