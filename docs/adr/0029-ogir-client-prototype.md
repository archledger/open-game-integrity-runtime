# ADR-0029: The ogir-client prototype (the wine bridge)

- Status: Accepted
- Date: 2026-09-08
- Owners: Initial maintainer
- Related issues: [Local M5-033 issue](../../planning/issues/033-ogir-client.md)
- Supersedes: None
- Superseded by: None

## Context

M5's roadmap asks for a minimal Windows PE DLL with a stable C ABI
(sdk/include/ogir.h) that a game under Wine/Proton uses to reach the
unprivileged local portal (ADR-0027) without trusting
Windows-provided identity fields. Mainline wine's ws2_32 has no
AF_UNIX support (M5 entry scoping), so the transport must cross the
Windows/Unix boundary inside the wine process. The entry spike
(2026-09-07, task-18-scoping/m5-spike-unixlib) proved the crossing
possible; this slice turns it into the shippable artifact set.

## Decision drivers

- The bridge must be loadable the way real games load DLLs, under
  stock wine AND Proton, without a private wine fork.
- No TPM call, no privileged operation, no raw TBS forwarding
  (wine/README.md rules).
- Fail closed everywhere: malformed ABI input, wrong architecture,
  absent portal.
- Dev-host reproducibility with committed sources and a structural
  build gate; CI validates committed evidence only.

## The executed loader map (all traced on wine-11.0 Staging)

1. WINEDLLPATH is NOT honored for import resolution (control
   experiment: pointing it at /nonexistent changes nothing).
2. Runtime LoadLibraryA never resolves a winelib .so artifact; only
   the loader's import pass does.
3. A native PE loaded with WINEDLLOVERRIDES=n receives NO unixlib
   attach: the attach search runs in the unforced n,b builtin phase.
4. A dispatch-only .so in wine's x86_64-unix directory gets loaded
   AS the module and aborts on stub exports unless it also carries
   real spec-bound exports.
5. The proven deployment: a native mingw PE (the ABI surface)
   beside the application, with a winegcc-built .so carrying REAL
   spec-bound ms_abi exports AND initialized dispatch tables
   installed in wine's x86_64-unix directory, loaded WITHOUT
   overrides. Either loader role then works: the .so may serve as
   the module (its own exports) or as the unixlib (its dispatch
   entries).
6. An UNINITIALIZED dispatch table (bss) attaches nothing: every
   unix call fails closed. The build gate now asserts the tables
   are data, not bss.

## Options considered

1. **A pure winelib .so as the sole artifact, LoadLibrary'd at
   runtime.** Rejected by execution: LoadLibraryA never resolves a
   winelib artifact in wine 11 (only the loader's import pass does),
   so a game's dynamic loading path cannot reach it.
2. **A native PE with WINEDLLOVERRIDES=n plus a unixlib.** Rejected
   by execution: forcing native skips the builtin phase where the
   unixlib attach runs - the dispatch has nothing to call.
3. **A dispatch-only unixlib in the machine-unix directory.**
   Rejected by execution: the loader pulls it in AS the module and
   aborts on stub exports (no spec) - "unimplemented function".
4. **The shipped pair: native PE beside the app + winegcc unixlib
   with real spec-bound ms_abi exports AND initialized dispatch
   tables in the machine-unix directory, unforced load.** Either
   loader role works: module-by-spec or attach-by-tables.

## Decision

Ship the pair. `wine/ogir-client/pe/ogir_client.c` is the real PE
DLL (mingw, both AMD64 and i386): the public C ABI with strict
argument validation (null out pointers, null-data-with-length,
oversized blobs beyond 4096, capacity checks, null-tolerance on
close) and transport open/close dispatched through ntdll's
`__wine_unix_call` (bound via a dlltool import library for the two
wine-private data exports).
`wine/ogir-client/ogir_client_dll.c` is the winegcc artifact
spec-bound to ms_abi wrappers (the header's default-convention
declarations collide with ms_abi definitions, so the wrappers carry
distinct names): the same native transport the dispatch entries
serve - AF_UNIX connect, the bounded frame codec mirroring the
portal's (u32 BE length prefix, 1024-byte ceiling), and the Hello
handshake that fails closed on anything but the HelloAck shape.
`abi_test.c` is the harness (both architectures) covering the
ABI-layer attack legs; `build.sh` builds everything;
`scripts/test-ogir-client-build.py` is the fail-closed structural
gate (loader-contract symbols, initialized dispatch tables, PE
export surfaces, per-architecture machine checks);
`examples/portal-serve.rs` is the development portal host.

Deployment note (honest): the unixlib must live in wine's
machine-unix directory (or an equivalent loader-visible path); a
beside-the-app .so alone is not attachable in wine 11. A launcher
installs the pair per prefix; system-wide install needs elevated
copy. This constraint is recorded rather than worked around.

## Consequences

- The WoW64 leg fails CLOSED by design in the prototype: a 32-bit
  client's unix calls return UNAVAILABLE (custom arg structs need a
  proper wow64 conversion layer - future work; the recorded
  layout-mismatch defense is exactly this fail-closed behavior).
- Session establishment (begin/permit/sign) returns UNSUPPORTED
  until the M5-034/035 message set lands; the transport itself is
  proven.
- No TPM call, no privileged operation, no raw TBS forwarding
  anywhere in the bridge (wine/README.md rules).

## Threat-model impact

The bridge adds an unprivileged client surface only. Replaced/patched
DLL attacks land in M5-035's suite; the ABI layer already fails
closed on malformed arguments, and identity remains kernel-derived
(SO_PEERCRED at the portal).

## Privacy impact

None: the bridge transports the handshake bytes; no user data, no
logging (redacted tracing arrives with M5-034).

## Dependency and license impact

No Rust dependency changes. The bridge is Apache-2.0 OGIR code, not
an upstream Wine patch (wine/upstream-patches remains untouched);
mingw and winegcc are dev-host build tools.

## Validation

Executed on the dev host (evidence in task-18-scoping/m5-033/):
the 64-bit harness under wine against the LIVE Rust portal -
13/13 PASS including "open succeeded against the portal", with the
portal logging the wine process's kernel credentials
(pid/uid/gid observed, CallerBinding pinned alive, connection
served). The 32-bit harness: every ABI check passes and open fails
closed (UNAVAILABLE) per the WoW64 note. The build gate PASS.
Full house gates in the slice record.

## Rollback

Revert the commit; the bridge sources, build, gate, and example
disappear together. The installed test artifacts in wine's system
directory are dev-host state (remove with sudo rm).

## Primary sources

- The M5 entry spike (2026-09-07) and this slice's traced loader
  experiments (the six-point map above).
- ADR-0027 (the portal the bridge speaks to), ADR-0028 (the binding
  the portal pins with).
