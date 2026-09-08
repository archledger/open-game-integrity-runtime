# Unreal Engine integration design (M6-038, ADR-0034)

A design note, deliberately not a plugin: the roadmap asks for a
sample Unreal-facing design without committing to a full plugin.

## The five-step target (from the roadmap)

A game - or an Unreal title - needs only:

```text
request challenge from its server
pass challenge to OGIR
submit opaque permit and session proof
handle allow / restricted / unsupported / retry / deny
```

It must not parse TPM logs or make the final local trust decision.
Every step below keeps that boundary.

## Layering inside Unreal

```text
GameServer (publisher backend, owns policy)
    ^  HTTP (the publisher's own API)
GameMode / Session subsystem (C++ gameplay code)
    |  uses ogir::Client / ogir::Session (the C++ wrapper)
    v
OGIR client transport (the v1 C ABI, the M5 bridge under Proton)
```

- **The plugin boundary** would be one UE module wrapping
  `sdk/cpp/include/ogir/client.hpp`: a `UOgirClientComponent` on
  the game instance owning the transport lifetime, and a
  `FOgirResult` USTRUCT mirroring `ogir_result` (verdict family,
  retryable, reason code, permit bytes) so Blueprints can switch
  on the five families without ever seeing raw C.
- **The verdict families map to gameplay states**, not bans:
  `Allow` proceeds; `Restricted` proceeds with reduced trust
  (whatever the title's policy defines); `Unsupported` and `Retry`
  route to graceful fallback paths; `Deny` is the publisher
  server's decision relayed, never a local judgment.
- **No-ban semantics** (the ADR-0033 wire shape enforced): an
  engine integration physically cannot misread `unsupported` as
  `deny` - the families are distinct enum values in `ogir_result`
  and the USTRUCT mirror.

## Threading and lifetime

- `ogir::Client` construction opens the unprivileged local
  transport; on Linux/Proton that is the M5 bridge (a winelib
  unixlib beside the game), on a native client the Rust portal.
  Construct once per process on the game thread; the underlying
  transport is a same-UID Unix socket.
- `Session::result()` copies the permit out of session memory; UE
  code should immediately move those bytes to the game server
  request and never cache verdicts - freshness is the verifier's
  authority (ADR-0005/0014).
- The proof-of-possession call (`sign_binding`) is for the
  publisher's channel binding at session start; treat the
  signature as opaque.

## What a plugin would add (and why it is not yet here)

- A UE module with the component/USTRUCT above, plus build
  integration for the bridge artifact per platform.
- Blueprint nodes for the five-step flow.
- Editor-time developer mode (talking to the dev daemon,
  `ogir-dev-verifierd`) for studio testing without any TPM.

The conformance kit (M6-039) exercises the same five steps over
the real ABI; a plugin arrives only after the kit is stable, so a
studio never integrates against a moving target.

## Deployment under Proton/Steam (recap of ADR-0029/0030)

- 64-bit: the PE DLL beside the game executable plus the unixlib
  in the wine installation's machine-unix directory (per-prefix
  recipe on mainline; Staging app-dir recipe where proven).
- 32-bit WoW64: fail-closed today (recorded layout-mismatch
  defense); a proper wow64 conversion layer is future work.
- The sample integration target and the conformance kit land with
  M6-039.
