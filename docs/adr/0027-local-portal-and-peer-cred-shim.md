# ADR-0027: The unprivileged local portal and the audited SO_PEERCRED shim

- Status: Accepted
- Date: 2026-09-07
- Owners: Initial maintainer
- Related issues: [Local M5-031 issue](../../planning/issues/031-portal.md)
- Supersedes: None
- Superseded by: None

## Context

M5 opens with the roadmap's implementation order step 1: a native
Linux sample client to an unprivileged local portal - the endpoint
every later slice (the PE DLL, the Wine/Proton transport, the caller
binding) builds on. The M5 entry spike (2026-09-07,
ogir/task-18-scoping/m5-spike-unixlib) proved the wine-side
mechanics: a Windows PE client can reach a native Unix-domain socket
through a winegcc-built unixlib, and the kernel reports the WINE
process's credentials to the listener. The portal therefore
authenticates by SO_PEERCRED - kernel-derived, never caller-supplied
- which is also the roadmap deliverable "Authenticated Unix-domain
IPC".

std's `UnixStream::peer_cred` remains unstable
(`peer_credentials_unix_socket`), so the credentials read needs
either a tiny libc call or a new dependency.

## Decision drivers

- Caller identity must come from the kernel; nothing a client sends
  may influence it (the M5 exit criterion "a fake local process
  cannot obtain evidence merely by copying identifiers" starts
  here).
- Messages must be normalized and bounded before any session logic
  sees them (the exit criterion "the agent sees only normalized
  bounded messages").
- No new Rust dependencies (the signed inventory stays); no
  hand-implemented cryptography (none needed here).
- The workspace unsafe posture stays forbid-by-default with
  audited, gate-enforced exceptions (ADR-0020's pattern).

## Options considered

1. **std `peer_cred`.** Unstable on the pinned toolchain. Rejected.
2. **The `nix`/`rustix` crate.** A new signed-inventory dependency
   for one `getsockopt` call; supply-chain surface outweighs the
   benefit (the ADR-0018 bar was a whole TPM stack, not one
   syscall).
3. **A locally declared `getsockopt` call inside one audited
   `#[allow(unsafe_code)]` function**, mirroring ADR-0020's audited
   marshaling block, with the isolation gate extended to enforce
   exactly one such block per carved-out crate.

## Decision

Adopt option 3. ogir-agent declares its own lint table
(`unsafe_code = "deny"`, every other lint mirroring the workspace)
and carries exactly one audited block: `getsockopt_peer_cred` in
`portal.rs`, performing one `SOL_SOCKET`/`SO_PEERCRED` call into a
stack `ucred` with a written safety argument.
`scripts/test-mock-substrate.py` now enforces the two-crate,
one-block-each posture (ADR-0020 in ogir-attest-tpm, ADR-0027 in
ogir-agent); every other crate keeps the workspace forbid.

The portal itself (`ogir_agent::portal`): `Portal::bind` creates
only directories it creates (never re-permissions a pre-existing
shared directory), binds 0600 (parent 0700 when freshly created);
`accept` reads credentials BEFORE any payload is parsed; frames are
u32-length-prefixed with a 1024-byte ceiling that rejects without
reading the body (allocation-bounded flood defense); connections
carry at most 16 frames; requests decode fail-closed (bounded UTF-8
names, unknown kinds rejected) and answers are normalized
responses built from the KERNEL-OBSERVED credentials. The v1 message
set is deliberately minimal: Hello/HelloAck (the ack reports the
observed credentials; nothing from the Hello is trusted) and
Rejected. The native sample client is
`crates/ogir-agent/examples/portal-client.rs`.

## Consequences

- Later M5 slices extend the message set; the framing, bounds, and
  credential discipline are now fixed infrastructure.
- A second audited unsafe block exists workspace-wide; the gate
  makes any third one a hard failure pending its own ADR.
- The portal is per-UID (0600 socket); cross-UID connection is out
  of scope by design.

## Threat-model impact

The portal opens no new privileged surface (unprivileged socket,
same-UID only). Identity copying, spoofed clients, and floods fail
closed into normalized rejections or errors; the request flood leg
is bounded per connection (frame budget) and per frame (length
ceiling without body allocation).

## Privacy impact

The portal observes kernel credentials (pid/uid/gid) and bounded
client-supplied names; it logs nothing itself. Redacted tracing
arrives with the M5-034 transport slice.

## Dependency and license impact

None: no crates added; the `getsockopt` declaration is local.

## Validation

Executed on the dev host: ogir-agent 29 tests green (6 portal unit +
7 portal integration: the credential round trip against a real
socket, permissions and self-cleaning, flood bounded, oversized and
malformed fail-closed, wire round trip; plus the pre-existing 16).
The isolation gate enforces the new two-block posture. Full house
gates in the slice record. Development lessons: sun_path is 108
bytes (cargo's deep tmpdir overflows it - the tests bind short
/tmp paths); the portal must never chmod a pre-existing parent
(the first draft's EPERM chmod("/tmp") was exactly the kind of
unprivileged-surface violation this slice exists to avoid).

## Rollback

Revert the commit; the portal module, tests, example, and the gate
amendment disappear together, restoring the ADR-0020 single-block
posture.

## Primary sources

- unix(7): SO_PEERCRED returns struct ucred {pid, uid, gid} for
  connected AF_UNIX stream sockets.
- The M5 entry spike evidence (2026-09-07): the wine process's real
  pid/uid/gid observed across the unixlib bridge.
- ADR-0020 (the audited-block pattern this decision extends).
