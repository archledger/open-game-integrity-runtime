# M5-031: The unprivileged local portal and the native sample client
<!-- labels: type: implementation,area: agent,area: protocol,status: needs-review -->
<!-- milestone: M5 Proton Bridge -->


## Problem

M5's implementation order starts with a native Linux sample client
to a local portal - the endpoint every later slice (the PE DLL, the
Wine/Proton transport, the caller binding) builds on. The portal
must authenticate connections by KERNEL-derived credentials and see
only normalized bounded messages; nothing a client sends may
influence its identity.

## What this slice delivers

1. `ogir_agent::portal` - the unprivileged local portal (ADR-0027):
   same-UID Unix-domain socket (0600; freshly created parents 0700;
   pre-existing directories never re-permissioned); SO_PEERCRED read
   BEFORE any payload parses; u32 length-prefixed frames with a
   1024-byte ceiling that rejects without reading the body; 16
   frames per connection; fail-closed decoding; normalized
   responses built from the OBSERVED credentials; a minimal v1
   message set (Hello/HelloAck/Rejected).
2. The audited unsafe posture extension: ogir-agent's own lint table
   with exactly one `#[allow(unsafe_code)]` block (the getsockopt
   shim, with a written safety argument); the isolation gate amended
   to enforce the two-crate one-block-each posture (ADR-0020 +
   ADR-0027); no new dependencies.
3. `crates/ogir-agent/examples/portal-client.rs` - the native Linux
   sample client (roadmap implementation-order step 1).
4. ADR-0027 + index row; ROADMAP M5-031 boundary; this issue; the
   plan doc.

## Executed evidence (dev host)

- ogir-agent: 29 tests green (6 portal unit, 7 portal integration
  against real sockets: the credential round trip (kernel-observed
  pid/uid equal the test process), socket permissions 0600 and
  self-cleaning, request flood bounded with the Flooded verdict,
  oversized prefix rejected without body allocation, malformed input
  answered with the normalized rejection, wire round trip).
- The isolation gate PASS under the amended two-block posture.

## Security invariants

- Identity is kernel-derived; a client cannot claim a pid/uid.
- Fail-closed everywhere: unknown, oversized, truncated, and
  non-UTF-8 input rejects; frame and connection budgets bound
  hostile peers without allocation.
- No privileged operation; no new dependencies; the second audited
  unsafe block is gate-enforced with a written safety argument.

## Out of scope

- pidfd/process-start-time binding (M5-032); the PE DLL and the
  Wine/Proton transport (M5-033/034); richer messages (session
  operations) arrive with those slices; redacted tracing (M5-034).
