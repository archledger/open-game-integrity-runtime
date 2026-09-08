# Casual fallback and no-ban semantics (M6-039, ADR-0035)

The integration contract for game studios: what each verdict
family means for gameplay, what a publisher's server may and may
not do with it, and how unsupported platforms fall back without
ever punishing a player.

## The one rule

**An attestation result is never a cheating accusation.** OGIR
reports which reference state a machine matches, or exactly why it
does not. It never says "cheater". A publisher's response to any
verdict is the publisher's policy decision - and the SDK's shape
makes the safe mappings the easy ones.

## The verdict families and their intended mappings

| Family | Meaning | Intended gameplay mapping |
| --- | --- | --- |
| `allow` | The evidence matched the accepted profile | Protected-session features on |
| `restricted` | Admission with reduced scope (a policy-emitted grade) | Features on with the publisher's reduced-scope set |
| `unsupported` | The platform/profile is not one OGIR can appraise (an old kernel, an unknown firmware, a 32-bit-only stack) | **Casual fallback**: full game, no protected extras. No flag, no ban |
| `retry` | A transient condition (verifier outage, attestation service unavailable) | Retry after backoff. Never punitive while retrying |
| `deny` | The publisher's server relayed a denial of its own | The publisher's own decision; graceful end of the protected flow |

The wire shape (ADR-0033) keeps these as distinct enum values with
stable reason codes and retry guidance - and the frozen v1 SDK
(ADR-0034) mirrors them as distinct ABI values, so an integration
cannot accidentally collapse `unsupported` into `deny`. The
publisher-treats-unsupported-as-cheating category is a wire-shape
impossibility.

## The casual fallback path

When a client reports `unsupported`, the sample mapping is:

1. The game runs at full functionality.
2. Protected-session extras (whatever the title defines - ranked
   matchmaking, economies, server-authoritative modes) are off for
   that session.
3. No account flag is set. No telemetry escalates. The next
   session re-attempts normally - a platform update may appraise
   cleanly the same day.

The sample backend (`crates/ogir-dev-verifierd/examples/
sample-game-server.rs`) demonstrates exactly this table; the
conformance kit verifies the wire contract that makes it safe.

## What a publisher must NOT do

- **Never treat `unsupported` or `retry` as a ban reason.** These
  families say the ATTESTATION could not complete, not that the
  player did anything.
- **Never fabricate a local trust decision.** The client SDK
  transports; the publisher's server decides (ADR-0004).
- **Never parse evidence or permits beyond the opaque relay.** The
  SDK hands the publisher opaque bytes; the permit's internals are
  the verifier's.
- **Never let the verdict family decide account state.** Verdicts
  are per-session; account actions are a human-policy question
  outside OGIR entirely.

## Trying the flow locally

```sh
cargo build -p ogir-dev-verifierd --release
./target/release/ogir-dev-verifierd &            # developer mode on 127.0.0.1:8080
python3 scripts/conformance-kit.py --daemon 127.0.0.1:8080   # the publisher kit
./target/release/examples/sample-game-server     # the five-step demo
```

The kit is the same artifact CI runs: a fresh publisher can verify
their deployment handles the full contract - the five-step flow,
all five families, the lifecycle, the freshness rules, and the
wire bounds - without any Linux kernel knowledge.
