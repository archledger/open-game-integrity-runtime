# Measured-boot profile states: what OGIR accepts, and what it reports

This is the user-facing explanation of the accepted and unsupported
states for a measured Linux boot profile (M4). It answers the
question a player, an admin, or a publisher asks when a session is
denied: what did the verifier actually decide, and what should
happen next?

The one-line summary: **OGIR never says "cheater". It says which
reference state the machine matches, or exactly why it does not.**

## How a decision is made

The verifier holds pinned, reviewed reference data: a signed
[reference manifest](../crates/ogir-bootlog/src/manifest.rs) binding
ONE narrow platform profile (name and revision, expected SHA-256 PCR
values, required Secure Boot state, component version floors,
accepted component signing roots, and revocations) to a signature by
a manifest anchor key it pins itself
([ADR-0025](adr/0025-signed-reference-manifest.md)).

A boot under test produces three pieces of evidence that must agree
(the M4-028c triangle): the firmware event log, the live PCR values,
and a TPM2 quote. The verifier replays the log, compares the replay
against the live read and the quote's attested digest, verifies the
quote's signature, and only then matches the result against the
manifest. Any leg failing is a specific, named state below.

## Accepted

Every leg holds and the manifest matches:

- the event log parses and replays to PCR values equal to the live
  read and to the quote's attested digest;
- the quote signature verifies against the enrolled key;
- the replayed values equal the manifest's `pcr-expectation` set;
- Secure Boot was required and enabled;
- every declared component is at or above its floor and not revoked;
- the boot was signed by an accepted signing root.

This is the only state that can support an allow.

## Unsupported (reference data does not match)

These states mean the machine does not match the accepted profile.
They are deterministic and explainable, and none of them is evidence
of an attack:

| State | What the verifier reports | What to do |
| --- | --- | --- |
| Unknown profile | `UnsupportedProfile` | The firmware or image changed since the last review; await a new signed manifest |
| Firmware update | `UnsupportedProfile` (new measurements) | Re-review after the update; the old expectations no longer match |
| Component below floor | `BelowMinimumVersion` | Update the component; the floor rose by review |
| Revoked component | `ComponentRevoked` | The exact component version was retired by review; use the newer one |
| Undeclared component | `UnknownComponent` | The profile does not describe this component at all; fail closed |
| Custom Secure Boot key | Signing-root mismatch | The boot was signed by a root the manifest does not accept (see below) |
| No TPM / cleared TPM | Backend fail-closed error | No measurable state exists; nothing can be claimed |

### The custom-key distinction

"Secure Boot enabled" alone is never sufficient (an M4 exit
criterion). A machine can enroll its own Secure Boot key and boot a
self-signed UKI with Secure Boot happily enabled. The manifest's
signing roots close that gap: the accepted profile names the exact
key fingerprint whose signature boot components must carry. A boot
under any other key - a vendor key, a user-enrolled custom key -
measures differently (PCR 7 records the Secure Boot configuration)
and its components are not signed by an accepted root, so the state
is reported as a signing-root mismatch: unsupported, not malicious. Since M4-030 the
enforcement is also proven live in the emulator:
`image/enroll-test-key.sh` derives the TEST-ONLY-enrolled varstore
and `scripts/test-sb-boot.py` boots under it both ways - the good
UKI boots with the kernel reporting lockdown from EFI Secure Boot
mode, and a one-byte-modified UKI is rejected by the firmware
(ADR-0026).

## Attack-indicating (evidence is internally inconsistent)

These states mean the evidence contradicts itself. They are still
not cheating verdicts - they are recorded, deterministic
observations for the publisher to act on:

| State | What the verifier reports |
| --- | --- |
| Event log does not reproduce the quoted PCRs | `PcrMismatch` (the M4-027 log-quote bridge) |
| Forged, truncated, or reordered event log | Parser rejection (`Truncated`, `NotTcg2`, `Malformed`) |
| Tampered or forged manifest | `SignatureInvalid` (TPM verification) |
| Weakening manifest update | Successor check rejection (floors never fall, revocations never vanish) |
| Tampered quote | `SignatureInvalid` / nonce mismatch |

The distinction that matters: an **unsupported** state is consistent
evidence that simply does not match reviewed reference data, while an
**attack-indicating** state is evidence that could not have been
produced honestly by the platform it claims to come from. The
verifier's outputs keep them separate all the way through
(`BootlogError` variants above), so policy can treat them
differently without guessing.

## Updating the accepted profile

The accepted profile changes only through a new signed manifest
revision (an M4 exit criterion):

1. the new manifest is signed by the manifest anchor key;
2. it must be a non-weakening successor of the accepted revision:
   the revision rises, PCR expectations are carried forward, floors
   only rise, Secure Boot only tightens, revocations persist, and no
   new signing root is added;
3. anything else - a changed PCR expectation, an added root, a
   lowered floor - is NOT a successor and requires a fresh reviewed
   acceptance (rotating a signing root or accepting a new image is a
   trust decision, not a routine update).

The committed fixtures demonstrate the full flow: `manifest.txt`
(revision 1, the accepted capture profile) and
`manifest-revoked.txt` (revision 2, retiring the v1 test UKI by
revocation and floor rise), both verified by
[the M4-029 suite](../crates/ogir-attest-tpm/tests/reference_manifest.rs).

## What this does not cover

Real-hardware platform diversity (this profile is the emulated test
image), multiple simultaneously accepted profiles, and automatic
manifest distribution are deliberately out of M4 scope; see the
[roadmap](ROADMAP.md).
