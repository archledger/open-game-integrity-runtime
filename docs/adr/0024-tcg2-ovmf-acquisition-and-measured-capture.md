# ADR-0024: Pinned TCG2-enabled OVMF acquisition and the measured capture

- Status: Accepted
- Date: 2026-09-07
- Owners: Initial maintainer
- Related issues: [Local M4-028c issue](../../planning/issues/028c-measured-capture.md)
- Supersedes: None
- Superseded by: None

## Context

The M4-028b boot harness proved the chassis but documented a blocker:
Fedora's `edk2-ovmf-20260812` performs no TPM2 measurements. M4-028c
re-verified that finding empirically (not by strings): a full boot
under an swtpm trace shows zero firmware TPM2_Extend traffic, PCRs
0-7 stay zero, and the kernel publishes no event log - while the
guest kernel itself drives the TPM fine (the observed PCR 10 activity
is the kernel's IMA plus its TPM2 HMAC-session support, not firmware).
The original strings-based evidence was also shown insufficient on its
own: firmware volumes are compressed, so an absent string proves
nothing either way; only executed-TPM-traffic or live-PCR evidence
settles it.

The measurement capability therefore has to come from outside
Fedora's package set, and the capture that uses it must produce
evidence the repo can validate durably.

## Decision drivers

- No Rust dependency changes (the 53-crate signed inventory stays).
- Every external input is pinned and hash-verified; nothing runs
  from an unverifiable download.
- Evidence must be validated by the repo's own code (ogir-bootlog
  replay, ogir-attest-tpm verification), not by trust in the capture
  tooling.
- Real fixtures over synthetic ones; TEST-ONLY key posture unchanged.

## Options considered

1. **Build edk2 from source with TCG2 enabled.** Full control, but a
   multi-gigabyte toolchain and an hour-plus build for a test input;
   unacceptable cost for a fixture source.
2. **Use another distribution's OVMF package (Ubuntu `ovmf-generic`).**
   TCG2 included, packaged reproducibly, hash-pinnable; the exact
   package and every extracted byte are verified against committed
   SHA-256 values.
3. **Use a TCG/edk2 prebuilt snapshot.** Least provenance; rejected.

## Decision

Adopt option 2: `image/fetch-ovmf-tcg2.sh` downloads the pinned
Ubuntu `ovmf-generic_2026.05-2ubuntu2_all.deb`, verifies the package
and both extracted firmware volumes against committed SHA-256 hashes,
and fails closed on any mismatch. The OVMF pair is a build input
(gitignored), never a committed binary.

The capture itself (`image/boot-capture.sh`) builds a SECOND signed
UKI - the same TEST-ONLY key, with a capture init embedded in the
initramfs - so systemd-stub measures the capture boot into PCR 11
through the firmware's TCG2 protocol exactly as it would any UKI.
The guest exports the binary event log, the live PCR read, and a
TPM2 quote (canonical `createek`/`createak` EK-AK pair, recorded
nonce) to an IDE scratch disk; the host splits the evidence stream
on a 64-bit-random magic line. `scripts/test-measured-capture.py`
gates the artifacts at capture time; the committed fixture is then
validated durably by the Rust triangle test
(`crates/ogir-attest-tpm/tests/uki_capture_triangle.rs`): replay vs
live PCR values vs quoted digest, plus QuoteVerifier signature
verification and a tamper rejection.

## Consequences

- The measured-boot proof (firmware PCRs plus the UKI-phase PCR 11)
  runs on the dev host; CI validates the committed evidence via the
  Rust test without booting.
- The Spec ID `digestSize` parser fix (u16, per the TCG EFI spec) was
  forced by the multi-bank log the single-bank host fixture could
  never exercise.
- Secure Boot enrollment (the test-key varstore) remains open and is
  deliberate: the measurement chain does not depend on it; it belongs
  with the M4-030 attack categories that need SB enforcement.
- The pinned URL and hashes must rotate deliberately (a new pin is a
  reviewed change, not a silent fetch).

## Threat-model impact

No runtime trust boundary changes: the capture is test tooling and
evidence. The TCG2 OVMF is a hash-verified build input used only by
the emulator harness. The committed fixture is evidence to be
validated, never trusted input to production code; the TEST-ONLY key
posture (ADR-0016) is unchanged. The parser fix tightens validation
(a misaligned Spec ID table now fails closed instead of parsing
garbage), so the change strengthens, not weakens, the log-ingestion
boundary.

## Privacy impact

None. The capture runs an emulated test image with synthetic data;
the fixture carries firmware and UKI measurements only, no user data
and no publisher identity.

## Dependency and license impact

No Rust dependency changes; the signed 53-crate inventory is
untouched. The Ubuntu ovmf-generic .deb is a dev-host build input
(hash-pinned, gitignored output), not a linked dependency; its
license (edk2, BSD-2-Clause-Patent) applies to firmware we execute in
an emulator, not to distributed code.

## Validation

Executed on the dev host: the Fedora-OVMF negative proof (PCRs 0-9/11
zero, no event log), the Ubuntu-OVMF positive capture (PCRs 0-7 and 9
measured, PCR 11 non-zero from sd-stub), the capture gate
(scripts/test-measured-capture.py PASS; zeroed-PCR-11 negative
rejects), and the durable Rust triangle
(uki_capture_triangle: replay == live, quoted digest == replay's
SHA256, nonce echoed, QuoteVerifier accepts, tamper rejects; 2/2).
All house gates green; the full workspace suite passes.

## Rollback

Revert the commit; the parser returns to its previous (u8) read and
the fixture/tests disappear with it. The fetched OVMF pair lives only
in the gitignored build directory and can be deleted at any time.

## Primary sources

- TCG EFI Protocol Specification: TCG_EFI_SPEC_ID_EVENT and
  TCG_EFI_SPEC_ID_ALGORITHM (digestSize is a u16 field).
- TPM 2.0 Library Part 2: TPMS_ATTEST and TPMS_ATTEST_QUOTE layouts;
  TPM2_CC command codes as published in tss2_tpm2_types.h.
- The executed capture evidence on the dev host (2026-09-07): the
  swtpm command traces, the in-guest pcrread transcript, and the
  exported fixture committed with this decision.
