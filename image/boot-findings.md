# M4-028b boot-harness findings and the TCG2 blocker

- agent: zcode
- timestamp: 2026-09-06T21:15:00-04:00

## What works (executed on the dev host)

1. **The full boot chassis**: swtpm (UNIX-ctrl socket) + QEMU (q35,
   TCG, no KVM) + OVMF + the built ESP. The UKI loads and the firmware
   measures OR rejects it; the TPM state persists (4.4KB
   `tpm2-00.permall`); the serial log captures the firmware messages.

2. **Secure Boot enforcement (proven)**: with `OVMF_CODE.secboot.fd`,
   OVMF rejects the UKI ("Access Denied -- rejected probably by Secure
   Boot") because the test key is not enrolled. This IS the correct
   behavior and demonstrates the enforcement point.

3. **The UKI boots (proven)**: with the non-secboot `OVMF_CODE.fd`,
   the UKI boots: the kernel starts, dracut runs, systemd reaches
   emergency mode (no root filesystem - by design), and the kernel's
   serial output confirms the command line `ogir.test=1`.

## The blocker: Fedora's OVMF has no TCG2 support

Verified: `strings` finds ZERO `Tcg2Dxe` references in every OVMF_CODE
variant shipped by `edk2-ovmf-20260812` (non-secboot, secboot, and
pcrlock). Without TCG2Dxe, OVMF performs NO TPM2 measurements; the
PCRs remain zero regardless of the boot outcome. This is a
distribution packaging fact, not a configuration issue.

## Fix options (any one suffices)

1. **Build edk2 from source** with `-D TCG2_ENABLE=TRUE` (the
   upstream default for the OvmfPkg platform; Fedora's build disables
   it or uses a different DXE distribution).
2. **Use another distribution's OVMF**: Debian/Ubuntu's `ovmf`
   package includes the TCG2 driver (the standard `OVMF_CODE.fd`
   there has TPM2 measurement support).
3. **Use the edk2 prebuilt from the TCG/edk2 repos** (the
   "OVMF-SNAPSHOT" binaries from the tpm2 infra project).

Any of these drops into `image/boot-test.sh` via the `OVMF_CODE`
override - the harness needs no other change.

## What M4-028b still needs after the blocker clears

- A TCG2-enabled OVMF (one of the three fixes above).
- The test-key-enrolled varstore (OVMF Shell `EnRoll` or a
  pre-built varstore fixture).
- The PCR readback path: with TCG2 OVMF, the PCRs will actually
  contain measurements; the readback method (swtpm state or a
  in-guest reader for the event log) is then the remaining work.

## Resolution (M4-028c, 2026-09-07)

The blocker is CONFIRMED and RESOLVED.

**Confirmed empirically, not by strings.** A traced swtpm under the
Fedora OVMF shows zero firmware TPM2_Extend traffic and a full guest
boot leaves PCRs 0-9 and 11 at zero with no event log published
(read live from inside the guest through /dev/tpmrm0). One caveat on
the original evidence: firmware volumes are LZMA-compressed, so
`strings` alone can prove nothing either way - Ubuntu's TCG2-enabled
OVMF also shows zero Tcg2Dxe strings. Only executed TPM traffic or
live PCR values settle the question. (The PCR 10 activity observed
during the first trace is NOT firmware: it is the Linux kernel's IMA
plus its TPM2 HMAC-session support, which CreatePrimary/StartAuthSession
sequence made look deceptively like a firmware TCG2 flow.)

**Resolved** by fix option 2: `image/fetch-ovmf-tcg2.sh` pins Ubuntu's
`ovmf-generic_2026.05-2ubuntu2_all.deb`, verifies the package and both
extracted firmware volumes against committed SHA-256 hashes, and
`image/boot-capture.sh` runs the measured capture under it (ADR-0024):
firmware PCRs 0-7 and 9 all measured, the event log published and
exported from the guest, and the sd-stub UKI phase measured into
PCR 11 (non-zero, replay-validated).

**Still open, deliberately:** the test-key-enrolled varstore and
Secure Boot enforcement of the capture image (the M4-030 attack
categories that need SB, not the measurement chain).

