# M4-028a: The test-image build
<!-- labels: type: implementation,area: measured-boot,risk: supply-chain,status: needs-review -->
<!-- milestone: M4 Measured Boot Profile -->

Status: Local integration candidate; no live GitHub issue yet. First half of the M4-028 test-image slice under the accepted entry recommendations.

## Problem

The roadmap's dedicated test image needs a build: a signed UKI with a
known command line that OVMF measures into PCR 11, packed into a boot
FAT ESP - reproducibly, with test-only key material.

## Scope

- `image/keys/generate-test-keys.sh`: fresh self-signed TEST-ONLY
  Secure Boot keys (refuses to overwrite; the committed pair makes
  fixture builds deterministic).
- `image/build-image.sh`: ukify (kernel + initramfs + cmdline.test +
  systemd-stub) -> sbsign -> a 100MB FAT ESP carrying
  EFI/BOOT/BOOTX64.EFI. No rootfs: the measurement chain is the
  product.
- `scripts/test-image-build.py`: static verification (PE magic,
  sbverify against the committed key, TEST-ONLY subject branding,
  .linux/.initrd/.uname/.cmdline sections, the exact command line,
  the ESP boot entry) - fail closed.
- `image/README.md`, the known command line, the roadmap boundary,
  this issue, and the plan.

## Acceptance criteria

- The verification script passes against a locally built image (and
  the build was executed and verified on the dev host: a 75MB signed
  UKI whose .cmdline carries exactly the test line).
- All house gates green.

## Current state

- 2026-09-06: Implemented in `research/m4-028a-image-build` from
  `891f016`; awaiting human review and the signed-commit gate.
