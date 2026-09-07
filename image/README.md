# OGIR test image (M4-028a)

A minimal, UKI-only measured-boot test image: no rootfs, no full OS,
no production user data. The measurement chain is what M4 proves.

- `keys/generate-test-keys.sh` — fresh self-signed TEST-ONLY Secure
  Boot keys (clearly labeled; never production, per the ADR-0016
  philosophy). The committed `keys/test-*.der`/`*.pem` pair makes
  fixture builds deterministic.
- `build-image.sh` — assembles the UKI with ukify (kernel + initramfs
  + known command line + systemd-stub), signs it with sbsign against
  the test key, and packs it into a FAT ESP image with mtools.

Outputs land in `image/build/`: `ogir-test.uki` (the signed UKI) and
`ogir-test.esp` (the FAT ESP). M4-028b boots the ESP under
OVMF + swtpm and exports the event-log fixture.

## Tooling

Fedora: `dnf install systemd-ukify systemd-boot sbsigntools mtools
dosfstools edk2-ovmf`. CI (ubuntu): the `ovmf`, `systemd-ukify`,
`systemd-boot-efi` (or equivalent stub package), `sbsigntool`,
`mtools`, `dosfstools` packages. The host kernel and its initramfs
serve as the payload (override with `OGIR_KERNEL`/`OGIR_INITRD`).

## Security notes

The keys here gate a TEST image's Secure Boot chain for fixture
reproducibility. They are committed deliberately: deterministic
fixtures require stable test identities (the same trade ADR-0016 made
for the mock namespace). Never enroll them on production hardware and
never treat artifacts signed by them as production-trusted.
