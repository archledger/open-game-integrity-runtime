# OGIR test image (M4-028a)

A minimal, UKI-only measured-boot test image: no rootfs, no full OS,
no production user data. The measurement chain is what M4 proves.

- `keys/generate-test-keys.sh` — fresh self-signed TEST-ONLY Secure
  Boot keys (clearly labeled; never production, per the ADR-0016
  philosophy). The committed `keys/test-*.der`/`*.pem` pair makes
  fixture builds deterministic.
- `keys/generate-test-manifest-key.sh` - the TEST-ONLY reference-
  manifest anchor key pair (ADR-0025), also committed for
  deterministic fixtures; `scripts/sign-reference-manifest.sh` uses
  it to sign manifest payloads.
- `build-image.sh` — assembles the UKI with ukify (kernel + initramfs
  + known command line + systemd-stub), signs it with sbsign against
  the test key, and packs it into a FAT ESP image with mtools.

Outputs land in `image/build/`: `ogir-test.uki` (the signed UKI) and
`ogir-test.esp` (the FAT ESP). M4-028b boots the ESP under
OVMF + swtpm (`boot-test.sh`).

## The measured capture (M4-028c)

`fetch-ovmf-tcg2.sh` obtains the pinned, hash-verified TCG2-enabled
OVMF the capture requires (Fedora's ships none; see
`boot-findings.md` and ADR-0024). `boot-capture.sh` then builds a
SECOND signed UKI - the same TEST-ONLY key, with a capture init
embedded in the initramfs (`capture-init.sh`, nonce-substituted at
build time) - boots it under the TCG2 OVMF + swtpm, and exports the
full evidence set from inside the guest: the binary TCG2 event log,
the live PCR values, and a TPM2 quote (canonical `createek`/
`createak` pair) with the recorded nonce. sd-stub measures the
capture UKI into PCR 11 through the firmware's TCG2 protocol like any
UKI. Artifacts land in `image/build/capture/artifacts/`;
`scripts/test-measured-capture.py` gates them, and the committed
fixture is validated by the Rust triangle test in
`crates/ogir-attest-tpm/tests/uki_capture_triangle.rs`.

The capture is a dev-host gate (QEMU boots are not wired into CI);
the committed evidence is what CI validates.

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
