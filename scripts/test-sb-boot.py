#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed Secure Boot enforcement gate (M4-030, ADR-0026).

Two boots under the TCG2-enabled OVMF_CODE_4M.secboot.fd plus the
TEST-ONLY-enrolled varstore:

  1. the GOOD ESP boots: the serial log must carry the known command
     line AND the kernel's own Secure Boot lockdown notice - Secure
     Boot was enforced and satisfied;
  2. the TAMPERED ESP (one flipped byte inside the signed UKI) must
     be REJECTED by the firmware: no command line in the serial log.

This is the firmware-side leg of the modified-UKI attack category;
the measurement-side legs are the Rust suite
(crates/ogir-attest-tpm/tests/measured_attack_suite.rs).

Usage: PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-sb-boot.py
"""

import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

IMAGE_DIR = Path(__file__).resolve().parent.parent / "image"
BUILD_DIR = IMAGE_DIR / "build"
OVMF_DIR = BUILD_DIR / "ovmf-tcg2"
SECBOOT_CODE = OVMF_DIR / "OVMF_CODE_4M.secboot.fd"
ENROLLED_VARS = OVMF_DIR / "OVMF_VARS_enrolled.fd"
GOOD_ESP = BUILD_DIR / "ogir-test.esp"
TAMPERED_ESP = BUILD_DIR / "ogir-test-tampered.esp"
SERIAL_LOG = BUILD_DIR / "boot" / "serial.log"

KNOWN_CMDLINE = "ogir.test=1 console=ttyS0,115200 panic=-1"
LOCKDOWN_NOTICE = "locked down from EFI Secure Boot mode"
SB_REJECTION = "rejected probably by Secure Boot"


def fail(message: str) -> None:
    print(f"sb-boot gate FAILED: {message}")
    raise SystemExit(1)


def run(command: list, **kwargs) -> subprocess.CompletedProcess:
    result = subprocess.run(command, **kwargs)
    if result.returncode != 0:
        fail(f"command failed ({result.returncode}): {' '.join(command[:4])}")
    return result


def boot(esp: Path, inner_timeout: int) -> str:
    """Runs one boot. NEITHER boot exits QEMU on its own: the good
    UKI's kernel lands in the initramfs emergency shell waiting for
    input, and a rejected boot leaves OVMF at its menu - so the
    script's inner QEMU timeout (exit 124) is the normal end for
    both. The verdict comes from the serial log, never the exit
    code."""
    result = subprocess.run(
        [
            "bash",
            str(IMAGE_DIR / "boot-test.sh"),
        ],
        env={
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "OGIR_OVMF_CODE": str(SECBOOT_CODE),
            "OGIR_OVMF_VARS": str(ENROLLED_VARS),
            "OGIR_ESP": str(esp),
            "OGIR_BOOT_TIMEOUT": str(inner_timeout),
        },
        cwd=IMAGE_DIR,
        capture_output=True,
        timeout=inner_timeout + 120,
    )
    if result.returncode not in (0, 124):
        fail(f"boot script failed ({result.returncode})")
    if not SERIAL_LOG.is_file():
        fail("boot produced no serial log")
    return SERIAL_LOG.read_text(errors="replace")


def build_tampered_esp() -> None:
    """Copies the good ESP and flips one byte inside the signed UKI
    (deterministic: the middle byte of BOOTX64.EFI)."""
    if TAMPERED_ESP.is_file():
        return
    if not GOOD_ESP.is_file():
        fail(f"missing input {GOOD_ESP} (build-image.sh)")
    run(["cp", str(GOOD_ESP), str(TAMPERED_ESP)])
    run(
        ["mcopy", "-i", str(TAMPERED_ESP), "::/EFI/BOOT/BOOTX64.EFI", "/tmp/ogir-bootx64.efi"],
        timeout=60,
    )
    uki = Path("/tmp/ogir-bootx64.efi")
    data = bytearray(uki.read_bytes())
    if len(data) < 2:
        fail("the extracted UKI is empty")
    data[len(data) // 2] ^= 0x01
    uki.write_bytes(bytes(data))
    run(["mdel", "-i", str(TAMPERED_ESP), "::/EFI/BOOT/BOOTX64.EFI"], timeout=60)
    run(
        ["mcopy", "-i", str(TAMPERED_ESP), str(uki), "::/EFI/BOOT/BOOTX64.EFI"],
        timeout=60,
    )
    # Fail closed: the tampered UKI's signature must actually be broken.
    verify = subprocess.run(
        ["sbverify", "--cert", str(IMAGE_DIR / "keys" / "ogir-test.crt"), str(uki)],
        capture_output=True,
        text=True,
    )
    if "Signature verification OK" in verify.stdout:
        fail("the tamper did not break the signature")
    print("tampered ESP built (signature broken by construction)")


def main() -> None:
    for path in (SECBOOT_CODE, ENROLLED_VARS, GOOD_ESP):
        if not path.is_file():
            fail(f"missing input {path} (fetch-ovmf-tcg2.sh, enroll-test-key.sh, build-image.sh)")

    build_tampered_esp()

    good_serial = boot(GOOD_ESP, inner_timeout=150)
    if KNOWN_CMDLINE not in good_serial:
        fail("the good ESP did not boot the known command line under Secure Boot")
    if LOCKDOWN_NOTICE not in good_serial:
        fail("the kernel did not report lockdown from EFI Secure Boot mode")

    tampered_serial = boot(TAMPERED_ESP, inner_timeout=60)
    if KNOWN_CMDLINE in tampered_serial:
        fail("the tampered UKI BOOTED under the enrolled Secure Boot varstore")
    if SB_REJECTION not in tampered_serial:
        fail("the tampered UKI was not visibly rejected by Secure Boot")

    print(
        "sb-boot gate PASS: the enrolled varstore enforces the TEST-ONLY key "
        "(good UKI boots with SB lockdown; the modified UKI is rejected by the firmware)"
    )


if __name__ == "__main__":
    main()
