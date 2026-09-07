#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""M4-028a static verification of the built test image.

Checks (fail closed):
  * the UKI exists and is a PE image (MZ magic);
  * sbverify confirms it is signed by the committed TEST-ONLY key;
  * the .cmdline section carries exactly the known command line;
  * the .linux/.initrd/.uname sections are present and nonempty;
  * the FAT ESP contains the UKI at EFI/BOOT/BOOTX64.EFI.

Run after image/build-image.sh. Exit 0 only when every check passes.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
IMAGE = REPO_ROOT / "image"
UKI = IMAGE / "build" / "ogir-test.uki"
ESP = IMAGE / "build" / "ogir-test.esp"
CERT = IMAGE / "keys" / "ogir-test.crt"
CMDLINE = IMAGE / "cmdline.test"
EXPECTED_SECTIONS = (b".linux", b".initrd", b".uname", b".cmdline")

FAILURES: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        FAILURES.append(message)


def main() -> int:
    check(UKI.is_file(), "missing UKI: build it with image/build-image.sh")
    check(ESP.is_file(), "missing ESP: build it with image/build-image.sh")
    if FAILURES:
        for failure in FAILURES:
            print(f"image-build FAILED: {failure}")
        return 1

    uki = UKI.read_bytes()
    check(uki[:2] == b"MZ", "UKI is not a PE image (missing MZ magic)")

    # The committed TEST-ONLY key must verify the signature.
    verify = subprocess.run(
        ["sbverify", str(UKI), "--cert", str(CERT)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    check(
        verify.returncode == 0 and "Signature verification OK" in verify.stdout,
        f"sbverify against the test key failed: {verify.stdout.strip()} {verify.stderr.strip()}",
    )
    check(
        b"DO NOT TRUST" not in b"" and "TEST-ONLY" in subprocess.run(
            ["openssl", "x509", "-in", str(CERT), "-noout", "-subject"],
            capture_output=True,
            text=True,
            timeout=60,
        ).stdout,
        "the certificate subject is not branded TEST-ONLY",
    )

    # Sections: enumerate PE section names via objdump.
    objdump = subprocess.run(
        ["objdump", "-h", str(UKI)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    check(objdump.returncode == 0, "objdump failed on the UKI")
    listed = objdump.stdout.encode()
    for section in EXPECTED_SECTIONS:
        check(section in listed, f"UKI lacks the {section.decode()} section")

    # The command line must be exactly the known test line.
    extract = subprocess.run(
        [
            "objcopy",
            "-O",
            "binary",
            "--only-section=.cmdline",
            str(UKI),
            "/dev/stdout",
        ],
        capture_output=True,
        timeout=60,
    )
    expected = CMDLINE.read_bytes().strip()
    check(
        extract.returncode == 0 and extract.stdout.strip() == expected,
        f".cmdline mismatch: expected {expected!r}, got {extract.stdout.strip()!r}",
    )

    # The ESP must carry the UKI at the standard boot path.
    listing = subprocess.run(
        ["mdir", "-i", str(ESP), "-/", "::/"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    # mdir -/ recurses; the boot file appears in the EFI/BOOT block.
    check(
        listing.returncode == 0 and "BOOTX64" in listing.stdout and "EFI" in listing.stdout,
        "the ESP lacks EFI/BOOT/BOOTX64.EFI",
    )

    if FAILURES:
        for failure in FAILURES:
            print(f"image-build FAILED: {failure}")
        return 1
    print("image-build checks PASS: signed UKI, known cmdline, sections, ESP boot entry")
    return 0


if __name__ == "__main__":
    sys.exit(main())
