#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed checks over a measured-boot capture (M4-028c).

Verifies the artifacts image/boot-capture.sh exports BEFORE they are
promoted to fixtures: every file present and non-empty, the binary log
carries the TCG2 Spec ID signature, PCR 11 (the sd-stub UKI bank) is
measured non-zero, and the recorded nonce appears in the quote's
attestation. The durable replay/quote/signature validation is the
Rust triangle test (crates/ogir-attest-tpm/tests/uki_capture_triangle.rs);
this gate catches a bad capture at capture time.

Usage: PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-measured-capture.py \
           [artifacts-dir (default image/build/capture/artifacts)]
"""

import sys
from pathlib import Path

sys.dont_write_bytecode = True

REQUIRED = [
    "event-log.bin",
    "pcrs.txt",
    "quote.msg",
    "quote.sig",
    "quote.pcrs",
    "ak.pem",
    "nonce.txt",
    "report.txt",
]

FAILURES = []


def check(condition: bool, message: str) -> None:
    if not condition:
        FAILURES.append(message)


def main() -> int:
    # The canonical capture directory, derived from the script's own
    # location (a build-controlled constant, never user input): this
    # gate validates THE capture boot-capture.sh just produced.
    artifacts = Path(__file__).resolve().parents[1] / "image" / "build" / "capture" / "artifacts"
    if not artifacts.is_dir():
        print(f"FAIL: artifacts directory missing: {artifacts}")
        return 1

    blobs = {}
    for name in REQUIRED:
        path = artifacts / name
        check(path.is_file(), f"missing artifact: {name}")
        if path.is_file():
            blobs[name] = path.read_bytes()
            check(len(blobs[name]) > 0, f"empty artifact: {name}")

    if FAILURES:
        for failure in FAILURES:
            print(f"FAIL: {failure}")
        return 1

    # The binary log must carry the TCG2 EFI Spec ID event signature.
    check(blobs["event-log.bin"].find(b"Spec ID Event03") >= 0,
          "event-log.bin lacks the TCG2 Spec ID Event03 signature")

    # PCR 11 (the sd-stub UKI bank) must be measured non-zero in the
    # live SHA-256 read.
    sha256_bank = {}
    in_bank = False
    for line in blobs["pcrs.txt"].decode("ascii", "strict").splitlines():
        if line.startswith("  sha256:"):
            in_bank = True
            continue
        if not in_bank or ":" not in line:
            continue
        index_text, value_text = line.split(":", 1)
        index_text, value_text = index_text.strip(), value_text.strip()
        if not index_text.isdigit():
            break  # the sha1: section header
        sha256_bank[int(index_text)] = value_text
    check(len(sha256_bank) >= 9, f"pcrs.txt sha256 bank too small: {sorted(sha256_bank)}")
    check(sha256_bank.get(11, "0x" + "0" * 64) != "0x" + "0" * 64,
          "PCR 11 is zero: the UKI phase was not measured")
    zero_pcrs = [index for index, value in sha256_bank.items() if set(value[2:]) == {"0"}]
    check(zero_pcrs == [], f"unexpected zero PCRs in the capture set: {zero_pcrs}")

    # The quote must echo the recorded nonce (TPMS_ATTEST extraData is
    # the first TPM2B after magic+type+TPM2B_NAME).
    nonce_hex = blobs["nonce.txt"].decode("ascii", "strict").strip()
    check(len(nonce_hex) == 64, f"nonce is not 32 bytes: {nonce_hex!r}")
    attest = blobs["quote.msg"]
    check(len(attest) >= 12, "quote.msg too short for the attest header")
    check(int.from_bytes(attest[0:4], "big") == 0xFF544347, "quote.msg lacks the TPM2 magic")
    check(int.from_bytes(attest[4:6], "big") == 0x8018, "quote.msg is not a QUOTE attestation")
    offset = 6
    offset += 2 + int.from_bytes(attest[offset:offset + 2], "big")  # qualifiedSigner
    extra_len = int.from_bytes(attest[offset:offset + 2], "big")
    extra = attest[offset + 2:offset + 2 + extra_len]
    check(extra.hex() == nonce_hex, "the quote does not echo the recorded nonce")

    # The report must show a clean capture.
    report = blobs["report.txt"].decode("utf-8", "replace")
    check("EVENTLOG-MISSING" not in report, "the guest saw no event log")
    check("TPM-MISSING" not in report, "the guest saw no TPM")
    check("MISSING" not in report, "the guest reported a missing capture piece")

    if FAILURES:
        for failure in FAILURES:
            print(f"FAIL: {failure}")
        return 1

    print(f"measured-capture checks PASS ({artifacts}); "
          f"PCR 11 = {sha256_bank.get(11)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
