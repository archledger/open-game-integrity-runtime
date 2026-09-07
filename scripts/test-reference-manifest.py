#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed static checks over the reference-manifest fixtures.

Runs before the fixtures are trusted as committed evidence: the
canonical grammar's static properties (field order, hex widths, the
signature line last) and the coherence of the committed signing-root
fingerprint with the committed TEST-ONLY image key. The durable
parse/replay/signature validation is the Rust suite
(crates/ogir-attest-tpm/tests/reference_manifest.rs); this gate
catches a broken fixture at signing time, when the private anchor is
still at hand.

Usage: PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-reference-manifest.py
"""

import hashlib
import sys
from pathlib import Path

sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = REPO_ROOT / "crates" / "ogir-attest-tpm" / "tests" / "fixtures" / "manifest"
IMAGE_KEY_DER = REPO_ROOT / "image" / "keys" / "test-image-key.der"

# The one legal field order (ADR-0025): singular fields first, then
# the repeatable list blocks, then the signature line.
FIELD_POSITION = {
    "ogir-manifest-version": 0,
    "profile": 1,
    "revision": 2,
    "secure-boot": 3,
    "pcr-bank": 4,
    "pcr-expectation": 5,
    "minimum-version": 6,
    "signing-root": 7,
    "revoked": 8,
    "signature": 9,
}


def fail(message: str) -> None:
    print(f"reference-manifest gate FAILED: {message}")
    raise SystemExit(1)


def is_lower_hex(text: str) -> bool:
    return all(c in "0123456789abcdef" for c in text)


def check_manifest(path: Path) -> list:
    if not path.is_file() or path.stat().st_size == 0:
        fail(f"missing or empty fixture: {path}")
    raw = path.read_bytes()
    if b"\r" in raw or b"\t" in raw:
        fail(f"{path.name}: CR or tab byte")
    if not raw.endswith(b"\n"):
        fail(f"{path.name}: missing final newline")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        fail(f"{path.name}: non-ascii byte")

    lines = text.split("\n")
    if lines[-1] != "":
        fail(f"{path.name}: must end with exactly one newline")
    lines = lines[:-1]

    if not lines[-1].startswith("signature: "):
        fail(f"{path.name}: signature line must be last")
    signature_hex = lines[-1][len("signature: "):]
    if len(signature_hex) != 512 or not is_lower_hex(signature_hex):
        fail(f"{path.name}: signature must be 512 lowercase hex characters")

    seen_singular = set()
    last_position = -1
    for line in lines[:-1]:
        if line == "" or line.endswith(" ") or ": " not in line:
            fail(f"{path.name}: malformed line {line!r}")
        field, _value = line.split(": ", 1)
        position = FIELD_POSITION.get(field)
        if position is None:
            fail(f"{path.name}: unknown field {field}")
        if position == 9:
            fail(f"{path.name}: signature line is not part of the payload")
        if position < last_position:
            fail(f"{path.name}: field {field} out of order")
        if position < 5:
            if field in seen_singular:
                fail(f"{path.name}: repeated field {field}")
            seen_singular.add(field)
        last_position = position

    for required in FIELD_POSITION:
        if FIELD_POSITION[required] < 5 and required not in seen_singular:
            fail(f"{path.name}: missing field {required}")
    return lines


def check_modulus(name: str) -> None:
    path = FIXTURE_DIR / name
    if not path.is_file():
        fail(f"missing fixture: {path}")
    text = path.read_text().strip()
    if len(text) != 512 or not is_lower_hex(text):
        fail(f"{name}: must be 512 lowercase hex characters")


def check_signing_root(lines: list, image_key_fingerprint: str) -> None:
    for line in lines:
        if line.startswith("signing-root: image-key="):
            if line.split("=", 1)[1] == image_key_fingerprint:
                return
    fail("no signing-root matches the committed image key fingerprint")


def main() -> None:
    for name in ("manifest.txt", "manifest-revoked.txt"):
        lines = check_manifest(FIXTURE_DIR / name)
        fingerprint = hashlib.sha256(IMAGE_KEY_DER.read_bytes()).hexdigest()
        check_signing_root(lines, fingerprint)

    for name in ("anchor-modulus.hex", "image-key-modulus.hex"):
        check_modulus(name)

    print(
        "reference-manifest gate PASS: 2 manifests, grammar static checks, "
        "modulus widths, and the committed image-key fingerprint"
    )


if __name__ == "__main__":
    main()
