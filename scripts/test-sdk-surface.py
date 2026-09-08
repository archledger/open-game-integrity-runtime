#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed SDK surface checks (M6-038, ADR-0034): the v1 ABI
freeze. The header must carry the version macros, every frozen
export, the structured verdict surface, and nothing may remove a
frozen symbol; the C++ wrapper must keep its guards. This is what
the M6-039 conformance kit builds on.

Usage: PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-sdk-surface.py
"""

import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
HEADER = ROOT / "sdk" / "include" / "ogir.h"
WRAPPER = ROOT / "sdk" / "cpp" / "include" / "ogir" / "client.hpp"

FROZEN_EXPORTS = [
    "ogir_abi_version",
    "ogir_client_open",
    "ogir_client_close",
    "ogir_session_begin",
    "ogir_session_get_permit",
    "ogir_session_get_result",
    "ogir_session_sign_binding",
    "ogir_session_close",
]

FROZEN_MACROS = [
    "OGIR_ABI_VERSION_MAJOR 1",
    "OGIR_ABI_VERSION_MINOR 0",
]

FROZEN_ENUMS = [
    "OGIR_VERDICT_ALLOW",
    "OGIR_VERDICT_RESTRICTED",
    "OGIR_VERDICT_UNSUPPORTED",
    "OGIR_VERDICT_RETRY",
    "OGIR_VERDICT_DENY",
]


def fail(message: str) -> None:
    print(f"sdk surface gate FAILED: {message}")
    raise SystemExit(1)


def main() -> None:
    header = HEADER.read_text(encoding="utf-8")
    for macro in FROZEN_MACROS:
        if f"#define {macro}" not in header:
            fail(f"frozen macro lost: {macro}")
    for enum_value in FROZEN_ENUMS:
        if enum_value not in header:
            fail(f"frozen verdict value lost: {enum_value}")
    for export in FROZEN_EXPORTS:
        if export not in header:
            fail(f"frozen export lost: {export}")
    if "ogir_result" not in header or "retryable" not in header:
        fail("the structured result surface was lost")
    if "No source or binary compatibility" in header:
        fail("the header still carries the pre-freeze disclaimer")

    wrapper = WRAPPER.read_text(encoding="utf-8")
    for marker in [
        "OGIR_CPP_CLIENT_HPP",
        "enum class Verdict",
        "Unsupported",
        "ogir_session_get_result",
    ]:
        if marker not in wrapper:
            fail(f"C++ wrapper lost {marker}")

    print(
        "sdk surface gate PASS: v1 ABI frozen (8 exports, version macros, "
        "5 verdict families, structured result) and the C++ wrapper intact"
    )


if __name__ == "__main__":
    main()
