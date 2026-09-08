#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed structural checks over the ogir-client build (M5-033).

Validates the artifacts wine/ogir-client/build.sh produces BEFORE
they are trusted for a transport run: the winelib module carries
the loader contract symbols and real spec-bound exports with real
dispatch entries; the PE variants export the public C ABI; the
32-bit PE is a distinct architecture. The functional legs (the ABI
harness under wine against a live portal) are dev-host gates; this
gate catches a broken build at build time.

Usage: PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-ogir-client-build.py
"""

import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "proton" / "ogir-client" / "build"

REQUIRED_SO_SYMBOLS = [
    "__wine_spec_nt_header",
    "__wine_unix_call_funcs",
    "__wine_unix_call_wow64_funcs",
    "ogir_client_open_msabi",
    "ogir_session_close_msabi",
]
REQUIRED_PE_EXPORTS = [
    "ogir_client_open",
    "ogir_client_close",
    "ogir_session_begin",
    "ogir_session_get_permit",
    "ogir_session_sign_binding",
    "ogir_session_close",
]


def fail(message: str) -> None:
    print(f"ogir-client build gate FAILED: {message}")
    raise SystemExit(1)


def dynamic_symbols(path: Path) -> set:
    result = subprocess.run(
        ["nm", "-D", str(path)], capture_output=True, text=True, check=True
    )
    symbols = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3:
            symbols.add(fields[-1])
    return symbols


def pe_exports(path: Path) -> set:
    """Names from the export name-pointer table (ordinal/hint/name
    lines) - the authoritative list for this gate."""
    result = subprocess.run(
        ["x86_64-w64-mingw32-objdump", "-p", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    names = set()
    in_names = False
    for line in result.stdout.splitlines():
        if "Ordinal   Hint Name" in line:
            in_names = True
            continue
        if in_names:
            fields = line.split()
            if fields and fields[-1].startswith("ogir_"):
                names.add(fields[-1])
            elif names:
                break
    return names


def pe_machine(path: Path) -> int:
    with path.open("rb") as handle:
        header = handle.read(4096)
    pe_offset = int.from_bytes(header[0x3C:0x40], "little")
    return int.from_bytes(header[pe_offset + 4 : pe_offset + 6], "little")


def main() -> None:
    artifacts = {
        "winelib module": BUILD / "ogir-client.dll.so",
        "64-bit PE": BUILD / "ogir-client.dll",
        "32-bit PE": BUILD / "ogir-client32.dll",
        "64-bit harness": BUILD / "ogir-abi-test.exe",
        "32-bit harness": BUILD / "ogir-abi-test32.exe",
    }
    for name, path in artifacts.items():
        if not path.is_file() or path.stat().st_size == 0:
            fail(f"missing or empty artifact: {name} ({path})")

    symbols = dynamic_symbols(BUILD / "ogir-client.dll.so")
    for symbol in REQUIRED_SO_SYMBOLS:
        if symbol not in symbols:
            fail(f"the winelib module lost {symbol}")

    # The dispatch tables must be INITIALIZED (data, not bss): an
    # uninitialized table attaches nothing and every unix call fails.
    result = subprocess.run(
        ["nm", "-D", str(BUILD / "ogir-client.dll.so")],
        capture_output=True,
        text=True,
        check=True,
    )
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[-1] in ("__wine_unix_call_funcs", "__wine_unix_call_wow64_funcs"):
            if fields[1] != "D":
                fail(f"{fields[-1]} is uninitialized (bss); the attach path would fail")

    for name in ("ogir-client.dll", "ogir-client32.dll"):
        exports = pe_exports(BUILD / name)
        missing = [export for export in REQUIRED_PE_EXPORTS if export not in exports]
        if missing:
            fail(f"{name} lost exports: {missing}")

    if pe_machine(BUILD / "ogir-client.dll") != 0x8664:
        fail("ogir-client.dll is not AMD64")
    if pe_machine(BUILD / "ogir-client32.dll") != 0x014C:
        fail("ogir-client32.dll is not i386")

    print(
        "ogir-client build gate PASS: winelib loader contract + spec exports, "
        "64-bit and 32-bit PE ABI surfaces, initialized dispatch tables"
    )


if __name__ == "__main__":
    main()
