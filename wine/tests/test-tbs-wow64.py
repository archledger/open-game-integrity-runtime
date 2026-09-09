#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""WoW64/PE ABI gate over the TBS compat layer (M10-051, ADR-0047).

Builds wine/tbs/tbs.c + the scenario harness as PE binaries with
the mingw cross-compilers (winsock transport, -DOGIR_TBS_PE), then
runs the SAME TBS behavior matrix under Wine - the i686 leg
through Wine's WoW64 - against a REAL per-prefix swtpm:

- ABI evidence: the object-level symbol shapes (i386 stdcall
  decorations with exact argument-byte counts; x64 undecorated).
- The functional matrix per architecture: fail-closed presence,
  the documented validation codes, a real GetRandom round-trip
  with per-architecture DISTINCT random payloads (the vTPM must
  never serve one caller's bytes to the other), the
  insufficient-buffer contract, cancel, device info, close
  semantics, cycling, and two interleaved contexts.
- The capability contract: device-info reserved fields stay 0.

Dev-host gate (CI has no Wine); requires wine, swtpm, and the
mingw cross-compilers.

Usage: PYTHONDONTWRITEBYTECODE=1 python3 wine/tests/test-tbs-wow64.py
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent.parent
TBS_C = ROOT / "wine" / "tbs" / "tbs.c"
TBS_H_DIR = ROOT / "wine" / "tbs" / "include"
HARNESS_C = ROOT / "wine" / "tests" / "tbs_harness.c"
MANAGER = ROOT / "wine" / "vtpm" / "vtpm-manager.sh"

# The documented stdcall argument-byte counts (7 pointer-size
# args for Submit -> @28; the ABI Windows import libs expect).
I386_SYMBOLS = {
    "_Tbsi_Context_Create@8",
    "_Tbsip_Submit_Command@28",
    "_Tbsip_Cancel_Commands@4",
    "_Tbsip_Context_Close@4",
    "_Tbsi_GetDeviceInfo@8",
}
X64_SYMBOLS = {
    "Tbsi_Context_Create",
    "Tbsip_Submit_Command",
    "Tbsip_Cancel_Commands",
    "Tbsip_Context_Close",
    "Tbsi_GetDeviceInfo",
}

ARCHES = {
    "x86_64": {"cc": "x86_64-w64-mingw32-gcc", "nm": "x86_64-w64-mingw32-nm", "symbols": X64_SYMBOLS},
    "i686": {"cc": "i686-w64-mingw32-gcc", "nm": "i686-w64-mingw32-nm", "symbols": I386_SYMBOLS},
}

FAILURES: list[str] = []


def fail(message: str) -> None:
    print(f"tbs wow64 gate FAILED: {message}")
    FAILURES.append(message)


def expect(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        fail(f"{label}: {detail}")


def parse_output(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        tokens = line.split()
        for i in range(0, len(tokens) - 1, 2):
            out.setdefault(tokens[i], tokens[i + 1])
    return out


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="ogir-tbs-wow64-"))
    runtime_dir = tmp / "runtime"
    prefix = tmp / "prefix"
    runtime_dir.mkdir()
    prefix.mkdir()

    # === Build both PE objects; the symbol shapes are ABI evidence. ===
    binaries: dict[str, Path] = {}
    for arch, tools in ARCHES.items():
        obj = tmp / f"tbs_{arch}.o"
        compiled = subprocess.run(
            [tools["cc"], "-std=c17", "-Wall", "-Wextra", "-Werror", "-DOGIR_TBS_PE",
             f"-I{TBS_H_DIR}", "-c", str(TBS_C), "-o", str(obj)],
            capture_output=True, text=True, timeout=120)
        if compiled.returncode != 0:
            raise SystemExit(f"tbs wow64 gate FAILED: {arch} compile:\n{compiled.stderr}")
        listed = subprocess.run([tools["nm"], str(obj)], capture_output=True, text=True, timeout=60)
        defined = {line.split()[-1] for line in listed.stdout.splitlines() if " T " in line}
        missing = tools["symbols"] - defined
        expect(f"{arch} entry-point symbols", not missing,
               f"missing from the object: {sorted(missing)}")
        exe = tmp / f"harness_{arch}.exe"
        linked = subprocess.run(
            [tools["cc"], "-std=c17", "-Wall", "-Wextra", "-Werror", "-DOGIR_TBS_PE",
             f"-I{TBS_H_DIR}", str(TBS_C), str(HARNESS_C), "-o", str(exe), "-lws2_32"],
            capture_output=True, text=True, timeout=120)
        if linked.returncode != 0:
            raise SystemExit(f"tbs wow64 gate FAILED: {arch} link:\n{linked.stderr}")
        binaries[arch] = exe

    env = dict(os.environ)
    env["XDG_RUNTIME_DIR"] = str(runtime_dir)
    env["WINEPREFIX"] = str(prefix)

    def manager(action: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(MANAGER), action, str(prefix)], capture_output=True, text=True, timeout=60, env=env
        )

    def harness(arch: str, scenario: str, arg: str = "") -> dict[str, str]:
        argv = [str(binaries[arch]), scenario] + ([arg] if arg else [])
        result = subprocess.run(
            ["wine"] + argv, capture_output=True, text=True, timeout=180, env=env
        )
        return parse_output(result.stdout)

    try:
        boot = subprocess.run(["wineboot", "-u"], capture_output=True, text=True,
                              timeout=300, env=env)
        if boot.returncode != 0:
            raise SystemExit(f"tbs wow64 gate FAILED: wineboot: {boot.stderr}")
        started = manager("start")
        if started.returncode != 0:
            raise SystemExit(f"tbs wow64 gate FAILED: manager start: {started.stderr}")

        payloads: dict[str, str] = {}
        for arch in ARCHES:
            tag = arch

            # Presence + the documented validation codes.
            out = harness(arch, "create-basic")
            expect(f"[{tag}] create", out.get("CODE") == "0x00000000", f"{out}")
            expect(f"[{tag}] create v1 rejected", harness(arch, "create-v1").get("CODE") == "0x8028400f")
            expect(f"[{tag}] bad locality rejected", harness(arch, "submit-bad-locality").get("CODE") == "0x80284002")
            expect(f"[{tag}] close invalid handle", harness(arch, "close-invalid").get("CODE") == "0x80284004")
            out = harness(arch, "close-twice")
            expect(f"[{tag}] close second", out.get("SECOND") == "0x80284004", f"{out}")
            expect(f"[{tag}] submit after close", harness(arch, "submit-after-close").get("CODE") == "0x80284004")

            # The real round-trip.
            out = harness(arch, "submit-random", "16")
            expect(f"[{tag}] getrandom", out.get("CODE") == "0x00000000", f"{out}")
            response = out.get("RESPONSE", "")
            expect(f"[{tag}] getrandom shape", response[0:4] == "8001" and response[12:20] == "00000000"
                   and response[20:24] == "0010", response)
            expect(f"[{tag}] getrandom size 28", out.get("SIZE") == "28", f"{out}")
            expect(f"[{tag}] getrandom payload nonzero", any(c != "0" for c in response[24:]), response)
            payloads[tag] = response
            expect(f"[{tag}] insufficient buffer", harness(arch, "submit-small-result").get("CODE") == "0x80284005")

            # Cancel + device info (the capability contract fields).
            out = harness(arch, "cancel-basic")
            expect(f"[{tag}] cancel", out.get("CODE") == "0x00000000", f"{out}")
            out = harness(arch, "deviceinfo")
            expect(f"[{tag}] deviceinfo", out.get("CODE") == "0x00000000" and out.get("TPMVERSION") == "2"
                   and out.get("IFACE") == "0" and out.get("IMPL") == "0", f"{out}")

            # Lifecycle under repetition.
            out = harness(arch, "cycle")
            expect(f"[{tag}] cycle", out.get("CREATE5") == "ok" and out.get("CODE") == "0x00000000", f"{out}")
            out = harness(arch, "two-contexts")
            expect(f"[{tag}] two contexts", out.get("OTHER") == "ok"
                   and out.get("FIRSTSUBMIT", "").startswith("0x00000000"), f"{out}")

        # The two callers must have received DIFFERENT bytes.
        expect("cross-architecture payload distinctness", payloads["x86_64"] != payloads["i686"],
               "both architectures saw identical random bytes")

        # === The vTPM dies: both architectures fail closed. ===
        stopped = manager("stop")
        if stopped.returncode != 0:
            fail(f"manager stop failed: {stopped.stderr}")
        for arch in ARCHES:
            expect(f"[{arch}] fail-closed after stop", harness(arch, "create-basic").get("CREATE") == "0xffffffff")
    finally:
        manager("stop")
        shutil.rmtree(tmp, ignore_errors=True)

    if FAILURES:
        raise SystemExit(1)
    print(
        "tbs wow64 gate PASS: i386 stdcall and x64 symbol shapes, the behavior "
        "matrix under Wine for both PE architectures (i686 via WoW64), distinct "
        "per-architecture random payloads, fail-closed after the vTPM stops"
    )


if __name__ == "__main__":
    main()
