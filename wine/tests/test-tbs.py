#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fail-closed gate over the TBS compat layer (M10-049, ADR-0045).

Compiles wine/tbs/tbs.c in standalone mode with the scenario
harness, then drives it against a REAL per-prefix swtpm started
by the M10-048 manager. NEGATIVE TESTS FIRST (no-vtpm presence,
every documented parameter error, handle misuse), then the happy
paths (a real TPM2_GetRandom round-trip, the insufficient-buffer
contract, in-place buffers, TPM-error transparency, cancel,
device info, context cycling, two interleaved contexts), and the
source-level physical-isolation grep.

Usage: PYTHONDONTWRITEBYTECODE=1 python3 wine/tests/test-tbs.py
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

FAILURES: list[str] = []


def fail(message: str) -> None:
    print(f"tbs gate FAILED: {message}")
    FAILURES.append(message)


def expect(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        fail(f"{label}: {detail}")


def code_of(out: dict[str, str], key: str = "CODE") -> str:
    return out.get(key, "missing")


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="ogir-tbs-test-"))
    prefix = tmp / "prefix"
    runtime_dir = tmp / "runtime"
    prefix.mkdir()
    runtime_dir.mkdir()
    binary = tmp / "tbs_harness"

    compile_result = subprocess.run(
        [
            "gcc",
            "-std=c17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DOGIR_TBS_STANDALONE",
            f"-I{TBS_H_DIR}",
            str(TBS_C),
            str(HARNESS_C),
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if compile_result.returncode != 0:
        raise SystemExit(f"tbs gate FAILED: harness compile:\n{compile_result.stderr}")

    env = dict(os.environ)
    # The test OWNS both env inputs (the M1-013F lesson): its own
    # runtime root and its own prefix - no env value the test did
    # not set ever feeds a path the layer builds.
    env["XDG_RUNTIME_DIR"] = str(runtime_dir)
    env["WINEPREFIX"] = str(prefix)
    env.pop("OGIR_VTPM_TEST_LEGACY", None)

    def harness(scenario: str, arg: str = "") -> dict[str, str]:
        result = subprocess.run(
            [str(binary), scenario] + ([arg] if arg else []),
            capture_output=True,
            text=True,
            timeout=90,
            env=env,
        )
        out: dict[str, str] = {}
        for line in result.stdout.splitlines():
            tokens = line.split()
            for i in range(0, len(tokens) - 1, 2):
                out.setdefault(tokens[i], tokens[i + 1])
        return out

    def manager(action: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(MANAGER), action, str(prefix)],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )

    try:
        # --- Physical isolation (mechanical): the layer has no
        #     host TPM reference at the source level.
        source = TBS_C.read_text(encoding="utf-8")
        header = (TBS_H_DIR / "tbs.h").read_text(encoding="utf-8")
        for forbidden in ["/dev/tpm", "tpm2_", "/dev/tpmrm"]:
            for name, blob in (("tbs.c", source), ("tbs.h", header)):
                if forbidden in blob:
                    fail(f"the layer must never reference the host TPM ({forbidden} in {name})")

        # === NEGATIVE FIRST: no vtpm is running yet. ===
        out = harness("create-basic")
        expect("create without vtpm", "CREATE" in out and out["CREATE"] == "0xffffffff",
               f"expected create failure, got {out}")
        out = harness("deviceinfo")
        expect("deviceinfo without vtpm", code_of(out) == "0x8028400f",
               f"expected TBS_E_TPM_NOT_FOUND, got {out}")

        # Parameter errors (checked before any IO - no vtpm needed).
        expect("create null out", code_of(harness("create-null-out")) == "0x80284003")
        expect("create null params", code_of(harness("create-null-params")) == "0x80284002")
        expect("create v1 (1.2 request)", code_of(harness("create-v1")) == "0x8028400f")
        expect("create v3", code_of(harness("create-v3")) == "0x80284007")
        expect("create v2 without includeTpm20", code_of(harness("create-v2-no20")) == "0x8028400f")
        expect("cancel invalid handle", code_of(harness("cancel-invalid")) == "0x80284004")
        expect("close invalid handle", code_of(harness("close-invalid")) == "0x80284004")
        expect("submit invalid handle", code_of(harness("submit-invalid-context")) == "0x80284004")

        # === The vtpm goes live. ===
        started = manager("start")
        if started.returncode != 0:
            raise SystemExit(f"tbs gate FAILED: manager start: {started.stderr}")

        # Context lifecycle.
        out = harness("create-basic")
        expect("create with vtpm", code_of(out) == "0x00000000", f"{out}")
        out = harness("close-twice")
        expect("close first", code_of(out) == "0x00000000", f"{out}")
        expect("close second", out.get("SECOND") == "0x80284004", f"{out}")
        out = harness("submit-after-close")
        expect("submit after close", code_of(out) == "0x80284004", f"{out}")

        # Parameter matrix against a live context.
        expect("submit short command", code_of(harness("submit-short")) == "0x80284002")
        expect("submit null command", code_of(harness("submit-null-command")) == "0x80284002")
        expect("submit null result size", code_of(harness("submit-null-resultsize")) == "0x80284003")
        expect("submit oversize command", code_of(harness("submit-oversize")) == "0x8028400e")
        expect("submit bad locality", code_of(harness("submit-bad-locality")) == "0x80284002")
        expect("submit bad priority", code_of(harness("submit-bad-priority")) == "0x80284002")

        # The real round-trip: TPM2_GetRandom(16).
        out = harness("submit-random", "16")
        expect("submit getrandom", code_of(out) == "0x00000000", f"{out}")
        response = out.get("RESPONSE", "")
        expect("getrandom response present", len(response) >= 24, f"{out}")
        if len(response) >= 24:
            expect("getrandom tag", response[0:4] == "8001", response[0:4])
            expect("getrandom tpm rc", response[12:20] == "00000000", response[12:20])
            expect("getrandom count 16", response[20:24] == "0010", response[20:24])
            expect("getrandom payload nonzero", any(c != "0" for c in response[24:]), response[24:])
            declared = int(out.get("SIZE", "0"))
            expect("getrandom size math", declared == 28, f"SIZE {declared}")

        # The documented too-small contract.
        out = harness("submit-small-result")
        expect("insufficient buffer code", code_of(out) == "0x80284005", f"{out}")
        expect("insufficient buffer size", out.get("SIZE") == "28", f"{out}")

        # In-place buffers are documented as allowed.
        out = harness("submit-inplace")
        expect("inplace code", code_of(out) == "0x00000000", f"{out}")
        expect("inplace response", out.get("RESPONSE", "")[12:20] == "00000000", f"{out}")

        # TRANSPARENCY: a truncated GetRandom must come back as
        # the TPM's OWN error in the buffer with transport success
        # (the layer never synthesizes TPM errors).
        out = harness("submit-tpm-error")
        expect("tpm-error transport code", code_of(out) == "0x00000000", f"{out}")
        expect("tpm-error verbatim", out.get("RESPONSE", "")[12:20] != "00000000",
               "the TPM's own error must be in the response")

        # Cancel (bounded: swtpm cannot interrupt a synchronous
        # command; the API reports what the vtpm says).
        out = harness("cancel-basic")
        expect("cancel code", code_of(out) == "0x00000000", f"{out}")
        expect("cancel close", out.get("CLOSE") == "0x00000000", f"{out}")

        # Device info.
        out = harness("deviceinfo")
        expect("deviceinfo code", code_of(out) == "0x00000000", f"{out}")
        expect("deviceinfo struct version", out.get("STRUCTVERSION") == "2", f"{out}")
        expect("deviceinfo tpm version", out.get("TPMVERSION") == "2", f"{out}")
        expect("deviceinfo iface reserved", out.get("IFACE") == "0", f"{out}")
        expect("deviceinfo impl reserved", out.get("IMPL") == "0", f"{out}")
        expect("deviceinfo small size", code_of(harness("deviceinfo-small")) == "0x80284002")
        expect("deviceinfo null", code_of(harness("deviceinfo-null")) == "0x80284002")

        # Cycling: create/close x5 then a submit (the server-mode
        # socket must keep accepting).
        out = harness("cycle")
        for i in range(1, 6):
            expect(f"cycle create {i}", out.get(f"CREATE{i}") == "ok", f"{out}")
        expect("cycle submit", code_of(out) == "0x00000000", f"{out}")

        # Two contexts, interleaved submits (the disconnect-mode
        # data channel exists for exactly this).
        out = harness("two-contexts")
        expect("second context", out.get("OTHER") == "ok", f"{out}")
        expect("second context submit", out.get("OTHERSUBMIT", "").startswith("0x00000000"), f"{out}")
        expect("first context submit", out.get("FIRSTSUBMIT", "").startswith("0x00000000"), f"{out}")
        expect("both close", out.get("CLOSE1") == "0x00000000" and out.get("CLOSE2") == "0x00000000", f"{out}")

        # === The vtpm goes away: presence fails closed again. ===
        stopped = manager("stop")
        if stopped.returncode != 0:
            fail(f"manager stop failed: {stopped.stderr}")
        out = harness("create-basic")
        expect("create after stop", out.get("CREATE") == "0xffffffff", f"{out}")
        expect("deviceinfo after stop", code_of(harness("deviceinfo")) == "0x8028400f")
    finally:
        manager("stop")
        shutil.rmtree(tmp, ignore_errors=True)

    if FAILURES:
        raise SystemExit(1)
    print(
        "tbs gate PASS: no-vtpm fail-closed, parameter matrix, handle misuse, "
        "getrandom round-trip, insufficient-buffer contract, in-place, "
        "tpm-error transparency, cancel, device info, cycling, interleaved "
        "contexts, no host-TPM reference"
    )


if __name__ == "__main__":
    main()
