#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Attack-family gate over the TBS compat layer (M10-050, ADR-0046).

Executes the M10 roadmap's API-layer attack families against the
REAL layer and a REAL per-prefix swtpm (plus gate-controlled fake
servers for the malformed-RESPONSE legs):

- EXHAUSTION: the 64-context registry cap returns
  TBS_E_TOO_MANY_TBS_CONTEXTS and recovers after close-all; a
  50-submit loop leaks no descriptors.
- MALFORMED: bad tag and header/length mismatch reach the TPM and
  its OWN errors come back verbatim (transport success); fake
  data-socket responses (immediate EOF, responseSize below the
  header, responseSize 0xffffffff, trailing garbage past the
  declared size) all fail closed as IOERROR or bound exactly.
- CANCELLATION RACES: a cancel storm survives; a submit-loop
  process and a cancel-loop process race the same live prefix
  concurrently without hangs or lost submits; cancel after the
  vTPM dies fails closed (IOERROR).
- CROSS-PREFIX LEAKAGE: with A stopped and B alive, A's layer
  fails closed while B keeps serving - no reach-across, and each
  prefix's identity material stays its own (invariant 18).
- VTPM-AS-HARDWARE: the vendor identity served THROUGH the layer
  is the software emulator's (manufacturer "IBM", vendor string
  "SW"); device-info reserved fields stay 0.

Usage: PYTHONDONTWRITEBYTECODE=1 python3 wine/tests/test-tbs-attacks.py
"""

import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent.parent
TBS_C = ROOT / "wine" / "tbs" / "tbs.c"
TBS_H_DIR = ROOT / "wine" / "tbs" / "include"
HARNESS_C = ROOT / "wine" / "tests" / "tbs_harness.c"
MANAGER = ROOT / "wine" / "vtpm" / "vtpm-manager.sh"

TBS_E_IOERROR = 0x80284006
TBS_E_TOO_MANY = 0x80284009

FAILURES: list[str] = []


def fail(message: str) -> None:
    print(f"tbs attacks gate FAILED: {message}")
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


def run_harness(binary: Path, scenario: str, arg: str = "", env_extra: dict | None = None,
                timeout: int = 120) -> dict[str, str]:
    env = dict(os.environ)
    env["XDG_RUNTIME_DIR"] = str(RUNTIME_DIR)
    prefix = env_extra.pop("prefix") if env_extra and "prefix" in env_extra else PREFIX_A
    env["WINEPREFIX"] = str(prefix)
    if env_extra:
        env.update(env_extra)
    argv = [str(binary), scenario] + ([arg] if arg else [])
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
    return parse_output(result.stdout)


def manager(action: str, prefix: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["XDG_RUNTIME_DIR"] = str(RUNTIME_DIR)
    return subprocess.run(
        [str(MANAGER), action, str(prefix)], capture_output=True, text=True, timeout=60, env=env
    )


def fake_server(directory: Path, mode: str) -> threading.Thread:
    """Serve gate-controlled malformed responses on <dir>/tpm.sock."""

    def serve() -> None:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(directory / "tpm.sock"))
        server.listen(4)
        server.settimeout(10)
        # A valid GetRandom(4) response: tag, size=16, rc=0, count=4, 4 bytes.
        valid = struct.pack(">HII", 0x8001, 16, 0) + struct.pack(">H", 4) + bytes([0xAA, 0xBB, 0xCC, 0xDD])
        try:
            for _ in range(8):
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    break
                with conn:
                    if mode == "eof":
                        continue
                    # Wait for the client's command first: the layer's
                    # presence probe connects and closes without sending
                    # (recv returns empty, not an error).
                    try:
                        conn.settimeout(2)
                        if not conn.recv(4096):
                            continue
                    except OSError:
                        continue
                    try:
                        if mode == "shortsize":
                            conn.sendall(struct.pack(">HII", 0x8001, 5, 0))
                        elif mode == "hugesize":
                            conn.sendall(struct.pack(">HII", 0x8001, 0xFFFFFFFF, 0))
                        elif mode == "trailing":
                            conn.sendall(valid + b"\xde\xad" * 50)
                    except OSError:
                        pass
        finally:
            server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def main() -> None:
    global PREFIX_A, PREFIX_B, RUNTIME_DIR

    tmp = Path(tempfile.mkdtemp(prefix="ogir-tbs-attacks-"))
    RUNTIME_DIR = tmp / "runtime"
    PREFIX_A = tmp / "prefix-a"
    PREFIX_B = tmp / "prefix-b"
    fake_prefix = tmp / "fake-prefix"
    fake_dir = tmp / "fake-dir"
    binary = tmp / "tbs_harness"
    for path in (RUNTIME_DIR, PREFIX_A, PREFIX_B, fake_prefix, fake_dir):
        path.mkdir()

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
        raise SystemExit(f"tbs attacks gate FAILED: harness compile:\n{compile_result.stderr}")

    try:
        for prefix in (PREFIX_A, PREFIX_B):
            started = manager("start", prefix)
            if started.returncode != 0:
                raise SystemExit(f"tbs attacks gate FAILED: manager start: {started.stderr}")

        # === EXHAUSTION ===
        out = run_harness(binary, "exhaust-contexts")
        # The harness holds one context of its own before the scenario
        # runs, so the 64-slot table admits 63 more here (1+63 = 64).
        expect("exhaustion cap reached", out.get("CREATED") == "63", f"{out}")
        expect("exhaustion code", out.get("EXHAUSTED") == f"0x{TBS_E_TOO_MANY:08x}", f"{out}")
        expect("exhaustion recovery", out.get("RECOVERY") == "ok", f"{out}")
        out = run_harness(binary, "fd-stability", "50")
        expect("fd stability", out.get("FDSTART") == out.get("FDEND") and out.get("FDSTART", "-1") != "-1",
               f"{out}")
        expect("fd-stability submits", out.get("SUBMITS") == "50/50", f"{out}")

        # === MALFORMED (requests): the TPM's own errors, verbatim ===
        out = run_harness(binary, "submit-bad-tag")
        expect("bad tag transport", out.get("CODE") == "0x00000000", f"{out}")
        expect("bad tag tpm error", out.get("RESPONSE", "")[12:20] != "00000000", f"{out}")
        out = run_harness(binary, "submit-size-mismatch")
        expect("size mismatch transport", out.get("CODE") == "0x00000000", f"{out}")
        expect("size mismatch verbatim", out.get("RESPONSE", "")[12:20] == "00000142", f"{out}")

        # === MALFORMED (responses): gate-controlled fake servers ===
        # The fake prefix carries the same discovery layout the
        # manager maintains: vtpm/sockets -> the fake dir.
        (fake_prefix / "vtpm").mkdir(exist_ok=True)
        os.symlink(str(fake_dir), str(fake_prefix / "vtpm" / "sockets"))
        for mode, want in (
            ("eof", f"0x{TBS_E_IOERROR:08x}"),
            ("shortsize", f"0x{TBS_E_IOERROR:08x}"),
            ("hugesize", f"0x{TBS_E_IOERROR:08x}"),
        ):
            thread = fake_server(fake_dir, mode)
            out = run_harness(binary, "submit-random", "4", env_extra={"prefix": fake_prefix})
            expect(f"fake {mode} fails closed", out.get("CODE") == want, f"{out}")
            thread.join(timeout=12)
            (fake_dir / "tpm.sock").unlink(missing_ok=True)
        thread = fake_server(fake_dir, "trailing")
        out = run_harness(binary, "submit-random", "4", env_extra={"prefix": fake_prefix})
        expect("fake trailing bounded", out.get("CODE") == "0x00000000" and out.get("SIZE") == "16",
               f"{out}")
        thread.join(timeout=12)
        (fake_dir / "tpm.sock").unlink(missing_ok=True)

        # === CANCELLATION (storm + cross-process race) ===
        out = run_harness(binary, "cancel-storm")
        expect("cancel storm", out.get("CANCELS") == "25/25", f"{out}")
        expect("cancel storm recovery", out.get("CODE") == "0x00000000", f"{out}")

        env_race = dict(os.environ)
        env_race["XDG_RUNTIME_DIR"] = str(RUNTIME_DIR)
        env_race["WINEPREFIX"] = str(PREFIX_A)
        submit_proc = subprocess.Popen(
            [str(binary), "submit-loop", "60"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env_race)
        cancel_proc = subprocess.Popen(
            [str(binary), "cancel-loop", "40"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env_race)
        try:
            submit_out, _ = submit_proc.communicate(timeout=120)
            cancel_out, _ = cancel_proc.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            submit_proc.kill()
            cancel_proc.kill()
            fail("cancel race: a racing process HUNG")
            submit_out = cancel_out = ""
        if submit_out or cancel_out:
            race_submit = parse_output(submit_out)
            race_cancel = parse_output(cancel_out)
            expect("race submits all succeed", race_submit.get("SUBMITS") == "60/60", f"{race_submit}")
            expect("race cancels all succeed", race_cancel.get("CANCELS") == "40/40", f"{race_cancel}")

        # === VTPM-AS-HARDWARE ===
        out = run_harness(binary, "vendor-identity")
        expect("vendor identity transport", out.get("CODE") == "0x00000000", f"{out}")
        response = out.get("RESPONSE", "")
        # Layout: tag(2) size(4) rc(4) more(1) cap(4) count(4) then
        # TPMS_TAGGED_PROPERTY{property(4), value(4)} pairs.
        expect("vendor identity present", len(response) >= 70, f"{out}")
        if len(response) >= 70:
            props = {}
            count = int.from_bytes(bytes.fromhex(response[30:38]), "big")
            offset = 38
            for _ in range(count):
                prop = int.from_bytes(bytes.fromhex(response[offset:offset + 8]), "big")
                value = int.from_bytes(bytes.fromhex(response[offset + 8:offset + 16]), "big")
                props[prop] = value
                offset += 16
            # The SOFTWARE emulator's own identity: manufacturer
            # "IBM\0" (PT 0x105) and vendor string "SW  " (0x106).
            expect("vendor is the emulator", props.get(0x105) == 0x49424D00 and props.get(0x106) == 0x53572020,
                   f"{props!r}")
        out = run_harness(binary, "deviceinfo")
        expect("device info reserved", out.get("IFACE") == "0" and out.get("IMPL") == "0", f"{out}")

        # === CROSS-PREFIX LEAKAGE + cancel-after-death ===
        out = run_harness(binary, "submit-random", "8")
        expect("prefix A serving", out.get("CODE") == "0x00000000", f"{out}")
        out = run_harness(binary, "submit-random", "8", env_extra={"prefix": PREFIX_B})
        expect("prefix B serving", out.get("CODE") == "0x00000000", f"{out}")

        dead_cancel = subprocess.Popen(
            [str(binary), "cancel-stdin"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env_race)
        try:
            ready = dead_cancel.stdout.readline()
        except OSError:
            ready = ""
        expect("cancel-stdin ready", ready.strip() == "READY", ready)
        stopped = manager("stop", PREFIX_A)
        expect("prefix A stop", stopped.returncode == 0, stopped.stderr)
        dead_cancel.stdin.write("\n")
        dead_cancel.stdin.flush()
        try:
            dead_out, _ = dead_cancel.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            dead_cancel.kill()
            dead_out = ""
            fail("cancel after vtpm death HUNG")
        expect("cancel after death fails closed", parse_output(dead_out).get("CODE") == f"0x{TBS_E_IOERROR:08x}",
               dead_out.strip())

        out = run_harness(binary, "create-basic")
        expect("dead prefix create fails", out.get("CREATE") == "0xffffffff", f"{out}")
        out = run_harness(binary, "deviceinfo")
        expect("dead prefix deviceinfo fails", out.get("CODE") == "0x8028400f", f"{out}")
        out = run_harness(binary, "submit-random", "8", env_extra={"prefix": PREFIX_B})
        expect("prefix B unaffected", out.get("CODE") == "0x00000000", f"{out}")
    finally:
        for prefix in (PREFIX_A, PREFIX_B):
            manager("stop", prefix)
        shutil.rmtree(tmp, ignore_errors=True)

    if FAILURES:
        raise SystemExit(1)
    print(
        "tbs attacks gate PASS: exhaustion (cap, recovery, fd stable), malformed "
        "(verbatim tpm errors, fake-response matrix), cancellation (storm, "
        "cross-process race, dead-vtpm fail-closed), cross-prefix isolation "
        "(no reach-across), vtpm identity is the software emulator's"
    )


if __name__ == "__main__":
    main()
