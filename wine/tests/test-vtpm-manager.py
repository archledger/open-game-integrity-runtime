#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fail-closed checks over the per-prefix vTPM manager (M10-048).

Covers the M10 attack-test families the manager itself owns:
- PHYSICAL ISOLATION: the manager never references the host TPM
  (no /dev/tpm* path, no tpm2_* device commands - only swtpm).
- PREFIX ISOLATION: two prefixes get DIFFERENT state dirs and
  DIFFERENT sockets; one prefix's state file is never inside the
  other's tree.
- RESET: reset wipes the state and restarts (a fresh permall).
- CLEANUP: stop removes the socket and pid.
- EXHAUSTION/malformed/cancel: delegated to the TBS layer's tests
  (the manager surface has no command path).

Usage: PYTHONDONTWRITEBYTECODE=1 python3 wine/tests/test-vtpm-manager.py
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent.parent
MANAGER = ROOT / "wine" / "vtpm" / "vtpm-manager.sh"

FAILURES: list[str] = []


def fail(message: str) -> None:
    print(f"vtpm manager gate FAILED: {message}")
    FAILURES.append(message)


def run(prefix: Path, action: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(MANAGER), action, str(prefix)], capture_output=True, text=True, timeout=30
    )


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="ogir-vtpm-test-"))
    runtime_dir = tmp / "runtime"
    runtime_dir.mkdir()
    # The test OWNS the runtime root for its children: the env
    # value never feeds a path the test builds (it replaces it).
    os.environ["XDG_RUNTIME_DIR"] = str(runtime_dir)
    try:
        one = tmp / "prefix-one"
        two = tmp / "prefix-two"
        one.mkdir()
        two.mkdir()

        # --- Physical isolation (mechanical): no host TPM path.
        script = MANAGER.read_text(encoding="utf-8")
        for forbidden in ["/dev/tpm", "tpm2_", "/dev/tpmrm"]:
            if forbidden in script:
                fail(f"the manager must never reference the host TPM ({forbidden})")

        # --- Prefix isolation: different state, different sockets.
        for prefix in (one, two):
            result = run(prefix, "start")
            if result.returncode != 0:
                fail(f"start failed for {prefix.name}: {result.stderr}")
        # The expected socket paths, computed exactly as the
        # manager computes them (hash of the prefix path): no env
        # value feeds a glob root.
        import hashlib

        def socket_path(prefix: Path) -> Path:
            digest = hashlib.sha256(str(prefix.resolve()).encode()).hexdigest()[:16]
            return Path("ogir-vtpm") / digest / "swtpm.sock"

        runtime = runtime_dir
        one_socket = runtime / socket_path(one)
        two_socket = runtime / socket_path(two)
        if not one_socket.exists() or not two_socket.exists():
            fail(f"both per-prefix sockets must exist: {one_socket}, {two_socket}")
        if one_socket == two_socket:
            fail("two prefixes must have two distinct sockets")
        state_one = one / "vtpm" / "tpm2-00.permall"
        state_two = two / "vtpm" / "tpm2-00.permall"
        if not (state_one.exists() and state_two.exists()):
            fail("both prefixes must own per-prefix state")
        if state_one.read_bytes() == state_two.read_bytes():
            # The permall blobs may legitimately share the initial
            # EK template bytes; the ISOLATION claim is about the
            # PATHS, asserted above. Do not over-claim here.
            pass

        # --- Cross-prefix access: the other prefix's state is
        #     outside this prefix's tree (the structural guard).
        if (one / "vtpm").resolve() == (two / "vtpm").resolve():
            fail("prefix state dirs must differ")

        # --- Reset wipes and restarts.
        marker_before = state_one.stat().st_mtime_ns if state_one.exists() else 0
        time.sleep(0.05)
        result = run(one, "reset")
        if result.returncode != 0:
            fail(f"reset failed: {result.stderr}")
        if run(one, "status").stdout.strip() != "running":
            fail("reset must restart the vtpm")
        if not state_one.exists():
            fail("reset must produce fresh state")
        marker_after = state_one.stat().st_mtime_ns
        if marker_after == marker_before:
            fail("reset must WIPE the state (mtime unchanged)")

        # --- Cleanup.
        for prefix in (one, two):
            run(prefix, "stop")
        if run(one, "status").stdout.strip() != "stopped":
            fail("stop must stop")
        if one_socket.exists() or two_socket.exists():
            fail("stop must remove both per-prefix sockets")
    finally:
        for prefix in (tmp / "prefix-one", tmp / "prefix-two"):
            run(prefix, "stop")
        shutil.rmtree(tmp, ignore_errors=True)

    if FAILURES:
        raise SystemExit(1)
    print(
        "vtpm manager gate PASS: physical isolation (no host TPM path), "
        "per-prefix state and sockets, reset wipes, cleanup removes"
    )


if __name__ == "__main__":
    main()
