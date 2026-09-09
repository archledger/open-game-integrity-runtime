#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""The M10 wine-gate suite in one fail-closed command (M10-052).

Runs every wine/ gate in order - the manager gate, the TBS
functional gate, the attack-family gate, and the WoW64 ABI gate -
plus the REPO-WIDE physical-isolation sweep (no wine/ source may
reference a host TPM path or tool). Each gate must PASS; the
first failure fails the suite. This is the reproducible entry
point the M10 exit audit (ADR-0048) executed its evidence with.

Requires the dev-host toolchain the individual gates document
(swtpm, wine, the mingw cross-compilers); CI runs the Rust and
registry gates instead.

Usage: PYTHONDONTWRITEBYTECODE=1 python3 wine/tests/run-all-gates.py
"""

import os
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent.parent
WINE = ROOT / "wine"

# The isolation sweep: NO wine/ source references the host TPM.
# (swtpm is the ONLY TPM-adjacent tool wine/ may name.)
FORBIDDEN_MARKERS = ("/dev/tpm", "/dev/tpmrm", "tpm2_")


def sweep_isolation() -> list[str]:
    problems: list[str] = []
    for path in sorted(WINE.rglob("*")):
        if not path.is_file() or path.suffix in {".md", ".spec"} or path.name.endswith(".json"):
            continue
        # The gate files themselves are excluded: they legitimately
        # carry the forbidden markers as the patterns they grep for.
        if path.parent.name == "tests":
            continue
        blob = path.read_text(encoding="utf-8", errors="replace")
        for marker in FORBIDDEN_MARKERS:
            if marker in blob:
                problems.append(f"{path.relative_to(ROOT)} references {marker!r}")
    return problems


def main() -> None:
    problems = sweep_isolation()
    if problems:
        for problem in problems:
            print(f"isolation sweep FAILED: {problem}")
        raise SystemExit(1)
    print("isolation sweep PASS: no wine/ source references the host TPM")

    gates = [
        WINE / "tests" / "test-vtpm-manager.py",
        WINE / "tests" / "test-tbs.py",
        WINE / "tests" / "test-tbs-attacks.py",
        WINE / "tests" / "test-tbs-wow64.py",
    ]
    env = dict(os.environ)
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    for gate in gates:
        result = subprocess.run(
            [sys.executable, str(gate)], capture_output=True, text=True, timeout=900, env=env
        )
        tail = (result.stdout or result.stderr).strip().splitlines()
        print(f"{gate.name}: {tail[-1] if tail else '(no output)'}")
        if result.returncode != 0:
            raise SystemExit(f"gate FAILED: {gate.name}")
    print("wine gate suite PASS: isolation sweep + manager + functional + attacks + wow64")


if __name__ == "__main__":
    main()
