#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The M9 security dashboard: test status, not marketing scores.

Prints one line per security invariant: the invariant, the mapped
scenario count, and the executable leg's status (pass when the
mapping exists and the suite is part of the release gate). No
scores, no colors, no severity arithmetic - status only.

Usage: PYTHONDONTWRITEBYTECODE=1 python3 scripts/security-dashboard.py
"""

import json
import re
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
INVARIANTS = ROOT / "docs" / "SECURITY_INVARIANTS.md"
SCENARIOS = ROOT / "lab" / "scenarios"


def main() -> None:
    text = INVARIANTS.read_text(encoding="utf-8")
    invariants = []
    for match in re.finditer(r"^(\d+)\.\s(.+)$", text, re.MULTILINE):
        invariants.append((int(match.group(1)), match.group(2)[:72]))

    mapped: dict[int, int] = {}
    for path in sorted(SCENARIOS.glob("*.scenario.json")):
        scenario = json.loads(path.read_text(encoding="utf-8"))
        for entry in scenario.get("invariants", []):
            for number in re.findall(r"\b(\d+)\b", str(entry)):
                number = int(number)
                if number <= len(invariants):
                    mapped[number] = mapped.get(number, 0) + 1

    # The release-gate status: the suite wiring is green when the
    # coverage gate passes (which the CI invocation proves).
    coverage = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check-invariant-coverage.py")],
        capture_output=True,
        text=True,
    )
    gate = "pass" if coverage.returncode == 0 else "fail"

    print(f"OGIR security dashboard (gate: {gate})")
    print(f"{'inv':>3}  {'scenarios':>9}  status  invariant")
    for number, summary in invariants:
        count = mapped.get(number, 0)
        status = "pass" if count > 0 and gate == "pass" else "fail"
        print(f"{number:>3}  {count:>9}  {status}  {summary}")


if __name__ == "__main__":
    main()
