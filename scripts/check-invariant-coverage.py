#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed invariant-to-scenario coverage check (M9-047).

The M9 exit criterion "every security invariant maps to at least
one executable scenario" made mechanical: every numbered invariant
in docs/SECURITY_INVARIANTS.md must appear in the `invariants`
array of at least one lab/scenarios/*.scenario.json. Unmapped
invariants fail the gate; the mapping is the dashboard's spine.

Usage: PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-invariant-coverage.py
"""

import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
INVARIANTS = ROOT / "docs" / "SECURITY_INVARIANTS.md"
SCENARIOS = ROOT / "lab" / "scenarios"

FAILURES: list[str] = []


def fail(message: str) -> None:
    print(f"invariant coverage FAILED: {message}")
    FAILURES.append(message)


def main() -> None:
    text = INVARIANTS.read_text(encoding="utf-8")
    numbered = {}
    for match in re.finditer(r"^(\d+)\.\s", text, re.MULTILINE):
        number = int(match.group(1))
        line = text[match.start():text.find("\n", match.start())]
        numbered[number] = line[: (line.find(". ") + 2)] + "..."
    if not numbered:
        fail("no numbered invariants found")
        return

    covered: dict[int, list[str]] = {}
    scenario_files = sorted(SCENARIOS.glob("*.scenario.json"))
    if not scenario_files:
        fail("no scenario files")
        return
    for path in scenario_files:
        try:
            scenario = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            fail(f"{path.name}: unparseable ({error})")
            continue
        for entry in scenario.get("invariants", []):
            for match in re.finditer(r"\b(\d+)\b", str(entry)):
                number = int(match.group(1))
                if number in numbered:
                    covered.setdefault(number, []).append(scenario["id"])

    uncovered = [number for number in sorted(numbered) if number not in covered]
    if uncovered:
        for number in uncovered:
            fail(f"invariant {number} ({numbered[number][:60]}) has no scenario")

    if FAILURES:
        raise SystemExit(1)
    print(
        f"invariant coverage PASS: {len(numbered)} invariants, "
        f"{len(covered)} mapped, {len(scenario_files)} scenarios"
    )


if __name__ == "__main__":
    main()
