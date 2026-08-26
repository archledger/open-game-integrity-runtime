#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Enforce owner and assurance-profile mappings on attack scenarios."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

TRACE_FIELDS = ("owner", "required_assurance_profile")
KEBAB_CASE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
TOP_LEVEL_FIELD = re.compile(r"^([a-z_][a-z0-9_]*):(?:[ \t]*(.*))?$")


def validate_schema_contract(schema: object) -> None:
    if not isinstance(schema, dict):
        raise ValueError("scenario schema root must be an object")

    required = schema.get("required")
    properties = schema.get("properties")
    if not isinstance(required, list) or not isinstance(properties, dict):
        raise ValueError("scenario schema must define required and properties")

    for field in TRACE_FIELDS:
        if field not in required:
            raise ValueError(f"scenario schema does not require {field}")
        field_schema = properties.get(field)
        if not isinstance(field_schema, dict) or field_schema.get("type") != "string":
            raise ValueError(f"scenario schema does not define string field {field}")
        pattern = field_schema.get("pattern")
        if not isinstance(pattern, str):
            raise ValueError(f"scenario schema does not constrain {field}")
        try:
            compiled = re.compile(pattern)
        except re.error as error:
            raise ValueError(f"scenario schema has invalid {field} pattern") from error
        if compiled.fullmatch("initial-maintainer") is None or compiled.fullmatch(
            "Invalid Value"
        ) is not None:
            raise ValueError(f"scenario schema has ineffective {field} pattern")


def validate_scenario_traceability(text: str, source: str) -> None:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line or raw_line[0].isspace() or raw_line.startswith("#"):
            continue
        match = TOP_LEVEL_FIELD.fullmatch(raw_line)
        if match is None:
            continue
        field, value = match.groups()
        if field not in TRACE_FIELDS:
            continue
        if field in values:
            raise ValueError(f"{source}:{line_number}: duplicate {field}")
        if value is None or KEBAB_CASE.fullmatch(value) is None:
            raise ValueError(f"{source}:{line_number}: invalid {field}")
        values[field] = value

    for field in TRACE_FIELDS:
        if field not in values:
            raise ValueError(f"{source}: missing {field}")


def run_self_tests() -> None:
    field_schema = {
        "type": "string",
        "pattern": r"^[a-z0-9]+(?:-[a-z0-9]+)*$",
    }
    valid_schema = {
        "required": list(TRACE_FIELDS),
        "properties": {field: dict(field_schema) for field in TRACE_FIELDS},
    }
    validate_schema_contract(valid_schema)

    valid_scenario = (
        "id: fixture\n"
        "owner: initial-maintainer\n"
        "required_assurance_profile: all-protected-modes\n"
    )
    validate_scenario_traceability(valid_scenario, "valid")

    invalid_cases = {
        "missing owner": "required_assurance_profile: all-protected-modes\n",
        "missing assurance profile": "owner: initial-maintainer\n",
        "invalid owner": (
            "owner: Initial Maintainer\n"
            "required_assurance_profile: all-protected-modes\n"
        ),
        "invalid assurance profile": (
            "owner: initial-maintainer\n"
            "required_assurance_profile: ALL\n"
        ),
        "duplicate owner": (
            "owner: initial-maintainer\n"
            "owner: verifier-team\n"
            "required_assurance_profile: all-protected-modes\n"
        ),
    }
    for name, scenario in invalid_cases.items():
        try:
            validate_scenario_traceability(scenario, name)
        except ValueError:
            print(f"PASS: {name}")
        else:
            raise AssertionError(f"invalid fixture passed: {name}")

    for omitted in TRACE_FIELDS:
        broken_schema = dict(valid_schema)
        broken_schema["required"] = [field for field in TRACE_FIELDS if field != omitted]
        try:
            validate_schema_contract(broken_schema)
        except ValueError:
            print(f"PASS: schema omits {omitted.replace('_', ' ')}")
        else:
            raise AssertionError(f"schema missing {omitted} requirement passed")

    print("All attack-scenario traceability tests passed.")


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        run_self_tests()
        return 0
    if sys.argv[1:]:
        print("usage: check-attack-scenario-traceability.py [--self-test]", file=sys.stderr)
        return 2

    repository = Path(__file__).resolve().parent.parent
    schema_path = repository / "lab" / "scenarios" / "schema.json"
    scenarios = sorted((repository / "lab" / "scenarios").glob("*.yml"))
    try:
        validate_schema_contract(json.loads(schema_path.read_text(encoding="utf-8")))
        if not scenarios:
            raise ValueError("no attack scenarios found")
        for scenario in scenarios:
            validate_scenario_traceability(
                scenario.read_text(encoding="utf-8"),
                str(scenario.relative_to(repository)),
            )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"attack-scenario traceability check failed: {error}", file=sys.stderr)
        return 1

    print(f"Attack-scenario traceability check passed for {len(scenarios)} scenario(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
