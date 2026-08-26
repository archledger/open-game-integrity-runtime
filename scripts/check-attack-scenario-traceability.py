#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Validate single-document JSON attack scenarios without third-party packages."""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path
from typing import NoReturn

TRACE_FIELDS = ("owner", "required_assurance_profile")
SUPPORTED_SCHEMA_KEYS = {
    "$id",
    "$schema",
    "additionalProperties",
    "items",
    "maxLength",
    "minItems",
    "minLength",
    "pattern",
    "properties",
    "required",
    "title",
    "type",
}
SUPPORTED_TYPES = {"array", "boolean", "object", "string"}


class ScenarioValidationError(ValueError):
    """A schema or scenario violated the supported contract."""


class DuplicateKeyError(ScenarioValidationError):
    """One JSON object repeated a key."""


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def parse_json_document(text: str, source: str) -> object:
    try:
        return json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise ScenarioValidationError(
            f"{source}:{error.lineno}:{error.colno}: {error.msg}"
        ) from error
    except DuplicateKeyError as error:
        raise ScenarioValidationError(f"{source}: {error}") from error


def read_json_document(path: Path) -> object:
    try:
        return parse_json_document(path.read_text(encoding="utf-8"), str(path))
    except OSError as error:
        raise ScenarioValidationError(f"cannot read {path}: {error}") from error


def fail(message: str) -> NoReturn:
    raise ScenarioValidationError(message)


def validate_schema_shape(schema: object, path: str = "schema") -> None:
    if not isinstance(schema, dict):
        fail(f"{path}: schema node must be an object")

    unknown = set(schema).difference(SUPPORTED_SCHEMA_KEYS)
    if unknown:
        fail(f"{path}: unsupported schema keyword(s): {', '.join(sorted(unknown))}")

    value_type = schema.get("type")
    if value_type is not None and (
        not isinstance(value_type, str) or value_type not in SUPPORTED_TYPES
    ):
        fail(f"{path}: unsupported type {value_type!r}")

    for metadata in ("$id", "$schema", "title"):
        value = schema.get(metadata)
        if value is not None and not isinstance(value, str):
            fail(f"{path}: {metadata} must be a string")

    pattern = schema.get("pattern")
    if pattern is not None:
        if not isinstance(pattern, str):
            fail(f"{path}: pattern must be a string")
        try:
            re.compile(pattern)
        except re.error as error:
            raise ScenarioValidationError(f"{path}: invalid pattern") from error

    for bound in ("maxLength", "minItems", "minLength"):
        value = schema.get(bound)
        if value is not None and (
            not isinstance(value, int) or isinstance(value, bool) or value < 0
        ):
            fail(f"{path}: {bound} must be a nonnegative integer")

    required = schema.get("required")
    if required is not None:
        if not isinstance(required, list) or not all(
            isinstance(item, str) for item in required
        ):
            fail(f"{path}: required must be a string array")
        if len(set(required)) != len(required):
            fail(f"{path}: required contains a duplicate field")

    additional = schema.get("additionalProperties")
    if additional is not None and not isinstance(additional, bool):
        fail(f"{path}: additionalProperties must be boolean")

    properties = schema.get("properties")
    if properties is not None:
        if not isinstance(properties, dict):
            fail(f"{path}: properties must be an object")
        for name, child in properties.items():
            validate_schema_shape(child, f"{path}.properties.{name}")

    items = schema.get("items")
    if items is not None:
        validate_schema_shape(items, f"{path}.items")


def validate_schema_contract(schema: object) -> dict[str, object]:
    validate_schema_shape(schema)
    if not isinstance(schema, dict):
        fail("scenario schema root must be an object")
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        fail("scenario schema root must be a closed object")

    required = schema.get("required")
    properties = schema.get("properties")
    if not isinstance(required, list) or not isinstance(properties, dict):
        fail("scenario schema must define required and properties")

    for field in TRACE_FIELDS:
        if field not in required:
            fail(f"scenario schema does not require {field}")
        field_schema = properties.get(field)
        if not isinstance(field_schema, dict) or field_schema.get("type") != "string":
            fail(f"scenario schema does not define string field {field}")
        pattern = field_schema.get("pattern")
        if not isinstance(pattern, str):
            fail(f"scenario schema does not constrain {field}")
        compiled = re.compile(pattern)
        if compiled.search("initial-maintainer") is None or compiled.search("Invalid Value"):
            fail(f"scenario schema has ineffective {field} pattern")

    return schema


def type_matches(value: object, expected: str) -> bool:
    return {
        "array": isinstance(value, list),
        "boolean": isinstance(value, bool),
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
    }[expected]


def validate_instance(value: object, schema: dict[str, object], path: str = "scenario") -> None:
    expected_type = schema.get("type")
    if isinstance(expected_type, str) and not type_matches(value, expected_type):
        fail(f"{path}: expected {expected_type}")

    if isinstance(value, dict):
        required = schema.get("required", [])
        properties = schema.get("properties", {})
        if not isinstance(required, list) or not isinstance(properties, dict):
            fail(f"{path}: invalid object schema")
        for field in required:
            if field not in value:
                fail(f"{path}: missing required field {field}")
        if schema.get("additionalProperties") is False:
            unknown = set(value).difference(properties)
            if unknown:
                fail(f"{path}: unknown field(s): {', '.join(sorted(unknown))}")
        for field, child_schema in properties.items():
            if field in value:
                if not isinstance(child_schema, dict):
                    fail(f"{path}.{field}: invalid property schema")
                validate_instance(value[field], child_schema, f"{path}.{field}")

    if isinstance(value, list):
        minimum = schema.get("minItems")
        if isinstance(minimum, int) and len(value) < minimum:
            fail(f"{path}: requires at least {minimum} item(s)")
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(value):
                validate_instance(item, items, f"{path}[{index}]")

    if isinstance(value, str):
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        pattern = schema.get("pattern")
        if isinstance(minimum, int) and len(value) < minimum:
            fail(f"{path}: shorter than {minimum} character(s)")
        if isinstance(maximum, int) and len(value) > maximum:
            fail(f"{path}: longer than {maximum} character(s)")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            fail(f"{path}: does not match required pattern")


def expect_failure(name: str, operation: object) -> None:
    try:
        if callable(operation):
            operation()
        else:
            fail("self-test operation is not callable")
    except ScenarioValidationError:
        print(f"PASS: {name}")
    else:
        raise AssertionError(f"invalid fixture passed: {name}")


def valid_scenario() -> dict[str, object]:
    return {
        "id": "OGIR-TEST-001",
        "title": "Traceability fixture",
        "attacker": "A1",
        "owner": "initial-maintainer",
        "required_assurance_profile": "all-protected-modes",
        "assets": ["protected_session_authorization"],
        "preconditions": [],
        "steps": ["attempt replay"],
        "expected": {
            "decision": "deny",
            "reason": "replay-detected",
            "automatic_ban": False,
        },
        "invariants": ["replay fails"],
        "residual_risk": [],
    }


def run_self_tests(schema: dict[str, object]) -> None:
    fixture = valid_scenario()
    validate_instance(fixture, schema, "valid")

    for field in TRACE_FIELDS:
        missing = copy.deepcopy(fixture)
        del missing[field]
        expect_failure(
            f"missing {field.replace('_', ' ')}",
            lambda missing=missing: validate_instance(missing, schema, "missing"),
        )

        malformed = copy.deepcopy(fixture)
        malformed[field] = "Invalid Value"
        expect_failure(
            f"invalid {field.replace('_', ' ')}",
            lambda malformed=malformed: validate_instance(malformed, schema, "invalid"),
        )

        broken_schema = copy.deepcopy(schema)
        required = broken_schema.get("required")
        if not isinstance(required, list):
            raise AssertionError("valid schema lost required array")
        required.remove(field)
        expect_failure(
            f"schema omits {field.replace('_', ' ')}",
            lambda broken_schema=broken_schema: validate_schema_contract(broken_schema),
        )

    duplicate = (
        '{"owner":"initial-maintainer","owner":"verifier-team",'
        '"required_assurance_profile":"all-protected-modes"}'
    )
    expect_failure(
        "quoted duplicate owner",
        lambda: parse_json_document(duplicate, "quoted-duplicate"),
    )

    multiple_documents = json.dumps(fixture) + "\n---\n" + json.dumps(fixture)
    expect_failure(
        "multiple scenario documents",
        lambda: parse_json_document(multiple_documents, "multiple-documents"),
    )

    unknown = copy.deepcopy(fixture)
    unknown["unreviewed"] = True
    expect_failure(
        "unknown scenario field",
        lambda: validate_instance(unknown, schema, "unknown"),
    )

    print("All attack-scenario validation tests passed.")


def load_repository_contract() -> tuple[Path, dict[str, object], list[Path]]:
    repository = Path(__file__).resolve().parent.parent
    scenario_directory = repository / "lab" / "scenarios"
    schema_path = scenario_directory / "schema.json"
    if schema_path.is_symlink() or not schema_path.is_file():
        fail("attack-scenario schema must be a regular file")
    schema = validate_schema_contract(read_json_document(schema_path))
    scenarios: list[Path] = []
    try:
        entries = sorted(scenario_directory.iterdir())
    except OSError as error:
        raise ScenarioValidationError(
            f"cannot list attack-scenario directory: {error}"
        ) from error
    for entry in entries:
        if entry == schema_path:
            continue
        if entry.is_symlink() or not entry.is_file() or not entry.name.endswith(
            ".scenario.json"
        ):
            fail(f"unexpected attack-scenario path: {entry.relative_to(repository)}")
        scenarios.append(entry)
    if not scenarios:
        fail("no attack scenarios found")
    return repository, schema, scenarios


def main() -> int:
    if sys.argv[1:] not in ([], ["--self-test"]):
        print("usage: check-attack-scenario-traceability.py [--self-test]", file=sys.stderr)
        return 2

    try:
        repository, schema, scenarios = load_repository_contract()
        if sys.argv[1:] == ["--self-test"]:
            run_self_tests(schema)
            return 0
        for scenario in scenarios:
            instance = read_json_document(scenario)
            validate_instance(instance, schema, str(scenario.relative_to(repository)))
    except ScenarioValidationError as error:
        print(f"attack-scenario validation failed: {error}", file=sys.stderr)
        return 1

    print(f"Attack-scenario validation passed for {len(scenarios)} scenario(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
