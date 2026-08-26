#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Validate single-document JSON attack scenarios without third-party packages."""

from __future__ import annotations

import copy
import json
import math
import re
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

TRACE_FIELDS = ("owner", "required_assurance_profile")
EXPECTED_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
ATTACKER_PATTERN = r"^A[0-8]$"
KEBAB_PATTERN = r"^(?![\s\S]*[^a-z0-9-])[a-z0-9]+(?:-[a-z0-9]+)*$"
SAFE_PATTERN_MATCHERS = {
    ATTACKER_PATTERN: re.compile(ATTACKER_PATTERN),
    KEBAB_PATTERN: re.compile(KEBAB_PATTERN),
}
APPROVED_OWNERS = {"initial-maintainer"}
APPROVED_ASSURANCE_PROFILES = {"all-protected-modes"}
MAX_DOCUMENT_BYTES = 65_536
MAX_NESTING_DEPTH = 16
MAX_OBJECT_FIELDS = 64
MAX_ARRAY_ITEMS = 256
MAX_STRING_CHARACTERS = 4_096
MAX_NUMBER_CHARACTERS = 64
MAX_TOTAL_NODES = 4_096
MAX_SCENARIO_FILES = 128
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
    if len(pairs) > MAX_OBJECT_FIELDS:
        raise ScenarioValidationError(
            f"object exceeds {MAX_OBJECT_FIELDS} fields"
        )
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError("duplicate JSON key")
        value[key] = item
    return value


def reject_non_json_constant(constant: str) -> NoReturn:
    del constant
    raise ScenarioValidationError("non-JSON numeric constant")


def parse_bounded_integer(token: str) -> int:
    if len(token) > MAX_NUMBER_CHARACTERS:
        fail(f"integer exceeds {MAX_NUMBER_CHARACTERS} characters")
    return int(token)


def parse_bounded_float(token: str) -> float:
    if len(token) > MAX_NUMBER_CHARACTERS:
        fail(f"number exceeds {MAX_NUMBER_CHARACTERS} characters")
    value = float(token)
    if not math.isfinite(value):
        fail("number is outside the finite parser range")
    return value


def diagnostic_source(source: str) -> str:
    del source
    return "attack-scenario input"


def validate_resource_limits(value: object) -> None:
    total_nodes = 0

    def visit(node: object, depth: int) -> None:
        nonlocal total_nodes
        total_nodes += 1
        if total_nodes > MAX_TOTAL_NODES:
            fail(f"document exceeds {MAX_TOTAL_NODES} total nodes")
        if depth > MAX_NESTING_DEPTH:
            fail(f"document exceeds nesting depth {MAX_NESTING_DEPTH}")

        if isinstance(node, dict):
            if len(node) > MAX_OBJECT_FIELDS:
                fail(f"object exceeds {MAX_OBJECT_FIELDS} fields")
            for key, item in node.items():
                if len(key) > MAX_STRING_CHARACTERS:
                    fail(f"object key exceeds {MAX_STRING_CHARACTERS} characters")
                visit(item, depth + 1)
        elif isinstance(node, list):
            if len(node) > MAX_ARRAY_ITEMS:
                fail(f"array exceeds {MAX_ARRAY_ITEMS} items")
            for item in node:
                visit(item, depth + 1)
        elif isinstance(node, str) and len(node) > MAX_STRING_CHARACTERS:
            fail(f"string exceeds {MAX_STRING_CHARACTERS} characters")

    visit(value, 0)


def parse_json_document(text: str, source: str) -> object:
    label = diagnostic_source(source)
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ScenarioValidationError(f"{label}: invalid Unicode") from error
    if len(encoded) > MAX_DOCUMENT_BYTES:
        fail(f"{label}: document exceeds {MAX_DOCUMENT_BYTES} bytes")

    try:
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_non_json_constant,
            parse_float=parse_bounded_float,
            parse_int=parse_bounded_integer,
        )
        validate_resource_limits(value)
        return value
    except json.JSONDecodeError as error:
        raise ScenarioValidationError(
            f"{label}:{error.lineno}:{error.colno}: malformed JSON"
        ) from error
    except (RecursionError, ScenarioValidationError) as error:
        raise ScenarioValidationError(f"{label}: {error}") from error
    except (OverflowError, ValueError) as error:
        raise ScenarioValidationError(f"{label}: invalid JSON number") from error


def read_json_document(path: Path, source: str) -> object:
    label = diagnostic_source(source)
    try:
        with path.open("rb") as stream:
            encoded = stream.read(MAX_DOCUMENT_BYTES + 1)
    except OSError as error:
        raise ScenarioValidationError(f"cannot read {label}") from error
    if len(encoded) > MAX_DOCUMENT_BYTES:
        fail(f"{label}: document exceeds {MAX_DOCUMENT_BYTES} bytes")
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ScenarioValidationError(f"{label}: invalid UTF-8") from error
    return parse_json_document(text, label)


def fail(message: str) -> NoReturn:
    raise ScenarioValidationError(message)


def validate_schema_shape(schema: object, path: str = "schema") -> None:
    path = diagnostic_source(path)
    if not isinstance(schema, dict):
        fail(f"{path}: schema node must be an object")

    unknown = set(schema).difference(SUPPORTED_SCHEMA_KEYS)
    if unknown:
        fail(f"{path}: unsupported schema keyword")

    value_type = schema.get("type")
    if value_type is not None and (
        not isinstance(value_type, str) or value_type not in SUPPORTED_TYPES
    ):
        fail(f"{path}: unsupported type")

    for metadata in ("$id", "$schema", "title"):
        value = schema.get(metadata)
        if value is not None and not isinstance(value, str):
            fail(f"{path}: {metadata} must be a string")

    pattern = schema.get("pattern")
    if pattern is not None:
        if not isinstance(pattern, str):
            fail(f"{path}: pattern must be a string")
        if pattern not in SAFE_PATTERN_MATCHERS:
            fail(f"{path}: schema pattern is not approved")

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
        for index, child in enumerate(properties.values()):
            validate_schema_shape(child, f"{path}.properties[{index}]")

    items = schema.get("items")
    if items is not None:
        validate_schema_shape(items, f"{path}.items")


def validate_schema_contract(schema: object) -> dict[str, object]:
    validate_schema_shape(schema)
    if not isinstance(schema, dict):
        fail("scenario schema root must be an object")
    if schema.get("$schema") != EXPECTED_SCHEMA_DIALECT:
        fail(f"scenario schema must declare {EXPECTED_SCHEMA_DIALECT}")
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
        compiled = SAFE_PATTERN_MATCHERS.get(pattern)
        if compiled is None:
            fail(f"scenario schema has unapproved {field} pattern")
        if (
            compiled.search("initial-maintainer") is None
            or compiled.search("Invalid Value") is not None
            or compiled.search("initial-maintainer\n") is not None
        ):
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
    path = diagnostic_source(path)
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
                fail(f"{path}: missing required field")
        if schema.get("additionalProperties") is False:
            unknown = set(value).difference(properties)
            if unknown:
                fail(f"{path}: unknown field")
        for index, (field, child_schema) in enumerate(properties.items()):
            if field in value:
                if not isinstance(child_schema, dict):
                    fail(f"{path}.property[{index}]: invalid property schema")
                validate_instance(value[field], child_schema, f"{path}.property[{index}]")

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
        if isinstance(pattern, str):
            matcher = SAFE_PATTERN_MATCHERS.get(pattern)
            if matcher is None:
                fail(f"{path}: schema pattern is not approved")
            if matcher.search(value) is None:
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


def expect_redacted_failure(name: str, operation: object) -> None:
    try:
        if callable(operation):
            operation()
        else:
            fail("self-test operation is not callable")
    except ScenarioValidationError as error:
        rendered = str(error)
        forbidden = ("/home/", "\n", "\r", "\x1b", "::error::", "::warning::")
        if any(value in rendered for value in forbidden):
            raise AssertionError(f"unsafe diagnostic data leaked: {name}") from error
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


def validate_scenario_count(count: int) -> None:
    if count == 0:
        fail("no attack scenarios found")
    if count > MAX_SCENARIO_FILES:
        fail(f"more than {MAX_SCENARIO_FILES} attack scenarios")


def validate_scenario_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        fail("attack-scenario directory must be a regular directory")


def validate_regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        fail("attack-scenario input must be a regular file")


def validate_repository_semantics(scenarios: list[object]) -> None:
    identifiers: set[str] = set()
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            fail("attack scenario must be an object")
        identifier = scenario.get("id")
        owner = scenario.get("owner")
        profile = scenario.get("required_assurance_profile")
        if not isinstance(identifier, str) or identifier in identifiers:
            fail("attack-scenario identifier is missing or duplicated")
        if owner not in APPROVED_OWNERS:
            fail("attack-scenario owner is not registered")
        if profile not in APPROVED_ASSURANCE_PROFILES:
            fail("attack-scenario assurance profile is not registered")
        identifiers.add(identifier)


def run_self_tests(schema: dict[str, object]) -> None:
    fixture = valid_scenario()
    validate_instance(fixture, schema, "valid")
    validate_repository_semantics([fixture])
    parse_json_document("{}" + " " * (MAX_DOCUMENT_BYTES - 2), "max-bytes")
    parse_json_document(
        "[" * MAX_NESTING_DEPTH + "0" + "]" * MAX_NESTING_DEPTH,
        "max-depth",
    )
    parse_json_document(
        json.dumps({f"field-{index}": index for index in range(MAX_OBJECT_FIELDS)}),
        "max-fields",
    )
    parse_json_document(json.dumps(list(range(MAX_ARRAY_ITEMS))), "max-items")
    parse_json_document(json.dumps("x" * MAX_STRING_CHARACTERS), "max-string")
    parse_json_document(
        json.dumps({"x" * MAX_STRING_CHARACTERS: True}), "max-key"
    )
    parse_json_document("9" * MAX_NUMBER_CHARACTERS, "max-number")
    parse_json_document(
        "0." + "1" * (MAX_NUMBER_CHARACTERS - 2), "max-float-token"
    )
    validate_scenario_count(MAX_SCENARIO_FILES)
    print("PASS: parser resource boundaries")

    expect_failure("zero scenario files", lambda: validate_scenario_count(0))
    expect_failure(
        "excessive scenario files",
        lambda: validate_scenario_count(MAX_SCENARIO_FILES + 1),
    )

    with tempfile.TemporaryDirectory(prefix="ogir-scenario-self-test-") as directory:
        root = Path(directory)
        regular = root / "regular"
        regular.mkdir()
        linked = root / "linked"
        linked.symlink_to(regular, target_is_directory=True)
        expect_failure(
            "symlinked scenario directory",
            lambda: validate_scenario_directory(linked),
        )
        regular_file = root / "regular-file"
        regular_file.write_text("{}", encoding="utf-8")
        linked_file = root / "linked-file"
        linked_file.symlink_to(regular_file)
        validate_regular_file(regular_file)
        expect_failure(
            "symlinked scenario file",
            lambda: validate_regular_file(linked_file),
        )

    duplicate_identifier = copy.deepcopy(fixture)
    expect_failure(
        "duplicate scenario identifier",
        lambda: validate_repository_semantics([fixture, duplicate_identifier]),
    )
    unregistered_owner = copy.deepcopy(fixture)
    unregistered_owner["owner"] = "unregistered-owner"
    expect_failure(
        "unregistered scenario owner",
        lambda: validate_repository_semantics([unregistered_owner]),
    )
    unregistered_profile = copy.deepcopy(fixture)
    unregistered_profile["required_assurance_profile"] = "unregistered-profile"
    expect_failure(
        "unregistered assurance profile",
        lambda: validate_repository_semantics([unregistered_profile]),
    )

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

        terminal_newline = copy.deepcopy(fixture)
        terminal_newline[field] = f"{fixture[field]}\n"
        expect_failure(
            f"terminal newline in {field.replace('_', ' ')}",
            lambda terminal_newline=terminal_newline: validate_instance(
                terminal_newline, schema, "terminal-newline"
            ),
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

    attacker_newline = copy.deepcopy(fixture)
    attacker_newline["attacker"] = "A1\n"
    expect_failure(
        "terminal newline in attacker",
        lambda: validate_instance(attacker_newline, schema, "attacker-newline"),
    )

    duplicate = (
        '{"owner":"initial-maintainer","owner":"verifier-team",'
        '"required_assurance_profile":"all-protected-modes"}'
    )
    expect_failure(
        "quoted duplicate owner",
        lambda: parse_json_document(duplicate, "quoted-duplicate"),
    )

    for constant in ("NaN", "Infinity", "-Infinity"):
        expect_failure(
            f"non-JSON numeric constant {constant}",
            lambda constant=constant: parse_json_document(
                f'{{"nonfinite":{constant}}}', "nonfinite"
            ),
        )
    expect_failure(
        "non-finite numeric exponent",
        lambda: parse_json_document("1e9999", "nonfinite-exponent"),
    )
    expect_failure(
        "excessive integer token",
        lambda: parse_json_document("9" * (MAX_NUMBER_CHARACTERS + 1), "long-integer"),
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

    nested_unknown = copy.deepcopy(fixture)
    expected = nested_unknown.get("expected")
    if not isinstance(expected, dict):
        raise AssertionError("valid fixture lost expected object")
    expected["unreviewed"] = True
    expect_failure(
        "unknown nested expected field",
        lambda: validate_instance(nested_unknown, schema, "nested-unknown"),
    )

    for dialect in ("http://json-schema.org/draft-07/schema#", "not-a-uri", ""):
        wrong_dialect = copy.deepcopy(schema)
        wrong_dialect["$schema"] = dialect
        expect_failure(
            f"wrong schema dialect {dialect!r}",
            lambda wrong_dialect=wrong_dialect: validate_schema_contract(wrong_dialect),
        )

    unsafe_pattern = copy.deepcopy(schema)
    unsafe_properties = unsafe_pattern.get("properties")
    if not isinstance(unsafe_properties, dict):
        raise AssertionError("valid schema lost properties")
    unsafe_owner = unsafe_properties.get("owner")
    if not isinstance(unsafe_owner, dict):
        raise AssertionError("valid schema lost owner")
    for name, pattern in (
        ("backtracking", r"^(?![\s\S]*[^a-z0-9-])(?:[a-z0-9-]+)+$"),
        ("oversized repetition", "a{999999999999999999999}"),
    ):
        unsafe_owner["pattern"] = pattern
        expect_failure(
            f"non-whitelisted {name} schema pattern",
            lambda: validate_schema_contract(unsafe_pattern),
        )

    expect_failure(
        "oversized document",
        lambda: parse_json_document(
            json.dumps("x" * MAX_DOCUMENT_BYTES), "oversized"
        ),
    )

    expect_failure(
        "excessive nesting",
        lambda: parse_json_document("[" * 17 + "0" + "]" * 17, "deep"),
    )
    expect_failure(
        "excessive object fields",
        lambda: parse_json_document(
            json.dumps({f"field-{index}": index for index in range(65)}),
            "wide-object",
        ),
    )
    expect_failure(
        "excessive array items",
        lambda: parse_json_document(json.dumps(list(range(257))), "wide-array"),
    )
    expect_failure(
        "excessive string",
        lambda: parse_json_document(json.dumps("x" * 4_097), "long-string"),
    )
    expect_failure(
        "excessive object key",
        lambda: parse_json_document(
            json.dumps({"x" * (MAX_STRING_CHARACTERS + 1): True}),
            "long-key",
        ),
    )
    expect_failure(
        "excessive finite float token",
        lambda: parse_json_document(
            "0." + "1" * (MAX_NUMBER_CHARACTERS - 1),
            "long-float-token",
        ),
    )
    expect_failure(
        "excessive total nodes",
        lambda: parse_json_document(
            json.dumps(
                {
                    f"field-{field}": list(range(MAX_OBJECT_FIELDS))
                    for field in range(MAX_OBJECT_FIELDS)
                }
            ),
            "many-nodes",
        ),
    )

    expect_redacted_failure(
        "parser diagnostic redacts absolute path",
        lambda: parse_json_document(
            "{", "/home/private-user/private-repository/scenario.json"
        ),
    )
    expect_redacted_failure(
        "parser diagnostic rejects filename control injection",
        lambda: parse_json_document(
            "{", "evil\n::error::forged\x1b.scenario.json"
        ),
    )
    expect_redacted_failure(
        "duplicate-key diagnostic redacts attacker path",
        lambda: parse_json_document(
            '{"/home/private-key":1,"/home/private-key":2}', "duplicate-private"
        ),
    )
    expect_redacted_failure(
        "I/O diagnostic redacts absolute path",
        lambda: read_json_document(
            Path("/definitely-missing-ogir-scenario.json"),
            "/home/private-user/private-repository/scenario.json",
        ),
    )
    expect_redacted_failure(
        "schema diagnostic redacts attacker path",
        lambda: validate_schema_shape(
            {"properties": {"/home/private-key": {"unsupported": True}}},
            "/home/private-schema",
        ),
    )
    expect_redacted_failure(
        "instance diagnostic redacts caller path",
        lambda: validate_instance(
            {"unreviewed": True}, schema, "/home/private-instance"
        ),
    )

    print("All attack-scenario validation tests passed.")


def load_repository_contract() -> tuple[Path, dict[str, object], list[Path]]:
    repository = Path(__file__).resolve().parent.parent
    scenario_directory = repository / "lab" / "scenarios"
    validate_scenario_directory(scenario_directory)
    schema_path = scenario_directory / "schema.json"
    validate_regular_file(schema_path)
    schema = validate_schema_contract(
        read_json_document(schema_path, "lab/scenarios/schema.json")
    )
    scenarios: list[Path] = []
    try:
        entries = scenario_directory.iterdir()
    except OSError as error:
        raise ScenarioValidationError("cannot list attack-scenario directory") from error
    for entry in entries:
        if entry == schema_path:
            continue
        if not entry.name.endswith(".scenario.json"):
            fail("unexpected attack-scenario path")
        validate_regular_file(entry)
        scenarios.append(entry)
        if len(scenarios) > MAX_SCENARIO_FILES:
            validate_scenario_count(len(scenarios))
    validate_scenario_count(len(scenarios))
    scenarios.sort()
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
        instances: list[object] = []
        for scenario in scenarios:
            source = str(scenario.relative_to(repository))
            instance = read_json_document(scenario, source)
            validate_instance(instance, schema, source)
            instances.append(instance)
        validate_repository_semantics(instances)
    except (AssertionError, ScenarioValidationError) as error:
        print(f"attack-scenario validation failed: {error}", file=sys.stderr)
        return 1
    except Exception:
        print("attack-scenario validation failed: internal error", file=sys.stderr)
        return 1

    print(f"Attack-scenario validation passed for {len(scenarios)} scenario(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
