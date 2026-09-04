#!/usr/bin/env python3
"""Registry-driven compatibility tests for the attack-scenario validator."""

from __future__ import annotations

import copy
import importlib.util
import json
import json.scanner
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from typing import Any, NoReturn


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import abstract_conformance_registry as registry


SELF_TEST_STDOUT = """PASS: parser resource boundaries
PASS: zero scenario files
PASS: excessive scenario files
PASS: symlinked scenario directory
PASS: symlinked scenario file
PASS: duplicate scenario identifier
PASS: unregistered scenario owner
PASS: unregistered assurance profile
PASS: missing owner
PASS: invalid owner
PASS: terminal newline in owner
PASS: schema omits owner
PASS: missing required assurance profile
PASS: invalid required assurance profile
PASS: terminal newline in required assurance profile
PASS: schema omits required assurance profile
PASS: terminal newline in attacker
PASS: quoted duplicate owner
PASS: non-JSON numeric constant NaN
PASS: non-JSON numeric constant Infinity
PASS: non-JSON numeric constant -Infinity
PASS: non-finite numeric exponent
PASS: excessive integer token
PASS: multiple scenario documents
PASS: unknown scenario field
PASS: unknown nested expected field
PASS: wrong schema dialect 'http://json-schema.org/draft-07/schema#'
PASS: wrong schema dialect 'not-a-uri'
PASS: wrong schema dialect ''
PASS: non-whitelisted backtracking schema pattern
PASS: non-whitelisted oversized repetition schema pattern
PASS: oversized document
PASS: excessive nesting
PASS: excessive object fields
PASS: excessive array items
PASS: excessive string
PASS: excessive object key
PASS: excessive finite float token
PASS: excessive total nodes
PASS: parser diagnostic redacts absolute path
PASS: parser diagnostic rejects filename control injection
PASS: duplicate-key diagnostic redacts attacker path
PASS: I/O diagnostic redacts absolute path
PASS: schema diagnostic redacts attacker path
PASS: instance diagnostic redacts caller path
All attack-scenario validation tests passed.
"""


class TransformError(AssertionError):
    pass


def _load_checker(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("attack_scenario_checker", path)
    if spec is None or spec.loader is None:
        raise TransformError("cannot load frozen checker")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pointer_parent(document: Any, pointer: str) -> tuple[Any, str]:
    if not pointer.startswith("/"):
        raise TransformError("invalid registry pointer")
    parts = [
        part.replace("~1", "/").replace("~0", "~")
        for part in pointer[1:].split("/")
    ]
    parent = document
    for part in parts[:-1]:
        try:
            parent = parent[int(part)] if isinstance(parent, list) else parent[part]
        except (IndexError, KeyError, TypeError, ValueError) as error:
            raise TransformError("invalid registry pointer") from error
    return parent, parts[-1]


def _apply_mutation(document: Any, mutation: dict[str, Any]) -> Any:
    result = copy.deepcopy(document)
    parent, key = _pointer_parent(result, mutation["pointer"])
    operation = mutation.get("operation", "set")
    expected = mutation["expected_old"]
    if operation == "remove-array-value":
        try:
            values = parent[key]
        except (KeyError, TypeError) as error:
            raise TransformError("invalid registry pointer") from error
        if not isinstance(values, list) or values.count(expected) != 1:
            raise TransformError(
                f"expected_old={expected!r} does not occur exactly once"
            )
        values.remove(expected)
        return result
    if operation not in {"set", "remove"} or not isinstance(parent, dict):
        raise TransformError("unsupported registry mutation")
    absent = expected == {"absent": True}
    if absent:
        if key in parent:
            raise TransformError(f"expected_old=absent but actual={parent[key]!r}")
    elif key not in parent or parent[key] != expected:
        actual = parent[key] if key in parent else {"absent": True}
        raise TransformError(f"expected_old={expected!r} but actual={actual!r}")
    if operation == "remove":
        del parent[key]
    else:
        parent[key] = copy.deepcopy(mutation["value"])
    return result


def _construct(arguments: dict[str, Any], limits: dict[str, Any], scenario: Any) -> str:
    constructor = arguments["constructor"]
    if constructor == "number-token-boundary":
        size = limits[arguments["scope"]]["number_token_characters"] + (
            arguments["relation"] == "over"
        )
        return arguments["digit"] * size
    if constructor == "two-json-documents":
        if arguments["document"] != "valid_scenario":
            raise TransformError("unknown registry document")
        document = json.dumps(scenario)
        return document + arguments["separator"] + document
    if constructor == "json-string":
        return json.dumps(arguments["character"] * arguments["characters"])
    if constructor == "nested-array":
        return (
            "[" * arguments["depth"]
            + json.dumps(arguments["leaf"])
            + "]" * arguments["depth"]
        )
    if constructor == "indexed-object":
        return json.dumps(
            {
                f'{arguments["key_prefix"]}{index}': index
                for index in range(arguments["fields"])
            }
        )
    if constructor == "integer-array":
        return json.dumps(list(range(arguments["items"])))
    if constructor == "single-field-object":
        return json.dumps(
            {
                arguments["key_character"] * arguments["key_characters"]: arguments[
                    "value"
                ]
            }
        )
    if constructor == "finite-float-token":
        return arguments["prefix"] + arguments["digit"] * (
            arguments["token_characters"] - len(arguments["prefix"])
        )
    if constructor == "indexed-object-of-integer-arrays":
        return json.dumps(
            {
                f"field-{field}": list(range(arguments["items_per_array"]))
                for field in range(arguments["fields"])
            }
        )
    raise TransformError(f"unsupported attack constructor {constructor!r}")


class AttackParityTests(unittest.TestCase):
    authority: registry.Task3Authority
    checker: ModuleType
    checker_path: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = registry.load_task3_authority()
        override = os.environ.get("M1_013_ATTACK_CHECKER")
        checker_path = (
            Path(override)
            if override is not None
            else SCRIPT_DIR.parent / cls.authority.attack_baseline["checker"]["path"]
        )
        cls.checker_path = checker_path
        if os.environ.get("M1_013_ATTACK_WORKER") is not None:
            cls.checker = _load_checker(checker_path)

    def _validate_transform(self, case: registry.LoaderCase) -> dict[str, Any]:
        program = self.authority.attack_transforms[case.identifier]["ast"]
        self.assertEqual(program["node"], "sequence")
        self.assertEqual(len(program["steps"]), 3)
        first, probe, last = program["steps"]
        reference = {
            "node": "ref",
            "subject": "baseline",
            "id": case.baseline,
        }
        self.assertEqual(first, reference)
        self.assertEqual(probe["node"], "probe")
        self.assertEqual(probe["adapter"], "frozen-attack-checker")
        self.assertEqual(probe["input"]["repository"], reference)
        self.assertEqual(last["node"], "expect-unchanged")
        self.assertEqual(last["input"], reference)
        self.assertEqual(
            last["subjects"],
            [
                "scripts/check-attack-scenario-traceability.py",
                "lab/scenarios/schema.json",
                "lab/scenarios/*.scenario.json",
            ],
        )
        return probe["input"]

    def _resource_boundaries(self) -> None:
        checker = self.checker
        constants = self.authority.attack_baseline["constants"]
        checker.parse_json_document(
            "{}" + " " * (constants["MAX_DOCUMENT_BYTES"] - 2), "max-bytes"
        )
        checker.parse_json_document(
            "[" * constants["MAX_NESTING_DEPTH"]
            + "0"
            + "]" * constants["MAX_NESTING_DEPTH"],
            "max-depth",
        )
        checker.parse_json_document(
            json.dumps(
                {
                    f"field-{index}": index
                    for index in range(constants["MAX_OBJECT_FIELDS"])
                }
            ),
            "max-fields",
        )
        checker.parse_json_document(
            json.dumps(list(range(constants["MAX_ARRAY_ITEMS"]))), "max-items"
        )
        checker.parse_json_document(
            json.dumps("x" * constants["MAX_STRING_CHARACTERS"]), "max-string"
        )
        checker.parse_json_document(
            json.dumps({"x" * constants["MAX_STRING_CHARACTERS"]: True}),
            "max-key",
        )
        checker.parse_json_document(
            "9" * constants["MAX_NUMBER_CHARACTERS"], "max-number"
        )
        checker.parse_json_document(
            "0." + "1" * (constants["MAX_NUMBER_CHARACTERS"] - 2),
            "max-float-token",
        )
        checker.validate_scenario_count(constants["MAX_SCENARIO_FILES"])
        default_documents = {
            "array": "[" * 1_000 + "0" + "]" * 1_000,
            "object": '{"x":' * 1_000 + "0" + "}" * 1_000,
        }
        default_messages = {
            "array": (
                "attack-scenario input: maximum recursion depth exceeded while "
                "decoding a JSON array from a unicode string"
            ),
            "object": (
                "attack-scenario input: maximum recursion depth exceeded while "
                "decoding a JSON object from a unicode string"
            ),
        }
        observed_default: dict[str, str] = {}
        expected_default: dict[str, str] = {}
        with tempfile.TemporaryDirectory(
            prefix="ogir-attack-parity-default-recursion-"
        ) as temporary:
            root = Path(temporary)
            for context, text in default_documents.items():
                try:
                    json.loads(text)
                except RecursionError:
                    expected_default[context] = default_messages[context]
                else:
                    expected_default[context] = (
                        "attack-scenario input: document exceeds nesting depth 16"
                    )
                path = root / f"{context}.json"
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(checker.ScenarioValidationError) as raised:
                    checker.read_json_document(path, context)
                observed_default[context] = str(raised.exception)
        self.assertEqual(observed_default, expected_default)

        original_scanner = json.scanner.make_scanner
        original_recursion_limit = sys.getrecursionlimit()
        try:
            json.scanner.make_scanner = getattr(json.scanner, "py_make_scanner")
            sys.setrecursionlimit(200)
            with tempfile.TemporaryDirectory(
                prefix="ogir-attack-parity-recursion-"
            ) as temporary:
                path = Path(temporary) / "recursive.json"
                path.write_text("[" * 500 + "0" + "]" * 500, encoding="utf-8")
                with self.assertRaises(checker.ScenarioValidationError) as raised:
                    checker.read_json_document(path, "recursion")
            self.assertEqual(
                str(raised.exception),
                "attack-scenario input: maximum recursion depth exceeded",
            )
        finally:
            sys.setrecursionlimit(original_recursion_limit)
            json.scanner.make_scanner = original_scanner

    def _invoke_cli(self, arguments: dict[str, Any]) -> int:
        old_argv = sys.argv
        old_loader = self.checker.load_repository_contract
        try:
            sys.argv = [str(SCRIPT_DIR / "check-attack-scenario-traceability.py")]
            sys.argv.extend(arguments["argv"])
            fault = arguments.get("fault")
            if fault is not None:
                exception = (
                    self.checker.ScenarioValidationError
                    if fault["raises"] == "ScenarioValidationError"
                    else RuntimeError
                )

                def fail_load() -> NoReturn:
                    raise exception(fault["message"])

                setattr(self.checker, "load_repository_contract", fail_load)
            return self.checker.main()
        finally:
            sys.argv = old_argv
            setattr(self.checker, "load_repository_contract", old_loader)

    def _invoke(self, probe: dict[str, Any]) -> Any:
        checker = self.checker
        entrypoint = probe["entrypoint"]
        arguments = probe["arguments"]
        baseline = self.authority.attack_baseline
        document = {
            "schema": baseline["schema"]["value"],
            "valid_scenario": baseline["valid_scenario"],
        }
        mutation = arguments.get("mutation")
        if mutation is not None:
            document = _apply_mutation(document, mutation)
        if entrypoint == "run_self_test_fragment":
            self.assertEqual(arguments, {"fragment": "parser-resource-boundaries"})
            return self._resource_boundaries()
        if entrypoint == "validate_scenario_count":
            return checker.validate_scenario_count(arguments["count"])
        if entrypoint in {"validate_scenario_directory", "validate_regular_file"}:
            with tempfile.TemporaryDirectory(prefix="ogir-attack-parity-") as temporary:
                root = Path(temporary)
                filesystem = arguments["filesystem"]
                symlink = filesystem["symlink"]
                self.assertEqual(arguments["path"], symlink["path"])
                if entrypoint == "validate_scenario_directory":
                    regular_name = filesystem["regular_directory"]
                    self.assertEqual(symlink["target"], regular_name)
                    regular = root / regular_name
                    regular.mkdir()
                    path = root / arguments["path"]
                    path.symlink_to(symlink["target"], target_is_directory=True)
                else:
                    regular_spec = filesystem["regular_file"]
                    self.assertEqual(symlink["target"], regular_spec["path"])
                    regular = root / regular_spec["path"]
                    regular.write_text(regular_spec["contents"], encoding="utf-8")
                    path = root / arguments["path"]
                    path.symlink_to(symlink["target"])
                return getattr(checker, entrypoint)(path)
        if entrypoint == "validate_repository_semantics":
            if "scenarios" in arguments:
                scenarios = [
                    copy.deepcopy(baseline[name]) for name in arguments["scenarios"]
                ]
            else:
                scenarios = [document["valid_scenario"]]
            return checker.validate_repository_semantics(scenarios)
        if entrypoint == "validate_instance":
            instance = arguments.get("instance", document["valid_scenario"])
            schema = (
                baseline["schema"]["value"]
                if arguments.get("schema") == "schema" or "schema" not in arguments
                else arguments["schema"]
            )
            return checker.validate_instance(instance, schema, arguments.get("source", "case"))
        if entrypoint == "validate_schema_contract":
            return checker.validate_schema_contract(document["schema"])
        if entrypoint == "validate_schema_shape":
            return checker.validate_schema_shape(arguments["schema"], arguments["source"])
        if entrypoint == "parse_json_document":
            text = (
                _construct(
                    arguments,
                    self.authority.core["resource_limits"],
                    baseline["valid_scenario"],
                )
                if "constructor" in arguments
                else arguments["text"]
            )
            return checker.parse_json_document(text, arguments["source"])
        if entrypoint == "read_json_document":
            if "path" in arguments:
                path = Path(arguments["path"])
                self.assertEqual(str(path), arguments["path"])
                return checker.read_json_document(path, arguments["source"])
            with tempfile.TemporaryDirectory(prefix="ogir-attack-parity-") as temporary:
                path = Path(temporary) / "input.json"
                path.write_bytes(bytes.fromhex(arguments["bytes_hex"]))
                return checker.read_json_document(path, arguments["source"])
        if entrypoint == "cli":
            return self._invoke_cli(arguments)
        raise TransformError(f"unsupported frozen checker entrypoint {entrypoint!r}")

    def _run_registry_case_worker(self, case: registry.LoaderCase) -> int:
        probe = self._validate_transform(case)
        try:
            result = self._invoke(probe)
        except self.checker.ScenarioValidationError as error:
            print(str(error), file=sys.stderr)
            return 3
        if probe["entrypoint"] == "cli":
            return result
        return 0

    def run_registry_case(self, case: registry.LoaderCase) -> None:
        environment = os.environ.copy()
        environment["M1_013_ATTACK_WORKER"] = case.identifier
        environment["M1_013_ATTACK_CASE"] = case.identifier
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve())],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        probe = self._validate_transform(case)
        expected = self.authority.attack_expectations.get(case.identifier, {})
        if probe["entrypoint"] == "cli":
            self.assertEqual(result.returncode, expected["expected_exit"])
            self.assertEqual(result.stderr, expected["expected_stderr"])
            if "expected_stdout" in expected:
                self.assertEqual(result.stdout, expected["expected_stdout"])
            else:
                self.assertEqual(result.stdout, SELF_TEST_STDOUT)
                self.assertEqual(
                    result.stdout.splitlines()[-1], expected["stdout_final_line"]
                )
            return
        expected_exit = 3 if case.disposition == "Malformed" else 0
        self.assertEqual(result.returncode, expected_exit)
        self.assertEqual(result.stdout, "")
        if case.disposition == "Conform":
            self.assertEqual(result.stderr, "")
            return
        self.assertNotEqual(result.stderr, "")
        rendered = result.stderr.removesuffix("\n")
        if "expected_message" in expected:
            self.assertEqual(rendered, expected["expected_message"])
        if expected.get("redaction_required"):
            self.assertFalse(
                any(
                    value in rendered
                    for value in (
                        "/home/",
                        "\n",
                        "\r",
                        "\x1b",
                        "::error::",
                        "::warning::",
                    )
                )
            )


def _install_case_tests() -> None:
    authority = registry.load_task3_authority()
    selected = os.environ.get("M1_013_ATTACK_CASE")
    admitted = [
        case
        for case in authority.attack_cases
        if selected is None or case.identifier == selected
    ]
    if not admitted:
        raise SystemExit("unknown attack parity case")
    for case in admitted:
        name = "test_" + case.identifier.replace("-", "_")

        def test(self: AttackParityTests, current: registry.LoaderCase = case) -> None:
            self.run_registry_case(current)

        test.__name__ = name
        setattr(AttackParityTests, name, test)


_install_case_tests()


if __name__ == "__main__":
    worker = os.environ.get("M1_013_ATTACK_WORKER")
    if worker is not None:
        worker_authority = registry.load_task3_authority()
        worker_cases = [
            case for case in worker_authority.attack_cases if case.identifier == worker
        ]
        if len(worker_cases) != 1:
            raise SystemExit("unknown attack parity worker case")
        AttackParityTests.setUpClass()
        worker_test = AttackParityTests()
        raise SystemExit(worker_test._run_registry_case_worker(worker_cases[0]))
    suite = unittest.TestSuite()
    selected = os.environ.get("M1_013_ATTACK_CASE")
    for admitted_case in registry.load_task3_authority().attack_cases:
        if selected is None or admitted_case.identifier == selected:
            method = "test_" + admitted_case.identifier.replace("-", "_")
            suite.addTest(AttackParityTests(method))
    outcome = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not outcome.wasSuccessful())
