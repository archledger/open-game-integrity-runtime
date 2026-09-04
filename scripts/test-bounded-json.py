#!/usr/bin/env python3
"""Registry-driven tests for the shared bounded JSON loader."""

from __future__ import annotations

import copy
import dataclasses
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import abstract_conformance_registry as registry
import bounded_json


DIAGNOSTIC = "abstract-conformance:layer-2:malformed"


class AstError(ValueError):
    pass


def _pointer_parts(pointer: str) -> list[str]:
    if not pointer.startswith("/"):
        raise AstError("pointer")
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def _set_pointer(document: Any, pointer: str, expected: Any, value: Any) -> Any:
    result = copy.deepcopy(document)
    parts = _pointer_parts(pointer)
    parent = result
    for part in parts[:-1]:
        parent = parent[int(part)] if isinstance(parent, list) else parent[part]
    key = parts[-1]
    absent = isinstance(expected, dict) and expected == {"absent": True}
    if isinstance(parent, list):
        index = int(key)
        if absent or parent[index] != expected:
            raise AstError("set")
        parent[index] = copy.deepcopy(value)
    else:
        if absent:
            if key in parent:
                raise AstError("set")
        elif parent.get(key, object()) != expected:
            raise AstError("set")
        parent[key] = copy.deepcopy(value)
    return result


def _serialize_generated(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _resource_value(parameters: dict[str, Any], limits: dict[str, Any]) -> bytes:
    scope = parameters["scope"]
    dimension = parameters["dimension"]
    relation = parameters["relation"]
    target = limits[scope][dimension] + (relation == "over")
    if parameters.get("numeric_kind") in {"integer", "float"}:
        return parameters["token"].encode("ascii")
    if dimension == "bytes":
        return b" " * (target - 2) + b"{}"
    if dimension == "depth":
        value: Any = None
        for _ in range(target - 1):
            value = [value]
        return _serialize_generated(value)
    if dimension == "object_fields":
        return _serialize_generated({f"k{index}": None for index in range(target)})
    if dimension == "array_items":
        return _serialize_generated([None] * target)
    if dimension == "string_characters":
        return _serialize_generated("x" * target)
    if dimension == "object_key_characters":
        return _serialize_generated({"k" * target: None})
    if dimension == "total_nodes":
        remaining = target - 1
        result: list[Any] = []
        maximum = limits[scope]["array_items"]
        while remaining:
            if remaining == 1:
                result.append(None)
                remaining -= 1
            else:
                children = min(maximum, remaining - 1)
                result.append([None] * children)
                remaining -= children + 1
        return _serialize_generated(result)
    raise AstError("resource")


def _generate(constructor: str, parameters: dict[str, Any], limits: dict[str, Any]) -> bytes:
    if constructor == "resource-boundary":
        return _resource_value(parameters, limits)
    if constructor == "number-token-boundary":
        size = limits[parameters["scope"]]["number_token_characters"] + (
            parameters["relation"] == "over"
        )
        prefix = parameters.get("prefix") or ""
        return (prefix + parameters["digit"] * (size - len(prefix))).encode("ascii")
    if constructor == "invalid-utf8-document":
        return (
            parameters["prefix"].encode("ascii")
            + bytes.fromhex(parameters["invalid_byte_hex"])
            + parameters["suffix"].encode("ascii")
        )
    if constructor == "json-number-document":
        return parameters["token"].encode("ascii")
    raise AstError("constructor")


def _eval_input(node: dict[str, Any], baselines: dict[str, Any], limits: dict[str, Any]) -> Any:
    kind = node["node"]
    if kind == "ref":
        return copy.deepcopy(baselines[node["id"]]["ast"]["value"])
    if kind == "bytes-append":
        value = _eval_input(node["input"], baselines, limits)
        value["bytes_utf8"] += node["bytes"]
        value["filesystem"]["input.json"]["bytes_utf8"] = value["bytes_utf8"]
        return value
    if kind == "bytes-replace":
        value = _eval_input(node["input"], baselines, limits)
        raw = value["bytes_utf8"]
        if raw.count(node["old_ascii"]) != node["expected_occurrences"]:
            raise AstError("replace")
        value["bytes_utf8"] = raw.replace(node["old_ascii"], node["new_ascii"])
        value["filesystem"]["input.json"]["bytes_utf8"] = value["bytes_utf8"]
        return value
    if kind == "generate":
        return _generate(node["constructor"], node["parameters"], limits)
    if kind == "set":
        source = _eval_input(node["input"], baselines, limits)
        if isinstance(source, dict) and "bytes_utf8" in source:
            source = json.loads(source["bytes_utf8"])
        return _set_pointer(
            source,
            node["pointer"],
            node["expected_old"],
            node["value"],
        )
    if kind == "fs-remove":
        value = _eval_input(node["input"], baselines, limits)
        value["filesystem"].pop(node["relative_path"])
        return value
    if kind == "fs-create":
        value = _eval_input(node["input"], baselines, limits)
        value["filesystem"][node["relative_path"]] = {
            "kind": node["kind"],
            "contents": node["contents"],
        }
        if node["relative_path"] == "approved-root-link":
            value["approved_root"] = "approved-root-link"
        return value
    if kind == "fs-rename":
        value = _eval_input(node["input"], baselines, limits)
        entry = value["filesystem"].pop(node["old_relative_path"])
        value["filesystem"][node["new_relative_path"]] = entry
        value["input_path"] = node["new_relative_path"]
        return value
    raise AstError("node")


def _probe_input(case: registry.LoaderCase, authority: registry.Task2Authority) -> Any:
    ast = authority.validators["validator_transforms"][case.transform]["ast"]
    probe = ast["steps"][-1]
    if probe["node"] != "probe":
        raise AstError("probe")
    return _eval_input(probe["input"], authority.validators["validator_baselines"], authority.core["resource_limits"])


def _write_fixture(root: Path, value: Any) -> tuple[Path, str]:
    approved = root / "approved-root"
    approved.mkdir()
    outside = approved / "outside.json"
    outside.write_bytes(b"{}")
    if isinstance(value, bytes):
        (approved / "input.json").write_bytes(value)
        return approved, "input.json"

    for relative, entry in value["filesystem"].items():
        if relative == "approved-root":
            continue
        target = approved / relative if relative != "approved-root-link" else root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if entry["kind"] == "regular-file":
            target.write_bytes(entry["bytes_utf8"].encode("utf-8"))
        elif entry["kind"] == "directory":
            target.mkdir()
        elif entry["kind"] == "symlink":
            target.symlink_to(entry["contents"])
        else:
            raise AstError("filesystem")
    return root / value["approved_root"], value["input_path"]


class InterfaceTests(unittest.TestCase):
    def test_registry_and_loader_interfaces_are_importable(self) -> None:
        authority = registry.load_task2_authority()
        self.assertTrue(authority.loader_cases)
        self.assertTrue(callable(bounded_json.load_bounded_json))
        self.assertTrue(callable(bounded_json.load_bounded_json_with_identity))

    def test_registry_bijection_and_exact_equivalence_classes(self) -> None:
        authority = registry.load_task2_authority()
        self.assertEqual(
            [case.identifier for case in authority.loader_cases],
            list(authority.loader_transforms),
        )
        self.assertEqual(
            registry.exact_equivalence_classes(authority),
            (("v1-loader-valid-object", "v1-loader-valid-utf8"),),
        )


class LoaderCaseTests(unittest.TestCase):
    authority: registry.Task2Authority

    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = registry.load_task2_authority()

    def run_registry_case(self, case: registry.LoaderCase) -> None:
        value = _probe_input(case, self.authority)
        limits = bounded_json.JsonLimits.from_mapping(self.authority.core["resource_limits"]["fixture"])
        adapter = self.authority.validators["validator_transforms"][case.transform]["ast"]["steps"][-1]["adapter"]
        if adapter == "bounded-json-diagnostic":
            rendered = bounded_json.render_bounded_json_error(
                DIAGNOSTIC, RuntimeError(json.dumps(value, default=str))
            )
            self.assertEqual(rendered, DIAGNOSTIC)
            return
        with tempfile.TemporaryDirectory() as temporary:
            approved_root, relative_path = _write_fixture(Path(temporary), value)
            if case.disposition == "Conform":
                try:
                    bounded_json.load_bounded_json(
                        approved_root, relative_path, limits, DIAGNOSTIC
                    )
                except Exception:
                    self.fail("conforming registry input was rejected")
                return
            try:
                bounded_json.load_bounded_json(
                    approved_root, relative_path, limits, DIAGNOSTIC
                )
            except bounded_json.BoundedJsonError as error:
                self.assertEqual(str(error), DIAGNOSTIC)
                self.assertIsNone(error.__cause__)
            except Exception:
                self.fail("rejecting registry input escaped the fixed error boundary")
            else:
                self.fail("rejecting registry input was accepted")


class LoaderSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        authority = registry.load_task2_authority()
        cls.limits = bounded_json.JsonLimits.from_mapping(
            authority.core["resource_limits"]["fixture"]
        )

    def test_returns_complete_parsed_document(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_text(
                '{"name":"fixture","nested":{"enabled":true,"values":[1,null,"end"]}}',
                encoding="utf-8",
            )
            result = bounded_json.load_bounded_json(
                root, "input.json", self.limits, DIAGNOSTIC
            )

        self.assertEqual(
            result,
            {
                "name": "fixture",
                "nested": {"enabled": True, "values": [1, None, "end"]},
            },
        )

    def test_identity_api_returns_stable_same_descriptor_identity(self) -> None:
        original_fstat = os.fstat
        observations: list[os.stat_result] = []

        def observed_fstat(file_descriptor: int) -> os.stat_result:
            current = original_fstat(file_descriptor)
            if stat.S_ISREG(current.st_mode):
                observations.append(current)
            return current

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_text('{"value":"stable"}', encoding="utf-8")
            with mock.patch.object(
                bounded_json.os, "fstat", side_effect=observed_fstat
            ):
                value, identity = bounded_json.load_bounded_json_with_identity(
                    root, "input.json", self.limits, DIAGNOSTIC
                )

        self.assertEqual(value, {"value": "stable"})
        self.assertEqual(len(observations), 2)
        self.assertEqual(
            identity,
            bounded_json.StableFileIdentity.from_stat(observations[0]),
        )
        self.assertEqual(
            identity,
            bounded_json.StableFileIdentity.from_stat(observations[1]),
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            identity.size = 0

    def test_identity_api_detects_byte_identical_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "input.json"
            replacement = root / "replacement.json"
            path.write_text('{"value":"stable"}', encoding="utf-8")
            replacement.write_bytes(path.read_bytes())
            value, identity = bounded_json.load_bounded_json_with_identity(
                root, "input.json", self.limits, DIAGNOSTIC
            )
            os.replace(replacement, path)
            replacement_identity = bounded_json.StableFileIdentity.from_stat(
                os.stat(path, follow_symlinks=False)
            )

        self.assertEqual(value, {"value": "stable"})
        self.assertNotEqual(identity, replacement_identity)

    def test_matching_identity_rejects_an_unadmitted_root_hierarchy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            admitted = base / "admitted"
            replay = base / "replay"
            (admitted / "nested").mkdir(parents=True)
            (replay / "nested").mkdir(parents=True)
            admitted_file = admitted / "nested" / "input.json"
            replay_file = replay / "nested" / "input.json"
            admitted_file.write_text('{"value":"stable"}', encoding="utf-8")
            os.link(admitted_file, replay_file)
            expected_file = bounded_json.StableFileIdentity.from_stat(
                os.stat(admitted_file, follow_symlinks=False)
            )
            expected_hierarchy = tuple(
                bounded_json.StableFileIdentity.from_stat(
                    os.stat(path, follow_symlinks=False)
                )
                for path in (admitted, admitted / "nested")
            )

            with self.assertRaises(bounded_json.BoundedJsonError) as raised:
                bounded_json.load_bounded_json_matching_identity(
                    replay,
                    "nested/input.json",
                    self.limits,
                    DIAGNOSTIC,
                    expected_file,
                    expected_hierarchy=expected_hierarchy,
                )

        self.assertEqual(str(raised.exception), DIAGNOSTIC)
        self.assertEqual(raised.exception.category, "identity")
        self.assertIsNone(raised.exception.__cause__)

    def test_matching_identity_rechecks_held_directory_descriptors(self) -> None:
        original_fstat = os.fstat
        directory_observations = 0

        def drifting_fstat(file_descriptor: int) -> Any:
            nonlocal directory_observations
            current = original_fstat(file_descriptor)
            if not stat.S_ISDIR(current.st_mode):
                return current
            directory_observations += 1
            if directory_observations == 3:
                return _stat_view(current, st_mtime_ns=current.st_mtime_ns + 1)
            return current

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested = root / "nested"
            nested.mkdir()
            path = nested / "input.json"
            path.write_text("{}", encoding="utf-8")
            expected_file = bounded_json.StableFileIdentity.from_stat(
                os.stat(path, follow_symlinks=False)
            )
            expected_hierarchy = tuple(
                bounded_json.StableFileIdentity.from_stat(
                    os.stat(directory, follow_symlinks=False)
                )
                for directory in (root, nested)
            )

            with mock.patch.object(
                bounded_json.os, "fstat", side_effect=drifting_fstat
            ):
                with self.assertRaises(bounded_json.BoundedJsonError) as raised:
                    bounded_json.load_bounded_json_matching_identity(
                        root,
                        "nested/input.json",
                        self.limits,
                        DIAGNOSTIC,
                        expected_file,
                        expected_hierarchy=expected_hierarchy,
                    )

        self.assertEqual(str(raised.exception), DIAGNOSTIC)
        self.assertEqual(raised.exception.category, "identity")
        self.assertIsNone(raised.exception.__cause__)

    def test_matching_identity_classifies_root_open_failure_as_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            root.mkdir()
            path = root / "input.json"
            path.write_text("{}", encoding="utf-8")
            expected_file = bounded_json.StableFileIdentity.from_stat(
                os.stat(path, follow_symlinks=False)
            )
            expected_hierarchy = (
                bounded_json.StableFileIdentity.from_stat(
                    os.stat(root, follow_symlinks=False)
                ),
            )
            moved = base / "admitted"
            root.replace(moved)
            root.symlink_to(moved.name, target_is_directory=True)

            with self.assertRaises(bounded_json.BoundedJsonError) as raised:
                bounded_json.load_bounded_json_matching_identity(
                    root,
                    "input.json",
                    self.limits,
                    DIAGNOSTIC,
                    expected_file,
                    expected_hierarchy=expected_hierarchy,
                )

        self.assertEqual(str(raised.exception), DIAGNOSTIC)
        self.assertEqual(raised.exception.category, "identity")
        self.assertIsNone(raised.exception.__cause__)

    def test_matching_identity_classifies_missing_ancestor_as_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "nested" / "input.json"
            path.parent.mkdir()
            path.write_text("{}", encoding="utf-8")
            expected_file = bounded_json.StableFileIdentity.from_stat(
                os.stat(path, follow_symlinks=False)
            )
            missing_identity = bounded_json.StableFileIdentity.from_stat(
                os.stat(path.parent, follow_symlinks=False)
            )
            path.unlink()
            path.parent.rmdir()
            expected_hierarchy = (
                bounded_json.StableFileIdentity.from_stat(
                    os.stat(root, follow_symlinks=False)
                ),
                missing_identity,
            )

            with self.assertRaises(bounded_json.BoundedJsonError) as raised:
                bounded_json.load_bounded_json_matching_identity(
                    root,
                    "nested/input.json",
                    self.limits,
                    DIAGNOSTIC,
                    expected_file,
                    expected_hierarchy=expected_hierarchy,
                )

        self.assertEqual(str(raised.exception), DIAGNOSTIC)
        self.assertEqual(raised.exception.category, "identity")
        self.assertIsNone(raised.exception.__cause__)

    def test_matching_identity_classifies_missing_final_entry_as_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "input.json"
            path.write_text("{}", encoding="utf-8")
            expected_file = bounded_json.StableFileIdentity.from_stat(
                os.stat(path, follow_symlinks=False)
            )
            path.unlink()
            expected_hierarchy = (
                bounded_json.StableFileIdentity.from_stat(
                    os.stat(root, follow_symlinks=False)
                ),
            )

            with self.assertRaises(bounded_json.BoundedJsonError) as raised:
                bounded_json.load_bounded_json_matching_identity(
                    root,
                    "input.json",
                    self.limits,
                    DIAGNOSTIC,
                    expected_file,
                    expected_hierarchy=expected_hierarchy,
                )

        self.assertEqual(str(raised.exception), DIAGNOSTIC)
        self.assertEqual(raised.exception.category, "identity")
        self.assertIsNone(raised.exception.__cause__)

    def test_unbound_missing_final_entry_remains_io(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(bounded_json.BoundedJsonError) as raised:
                bounded_json.load_bounded_json(
                    root, "missing.json", self.limits, DIAGNOSTIC
                )

        self.assertEqual(str(raised.exception), DIAGNOSTIC)
        self.assertEqual(raised.exception.category, "io")
        self.assertIsNone(raised.exception.__cause__)

    def test_nonregular_final_classification_depends_on_hierarchy_binding(
        self,
    ) -> None:
        for bound, expected_category in ((True, "identity"), (False, "io")):
            with self.subTest(bound=bound):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    path = root / "input.json"
                    path.mkdir()
                    identity = bounded_json.StableFileIdentity.from_stat(
                        os.stat(path, follow_symlinks=False)
                    )
                    hierarchy = (
                        bounded_json.StableFileIdentity.from_stat(
                            os.stat(root, follow_symlinks=False)
                        ),
                    )

                    with self.assertRaises(bounded_json.BoundedJsonError) as raised:
                        if bound:
                            bounded_json.load_bounded_json_matching_identity(
                                root,
                                "input.json",
                                self.limits,
                                DIAGNOSTIC,
                                identity,
                                expected_hierarchy=hierarchy,
                            )
                        else:
                            bounded_json.load_bounded_json(
                                root, "input.json", self.limits, DIAGNOSTIC
                            )

                self.assertEqual(str(raised.exception), DIAGNOSTIC)
                self.assertEqual(raised.exception.category, expected_category)
                self.assertIsNone(raised.exception.__cause__)

    def test_final_metadata_drift_classification_depends_on_hierarchy_binding(
        self,
    ) -> None:
        original_fstat = os.fstat
        for bound, expected_category in ((True, "identity"), (False, "io")):
            with self.subTest(bound=bound):
                regular_observations = 0

                def drifting_fstat(file_descriptor: int) -> Any:
                    nonlocal regular_observations
                    current = original_fstat(file_descriptor)
                    if not stat.S_ISREG(current.st_mode):
                        return current
                    regular_observations += 1
                    if regular_observations == 2:
                        return _stat_view(
                            current, st_mtime_ns=current.st_mtime_ns + 1
                        )
                    return current

                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    path = root / "input.json"
                    path.write_text("{}", encoding="utf-8")
                    identity = bounded_json.StableFileIdentity.from_stat(
                        os.stat(path, follow_symlinks=False)
                    )
                    hierarchy = (
                        bounded_json.StableFileIdentity.from_stat(
                            os.stat(root, follow_symlinks=False)
                        ),
                    )
                    with mock.patch.object(
                        bounded_json.os, "fstat", side_effect=drifting_fstat
                    ):
                        with self.assertRaises(
                            bounded_json.BoundedJsonError
                        ) as raised:
                            if bound:
                                bounded_json.load_bounded_json_matching_identity(
                                    root,
                                    "input.json",
                                    self.limits,
                                    DIAGNOSTIC,
                                    identity,
                                    expected_hierarchy=hierarchy,
                                )
                            else:
                                bounded_json.load_bounded_json(
                                    root, "input.json", self.limits, DIAGNOSTIC
                                )

                self.assertEqual(str(raised.exception), DIAGNOSTIC)
                self.assertEqual(raised.exception.category, expected_category)
                self.assertIsNone(raised.exception.__cause__)

    def test_short_read_classification_depends_on_hierarchy_binding(self) -> None:
        for bound, expected_category in ((True, "identity"), (False, "io")):
            with self.subTest(bound=bound):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    path = root / "input.json"
                    path.write_text("{}", encoding="utf-8")
                    identity = bounded_json.StableFileIdentity.from_stat(
                        os.stat(path, follow_symlinks=False)
                    )
                    hierarchy = (
                        bounded_json.StableFileIdentity.from_stat(
                            os.stat(root, follow_symlinks=False)
                        ),
                    )
                    with mock.patch.object(bounded_json.os, "read", return_value=b""):
                        with self.assertRaises(
                            bounded_json.BoundedJsonError
                        ) as raised:
                            if bound:
                                bounded_json.load_bounded_json_matching_identity(
                                    root,
                                    "input.json",
                                    self.limits,
                                    DIAGNOSTIC,
                                    identity,
                                    expected_hierarchy=hierarchy,
                                )
                            else:
                                bounded_json.load_bounded_json(
                                    root, "input.json", self.limits, DIAGNOSTIC
                                )

                self.assertEqual(str(raised.exception), DIAGNOSTIC)
                self.assertEqual(raised.exception.category, expected_category)
                self.assertIsNone(raised.exception.__cause__)

    def test_matching_identity_preserves_nonfilesystem_categories(self) -> None:
        cases = (
            (b"{}", dataclasses.replace(self.limits, bytes=1), "bytes"),
            (b"\xff", self.limits, "utf8"),
            (b'{"x":1,"x":2}', self.limits, "duplicate"),
            (b"{", self.limits, "malformed"),
        )
        for raw, limits, expected_category in cases:
            with self.subTest(category=expected_category):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    path = root / "input.json"
                    path.write_bytes(raw)
                    identity = bounded_json.StableFileIdentity.from_stat(
                        os.stat(path, follow_symlinks=False)
                    )
                    hierarchy = (
                        bounded_json.StableFileIdentity.from_stat(
                            os.stat(root, follow_symlinks=False)
                        ),
                    )

                    with self.assertRaises(bounded_json.BoundedJsonError) as raised:
                        bounded_json.load_bounded_json_matching_identity(
                            root,
                            "input.json",
                            limits,
                            DIAGNOSTIC,
                            identity,
                            expected_hierarchy=hierarchy,
                        )

                self.assertEqual(str(raised.exception), DIAGNOSTIC)
                self.assertEqual(raised.exception.category, expected_category)
                self.assertIsNone(raised.exception.__cause__)

    def test_identity_api_metadata_drift_uses_fixed_diagnostic(self) -> None:
        original_fstat = os.fstat
        regular_observations = 0

        def drifting_fstat(file_descriptor: int) -> Any:
            nonlocal regular_observations
            current = original_fstat(file_descriptor)
            if not stat.S_ISREG(current.st_mode):
                return current
            regular_observations += 1
            if regular_observations == 2:
                return _stat_view(current, st_uid=4_294_967_295)
            return current

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_text("{}", encoding="utf-8")
            with mock.patch.object(
                bounded_json.os, "fstat", side_effect=drifting_fstat
            ):
                with self.assertRaises(bounded_json.BoundedJsonError) as raised:
                    bounded_json.load_bounded_json_with_identity(
                        root, "input.json", self.limits, DIAGNOSTIC
                    )

        self.assertEqual(str(raised.exception), DIAGNOSTIC)
        self.assertEqual(raised.exception.category, "io")
        self.assertNotIn("4294967295", repr(raised.exception))

    def test_reports_fixed_malformed_location_for_compatibility_formatter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_text("{", encoding="utf-8")
            with self.assertRaises(bounded_json.BoundedJsonError) as raised:
                bounded_json.load_bounded_json(
                    root, "input.json", self.limits, DIAGNOSTIC
                )

        self.assertEqual(getattr(raised.exception, "category", None), "malformed")
        self.assertEqual(getattr(raised.exception, "line", None), 1)
        self.assertEqual(getattr(raised.exception, "column", None), 2)
        self.assertEqual(str(raised.exception), DIAGNOSTIC)

    def test_supports_legacy_root_depth_counting(self) -> None:
        self.assertIn("root_depth", bounded_json.JsonLimits.__dataclass_fields__)
        limits = dataclasses.replace(self.limits, root_depth=0)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_text(
                "[" * limits.depth + "0" + "]" * limits.depth,
                encoding="utf-8",
            )
            bounded_json.load_bounded_json(root, "input.json", limits, DIAGNOSTIC)

    def test_reports_object_limit_before_duplicate_for_legacy_formatter(self) -> None:
        limits = dataclasses.replace(self.limits, object_fields=1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_text('{"x":1,"x":2}', encoding="utf-8")
            with self.assertRaises(bounded_json.BoundedJsonError) as raised:
                bounded_json.load_bounded_json(
                    root, "input.json", limits, DIAGNOSTIC
                )

        self.assertEqual(raised.exception.category, "object-fields")

    def test_classifies_unknown_recursion_without_retaining_exception_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_text("{}", encoding="utf-8")
            with mock.patch.object(
                bounded_json.json,
                "loads",
                side_effect=RecursionError("unreviewed recursion detail"),
            ):
                with self.assertRaises(bounded_json.BoundedJsonError) as raised:
                    bounded_json.load_bounded_json(
                        root, "input.json", self.limits, DIAGNOSTIC
                    )

        self.assertEqual(raised.exception.category, "recursion")
        self.assertEqual(getattr(raised.exception, "context", None), "unknown")
        self.assertEqual(str(raised.exception), DIAGNOSTIC)
        self.assertNotIn("unreviewed recursion detail", repr(raised.exception))

    def test_rejects_utf16_instead_of_autodetecting_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_bytes('{"value":"alpha"}'.encode("utf-16"))
            with self.assertRaises(bounded_json.BoundedJsonError):
                bounded_json.load_bounded_json(root, "input.json", self.limits, DIAGNOSTIC)

    def test_rejects_symlinked_ancestor_component(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "approved"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "input.json").write_text("{}", encoding="utf-8")
            (root / "link").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(bounded_json.BoundedJsonError):
                bounded_json.load_bounded_json(
                    root, "link/input.json", self.limits, DIAGNOSTIC
                )

    def test_reads_at_most_the_byte_limit_plus_one(self) -> None:
        delivered = 0
        original_read = os.read

        def observed_read(file_descriptor: int, count: int) -> bytes:
            nonlocal delivered
            chunk = original_read(file_descriptor, count)
            delivered += len(chunk)
            return chunk

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_bytes(b" " * 100_000)
            with mock.patch.object(bounded_json.os, "read", side_effect=observed_read):
                with self.assertRaises(bounded_json.BoundedJsonError):
                    bounded_json.load_bounded_json(
                        root, "input.json", self.limits, DIAGNOSTIC
                    )
        self.assertLessEqual(delivered, self.limits.bytes + 1)

    def test_rejects_a_nonregular_final_descriptor(self) -> None:
        original_fstat = os.fstat

        def nonregular_fstat(file_descriptor: int) -> Any:
            current = original_fstat(file_descriptor)
            if stat.S_ISREG(current.st_mode):
                return _stat_view(current, st_mode=stat.S_IFDIR | 0o700)
            return current

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_text("{}", encoding="utf-8")
            with mock.patch.object(bounded_json.os, "fstat", side_effect=nonregular_fstat):
                with self.assertRaises(bounded_json.BoundedJsonError):
                    bounded_json.load_bounded_json(
                        root, "input.json", self.limits, DIAGNOSTIC
                    )

    def test_rejects_final_descriptor_metadata_drift(self) -> None:
        original_fstat = os.fstat
        regular_observations = 0

        def drifting_fstat(file_descriptor: int) -> Any:
            nonlocal regular_observations
            current = original_fstat(file_descriptor)
            if not stat.S_ISREG(current.st_mode):
                return current
            regular_observations += 1
            if regular_observations == 2:
                return _stat_view(current, st_mtime_ns=current.st_mtime_ns + 1)
            return current

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_text("{}", encoding="utf-8")
            with mock.patch.object(bounded_json.os, "fstat", side_effect=drifting_fstat):
                with self.assertRaises(bounded_json.BoundedJsonError):
                    bounded_json.load_bounded_json(
                        root, "input.json", self.limits, DIAGNOSTIC
                    )


def _stat_view(current: os.stat_result, **changes: int) -> SimpleNamespace:
    fields = {
        name: getattr(current, name)
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    }
    fields.update(changes)
    return SimpleNamespace(**fields)


def _install_case_tests() -> None:
    authority = registry.load_task2_authority()
    for case in authority.loader_cases:
        name = "test_" + case.identifier.replace("-", "_")

        def test(self: LoaderCaseTests, selected: registry.LoaderCase = case) -> None:
            self.run_registry_case(selected)

        test.__name__ = name
        setattr(LoaderCaseTests, name, test)


_install_case_tests()


if __name__ == "__main__":
    replay_through = os.environ.get("M1_013_REPLAY_THROUGH")
    if replay_through is None:
        unittest.main(verbosity=2)
    else:
        suite = unittest.TestSuite()
        found = False
        for admitted_case in registry.load_task2_authority().loader_cases:
            method = "test_" + admitted_case.identifier.replace("-", "_")
            suite.addTest(LoaderCaseTests(method))
            if admitted_case.identifier == replay_through:
                found = True
                break
        if not found:
            raise SystemExit("unknown replay case")
        outcome = unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(not outcome.wasSuccessful())
