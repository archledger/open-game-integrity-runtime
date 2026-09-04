#!/usr/bin/env python3
"""Registry-driven tests for abstract conformance layer 1."""

from __future__ import annotations

import copy
import contextlib
import shutil
from dataclasses import replace
import importlib
import io
import json
import os
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import abstract_conformance_registry as registry
import bounded_json

conformance = importlib.import_module("abstract_conformance")


class ConformanceAssertionError(AssertionError):
    def __init__(self, *_args):
        super().__init__("conformance assertion mismatch")
        self.__suppress_context__ = True


class ConformanceTestCase(unittest.TestCase):
    # unittest may construct diffs from hostile filenames or complete fixture
    # bytes. Preserve its predicates while discarding those diagnostic values.
    failureException = ConformanceAssertionError


class InterfaceTests(ConformanceTestCase):
    def test_task4_interfaces_are_importable(self) -> None:
        try:
            conformance = importlib.import_module("abstract_conformance")
        except ModuleNotFoundError:
            conformance = None

        self.assertTrue(callable(getattr(registry, "load_task4_authority", None)))
        self.assertTrue(callable(getattr(conformance, "build_synthetic_corpus", None)))
        self.assertTrue(callable(getattr(conformance, "validate_layer1", None)))
        self.assertTrue(callable(getattr(conformance, "run_layer1_self_tests", None)))

    def test_task5_interfaces_are_importable(self) -> None:
        self.assertTrue(callable(getattr(registry, "load_task5_authority", None)))
        self.assertTrue(callable(getattr(conformance, "build_task5_corpus", None)))
        self.assertTrue(callable(getattr(conformance, "reproduce_early_fixture", None)))
        self.assertTrue(callable(getattr(conformance, "run_early_fixture_case", None)))
        self.assertTrue(callable(getattr(conformance, "admit_layer1", None)))
        self.assertTrue(
            callable(getattr(conformance, "run_admitted_early_fixture_case", None))
        )

    def test_task6_interfaces_are_importable(self) -> None:
        self.assertTrue(callable(getattr(registry, "load_task6_authority", None)))
        self.assertTrue(callable(getattr(conformance, "build_task6_corpus", None)))
        self.assertTrue(callable(getattr(conformance, "reproduce_snapshot_fixture", None)))
        self.assertTrue(callable(getattr(conformance, "reconstruct_snapshot", None)))
        self.assertTrue(callable(getattr(conformance, "check_snapshot_coverage", None)))
        self.assertTrue(callable(getattr(conformance, "appraise_snapshot", None)))
        self.assertTrue(callable(getattr(conformance, "run_snapshot_focused_case", None)))
        self.assertTrue(callable(getattr(conformance, "run_admitted_snapshot_case", None)))


class BootstrapTests(ConformanceTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = registry.load_task4_authority()

    def test_task4_authority_preserves_corpus_registry_order(self) -> None:
        identifiers = [case.identifier for case in self.authority.corpus_cases]
        self.assertEqual(len(identifiers), 105)
        self.assertEqual(identifiers[0], "v1-corpus-canonical")
        self.assertEqual(identifiers[-1], "v1-corpus-coverage-registered-case-unmapped")
        self.assertEqual(identifiers, list(self.authority.corpus_transforms))
        effective: dict[str, list[str]] = {}
        for case in self.authority.corpus_cases:
            probe = self.authority.corpus_transforms[case.identifier]["ast"]["steps"][-1]
            key = json.dumps(
                [probe["adapter"], probe["input"], case.checkpoint, case.disposition],
                sort_keys=True,
                separators=(",", ":"),
            )
            effective.setdefault(key, []).append(case.identifier)
        self.assertEqual(
            [members for members in effective.values() if len(members) > 1],
            [],
        )

    def test_builds_complete_synthetic_canonical_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            conformance.build_synthetic_corpus(self.authority, root)
            corpus_root = root / "lab" / "conformance"
            self.assertTrue(corpus_root.is_dir())
            manifest = json.loads((corpus_root / "corpus.json").read_bytes())
            snapshot_files = sorted((corpus_root / "snapshots").iterdir())
            history_files = sorted((corpus_root / "histories").iterdir())

            self.assertEqual(
                manifest["counts"],
                {"snapshots": 69, "histories": 55, "total": 124},
            )
            self.assertEqual(len(snapshot_files), 69)
            self.assertEqual(len(history_files), 55)
            self.assertTrue(
                all(
                    path.is_file() and not path.is_symlink()
                    for path in snapshot_files + history_files
                )
            )
            self.assertEqual(
                {
                    str(path.relative_to(corpus_root))
                    for path in snapshot_files + history_files
                },
                {row[2] for row in manifest["fixtures"]},
            )
            self.assertEqual(
                sorted(path.name for path in corpus_root.iterdir()),
                ["corpus.json", "histories", "snapshots"],
            )


class Layer1Tests(ConformanceTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = registry.load_task4_authority()

    def test_canonical_synthetic_corpus_passes_layer1(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            conformance.build_synthetic_corpus(self.authority, root)
            manifest = conformance.validate_layer1(self.authority, root)

        self.assertIn("format_version", manifest)
        self.assertEqual(manifest["format_version"], 1)
        self.assertEqual(len(manifest["fixtures"]), 124)
        self.assertEqual(len(manifest["validator_cases"]), 202)

    def test_layer1_self_tests_execute_every_admitted_corpus_case(self) -> None:
        self.assertEqual(conformance.run_layer1_self_tests(self.authority), 105)

    def test_cli_success_emits_no_unregistered_diagnostic(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "check-abstract-conformance.py"),
                "--self-test",
            ],
            cwd=SCRIPT_DIR.parent,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_coverage_rejects_unknown_id_without_cardinality_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            conformance.build_synthetic_corpus(self.authority, root)
            manifest_path = root / self.authority.core["paths"]["corpus_manifest"]
            manifest = json.loads(manifest_path.read_bytes())
            manifest["coverage"]["requirement-positive-reconstruction"][0] = (
                "unknown-registered-id"
            )
            manifest_path.write_text(
                json.dumps(manifest, separators=(",", ":")), encoding="utf-8"
            )

            with self.assertRaisesRegex(
                bounded_json.BoundedJsonError,
                "^abstract-conformance:layer-1:malformed$",
            ):
                conformance.validate_layer1(self.authority, root)

    def test_coverage_rejects_same_union_cross_tag_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            conformance.build_synthetic_corpus(self.authority, root)
            manifest_path = root / self.authority.core["paths"]["corpus_manifest"]
            manifest = json.loads(manifest_path.read_bytes())
            positive = manifest["coverage"]["requirement-positive-reconstruction"]
            changed = manifest["coverage"]["requirement-transcript-single-change"]
            positive[positive.index("valid-initial-base-profile")] = (
                "challenge-protocol-version-changed"
            )
            changed[changed.index("challenge-protocol-version-changed")] = (
                "valid-initial-base-profile"
            )
            manifest_path.write_text(
                json.dumps(manifest, separators=(",", ":")), encoding="utf-8"
            )

            with self.assertRaisesRegex(
                bounded_json.BoundedJsonError,
                "^abstract-conformance:layer-1:malformed$",
            ):
                conformance.validate_layer1(self.authority, root)

    def test_inventory_rejects_directory_swap_after_identity_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "candidate"
            root.mkdir()
            conformance.build_synthetic_corpus(self.authority, root)
            snapshot_directory = root / "lab" / "conformance" / "snapshots"
            external_directory = temporary_root / "external-snapshots"
            snapshot_identity = conformance.os.stat(snapshot_directory)
            original_scandir = conformance.os.scandir
            swapped = False

            def swap_before_scandir(path: Any = None) -> Any:
                nonlocal swapped
                checked_snapshot_path = not isinstance(path, int) and Path(
                    path
                ) == snapshot_directory
                checked_snapshot_descriptor = (
                    isinstance(path, int)
                    and conformance.os.fstat(path).st_dev == snapshot_identity.st_dev
                    and conformance.os.fstat(path).st_ino == snapshot_identity.st_ino
                )
                if not swapped and (
                    checked_snapshot_path or checked_snapshot_descriptor
                ):
                    swapped = True
                    conformance.os.rename(snapshot_directory, external_directory)
                    conformance.os.symlink(
                        external_directory,
                        snapshot_directory,
                        target_is_directory=True,
                    )
                return original_scandir(path)

            with mock.patch.object(
                conformance.os, "scandir", side_effect=swap_before_scandir
            ):
                with self.assertRaisesRegex(
                    bounded_json.BoundedJsonError,
                    "^abstract-conformance:layer-1:malformed$",
                ):
                    conformance.validate_layer1(self.authority, root)

            self.assertTrue(swapped)

    def test_inventory_rejects_manifest_replacement_after_bounded_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            conformance.build_synthetic_corpus(self.authority, root)
            manifest_path = root / self.authority.core["paths"]["corpus_manifest"]
            replacement_path = manifest_path.with_name("replacement.json")
            replacement_path.write_bytes(manifest_path.read_bytes())
            original_read_file = bounded_json._read_file
            replaced = False

            def replace_after_read(*args: Any, **kwargs: Any) -> Any:
                nonlocal replaced
                result = original_read_file(*args, **kwargs)
                if not replaced:
                    replaced = True
                    conformance.os.replace(replacement_path, manifest_path)
                return result

            with mock.patch.object(
                bounded_json, "_read_file", side_effect=replace_after_read
            ):
                with self.assertRaisesRegex(
                    bounded_json.BoundedJsonError,
                    "^abstract-conformance:layer-1:malformed$",
                ):
                    conformance.validate_layer1(self.authority, root)

            self.assertTrue(replaced)

    def test_inventory_rejects_manifest_metadata_drift_after_identity_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            conformance.build_synthetic_corpus(self.authority, root)
            manifest_path = root / self.authority.core["paths"]["corpus_manifest"]
            manifest_bytes = manifest_path.read_bytes()
            original_scandir = conformance.os.scandir
            scans = 0

            def modify_before_fixture_scan(path: Any = None) -> Any:
                nonlocal scans
                scans += 1
                if scans == 2:
                    manifest_path.write_bytes(manifest_bytes)
                return original_scandir(path)

            with mock.patch.object(
                conformance.os, "scandir", side_effect=modify_before_fixture_scan
            ):
                with self.assertRaisesRegex(
                    bounded_json.BoundedJsonError,
                    "^abstract-conformance:layer-1:malformed$",
                ):
                    conformance.validate_layer1(self.authority, root)

            self.assertGreaterEqual(scans, 2)

    def test_executable_table_rejects_expected_keys_with_none_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            conformance.build_synthetic_corpus(self.authority, root)
            empty_implementations = {
                identifier: None
                for identifier in self.authority.executable_transforms
            }

            with self.assertRaisesRegex(
                bounded_json.BoundedJsonError,
                "^abstract-conformance:layer-1:malformed$",
            ):
                conformance.validate_layer1(
                    self.authority,
                    root,
                    empty_implementations,
                )


class RegistryCaseTests(ConformanceTestCase):
    authority: registry.Task4Authority

    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = registry.load_task4_authority()

    def run_registry_case(self, case: registry.LoaderCase) -> None:
        runner = getattr(conformance, "run_layer1_case", None)
        if not callable(runner):
            self.fail("run_layer1_case is not callable")
        try:
            runner(self.authority, case)
        except AssertionError:
            self.fail("registry case rejected")


class Task5Tests(ConformanceTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        loader = getattr(registry, "load_task5_authority", None)
        if not callable(loader):
            raise AssertionError("load_task5_authority is not callable")
        cls.authority = loader()

    def build_complete_case_root(
        self, root: Path, case: registry.FixtureCase
    ) -> None:
        conformance.build_synthetic_corpus(self.authority, root)
        source = SCRIPT_DIR.parent / "lab" / "conformance" / case.path
        target = root / "lab" / "conformance" / case.path
        target.write_bytes(source.read_bytes())

    def assert_admitted_case_rejects_root(
        self,
        admission: Any,
        case: registry.FixtureCase,
        root: Path,
    ) -> None:
        with self.assertRaisesRegex(
            bounded_json.BoundedJsonError,
            "^abstract-conformance:layer-2:malformed$",
        ) as caught:
            conformance.run_admitted_early_fixture_case(
                self.authority,
                admission,
                case.identifier,
                root,
            )
        self.assertEqual(caught.exception.category, "identity")
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.line)
        self.assertIsNone(caught.exception.column)
        self.assertIsNone(caught.exception.context)
        rendered = repr(caught.exception)
        self.assertNotIn(str(root), rendered)

    def assert_final_entry_directory_race_is_rejected(
        self, case: registry.FixtureCase
    ) -> None:
        original_open = bounded_json.os.open
        original_read = bounded_json.os.read
        replaced = False
        fixture_reads = 0

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_complete_case_root(root, case)
            admission = conformance.admit_layer1(self.authority, root)
            fixture = root / "lab" / "conformance" / case.path
            moved = fixture.with_suffix(".admitted")

            def replace_before_final_open(
                path: Any,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal replaced
                if path == fixture.name and dir_fd is not None and not replaced:
                    fixture.replace(moved)
                    fixture.mkdir()
                    replaced = True
                return original_open(path, flags, mode, dir_fd=dir_fd)

            def observed_read(file_descriptor: int, count: int) -> bytes:
                nonlocal fixture_reads
                fixture_reads += 1
                return original_read(file_descriptor, count)

            with mock.patch.object(
                bounded_json.os, "open", side_effect=replace_before_final_open
            ), mock.patch.object(
                bounded_json.os, "read", side_effect=observed_read
            ):
                self.assert_admitted_case_rejects_root(admission, case, root)

            self.assertTrue(replaced)
            self.assertTrue(fixture.is_dir())
            self.assertTrue(moved.is_file())
            self.assertEqual(fixture_reads, 0)

    def test_early_case_rejects_manifest_before_exposing_expectation(self) -> None:
        case = self.authority.fixture_cases[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_complete_case_root(root, case)
            manifest = root / self.authority.core["paths"]["corpus_manifest"]
            manifest.write_bytes(b"{}")

            with self.assertRaisesRegex(
                bounded_json.BoundedJsonError,
                "^abstract-conformance:layer-1:malformed$",
            ):
                conformance.run_early_fixture_case(self.authority, case, root)

    def test_task5_only_corpus_cannot_produce_admission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            conformance.build_task5_corpus(self.authority, root)
            with self.assertRaisesRegex(
                bounded_json.BoundedJsonError,
                "^abstract-conformance:layer-1:malformed$",
            ):
                conformance.admit_layer1(self.authority, root)

    def test_layer1_admission_manifest_is_immutable_evidence(self) -> None:
        case = self.authority.fixture_cases[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_complete_case_root(root, case)
            admission = conformance.admit_layer1(self.authority, root)
            admission._manifest_value()["fixtures"].clear()

            self.assertEqual(
                conformance.run_admitted_early_fixture_case(
                    self.authority, admission, case.identifier, root
                ),
                (case.checkpoint, case.disposition),
            )

    def test_layer1_admission_rejects_public_construction(self) -> None:
        with self.assertRaisesRegex(
            TypeError, "^layer-1 admissions are produced only by admit_layer1$"
        ):
            conformance.Layer1Admission(object(), {}, object())

    def test_post_admission_fixture_identity_drift_is_rejected(self) -> None:
        for case in self.authority.fixture_cases[:2]:
            for mutation in ("replacement", "metadata"):
                with self.subTest(identifier=case.identifier, mutation=mutation):
                    with tempfile.TemporaryDirectory() as temporary:
                        root = Path(temporary)
                        self.build_complete_case_root(root, case)
                        admission = conformance.admit_layer1(self.authority, root)
                        fixture = root / "lab" / "conformance" / case.path
                        if mutation == "replacement":
                            replacement = fixture.with_suffix(".replacement")
                            replacement.write_bytes(fixture.read_bytes())
                            replacement.replace(fixture)
                        else:
                            state = fixture.stat()
                            os.utime(
                                fixture,
                                ns=(state.st_atime_ns, state.st_mtime_ns + 1_000_000),
                            )

                        with self.assertRaisesRegex(
                            bounded_json.BoundedJsonError,
                            "^abstract-conformance:layer-2:malformed$",
                        ) as caught:
                            conformance.run_admitted_early_fixture_case(
                                self.authority,
                                admission,
                                case.identifier,
                                root,
                            )
                        self.assertIsNone(caught.exception.__cause__)

    def test_layer1_admission_rejects_out_of_root_hard_link_replay(self) -> None:
        case = self.authority.fixture_cases[1]
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            admitted_root = base / "admitted"
            admitted_root.mkdir()
            self.build_complete_case_root(admitted_root, case)

            replay_root = base / "replay"
            replay_fixture = replay_root / "lab" / "conformance" / case.path
            replay_fixture.parent.mkdir(parents=True)
            admitted_fixture = admitted_root / "lab" / "conformance" / case.path
            os.link(admitted_fixture, replay_fixture)
            admission = conformance.admit_layer1(self.authority, admitted_root)
            self.assertFalse(
                (replay_root / self.authority.core["paths"]["corpus_manifest"])
                .exists()
            )

            self.assert_admitted_case_rejects_root(admission, case, replay_root)

    def test_layer1_admission_rejects_root_replacement(self) -> None:
        case = self.authority.fixture_cases[1]
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            root.mkdir()
            self.build_complete_case_root(root, case)
            replacement = base / "replacement"
            replay_fixture = replacement / "lab" / "conformance" / case.path
            replay_fixture.parent.mkdir(parents=True)
            os.link(root / "lab" / "conformance" / case.path, replay_fixture)
            admission = conformance.admit_layer1(self.authority, root)

            moved = base / "moved"
            root.replace(moved)
            replacement.replace(root)

            self.assert_admitted_case_rejects_root(admission, case, root)

    def test_layer2_admission_rejects_root_symlink_to_admitted_directory(
        self,
    ) -> None:
        case = self.authority.fixture_cases[0]
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            root.mkdir()
            self.build_complete_case_root(root, case)
            admission = conformance.admit_layer1(self.authority, root)

            moved = base / "admitted"
            root.replace(moved)
            root.symlink_to(moved.name, target_is_directory=True)

            self.assert_admitted_case_rejects_root(admission, case, root)

    def test_layer3_admission_rejects_root_symlink_to_admitted_directory(
        self,
    ) -> None:
        case = self.authority.fixture_cases[1]
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            root.mkdir()
            self.build_complete_case_root(root, case)
            admission = conformance.admit_layer1(self.authority, root)

            moved = base / "admitted"
            root.replace(moved)
            root.symlink_to(moved.name, target_is_directory=True)

            self.assert_admitted_case_rejects_root(admission, case, root)

    def test_layer2_admission_rejects_final_entry_directory_race(self) -> None:
        self.assert_final_entry_directory_race_is_rejected(
            self.authority.fixture_cases[0]
        )

    def test_layer3_admission_rejects_final_entry_directory_race(self) -> None:
        self.assert_final_entry_directory_race_is_rejected(
            self.authority.fixture_cases[1]
        )

    def test_layer1_admission_rejects_fixture_directory_substitution(self) -> None:
        case = self.authority.fixture_cases[1]
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            root.mkdir()
            self.build_complete_case_root(root, case)

            fixture_directory = (
                root / "lab" / "conformance" / Path(case.path).parent
            )
            replacement = base / "snapshots-replay"
            replacement.mkdir()
            os.link(
                fixture_directory / Path(case.path).name,
                replacement / Path(case.path).name,
            )
            admission = conformance.admit_layer1(self.authority, root)

            moved = fixture_directory.with_name("snapshots-admitted")
            fixture_directory.replace(moved)
            replacement.replace(fixture_directory)

            self.assert_admitted_case_rejects_root(admission, case, root)

    def test_layer1_admission_rejects_ancestor_directory_substitution(self) -> None:
        case = self.authority.fixture_cases[1]
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            root.mkdir()
            self.build_complete_case_root(root, case)
            replacement = base / "lab-replay"
            replay_fixture = replacement / "conformance" / case.path
            replay_fixture.parent.mkdir(parents=True)
            os.link(root / "lab" / "conformance" / case.path, replay_fixture)
            admission = conformance.admit_layer1(self.authority, root)

            (root / "lab").replace(base / "lab-admitted")
            replacement.replace(root / "lab")

            self.assert_admitted_case_rejects_root(admission, case, root)

    def test_layer1_admission_rejects_symlinked_directory_alias(self) -> None:
        case = self.authority.fixture_cases[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_complete_case_root(root, case)
            admission = conformance.admit_layer1(self.authority, root)
            fixture_directory = (
                root / "lab" / "conformance" / Path(case.path).parent
            )
            moved = fixture_directory.with_name("snapshots-admitted")
            fixture_directory.replace(moved)
            fixture_directory.symlink_to(moved.name, target_is_directory=True)

            self.assert_admitted_case_rejects_root(admission, case, root)

    def test_layer1_admission_rejects_hierarchy_metadata_drift(self) -> None:
        case = self.authority.fixture_cases[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_complete_case_root(root, case)
            admission = conformance.admit_layer1(self.authority, root)
            fixture_directory = (
                root / "lab" / "conformance" / Path(case.path).parent
            )
            state = fixture_directory.stat()
            os.utime(
                fixture_directory,
                ns=(state.st_atime_ns, state.st_mtime_ns + 1_000_000),
            )

            self.assert_admitted_case_rejects_root(admission, case, root)

    def test_task5_authority_preserves_early_fixture_registry_order(self) -> None:
        expected = [
            row[0]
            for row in self.authority.manifest["fixtures"]
            if row[5] in {"layer-2", "layer-3"}
        ]
        actual = [case.identifier for case in self.authority.fixture_cases]
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 10)
        self.assertEqual(actual[0], "fixture-duplicate-object-name")
        self.assertEqual(actual[-1], "history-unknown-time-domain-substitution")

    def test_admitted_early_baselines_pass_layer3_shape(self) -> None:
        for identifier in (
            "valid-initial-base-profile",
            "history-valid-initial-collection",
        ):
            with self.subTest(identifier=identifier):
                self.assertEqual(
                    conformance._fixture_shape_result(
                        self.authority,
                        self.authority.baselines[identifier],
                    ),
                    ("layer-4", "Conform"),
                )

    def test_fixture_shape_uses_registry_kind_and_schema_pairing(self) -> None:
        authority = copy.deepcopy(self.authority)
        schemas = authority.validators["schemas"]
        envelope = schemas["FixtureEnvelope"]
        candidate_ref = envelope["properties"]["candidate"]["union"][0]["ref"]
        renamed_ref = "RenamedSnapshotCandidate"
        schemas[renamed_ref] = schemas.pop(candidate_ref)
        envelope["properties"]["candidate"]["union"][0]["ref"] = renamed_ref
        authority.validators["domains"]["FixtureKind"]["values"][0] = "snapshot-v2"
        value = copy.deepcopy(authority.baselines["valid-initial-base-profile"])
        value["kind"] = "snapshot-v2"

        self.assertEqual(
            conformance._fixture_shape_result(authority, value),
            ("layer-4", "Conform"),
        )

    def test_fixture_shape_uses_registry_criticality_membership(self) -> None:
        authority = copy.deepcopy(self.authority)
        case = next(
            item
            for item in authority.fixture_cases
            if item.identifier == "unknown-critical-semantic"
        )
        value = json.loads(conformance.reproduce_early_fixture(authority, case))
        replacement = "future-criticality-v2"
        authority.validators["domains"]["Criticality"]["values"][0] = replacement
        authority.transforms[case.transform]["new"]["value"]["criticality"] = replacement
        value["candidate"]["transcript"]["test_only_semantic"][
            "criticality"
        ] = replacement

        self.assertEqual(
            conformance._fixture_shape_result(authority, value),
            ("layer-3", "Unsupported"),
        )

    def test_fixture_shape_uses_registry_time_domain_membership(self) -> None:
        authority = copy.deepcopy(self.authority)
        replacement = "protected-clock-v2"
        authority.validators["domains"]["TimeDomain"]["values"][0] = replacement
        for transform in authority.transforms.values():
            pointer = transform.get("path") or transform.get("pointer") or ""
            if pointer.endswith("/time_domain"):
                transform["old"] = replacement
        value = copy.deepcopy(
            authority.baselines["history-valid-initial-collection"]
        )
        value["candidate"]["collections"][0]["time_domain"] = replacement

        self.assertEqual(
            conformance._fixture_shape_result(authority, value),
            ("layer-4", "Conform"),
        )

    def test_fixture_shape_uses_registry_unknown_time_domain_outcome(self) -> None:
        authority = copy.deepcopy(self.authority)
        case = next(
            item
            for item in authority.fixture_cases
            if item.identifier == "history-unknown-time-domain-substitution"
        )
        value = json.loads(conformance.reproduce_early_fixture(authority, case))
        replacement = "future-time-domain-v2"
        authority.validators["domains"]["TimeDomain"]["values"][2] = replacement
        authority.transforms[case.transform]["value"] = replacement
        value["candidate"]["collections"][0]["time_domain"] = replacement

        self.assertEqual(
            conformance._fixture_shape_result(authority, value),
            ("layer-3", "Unsupported"),
        )

    def test_task5_corpus_has_complete_manifest_and_only_early_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            conformance.build_task5_corpus(self.authority, root)
            corpus_root = root / "lab" / "conformance"
            manifest_path = corpus_root / "corpus.json"
            fixture_paths = sorted(
                path.relative_to(corpus_root).as_posix()
                for directory in ("snapshots", "histories")
                for path in (corpus_root / directory).iterdir()
            )

            self.assertEqual(
                manifest_path.read_bytes(),
                conformance._manifest_bytes(self.authority.manifest),
            )
            self.assertEqual(
                fixture_paths,
                sorted(case.path for case in self.authority.fixture_cases),
            )
            self.assertEqual(json.loads(manifest_path.read_bytes())["counts"], {
                "snapshots": 69,
                "histories": 55,
                "total": 124,
            })

    def test_checked_in_task5_fixtures_match_admitted_reproduction(self) -> None:
        corpus_root = SCRIPT_DIR.parent / "lab" / "conformance"
        self.assertEqual(
            (corpus_root / "corpus.json").read_bytes(),
            conformance._manifest_bytes(self.authority.manifest),
        )
        actual_paths = sorted(
            path.relative_to(corpus_root).as_posix()
            for directory in ("snapshots", "histories")
            for path in (corpus_root / directory).iterdir()
        )
        self.assertTrue(
            set(case.path for case in self.authority.fixture_cases)
            <= set(actual_paths)
        )
        for case in self.authority.fixture_cases:
            self.assertEqual(
                (corpus_root / case.path).read_bytes(),
                conformance.reproduce_early_fixture(self.authority, case),
            )

    def test_layer2_stops_before_shape_validation(self) -> None:
        case = self.authority.fixture_cases[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_complete_case_root(root, case)
            with mock.patch.object(
                conformance,
                "_fixture_shape_result",
                side_effect=AssertionError("later layer reached"),
            ) as shape:
                self.assertEqual(
                    conformance.run_early_fixture_case(self.authority, case, root),
                    ("layer-2", "Malformed"),
                )
            shape.assert_not_called()

    def test_reproduction_mismatch_stops_before_shape_validation(self) -> None:
        case = self.authority.fixture_cases[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_complete_case_root(root, case)
            fixture = root / "lab" / "conformance" / case.path
            value = json.loads(fixture.read_bytes())
            value["oracle"]["expected_context"]["game"] = "game-beta"
            fixture.write_bytes(conformance._manifest_bytes(value))
            with mock.patch.object(conformance, "_fixture_shape_result") as shape:
                with self.assertRaisesRegex(
                    AssertionError, "^fixture reproduction mismatch$"
                ):
                    conformance.run_early_fixture_case(self.authority, case, root)
            shape.assert_not_called()

    def test_fixture_reproduction_and_admission_use_one_file_read(self) -> None:
        for case in self.authority.fixture_cases[:2]:
            with self.subTest(identifier=case.identifier):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.build_complete_case_root(root, case)
                    with mock.patch.object(
                        bounded_json,
                        "_read_file",
                        wraps=bounded_json._read_file,
                    ) as read_file:
                        conformance.run_early_fixture_case(self.authority, case, root)
                    relative = str(
                        Path(self.authority.core["paths"]["corpus_manifest"]).parent
                        / case.path
                    )
                    fixture_reads = [
                        call
                        for call in read_file.call_args_list
                        if call.args[1] == relative
                    ]
                    self.assertEqual(len(fixture_reads), 1)

    def test_layer3_reproduction_ignores_only_object_member_order(self) -> None:
        case = self.authority.fixture_cases[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_complete_case_root(root, case)
            fixture = root / "lab" / "conformance" / case.path
            value = json.loads(fixture.read_bytes())
            fixture.write_text(
                json.dumps(dict(reversed(list(value.items()))), indent=2),
                encoding="utf-8",
            )

            self.assertEqual(
                conformance.run_early_fixture_case(self.authority, case, root),
                ("layer-3", "Malformed"),
            )

    def test_layer3_reproduction_distinguishes_boolean_from_integer(self) -> None:
        case = self.authority.fixture_cases[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_complete_case_root(root, case)
            fixture = root / "lab" / "conformance" / case.path
            value = json.loads(fixture.read_bytes())
            value["format_version"] = True
            fixture.write_bytes(conformance._manifest_bytes(value))
            with mock.patch.object(conformance, "_fixture_shape_result") as shape:
                with self.assertRaisesRegex(
                    AssertionError, "^fixture reproduction mismatch$"
                ):
                    conformance.run_early_fixture_case(self.authority, case, root)
            shape.assert_not_called()

    def test_layer3_reproduction_preserves_array_order(self) -> None:
        case = self.authority.fixture_cases[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_complete_case_root(root, case)
            fixture = root / "lab" / "conformance" / case.path
            value = json.loads(fixture.read_bytes())
            claims = value["candidate"]["transcript"]["claims"]
            claims[0], claims[1] = claims[1], claims[0]
            fixture.write_bytes(conformance._manifest_bytes(value))
            with mock.patch.object(conformance, "_fixture_shape_result") as shape:
                with self.assertRaisesRegex(
                    AssertionError, "^fixture reproduction mismatch$"
                ):
                    conformance.run_early_fixture_case(self.authority, case, root)
            shape.assert_not_called()

    def run_early_case(self, identifier: str) -> None:
        case = next(
            case for case in self.authority.fixture_cases
            if case.identifier == identifier
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_complete_case_root(root, case)
            baseline_before = copy.deepcopy(self.authority.baselines[case.baseline])
            expected = conformance.reproduce_early_fixture(self.authority, case)
            fixture = root / "lab" / "conformance" / case.path

            self.assertEqual(fixture.read_bytes(), expected)
            if case.checkpoint == "layer-3":
                baseline = self.authority.baselines[case.baseline]
                self.assertEqual(
                    json.loads(fixture.read_bytes())["oracle"],
                    baseline["oracle"],
                )
            try:
                actual = conformance.run_early_fixture_case(self.authority, case, root)
            except AssertionError:
                self.fail("early fixture case rejected")
            self.assertEqual(actual, (case.checkpoint, case.disposition))
            self.assertEqual(self.authority.baselines[case.baseline], baseline_before)


class Task6AuthorityTests(ConformanceTestCase):
    def test_task6_authority_is_snapshot_only_and_registry_ordered(self) -> None:
        authority = registry.load_task6_authority()
        manifest_rows = [
            row for row in authority.manifest["fixtures"] if row[1] == "snapshot"
        ]

        self.assertEqual(
            [case.identifier for case in authority.snapshot_cases],
            [row[0] for row in manifest_rows],
        )
        self.assertEqual(len(authority.snapshot_cases), 69)
        self.assertEqual(len(authority.focused_rows), 58)
        self.assertEqual(
            authority.focused_rows,
            tuple(
                tuple(row)
                for row in authority.snapshots["focused_expected_tuples"]
            ),
        )

    def test_task6_authority_returns_independent_values(self) -> None:
        first = registry.load_task6_authority()
        second = registry.load_task6_authority()
        first.manifest["fixtures"].clear()
        first.baselines["valid-initial-base-profile"]["oracle"].clear()

        self.assertEqual(len(second.manifest["fixtures"]), 124)
        self.assertIn(
            "authenticated_challenge",
            second.baselines["valid-initial-base-profile"]["oracle"],
        )


class Task6SnapshotTests(ConformanceTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = registry.load_task6_authority()

    def require_callable(self, name: str) -> Any:
        function = getattr(conformance, name, None)
        self.assertTrue(callable(function), f"{name} is not callable")
        return function

    def transformed_fixture(self, identifier: str) -> tuple[Any, Any, Any]:
        case = next(
            case for case in self.authority.snapshot_cases
            if case.identifier == identifier
        )
        transform = self.authority.transforms[case.transform]
        baseline = copy.deepcopy(self.authority.baselines[case.baseline])
        return case, transform, conformance._apply_fixture_transform(
            baseline, transform
        )

    def build_complete_snapshot_root(self, root: Path) -> None:
        conformance.build_synthetic_corpus(self.authority, root)
        corpus_root = root / "lab" / "conformance"
        for case in self.authority.snapshot_cases:
            (corpus_root / case.path).write_bytes(
                conformance.reproduce_snapshot_fixture(self.authority, case)
            )

    def test_reproduces_and_materializes_all_admitted_snapshots(self) -> None:
        reproduce = self.require_callable("reproduce_snapshot_fixture")
        build = self.require_callable("build_task6_corpus")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build(self.authority, root)
            corpus_root = root / "lab" / "conformance"
            snapshots = sorted(
                path.relative_to(corpus_root).as_posix()
                for path in (corpus_root / "snapshots").iterdir()
            )
            histories = sorted(
                path.relative_to(corpus_root).as_posix()
                for path in (corpus_root / "histories").iterdir()
            )

            self.assertEqual(
                snapshots,
                sorted(case.path for case in self.authority.snapshot_cases),
            )
            self.assertEqual(
                histories,
                [
                    "histories/history-client-utc-substitution.json",
                    "histories/history-unknown-time-domain-substitution.json",
                ],
            )
            for case in self.authority.snapshot_cases:
                self.assertEqual(
                    (corpus_root / case.path).read_bytes(),
                    reproduce(self.authority, case),
                )

    def test_materialization_updates_the_existing_task5_corpus(self) -> None:
        build = self.require_callable("build_task6_corpus")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            conformance.build_synthetic_corpus(self.authority, root)

            build(self.authority, root)

            self.assertEqual(
                len(list((root / "lab" / "conformance" / "snapshots").iterdir())),
                69,
            )

    def test_reconstruction_is_independent_and_immutable(self) -> None:
        reconstruct = self.require_callable("reconstruct_snapshot")
        baseline = copy.deepcopy(
            self.authority.baselines["valid-initial-base-profile"]
        )
        candidate_before = copy.deepcopy(baseline["candidate"])
        oracle_before = copy.deepcopy(baseline["oracle"])
        case, _transform, changed = self.transformed_fixture(
            "challenge-protocol-version-changed"
        )

        baseline_result, reconstructed = reconstruct(
            self.authority, baseline["candidate"], baseline["oracle"]
        )
        changed_result, changed_reconstruction = reconstruct(
            self.authority, changed["candidate"], changed["oracle"]
        )

        self.assertEqual(baseline_result, "Conform")
        self.assertIsNotNone(reconstructed)
        self.assertEqual(changed_result, case.disposition)
        self.assertIsNone(changed_reconstruction)
        self.assertEqual(baseline["candidate"], candidate_before)
        self.assertEqual(baseline["oracle"], oracle_before)

    def test_reconstruction_rejects_coherent_profile_provenance_drift(self) -> None:
        baseline = copy.deepcopy(
            self.authority.baselines["valid-initial-base-profile"]
        )
        baseline["candidate"]["transcript"]["claims"][1]["provenance"] = (
            "trusted-agent-observed"
        )
        baseline["oracle"]["expected_claims"][1]["provenance"] = (
            "trusted-agent-observed"
        )

        self.assertEqual(
            conformance.reconstruct_snapshot(
                self.authority, baseline["candidate"], baseline["oracle"]
            ),
            ("EvidenceInvalid", None),
        )

    def test_reconstruction_rejects_coherent_profile_authority_drift(self) -> None:
        baseline = copy.deepcopy(
            self.authority.baselines["valid-initial-base-profile"]
        )
        baseline["candidate"]["transcript"]["evidence_time"][
            "authority_contract"
        ] = "authority-beta"
        baseline["oracle"]["expected_evidence_time"]["authority_contract"] = (
            "authority-beta"
        )

        self.assertEqual(
            conformance.reconstruct_snapshot(
                self.authority, baseline["candidate"], baseline["oracle"]
            ),
            ("EvidenceInvalid", None),
        )

    def test_reconstruction_rejects_coherent_duration_over_profile_ceiling(self) -> None:
        baseline = copy.deepcopy(
            self.authority.baselines["valid-initial-base-profile"]
        )
        baseline["candidate"]["transcript"]["evidence_time"][
            "snapshot_freeze_end"
        ] = 1201
        baseline["oracle"]["expected_evidence_time"]["snapshot_freeze_end"] = 1201

        self.assertEqual(
            conformance.reconstruct_snapshot(
                self.authority, baseline["candidate"], baseline["oracle"]
            ),
            ("EvidenceInvalid", None),
        )

    def test_reconstruction_rejects_each_renewal_high_water_drift(self) -> None:
        def authority_drift(value: Any) -> None:
            value["oracle"]["prior_temporal_state"]["authority_contract"] = (
                "authority-beta"
            )

        def epoch_drift(value: Any) -> None:
            value["oracle"]["prior_temporal_state"]["epoch_relation"] = "epoch-beta"

        def sequence_reuse(value: Any) -> None:
            value["candidate"]["transcript"]["evidence_time"]["sequence"] = 1
            value["oracle"]["expected_evidence_time"]["sequence"] = 1

        def interval_overlap(value: Any) -> None:
            evidence_time = value["candidate"]["transcript"]["evidence_time"]
            evidence_time["collection_start"] = 1199
            evidence_time["snapshot_freeze_end"] = 1299
            value["oracle"]["expected_evidence_time"] = copy.deepcopy(evidence_time)

        for name, mutate in (
            ("authority", authority_drift),
            ("epoch", epoch_drift),
            ("sequence", sequence_reuse),
            ("interval", interval_overlap),
        ):
            baseline = copy.deepcopy(
                self.authority.baselines["valid-same-session-renewal"]
            )
            mutate(baseline)
            with self.subTest(relationship=name):
                self.assertEqual(
                    conformance.reconstruct_snapshot(
                        self.authority, baseline["candidate"], baseline["oracle"]
                    ),
                    ("EvidenceInvalid", None),
                )

    def test_context_stimulus_result_depends_on_replacement_disagreement(self) -> None:
        _case, _transform, changed = self.transformed_fixture(
            "evidence-reused-for-account"
        )
        changed["candidate"]["transcript"]["test_only_semantic"]["replacement"] = {
            "kind": "scalar",
            "token": changed["oracle"]["expected_context"]["account"],
        }

        result, reconstructed = conformance.reconstruct_snapshot(
            self.authority, changed["candidate"], changed["oracle"]
        )

        self.assertEqual(result, "Conform")
        self.assertIsNotNone(reconstructed)

    def test_policy_stimulus_compares_the_independent_policy_identifier(self) -> None:
        for token, expected in (
            ("policy-ranked", "Conform"),
            ("policy-casual", "ContextBindingMismatch"),
        ):
            _case, _transform, changed = self.transformed_fixture(
                "evidence-reused-for-policy"
            )
            changed["candidate"]["transcript"]["test_only_semantic"][
                "replacement"
            ]["token"] = token
            with self.subTest(expected=expected):
                self.assertEqual(
                    conformance._fixture_shape_result(self.authority, changed),
                    ("layer-4", "Conform"),
                )
                result, reconstructed = conformance.reconstruct_snapshot(
                    self.authority, changed["candidate"], changed["oracle"]
                )
                self.assertEqual(result, expected)
                self.assertEqual(reconstructed is not None, expected == "Conform")

    def test_key_stimulus_result_depends_on_replacement_disagreement(self) -> None:
        _case, _transform, changed = self.transformed_fixture(
            "key-reused-after-publisher-change"
        )
        changed["candidate"]["transcript"]["test_only_semantic"]["replacement"] = {
            "kind": "scalar",
            "token": changed["oracle"]["resolved_key"]["publisher"],
        }

        result, reconstructed = conformance.reconstruct_snapshot(
            self.authority, changed["candidate"], changed["oracle"]
        )

        self.assertEqual(result, "Conform")
        self.assertIsNotNone(reconstructed)

    def test_current_process_stimulus_uses_independent_appraisal_value(self) -> None:
        _case, _transform, changed = self.transformed_fixture(
            "renewal-claims-not-current"
        )
        accepted = next(
            row["value"]
            for row in changed["oracle"]["appraisal"]["acceptable_claim_values"]
            if row["meaning"] == "process-binding-identity"
        )
        changed["candidate"]["transcript"]["test_only_semantic"]["replacement"] = (
            copy.deepcopy(accepted)
        )

        result, reconstructed = conformance.reconstruct_snapshot(
            self.authority, changed["candidate"], changed["oracle"]
        )
        self.assertEqual(result, "Conform")
        self.assertIsNotNone(reconstructed)
        assert reconstructed is not None
        self.assertEqual(
            conformance.check_snapshot_coverage(
                self.authority, changed["candidate"]["coverage"], reconstructed
            ),
            "Conform",
        )
        self.assertEqual(
            conformance.appraise_snapshot(
                self.authority,
                changed["candidate"],
                changed["oracle"],
                reconstructed,
            ),
            "Conform",
        )

    def test_current_process_appraisal_does_not_depend_on_transform_inventory(self) -> None:
        _case, _transform, changed = self.transformed_fixture(
            "renewal-claims-not-current"
        )
        authority = registry.load_task6_authority()
        authority.transforms.clear()

        result, reconstructed = conformance.reconstruct_snapshot(
            authority, changed["candidate"], changed["oracle"]
        )

        self.assertEqual(result, "Conform")
        self.assertIsNotNone(reconstructed)
        assert reconstructed is not None
        self.assertEqual(
            conformance.appraise_snapshot(
                authority, changed["candidate"], changed["oracle"], reconstructed
            ),
            "EvidenceInvalid",
        )

    def test_semantic_stimuli_do_not_depend_on_transform_inventory(self) -> None:
        semantic_cases = []
        for case in self.authority.snapshot_cases:
            if case.transform is None:
                continue
            transform = self.authority.transforms[case.transform]
            if transform.get("pointer") != "/candidate/transcript/test_only_semantic":
                continue
            if case.checkpoint not in {"layer-4", "layer-6"}:
                continue
            semantic_cases.append((
                case,
                conformance._apply_fixture_transform(
                    self.authority.baselines[case.baseline], transform
                ),
            ))
        authority = registry.load_task6_authority()
        authority.transforms.clear()

        for case, changed in semantic_cases:
            with self.subTest(identifier=case.identifier):
                result, reconstructed = conformance.reconstruct_snapshot(
                    authority, changed["candidate"], changed["oracle"]
                )
                if case.checkpoint == "layer-4":
                    self.assertEqual(result, case.disposition)
                    continue
                self.assertEqual(result, "Conform")
                self.assertIsNotNone(reconstructed)
                assert reconstructed is not None
                self.assertEqual(
                    conformance.check_snapshot_coverage(
                        authority, changed["candidate"]["coverage"], reconstructed
                    ),
                    "Conform",
                )
                self.assertEqual(
                    conformance.appraise_snapshot(
                        authority,
                        changed["candidate"],
                        changed["oracle"],
                        reconstructed,
                    ),
                    case.disposition,
                )

    def test_coverage_is_exact_and_independent(self) -> None:
        reconstruct = self.require_callable("reconstruct_snapshot")
        coverage = self.require_callable("check_snapshot_coverage")
        baseline = copy.deepcopy(
            self.authority.baselines["valid-initial-base-profile"]
        )
        reconstruction_result, reconstructed = reconstruct(
            self.authority, baseline["candidate"], baseline["oracle"]
        )
        self.assertEqual(reconstruction_result, "Conform")
        self.assertIsNotNone(reconstructed)
        assert reconstructed is not None
        case, _transform, changed = self.transformed_fixture(
            "evidence-binding-used-for-protected-result"
        )

        self.assertEqual(
            coverage(self.authority, baseline["candidate"]["coverage"], reconstructed),
            "Conform",
        )
        self.assertEqual(
            coverage(self.authority, changed["candidate"]["coverage"], reconstructed),
            case.disposition,
        )

    def test_coverage_rejects_every_entry_omission_substitution_and_duplicate(self) -> None:
        for baseline_id, baseline_value in self.authority.baselines.items():
            baseline = copy.deepcopy(baseline_value)
            result, reconstructed = conformance.reconstruct_snapshot(
                self.authority, baseline["candidate"], baseline["oracle"]
            )
            self.assertEqual(result, "Conform", baseline_id)
            self.assertIsNotNone(reconstructed, baseline_id)
            assert reconstructed is not None
            coverage = baseline["candidate"]["coverage"]
            self.assertEqual(
                conformance.check_snapshot_coverage(
                    self.authority, coverage, reconstructed
                ),
                "Conform",
                baseline_id,
            )
            for index, entry in enumerate(coverage):
                with self.subTest(baseline=baseline_id, index=index, mutation="omit"):
                    mutated = copy.deepcopy(coverage)
                    del mutated[index]
                    self.assertEqual(
                        conformance.check_snapshot_coverage(
                            self.authority, mutated, reconstructed
                        ),
                        "EvidenceInvalid",
                    )
                with self.subTest(
                    baseline=baseline_id, index=index, mutation="substitute"
                ):
                    mutated = copy.deepcopy(coverage)
                    mutated[index]["value"] = None
                    self.assertEqual(
                        conformance.check_snapshot_coverage(
                            self.authority, mutated, reconstructed
                        ),
                        "EvidenceInvalid",
                    )
                with self.subTest(
                    baseline=baseline_id, index=index, mutation="duplicate"
                ):
                    mutated = copy.deepcopy(coverage)
                    mutated.insert(index, copy.deepcopy(entry))
                    self.assertEqual(
                        conformance.check_snapshot_coverage(
                            self.authority, mutated, reconstructed
                        ),
                        "EvidenceInvalid",
                    )

    def test_coverage_rejects_every_relationship_mutation(self) -> None:
        for baseline_id, baseline_value in self.authority.baselines.items():
            baseline = copy.deepcopy(baseline_value)
            result, reconstructed = conformance.reconstruct_snapshot(
                self.authority, baseline["candidate"], baseline["oracle"]
            )
            self.assertEqual(result, "Conform", baseline_id)
            self.assertIsNotNone(reconstructed, baseline_id)
            assert reconstructed is not None
            coverage = baseline["candidate"]["coverage"]
            self.assertEqual(
                conformance.check_snapshot_coverage(
                    self.authority, coverage, reconstructed
                ),
                "Conform",
                baseline_id,
            )
            for index, entry in enumerate(coverage):
                for relationship_index, relationship in enumerate(
                    entry["relationships"]
                ):
                    with self.subTest(
                        baseline=baseline_id,
                        index=index,
                        relationship=relationship,
                        mutation="omit",
                    ):
                        mutated = copy.deepcopy(coverage)
                        del mutated[index]["relationships"][relationship_index]
                        self.assertEqual(
                            conformance.check_snapshot_coverage(
                                self.authority, mutated, reconstructed
                            ),
                            "EvidenceInvalid",
                        )
                    with self.subTest(
                        baseline=baseline_id,
                        index=index,
                        relationship=relationship,
                        mutation="substitute",
                    ):
                        mutated = copy.deepcopy(coverage)
                        mutated[index]["relationships"][relationship_index] = (
                            "wrong-relationship"
                        )
                        self.assertEqual(
                            conformance.check_snapshot_coverage(
                                self.authority, mutated, reconstructed
                            ),
                            "EvidenceInvalid",
                        )

    def test_coverage_rejects_component_and_entry_order_substitution(self) -> None:
        for baseline_id, baseline_value in self.authority.baselines.items():
            baseline = copy.deepcopy(baseline_value)
            result, reconstructed = conformance.reconstruct_snapshot(
                self.authority, baseline["candidate"], baseline["oracle"]
            )
            self.assertEqual(result, "Conform", baseline_id)
            self.assertIsNotNone(reconstructed, baseline_id)
            assert reconstructed is not None
            coverage = baseline["candidate"]["coverage"]
            self.assertEqual(
                conformance.check_snapshot_coverage(
                    self.authority, coverage, reconstructed
                ),
                "Conform",
                baseline_id,
            )
            for index in range(len(coverage)):
                with self.subTest(baseline=baseline_id, index=index):
                    mutated = copy.deepcopy(coverage)
                    mutated[index]["component"] += "-wrong"
                    self.assertEqual(
                        conformance.check_snapshot_coverage(
                            self.authority, mutated, reconstructed
                        ),
                        "EvidenceInvalid",
                    )
            reordered = copy.deepcopy(coverage)
            reordered[0], reordered[1] = reordered[1], reordered[0]
            self.assertEqual(
                conformance.check_snapshot_coverage(
                    self.authority, reordered, reconstructed
                ),
                "EvidenceInvalid",
                baseline_id,
            )

    def test_coverage_derivation_observes_every_reconstructed_field_and_claim(self) -> None:
        def scalar_mutations(value: Any, path: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
            if isinstance(value, dict):
                return [
                    nested
                    for key, child in value.items()
                    for nested in scalar_mutations(child, path + (key,))
                ]
            if isinstance(value, list):
                return [
                    nested
                    for index, child in enumerate(value)
                    for nested in scalar_mutations(child, path + (index,))
                ]
            return [path]

        for baseline_id, baseline_value in self.authority.baselines.items():
            baseline = copy.deepcopy(baseline_value)
            result, reconstructed = conformance.reconstruct_snapshot(
                self.authority, baseline["candidate"], baseline["oracle"]
            )
            self.assertEqual(result, "Conform", baseline_id)
            self.assertIsNotNone(reconstructed, baseline_id)
            assert reconstructed is not None
            self.assertEqual(
                conformance.check_snapshot_coverage(
                    self.authority,
                    baseline["candidate"]["coverage"],
                    reconstructed,
                ),
                "Conform",
                baseline_id,
            )
            for path in scalar_mutations(reconstructed):
                mutated = copy.deepcopy(reconstructed)
                parent = mutated
                for component in path[:-1]:
                    parent = parent[component]
                leaf = path[-1]
                original = parent[leaf]
                parent[leaf] = original + 1 if type(original) is int else str(original) + "-wrong"
                with self.subTest(baseline=baseline_id, path=path):
                    self.assertEqual(
                        conformance.check_snapshot_coverage(
                            self.authority,
                            baseline["candidate"]["coverage"],
                            mutated,
                        ),
                        "EvidenceInvalid",
                    )

    def test_appraisal_is_separate_from_reconstruction_and_coverage(self) -> None:
        reconstruct = self.require_callable("reconstruct_snapshot")
        appraise = self.require_callable("appraise_snapshot")
        baseline = copy.deepcopy(
            self.authority.baselines["valid-same-session-renewal"]
        )
        reconstruction_result, reconstructed = reconstruct(
            self.authority, baseline["candidate"], baseline["oracle"]
        )
        self.assertEqual(reconstruction_result, "Conform")
        self.assertIsNotNone(reconstructed)
        assert reconstructed is not None
        case, _transform, changed = self.transformed_fixture(
            "renewal-claims-not-current"
        )

        self.assertEqual(
            appraise(self.authority, baseline["candidate"], baseline["oracle"], reconstructed),
            "Conform",
        )
        self.assertEqual(
            appraise(self.authority, changed["candidate"], changed["oracle"], reconstructed),
            case.disposition,
        )

    def test_focused_row_rebuilds_each_layer_prerequisite(self) -> None:
        run = self.require_callable("run_snapshot_focused_case")
        row = self.authority.focused_rows[0]

        self.assertEqual(
            tuple(run(self.authority, row[0], layer) for layer in (4, 5, 6)),
            row[1:],
        )

    def test_layer6_focused_case_requires_fresh_valid_baseline_coverage(self) -> None:
        authority = registry.load_task6_authority()
        authority.baselines["valid-same-session-renewal"]["candidate"]["coverage"][
            0
        ]["value"] = 2
        with mock.patch.object(
            conformance,
            "appraise_snapshot",
            wraps=conformance.appraise_snapshot,
        ) as appraisal:
            with self.assertRaisesRegex(AssertionError, "focused baseline coverage"):
                conformance.run_snapshot_focused_case(
                    authority, "renewal-claims-not-current", 6
                )
        appraisal.assert_not_called()

    def test_normal_snapshot_pipeline_matches_every_manifest_outcome(self) -> None:
        run = self.require_callable("run_admitted_snapshot_case")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_complete_snapshot_root(root)
            admission = conformance.admit_layer1(self.authority, root)

            actual = [
                run(self.authority, admission, case.identifier, root)
                for case in self.authority.snapshot_cases
            ]

        self.assertEqual(
            actual,
            [(case.checkpoint, case.disposition) for case in self.authority.snapshot_cases],
        )

    def test_normal_snapshot_pipeline_stops_at_earliest_semantic_layer(self) -> None:
        run = self.require_callable("run_admitted_snapshot_case")
        representatives = {
            "challenge-protocol-version-changed": (0, 0),
            "evidence-binding-used-for-protected-result": (1, 0),
            "renewal-claims-not-current": (1, 1),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_complete_snapshot_root(root)
            admission = conformance.admit_layer1(self.authority, root)
            for identifier, expected_calls in representatives.items():
                with self.subTest(identifier=identifier), mock.patch.object(
                    conformance,
                    "check_snapshot_coverage",
                    wraps=conformance.check_snapshot_coverage,
                ) as coverage, mock.patch.object(
                    conformance,
                    "appraise_snapshot",
                    wraps=conformance.appraise_snapshot,
                ) as appraisal:
                    case = next(
                        case for case in self.authority.snapshot_cases
                        if case.identifier == identifier
                    )
                    self.assertEqual(
                        run(self.authority, admission, identifier, root),
                        (case.checkpoint, case.disposition),
                    )
                    self.assertEqual(
                        (coverage.call_count, appraisal.call_count), expected_calls
                    )

    def test_task6_only_corpus_remains_incomplete_until_histories_exist(self) -> None:
        # Task 7 completes the checked-in corpus; retain the original rejection
        # contract against a real Task 6-only materialization.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            conformance.build_task6_corpus(self.authority, root)
            with self.assertRaisesRegex(
                bounded_json.BoundedJsonError,
                "^abstract-conformance:layer-1:malformed$",
            ):
                conformance.admit_layer1(self.authority, root)

    def test_checked_in_snapshot_inventory_and_bytes_are_exact(self) -> None:
        corpus_root = SCRIPT_DIR.parent / "lab" / "conformance"
        snapshots = sorted(
            path.relative_to(corpus_root).as_posix()
            for path in (corpus_root / "snapshots").iterdir()
        )
        histories = sorted(
            path.relative_to(corpus_root).as_posix()
            for path in (corpus_root / "histories").iterdir()
        )
        self.assertEqual(
            snapshots,
            sorted(case.path for case in self.authority.snapshot_cases),
        )
        self.assertEqual(
            histories,
            sorted(row[2] for row in self.authority.manifest["fixtures"] if row[1] == "history"),
        )
        for case in self.authority.snapshot_cases:
            self.assertEqual(
                (corpus_root / case.path).read_bytes(),
                conformance.reproduce_snapshot_fixture(self.authority, case),
            )

    def test_snapshot_identity_mutation_is_rejected_and_restoration_succeeds(self) -> None:
        run = self.require_callable("run_admitted_snapshot_case")
        identifier = "valid-initial-base-profile"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_complete_snapshot_root(root)
            admission = conformance.admit_layer1(self.authority, root)
            path = root / "lab" / "conformance" / "snapshots" / f"{identifier}.json"
            original = path.read_bytes()
            try:
                path.write_bytes(original + b" ")
                with self.assertRaisesRegex(
                    bounded_json.BoundedJsonError,
                    "^abstract-conformance:layer-2:malformed$",
                ) as rejected:
                    run(self.authority, admission, identifier, root)
                self.assertEqual(rejected.exception.category, "identity")
            finally:
                path.write_bytes(original)
            admission = conformance.admit_layer1(self.authority, root)
            self.assertEqual(
                run(self.authority, admission, identifier, root),
                ("layer-6-success", "Conform"),
            )

    def test_claim_order_is_nonsemantic_but_duplicates_remain_invalid(self) -> None:
        reconstruct = self.require_callable("reconstruct_snapshot")
        coverage = self.require_callable("check_snapshot_coverage")
        appraise = self.require_callable("appraise_snapshot")
        baseline = copy.deepcopy(
            self.authority.baselines["valid-initial-base-profile"]
        )
        baseline["candidate"]["transcript"]["claims"].reverse()
        result, reconstructed = reconstruct(
            self.authority, baseline["candidate"], baseline["oracle"]
        )
        self.assertEqual(result, "Conform")
        self.assertIsNotNone(reconstructed)
        assert reconstructed is not None
        self.assertEqual(
            coverage(self.authority, baseline["candidate"]["coverage"], reconstructed),
            "Conform",
        )
        self.assertEqual(
            appraise(self.authority, baseline["candidate"], baseline["oracle"], reconstructed),
            "Conform",
        )

        duplicate = copy.deepcopy(
            self.authority.baselines["valid-initial-base-profile"]
        )
        duplicate["candidate"]["transcript"]["claims"][0]["meaning"] = (
            duplicate["candidate"]["transcript"]["claims"][1]["meaning"]
        )
        self.assertEqual(
            conformance._fixture_shape_result(self.authority, duplicate),
            ("layer-3", "Malformed"),
        )

    def test_claim_order_is_nonsemantic_for_every_valid_snapshot_baseline(self) -> None:
        for baseline_id, baseline_value in self.authority.baselines.items():
            for ordering in ("reverse", "rotate", "meaning-descending"):
                baseline = copy.deepcopy(baseline_value)
                claims = baseline["candidate"]["transcript"]["claims"]
                if ordering == "reverse":
                    claims.reverse()
                elif ordering == "rotate":
                    claims[:] = claims[1:] + claims[:1]
                else:
                    claims.sort(key=lambda claim: claim["meaning"], reverse=True)
                with self.subTest(baseline=baseline_id, ordering=ordering):
                    result, reconstructed = conformance.reconstruct_snapshot(
                        self.authority,
                        baseline["candidate"],
                        baseline["oracle"],
                    )
                    self.assertEqual(result, "Conform")
                    self.assertIsNotNone(reconstructed)
                    assert reconstructed is not None
                    self.assertEqual(
                        conformance.check_snapshot_coverage(
                            self.authority,
                            baseline["candidate"]["coverage"],
                            reconstructed,
                        ),
                        "Conform",
                    )
                    self.assertEqual(
                        conformance.appraise_snapshot(
                            self.authority,
                            baseline["candidate"],
                            baseline["oracle"],
                            reconstructed,
                        ),
                        "Conform",
                    )

    def test_oracle_and_candidate_claim_order_are_independently_nonsemantic(self) -> None:
        for baseline_id, baseline_value in self.authority.baselines.items():
            for candidate_reversed in (False, True):
                for ordering in ("reverse", "rotate", "meaning-descending"):
                    baseline = copy.deepcopy(baseline_value)
                    if candidate_reversed:
                        baseline["candidate"]["transcript"]["claims"].reverse()
                    claims = baseline["oracle"]["expected_claims"]
                    if ordering == "reverse":
                        claims.reverse()
                    elif ordering == "rotate":
                        claims[:] = claims[1:] + claims[:1]
                    else:
                        claims.sort(key=lambda claim: claim["meaning"], reverse=True)
                    before = copy.deepcopy(baseline)
                    with self.subTest(
                        baseline=baseline_id,
                        candidate_reversed=candidate_reversed,
                        oracle_order=ordering,
                    ):
                        self.assertEqual(
                            conformance._fixture_shape_result(self.authority, baseline),
                            ("layer-4", "Conform"),
                        )
                        result, reconstructed = conformance.reconstruct_snapshot(
                            self.authority, baseline["candidate"], baseline["oracle"]
                        )
                        self.assertEqual(result, "Conform")
                        self.assertIsNotNone(reconstructed)
                        assert reconstructed is not None
                        self.assertEqual(
                            conformance.check_snapshot_coverage(
                                self.authority,
                                baseline["candidate"]["coverage"],
                                reconstructed,
                            ),
                            "Conform",
                        )
                        self.assertEqual(
                            conformance.appraise_snapshot(
                                self.authority,
                                baseline["candidate"],
                                baseline["oracle"],
                                reconstructed,
                            ),
                            "Conform",
                        )
                        self.assertEqual(baseline, before)

    def test_normal_pipeline_accepts_reordered_oracle_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.build_complete_snapshot_root(root)
            for case in self.authority.snapshot_cases:
                if case.transform is not None:
                    continue
                path = root / "lab" / "conformance" / case.path
                value = json.loads(path.read_bytes())
                value["oracle"]["expected_claims"].reverse()
                path.write_bytes(conformance._manifest_bytes(value))
            admission = conformance.admit_layer1(self.authority, root)
            for case in self.authority.snapshot_cases:
                if case.transform is not None:
                    continue
                with self.subTest(baseline=case.identifier):
                    self.assertEqual(
                        conformance.run_admitted_snapshot_case(
                            self.authority, admission, case.identifier, root
                        ),
                        ("layer-6-success", "Conform"),
                    )

    def test_duplicate_claim_occurrence_is_rejected_for_every_valid_baseline(self) -> None:
        for baseline_id, baseline_value in self.authority.baselines.items():
            duplicate = copy.deepcopy(baseline_value)
            duplicate["candidate"]["transcript"]["claims"][0]["meaning"] = (
                duplicate["candidate"]["transcript"]["claims"][1]["meaning"]
            )
            with self.subTest(baseline=baseline_id):
                self.assertEqual(
                    conformance._fixture_shape_result(self.authority, duplicate),
                    ("layer-3", "Malformed"),
                )

    def run_snapshot_reproduction(self, identifier: str) -> None:
        case = next(
            case for case in self.authority.snapshot_cases
            if case.identifier == identifier
        )
        authority_before = copy.deepcopy(self.authority)
        raw = conformance.reproduce_snapshot_fixture(self.authority, case)
        if case.transform is None:
            self.assertEqual(
                raw,
                conformance._manifest_bytes(self.authority.baselines[case.identifier]),
            )
        elif case.checkpoint != "layer-2":
            value = json.loads(raw)
            self.assertEqual(
                value,
                conformance._apply_fixture_transform(
                    self.authority.baselines[case.baseline],
                    self.authority.transforms[case.transform],
                ),
            )
            self.assertEqual(
                value["oracle"],
                self.authority.baselines[case.baseline]["oracle"],
            )
        self.assertEqual(self.authority, authority_before)

    def run_focused_invocation(self, identifier: str, layer: int, expected: str) -> None:
        authority_before = copy.deepcopy(self.authority)
        self.assertEqual(
            conformance.run_snapshot_focused_case(
                self.authority, identifier, layer
            ),
            expected,
        )
        self.assertEqual(self.authority, authority_before)


def _install_task5_case_tests() -> None:
    authority = registry.load_task5_authority()
    for case in authority.fixture_cases:
        identifier = case.identifier
        name = "test_task5_" + identifier.replace("-", "_")

        def test(self: Task5Tests, selected: str = identifier) -> None:
            self.run_early_case(selected)

        test.__name__ = name
        setattr(Task5Tests, name, test)


def _install_task6_case_tests() -> None:
    authority = registry.load_task6_authority()
    for case in authority.snapshot_cases:
        identifier = case.identifier
        name = "test_task6_reproduce_" + identifier.replace("-", "_")

        def reproduction_test(
            self: Task6SnapshotTests, selected: str = identifier
        ) -> None:
            self.run_snapshot_reproduction(selected)

        reproduction_test.__name__ = name
        setattr(Task6SnapshotTests, name, reproduction_test)
    for row in authority.focused_rows:
        for offset, layer in enumerate((4, 5, 6), start=1):
            identifier = row[0]
            expected = row[offset]
            name = (
                "test_task6_focused_layer_"
                + str(layer)
                + "_"
                + identifier.replace("-", "_")
            )

            def focused_test(
                self: Task6SnapshotTests,
                selected: str = identifier,
                selected_layer: int = layer,
                selected_expected: str = expected,
            ) -> None:
                self.run_focused_invocation(
                    selected, selected_layer, selected_expected
                )

            focused_test.__name__ = name
            setattr(Task6SnapshotTests, name, focused_test)


def _install_case_tests() -> None:
    authority = registry.load_task4_authority()
    for case in authority.corpus_cases:
        name = "test_" + case.identifier.replace("-", "_")

        def test(self: RegistryCaseTests, selected: registry.LoaderCase = case) -> None:
            self.run_registry_case(selected)

        test.__name__ = name
        setattr(RegistryCaseTests, name, test)


_install_case_tests()
_install_task5_case_tests()
_install_task6_case_tests()


class Task10ReviewTests(ConformanceTestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority = registry.load_task4_authority()
        cls.snapshots = registry.load_task6_authority()
        cls.early = registry.load_task5_authority()

    def copy_corpus(self, root):
        shutil.copytree(SCRIPT_DIR.parent / "lab" / "conformance",
                        root / "lab" / "conformance")

    def test_snapshot_shape_is_independent_of_expected_tuples_and_transforms(self):
        for identifier, expected in (
            ("unknown-critical-semantic", ("layer-3", "Unsupported")),
            ("evidence-reused-for-account", ("layer-4", "Conform")),
        ):
            case = next(case for case in self.snapshots.snapshot_cases
                        if case.identifier == identifier)
            value = json.loads(conformance.reproduce_snapshot_fixture(self.snapshots, case))
            for mutation in ("expectations", "transforms"):
                with self.subTest(identifier=identifier, mutation=mutation):
                    authority = copy.deepcopy(self.snapshots)
                    if mutation == "expectations":
                        authority = replace(authority, snapshot_cases=tuple(
                            replace(row, checkpoint="layer-6-success", disposition="Conform")
                            for row in authority.snapshot_cases))
                    else:
                        authority.transforms.clear()
                    self.assertEqual(conformance._fixture_shape_result(authority, value), expected)

    def test_history_shape_is_independent_of_expected_tuples_and_transforms(self):
        for domain, expected in (
            ("protected-monotonic", ("layer-4", "Conform")),
            ("client-utc", ("layer-3", "Malformed")),
            ("unknown-critical-time-domain", ("layer-3", "Unsupported")),
        ):
            value = copy.deepcopy(self.early.baselines["history-valid-initial-collection"])
            for collection in value["candidate"]["collections"]:
                collection["time_domain"] = domain
            for mutation in ("expectations", "transforms"):
                with self.subTest(domain=domain, mutation=mutation):
                    authority = copy.deepcopy(self.authority)
                    if mutation == "expectations":
                        manifest = authority.validators["validator_baselines"]["baseline-corpus-v1"]["ast"]["value"]
                        for row in manifest["fixtures"]:
                            row[5:7] = ["layer-6-success", "Conform"]
                    else:
                        authority.histories["negative_transforms"].clear()
                    self.assertEqual(conformance._fixture_shape_result(authority, value), expected)

    def test_protected_session_provenance_mismatch_is_evidence_invalid(self):
        value = copy.deepcopy(self.snapshots.baselines["valid-initial-base-profile"])
        claim = next(row for row in value["candidate"]["transcript"]["claims"]
                     if row["meaning"] == "protected-session-identity")
        claim["provenance"] = "hardware-certified"
        self.assertEqual(conformance._fixture_shape_result(self.snapshots, value),
                         ("layer-4", "Conform"))
        self.assertEqual(conformance.reconstruct_snapshot(
            self.snapshots, value["candidate"], value["oracle"]),
            ("EvidenceInvalid", None))

    def test_claim_token_alias_does_not_change_claim_meaning(self):
        for meaning in ("attesting-agent-identity", "process-binding-identity"):
            with self.subTest(meaning=meaning):
                value = copy.deepcopy(self.snapshots.baselines["valid-initial-base-profile"])
                supplied = next(row for row in value["candidate"]["transcript"]["claims"]
                                if row["meaning"] == meaning)
                expected = next(row for row in value["oracle"]["expected_claims"]
                                if row["meaning"] == meaning)
                supplied["value"]["token"] = value["oracle"]["expected_context"]["protected_session"]
                expected["value"] = copy.deepcopy(supplied["value"])
                self.assertEqual(conformance._fixture_shape_result(self.snapshots, value),
                                 ("layer-4", "Conform"))
                self.assertEqual(conformance.reconstruct_snapshot(
                    self.snapshots, value["candidate"], value["oracle"])[0], "Conform")
                supplied["value"]["token"] = "agent-beta"
                self.assertEqual(conformance.reconstruct_snapshot(
                    self.snapshots, value["candidate"], value["oracle"]),
                    ("EvidenceInvalid", None))

    def test_protected_session_value_mismatch_remains_context_mismatch(self):
        value = copy.deepcopy(self.snapshots.baselines["valid-initial-base-profile"])
        supplied = next(row for row in value["candidate"]["transcript"]["claims"]
                        if row["meaning"] == "protected-session-identity")
        supplied["value"]["token"] = "session-beta"
        self.assertEqual(conformance.reconstruct_snapshot(
            self.snapshots, value["candidate"], value["oracle"]),
            ("ContextBindingMismatch", None))

    def test_generated_consumer_assertions_are_failures_and_other_exceptions_are_errors(self):
        for test_class, method, runner, authority in (
            (RegistryCaseTests, "test_v1_corpus_canonical", "run_layer1_case", self.authority),
            (Task5Tests, "test_task5_fixture_duplicate_object_name", "run_early_fixture_case", self.early),
        ):
            for exception, failures, errors in ((AssertionError, 1, 0), (RuntimeError, 0, 1)):
                with self.subTest(runner=runner, exception=exception.__name__):
                    test = test_class(method)
                    test.authority = authority
                    output = io.StringIO()
                    with mock.patch.object(conformance, runner, side_effect=exception("invocation probe")):
                        result = unittest.TextTestRunner(stream=output).run(test)
                    self.assertEqual(len(result.failures), failures)
                    self.assertEqual(len(result.errors), errors)
                    if failures:
                        self.assertIn("conformance assertion mismatch", output.getvalue())
                        self.assertNotIn("invocation probe", output.getvalue())

    def test_hostile_fixture_assertion_output_is_redacted(self):
        for mutation in ("bytes", "filename"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.copy_corpus(root)
                corpus = root / "lab" / "conformance"
                marker = "HOSTILE_FIXTURE_ASSERTION_MARKER"
                if mutation == "bytes":
                    (corpus / self.snapshots.snapshot_cases[0].path).write_bytes(marker.encode())
                else:
                    (corpus / "snapshots" / (marker + ".json")).write_text("{}")
                output = io.StringIO()
                test = Task6SnapshotTests("test_checked_in_snapshot_inventory_and_bytes_are_exact")
                test.authority = self.snapshots
                with mock.patch(__name__ + ".SCRIPT_DIR", root / "scripts"):
                    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                        result = unittest.TextTestRunner(stream=output).run(test)
                self.assertEqual(len(result.failures), 1)
                self.assertEqual(len(result.errors), 0)
                self.assertTrue(marker not in output.getvalue(), "fixture assertion leaked input")
                self.assertIn("conformance assertion mismatch", output.getvalue())

    def test_inventory_stops_on_first_unexpected_name(self):
        for directory in ("", "snapshots", "histories"):
            with self.subTest(directory=directory), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.copy_corpus(root)
                selected = root / "lab" / "conformance" / directory
                (selected / "unexpected.json").write_text("{}")
                original = os.scandir
                seen = []

                @contextlib.contextmanager
                def guarded_scan(fd):
                    with original(fd) as entries:
                        def guarded_entries():
                            for entry in entries:
                                seen.append(entry.name)
                                yield entry
                                if entry.name == "unexpected.json":
                                    self.fail("inventory continued after unexpected name")
                        yield guarded_entries()

                with mock.patch.object(os, "scandir", guarded_scan):
                    with self.assertRaisesRegex(bounded_json.BoundedJsonError,
                                                "^abstract-conformance:layer-1:malformed$"):
                        conformance.admit_layer1(self.authority, root)
                self.assertIn("unexpected.json", seen)
                self.assertLessEqual(len(seen), 128)

    def test_oversized_layer2_fixture_cannot_claim_reproduction(self):
        for runner, authority in ((conformance.run_admitted_snapshot_case, self.snapshots),
                                  (conformance.run_admitted_early_fixture_case, self.early)):
            with self.subTest(runner=runner.__name__), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.copy_corpus(root)
                fixture = root / "lab/conformance/snapshots/fixture-duplicate-object-name.json"
                fixture.write_bytes(b" " * (authority.core["resource_limits"]["fixture"]["bytes"] + 1))
                admission = conformance.admit_layer1(authority, root)
                with mock.patch.object(os, "read", side_effect=AssertionError("oversized fixture read")):
                    with self.assertRaisesRegex(AssertionError, "reproduction mismatch"):
                        runner(authority, admission, "fixture-duplicate-object-name", root)

    def test_normal_pipeline_rejects_unregistered_layer2_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_corpus(root)
            fixture = root / "lab/conformance/snapshots/fixture-duplicate-object-name.json"
            fixture.write_bytes(b"{")
            with self.assertRaisesRegex(AssertionError, "reproduction mismatch"):
                conformance.run_corpus(self.authority, self.snapshots, root)

    def test_normal_pipeline_layer3_reproduction_preserves_claim_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_corpus(root)
            fixture = root / "lab/conformance/snapshots/required-claim-omitted.json"
            value = json.loads(fixture.read_bytes())
            value["candidate"]["transcript"]["claims"].reverse()
            fixture.write_text(json.dumps(value))
            with self.assertRaisesRegex(AssertionError, "reproduction mismatch"):
                conformance.run_corpus(self.authority, self.snapshots, root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
