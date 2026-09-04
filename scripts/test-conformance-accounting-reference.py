#!/usr/bin/env python3
"""Compare independently derived operation vectors with actual scoped work."""
from __future__ import annotations

import unittest
import json
import os
import tempfile
from pathlib import Path
from unittest import mock

import abstract_conformance_registry as registry
import bounded_json
from conformance_accounting_reference import CostModel, ReferenceError, predict_admission, predict_snapshot, snapshot_focused_vector, predict_corpus
from conformance_corpus_cost_reference import corpus_case_vector
from conformance_history_cost_reference import history_focused_vector
from conformance_loader_cost_reference import nonfile_case_vector


class ReferenceBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority = registry.load_task4_authority()
        cls.snapshots = registry.load_task6_authority()
        cls.manifest = cls.authority.core["paths"]["corpus_manifest"]
        cls.canonical = cls.authority.validators["validator_baselines"]["baseline-corpus-v1"]["ast"]["value"]

    def manifest_path(self, root):
        path = root / self.manifest
        path.parent.mkdir(parents=True)
        return path

    def test_rejected_manifest_stops_before_fixture_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.manifest_path(root).write_bytes(b"null")
            with mock.patch.object(bounded_json, "_read_file", wraps=bounded_json._read_file) as reader:
                with self.assertRaises(ReferenceError):
                    predict_corpus(self.authority, self.snapshots, root)
            self.assertTrue(reader.call_count == 1, "fixture read after manifest rejection")

    def test_oversized_manifest_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            maximum = self.authority.core["resource_limits"]["manifest"]["bytes"]
            with self.manifest_path(root).open("wb") as file:
                file.truncate(maximum + 1)
            with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded reference read")):
                with mock.patch.object(os, "read", side_effect=AssertionError("oversized physical read")):
                    with self.assertRaises(ReferenceError):
                        predict_corpus(self.authority, self.snapshots, root)

    def test_unadmitted_path_rejected_before_fixture_read(self):
        value = json.loads(json.dumps(self.canonical))
        value["fixtures"][0][2] = "../outside.json"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.manifest_path(root).write_text(json.dumps(value))
            with mock.patch.object(bounded_json, "_read_file", wraps=bounded_json._read_file) as reader:
                with self.assertRaises(ReferenceError):
                    predict_corpus(self.authority, self.snapshots, root)
            self.assertTrue(reader.call_count == 1, "unadmitted fixture read")

    def test_symlink_manifest_rejected_without_following(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self.manifest_path(root)
            target = root / "outside.json"
            target.write_bytes(b"null")
            path.symlink_to(target)
            with mock.patch.object(os, "read", side_effect=AssertionError("followed manifest link")):
                with self.assertRaises(ReferenceError):
                    predict_corpus(self.authority, self.snapshots, root)

    def test_nonregular_manifest_rejected_without_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.manifest_path(root).mkdir()
            with mock.patch.object(os, "read", side_effect=AssertionError("read nonregular manifest")):
                with self.assertRaises(ReferenceError):
                    predict_corpus(self.authority, self.snapshots, root)

    def test_fixture_symlink_rejected_after_manifest_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.manifest_path(root)
            manifest.write_text(json.dumps(self.canonical))
            fixture = manifest.parent / self.canonical["fixtures"][0][2]
            fixture.parent.mkdir(parents=True)
            outside = root / "outside.json"
            outside.write_bytes(b"null")
            fixture.symlink_to(outside)
            with mock.patch.object(bounded_json, "_read_file", wraps=bounded_json._read_file) as reader:
                with self.assertRaises(ReferenceError):
                    predict_corpus(self.authority, self.snapshots, root)
            self.assertTrue(reader.call_count == 2, "fixture link rejection boundary")

    def test_raw_reader_fifo_is_nonblocking_and_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(root / "input")
            original = os.open
            def guarded_open(path, flags, *args, **kwargs):
                if path == "input":
                    self.assertTrue(bool(flags & os.O_NONBLOCK), "blocking nonregular open")
                return original(path, flags, *args, **kwargs)
            with mock.patch.object(os, "open", side_effect=guarded_open):
                with self.assertRaises(bounded_json.BoundedJsonError):
                    bounded_json.read_bounded_bytes(root, "input", 8, "fixed")

    def test_raw_reader_rejects_file_change_during_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "input"
            path.write_bytes(b"{}")
            original = os.read
            changed = False
            def changing_read(descriptor, size):
                nonlocal changed
                result = original(descriptor, size)
                if not changed:
                    changed = True
                    path.write_bytes(b"null")
                return result
            with mock.patch.object(os, "read", side_effect=changing_read):
                with self.assertRaises(bounded_json.BoundedJsonError):
                    bounded_json.read_bounded_bytes(root, "input", 8, "fixed")


class ReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority = registry.load_task4_authority()
        cls.snapshots = registry.load_task6_authority()
        cls.root = Path(__file__).resolve().parents[1]
        # All expected values are derived before the consumer is imported.
        cls.admission_vector, cls.normal_vectors, cls.earliest_stop_total = predict_corpus(
            cls.authority, cls.snapshots, cls.root)
        cls.snapshot_vectors = {
            case.identifier: cls.normal_vectors[case.identifier]
            for case in cls.snapshots.snapshot_cases
        }
        cls.focused_vectors = {
            (row[0], layer): snapshot_focused_vector(cls.snapshots, row[0], layer)
            for row in cls.snapshots.focused_rows for layer in (4, 5, 6)
        }
        cls.corpus_vectors = {case.identifier: corpus_case_vector(cls.authority, case, dispatched=True)
                              for case in cls.authority.corpus_cases}
        cls.history_focused_vectors = {
            (row[0], layer): history_focused_vector(cls.authority, row[0], layer)
            for row in cls.authority.histories["focused_expected_tuples"] for layer in (4, 5, 6)
        }
        cls.nonfile_cases = tuple(registry.LoaderCase(*row) for row in cls.authority.validators["validator_cases"]
                                  if row[1] != "corpus-mutation")
        cls.nonfile_vectors = {case.identifier: nonfile_case_vector(cls.authority, case)
                               for case in cls.nonfile_cases}
        cls.checked_rows = []
        for selected, rows, function in (
            (cls.snapshots, cls.snapshots.focused_rows, snapshot_focused_vector),
            (cls.authority, cls.authority.histories["focused_expected_tuples"], history_focused_vector),
        ):
            for row in rows:
                for layer, outcome in zip((4, 5, 6), row[1:], strict=True):
                    cls.checked_rows.append((row[0], layer, outcome,
                        function(selected, row[0], layer, checked=True)))
        import abstract_conformance as consumer
        cls.consumer = consumer
        cls.admission = consumer.admit_layer1(cls.authority, cls.root)

    def test_schema_reference_short_circuit(self):
        model = CostModel(self.authority)
        self.assertTrue(model.typed(None, {"union": [{"type": "boolean"}, {"type": "null"}]}))
        self.assertTrue(model.vector == (0, 3, 0, 0, 0, 0, 0), "reference schema cost")

    def test_recursive_comparison_reference(self):
        model = CostModel(self.authority)
        self.assertFalse(model.equal([True, 2], [1, 2]))
        self.assertTrue(model.vector == (0, 0, 0, 0, 0, 0, 2), "reference comparison cost")

    def test_admission_vector(self):
        _, actual = self.consumer.measure_call(self.consumer.admit_layer1, self.authority, self.root)
        self.assertTrue(actual == self.admission_vector, "admission accounting mismatch")

    def test_all_snapshot_vectors(self):
        for case in self.snapshots.snapshot_cases:
            with self.subTest(case=case.identifier):
                _, actual = self.consumer.measure_call(self.consumer.run_admitted_snapshot_case,
                    self.snapshots, self.admission, case.identifier, self.root)
                self.assertTrue(actual == self.snapshot_vectors[case.identifier], "snapshot accounting mismatch")

    def test_all_snapshot_focused_vectors(self):
        for row in self.snapshots.focused_rows:
            for layer in (4, 5, 6):
                with self.subTest(case=row[0], layer=layer):
                    _, actual = self.consumer.measure_call(self.consumer.run_snapshot_focused_case,
                        self.snapshots, row[0], layer)
                    self.assertTrue(actual == self.focused_vectors[row[0], layer], "focused accounting mismatch")

    def test_all_corpus_mutation_vectors(self):
        for case in self.authority.corpus_cases:
            with self.subTest(case=case.identifier):
                _, actual = self.consumer.measure_call(self.consumer.run_validator_case, self.authority, case)
                self.assertTrue(actual == self.corpus_vectors[case.identifier], "corpus accounting mismatch")

    def test_all_normal_vectors_and_earliest_stop_total(self):
        admission, actual_rows = self.consumer.run_corpus(self.authority, self.snapshots, self.root)
        self.assertTrue(admission == self.admission_vector, "aggregate admission mismatch")
        total = sum(admission)
        self.assertTrue(len(actual_rows) == len(self.normal_vectors), "aggregate inventory mismatch")
        self.assertTrue(tuple(row[0] for row in actual_rows) == tuple(self.normal_vectors),
                        "aggregate manifest order mismatch")
        for identifier, _, actual in actual_rows:
            with self.subTest(case=identifier):
                self.assertTrue(actual == self.normal_vectors[identifier], "normal accounting mismatch")
            total += sum(actual)
        self.assertTrue(total == self.earliest_stop_total, "earliest-stop total mismatch")

    def test_all_remaining_nonfile_vectors(self):
        adapters = self.consumer._case_adapters()
        for case in self.nonfile_cases:
            with self.subTest(case=case.identifier):
                _, actual = self.consumer.measure_call(self.consumer.run_validator_case,
                    self.authority, case, adapters)
                self.assertTrue(actual == self.nonfile_vectors[case.identifier], "nonfile accounting mismatch")

    def test_all_history_focused_vectors(self):
        for row in self.authority.histories["focused_expected_tuples"]:
            for layer in (4, 5, 6):
                with self.subTest(case=row[0], layer=layer):
                    _, actual = self.consumer.measure_call(self.consumer.run_history_focused_case,
                        self.authority, row[0], layer)
                    self.assertTrue(actual == self.history_focused_vectors[row[0], layer], "history focused accounting mismatch")

    def test_checked_focused_matrix_order_and_vectors(self):
        actual = self.consumer.run_focused_matrix(self.authority, self.snapshots)
        self.assertTrue(actual == tuple(self.checked_rows), "checked focused matrix mismatch")

    def test_history_omitted_charge_mutants_are_detected(self):
        original = self.consumer._charge
        case = next(row for row in self.authority.histories["focused_expected_tuples"] if row[3] == "Conform")
        expected = self.history_focused_vectors[case[0], 6]
        for category in ("history_actions", "lifecycle_state_field_comparisons"):
            with self.subTest(category=category):
                def omitted(name):
                    if name != category:
                        original(name)
                with mock.patch.object(self.consumer, "_charge", side_effect=omitted):
                    _, actual = self.consumer.measure_call(self.consumer.run_history_focused_case,
                        self.authority, case[0], 6)
                self.assertTrue(actual != expected, "history omission mutant survived")
                _, restored = self.consumer.measure_call(self.consumer.run_history_focused_case,
                    self.authority, case[0], 6)
                self.assertTrue(restored == expected, "history omission restoration mismatch")

    def test_corpus_omitted_charge_mutants_are_detected(self):
        original = self.consumer._charge
        case = self.authority.corpus_cases[0]
        for category in ("decoded_node_visits", "schema_assertions", "oracle_assertions"):
            with self.subTest(category=category):
                def omitted(name):
                    if name != category:
                        original(name)
                with mock.patch.object(self.consumer, "_charge", side_effect=omitted):
                    _, actual = self.consumer.measure_call(self.consumer.run_validator_case, self.authority, case)
                self.assertTrue(actual != self.corpus_vectors[case.identifier], "corpus omission mutant survived")

    def test_omitted_charge_mutants_are_detected(self):
        # Isolated charge omissions must disagree with independently derived
        # expected values; no consumer source mutation or saved output is used.
        original = self.consumer._charge
        case = self.snapshots.snapshot_cases[0]
        expected = self.snapshot_vectors[case.identifier]
        for category in ("decoded_node_visits", "schema_assertions", "claim_comparisons",
                         "coverage_entry_comparisons", "oracle_assertions"):
            with self.subTest(category=category):
                def omitted(name):
                    if name != category:
                        original(name)
                with mock.patch.object(self.consumer, "_charge", side_effect=omitted):
                    _, actual = self.consumer.measure_call(self.consumer.run_admitted_snapshot_case,
                        self.snapshots, self.admission, case.identifier, self.root)
                self.assertTrue(actual != expected, "omitted charge mutant survived")

    def test_later_layer_overrun_is_detected(self):
        case = next(case for case in self.snapshots.snapshot_cases if case.checkpoint == "layer-4")
        original = self.consumer.reconstruct_snapshot
        def overrun(*args, **kwargs):
            result = original(*args, **kwargs)
            self.consumer._charge("coverage_entry_comparisons")
            return result
        with mock.patch.object(self.consumer, "reconstruct_snapshot", side_effect=overrun):
            _, actual = self.consumer.measure_call(self.consumer.run_admitted_snapshot_case,
                self.snapshots, self.admission, case.identifier, self.root)
        self.assertTrue(actual != self.snapshot_vectors[case.identifier], "later-layer overrun mutant survived")


class ReviewFixReferenceTests(unittest.TestCase):
    def test_early_content_assertion_and_session_value_comparison_costs(self):
        authority = registry.load_task4_authority()
        snapshots = registry.load_task6_authority()
        root = Path(__file__).resolve().parents[1]
        _, normal, total = predict_corpus(authority, snapshots, root)
        # Derived from the reference before measurement: one content predicate,
        # and three recursive scalar-value units (object, kind, token).
        self.assertEqual(normal["fixture-duplicate-object-name"], (0, 0, 0, 0, 0, 0, 2))
        self.assertEqual(normal["protected-session-identity-changed"],
                         (515, 1851, 51, 0, 0, 0, 549))
        self.assertEqual(snapshot_focused_vector(
            snapshots, "protected-session-identity-changed", 4, checked=True),
            (0, 0, 50, 0, 0, 0, 33))
        self.assertEqual(total, 407444)


if __name__ == "__main__":
    unittest.main()
