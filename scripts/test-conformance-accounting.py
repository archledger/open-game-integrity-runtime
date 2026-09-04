#!/usr/bin/env python3
"""Operation budget, focused orchestration, and safe CLI regressions."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import inspect
import tempfile
from pathlib import Path
from unittest import mock
import traceback
import unittest
import bounded_json
import abstract_conformance as conformance
import abstract_conformance_registry as registry


class AccountingAssertionError(AssertionError):
    def __init__(self, *_args):
        super().__init__("accounting assertion mismatch")
        self.__suppress_context__ = True


class AccountingTests(unittest.TestCase):
    failureException = AccountingAssertionError
    @classmethod
    def setUpClass(cls):
        cls.authority = registry.load_task4_authority()

    def test_budget_interface(self):
        self.assertTrue(callable(getattr(conformance, 'operation_scope', None)),
                        'operation scope missing')

    def test_schema_charge_before_predicate(self):
        with conformance.operation_scope(self.authority) as budget:
            budget.maximum = 0
            with self.assertRaises(conformance.OperationBudgetExceeded):
                conformance._valid_typed(None, {"type": "null"}, {}, {})
            self.assertEqual(budget.vector, (0, 1, 0, 0, 0, 0, 0))

    def test_private_million_boundary(self):
        with conformance.operation_scope(self.authority) as budget:
            for _ in range(1_000_000):
                budget.charge("oracle_assertions")
            self.assertEqual(budget.total, 1_000_000)
            with self.assertRaises(conformance.OperationBudgetExceeded):
                budget.charge("oracle_assertions")
            self.assertEqual(budget.total, 1_000_001)

    def test_nested_failure_restores_scope(self):
        with conformance.operation_scope(self.authority) as outer:
            outer.charge("oracle_assertions")
            with self.assertRaises(conformance.OperationBudgetExceeded):
                with conformance.operation_scope(self.authority) as inner:
                    inner.maximum = 0
                    inner.charge("oracle_assertions")
            conformance._charge("schema_assertions")
            self.assertEqual(outer.vector, (0, 1, 0, 0, 0, 0, 1))
        self.assertIsNone(conformance._CURRENT_BUDGET.get())

    def test_unknown_category_fails_without_spending(self):
        with conformance.operation_scope(self.authority) as budget:
            with self.assertRaisesRegex(RuntimeError, '^abstract-conformance:internal:internal-failure$'):
                budget.charge('/private/::error::')
            self.assertEqual(budget.total, 0)

    def test_decoded_callback_before_work(self):
        loader = bounded_json.load_bounded_json
        self.assertIn("node_visit", inspect.signature(loader).parameters)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_text('{"a":[1,null]}')
            limits = bounded_json.JsonLimits.from_mapping(self.authority.core["resource_limits"]["fixture"])
            seen = []
            value = loader(root, "input.json", limits, conformance.LAYER2_DIAGNOSTIC,
                           node_visit=lambda: seen.append(None))
            self.assertEqual(len(seen), 4)
            self.assertEqual(value, {"a": [1, None]})
            with conformance.operation_scope(self.authority) as budget:
                budget.maximum = 0
                with self.assertRaises(conformance.OperationBudgetExceeded):
                    loader(root, "input.json", limits, conformance.LAYER2_DIAGNOSTIC,
                           node_visit=lambda: budget.charge("decoded_node_visits"))
                self.assertEqual(budget.vector, (1, 0, 0, 0, 0, 0, 0))

    def test_oracle_comparison_is_metered_before_equality(self):
        with conformance.operation_scope(self.authority) as budget:
            budget.maximum = 0
            with self.assertRaises(conformance.OperationBudgetExceeded):
                conformance._same_json_value({"x": 1}, {"x": 1})
            self.assertEqual(budget.vector, (0, 0, 0, 0, 0, 0, 1))

    def test_comparison_visits_exact_types_and_short_circuits(self):
        with conformance.operation_scope(self.authority) as budget:
            self.assertTrue(conformance._same_json_value({"x": [1, None]}, {"x": [1, None]}))
            self.assertEqual(budget.vector, (0, 0, 0, 0, 0, 0, 4))
        with conformance.operation_scope(self.authority) as budget:
            self.assertFalse(conformance._same_json_value([True, 1], [1, 1]))
            self.assertEqual(budget.total, 2)

    def test_claims_have_separate_charges(self):
        authority = registry.load_task6_authority()
        baseline = next(iter(authority.baselines.values()))
        with conformance.operation_scope(authority) as budget:
            result, _ = conformance.reconstruct_snapshot(authority, baseline["candidate"], baseline["oracle"])
            self.assertTrue(result == "Conform", "baseline reconstruction")
            self.assertGreater(budget.vector[2], 0)

    def test_coverage_has_separate_charges(self):
        authority = registry.load_task6_authority()
        baseline = next(iter(authority.baselines.values()))
        _, reconstructed = conformance.reconstruct_snapshot(authority, baseline["candidate"], baseline["oracle"])
        with conformance.operation_scope(authority) as budget:
            result = conformance.check_snapshot_coverage(authority, baseline["candidate"]["coverage"], reconstructed)
            self.assertTrue(result == "Conform", "baseline coverage")
            self.assertGreater(budget.vector[3], 0)

    def test_actions_have_separate_charges(self):
        baseline = self.authority.histories["baselines"][0]
        with conformance.operation_scope(self.authority) as budget:
            conformance.replay_history_oracle(self.authority, baseline["oracle"])
            self.assertEqual(budget.vector[4], len(baseline["oracle"]["actions"]))

    def test_state_fields_have_separate_charges(self):
        baseline = self.authority.histories["baselines"][0]
        with conformance.operation_scope(self.authority) as budget:
            result, _, _ = conformance.evaluate_history(self.authority, baseline["candidate"], baseline["oracle"])
            self.assertTrue(result == "Conform", "baseline lifecycle")
            self.assertGreater(budget.vector[5], 0)

    def test_public_admission_owns_fresh_budget(self):
        root = Path(__file__).resolve().parent.parent
        with conformance.operation_scope(self.authority) as outer:
            outer.maximum = 0
            _, vector = conformance.measure_call(conformance.admit_layer1, self.authority, root)
            self.assertGreater(vector[0], 0)
            self.assertGreater(vector[1], 0)
            self.assertEqual(outer.total, 0)

    def test_matrix_interface(self):
        self.assertTrue(callable(getattr(conformance, "run_focused_matrix", None)), "focused matrix runner missing")

    def test_registered_case_interface(self):
        self.assertTrue(callable(getattr(conformance, "run_validator_case", None)), "registered case runner missing")

    def test_cli_normal_validation_is_supported_and_silent(self):
        spec = importlib.util.spec_from_file_location("conformance_cli", Path(__file__).with_name("check-abstract-conformance.py"))
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = cli.main([])
        self.assertEqual(status, 0)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "")

    def test_cli_faults_and_unknown_arguments_are_fixed(self):
        spec = importlib.util.spec_from_file_location("conformance_cli", Path(__file__).with_name("check-abstract-conformance.py"))
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        for fault, expected in ((RuntimeError("/private/key\r\n::error::"), "internal-failure"),
                                (conformance.OperationBudgetExceeded(), "operation-budget-exhausted")):
            output, errors = io.StringIO(), io.StringIO()
            with mock.patch.object(conformance, "run_corpus", side_effect=fault):
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    status = cli.main([])
            self.assertEqual(status, 1)
            self.assertEqual(output.getvalue(), "")
            self.assertTrue(errors.getvalue() == "abstract-conformance:internal:" + expected + "\n",
                            "CLI fault diagnostic")
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(cli.main(["/private/key\r\n::error::"]), 2)
        self.assertEqual(errors.getvalue(), "abstract-conformance:internal:internal-failure\n")

    def test_aggregate_admits_both_commands_under_hard_timeout(self):
        seconds = self.authority.core["resource_limits"]["wall_clock_seconds"]
        gate = Path(__file__).with_name("check.sh").read_text()
        command = f"timeout --signal=KILL {seconds}s python3 ./scripts/check-abstract-conformance.py"
        self.assertIn(command + "\n", gate)
        self.assertIn(command + " --self-test\n", gate)
        for test in ("test-conformance-accounting.py", "test-conformance-accounting-reference.py"):
            self.assertIn(f"timeout --signal=KILL {seconds}s python3 -W error ./scripts/{test}\n", gate)
        self.assertIn("python3 ./scripts/check-attack-scenario-traceability.py --self-test\n", gate)
        self.assertIn("python3 ./scripts/check-attack-scenario-traceability.py\n", gate)

    def test_snapshot_expectation_error_redacts_modeled_result(self):
        root = Path(__file__).resolve().parent.parent
        authority = registry.load_task6_authority()
        admission = conformance.admit_layer1(self.authority, root)
        case = next(case for case in authority.snapshot_cases if case.checkpoint == "layer-6-success")
        sentinel = "/private/model-value::error::"
        with mock.patch.object(conformance, "reconstruct_snapshot", return_value=(sentinel, None)):
            try:
                conformance.run_admitted_snapshot_case(authority, admission, case.identifier, root)
            except AssertionError as error:
                self.assertTrue(str(error) == "snapshot registry expectation mismatch", "snapshot assertion diagnostic")
                self.assertNotIn(sentinel, "".join(traceback.format_exception(error)))
            else:
                self.fail("unexpected result accepted")

    def test_result_assertion_charges_before_predicate(self):
        visited = []
        with conformance.operation_scope(self.authority) as budget:
            budget.maximum = 0
            with self.assertRaises(conformance.OperationBudgetExceeded):
                conformance._require(lambda: visited.append(None) or True)
            self.assertEqual(visited, [])
            self.assertEqual(budget.vector, (0, 0, 0, 0, 0, 0, 1))

    def test_assertion_failure_suppresses_modeled_values_and_context(self):
        sentinel = "accounting-private-sentinel"
        for operation in (lambda: self.assertEqual(sentinel, ""),
                          lambda: self.assertNotIn(sentinel, sentinel)):
            try:
                operation()
            except self.failureException as error:
                if sentinel in "".join(traceback.format_exception(error)):
                    raise AssertionError("unsafe accounting assertion") from None
            else:
                raise AssertionError("missing accounting assertion")
        try:
            with self.assertRaisesRegex(ValueError, "fixed-expected"):
                raise ValueError(sentinel)
        except self.failureException as error:
            if sentinel in "".join(traceback.format_exception(error)):
                raise AssertionError("unsafe accounting assertion context") from None
        else:
            raise AssertionError("missing accounting assertion")

    def test_fresh_scope_resets_comparison_category(self):
        root = Path(__file__).resolve().parent.parent
        _, baseline = conformance.measure_call(conformance.admit_layer1, self.authority, root)
        token = conformance._COMPARISON_CATEGORY.set("claim_comparisons")
        try:
            _, nested = conformance.measure_call(conformance.admit_layer1, self.authority, root)
            self.assertEqual(nested, baseline)
            self.assertEqual(conformance._COMPARISON_CATEGORY.get(), "claim_comparisons")
        finally:
            conformance._COMPARISON_CATEGORY.reset(token)

    def test_focused_matrix_checks_stay_inside_fresh_invocations(self):
        snapshots = registry.load_task6_authority()
        expected = [(row[0], layer, row[layer - 3])
                    for rows in (snapshots.focused_rows, self.authority.histories["focused_expected_tuples"])
                    for row in rows for layer in (4, 5, 6)]
        with conformance.operation_scope(self.authority) as outer:
            outer.maximum = 0
            try:
                rows = conformance.run_focused_matrix(self.authority, snapshots)
            except conformance.OperationBudgetExceeded:
                self.fail("focused matrix spent caller budget")
            self.assertEqual(outer.total, 0)
        self.assertEqual([(identifier, layer, outcome) for identifier, layer, outcome, _ in rows], expected)

    def test_focused_prerequisite_is_charged_before_predicate(self):
        authority = registry.load_task6_authority()
        visited = []
        class Observed(str):
            def __ne__(self, other):
                visited.append(None)
                return False
        original = conformance.OperationBudget.__init__
        def empty(budget, contract):
            original(budget, contract)
            budget.maximum = 0
        with mock.patch.object(conformance.OperationBudget, "__init__", empty):
            with mock.patch.object(conformance, "reconstruct_snapshot", return_value=(Observed("Conform"), {})):
                with self.assertRaises(conformance.OperationBudgetExceeded):
                    conformance.run_snapshot_focused_case(authority, authority.focused_rows[0][0], 5)
        self.assertEqual(visited, [])

    def test_reproduction_assertion_is_charged_before_comparison(self):
        authority = registry.load_task6_authority()
        root = Path(__file__).resolve().parent.parent
        admission = conformance.admit_layer1(self.authority, root)
        case = next(case for case in authority.snapshot_cases if case.checkpoint == "layer-6-success")
        value = authority.baselines[case.baseline or case.identifier]
        visited = []
        original = conformance.OperationBudget.__init__
        def empty(budget, contract):
            original(budget, contract)
            budget.maximum = 0
        with mock.patch.object(conformance.OperationBudget, "__init__", empty):
            with mock.patch.object(conformance.bounded_json, "load_bounded_json_matching_identity", return_value=value):
                with mock.patch.object(conformance, "_same_typed_snapshot", side_effect=lambda *args: visited.append(None) or True):
                    with self.assertRaises(conformance.OperationBudgetExceeded):
                        conformance.run_admitted_snapshot_case(authority, admission, case.identifier, root)
        self.assertEqual(visited, [])


class DiagnosticCases(unittest.TestCase):
    failureException = AccountingAssertionError
    @classmethod
    def setUpClass(cls):
        cls.authority = registry.load_task4_authority()
        cls.adapters = conformance._case_adapters()


def _install_diagnostics():
    authority = registry.load_task4_authority()
    for row in authority.validators["validator_cases"]:
        if row[0].startswith("v1-diagnostic-"):
            case = registry.LoaderCase(*row)
            def test(self, selected=case):
                try:
                    _, vector = conformance.measure_call(conformance.run_validator_case,
                        self.authority, selected, self.adapters)
                except AssertionError:
                    self.fail("diagnostic case rejected")
                self.assertEqual(vector, (0, 0, 0, 0, 0, 0, 2))
            setattr(DiagnosticCases, "test_" + case.identifier.replace("-", "_"), test)


_install_diagnostics()


if __name__ == '__main__':
    unittest.main()
