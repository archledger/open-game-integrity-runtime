#!/usr/bin/env python3
"""Independent literal-state and admitted-row history conformance tests."""

from __future__ import annotations

import copy
from dataclasses import fields, is_dataclass
import json
import os
from pathlib import Path
import tempfile
import traceback
import unittest
from unittest import mock

import abstract_conformance as conformance
import abstract_conformance_registry as registry


ROOT = Path(__file__).resolve().parent.parent


def initial_state() -> dict:
    """Hand-written complete state, not derived from the implementation/oracle."""
    return {
        "session": {"status": "active", "session_id": "session-alpha",
                    "publisher": "publisher-alpha", "live_subject": "subject-alpha",
                    "actual_public_key": "1" * 64, "session_public_key_id": "2" * 64,
                    "continuity": "intact"},
        "profile": {"profile_id": "profile-base-v1", "authority_contract": "authority-alpha",
                    "protected_source": "source-alpha", "profile_duration_ceiling": 100,
                    "publisher_duration_ceiling": 100, "effective_duration_ceiling": 100,
                    "policy_strength": 2},
        "challenge": {"status": "absent", "challenge_ref": None, "nonce": None,
                      "issued_tick": None, "expires_tick": None, "receipt_tick": None,
                      "consumed": False},
        "collection": {"status": "absent", "collection_ref": None, "challenge_ref": None,
                       "authority_contract": None, "protected_source": None,
                       "epoch_relation": None, "sequence": None, "collection_start": None,
                       "snapshot_freeze_end": None, "observation_ref": None,
                       "current_subject_revalidated": False, "origin_class": None},
        "evidence": {"proof_state": "absent", "coverage_state": "absent",
                     "authority_statement_state": "absent", "submitted_observation_ref": None,
                     "submission_receipt_tick": None},
        "high_water": {"status": "absent", "authority_contract": None,
                       "protected_source": None, "epoch_relation": None,
                       "greatest_sequence": None, "latest_freeze_end": None},
        "ordering": {"active_collection_ref": None, "in_flight_observation_ref": None,
                     "compare_generation": 0},
        "appraisal": {"claim_state": "not-appraised", "rejected_claim_meaning": None,
                      "policy_state": "not-appraised"},
        "retention": {"temporal_state": "absent", "deletion_required": False},
    }


def collection_state(*, renewed: bool = False, stage: str = "validated") -> dict:
    """Literal expected sections for the first collection or ordinary renewal."""
    state = initial_state()
    suffix, sequence, start, end = ("1", 2, 1300, 1400) if renewed else ("0", 1, 1100, 1200)
    state["challenge"] = {
        "status": "authenticated", "challenge_ref": "t-q" + suffix,
        "nonce": ("0" * 63) + ("2" if renewed else "1"),
        "issued_tick": 1501 if renewed else 1000,
        "expires_tick": 2500 if renewed else 2000,
        "receipt_tick": 1700 if renewed else 1500,
        "consumed": stage in {"submitted", "validated"},
    }
    state["collection"] = {
        "status": "open" if stage == "opened" else "frozen",
        "collection_ref": "t-c" + suffix, "challenge_ref": "t-q" + suffix,
        "authority_contract": "authority-alpha", "protected_source": "source-alpha",
        "epoch_relation": "epoch-alpha", "sequence": sequence, "collection_start": start,
        "snapshot_freeze_end": end,
        "observation_ref": None if stage == "opened" else "t-o" + suffix,
        "current_subject_revalidated": False, "origin_class": None,
    }
    state["ordering"]["active_collection_ref"] = "t-c" + suffix
    if renewed:
        state["high_water"] = {
            "status": "available", "authority_contract": "authority-alpha",
            "protected_source": "source-alpha", "epoch_relation": "epoch-alpha",
            "greatest_sequence": 1, "latest_freeze_end": 1200,
        }
        state["ordering"]["compare_generation"] = 1
        state["retention"]["temporal_state"] = "retained"
    if stage != "opened":
        state["evidence"] = {
            "proof_state": "pending", "coverage_state": "pending",
            "authority_statement_state": "authenticated", "submitted_observation_ref": None,
            "submission_receipt_tick": None,
        }
    if stage in {"submitted", "validated"}:
        state["evidence"] = {
            "proof_state": "covered", "coverage_state": "valid",
            "authority_statement_state": "authenticated", "submitted_observation_ref": "t-o" + suffix,
            "submission_receipt_tick": 1700 if renewed else 1500,
        }
        state["ordering"]["in_flight_observation_ref"] = "t-o" + suffix
    if stage == "validated":
        state["high_water"] = {
            "status": "available", "authority_contract": "authority-alpha",
            "protected_source": "source-alpha", "epoch_relation": "epoch-alpha",
            "greatest_sequence": sequence, "latest_freeze_end": end,
        }
        state["ordering"].update(in_flight_observation_ref=None, compare_generation=sequence)
        state["appraisal"].update(claim_state="accepted", policy_state="accepted")
        state["retention"]["temporal_state"] = "retained"
    return state


def lost_state(before: dict) -> dict:
    state = copy.deepcopy(before)
    state["session"].update(status="lost", continuity="lost")
    empty = initial_state()
    for section in ("challenge", "collection", "evidence"):
        state[section] = empty[section]
    state["high_water"] = {"status": "deleted", "authority_contract": None,
                           "protected_source": None, "epoch_relation": None,
                           "greatest_sequence": None, "latest_freeze_end": None}
    state["ordering"].update(active_collection_ref=None, in_flight_observation_ref=None)
    state["retention"] = {"temporal_state": "deleted", "deletion_required": False}
    return state


def terminal_state(*, deleted: bool) -> dict:
    state = collection_state(renewed=True)
    state["session"].update(status="ended", continuity="lost")
    empty = initial_state()
    for section in ("challenge", "collection", "evidence"):
        state[section] = empty[section]
    state["ordering"].update(active_collection_ref=None, in_flight_observation_ref=None)
    state["retention"] = {"temporal_state": "retained", "deletion_required": True}
    if deleted:
        state["high_water"] = lost_state(initial_state())["high_water"]
        state["retention"] = {"temporal_state": "deleted", "deletion_required": False}
    return state


def new_session_initial() -> dict:
    state = initial_state()
    state["session"].update(session_id="session-beta", live_subject="subject-beta",
                            actual_public_key="5" * 64, session_public_key_id="6" * 64)
    return state


def focused_final_state(transform: str) -> dict:
    """Hand-derived final full states for all forty semantic transformations."""
    if transform == "open-before-challenge-receipt":
        return initial_state()
    if transform in {"proof-before-snapshot-freeze", "omit-cached-current-subject-revalidation",
                     "omit-boot-origin-current-subject-revalidation"}:
        return collection_state(stage="opened")
    if transform == "change-after-snapshot-freeze":
        return collection_state(stage="frozen")
    if transform == "substitute-covered-challenge":
        return collection_state()
    if transform in {"reuse-collection-sequence", "decrease-collection-sequence"}:
        state = initial_state()
        state["ordering"]["compare_generation"] = 1
        return lost_state(state)
    if transform in {"change-protected-epoch", "reset-sequence-on-profile-transition"}:
        state = initial_state()
        state["ordering"]["compare_generation"] = 1
        state["profile"].update(profile_id="profile-extended-v1", authority_contract="authority-beta",
                                protected_source="source-beta")
        return lost_state(state)
    if transform in {"change-protected-source", "overlap-collection-interval"}:
        return lost_state(collection_state(renewed=True, stage="submitted"))
    if transform in {"restart-collection-authority", "restart-protected-source", "restart-protected-session",
                     "rollback-protected-source", "repair-high-water-from-client", "remove-temporal-high-water",
                     "corrupt-temporal-high-water", "contradict-temporal-high-water", "rollback-temporal-high-water"}:
        return lost_state(collection_state())
    if transform in {"discontinue-protected-source", "order-start-after-freeze-end"}:
        return lost_state(initial_state())
    if transform == "open-concurrent-collection":
        return collection_state(renewed=True, stage="opened")
    if transform == "race-temporal-compare-and-advance":
        return lost_state(collection_state(renewed=True))
    if transform in {"exceed-profile-duration-ceiling", "exceed-publisher-duration-ceiling"}:
        state = collection_state(stage="submitted")
        state["collection"]["snapshot_freeze_end"] = 1201 if transform == "exceed-profile-duration-ceiling" else 1151
        if transform == "exceed-publisher-duration-ceiling":
            state["profile"].update(publisher_duration_ceiling=50, effective_duration_ceiling=50)
        else:
            state["profile"]["publisher_duration_ceiling"] = 150
        state["evidence"] = initial_state()["evidence"]
        state["ordering"]["in_flight_observation_ref"] = None
        return state
    if transform in {"receive-at-challenge-expiry", "receive-after-challenge-expiry"}:
        state = collection_state(stage="frozen")
        state["challenge"]["receipt_tick"] = 1999
        state["evidence"] = initial_state()["evidence"]
        return state
    if transform in {"outage-collection-authority", "outage-temporal-store"}:
        state = collection_state()
        state["high_water"]["status"] = "unavailable"
        state["evidence"]["authority_statement_state"] = "unavailable"
        return state
    if transform == "reject-claim-after-temporal-advance":
        state = collection_state(renewed=True)
        state["appraisal"].update(claim_state="rejected", rejected_claim_meaning="platform-identity",
                                  policy_state="not-appraised")
        return state
    if transform == "reject-policy-after-temporal-advance":
        state = collection_state(renewed=True)
        state["appraisal"]["policy_state"] = "rejected"
        return state
    if transform in {"invalidate-abstract-coverage", "unauthenticate-authority-statement"}:
        return collection_state(renewed=True)
    if transform == "omit-terminal-temporal-deletion":
        return terminal_state(deleted=False)
    if transform == "reuse-ended-session-epoch":
        return lost_state(terminal_state(deleted=True))
    if transform in {"substitute-ended-epoch-in-new-session", "reuse-key-after-terminal"}:
        return lost_state(new_session_initial())
    if transform == "weaken-policy-with-same-key":
        return collection_state()
    raise AssertionError("unregistered literal state")


def literal_equal(left, right) -> bool:
    """Independent exact-type comparison; never formats modeled values."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(literal_equal(left[key], right[key]) for key in left)
    if isinstance(left, (list, tuple)):
        return len(left) == len(right) and all(literal_equal(a, b) for a, b in zip(left, right))
    if is_dataclass(left):
        return all(literal_equal(getattr(left, field.name), getattr(right, field.name)) for field in fields(left))
    return left == right


class HistoryAssertionError(AssertionError):
    def __init__(self, *_args):
        super().__init__("history assertion mismatch")
        self.__suppress_context__ = True


class HistoryTests(unittest.TestCase):
    failureException = HistoryAssertionError

    def assertEqual(self, first, second, msg=None):
        if not literal_equal(first, second):
            self.fail("history assertion mismatch")

    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = registry.load_task4_authority()

    def baseline(self, identifier="history-valid-initial-collection") -> dict:
        row = next(row for row in self.authority.histories["baselines"] if row["id"] == identifier)
        return copy.deepcopy(row)

    def test_outage_requires_intact_independent_recovery(self) -> None:
        transform = next(row for row in self.authority.histories["negative_transforms"] if row["id"] == "outage-temporal-store")
        baseline = self.baseline(transform["baseline"])
        changed = conformance._apply_fixture_transform(baseline, transform)
        outage = next(row for row in changed["candidate"]["actions"] if row["label"] == "outage")
        trusted_ref = "t-" + outage["args"][1][2:]
        trusted = next(row for row in baseline["oracle"]["trusted_recoveries"] if row["id"] == trusted_ref)
        trusted["intact"] = False
        result, _, state = conformance.evaluate_history(self.authority, changed["candidate"], baseline["oracle"])
        self.assertEqual(result, "ProtectedSessionLost")
        self.assertEqual(state, lost_state(collection_state()))

    def test_outage_reference_guard_is_terminal_and_follows_component_guard(self) -> None:
        transform = next(row for row in self.authority.histories["negative_transforms"] if row["id"] == "outage-temporal-store")
        baseline = self.baseline(transform["baseline"])
        changed = conformance._apply_fixture_transform(baseline, transform)
        outage = next(row for row in changed["candidate"]["actions"] if row["label"] == "outage")
        trusted_ref = "t-" + outage["args"][1][2:]
        baseline["oracle"]["trusted_recoveries"] = [row for row in baseline["oracle"]["trusted_recoveries"] if row["id"] != trusted_ref]
        result, _, state = conformance.evaluate_history(self.authority, changed["candidate"], baseline["oracle"])
        self.assertEqual(result, "ProtectedSessionLost")
        self.assertEqual(state, lost_state(collection_state()))
        outage["args"] = ["unknown-component", "c-missing"]
        result, _, state = conformance.evaluate_history(self.authority, changed["candidate"], baseline["oracle"])
        self.assertEqual(result, "AttestationUnavailable")
        self.assertEqual(state, collection_state())

    def test_assertion_traceback_suppresses_sensitive_exception_context(self) -> None:
        sentinel = "private-sentinel-value"
        try:
            with self.assertRaisesRegex(ValueError, "expected-fixed"):
                raise ValueError(sentinel)
        except self.failureException as error:
            rendered = "".join(traceback.format_exception(error))
            if sentinel in rendered or "history assertion mismatch" not in rendered:
                raise AssertionError("unsafe assertion traceback") from None
        else:
            raise AssertionError("missing assertion rejection")

    def test_assertion_failure_diagnostics_are_fixed_and_type_sensitive(self) -> None:
        for operation in (lambda: self.assertEqual({"key": "modeled-sentinel"}, {}),
                          lambda: self.assertIn("modeled-sentinel", []),
                          lambda: self.assertEqual({"field": True}, {"field": 1})):
            try:
                operation()
            except self.failureException as error:
                if str(error) != "history assertion mismatch":
                    raise AssertionError("unsafe assertion diagnostics") from None
            else:
                raise AssertionError("missing assertion rejection")

    def test_renewal_context_failure_precedes_policy_failure(self) -> None:
        baseline = self.baseline("history-valid-same-session-renewal")
        baseline["oracle"]["trusted_authorities"][1]["publisher"] = "publisher-beta"
        baseline["oracle"]["trusted_profiles"][0]["policy_strength"] = 1
        trusted, _ = conformance.replay_history_oracle(self.authority, baseline["oracle"])
        self.assertEqual(trusted[4]["expected_disposition"], "ContextBindingMismatch")
        result, transitions, state = conformance.evaluate_history(self.authority, baseline["candidate"], baseline["oracle"])
        self.assertEqual(result, "ContextBindingMismatch")
        self.assertEqual(len(transitions), 5)
        self.assertEqual(state, collection_state())

    def test_concurrent_nested_validation_failure_still_loses_session(self) -> None:
        baseline = self.baseline("history-valid-same-session-renewal")
        baseline["candidate"]["collections"][1]["snapshot_freeze_end"] = 1401
        baseline["oracle"]["trusted_authorities"][1]["snapshot_freeze_end"] = 1401
        baseline["candidate"]["actions"][-1] = {"label": "concurrent-submit", "args": ["c-o1", "c-o2"]}
        baseline["oracle"]["actions"][-1] = {"label": "concurrent-submit", "args": ["t-o1", "t-o2"]}
        result, rebuilt = conformance.reconstruct_history(self.authority, baseline["candidate"], baseline["oracle"])
        self.assertEqual(result, "Conform")
        self.assertEqual(conformance.check_history_coverage(self.authority, baseline["candidate"], rebuilt), "Conform")
        trusted, expected = conformance.replay_history_oracle(self.authority, baseline["oracle"])
        literal = lost_state(collection_state(renewed=True, stage="submitted"))
        self.assertEqual(trusted[-1]["expected_disposition"], "ProtectedSessionLost")
        self.assertEqual(expected, literal)
        result, _, state = conformance.evaluate_history(self.authority, baseline["candidate"], baseline["oracle"])
        self.assertEqual(result, "ProtectedSessionLost")
        self.assertEqual(state, literal)

    def test_action_challenge_alias_rejects_before_collection_or_advance(self) -> None:
        baseline = self.baseline()
        alias = next(row for row in baseline["candidate"]["challenges"] if row["id"] == "c-q-alt")
        alias.update(baseline["candidate"]["challenges"][0], id="c-q-alt")
        baseline["candidate"]["actions"][0]["args"][0] = "c-q-alt"
        result, rebuilt = conformance.reconstruct_history(self.authority, baseline["candidate"], baseline["oracle"])
        self.assertEqual(result, "Conform")
        self.assertEqual(conformance.check_history_coverage(self.authority, baseline["candidate"], rebuilt), "Conform")
        result, transitions, state = conformance.evaluate_history(self.authority, baseline["candidate"], baseline["oracle"])
        self.assertEqual(result, "ContextBindingMismatch")
        self.assertEqual(len(transitions), 1)
        self.assertEqual(state, initial_state())

    def test_challenge_alias_cannot_substitute_independent_reference(self) -> None:
        for status in ("authenticated", "absent"):
            baseline = self.baseline()
            alias = next(row for row in baseline["candidate"]["challenges"] if row["id"] == "c-q-alt")
            alias.update(baseline["candidate"]["challenges"][0], id="c-q-alt", status=status)
            baseline["candidate"]["observations"][0]["challenge_ref"] = "c-q-alt"
            result, rebuilt = conformance.reconstruct_history(self.authority, baseline["candidate"], baseline["oracle"])
            self.assertEqual(result, "ContextBindingMismatch")
            self.assertIsNone(rebuilt)

    def test_initial_replay_emits_every_complete_literal_transition(self) -> None:
        baseline = self.baseline()
        before = copy.deepcopy(baseline)
        transitions, final = conformance.replay_history_oracle(self.authority, baseline["oracle"])
        expected = [initial_state()] + [collection_state(stage=stage) for stage in
                                      ("opened", "frozen", "submitted", "validated")]
        self.assertEqual(len(transitions), 4)
        for index, transition in enumerate(transitions):
            self.assertEqual(transition, {
                "action_index": index, "action": baseline["oracle"]["actions"][index],
                "expected_disposition": "Conform", "pre_state": expected[index],
                "post_state": expected[index + 1],
            })
        self.assertEqual(final, expected[-1])
        self.assertEqual(baseline, before)

    def test_renewal_preserves_literal_high_water_and_closed_profile(self) -> None:
        baseline = self.baseline("history-valid-same-session-renewal")
        transitions, final = conformance.replay_history_oracle(self.authority, baseline["oracle"])
        self.assertEqual(len(transitions), 8)
        self.assertEqual(transitions[4]["pre_state"], collection_state())
        for index, stage in enumerate(("opened", "frozen", "submitted", "validated"), 4):
            self.assertEqual(transitions[index]["post_state"], collection_state(renewed=True, stage=stage))
        self.assertEqual(final, collection_state(renewed=True))

    def test_candidate_initial_derivation_matches_literal_state(self) -> None:
        baseline = self.baseline()
        disposition, transitions, final = conformance.evaluate_history(
            self.authority, baseline["candidate"], baseline["oracle"])
        self.assertEqual(disposition, "Conform")
        self.assertEqual(final, collection_state())
        self.assertEqual(len(transitions), 4)

    def test_every_positive_history_has_independent_equal_complete_states(self) -> None:
        for row in self.authority.histories["baselines"]:
            baseline = copy.deepcopy(row)
            before = copy.deepcopy(baseline)
            trusted, expected = conformance.replay_history_oracle(self.authority, baseline["oracle"])
            disposition, candidate, actual = conformance.evaluate_history(
                self.authority, baseline["candidate"], baseline["oracle"])
            with self.subTest(baseline=row["id"]):
                self.assertEqual(disposition, "Conform")
                self.assertEqual(actual, expected)
                self.assertEqual(candidate, trusted)
                self.assertEqual(baseline, before)

    def run_focused(self, transform: str, layer: int, expected: str) -> None:
        before = copy.deepcopy(self.authority)
        self.assertEqual(conformance.run_history_focused_case(self.authority, transform, layer), expected)
        self.assertEqual(self.authority, before)

    def run_literal_state(self, identifier: str, expected: str) -> None:
        transform = next(row for row in self.authority.histories["negative_transforms"] if row["id"] == identifier)
        baseline = self.baseline(transform["baseline"])
        changed = conformance._apply_fixture_transform(baseline, transform)
        result, prerequisites = conformance.reconstruct_history(self.authority, baseline["candidate"], baseline["oracle"])
        self.assertEqual(result, "Conform")
        disposition, transitions, final = conformance.evaluate_history(
            self.authority, changed["candidate"], baseline["oracle"], prerequisites)
        self.assertEqual(disposition, expected)
        self.assertEqual(final, focused_final_state(identifier))
        self.assertTrue(transitions)
        self.assertEqual(transitions[-1]["post_state"], final)

    def test_invalid_coverage_never_advances_candidate_high_water(self) -> None:
        for identifier in ("invalidate-abstract-coverage", "unauthenticate-authority-statement"):
            transform = next(row for row in self.authority.histories["negative_transforms"] if row["id"] == identifier)
            baseline = self.baseline(transform["baseline"])
            changed = conformance._apply_fixture_transform(baseline, transform)
            expected = collection_state(renewed=True, stage="submitted")
            expected["evidence"] = initial_state()["evidence"]
            expected["ordering"]["in_flight_observation_ref"] = None
            disposition, _, actual = conformance.evaluate_history(self.authority, changed["candidate"], baseline["oracle"])
            self.assertEqual(disposition, "EvidenceInvalid")
            self.assertEqual(actual, expected)

    def test_keyed_reconstruction_and_replay_ignore_registry_array_order(self) -> None:
        baseline = self.baseline("history-valid-same-session-renewal")
        original = copy.deepcopy(baseline)
        for rows in baseline["candidate"].values():
            if isinstance(rows, list) and rows and "label" not in rows[0]:
                rows.reverse()
        for name, rows in baseline["oracle"].items():
            if name not in {"actions", "initial_state"}:
                rows.reverse()
        self.assertEqual(conformance.reconstruct_history(self.authority, baseline["candidate"], baseline["oracle"]),
                         conformance.reconstruct_history(self.authority, original["candidate"], original["oracle"]))
        self.assertEqual(conformance.replay_history_oracle(self.authority, baseline["oracle"]),
                         conformance.replay_history_oracle(self.authority, original["oracle"]))
        self.assertEqual(conformance.evaluate_history(self.authority, baseline["candidate"], baseline["oracle"]),
                         conformance.evaluate_history(self.authority, original["candidate"], original["oracle"]))

    def test_candidate_reference_never_falls_back_to_trusted_registry(self) -> None:
        baseline = self.baseline()
        baseline["candidate"]["actions"][0]["args"][0] = "t-q0"
        disposition, _, final = conformance.evaluate_history(self.authority, baseline["candidate"], baseline["oracle"])
        self.assertEqual(disposition, "EvidenceInvalid")
        self.assertEqual(final, initial_state())

    def test_duplicate_or_missing_counterpart_cannot_bless_observation(self) -> None:
        for duplicate in (True, False):
            baseline = self.baseline()
            if duplicate:
                baseline["oracle"]["observation_oracles"] *= 2
            else:
                baseline["oracle"]["observation_oracles"] = []
            self.assertEqual(conformance.reconstruct_history(self.authority, baseline["candidate"], baseline["oracle"]),
                             ("EvidenceInvalid", None))

    def test_focused_prerequisites_are_fresh_and_coverage_checked(self) -> None:
        with mock.patch.object(conformance, "check_history_coverage", return_value="EvidenceInvalid"):
            with self.assertRaisesRegex(AssertionError, "^history focused baseline coverage$"):
                conformance.run_history_focused_case(self.authority, "invalidate-abstract-coverage", 6)

    def test_initial_temporal_substitution_rejects_before_high_water_advance(self) -> None:
        for field, replacement in (("epoch_relation", "epoch-beta"), ("sequence", 2),
                                   ("authority_contract", "authority-beta"), ("protected_source", "source-beta")):
            baseline = self.baseline()
            baseline["candidate"]["collections"][0][field] = replacement
            with self.subTest(field=field):
                disposition, transitions, final = conformance.evaluate_history(
                    self.authority, baseline["candidate"], baseline["oracle"])
                self.assertEqual(disposition, "EvidenceInvalid")
                self.assertEqual(final["high_water"], initial_state()["high_water"])
                self.assertEqual(final["ordering"]["compare_generation"], 0)
                self.assertEqual(transitions[-1]["action"]["label"], "validate")

    def test_unavailable_trusted_authority_preserves_initial_state(self) -> None:
        baseline = self.baseline()
        baseline["oracle"]["trusted_authorities"][0]["availability"] = "unavailable"
        disposition, transitions, final = conformance.evaluate_history(
            self.authority, baseline["candidate"], baseline["oracle"])
        self.assertEqual(disposition, "AttestationUnavailable")
        self.assertEqual(final, initial_state())
        self.assertEqual(len(transitions), 1)

    def test_unauthenticated_trusted_challenge_preserves_initial_state(self) -> None:
        baseline = self.baseline()
        baseline["oracle"]["trusted_challenges"][0]["status"] = "absent"
        disposition, _, final = conformance.evaluate_history(self.authority, baseline["candidate"], baseline["oracle"])
        self.assertEqual(disposition, "EvidenceInvalid")
        self.assertEqual(final, initial_state())

    def test_trusted_authority_context_mismatch_preserves_initial_state(self) -> None:
        baseline = self.baseline()
        baseline["oracle"]["trusted_authorities"][0]["publisher"] = "publisher-beta"
        disposition, _, final = conformance.evaluate_history(self.authority, baseline["candidate"], baseline["oracle"])
        self.assertEqual(disposition, "ContextBindingMismatch")
        self.assertEqual(final, initial_state())

    def test_recovery_does_not_restore_before_later_policy_guard(self) -> None:
        baseline = self.baseline("history-valid-store-outage-recovery")
        baseline["candidate"]["sessions"][0]["policy_strength"] = 1
        expected = initial_state()
        expected["high_water"] = {"status": "unavailable", "authority_contract": "authority-alpha",
                                  "protected_source": "source-alpha", "epoch_relation": "epoch-alpha",
                                  "greatest_sequence": 1, "latest_freeze_end": 1200}
        expected["ordering"]["compare_generation"] = 1
        expected["appraisal"].update(claim_state="accepted", policy_state="accepted")
        expected["retention"]["temporal_state"] = "retained"
        disposition, _, actual = conformance.evaluate_history(self.authority, baseline["candidate"], baseline["oracle"])
        self.assertEqual(disposition, "PolicyDenied")
        self.assertEqual(actual, expected)

    def test_candidate_evaluation_never_mutates_oracle(self) -> None:
        baseline = self.baseline()
        before = copy.deepcopy(baseline["oracle"])
        conformance.evaluate_history(self.authority, baseline["candidate"], baseline["oracle"])
        self.assertEqual(baseline["oracle"], before)

    def test_terminal_deletion_complete_literal_states(self) -> None:
        baseline = self.baseline("history-valid-terminal-end-deletion")
        transitions, final = conformance.replay_history_oracle(self.authority, baseline["oracle"])
        self.assertEqual(transitions[8]["post_state"], terminal_state(deleted=False))
        self.assertEqual(final, terminal_state(deleted=True))

    def test_trusted_duration_rejection_preserves_unadvanced_state(self) -> None:
        baseline = self.baseline()
        baseline["oracle"]["trusted_authorities"][0]["snapshot_freeze_end"] = 1201
        transitions, final = conformance.replay_history_oracle(self.authority, baseline["oracle"])
        expected = collection_state(stage="submitted")
        expected["collection"]["snapshot_freeze_end"] = 1201
        expected["evidence"] = initial_state()["evidence"]
        expected["ordering"]["in_flight_observation_ref"] = None
        self.assertEqual(transitions[-1]["expected_disposition"], "EvidenceInvalid")
        self.assertEqual(final, expected)

    def test_materializes_complete_reproducible_history_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            conformance.build_task7_corpus(self.authority, root)
            self.assertTrue((root / "lab/conformance/corpus.json").is_file())
            corpus = root / "lab/conformance"
            self.assertEqual(len(list((corpus / "snapshots").iterdir())), 69)
            self.assertEqual(len(list((corpus / "histories").iterdir())), 55)
            admission = conformance.admit_layer1(self.authority, root)
            for row in admission._manifest_value()["fixtures"]:
                if row[1] != "history":
                    continue
                case = registry.FixtureCase(*row)
                with self.subTest(case=case.identifier):
                    self.assertEqual((corpus / case.path).read_bytes(),
                                     conformance.reproduce_history_fixture(self.authority, case))
                    self.assertEqual(conformance.run_admitted_history_case(self.authority, admission, case.identifier, root),
                                     (case.checkpoint, case.disposition))

    def test_materializer_never_follows_dangling_file_or_directory_symlinks(self) -> None:
        for relative in ("lab/conformance/corpus.json", "lab", "lab/conformance",
                         "lab/conformance/snapshots", "lab/conformance/histories"):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                root.mkdir()
                link = root / relative
                link.parent.mkdir(parents=True, exist_ok=True)
                target = Path(temporary) / "outside"
                if not relative.endswith(".json"):
                    target.mkdir()
                os.symlink(target, link)
                with self.subTest(relative=relative):
                    with self.assertRaises(conformance._TransformError):
                        conformance.build_task7_corpus(self.authority, root)
                    if relative.endswith(".json"):
                        self.assertFalse(target.exists())
                    else:
                        self.assertEqual(list(target.iterdir()), [])

    def test_checked_in_complete_history_inventory_and_normal_results(self) -> None:
        corpus = ROOT / "lab/conformance"
        self.assertEqual(len(list((corpus / "histories").iterdir())), 55)
        admission = conformance.admit_layer1(self.authority, ROOT)
        for row in admission._manifest_value()["fixtures"]:
            if row[1] == "history":
                case = registry.FixtureCase(*row)
                self.assertEqual((corpus / case.path).read_bytes(), conformance.reproduce_history_fixture(self.authority, case))
                self.assertEqual(conformance.run_admitted_history_case(self.authority, admission, case.identifier, ROOT),
                                 (case.checkpoint, case.disposition))

    def test_history_pipeline_stops_at_each_earliest_failing_layer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            conformance.build_task7_corpus(self.authority, root)
            admission = conformance.admit_layer1(self.authority, root)
            for identifier, expected, calls in (
                ("history-client-utc-substitution", ("layer-3", "Malformed"), (0, 0, 0)),
                ("history-cross-challenge-substitution", ("layer-4", "ContextBindingMismatch"), (1, 0, 0)),
                ("history-invalid-coverage-no-advance", ("layer-5", "EvidenceInvalid"), (1, 1, 0)),
                ("history-policy-rejected-after-advance", ("layer-6", "PolicyDenied"), (1, 1, 1)),
            ):
                with mock.patch.object(conformance, "reconstruct_history", wraps=conformance.reconstruct_history) as reconstruction, \
                     mock.patch.object(conformance, "check_history_coverage", wraps=conformance.check_history_coverage) as coverage, \
                     mock.patch.object(conformance, "evaluate_history", wraps=conformance.evaluate_history) as lifecycle:
                    self.assertEqual(conformance.run_admitted_history_case(self.authority, admission, identifier, root), expected)
                    self.assertEqual((reconstruction.call_count, coverage.call_count, lifecycle.call_count), calls)

    def test_internal_contract_errors_are_fixed_and_input_independent(self) -> None:
        for text in ("unknown", "::error::private-material", "/private/home/secret"):
            baseline = self.baseline()
            baseline["oracle"]["actions"][0]["label"] = text
            with self.assertRaisesRegex(ValueError, "^history internal contract$"):
                conformance.replay_history_oracle(self.authority, baseline["oracle"])
            baseline = self.baseline()
            baseline["candidate"]["actions"][0]["args"][0] = text
            self.assertEqual(conformance.evaluate_history(self.authority, baseline["candidate"], baseline["oracle"])[0], "EvidenceInvalid")

    def test_integer_and_boolean_values_never_alias_in_trusted_guards(self) -> None:
        baseline = self.baseline()
        baseline["oracle"]["observation_oracles"][0]["current_subject_revalidated"] = 1
        transitions, _ = conformance.replay_history_oracle(self.authority, baseline["oracle"])
        self.assertEqual(transitions[1]["expected_disposition"], "EvidenceInvalid")
        self.assertEqual(transitions[1]["post_state"], collection_state(stage="opened"))

    def test_checked_increment_overflow_and_boolean_receipt_fail_closed(self) -> None:
        baseline = self.baseline()
        domain = self.authority.validators["domains"]["Natural"]
        maximum = domain["maximum"]
        index = self.authority.histories["state_tuple_fields"].index("ordering.compare_generation")
        baseline["oracle"]["initial_state"][index] = maximum
        with self.assertRaisesRegex(ValueError, "^history internal contract$"):
            conformance.replay_history_oracle(self.authority, baseline["oracle"])
        disposition, _, final = conformance.evaluate_history(self.authority, baseline["candidate"], baseline["oracle"])
        expected = collection_state(stage="submitted")
        expected["ordering"]["compare_generation"] = maximum
        self.assertEqual(disposition, "EvidenceInvalid")
        self.assertEqual(final, expected)
        baseline = self.baseline()
        baseline["candidate"]["actions"][2]["args"][1] = True
        disposition, _, final = conformance.evaluate_history(self.authority, baseline["candidate"], baseline["oracle"])
        self.assertEqual(disposition, "EvidenceInvalid")
        self.assertEqual(final, collection_state(stage="frozen"))


def install_focused_tests() -> None:
    authority = registry.load_task4_authority()
    for transform, *expected in authority.histories["focused_expected_tuples"]:
        def state_test(self, selected=transform, selected_result=expected[2]):
            self.run_literal_state(selected, selected_result)
        setattr(HistoryTests, "test_literal_state_" + transform.replace("-", "_"), state_test)
        for layer, result in zip((4, 5, 6), expected, strict=True):
            def test(self, selected=transform, selected_layer=layer, selected_result=result):
                self.run_focused(selected, selected_layer, selected_result)
            setattr(HistoryTests, "test_focused_layer_" + str(layer) + "_" + transform.replace("-", "_"), test)


install_focused_tests()

if __name__ == "__main__":
    unittest.main(verbosity=2)
