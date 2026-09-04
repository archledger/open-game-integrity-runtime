"""Representation-neutral abstract-conformance validation."""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import stat
import tempfile
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Any, NoReturn

import abstract_conformance_registry as registry
import bounded_json


LAYER1_DIAGNOSTIC = "abstract-conformance:layer-1:malformed"
LAYER2_DIAGNOSTIC = "abstract-conformance:layer-2:malformed"


class OperationBudgetExceeded(RuntimeError):
    """Fixed, value-independent budget failure; never a semantic rejection."""

    def __init__(self):
        super().__init__("abstract-conformance:internal:operation-budget-exhausted")


class OperationBudget:
    """Invocation-local counters, presented in the admitted category order."""

    def __init__(self, contract):
        self.categories = tuple(contract["category_order"])
        self.maximum = contract["allowed_maximum"]
        self._counts = dict.fromkeys(self.categories, 0)
        self.total = 0

    @property
    def vector(self):
        return tuple(self._counts[category] for category in self.categories)

    def charge(self, category):
        if category not in self._counts:
            raise RuntimeError("abstract-conformance:internal:internal-failure")
        self._counts[category] += 1
        self.total += 1
        if self.total > self.maximum:
            raise OperationBudgetExceeded() from None


_CURRENT_BUDGET = ContextVar("abstract_conformance_budget", default=None)
_COMPARISON_CATEGORY = ContextVar("abstract_conformance_comparison", default="oracle_assertions")
_BUDGET_OBSERVER = ContextVar("abstract_conformance_observer", default=None)


@contextmanager
def operation_scope(authority):
    """Fresh scope, including for nested validations; restore even on failure."""
    budget = OperationBudget(authority.core["operation_charging"])
    token = _CURRENT_BUDGET.set(budget)
    category_token = _COMPARISON_CATEGORY.set("oracle_assertions")
    try:
        yield budget
    finally:
        _COMPARISON_CATEGORY.reset(category_token)
        _CURRENT_BUDGET.reset(token)
        observer = _BUDGET_OBSERVER.get()
        if observer is not None:
            observer.append(budget.vector)


def _charge(category):
    budget = _CURRENT_BUDGET.get()
    if budget is not None:
        budget.charge(category)


def _metered(function):
    @wraps(function)
    def run(authority, *args, **kwargs):
        with operation_scope(authority):
            return function(authority, *args, **kwargs)
    return run


def measure_call(function, *args, **kwargs):
    """Observe one public invocation without lending it a caller's budget."""
    vectors = []
    token = _BUDGET_OBSERVER.set(vectors)
    try:
        result = function(*args, **kwargs)
    finally:
        _BUDGET_OBSERVER.reset(token)
    if len(vectors) != 1:
        raise RuntimeError("abstract-conformance:internal:internal-failure")
    return result, vectors[0]


def _compared(category, left, right):
    token = _COMPARISON_CATEGORY.set(category)
    try:
        return _same_json_value(left, right)
    finally:
        _COMPARISON_CATEGORY.reset(token)


def _visit_decoded_node():
    _charge("decoded_node_visits")


def _history_error() -> NoReturn:
    raise ValueError("history internal contract")


def _history_record(records: list[dict[str, Any]], identifier: Any) -> dict[str, Any]:
    matches = [row for row in records if _same_json_value(row["id"], identifier)]
    if len(matches) != 1:
        _history_error()
    return copy.deepcopy(matches[0])


def _history_initial(authority: registry.Task4Authority, oracle: dict[str, Any]) -> dict[str, Any]:
    fields = authority.histories["state_tuple_fields"]
    values = oracle["initial_state"]
    if len(fields) != len(values):
        _history_error()
    state: dict[str, Any] = {}
    for field, value in zip(fields, values, strict=True):
        section, name = field.split(".")
        state.setdefault(section, {})[name] = copy.deepcopy(value)
    _history_check_state(authority, state)
    return state


def _history_check_state(authority: registry.Task4Authority, state: dict[str, Any]) -> None:
    if not _valid_typed(state, authority.validators["schemas"]["LifecycleState"],
                        authority.validators["schemas"], authority.validators["domains"]):
        _history_error()


def _history_number(authority: registry.Task4Authority, value: Any, domain: str = "Natural") -> int:
    if type(value) is not int or not _valid_domain(value, domain, authority.validators["domains"]):
        _history_error()
    return value


def _history_clear(authority: registry.Task4Authority, state: dict[str, Any], section: str) -> None:
    state[section] = copy.deepcopy(authority.histories["empty_values"][section])
    if section == "collection":
        state["ordering"]["active_collection_ref"] = None
    if section == "evidence":
        state["ordering"]["in_flight_observation_ref"] = None


def _history_delete(authority: registry.Task4Authority, state: dict[str, Any]) -> None:
    state["high_water"] = copy.deepcopy(authority.histories["empty_values"]["high_water_deleted"])
    state["retention"] = {"temporal_state": "deleted", "deletion_required": False}


def _history_loss(authority: registry.Task4Authority, state: dict[str, Any]) -> None:
    state["session"].update(status="lost", continuity="lost")
    for section in ("challenge", "collection", "evidence"):
        _history_clear(authority, state, section)
    _history_delete(authority, state)


def _history_advance(authority: registry.Task4Authority, state: dict[str, Any]) -> None:
    collection = state["collection"]
    generation = _history_number(
        authority, _history_number(authority, state["ordering"]["compare_generation"]) + 1)
    state["high_water"] = {
        "status": "available",
        **{field: collection[field] for field in ("authority_contract", "protected_source", "epoch_relation")},
        "greatest_sequence": collection["sequence"],
        "latest_freeze_end": collection["snapshot_freeze_end"],
    }
    state["ordering"]["compare_generation"] = generation
    state["ordering"]["in_flight_observation_ref"] = None
    state["retention"]["temporal_state"] = "retained"


def _history_operand(value: Any, state: dict[str, Any], arguments: dict[str, Any],
                     bindings: dict[str, Any]) -> Any:
    if not isinstance(value, str):
        return copy.deepcopy(value)
    parts = value.split(".")
    if parts[0] == "state":
        selected = state
        parts = parts[1:]
    elif parts[0] in bindings:
        selected = bindings[parts[0]]
        parts = parts[1:]
    elif value in arguments:
        return copy.deepcopy(arguments[value])
    else:
        return value
    for part in parts:
        if not isinstance(selected, dict) or part not in selected:
            _history_error()
        selected = selected[part]
    return copy.deepcopy(selected)


def _history_guard(authority, oracle, state, arguments, bindings, guard) -> bool:
    _charge("oracle_assertions")
    left, operator, right = guard[:3]
    left = _history_operand(left, state, arguments, bindings)
    right = _history_operand(right, state, arguments, bindings)
    if operator == "eq":
        return _same_json_value(left, right)
    if operator == "in":
        return any(_same_json_value(left, item) for item in right)
    if operator == "is-null":
        return left is None
    if operator in {"lt", "lte", "gt"}:
        left, right = _history_number(authority, left), _history_number(authority, right)
        return {"lt": left < right, "lte": left <= right, "gt": left > right}[operator]
    if operator == "trusted-ref-exists":
        return sum(_same_json_value(row["id"], left) for row in oracle[right]) == 1
    if operator == "duration-within-effective-ceiling":
        start = _history_number(authority, left["collection_start"], "ProtectedTick")
        end = _history_number(authority, left["snapshot_freeze_end"], "ProtectedTick")
        ceilings = [_history_number(authority, right[field], "Duration")
                    for field in ("profile_duration_ceiling", "publisher_duration_ceiling")]
        return start <= end and end - start <= min(ceilings)
    if operator == "matches-active-session":
        return all(_same_json_value(left[field], state["session"][field]) for field in
                   ("publisher", "live_subject", "actual_public_key", "session_public_key_id")) and (
            _history_record(oracle["trusted_sessions"], left["session_ref"])["session_id"]
            == state["session"]["session_id"])
    if operator == "matches-high-water":
        if right["status"] == "absent":
            return True
        if right["status"] != "available":
            return False
        pair = ("authority_contract", "protected_source")
        same_pair = all(left[field] == right[field] for field in pair)
        profile = bindings["trusted_profile"]
        observation = bindings["trusted_observation"]
        collection = _history_record(oracle["trusted_authorities"], observation["collection_ref"])
        registered_transition = all(left[field] == profile[field] for field in pair) and all(
            collection[field] == "intact" for field in ("authority_continuity", "source_continuity"))
        return (left["epoch_relation"] == right["epoch_relation"]
                and _history_number(authority, left["sequence"], "ProtectedSequence")
                > _history_number(authority, right["greatest_sequence"], "ProtectedSequence")
                and _history_number(authority, left["collection_start"], "ProtectedTick")
                >= _history_number(authority, right["latest_freeze_end"], "ProtectedTick")
                and (same_pair or registered_transition))
    if operator == "recoverable":
        if left["status"] == "available":
            return True
        recovery = bindings.get("trusted_recovery")
        return (left["status"] == "unavailable" and recovery is not None
                and recovery["intact"] is True
                and recovery["component"] in {"collection-authority", "temporal-store"}
                and recovery["fresh_challenge_ref"] == arguments["challenge_ref"]
                and recovery["temporal_state"]["status"] == "available"
                and all(_same_json_value(value, recovery["temporal_state"][field])
                        for field, value in left.items() if field != "status"))
    if operator == "policy-not-weakened":
        return _history_number(authority, left["policy_strength"]) >= _history_number(authority, right["policy_strength"])
    if operator == "different-new-session":
        if left["predecessor_session_id"] is None:
            return True
        return (left["session_id"] != left["predecessor_session_id"]
                and left["actual_public_key"] != left["predecessor_actual_public_key"]
                and left["session_public_key_id"] != left["predecessor_session_public_key_id"]
                and right != left["predecessor_epoch"])
    _history_error()


def _history_effect(authority, oracle, state, arguments, bindings, effect) -> None:
    if isinstance(effect, list):
        operation, path, operand = effect
        if operation != "set" or not path.startswith("state."):
            _history_error()
        parts = path.split(".")[1:]
        target = state
        for part in parts[:-1]:
            target = target[part]
        if parts[-1] not in target:
            _history_error()
        target[parts[-1]] = _history_operand(operand, state, arguments, bindings)
    elif effect == "identity":
        return
    elif effect.startswith("clear-"):
        _history_clear(authority, state, effect.removeprefix("clear-"))
    elif effect == "load-challenge":
        challenge = bindings["trusted_challenge"]
        state["challenge"] = {field: copy.deepcopy(challenge[field])
                              for field in state["challenge"] if field in challenge}
        state["challenge"].update(status="authenticated", challenge_ref=challenge["id"], consumed=False)
    elif effect == "open-collection":
        collection = bindings["trusted_authority"]
        _history_clear(authority, state, "collection")
        state["collection"].update({field: copy.deepcopy(collection[field])
                                    for field in state["collection"] if field in collection})
        state["collection"].update(status="open", collection_ref=collection["id"], observation_ref=None)
        state["ordering"]["active_collection_ref"] = collection["id"]
    elif effect == "freeze-observation":
        state["collection"].update(status="frozen", observation_ref=arguments["observation_ref"])
        state["evidence"].update(proof_state="pending", coverage_state="pending",
                                  authority_statement_state=bindings["trusted_authority"]["authority_statement_state"])
    elif effect == "submit-observation":
        observation = bindings["trusted_observation"]
        state["challenge"].update(receipt_tick=arguments["receipt_tick"], consumed=True)
        state["evidence"].update(
            proof_state="covered", coverage_state=observation["coverage_state"],
            authority_statement_state=observation["authority_statement_state"],
            submitted_observation_ref=observation["id"], submission_receipt_tick=arguments["receipt_tick"])
        state["ordering"]["in_flight_observation_ref"] = observation["id"]
    elif effect == "advance-high-water":
        _history_advance(authority, state)
    elif effect in {"restore-high-water", "restore-high-water-if-needed"}:
        if effect == "restore-high-water" or state["high_water"]["status"] == "unavailable":
            state["high_water"] = copy.deepcopy(bindings["trusted_recovery"]["temporal_state"])
            state["high_water"]["status"] = "available"
    elif effect == "terminal-loss":
        _history_loss(authority, state)
    elif effect == "concurrent-first-wins-then-loss":
        disposition, advanced = _history_trusted_step(authority, oracle, state,
            {"label": "validate", "args": [arguments["first_observation_ref"]]})
        if disposition == "Conform":
            state.clear()
            state.update(advanced)
        _history_loss(authority, state)
    elif effect == "delete-high-water":
        _history_delete(authority, state)
    else:
        _history_error()


def _history_trusted_step(authority, oracle, current, action):
    _charge("history_actions")
    state = copy.deepcopy(current)
    rules = [rule for rule in authority.histories["action_rules"] if rule["label"] == action["label"]]
    if len(rules) != 1 or len(action["args"]) != len(rules[0]["arguments"]):
        _history_error()
    rule = rules[0]
    arguments = dict(zip(rule["arguments"], action["args"], strict=True))
    bindings: dict[str, Any] = {}
    resolution = authority.histories["interpreter"]["record_resolution"][action["label"]]
    for name, specification in resolution.items():
        if isinstance(specification, dict):
            condition = specification["required_only_when"]
            if not _history_guard(authority, oracle, state, arguments, bindings,
                                  [condition[1], condition[0], condition[2]]):
                bindings[name] = None
                continue
            operation, field, selector = specification["selector"]
            if operation != "unique-eq":
                _history_error()
            value = _history_operand(selector, state, arguments, bindings)
            matches = [row for row in oracle[specification["registry"]]
                       if _same_json_value(row[field], value)]
            if len(matches) != 1:
                _history_error()
            bindings[name] = copy.deepcopy(matches[0])
        else:
            source, key = specification
            bindings[name] = _history_record(oracle[source], _history_operand(key, state, arguments, bindings))
    for guard in rule["guards"]:
        if not _history_guard(authority, oracle, state, arguments, bindings, guard):
            _history_effect(authority, oracle, state, arguments, bindings, guard[4])
            _history_check_state(authority, state)
            return guard[3], state
    for effect in rule["success_effect"]:
        _history_effect(authority, oracle, state, arguments, bindings, effect)
    _history_check_state(authority, state)
    return rule["success_disposition"], state


def replay_history_oracle(authority: registry.Task4Authority, oracle: dict[str, Any]):
    """Replay only admitted trusted inputs using the closed ordered rule registry."""
    try:
        state = _history_initial(authority, oracle)
        transitions = []
        for index, action in enumerate(oracle["actions"]):
            before = copy.deepcopy(state)
            disposition, state = _history_trusted_step(authority, oracle, state, action)
            transitions.append({"action_index": index, "action": copy.deepcopy(action),
                                "expected_disposition": disposition, "pre_state": before,
                                "post_state": copy.deepcopy(state)})
        return transitions, copy.deepcopy(state)
    except (KeyError, TypeError, IndexError, OverflowError):
        _history_error()


def _history_counterpart(authority, identifier):
    separation = authority.histories["separation"]
    prefix = separation["candidate_ids_prefix"]
    if not isinstance(identifier, str) or not identifier.startswith(prefix) or identifier == prefix:
        _history_error()
    return separation["trusted_ids_prefix"] + identifier[len(prefix):]


def _history_candidate_record(authority, candidate, name, identifier):
    # Resolve the candidate reference in its own registry before any correspondence.
    _history_counterpart(authority, identifier)
    return _history_record(candidate[name], identifier)


def reconstruct_history(authority, candidate, oracle):
    """Reconstruct each observation from keyed, independent context authorities."""
    _charge("oracle_assertions")
    reconstructed = {}
    try:
        purposes = {row["envelope"]["candidate"]["transcript"]["purpose"]
                    for row in authority.snapshots["baselines"]}
        if len(purposes) != 1:
            _history_error()
        for observation in candidate["observations"]:
            observation = _history_candidate_record(authority, candidate, "observations", observation["id"])
            identifier = _history_counterpart(authority, observation["id"])
            trusted = _history_record(oracle["observation_oracles"], identifier)
            challenge = _history_candidate_record(authority, candidate, "challenges", observation["challenge_ref"])
            collection = _history_candidate_record(authority, candidate, "collections", observation["collection_ref"])
            session = _history_candidate_record(authority, candidate, "sessions", observation["session_ref"])
            expected_challenge = _history_record(oracle["trusted_challenges"], trusted["challenge_ref"])
            expected_session = _history_record(oracle["trusted_sessions"], trusted["session_ref"])
            profile = _history_record(oracle["trusted_profiles"], trusted["profile_id"])
            if (_history_counterpart(authority, challenge["id"]) != trusted["challenge_ref"]
                    or any(not _same_json_value(challenge[field], expected_challenge[field])
                    for field in ("publisher", "nonce", "issued_tick", "expires_tick"))
                    or _history_counterpart(authority, session["id"]) != trusted["session_ref"]
                    or any(not _same_json_value(session[field], expected_session[field])
                           for field in ("publisher", "live_subject"))
                    or any(not _same_json_value(session["key_handle_association"][field], expected_session[field])
                           for field in ("actual_public_key", "session_public_key_id"))):
                return "ContextBindingMismatch", None
            if (identifier in reconstructed or observation["purpose"] not in purposes
                    or observation["profile_id"] != trusted["profile_id"]
                    or collection["profile_id"] != profile["id"]
                    or _history_counterpart(authority, collection["id"]) != trusted["collection_ref"]):
                return "EvidenceInvalid", None
            reconstructed[identifier] = {
                "observation": trusted, "challenge": expected_challenge,
                "session": expected_session, "profile": profile,
                "authority": _history_record(oracle["trusted_authorities"], trusted["collection_ref"]),
            }
        if set(reconstructed) != {row["id"] for row in oracle["observation_oracles"]}:
            return "EvidenceInvalid", None
        return "Conform", reconstructed
    except (KeyError, TypeError, ValueError, IndexError):
        return "EvidenceInvalid", None


def check_history_coverage(authority, candidate, reconstructed):
    """Check the admitted abstract proof observations independently of lifecycle."""
    _charge("oracle_assertions")
    try:
        seen = set()
        for observation in candidate["observations"]:
            identifier = _history_counterpart(authority, observation["id"])
            expected = reconstructed[identifier]["observation"]
            if (identifier in seen or observation["coverage_state"] != "valid"
                    or observation["authority_statement_state"] != "authenticated"
                    or not _compared("coverage_entry_comparisons", observation["coverage_state"], expected["coverage_state"])
                    or not _compared("coverage_entry_comparisons", observation["authority_statement_state"], expected["authority_statement_state"])):
                return "EvidenceInvalid"
            seen.add(identifier)
        return "Conform" if seen == set(reconstructed) else "EvidenceInvalid"
    except (KeyError, TypeError, ValueError):
        return "EvidenceInvalid"


def _history_candidate_action(authority, action):
    rules = [row for row in authority.histories["action_rules"] if row["label"] == action["label"]]
    if len(rules) != 1 or len(action["args"]) != len(rules[0]["arguments"]):
        _history_error()
    reference_arguments = {"observation_ref", "first_observation_ref", "second_observation_ref",
                           "challenge_ref", "collection_ref", "session_ref", "recovery_ref"}
    return {"label": action["label"], "args": [
        _history_counterpart(authority, value) if name in reference_arguments else copy.deepcopy(value)
        for name, value in zip(rules[0]["arguments"], action["args"], strict=True)]}


def _history_candidate_step(authority, candidate, oracle, state, action, prerequisites):
    _charge("history_actions")
    """Evaluate observed actions directly; never synthesize or modify oracle records."""
    label, args = action["label"], action["args"]
    _history_candidate_action(authority, action)  # Check the admitted arity and vocabulary.
    collection = state["collection"]
    evidence = state["evidence"]
    water = state["high_water"]
    ordering = state["ordering"]

    def record(name, identifier):
        return _history_candidate_record(authority, candidate, name, identifier)

    def canonical(identifier):
        return _history_counterpart(authority, identifier)

    def lose():
        _history_loss(authority, state)
        return "ProtectedSessionLost"

    def clear(disposition):
        _history_clear(authority, state, "evidence")
        return disposition

    def observation_inputs(identifier):
        observed = record("observations", identifier)
        expected = (prerequisites[canonical(identifier)]["observation"] if prerequisites is not None
                    else _history_record(oracle["observation_oracles"], canonical(identifier)))
        return observed, expected

    if label in {"collection-open", "renewal"}:
        if state["session"]["status"] != "active":
            return lose() if label == "renewal" else "EvidenceInvalid"
        if label == "renewal" and state["session"]["continuity"] != "intact":
            return lose()
        challenge, opened = record("challenges", args[0]), record("collections", args[1])
        if label == "collection-open":
            if collection["status"] != "absent" or water["status"] != "absent":
                return "EvidenceInvalid"
        elif collection["status"] not in {"absent", "frozen", "dropped"} or ordering["in_flight_observation_ref"] is not None:
            return "EvidenceInvalid"
        if challenge["status"] != "authenticated":
            return "EvidenceInvalid"
        trusted_authority = _history_record(oracle["trusted_authorities"], canonical(opened["id"]))
        trusted_challenge = _history_record(oracle["trusted_challenges"], trusted_authority["challenge_ref"])
        if trusted_challenge["status"] != "authenticated":
            return "EvidenceInvalid"
        if label == "collection-open" and trusted_authority["availability"] != "available":
            return "AttestationUnavailable"
        session = record("sessions", next(row["session_ref"] for row in candidate["observations"]
                                         if row["collection_ref"] == opened["id"]))
        trusted_session = _history_record(oracle["trusted_sessions"], canonical(session["id"]))
        profile = _history_record(oracle["trusted_profiles"], opened["profile_id"])
        def context_matches():
            if (any(not _same_json_value(session[field], state["session"][field]) for field in ("publisher", "live_subject"))
                    or any(not _same_json_value(session["key_handle_association"][field], state["session"][field])
                           for field in ("actual_public_key", "session_public_key_id"))):
                return False
            if (canonical(challenge["id"]) != trusted_authority["challenge_ref"]
                    or trusted_session["session_id"] != state["session"]["session_id"]
                    or trusted_authority["session_ref"] != trusted_session["id"]
                    or any(not _same_json_value(trusted_authority[field], state["session"][field])
                           for field in ("publisher", "live_subject", "actual_public_key", "session_public_key_id"))
                    or any(not _same_json_value(challenge[field], trusted_challenge[field])
                           for field in ("publisher", "nonce", "issued_tick", "expires_tick"))):
                return False
            return True

        restored_water = None
        if trusted_session["predecessor_session_id"] is not None and (
                state["session"]["session_id"] == trusted_session["predecessor_session_id"]
                or session["key_handle_association"]["actual_public_key"] == trusted_session["predecessor_actual_public_key"]
                or session["key_handle_association"]["session_public_key_id"] == trusted_session["predecessor_session_public_key_id"]
                or opened["epoch_relation"] == trusted_session["predecessor_epoch"]):
            return lose()
        if label == "renewal":
            if any(row["source"] != "verifier" or row["status"] not in {"available", "unavailable"}
                   for row in candidate["temporal_states"]):
                return lose()
            if water["status"] == "unavailable":
                recoveries = [row for row in candidate["recovery_inputs"] if row["fresh_challenge_ref"] == args[0]]
                trusted_recoveries = [row for row in oracle["trusted_recoveries"]
                                      if row["fresh_challenge_ref"] == canonical(args[0])]
                if len(recoveries) != 1 or len(trusted_recoveries) != 1:
                    return "AttestationUnavailable"
                recovery, trusted_recovery = recoveries[0], trusted_recoveries[0]
                temporal = record("temporal_states", recovery["temporal_state_ref"])
                if (recovery["intact"] is not True or trusted_recovery["intact"] is not True
                        or recovery["component"] != trusted_recovery["component"]
                        or canonical(recovery["id"]) != trusted_recovery["id"]
                        or temporal["source"] != "verifier"
                        or trusted_recovery["temporal_state"]["status"] != "available"
                        or any(not _same_json_value(value, trusted_recovery["temporal_state"][field])
                               or not _same_json_value(value, temporal[field])
                               for field, value in water.items() if field != "status")):
                    return "AttestationUnavailable"
                restored_water = copy.deepcopy(trusted_recovery["temporal_state"])
            elif water["status"] != "available":
                return lose()
            if not context_matches():
                return "ContextBindingMismatch"
            if (_history_number(authority, session["policy_strength"]) < _history_number(authority, state["profile"]["policy_strength"])
                    or _history_number(authority, profile["policy_strength"]) < _history_number(authority, state["profile"]["policy_strength"])):
                return "PolicyDenied"
        if (any(trusted_authority[field] != "intact" for field in ("authority_continuity", "source_continuity"))
                or any(event["component"] == "protected-source" and event["continuity"] != "intact"
                       for event in candidate["events"])):
            return lose()
        if label == "collection-open" and not context_matches():
            return "ContextBindingMismatch"
        if restored_water is not None:
            state["high_water"] = restored_water
        state["challenge"] = {"status": "authenticated", "challenge_ref": canonical(challenge["id"]),
                              **{field: copy.deepcopy(challenge[field]) for field in
                                 ("nonce", "issued_tick", "expires_tick", "receipt_tick")}, "consumed": False}
        _history_clear(authority, state, "collection")
        state["collection"].update({field: copy.deepcopy(opened[field]) for field in
            ("authority_contract", "protected_source", "epoch_relation", "sequence", "collection_start", "snapshot_freeze_end")})
        state["collection"].update(status="open", collection_ref=canonical(opened["id"]),
                                    challenge_ref=canonical(opened["challenge_ref"]))
        ordering["active_collection_ref"] = canonical(opened["id"])
        _history_clear(authority, state, "evidence")
        if label == "renewal":
            state["profile"] = {"profile_id": profile["id"], **{field: copy.deepcopy(profile[field])
                                for field in state["profile"] if field != "profile_id"}}
        state["appraisal"] = {"claim_state": "not-appraised", "rejected_claim_meaning": None, "policy_state": "not-appraised"}
        return "Conform"
    if label == "snapshot-freeze":
        opened, (observation, expected) = record("collections", args[0]), observation_inputs(args[1])
        if collection["status"] != "open" or collection["collection_ref"] != canonical(args[0]):
            return "EvidenceInvalid"
        if collection["collection_start"] > collection["snapshot_freeze_end"]:
            return lose()
        if opened["current_subject_revalidated"] is not True or observation["current_subject_revalidated"] is not True or expected["current_subject_revalidated"] is not True:
            return "EvidenceInvalid"
        collection.update(status="frozen", observation_ref=canonical(args[1]))
        evidence.update(proof_state="pending", coverage_state="pending",
                        authority_statement_state=expected["authority_statement_state"])
        return "Conform"
    if label == "drop":
        record("collections", args[0])
        if (collection["collection_ref"] != canonical(args[0]) or collection["status"] not in {"open", "frozen"}
                or evidence["submitted_observation_ref"] is not None):
            return "EvidenceInvalid"
        _history_clear(authority, state, "collection")
        _history_clear(authority, state, "evidence")
        return "Conform"
    if label == "submit":
        observation, expected = observation_inputs(args[0])
        receipt = _history_number(authority, args[1], "ProtectedTick")
        if collection["status"] != "frozen" or collection["observation_ref"] != canonical(args[0]):
            return "EvidenceInvalid"
        if receipt >= state["challenge"]["expires_tick"]:
            return clear("Expired")
        if receipt < state["challenge"]["issued_tick"]:
            return clear("EvidenceInvalid")
        if ordering["in_flight_observation_ref"] is not None or observation["claims_current"] is not True:
            return "EvidenceInvalid"
        state["challenge"].update(receipt_tick=receipt, consumed=True)
        coverage_input = expected if prerequisites is not None else observation
        evidence.update(proof_state="covered", coverage_state=coverage_input["coverage_state"],
                        authority_statement_state=coverage_input["authority_statement_state"],
                        submitted_observation_ref=canonical(args[0]), submission_receipt_tick=receipt)
        ordering["in_flight_observation_ref"] = canonical(args[0])
        return "Conform"
    if label == "concurrent-submit":
        if water["status"] != "available":
            return lose()
        record("observations", args[0])
        record("observations", args[1])
        _history_candidate_step(authority, candidate, oracle, state,
                                {"label": "validate", "args": [args[0]]}, prerequisites)
        return lose()
    if label == "validate":
        observation, expected = observation_inputs(args[0])
        coverage_input = expected if prerequisites is not None else observation
        if evidence["submitted_observation_ref"] != canonical(args[0]):
            return "EvidenceInvalid"
        if coverage_input["coverage_state"] != "valid" or coverage_input["authority_statement_state"] != "authenticated":
            return clear("EvidenceInvalid")
        if water["status"] not in {"absent", "available"}:
            return lose()
        start = _history_number(authority, collection["collection_start"], "ProtectedTick")
        end = _history_number(authority, collection["snapshot_freeze_end"], "ProtectedTick")
        if start > end:
            return lose()
        if water["status"] == "available":
            pair = ("authority_contract", "protected_source")
            registered = _history_record(oracle["trusted_profiles"], expected["profile_id"])
            if (collection["epoch_relation"] != water["epoch_relation"]
                    or _history_number(authority, collection["sequence"], "ProtectedSequence")
                    <= _history_number(authority, water["greatest_sequence"], "ProtectedSequence")
                    or start < _history_number(authority, water["latest_freeze_end"], "ProtectedTick")
                    or any(collection[field] != registered[field] for field in pair)):
                return lose()
        ceiling = min(_history_number(authority, state["profile"][field], "Duration")
                      for field in ("profile_duration_ceiling", "publisher_duration_ceiling"))
        if end - start > ceiling:
            return clear("EvidenceInvalid")
        trusted_authority = _history_record(oracle["trusted_authorities"], expected["collection_ref"])
        if any(not _same_json_value(collection[field], trusted_authority[field]) for field in
               ("authority_contract", "protected_source", "epoch_relation", "sequence",
                "collection_start", "snapshot_freeze_end", "challenge_ref")):
            return clear("EvidenceInvalid")
        _history_advance(authority, state)
        state["appraisal"].update(claim_state="accepted", rejected_claim_meaning=None, policy_state="accepted")
        return "Conform"
    if label == "claim-rejection":
        record("observations", args[0])
        if water["status"] != "available" or collection["observation_ref"] != canonical(args[0]):
            return "EvidenceInvalid"
        state["appraisal"].update(claim_state="rejected", rejected_claim_meaning=args[1], policy_state="not-appraised")
        return "EvidenceInvalid"
    if label == "policy-rejection":
        if water["status"] == "available" and state["appraisal"]["claim_state"] == "accepted" and state["appraisal"]["policy_state"] == "accepted":
            state["appraisal"]["policy_state"] = "rejected"
        return "PolicyDenied"
    if label == "outage":
        if args[0] not in {"collection-authority", "temporal-store"}:
            return "AttestationUnavailable"
        try:
            recovery = record("recovery_inputs", args[1])
            trusted_recovery = _history_record(oracle["trusted_recoveries"], canonical(recovery["id"]))
        except (KeyError, TypeError, ValueError):
            return lose()
        if recovery["intact"] is not True or trusted_recovery["intact"] is not True:
            return lose()
        water["status"] = "unavailable"
        evidence["authority_statement_state"] = "unavailable"
        ordering["in_flight_observation_ref"] = None
        return "AttestationUnavailable"
    if label in {"restart", "rollback"}:
        return lose()
    if label == "terminal-end":
        session = record("sessions", args[0])
        trusted_session = _history_record(oracle["trusted_sessions"], canonical(session["id"]))
        if state["session"]["status"] != "active" or state["session"]["session_id"] != trusted_session["session_id"] or ordering["in_flight_observation_ref"] is not None:
            return "EvidenceInvalid"
        state["session"].update(status="ended", continuity="lost")
        for section in ("challenge", "collection", "evidence"):
            _history_clear(authority, state, section)
        state["retention"] = {"temporal_state": "retained", "deletion_required": True}
        return "Conform"
    if label == "deletion":
        if state["session"]["status"] not in {"ended", "lost"} or state["retention"] != {"temporal_state": "retained", "deletion_required": True}:
            return "EvidenceInvalid"
        _history_delete(authority, state)
        return "Conform"
    _history_error()


def _same_history_transitions(left, right):
    _charge("oracle_assertions")
    if len(left) != len(right):
        return False
    for observed, expected in zip(left, right, strict=True):
        for key in observed:
            category = ("lifecycle_state_field_comparisons" if key in {"pre_state", "post_state"}
                        else "oracle_assertions")
            if not _compared(category, observed[key], expected[key]):
                return False
    return True

def evaluate_history(authority, candidate, oracle, prerequisites=None):
    """Evaluate candidate observations; stop at first failure with complete state."""
    _charge("oracle_assertions")
    state = _history_initial(authority, oracle)
    transitions = []
    try:
        for index, action in enumerate(candidate["actions"]):
            before = copy.deepcopy(state)
            disposition = _history_candidate_step(authority, candidate, oracle, state, action, prerequisites)
            _history_check_state(authority, state)
            transitions.append({"action_index": index, "action": _history_candidate_action(authority, action),
                                "expected_disposition": disposition, "pre_state": before,
                                "post_state": copy.deepcopy(state)})
            if disposition != "Conform":
                return disposition, transitions, copy.deepcopy(state)
        if state["retention"]["deletion_required"] is True:
            return "EvidenceInvalid", transitions, copy.deepcopy(state)
        if [_history_candidate_action(authority, action) for action in candidate["actions"]] != oracle["actions"]:
            return "EvidenceInvalid", transitions, copy.deepcopy(state)
        trusted_transitions, trusted_final = replay_history_oracle(authority, oracle)
        if not _same_history_transitions(transitions, trusted_transitions) or not _compared(
                "lifecycle_state_field_comparisons", state, trusted_final):
            return "EvidenceInvalid", transitions, copy.deepcopy(state)
        return "Conform", transitions, copy.deepcopy(state)
    except (KeyError, TypeError, ValueError, IndexError, StopIteration):
        return "EvidenceInvalid", transitions, copy.deepcopy(state)


@_metered
def run_history_focused_case(authority, identifier, layer):
    return _run_history_focused_case(authority, identifier, layer)


def _run_history_focused_case(authority, identifier, layer):
    if layer not in {4, 5, 6}:
        raise ValueError("history focused layer")
    transform = next(row for row in authority.histories["negative_transforms"] if row["id"] == identifier)
    baseline = next(row for row in authority.histories["baselines"] if row["id"] == transform["baseline"])
    changed = _apply_fixture_transform(baseline, transform)
    if layer == 4:
        return reconstruct_history(authority, changed["candidate"], baseline["oracle"])[0]
    result, reconstructed = reconstruct_history(authority, baseline["candidate"], baseline["oracle"])
    _require(lambda: not (result != 'Conform' or reconstructed is None), 'history focused baseline reconstruction')
    if layer == 5:
        return check_history_coverage(authority, changed["candidate"], reconstructed)
    _require(lambda: not (check_history_coverage(authority, baseline['candidate'], reconstructed) != 'Conform'), 'history focused baseline coverage')
    return evaluate_history(authority, changed["candidate"], baseline["oracle"], reconstructed)[0]


def build_task7_corpus(authority, root):
    """Materialize the admitted corpus without changing existing exact fixtures."""
    snapshot_authority = registry.load_task6_authority()
    corpus = root / Path(authority.core["paths"]["corpus_manifest"]).parent
    manifest = authority.validators["validator_baselines"]["baseline-corpus-v1"]["ast"]["value"]
    documents = [(root / authority.core["paths"]["corpus_manifest"], _manifest_bytes(manifest))]
    for row in manifest["fixtures"]:
        case = registry.FixtureCase(*row)
        raw = (reproduce_history_fixture(authority, case) if case.kind == "history"
               else reproduce_snapshot_fixture(snapshot_authority, case))
        documents.append((corpus / case.path, raw))
    for path, raw in documents:
        _write_history_corpus_document(root, path.relative_to(root), raw)


def _write_history_corpus_document(root, relative, raw):
    """Write only through anchored regular-directory descriptors, never links."""
    descriptors = []
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptors.append(os.open(root, directory_flags))
        for part in relative.parts[:-1]:
            try:
                os.mkdir(part, dir_fd=descriptors[-1])
            except FileExistsError:
                pass
            descriptors.append(os.open(part, directory_flags, dir_fd=descriptors[-1]))
        name = relative.name
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                         0o666, dir_fd=descriptors[-1])
        except FileExistsError:
            fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
                         dir_fd=descriptors[-1])
            descriptors.append(fd)
            if not stat.S_ISREG(os.fstat(fd).st_mode) or os.read(fd, len(raw) + 1) != raw:
                raise _TransformError("corpus materialization mismatch")
        else:
            descriptors.append(fd)
            remaining = memoryview(raw)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise _TransformError("corpus materialization failure")
                remaining = remaining[written:]
    except OSError:
        raise _TransformError("corpus materialization failure") from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def reproduce_history_fixture(authority, case):
    identifier = case.identifier if case.baseline is None else case.baseline
    baseline = next(row for row in authority.histories["baselines"] if row["id"] == identifier)
    envelope = {"format_version": authority.histories["format_version"], "kind": "history",
                "candidate": copy.deepcopy(baseline["candidate"]), "oracle": copy.deepcopy(baseline["oracle"])}
    if case.transform is not None:
        transform = next(row for row in authority.histories["negative_transforms"] if row["id"] == case.transform)
        if transform["baseline"] != identifier:
            raise _TransformError("history fixture binding")
        envelope = _apply_fixture_transform(envelope, transform)
    return _manifest_bytes(envelope)


@_metered
def run_admitted_history_case(authority, admission, identifier, root):
    """Run one admitted history through the unchanged six-layer ordering."""
    if type(admission) is not Layer1Admission:
        raise TypeError("invalid layer-1 admission")
    rows = {row[0]: row for row in admission._manifest_value()["fixtures"]}
    try:
        case = registry.FixtureCase(*rows[identifier])
    except (KeyError, ValueError, TypeError):
        _reject_layer1()
    if case.kind != "history":
        _reject_layer1()
    relative = str(Path(authority.core["paths"]["corpus_manifest"]).parent / case.path)
    expected_identity, expected_hierarchy = admission._fixture_read_evidence(relative)
    limits = bounded_json.JsonLimits.from_mapping(authority.core["resource_limits"]["fixture"])
    try:
        value = bounded_json.load_bounded_json_matching_identity(root, relative, limits,
            LAYER2_DIAGNOSTIC, expected_identity, expected_hierarchy=expected_hierarchy, node_visit=_visit_decoded_node)
    except bounded_json.BoundedJsonError as error:
        if error.category == "identity":
            raise
        actual = ("layer-2", "Malformed")
    else:
        _require(lambda: _same_json_value(value, json.loads(reproduce_history_fixture(authority, case))), 'history reproduction mismatch')
        shape = _fixture_shape_result(authority, value)
        if shape != ("layer-4", "Conform"):
            actual = shape
        else:
            disposition, reconstructed = reconstruct_history(authority, value["candidate"], value["oracle"])
            if disposition != "Conform" or reconstructed is None:
                actual = ("layer-4", disposition)
            else:
                disposition = check_history_coverage(authority, value["candidate"], reconstructed)
                if disposition != "Conform":
                    actual = ("layer-5", disposition)
                else:
                    disposition, _, _ = evaluate_history(authority, value["candidate"], value["oracle"], reconstructed)
                    actual = ("layer-6-success" if disposition == "Conform" else "layer-6", disposition)
    _require(lambda: not (actual != (case.checkpoint, case.disposition)), 'history registry expectation mismatch')
    return actual


@dataclass
class _CorpusSpec:
    entries: dict[str, tuple[str, bytes | str | None]]
    executable_transforms: set[str]


@dataclass(frozen=True)
class _Layer1IdentityEvidence:
    manifest: bounded_json.StableFileIdentity
    directories: tuple[tuple[str, bounded_json.StableFileIdentity], ...]
    fixtures: tuple[tuple[str, bounded_json.StableFileIdentity], ...]


_ADMISSION_TOKEN = object()


class Layer1Admission:
    """Opaque evidence that one complete corpus passed layer 1."""

    __slots__ = (
        "__directory_identities",
        "__fixture_identities",
        "__manifest",
        "__manifest_identity",
        "__token",
    )

    def __init__(
        self,
        token: object,
        manifest: dict[str, Any],
        identities: _Layer1IdentityEvidence,
    ) -> None:
        if token is not _ADMISSION_TOKEN:
            raise TypeError("layer-1 admissions are produced only by admit_layer1")
        self.__token = token
        self.__manifest = copy.deepcopy(manifest)
        self.__manifest_identity = identities.manifest
        self.__directory_identities = tuple(identities.directories)
        self.__fixture_identities = tuple(identities.fixtures)

    def _manifest_value(self) -> dict[str, Any]:
        if self.__token is not _ADMISSION_TOKEN:
            raise TypeError("invalid layer-1 admission")
        return copy.deepcopy(self.__manifest)

    def _fixture_read_evidence(
        self, relative_path: str
    ) -> tuple[
        bounded_json.StableFileIdentity,
        tuple[bounded_json.StableFileIdentity, ...],
    ]:
        if self.__token is not _ADMISSION_TOKEN:
            raise TypeError("invalid layer-1 admission")
        directory_identities = dict(self.__directory_identities)
        fixture_identities = dict(self.__fixture_identities)
        parts = Path(relative_path).parts
        prefixes = [""]
        current = Path()
        for part in parts[:-1]:
            current /= part
            prefixes.append(str(current))
        return (
            fixture_identities[relative_path],
            tuple(directory_identities[prefix] for prefix in prefixes),
        )


class _TransformError(ValueError):
    pass


def _reject_layer1() -> NoReturn:
    raise bounded_json.BoundedJsonError(LAYER1_DIAGNOSTIC)


def _valid_domain(value: Any, name: str, domains: dict[str, Any]) -> bool:
    _charge("schema_assertions")
    domain = domains[name]
    if "domain" in domain:
        return _valid_domain(value, domain["domain"], domains)
    kind = domain.get("json_type")
    if kind == "integer-not-boolean":
        if type(value) is not int:
            return False
        return (
            value in domain.get("values", [value])
            and domain.get("minimum", value) <= value <= domain.get("maximum", value)
        )
    if kind != "string" or not isinstance(value, str):
        return False
    if value not in domain.get("values", [value]):
        return False
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    if not domain.get("min_bytes", 0) <= len(encoded) <= domain.get(
        "max_bytes", len(encoded)
    ):
        return False
    pattern = domain.get("ascii_pattern")
    if pattern is not None and re.fullmatch(pattern, value) is None:
        return False
    if name == "FixturePath":
        parts = value.split(domain["separator"])
        if (
            any(part in domain["forbidden_components"] for part in parts)
            or any(
                len(part.encode("ascii")) > domain["component_max_bytes"]
                for part in parts
            )
            or any(
                re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", part) is None
                for part in parts
            )
        ):
            return False
    return True


def _valid_typed(
    value: Any,
    form: dict[str, Any],
    schemas: dict[str, Any],
    domains: dict[str, Any],
) -> bool:
    _charge("schema_assertions")
    if "const" in form and value != form["const"]:
        return False
    if "domain" in form:
        return _valid_domain(value, form["domain"], domains)
    if "ref" in form:
        return _valid_typed(value, schemas[form["ref"]], schemas, domains)
    if "union" in form:
        return any(
            _valid_typed(value, item, schemas, domains) for item in form["union"]
        )
    kind = form["type"]
    if kind == "boolean":
        return type(value) is bool
    if kind == "null":
        return value is None
    if kind == "string":
        return isinstance(value, str)
    if kind == "json-scalar":
        return value is None or type(value) in {bool, int, float, str}
    if kind == "json-value":
        return value is None or type(value) in {bool, int, float, str, list, dict}
    if kind in {"array", "tuple"}:
        if (
            not isinstance(value, list)
            or not form["min_items"] <= len(value) <= form["max_items"]
        ):
            return False
        item_forms = (
            form["items"] if kind == "tuple" else [form["items"]] * len(value)
        )
        if len(item_forms) != len(value) or not all(
            _valid_typed(item, item_form, schemas, domains)
            for item, item_form in zip(value, item_forms, strict=True)
        ):
            return False
        unique_by = form.get("unique_by")
        if unique_by is not None:
            keys = [
                item[0] if isinstance(item, list) else item[unique_by]
                for item in value
            ]
            if len(keys) != len(set(keys)):
                return False
        if form.get("unique_items") is True:
            serialized = [
                json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value
            ]
            if len(serialized) != len(set(serialized)):
                return False
        return True
    if kind == "object":
        return (
            isinstance(value, dict)
            and set(value) == set(form["required"])
            and all(
                _valid_typed(value[key], property_form, schemas, domains)
                for key, property_form in form["properties"].items()
            )
        )
    return False


def _manifest_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _stable_metadata(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _inventory_names(directory_fd: int, expected: set[str]) -> set[str]:
    """Stop before retaining or visiting beyond the exact admitted inventory."""
    names: set[str] = set()
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            if entry.name not in expected or entry.name in names:
                _reject_layer1()
            names.add(entry.name)
    if names != expected:
        _reject_layer1()
    return names


def _validate_inventory(
    root: Path,
    manifest: dict[str, Any],
    paths: dict[str, Any],
    manifest_identity: bounded_json.StableFileIdentity,
) -> _Layer1IdentityEvidence:
    manifest_relative = Path(paths["corpus_manifest"])
    snapshot_directory = paths["snapshot_prefix"].rstrip("/")
    history_directory = paths["history_prefix"].rstrip("/")
    expected_by_directory = {
        snapshot_directory: {
            row[2].split("/", 1)[1]
            for row in manifest["fixtures"]
            if row[1] == "snapshot"
        },
        history_directory: {
            row[2].split("/", 1)[1]
            for row in manifest["fixtures"]
            if row[1] == "history"
        },
    }
    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    descriptors: list[int] = []
    opened: list[tuple[int, str, int, os.stat_result]] = []
    fixture_directories: list[tuple[int, str]] = []
    fixture_identities: dict[str, bounded_json.StableFileIdentity] = {}
    directory_identities: dict[str, bounded_json.StableFileIdentity] = {}
    try:
        descriptors.append(os.open(root, directory_flags))
        root_before = os.fstat(descriptors[0])
        directory_identities[""] = bounded_json.StableFileIdentity.from_stat(
            root_before
        )
        opened_relative = Path()
        for part in manifest_relative.parent.parts:
            parent_fd = descriptors[-1]
            directory_fd = os.open(part, directory_flags, dir_fd=parent_fd)
            descriptors.append(directory_fd)
            before = os.fstat(directory_fd)
            named_before = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(before.st_mode)
                or _stable_metadata(named_before) != _stable_metadata(before)
            ):
                _reject_layer1()
            opened_relative /= part
            directory_identities[str(opened_relative)] = (
                bounded_json.StableFileIdentity.from_stat(before)
            )
            opened.append((parent_fd, part, directory_fd, before))

        corpus_fd = descriptors[-1]
        _inventory_names(corpus_fd, {
            manifest_relative.name,
            snapshot_directory,
            history_directory,
        })
        manifest_state = os.stat(
            manifest_relative.name,
            dir_fd=corpus_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(manifest_state.st_mode)
            or bounded_json.StableFileIdentity.from_stat(manifest_state)
            != manifest_identity
        ):
            _reject_layer1()
        for directory, expected_names in expected_by_directory.items():
            directory_fd = os.open(directory, directory_flags, dir_fd=corpus_fd)
            descriptors.append(directory_fd)
            before = os.fstat(directory_fd)
            named_before = os.stat(
                directory,
                dir_fd=corpus_fd,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(before.st_mode)
                or _stable_metadata(named_before) != _stable_metadata(before)
            ):
                _reject_layer1()
            directory_identities[str(manifest_relative.parent / directory)] = (
                bounded_json.StableFileIdentity.from_stat(before)
            )
            names = _inventory_names(directory_fd, expected_names)
            for name in names:
                file_state = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                if not stat.S_ISREG(file_state.st_mode):
                    _reject_layer1()
                fixture_relative = str(
                    manifest_relative.parent / directory / name
                )
                fixture_identities[fixture_relative] = (
                    bounded_json.StableFileIdentity.from_stat(file_state)
                )
            fixture_directories.append((directory_fd, directory))
            after = os.fstat(directory_fd)
            named_after = os.stat(
                directory,
                dir_fd=corpus_fd,
                follow_symlinks=False,
            )
            if (
                _stable_metadata(after) != _stable_metadata(before)
                or _stable_metadata(named_after) != _stable_metadata(before)
            ):
                _reject_layer1()

        manifest_after = os.stat(
            manifest_relative.name,
            dir_fd=corpus_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(manifest_after.st_mode)
            or bounded_json.StableFileIdentity.from_stat(manifest_after)
            != manifest_identity
        ):
            _reject_layer1()
        for directory_fd, directory in fixture_directories:
            for name in expected_by_directory[directory]:
                current = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(current.st_mode)
                    or bounded_json.StableFileIdentity.from_stat(current)
                    != fixture_identities[
                        str(manifest_relative.parent / directory / name)
                    ]
                ):
                    _reject_layer1()
        for parent_fd, name, directory_fd, before in reversed(opened):
            after = os.fstat(directory_fd)
            named_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                _stable_metadata(after) != _stable_metadata(before)
                or _stable_metadata(named_after) != _stable_metadata(before)
            ):
                _reject_layer1()
        if _stable_metadata(os.fstat(descriptors[0])) != _stable_metadata(root_before):
            _reject_layer1()
    except OSError:
        _reject_layer1()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return _Layer1IdentityEvidence(
        manifest_identity,
        tuple(directory_identities.items()),
        tuple(fixture_identities.items()),
    )


def _canonical_spec(authority: registry.Task4Authority) -> _CorpusSpec:
    manifest = copy.deepcopy(
        authority.validators["validator_baselines"]["baseline-corpus-v1"]["ast"][
            "value"
        ]
    )
    paths = authority.core["paths"]
    manifest_path = Path(paths["corpus_manifest"])
    corpus_root = manifest_path.parent
    entries: dict[str, tuple[str, bytes | str | None]] = {}
    for parent in reversed(manifest_path.parents[:-1]):
        entries[str(parent)] = ("directory", None)
    entries[str(corpus_root / paths["snapshot_prefix"])] = ("directory", None)
    entries[str(corpus_root / paths["history_prefix"])] = ("directory", None)
    entries[str(manifest_path)] = ("regular-file", _manifest_bytes(manifest))
    for row in manifest["fixtures"]:
        entries[str(corpus_root / row[2])] = ("regular-file", b"{}")
    return _CorpusSpec(entries, set(authority.executable_transforms))


def _materialize(spec: _CorpusSpec, root: Path) -> None:
    for relative, (kind, _contents) in sorted(
        spec.entries.items(), key=lambda item: (item[0].count("/"), item[0])
    ):
        if kind == "directory":
            (root / relative).mkdir(parents=True)
    for relative, (kind, contents) in sorted(spec.entries.items()):
        path = root / relative
        if kind == "regular-file":
            if not isinstance(contents, bytes):
                raise _TransformError("file contents")
            path.write_bytes(contents)
        elif kind == "symlink":
            if not isinstance(contents, str):
                raise _TransformError("symlink contents")
            path.symlink_to(contents)


def _pointer_parts(pointer: str) -> list[str]:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise _TransformError("pointer")
    return [
        part.replace("~1", "/").replace("~0", "~")
        for part in pointer[1:].split("/")
    ]


def _select(value: Any, pointer: str) -> Any:
    for part in _pointer_parts(pointer):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def _parent(value: Any, pointer: str) -> tuple[Any, str]:
    parts = _pointer_parts(pointer)
    parent = value
    for part in parts[:-1]:
        parent = parent[int(part)] if isinstance(parent, list) else parent[part]
    return parent, parts[-1]


def _resolved_expected(
    authority: registry.Task4Authority,
    value: Any,
) -> Any:
    if isinstance(value, dict) and value.get("node") == "ref":
        return _evaluate(authority, value)
    return copy.deepcopy(value)


def _mutate_pointer(
    authority: registry.Task4Authority,
    node: dict[str, Any],
) -> Any:
    result = copy.deepcopy(_evaluate(authority, node["input"]))
    parent, key = _parent(result, node["pointer"])
    expected = _resolved_expected(authority, node.get("expected_old"))
    absent = expected == {"absent": True}
    if node["node"] == "append":
        target = _select(result, node["pointer"])
        if not isinstance(target, list):
            raise _TransformError("append")
        target.append(copy.deepcopy(node["value"]))
        return result
    if isinstance(parent, list):
        index = int(key)
        if absent or parent[index] != expected:
            raise _TransformError("precondition")
        if node["node"] == "remove":
            del parent[index]
        else:
            parent[index] = copy.deepcopy(node["value"])
        return result
    if absent:
        if key in parent:
            raise _TransformError("precondition")
    elif key not in parent or parent[key] != expected:
        raise _TransformError("precondition")
    if node["node"] == "remove":
        del parent[key]
    else:
        parent[key] = copy.deepcopy(node["value"])
    return result


def _resource_bytes(parameters: dict[str, Any], limits: dict[str, Any]) -> bytes:
    dimension = parameters["dimension"]
    target = limits[parameters["scope"]][dimension] + (
        parameters["relation"] == "over"
    )
    if dimension == "bytes":
        return b" " * (target - 2) + b"{}"
    if dimension == "depth":
        value: Any = None
        for _ in range(target - 1):
            value = [value]
    elif dimension == "object_fields":
        value = {f"k{index}": None for index in range(target)}
    elif dimension == "array_items":
        value = [None] * target
    elif dimension == "string_characters":
        value = "x" * target
    elif dimension == "object_key_characters":
        value = {"k" * target: None}
    elif dimension == "total_nodes":
        remaining = target - 1
        value = []
        maximum = limits[parameters["scope"]]["array_items"]
        while remaining:
            children = min(maximum, max(remaining - 1, 0))
            value.append([None] * children if children else None)
            remaining -= children + 1
    else:
        raise _TransformError("resource")
    return _manifest_bytes(value)


def _generate(authority: registry.Task4Authority, node: dict[str, Any]) -> bytes:
    constructor = node["constructor"]
    parameters = node["parameters"]
    if constructor == "invalid-utf8-document":
        return (
            parameters["prefix"].encode("ascii")
            + bytes.fromhex(parameters["invalid_byte_hex"])
            + parameters["suffix"].encode("ascii")
        )
    if constructor == "json-number-document":
        return parameters["token"].encode("ascii")
    if constructor == "number-token-boundary":
        size = authority.core["resource_limits"][parameters["scope"]][
            "number_token_characters"
        ] + (parameters["relation"] == "over")
        prefix = parameters.get("prefix", "")
        digit = parameters.get("digit", "1")
        return (prefix + digit * (size - len(prefix))).encode("ascii")
    if constructor == "resource-boundary":
        return _resource_bytes(parameters, authority.core["resource_limits"])
    raise _TransformError("constructor")


def _as_spec(authority: registry.Task4Authority, value: Any) -> _CorpusSpec:
    if isinstance(value, _CorpusSpec):
        return copy.deepcopy(value)
    spec = _canonical_spec(authority)
    if isinstance(value, bytes):
        spec.entries["lab/conformance/corpus.json"] = ("regular-file", value)
    elif isinstance(value, dict) and all(
        item == {"registered": True} for item in value.values()
    ):
        spec.executable_transforms = set(value)
    else:
        spec.entries["lab/conformance/corpus.json"] = (
            "regular-file",
            _manifest_bytes(value),
        )
    return spec


def _filesystem_mutation(
    authority: registry.Task4Authority,
    node: dict[str, Any],
) -> _CorpusSpec:
    spec = _as_spec(authority, _evaluate(authority, node["input"]))
    operation = node["node"]
    if operation == "fs-remove":
        relative = node["relative_path"]
        removed = [
            path
            for path in spec.entries
            if path == relative or path.startswith(relative + "/")
        ]
        if not removed or spec.entries[relative][0] != node["expected_kind"]:
            raise _TransformError("filesystem precondition")
        for path in removed:
            del spec.entries[path]
    elif operation == "fs-create":
        relative = node["relative_path"]
        if relative in spec.entries:
            raise _TransformError("filesystem precondition")
        contents = node["contents"]
        if node["kind"] == "regular-file":
            contents = contents.encode("utf-8")
        spec.entries[relative] = (node["kind"], contents)
    elif operation == "fs-rename":
        old = node["old_relative_path"]
        new = node["new_relative_path"]
        moved = [
            path
            for path in spec.entries
            if path == old or path.startswith(old + "/")
        ]
        if not moved or spec.entries[old][0] != node["expected_kind"]:
            raise _TransformError("filesystem precondition")
        replacements = {
            new + path[len(old) :]: spec.entries[path]
            for path in moved
        }
        for path in moved:
            del spec.entries[path]
        spec.entries.update(replacements)
    return spec


def _evaluate(authority: registry.Task4Authority, node: dict[str, Any]) -> Any:
    kind = node["node"]
    if kind == "sequence":
        return _evaluate(authority, node["steps"][-1])
    if kind == "probe":
        return _evaluate(authority, node["input"])
    if kind == "literal":
        return copy.deepcopy(node["value"])
    if kind == "ref":
        if node["subject"] == "baseline":
            value = authority.validators["validator_baselines"][node["id"]]["ast"][
                "value"
            ]
        elif node["subject"] == "corpus-validator" and node["id"] == "validator-transforms":
            value = {
                identifier: {"registered": True}
                for identifier in authority.executable_transforms
            }
        else:
            raise _TransformError("reference")
        result = copy.deepcopy(value)
        return _select(result, node["pointer"]) if "pointer" in node else result
    if kind in {"set", "remove", "append"}:
        return _mutate_pointer(authority, node)
    if kind == "bytes-append":
        value = _evaluate(authority, node["input"])
        raw = value if isinstance(value, bytes) else _manifest_bytes(value)
        return raw + node["bytes"].encode("utf-8")
    if kind == "bytes-replace":
        value = _evaluate(authority, node["input"])
        raw = value if isinstance(value, bytes) else _manifest_bytes(value)
        old = node["old_ascii"].encode("ascii")
        if raw.count(old) != node["expected_occurrences"]:
            raise _TransformError("bytes precondition")
        return raw.replace(old, node["new_ascii"].encode("ascii"))
    if kind == "generate":
        return _generate(authority, node)
    if kind in {"fs-create", "fs-remove", "fs-rename"}:
        return _filesystem_mutation(authority, node)
    raise _TransformError("node")


def build_synthetic_corpus(
    authority: registry.Task4Authority,
    root: Path,
) -> None:
    _materialize(_canonical_spec(authority), root)


def _fixture_value(value: dict[str, Any]) -> Any:
    if value["type"] == "absent":
        return {"absent": True}
    return copy.deepcopy(value.get("value"))


def _apply_fixture_transform(
    baseline: dict[str, Any], transform: dict[str, Any]
) -> dict[str, Any]:
    result = copy.deepcopy(baseline)
    pointer = transform.get("pointer", transform.get("path"))
    if not isinstance(pointer, str) or not pointer.startswith("/candidate/"):
        raise _TransformError("fixture pointer")
    if transform["operation"] == "insert":
        target = _select(result, pointer)
        index = transform["index"]
        if not isinstance(target, list) or type(index) is not int or not 0 <= index <= len(target):
            raise _TransformError("fixture precondition")
        target.insert(index, copy.deepcopy(transform["value"]))
        return result
    parent, key = _parent(result, pointer)
    old = transform["old"]
    expected = _fixture_value(old) if isinstance(old, dict) and "type" in old else old
    operation = transform["operation"]
    replacement = None
    if operation in {"add", "replace"}:
        replacement = (
            _fixture_value(transform["new"])
            if "new" in transform
            else copy.deepcopy(transform["value"])
        )
    if isinstance(parent, list):
        index = int(key)
        if operation == "add":
            if expected != {"absent": True} or index != len(parent):
                raise _TransformError("fixture precondition")
            parent.insert(index, _fixture_value(transform["new"]))
        else:
            if index >= len(parent) or parent[index] != expected:
                raise _TransformError("fixture precondition")
            if operation == "remove":
                del parent[index]
            elif operation == "replace":
                parent[index] = replacement
            else:
                raise _TransformError("fixture operation")
    else:
        if key not in parent or parent[key] != expected:
            raise _TransformError("fixture precondition")
        if operation == "remove":
            del parent[key]
        elif operation == "replace":
            parent[key] = replacement
        else:
            raise _TransformError("fixture operation")
    if result["oracle"] != baseline["oracle"] or result == baseline:
        raise _TransformError("fixture postcondition")
    return result


def reproduce_early_fixture(
    authority: registry.Task5Authority,
    case: registry.FixtureCase,
) -> bytes:
    baseline = authority.baselines[case.baseline]
    transform = authority.transforms[case.transform]
    if transform["baseline"] != case.baseline:
        raise _TransformError("fixture baseline")
    if case.checkpoint == "layer-2":
        profile = transform["serialization_profile"]
        if (
            profile["encoding"] != "UTF-8"
            or profile["sort_keys"] is not True
            or profile["separators"] != [",", ":"]
            or profile["ensure_ascii"] is not True
            or profile["allow_nan"] is not False
            or profile["final_newline"] is not False
        ):
            raise _TransformError("serialization profile")
        raw = _manifest_bytes(baseline)
        old = transform["old"]["value"].encode("utf-8")
        new = transform["new"]["value"].encode("utf-8")
        if raw.count(old) != transform["precondition"]["old_occurrences"]:
            raise _TransformError("fixture byte precondition")
        return raw.replace(old, new, 1)
    return _manifest_bytes(_apply_fixture_transform(baseline, transform))


def build_task5_corpus(authority: registry.Task5Authority, root: Path) -> None:
    """Materialize the complete manifest and only Task 5 fixture documents."""
    corpus_root = root / Path(authority.core["paths"]["corpus_manifest"]).parent
    (corpus_root / authority.core["paths"]["snapshot_prefix"]).mkdir(parents=True)
    (corpus_root / authority.core["paths"]["history_prefix"]).mkdir(parents=True)
    (root / authority.core["paths"]["corpus_manifest"]).write_bytes(
        _manifest_bytes(authority.manifest)
    )
    for case in authority.fixture_cases:
        (corpus_root / case.path).write_bytes(
            reproduce_early_fixture(authority, case)
        )


def reproduce_snapshot_fixture(
    authority: registry.Task6Authority,
    case: registry.FixtureCase,
) -> bytes:
    """Reproduce one admitted snapshot from its baseline and transform."""
    baseline = authority.baselines[case.identifier if case.baseline is None else case.baseline]
    if case.transform is None:
        return _manifest_bytes(baseline)
    transform = authority.transforms[case.transform]
    if transform["fixture"] != case.identifier or transform["baseline"] != case.baseline:
        raise _TransformError("snapshot fixture binding")
    if transform["operation"] == "byte-replace-once":
        task5 = registry.Task5Authority(
            authority.core,
            authority.validators,
            authority.manifest,
            (case,),
            authority.baselines,
            authority.transforms,
            authority.executable_transforms,
        )
        return reproduce_early_fixture(task5, case)
    return _manifest_bytes(_apply_fixture_transform(baseline, transform))


def build_task6_corpus(authority: registry.Task6Authority, root: Path) -> None:
    """Materialize all snapshots while retaining only Task 5 history fixtures."""
    corpus_root = root / Path(authority.core["paths"]["corpus_manifest"]).parent
    (corpus_root / authority.core["paths"]["snapshot_prefix"]).mkdir(
        parents=True, exist_ok=True
    )
    (corpus_root / authority.core["paths"]["history_prefix"]).mkdir(
        parents=True, exist_ok=True
    )
    (root / authority.core["paths"]["corpus_manifest"]).write_bytes(
        _manifest_bytes(authority.manifest)
    )
    for case in authority.snapshot_cases:
        (corpus_root / case.path).write_bytes(
            reproduce_snapshot_fixture(authority, case)
        )
    for case in authority.retained_history_cases:
        task5 = registry.Task5Authority(
            authority.core,
            authority.validators,
            authority.manifest,
            (case,),
            authority.retained_history_baselines,
            authority.retained_history_transforms,
            authority.executable_transforms,
        )
        (corpus_root / case.path).write_bytes(reproduce_early_fixture(task5, case))


def _claims_by_meaning(claims: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {claim["meaning"]: copy.deepcopy(claim) for claim in claims}


def _snapshot_purpose(authority: registry.Task6Authority) -> str:
    purposes = {
        baseline["candidate"]["transcript"]["purpose"]
        for baseline in authority.baselines.values()
    }
    if len(purposes) != 1:
        raise _TransformError("snapshot purpose authority")
    return next(iter(purposes))


def _domain_exclusion_result(
    semantic: dict[str, Any],
    oracle: dict[str, Any],
) -> str:
    name = semantic["name"]
    replacement = semantic["replacement"]
    if name == "current-live-process":
        return "Conform"
    if replacement.get("kind") != "scalar" or "token" not in replacement:
        return "EvidenceInvalid"
    replacement_value = replacement["token"]
    expected_prefix = "expected-"
    if name.startswith(expected_prefix):
        field = name[len(expected_prefix) :].replace("-", "_")
        if field in oracle["expected_context"]:
            expected_value = oracle["expected_context"][field]
            if field == "policy":
                # This scalar stimulus substitutes the policy ID only. The
                # complete policy (including version) is checked with challenge.
                expected_value = expected_value["id"]
            return (
                "Conform"
                if _same_json_value(replacement_value, expected_value)
                else "ContextBindingMismatch"
            )
    new_key_prefix = "same-key-new-"
    if name.startswith(new_key_prefix):
        field = name[len(new_key_prefix) :].replace("-", "_")
        matching_fields = [
            key
            for key in oracle["resolved_key"]
            if key == field or key.endswith("_" + field)
        ]
        if len(matching_fields) == 1:
            return (
                "Conform"
                if _same_json_value(
                    replacement_value, oracle["resolved_key"][matching_fields[0]]
                )
                else "ContextBindingMismatch"
            )
    if name == "same-key-without-fresh-challenge":
        return (
            "Conform"
            if _same_json_value(
                replacement_value, oracle["authenticated_challenge"]["nonce"]
            )
            else "ContextBindingMismatch"
        )
    return "EvidenceInvalid"


def reconstruct_snapshot(
    authority: registry.Task6Authority,
    candidate: dict[str, Any],
    oracle: dict[str, Any],
) -> tuple[str, dict[str, Any] | None]:
    """Reconstruct a transcript solely from independent snapshot oracle inputs."""
    _charge("oracle_assertions")
    candidate = copy.deepcopy(candidate)
    oracle = copy.deepcopy(oracle)
    transcript = candidate["transcript"]
    challenge = oracle["authenticated_challenge"]
    context = oracle["expected_context"]
    resolved_key = oracle["resolved_key"]
    for field in ("publisher", "game", "build", "account", "match", "policy"):
        if not _same_json_value(challenge[field], context[field]):
            return ("ContextBindingMismatch", None)
    for field in ("publisher", "protected_session", "live_subject"):
        if not _same_json_value(resolved_key[field], context[field]):
            return ("ContextBindingMismatch", None)
    if not _same_json_value(transcript["challenge"], challenge):
        return ("ContextBindingMismatch", None)
    if any(
        not _same_json_value(transcript[field], resolved_key[field])
        for field in ("actual_public_key", "session_public_key_id")
    ) or not _same_json_value(
        transcript["key_association"],
        {
            field: resolved_key[field]
            for field in ("publisher", "protected_session", "live_subject")
        },
    ):
        return ("ContextBindingMismatch", None)

    expected_claims = _claims_by_meaning(oracle["expected_claims"])
    candidate_claims = _claims_by_meaning(transcript["claims"])
    if set(candidate_claims) != set(expected_claims):
        return ("EvidenceInvalid", None)
    for meaning, expected in expected_claims.items():
        if not _compared("claim_comparisons", candidate_claims[meaning], expected):
            # The seventh version-1 ClaimMeaning role is protected-session identity.
            session_meaning = authority.validators["domains"]["ClaimMeaning"]["values"][6]
            if meaning == session_meaning and not _compared(
                "claim_comparisons", candidate_claims[meaning]["value"], expected["value"]
            ):
                return ("ContextBindingMismatch", None)
            return ("EvidenceInvalid", None)

    profile = oracle["registered_profile"]
    if not _same_json_value(transcript["profile"], profile["id"]):
        return ("EvidenceInvalid", None)
    if not _same_json_value(transcript["evidence_time"], oracle["expected_evidence_time"]):
        return ("EvidenceInvalid", None)
    profile_provenance = {
        row["meaning"]: row["provenance"] for row in profile["claim_provenance"]
    }
    if set(profile_provenance) != set(expected_claims) or any(
        not _compared("claim_comparisons", claim["provenance"], profile_provenance[meaning])
        for meaning, claim in expected_claims.items()
    ):
        return ("EvidenceInvalid", None)
    evidence_time = oracle["expected_evidence_time"]
    if profile["authority_contract"] != evidence_time["authority_contract"]:
        return ("EvidenceInvalid", None)
    duration = evidence_time["snapshot_freeze_end"] - evidence_time["collection_start"]
    if duration < 0 or duration > profile["duration_ceiling"]:
        return ("EvidenceInvalid", None)
    prior = oracle["prior_temporal_state"]
    if prior is not None and (
        prior["authority_contract"] != profile["authority_contract"]
        or prior["epoch_relation"] != evidence_time["epoch_relation"]
        or evidence_time["sequence"] <= prior["greatest_sequence"]
        or evidence_time["collection_start"] < prior["latest_freeze_end"]
    ):
        return ("EvidenceInvalid", None)
    if not _same_json_value(transcript["purpose"], _snapshot_purpose(authority)):
        return ("EvidenceInvalid", None)
    semantic = transcript["test_only_semantic"]
    if semantic is not None:
        result = _domain_exclusion_result(semantic, oracle)
        if result != "Conform":
            return (result, None)

    reconstructed = {
        "challenge": copy.deepcopy(challenge),
        "profile": oracle["registered_profile"]["id"],
        "actual_public_key": resolved_key["actual_public_key"],
        "session_public_key_id": resolved_key["session_public_key_id"],
        "key_association": {
            field: resolved_key[field]
            for field in ("publisher", "protected_session", "live_subject")
        },
        "evidence_time": copy.deepcopy(oracle["expected_evidence_time"]),
        "purpose": _snapshot_purpose(authority),
        # Claim-entry order is nonsemantic on either side. Use the admitted
        # profile order for the ordered coverage projection, never input order.
        "claims": [
            copy.deepcopy(expected_claims[meaning])
            for meaning in profile["required_claim_meanings"]
        ],
    }
    return ("Conform", reconstructed)


def _schema_object_leaves(
    value: dict[str, Any],
    schema_name: str,
    schemas: dict[str, Any],
    path: tuple[str, ...] = (),
) -> list[tuple[tuple[str, ...], Any]]:
    schema = schemas[schema_name]
    leaves: list[tuple[tuple[str, ...], Any]] = []
    for field in schema["required"]:
        field_path = path + (field,)
        form = schema["properties"][field]
        reference = form.get("ref")
        if reference is not None and schemas[reference].get("type") == "object":
            leaves.extend(
                _schema_object_leaves(value[field], reference, schemas, field_path)
            )
        else:
            leaves.append((field_path, value[field]))
    return leaves


def _expected_snapshot_coverage(
    authority: registry.Task6Authority, transcript: dict[str, Any]
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []

    def add(component: str, value: Any, relationships: list[str]) -> None:
        entries.append({
            "component": component,
            "value": copy.deepcopy(value),
            "relationships": relationships,
        })

    schemas = authority.validators["schemas"]
    for path, value in _schema_object_leaves(
        transcript["challenge"], "Challenge", schemas
    ):
        add("challenge-" + "-".join(path).replace("_", "-"), value, ["exact-value"])
    add("evidence-profile", transcript["profile"], ["exact-value"])
    add(
        "actual-session-public-key",
        transcript["actual_public_key"],
        ["exact-value", "exact-association"],
    )
    add(
        "session-public-key-id",
        transcript["session_public_key_id"],
        ["exact-value", "exact-association"],
    )
    add("key-association", transcript["key_association"], ["exact-association"])
    for path, value in _schema_object_leaves(
        transcript["evidence_time"], "EvidenceTime", schemas
    ):
        add("evidence-" + "-".join(path).replace("_", "-"), value, ["exact-time"])
    add("evidence-purpose", transcript["purpose"], ["exact-purpose"])
    for claim in transcript["claims"]:
        relationships = ["exact-value", "exact-provenance"]
        if claim["value"]["kind"] == "semantic-identity":
            relationships.append("exact-identity-part")
        if claim["meaning"] in {
            "process-binding-identity",
            "protected-session-identity",
            "enforcement-policy-state",
            "attestation-identity",
        }:
            relationships.append("exact-association")
        add("claim-" + claim["meaning"], claim, relationships)
    return entries


def check_snapshot_coverage(
    authority: registry.Task6Authority,
    coverage: list[dict[str, Any]],
    reconstructed: dict[str, Any],
) -> str:
    """Compare candidate abstract coverage with independently rebuilt coverage."""
    _charge("oracle_assertions")
    return (
        "Conform"
        if _compared(
            "coverage_entry_comparisons", coverage, _expected_snapshot_coverage(authority, reconstructed)
        )
        else "EvidenceInvalid"
    )


def appraise_snapshot(
    authority: registry.Task6Authority,
    candidate: dict[str, Any],
    oracle: dict[str, Any],
    reconstructed: dict[str, Any],
) -> str:
    """Appraise values, provenance, policy, and current-subject state separately."""
    _charge("oracle_assertions")
    appraisal = copy.deepcopy(oracle["appraisal"])
    claims = _claims_by_meaning(reconstructed["claims"])
    accepted_values = {
        row["meaning"]: row["value"] for row in appraisal["acceptable_claim_values"]
    }
    accepted_provenance = {
        row["meaning"]: row["provenance"]
        for row in appraisal["acceptable_provenance"]
    }
    if set(claims) != set(accepted_values) or set(claims) != set(accepted_provenance):
        return "EvidenceInvalid"
    if any(
        not _compared("claim_comparisons", claim["value"], accepted_values[meaning])
        or not _compared("claim_comparisons", claim["provenance"], accepted_provenance[meaning])
        for meaning, claim in claims.items()
    ):
        return "EvidenceInvalid"
    if reconstructed["key_association"]["live_subject"] != appraisal["current_live_subject"]:
        return "EvidenceInvalid"
    semantic = candidate["transcript"]["test_only_semantic"]
    if semantic is not None and semantic["name"] == "current-live-process":
        accepted_process = accepted_values.get("process-binding-identity")
        if accepted_process is None or not _same_json_value(
            semantic["replacement"], accepted_process
        ):
            return "EvidenceInvalid"
    return "Conform" if appraisal["policy_accepts"] is True else "PolicyDenied"


@_metered
def run_snapshot_focused_case(authority, identifier, layer):
    return _run_snapshot_focused_case(authority, identifier, layer)


def _run_snapshot_focused_case(
    authority: registry.Task6Authority,
    identifier: str,
    layer: int,
) -> str:
    """Run one semantic oracle with freshly rebuilt baseline prerequisites."""
    if layer not in {4, 5, 6}:
        raise ValueError("snapshot focused layer")
    case = next(case for case in authority.snapshot_cases if case.identifier == identifier)
    baseline = copy.deepcopy(authority.baselines[case.baseline])
    changed = _apply_fixture_transform(baseline, authority.transforms[case.transform])
    if layer == 4:
        return reconstruct_snapshot(
            authority, changed["candidate"], changed["oracle"]
        )[0]
    result, reconstructed = reconstruct_snapshot(
        authority, baseline["candidate"], baseline["oracle"]
    )
    _require(lambda: not (result != 'Conform' or reconstructed is None), 'focused baseline reconstruction')
    if layer == 5:
        return check_snapshot_coverage(
            authority, changed["candidate"]["coverage"], reconstructed
        )
    coverage = check_snapshot_coverage(
        authority, baseline["candidate"]["coverage"], reconstructed
    )
    _require(lambda: not (coverage != 'Conform'), 'focused baseline coverage')
    return appraise_snapshot(
        authority, changed["candidate"], changed["oracle"], reconstructed
    )


def _same_typed_snapshot(left: Any, right: Any, *, claims: bool = False) -> bool:
    _charge(_COMPARISON_CATEGORY.get())
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _same_typed_snapshot(
                left[key], right[key], claims=claims or key in {"claims", "expected_claims"}
            )
            for key in left
        )
    if isinstance(left, list):
        if claims:
            if not all(isinstance(item, dict) and "meaning" in item for item in left + right):
                return False
            left = sorted(left, key=lambda item: item["meaning"])
            right = sorted(right, key=lambda item: item["meaning"])
        return len(left) == len(right) and all(
            _same_typed_snapshot(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


@_metered
def run_admitted_snapshot_case(
    authority: registry.Task6Authority,
    admission: Layer1Admission,
    identifier: str,
    root: Path,
) -> tuple[str, str]:
    """Run one admitted snapshot through the earliest-failure pipeline."""
    if type(admission) is not Layer1Admission:
        raise TypeError("invalid layer-1 admission")
    rows = {row[0]: row for row in admission._manifest_value()["fixtures"]}
    try:
        case = registry.FixtureCase(*rows[identifier])
    except (KeyError, TypeError, ValueError):
        _reject_layer1()
    if case.kind != "snapshot":
        _reject_layer1()
    expected_bytes = reproduce_snapshot_fixture(authority, case)
    relative = str(
        Path(authority.core["paths"]["corpus_manifest"]).parent / case.path
    )
    expected_identity, expected_hierarchy = admission._fixture_read_evidence(relative)
    limits = bounded_json.JsonLimits.from_mapping(
        authority.core["resource_limits"]["fixture"]
    )
    try:
        value = bounded_json.load_bounded_json_matching_identity(
            root,
            relative,
            limits,
            LAYER2_DIAGNOSTIC,
            expected_identity,
            expected_bytes=expected_bytes if case.checkpoint == "layer-2" else None,
            expected_hierarchy=expected_hierarchy,
            node_visit=_visit_decoded_node,
        )
    except bounded_json.BoundedJsonError as error:
        if error.category == "identity":
            raise
        # Byte-limit rejection occurs before the loader can prove content equality.
        _require(lambda: error.category not in {"content", "bytes"}, 'snapshot reproduction mismatch')
        actual = ("layer-2", "Malformed")
    else:
        expected = json.loads(expected_bytes)
        comparison = _same_json_value if case.checkpoint == "layer-3" else _same_typed_snapshot
        _require(lambda: comparison(value, expected), 'snapshot reproduction mismatch')
        shape = _fixture_shape_result(authority, value)
        if shape != ("layer-4", "Conform"):
            actual = shape
        else:
            reconstruction, reconstructed = reconstruct_snapshot(
                authority, value["candidate"], value["oracle"]
            )
            if reconstruction != "Conform" or reconstructed is None:
                actual = ("layer-4", reconstruction)
            else:
                coverage = check_snapshot_coverage(
                    authority, value["candidate"]["coverage"], reconstructed
                )
                if coverage != "Conform":
                    actual = ("layer-5", coverage)
                else:
                    appraisal = appraise_snapshot(
                        authority, value["candidate"], value["oracle"], reconstructed
                    )
                    actual = (
                        "layer-6-success" if appraisal == "Conform" else "layer-6",
                        appraisal,
                    )
    _require(lambda: not (actual != (case.checkpoint, case.disposition)), 'snapshot registry expectation mismatch')
    return actual


def _same_json_value(left: Any, right: Any) -> bool:
    _charge(_COMPARISON_CATEGORY.get())
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _same_json_value(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _same_json_value(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


def _fixture_shape_result(
    authority: registry.Task5Authority | registry.Task6Authority, value: Any
) -> tuple[str, str]:
    schemas = authority.validators["schemas"]
    domains = authority.validators["domains"]
    envelope = schemas["FixtureEnvelope"]
    if not _valid_typed(value, envelope, schemas, domains):
        return ("layer-3", "Malformed")
    kind_domain = envelope["properties"]["kind"]["domain"]
    kinds = domains[kind_domain]["values"]
    candidate_forms = envelope["properties"]["candidate"]["union"]
    oracle_forms = envelope["properties"]["oracle"]["union"]
    try:
        kind_index = kinds.index(value["kind"])
        candidate_form = candidate_forms[kind_index]
        oracle_form = oracle_forms[kind_index]
    except (IndexError, KeyError, ValueError):
        return ("layer-3", "Malformed")
    if not _valid_typed(
        value["candidate"], candidate_form, schemas, domains
    ) or not _valid_typed(value["oracle"], oracle_form, schemas, domains):
        return ("layer-3", "Malformed")

    candidate_schema = schemas[candidate_form["ref"]]
    if "transcript" in candidate_schema["properties"]:
        semantic = value["candidate"]["transcript"]["test_only_semantic"]
        # Version-1 ordered domain roles are unknown-critical and domain-exclusion.
        # Outcomes implement the shape rule, never a fixture's expected answer.
        unknown_critical, domain_exclusion = domains["Criticality"]["values"]
        if semantic is not None and semantic["criticality"] == unknown_critical:
            return ("layer-3", "Unsupported")
        if semantic is not None and semantic["criticality"] != domain_exclusion:
            return ("layer-3", "Malformed")
        meanings = [
            claim["meaning"] for claim in value["candidate"]["transcript"]["claims"]
        ]
        required = value["oracle"]["registered_profile"]["required_claim_meanings"]
        if len(meanings) != len(required) or set(meanings) != set(required):
            return ("layer-3", "Malformed")
    elif "collections" in candidate_schema["properties"]:
        time_domains = {
            collection["time_domain"] for collection in value["candidate"]["collections"]
        }
        # Version-1 time-domain roles: protected collection, client wall clock,
        # and an unknown critical domain. The JSON domain supplies their names.
        protected, client_utc, unknown_critical = domains["TimeDomain"]["values"]
        if unknown_critical in time_domains:
            return ("layer-3", "Unsupported")
        if client_utc in time_domains or time_domains != {protected}:
            return ("layer-3", "Malformed")
    else:
        return ("layer-3", "Malformed")
    return ("layer-4", "Conform")


def run_early_fixture_case(
    authority: registry.Task5Authority,
    case: registry.FixtureCase,
    root: Path,
) -> tuple[str, str]:
    admission = admit_layer1(authority, root)
    return run_admitted_early_fixture_case(
        authority, admission, case.identifier, root
    )


@_metered
def run_admitted_early_fixture_case(
    authority: registry.Task5Authority,
    admission: Layer1Admission,
    identifier: str,
    root: Path,
) -> tuple[str, str]:
    if type(admission) is not Layer1Admission:
        raise TypeError("invalid layer-1 admission")
    admitted_rows = {
        row[0]: row for row in admission._manifest_value()["fixtures"]
    }
    try:
        admitted_case = registry.FixtureCase(*admitted_rows[identifier])
    except (KeyError, TypeError, ValueError):
        _reject_layer1()
    expected_bytes = reproduce_early_fixture(authority, admitted_case)
    relative = str(
        Path(authority.core["paths"]["corpus_manifest"]).parent
        / admitted_case.path
    )
    limits = bounded_json.JsonLimits.from_mapping(
        authority.core["resource_limits"]["fixture"]
    )
    expected_identity, expected_hierarchy = admission._fixture_read_evidence(relative)
    try:
        if admitted_case.checkpoint == "layer-2":
            value = bounded_json.load_bounded_json_matching_identity(
                root,
                relative,
                limits,
                LAYER2_DIAGNOSTIC,
                expected_identity,
                expected_bytes,
                expected_hierarchy,
                node_visit=_visit_decoded_node,
            )
        else:
            value = bounded_json.load_bounded_json_matching_identity(
                root,
                relative,
                limits,
                LAYER2_DIAGNOSTIC,
                expected_identity,
                expected_hierarchy=expected_hierarchy,
                node_visit=_visit_decoded_node,
            )
            _require(lambda: _same_json_value(value, json.loads(expected_bytes)), 'fixture reproduction mismatch')
    except bounded_json.BoundedJsonError as error:
        if error.category == "identity":
            _require(lambda: not (str(error) != LAYER2_DIAGNOSTIC or error.__cause__ is not None), 'unsafe layer-2 diagnostic')
            raise
        # Byte-limit rejection occurs before the loader can prove content equality.
        _require(lambda: error.category not in {"content", "bytes"}, 'fixture reproduction mismatch')
        actual = ("layer-2", "Malformed")
        _require(lambda: not (str(error) != LAYER2_DIAGNOSTIC or error.__cause__ is not None), 'unsafe layer-2 diagnostic')
    else:
        actual = _fixture_shape_result(authority, value)
    _require(lambda: not (actual != (admitted_case.checkpoint, admitted_case.disposition)), 'early fixture registry expectation mismatch')
    return actual


@_metered
def admit_layer1(authority, root, executable_transforms=None):
    return _admit_layer1(authority, root, executable_transforms)


def _admit_layer1(
    authority: registry.Task4Authority | registry.Task5Authority,
    root: Path,
    executable_transforms: dict[str, Any] | None = None,
) -> Layer1Admission:
    selected_transforms = (
        authority.executable_transforms
        if executable_transforms is None
        else executable_transforms
    )
    limits = bounded_json.JsonLimits.from_mapping(
        authority.core["resource_limits"]["manifest"]
    )
    value, manifest_identity = bounded_json.load_bounded_json_with_identity(
        root,
        authority.core["paths"]["corpus_manifest"],
        limits,
        LAYER1_DIAGNOSTIC,
        node_visit=_visit_decoded_node,
    )
    if not isinstance(value, dict):
        _reject_layer1()
    if (
        set(value) != {
            "format_version",
            "counts",
            "fixtures",
            "validator_cases",
            "coverage",
        }
        or type(value["format_version"]) is not int
        or value["format_version"] != 1
        or not isinstance(value["counts"], dict)
        or not isinstance(value["fixtures"], list)
        or not isinstance(value["validator_cases"], list)
        or not isinstance(value["coverage"], dict)
    ):
        _reject_layer1()
    if not _valid_typed(
        value,
        authority.validators["schemas"]["Manifest"],
        authority.validators["schemas"],
        authority.validators["domains"],
    ):
        _reject_layer1()
    fixture_paths = [row[2] for row in value["fixtures"]]
    if len(fixture_paths) != len(set(fixture_paths)):
        _reject_layer1()
    paths = authority.core["paths"]
    for row in value["fixtures"]:
        expected_prefix = (
            paths["snapshot_prefix"] if row[1] == "snapshot" else paths["history_prefix"]
        )
        if not row[2].startswith(expected_prefix) or not row[2].endswith(
            paths["fixture_suffix"]
        ):
            _reject_layer1()
    canonical_manifest = authority.validators["validator_baselines"][
        "baseline-corpus-v1"
    ]["ast"]["value"]
    fixtures_by_id = {row[0]: row for row in value["fixtures"]}
    canonical_fixtures_by_id = {
        row[0]: row for row in canonical_manifest["fixtures"]
    }
    if not _same_json_value(fixtures_by_id, canonical_fixtures_by_id):
        _reject_layer1()
    cases_by_id = {row[0]: row for row in value["validator_cases"]}
    canonical_cases_by_id = {
        row[0]: row for row in canonical_manifest["validator_cases"]
    }
    if (
        not _same_json_value(cases_by_id, canonical_cases_by_id)
        or not _same_json_value(selected_transforms, authority.executable_transforms)
    ):
        _reject_layer1()
    registered = set(fixtures_by_id) | set(cases_by_id)
    if len(registered) != len(fixtures_by_id) + len(cases_by_id):
        _reject_layer1()
    mapped = {
        identifier
        for identifiers in value["coverage"].values()
        for identifier in identifiers
    }
    if mapped != registered or not _same_json_value(value["coverage"], canonical_manifest["coverage"]):
        _reject_layer1()
    identities = _validate_inventory(root, value, paths, manifest_identity)
    return Layer1Admission(_ADMISSION_TOKEN, value, identities)


def validate_layer1(
    authority: registry.Task4Authority | registry.Task5Authority,
    root: Path,
    executable_transforms: dict[str, Any] | None = None,
) -> dict[str, Any]:
    admission = admit_layer1(authority, root, executable_transforms)
    return copy.deepcopy(admission._manifest_value())


def run_layer1_self_tests(authority: registry.Task4Authority | None = None) -> int:
    selected = registry.load_task4_authority() if authority is None else authority
    for case in selected.corpus_cases:
        run_layer1_case(selected, case)
    return len(selected.corpus_cases)


@_metered
def run_layer1_case(authority, case):
    return _run_layer1_case(authority, case)

def _run_layer1_case(
    authority: registry.Task4Authority,
    case: registry.LoaderCase,
) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        canonical_root = Path(temporary) / "canonical"
        canonical_root.mkdir()
        build_synthetic_corpus(authority, canonical_root)
        _admit_layer1(authority, canonical_root)

        checkpoint = case.checkpoint
        disposition = case.disposition
        program = authority.corpus_transforms[case.identifier]["ast"]
        spec = _as_spec(authority, _evaluate(authority, program))
        candidate_root = Path(temporary) / "candidate"
        candidate_root.mkdir()
        _materialize(spec, candidate_root)
        try:
            _admit_layer1(
                authority,
                candidate_root,
                {
                    identifier: authority.executable_transforms[identifier]
                    for identifier in spec.executable_transforms
                },
            )
        except bounded_json.BoundedJsonError as error:
            actual = ("layer-1", "Malformed")
            _require(lambda: not (str(error) != LAYER1_DIAGNOSTIC or error.__cause__ is not None), 'unsafe layer-1 diagnostic')
        else:
            actual = ("layer-1", "Conform")
        _require(lambda: not (actual != (checkpoint, disposition)), 'layer-1 registry expectation mismatch')


def _require(condition, message="abstract-conformance:internal:internal-failure"):
    _charge("oracle_assertions")
    if not condition():
        raise AssertionError(message) from None


def _load_test_adapter(filename):
    """Load existing registered test adapters, without running unittest discovery."""
    import importlib.util

    path = Path(__file__).resolve().parent / filename
    spec = importlib.util.spec_from_file_location("_conformance_" + path.stem.replace("-", "_"), path)
    if spec is None or spec.loader is None:
        raise RuntimeError("abstract-conformance:internal:internal-failure")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _case_adapters():
    return {"loader-probe": _load_test_adapter("test-bounded-json.py"),
            "attack-loader-parity": _load_test_adapter("test-attack-scenario-parity.py")}


def _run_loader_case(authority, case, adapter):
    value = adapter._probe_input(case, authority)
    probe = authority.validators["validator_transforms"][case.transform]["ast"]["steps"][-1]
    if probe["adapter"] == "bounded-json-diagnostic":
        rendered = bounded_json.render_bounded_json_error(
            LAYER2_DIAGNOSTIC, RuntimeError(json.dumps(value, default=str)))
        _require(lambda: rendered == LAYER2_DIAGNOSTIC)
        return
    limits = bounded_json.JsonLimits.from_mapping(authority.core["resource_limits"]["fixture"])
    with tempfile.TemporaryDirectory() as temporary:
        root, relative = adapter._write_fixture(Path(temporary), value)
        try:
            bounded_json.load_bounded_json(root, relative, limits, LAYER2_DIAGNOSTIC,
                                              node_visit=_visit_decoded_node,
            )
        except bounded_json.BoundedJsonError as error:
            _require(lambda: case.disposition == "Malformed" and str(error) == LAYER2_DIAGNOSTIC)
        else:
            _require(lambda: case.disposition == "Conform")


def _run_attack_case(authority, case, adapter):
    """Reuse the actual legacy checker; capture its unchanged compatibility output."""
    import contextlib
    import io

    test = adapter.AttackParityTests()
    test.authority = registry.Task3Authority(
        authority.core,
        tuple(registry.LoaderCase(*row) for row in authority.validators["validator_cases"]
              if row[1] == "attack-loader-parity"),
        {row[0]: authority.validators["validator_transforms"][row[3]]
         for row in authority.validators["validator_cases"] if row[1] == "attack-loader-parity"},
        authority.validators["validator_baselines"]["baseline-attack-repository"]["ast"]["value"],
        authority.validators["attack_parity_expectations"]["by_case_id"],
    )
    checker = Path(__file__).resolve().parent.parent / test.authority.attack_baseline["checker"]["path"]
    test.checker = adapter._load_checker(checker)
    output, errors = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
        status = test._run_registry_case_worker(case)
    expected = test.authority.attack_expectations.get(case.identifier, {})
    probe = test._validate_transform(case)
    if probe["entrypoint"] == "cli":
        _require(lambda: status == expected["expected_exit"] and errors.getvalue() == expected["expected_stderr"])
        _require(lambda: output.getvalue() == expected.get("expected_stdout", adapter.SELF_TEST_STDOUT))
        if "stdout_final_line" in expected:
            _require(lambda: output.getvalue().splitlines()[-1] == expected["stdout_final_line"])
    else:
        _require(lambda: status == (3 if case.disposition == "Malformed" else 0) and output.getvalue() == "")
        rendered = errors.getvalue().removesuffix("\n")
        _require(lambda: bool(rendered) == (case.disposition == "Malformed"))
        if "expected_message" in expected:
            _require(lambda: rendered == expected["expected_message"])
        if expected.get("redaction_required"):
            _require(lambda: not any(part in rendered for part in
                             ("/home/", "\n", "\r", "\x1b", "::error::", "::warning::")))


@_metered
def run_validator_case(authority, case, adapters=None):
    """Dispatch only an admitted registered case in one fresh budget scope."""
    admitted = next((registry.LoaderCase(*row) for row in authority.validators["validator_cases"]
                     if row[0] == case.identifier), None)
    _require(lambda: admitted is not None and admitted == case)
    if case.operation == "corpus-mutation":
        return _run_layer1_case(authority, admitted)
    if adapters is None:
        adapters = _case_adapters()
    if case.operation == "loader-probe":
        return _run_loader_case(authority, admitted, adapters[case.operation])
    if case.operation == "attack-loader-parity":
        return _run_attack_case(authority, admitted, adapters[case.operation])
    _require(lambda: False)


@_metered
def run_focused_case(authority, identifier, layer):
    """Check one independent focused invocation within its own fresh budget."""
    if layer not in (4, 5, 6):
        raise ValueError("focused layer")
    if isinstance(authority, registry.Task6Authority):
        rows = authority.focused_rows
        function = _run_snapshot_focused_case
    else:
        rows = authority.histories["focused_expected_tuples"]
        function = _run_history_focused_case
    row = next(row for row in rows if row[0] == identifier)
    actual = function(authority, identifier, layer)
    _require(lambda: actual == row[layer - 3])
    return actual


def run_focused_matrix(authority=None, snapshot_authority=None):
    """Literal admitted row order, each layer rebuilding its own prerequisites."""
    authority = registry.load_task4_authority() if authority is None else authority
    snapshots = registry.load_task6_authority() if snapshot_authority is None else snapshot_authority
    results = []
    for selected, rows in (
        (snapshots, snapshots.focused_rows),
        (authority, authority.histories["focused_expected_tuples"]),
    ):
        for row in rows:
            for layer in (4, 5, 6):
                actual, vector = measure_call(run_focused_case, selected, row[0], layer)
                results.append((row[0], layer, actual, vector))
    return tuple(results)


def run_corpus(authority=None, snapshot_authority=None, root=None):
    authority = registry.load_task4_authority() if authority is None else authority
    snapshots = registry.load_task6_authority() if snapshot_authority is None else snapshot_authority
    root = Path(__file__).resolve().parent.parent if root is None else root
    admission, admission_vector = measure_call(admit_layer1, authority, root)
    results = []
    for row in admission._manifest_value()["fixtures"]:
        selected, function = ((snapshots, run_admitted_snapshot_case) if row[1] == "snapshot"
                              else (authority, run_admitted_history_case))
        actual, vector = measure_call(function, selected, admission, row[0], root)
        results.append((row[0], actual, vector))
    return admission_vector, tuple(results)


def run_self_tests(authority=None):
    authority = registry.load_task4_authority() if authority is None else authority
    # Admit the complete canonical corpus before consuming case expectations.
    admission = admit_layer1(authority, Path(__file__).resolve().parent.parent)
    adapters = _case_adapters()
    results = []
    for row in admission._manifest_value()["validator_cases"]:
        case = registry.LoaderCase(*row)
        _, vector = measure_call(run_validator_case, authority, case, adapters)
        results.append((case.identifier, vector))
    focused = run_focused_matrix(authority)
    return tuple(results), focused
