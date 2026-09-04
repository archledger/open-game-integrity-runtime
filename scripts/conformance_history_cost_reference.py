"""Independent cost traces for the finite admitted history matrix.

No consumer import or measured counters are used. Ordered registry rules describe
trusted guard costs; success effects project the state needed for schema costs.
Candidate paths use separately reviewed, named stopping points for the admitted
single-edit stimuli. This is a cost model for these cases, not a validator.
"""

from __future__ import annotations

import copy

from conformance_accounting_reference import CostModel, ReferenceError, transformed


# A trace names the failing action index, its last completed cost segment and
# resulting state shape. Indices follow the admitted baseline and one transform.
_STOPS = {
    "open-before-challenge-receipt": (0, "open-pair", "identity"),
    "proof-before-snapshot-freeze": (1, "submit", "identity"),
    "change-after-snapshot-freeze": (2, "submit", "identity"),
    "reuse-collection-sequence": (6, "validate-sequence", "terminal-loss"),
    "decrease-collection-sequence": (6, "validate-sequence", "terminal-loss"),
    "change-protected-epoch": (3, "validate-epoch", "terminal-loss"),
    "change-protected-source": (7, "validate-water", "terminal-loss"),
    "restart-collection-authority": (4, "none", "terminal-loss"),
    "restart-protected-source": (4, "none", "terminal-loss"),
    "restart-protected-session": (4, "none", "terminal-loss"),
    "discontinue-protected-source": (0, "open-records", "terminal-loss"),
    "rollback-protected-source": (4, "none", "terminal-loss"),
    "open-concurrent-collection": (5, "open-pair", "identity"),
    "overlap-collection-interval": (7, "validate-water", "terminal-loss"),
    "race-temporal-compare-and-advance": (7, "concurrent", "terminal-loss"),
    "order-start-after-freeze-end": (1, "freeze", "terminal-loss"),
    "exceed-profile-duration-ceiling": (3, "validate-ceiling", "clear-evidence"),
    "exceed-publisher-duration-ceiling": (3, "validate-ceiling", "clear-evidence"),
    "receive-at-challenge-expiry": (2, "submit", "clear-evidence"),
    "receive-after-challenge-expiry": (2, "submit", "clear-evidence"),
    "omit-cached-current-subject-revalidation": (1, "freeze", "identity"),
    "omit-boot-origin-current-subject-revalidation": (1, "freeze", "identity"),
    "outage-collection-authority": (4, "outage", "outage"),
    "outage-temporal-store": (4, "outage", "outage"),
    "repair-high-water-from-client": (4, "open-records", "terminal-loss"),
    "remove-temporal-high-water": (4, "open-records", "terminal-loss"),
    "corrupt-temporal-high-water": (4, "open-records", "terminal-loss"),
    "contradict-temporal-high-water": (4, "open-records", "terminal-loss"),
    "rollback-temporal-high-water": (4, "open-records", "terminal-loss"),
    "reject-claim-after-temporal-advance": (8, "claim", "claim"),
    "reject-policy-after-temporal-advance": (8, "none", "policy"),
    "reset-sequence-on-profile-transition": (3, "validate-sequence", "terminal-loss"),
    "reuse-ended-session-epoch": (10, "none", "terminal-loss"),
    "substitute-ended-epoch-in-new-session": (0, "open-records", "terminal-loss"),
    "reuse-key-after-terminal": (0, "open-records", "terminal-loss"),
    "weaken-policy-with-same-key": (4, "renewal-policy-first", "identity"),
}
_PASS = {"substitute-covered-challenge", "invalidate-abstract-coverage",
         "unauthenticate-authority-statement", "substitute-client-utc",
         "substitute-unknown-critical-time-domain", None}


def _pick(rows, identifier):
    return next(row for row in rows if row["id"] == identifier)


def _canonical(identifier):
    return "t-" + identifier[2:]


def _record(model, rows, identifier):
    # All IDs are scalar strings and resolution scans the entire admitted table.
    model.add("oracle_assertions", len(rows))
    return _pick(rows, identifier)


def _initial(model, oracle):
    state = {}
    for path, value in zip(model.authority.histories["state_tuple_fields"], oracle["initial_state"]):
        section, field = path.split(".")
        state.setdefault(section, {})[field] = copy.deepcopy(value)
    return state


def _check(model, state):
    if not model.typed(state, model.schemas["LifecycleState"]):
        raise ReferenceError("history cost reference state") from None


def _operand(value, state, arguments, bindings):
    if not isinstance(value, str):
        return copy.deepcopy(value)
    head, *tail = value.split(".")
    if head == "state":
        selected = state
    elif head in bindings:
        selected = bindings[head]
    else:
        return copy.deepcopy(arguments.get(value, value))
    for field in tail:
        selected = selected[field]
    return copy.deepcopy(selected)


def _bindings(model, oracle, state, action, *, charge=False):
    rules = model.authority.histories["action_rules"]
    rule = next(row for row in rules if row["label"] == action["label"])
    args = dict(zip(rule["arguments"], action["args"]))
    bindings = {}
    for name, spec in model.authority.histories["interpreter"]["record_resolution"][action["label"]].items():
        if isinstance(spec, dict):
            condition = spec["required_only_when"]
            value = _operand(condition[1], state, args, bindings)
            if charge:
                model.add("oracle_assertions")  # conditional guard predicate
                model.equal(value, condition[2])
            if value != condition[2]:
                bindings[name] = None
                continue
            _, field, selector = spec["selector"]
            target = _operand(selector, state, args, bindings)
            rows = oracle[spec["registry"]]
            if charge:
                model.add("oracle_assertions", len(rows))
            bindings[name] = next(row for row in rows if row[field] == target)
        else:
            rows = oracle[spec[0]]
            target = _operand(spec[1], state, args, bindings)
            bindings[name] = _record(model, rows, target) if charge else _pick(rows, target)
    return rule, args, bindings


def _effect(model, state, name, args, bindings):
    """Project admitted successful rule effects; no semantic decision oracle."""
    empty = model.authority.histories["empty_values"]
    if isinstance(name, list):
        _, path, value = name
        *prefix, field = path.split(".")[1:]
        target = state
        for part in prefix:
            target = target[part]
        target[field] = _operand(value, state, args, bindings)
    elif name == "identity":
        pass
    elif name.startswith("clear-"):
        section = name[6:]
        state[section] = copy.deepcopy(empty[section])
        if section in {"collection", "evidence"}:
            field = "active_collection_ref" if section == "collection" else "in_flight_observation_ref"
            state["ordering"][field] = None
    elif name == "load-challenge":
        source = bindings["trusted_challenge"]
        state["challenge"] = {key: copy.deepcopy(source[key]) for key in state["challenge"] if key in source}
        state["challenge"].update(status="authenticated", challenge_ref=source["id"], consumed=False)
    elif name == "open-collection":
        source = bindings["trusted_authority"]
        _effect(model, state, "clear-collection", args, bindings)
        state["collection"].update({key: copy.deepcopy(source[key]) for key in state["collection"] if key in source})
        state["collection"].update(status="open", collection_ref=source["id"], observation_ref=None)
        state["ordering"]["active_collection_ref"] = source["id"]
    elif name == "freeze-observation":
        state["collection"].update(status="frozen", observation_ref=args["observation_ref"])
        state["evidence"].update(proof_state="pending", coverage_state="pending",
                                  authority_statement_state=bindings["trusted_authority"]["authority_statement_state"])
    elif name == "submit-observation":
        source = bindings["trusted_observation"]
        state["challenge"].update(receipt_tick=args["receipt_tick"], consumed=True)
        state["evidence"].update(proof_state="covered", coverage_state=source["coverage_state"],
            authority_statement_state=source["authority_statement_state"],
            submitted_observation_ref=source["id"], submission_receipt_tick=args["receipt_tick"])
        state["ordering"]["in_flight_observation_ref"] = source["id"]
    elif name == "advance-high-water":
        source = state["collection"]
        state["high_water"] = {"status": "available", **{key: source[key] for key in
            ("authority_contract", "protected_source", "epoch_relation")},
            "greatest_sequence": source["sequence"], "latest_freeze_end": source["snapshot_freeze_end"]}
        state["ordering"]["compare_generation"] += 1
        state["ordering"]["in_flight_observation_ref"] = None
        state["retention"]["temporal_state"] = "retained"
    elif name == "restore-high-water-if-needed":
        if state["high_water"]["status"] == "unavailable":
            state["high_water"] = copy.deepcopy(bindings["trusted_recovery"]["temporal_state"])
            state["high_water"]["status"] = "available"
    elif name == "delete-high-water":
        state["high_water"] = copy.deepcopy(empty["high_water_deleted"])
        state["retention"] = {"temporal_state": "deleted", "deletion_required": False}
    elif name == "terminal-loss":
        state["session"].update(status="lost", continuity="lost")
        for section in ("challenge", "collection", "evidence"):
            _effect(model, state, "clear-" + section, args, bindings)
        _effect(model, state, "delete-high-water", args, bindings)
    else:
        raise ReferenceError("history cost reference effect") from None


def _numbers(model, values, domain="Natural"):
    for value in values:
        model.domain(value, domain)


def _guard_cost(model, oracle, state, args, bindings, guard):
    # Replayed trusted baselines are all successful. The algebra counts each
    # successful guard's cost, including short-circuit membership and null water.
    left, op, right = guard[:3]
    left, right = (_operand(item, state, args, bindings) for item in (left, right))
    model.add("oracle_assertions")
    if op == "eq":
        model.equal(left, right)
    elif op == "in":
        for value in right:
            if model.equal(left, value):
                break
    elif op in {"lt", "lte", "gt"}:
        _numbers(model, (left, right))
    elif op == "trusted-ref-exists":
        model.add("oracle_assertions", len(oracle[right]))
    elif op == "matches-active-session":
        for field in ("publisher", "live_subject", "actual_public_key", "session_public_key_id"):
            model.equal(left[field], state["session"][field])
        _record(model, oracle["trusted_sessions"], left["session_ref"])
    elif op == "matches-high-water" and right["status"] == "available":
        _record(model, oracle["trusted_authorities"], bindings["trusted_observation"]["collection_ref"])
        _numbers(model, (left["sequence"], right["greatest_sequence"]), "ProtectedSequence")
        _numbers(model, (left["collection_start"], right["latest_freeze_end"]), "ProtectedTick")
    elif op == "duration-within-effective-ceiling":
        _numbers(model, (left["collection_start"], left["snapshot_freeze_end"]), "ProtectedTick")
        _numbers(model, (right["profile_duration_ceiling"], right["publisher_duration_ceiling"]), "Duration")
    elif op == "recoverable" and left["status"] == "unavailable":
        for field, value in left.items():
            if field != "status":
                model.equal(value, bindings["trusted_recovery"]["temporal_state"][field])
    elif op == "policy-not-weakened":
        _numbers(model, (left["policy_strength"], right["policy_strength"]))


def _reconstruction(model, candidate, oracle):
    model.add("oracle_assertions")
    for observation in candidate["observations"]:
        _record(model, candidate["observations"], observation["id"])
        trusted = _record(model, oracle["observation_oracles"], _canonical(observation["id"]))
        challenge = _record(model, candidate["challenges"], observation["challenge_ref"])
        _record(model, candidate["collections"], observation["collection_ref"])
        session = _record(model, candidate["sessions"], observation["session_ref"])
        challenge_expected = _record(model, oracle["trusted_challenges"], trusted["challenge_ref"])
        session_expected = _record(model, oracle["trusted_sessions"], trusted["session_ref"])
        _record(model, oracle["trusted_profiles"], trusted["profile_id"])
        if _canonical(challenge["id"]) != trusted["challenge_ref"]:
            return False
        for left, right, fields in ((challenge, challenge_expected, ("publisher", "nonce", "issued_tick", "expires_tick")),
                                    (session, session_expected, ("publisher", "live_subject")),
                                    (session["key_handle_association"], session_expected, ("actual_public_key", "session_public_key_id"))):
            if not all(model.equal(left[field], right[field]) for field in fields):
                return False
        _record(model, oracle["trusted_authorities"], trusted["collection_ref"])
    return True


def _coverage(model, candidate, oracle):
    model.add("oracle_assertions")
    for observation in candidate["observations"]:
        if observation["coverage_state"] != "valid" or observation["authority_statement_state"] != "authenticated":
            return False
        expected = _pick(oracle["observation_oracles"], _canonical(observation["id"]))
        for field in ("coverage_state", "authority_statement_state"):
            model.equal(observation[field], expected[field], "coverage_entry_comparisons")
    return True


def _action(model, action):
    rule = next(row for row in model.authority.histories["action_rules"] if row["label"] == action["label"])
    refs = {"observation_ref", "first_observation_ref", "second_observation_ref",
            "challenge_ref", "collection_ref", "session_ref", "recovery_ref"}
    return {"label": action["label"], "args": [_canonical(value) if name in refs else value
        for name, value in zip(rule["arguments"], action["args"])]}


def _candidate_cost(model, candidate, oracle, state, action, stop=None):
    """Cost segments for candidate actions, ending at the named failure gate."""
    model.add("history_actions")
    label, args = action["label"], action["args"]
    if stop == "none":
        return
    def record(name, identifier):
        return _record(model, candidate[name], identifier)
    if label in {"collection-open", "renewal"}:
        challenge = record("challenges", args[0])
        opened = record("collections", args[1])
        if stop == "open-pair":
            return
        authority = _record(model, oracle["trusted_authorities"], _canonical(opened["id"]))
        trusted_challenge = _record(model, oracle["trusted_challenges"], authority["challenge_ref"])
        observation = next(row for row in candidate["observations"] if row["collection_ref"] == opened["id"])
        session = record("sessions", observation["session_ref"])
        _record(model, oracle["trusted_sessions"], _canonical(session["id"]))
        profile = _record(model, oracle["trusted_profiles"], opened["profile_id"])
        if stop == "open-records":
            return
        if label == "renewal" and state["high_water"]["status"] == "unavailable":
            recovery = next(row for row in candidate["recovery_inputs"] if row["fresh_challenge_ref"] == args[0])
            trusted = next(row for row in oracle["trusted_recoveries"] if row["fresh_challenge_ref"] == _canonical(args[0]))
            temporal = record("temporal_states", recovery["temporal_state_ref"])
            for field, value in state["high_water"].items():
                if field != "status":
                    model.equal(value, trusted["temporal_state"][field])
                    model.equal(value, temporal[field])
        for source, target, fields in (
            (session, state["session"], ("publisher", "live_subject")),
            (session["key_handle_association"], state["session"], ("actual_public_key", "session_public_key_id")),
            (authority, state["session"], ("publisher", "live_subject", "actual_public_key", "session_public_key_id")),
            (challenge, trusted_challenge, ("publisher", "nonce", "issued_tick", "expires_tick")),
        ):
            for field in fields:
                model.equal(source[field], target[field])
        if label == "renewal":
            _numbers(model, (session["policy_strength"], state["profile"]["policy_strength"]))
            if stop != "renewal-policy-first":
                _numbers(model, (profile["policy_strength"], state["profile"]["policy_strength"]))
    elif label == "snapshot-freeze":
        record("collections", args[0])
        record("observations", args[1])
    elif label == "submit":
        record("observations", args[0])
        _numbers(model, (args[1],), "ProtectedTick")
    elif label == "validate":
        observed = record("observations", args[0])
        expected = _pick(oracle["observation_oracles"], _canonical(observed["id"]))
        collection, water = state["collection"], state["high_water"]
        _numbers(model, (collection["collection_start"], collection["snapshot_freeze_end"]), "ProtectedTick")
        if water["status"] == "available":
            _record(model, oracle["trusted_profiles"], expected["profile_id"])
            if stop == "validate-epoch":
                return
            _numbers(model, (collection["sequence"], water["greatest_sequence"]), "ProtectedSequence")
            if stop == "validate-sequence":
                return
            _numbers(model, (water["latest_freeze_end"],), "ProtectedTick")
            if stop == "validate-water":
                return
        _numbers(model, (state["profile"]["profile_duration_ceiling"], state["profile"]["publisher_duration_ceiling"]), "Duration")
        if stop == "validate-ceiling":
            return
        authority = _record(model, oracle["trusted_authorities"], expected["collection_ref"])
        for field in ("authority_contract", "protected_source", "epoch_relation", "sequence",
                      "collection_start", "snapshot_freeze_end", "challenge_ref"):
            model.equal(collection[field], authority[field])
        _numbers(model, (state["ordering"]["compare_generation"], state["ordering"]["compare_generation"] + 1))
    elif label == "concurrent-submit":
        for identifier in args:
            record("observations", identifier)
        _candidate_cost(model, candidate, oracle, state, {"label": "validate", "args": [args[0]]})
    elif label == "drop":
        record("collections", args[0])
    elif label == "outage":
        recovery = record("recovery_inputs", args[1])
        _record(model, oracle["trusted_recoveries"], _canonical(recovery["id"]))
    elif label == "claim-rejection":
        record("observations", args[0])
    elif label == "terminal-end":
        session = record("sessions", args[0])
        _record(model, oracle["trusted_sessions"], _canonical(session["id"]))
    elif label not in {"deletion", "policy-rejection", "restart", "rollback"}:
        raise ReferenceError("history cost reference action") from None


def _success_projection(model, oracle, state, action, candidate=None):
    rule, args, bindings = _bindings(model, oracle, state, action)
    for effect in rule["success_effect"]:
        _effect(model, state, effect, args, bindings)
    if candidate is not None and action["label"] in {"collection-open", "renewal"}:
        # The candidate imports the observed collection values; trusted replay
        # imports independently registered values. Their differing leaves affect
        # later comparisons but not the reference's success-path selection.
        opened = _pick(candidate["collections"], "c-" + action["args"][1][2:])
        for field in ("authority_contract", "protected_source", "epoch_relation", "sequence",
                      "collection_start", "snapshot_freeze_end"):
            state["collection"][field] = opened[field]


def _evaluation(model, candidate, oracle, identifier):
    model.add("oracle_assertions")
    state = _initial(model, oracle)
    _check(model, state)
    if identifier not in _STOPS and identifier not in _PASS and identifier != "omit-terminal-temporal-deletion":
        raise ReferenceError("history cost reference trace") from None
    stopping = _STOPS.get(identifier)
    transitions = []
    for index, action in enumerate(candidate["actions"]):
        before = copy.deepcopy(state)
        active_stop = stopping if stopping and stopping[0] == index else None
        _candidate_cost(model, candidate, oracle, state, action, active_stop[1] if active_stop else None)
        canonical = _action(model, action)
        if active_stop:
            effect = active_stop[2]
            if effect == "outage":
                state["high_water"]["status"] = "unavailable"
                state["evidence"]["authority_statement_state"] = "unavailable"
                state["ordering"]["in_flight_observation_ref"] = None
            elif effect == "claim":
                state["appraisal"].update(claim_state="rejected", rejected_claim_meaning=action["args"][1], policy_state="not-appraised")
            elif effect == "policy":
                state["appraisal"]["policy_state"] = "rejected"
            else:
                _effect(model, state, effect, {}, {})
            _check(model, state)
            return
        _success_projection(model, oracle, state, canonical, candidate)
        _check(model, state)
        transitions.append((before, copy.deepcopy(state), canonical))
    if identifier == "omit-terminal-temporal-deletion":
        return
    # Completion rebuilds one independent trusted replay. Its state schema is
    # checked at initialization and after every action; guard rules are ordered.
    trusted = _initial(model, oracle)
    _check(model, trusted)
    for action in oracle["actions"]:
        model.add("history_actions")
        rule, args, bindings = _bindings(model, oracle, trusted, action, charge=True)
        for guard in rule["guards"]:
            _guard_cost(model, oracle, trusted, args, bindings, guard)
        if "advance-high-water" in rule["success_effect"]:
            _numbers(model, (trusted["ordering"]["compare_generation"], trusted["ordering"]["compare_generation"] + 1))
        _success_projection(model, oracle, trusted, action)
        _check(model, trusted)
    model.add("oracle_assertions")  # transition array comparison container
    for index, (before, after, action) in enumerate(transitions):
        model.equal(index, index)
        model.equal(action, action)
        model.equal("Conform", "Conform")
        model.equal(before, before, "lifecycle_state_field_comparisons")
        model.equal(after, after, "lifecycle_state_field_comparisons")
    model.equal(state, state, "lifecycle_state_field_comparisons")


def history_normal_cost(model, value, case):
    """Add semantic cost to a model already charged for decode and shape."""
    candidate, oracle = value["candidate"], value["oracle"]
    if case.checkpoint in {"layer-2", "layer-3"}:
        return
    if not _reconstruction(model, candidate, oracle):
        return
    if not _coverage(model, candidate, oracle):
        return
    _evaluation(model, candidate, oracle, case.transform)


def history_focused_vector(authority, identifier, layer, *, checked=False):
    """Predict raw or result-checked invocation with fresh prerequisites."""
    try:
        if layer not in {4, 5, 6}:
            raise ReferenceError("history cost reference layer")
        transform = _pick(authority.histories["negative_transforms"], identifier)
        baseline = _pick(authority.histories["baselines"], transform["baseline"])
        changed = transformed(baseline, transform)
        model = CostModel(authority)
        _reconstruction(model, changed["candidate"] if layer == 4 else baseline["candidate"], baseline["oracle"])
        if layer >= 5:
            model.add("oracle_assertions")  # baseline reconstruction assertion
            _coverage(model, changed["candidate"] if layer == 5 else baseline["candidate"], baseline["oracle"])
        if layer == 6:
            model.add("oracle_assertions")  # baseline coverage assertion
            _evaluation(model, changed["candidate"], baseline["oracle"], identifier)
        if checked:
            model.add("oracle_assertions")  # result versus admitted focused row
        return model.vector
    except (KeyError, IndexError, StopIteration, TypeError, ValueError):
        raise ReferenceError("history cost reference input") from None
