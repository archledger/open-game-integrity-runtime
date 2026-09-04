"""Independent cost predictions for registered loader and parity adapters.

Only admitted recipes and the documented assertion units supply expected counts;
this module never imports a consumer, its recorded counters, or a test adapter.
"""
from __future__ import annotations

import copy

from conformance_accounting_reference import CostModel
from conformance_corpus_cost_reference import _generated


def _bytes(authority, node):
    kind = node["node"]
    if kind.startswith("fs-"):
        # Every admitted loader filesystem transform fails before decoding:
        # missing/nonregular/link/escaped final path or linked approved root.
        return None
    if kind == "ref":
        baseline = authority.validators["validator_baselines"][node["id"]]["ast"]["value"]
        return baseline["bytes_utf8"].encode("utf-8")
    if kind == "bytes-append":
        return _bytes(authority, node["input"]) + node["bytes"].encode("utf-8")
    if kind == "bytes-replace":
        return _bytes(authority, node["input"]).replace(
            node["old_ascii"].encode("ascii"), node["new_ascii"].encode("ascii"))
    if kind == "generate":
        parameters = node["parameters"]
        if parameters.get("numeric_kind") in {"integer", "float"}:
            return parameters["token"].encode("ascii")
        normalized = copy.deepcopy(node)
        if normalized["parameters"].get("prefix") is None and "prefix" in normalized["parameters"]:
            normalized["parameters"]["prefix"] = ""
        return _generated(authority, normalized)
    raise ValueError("unmodeled loader reference recipe")


def nonfile_case_vector(authority, case):
    model = CostModel(authority)
    # Registered dispatcher compares the selected immutable tuple once.
    model.add("oracle_assertions")
    transform = authority.validators["validator_transforms"][case.transform]["ast"]
    if case.operation == "loader-probe":
        probe = transform["steps"][-1]
        if probe["adapter"] != "bounded-json-diagnostic":
            raw = _bytes(authority, probe["input"])
            if raw is not None:
                model.decode(raw, authority.core["resource_limits"]["fixture"])
        # Exactly one returned-value/rejection/diagnostic equality predicate.
        model.add("oracle_assertions")
    elif case.operation == "attack-loader-parity":
        probe = transform["steps"][1]["input"]
        expected = authority.validators["attack_parity_expectations"]["by_case_id"].get(case.identifier, {})
        # Legacy checker internals retain no conformance budget. Its captured
        # output crosses two mandatory wrapper assertion predicates.
        model.add("oracle_assertions", 2)
        if probe["entrypoint"] == "cli":
            model.add("oracle_assertions", int("stdout_final_line" in expected))
        else:
            model.add("oracle_assertions", int("expected_message" in expected))
            model.add("oracle_assertions", int(bool(expected.get("redaction_required"))))
    else:
        raise ValueError("unmodeled nonfile reference case")
    return model.vector
