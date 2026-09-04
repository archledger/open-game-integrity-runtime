"""Independent implementation-cost algebra for admitted conformance inputs.

This module never imports the consumer, its counters, or captured execution data.
The accounting contract fixes the units; ordered schemas and literal JSON values
determine their multiplicity.  This is a test reference, not format authority.
"""

from __future__ import annotations

import copy
import json
import math
import re
from pathlib import Path
from types import SimpleNamespace

import bounded_json


class ReferenceError(ValueError):
    """Fixed safe failure for an input outside the reference's modeled domain."""


class CostModel:
    """Accumulate independent cost; every public prediction creates a new model."""

    def __init__(self, authority):
        self.authority = authority
        self.categories = tuple(authority.core["operation_charging"]["category_order"])
        self.counts = dict.fromkeys(self.categories, 0)
        self.schemas = authority.validators["schemas"]
        self.domains = authority.validators["domains"]

    @property
    def vector(self):
        return tuple(self.counts[name] for name in self.categories)

    @property
    def total(self):
        return sum(self.vector)

    def add(self, category, amount=1):
        self.counts[category] += amount

    def equal(self, left, right, category="oracle_assertions", *, claims=False,
              unordered_claims=False):
        """Exact type recursive comparison; first mismatch stops sibling traversal."""
        self.add(category)
        if type(left) is not type(right):
            return False
        if isinstance(left, dict):
            if left.keys() != right.keys():
                return False
            for key in left:
                if not self.equal(left[key], right[key], category,
                                  claims=claims or (unordered_claims and key in {"claims", "expected_claims"}),
                                  unordered_claims=unordered_claims):
                    return False
            return True
        if isinstance(left, list):
            if len(left) != len(right):
                return False
            if claims:
                left = sorted(left, key=lambda item: item["meaning"])
                right = sorted(right, key=lambda item: item["meaning"])
            return all(self.equal(a, b, category, unordered_claims=unordered_claims)
                       for a, b in zip(left, right))
        return left == right

    def domain(self, value, name):
        self.add("schema_assertions")
        rule = self.domains[name]
        if "domain" in rule:
            return self.domain(value, rule["domain"])
        if rule.get("json_type") == "integer-not-boolean":
            return (type(value) is int and value in rule.get("values", [value])
                    and rule.get("minimum", value) <= value <= rule.get("maximum", value))
        if rule.get("json_type") != "string" or not isinstance(value, str):
            return False
        if not value.isascii() or value not in rule.get("values", [value]):
            return False
        if not rule.get("min_bytes", 0) <= len(value) <= rule.get("max_bytes", len(value)):
            return False
        if "ascii_pattern" in rule and re.fullmatch(rule["ascii_pattern"], value) is None:
            return False
        if name == "FixturePath":
            for component in value.split(rule["separator"]):
                if (component in rule["forbidden_components"]
                        or len(component) > rule["component_max_bytes"]
                        or re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", component) is None):
                    return False
        return True

    def typed(self, value, form):
        self.add("schema_assertions")
        if "const" in form and value != form["const"]:
            return False
        for selector in ("domain", "ref", "union"):
            if selector not in form:
                continue
            if selector == "domain":
                return self.domain(value, form[selector])
            if selector == "ref":
                return self.typed(value, self.schemas[form[selector]])
            return any(self.typed(value, member) for member in form[selector])
        kind = form["type"]
        primitives = {"boolean": {bool}, "null": {type(None)}, "string": {str},
                      "json-scalar": {type(None), bool, int, float, str},
                      "json-value": {type(None), bool, int, float, str, list, dict}}
        if kind in primitives:
            return type(value) in primitives[kind]
        if kind == "object":
            if not isinstance(value, dict) or set(value) != set(form["required"]):
                return False
            return all(self.typed(value[name], child) for name, child in form["properties"].items())
        if kind in {"array", "tuple"}:
            if not isinstance(value, list) or not form["min_items"] <= len(value) <= form["max_items"]:
                return False
            children = form["items"] if kind == "tuple" else [form["items"]] * len(value)
            if len(children) != len(value):
                return False
            if not all(self.typed(item, child) for item, child in zip(value, children)):
                return False
            if "unique_by" in form:
                keys = [item[0] if isinstance(item, list) else item[form["unique_by"]] for item in value]
                if len(set(keys)) != len(keys):
                    return False
            if form.get("unique_items"):
                encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
                if len(set(encoded)) != len(encoded):
                    return False
            return True
        return False

    def decode(self, raw, limits):
        """Model decoder rejection before visits, then bounded preorder traversal.

        A None result denotes rejection (corpus roots are objects). Resource
        checks count the failing node. Keys never contribute value visits.
        """
        def reject(*_):
            raise ReferenceError("reference decoding rejected")

        def pairs(items):
            if len(items) > limits["object_fields"] or len(dict(items)) != len(items):
                reject()
            return dict(items)

        def number(token):
            if len(token) > limits["number_token_characters"]:
                reject()
            result = float(token) if any(mark in token for mark in ".eE") else int(token)
            if isinstance(result, float) and not math.isfinite(result):
                reject()
            return result

        if len(raw) > limits["bytes"]:
            return None
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                               parse_int=number, parse_float=number, parse_constant=reject)
        except (ValueError, UnicodeError, RecursionError):
            return None
        pending = [(value, 1)]
        visits = 0
        while pending:
            node, depth = pending.pop()
            self.add("decoded_node_visits")
            visits += 1
            if visits > limits["total_nodes"] or depth > limits["depth"]:
                return None
            if isinstance(node, dict):
                if len(node) > limits["object_fields"] or any(len(key) > limits["object_key_characters"] for key in node):
                    return None
                pending.extend((child, depth + 1) for child in reversed(list(node.values())))
            elif isinstance(node, list):
                if len(node) > limits["array_items"]:
                    return None
                pending.extend((child, depth + 1) for child in reversed(node))
            elif isinstance(node, str) and len(node) > limits["string_characters"]:
                return None
        return value

    def admission(self, value, selected_transforms=None):
        """Admission's charged schema predicate after its fixed envelope gate."""
        if (not isinstance(value, dict)
                or set(value) != {"format_version", "counts", "fixtures", "validator_cases", "coverage"}
                or type(value["format_version"]) is not int or value["format_version"] != 1
                or not isinstance(value["counts"], dict) or not isinstance(value["fixtures"], list)
                or not isinstance(value["validator_cases"], list) or not isinstance(value["coverage"], dict)):
            return False
        if not self.typed(value, self.schemas["Manifest"]):
            return False
        paths = self.authority.core["paths"]
        fixture_paths = [row[2] for row in value["fixtures"]]
        if len(set(fixture_paths)) != len(fixture_paths):
            return False
        for row in value["fixtures"]:
            prefix = paths["snapshot_prefix"] if row[1] == "snapshot" else paths["history_prefix"]
            if not row[2].startswith(prefix) or not row[2].endswith(paths["fixture_suffix"]):
                return False
        canonical = self.authority.validators["validator_baselines"]["baseline-corpus-v1"]["ast"]["value"]
        maps = []
        for field in ("fixtures", "validator_cases"):
            supplied = {row[0]: row for row in value[field]}
            expected = {row[0]: row for row in canonical[field]}
            if not self.equal(supplied, expected):
                return False
            maps.append(supplied)
        executable = self.authority.executable_transforms
        if not self.equal(executable if selected_transforms is None else selected_transforms, executable):
            return False
        registered = set(maps[0]) | set(maps[1])
        if len(registered) != len(maps[0]) + len(maps[1]):
            return False
        mapped = {identifier for identifiers in value["coverage"].values() for identifier in identifiers}
        if mapped != registered:
            return False
        return self.equal(value["coverage"], canonical["coverage"])

    def shape(self, value):
        """Envelope plus kind-selected predicates; uncharged semantic gates follow."""
        form = self.schemas["FixtureEnvelope"]
        if not self.typed(value, form):
            return False
        kinds = self.domains[form["properties"]["kind"]["domain"]]["values"]
        index = kinds.index(value["kind"])
        for field in ("candidate", "oracle"):
            if not self.typed(value[field], form["properties"][field]["union"][index]):
                return False
        return True


def predict_admission(authority, raw, selected_transforms=None):
    model = CostModel(authority)
    value = model.decode(raw, authority.core["resource_limits"]["manifest"])
    if value is not None:
        model.admission(value, selected_transforms)
    return model.vector


def snapshot_reconstruction(model, candidate, oracle):
    """Cost the ordered independent input checks and project trusted coverage data."""
    model.add("oracle_assertions")
    transcript = candidate["transcript"]
    challenge, context, key = (oracle[name] for name in
                               ("authenticated_challenge", "expected_context", "resolved_key"))
    comparisons = [(challenge[name], context[name])
                   for name in ("publisher", "game", "build", "account", "match", "policy")]
    comparisons.extend((key[name], context[name])
                       for name in ("publisher", "protected_session", "live_subject"))
    comparisons.append((transcript["challenge"], challenge))
    comparisons.extend((transcript[name], key[name])
                       for name in ("actual_public_key", "session_public_key_id"))
    association = {name: key[name] for name in ("publisher", "protected_session", "live_subject")}
    comparisons.append((transcript["key_association"], association))
    if not all(model.equal(left, right) for left, right in comparisons):
        return None
    expected = {claim["meaning"]: claim for claim in oracle["expected_claims"]}
    supplied = {claim["meaning"]: claim for claim in transcript["claims"]}
    if expected.keys() != supplied.keys():
        return None
    for name, claim in expected.items():
        if not model.equal(supplied[name], claim, "claim_comparisons"):
            # Failed session-identity entries also compare the typed value to
            # distinguish association inequality from provenance inequality.
            if name == model.domains["ClaimMeaning"]["values"][6]:
                model.equal(supplied[name]["value"], claim["value"], "claim_comparisons")
            return None
    profile, timing = oracle["registered_profile"], oracle["expected_evidence_time"]
    if not model.equal(transcript["profile"], profile["id"]):
        return None
    if not model.equal(transcript["evidence_time"], timing):
        return None
    provenance = {row["meaning"]: row["provenance"] for row in profile["claim_provenance"]}
    if expected.keys() != provenance.keys():
        return None
    if not all(model.equal(claim["provenance"], provenance[name], "claim_comparisons")
               for name, claim in expected.items()):
        return None
    if profile["authority_contract"] != timing["authority_contract"]:
        return None
    duration = timing["snapshot_freeze_end"] - timing["collection_start"]
    if not 0 <= duration <= profile["duration_ceiling"]:
        return None
    prior = oracle["prior_temporal_state"]
    if prior is not None and (prior["authority_contract"] != profile["authority_contract"]
                              or prior["epoch_relation"] != timing["epoch_relation"]
                              or timing["sequence"] <= prior["greatest_sequence"]
                              or timing["collection_start"] < prior["latest_freeze_end"]):
        return None
    purpose = next(iter(model.authority.baselines.values()))["candidate"]["transcript"]["purpose"]
    if not model.equal(transcript["purpose"], purpose):
        return None
    stimulus = transcript["test_only_semantic"]
    if stimulus is not None and stimulus["name"] != "current-live-process":
        name, replacement = stimulus["name"], stimulus["replacement"]
        if replacement.get("kind") != "scalar" or "token" not in replacement:
            return None
        compared = None
        if name.startswith("expected-"):
            field = name.removeprefix("expected-").replace("-", "_")
            if field in context:
                compared = context[field]["id"] if field == "policy" else context[field]
        elif name.startswith("same-key-new-"):
            field = name.removeprefix("same-key-new-").replace("-", "_")
            keys = [item for item in key if item == field or item.endswith("_" + field)]
            if len(keys) == 1:
                compared = key[keys[0]]
        elif name == "same-key-without-fresh-challenge":
            compared = challenge["nonce"]
        if compared is None or not model.equal(replacement["token"], compared):
            return None
    return {"challenge": challenge, "profile": profile["id"],
            "actual_public_key": key["actual_public_key"],
            "session_public_key_id": key["session_public_key_id"],
            "key_association": association, "evidence_time": timing,
            "purpose": purpose,
            "claims": [expected[name] for name in profile["required_claim_meanings"]]}


def snapshot_coverage(model, supplied, rebuilt):
    model.add("oracle_assertions")
    entries = []

    def entry(name, value, relationships):
        entries.append({"component": name, "value": value, "relationships": relationships})

    def leaves(value, schema_name, prefix):
        schema = model.schemas[schema_name]
        for field in schema["required"]:
            name = prefix + "-" + field.replace("_", "-")
            child = schema["properties"][field].get("ref")
            if child is not None and model.schemas[child].get("type") == "object":
                yield from leaves(value[field], child, name)
            else:
                yield name, value[field]

    for name, value in leaves(rebuilt["challenge"], "Challenge", "challenge"):
        entry(name, value, ["exact-value"])
    entry("evidence-profile", rebuilt["profile"], ["exact-value"])
    for name, field in (("actual-session-public-key", "actual_public_key"),
                        ("session-public-key-id", "session_public_key_id")):
        entry(name, rebuilt[field], ["exact-value", "exact-association"])
    entry("key-association", rebuilt["key_association"], ["exact-association"])
    for name, value in leaves(rebuilt["evidence_time"], "EvidenceTime", "evidence"):
        entry(name, value, ["exact-time"])
    entry("evidence-purpose", rebuilt["purpose"], ["exact-purpose"])
    for claim in rebuilt["claims"]:
        relationships = ["exact-value", "exact-provenance"]
        if claim["value"]["kind"] == "semantic-identity":
            relationships.append("exact-identity-part")
        if claim["meaning"] in {"process-binding-identity", "protected-session-identity",
                                 "enforcement-policy-state", "attestation-identity"}:
            relationships.append("exact-association")
        entry("claim-" + claim["meaning"], claim, relationships)
    return model.equal(supplied, entries, "coverage_entry_comparisons")


def snapshot_appraisal(model, candidate, oracle, rebuilt):
    model.add("oracle_assertions")
    appraisal = oracle["appraisal"]
    claims = {row["meaning"]: row for row in rebuilt["claims"]}
    values = {row["meaning"]: row["value"] for row in appraisal["acceptable_claim_values"]}
    provenance = {row["meaning"]: row["provenance"] for row in appraisal["acceptable_provenance"]}
    if claims.keys() != values.keys() or claims.keys() != provenance.keys():
        return
    for name, claim in claims.items():
        if not model.equal(claim["value"], values[name], "claim_comparisons"):
            return
        if not model.equal(claim["provenance"], provenance[name], "claim_comparisons"):
            return
    if rebuilt["key_association"]["live_subject"] != appraisal["current_live_subject"]:
        return
    stimulus = candidate["transcript"]["test_only_semantic"]
    if stimulus is not None and stimulus["name"] == "current-live-process":
        accepted = values.get("process-binding-identity")
        if accepted is not None:
            model.equal(stimulus["replacement"], accepted)


def predict_snapshot(authority, raw, case):
    """Expected earliest-stop vector for one exact admitted snapshot document."""
    model = CostModel(authority)
    value = model.decode(raw, authority.core["resource_limits"]["fixture"])
    if value is None:
        model.add("oracle_assertions")  # reject bytes unlike the registered early transform
        model.add("oracle_assertions")  # final actual-versus-manifest result assertion
        return model.vector
    model.add("oracle_assertions")  # containing reproduction assertion predicate
    model.equal(value, value, unordered_claims=case.checkpoint != "layer-3")
    model.shape(value)
    if case.checkpoint in {"layer-2", "layer-3"}:
        model.add("oracle_assertions")
        return model.vector
    rebuilt = snapshot_reconstruction(model, value["candidate"], value["oracle"])
    if rebuilt is None:
        model.add("oracle_assertions")
        return model.vector
    if snapshot_coverage(model, value["candidate"]["coverage"], rebuilt):
        snapshot_appraisal(model, value["candidate"], value["oracle"], rebuilt)
    model.add("oracle_assertions")
    return model.vector


def snapshot_focused_vector(authority, identifier, layer, *, checked=False):
    model = CostModel(authority)
    case = next(row for row in authority.snapshot_cases if row.identifier == identifier)
    baseline = authority.baselines[case.baseline]
    changed = transformed(baseline, authority.transforms[case.transform])
    selected = changed if layer == 4 else baseline
    rebuilt = snapshot_reconstruction(model, selected["candidate"], selected["oracle"])
    if layer >= 5:
        model.add("oracle_assertions")  # reconstructed baseline prerequisite
        coverage = changed if layer == 5 else baseline
        snapshot_coverage(model, coverage["candidate"]["coverage"], rebuilt)
    if layer == 6:
        model.add("oracle_assertions")  # baseline coverage prerequisite
        snapshot_appraisal(model, changed["candidate"], changed["oracle"], rebuilt)
    if checked:
        model.add("oracle_assertions")  # result-versus-admitted-focused-row predicate
    return model.vector


def predict_history(authority, raw, case):
    from conformance_history_cost_reference import history_normal_cost

    model = CostModel(authority)
    value = model.decode(raw, authority.core["resource_limits"]["fixture"])
    if value is not None:
        model.add("oracle_assertions")  # containing reproduction assertion predicate
        model.equal(value, value)
        model.shape(value)
        history_normal_cost(model, value, case)
    model.add("oracle_assertions")  # final actual-versus-manifest result assertion
    return model.vector


def predict_corpus(authority, snapshots, root):
    """Admission and all normal vectors; aggregate sums fresh case scopes."""
    relative_manifest = authority.core["paths"]["corpus_manifest"]
    raw = _reference_bytes(root, relative_manifest, authority.core["resource_limits"]["manifest"]["bytes"])
    model = CostModel(authority)
    manifest = model.decode(raw, authority.core["resource_limits"]["manifest"])
    if manifest is None or not model.admission(manifest):
        raise ReferenceError("reference manifest rejected") from None
    admission = model.vector
    corpus = Path(relative_manifest).parent
    fields = ("identifier", "kind", "path", "baseline", "transform", "checkpoint", "disposition")
    vectors = {}
    for row in manifest["fixtures"]:
        case = SimpleNamespace(**dict(zip(fields, row, strict=True)))
        raw = _reference_bytes(root, str(corpus / case.path),
                               authority.core["resource_limits"]["fixture"]["bytes"])
        function, selected = ((predict_snapshot, snapshots) if case.kind == "snapshot"
                              else (predict_history, authority))
        vectors[case.identifier] = function(selected, raw, case)
    total = sum(admission) + sum(sum(vector) for vector in vectors.values())
    return admission, vectors, total


def _reference_bytes(root, relative, maximum):
    try:
        return bounded_json.read_bounded_bytes(Path(root), relative, maximum,
                                               "abstract-conformance:internal:internal-failure")
    except bounded_json.BoundedJsonError:
        raise ReferenceError("reference physical input rejected") from None


def transformed(baseline, transform):
    """Apply admitted structural one-change data without consumer helpers."""
    value = copy.deepcopy(baseline)
    pointer = transform.get("pointer") or transform["path"]
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/")[1:]]
    parent = value
    for part in parts[:-1]:
        parent = parent[int(part)] if isinstance(parent, list) else parent[part]
    key = int(parts[-1]) if isinstance(parent, list) else parts[-1]
    operation = transform["operation"]
    replacement = transform.get("new", transform.get("value"))
    if isinstance(replacement, dict) and "type" in replacement:
        replacement = replacement["value"]
    if operation == "insert":
        parent[key].insert(transform["index"], copy.deepcopy(replacement))
    elif operation == "remove":
        del parent[key]
    elif operation == "add" and isinstance(parent, list):
        parent.insert(key, copy.deepcopy(replacement))
    elif operation in {"replace", "add"}:
        parent[key] = copy.deepcopy(replacement)
    else:
        raise ReferenceError("unsupported reference transform")
    return value
