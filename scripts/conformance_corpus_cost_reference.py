"""Independent cost inputs for admitted corpus-mutation cases.

Recipes are interpreted from trusted planning data without importing the consumer.
Only the manifest and executable selection affect charged admission operations;
fixture filesystem mutations occur after those operations in the inventory gate.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import json

from conformance_accounting_reference import predict_admission


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _at(value, pointer):
    for part in pointer.split("/")[1:]:
        key = part.replace("~1", "/").replace("~0", "~")
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


@dataclass
class _Source:
    raw: bytes | None
    transforms: dict


def _source(authority, value):
    if isinstance(value, _Source):
        return value
    canonical = authority.validators["validator_baselines"]["baseline-corpus-v1"]["ast"]["value"]
    selected = authority.executable_transforms
    if isinstance(value, dict) and all(v == {"registered": True} for v in value.values()):
        selected = {key: selected[key] for key in value}
        value = canonical
    return _Source(value if isinstance(value, bytes) else _encode(value), selected)


def _generated(authority, node):
    p = node["parameters"]
    kind = node["constructor"]
    if kind == "invalid-utf8-document":
        return p["prefix"].encode("ascii") + bytes.fromhex(p["invalid_byte_hex"]) + p["suffix"].encode("ascii")
    if kind == "json-number-document":
        return p["token"].encode("ascii")
    limits = authority.core["resource_limits"][p["scope"]]
    if kind == "number-token-boundary":
        length = limits["number_token_characters"] + int(p["relation"] == "over")
        prefix = p.get("prefix", "")
        return (prefix + p.get("digit", "1") * (length - len(prefix))).encode("ascii")
    if kind != "resource-boundary":
        raise ValueError("unknown reference constructor")
    dimension = p["dimension"]
    size = limits[dimension] + int(p["relation"] == "over")
    if dimension == "bytes":
        return b" " * (size - 2) + b"{}"
    if dimension == "depth":
        return ("[" * (size - 1) + "null" + "]" * (size - 1)).encode("ascii")
    if dimension == "object_fields":
        return _encode({f"k{i}": None for i in range(size)})
    if dimension == "array_items":
        return _encode([None] * size)
    if dimension == "string_characters":
        return _encode("x" * size)
    if dimension == "object_key_characters":
        return _encode({"k" * size: None})
    if dimension == "total_nodes":
        full, remainder = divmod(size - 1, limits["array_items"] + 1)
        groups = [[None] * limits["array_items"] for _ in range(full)]
        if remainder:
            groups.append([None] * (remainder - 1) if remainder > 1 else None)
        return _encode(groups)
    raise ValueError("unknown reference resource")


def corpus_source(authority, node):
    """Resolve an admitted recipe without touching the filesystem or counters."""
    operation = node["node"]
    if operation in {"sequence", "probe"}:
        return corpus_source(authority, node["steps"][-1] if operation == "sequence" else node["input"])
    if operation == "ref":
        if node["subject"] == "baseline":
            value = authority.validators["validator_baselines"][node["id"]]["ast"]["value"]
        else:
            value = {key: {"registered": True} for key in authority.executable_transforms}
        return copy.deepcopy(_at(value, node["pointer"]) if "pointer" in node else value)
    if operation == "literal":
        return copy.deepcopy(node["value"])
    if operation == "generate":
        return _generated(authority, node)
    value = corpus_source(authority, node["input"])
    if operation.startswith("fs-"):
        source = _source(authority, value)
        manifest = authority.core["paths"]["corpus_manifest"]
        path = node.get("relative_path", node.get("old_relative_path"))
        if manifest == path or manifest.startswith(path + "/"):
            source.raw = None
            if operation == "fs-create" and node["kind"] == "regular-file" and path == manifest:
                source.raw = node["contents"].encode("utf-8")
        return source
    if operation.startswith("bytes-"):
        raw = value if isinstance(value, bytes) else _encode(value)
        if operation == "bytes-append":
            return raw + node["bytes"].encode("utf-8")
        return raw.replace(node["old_ascii"].encode("ascii"), node["new_ascii"].encode("ascii"))
    pointer = node["pointer"]
    if operation == "append":
        _at(value, pointer).append(copy.deepcopy(node["value"]))
        return value
    parent_pointer, _, key = pointer.rpartition("/")
    parent = _at(value, parent_pointer)
    key = key.replace("~1", "/").replace("~0", "~")
    key = int(key) if isinstance(parent, list) else key
    if operation == "remove":
        del parent[key]
    elif operation == "set":
        parent[key] = copy.deepcopy(node["value"])
    else:
        raise ValueError("unknown reference recipe")
    return value


def corpus_case_vector(authority, case, *, dispatched=False):
    """Sum fresh canonical and changed admission work inside one corpus case."""
    baseline = authority.validators["validator_baselines"]["baseline-corpus-v1"]["ast"]["value"]
    canonical = predict_admission(authority, _encode(baseline))
    recipe = authority.corpus_transforms[case.identifier]["ast"]
    changed = _source(authority, corpus_source(authority, recipe))
    other = ((0,) * len(canonical) if changed.raw is None else
             predict_admission(authority, changed.raw, selected_transforms=changed.transforms))
    result = [a + b for a, b in zip(canonical, other, strict=True)]
    # Every case checks its outcome. A registered malformed case first asserts
    # the fixed loader diagnostic; public dispatch also checks the case tuple.
    oracle = authority.core["operation_charging"]["category_order"].index("oracle_assertions")
    result[oracle] += 1 + int(case.disposition == "Malformed") + int(dispatched)
    return tuple(result)
