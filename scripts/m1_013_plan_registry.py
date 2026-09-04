"""Fail-closed validator for the sharded M1-013 planning registry."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REGISTRY = (
    ROOT / "docs/superpowers/plans/2026-09-02-m1-013-format-v1-registry.json"
)
BOOTSTRAP_LIMITS = {
    "bytes_per_file": 524288,
    "depth": 16,
    "object_fields": 512,
    "array_items": 512,
    "string_characters": 4096,
    "object_key_characters": 4096,
    "number_token_characters": 64,
    "total_nodes_per_file": 32768,
    "shard_files": 4,
}
SHARDS = (
    ("core", "docs/superpowers/plans/m1-013-format-v1/core.json"),
    ("snapshots", "docs/superpowers/plans/m1-013-format-v1/snapshots.json"),
    ("histories", "docs/superpowers/plans/m1-013-format-v1/histories.json"),
    ("validators", "docs/superpowers/plans/m1-013-format-v1/validators.json"),
)
COUNTS = {
    "snapshots": 69,
    "histories": 55,
    "fixtures": 124,
    "validator_cases": 202,
    "focused_rows": 98,
    "focused_invocations": 294,
    "history_actions": 14,
}
CATEGORIES = [
    "decoded_node_visits",
    "schema_assertions",
    "claim_comparisons",
    "coverage_entry_comparisons",
    "history_actions",
    "lifecycle_state_field_comparisons",
    "oracle_assertions",
]
ID_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
ABSENT = object()
DISPOSITIONS = {
    "Conform", "Malformed", "Unsupported", "ContextBindingMismatch",
    "EvidenceInvalid", "Expired", "AttestationUnavailable",
    "ProtectedSessionLost", "PolicyDenied",
}
CHECKPOINTS = {
    "layer-1", "layer-2", "layer-3", "layer-4", "layer-5", "layer-6",
    "layer-6-success", "attack-parity", "internal",
}
VALIDATOR_OPERATIONS = {"corpus-mutation", "loader-probe", "attack-loader-parity"}
REQUIREMENT_TAGS = {
    "requirement-positive-reconstruction", "requirement-transcript-single-change",
    "requirement-shape-domain", "requirement-evidence-time",
    "requirement-parser-resource", "requirement-manifest-inventory",
    "requirement-diagnostic-redaction", "requirement-attack-loader-parity",
    "requirement-focused-oracles", "requirement-claim-order",
}
RESOURCE_LIMITS = {
    "dimensions": [
        "bytes", "depth", "object_fields", "array_items", "string_characters",
        "object_key_characters", "number_token_characters", "total_nodes",
    ],
    "fixture": {
        "bytes": 65536, "depth": 16, "object_fields": 64, "array_items": 256,
        "string_characters": 4096, "object_key_characters": 4096,
        "number_token_characters": 64, "total_nodes": 4096,
    },
    "manifest": {
        "bytes": 524288, "depth": 16, "object_fields": 512, "array_items": 512,
        "string_characters": 4096, "object_key_characters": 4096,
        "number_token_characters": 64, "total_nodes": 32768,
    },
    "wall_clock_seconds": 30,
    "max_fixture_files": 128,
}
RESOURCE_CONSTRUCTORS = {
    "closed": True,
    "id_pattern": (
        "(?:fixture|manifest)-(?:bytes|depth|object-fields|array-items|"
        "string-characters|object-key-characters|number-token-characters|"
        "total-nodes)-(?:exact|over)"
    ),
    "scopes": ["fixture", "manifest"],
    "relations": {
        "exact": {
            "value_rule": "equal-to-selected-scope-dimension-limit",
            "expected_disposition": "Conform",
        },
        "over": {
            "value_rule": "selected-scope-dimension-limit-plus-one",
            "expected_disposition": "Malformed",
        },
    },
    "constructor_opcode": "resource-boundary",
    "all_scope_dimension_relation_products_required": True,
    "validator_case_per_product_required": False,
    "product_admission_rule": (
        "All 32 scope x dimension x relation products must be constructible and "
        "validated by the planning checker; validator cases consume only admitted "
        "products and are not in one-to-one correspondence with those products."
    ),
    "constructor_ids_globally_unique": True,
    "unqualified_legacy_ids_forbidden": [
        "bytes_exact", "bytes_over", "depth_exact", "depth_over",
        "fields_exact", "fields_over", "items_exact", "items_over",
        "string_exact", "string_over", "key_exact", "key_over",
        "integer_exact", "integer_over", "float_exact", "float_over",
        "fixture_nodes_exact", "fixture_nodes_over", "manifest_nodes_exact",
        "manifest_nodes_over",
    ],
}
CORE_PATHS = {
    "registry_root": "docs/superpowers/plans/m1-013-format-v1/",
    "core": "docs/superpowers/plans/m1-013-format-v1/core.json",
    "corpus_manifest": "lab/conformance/corpus.json",
    "snapshot_prefix": "snapshots/", "history_prefix": "histories/",
    "fixture_suffix": ".json",
    "baseline_module": "scripts/abstract_conformance_registry.py",
    "loader_module": "scripts/bounded_json.py",
    "validator_module": "scripts/abstract_conformance.py",
    "validator_cli": "scripts/check-abstract-conformance.py",
}
CORE_DIAGNOSTICS = {
    "closed_pairs": [
        ["layer-1", "malformed"],
        ["layer-2", "malformed"],
        ["layer-3", "malformed"],
        ["layer-3", "unsupported"],
        ["layer-4", "context-binding-mismatch"],
        ["layer-4", "evidence-invalid"],
        ["layer-5", "evidence-invalid"],
        ["layer-6", "evidence-invalid"],
        ["layer-6", "expired"],
        ["layer-6", "attestation-unavailable"],
        ["layer-6", "protected-session-lost"],
        ["layer-6", "policy-denied"],
        ["attack-parity", "malformed"],
        ["internal", "internal-failure"],
        ["internal", "operation-budget-exhausted"],
    ],
    "unknown_pairs_forbidden": True,
    "rendered_pairs_only": True,
    "line_column_for_conformance": False,
    "candidate_labels_allowed": False,
    "absolute_paths_allowed": False,
    "raw_candidate_values_allowed": False,
    "control_characters_allowed": False,
    "ci_command_fragments_allowed": False,
    "tracebacks_allowed": False,
}
PLANNING_CONSTRAINTS = {
    "fixture_data_synthetic_only": True,
    "real_biometrics_forbidden": True,
    "real_attestation_identities_forbidden": True,
    "private_keys_forbidden": True,
    "runtime_type_selected": False,
    "production_parser_selected": False,
    "production_schema_selected": False,
    "wire_representation_selected": False,
    "canonical_encoding_selected": False,
    "cryptographic_mechanism_selected": False,
    "tpm_mapping_selected": False,
    "persistence_mechanism_selected": False,
    "production_resource_limits_selected": False,
    "passing_checker_authorizes_implementation": False,
}
ACTION_ARITIES = {
    "collection-open": 2,
    "snapshot-freeze": 2,
    "drop": 1,
    "submit": 2,
    "validate": 1,
    "claim-rejection": 2,
    "policy-rejection": 0,
    "renewal": 2,
    "concurrent-submit": 2,
    "outage": 2,
    "rollback": 1,
    "restart": 1,
    "terminal-end": 1,
    "deletion": 0,
}
SOURCE_BINDINGS = {
    "attack_checker": {
        "path": "scripts/check-attack-scenario-traceability.py",
        "sha256": "fce127c01273733bd7c6b0306e1e041a13fad855e3e62268e08c39d9979f076f",
        "git_blob": "6826adbd98dccdfc109b3bba2e46f266aa72bc25",
    },
    "attack_schema": {
        "path": "lab/scenarios/schema.json",
        "sha256": "0791cea36aa3767469b84192223a5e2af4743cb9173fc0e8aa34c268149a853e",
        "git_blob": "0d111f30da2c4db090d1e035dec57d96835ed6df",
    },
}
# This pins the reviewed root-index bytes after all specific semantic checks run;
# it is a final trust anchor, not a duplicate semantic registry.
CANONICAL_ROOT_SHA256 = "f1e10e933681e6ea86fc34172e7a6560c011479b8ba2b4e69c5205cc069f6d9e"
COMPARISON_RULES_SHA256 = "078c5b4b67bc8d1294f112621f3bbf6679df032b59b67e2515b882aa93e2869c"
HISTORY_SEMANTICS_SHA256 = "646cc2cae678a71054f4c32229cc1ee3e0ec645c8c8faa89a7a975693f509760"
HISTORY_FOCUSED_SHA256 = "fd34880c69621f64da6b264d11d9a91d68e11056511d40c266cf78dbf4e307c0"
VALIDATOR_OUTCOMES_SHA256 = "67aab07dfefd5e588c8f9fd53dcfbb6bc0ec3de58cc6ad250a5cfcaad75de4d5"


class RegistryError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class RegistrySummary:
    snapshots: int
    histories: int
    validator_cases: int
    focused_invocations: int


def _reject(code: str) -> NoReturn:
    raise RegistryError(code)


def _canonical_sha256(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _require_os_capabilities() -> None:
    required_flags = ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC")
    if (
        not callable(getattr(os, "open", None))
        or not callable(getattr(os, "fstat", None))
        or any(
            type(getattr(os, name, None)) is not int or getattr(os, name) == 0
            for name in required_flags
        )
        or os.open not in getattr(os, "supports_dir_fd", ())
    ):
        _reject("internal")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject("json")
        result[key] = value
    return result


def _parse_int(token: str) -> int:
    if len(token) > BOOTSTRAP_LIMITS["number_token_characters"]:
        _reject("resource")
    return int(token)


def _parse_float(token: str) -> float:
    if len(token) > BOOTSTRAP_LIMITS["number_token_characters"]:
        _reject("resource")
    value = float(token)
    if not math.isfinite(value):
        _reject("json")
    return value


def _reject_constant(_value: str) -> NoReturn:
    _reject("json")


def _check_tree(value: Any, depth: int = 1) -> int:
    if depth > BOOTSTRAP_LIMITS["depth"]:
        _reject("resource")
    nodes = 1
    if isinstance(value, dict):
        if len(value) > BOOTSTRAP_LIMITS["object_fields"]:
            _reject("resource")
        for key, child in value.items():
            if len(key) > BOOTSTRAP_LIMITS["object_key_characters"]:
                _reject("resource")
            nodes += _check_tree(child, depth + 1)
    elif isinstance(value, list):
        if len(value) > BOOTSTRAP_LIMITS["array_items"]:
            _reject("resource")
        for child in value:
            nodes += _check_tree(child, depth + 1)
    elif isinstance(value, str):
        if len(value) > BOOTSTRAP_LIMITS["string_characters"]:
            _reject("resource")
    if nodes > BOOTSTRAP_LIMITS["total_nodes_per_file"]:
        _reject("resource")
    return nodes


def _open_directory(path: Path) -> int:
    try:
        return os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise RegistryError("file") from error


def _stable_metadata(state: os.stat_result) -> tuple[int, ...]:
    return (
        state.st_dev, state.st_ino, state.st_mode, state.st_nlink,
        state.st_uid, state.st_gid, state.st_size,
        state.st_mtime_ns, state.st_ctime_ns,
    )


def _read_relative(root_fd: int, relative: str) -> bytes:
    parts = relative.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        _reject("file")
    directory_fd = os.dup(root_fd)
    try:
        directory_flags = (
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        for part in parts[:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode):
                _reject("file")
            if before.st_size > BOOTSTRAP_LIMITS["bytes_per_file"]:
                _reject("resource")
            chunks: list[bytes] = []
            remaining = BOOTSTRAP_LIMITS["bytes_per_file"] + 1
            while remaining:
                chunk = os.read(file_fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(file_fd)
            if len(raw) > BOOTSTRAP_LIMITS["bytes_per_file"]:
                _reject("resource")
            if (
                len(raw) != after.st_size
                or _stable_metadata(before) != _stable_metadata(after)
            ):
                _reject("file")
        finally:
            os.close(file_fd)
    except RegistryError:
        raise
    except OSError as error:
        raise RegistryError("file") from error
    finally:
        os.close(directory_fd)
    return raw


def _load_relative(root_fd: int, relative: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = _read_relative(root_fd, relative)
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_int=_parse_int,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except RegistryError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise RegistryError("json") from error
    if not isinstance(value, dict):
        _reject("json")
    _check_tree(value)
    return value, raw


def _open_relative_directory(root_fd: int, relative: str) -> int:
    directory_fd = os.dup(root_fd)
    try:
        flags = (
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        for part in relative.split("/"):
            if part in {"", ".", ".."}:
                _reject("file")
            next_fd = os.open(part, flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        result = directory_fd
        directory_fd = -1
        return result
    except OSError as error:
        raise RegistryError("file") from error
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)


def _directory_state(directory_fd: int) -> tuple[int, ...]:
    try:
        state = os.fstat(directory_fd)
    except OSError as error:
        raise RegistryError("file") from error
    if not stat.S_ISDIR(state.st_mode):
        _reject("file")
    return _stable_metadata(state)


def _list_directory(directory_fd: int) -> set[str]:
    try:
        return set(os.listdir(directory_fd))
    except OSError as error:
        raise RegistryError("file") from error


def _require_keys(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        _reject(code)
    return value


def _valid_id(identifier: Any) -> bool:
    if not isinstance(identifier, str):
        return False
    try:
        encoded = identifier.encode("ascii")
    except UnicodeEncodeError:
        return False
    return len(encoded) <= 128 and ID_RE.fullmatch(identifier) is not None


def _ids(rows: list[Any], code: str) -> list[str]:
    result: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            _reject(code)
        identifier = row.get("id")
        if not _valid_id(identifier):
            _reject(code)
        assert isinstance(identifier, str)
        result.append(identifier)
    if len(result) != len(set(result)):
        _reject(code)
    return result


def _decode_pointer(pointer: Any) -> list[str]:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        _reject("pointer")
    parts = pointer[1:].split("/")
    result: list[str] = []
    for part in parts:
        if re.search(r"~(?:[^01]|$)", part):
            _reject("pointer")
        result.append(part.replace("~1", "/").replace("~0", "~"))
    return result


def _index(part: str, length: int, *, insert: bool = False) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]*", part):
        _reject("pointer")
    index = int(part)
    maximum = length if insert else length - 1
    if index > maximum:
        _reject("pointer")
    return index


def _select(document: Any, pointer: Any) -> Any:
    value = document
    for part in _decode_pointer(pointer):
        if isinstance(value, dict):
            if part not in value:
                _reject("pointer")
            value = value[part]
        elif isinstance(value, list):
            value = value[_index(part, len(value))]
        else:
            _reject("pointer")
    return value


def _parent(document: Any, pointer: Any) -> tuple[Any, str]:
    parts = _decode_pointer(pointer)
    if not parts:
        _reject("pointer")
    value = document
    for part in parts[:-1]:
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list):
            value = value[_index(part, len(value))]
        else:
            _reject("pointer")
    return value, parts[-1]


def _unwrap_typed(value: Any) -> Any:
    if not isinstance(value, dict) or "type" not in value:
        _reject("snapshot-transform")
    if value == {"type": "absent"}:
        return ABSENT
    if set(value) != {"type", "value"}:
        _reject("snapshot-transform")
    return value["value"]


def _apply_json_operation(
    document: dict[str, Any], operation: str, pointer: Any, old: Any, new: Any
) -> dict[str, Any]:
    result = copy.deepcopy(document)
    parent, part = _parent(result, pointer)
    if operation == "replace":
        current = _select(result, pointer)
        if current != old or old == new:
            _reject("pointer")
        if isinstance(parent, dict):
            parent[part] = copy.deepcopy(new)
        elif isinstance(parent, list):
            parent[_index(part, len(parent))] = copy.deepcopy(new)
        else:
            _reject("pointer")
    elif operation == "remove":
        current = _select(result, pointer)
        if current != old:
            _reject("pointer")
        if isinstance(parent, dict):
            del parent[part]
        elif isinstance(parent, list):
            del parent[_index(part, len(parent))]
        else:
            _reject("pointer")
    elif operation in {"add", "insert"}:
        if not isinstance(parent, list):
            _reject("pointer")
        parent.insert(_index(part, len(parent), insert=True), copy.deepcopy(new))
    else:
        _reject("pointer")
    if result == document:
        _reject("pointer")
    return result


def _validate_resource_constructor_contract(core: dict[str, Any]) -> None:
    contract = core.get("resource_constructors")
    limits = core.get("resource_limits")
    dimensions = RESOURCE_LIMITS["dimensions"]
    if (
        contract != RESOURCE_CONSTRUCTORS
        or not isinstance(limits, dict)
        or limits.get("dimensions") != dimensions
        or set(limits) != {
            "dimensions", "fixture", "manifest", "wall_clock_seconds",
            "max_fixture_files",
        }
        or any(
            not isinstance(limits.get(scope), dict)
            or set(limits[scope]) != set(dimensions)
            for scope in RESOURCE_CONSTRUCTORS["scopes"]
        )
    ):
        _reject("resource-constructor")
    products = [
        (scope, dimension, relation)
        for scope in RESOURCE_CONSTRUCTORS["scopes"]
        for dimension in dimensions
        for relation in RESOURCE_CONSTRUCTORS["relations"]
    ]
    if len(products) != 32:
        _reject("resource-constructor")
    for scope, dimension, relation in products:
        _resource_value(scope, dimension, relation, limits)
        _validate_resource_nodes([{
            "node": "generate",
            "constructor": RESOURCE_CONSTRUCTORS["constructor_opcode"],
            "parameters": {
                "scope": scope, "dimension": dimension, "relation": relation,
            },
        }], core)


def _validate_core(core: dict[str, Any]) -> None:
    expected = {
        "format_version", "registry_kind", "authority", "scope",
        "production_representation", "production_choices_authorized",
        "closed_top_level", "counts", "paths", "shards", "ast_meta_schema",
        "snapshot_baseline_serialization", "namespace_policy", "resource_limits",
        "resource_constructors", "diagnostics", "comparison_rules",
        "checker_bootstrap", "operation_charging", "planning_constraints",
    }
    _require_keys(core, expected, "core")
    if type(core["format_version"]) is not int or core["format_version"] != 1 or core["closed_top_level"] is not True:
        _reject("core")
    if core["counts"] != COUNTS:
        _reject("counts")
    if (
        core["production_representation"] is not False
        or core["production_choices_authorized"] is not False
        or core["diagnostics"] != CORE_DIAGNOSTICS
        or core["planning_constraints"] != PLANNING_CONSTRAINTS
        or _canonical_sha256(core["comparison_rules"]) != COMPARISON_RULES_SHA256
    ):
        _reject("core")
    if core["paths"] != CORE_PATHS:
        _reject("path")
    _validate_resource_constructor_contract(core)
    if core["resource_limits"] != RESOURCE_LIMITS:
        _reject("limits")
    bootstrap = core["checker_bootstrap"]
    bootstrap_keys = {
        "limits_are_checker_constants_not_registry-derived",
        "core_must_validate_before_any_shard_is_opened",
        "shard_path_must_validate_before_file_access", "symlinks_forbidden",
        "nonregular_files_forbidden", "path_escape_forbidden",
        "duplicate_object_names_forbidden", "utf8_required",
        "single_json_document_required", "nonfinite_numbers_forbidden", "limits",
        "registry_cannot_raise_bootstrap_limits", "bootstrap_failure_pair",
    }
    if (
        not isinstance(bootstrap, dict) or set(bootstrap) != bootstrap_keys
        or bootstrap.get("limits") != BOOTSTRAP_LIMITS
        or any(
            bootstrap.get(key) is not True
            for key in bootstrap_keys - {"limits", "bootstrap_failure_pair"}
        )
        or bootstrap.get("bootstrap_failure_pair") != ["internal", "internal-failure"]
    ):
        _reject("bootstrap")
    shard_contract = core["shards"]
    if (
        shard_contract.get("allowed_names") != [name for name, _ in SHARDS]
        or shard_contract.get("files") != dict(SHARDS)
        or shard_contract.get("closed_inventory") is not True
        or shard_contract.get("unlisted_shards_forbidden") is not True
    ):
        _reject("core")
    operations = core["operation_charging"]
    operation_keys = {
        "closed_categories", "category_order", "charge_unit_per_operation",
        "increment_before_work", "allowed_maximum", "first_rejected_operation",
        "exhaustion_pair", "uncharged_categories_forbidden",
        "category_reordering_forbidden", "derived_total_required",
        "operation_vectors_required",
        "operation_vectors_are_implementation_evidence_derived_later",
        "planning_checker_must_not_execute_future_validator_behavior",
    }
    if (
        not isinstance(operations, dict) or set(operations) != operation_keys
        or operations.get("closed_categories") != CATEGORIES
        or operations.get("category_order") != CATEGORIES
        or operations.get("charge_unit_per_operation") != 1
        or operations.get("increment_before_work") is not True
        or operations.get("allowed_maximum") != 1_000_000
        or operations.get("first_rejected_operation") != 1_000_001
        or operations.get("exhaustion_pair") != ["internal", "operation-budget-exhausted"]
        or operations.get("uncharged_categories_forbidden") is not True
        or operations.get("category_reordering_forbidden") is not True
        or operations.get("derived_total_required") is not False
        or operations.get("operation_vectors_required") is not False
        or operations.get("operation_vectors_are_implementation_evidence_derived_later") is not True
        or operations.get("planning_checker_must_not_execute_future_validator_behavior") is not True
        or any(key in operations for key in ("vectors", "operation_vectors", "earliest_stop_total", "aggregate_total"))
    ):
        _reject("operations")


def _serialize_snapshot(value: Any, profile: dict[str, Any]) -> bytes:
    expected = {
        "purpose": "test-only-layer-2-one-change-proof",
        "production_representation": False,
        "encoding": "UTF-8",
        "sort_keys": True,
        "separators": [",", ":"],
        "ensure_ascii": True,
        "allow_nan": False,
        "final_newline": False,
    }
    if profile != expected:
        _reject("snapshot-transform")
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise RegistryError("snapshot-transform") from error


def _validate_snapshots(snapshot: dict[str, Any]) -> tuple[set[str], set[str]]:
    _require_keys(snapshot, {
        "format_version", "authority", "scope", "closed", "counts", "baselines",
        "operation_vocabulary", "target_namespaces", "one_change_rules",
        "transforms", "focused_expected_tuples",
    }, "snapshot")
    if snapshot["counts"] != {
        "baselines": 3, "negative_transforms": 66, "focused_expected_tuples": 58,
    }:
        _reject("counts")
    baselines = snapshot["baselines"]
    transforms = snapshot["transforms"]
    focused = snapshot["focused_expected_tuples"]
    if not isinstance(baselines, list) or not isinstance(transforms, list):
        _reject("snapshot")
    baseline_ids = _ids(baselines, "snapshot")
    baseline_map = {row["id"]: row["envelope"] for row in baselines}
    transform_ids = _ids(transforms, "snapshot-transform")
    fixtures: set[str] = set(baseline_ids)
    allowed_targets = set(snapshot["target_namespaces"])
    allowed_operations = set(snapshot["operation_vocabulary"])
    for transform in transforms:
        common = {
            "id", "fixture", "baseline", "target_namespace", "operation", "pointer",
            "old", "new", "precondition", "expected", "one_change_rule",
        }
        extra = {"serialization_profile"} if transform["operation"] == "byte-replace-once" else set()
        _require_keys(transform, common | extra, "snapshot-transform")
        fixture = transform["fixture"]
        if (
            not isinstance(fixture, str) or ID_RE.fullmatch(fixture) is None
            or fixture in fixtures or transform["baseline"] not in baseline_map
            or transform["operation"] not in allowed_operations
            or transform["target_namespace"] not in allowed_targets
            or transform["precondition"].get("writes_exactly") != 1
            or transform["precondition"].get("oracle_unchanged") is not True
        ):
            _reject("snapshot-transform")
        fixtures.add(fixture)
        baseline = baseline_map[transform["baseline"]]
        oracle_before = json.dumps(baseline["oracle"], sort_keys=True, separators=(",", ":"))
        if transform["operation"] == "byte-replace-once":
            if transform["target_namespace"] != "candidate-bytes" or transform["pointer"] is not None:
                _reject("snapshot-transform")
            raw = _serialize_snapshot(baseline, transform["serialization_profile"])
            old = _unwrap_typed(transform["old"])
            new = _unwrap_typed(transform["new"])
            if not isinstance(old, str) or not isinstance(new, str) or old == new:
                _reject("snapshot-transform")
            old_bytes, new_bytes = old.encode("utf-8"), new.encode("utf-8")
            candidate_bytes = _serialize_snapshot(
                baseline["candidate"], transform["serialization_profile"]
            )
            candidate_region_start = len(b'{"candidate":')
            candidate_region_end = candidate_region_start + len(candidate_bytes)
            occurrence = raw.find(old_bytes)
            expected_occurrences = transform["precondition"].get("old_occurrences")
            if (
                transform["precondition"].get("baseline_id") != transform["baseline"]
                or raw.count(old_bytes) != expected_occurrences or expected_occurrences != 1
                or occurrence < candidate_region_start
                or occurrence + len(old_bytes) > candidate_region_end
            ):
                _reject("snapshot-transform")
            changed = raw.replace(old_bytes, new_bytes, 1)
            oracle_bytes = _serialize_snapshot(baseline["oracle"], transform["serialization_profile"])
            if changed == raw or oracle_bytes not in changed:
                _reject("snapshot-transform")
        else:
            if transform["target_namespace"] != "candidate":
                _reject("snapshot-transform")
            if not isinstance(transform["pointer"], str) or not transform["pointer"].startswith("/candidate/"):
                _reject("snapshot-transform")
            old, new = _unwrap_typed(transform["old"]), _unwrap_typed(transform["new"])
            operation = transform["operation"]
            if operation == "replace" and (
                transform["precondition"].get("pointer_exists") is not True
                or transform["precondition"].get("equals_old") is not True
            ):
                _reject("snapshot-transform")
            if operation == "remove" and (
                transform["precondition"].get("pointer_exists") is not True
                or transform["precondition"].get("equals_old") is not True
            ):
                _reject("snapshot-transform")
            if operation == "add" and transform["precondition"].get("target_absent") is not True:
                _reject("snapshot-transform")
            if operation == "remove" and new is not ABSENT:
                _reject("snapshot-transform")
            if operation == "add" and old is not ABSENT:
                _reject("snapshot-transform")
            try:
                changed = _apply_json_operation(
                    baseline, operation, transform["pointer"], old, new
                )
            except RegistryError as error:
                raise RegistryError("snapshot-transform") from error
            oracle_after = json.dumps(changed["oracle"], sort_keys=True, separators=(",", ":"))
            if oracle_after != oracle_before:
                _reject("snapshot-transform")
    if len(fixtures) != 69 or len(transform_ids) != 66:
        _reject("counts")
    if not isinstance(focused, list) or len(focused) != 58:
        _reject("focused")
    focused_ids: list[str] = []
    expected_by_fixture = {row["fixture"]: row["expected"] for row in transforms}
    for row in focused:
        if (
            not isinstance(row, list)
            or len(row) != 4
            or row[0] not in expected_by_fixture
            or any(value not in DISPOSITIONS for value in row[1:])
        ):
            _reject("focused")
        expected = expected_by_fixture[row[0]]
        layer = expected.get("layer")
        if layer not in {"layer-4", "layer-5", "layer-6"}:
            _reject("focused")
        if row[int(layer[-1]) - 3] != expected.get("disposition"):
            _reject("focused")
        focused_ids.append(row[0])
    if len(set(focused_ids)) != 58:
        _reject("focused")
    return fixtures, set(transform_ids)


def _candidate_reference_sets(candidate: dict[str, Any]) -> dict[str, set[str]]:
    names = {
        "observation_ref": "observations", "first_observation_ref": "observations",
        "second_observation_ref": "observations", "challenge_ref": "challenges",
        "collection_ref": "collections", "session_ref": "sessions",
        "temporal_state_ref": "temporal_states", "recovery_ref": "recovery_inputs",
    }
    result: dict[str, set[str]] = {}
    for registry in set(names.values()):
        rows = candidate.get(registry)
        if not isinstance(rows, list):
            _reject("history-reference")
        identifiers = _ids(rows, "history-reference")
        if any(not item.startswith("c-") for item in identifiers):
            _reject("history-reference")
        result[registry] = set(identifiers)
    return result


def _validate_candidate_references(
    candidate: dict[str, Any], action_arguments: dict[str, list[str]], *, records: bool = True
) -> set[str]:
    references = _candidate_reference_sets(candidate)
    field_registry = {
        "challenge_ref": "challenges", "collection_ref": "collections",
        "session_ref": "sessions", "temporal_state_ref": "temporal_states",
        "fresh_challenge_ref": "challenges",
    }
    if records:
        for registry in ("observations", "collections", "recovery_inputs"):
            for record in candidate[registry]:
                for field, target in field_registry.items():
                    if field in record and record[field] is not None and record[field] not in references[target]:
                        _reject("history-reference")
    labels: set[str] = set()
    actions = candidate.get("actions")
    if not isinstance(actions, list):
        _reject("history-reference")
    argument_registry = {
        "observation_ref": "observations", "first_observation_ref": "observations",
        "second_observation_ref": "observations", "challenge_ref": "challenges",
        "collection_ref": "collections", "session_ref": "sessions",
        "recovery_ref": "recovery_inputs",
    }
    for action in actions:
        _require_keys(action, {"label", "args"}, "history-reference")
        label, args = action["label"], action["args"]
        if label not in action_arguments or not isinstance(args, list) or len(args) != len(action_arguments[label]):
            _reject("history-reference")
        labels.add(label)
        for name, value in zip(action_arguments[label], args, strict=True):
            registry = argument_registry.get(name)
            if registry is not None and value not in references[registry]:
                _reject("history-reference")
    return labels


def _validate_oracle_references(oracle: dict[str, Any], action_arguments: dict[str, list[str]]) -> None:
    registries = {
        "observation_ref": "observation_oracles",
        "first_observation_ref": "observation_oracles",
        "second_observation_ref": "observation_oracles",
        "challenge_ref": "trusted_challenges",
        "collection_ref": "trusted_authorities",
        "session_ref": "trusted_sessions",
        "recovery_ref": "trusted_recoveries",
    }
    ids: dict[str, set[str]] = {}
    for registry in set(registries.values()):
        rows = oracle.get(registry)
        if not isinstance(rows, list):
            _reject("history-reference")
        identifiers = _ids(rows, "history-reference")
        if any(not item.startswith("t-") for item in identifiers):
            _reject("history-reference")
        ids[registry] = set(identifiers)
    profiles = oracle.get("trusted_profiles")
    if not isinstance(profiles, list):
        _reject("history-reference")
    profile_ids = set(_ids(profiles, "history-reference"))
    if any(not item.startswith("profile-") for item in profile_ids):
        _reject("history-reference")
    record_references = {
        "observation_oracles": {
            "challenge_ref": ids["trusted_challenges"],
            "collection_ref": ids["trusted_authorities"],
            "session_ref": ids["trusted_sessions"],
            "profile_id": profile_ids,
        },
        "trusted_authorities": {
            "challenge_ref": ids["trusted_challenges"],
            "session_ref": ids["trusted_sessions"],
            "profile_id": profile_ids,
        },
        "trusted_recoveries": {
            "fresh_challenge_ref": ids["trusted_challenges"],
        },
    }
    for registry, fields in record_references.items():
        for record in oracle[registry]:
            if any(record.get(field) not in targets for field, targets in fields.items()):
                _reject("history-reference")
    for action in oracle.get("actions", []):
        label, args = action.get("label"), action.get("args")
        if label not in action_arguments or not isinstance(args, list) or len(args) != len(action_arguments[label]):
            _reject("history-reference")
        for name, value in zip(action_arguments[label], args, strict=True):
            registry = registries.get(name)
            if registry is not None and value not in ids[registry]:
                _reject("history-reference")


def _validate_histories(history: dict[str, Any]) -> tuple[set[str], set[str]]:
    _require_keys(history, {
        "format_version", "authority", "scope", "counts", "domains", "schemas",
        "state_tuple_fields", "empty_values", "baseline_record_contract", "baselines",
        "action_rules", "interpreter", "negative_transforms", "transform_interpreter",
        "negative_fixture_ids", "focused_expected_tuples", "reachability", "separation",
    }, "history")
    if history["counts"] != {"valid_baselines": 13, "negative_transforms": 42, "action_rules": 14}:
        _reject("counts")
    if history.get("separation", {}).get("candidate_supplies_oracle") is not False:
        _reject("history")
    if (
        set(history["domains"].get("disposition", [])) != DISPOSITIONS
        or history["domains"].get("high_water_status")
        != ["absent", "available", "unavailable", "corrupt", "contradictory", "rolled-back", "deleted"]
    ):
        _reject("history")
    rules = history["action_rules"]
    if not isinstance(rules, list) or len(rules) != 14:
        _reject("history-reachability")
    labels: list[str] = []
    action_arguments: dict[str, list[str]] = {}
    for rule in rules:
        if not isinstance(rule.get("label"), str) or not isinstance(rule.get("arguments"), list):
            _reject("history-reachability")
        labels.append(rule["label"])
        action_arguments[rule["label"]] = rule["arguments"]
    if len(set(labels)) != 14:
        _reject("history-reachability")
    if {
        label: len(action_arguments[label]) for label in labels
    } != ACTION_ARITIES:
        _reject("history")
    history_semantics = {
        key: history[key]
        for key in ("interpreter", "action_rules", "transform_interpreter")
    }
    if _canonical_sha256(history_semantics) != HISTORY_SEMANTICS_SHA256:
        _reject("history")
    baselines = history["baselines"]
    transforms = history["negative_transforms"]
    fixture_ids = history["negative_fixture_ids"]
    focused = history["focused_expected_tuples"]
    if _canonical_sha256(focused) != HISTORY_FOCUSED_SHA256:
        _reject("focused")
    if not isinstance(baselines, list) or not isinstance(transforms, list) or not isinstance(fixture_ids, list):
        _reject("history")
    baseline_ids = _ids(baselines, "history")
    baseline_map = {row["id"]: row for row in baselines}
    transform_ids = _ids(transforms, "history-transform")
    transformed: dict[str, dict[str, Any]] = {}
    baseline_labels: dict[str, set[str]] = {}
    for baseline in baselines:
        baseline_labels[baseline["id"]] = _validate_candidate_references(
            baseline["candidate"], action_arguments
        )
        _validate_oracle_references(baseline["oracle"], action_arguments)
    for transform in transforms:
        required = {"id", "baseline", "target", "operation", "path"}
        operation = transform.get("operation")
        required |= {"old", "value"} if operation == "replace" else ({"old"} if operation == "remove" else {"index", "value"})
        _require_keys(transform, required, "history-transform")
        if transform["baseline"] not in baseline_map or transform["target"] != "candidate":
            _reject("history-transform")
        if not isinstance(transform["path"], str) or not transform["path"].startswith("/candidate/"):
            _reject("history-transform")
        wrapped = {"candidate": baseline_map[transform["baseline"]]["candidate"]}
        try:
            if operation == "insert":
                pointer = f'{transform["path"]}/{transform["index"]}'
                changed = _apply_json_operation(wrapped, "insert", pointer, ABSENT, transform["value"])
            elif operation == "remove":
                changed = _apply_json_operation(wrapped, "remove", transform["path"], transform["old"], ABSENT)
            elif operation == "replace":
                changed = _apply_json_operation(wrapped, "replace", transform["path"], transform["old"], transform["value"])
            else:
                _reject("pointer")
        except RegistryError as error:
            raise RegistryError("history-transform") from error
        transformed[transform["id"]] = changed["candidate"]
        _validate_candidate_references(changed["candidate"], action_arguments)
    if len(transform_ids) != 42:
        _reject("counts")
    fixtures = set(baseline_ids)
    mapped_transforms: list[str] = []
    for row in fixture_ids:
        if not isinstance(row, list) or len(row) != 2 or row[0] not in transformed:
            _reject("history-transform")
        if row[1] in fixtures or not isinstance(row[1], str):
            _reject("history-transform")
        mapped_transforms.append(row[0])
        fixtures.add(row[1])
    if mapped_transforms != transform_ids or len(fixtures) != 55:
        _reject("history-transform")
    if not isinstance(focused, list) or len(focused) != 40:
        _reject("focused")
    focused_ids: list[str] = []
    for row in focused:
        if (
            not isinstance(row, list)
            or len(row) != 4
            or row[0] not in transformed
            or any(value not in DISPOSITIONS for value in row[1:])
        ):
            _reject("focused")
        focused_ids.append(row[0])
    if len(focused_ids) != len(set(focused_ids)):
        _reject("focused")
    reachability = history["reachability"]
    if not isinstance(reachability, dict) or set(reachability) != set(labels):
        _reject("history-reachability")
    for label, sources in reachability.items():
        if not isinstance(sources, list) or not sources or len(sources) != len(set(sources)):
            _reject("history-reachability")
        for source in sources:
            if source in baseline_labels:
                reached = baseline_labels[source]
            elif source in transformed:
                reached = _validate_candidate_references(
                    transformed[source], action_arguments
                )
            else:
                _reject("history-reachability")
            if label not in reached:
                _reject("history-reachability")
    return fixtures, set(transform_ids)


def _validate_schema_form(value: Any, schemas: set[str], domains: set[str]) -> None:
    if not isinstance(value, dict):
        _reject("schema")
    forms = [name for name in ("type", "domain", "ref", "union") if name in value]
    if len(forms) != 1:
        _reject("schema")
    form = forms[0]
    if form == "domain":
        if set(value) - {"domain", "const"} or value["domain"] not in domains:
            _reject("schema")
    elif form == "ref":
        if set(value) != {"ref"} or value["ref"] not in schemas:
            _reject("schema")
    elif form == "union":
        if set(value) != {"union"}:
            _reject("schema")
        variants = value["union"]
        if not isinstance(variants, list) or len(variants) < 2:
            _reject("schema")
        for variant in variants:
            _validate_schema_form(variant, schemas, domains)
    elif value["type"] == "array":
        if set(value) - {
            "type", "items", "min_items", "max_items", "unique_by", "unique_items"
        }:
            _reject("schema")
        if not isinstance(value.get("min_items"), int) or isinstance(value["min_items"], bool):
            _reject("schema")
        if not isinstance(value.get("max_items"), int) or value["min_items"] > value["max_items"]:
            _reject("schema")
        _validate_schema_form(value.get("items"), schemas, domains)
    elif value["type"] == "tuple":
        if set(value) != {"type", "closed", "items", "min_items", "max_items"}:
            _reject("schema")
        items = value.get("items")
        if (
            value.get("closed") is not True or not isinstance(items, list)
            or value.get("min_items") != len(items)
            or value.get("max_items") != len(items)
        ):
            _reject("schema")
        for item in items:
            _validate_schema_form(item, schemas, domains)
    elif value["type"] == "object":
        if set(value) != {"type", "closed", "required", "properties"}:
            _reject("schema")
        properties, required = value.get("properties"), value.get("required")
        if (
            value.get("closed") is not True or not isinstance(properties, dict)
            or not isinstance(required, list) or set(required) != set(properties)
        ):
            _reject("schema")
        for item in properties.values():
            _validate_schema_form(item, schemas, domains)
    elif value["type"] not in {
        "string", "boolean", "null", "json-scalar", "json-value"
    }:
        _reject("schema")
    elif set(value) - {"type", "const"}:
        _reject("schema")


def _validate_schemas(validators: dict[str, Any]) -> None:
    schemas = validators["schemas"]
    domains = validators["domains"]
    if not isinstance(schemas, dict) or not isinstance(domains, dict):
        _reject("schema")
    schema_names, domain_names = set(schemas), set(domains)
    for domain in domains.values():
        if not isinstance(domain, dict):
            _reject("schema")
        if "domain" in domain and domain["domain"] not in domain_names:
            _reject("schema")
    for schema in schemas.values():
        if not isinstance(schema, dict) or schema.get("closed") is not True:
            _reject("schema")
        kind = schema.get("type")
        if kind == "object":
            required, properties = schema.get("required"), schema.get("properties")
            if (
                not isinstance(required, list) or len(required) != len(set(required))
                or not isinstance(properties, dict) or set(required) != set(properties)
            ):
                _reject("schema")
            for property_schema in properties.values():
                _validate_schema_form(property_schema, schema_names, domain_names)
        elif kind == "tuple":
            items = schema.get("items")
            if (
                not isinstance(items, list)
                or schema.get("min_items") != len(items)
                or schema.get("max_items") != len(items)
            ):
                _reject("schema")
            for item in items:
                _validate_schema_form(item, schema_names, domain_names)
        else:
            _reject("schema")

    if domains.get("ValidatorOperation", {}).get("values") != [
        "corpus-mutation", "loader-probe", "attack-loader-parity"
    ]:
        _reject("schema")
    if domains.get("Checkpoint", {}).get("values") != [
        "layer-1", "layer-2", "layer-3", "layer-4", "layer-5", "layer-6",
        "layer-6-success", "attack-parity", "internal",
    ]:
        _reject("schema")
    if domains.get("Disposition", {}).get("values") != [
        "Conform", "Malformed", "Unsupported", "ContextBindingMismatch",
        "EvidenceInvalid", "Expired", "AttestationUnavailable",
        "ProtectedSessionLost", "PolicyDenied",
    ]:
        _reject("schema")
    fixture_path = domains.get("FixturePath", {})
    if fixture_path.get("component_max_bytes") != 128:
        _reject("schema")
    history_action = schemas.get("HistoryAction", {})
    if history_action.get("properties", {}).get("args", {}).get("min_items") != 0:
        _reject("schema")


def _validate_domain(value: Any, name: str, domains: dict[str, Any]) -> bool:
    domain = domains[name]
    if "domain" in domain:
        return _validate_domain(value, domain["domain"], domains)
    kind = domain.get("json_type")
    if kind == "integer-not-boolean":
        valid = type(value) is int
    elif kind == "string":
        valid = isinstance(value, str)
    else:
        return False
    if not valid:
        return False
    if "values" in domain and value not in domain["values"]:
        return False
    if type(value) is int:
        return domain.get("minimum", value) <= value <= domain.get("maximum", value)
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    if domain.get("ascii_only") is True and len(encoded) != len(value):
        return False
    if not domain.get("min_bytes", 0) <= len(encoded) <= domain.get("max_bytes", len(encoded)):
        return False
    pattern = domain.get("ascii_pattern")
    if pattern is not None and re.fullmatch(pattern, value) is None:
        return False
    if name == "FixturePath":
        parts = value.split("/")
        if (
            any(part in domain["forbidden_components"] for part in parts)
            or any(len(part.encode("utf-8")) > domain["component_max_bytes"] for part in parts)
            or any(re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", part) is None for part in parts)
        ):
            return False
    return True


def _validate_typed_value(
    value: Any,
    form: dict[str, Any],
    schemas: dict[str, Any],
    domains: dict[str, Any],
) -> bool:
    if "const" in form and value != form["const"]:
        return False
    if "domain" in form:
        return _validate_domain(value, form["domain"], domains)
    if "ref" in form:
        return _validate_typed_value(value, schemas[form["ref"]], schemas, domains)
    if "union" in form:
        return any(_validate_typed_value(value, item, schemas, domains) for item in form["union"])
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
        if not isinstance(value, list) or not form["min_items"] <= len(value) <= form["max_items"]:
            return False
        item_forms = form["items"] if kind == "tuple" else [form["items"]] * len(value)
        if len(item_forms) != len(value):
            return False
        if not all(
            _validate_typed_value(item, item_form, schemas, domains)
            for item, item_form in zip(value, item_forms, strict=True)
        ):
            return False
        unique_by = form.get("unique_by")
        if unique_by is not None:
            try:
                keys = [item[0] if isinstance(item, list) else item[unique_by] for item in value]
            except (KeyError, IndexError, TypeError):
                return False
            if len(keys) != len(set(keys)):
                return False
        if form.get("unique_items") is True:
            serialized = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(serialized) != len(set(serialized)):
                return False
        return True
    if kind == "object":
        if not isinstance(value, dict) or set(value) != set(form["required"]):
            return False
        return all(
            _validate_typed_value(value[key], property_form, schemas, domains)
            for key, property_form in form["properties"].items()
        )
    return False


def _validate_candidate_schema(
    value: Any, schema: str, validators: dict[str, Any]
) -> bool:
    schemas, domains = validators["schemas"], validators["domains"]
    if not _validate_typed_value(value, schemas[schema], schemas, domains):
        return False
    if schema == "SnapshotCandidate":
        transcript = value["transcript"]
        expected_claims = (
            {
                "attesting-agent-identity", "platform-identity",
                "boot-measurement-identity", "runtime-manifest-identity",
                "game-manifest-identity", "process-binding-identity",
                "protected-session-identity", "enforcement-policy-state",
            },
            {
                "attesting-agent-identity", "platform-identity",
                "boot-measurement-identity", "runtime-manifest-identity",
                "game-manifest-identity", "process-binding-identity",
                "protected-session-identity", "enforcement-policy-state",
                "attestation-identity", "runtime-measurement-identity",
            },
        )
        meanings = {claim["meaning"] for claim in transcript["claims"]}
        return (
            meanings in expected_claims
            and (
                transcript["test_only_semantic"] is None
                or transcript["test_only_semantic"]["criticality"] == "domain-exclusion"
            )
        )
    if schema == "HistoryCandidate":
        return all(
            collection["time_domain"] == "protected-monotonic"
            for collection in value["collections"]
        )
    return True


def _require_typed(
    value: Any, schema: str, validators: dict[str, Any]
) -> None:
    if not _validate_candidate_schema(value, schema, validators):
        _reject("baseline-schema")


def _validate_transform_schema_prerequisites(
    snapshots: dict[str, Any], histories: dict[str, Any], validators: dict[str, Any]
) -> None:
    schemas, domains = validators["schemas"], validators["domains"]
    snapshot_baselines = {
        row["id"]: row["envelope"] for row in snapshots["baselines"]
    }
    for transform in snapshots["transforms"]:
        layer = transform["expected"]["layer"]
        if transform["operation"] == "byte-replace-once":
            if layer != "layer-2":
                _reject("baseline-schema")
            continue
        baseline = snapshot_baselines[transform["baseline"]]
        changed = _apply_json_operation(
            baseline,
            transform["operation"],
            transform["pointer"],
            _unwrap_typed(transform["old"]),
            _unwrap_typed(transform["new"]),
        )
        candidate_valid = _validate_candidate_schema(
            changed["candidate"], "SnapshotCandidate", validators
        )
        oracle_valid = _validate_typed_value(
            changed["oracle"], schemas["SnapshotOracle"], schemas, domains
        )
        envelope_valid = _validate_typed_value(
            changed, schemas["FixtureEnvelope"], schemas, domains
        )
        if (
            layer == "layer-3" and candidate_valid
            or layer in {"layer-4", "layer-5", "layer-6"}
            and not (candidate_valid and oracle_valid and envelope_valid)
            or layer not in {"layer-3", "layer-4", "layer-5", "layer-6"}
        ):
            _reject("baseline-schema")

    manifest = validators["validator_baselines"]["baseline-corpus-v1"]["ast"]["value"]
    layers_by_transform = {
        row[4]: row[5]
        for row in manifest["fixtures"]
        if row[1] == "history" and row[4] is not None
    }
    history_baselines = {row["id"]: row for row in histories["baselines"]}
    for transform in histories["negative_transforms"]:
        changed = copy.deepcopy(history_baselines[transform["baseline"]])
        if transform["operation"] == "insert":
            changed = _apply_json_operation(
                changed,
                "insert",
                f'{transform["path"]}/{transform["index"]}',
                ABSENT,
                transform["value"],
            )
        elif transform["operation"] == "remove":
            changed = _apply_json_operation(
                changed, "remove", transform["path"], transform["old"], ABSENT
            )
        else:
            changed = _apply_json_operation(
                changed,
                "replace",
                transform["path"],
                transform["old"],
                transform["value"],
            )
        layer = layers_by_transform.get(transform["id"])
        candidate_valid = _validate_candidate_schema(
            changed["candidate"], "HistoryCandidate", validators
        )
        oracle_valid = _validate_typed_value(
            changed["oracle"], schemas["HistoryOracle"], schemas, domains
        )
        if (
            layer == "layer-3" and candidate_valid
            or layer in {"layer-4", "layer-5", "layer-6"}
            and not (candidate_valid and oracle_valid)
            or layer not in {"layer-3", "layer-4", "layer-5", "layer-6"}
        ):
            _reject("baseline-schema")


def _validate_canonical_baselines(
    snapshots: dict[str, Any], histories: dict[str, Any], validators: dict[str, Any]
) -> None:
    for baseline in snapshots["baselines"]:
        _require_typed(baseline["envelope"], "FixtureEnvelope", validators)
    for baseline in histories["baselines"]:
        _require_typed(baseline["candidate"], "HistoryCandidate", validators)
        _require_typed(baseline["oracle"], "HistoryOracle", validators)
    manifest = validators["validator_baselines"]["baseline-corpus-v1"]["ast"]["value"]
    _require_typed(manifest, "Manifest", validators)


def _focused_vector(layer: str, disposition: str) -> list[str]:
    result = ["Conform", "Conform", "Conform"]
    if layer not in {"layer-4", "layer-5", "layer-6"}:
        _reject("focused")
    result[int(layer[-1]) - 4] = disposition
    return result


def _validate_manifest_authority(
    snapshots: dict[str, Any], histories: dict[str, Any], validators: dict[str, Any]
) -> None:
    manifest = validators["validator_baselines"]["baseline-corpus-v1"]["ast"]["value"]
    expected_fixtures: list[list[Any]] = []
    for baseline in snapshots["baselines"]:
        identifier = baseline["id"]
        expected_fixtures.append([
            identifier, "snapshot", f"snapshots/{identifier}.json", None, None,
            "layer-6-success", "Conform",
        ])
    snapshot_focused: list[list[Any]] = []
    for transform in snapshots["transforms"]:
        expected = transform["expected"]
        fixture = transform["fixture"]
        expected_fixtures.append([
            fixture, "snapshot", f"snapshots/{fixture}.json", transform["baseline"],
            transform["id"], expected["layer"], expected["disposition"],
        ])
        if expected["layer"] in {"layer-4", "layer-5", "layer-6"}:
            snapshot_focused.append([
                fixture, *_focused_vector(expected["layer"], expected["disposition"])
            ])
    if snapshots["focused_expected_tuples"] != snapshot_focused:
        _reject("focused")

    for baseline in histories["baselines"]:
        identifier = baseline["id"]
        expected_fixtures.append([
            identifier, "history", f"histories/{identifier}.json", None, None,
            "layer-6-success", "Conform",
        ])
    focused_by_transform = {row[0]: row[1:] for row in histories["focused_expected_tuples"]}
    special = {
        "substitute-client-utc": ("layer-3", "Malformed"),
        "substitute-unknown-critical-time-domain": ("layer-3", "Unsupported"),
    }
    history_focused_fixture_ids: list[str] = []
    transform_by_id = {row["id"]: row for row in histories["negative_transforms"]}
    for transform_id, fixture in histories["negative_fixture_ids"]:
        transform = transform_by_id[transform_id]
        if transform_id in focused_by_transform:
            vector = focused_by_transform[transform_id]
            failures = [
                (f"layer-{index + 4}", value)
                for index, value in enumerate(vector)
                if value != "Conform"
            ]
            if not failures:
                _reject("focused")
            layer, disposition = failures[0]
            history_focused_fixture_ids.append(fixture)
        else:
            if transform_id not in special:
                _reject("focused")
            layer, disposition = special[transform_id]
        expected_fixtures.append([
            fixture, "history", f"histories/{fixture}.json", transform["baseline"],
            transform_id, layer, disposition,
        ])
    if manifest["counts"] != {"snapshots": 69, "histories": 55, "total": 124}:
        _reject("manifest")
    if manifest["fixtures"] != expected_fixtures:
        _reject("manifest")
    if manifest["validator_cases"] != validators["validator_cases"]:
        _reject("manifest")
    focused_ids = [row[0] for row in snapshot_focused] + history_focused_fixture_ids
    if validators["coverage"]["requirement-focused-oracles"] != focused_ids:
        _reject("focused")
    if manifest["coverage"] != validators["coverage"]:
        _reject("manifest")


def _walk_ast(
    value: Any,
    language: dict[str, Any],
    baseline_ids: set[str],
    baseline_values: dict[str, Any] | None = None,
    reject_outcomes: bool = True,
) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    if isinstance(value, dict):
        forbidden_outcomes = {"checkpoint", "disposition", "result", "expected"}
        allowed_expected = {"expected_old", "expected_occurrences", "expected_kind"}
        if reject_outcomes and (
            set(value) & forbidden_outcomes
            or any(
                key.startswith("expected_") and key not in allowed_expected
                for key in value
            )
        ):
            _reject("validator-ast")
        if "node" in value:
            node = value["node"]
            spec = language["nodes"].get(node)
            if not isinstance(spec, dict):
                _reject("validator-ast")
            allowed = set(spec["required"]) | set(spec.get("optional", []))
            if set(value) != allowed - (set(spec.get("optional", [])) - set(value)):
                _reject("validator-ast")
            nodes.append(value)
            if node == "ref":
                if value["subject"] not in language["registered_subjects"]:
                    _reject("validator-ast")
                if value["subject"] == "baseline" and value["id"] not in baseline_ids:
                    _reject("validator-ast")
                if "pointer" in value:
                    _decode_pointer(value["pointer"])
                    if value["subject"] == "baseline" and baseline_values is not None:
                        try:
                            _select(baseline_values[value["id"]], value["pointer"])
                        except RegistryError as error:
                            raise RegistryError("validator-ast") from error
            if node == "sequence":
                minimum, maximum = spec["cardinality"]
                if not isinstance(value["steps"], list) or not minimum <= len(value["steps"]) <= maximum:
                    _reject("validator-ast")
            if node == "generate" and value["constructor"] not in spec["constructors"]:
                _reject("validator-ast")
            if node == "fs-create" and value["kind"] not in spec["kinds"]:
                _reject("validator-ast")
        for child in value.values():
            nodes.extend(
                _walk_ast(child, language, baseline_ids, baseline_values, reject_outcomes)
            )
    elif isinstance(value, list):
        for child in value:
            nodes.extend(
                _walk_ast(child, language, baseline_ids, baseline_values, reject_outcomes)
            )
    return nodes


def _reject_operation_evidence(value: Any) -> None:
    forbidden = {"earliest_stop_total", "aggregate_total", "operation_vectors", "vectors"}
    if isinstance(value, dict):
        if set(value) & forbidden:
            _reject("operations")
        for child in value.values():
            _reject_operation_evidence(child)
    elif isinstance(value, list):
        for child in value:
            _reject_operation_evidence(child)


def _resource_value(scope: str, dimension: str, relation: str, limits: dict[str, Any]) -> Any:
    target = limits[scope][dimension] + (relation == "over")
    if dimension == "bytes":
        return b" " * (target - 2) + b"{}"
    if dimension == "depth":
        value: Any = None
        for _ in range(target - 1):
            value = [value]
        return value
    if dimension == "object_fields":
        return {f"k{index}": None for index in range(target)}
    if dimension == "array_items":
        return [None] * target
    if dimension == "string_characters":
        return "x" * target
    if dimension == "object_key_characters":
        return {"k" * target: None}
    if dimension == "number_token_characters":
        return ("1" * target).encode("ascii")
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
        return result
    _reject("resource-constructor")


def _metrics(value: Any) -> dict[str, int]:
    if isinstance(value, bytes):
        return {
            "bytes": len(value), "depth": 1, "object_fields": 0, "array_items": 0,
            "string_characters": 0, "object_key_characters": 0,
            "number_token_characters": len(value) if value and value[:1].isdigit() else 0,
            "total_nodes": 1,
        }
    result = {
        "bytes": len(json.dumps(value, separators=(",", ":")).encode("utf-8")),
        "depth": 1, "object_fields": 0, "array_items": 0,
        "string_characters": 0, "object_key_characters": 0,
        "number_token_characters": 0, "total_nodes": 0,
    }
    def walk(item: Any, depth: int) -> None:
        result["total_nodes"] += 1
        result["depth"] = max(result["depth"], depth)
        if isinstance(item, dict):
            result["object_fields"] = max(result["object_fields"], len(item))
            result["object_key_characters"] = max(
                [result["object_key_characters"], *(len(key) for key in item)]
            )
            for child in item.values():
                walk(child, depth + 1)
        elif isinstance(item, list):
            result["array_items"] = max(result["array_items"], len(item))
            for child in item:
                walk(child, depth + 1)
        elif isinstance(item, str):
            result["string_characters"] = max(result["string_characters"], len(item))
    walk(value, 1)
    return result


def _validate_resource_nodes(nodes: list[dict[str, Any]], core: dict[str, Any]) -> None:
    limits = core["resource_limits"]
    dimensions = set(limits["dimensions"])
    scopes = set(core["resource_constructors"]["scopes"])
    relations = set(core["resource_constructors"]["relations"])
    for node in nodes:
        if node.get("node") != "generate" or node.get("constructor") != "resource-boundary":
            continue
        parameters = node["parameters"]
        if not isinstance(parameters, dict):
            _reject("resource-constructor")
        scope_value = parameters.get("scope")
        dimension_value = parameters.get("dimension")
        relation_value = parameters.get("relation")
        if (
            not isinstance(scope_value, str) or scope_value not in scopes
            or not isinstance(dimension_value, str) or dimension_value not in dimensions
            or not isinstance(relation_value, str) or relation_value not in relations
        ):
            _reject("resource-constructor")
        scope, dimension, relation = scope_value, dimension_value, relation_value
        value = _resource_value(scope, dimension, relation, limits)
        metrics = _metrics(value)
        expected = limits[scope][dimension] + (relation == "over")
        if metrics[dimension] != expected:
            _reject("resource-constructor")
        for other in dimensions - {dimension}:
            if metrics[other] > limits[scope][other]:
                _reject("resource-constructor")


def _expected_resource_node(case_id: str) -> tuple[str, dict[str, Any]] | None:
    names = {
        "bytes": "bytes", "depth": "depth", "fields": "object_fields",
        "items": "array_items", "string": "string_characters",
        "key": "object_key_characters", "nodes": "total_nodes",
        "total-nodes": "total_nodes", "integer-token": "number_token_characters",
        "float-token": "number_token_characters",
    }
    scope: str
    relation: str
    marker: str
    if case_id.startswith("v1-corpus-manifest-") and case_id.endswith("-over-limit"):
        scope, relation = "manifest", "over"
        marker = case_id.removeprefix("v1-corpus-manifest-").removesuffix("-over-limit")
    elif case_id.startswith("v1-loader-exact-max-"):
        scope, relation = "fixture", "exact"
        marker = case_id.removeprefix("v1-loader-exact-max-")
    elif case_id.startswith("v1-loader-") and case_id.endswith("-over-limit"):
        scope, relation = "fixture", "over"
        marker = case_id.removeprefix("v1-loader-").removesuffix("-over-limit")
    else:
        return None
    dimension = names.get(marker)
    if dimension is None:
        return None
    if marker in {"integer-token", "float-token"} and relation == "over":
        kind = marker.removesuffix("-token")
        result: dict[str, Any] = {"kind": kind, "scope": scope, "relation": relation}
        if scope == "fixture" and kind == "integer":
            result.update({"prefix": None, "digit": "9"})
        elif kind == "integer":
            result["digit"] = "9"
        elif scope == "fixture":
            result.update({"prefix": "0.", "digit": "9"})
        else:
            result["prefix"] = "0."
        return "number-token-boundary", result
    result = {"scope": scope, "dimension": dimension, "relation": relation}
    if relation == "exact":
        result["numeric_kind"] = None
    if marker == "integer-token":
        result.update({
            "numeric_kind": "integer",
            "token_characters": 64,
            "token": "1" + "0" * 63,
            "grammar": {
                "sign": "absent", "integer_first_digit": "1",
                "integer_remaining_digit": "0", "integer_remaining_characters": 63,
                "fraction": "absent", "exponent": "absent",
            },
        })
    elif marker == "float-token":
        result.update({
            "numeric_kind": "float",
            "token_characters": 64,
            "token": "0." + "1" * 62,
            "grammar": {
                "sign": "absent", "integer_part": "0", "decimal_point": ".",
                "fraction_digit": "1", "fraction_characters": 62,
                "exponent": "absent", "finite": True,
            },
        })
    return "resource-boundary", result


def _git_blob_sha1(raw: bytes) -> str:
    header = f"blob {len(raw)}\0".encode("ascii")
    return hashlib.sha1(header + raw).hexdigest()


def _validate_source_bindings(
    bindings: Any, attack_baseline: Any, root_fd: int
) -> None:
    if not isinstance(bindings, dict) or set(bindings) != {
        "attack_checker", "attack_schema", "attack_scenarios"
    } or not isinstance(attack_baseline, dict):
        _reject("source-binding")
    checker = bindings["attack_checker"]
    schema = bindings["attack_schema"]
    scenarios = bindings["attack_scenarios"]
    if (
        not isinstance(checker, dict) or set(checker) != {"path", "sha256", "git_blob"}
        or not isinstance(schema, dict) or set(schema) != {"path", "sha256", "git_blob"}
        or checker["path"] != SOURCE_BINDINGS["attack_checker"]["path"]
        or schema["path"] != SOURCE_BINDINGS["attack_schema"]["path"]
        or attack_baseline.get("checker") != checker
        or not isinstance(attack_baseline.get("schema"), dict)
        or {
            key: attack_baseline["schema"].get(key)
            for key in ("path", "sha256", "git_blob")
        } != schema
        or not isinstance(scenarios, dict)
        or set(scenarios) != {"glob", "count", "files"}
        or scenarios["glob"] != "lab/scenarios/*.scenario.json"
        or scenarios["count"] != 30
        or scenarios["files"] != attack_baseline.get("scenario_files")
    ):
        _reject("source-binding")
    files = scenarios["files"]
    if not isinstance(files, list) or len(files) != 30:
        _reject("source-binding")
    declared_paths: list[str] = []
    for row in files:
        if (
            not isinstance(row, dict) or set(row) != {"path", "sha256"}
            or not isinstance(row["path"], str)
            or not row["path"].startswith("lab/scenarios/")
            or not row["path"].endswith(".scenario.json")
            or not isinstance(row["sha256"], str)
            or HEX_RE.fullmatch(row["sha256"]) is None
        ):
            _reject("source-binding")
        declared_paths.append(row["path"])
    if len(set(declared_paths)) != 30:
        _reject("source-binding")
    for authority in (checker, schema):
        if (
            not isinstance(authority["sha256"], str)
            or HEX_RE.fullmatch(authority["sha256"]) is None
            or not isinstance(authority["git_blob"], str)
            or re.fullmatch(r"[0-9a-f]{40}", authority["git_blob"]) is None
        ):
            _reject("source-binding")

    try:
        scenario_fd = _open_relative_directory(root_fd, "lab/scenarios")
        try:
            initial_state = _directory_state(scenario_fd)
            inventory = _list_directory(scenario_fd)
            actual_paths = {
                f"lab/scenarios/{name}"
                for name in inventory
                if name.endswith(".scenario.json")
            }
            if actual_paths != set(declared_paths):
                _reject("source-binding")
            for authority in (checker, schema):
                raw = _read_relative(root_fd, authority["path"])
                if (
                    hashlib.sha256(raw).hexdigest() != authority["sha256"]
                    or _git_blob_sha1(raw) != authority["git_blob"]
                ):
                    _reject("source-binding")
            by_path = {row["path"]: row["sha256"] for row in files}
            for path in declared_paths:
                raw = _read_relative(scenario_fd, Path(path).name)
                if hashlib.sha256(raw).hexdigest() != by_path[path]:
                    _reject("source-binding")
            if (
                _list_directory(scenario_fd) != inventory
                or _directory_state(scenario_fd) != initial_state
            ):
                _reject("source-binding")
        finally:
            os.close(scenario_fd)
    except RegistryError as error:
        if error.code == "source-binding":
            raise
        raise RegistryError("source-binding") from error


def _validate_validators(
    validators: dict[str, Any], fixture_ids: set[str], core: dict[str, Any], root_fd: int
) -> set[str]:
    _require_keys(validators, {
        "format_version", "authority", "scope", "production_representation", "closed",
        "counts", "source_bindings", "domains", "schema_algebra", "schemas",
        "validator_baselines", "validator_cases", "transform_ast_language",
        "validator_transforms", "coverage", "attack_parity_expectations",
    }, "validator")
    if validators["counts"] != {
        "validator_cases": 202, "validator_transforms": 202,
        "validator_baselines": 3, "coverage_requirements": 10,
    }:
        _reject("counts")
    _validate_schemas(validators)
    baselines = validators["validator_baselines"]
    cases = validators["validator_cases"]
    transforms = validators["validator_transforms"]
    if not isinstance(baselines, dict) or set(baselines) != {
        "baseline-corpus-v1", "baseline-json-object", "baseline-attack-repository"
    }:
        _reject("validator-bijection")
    language = validators["transform_ast_language"]
    baseline_values: dict[str, Any] = {}
    for baseline_id, program in baselines.items():
        _require_keys(program, {"ast"}, "validator-ast")
        ast = program["ast"]
        if not isinstance(ast, dict) or ast.get("node") != "literal":
            _reject("validator-ast")
        _walk_ast(ast, language, set(baselines), reject_outcomes=False)
        baseline_values[baseline_id] = ast["value"]
    manifest = baseline_values["baseline-corpus-v1"]
    if (
        isinstance(manifest, dict)
        and isinstance(manifest.get("coverage"), dict)
        and isinstance(validators["coverage"], dict)
        and set(manifest["coverage"]) == set(validators["coverage"])
        and set(validators["coverage"]) != REQUIREMENT_TAGS
    ):
        _reject("manifest")
    _require_typed(baseline_values["baseline-corpus-v1"], "Manifest", validators)
    attack_baseline = baseline_values["baseline-attack-repository"]
    _validate_source_bindings(validators["source_bindings"], attack_baseline, root_fd)
    if not isinstance(cases, list) or len(cases) != 202 or not isinstance(transforms, dict):
        _reject("validator-bijection")
    case_ids: list[str] = []
    case_by_transform: dict[str, list[Any]] = {}
    for case in cases:
        if not isinstance(case, list) or len(case) != 6:
            _reject("validator-bijection")
        identifier, operation, baseline, transform, checkpoint, disposition = case
        if (
            not _valid_id(identifier)
            or baseline not in baselines or not _valid_id(transform)
            or transform != identifier
            or operation not in VALIDATOR_OPERATIONS
            or checkpoint not in CHECKPOINTS
            or disposition not in DISPOSITIONS
        ):
            _reject("validator-bijection")
        case_ids.append(identifier)
        if transform in case_by_transform:
            _reject("validator-bijection")
        case_by_transform[transform] = case
    if (
        len(set(case_ids)) != 202
        or set(transforms) != set(case_by_transform)
    ):
        _reject("validator-bijection")
    attack_expectations = validators["attack_parity_expectations"]
    expected_attack_keys = {
        "v1-attack-parser-diagnostic-absolute-path",
        "v1-attack-parser-diagnostic-control-injection",
        "v1-attack-duplicate-diagnostic-attacker-path",
        "v1-attack-io-diagnostic-absolute-path",
        "v1-attack-schema-diagnostic-attacker-path",
        "v1-attack-instance-diagnostic-caller-path",
        "v1-attack-exact-malformed-line-column",
        "v1-attack-exact-duplicate-message",
        "v1-attack-exact-invalid-utf8-message",
        "v1-attack-exact-io-message",
        "v1-attack-cli-normal-success",
        "v1-attack-cli-self-test-transcript",
        "v1-attack-cli-usage-exit",
        "v1-attack-cli-validation-failure-exit",
        "v1-attack-cli-internal-failure-exit",
    }
    if (
        not isinstance(attack_expectations, dict)
        or set(attack_expectations) != {"closed", "by_case_id"}
        or attack_expectations["closed"] is not True
        or not isinstance(attack_expectations["by_case_id"], dict)
        or set(attack_expectations["by_case_id"]) != expected_attack_keys
        or not expected_attack_keys <= set(case_ids)
    ):
        _reject("attack-parity")
    expectation_keys = {
        **{identifier: {"redaction_required"} for identifier in expected_attack_keys if "diagnostic" in identifier},
        **{identifier: {"expected_message"} for identifier in expected_attack_keys if "exact-" in identifier},
        "v1-attack-cli-normal-success": {"expected_exit", "expected_stdout", "expected_stderr"},
        "v1-attack-cli-self-test-transcript": {"expected_exit", "stdout_final_line", "expected_stderr"},
        "v1-attack-cli-usage-exit": {"expected_exit", "expected_stdout", "expected_stderr"},
        "v1-attack-cli-validation-failure-exit": {"expected_exit", "expected_stdout", "expected_stderr"},
        "v1-attack-cli-internal-failure-exit": {"expected_exit", "expected_stdout", "expected_stderr"},
    }
    for identifier, expectation in attack_expectations["by_case_id"].items():
        if not isinstance(expectation, dict) or set(expectation) != expectation_keys[identifier]:
            _reject("attack-parity")
        if "redaction_required" in expectation and expectation["redaction_required"] is not True:
            _reject("attack-parity")
        for key, value in expectation.items():
            if key == "expected_exit":
                if type(value) is not int or value not in {0, 1, 2}:
                    _reject("attack-parity")
            elif key != "redaction_required" and not isinstance(value, str):
                _reject("attack-parity")
    outcome_projection = [[row[0], row[4], row[5]] for row in cases]
    if _canonical_sha256(outcome_projection) != VALIDATOR_OUTCOMES_SHA256:
        _reject("manifest")
    if "v1-corpus-canonical" not in case_by_transform:
        _reject("manifest")
    all_nodes: list[dict[str, Any]] = []
    for transform_id, program in transforms.items():
        _require_keys(program, {"ast"}, "validator-ast")
        ast = program["ast"]
        if not isinstance(ast, dict) or ast.get("node") not in language["root_nodes"]:
            _reject("validator-ast")
        nodes = _walk_ast(ast, language, set(baselines), baseline_values)
        probes = [node for node in nodes if node.get("node") == "probe"]
        if len(probes) != 1:
            _reject("validator-ast")
        case = case_by_transform[transform_id]
        operation_adapters = {
            "corpus-mutation": {"corpus-validator"},
            "loader-probe": {"bounded-json-loader", "bounded-json-diagnostic"},
            "attack-loader-parity": {"frozen-attack-checker"},
        }
        operation_checkpoints = {
            "corpus-mutation": "layer-1",
            "loader-probe": "layer-2",
            "attack-loader-parity": "attack-parity",
        }
        if (
            probes[0].get("adapter") not in operation_adapters[case[1]]
            or case[4] != operation_checkpoints[case[1]]
            or (transform_id == "v1-corpus-canonical" and case[5] != "Conform")
        ):
            _reject("manifest")
        resource_nodes = [
            node for node in nodes
            if node.get("node") == "generate"
            and node.get("constructor") in {"resource-boundary", "number-token-boundary"}
        ]
        expected_resource = _expected_resource_node(transform_id)
        if expected_resource is None and resource_nodes:
            _reject("resource-constructor")
        if expected_resource is not None and (
            len(resource_nodes) != 1
            or resource_nodes[0].get("constructor") != expected_resource[0]
            or resource_nodes[0].get("parameters") != expected_resource[1]
        ):
            _reject("resource-constructor")
        all_nodes.extend(nodes)
    _validate_resource_nodes(all_nodes, core)
    coverage = validators["coverage"]
    if not isinstance(coverage, dict) or set(coverage) != REQUIREMENT_TAGS:
        _reject("coverage")
    registered = fixture_ids | set(case_ids)
    mapped: set[str] = set()
    for values in coverage.values():
        if (
            not isinstance(values, list) or not values
            or not all(isinstance(value, str) for value in values)
            or len(values) != len(set(values)) or not set(values) <= registered
        ):
            _reject("coverage")
        mapped.update(values)
    if mapped != registered:
        _reject("coverage")
    return set(case_ids)


def validate_registry(path: Path = DEFAULT_REGISTRY) -> RegistrySummary:
    _require_os_capabilities()
    absolute_path = path.absolute()
    repository = ROOT if absolute_path == DEFAULT_REGISTRY else absolute_path.parent
    index_relative = (
        str(DEFAULT_REGISTRY.relative_to(ROOT))
        if repository == ROOT
        else absolute_path.name
    )
    root_fd = _open_directory(repository)
    try:
        index, index_raw = _load_relative(root_fd, index_relative)
        _require_keys(index, {"format_version", "registry_kind", "closed", "shards"}, "index")
        if (
            type(index["format_version"]) is not int or index["format_version"] != 1
            or index["registry_kind"] != "m1-013-sharded-planning-registry-index"
            or index["closed"] is not True
            or not isinstance(index["shards"], list)
            or len(index["shards"]) != BOOTSTRAP_LIMITS["shard_files"]
        ):
            _reject("index")
        for entry, (name, relative_path) in zip(index["shards"], SHARDS, strict=True):
            _require_keys(entry, {"name", "path", "sha256"}, "index")
            if entry["name"] != name or entry["path"] != relative_path:
                _reject("index")
            digest = entry["sha256"]
            if not isinstance(digest, str) or HEX_RE.fullmatch(digest) is None:
                _reject("index")

        loaded: dict[str, dict[str, Any]] = {}
        shard_fd = _open_relative_directory(
            root_fd, "docs/superpowers/plans/m1-013-format-v1"
        )
        try:
            initial_state = _directory_state(shard_fd)
            actual_files = _list_directory(shard_fd)
            if actual_files != {Path(relative).name for _, relative in SHARDS}:
                _reject("index")
            for entry, (name, relative_path) in zip(
                index["shards"], SHARDS, strict=True
            ):
                shard, raw = _load_relative(shard_fd, Path(relative_path).name)
                if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
                    _reject("hash")
                loaded[name] = shard
                _reject_operation_evidence(shard)
                if name == "core":
                    _validate_core(shard)
            if (
                _list_directory(shard_fd) != actual_files
                or _directory_state(shard_fd) != initial_state
            ):
                _reject("file")
        finally:
            os.close(shard_fd)
    finally:
        os.close(root_fd)

    snapshot_fixtures, snapshot_transforms = _validate_snapshots(loaded["snapshots"])
    history_fixtures, history_transforms = _validate_histories(loaded["histories"])
    fixture_ids = snapshot_fixtures | history_fixtures
    declared_snapshot_ids = snapshot_fixtures | snapshot_transforms
    declared_history_ids = history_fixtures | history_transforms
    if len(fixture_ids) != 124 or declared_snapshot_ids & declared_history_ids:
        _reject("counts")
    source_root_fd = _open_directory(repository)
    try:
        validator_ids = _validate_validators(
            loaded["validators"], fixture_ids, loaded["core"], source_root_fd
        )
    finally:
        os.close(source_root_fd)
    if fixture_ids & validator_ids:
        _reject("validator-bijection")
    _validate_canonical_baselines(
        loaded["snapshots"], loaded["histories"], loaded["validators"]
    )
    _validate_manifest_authority(
        loaded["snapshots"], loaded["histories"], loaded["validators"]
    )
    _validate_transform_schema_prerequisites(
        loaded["snapshots"], loaded["histories"], loaded["validators"]
    )
    focused_rows = (
        len(loaded["snapshots"]["focused_expected_tuples"])
        + len(loaded["histories"]["focused_expected_tuples"])
    )
    focused_invocations = focused_rows * 3
    if focused_rows != COUNTS["focused_rows"] or focused_invocations != COUNTS["focused_invocations"]:
        _reject("focused")
    if hashlib.sha256(index_raw).hexdigest() != CANONICAL_ROOT_SHA256:
        _reject("root")
    return RegistrySummary(
        len(snapshot_fixtures), len(history_fixtures), len(validator_ids),
        focused_invocations,
    )
