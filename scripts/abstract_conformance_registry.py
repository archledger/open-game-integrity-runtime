"""Admitted Task 2 view of the M1-013 planning registry."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

import m1_013_plan_registry as planning


@dataclass(frozen=True)
class LoaderCase:
    identifier: str
    operation: str
    baseline: str
    transform: str
    checkpoint: str
    disposition: str


@dataclass(frozen=True)
class Task2Authority:
    core: dict[str, Any]
    snapshots: dict[str, Any]
    histories: dict[str, Any]
    validators: dict[str, Any]
    loader_cases: tuple[LoaderCase, ...]
    loader_transforms: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class Task3Authority:
    core: dict[str, Any]
    attack_cases: tuple[LoaderCase, ...]
    attack_transforms: dict[str, dict[str, Any]]
    attack_baseline: dict[str, Any]
    attack_expectations: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class Task4Authority:
    core: dict[str, Any]
    snapshots: dict[str, Any]
    histories: dict[str, Any]
    validators: dict[str, Any]
    corpus_cases: tuple[LoaderCase, ...]
    corpus_transforms: dict[str, dict[str, Any]]
    executable_transforms: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class FixtureCase:
    identifier: str
    kind: str
    path: str
    baseline: str
    transform: str
    checkpoint: str
    disposition: str


@dataclass(frozen=True)
class Task5Authority:
    core: dict[str, Any]
    validators: dict[str, Any]
    manifest: dict[str, Any]
    fixture_cases: tuple[FixtureCase, ...]
    baselines: dict[str, dict[str, Any]]
    transforms: dict[str, dict[str, Any]]
    executable_transforms: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class Task6Authority:
    core: dict[str, Any]
    snapshots: dict[str, Any]
    validators: dict[str, Any]
    manifest: dict[str, Any]
    snapshot_cases: tuple[FixtureCase, ...]
    focused_rows: tuple[tuple[str, str, str, str], ...]
    baselines: dict[str, dict[str, Any]]
    transforms: dict[str, dict[str, Any]]
    retained_history_cases: tuple[FixtureCase, ...]
    retained_history_baselines: dict[str, dict[str, Any]]
    retained_history_transforms: dict[str, dict[str, Any]]
    executable_transforms: dict[str, dict[str, Any]]


def load_task2_authority() -> Task2Authority:
    """Load only hash-admitted JSON authority after the planning gate succeeds."""
    planning.validate_registry()
    root_fd = planning._open_directory(planning.ROOT)
    try:
        index, index_raw = planning._load_relative(
            root_fd, str(planning.DEFAULT_REGISTRY.relative_to(planning.ROOT))
        )
        if hashlib.sha256(index_raw).hexdigest() != planning.CANONICAL_ROOT_SHA256:
            raise planning.RegistryError("root")
        shard_fd = planning._open_relative_directory(
            root_fd, "docs/superpowers/plans/m1-013-format-v1"
        )
        try:
            initial_state = planning._directory_state(shard_fd)
            actual_files = planning._list_directory(shard_fd)
            loaded: dict[str, dict[str, Any]] = {}
            for entry in index["shards"]:
                value, raw = planning._load_relative(
                    shard_fd, entry["path"].rsplit("/", 1)[-1]
                )
                if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
                    raise planning.RegistryError("hash")
                loaded[entry["name"]] = value
            if (
                planning._list_directory(shard_fd) != actual_files
                or planning._directory_state(shard_fd) != initial_state
            ):
                raise planning.RegistryError("file")
        finally:
            os.close(shard_fd)
    finally:
        os.close(root_fd)
    cases = tuple(
        LoaderCase(*row)
        for row in loaded["validators"]["validator_cases"]
        if row[1] == "loader-probe"
    )
    transforms = {
        case.identifier: loaded["validators"]["validator_transforms"][case.transform]
        for case in cases
    }
    return Task2Authority(
        loaded["core"],
        loaded["snapshots"],
        loaded["histories"],
        loaded["validators"],
        cases,
        transforms,
    )


def exact_equivalence_classes(authority: Task2Authority) -> tuple[tuple[str, ...], ...]:
    """Return duplicate effective probe classes in registry order."""
    groups: dict[str, list[str]] = {}
    for case in authority.loader_cases:
        probe = authority.loader_transforms[case.identifier]["ast"]["steps"][-1]
        key = json.dumps(
            [probe["adapter"], probe["input"], case.checkpoint, case.disposition],
            sort_keys=True,
            separators=(",", ":"),
        )
        groups.setdefault(key, []).append(case.identifier)
    return tuple(tuple(group) for group in groups.values() if len(group) > 1)


def load_task3_authority() -> Task3Authority:
    authority = load_task2_authority()
    validators = authority.validators
    cases = tuple(
        LoaderCase(*row)
        for row in validators["validator_cases"]
        if row[1] == "attack-loader-parity"
    )
    return Task3Authority(
        authority.core,
        cases,
        {
            case.identifier: validators["validator_transforms"][case.transform]
            for case in cases
        },
        validators["validator_baselines"]["baseline-attack-repository"]["ast"][
            "value"
        ],
        validators["attack_parity_expectations"]["by_case_id"],
    )


def load_task4_authority() -> Task4Authority:
    """Load the hash-admitted data needed by the layer-1 corpus validator."""
    task2 = load_task2_authority()
    cases = tuple(
        LoaderCase(*row)
        for row in task2.validators["validator_cases"]
        if row[1] == "corpus-mutation"
    )
    return Task4Authority(
        task2.core,
        task2.snapshots,
        task2.histories,
        task2.validators,
        cases,
        {
            case.identifier: task2.validators["validator_transforms"][case.transform]
            for case in cases
        },
        dict(task2.validators["validator_transforms"]),
    )


def load_task5_authority() -> Task5Authority:
    """Load the admitted baselines and transforms for layers 2 and 3."""
    task4 = load_task4_authority()
    manifest = task4.validators["validator_baselines"]["baseline-corpus-v1"][
        "ast"
    ]["value"]
    cases = tuple(
        FixtureCase(*row)
        for row in manifest["fixtures"]
        if row[5] in {"layer-2", "layer-3"}
    )
    snapshot_baselines = {
        row["id"]: row["envelope"] for row in task4.snapshots["baselines"]
    }
    history_baselines = {
        row["id"]: {
            "format_version": task4.histories["format_version"],
            "kind": "history",
            "candidate": row["candidate"],
            "oracle": row["oracle"],
        }
        for row in task4.histories["baselines"]
    }
    snapshot_transforms = {
        row["id"]: row for row in task4.snapshots["transforms"]
    }
    history_transforms = {
        row["id"]: row for row in task4.histories["negative_transforms"]
    }
    return Task5Authority(
        task4.core,
        task4.validators,
        copy.deepcopy(manifest),
        cases,
        snapshot_baselines | history_baselines,
        snapshot_transforms | history_transforms,
        task4.executable_transforms,
    )


def load_task6_authority() -> Task6Authority:
    """Load the admitted snapshot corpus and focused-oracle rows."""
    task4 = load_task4_authority()
    manifest = task4.validators["validator_baselines"]["baseline-corpus-v1"][
        "ast"
    ]["value"]
    snapshot_cases = tuple(
        FixtureCase(*row) for row in manifest["fixtures"] if row[1] == "snapshot"
    )
    task5 = load_task5_authority()
    return Task6Authority(
        copy.deepcopy(task4.core),
        copy.deepcopy(task4.snapshots),
        copy.deepcopy(task4.validators),
        copy.deepcopy(manifest),
        snapshot_cases,
        tuple(tuple(row) for row in task4.snapshots["focused_expected_tuples"]),
        {
            row["id"]: copy.deepcopy(row["envelope"])
            for row in task4.snapshots["baselines"]
        },
        {
            row["id"]: copy.deepcopy(row)
            for row in task4.snapshots["transforms"]
        },
        tuple(case for case in task5.fixture_cases if case.kind == "history"),
        {
            case.baseline: copy.deepcopy(task5.baselines[case.baseline])
            for case in task5.fixture_cases
            if case.kind == "history"
        },
        {
            case.transform: copy.deepcopy(task5.transforms[case.transform])
            for case in task5.fixture_cases
            if case.kind == "history"
        },
        copy.deepcopy(task4.executable_transforms),
    )
