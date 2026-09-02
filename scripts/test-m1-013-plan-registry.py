#!/usr/bin/env python3
"""Black-box regression tests for the sharded M1-013 planning registry."""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check-m1-013-plan-registry.py"
REGISTRY = ROOT / "docs/superpowers/plans/2026-09-02-m1-013-format-v1-registry.json"
SHARD_DIRECTORY = ROOT / "docs/superpowers/plans/m1-013-format-v1"
sys.path.insert(0, str(ROOT))
registry_module = importlib.import_module("scripts.m1_013_plan_registry")

EXPECTED_HISTORY_FOCUSED_TUPLES = [
    ["open-before-challenge-receipt", "Conform", "Conform", "EvidenceInvalid"],
    ["proof-before-snapshot-freeze", "Conform", "Conform", "EvidenceInvalid"],
    ["change-after-snapshot-freeze", "Conform", "Conform", "EvidenceInvalid"],
    ["substitute-covered-challenge", "ContextBindingMismatch", "Conform", "Conform"],
    ["reuse-collection-sequence", "Conform", "Conform", "ProtectedSessionLost"],
    ["decrease-collection-sequence", "Conform", "Conform", "ProtectedSessionLost"],
    ["change-protected-epoch", "Conform", "Conform", "ProtectedSessionLost"],
    ["change-protected-source", "Conform", "Conform", "ProtectedSessionLost"],
    ["restart-collection-authority", "Conform", "Conform", "ProtectedSessionLost"],
    ["restart-protected-source", "Conform", "Conform", "ProtectedSessionLost"],
    ["restart-protected-session", "Conform", "Conform", "ProtectedSessionLost"],
    ["discontinue-protected-source", "Conform", "Conform", "ProtectedSessionLost"],
    ["rollback-protected-source", "Conform", "Conform", "ProtectedSessionLost"],
    ["open-concurrent-collection", "Conform", "Conform", "EvidenceInvalid"],
    ["overlap-collection-interval", "Conform", "Conform", "ProtectedSessionLost"],
    ["race-temporal-compare-and-advance", "Conform", "Conform", "ProtectedSessionLost"],
    ["order-start-after-freeze-end", "Conform", "Conform", "ProtectedSessionLost"],
    ["exceed-profile-duration-ceiling", "Conform", "Conform", "EvidenceInvalid"],
    ["exceed-publisher-duration-ceiling", "Conform", "Conform", "EvidenceInvalid"],
    ["receive-at-challenge-expiry", "Conform", "Conform", "Expired"],
    ["receive-after-challenge-expiry", "Conform", "Conform", "Expired"],
    ["omit-cached-current-subject-revalidation", "Conform", "Conform", "EvidenceInvalid"],
    ["omit-boot-origin-current-subject-revalidation", "Conform", "Conform", "EvidenceInvalid"],
    ["outage-collection-authority", "Conform", "Conform", "AttestationUnavailable"],
    ["outage-temporal-store", "Conform", "Conform", "AttestationUnavailable"],
    ["repair-high-water-from-client", "Conform", "Conform", "ProtectedSessionLost"],
    ["remove-temporal-high-water", "Conform", "Conform", "ProtectedSessionLost"],
    ["corrupt-temporal-high-water", "Conform", "Conform", "ProtectedSessionLost"],
    ["contradict-temporal-high-water", "Conform", "Conform", "ProtectedSessionLost"],
    ["rollback-temporal-high-water", "Conform", "Conform", "ProtectedSessionLost"],
    ["reject-claim-after-temporal-advance", "Conform", "Conform", "EvidenceInvalid"],
    ["reject-policy-after-temporal-advance", "Conform", "Conform", "PolicyDenied"],
    ["invalidate-abstract-coverage", "Conform", "EvidenceInvalid", "Conform"],
    ["unauthenticate-authority-statement", "Conform", "EvidenceInvalid", "Conform"],
    ["reset-sequence-on-profile-transition", "Conform", "Conform", "ProtectedSessionLost"],
    ["omit-terminal-temporal-deletion", "Conform", "Conform", "EvidenceInvalid"],
    ["reuse-ended-session-epoch", "Conform", "Conform", "ProtectedSessionLost"],
    ["substitute-ended-epoch-in-new-session", "Conform", "Conform", "ProtectedSessionLost"],
    ["reuse-key-after-terminal", "Conform", "Conform", "ProtectedSessionLost"],
    ["weaken-policy-with-same-key", "Conform", "Conform", "PolicyDenied"],
]

DIAGNOSTIC_FIELDS = {
    "closed_pairs",
    "unknown_pairs_forbidden",
    "rendered_pairs_only",
    "line_column_for_conformance",
    "candidate_labels_allowed",
    "absolute_paths_allowed",
    "raw_candidate_values_allowed",
    "control_characters_allowed",
    "ci_command_fragments_allowed",
    "tracebacks_allowed",
}

PLANNING_CONSTRAINT_FIELDS = {
    "fixture_data_synthetic_only",
    "real_biometrics_forbidden",
    "real_attestation_identities_forbidden",
    "private_keys_forbidden",
    "runtime_type_selected",
    "production_parser_selected",
    "production_schema_selected",
    "wire_representation_selected",
    "canonical_encoding_selected",
    "cryptographic_mechanism_selected",
    "tpm_mapping_selected",
    "persistence_mechanism_selected",
    "production_resource_limits_selected",
    "passing_checker_authorizes_implementation",
}


def run_checker(path: Path = REGISTRY) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--registry", str(path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def run_checker_without_capability(capability: str) -> subprocess.CompletedProcess[str]:
    attribute = "supports_dir_fd" if capability == "dir_fd" else capability
    replacement = "frozenset()" if capability == "dir_fd" else "None"
    script = (
        "import os, runpy, sys, unittest.mock; "
        f"sys.path.insert(0, {str(CHECKER.parent)!r}); "
        f"namespace = runpy.run_path({str(CHECKER)!r}); "
        f"parser = namespace['argparse'].ArgumentParser(description=namespace['__doc__']); "
        "parser.add_argument('--registry', type=namespace['Path'], default=namespace['DEFAULT_REGISTRY']); "
        f"arguments = parser.parse_args(['--registry', {str(REGISTRY)!r}])\n"
        f"with unittest.mock.patch.object(os, {attribute!r}, {replacement}):\n"
        " try:\n"
        "  namespace['validate_registry'](arguments.registry)\n"
        " except namespace['RegistryError'] as error:\n"
        "  print(f'M1-013 plan registry invalid: {error.code}', file=sys.stderr); raise SystemExit(1)\n"
        " except Exception:\n"
        "  print('M1-013 plan registry invalid: internal', file=sys.stderr); raise SystemExit(1)\n"
        "raise SystemExit(0)"
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def run_checker_with_capability_value(
    capability: str, value: Any, path: Path = REGISTRY
) -> subprocess.CompletedProcess[str]:
    script = (
        "import os, runpy, sys, unittest.mock; "
        f"sys.path.insert(0, {str(CHECKER.parent)!r}); "
        f"namespace = runpy.run_path({str(CHECKER)!r}); "
        f"parser = namespace['argparse'].ArgumentParser(description=namespace['__doc__']); "
        "parser.add_argument('--registry', type=namespace['Path'], default=namespace['DEFAULT_REGISTRY']); "
        f"arguments = parser.parse_args(['--registry', {str(path)!r}])\n"
        f"with unittest.mock.patch.object(os, {capability!r}, {value!r}):\n"
        " try:\n"
        "  namespace['validate_registry'](arguments.registry)\n"
        " except namespace['RegistryError'] as error:\n"
        "  print(f'M1-013 plan registry invalid: {error.code}', file=sys.stderr); raise SystemExit(1)\n"
        " except Exception:\n"
        "  print('M1-013 plan registry invalid: internal', file=sys.stderr); raise SystemExit(1)\n"
        "raise SystemExit(0)"
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def run_checker_with_post_inventory_change(
    path: Path, relative_directory: str, mutation: str
) -> subprocess.CompletedProcess[str]:
    repository = path.parent
    script = f"""
import pathlib
import os
import shutil
import sys
import unittest.mock

sys.path.insert(0, {str(ROOT)!r})
from scripts import m1_013_plan_registry as registry

repository = pathlib.Path({str(repository)!r})
target_relative = {relative_directory!r}
mutation = {mutation!r}
target = repository / target_relative
expected_entries = {{entry.name for entry in target.iterdir()}}
original = os.listdir
changed = False

def enumerate_then_change(directory_fd):
    global changed
    entries = original(directory_fd)
    if set(entries) == expected_entries and not changed:
        changed = True
        if mutation == "late-file":
            (target / "late-extra.scenario.json").write_bytes(b"{{}}")
        elif mutation == "replace-directory":
            displaced = target.with_name(target.name + "-enumerated")
            target.rename(displaced)
            shutil.copytree(displaced, target)
            (target / "late-extra.scenario.json").write_bytes(b"{{}}")
    return entries

with unittest.mock.patch.object(os, "listdir", enumerate_then_change):
    try:
        summary = registry.validate_registry(pathlib.Path({str(path)!r}))
    except registry.RegistryError as error:
        print(f"M1-013 plan registry invalid: {{error.code}}", file=sys.stderr)
        raise SystemExit(1)
    except Exception:
        print("M1-013 plan registry invalid: internal", file=sys.stderr)
        raise SystemExit(1)
print(
    f"M1-013 plan registry valid: {{summary.snapshots}} snapshots, "
    f"{{summary.histories}} histories, {{summary.validator_cases}} validator cases, "
    f"{{summary.focused_invocations}} focused invocations."
)
"""
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def run_checker_with_in_place_read_mutation(
    path: Path, target_relative: str
) -> subprocess.CompletedProcess[str]:
    target = path.parent / target_relative
    script = f"""
import os
import pathlib
import stat
import sys
import unittest.mock

sys.path.insert(0, {str(ROOT)!r})
from scripts import m1_013_plan_registry as registry

target = pathlib.Path({str(target)!r})
target_state = target.stat()
target_fd = None
changed = False
original = os.fstat

def mutate_before_final_fstat(file_fd):
    global changed, target_fd
    if file_fd == target_fd and not changed:
        with target.open("r+b") as stream:
            first = stream.read(1)
            stream.seek(0)
            stream.write(b"!" if first != b"!" else b"?")
            stream.flush()
            os.fsync(stream.fileno())
        changed = True
    state = original(file_fd)
    if (
        target_fd is None
        and stat.S_ISREG(state.st_mode)
        and (state.st_dev, state.st_ino) == (target_state.st_dev, target_state.st_ino)
    ):
        target_fd = file_fd
    return state

with unittest.mock.patch.object(os, "fstat", mutate_before_final_fstat):
    try:
        summary = registry.validate_registry(pathlib.Path({str(path)!r}))
    except registry.RegistryError as error:
        print(f"M1-013 plan registry invalid: {{error.code}}", file=sys.stderr)
        raise SystemExit(1)
    except Exception:
        print("M1-013 plan registry invalid: internal", file=sys.stderr)
        raise SystemExit(1)
print(
    f"M1-013 plan registry valid: {{summary.snapshots}} snapshots, "
    f"{{summary.histories}} histories, {{summary.validator_cases}} validator cases, "
    f"{{summary.focused_invocations}} focused invocations."
)
"""
    return subprocess.run(
        [sys.executable, "-B", "-c", script],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def git_blob_sha1(raw: bytes) -> str:
    header = f"blob {len(raw)}\0".encode("ascii")
    return hashlib.sha1(header + raw).hexdigest()


def copy_isolated_repository(destination: Path) -> Path:
    registry = destination / "registry.json"
    shutil.copyfile(REGISTRY, registry)
    index = json.loads(REGISTRY.read_text(encoding="utf-8"))
    for entry in index["shards"]:
        target = destination / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / entry["path"], target)

    validators = json.loads(
        (SHARD_DIRECTORY / "validators.json").read_text(encoding="utf-8")
    )
    bindings = validators["source_bindings"]
    paths = [
        bindings["attack_checker"]["path"],
        bindings["attack_schema"]["path"],
        *(row["path"] for row in bindings["attack_scenarios"]["files"]),
    ]
    for relative in paths:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    return registry


def rewrite_isolated_validators(
    repository: Path, mutate: Callable[[dict[str, Any]], None]
) -> None:
    registry = repository / "registry.json"
    index = json.loads(registry.read_text(encoding="utf-8"))
    entry = next(row for row in index["shards"] if row["name"] == "validators")
    validators_path = repository / entry["path"]
    validators = json.loads(validators_path.read_text(encoding="utf-8"))
    mutate(validators)
    raw = json.dumps(validators, separators=(",", ":")).encode("utf-8")
    validators_path.write_bytes(raw)
    entry["sha256"] = hashlib.sha256(raw).hexdigest()
    registry.write_text(json.dumps(index), encoding="utf-8")


def ast_nodes(value: Any, node_name: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if value.get("node") == node_name:
            found.append(value)
        for child in value.values():
            found.extend(ast_nodes(child, node_name))
    elif isinstance(value, list):
        for child in value:
            found.extend(ast_nodes(child, node_name))
    return found


class PlanRegistryTests(unittest.TestCase):
    def assert_rejected(
        self,
        code: str,
        *,
        root_mutation: Callable[[dict[str, Any]], None] | None = None,
        shard: str | None = None,
        shard_mutation: Callable[[dict[str, Any]], None] | None = None,
        shard_mutations: dict[str, Callable[[dict[str, Any]], None]] | None = None,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            temporary_registry = copy_isolated_repository(temporary_root)
            index = json.loads(temporary_registry.read_text(encoding="utf-8"))

            mutations = dict(shard_mutations or {})
            if shard is not None:
                if shard_mutation is None:
                    raise AssertionError("shard mutation is required")
                mutations[shard] = shard_mutation
            for shard_name, mutate in mutations.items():
                entry = next(
                    item for item in index["shards"] if item["name"] == shard_name
                )
                shard_path = temporary_root / entry["path"]
                document = json.loads(shard_path.read_text(encoding="utf-8"))
                mutate(document)
                raw = json.dumps(document, separators=(",", ":")).encode("utf-8")
                shard_path.write_bytes(raw)
                entry["sha256"] = hashlib.sha256(raw).hexdigest()
            if root_mutation is not None:
                root_mutation(index)
            temporary_registry.write_text(json.dumps(index), encoding="utf-8")

            result = run_checker(temporary_registry)

        self.assertEqual(result.returncode, 1, result)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, f"M1-013 plan registry invalid: {code}\n")

    def test_canonical_sharded_registry_reports_planning_counts_only(self) -> None:
        result = run_checker()

        self.assertEqual(result.returncode, 0, result)
        self.assertEqual(result.stderr, "")
        self.assertEqual(
            result.stdout,
            "M1-013 plan registry valid: 69 snapshots, 55 histories, "
            "202 validator cases, 294 focused invocations.\n",
        )

    def test_root_index_rejects_shape_path_and_hash_drift(self) -> None:
        self.assert_rejected("root")
        self.assert_rejected("index", root_mutation=lambda root: root.__setitem__("extra", 1))
        self.assert_rejected(
            "index",
            root_mutation=lambda root: root["shards"][1].__setitem__(
                "path", "docs/superpowers/plans/m1-013-format-v1/other.json"
            ),
        )
        self.assert_rejected(
            "hash",
            root_mutation=lambda root: root["shards"][2].__setitem__("sha256", "0" * 64),
        )

    def test_core_rejects_bootstrap_count_and_operation_contract_drift(self) -> None:
        self.assert_rejected(
            "bootstrap",
            shard="core",
            shard_mutation=lambda core: core["checker_bootstrap"]["limits"].__setitem__(
                "bytes_per_file", 524289
            ),
        )
        self.assert_rejected(
            "counts",
            shard="core",
            shard_mutation=lambda core: core["counts"].__setitem__("fixtures", 123),
        )
        self.assert_rejected(
            "operations",
            shard="core",
            shard_mutation=lambda core: core["operation_charging"].__setitem__(
                "operation_vectors_required", True
            ),
        )

    def test_security_critical_planning_boundaries_are_fixed(self) -> None:
        self.assert_rejected(
            "core",
            shard="core",
            shard_mutation=lambda core: core.__setitem__(
                "production_choices_authorized", True
            ),
        )
        self.assert_rejected(
            "core",
            shard="core",
            shard_mutation=lambda core: core["diagnostics"].__setitem__(
                "raw_candidate_values_allowed", True
            ),
        )
        self.assert_rejected(
            "history",
            shard="histories",
            shard_mutation=lambda histories: histories["separation"].__setitem__(
                "candidate_supplies_oracle", True
            ),
        )
        self.assert_rejected(
            "history",
            shard="histories",
            shard_mutation=lambda histories: histories["interpreter"][
                "guard_operators"
            ].__setitem__("eq", "candidate-selected comparison"),
        )

    def test_complete_closed_core_security_dictionaries_are_authoritative(self) -> None:
        core = json.loads((SHARD_DIRECTORY / "core.json").read_text(encoding="utf-8"))
        self.assertEqual(set(core["diagnostics"]), DIAGNOSTIC_FIELDS)
        self.assertEqual(
            set(core["planning_constraints"]), PLANNING_CONSTRAINT_FIELDS
        )

        for dictionary, fields in (
            ("diagnostics", DIAGNOSTIC_FIELDS),
            ("planning_constraints", PLANNING_CONSTRAINT_FIELDS),
        ):
            for field in sorted(fields):
                def mutate(core, dictionary=dictionary, field=field) -> None:
                    value = core[dictionary][field]
                    if type(value) is bool:
                        core[dictionary][field] = not value
                    else:
                        value.append(["attacker-layer", "attacker-diagnostic"])

                with self.subTest(dictionary=dictionary, field=field):
                    self.assert_rejected(
                        "core", shard="core", shard_mutation=mutate
                    )

    def test_snapshot_transforms_reject_noop_and_oracle_target(self) -> None:
        def make_noop(snapshot) -> None:
            transform = snapshot["transforms"][1]
            transform["new"] = transform["old"]

        self.assert_rejected(
            "snapshot-transform", shard="snapshots", shard_mutation=make_noop
        )
        self.assert_rejected(
            "snapshot-transform",
            shard="snapshots",
            shard_mutation=lambda snapshot: snapshot["transforms"][1].__setitem__(
                "target_namespace", "oracle"
            ),
        )

    def test_candidate_snapshot_transform_pointer_stays_beneath_candidate(self) -> None:
        def mutate(snapshots) -> None:
            transform = snapshots["transforms"][1]
            transform["pointer"] = "/format_version"
            transform["old"] = {"type": "FormatVersion", "value": 1}
            transform["new"] = {"type": "FormatVersion", "value": 2}

        self.assert_rejected(
            "snapshot-transform", shard="snapshots", shard_mutation=mutate
        )

        boundary_cases = (
            ("before", '"candidate"', '"candidate" '),
            ("crossing", '"candidate":{', '"candidate":{},"candidate":{'),
            ("after", '"oracle":{', '"oracle":{},"oracle":{'),
        )
        for boundary, old, new in boundary_cases:
            def mutate_boundary(snapshots, old=old, new=new) -> None:
                transform = next(
                    row for row in snapshots["transforms"]
                    if row["operation"] == "byte-replace-once"
                )
                transform["old"]["value"] = old
                transform["new"]["value"] = new

            with self.subTest(boundary=boundary):
                self.assert_rejected(
                    "snapshot-transform",
                    shard="snapshots",
                    shard_mutation=mutate_boundary,
                )

    def test_history_transforms_references_and_reachability_are_checked(self) -> None:
        self.assert_rejected(
            "history-transform",
            shard="histories",
            shard_mutation=lambda histories: histories["negative_transforms"][0].__setitem__(
                "old", "wrong-precondition"
            ),
        )
        self.assert_rejected(
            "history-reference",
            shard="histories",
            shard_mutation=lambda histories: histories["baselines"][0]["candidate"][
                "actions"
            ][0]["args"].__setitem__(0, "c-missing"),
        )
        self.assert_rejected(
            "history-reachability",
            shard="histories",
            shard_mutation=lambda histories: histories["reachability"].pop("restart"),
        )

        def add_candidate_deletion_argument(histories) -> None:
            baseline = next(
                row for row in histories["baselines"]
                if row["id"] == "history-valid-terminal-end-deletion"
            )
            action = next(
                row for row in baseline["candidate"]["actions"]
                if row["label"] == "deletion"
            )
            action["args"].append("c-missing")
            transform = next(
                row for row in histories["negative_transforms"]
                if row["id"] == "omit-terminal-temporal-deletion"
            )
            transform["old"]["args"].append("c-missing")

        def add_candidate_policy_argument(histories) -> None:
            transform = next(
                row for row in histories["negative_transforms"]
                if row["id"] == "reject-policy-after-temporal-advance"
            )
            transform["value"]["args"].append("policy-missing")

        for action, mutate in (
            ("deletion", add_candidate_deletion_argument),
            ("policy-rejection", add_candidate_policy_argument),
        ):
            with self.subTest(namespace="candidate", action=action):
                self.assert_rejected(
                    "history-reference", shard="histories", shard_mutation=mutate
                )

    def test_schema_references_and_cardinalities_are_checked(self) -> None:
        self.assert_rejected(
            "schema",
            shard="validators",
            shard_mutation=lambda validators: validators["schemas"]["Manifest"][
                "properties"
            ]["counts"].__setitem__("ref", "MissingSchema"),
        )
        self.assert_rejected(
            "schema",
            shard="validators",
            shard_mutation=lambda validators: validators["schemas"]["Manifest"][
                "properties"
            ]["fixtures"].__setitem__("min_items", 125),
        )

    def test_literal_coverage_and_focused_counts_are_checked(self) -> None:
        self.assert_rejected(
            "coverage",
            shard="validators",
            shard_mutation=lambda validators: validators["coverage"].__setitem__(
                "requirement-claim-order", "not-a-literal-array"
            ),
        )
        self.assert_rejected(
            "focused",
            shard="snapshots",
            shard_mutation=lambda snapshots: snapshots["focused_expected_tuples"].pop(),
        )

    def test_every_snapshot_focused_result_field_is_authoritative(self) -> None:
        replacements = {
            "Conform": "Malformed",
            "Malformed": "Conform",
            "Unsupported": "Conform",
            "ContextBindingMismatch": "Conform",
            "EvidenceInvalid": "Conform",
            "Expired": "Conform",
            "AttestationUnavailable": "Conform",
            "ProtectedSessionLost": "Conform",
            "PolicyDenied": "Conform",
        }
        for row_index in range(58):
            for result_index in range(4):
                def mutate(snapshots, row_index=row_index, result_index=result_index) -> None:
                    row = snapshots["focused_expected_tuples"][row_index]
                    if result_index == 0:
                        row[result_index] = f"{row[result_index]}-renamed"
                    else:
                        row[result_index] = replacements[row[result_index]]

                with self.subTest(row=row_index, result=result_index):
                    self.assert_rejected(
                        "focused", shard="snapshots", shard_mutation=mutate
                    )

    def test_every_history_focused_tuple_field_is_authoritative(self) -> None:
        dispositions = {
            "Conform": "EvidenceInvalid",
            "Malformed": "Conform",
            "Unsupported": "Conform",
            "ContextBindingMismatch": "Conform",
            "EvidenceInvalid": "Conform",
            "Expired": "Conform",
            "AttestationUnavailable": "Conform",
            "ProtectedSessionLost": "Conform",
            "PolicyDenied": "Conform",
        }
        next_layer = {"layer-4": "layer-5", "layer-5": "layer-6", "layer-6": "layer-4"}
        canonical = json.loads(
            (SHARD_DIRECTORY / "histories.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            canonical["focused_expected_tuples"], EXPECTED_HISTORY_FOCUSED_TUPLES
        )
        for row_index in range(40):
            for field_index in range(4):
                def mutate(histories, row_index=row_index, field_index=field_index) -> None:
                    row = histories["focused_expected_tuples"][row_index]
                    if field_index == 0:
                        row[0] = f"{row[0]}-renamed"
                    else:
                        row[field_index] = dispositions[row[field_index]]

                with self.subTest(row=row_index, field=field_index):
                    self.assert_rejected(
                        "focused", shard="histories", shard_mutation=mutate
                    )

    def test_history_focused_vectors_reject_coherent_cross_shard_rewrite(self) -> None:
        def mutate_histories(histories) -> None:
            histories["focused_expected_tuples"][0][1:] = [
                "Conform", "EvidenceInvalid", "Conform"
            ]

        def mutate_validators(validators) -> None:
            manifest = validators["validator_baselines"]["baseline-corpus-v1"][
                "ast"
            ]["value"]
            fixture = next(
                row for row in manifest["fixtures"]
                if row[4] == "open-before-challenge-receipt"
            )
            fixture[5:] = ["layer-5", "EvidenceInvalid"]

        self.assert_rejected(
            "focused",
            shard_mutations={
                "histories": mutate_histories,
                "validators": mutate_validators,
            },
        )

    def test_all_history_focused_rows_are_explicit_and_ordered(self) -> None:
        for focused_index in range(58, 98):
            def mutate(validators, focused_index=focused_index) -> None:
                validators["coverage"]["requirement-focused-oracles"][
                    focused_index
                ] = "history-client-utc-substitution"

            with self.subTest(row=focused_index - 58):
                self.assert_rejected(
                    "focused", shard="validators", shard_mutation=mutate
                )

    def test_post_transform_history_record_references_must_resolve(self) -> None:
        def mutate(histories) -> None:
            transform = next(
                item
                for item in histories["negative_transforms"]
                if item["id"] == "substitute-covered-challenge"
            )
            transform["value"] = "c-missing"

        self.assert_rejected(
            "history-reference", shard="histories", shard_mutation=mutate
        )

    def test_trusted_authority_session_reference_must_resolve(self) -> None:
        mutations = (
            ("observation_oracles", "challenge_ref", "t-missing"),
            ("observation_oracles", "collection_ref", "t-missing"),
            ("observation_oracles", "session_ref", "t-missing"),
            ("observation_oracles", "profile_id", "profile-missing"),
            ("trusted_authorities", "challenge_ref", "t-missing"),
            ("trusted_authorities", "session_ref", "t-missing"),
            ("trusted_authorities", "profile_id", "profile-missing"),
        )
        for registry, field, value in mutations:
            def mutate(histories, registry=registry, field=field, value=value) -> None:
                histories["baselines"][0]["oracle"][registry][0][field] = value

            with self.subTest(registry=registry, field=field):
                self.assert_rejected(
                    "history-reference", shard="histories", shard_mutation=mutate
                )

        def add_oracle_deletion_argument(histories) -> None:
            baseline = next(
                row for row in histories["baselines"]
                if row["id"] == "history-valid-terminal-end-deletion"
            )
            action = next(
                row for row in baseline["oracle"]["actions"]
                if row["label"] == "deletion"
            )
            action["args"].append("t-missing")

        def add_oracle_policy_argument(histories) -> None:
            baseline = next(
                row for row in histories["baselines"]
                if row["id"] == "history-valid-same-session-renewal"
            )
            baseline["oracle"]["actions"].append(
                {"label": "policy-rejection", "args": ["policy-missing"]}
            )

        for action, action_mutation in (
            ("deletion", add_oracle_deletion_argument),
            ("policy-rejection", add_oracle_policy_argument),
        ):
            with self.subTest(namespace="oracle", action=action):
                self.assert_rejected(
                    "history-reference",
                    shard="histories",
                    shard_mutation=action_mutation,
                )

    def test_validator_bijection_and_closed_ast_are_checked(self) -> None:
        self.assert_rejected(
            "validator-bijection",
            shard="validators",
            shard_mutation=lambda validators: validators["validator_transforms"].pop(
                "v1-corpus-canonical"
            ),
        )
        self.assert_rejected(
            "validator-ast",
            shard="validators",
            shard_mutation=lambda validators: validators["validator_transforms"][
                "v1-corpus-canonical"
            ]["ast"].__setitem__("unknown", True),
        )
        self.assert_rejected(
            "validator-ast",
            shard="validators",
            shard_mutation=lambda validators: validators["validator_baselines"][
                "baseline-corpus-v1"
            ]["ast"].__setitem__("unknown", True),
        )

        def break_reference(validators) -> None:
            ast = validators["validator_transforms"]["v1-corpus-canonical"]["ast"]
            reference = next(step for step in ast["steps"] if step["node"] == "ref")
            reference["pointer"] = "/missing"

        self.assert_rejected(
            "validator-ast", shard="validators", shard_mutation=break_reference
        )

    def test_probe_outcomes_cannot_be_coherently_rewritten(self) -> None:
        def mutate(validators) -> None:
            case = validators["validator_cases"][0]
            case[4] = "layer-2"
            case[5] = "Malformed"
            manifest_case = validators["validator_baselines"]["baseline-corpus-v1"][
                "ast"
            ]["value"]["validator_cases"][0]
            manifest_case[4] = "layer-2"
            manifest_case[5] = "Malformed"

        self.assert_rejected(
            "manifest", shard="validators", shard_mutation=mutate
        )

    def test_probe_nodes_reject_direct_checkpoint_and_disposition_fields(self) -> None:
        for field, value in (
            ("checkpoint", "layer-1"),
            ("disposition", "Conform"),
        ):
            def mutate(validators, field=field, value=value) -> None:
                ast = validators["validator_transforms"]["v1-corpus-canonical"]["ast"]
                probe = next(step for step in ast["steps"] if step["node"] == "probe")
                probe[field] = value

            with self.subTest(field=field):
                self.assert_rejected(
                    "validator-ast", shard="validators", shard_mutation=mutate
                )

    def test_validator_ast_rejects_outcome_assertions_outside_probe_nodes(self) -> None:
        for field in (
            "checkpoint", "disposition", "result", "expected", "expected_outcome",
            "expected_exit", "expected_stdout", "expected_stderr",
        ):
            def mutate(validators, field=field) -> None:
                ast = validators["validator_transforms"]["v1-corpus-canonical"]["ast"]
                ast["steps"].insert(1, {
                    "node": "literal",
                    "value": {"nested": {field: "attacker-selected-outcome"}},
                })

            with self.subTest(field=field):
                self.assert_rejected(
                    "validator-ast", shard="validators", shard_mutation=mutate
                )

    def test_validator_disposition_rejects_coherent_manifest_rewrite(self) -> None:
        def mutate(validators) -> None:
            validators["validator_cases"][1][5] = "Unsupported"
            manifest = validators["validator_baselines"]["baseline-corpus-v1"][
                "ast"
            ]["value"]
            manifest["validator_cases"][1][5] = "Unsupported"

        self.assert_rejected(
            "manifest", shard="validators", shard_mutation=mutate
        )

    def test_manifest_fixture_tuples_match_fixture_authority(self) -> None:
        mutations: dict[str, Callable[[list[Any], dict[str, Any]], None]] = {
            "id": lambda row, manifest: row.__setitem__(0, "fixture-renamed"),
            "kind": lambda row, manifest: row.__setitem__(1, "history"),
            "path": lambda row, manifest: row.__setitem__(
                2, "snapshots/other-valid-path.json"
            ),
            "baseline": lambda row, manifest: row.__setitem__(
                3, "valid-initial-extended-profile"
            ),
            "mutation": lambda row, manifest: row.__setitem__(
                4, "change-challenge-publisher"
            ),
            "layer": lambda row, manifest: row.__setitem__(5, "layer-3"),
            "disposition": lambda row, manifest: row.__setitem__(6, "Unsupported"),
        }
        for field, change in mutations.items():
            def mutate(validators, change=change, field=field) -> None:
                manifest = validators["validator_baselines"]["baseline-corpus-v1"][
                    "ast"
                ]["value"]
                row = manifest["fixtures"][3]
                old_id = row[0]
                change(row, manifest)
                if field == "id":
                    row[2] = f"snapshots/{row[0]}.json"
                    for values in manifest["coverage"].values():
                        for index, identifier in enumerate(values):
                            if identifier == old_id:
                                values[index] = row[0]

            with self.subTest(field=field):
                self.assert_rejected(
                    "manifest", shard="validators", shard_mutation=mutate
                )

    def test_manifest_validator_tuples_match_validator_authority(self) -> None:
        def mutate_operation(validators) -> None:
            manifest = validators["validator_baselines"]["baseline-corpus-v1"]["ast"]["value"]
            validators["validator_cases"][0][1] = "loader-probe"
            validators["validator_cases"][0][4] = "layer-2"
            manifest["validator_cases"][0][1] = "loader-probe"
            manifest["validator_cases"][0][4] = "layer-2"

        def mutate_checkpoint(validators) -> None:
            manifest = validators["validator_baselines"]["baseline-corpus-v1"]["ast"]["value"]
            validators["validator_cases"][0][4] = "layer-2"
            manifest["validator_cases"][0][4] = "layer-2"

        def mutate_disposition(validators) -> None:
            manifest = validators["validator_baselines"]["baseline-corpus-v1"]["ast"]["value"]
            validators["validator_cases"][0][5] = "Malformed"
            manifest["validator_cases"][0][5] = "Malformed"

        for field, mutate in (
            ("operation", mutate_operation),
            ("checkpoint", mutate_checkpoint),
            ("disposition", mutate_disposition),
        ):
            with self.subTest(field=field):
                self.assert_rejected(
                    "manifest", shard="validators", shard_mutation=mutate
                )

    def test_manifest_tags_and_ids_reject_coherent_drift(self) -> None:
        def mutate_tag(validators) -> None:
            manifest = validators["validator_baselines"]["baseline-corpus-v1"]["ast"]["value"]
            for coverage in (validators["coverage"], manifest["coverage"]):
                coverage["requirement-renamed"] = coverage.pop("requirement-claim-order")

        def mutate_id(validators) -> None:
            old = "v1-corpus-canonical"
            new = "v1-corpus-canonical-renamed"
            manifest = validators["validator_baselines"]["baseline-corpus-v1"]["ast"]["value"]
            for cases in (validators["validator_cases"], manifest["validator_cases"]):
                cases[0][0] = new
                cases[0][3] = new
            validators["validator_transforms"][new] = validators["validator_transforms"].pop(old)
            for coverage in (validators["coverage"], manifest["coverage"]):
                for values in coverage.values():
                    for index, identifier in enumerate(values):
                        if identifier == old:
                            values[index] = new

        for field, mutate in (("tag", mutate_tag), ("id", mutate_id)):
            with self.subTest(field=field):
                self.assert_rejected(
                    "manifest", shard="validators", shard_mutation=mutate
                )

    def test_canonical_baselines_are_validated_against_registered_schemas(self) -> None:
        mutations = {
            "snapshot": (
                "snapshots",
                lambda shard: shard["baselines"][0]["envelope"].__setitem__(
                    "format_version", "1"
                ),
            ),
            "history": (
                "histories",
                lambda shard: shard["baselines"][0]["oracle"]["initial_state"].pop(),
            ),
            "manifest": (
                "validators",
                lambda shard: shard["validator_baselines"]["baseline-corpus-v1"]["ast"][
                    "value"
                ].pop("counts"),
            ),
        }
        for baseline, (shard, mutate) in mutations.items():
            with self.subTest(baseline=baseline):
                self.assert_rejected(
                    "baseline-schema", shard=shard, shard_mutation=mutate
                )

    def test_fixture_path_schema_pins_component_byte_limit(self) -> None:
        validators = json.loads(
            (SHARD_DIRECTORY / "validators.json").read_text(encoding="utf-8")
        )

        self.assertEqual(
            validators["domains"]["FixturePath"].get("component_max_bytes"), 128
        )
        domains = validators["domains"]
        self.assertTrue(
            registry_module._validate_domain(f'{"a" * 128}/x.json', "FixturePath", domains)
        )
        self.assertFalse(
            registry_module._validate_domain(f'{"a" * 129}/x.json', "FixturePath", domains)
        )

    def test_core_paths_reject_coherent_drift(self) -> None:
        for field in (
            "corpus_manifest", "snapshot_prefix", "history_prefix", "fixture_suffix",
            "baseline_module", "loader_module", "validator_module", "validator_cli",
        ):
            def mutate(core, field=field) -> None:
                core["paths"][field] = f"changed/{field}"

            with self.subTest(path=field):
                self.assert_rejected("path", shard="core", shard_mutation=mutate)

    def test_source_bindings_reject_coherent_drift(self) -> None:
        mutations = {
            "checker-path": lambda bindings: bindings["attack_checker"].__setitem__(
                "path", "scripts/other.py"
            ),
            "checker-sha256": lambda bindings: bindings["attack_checker"].__setitem__(
                "sha256", "0" * 64
            ),
            "checker-blob": lambda bindings: bindings["attack_checker"].__setitem__(
                "git_blob", "0" * 40
            ),
            "schema-path": lambda bindings: bindings["attack_schema"].__setitem__(
                "path", "lab/scenarios/other.json"
            ),
            "scenario-glob": lambda bindings: bindings["attack_scenarios"].__setitem__(
                "glob", "lab/scenarios/*.json"
            ),
            "scenario-count": lambda bindings: bindings["attack_scenarios"].__setitem__(
                "count", 29
            ),
            "scenario-file": lambda bindings: bindings["attack_scenarios"]["files"][0].__setitem__(
                "path", "lab/scenarios/other.scenario.json"
            ),
            "scenario-hash": lambda bindings: bindings["attack_scenarios"]["files"][0].__setitem__(
                "sha256", "0" * 64
            ),
        }
        for field, change in mutations.items():
            def mutate(validators, change=change) -> None:
                change(validators["source_bindings"])

            with self.subTest(binding=field):
                self.assert_rejected(
                    "source-binding", shard="validators", shard_mutation=mutate
                )

    def test_all_negative_transforms_reach_their_declared_structural_layer(self) -> None:
        snapshots = json.loads(
            (SHARD_DIRECTORY / "snapshots.json").read_text(encoding="utf-8")
        )
        histories = json.loads(
            (SHARD_DIRECTORY / "histories.json").read_text(encoding="utf-8")
        )
        validators = json.loads(
            (SHARD_DIRECTORY / "validators.json").read_text(encoding="utf-8")
        )
        schemas, domains = validators["schemas"], validators["domains"]

        snapshot_baselines = {
            row["id"]: row["envelope"] for row in snapshots["baselines"]
        }
        for transform in snapshots["transforms"]:
            baseline = snapshot_baselines[transform["baseline"]]
            layer = transform["expected"]["layer"]
            if transform["operation"] == "byte-replace-once":
                raw = registry_module._serialize_snapshot(
                    baseline, transform["serialization_profile"]
                )
                old = transform["old"]["value"].encode("utf-8")
                new = transform["new"]["value"].encode("utf-8")
                with self.subTest(kind="snapshot", transform=transform["id"]):
                    self.assertEqual(layer, "layer-2")
                    self.assertEqual(raw.count(old), 1)
                    self.assertNotEqual(raw.replace(old, new, 1), raw)
                continue

            changed = registry_module._apply_json_operation(
                baseline,
                transform["operation"],
                transform["pointer"],
                registry_module._unwrap_typed(transform["old"]),
                registry_module._unwrap_typed(transform["new"]),
            )
            candidate_valid = registry_module._validate_candidate_schema(
                changed["candidate"], "SnapshotCandidate", validators
            )
            oracle_valid = registry_module._validate_typed_value(
                changed["oracle"], schemas["SnapshotOracle"], schemas, domains
            )
            envelope_valid = registry_module._validate_typed_value(
                changed, schemas["FixtureEnvelope"], schemas, domains
            )
            with self.subTest(kind="snapshot", transform=transform["id"], layer=layer):
                if layer == "layer-3":
                    self.assertFalse(candidate_valid)
                elif layer in {"layer-4", "layer-5", "layer-6"}:
                    self.assertTrue(candidate_valid)
                    self.assertTrue(oracle_valid)
                    self.assertTrue(envelope_valid)
                else:
                    self.fail(f"unexpected snapshot layer: {layer}")
                if transform["id"] == "duplicate-covered-semantic-element":
                    self.assertEqual(layer, "layer-5")
                    self.assertTrue(candidate_valid)

        manifest = validators["validator_baselines"]["baseline-corpus-v1"]["ast"][
            "value"
        ]
        layers_by_transform = {
            row[4]: row[5]
            for row in manifest["fixtures"]
            if row[1] == "history" and row[4] is not None
        }
        history_baselines = {row["id"]: row for row in histories["baselines"]}
        for transform in histories["negative_transforms"]:
            wrapped = copy.deepcopy(history_baselines[transform["baseline"]])
            if transform["operation"] == "insert":
                pointer = f'{transform["path"]}/{transform["index"]}'
                changed = registry_module._apply_json_operation(
                    wrapped, "insert", pointer, registry_module.ABSENT, transform["value"]
                )
            elif transform["operation"] == "remove":
                changed = registry_module._apply_json_operation(
                    wrapped,
                    "remove",
                    transform["path"],
                    transform["old"],
                    registry_module.ABSENT,
                )
            else:
                changed = registry_module._apply_json_operation(
                    wrapped,
                    "replace",
                    transform["path"],
                    transform["old"],
                    transform["value"],
                )
            layer = layers_by_transform[transform["id"]]
            candidate_valid = registry_module._validate_candidate_schema(
                changed["candidate"], "HistoryCandidate", validators
            )
            oracle_valid = registry_module._validate_typed_value(
                changed["oracle"], schemas["HistoryOracle"], schemas, domains
            )
            with self.subTest(kind="history", transform=transform["id"], layer=layer):
                if layer == "layer-3":
                    self.assertFalse(candidate_valid)
                elif layer in {"layer-4", "layer-5", "layer-6"}:
                    self.assertTrue(candidate_valid)
                    self.assertTrue(oracle_valid)
                else:
                    self.fail(f"unexpected history layer: {layer}")

    def test_bound_attack_checker_and_schema_files_are_verified(self) -> None:
        validators = json.loads(
            (SHARD_DIRECTORY / "validators.json").read_text(encoding="utf-8")
        )
        for binding_name in ("attack_checker", "attack_schema"):
            relative = validators["source_bindings"][binding_name]["path"]
            for mutation in ("missing", "changed", "symlink", "nonregular"):
                with self.subTest(binding=binding_name, mutation=mutation):
                    with tempfile.TemporaryDirectory() as directory:
                        repository = Path(directory)
                        registry = copy_isolated_repository(repository)
                        path = repository / relative
                        if mutation == "missing":
                            path.unlink()
                        elif mutation == "changed":
                            path.write_bytes(path.read_bytes() + b"\n")
                        elif mutation == "symlink":
                            backing = repository / f"{binding_name}-identical"
                            shutil.copyfile(path, backing)
                            path.unlink()
                            os.symlink(os.path.relpath(backing, path.parent), path)
                        else:
                            path.unlink()
                            path.mkdir()
                        result = run_checker(registry)

                    self.assertEqual(result.returncode, 1, result)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(
                        result.stderr, "M1-013 plan registry invalid: source-binding\n"
                    )

    def test_bound_scenario_inventory_and_files_are_verified(self) -> None:
        validators = json.loads(
            (SHARD_DIRECTORY / "validators.json").read_text(encoding="utf-8")
        )
        files = validators["source_bindings"]["attack_scenarios"]["files"]
        relative = files[0]["path"]
        for mutation in (
            "missing", "changed", "symlink", "nonregular", "extra", "wrong-inventory"
        ):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as directory:
                    repository = Path(directory)
                    registry = copy_isolated_repository(repository)
                    path = repository / relative
                    if mutation == "missing":
                        path.unlink()
                    elif mutation == "changed":
                        path.write_bytes(path.read_bytes() + b"\n")
                    elif mutation == "symlink":
                        backing = repository / "scenario-identical"
                        shutil.copyfile(path, backing)
                        path.unlink()
                        os.symlink(os.path.relpath(backing, path.parent), path)
                    elif mutation == "nonregular":
                        path.unlink()
                        path.mkdir()
                    elif mutation == "extra":
                        shutil.copyfile(path, path.parent / "extra.scenario.json")
                    else:
                        path.rename(path.parent / "wrong-inventory.scenario.json")
                    result = run_checker(registry)

                self.assertEqual(result.returncode, 1, result)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr, "M1-013 plan registry invalid: source-binding\n"
                )

    def test_shard_directory_is_stable_after_inventory_enumeration(self) -> None:
        relative_directory = "docs/superpowers/plans/m1-013-format-v1"
        for mutation in ("unchanged", "late-file", "replace-directory"):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as directory:
                    registry = copy_isolated_repository(Path(directory))
                    result = run_checker_with_post_inventory_change(
                        registry, relative_directory, mutation
                    )

                if mutation == "unchanged":
                    self.assertEqual(result.returncode, 0, result)
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(
                        result.stdout,
                        "M1-013 plan registry valid: 69 snapshots, 55 histories, "
                        "202 validator cases, 294 focused invocations.\n",
                    )
                else:
                    self.assertEqual(result.returncode, 1, result)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(
                        result.stderr, "M1-013 plan registry invalid: file\n"
                    )

    def test_scenario_directory_is_stable_after_inventory_enumeration(self) -> None:
        relative_directory = "lab/scenarios"
        for mutation in ("unchanged", "late-file", "replace-directory"):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as directory:
                    registry = copy_isolated_repository(Path(directory))
                    result = run_checker_with_post_inventory_change(
                        registry, relative_directory, mutation
                    )

                if mutation == "unchanged":
                    self.assertEqual(result.returncode, 0, result)
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(
                        result.stdout,
                        "M1-013 plan registry valid: 69 snapshots, 55 histories, "
                        "202 validator cases, 294 focused invocations.\n",
                    )
                else:
                    self.assertEqual(result.returncode, 1, result)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(
                        result.stderr,
                        "M1-013 plan registry invalid: source-binding\n",
                    )

    def test_same_size_in_place_changes_during_file_reads_are_rejected(self) -> None:
        validators = json.loads(
            (SHARD_DIRECTORY / "validators.json").read_text(encoding="utf-8")
        )
        targets = (
            ("root-index", "registry.json", "file"),
            ("shard", "docs/superpowers/plans/m1-013-format-v1/snapshots.json", "file"),
            (
                "attack-checker",
                validators["source_bindings"]["attack_checker"]["path"],
                "source-binding",
            ),
            (
                "attack-schema",
                validators["source_bindings"]["attack_schema"]["path"],
                "source-binding",
            ),
            (
                "scenario",
                validators["source_bindings"]["attack_scenarios"]["files"][0]["path"],
                "source-binding",
            ),
        )
        for kind, relative, diagnostic in targets:
            with self.subTest(kind=kind):
                with tempfile.TemporaryDirectory() as directory:
                    repository = Path(directory)
                    registry = copy_isolated_repository(repository)
                    target = repository / relative
                    before = target.read_bytes()
                    result = run_checker_with_in_place_read_mutation(registry, relative)
                    after = target.read_bytes()

                self.assertEqual(len(after), len(before))
                self.assertNotEqual(after, before)
                self.assertEqual(result.returncode, 1, result)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr, f"M1-013 plan registry invalid: {diagnostic}\n"
                )

    def test_bound_file_hashes_are_derived_from_actual_bytes(self) -> None:
        validators = json.loads(
            (SHARD_DIRECTORY / "validators.json").read_text(encoding="utf-8")
        )
        for binding_name, baseline_name in (
            ("attack_checker", "checker"), ("attack_schema", "schema")
        ):
            for update in ("sha256", "git-blob", "both"):
                with self.subTest(binding=binding_name, update=update):
                    with tempfile.TemporaryDirectory() as directory:
                        repository = Path(directory)
                        registry = copy_isolated_repository(repository)
                        relative = validators["source_bindings"][binding_name]["path"]
                        path = repository / relative
                        path.write_bytes(path.read_bytes() + b"\n")
                        raw = path.read_bytes()
                        digest = hashlib.sha256(raw).hexdigest()
                        blob = git_blob_sha1(raw)

                        def update_bindings(document) -> None:
                            declared = document["source_bindings"][binding_name]
                            baseline = document["validator_baselines"][
                                "baseline-attack-repository"
                            ]["ast"]["value"][baseline_name]
                            for authority in (declared, baseline):
                                if update in {"sha256", "both"}:
                                    authority["sha256"] = digest
                                if update in {"git-blob", "both"}:
                                    authority["git_blob"] = blob

                        rewrite_isolated_validators(repository, update_bindings)
                        result = run_checker(registry)

                    expected = "root" if update == "both" else "source-binding"
                    self.assertEqual(result.returncode, 1, result)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(
                        result.stderr, f"M1-013 plan registry invalid: {expected}\n"
                    )

    def test_every_fixed_resource_limit_rejects_coherent_drift(self) -> None:
        dimensions = (
            "bytes", "depth", "object_fields", "array_items", "string_characters",
            "object_key_characters", "number_token_characters", "total_nodes",
        )
        for scope in ("fixture", "manifest"):
            for dimension in dimensions:
                def mutate_dimension(core, scope=scope, dimension=dimension) -> None:
                    core["resource_limits"][scope][dimension] += 1

                with self.subTest(scope=scope, dimension=dimension):
                    self.assert_rejected(
                        "limits", shard="core", shard_mutation=mutate_dimension
                    )
        for field in ("wall_clock_seconds", "max_fixture_files"):
            def mutate_outer_limit(core, field=field) -> None:
                core["resource_limits"][field] += 1

            with self.subTest(limit=field):
                self.assert_rejected(
                    "limits", shard="core", shard_mutation=mutate_outer_limit
                )

    def test_every_fixed_bootstrap_limit_rejects_coherent_drift(self) -> None:
        for field in (
            "bytes_per_file", "depth", "object_fields", "array_items",
            "string_characters", "object_key_characters", "number_token_characters",
            "total_nodes_per_file", "shard_files",
        ):
            def mutate_bootstrap(core, field=field) -> None:
                core["checker_bootstrap"]["limits"][field] += 1

            with self.subTest(limit=field):
                self.assert_rejected(
                    "bootstrap", shard="core", shard_mutation=mutate_bootstrap
                )

    def test_aggregate_operation_evidence_is_absent_from_every_shard(self) -> None:
        self.assert_rejected(
            "operations",
            shard="validators",
            shard_mutation=lambda validators: validators["validator_baselines"][
                "baseline-json-object"
            ]["ast"]["value"].__setitem__("earliest_stop_total", 1),
        )

    def test_resource_constructor_products_and_non_target_bounds_are_checked(self) -> None:
        def corrupt_resource(validators) -> None:
            ast = validators["validator_transforms"][
                "v1-corpus-manifest-bytes-over-limit"
            ]["ast"]
            generate = ast_nodes(ast, "generate")[0]
            generate["parameters"]["dimension"] = "depth"

        self.assert_rejected(
            "resource-constructor",
            shard="validators",
            shard_mutation=corrupt_resource,
        )

    def test_all_parameterized_resource_constructor_products_are_supported(self) -> None:
        core = json.loads(
            (SHARD_DIRECTORY / "core.json").read_text(encoding="utf-8")
        )
        limits = core["resource_limits"]
        products = {
            (scope, dimension, relation)
            for scope in ("fixture", "manifest")
            for dimension in (
                "bytes", "depth", "object_fields", "array_items",
                "string_characters", "object_key_characters",
                "number_token_characters", "total_nodes",
            )
            for relation in ("exact", "over")
        }
        self.assertEqual(len(products), 32)
        for scope, dimension, relation in sorted(products):
            with self.subTest(scope=scope, dimension=dimension, relation=relation):
                value = registry_module._resource_value(
                    scope, dimension, relation, limits
                )
                registry_module._validate_resource_nodes(
                    [{
                        "node": "generate",
                        "constructor": "resource-boundary",
                        "parameters": {
                            "scope": scope,
                            "dimension": dimension,
                            "relation": relation,
                        },
                    }],
                    core,
                )
                self.assertEqual(
                    registry_module._metrics(value)[dimension],
                    limits[scope][dimension] + (relation == "over"),
                )
        self.assertIs(
            core["resource_constructors"].get(
                "validator_case_per_product_required"
            ),
            False,
        )

    def test_resource_constructor_contract_rejects_coherent_drift(self) -> None:
        dimension_names = {
            "bytes": "bytes", "depth": "depth", "object_fields": "object-fields",
            "array_items": "array-items", "string_characters": "string-characters",
            "object_key_characters": "object-key-characters",
            "number_token_characters": "number-token-characters",
            "total_nodes": "total-nodes",
        }

        def mutate_contract(core, category, mutation) -> None:
            contract = core["resource_constructors"]
            limits = core["resource_limits"]
            contract["validator_case_per_product_required"] = False
            if category == "scope":
                values = contract["scopes"]
                if mutation == "drift":
                    values[0] = "sample"
                    limits["sample"] = limits.pop("fixture")
                    contract["id_pattern"] = contract["id_pattern"].replace(
                        "fixture|manifest", "sample|manifest"
                    )
                elif mutation == "addition":
                    values.append("sample")
                    limits["sample"] = copy.deepcopy(limits["fixture"])
                    contract["id_pattern"] = contract["id_pattern"].replace(
                        "fixture|manifest", "fixture|manifest|sample"
                    )
                else:
                    values.remove("fixture")
                    limits.pop("fixture")
                    contract["id_pattern"] = contract["id_pattern"].replace(
                        "fixture|manifest", "manifest"
                    )
            elif category == "dimension":
                dimensions = limits["dimensions"]
                old, new = "bytes", "octets"
                if mutation == "drift":
                    dimensions[0] = new
                    for scope in contract["scopes"]:
                        limits[scope][new] = limits[scope].pop(old)
                    contract["id_pattern"] = contract["id_pattern"].replace(
                        dimension_names[old] + "|", new + "|"
                    )
                elif mutation == "addition":
                    dimensions.append(new)
                    for scope in contract["scopes"]:
                        limits[scope][new] = limits[scope][old]
                    contract["id_pattern"] = contract["id_pattern"].replace(
                        dimension_names[old] + "|", dimension_names[old] + "|" + new + "|"
                    )
                else:
                    dimensions.remove(old)
                    for scope in contract["scopes"]:
                        limits[scope].pop(old)
                    contract["id_pattern"] = contract["id_pattern"].replace(
                        dimension_names[old] + "|", ""
                    )
            elif category == "relation":
                relations = contract["relations"]
                if mutation == "drift":
                    relations["equal"] = relations.pop("exact")
                    contract["id_pattern"] = contract["id_pattern"].replace(
                        "exact|over", "equal|over"
                    )
                elif mutation == "addition":
                    relations["under"] = copy.deepcopy(relations["exact"])
                    contract["id_pattern"] = contract["id_pattern"].replace(
                        "exact|over", "exact|over|under"
                    )
                else:
                    relations.pop("exact")
                    contract["id_pattern"] = contract["id_pattern"].replace(
                        "exact|over", "over"
                    )
            elif mutation == "drift":
                contract["validator_case_per_product_required"] = True
            elif mutation == "addition":
                contract["manifest_exact_validator_cases_required"] = False
            else:
                contract.pop("validator_case_per_product_required")

        for category in ("scope", "dimension", "relation", "clarification"):
            for mutation in ("drift", "addition", "removal"):
                with self.subTest(category=category, mutation=mutation):
                    self.assert_rejected(
                        "resource-constructor",
                        shard="core",
                        shard_mutation=lambda core, category=category, mutation=mutation: (
                            mutate_contract(core, category, mutation)
                        ),
                    )

    def test_exact_numeric_resource_constructors_are_required_once(self) -> None:
        for kind in ("integer", "float"):
            case_id = f"v1-loader-exact-max-{kind}-token"

            def delete_constructor(validators, case_id=case_id) -> None:
                ast = validators["validator_transforms"][case_id]["ast"]
                probe = ast_nodes(ast, "probe")[0]
                probe["input"] = {"node": "literal", "value": None}

            def duplicate_constructor(validators, case_id=case_id) -> None:
                ast = validators["validator_transforms"][case_id]["ast"]
                ast["steps"].append(copy.deepcopy(ast_nodes(ast, "generate")[0]))

            for mutation, mutate in (
                ("deleted", delete_constructor),
                ("duplicated", duplicate_constructor),
            ):
                with self.subTest(kind=kind, mutation=mutation):
                    self.assert_rejected(
                        "resource-constructor",
                        shard="validators",
                        shard_mutation=mutate,
                    )

    def test_exact_numeric_resource_constructor_kind_and_length_are_fixed(self) -> None:
        for kind in ("integer", "float"):
            case_id = f"v1-loader-exact-max-{kind}-token"

            def wrong_kind(validators, kind=kind, case_id=case_id) -> None:
                ast = validators["validator_transforms"][case_id]["ast"]
                parameters = {
                    "kind": kind,
                    "scope": "fixture",
                    "relation": "exact",
                    "digit": "9",
                }
                if kind == "float":
                    parameters["prefix"] = "0."
                for node in ast_nodes(ast, "generate"):
                    node["constructor"] = "number-token-boundary"
                    node["parameters"] = copy.deepcopy(parameters)

            def wrong_length(validators, case_id=case_id) -> None:
                ast = validators["validator_transforms"][case_id]["ast"]
                for node in ast_nodes(ast, "generate"):
                    node["parameters"]["relation"] = "over"

            for mutation, mutate in (
                ("wrong-kind", wrong_kind),
                ("wrong-length", wrong_length),
            ):
                with self.subTest(kind=kind, mutation=mutation):
                    self.assert_rejected(
                        "resource-constructor",
                        shard="validators",
                        shard_mutation=mutate,
                    )

    def test_numeric_constructor_grammar_is_closed(self) -> None:
        cases = (
            ("v1-loader-integer-token-over-limit", "digit", "x"),
            ("v1-loader-float-token-over-limit", "prefix", "NaN"),
            ("v1-corpus-manifest-integer-token-over-limit", "digit", "+"),
            ("v1-corpus-manifest-float-token-over-limit", "prefix", "1e9999"),
        )
        for case_id, field, replacement in cases:
            def mutate(validators, case_id=case_id, field=field, replacement=replacement) -> None:
                ast = validators["validator_transforms"][case_id]["ast"]
                for node in ast_nodes(ast, "generate"):
                    node["parameters"][field] = replacement

            with self.subTest(case=case_id):
                self.assert_rejected(
                    "resource-constructor",
                    shard="validators",
                    shard_mutation=mutate,
                )

    def test_shard_ancestor_symlink_is_rejected_without_value_disclosure(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks are unavailable")
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            backing = temporary_root / "backing"
            backing_shards = backing / "docs/superpowers/plans/m1-013-format-v1"
            backing_shards.mkdir(parents=True)
            index = json.loads(REGISTRY.read_text(encoding="utf-8"))
            for entry in index["shards"]:
                shutil.copyfile(ROOT / entry["path"], backing / entry["path"])
            os.symlink("backing/docs", temporary_root / "docs", target_is_directory=True)
            registry = temporary_root / "registry.json"
            registry.write_text(json.dumps(index), encoding="utf-8")

            result = run_checker(registry)

        self.assertEqual(result.returncode, 1, result)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "M1-013 plan registry invalid: file\n")

    def test_missing_no_follow_support_fails_closed(self) -> None:
        for capability in (
            "open", "dir_fd", "O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "fstat"
        ):
            with self.subTest(capability=capability):
                result = run_checker_without_capability(capability)

                self.assertEqual(result.returncode, 1, result)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr, "M1-013 plan registry invalid: internal\n"
                )

    def test_open_flag_values_must_be_positive_non_boolean_integers(self) -> None:
        for capability in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC"):
            for value in (0, True):
                with self.subTest(capability=capability, value=value):
                    result = run_checker_with_capability_value(capability, value)

                    self.assertEqual(result.returncode, 1, result)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(
                        result.stderr, "M1-013 plan registry invalid: internal\n"
                    )

    def test_zero_no_follow_flag_cannot_follow_identical_byte_symlink(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks are unavailable")
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            shard_directory = temporary_root / "docs/superpowers/plans/m1-013-format-v1"
            shard_directory.mkdir(parents=True)
            index = json.loads(REGISTRY.read_text(encoding="utf-8"))
            for entry in index["shards"]:
                shutil.copyfile(ROOT / entry["path"], temporary_root / entry["path"])
            core = shard_directory / "core.json"
            backing = temporary_root / "identical-core.json"
            shutil.copyfile(core, backing)
            core.unlink()
            os.symlink(os.path.relpath(backing, core.parent), core)
            registry = temporary_root / "registry.json"
            registry.write_text(json.dumps(index), encoding="utf-8")

            result = run_checker_with_capability_value("O_NOFOLLOW", 0, registry)

        self.assertEqual(result.returncode, 1, result)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "M1-013 plan registry invalid: internal\n")

    def test_history_action_schema_and_action_rules_separate_arity(self) -> None:
        histories = json.loads(
            (SHARD_DIRECTORY / "histories.json").read_text(encoding="utf-8")
        )
        validators = json.loads(
            (SHARD_DIRECTORY / "validators.json").read_text(encoding="utf-8")
        )
        zero_argument_actions = {"deletion", "policy-rejection"}
        arguments_by_action = {
            rule["label"]: rule["arguments"] for rule in histories["action_rules"]
        }
        self.assertEqual(
            {label for label, arguments in arguments_by_action.items() if not arguments},
            zero_argument_actions,
        )

        schemas = copy.deepcopy(validators["schemas"])
        schemas["HistoryAction"]["properties"]["args"]["min_items"] = 0
        for label in sorted(zero_argument_actions):
            with self.subTest(schema_action=label):
                self.assertTrue(
                    registry_module._validate_typed_value(
                        {"label": label, "args": []},
                        schemas["HistoryAction"],
                        schemas,
                        validators["domains"],
                    )
                )

        self.assert_rejected(
            "root",
            shard="validators",
            shard_mutation=lambda document: document["schemas"]["HistoryAction"][
                "properties"
            ]["args"].__setitem__("min_items", 0),
        )

        for label, arguments in arguments_by_action.items():
            if not arguments:
                continue

            def remove_arguments(histories, label=label) -> None:
                action = histories["baselines"][0]["candidate"]["actions"][0]
                action["label"] = label
                action["args"] = []

            with self.subTest(action_rule=label):
                self.assert_rejected(
                    "history-reference",
                    shard="histories",
                    shard_mutation=remove_arguments,
                )

    def test_final_shard_symlink_is_rejected_without_value_disclosure(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks are unavailable")
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            shard_directory = temporary_root / "docs/superpowers/plans/m1-013-format-v1"
            shard_directory.mkdir(parents=True)
            index = json.loads(REGISTRY.read_text(encoding="utf-8"))
            for entry in index["shards"]:
                shutil.copyfile(ROOT / entry["path"], temporary_root / entry["path"])
            core = shard_directory / "core.json"
            backing = temporary_root / "core-backing.json"
            core.replace(backing)
            os.symlink(os.path.relpath(backing, core.parent), core)
            registry = temporary_root / "registry.json"
            registry.write_text(json.dumps(index), encoding="utf-8")

            result = run_checker(registry)

        self.assertEqual(result.returncode, 1, result)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "M1-013 plan registry invalid: file\n")

    def test_shard_path_escape_is_rejected_before_file_access(self) -> None:
        secret = "../outside.json\n::error::injected"

        def mutate(root) -> None:
            root["shards"][1]["path"] = secret

        self.assert_rejected("index", root_mutation=mutate)

    def test_safe_diagnostics_hide_attacker_controlled_root_values(self) -> None:
        secret = "/home/private\n::error::injected"

        def add_secret(root) -> None:
            root[secret] = secret

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            document = json.loads(REGISTRY.read_text(encoding="utf-8"))
            add_secret(document)
            path.write_text(json.dumps(document), encoding="utf-8")
            result = run_checker(path)

        self.assertEqual(result.returncode, 1, result)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "M1-013 plan registry invalid: index\n")
        self.assertNotIn(secret, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
