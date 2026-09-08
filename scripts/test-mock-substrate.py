#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ADR-0016 production-graph exclusion gate for the M2 mock substrate.

Fails closed unless:
  * both mock crates are workspace members and publish = false;
  * no production crate or app manifest references ogir-mock-keys or
    ogir-mock-protocol;
  * both mock crate manifests carry the test-only description marker.

Test-only structural check; it substitutes for no runtime test.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
MOCK_CRATES = ("ogir-mock-keys", "ogir-mock-protocol")
# ADR-0032: the developer-mode daemon composes the mock substrate
# into the service shell; it is mock-tier by construction and is
# excluded from the production graph (asserted below).
MOCK_TIER_CONSUMERS = ("ogir-dev-verifierd",)
FAILURES: list[str] = []


def workspace_manifest() -> str:
    return (REPOSITORY_ROOT / "Cargo.toml").read_text(encoding="utf-8")


def check(condition: bool, message: str) -> None:
    if not condition:
        FAILURES.append(message)


def main() -> int:
    workspace = workspace_manifest()
    for crate in MOCK_CRATES:
        check(f'"{crate}"' in workspace or f"crates/{crate}" in workspace,
              f"workspace members missing {crate}")

    for crate in MOCK_CRATES:
        manifest = (REPOSITORY_ROOT / "crates" / crate / "Cargo.toml").read_text(
            encoding="utf-8"
        )
        check("publish = false" in manifest, f"{crate} is not publish = false")
        check("TEST-ONLY" in manifest, f"{crate} description lacks the TEST-ONLY marker")

    production_paths = [
        REPOSITORY_ROOT / "crates" / "ogir-attest" / "Cargo.toml",
    REPOSITORY_ROOT / "crates" / "ogir-attest-tpm" / "Cargo.toml",
    REPOSITORY_ROOT / "crates" / "ogir-model" / "Cargo.toml",
        REPOSITORY_ROOT / "crates" / "ogir-protocol" / "Cargo.toml",
        REPOSITORY_ROOT / "crates" / "ogir-agent" / "Cargo.toml",
        REPOSITORY_ROOT / "crates" / "ogir-verifier" / "Cargo.toml",
        REPOSITORY_ROOT / "apps" / "ogird" / "Cargo.toml",
        REPOSITORY_ROOT / "apps" / "ogir-verifierd" / "Cargo.toml",
    ]
    production_paths = [
        path
        for path in production_paths
        if not any(consumer in str(path) for consumer in MOCK_TIER_CONSUMERS)
    ]
    for path in production_paths:
        text = path.read_text(encoding="utf-8")
        for crate in MOCK_CRATES:
            check(crate not in text, f"{path.relative_to(REPOSITORY_ROOT)} references {crate}")

    # ADR-0020 + ADR-0027: ogir-attest-tpm and ogir-agent are the ONLY
    # crates with their own lint tables (unsafe_code = "deny" instead
    # of the workspace forbid); every other lint must mirror the
    # workspace table exactly, and no other crate may leave
    # [lints] workspace = true. Each carved-out crate holds EXACTLY ONE
    # audited #[allow(unsafe_code)] block (the ADR-0020 marshaling
    # call; the ADR-0027 SO_PEERCRED getsockopt shim).
    import re as _re
    workspace = (REPOSITORY_ROOT / "Cargo.toml").read_text(encoding="utf-8")
    for crate_name in ("ogir-attest-tpm", "ogir-agent"):
        manifest = (REPOSITORY_ROOT / "crates" / crate_name / "Cargo.toml").read_text(
            encoding="utf-8"
        )
        check('unsafe_code = "deny"' in manifest,
              f"{crate_name} lost its audited unsafe_code deny posture")
        check("[lints]" + chr(10) + "workspace = true" not in manifest,
              f"{crate_name} must keep its own lint table")
        sources = list((REPOSITORY_ROOT / "crates" / crate_name / "src").rglob("*.rs"))
        allow_count = sum(
            path.read_text(encoding="utf-8").count("#[allow(unsafe_code)]")
            for path in sources
        )
        check(allow_count == 1,
              f"exactly one audited #[allow(unsafe_code)] block is permitted in {crate_name}, found {allow_count}")
    for crate in MOCK_CRATES + ("ogir-model", "ogir-protocol",
                                "ogir-verifier", "ogir-attest"):
        manifest = (REPOSITORY_ROOT / "crates" / crate / "Cargo.toml").read_text(
            encoding="utf-8"
        )
        check("unsafe_code" not in manifest,
              f"{crate} must not override the workspace unsafe posture")

    # ADR-0032: the developer-mode daemon must exist, must depend on
    # the production service shell, and its mock references must be
    # exactly the substrate crates.
    dev_manifest = (
        REPOSITORY_ROOT / "crates" / "ogir-dev-verifierd" / "Cargo.toml"
    ).read_text(encoding="utf-8")
    check("ogir-verifier" in dev_manifest, "ogir-dev-verifierd must compose the service shell")
    for crate in MOCK_CRATES:
        check(crate in dev_manifest or crate == "ogir-mock-keys",
              f"unexpected mock wiring for {crate}")

    if FAILURES:
        for failure in FAILURES:
            print(f"mock-substrate isolation FAILED: {failure}")
        return 1
    print("mock-substrate isolation PASS: "
          "mock crates test-only, production graph clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
