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
        REPOSITORY_ROOT / "crates" / "ogir-model" / "Cargo.toml",
        REPOSITORY_ROOT / "crates" / "ogir-protocol" / "Cargo.toml",
        REPOSITORY_ROOT / "crates" / "ogir-agent" / "Cargo.toml",
        REPOSITORY_ROOT / "crates" / "ogir-verifier" / "Cargo.toml",
        REPOSITORY_ROOT / "apps" / "ogird" / "Cargo.toml",
        REPOSITORY_ROOT / "apps" / "ogir-verifierd" / "Cargo.toml",
    ]
    for path in production_paths:
        text = path.read_text(encoding="utf-8")
        for crate in MOCK_CRATES:
            check(crate not in text, f"{path.relative_to(REPOSITORY_ROOT)} references {crate}")

    if FAILURES:
        for failure in FAILURES:
            print(f"mock-substrate isolation FAILED: {failure}")
        return 1
    print("mock-substrate isolation PASS: "
          "mock crates test-only, production graph clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
