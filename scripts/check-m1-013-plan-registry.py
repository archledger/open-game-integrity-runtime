#!/usr/bin/env python3
"""Validate the sharded M1-013 planning registry."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from m1_013_plan_registry import DEFAULT_REGISTRY, RegistryError, validate_registry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    arguments = parser.parse_args(argv)
    try:
        summary = validate_registry(arguments.registry)
    except RegistryError as error:
        print(f"M1-013 plan registry invalid: {error.code}", file=sys.stderr)
        return 1
    except Exception:
        print("M1-013 plan registry invalid: internal", file=sys.stderr)
        return 1
    print(
        "M1-013 plan registry valid: "
        f"{summary.snapshots} snapshots, {summary.histories} histories, "
        f"{summary.validator_cases} validator cases, "
        f"{summary.focused_invocations} focused invocations."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
