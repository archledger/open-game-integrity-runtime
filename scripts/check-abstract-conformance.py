#!/usr/bin/env python3
"""Run the bounded abstract-conformance corpus and registered self-tests."""

from __future__ import annotations

import sys


def main(arguments: list[str]) -> int:
    internal = "abstract-conformance:internal:internal-failure"
    if arguments not in ([], ["--self-test"]):
        print(internal, file=sys.stderr)
        return 2
    try:
        import abstract_conformance

        authority = abstract_conformance.registry.load_task4_authority()
        if arguments:
            abstract_conformance.run_self_tests(authority)
        else:
            abstract_conformance.run_corpus(authority)
    except Exception as error:
        diagnostic = internal
        if "abstract_conformance" in locals():
            if isinstance(error, abstract_conformance.OperationBudgetExceeded):
                diagnostic = "abstract-conformance:internal:operation-budget-exhausted"
            elif isinstance(error, abstract_conformance.bounded_json.BoundedJsonError) and "authority" in locals():
                admitted = {
                    "abstract-conformance:" + checkpoint + ":" + category
                    for checkpoint, category in authority.core["diagnostics"]["closed_pairs"]
                }
                if str(error) in admitted:
                    diagnostic = str(error)
        print(diagnostic, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
