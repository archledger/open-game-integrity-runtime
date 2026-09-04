# OGIR attack laboratory

The attack lab converts security claims into executable scenarios.

Every scenario names an accountable `owner` and a
`required_assurance_profile`. The profile value `all-protected-modes` means the
invariant applies regardless of the selected attestation backend or hardware
assurance class; narrower profile names require a separately documented profile
definition.
The gate also requires globally unique scenario IDs and checks owner/profile
values against explicit in-code registries; registering a new value therefore
requires a reviewed validator and documentation change.

Each `*.scenario.json` file is exactly one JSON document. JSON's strict syntax
allows the standard-library validator to parse the document rather than scan
text; a duplicate-key hook rejects ambiguity before schema evaluation.

`scripts/check-attack-scenario-traceability.py` uses only the Python standard
library. It fails on unsupported schema keywords, validates the complete schema
subset used here, and rejects missing/malformed mappings, duplicate keys,
multiple documents, unknown fields, and all other schema violations. Its
self-tests and real repository check run in the aggregate gate.

The parser accepts only RFC 8259 numeric constants and exactly the declared
Draft 2020-12 schema dialect. It processes at most 128 scenario files; each
schema/scenario document is at most 65,536 UTF-8 bytes, 16 levels deep, 64
fields per object, 256 items per array, 4,096 characters per string/key, and
64 characters per number token and 4,096 total nodes. These fixed limits bound
pull-request-controlled parsing.
Diagnostics use one fixed context-free label and never print scenario filenames,
checkout/home paths, raw keys/properties, control characters, or CI annotation
commands.
Schema regexes are executable input: the validator permits only the exact
reviewed attacker-class and kebab-case patterns, never arbitrary backtracking
expressions. Every error omits raw keys, property names, caller paths, and I/O
paths; unexpected exceptions fail closed without a traceback. The scenario
directory, schema, and scenario entries must not be symlinks.

Initial responsibilities:

- validate machine-readable scenario files;
- run protocol replay and substitution tests;
- generate malformed bounded inputs;
- preserve regression inputs for every fixed defect;
- orchestrate software-TPM, VM, and later bare-metal tests;
- verify that unrelated user processes are not affected by protected-session policies.

Attack tooling must use test accounts, test keys, dedicated systems, and responsible-disclosure practices.

Parser/schema sources: [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html),
[JSON Schema Draft 2020-12 core](https://json-schema.org/draft/2020-12/json-schema-core),
[validation](https://json-schema.org/draft/2020-12/json-schema-validation), and
the Python standard-library [`json` documentation](https://docs.python.org/3/library/json.html).

## M1-013 local implementation evidence

The test-only [`conformance/corpus.json`](conformance/corpus.json) inventories
synthetic snapshots and ordered lifecycle histories, including intentional
single-change failures. The
[admitted JSON planning registry](../docs/superpowers/plans/2026-09-02-m1-013-format-v1-registry.json)
and its hash-bound shards define the format; use its checker before changing
fixtures. Do not create a second case list or edit expected outcomes to hide a
regression. Each negative must reproduce its registered baseline transform.

From the repository root, `python3 scripts/check-m1-013-plan-registry.py` admits
the planning authority. `python3 scripts/check-abstract-conformance.py` validates
the real corpus; `python3 scripts/check-abstract-conformance.py --self-test`
executes registered non-file cases and independent focused checks. Successful
execution is silent and exits zero; failures use fixed safe labels and a
nonzero exit. Use `PYTHONDONTWRITEBYTECODE=1 python3 -W error
scripts/test-conformance-documentation.py` to check the current documentation
candidate, including an untracked local issue. Run `PYTHONDONTWRITEBYTECODE=1
./scripts/check.sh` for the aggregate. Its conformance commands have a finite
outer timeout; direct commands should also run in a bounded test environment.

The shared `scripts/bounded_json.py` loader keeps file/JSON admission neutral.
Attack-scenario compatibility tests preserve its existing consumer's safe
messages, bounded numeric locations, accepted inputs, and exits. New
conformance diagnostics expose only fixed consumer/checkpoint/error-class
labels. Keep real identities, private keys, production evidence, host paths,
and confidential material out of fixtures and reports.

[Observed counts and test evidence](../docs/TEST_STRATEGY.md#m1-013-local-implementation-evidence)
describe Tasks 2–8. JSON is fixture notation only; it implements no production
protocol, cryptography, TPM mapping, persistence, permit, or admission path.
This uncommitted test-only candidate is prepared for Task 10 final local
verification and freeze. The freeze handoff will identify the exact candidate
and completed checks. Human line review, DCO certification, and separately
authorized Task 11 commit and publication remain pending.
