# OGIR attack laboratory

The attack lab converts security claims into executable scenarios.

Every scenario names an accountable `owner` and a
`required_assurance_profile`. The profile value `all-protected-modes` means the
invariant applies regardless of the selected attestation backend or hardware
assurance class; narrower profile names require a separately documented profile
definition.

Each `*.scenario.json` file is exactly one JSON document. JSON's strict syntax
allows the standard-library validator to parse the document rather than scan
text; a duplicate-key hook rejects ambiguity before schema evaluation.

`scripts/check-attack-scenario-traceability.py` uses only the Python standard
library. It fails on unsupported schema keywords, validates the complete schema
subset used here, and rejects missing/malformed mappings, duplicate keys,
multiple documents, unknown fields, and all other schema violations. Its
self-tests and real repository check run in the aggregate gate.

Initial responsibilities:

- validate machine-readable scenario files;
- run protocol replay and substitution tests;
- generate malformed bounded inputs;
- preserve regression inputs for every fixed defect;
- orchestrate software-TPM, VM, and later bare-metal tests;
- verify that unrelated user processes are not affected by protected-session policies.

Attack tooling must use test accounts, test keys, dedicated systems, and responsible-disclosure practices.
