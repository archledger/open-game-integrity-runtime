# OGIR attack laboratory

The attack lab converts security claims into executable scenarios.

Every scenario names an accountable `owner` and a
`required_assurance_profile`. The profile value `all-protected-modes` means the
invariant applies regardless of the selected attestation backend or hardware
assurance class; narrower profile names require a separately documented profile
definition.

`scripts/check-attack-scenario-traceability.py` uses only the Python standard
library. Its self-tests prove missing, malformed, and duplicate mappings fail;
the repository check verifies the schema contract and every scenario on each
aggregate run. Full JSON Schema validation remains available to attack-lab
tooling.

Initial responsibilities:

- validate machine-readable scenario files;
- run protocol replay and substitution tests;
- generate malformed bounded inputs;
- preserve regression inputs for every fixed defect;
- orchestrate software-TPM, VM, and later bare-metal tests;
- verify that unrelated user processes are not affected by protected-session policies.

Attack tooling must use test accounts, test keys, dedicated systems, and responsible-disclosure practices.
