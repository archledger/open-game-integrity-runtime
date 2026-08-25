# OGIR attack laboratory

The attack lab converts security claims into executable scenarios.

Initial responsibilities:

- validate machine-readable scenario files;
- run protocol replay and substitution tests;
- generate malformed bounded inputs;
- preserve regression inputs for every fixed defect;
- orchestrate software-TPM, VM, and later bare-metal tests;
- verify that unrelated user processes are not affected by protected-session policies.

Attack tooling must use test accounts, test keys, dedicated systems, and responsible-disclosure practices.
