# Instructions for AI coding agents

You are working on Open Game Integrity Runtime, security-sensitive experimental software.

## Mandatory reading order

1. `docs/SECURITY_INVARIANTS.md`
2. `docs/THREAT_MODEL.md`
3. `docs/ARCHITECTURE.md`
4. `docs/ROADMAP.md`
5. `docs/AI_DEVELOPMENT_POLICY.md`
6. The GitHub issue assigned to the task
7. Relevant architecture decision records

## Non-negotiable behavior

- Never guess an API, specification requirement, kernel behavior, Wine ABI, TPM property, or dependency capability.
- Research current primary documentation and upstream source before implementation.
- Do not fabricate dates, quotations, support claims, performance results, security guarantees, or test outcomes.
- Do not choose the fastest workaround merely to complete the task.
- Do not broaden scope without a separate issue and approval.
- Do not add a dependency until its purpose, license, maintenance status, and security impact are documented.
- Do not implement cryptographic primitives.
- Do not introduce `unsafe` Rust, raw physical-TPM forwarding, arbitrary privileged commands, or global monitoring.
- Do not treat local client claims as authoritative.
- Do not convert an attestation failure into a cheating accusation.
- Do not place secrets, private keys, real attestation identities, or confidential publisher material in prompts, code, tests, logs, or fixtures.

## Required implementation sequence

1. Restate the issue's security requirement and acceptance criteria.
2. Identify every trust boundary touched.
3. List primary sources and unresolved questions.
4. Write or update negative tests first.
5. Implement the smallest complete change.
6. Run formatting, linting, tests, and relevant fuzz/regression targets.
7. Inspect every warning and failure; do not suppress without justification.
8. Update architecture, threat model, protocol, privacy, and lessons-learned documentation where applicable.
9. Produce a concise review report with changed files, commands run, results, limitations, and residual risks.

## AI self-review

Before presenting code, independently search for:

- fail-open behavior;
- replay or cross-session reuse;
- confused-deputy paths;
- caller-controlled identity fields;
- TOCTOU races;
- length, integer, lifetime, and ownership errors;
- ambiguous serialization;
- secret or privacy leakage;
- unsafe privilege expansion;
- missing negative tests;
- undocumented assumptions;
- dependency or license conflicts.

## Human authority

AI output is a proposal. A human contributor must understand every changed line, verify source provenance, run the required checks, and accept responsibility under the project's contribution policy.
