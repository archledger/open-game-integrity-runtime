# AI-assisted development policy

## 1. Principle

AI is an untrusted contributor. It may accelerate research, scaffolding, testing, documentation, and review, but it cannot be the security authority, release authority, or owner of a claim.

A human contributor remains responsible for understanding every line, verifying sources and provenance, running tests, and signing the contribution.

## 2. Suitable AI work

- locating and comparing current primary specifications;
- producing a small initial implementation behind an already approved interface;
- generating unit, property, fuzz, mutation, and adversarial test ideas;
- building test fixtures from public specifications;
- mechanical refactoring with behavior-preserving tests;
- explaining code paths for human review;
- reviewing a patch for failure modes and missing tests;
- maintaining documentation and cross-reference consistency;
- converting threat scenarios into deterministic test cases.

## 3. Work AI may propose but never independently approve

- cryptographic protocol or parameter choices;
- TPM object templates, authorization policy, PCR selection, or key enrollment;
- verifier acceptance logic;
- evidence and permit serialization;
- trust-root, signing, reference-value, update, or revocation changes;
- privileged operations;
- `unsafe` Rust or C memory handling;
- Wine ABI and WoW64 marshalling;
- BPF/LSM enforcement;
- privacy claim expansion;
- security severity or vulnerability closure;
- production-readiness statements.

## 4. Prohibited prompt material

Never send an external model:

- private signing or TPM keys;
- raw endorsement credentials;
- real production attestation bundles;
- player identity or disciplinary data;
- confidential publisher source or architecture without authorization;
- embargoed vulnerability details without authorization;
- NDA material;
- secrets from environment variables, credential stores, logs, or CI.

Use an approved local or contractually controlled model for confidential work.

## 5. Required issue format

Every AI coding task starts from an issue containing:

```text
Problem
Security invariant(s)
Threat(s) addressed
In scope
Out of scope
Primary sources
Required interfaces
Positive tests
Negative tests
Fuzz/property tests
Privacy impact
Dependency impact
Acceptance criteria
```

The model must not invent missing requirements. Unresolved questions become explicit blockers or research tasks.

## 6. Required AI prompt structure

```text
Role:
  You are implementing one scoped OGIR issue.

Read first:
  docs/SECURITY_INVARIANTS.md
  docs/THREAT_MODEL.md
  docs/ARCHITECTURE.md
  relevant ADRs and issue

Rules:
  Use primary sources.
  Do not guess or fabricate.
  Do not add dependencies or unsafe code without approval.
  Do not broaden scope.
  Do not implement cryptographic primitives.
  Treat all client input as hostile.

Task:
  <one narrowly defined change>

Acceptance criteria:
  <deterministic criteria>

Required tests:
  <positive, negative, property, fuzz, regression>

Deliver:
  changed files;
  rationale;
  commands run and exact results;
  unresolved risks;
  documentation updated.
```

## 7. Development loop

1. **Research:** cite current official specifications and upstream source.
2. **Model:** identify assets, trust boundaries, invariants, and failure states.
3. **Test:** write negative and positive tests from the specification.
4. **Implement:** make the smallest complete change.
5. **Attack:** ask a separate AI reviewer to find bypasses without seeing the author's reasoning summary.
6. **Verify:** run deterministic tooling and manually inspect output.
7. **Document:** update architecture, threat model, protocol, and lessons learned.
8. **Human review:** understand each line and approve or reject.
9. **Merge:** only through the configured GitHub checks.

## 8. Independent AI review

The reviewer prompt should be adversarial:

```text
Assume this patch is wrong and an attacker controls every untrusted input.
Find concrete paths to:
- forge authorization;
- replay across sessions;
- confuse caller identity;
- race verification and use;
- expand privilege;
- leak private information;
- make parsers disagree;
- fail open;
- suppress required evidence;
- exploit dependency or supply-chain assumptions.

Do not praise the patch. Report only evidence-backed findings, test cases, and uncertainty.
```

The authoring model and reviewing model should not share hidden scratch reasoning. Their outputs are evidence for the human reviewer, not approval.

## 9. Contribution disclosure

Pull requests record:

```text
AI-Assisted: yes/no
AI-System: model/provider or local model
AI-Use: research | scaffold | implementation | tests | review | docs
Human-Reviewed-Every-Line: yes/no
Primary-Sources-Verified: yes/no
Threat-Model-Updated: yes/no
Fuzz-Target-Updated: yes/no
```

Do not publish sensitive prompts or vulnerability details merely to satisfy disclosure.

## 10. Learning from mistakes

Every confirmed defect adds:

- a regression test;
- an attack-lab scenario where applicable;
- a short entry in `docs/LESSONS_LEARNED.md` describing the mistaken assumption and durable prevention rule;
- updates to agent instructions if the failure was procedural;
- removal or correction of stale architectural claims.

AI may propose these updates, but a human must approve them.

## 11. Definition of done for AI-assisted code

A task is incomplete unless:

- all acceptance criteria are met;
- formatting, linting, and tests pass;
- failure paths are tested;
- no unsupported claim remains in documentation;
- relevant primary sources are recorded;
- security/privacy impacts are addressed;
- the human reviewer can explain the implementation without relying on the model;
- the pull request records AI use and DCO sign-off.
