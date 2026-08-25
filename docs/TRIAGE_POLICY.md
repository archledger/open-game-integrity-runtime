# Issue triage policy

OGIR uses namespaced labels and roadmap milestones to make scope, review risk,
and readiness visible without exposing private vulnerability details. This
policy governs public issues and pull requests; suspected vulnerabilities stay
in GitHub private vulnerability reporting or draft security advisories until
coordinated disclosure.

## Authority and responsibilities

- Contributors and reporters may propose classifications and state changes.
- Maintainers own canonical labels, milestones, assignments, and issue state.
- Only a maintainer may mark an issue ready, confirm or clear a blocker, add or
  remove `status: do-not-merge`, close/reopen project work, or close a
  milestone.
- Reviewers may request `status: do-not-merge`; a maintainer applies it before
  review continues and removes it only after the named condition is verified.
- An issue author may request withdrawal, but a maintainer records the public
  disposition and closes the issue.

GitHub's unprefixed default labels are preserved for historical metadata but
are noncanonical. Do not use them to communicate OGIR type, area, risk,
readiness, or completion state.

## Classification rules

A triaged roadmap issue has:

- exactly one `type:` label;
- one or more `area:` labels;
- every applicable `risk:` label, or none when the change has no listed review
  risk;
- exactly one workflow-state label from `status: needs-research`,
  `status: blocked`, `status: ready`, `status: needs-review`, or
  `status: experimental`;
- `status: do-not-merge` in addition to the workflow state when a hard merge
  stop is active;
- exactly one roadmap milestone once the work is accepted into M0–M12.

Apply risk labels before implementation or review begins. When the impact is
uncertain, use the more conservative applicable risk label until research
narrows it. Labels describe review surface, not vulnerability severity.

Example:

```text
M0-006: Establish labels, milestones, and triage policy
type: documentation
area: supply-chain
risk: trusted-computing-base
status: ready
milestone: M0 Repository Foundation
```

## Type labels

| Label | Meaning |
| --- | --- |
| `type: architecture` | Durable trust, protocol, privilege, privacy, dependency, licensing, or component decision. |
| `type: research` | Primary-source research or a bounded experiment that resolves one uncertainty. |
| `type: implementation` | Scoped product or infrastructure implementation. |
| `type: test` | Unit, integration, conformance, regression, or attack testing. |
| `type: fuzzing` | Fuzz, property, mutation, differential, or parser-hardening work. |
| `type: documentation` | Documentation or governance change without runtime behavior. |
| `type: security-hardening` | Defense-in-depth or attack-surface reduction. |
| `type: dependency` | Dependency, toolchain, license, provenance, or maintenance review. |
| `type: release` | Release, signing, provenance, update, or lifecycle work. |

## Area labels

| Label | Meaning |
| --- | --- |
| `area: model` | Pure domain model, identifiers, states, and invariants. |
| `area: protocol` | Challenge, evidence, permit, renewal, and revocation protocol. |
| `area: verifier` | Publisher verifier and relying-party boundary. |
| `area: agent` | Local portal, session coordination, and attestation agent. |
| `area: tpm` | TPM backend, identity, quote, enrollment, and resource handling. |
| `area: measured-boot` | Measured boot, UKI, PCR, event-log, and reference-value work. |
| `area: proton-bridge` | Windows ABI, Wine/Proton transport, and caller binding. |
| `area: session` | Protected-session lifecycle, observation, and enforcement. |
| `area: wine-tpm` | Separate Wine TPM compatibility workstream. |
| `area: attack-lab` | Executable adversarial scenarios and test infrastructure. |
| `area: supply-chain` | Build, dependency, provenance, CI, update, and release security. |
| `area: privacy` | Disclosure minimization, identity scope, retention, and privacy controls. |

## Risk labels

| Label | Meaning |
| --- | --- |
| `risk: trusted-computing-base` | Changes trusted code, acceptance logic, governance, or a trust decision. |
| `risk: privileged` | Changes privileged operations, authorization, or service isolation. |
| `risk: cryptography` | Changes signatures, keys, transcript binding, algorithms, or parameters. |
| `risk: parser` | Processes attacker-controlled structured input or changes canonical parsing. |
| `risk: privacy` | Changes claims, identifiers, logs, retention, or disclosed data. |
| `risk: compatibility` | May affect supported platforms, Wine, Proton, ABI, or migration behavior. |

Risk labels require the corresponding specialist review before merge. They are
not public severity ratings and must not reveal whether a private report is
confirmed, exploitable, or embargoed.

## Status labels and transitions

| Label | Entry condition | Exit condition |
| --- | --- | --- |
| `status: needs-research` | A named primary-source question or experiment blocks specification. | Evidence is linked and the issue becomes ready, experimental, or blocked on an external dependency. |
| `status: blocked` | A specific dependency, decision, resource, or external event prevents progress. | A maintainer verifies the named blocker and exit condition are resolved. |
| `status: ready` | Scope, non-scope, sources, acceptance criteria, security/privacy impact, and required tests are reviewable. | Work starts, becomes blocked, or reaches review. |
| `status: needs-review` | Implementation or research output is complete with deterministic evidence. | Required reviews and checks pass, or findings return it to another state. |
| `status: experimental` | Bounded research behavior is available without production guarantees. | A later issue accepts, supersedes, rejects, or removes the experiment. |
| `status: do-not-merge` | A named security, correctness, policy, or provenance condition is unresolved. | A maintainer verifies and records that the condition is resolved. |

A blocked issue comment names the blocker, its owner when known, the evidence
needed to clear it, and the next review date or triggering event. Do not use
`status: blocked` as an unbounded parking state.

## Milestones

Milestones M0–M12 are scope and exit-gate groupings from
[`ROADMAP.md`](ROADMAP.md), not delivery promises. They have no due dates.
Only maintainers assign or move issues between milestones. A maintainer closes
a milestone only after its roadmap exit criteria link to deterministic
evidence. `M12 Production Candidate` names a conditional assurance stage; it
does not promise production readiness or a release date.

## Done with evidence

There is no `status: done` label. An issue is done only when its closing record
links to evidence appropriate to its type:

- the merged pull request or accepted research artifact;
- exact commands and pass/fail results for required checks;
- positive and negative tests, including the permanent regression for a
  confirmed defect;
- documentation/ADR/protocol updates or a specific not-applicable rationale;
- remaining limitations, residual risks, and rollback information.

A closing pull request may close an issue automatically when its body contains
that evidence. Otherwise a maintainer adds the evidence before closing or
reopens the issue. Closing an issue does not assert that a player cheated, that
all attacks are prevented, or that a milestone is complete.

## Private security reports

1. Keep suspected vulnerabilities in GitHub private vulnerability reporting or
   a draft security advisory. Do not create a public issue or public severity
   label.
2. A maintainer privately records an owner, affected versions/commits, violated
   invariants, reproduction status, disclosure constraints, and the regression
   test required for confirmation.
3. Coordinate remediation and disclosure with the reporter, respecting their
   attribution preference and excluding secrets, player data, TPM identities,
   and unnecessary exploit detail.
4. After a fix and coordinated disclosure, create or update sanitized public
   work only when it helps users or future contributors. Use ordinary type,
   area, risk, status, and milestone labels; risk labels describe review scope,
   never severity.
5. Link a public advisory/CVE only after publication, and link the permanent
   regression evidence without reproducing embargoed material.

Security-report closure remains separate from attestation eligibility, player
discipline, and ban decisions.
