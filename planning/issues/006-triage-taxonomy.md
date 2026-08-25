# M0-006: Establish labels, milestones, and triage policy
<!-- labels: type: documentation,area: supply-chain,status: ready -->
<!-- milestone: M0 Repository Foundation -->

## Problem

The roadmap needs a repeatable way to distinguish research, implementation, security risk, component area, and maturity without public vulnerability triage leaking sensitive details.

## Security invariants

- Public labels do not expose embargoed vulnerability severity.
- Work marked done links to deterministic evidence.
- High-risk changes are visible before review begins.

## In scope

- Review and run `scripts/bootstrap-github.sh`.
- Document label meanings and ownership.
- Create milestones M0–M12.
- Define issue states and the “Done with evidence” rule.
- Define how private security reports enter public work after coordinated disclosure.

## Out of scope

- Assigning production dates.
- Publicly labeling untriaged vulnerabilities.
- Creating all 30 implementation issues before their dependencies are ready.

## Required tests

- Script is idempotent for labels and milestones.
- A sample issue can carry type, area, risk, status, and milestone labels without ambiguity.

## Acceptance criteria

- Labels and milestones match `docs/GITHUB_SETUP.md`.
- Triage policy states who may close, block, or mark an issue ready.
- No milestone makes a production-readiness promise.
