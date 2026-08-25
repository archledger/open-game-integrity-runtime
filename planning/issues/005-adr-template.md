# M0-005: Add the security-focused ADR template and decision index
<!-- labels: type: architecture,type: documentation,area: supply-chain,status: ready -->
<!-- milestone: M0 Repository Foundation -->

## Problem

Security-critical architectural decisions must preserve context, alternatives, trust effects, and rollback—not just a final choice.

## Security invariants

- No durable trust, protocol, privilege, privacy, serialization, or dependency decision exists only in a chat transcript.
- Superseded decisions remain traceable.

## In scope

- Add an ADR template with context, decision drivers, options, threat impact, privacy impact, dependency/license impact, validation, rollback, and status.
- Add an ADR index with accepted, proposed, superseded, and rejected states.
- Apply the template retrospectively to ADRs 0001–0004 without changing their decisions.

## Out of scope

- Choosing cryptographic or TPM libraries.
- Freezing the wire protocol.

## Required tests

- A documentation check confirms every ADR appears in the index.
- A sample rejected decision can be represented without deleting history.

## Acceptance criteria

- Template and index are linked from `docs/adr/README.md`.
- Existing ADRs contain the required security sections or documented not-applicable rationale.
