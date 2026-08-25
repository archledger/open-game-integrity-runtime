# Architecture decision records

Create one ADR for any durable decision affecting trust boundaries, protocol
semantics, cryptography, TPM behavior, privilege, privacy, dependencies in the
trusted computing base, licensing boundaries, release signing, reference
values, revocation, or compatibility guarantees.

Start from the [ADR template](template.md) and add the decision to the
[decision index](index.md) in the same commit.

## Naming

```text
NNNN-short-decision-title.md
```

The numeric identifier in the filename and `# ADR-NNNN:` title must match.

## Lifecycle

Valid states are `Proposed`, `Accepted`, `Superseded`, `Rejected`, and
`Experimental`. The decision index defines their meaning.

- Never delete a superseded or rejected ADR. It records why an option did not
  stand.
- A superseding ADR links both directions: the new record names what it
  supersedes, and the old record names its replacement.
- `Supersedes` and `Superseded by` use `None` or comma-separated links in the
  canonical form `[ADR-NNNN](NNNN-short-decision-title.md)`. Copy the exact
  values into the matching decision-index columns; every link must resolve and
  have its reciprocal metadata in the other ADR.
- A status change and its index update belong in the same commit.
- Every required section contains either its analysis or a specific
  not-applicable rationale. A blank heading is not sufficient.
- Only rendered Markdown structure satisfies the gate. Links, headings, or
  index rows inside HTML comments or code blocks do not count.
- Raw HTML outside code blocks is rejected so it cannot change whether policy
  metadata renders as Markdown structure.

Run the consistency gate before submitting changes:

```bash
./scripts/check-adr-index.sh
```
