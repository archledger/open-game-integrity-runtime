# M0-004: Establish DCO sign-off and contributor certification
<!-- labels: type: documentation,area: supply-chain,status: ready -->
<!-- milestone: M0 Repository Foundation -->

## Problem

Contributors need a clear representation that they have the right to submit code, including AI-assisted code, under the repository licenses.

## Security invariants

- Every merged commit has an attributable human contributor.
- AI assistance never substitutes for contributor responsibility or provenance review.
- The process does not silently transfer contributor copyright.

## In scope

- Add the Developer Certificate of Origin 1.1 text or canonical reference.
- Document `git commit -s` and sign-off repair steps.
- Select and configure a DCO enforcement method after reviewing its permissions and maintenance status.
- Add a negative test or temporary pull request demonstrating rejection of a missing sign-off.

## Out of scope

- Copyright assignment.
- Broad relicensing CLA.
- Treating DCO sign-off as proof that generated code is non-infringing.

## Primary sources

- DCO 1.1: https://developercertificate.org/
- Git sign-off documentation: https://git-scm.com/docs/git-commit

## Acceptance criteria

- Contribution documentation is unambiguous.
- The default merge path detects missing sign-off.
- Bot permissions and supply-chain implications are documented.
- AI disclosure remains separate from DCO certification.
