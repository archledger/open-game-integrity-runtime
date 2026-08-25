# Contributing to OGIR

OGIR is security-sensitive experimental software. Correctness, provenance, reviewability, and clearly bounded claims take priority over development speed.

## Before writing code

1. Read `docs/ARCHITECTURE.md`, `docs/SECURITY_INVARIANTS.md`, and `docs/THREAT_MODEL.md`.
2. Work from a GitHub issue with explicit scope, acceptance criteria, security impact, and test requirements.
3. Research current primary specifications and upstream source before selecting an API or dependency.
4. Create or update an architecture decision record for changes to trust boundaries, protocols, cryptography, privilege, dependencies, or persistent formats.
5. Write the negative tests that demonstrate how the feature must fail.

## Developer Certificate of Origin

Every commit proposed for merge must be certified under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/).
Read the certificate before signing. By adding a `Signed-off-by` trailer, the
person represented by the committer metadata makes the representations in that
certificate, including that they have the right to submit the contribution
under the project's licenses.

Configure Git with your own attributable name and email, review the complete
change, and create the commit with `-s` or `--signoff`:

```bash
git commit -s -m "Describe the contribution"
```

Git adds a trailer matching the committer identity:

```text
Signed-off-by: Contributor Name <contributor@example.com>
```

Inspect the result before pushing:

```bash
git log -1 --format='%H%n%B'
```

To repair only the latest unpublished commit after reviewing it:

```bash
git commit --amend --signoff --no-edit
```

To add your sign-off to every unpublished commit after a known upstream base:

```bash
git rebase --signoff <upstream>
```

Before opening an ordinary pull request to `main`, check the complete branch
range locally:

```bash
base_commit="$(git merge-base origin/main HEAD)"
./scripts/check-dco.sh "${base_commit}" HEAD
```

For a stacked pull request, use its actual target branch instead of
`origin/main` when finding the merge base.

Amending or rebasing changes commit IDs. Do not rewrite a published or shared
branch without coordinating with its maintainers. Never add another person's
sign-off, and never sign work you have not reviewed or cannot certify.

The automated check requires an exact trailer for each commit's committer. An
author and committer may differ, so the committer may certify contributed work
after reviewing it. Git name and email fields are self-asserted metadata: a
passing check proves that the trailer matches those fields, not that the named
person is authenticated or human. Pull-request authors and maintainers must
verify attribution during review.

GitHub-style `[bot]` committer identities are rejected as defense in depth, but
that pattern cannot identify every form of automation. The workflow also
requires GitHub to classify the pull-request author as a `User`, because that
account becomes the author of the final squash commit. A human must review an
automated change, recreate it on a human-authored branch and pull request, and
certify the resulting commits.

A DCO sign-off is not a copyright assignment, a contributor license agreement,
a cryptographic signature, or proof that code—generated or otherwise—is
non-infringing. Git's `-s`/`--signoff` and `-S` signing options serve different
purposes.

AI assistance is disclosed separately in the pull-request template. DCO
certification remains the human contributor's responsibility, and the human
must still verify provenance, licensing, correctness, and every changed line.

## Pull-request requirements

A pull request must include:

- the problem and threat addressed;
- the files and trust boundaries changed;
- primary-source references;
- positive and negative tests;
- fuzzing impact;
- privacy impact;
- compatibility and rollback impact;
- whether AI assisted the contribution;
- a `Signed-off-by` trailer matching the committer metadata and certifying the
  Developer Certificate of Origin on every commit.

Example:

```text
Signed-off-by: Contributor Name <contributor@example.com>
```

## Security-critical changes

The following require an explicit architecture decision record and an independent human review before a production release:

- cryptographic protocols or parameters;
- TPM commands, object templates, authorization policies, or key enrollment;
- verifier acceptance logic;
- evidence or permit parsing;
- local privileged operations;
- `unsafe` Rust or new C code;
- Wine ABI marshalling;
- BPF/LSM enforcement;
- update, signing, reference-value, or revocation logic;
- privacy claim expansion.

## Coding rules

- Safe Rust is the default. The workspace forbids `unsafe_code`.
- A future FFI crate may permit narrowly scoped `unsafe` only after an ADR and dedicated tests.
- Do not implement cryptographic primitives.
- Do not add dependencies without documenting purpose, maintenance status, license, transitive impact, and security surface.
- Do not log secrets, raw attestation identities, full evidence bundles, personal paths, or unrelated process information.
- Do not treat an attestation failure as proof of cheating.
- Do not silently broaden the protected-session policy.

## Local checks

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
```

Additional dependency, fuzzing, provenance, and bare-metal checks will become release gates as the relevant components are introduced.
