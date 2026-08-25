# GitHub setup guide

## 1. Recommended repository

Initial repository name:

```text
open-game-integrity-runtime
```

Use a public repository so the protocol, security claims, and development history are inspectable. An organization such as `open-game-integrity` can be created later; a personal public repository is acceptable for the experimental phase.

Recommended description:

```text
Experimental privacy-preserving Linux game-integrity and attestation runtime for Windows games running through Proton.
```

Recommended topics:

```text
linux gaming proton wine rust tpm attestation security open-source
```

## 2. Prepare the local repository

Replace placeholders first:

```bash
rg 'YOUR-GITHUB-ACCOUNT|YOUR_GITHUB_USERNAME' -n .
```

Then initialize:

```bash
git init -b main
git add .
git commit -s -m "chore: bootstrap OGIR research repository"
```

The `-s` flag adds the DCO `Signed-off-by` trailer.

## 3. Create the remote with GitHub CLI

Authenticate:

```bash
gh auth login
```

Create and push:

```bash
gh repo create open-game-integrity-runtime \
  --public \
  --source=. \
  --remote=origin \
  --push \
  --description "Experimental privacy-preserving Linux game-integrity and attestation runtime for Windows games running through Proton."
```

Then open settings:

```bash
gh repo view --web
```

## 4. Repository feature settings

Enable:

- Issues;
- Discussions for architecture/community questions;
- Projects if you will use a board;
- private vulnerability reporting;
- dependency graph;
- Dependabot alerts and security updates;
- secret scanning and push protection;
- CodeQL default setup where available;
- automatic deletion of head branches after merge.

Disable initially:

- Wiki, to avoid architecture drifting outside version control;
- GitHub Pages until documentation publishing is intentional;
- merge commits if you prefer a linear history;
- Actions from unapproved sources.

Recommended merge method:

- squash merge for ordinary pull requests;
- signed annotated tags for releases;
- no direct release from a contributor pull-request workflow.

## 5. Actions security

Repository Actions permissions:

- default `GITHUB_TOKEN` permission: read-only;
- allow GitHub-authored actions and a small explicit allowlist;
- require actions to be pinned to full commit SHAs when the organization setting becomes available;
- never run untrusted pull-request code with production secrets;
- avoid `pull_request_target` for build/test execution;
- require environment approval for future release signing;
- keep production signing outside ordinary CI until a reviewed design exists.

The included CI workflow pins `actions/checkout` to the reviewed commit for v7.0.1 and sets `persist-credentials: false`.

## 6. Main branch ruleset

### Solo-maintainer experimental phase

A mandatory external approval would make a solo repository unusable. Use:

- require pull requests before merge;
- required status check: `CI / rust`;
- require conversation resolution;
- require signed commits where practical;
- block force pushes;
- block branch deletion;
- require linear history;
- do not require a review count yet;
- voluntarily use an independent AI review plus your own line-by-line review;
- require a human external reviewer before calling any release production-capable.

Keep administrator bypass visible and documented. Do not bypass failed security checks merely to merge.

### After a second trusted maintainer

Add:

- at least one approving review for ordinary code;
- two independent approvals for cryptography, TPM, verifier acceptance, privileged code, C/unsafe code, BPF/LSM, signing/update, policy/reference, and privacy changes;
- CODEOWNERS review;
- dismissal of stale approvals;
- approval of the most recent push by someone other than the pusher;
- code-scanning merge protection.

## 7. Tag ruleset

Protect tags matching:

```text
v*
```

Require:

- creation only through the release process;
- signed annotated tag;
- no update or deletion after publication;
- release artifacts generated from the protected tag;
- provenance, SBOM, checksums, and signatures before production maturity.

During the research phase, use versions such as:

```text
v0.0.1-research.1
v0.1.0-prototype.1
```

Do not imply stability through `v1.0.0` prematurely.

## 8. GitHub security setup checklist

- [ ] Enable private vulnerability reporting.
- [ ] Enable secret scanning.
- [ ] Enable push protection.
- [ ] Enable dependency graph.
- [ ] Enable Dependabot alerts.
- [ ] Enable Dependabot security updates.
- [ ] Confirm `.github/dependabot.yml` opens Cargo and Actions updates.
- [ ] Enable CodeQL default setup for Rust/C/C++ as supported.
- [ ] Enable code-scanning merge protection after the first successful baseline.
- [ ] Set Actions token permissions to read-only.
- [ ] Restrict Actions to trusted/pinned sources.
- [ ] Add the main-branch ruleset.
- [ ] Add the protected-tag ruleset.
- [ ] Enable automatic head-branch deletion.
- [ ] Confirm no repository or organization secret is available to fork PRs.
- [ ] Add a security contact once a private maintained address exists.

## 9. Bootstrap scripts

After replacing repository placeholders and reviewing the scripts, create the
recommended labels and milestones:

```bash
./scripts/bootstrap-github.sh owner/open-game-integrity-runtime
```

Then review and create the first ten issue specifications:

```bash
./scripts/create-initial-issues.sh owner/open-game-integrity-runtime
```

The scripts do not configure branch protection, secret scanning, CodeQL, or
release trust. Those controls require explicit review in the repository settings.

## 10. Labels

Create these labels:

### Type

```text
type: architecture
type: research
type: implementation
type: test
type: fuzzing
type: documentation
type: security-hardening
type: dependency
type: release
```

### Area

```text
area: model
area: protocol
area: verifier
area: agent
area: tpm
area: measured-boot
area: proton-bridge
area: session
area: wine-tpm
area: attack-lab
area: supply-chain
area: privacy
```

### Risk

```text
risk: trusted-computing-base
risk: privileged
risk: cryptography
risk: parser
risk: privacy
risk: compatibility
```

### Status

```text
status: needs-research
status: blocked
status: ready
status: needs-review
status: experimental
status: do-not-merge
```

Avoid using severity labels for public untriaged vulnerability reports; those belong in private security advisories.

## 11. Milestones

Create GitHub milestones:

```text
M0 Repository Foundation
M1 Domain Model
M2 Mock End-to-End Proof
M3 TPM Backend
M4 Measured Boot Profile
M5 Proton Bridge
M6 Publisher SDK and Verifier
M7 Session Observation
M8 Scoped Enforcement
M9 Attack Laboratory
M10 Wine TPM Compatibility
M11 Publisher Pilot
M12 Production Candidate
```

Do not assign calendar dates until dependencies and evidence are understood.

## 12. Project board

Recommended columns:

```text
Research question
Specification ready
Ready for implementation
In progress
Adversarial review
Human review
Blocked
Done with evidence
```

“Done with evidence” means the issue links to tests and exact verification output, not merely a merged patch.

## 13. Initial pull-request workflow

```text
Issue with acceptance criteria
 -> research/ADR pull request when needed
 -> implementation branch
 -> AI authoring assistance
 -> deterministic local checks
 -> independent AI adversarial review
 -> human line-by-line review
 -> CI
 -> merge
 -> close issue with test evidence
```

Use branches such as:

```text
research/23-cbor-cose-evaluation
feat/14-replay-cache
security/21-cross-context-tests
docs/3-threat-model
```

## 14. First push sequence

1. Push the unchanged bootstrap as the signed initial commit.
2. Open Issue 1 to replace placeholders and verify licensing.
3. Open Issue 2 for GitHub settings and record screenshots/settings in the issue.
4. Open Issue 3 to run the Rust checks, fix any toolchain-specific warnings, and commit `Cargo.lock`.
5. Create milestone M0 and assign the first six foundation issues.
6. Open the first ADR pull request before adding any external Rust dependency.
7. Do not begin TPM or Proton code until M1 domain types and M2 mock flow are specified.
