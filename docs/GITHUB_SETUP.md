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

Initialize and stage the local repository:

```bash
git init -b main
git add .
```

Verify repository identity and source-license boundaries before committing:

```bash
./scripts/check-repository-metadata.sh
```

Then create the signed bootstrap commit:

```bash
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
- compulsory sign-off for web-based commits;
- automatic deletion of head branches after merge.

Disable initially:

- Wiki, to avoid architecture drifting outside version control;
- GitHub Pages until documentation publishing is intentional;
- merge commits if you prefer a linear history;
- Actions from unapproved sources.

Recommended merge method:

- squash merge ordinary pull requests only through the GitHub.com web interface,
  so compulsory web sign-off covers the newly created base-branch commit;
- do not directly merge bot-authored pull requests; recreate reviewed changes in
  a human-authored pull request;
- signed annotated tags for releases;
- no direct release from a contributor pull-request workflow.

## 5. Actions security

Repository Actions permissions:

- default `GITHUB_TOKEN` permission: read-only, with only the documented
  per-workflow exception needed to publish the DCO commit status;
- allow GitHub-authored actions and a small explicit allowlist;
- require actions to be pinned to full commit SHAs when the organization setting becomes available;
- never run untrusted pull-request code with production secrets;
- avoid `pull_request_target` for build/test execution;
- require environment approval for future release signing;
- keep production signing outside ordinary CI until a reviewed design exists.

The included CI workflow pins `actions/checkout` to the reviewed commit for v7.0.1 and sets `persist-credentials: false`.

### DCO status enforcement

The repository uses its own `scripts/check-dco.sh` and
`.github/workflows/dco.yml`; it does not install a third-party DCO app or run a
third-party DCO action. The local negative suite is:

```bash
./scripts/test-dco.sh
```

The workflow uses `pull_request_target` only to read commit metadata from the
trusted base branch. It checks out the exact base commit, fetches pull-request
Git objects without checking out or executing pull-request content, and runs the
base branch's checker. It also rejects pull requests whose authenticated GitHub
actor type is not `User`; a human-looking service account still requires review.
Do not change it to build or execute head-branch code.

Its `GITHUB_TOKEN` permissions are deliberately limited to:

- `contents: read`, for the trusted base checkout;
- `statuses: write`, solely to publish `DCO / signoff` on the pull-request head
  commit.

The token cannot write repository contents, modify pull requests, or approve
reviews. Because `pull_request_target` is a privileged trigger, this workflow
must remain secret-free: it references no repository or organization secrets,
but token permissions alone do not remove the trigger's potential secret
access. The only referenced action is GitHub-owned `actions/checkout`, pinned to
a full commit SHA with credentials not persisted. Status publication uses the
GitHub CLI preinstalled on GitHub-hosted runners. The remaining trusted supply
chain is GitHub Actions, the hosted runner image, Git, Bash, GitHub CLI, the
GitHub status API, and the checker on the protected base branch. CODEOWNERS
review applies to workflow changes.

The status check validates matching self-certification trailers on the
pull-request commits. Git metadata is not identity authentication. Human
accountability also depends on authenticated pull-request activity and human
review. Squash merge creates a different commit on `main`, so the repository's
compulsory web sign-off setting separately certifies that web-created commit by
its pull-request author. Do not use CLI/API merge paths unless they are later
proved to preserve this final-commit sign-off.

The active main ruleset already requires both `CI / rust` and `DCO / signoff`.
Its creation exemption permits the empty repository's first human-certified
push; it does not waive checks on later pull-request merges.

After this workflow exists on the default branch:

1. Open a temporary pull request with one unsigned commit and confirm the
   `DCO / signoff` status fails.
2. Repair that commit under the responsible human's identity and confirm the
   same status succeeds.
3. Confirm the already-required status blocks the unsigned test pull request
   from merging, then close it without merging.
4. Bind the required status to the GitHub Actions source when GitHub offers that
   selector for the newly observed context.

The local negative suite satisfies the pre-remote regression requirement, but
it does not substitute for this one-time live activation check.

## 6. Main branch ruleset

### Solo-maintainer experimental phase

A mandatory external approval would make a solo repository unusable. Use:

- require pull requests before merge;
- required status checks: `CI / rust` and `DCO / signoff`;
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
./scripts/bootstrap-github.sh archledger/open-game-integrity-runtime
```

Then review and create the first ten issue specifications:

```bash
./scripts/create-initial-issues.sh archledger/open-game-integrity-runtime
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

The remote began empty and the local bootstrap history predates enforcement. Do
not grandfather or push that unsigned history. The responsible human must:

1. Freeze the intended publication tip and review every commit and changed line.
2. From that clean tip, add their own certification to the complete unpublished
   history:

   ```bash
   git rebase --root --signoff
   ```

3. Reconcile any local stacked branch references affected by the rewritten
   commit IDs, then prove every reachable commit—including the root—is certified:

   ```bash
   ./scripts/check-dco.sh --root HEAD
   ```

4. Run `./scripts/check.sh` and inspect the complete range diff.
5. Push only that human-reviewed, certified history to create `main`. The
   ruleset's creation exemption exists solely for this bootstrap; do not use the
   owner bypass to evade later failed checks.
6. Run the one-time unsigned/signed pull-request activation test above before
   accepting ordinary contributions.
7. Record the resulting commit IDs and live-check evidence. Do not begin TPM or
   Proton code until M1 domain types and M2 mock flow are specified.

`git rebase --root --signoff` is a history rewrite and a legal certification.
It must be performed by the responsible human, never by an AI system or bot.
