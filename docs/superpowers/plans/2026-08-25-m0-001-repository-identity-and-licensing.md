# M0-001 Repository Identity and License Boundaries Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Execution status:** Implemented and independently reviewed. The Independent Review Amendments below supersede the original checker/test code samples in Tasks 1-2.

**Goal:** Replace the bootstrap's unresolved repository identity, document the initial copyright-notice policy, and add an automated fail-closed gate for repository identity and source-license boundaries.

**Architecture:** Add one dependency-free Bash checker that resolves the canonical worktree, fails closed on Git errors, validates staged regular source blobs, and one fixture-based Bash test that exercises the real checker against disposable repositories. Run the gate before Rust setup in CI, and keep the established Apache, Wine/LGPL, and BPF/GPL path boundaries explicit.

**Tech Stack:** Bash, Git 2.x plumbing, GitHub Actions, SPDX license identifiers, existing Markdown/TOML/YAML configuration. No new package, Rust crate, GitHub Action, or network service.

**Spec:** `planning/issues/001-replace-placeholders-and-license-map.md`

## Global Constraints

- The verified GitHub account and initial CODEOWNER is `archledger`.
- Default Rust core, verifier, SDK, documentation, scripts, and attack-lab source remain `Apache-2.0`.
- Source under `wine/` must declare `LGPL-2.1-or-later`.
- Source under `bpf/` must declare `GPL-2.0-only` until an approved license-boundary decision changes that rule.
- Every tracked `.rs`, `.c`, `.h`, `.sh`, and executable extensionless shell source must contain its path-appropriate `SPDX-License-Identifier` declaration.
- The current collective notice form remains `Copyright 2026 OGIR contributors.`; it does not assign contributor copyright or claim future contributions.
- Do not modify the verified license texts: local Apache, LGPL 2.1, and GPL 2.0 texts match their respective official upstream text files byte-for-byte.
- Do not add dependencies, generate `Cargo.lock`, implement Rust behavior, create a GitHub remote, push, or change external GitHub settings in this issue.
- AI-created local commits do not add a DCO `Signed-off-by` trailer. A human contributor must add the legal attestation before publication.

## Authoritative Sources

- REUSE Specification 3.3 comment-header and license-file rules: https://reuse.software/spec/
- SPDX license list entries: https://spdx.org/licenses/Apache-2.0.html, https://spdx.org/licenses/LGPL-2.1-or-later.html, https://spdx.org/licenses/GPL-2.0-only.html
- Apache License 2.0 official text and application guidance: https://www.apache.org/licenses/LICENSE-2.0.txt and https://www.apache.org/legal/apply-license
- GNU LGPL 2.1 and GPL 2.0 official texts: https://www.gnu.org/licenses/old-licenses/lgpl-2.1.txt and https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
- Wine's upstream license statement: https://github.com/wine-mirror/wine/blob/master/LICENSE
- Git tracked-file and search behavior: https://git-scm.com/docs/git-ls-files and https://git-scm.com/docs/git-grep
- GitHub CODEOWNERS identity and syntax rules: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners

---

### Task 1: Specify repository-metadata behavior with executable fixture tests

**Files:**
- Create: `scripts/test-repository-metadata.sh`
- Test: `scripts/test-repository-metadata.sh`

**Interfaces:**
- Consumes: executable `scripts/check-repository-metadata.sh [repository-root]`
- Produces: a zero-exit fixture suite covering a valid repository, both unresolved identity markers, missing SPDX metadata, and incorrect Wine/BPF license boundaries

- [ ] **Step 1: Write the failing behavior test**

Create `scripts/test-repository-metadata.sh` with this content:

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="${repository_root}/scripts/check-repository-metadata.sh"

if [[ ! -x "${checker}" ]]; then
  echo "metadata checker is missing or not executable: ${checker}" >&2
  exit 1
fi

fixture_root="$(mktemp -d)"
trap 'rm -rf -- "${fixture_root}"' EXIT
failures=0

make_fixture() {
  local name="$1"
  fixture="${fixture_root}/${name}"
  mkdir -p "${fixture}/src" "${fixture}/scripts" "${fixture}/wine" "${fixture}/bpf"
  git -C "${fixture}" init -q
  printf '%s\n' '// SPDX-License-Identifier: Apache-2.0' >"${fixture}/src/lib.rs"
  printf '%s\n' '#!/usr/bin/env bash' '# SPDX-License-Identifier: Apache-2.0' >"${fixture}/scripts/tool.sh"
  printf '%s\n' '/* SPDX-License-Identifier: LGPL-2.1-or-later */' >"${fixture}/wine/example.c"
  printf '%s\n' '/* SPDX-License-Identifier: GPL-2.0-only */' >"${fixture}/bpf/example.bpf.c"
  git -C "${fixture}" add .
}

expect_pass() {
  local name="$1"
  local output
  if output="$("${checker}" "${fixture}" 2>&1)"; then
    printf 'PASS: %s\n' "${name}"
  else
    printf 'FAIL: %s unexpectedly failed\n%s\n' "${name}" "${output}" >&2
    failures=$((failures + 1))
  fi
}

expect_fail() {
  local name="$1"
  local expected="$2"
  local output
  if output="$("${checker}" "${fixture}" 2>&1)"; then
    printf 'FAIL: %s unexpectedly passed\n' "${name}" >&2
    failures=$((failures + 1))
  elif [[ "${output}" != *"${expected}"* ]]; then
    printf 'FAIL: %s did not report %s\n%s\n' "${name}" "${expected}" "${output}" >&2
    failures=$((failures + 1))
  else
    printf 'PASS: %s\n' "${name}"
  fi
}

make_fixture clean
expect_pass "valid metadata"

make_fixture account-marker
account_marker='YOUR-GITHUB-'"ACCOUNT"
printf '%s\n' "${account_marker}" >"${fixture}/README.md"
git -C "${fixture}" add README.md
expect_fail "repository account marker" "unresolved repository identity marker"

make_fixture username-marker
username_marker='YOUR_GITHUB_'"USERNAME"
printf '%s\n' "${username_marker}" >"${fixture}/README.md"
git -C "${fixture}" add README.md
expect_fail "CODEOWNERS username marker" "unresolved repository identity marker"

make_fixture missing-spdx
printf '%s\n' 'pub fn missing_license() {}' >"${fixture}/src/missing.rs"
git -C "${fixture}" add src/missing.rs
expect_fail "missing source license" "src/missing.rs: expected SPDX-License-Identifier: Apache-2.0"

make_fixture wrong-wine-license
printf '%s\n' '/* SPDX-License-Identifier: Apache-2.0 */' >"${fixture}/wine/example.c"
git -C "${fixture}" add wine/example.c
expect_fail "incorrect Wine license" "wine/example.c: expected SPDX-License-Identifier: LGPL-2.1-or-later"

make_fixture wrong-bpf-license
printf '%s\n' '/* SPDX-License-Identifier: Apache-2.0 */' >"${fixture}/bpf/example.bpf.c"
git -C "${fixture}" add bpf/example.bpf.c
expect_fail "incorrect BPF license" "bpf/example.bpf.c: expected SPDX-License-Identifier: GPL-2.0-only"

if ((failures > 0)); then
  printf '%d repository metadata test(s) failed\n' "${failures}" >&2
  exit 1
fi

echo "All repository metadata tests passed."
```

Make it executable:

```bash
chmod +x scripts/test-repository-metadata.sh
```

- [ ] **Step 2: Run the test to verify the red state**

Run:

```bash
./scripts/test-repository-metadata.sh
```

Expected: exit 1 with `metadata checker is missing or not executable`; the failure is caused by the absent production checker.

### Task 2: Implement the minimal fail-closed metadata checker

**Files:**
- Create: `scripts/check-repository-metadata.sh`
- Test: `scripts/test-repository-metadata.sh`

**Interfaces:**
- Consumes: optional repository-root path; otherwise uses the current Git worktree root
- Produces: exit 0 only when tracked identity markers are absent and all tracked source files contain the license identifier required by their path

- [ ] **Step 1: Add the checker implementation**

Create `scripts/check-repository-metadata.sh` with this content:

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repository_root="${1:-}"
if [[ -z "${repository_root}" ]]; then
  repository_root="$(git rev-parse --show-toplevel)"
fi

if ! git -C "${repository_root}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "repository metadata check requires a Git worktree: ${repository_root}" >&2
  exit 2
fi

account_marker='YOUR-GITHUB-'"ACCOUNT"
username_marker='YOUR_GITHUB_'"USERNAME"
status=0

if marker_matches="$(
  git -C "${repository_root}" grep -n -F \
    -e "${account_marker}" \
    -e "${username_marker}" \
    -- .
)"; then
  echo "unresolved repository identity marker(s):" >&2
  printf '%s\n' "${marker_matches}" >&2
  status=1
fi

while IFS= read -r -d '' path; do
  case "${path}" in
    *.rs | *.c | *.h | *.sh)
      expected_license="Apache-2.0"
      case "${path}" in
        wine/*) expected_license="LGPL-2.1-or-later" ;;
        bpf/*) expected_license="GPL-2.0-only" ;;
      esac

      if ! grep -Fq -- "SPDX-License-Identifier: ${expected_license}" "${repository_root}/${path}"; then
        printf '%s: expected SPDX-License-Identifier: %s\n' "${path}" "${expected_license}" >&2
        status=1
      fi
      ;;
  esac
done < <(git -C "${repository_root}" ls-files -z)

if ((status != 0)); then
  exit "${status}"
fi

echo "Repository metadata check passed."
```

Make it executable:

```bash
chmod +x scripts/check-repository-metadata.sh
```

- [ ] **Step 2: Run the fixture suite to verify green behavior**

Run:

```bash
./scripts/test-repository-metadata.sh
```

Expected after independent-review remediation: fourteen `PASS:` lines followed by `All repository metadata tests passed.`

- [ ] **Step 3: Prove the checker fails against the unresolved bootstrap**

Run:

```bash
./scripts/check-repository-metadata.sh
```

Expected: exit 1 with `unresolved repository identity marker(s):` and paths in Cargo, CODEOWNERS, issue-template config, setup documentation, and the M0-001 issue body. No source-license error should appear.

- [ ] **Step 4: Commit the tested checker slice**

```bash
git add scripts/check-repository-metadata.sh scripts/test-repository-metadata.sh
git diff --cached --check
git commit -m "test: add repository metadata gate"
```

### Task 3: Replace repository identity and document the copyright-notice policy

**Files:**
- Modify: `Cargo.toml:17`
- Modify: `.github/CODEOWNERS:1-10`
- Modify: `.github/ISSUE_TEMPLATE/config.yml:1-8`
- Modify: `docs/GITHUB_SETUP.md:23-31`
- Modify: `planning/issues/001-replace-placeholders-and-license-map.md:5-10`
- Modify: `LICENSES.md:1-18`
- Verify unchanged: `NOTICE`, `LICENSE`, `LICENSES/Apache-2.0.txt`, `LICENSES/LGPL-2.1-or-later.txt`, `LICENSES/GPL-2.0-only.txt`
- Test: `scripts/check-repository-metadata.sh`

**Interfaces:**
- Consumes: verified GitHub login `archledger` and the existing three-path licensing map
- Produces: resolvable repository URLs, valid initial CODEOWNER entries, a documented non-assignment notice policy, and a clean repository-metadata check

- [ ] **Step 1: Replace repository URLs and CODEOWNERS identity**

Set the workspace repository field to:

```toml
repository = "https://github.com/archledger/open-game-integrity-runtime"
```

Set `.github/ISSUE_TEMPLATE/config.yml` contact URLs to:

```yaml
blank_issues_enabled: false
contact_links:
  - name: Private security report
    url: https://github.com/archledger/open-game-integrity-runtime/security/advisories/new
    about: Do not report vulnerabilities in a public issue.
  - name: Design discussion
    url: https://github.com/archledger/open-game-integrity-runtime/discussions
    about: Use Discussions for broad questions that are not yet implementation-ready.
```

Set `.github/CODEOWNERS` to:

```text
# Initial solo maintainer; expand ownership after a second trusted maintainer joins.
* @archledger

/docs/SECURITY_INVARIANTS.md @archledger
/docs/THREAT_MODEL.md @archledger
/docs/adr/ @archledger
/.github/workflows/ @archledger
/sdk/include/ @archledger
/wine/ @archledger
/bpf/ @archledger
```

- [ ] **Step 2: Replace self-referential scan documentation**

In `docs/GITHUB_SETUP.md`, place the metadata check after `git init -b main` and `git add .`, but before the bootstrap commit:

```bash
./scripts/check-repository-metadata.sh
```

In the M0-001 issue body's Problem section, use:

```markdown
The bootstrap contains unresolved repository owner and CODEOWNERS identity markers. The repository also crosses Apache-2.0, LGPL-2.1-or-later, and GPL-2.0-only boundaries. These must be explicit before accepting contributions.
```

- [ ] **Step 3: Record the initial notice policy without assigning contributor rights**

Append this section to `LICENSES.md`:

```markdown
## Copyright notice policy

The initial collective-work notice is `Copyright 2026 OGIR contributors.` Copyright in each contribution remains with its actual copyright holder unless separately transferred. The collective notice does not assign contributor rights or claim ownership of future contributions.
```

Keep `NOTICE` unchanged and verify its notice line exactly matches the documented form.

- [ ] **Step 4: Run the real repository gate**

Run:

```bash
./scripts/check-repository-metadata.sh
./scripts/test-repository-metadata.sh
```

Expected: both commands exit 0; after independent-review remediation the fixture suite reports fourteen passing cases.

- [ ] **Step 5: Verify official license texts were not modified**

Run:

```bash
git diff --exit-code 33ea390 -- LICENSE LICENSES/Apache-2.0.txt LICENSES/LGPL-2.1-or-later.txt LICENSES/GPL-2.0-only.txt
```

Expected: exit 0 with no output.

- [ ] **Step 6: Commit the identity and policy slice**

```bash
git add Cargo.toml .github/CODEOWNERS .github/ISSUE_TEMPLATE/config.yml docs/GITHUB_SETUP.md planning/issues/001-replace-placeholders-and-license-map.md LICENSES.md
git diff --cached --check
git commit -m "chore: establish repository identity and license policy"
```

### Task 4: Enforce repository metadata locally and in CI

**Files:**
- Modify: `scripts/check.sh:1-6`
- Modify: `.github/workflows/ci.yml:21-29`
- Test: `scripts/test-repository-metadata.sh`
- Test: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the two executable repository-metadata scripts from Tasks 1-2
- Produces: an early local and CI quality gate that runs before Rust toolchain installation

- [ ] **Step 1: Add metadata checks to the local aggregate script**

Insert these commands immediately after `set -euo pipefail` in `scripts/check.sh`:

```bash
./scripts/test-repository-metadata.sh
./scripts/check-repository-metadata.sh
```

- [ ] **Step 2: Add the early CI step**

Insert this step immediately after checkout and before Rust installation in `.github/workflows/ci.yml`:

```yaml
      - name: Check repository metadata
        run: |
          ./scripts/test-repository-metadata.sh
          ./scripts/check-repository-metadata.sh
```

- [ ] **Step 3: Validate executable behavior and shell quality**

Run:

```bash
./scripts/test-repository-metadata.sh
./scripts/check-repository-metadata.sh
bash -n scripts/*.sh
shellcheck scripts/*.sh
```

Expected: both metadata commands pass; Bash syntax and ShellCheck emit no findings.

- [ ] **Step 4: Commit CI integration**

```bash
git add scripts/check.sh .github/workflows/ci.yml
git diff --cached --check
git commit -m "ci: enforce repository metadata before builds"
```

## Independent Review Amendments

The first independent review of `33ea390..be85830` returned `Ready to merge? No`. The following test-first corrections supersede the original Tasks 1-2 checker snippets:

- bare repositories, corrupt indexes, marker-search failures, and tracked-file enumeration failures return infrastructure errors instead of passing;
- SPDX validation accepts exactly one path-appropriate comment declaration in the first five lines and rejects string decoys, missing, incorrect, duplicate, and conflicting declarations;
- tracked source symlinks/non-regular modes fail, and regular sources are validated from staged Git blobs rather than mutable worktree targets;
- any supplied subdirectory resolves to the canonical worktree top level before repository-wide scanning;
- generic owner/repository marker forms are rejected and all repository examples use `archledger`;
- executable extensionless shell sources are classified by their staged shebang and require SPDX metadata;
- the suite contains fourteen positive/negative fixtures covering these behaviors.

The configured repository and security/discussion URLs still return 404 until the public GitHub repository is created. That external acceptance criterion remains a blocker; this plan does not authorize creating or configuring the remote.

### Task 5: Run the M0-001 completion gate and review the final change

**Files:**
- Review: every path changed since `33ea390`
- Verify: repository and test scripts, CI workflow, license map, identity-bearing files

**Interfaces:**
- Consumes: Tasks 1-4 and the M0-001 acceptance criteria
- Produces: evidence that the local branch satisfies M0-001 without broadening into M0-002 or M0-003

- [ ] **Step 1: Run all in-scope deterministic checks**

```bash
./scripts/test-repository-metadata.sh
./scripts/check-repository-metadata.sh
bash -n scripts/*.sh
shellcheck scripts/*.sh
git diff --check 33ea390..HEAD
```

Expected: all commands exit 0 and the fixture suite reports fourteen passing cases.

- [ ] **Step 2: Confirm scope and sensitive-data hygiene**

```bash
git diff --stat 33ea390..HEAD
git diff --name-only 33ea390..HEAD
git grep -n -I -E '(BEGIN [A-Z ]*PRIVATE KEY|api[_-]?key[[:space:]]*[:=]|password[[:space:]]*[:=]|secret[[:space:]]*[:=]|token[[:space:]]*[:=])' HEAD -- .
```

Expected: only M0-001 plan, checker/test, repository identity, license-policy documentation, and CI/local-check integration paths changed; the sensitive-value scan returns no matches.

- [ ] **Step 3: Review failure behavior manually**

Confirm from the fixture suite and checker output that:

- either unresolved identity marker makes the gate fail;
- a missing source SPDX line makes the gate fail;
- an Apache declaration under `wine/` makes the gate fail;
- an Apache declaration under `bpf/` makes the gate fail;
- SPDX string decoys and conflicting headers make the gate fail;
- tracked source symlinks, bare repositories, corrupt indexes, and subdirectory-scope attempts fail closed;
- generic owner markers and executable extensionless shell sources without SPDX metadata make the gate fail;
- the valid fixture and real repository pass;
- the checker resolves the canonical worktree and examines staged regular source blobs from NUL-delimited Git index records.

- [ ] **Step 4: Record limitations accurately**

The handoff and final report must state:

- full Rust compilation, Clippy, tests, docs, `cargo deny`, and `Cargo.lock` generation remain M0-003 work;
- no GitHub remote, repository, ruleset, issue, PR, or security setting was created;
- configured repository/security/discussion URLs remain an explicit 404 blocker until remote creation is separately authorized;
- local commits have no AI-applied DCO sign-off and require human review before publication;
- this gate enforces the issue's source-file subset and is not a claim of full REUSE 3.3 compliance for every repository file.

- [ ] **Step 5: Refresh project state**

Update `/home/wisbfime/Agent Shared Memory/project-open-game-integrity-runtime.md` Current State and append a factual codex checkpoint with exact branch, OIDs, changed paths, command results, external state, rollback, lessons, and next action. Update the matching row in `/home/wisbfime/Agent Shared Memory/index.md`.
