# M0-002: Configure GitHub rulesets and repository security features
<!-- labels: type: security-hardening,area: supply-chain,risk: trusted-computing-base,status: ready -->
<!-- milestone: M0 Repository Foundation -->

## Problem

The repository cannot rely on maintainer memory for branch, Actions, dependency, secret, and vulnerability-reporting controls.

## Security invariants

- The default branch cannot merge code that fails required checks.
- Fork pull requests cannot access production secrets.
- Vulnerabilities have a private reporting path.
- Force pushes and deletion of protected refs are blocked.

## In scope

- Apply the solo-maintainer branch ruleset documented in `docs/GITHUB_SETUP.md`.
- Set default `GITHUB_TOKEN` permissions to read-only.
- Enable private vulnerability reporting, dependency graph, Dependabot alerts/security updates, secret scanning/push protection, and CodeQL default setup where available.
- Protect `v*` tags without creating production signing keys.
- Record the exact settings and any plan/permission limitations in this issue.

## Out of scope

- Production release signing.
- Mandatory second-person review before a second trusted maintainer exists.
- Bypassing unavailable GitHub plan features with insecure custom automation.

## Primary sources

- GitHub rulesets: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets
- GitHub Actions hardening: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
- Secret scanning: https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning
- CodeQL default setup: https://docs.github.com/en/code-security/code-scanning/enabling-code-scanning/configuring-default-setup-for-code-scanning

## Required tests

- A pull request with a failing CI check cannot merge through the normal path.
- A test secret pattern is blocked in a disposable branch without committing a real secret.
- A private vulnerability report can be opened by an authorized test account or the configuration is independently verified.

## Acceptance criteria

- Settings match the documented solo-maintainer profile.
- Every unavailable control has a documented compensating measure.
- Screenshots or exported settings are attached without leaking sensitive repository data.
