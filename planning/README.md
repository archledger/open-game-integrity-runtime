# Initial implementation backlog

The files under `planning/issues/` are reviewable GitHub issue bodies for the
first ten roadmap tasks. They deliberately begin with process, model, and state
machine work rather than TPM, Wine, BPF, or privileged code.

After creating the repository and running `scripts/bootstrap-github.sh`, review
each issue body and then run:

```bash
./scripts/create-initial-issues.sh owner/open-game-integrity-runtime
```

The script skips exact-title duplicates. Do not run it until repository
placeholders and GitHub settings have been reviewed.
