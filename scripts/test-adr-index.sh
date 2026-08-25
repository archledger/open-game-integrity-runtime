#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="${repository_root}/scripts/check-adr-index.sh"

if [[ ! -x "${checker}" ]]; then
  echo "ADR checker is missing or not executable: ${checker}" >&2
  exit 1
fi

fixture_root="$(mktemp -d)"
trap 'rm -rf -- "${fixture_root}"' EXIT
failures=0

write_adr() {
  local path="$1"
  local id="$2"
  local title="$3"
  local status="$4"

  printf '%s\n' \
    "# ADR-${id}: ${title}" \
    "" \
    "- Status: ${status}" \
    "- Date: 2026-08-25" \
    "- Owners: Test Maintainer" \
    "- Related issues: None" \
    "" \
    "## Context" \
    "Test context." \
    "" \
    "## Decision drivers" \
    "Test driver." \
    "" \
    "## Options considered" \
    "Test option." \
    "" \
    "## Decision" \
    "Test decision." \
    "" \
    "## Consequences" \
    "Test consequence." \
    "" \
    "## Threat-model impact" \
    "Not applicable because this is a fixture." \
    "" \
    "## Privacy impact" \
    "Not applicable because this is a fixture." \
    "" \
    "## Dependency and license impact" \
    "Not applicable because this is a fixture." \
    "" \
    "## Validation" \
    "Run the fixture checker." \
    "" \
    "## Rollback" \
    "Restore the prior fixture." \
    "" \
    "## Primary sources" \
    "Not applicable because this is a fixture." >"${path}"
}

write_index() {
  local include_rejected="$1"

  printf '%s\n' \
    "# ADR index" \
    "" \
    "| ADR | Status | Decision |" \
    "| --- | --- | --- |" \
    "| [ADR-0001](0001-accepted.md) | Accepted | Accepted fixture |" \
    >"${fixture}/docs/adr/index.md"

  if [[ "${include_rejected}" == "yes" ]]; then
    printf '%s\n' \
      "| [ADR-0002](0002-rejected.md) | Rejected | Rejected fixture retained |" \
      >>"${fixture}/docs/adr/index.md"
  fi
}

write_template() {
  printf '%s\n' \
    "# ADR-NNNN: Title" \
    "" \
    "- Status: Proposed | Accepted | Superseded | Rejected | Experimental" \
    "- Date: YYYY-MM-DD" \
    "- Owners: Decision owners" \
    "- Related issues: Issue links" \
    "" \
    "## Context" \
    "Describe the problem and constraints." \
    "" \
    "## Decision drivers" \
    "List the forces that shape the decision." \
    "" \
    "## Options considered" \
    "Describe each viable option and why it was accepted or rejected." \
    "" \
    "## Decision" \
    "State the selected decision." \
    "" \
    "## Consequences" \
    "Record positive and negative consequences." \
    "" \
    "## Threat-model impact" \
    "Describe changed threats or explain why none apply." \
    "" \
    "## Privacy impact" \
    "Describe changed disclosures or explain why none apply." \
    "" \
    "## Dependency and license impact" \
    "Describe dependency and licensing effects or explain why none apply." \
    "" \
    "## Validation" \
    "List the evidence required to validate the decision." \
    "" \
    "## Rollback" \
    "Describe safe reversal or why reversal requires a superseding ADR." \
    "" \
    "## Primary sources" \
    "List authoritative sources." >"${fixture}/docs/adr/template.md"
}

make_fixture() {
  local name="$1"
  fixture="${fixture_root}/${name}"
  mkdir -p "${fixture}/docs/adr"
  git -C "${fixture}" init -q
  printf '%s\n' \
    "# Architecture decision records" \
    "" \
    "See the [decision index](index.md) and [ADR template](template.md)." \
    >"${fixture}/docs/adr/README.md"
  write_template
  write_adr "${fixture}/docs/adr/0001-accepted.md" "0001" \
    "Accepted fixture" "Accepted"
  write_adr "${fixture}/docs/adr/0002-rejected.md" "0002" \
    "Rejected fixture" "Rejected"
  write_index yes
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
    printf 'FAIL: %s did not report %s\n%s\n' \
      "${name}" "${expected}" "${output}" >&2
    failures=$((failures + 1))
  else
    printf 'PASS: %s\n' "${name}"
  fi
}

make_fixture valid-with-rejected
expect_pass "accepted and rejected ADRs remain indexed"

make_fixture missing-index-entry
write_index no
git -C "${fixture}" add docs/adr/index.md
expect_fail "ADR omitted from index" \
  "ADR-0002 is missing from docs/adr/index.md"

make_fixture stale-index-entry
printf '%s\n' \
  "| [ADR-0099](0099-deleted.md) | Rejected | Deleted ADR must not disappear |" \
  >>"${fixture}/docs/adr/index.md"
git -C "${fixture}" add docs/adr/index.md
expect_fail "index references deleted ADR" \
  "ADR-0099 index entry references missing docs/adr/0099-deleted.md"

make_fixture duplicate-index-entry
printf '%s\n' \
  "| [ADR-0001](0001-accepted.md) | Accepted | Duplicate fixture |" \
  >>"${fixture}/docs/adr/index.md"
git -C "${fixture}" add docs/adr/index.md
expect_fail "duplicate ADR index entry" \
  "ADR-0001 has duplicate entries in docs/adr/index.md"

make_fixture mismatched-index-status
sed -i \
  's/| Accepted | Accepted fixture |/| Proposed | Accepted fixture |/' \
  "${fixture}/docs/adr/index.md"
git -C "${fixture}" add docs/adr/index.md
expect_fail "index status differs from ADR" \
  "ADR-0001 index status does not match staged ADR status"

make_fixture invalid-adr-status
sed -i 's/^- Status: Accepted$/- Status: Deprecated/' \
  "${fixture}/docs/adr/0001-accepted.md"
sed -i \
  's/| Accepted | Accepted fixture |/| Deprecated | Accepted fixture |/' \
  "${fixture}/docs/adr/index.md"
git -C "${fixture}" add docs/adr/0001-accepted.md docs/adr/index.md
expect_fail "unsupported ADR status" \
  "docs/adr/0001-accepted.md: invalid ADR status: Deprecated"

make_fixture mismatched-adr-identifier
sed -i '1s/^# ADR-0001:/# ADR-0009:/' \
  "${fixture}/docs/adr/0001-accepted.md"
git -C "${fixture}" add docs/adr/0001-accepted.md
expect_fail "ADR title identifier differs from filename" \
  "docs/adr/0001-accepted.md: ADR identifier does not match filename"

make_fixture invalid-adr-title
sed -i '1s/^# ADR-0001:/# Decision 0001:/' \
  "${fixture}/docs/adr/0001-accepted.md"
git -C "${fixture}" add docs/adr/0001-accepted.md
expect_fail "ADR title does not use canonical form" \
  "docs/adr/0001-accepted.md: invalid ADR title"

make_fixture missing-required-section
sed -i '/^## Privacy impact$/d' \
  "${fixture}/docs/adr/0001-accepted.md"
git -C "${fixture}" add docs/adr/0001-accepted.md
expect_fail "ADR omits required security section" \
  "docs/adr/0001-accepted.md: missing required ADR section: Privacy impact"

make_fixture empty-required-section
sed -i '/^## Privacy impact$/ { n; d; }' \
  "${fixture}/docs/adr/0001-accepted.md"
git -C "${fixture}" add docs/adr/0001-accepted.md
expect_fail "ADR leaves required security section empty" \
  "docs/adr/0001-accepted.md: empty required ADR section: Privacy impact"

make_fixture duplicate-required-section
printf '%s\n' "" "## Privacy impact" "Duplicate impact." \
  >>"${fixture}/docs/adr/0001-accepted.md"
git -C "${fixture}" add docs/adr/0001-accepted.md
expect_fail "ADR duplicates required section" \
  "docs/adr/0001-accepted.md: duplicate required ADR section: Privacy impact"

make_fixture missing-template
git -C "${fixture}" rm -q -f docs/adr/template.md
expect_fail "ADR template is deleted" \
  "docs/adr/template.md is missing from staged files"

make_fixture incomplete-template
sed -i '/^## Privacy impact$/d' "${fixture}/docs/adr/template.md"
git -C "${fixture}" add docs/adr/template.md
expect_fail "ADR template omits required section" \
  "docs/adr/template.md: missing required ADR section: Privacy impact"

make_fixture empty-template-section
sed -i '/^## Privacy impact$/ { n; d; }' \
  "${fixture}/docs/adr/template.md"
git -C "${fixture}" add docs/adr/template.md
expect_fail "ADR template leaves required section empty" \
  "docs/adr/template.md: empty required ADR section: Privacy impact"

make_fixture duplicate-template-section
printf '%s\n' "" "## Privacy impact" "Duplicate impact." \
  >>"${fixture}/docs/adr/template.md"
git -C "${fixture}" add docs/adr/template.md
expect_fail "ADR template duplicates required section" \
  "docs/adr/template.md: duplicate required ADR section: Privacy impact"

make_fixture missing-readme-links
printf '%s\n' "# Architecture decision records" \
  >"${fixture}/docs/adr/README.md"
git -C "${fixture}" add docs/adr/README.md
expect_fail "ADR README omits navigation links" \
  "docs/adr/README.md must link to index.md and template.md"

make_fixture missing-readme
git -C "${fixture}" rm -q -f docs/adr/README.md
expect_fail "ADR README is deleted" \
  "docs/adr/README.md is missing from staged files"

make_fixture staged-adr-wins
sed -i '/^## Privacy impact$/d' \
  "${fixture}/docs/adr/0001-accepted.md"
expect_pass "staged ADR is not hidden by worktree edit"

make_fixture staged-index-wins
write_index no
expect_pass "staged index is not hidden by worktree edit"

make_fixture subdirectory-root
fixture="${fixture}/docs"
expect_pass "subdirectory invocation uses canonical repository root"

fixture="${fixture_root}/bare.git"
git init --bare -q "${fixture}"
expect_fail "bare repository" "ADR index check requires a Git worktree"

make_fixture corrupt-index
printf '%s\n' "corrupt-index" >"${fixture}/.git/index"
expect_fail "corrupt Git index" \
  "ADR index check failed to enumerate staged ADR files"

if ((failures > 0)); then
  printf '%d ADR index test(s) failed\n' "${failures}" >&2
  exit 1
fi

echo "All ADR index tests passed."
