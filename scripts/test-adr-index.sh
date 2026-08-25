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
  printf '%s\n' \
    "# ADR-NNNN: Title" \
    "" \
    "Template content is supplied by the project." \
    >"${fixture}/docs/adr/template.md"
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

if ((failures > 0)); then
  printf '%d ADR index test(s) failed\n' "${failures}" >&2
  exit 1
fi

echo "All ADR index tests passed."
