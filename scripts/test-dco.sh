#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="${repository_root}/scripts/check-dco.sh"

if [[ ! -x "${checker}" ]]; then
  echo "DCO checker is missing or not executable: ${checker}" >&2
  exit 1
fi

fixture_root="$(mktemp -d)"
trap 'rm -rf -- "${fixture_root}"' EXIT
failures=0

make_fixture() {
  local name="$1"
  fixture="${fixture_root}/${name}"
  mkdir -p "${fixture}"
  git -C "${fixture}" init -q
  git -C "${fixture}" config user.name "Test Contributor"
  git -C "${fixture}" config user.email "test.contributor@example.com"
  git -C "${fixture}" config commit.gpgsign false
  printf '%s\n' "base" >"${fixture}/content.txt"
  git -C "${fixture}" add content.txt
  git -C "${fixture}" commit -q -s -m "base commit"
  base="$(git -C "${fixture}" rev-parse HEAD)"
}

change_content() {
  local value="$1"
  printf '%s\n' "${value}" >>"${fixture}/content.txt"
  git -C "${fixture}" add content.txt
}

expect_pass() {
  local name="$1"
  local output
  if output="$("${checker}" "${base}" "${head}" "${fixture}" 2>&1)"; then
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
  if output="$("${checker}" "${base}" "${head}" "${fixture}" 2>&1)"; then
    printf 'FAIL: %s unexpectedly passed\n' "${name}" >&2
    failures=$((failures + 1))
  elif [[ "${output}" != *"${expected}"* ]]; then
    printf 'FAIL: %s did not report %s\n%s\n' "${name}" "${expected}" "${output}" >&2
    failures=$((failures + 1))
  else
    printf 'PASS: %s\n' "${name}"
  fi
}

make_fixture signed
change_content signed
git -C "${fixture}" commit -q -s -m "signed commit"
head="$(git -C "${fixture}" rev-parse HEAD)"
expect_pass "matching committer sign-off"

make_fixture signed-root-history
change_content signed-root-history
git -C "${fixture}" commit -q -s -m "signed descendant"
head="$(git -C "${fixture}" rev-parse HEAD)"
base="--root"
expect_pass "signed root history"

fixture="${fixture_root}/unsigned-root-history"
mkdir -p "${fixture}"
git -C "${fixture}" init -q
git -C "${fixture}" config user.name "Test Contributor"
git -C "${fixture}" config user.email "test.contributor@example.com"
git -C "${fixture}" config commit.gpgsign false
printf '%s\n' "unsigned root" >"${fixture}/content.txt"
git -C "${fixture}" add content.txt
git -C "${fixture}" commit -q -m "unsigned root commit"
change_content signed-descendant
git -C "${fixture}" commit -q -s -m "signed descendant"
head="$(git -C "${fixture}" rev-parse HEAD)"
base="--root"
expect_fail "unsigned root in full-history audit" \
  "missing committer DCO sign-off"

make_fixture distinct-author
change_content distinct-author
git -C "${fixture}" commit -q -s -m "committer signs contributed work" \
  --author="Original Author <original.author@example.com>"
head="$(git -C "${fixture}" rev-parse HEAD)"
expect_pass "committer sign-off with distinct author"

make_fixture subdirectory
change_content subdirectory
git -C "${fixture}" commit -q -s -m "signed commit from a subdirectory"
head="$(git -C "${fixture}" rev-parse HEAD)"
mkdir -p "${fixture}/nested"
fixture="${fixture}/nested"
expect_pass "repository subdirectory"

make_fixture automated-committer
git -C "${fixture}" config user.name "dependency-bot[bot]"
git -C "${fixture}" config user.email \
  "dependency-bot[bot]@users.noreply.github.com"
change_content automated-committer
git -C "${fixture}" commit -q -s -m "automated signed commit"
head="$(git -C "${fixture}" rev-parse HEAD)"
expect_fail "automated committer sign-off" \
  "automated committer cannot provide human DCO certification"

make_fixture missing
change_content missing
git -C "${fixture}" commit -q -m "missing sign-off"
head="$(git -C "${fixture}" rev-parse HEAD)"
expect_fail "missing sign-off" "missing committer DCO sign-off"

make_fixture mismatched
change_content mismatched
git -C "${fixture}" commit -q -m "mismatched sign-off" \
  -m "Signed-off-by: Other Person <other@example.com>"
head="$(git -C "${fixture}" rev-parse HEAD)"
expect_fail "mismatched sign-off" "missing committer DCO sign-off"

make_fixture body-decoy
change_content body-decoy
git -C "${fixture}" commit -q -m "body decoy" \
  -m "Signed-off-by: Test Contributor <test.contributor@example.com>" \
  -m "This paragraph keeps the sign-off out of the trailer block."
head="$(git -C "${fixture}" rev-parse HEAD)"
expect_fail "body sign-off decoy" "missing committer DCO sign-off"

make_fixture mixed-range
change_content first-signed
git -C "${fixture}" commit -q -s -m "first signed commit"
change_content second-missing
git -C "${fixture}" commit -q -m "second commit missing sign-off"
head="$(git -C "${fixture}" rev-parse HEAD)"
expect_fail "one unsigned commit in range" "missing committer DCO sign-off"

make_fixture empty-range
head="${base}"
expect_fail "empty commit range" "DCO check requires at least one commit"

make_fixture invalid-ref
head="not-a-commit"
expect_fail "invalid head ref" "invalid head commit"

make_fixture invalid-base
change_content invalid-base
git -C "${fixture}" commit -q -s -m "signed commit with invalid base input"
head="$(git -C "${fixture}" rev-parse HEAD)"
base="not-a-commit"
expect_fail "invalid base ref" "invalid base commit"

fixture="${fixture_root}/not-a-repository"
mkdir -p "${fixture}"
base="not-a-commit"
head="not-a-commit"
expect_fail "non-repository path" "not a Git repository"

if ((failures > 0)); then
  printf '%d DCO test(s) failed\n' "${failures}" >&2
  exit 1
fi

echo "All DCO tests passed."
