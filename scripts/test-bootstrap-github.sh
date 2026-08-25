#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

fake_gh() {
  local state_root="${OGIR_FAKE_GH_STATE:?}"
  local resource="${1:-}"
  shift || true

  case "${resource}" in
    label)
      [[ "${1:-}" == "create" ]] || return 2
      shift
      fake_label_create "${state_root}" "$@"
      ;;
    api)
      fake_api "${state_root}" "$@"
      ;;
    issue)
      fake_issue "${state_root}" "$@"
      ;;
    *)
      printf 'unsupported fake gh resource: %s\n' "${resource}" >&2
      return 2
      ;;
  esac
}

fake_issue() {
  local state_root="$1"
  local operation="$2"
  shift 2

  case "${operation}" in
    list)
      cat "${state_root}/issues.txt"
      ;;
    create)
      fake_issue_create "${state_root}" "$@"
      ;;
    *)
      printf 'unsupported fake issue operation: %s\n' \
        "${operation}" >&2
      return 2
      ;;
  esac
}

fake_issue_create() {
  local state_root="$1"
  shift
  local title=""
  local body_file=""
  local milestone=""
  local label labels_csv=""
  local -a labels=()

  while (($# > 0)); do
    case "$1" in
      --repo)
        shift 2
        ;;
      --title)
        title="$2"
        shift 2
        ;;
      --body-file)
        body_file="$2"
        shift 2
        ;;
      --milestone)
        milestone="$2"
        shift 2
        ;;
      --label)
        labels+=("$2")
        shift 2
        ;;
      *)
        printf 'unsupported fake issue-create argument: %s\n' "$1" >&2
        return 2
        ;;
    esac
  done

  [[ -n "${title}" && -f "${body_file}" && -n "${milestone}" ]] || {
    echo "incomplete fake issue create" >&2
    return 1
  }
  awk -F '\t' -v milestone="${milestone}" \
    '$2 == milestone { found = 1 } END { exit !found }' \
    "${state_root}/milestones.tsv" || {
      printf 'unknown milestone: %s\n' "${milestone}" >&2
      return 1
    }

  for label in "${labels[@]}"; do
    awk -F '\t' -v label="${label}" \
      '$1 == label { found = 1 } END { exit !found }' \
      "${state_root}/labels.tsv" || {
        printf 'unknown label: %s\n' "${label}" >&2
        return 1
      }
    if [[ -n "${labels_csv}" ]]; then
      labels_csv+=","
    fi
    labels_csv+="${label}"
  done

  printf '%s\t%s\t%s\t%s\n' \
    "${title}" "${milestone}" "${labels_csv}" "${body_file}" \
    >>"${state_root}/issue-creations.tsv"
  printf '%s\n' "${title}" >>"${state_root}/issues.txt"
  echo "https://example.invalid/issues/1"
}

fake_label_create() {
  local state_root="$1"
  local name="$2"
  shift 2
  local color=""
  local description=""
  local temp_file

  while (($# > 0)); do
    case "$1" in
      --repo)
        shift 2
        ;;
      --color)
        color="$2"
        shift 2
        ;;
      --description)
        description="$2"
        shift 2
        ;;
      --force)
        shift
        ;;
      *)
        printf 'unsupported fake label argument: %s\n' "$1" >&2
        return 2
        ;;
    esac
  done

  temp_file="$(mktemp "${state_root}/labels.XXXXXX")"
  awk -F '\t' -v name="${name}" '$1 != name' \
    "${state_root}/labels.tsv" >"${temp_file}"
  printf '%s\t%s\t%s\n' "${name}" "${color}" "${description}" \
    >>"${temp_file}"
  mv -- "${temp_file}" "${state_root}/labels.tsv"
}

fake_api() {
  local state_root="$1"
  shift
  local method="GET"
  local endpoint=""
  local jq_filter=""
  local -a fields=()

  while (($# > 0)); do
    case "$1" in
      --method)
        method="$2"
        shift 2
        ;;
      --paginate)
        shift
        ;;
      --jq)
        jq_filter="$2"
        shift 2
        ;;
      -f | -F)
        fields+=("$2")
        shift 2
        ;;
      repos/*)
        endpoint="$1"
        shift
        ;;
      *)
        printf 'unsupported fake api argument: %s\n' "$1" >&2
        return 2
        ;;
    esac
  done

  case "${method}:${endpoint}" in
    GET:*/milestones\?*)
      if [[ "${jq_filter}" == ".[].title" ]]; then
        cut -f 2 "${state_root}/milestones.tsv"
      else
        awk -F '\t' 'BEGIN { OFS = "\t" } { print $1, $2, $3, $4, $5 }' \
          "${state_root}/milestones.tsv"
      fi
      ;;
    POST:*/milestones)
      fake_create_milestone "${state_root}" "${fields[@]}"
      ;;
    PATCH:*/milestones/*)
      fake_update_milestone "${state_root}" "${endpoint##*/}" \
        "${fields[@]}"
      ;;
    *)
      printf 'unsupported fake api call: %s %s\n' \
        "${method}" "${endpoint}" >&2
      return 2
      ;;
  esac
}

field_value() {
  local wanted="$1"
  shift
  local field
  for field in "$@"; do
    if [[ "${field%%=*}" == "${wanted}" ]]; then
      printf '%s' "${field#*=}"
      return 0
    fi
  done
  return 1
}

fake_create_milestone() {
  local state_root="$1"
  shift
  local title description state due_on next_number
  title="$(field_value title "$@")"
  description="$(field_value description "$@")"
  state="$(field_value state "$@" 2>/dev/null || printf 'open')"
  due_on="$(field_value due_on "$@" 2>/dev/null || true)"

  if awk -F '\t' -v title="${title}" '$2 == title { found = 1 } END { exit !found }' \
    "${state_root}/milestones.tsv"; then
    printf 'duplicate milestone: %s\n' "${title}" >&2
    return 1
  fi

  next_number="$((
    $(awk -F '\t' 'BEGIN { max = 0 } $1 > max { max = $1 } END { print max }' \
      "${state_root}/milestones.tsv") + 1
  ))"
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "${next_number}" "${title}" "${state}" "${description}" "${due_on}" \
    >>"${state_root}/milestones.tsv"
}

fake_update_milestone() {
  local state_root="$1"
  local number="$2"
  shift 2
  local description state due_on temp_file
  description="$(field_value description "$@")"
  state="$(field_value state "$@")"
  due_on="$(field_value due_on "$@" 2>/dev/null || true)"
  [[ "${due_on}" == "null" ]] && due_on=""

  temp_file="$(mktemp "${state_root}/milestones.XXXXXX")"
  awk -F '\t' -v OFS='\t' -v number="${number}" \
    -v state="${state}" -v description="${description}" -v due_on="${due_on}" '
      $1 == number {
        $3 = state
        $4 = description
        $5 = due_on
      }
      { print }
    ' "${state_root}/milestones.tsv" >"${temp_file}"
  mv -- "${temp_file}" "${state_root}/milestones.tsv"
}

if [[ "${OGIR_FAKE_GH:-}" == "1" ]]; then
  fake_gh "$@"
  exit $?
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bootstrap="${repository_root}/scripts/bootstrap-github.sh"
create_issues="${repository_root}/scripts/create-initial-issues.sh"
fixture_root="$(mktemp -d)"
trap 'rm -rf -- "${fixture_root}"' EXIT
mkdir -p "${fixture_root}/bin" "${fixture_root}/state"
ln -s -- "${repository_root}/scripts/test-bootstrap-github.sh" \
  "${fixture_root}/bin/gh"
: >"${fixture_root}/state/labels.tsv"
: >"${fixture_root}/state/milestones.tsv"
: >"${fixture_root}/state/issues.txt"
: >"${fixture_root}/state/issue-creations.tsv"

run_bootstrap() {
  PATH="${fixture_root}/bin:${PATH}" \
    OGIR_FAKE_GH=1 \
    OGIR_FAKE_GH_STATE="${fixture_root}/state" \
    "${bootstrap}" "example/ogir"
}

failures=0

expect_equal() {
  local name="$1"
  local expected="$2"
  local actual="$3"
  if [[ "${actual}" == "${expected}" ]]; then
    printf 'PASS: %s\n' "${name}"
  else
    printf 'FAIL: %s (expected %s, got %s)\n' \
      "${name}" "${expected}" "${actual}" >&2
    failures=$((failures + 1))
  fi
}

expected_milestones=(
  "M0 Repository Foundation"
  "M1 Domain Model"
  "M2 Mock End-to-End Proof"
  "M3 TPM Backend"
  "M4 Measured Boot Profile"
  "M5 Proton Bridge"
  "M6 Publisher SDK and Verifier"
  "M7 Session Observation"
  "M8 Scoped Enforcement"
  "M9 Attack Laboratory"
  "M10 Wine TPM Compatibility"
  "M11 Publisher Pilot"
  "M12 Production Candidate"
)
milestone_description="See docs/ROADMAP.md for scope and exit criteria."

run_bootstrap >/dev/null
expect_equal "first run creates 33 canonical labels" "33" \
  "$(wc -l <"${fixture_root}/state/labels.tsv")"
expect_equal "first run creates 13 milestones" "13" \
  "$(wc -l <"${fixture_root}/state/milestones.tsv")"

for title in "${expected_milestones[@]}"; do
  if awk -F '\t' -v title="${title}" -v description="${milestone_description}" '
    $2 == title && $3 == "open" && $4 == description && $5 == "" {
      found = 1
    }
    END { exit !found }
  ' "${fixture_root}/state/milestones.tsv"; then
    printf 'PASS: milestone converged: %s\n' "${title}"
  else
    printf 'FAIL: milestone did not converge: %s\n' "${title}" >&2
    failures=$((failures + 1))
  fi
done

PATH="${fixture_root}/bin:${PATH}" \
  OGIR_FAKE_GH=1 \
  OGIR_FAKE_GH_STATE="${fixture_root}/state" \
  gh api --method PATCH \
    "repos/example/ogir/milestones/13" \
    -f state=closed \
    -f description="Drifted description" \
    -f due_on="2030-01-01T00:00:00Z" >/dev/null

run_bootstrap >/dev/null
expect_equal "second run keeps 33 labels" "33" \
  "$(wc -l <"${fixture_root}/state/labels.tsv")"
expect_equal "second run keeps 13 milestones" "13" \
  "$(wc -l <"${fixture_root}/state/milestones.tsv")"

if awk -F '\t' -v description="${milestone_description}" '
  $2 == "M12 Production Candidate" &&
    $3 == "open" && $4 == description && $5 == "" { found = 1 }
  END { exit !found }
' "${fixture_root}/state/milestones.tsv"; then
  printf 'PASS: second run repairs milestone drift\n'
else
  printf 'FAIL: second run did not repair milestone drift\n' >&2
  failures=$((failures + 1))
fi

for issue_file in "${repository_root}"/planning/issues/*.md; do
  if [[ "${issue_file}" == */006-triage-taxonomy.md ]]; then
    continue
  fi
  sed -n '1s/^# //p' "${issue_file}" \
    >>"${fixture_root}/state/issues.txt"
done

PATH="${fixture_root}/bin:${PATH}" \
  OGIR_FAKE_GH=1 \
  OGIR_FAKE_GH_STATE="${fixture_root}/state" \
  "${create_issues}" "example/ogir" >/dev/null

expect_equal "sample issue is created once" "1" \
  "$(wc -l <"${fixture_root}/state/issue-creations.tsv")"
IFS=$'\t' read -r created_title created_milestone created_labels \
  created_body <"${fixture_root}/state/issue-creations.tsv"
expect_equal "sample issue title" \
  "M0-006: Establish labels, milestones, and triage policy" \
  "${created_title}"
expect_equal "sample issue milestone" "M0 Repository Foundation" \
  "${created_milestone}"
expect_equal "sample issue taxonomy is unambiguous" \
  "type: documentation,area: supply-chain,risk: trusted-computing-base,status: ready" \
  "${created_labels}"
expect_equal "sample issue uses the reviewed specification" \
  "${repository_root}/planning/issues/006-triage-taxonomy.md" \
  "${created_body}"

PATH="${fixture_root}/bin:${PATH}" \
  OGIR_FAKE_GH=1 \
  OGIR_FAKE_GH_STATE="${fixture_root}/state" \
  "${create_issues}" "example/ogir" >/dev/null
expect_equal "sample issue creation is idempotent" "1" \
  "$(wc -l <"${fixture_root}/state/issue-creations.tsv")"

if ((failures > 0)); then
  printf '%d GitHub bootstrap test(s) failed\n' "${failures}" >&2
  exit 1
fi

echo "All GitHub bootstrap tests passed."
