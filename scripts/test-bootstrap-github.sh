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
      fake_issue_list "${state_root}" "$@"
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

fake_issue_list() {
  local state_root="$1"
  shift
  local limit="500"

  while (($# > 0)); do
    case "$1" in
      --repo | --state | --json | --jq)
        shift 2
        ;;
      --limit)
        limit="$2"
        shift 2
        ;;
      *)
        printf 'unsupported fake issue-list argument: %s\n' "$1" >&2
        return 2
        ;;
    esac
  done

  sed -n "1,${limit}p" "${state_root}/issues.txt"
}

fake_issue_create() {
  local state_root="$1"
  shift
  local title=""
  local body_file=""
  local milestone=""
  local label labels_csv="" canonical_labels body_base64 next_number
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
  canonical_labels="$(
    printf '%s\n' "${labels[@]}" | LC_ALL=C sort | awk '
      BEGIN { first = 1 }
      {
        printf "%s%s", first ? "" : ",", $0
        first = 0
      }
      END { print "" }
    '
  )"
  body_base64="$(base64 <"${body_file}" | tr -d '\n')"
  next_number="$((
    $(awk -F '\t' 'BEGIN { max = 0 } $1 > max { max = $1 } END { print max }' \
      "${state_root}/issue-metadata.tsv") + 1
  ))"
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "${next_number}" "${title}" "${milestone}" \
    "${canonical_labels}" "${body_base64}" \
    >>"${state_root}/issue-metadata.tsv"
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
  local paginate="false"
  local -a fields=()

  while (($# > 0)); do
    case "$1" in
      --method)
        method="$2"
        shift 2
        ;;
      --paginate)
        paginate="true"
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
    GET:*/issues\?*)
      if [[ "${paginate}" != "true" ||
        "${jq_filter}" != '.[] | select(.pull_request == null) | [.number, .title, (.milestone.title // ""), ([.labels[].name] | sort | join(",")), ((.body // "") | @base64)] | @tsv' ]]; then
        echo "issue API query must paginate and exclude pull requests" >&2
        return 2
      fi
      cat "${state_root}/issue-metadata.tsv"
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
: >"${fixture_root}/state/issue-metadata.tsv"

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

seed_canonical_issue() {
  local number="$1"
  local issue_file="$2"
  local title labels milestone label canonical_labels body_base64
  local -a label_array=()

  title="$(sed -n '1s/^# //p' "${issue_file}")"
  labels="$(sed -n 's/^<!-- labels: \(.*\) -->$/\1/p' "${issue_file}")"
  milestone="$(sed -n 's/^<!-- milestone: \(.*\) -->$/\1/p' "${issue_file}")"
  IFS=',' read -r -a label_array <<<"${labels}"
  for label in "${label_array[@]}"; do
    label="${label#"${label%%[![:space:]]*}"}"
    label="${label%"${label##*[![:space:]]}"}"
    printf '%s\n' "${label}"
  done | LC_ALL=C sort >"${fixture_root}/state/issue-labels.tmp"
  canonical_labels="$(awk '
    BEGIN { first = 1 }
    {
      printf "%s%s", first ? "" : ",", $0
      first = 0
    }
    END { print "" }
  ' "${fixture_root}/state/issue-labels.tmp")"
  body_base64="$(base64 <"${issue_file}" | tr -d '\n')"

  printf '%s\t%s\t%s\t%s\t%s\n' \
    "${number}" "${title}" "${milestone}" \
    "${canonical_labels}" "${body_base64}" \
    >>"${fixture_root}/state/issue-metadata.tsv"
  printf '%s\n' "${title}" >>"${fixture_root}/state/issues.txt"
}

seed_other_canonical_issues() {
  local issue_file
  local number=1

  for issue_file in "${repository_root}"/planning/issues/*.md; do
    if [[ "${issue_file}" == */006-triage-taxonomy.md ]]; then
      continue
    fi
    seed_canonical_issue "${number}" "${issue_file}"
    number=$((number + 1))
  done
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
expected_milestone_descriptions=(
  "Create a public, reviewable project where unsafe process choices are difficult from the first commit."
  "Define what OGIR means before deciding how bytes are encoded or which libraries implement it."
  "Prove challenge, evidence, verifier, permit, and session-key binding without involving TPM complexity."
  "Replace the mock attester with real TPM-backed freshness and key possession while keeping the rest of the system backend-agnostic."
  "Prove one narrow, documented Linux platform profile rather than claiming generic Linux trust."
  "Allow a Windows sample game under stock Proton to invoke OGIR without trusting Windows-provided identity fields."
  "Make the integration experience credible for a game studio while retaining publisher control."
  "Bind the attestation report to the actual live game process tree before enforcing restrictions."
  "Add only the minimum game-scoped controls needed for a clearly defined threat class."
  "Turn the threat model into executable, repeatable adversarial testing."
  "Improve ordinary Windows TPM API compatibility under Wine without conflating it with physical-host attestation."
  "Earn justified trust rather than asking publishers to trust project reputation alone."
  "Offer one supportable, versioned profile with explicit lifecycle and residual risk."
)
expected_labels=(
  $'type: architecture\t5319E7\tDurable trust, protocol, privilege, or component decision'
  $'type: research\t1D76DB\tEvidence-gathering spike that unblocks a decision'
  $'type: implementation\t0E8A16\tScoped implementation work'
  $'type: test\tBFDADC\tUnit, integration, conformance, or regression testing'
  $'type: fuzzing\tD4C5F9\tFuzz, property, mutation, or parser hardening'
  $'type: documentation\t0075CA\tDocumentation-only change'
  $'type: security-hardening\tB60205\tDefense-in-depth or attack-surface reduction'
  $'type: dependency\t0366D6\tDependency or toolchain review'
  $'type: release\tFBCA04\tRelease, provenance, signing, or lifecycle work'
  $'area: model\tC5DEF5\tPure domain model and invariants'
  $'area: protocol\tC5DEF5\tChallenge, evidence, permit, renewal, and revocation protocol'
  $'area: verifier\tC5DEF5\tPublisher verifier and relying-party boundary'
  $'area: agent\tC5DEF5\tLocal portal and attestation agent'
  $'area: tpm\tC5DEF5\tTPM backend, identity, quote, and enrollment'
  $'area: measured-boot\tC5DEF5\tMeasured boot, UKI, PCR, and reference values'
  $'area: proton-bridge\tC5DEF5\tWindows ABI, Wine/Proton transport, and caller binding'
  $'area: session\tC5DEF5\tProtected-session lifecycle, observation, and enforcement'
  $'area: wine-tpm\tC5DEF5\tSeparate Wine TPM compatibility workstream'
  $'area: attack-lab\tC5DEF5\tExecutable adversarial scenarios and test infrastructure'
  $'area: supply-chain\tC5DEF5\tBuild, dependency, provenance, update, and release security'
  $'area: privacy\tC5DEF5\tDisclosure minimization, identity scope, and privacy controls'
  $'risk: trusted-computing-base\tB60205\tChanges trusted code or a trust decision'
  $'risk: privileged\tB60205\tChanges privileged operations or service isolation'
  $'risk: cryptography\tB60205\tChanges signature, key, transcript, or cryptographic behavior'
  $'risk: parser\tD93F0B\tProcesses attacker-controlled structured input'
  $'risk: privacy\tD93F0B\tChanges claims, identifiers, logs, or disclosed data'
  $'risk: compatibility\tFBCA04\tMay affect supported platforms, Wine, or Proton'
  $'status: needs-research\tEDEDED\tBlocked on primary-source research or experiment'
  $'status: blocked\t000000\tCannot proceed until a named dependency is resolved'
  $'status: ready\t0E8A16\tSpecification and acceptance criteria are implementation-ready'
  $'status: needs-review\tFBCA04\tAwaiting adversarial or human review'
  $'status: experimental\tD4C5F9\tResearch behavior without production guarantees'
  $'status: do-not-merge\tB60205\tMust not merge until the blocker is removed'
)
run_bootstrap >/dev/null
expect_equal "first run creates 33 canonical labels" "33" \
  "$(wc -l <"${fixture_root}/state/labels.tsv")"
expect_equal "first run creates 13 milestones" "13" \
  "$(wc -l <"${fixture_root}/state/milestones.tsv")"

mapfile -t roadmap_objectives < <(
  awk '
    /^# Milestone M[0-9]+ / { milestone = $0 }
    /^## Objective$/ {
      getline
      getline
      if (milestone != "") {
        print
      }
    }
  ' "${repository_root}/docs/ROADMAP.md"
)
expect_equal "roadmap exposes 13 milestone objectives" "13" \
  "${#roadmap_objectives[@]}"
for milestone_index in "${!expected_milestone_descriptions[@]}"; do
  expect_equal \
    "bootstrap description matches roadmap objective ${milestone_index}" \
    "${roadmap_objectives[${milestone_index}]}" \
    "${expected_milestone_descriptions[${milestone_index}]}"
done

for expected_label in "${expected_labels[@]}"; do
  if grep -Fqx -- "${expected_label}" \
    "${fixture_root}/state/labels.tsv"; then
    printf 'PASS: label converged: %s\n' "${expected_label%%$'\t'*}"
  else
    printf 'FAIL: label did not converge: %s\n' \
      "${expected_label%%$'\t'*}" >&2
    failures=$((failures + 1))
  fi
done

for milestone_index in "${!expected_milestones[@]}"; do
  title="${expected_milestones[${milestone_index}]}"
  description="${expected_milestone_descriptions[${milestone_index}]}"
  if awk -F '\t' -v title="${title}" -v description="${description}" '
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
  gh label create "status: ready" \
    --repo "example/ogir" \
    --color "FFFFFF" \
    --description "Drifted label" \
    --force >/dev/null

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
if grep -Fqx -- \
  $'status: ready\t0E8A16\tSpecification and acceptance criteria are implementation-ready' \
  "${fixture_root}/state/labels.tsv"; then
  printf 'PASS: second run repairs label drift\n'
else
  printf 'FAIL: second run did not repair label drift\n' >&2
  failures=$((failures + 1))
fi

if awk -F '\t' -v description="${expected_milestone_descriptions[12]}" '
  $2 == "M12 Production Candidate" &&
    $3 == "open" && $4 == description && $5 == "" { found = 1 }
  END { exit !found }
' "${fixture_root}/state/milestones.tsv"; then
  printf 'PASS: second run repairs milestone drift\n'
else
  printf 'FAIL: second run did not repair milestone drift\n' >&2
  failures=$((failures + 1))
fi

seed_other_canonical_issues

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

: >"${fixture_root}/state/issues.txt"
: >"${fixture_root}/state/issue-creations.tsv"
: >"${fixture_root}/state/issue-metadata.tsv"
seed_other_canonical_issues
for ((issue_number = 10; issue_number <= 500; issue_number++)); do
  printf '%s\tExisting filler issue %03d\t\t\t\n' \
    "${issue_number}" "${issue_number}" \
    >>"${fixture_root}/state/issue-metadata.tsv"
  printf 'Existing filler issue %03d\n' "${issue_number}" \
    >>"${fixture_root}/state/issues.txt"
done
seed_canonical_issue \
  "501" \
  "${repository_root}/planning/issues/006-triage-taxonomy.md"

PATH="${fixture_root}/bin:${PATH}" \
  OGIR_FAKE_GH=1 \
  OGIR_FAKE_GH_STATE="${fixture_root}/state" \
  "${create_issues}" "example/ogir" >/dev/null
expect_equal "existing issue beyond 500 is not duplicated" "0" \
  "$(wc -l <"${fixture_root}/state/issue-creations.tsv")"

: >"${fixture_root}/state/issues.txt"
: >"${fixture_root}/state/issue-creations.tsv"
: >"${fixture_root}/state/issue-metadata.tsv"
seed_other_canonical_issues
printf '%s\t%s\t%s\t%s\t%s\n' \
  "10" \
  "M0-006: Establish labels, milestones, and triage policy" \
  "M12 Production Candidate" \
  "bug" \
  "bWFsZm9ybWVk" \
  >>"${fixture_root}/state/issue-metadata.tsv"
printf '%s\n' "M0-006: Establish labels, milestones, and triage policy" \
  >>"${fixture_root}/state/issues.txt"
if malformed_issue_output="$(
  PATH="${fixture_root}/bin:${PATH}" \
    OGIR_FAKE_GH=1 \
    OGIR_FAKE_GH_STATE="${fixture_root}/state" \
    "${create_issues}" "example/ogir" 2>&1
)"; then
  printf 'FAIL: malformed same-title issue unexpectedly passed\n' >&2
  failures=$((failures + 1))
elif [[ "${malformed_issue_output}" == \
  *"existing issue does not match canonical specification: M0-006: Establish labels, milestones, and triage policy"* ]]; then
  printf 'PASS: malformed same-title issue fails closed\n'
else
  printf 'FAIL: malformed issue error was not specific\n%s\n' \
    "${malformed_issue_output}" >&2
  failures=$((failures + 1))
fi

: >"${fixture_root}/state/issues.txt"
: >"${fixture_root}/state/issue-creations.tsv"
: >"${fixture_root}/state/issue-metadata.tsv"
seed_other_canonical_issues
seed_canonical_issue \
  "10" \
  "${repository_root}/planning/issues/006-triage-taxonomy.md"
seed_canonical_issue \
  "11" \
  "${repository_root}/planning/issues/006-triage-taxonomy.md"
if duplicate_issue_output="$(
  PATH="${fixture_root}/bin:${PATH}" \
    OGIR_FAKE_GH=1 \
    OGIR_FAKE_GH_STATE="${fixture_root}/state" \
    "${create_issues}" "example/ogir" 2>&1
)"; then
  printf 'FAIL: duplicate issue titles unexpectedly passed\n' >&2
  failures=$((failures + 1))
elif [[ "${duplicate_issue_output}" == \
  *"duplicate issue title: M0-006: Establish labels, milestones, and triage policy"* ]]; then
  printf 'PASS: duplicate issue titles fail closed\n'
else
  printf 'FAIL: duplicate issue error was not specific\n%s\n' \
    "${duplicate_issue_output}" >&2
  failures=$((failures + 1))
fi

printf '%s\t%s\t%s\t%s\t%s\n' \
  "99" \
  "M0 Repository Foundation" \
  "closed" \
  "Ambiguous duplicate" \
  "2030-01-01T00:00:00Z" \
  >>"${fixture_root}/state/milestones.tsv"
if duplicate_output="$(run_bootstrap 2>&1)"; then
  printf 'FAIL: duplicate milestone titles unexpectedly passed\n' >&2
  failures=$((failures + 1))
elif [[ "${duplicate_output}" == *"duplicate milestone title: M0 Repository Foundation"* ]]; then
  printf 'PASS: duplicate milestone titles fail closed\n'
else
  printf 'FAIL: duplicate milestone error was not specific\n%s\n' \
    "${duplicate_output}" >&2
  failures=$((failures + 1))
fi

if ((failures > 0)); then
  printf '%d GitHub bootstrap test(s) failed\n' "${failures}" >&2
  exit 1
fi

echo "All GitHub bootstrap tests passed."
