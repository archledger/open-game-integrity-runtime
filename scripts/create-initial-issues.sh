#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI (gh) is required." >&2
  exit 1
fi

repository="${1:-}"
if [[ -z "${repository}" ]]; then
  repository="$(gh repo view --json nameWithOwner --jq '.nameWithOwner')"
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
existing_issues="$(
  gh api --paginate "repos/${repository}/issues?state=all&per_page=100" \
    --jq '.[] | select(.pull_request == null) | [.number, .title, (.milestone.title // ""), ([.labels[].name] | sort | join(",")), ((.body // "") | @base64)] | @tsv'
)"

for file in "${root}"/planning/issues/*.md; do
  title="$(sed -n '1s/^# //p' "${file}")"
  labels="$(sed -n 's/^<!-- labels: \(.*\) -->$/\1/p' "${file}")"
  milestone="$(sed -n 's/^<!-- milestone: \(.*\) -->$/\1/p' "${file}")"

  if [[ -z "${title}" || -z "${labels}" || -z "${milestone}" ]]; then
    echo "Invalid issue specification: ${file}" >&2
    exit 1
  fi

  IFS=',' read -r -a label_array <<<"${labels}"
  for label_index in "${!label_array[@]}"; do
    label_array["${label_index}"]="$(
      printf '%s' "${label_array[${label_index}]}" | xargs
    )"
  done

  canonical_labels="$(
    printf '%s\n' "${label_array[@]}" | LC_ALL=C sort | awk '
      BEGIN { first = 1 }
      {
        printf "%s%s", first ? "" : ",", $0
        first = 0
      }
      END { print "" }
    '
  )"
  canonical_body="$(base64 <"${file}" | tr -d '\n')"
  issue_match_count="$(
    awk -F '\t' -v title="${title}" \
      '$2 == title { count++ } END { print count + 0 }' \
      <<<"${existing_issues}"
  )"
  if ((issue_match_count > 1)); then
    printf 'duplicate issue title: %s\n' "${title}" >&2
    exit 1
  fi
  if ((issue_match_count == 1)); then
    existing_issue="$(
      awk -F '\t' -v title="${title}" '$2 == title { print; exit }' \
        <<<"${existing_issues}"
    )"
    IFS=$'\t' read -r _ _ existing_milestone existing_labels \
      existing_body <<<"${existing_issue}"
    if [[ "${existing_milestone}" != "${milestone}" ||
      "${existing_labels}" != "${canonical_labels}" ||
      "${existing_body}" != "${canonical_body}" ]]; then
      printf 'existing issue does not match canonical specification: %s\n' \
        "${title}" >&2
      exit 1
    fi
    printf 'Skipping existing issue: %s\n' "${title}"
    continue
  fi

  args=(issue create --repo "${repository}" --title "${title}" --body-file "${file}" --milestone "${milestone}")
  for label in "${label_array[@]}"; do
    args+=(--label "${label}")
  done

  gh "${args[@]}"
done
