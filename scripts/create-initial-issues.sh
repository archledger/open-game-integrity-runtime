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
existing_titles="$(gh issue list --repo "${repository}" --state all --limit 500 --json title --jq '.[].title')"

for file in "${root}"/planning/issues/*.md; do
  title="$(sed -n '1s/^# //p' "${file}")"
  labels="$(sed -n 's/^<!-- labels: \(.*\) -->$/\1/p' "${file}")"
  milestone="$(sed -n 's/^<!-- milestone: \(.*\) -->$/\1/p' "${file}")"

  if [[ -z "${title}" || -z "${labels}" || -z "${milestone}" ]]; then
    echo "Invalid issue specification: ${file}" >&2
    exit 1
  fi

  if grep -Fqx -- "${title}" <<<"${existing_titles}"; then
    printf 'Skipping existing issue: %s\n' "${title}"
    continue
  fi

  args=(issue create --repo "${repository}" --title "${title}" --body-file "${file}" --milestone "${milestone}")
  IFS=',' read -r -a label_array <<<"${labels}"
  for label in "${label_array[@]}"; do
    label="$(printf '%s' "${label}" | xargs)"
    args+=(--label "${label}")
  done

  gh "${args[@]}"
done
