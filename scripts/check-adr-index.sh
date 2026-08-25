#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repository_root="${1:-}"
if [[ -z "${repository_root}" ]]; then
  repository_root="$(git rev-parse --show-toplevel)"
fi

inside_work_tree="$(
  git -C "${repository_root}" rev-parse --is-inside-work-tree 2>/dev/null
)" || {
  echo "ADR index check requires a Git worktree: ${repository_root}" >&2
  exit 2
}
if [[ "${inside_work_tree}" != "true" ]]; then
  echo "ADR index check requires a Git worktree: ${repository_root}" >&2
  exit 2
fi
repository_root="$(git -C "${repository_root}" rev-parse --show-toplevel)" || {
  echo "ADR index check failed to resolve the Git worktree root" >&2
  exit 2
}

tracked_paths_file="$(mktemp)"
index_file="$(mktemp)"
adr_file="$(mktemp)"
trap 'rm -f -- "${tracked_paths_file}" "${index_file}" "${adr_file}"' EXIT

if ! git -C "${repository_root}" ls-files --stage -z -- docs/adr \
  >"${tracked_paths_file}"; then
  echo "ADR index check failed to enumerate staged ADR files" >&2
  exit 2
fi

if ! git -C "${repository_root}" ls-files --error-unmatch -- \
  docs/adr/index.md >/dev/null 2>&1; then
  echo "docs/adr/index.md is missing from staged files" >&2
  exit 1
fi
if ! git -C "${repository_root}" show :docs/adr/index.md >"${index_file}"; then
  echo "ADR index check failed to read staged docs/adr/index.md" >&2
  exit 2
fi

declare -A adr_paths=()
status=0

while IFS= read -r -d '' tracked_entry; do
  path="${tracked_entry#*$'\t'}"
  case "${path}" in
    docs/adr/[0-9][0-9][0-9][0-9]-*.md) ;;
    *) continue ;;
  esac

  filename="${path##*/}"
  adr_id="${filename%%-*}"
  if [[ -n "${adr_paths[${adr_id}]:-}" ]]; then
    printf 'ADR-%s has multiple staged files\n' "${adr_id}" >&2
    status=1
    continue
  fi
  adr_paths["${adr_id}"]="${path}"

  if ! git -C "${repository_root}" show ":${path}" >"${adr_file}"; then
    printf '%s: failed to read staged ADR content\n' "${path}" >&2
    exit 2
  fi

  adr_status="$(grep -a -E '^- Status: [^[:space:]].*$' "${adr_file}" || true)"
  adr_status="${adr_status#- Status: }"
  case "${adr_status}" in
    Proposed | Accepted | Superseded | Rejected | Experimental) ;;
    *)
      printf '%s: invalid ADR status: %s\n' "${path}" "${adr_status:-missing}" >&2
      status=1
      continue
      ;;
  esac

  expected_index_prefix="| [ADR-${adr_id}](${filename}) | ${adr_status} |"
  if ! grep -a -Fq -- "${expected_index_prefix}" "${index_file}"; then
    printf 'ADR-%s is missing from docs/adr/index.md\n' "${adr_id}" >&2
    status=1
  fi
done <"${tracked_paths_file}"

if ((status != 0)); then
  exit 1
fi

printf 'ADR index check passed for %d decision record(s).\n' "${#adr_paths[@]}"
