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

required_sections=(
  "Context"
  "Decision drivers"
  "Options considered"
  "Decision"
  "Consequences"
  "Threat-model impact"
  "Privacy impact"
  "Dependency and license impact"
  "Validation"
  "Rollback"
  "Primary sources"
)

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
  docs/adr/template.md >/dev/null 2>&1; then
  echo "docs/adr/template.md is missing from staged files" >&2
  exit 1
fi
if ! git -C "${repository_root}" ls-files --error-unmatch -- \
  docs/adr/README.md >/dev/null 2>&1; then
  echo "docs/adr/README.md is missing from staged files" >&2
  exit 1
fi
if ! git -C "${repository_root}" show :docs/adr/README.md >"${adr_file}"; then
  echo "ADR index check failed to read staged docs/adr/README.md" >&2
  exit 2
fi
if ! grep -a -Fq -- '](index.md)' "${adr_file}" ||
  ! grep -a -Fq -- '](template.md)' "${adr_file}"; then
  echo "docs/adr/README.md must link to index.md and template.md" >&2
  exit 1
fi
if ! git -C "${repository_root}" show :docs/adr/template.md >"${adr_file}"; then
  echo "ADR index check failed to read staged docs/adr/template.md" >&2
  exit 2
fi
for required_section in "${required_sections[@]}"; do
  section_count="$(
    grep -a -Fxc -- "## ${required_section}" "${adr_file}" || true
  )"
  if ((section_count == 0)); then
    printf 'docs/adr/template.md: missing required ADR section: %s\n' \
      "${required_section}" >&2
    exit 1
  fi
  if ! awk -v heading="## ${required_section}" '
    $0 == heading { inside = 1; next }
    inside && /^## / { exit 1 }
    inside && $0 !~ /^[[:space:]]*$/ { found = 1; exit 0 }
    END { if (!found) exit 1 }
  ' "${adr_file}"; then
    printf 'docs/adr/template.md: empty required ADR section: %s\n' \
      "${required_section}" >&2
    exit 1
  fi
done
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
declare -A adr_statuses=()
declare -A index_paths=()
declare -A index_statuses=()
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

  title_line=""
  IFS= read -r title_line <"${adr_file}" || true
  if [[ ! "${title_line}" =~ ^#[[:space:]]ADR-([0-9]{4}):[[:space:]].+$ ]]; then
    printf '%s: invalid ADR title\n' "${path}" >&2
    status=1
    continue
  fi
  if [[ "${BASH_REMATCH[1]}" != "${adr_id}" ]]; then
    printf '%s: ADR identifier does not match filename\n' "${path}" >&2
    status=1
    continue
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
  adr_statuses["${adr_id}"]="${adr_status}"

  for required_section in "${required_sections[@]}"; do
    section_count="$(
      grep -a -Fxc -- "## ${required_section}" "${adr_file}" || true
    )"
    if ((section_count == 0)); then
      printf '%s: missing required ADR section: %s\n' \
        "${path}" "${required_section}" >&2
      status=1
      continue
    fi
    if ((section_count > 1)); then
      printf '%s: duplicate required ADR section: %s\n' \
        "${path}" "${required_section}" >&2
      status=1
      continue
    fi
    if ! awk -v heading="## ${required_section}" '
      $0 == heading { inside = 1; next }
      inside && /^## / { exit 1 }
      inside && $0 !~ /^[[:space:]]*$/ { found = 1; exit 0 }
      END { if (!found) exit 1 }
    ' "${adr_file}"; then
      printf '%s: empty required ADR section: %s\n' \
        "${path}" "${required_section}" >&2
      status=1
    fi
  done
done <"${tracked_paths_file}"

index_row_pattern='^[[:space:]]*\|[[:space:]]*\[ADR-([0-9]{4})\]\(([^)]+)\)[[:space:]]*\|[[:space:]]*([^|]+)[[:space:]]*\|'
while IFS= read -r index_line; do
  if [[ ! "${index_line}" =~ ${index_row_pattern} ]]; then
    continue
  fi

  index_id="${BASH_REMATCH[1]}"
  index_path="${BASH_REMATCH[2]}"
  index_status="${BASH_REMATCH[3]}"
  index_status="${index_status#"${index_status%%[![:space:]]*}"}"
  index_status="${index_status%"${index_status##*[![:space:]]}"}"

  if [[ -n "${index_paths[${index_id}]:-}" ]]; then
    printf 'ADR-%s has duplicate entries in docs/adr/index.md\n' \
      "${index_id}" >&2
    status=1
    continue
  fi

  index_paths["${index_id}"]="${index_path}"
  index_statuses["${index_id}"]="${index_status}"
  full_index_path="docs/adr/${index_path}"
  if [[ "${adr_paths[${index_id}]:-}" != "${full_index_path}" ]]; then
    printf 'ADR-%s index entry references missing %s\n' \
      "${index_id}" "${full_index_path}" >&2
    status=1
  fi
done <"${index_file}"

for adr_id in "${!adr_paths[@]}"; do
  if [[ -z "${index_paths[${adr_id}]:-}" ]]; then
    printf 'ADR-%s is missing from docs/adr/index.md\n' "${adr_id}" >&2
    status=1
    continue
  fi

  expected_path="${adr_paths[${adr_id}]#docs/adr/}"
  if [[ "${index_paths[${adr_id}]}" != "${expected_path}" ]]; then
    printf 'ADR-%s index path does not match staged ADR file\n' "${adr_id}" >&2
    status=1
  fi
  if [[ "${index_statuses[${adr_id}]}" != "${adr_statuses[${adr_id}]}" ]]; then
    printf 'ADR-%s index status does not match staged ADR status\n' \
      "${adr_id}" >&2
    status=1
  fi
done

if ((status != 0)); then
  exit 1
fi

printf 'ADR index check passed for %d decision record(s).\n' "${#adr_paths[@]}"
