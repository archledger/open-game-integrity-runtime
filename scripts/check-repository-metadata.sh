#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repository_root="${1:-}"
if [[ -z "${repository_root}" ]]; then
  repository_root="$(git rev-parse --show-toplevel)"
fi

inside_work_tree="$(git -C "${repository_root}" rev-parse --is-inside-work-tree 2>/dev/null)" || {
  echo "repository metadata check requires a Git worktree: ${repository_root}" >&2
  exit 2
}
if [[ "${inside_work_tree}" != "true" ]]; then
  echo "repository metadata check requires a Git worktree: ${repository_root}" >&2
  exit 2
fi
repository_root="$(git -C "${repository_root}" rev-parse --show-toplevel)" || {
  echo "repository metadata check failed to resolve the Git worktree root" >&2
  exit 2
}

account_marker='YOUR-GITHUB-'"ACCOUNT"
username_marker='YOUR_GITHUB_'"USERNAME"
generic_owner_marker='owner/'"open-game-integrity-runtime"
status=0

marker_status=0
marker_matches="$(
  git -C "${repository_root}" grep --cached -n -F \
    -e "${account_marker}" \
    -e "${username_marker}" \
    -e "${generic_owner_marker}" \
    -- .
)" || marker_status=$?
case "${marker_status}" in
  0)
    echo "unresolved repository identity marker(s):" >&2
    printf '%s\n' "${marker_matches}" >&2
    status=1
    ;;
  1) ;;
  *)
    echo "repository metadata check failed to search tracked content" >&2
    exit 2
    ;;
esac

tracked_paths_file="$(mktemp)"
source_blob_file="$(mktemp)"
trap 'rm -f -- "${tracked_paths_file}" "${source_blob_file}"' EXIT
if ! git -C "${repository_root}" ls-files --stage -z >"${tracked_paths_file}"; then
  echo "repository metadata check failed to enumerate tracked files" >&2
  exit 2
fi

validate_spdx_header() {
  local path="$1"
  local expected_license="$2"
  local source_file="$3"
  local source_kind="$4"
  local declaration_output
  local declaration_status=0
  local declaration_text
  local actual_license
  local line_number
  local declaration_search_pattern
  local shell_declaration_pattern='^[[:space:]]*#[[:space:]]*SPDX-License-Identifier:[[:space:]]*([^[:space:]]+)[[:space:]]*$'
  local line_declaration_pattern='^[[:space:]]*//[[:space:]]*SPDX-License-Identifier:[[:space:]]*([^[:space:]]+)[[:space:]]*$'
  local block_declaration_pattern='^[[:space:]]*/\*[[:space:]]*SPDX-License-Identifier:[[:space:]]*([^[:space:]]+)[[:space:]]*\*/[[:space:]]*$'
  local declaration_valid=0
  local -a declarations=()

  case "${source_kind}" in
    shell)
      declaration_search_pattern='^[[:space:]]*#[[:space:]]*SPDX-License-Identifier:'
      ;;
    rust | c)
      declaration_search_pattern='^[[:space:]]*(//|/\*)[[:space:]]*SPDX-License-Identifier:'
      ;;
    *)
      printf '%s: unknown source kind: %s\n' "${path}" "${source_kind}" >&2
      exit 2
      ;;
  esac

  declaration_output="$(
    grep -a -n -E \
      "${declaration_search_pattern}" \
      "${source_file}"
  )" || declaration_status=$?

  case "${declaration_status}" in
    0)
      while IFS= read -r declaration; do
        declarations+=("${declaration}")
      done <<<"${declaration_output}"
      ;;
    1) ;;
    *)
      printf '%s: failed to inspect SPDX metadata\n' "${path}" >&2
      exit 2
      ;;
  esac

  if ((${#declarations[@]} != 1)); then
    printf '%s: invalid SPDX license header\n' "${path}" >&2
    printf '%s: expected SPDX-License-Identifier: %s exactly once in the first 5 lines\n' \
      "${path}" "${expected_license}" >&2
    status=1
    return
  fi

  declaration_text="${declarations[0]#*:}"
  case "${source_kind}" in
    shell)
      if [[ "${declaration_text}" =~ ${shell_declaration_pattern} ]]; then
        actual_license="${BASH_REMATCH[1]}"
        declaration_valid=1
      fi
      ;;
    rust | c)
      if [[ "${declaration_text}" =~ ${line_declaration_pattern} ]]; then
        actual_license="${BASH_REMATCH[1]}"
        declaration_valid=1
      elif [[ "${declaration_text}" =~ ${block_declaration_pattern} ]]; then
        actual_license="${BASH_REMATCH[1]}"
        declaration_valid=1
      fi
      ;;
  esac

  if ((declaration_valid == 0)); then
    printf '%s: invalid SPDX license header\n' "${path}" >&2
    printf '%s: expected SPDX-License-Identifier: %s exactly once in the first 5 lines\n' \
      "${path}" "${expected_license}" >&2
    status=1
    return
  fi

  line_number="${declarations[0]%%:*}"
  if [[ "${actual_license}" != "${expected_license}" ]] || ((line_number > 5)); then
    printf '%s: invalid SPDX license header\n' "${path}" >&2
    printf '%s: expected SPDX-License-Identifier: %s exactly once in the first 5 lines\n' \
      "${path}" "${expected_license}" >&2
    status=1
  fi
}

shell_shebang_pattern='^#!.*[[:space:]/](a|ba|da|k|z)?sh([[:space:]]|$)'

while IFS= read -r -d '' tracked_entry; do
  tracked_metadata="${tracked_entry%%$'\t'*}"
  path="${tracked_entry#*$'\t'}"
  tracked_mode="${tracked_metadata%% *}"
  is_source=0
  source_blob_loaded=0
  source_kind=""

  case "${path}" in
    *.rs)
      is_source=1
      source_kind="rust"
      ;;
    *.c | *.h)
      is_source=1
      source_kind="c"
      ;;
    *.sh)
      is_source=1
      source_kind="shell"
      ;;
  esac

  if ((is_source == 0)) &&
    [[ "${tracked_mode}" == "100644" || "${tracked_mode}" == "100755" ]]; then
    if ! git -C "${repository_root}" show ":${path}" >"${source_blob_file}"; then
      printf '%s: failed to read staged source content\n' "${path}" >&2
      exit 2
    fi
    source_blob_loaded=1
    first_line=""
    IFS= read -r first_line <"${source_blob_file}" || true
    if [[ "${first_line}" =~ ${shell_shebang_pattern} ]]; then
      is_source=1
      source_kind="shell"
    fi
  fi

  if ((is_source == 0)); then
    continue
  fi

  if [[ "${tracked_mode}" != "100644" && "${tracked_mode}" != "100755" ]]; then
    printf '%s: tracked source must be a regular file\n' "${path}" >&2
    status=1
    continue
  fi

  if ((source_blob_loaded == 0)); then
    if ! git -C "${repository_root}" show ":${path}" >"${source_blob_file}"; then
      printf '%s: failed to read staged source content\n' "${path}" >&2
      exit 2
    fi
  fi

  expected_license="Apache-2.0"
  case "${path}" in
    wine/*) expected_license="LGPL-2.1-or-later" ;;
    bpf/*) expected_license="GPL-2.0-only" ;;
  esac

  validate_spdx_header "${path}" "${expected_license}" "${source_blob_file}" "${source_kind}"
done <"${tracked_paths_file}"

if ((status != 0)); then
  exit "${status}"
fi

echo "Repository metadata check passed."
