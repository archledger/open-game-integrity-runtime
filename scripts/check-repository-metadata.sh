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
  git -C "${repository_root}" grep -n -F \
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
  local declaration_output
  local declaration_status=0
  local line_number
  local -a declarations=()

  declaration_output="$(
    grep -a -n -E \
      '^[[:space:]]*(#|//|/\*)[[:space:]]*SPDX-License-Identifier:' \
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

  if ((${#declarations[@]} != 1)) ||
    ! grep -Eq \
      "^[0-9]+:[[:space:]]*(#|//|/\\*)[[:space:]]*SPDX-License-Identifier:[[:space:]]*${expected_license}([[:space:]]*\\*/)?[[:space:]]*$" \
      <<<"${declarations[0]:-}"; then
    printf '%s: invalid SPDX license header\n' "${path}" >&2
    printf '%s: expected SPDX-License-Identifier: %s exactly once in the first 5 lines\n' \
      "${path}" "${expected_license}" >&2
    status=1
    return
  fi

  line_number="${declarations[0]%%:*}"
  if ((line_number > 5)); then
    printf '%s: invalid SPDX license header\n' "${path}" >&2
    printf '%s: expected SPDX-License-Identifier: %s exactly once in the first 5 lines\n' \
      "${path}" "${expected_license}" >&2
    status=1
  fi
}

while IFS= read -r -d '' tracked_entry; do
  tracked_metadata="${tracked_entry%%$'\t'*}"
  path="${tracked_entry#*$'\t'}"
  tracked_mode="${tracked_metadata%% *}"

  case "${path}" in
    *.rs | *.c | *.h | *.sh)
      expected_license="Apache-2.0"
      case "${path}" in
        wine/*) expected_license="LGPL-2.1-or-later" ;;
        bpf/*) expected_license="GPL-2.0-only" ;;
      esac

      if [[ "${tracked_mode}" != "100644" && "${tracked_mode}" != "100755" ]]; then
        printf '%s: tracked source must be a regular file\n' "${path}" >&2
        status=1
        continue
      fi

      if ! git -C "${repository_root}" show ":${path}" >"${source_blob_file}"; then
        printf '%s: failed to read staged source content\n' "${path}" >&2
        exit 2
      fi

      validate_spdx_header "${path}" "${expected_license}" "${source_blob_file}"
      ;;
  esac
done <"${tracked_paths_file}"

if ((status != 0)); then
  exit "${status}"
fi

echo "Repository metadata check passed."
