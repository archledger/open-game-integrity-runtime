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

account_marker='YOUR-GITHUB-'"ACCOUNT"
username_marker='YOUR_GITHUB_'"USERNAME"
status=0

marker_status=0
marker_matches="$(
  git -C "${repository_root}" grep -n -F \
    -e "${account_marker}" \
    -e "${username_marker}" \
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
trap 'rm -f -- "${tracked_paths_file}"' EXIT
if ! git -C "${repository_root}" ls-files -z >"${tracked_paths_file}"; then
  echo "repository metadata check failed to enumerate tracked files" >&2
  exit 2
fi

while IFS= read -r -d '' path; do
  case "${path}" in
    *.rs | *.c | *.h | *.sh)
      expected_license="Apache-2.0"
      case "${path}" in
        wine/*) expected_license="LGPL-2.1-or-later" ;;
        bpf/*) expected_license="GPL-2.0-only" ;;
      esac

      if ! grep -Fq -- "SPDX-License-Identifier: ${expected_license}" "${repository_root}/${path}"; then
        printf '%s: expected SPDX-License-Identifier: %s\n' "${path}" "${expected_license}" >&2
        status=1
      fi
      ;;
  esac
done <"${tracked_paths_file}"

if ((status != 0)); then
  exit "${status}"
fi

echo "Repository metadata check passed."
