#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repository_root="${1:-}"
if [[ -z "${repository_root}" ]]; then
  repository_root="$(git rev-parse --show-toplevel)"
fi

if ! git -C "${repository_root}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "repository metadata check requires a Git worktree: ${repository_root}" >&2
  exit 2
fi

account_marker='YOUR-GITHUB-'"ACCOUNT"
username_marker='YOUR_GITHUB_'"USERNAME"
status=0

if marker_matches="$(
  git -C "${repository_root}" grep -n -F \
    -e "${account_marker}" \
    -e "${username_marker}" \
    -- .
)"; then
  echo "unresolved repository identity marker(s):" >&2
  printf '%s\n' "${marker_matches}" >&2
  status=1
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
done < <(git -C "${repository_root}" ls-files -z)

if ((status != 0)); then
  exit "${status}"
fi

echo "Repository metadata check passed."
