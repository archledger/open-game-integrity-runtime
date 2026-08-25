#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

usage() {
  echo "Usage: $0 <base-commit|--root> <head-commit> [repository]" >&2
}

if (($# < 2 || $# > 3)); then
  usage
  exit 2
fi

base_ref="$1"
head_ref="$2"
repository_path="${3:-.}"

if ! repository_root="$(git -C "${repository_path}" rev-parse --show-toplevel 2>/dev/null)"; then
  echo "not a Git repository: ${repository_path}" >&2
  exit 2
fi

root_audit=0
if [[ "${base_ref}" == "--root" ]]; then
  root_audit=1
else
  if ! base_commit="$(
    git -C "${repository_root}" rev-parse --verify --quiet --end-of-options \
      "${base_ref}^{commit}"
  )"; then
    echo "invalid base commit: ${base_ref}" >&2
    exit 2
  fi
fi

if ! head_commit="$(
  git -C "${repository_root}" rev-parse --verify --quiet --end-of-options \
    "${head_ref}^{commit}"
)"; then
  echo "invalid head commit: ${head_ref}" >&2
  exit 2
fi

commit_list="$(mktemp)"
trap 'rm -f -- "${commit_list}"' EXIT

if ((root_audit != 0)); then
  range=("${head_commit}")
else
  range=("${base_commit}..${head_commit}")
fi

if ! git -C "${repository_root}" rev-list --reverse \
  "${range[@]}" >"${commit_list}"; then
  echo "unable to enumerate commits in the DCO range" >&2
  exit 2
fi

if [[ ! -s "${commit_list}" ]]; then
  echo "DCO check requires at least one commit" >&2
  exit 1
fi

checked=0
failed=0

while IFS= read -r commit; do
  committer_name="$(git -C "${repository_root}" show -s --format=%cn "${commit}")"
  committer_email="$(git -C "${repository_root}" show -s --format=%ce "${commit}")"
  expected_trailer="Signed-off-by: ${committer_name} <${committer_email}>"

  if [[ "${committer_name,,}" == *"[bot]"* ||
        "${committer_email,,}" == *"[bot]@"* ]]; then
    echo "${commit}: automated committer cannot provide human DCO certification" >&2
    failed=1
    checked=$((checked + 1))
    continue
  fi

  trailers="$(
    git -C "${repository_root}" show -s --format=%B "${commit}" |
      git -C "${repository_root}" interpret-trailers --parse
  )"

  if ! grep -Fqx -- "${expected_trailer}" <<<"${trailers}"; then
    echo "${commit}: missing committer DCO sign-off: ${expected_trailer}" >&2
    failed=1
  fi

  checked=$((checked + 1))
done <"${commit_list}"

if ((failed != 0)); then
  exit 1
fi

printf 'DCO check passed for %d commit(s).\n' "${checked}"
