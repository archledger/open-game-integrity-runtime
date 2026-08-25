#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="${repository_root}/scripts/check-repository-metadata.sh"

if [[ ! -x "${checker}" ]]; then
  echo "metadata checker is missing or not executable: ${checker}" >&2
  exit 1
fi

fixture_root="$(mktemp -d)"
trap 'rm -rf -- "${fixture_root}"' EXIT
failures=0

make_fixture() {
  local name="$1"
  fixture="${fixture_root}/${name}"
  mkdir -p "${fixture}/src" "${fixture}/scripts" "${fixture}/wine" "${fixture}/bpf"
  git -C "${fixture}" init -q
  printf '%s\n' '// SPDX-License-Identifier: Apache-2.0' >"${fixture}/src/lib.rs"
  printf '%s\n' '#!/usr/bin/env bash' '# SPDX-License-Identifier: Apache-2.0' >"${fixture}/scripts/tool.sh"
  printf '%s\n' '/* SPDX-License-Identifier: LGPL-2.1-or-later */' >"${fixture}/wine/example.c"
  printf '%s\n' '/* SPDX-License-Identifier: GPL-2.0-only */' >"${fixture}/bpf/example.bpf.c"
  git -C "${fixture}" add .
}

expect_pass() {
  local name="$1"
  local output
  if output="$("${checker}" "${fixture}" 2>&1)"; then
    printf 'PASS: %s\n' "${name}"
  else
    printf 'FAIL: %s unexpectedly failed\n%s\n' "${name}" "${output}" >&2
    failures=$((failures + 1))
  fi
}

expect_fail() {
  local name="$1"
  local expected="$2"
  local output
  if output="$("${checker}" "${fixture}" 2>&1)"; then
    printf 'FAIL: %s unexpectedly passed\n' "${name}" >&2
    failures=$((failures + 1))
  elif [[ "${output}" != *"${expected}"* ]]; then
    printf 'FAIL: %s did not report %s\n%s\n' "${name}" "${expected}" "${output}" >&2
    failures=$((failures + 1))
  else
    printf 'PASS: %s\n' "${name}"
  fi
}

make_fixture clean
expect_pass "valid metadata"

make_fixture account-marker
account_marker='YOUR-GITHUB-'"ACCOUNT"
printf '%s\n' "${account_marker}" >"${fixture}/README.md"
git -C "${fixture}" add README.md
expect_fail "repository account marker" "unresolved repository identity marker"

make_fixture username-marker
username_marker='YOUR_GITHUB_'"USERNAME"
printf '%s\n' "${username_marker}" >"${fixture}/README.md"
git -C "${fixture}" add README.md
expect_fail "CODEOWNERS username marker" "unresolved repository identity marker"

make_fixture missing-spdx
printf '%s\n' 'pub fn missing_license() {}' >"${fixture}/src/missing.rs"
git -C "${fixture}" add src/missing.rs
expect_fail "missing source license" "src/missing.rs: expected SPDX-License-Identifier: Apache-2.0"

make_fixture wrong-wine-license
printf '%s\n' '/* SPDX-License-Identifier: Apache-2.0 */' >"${fixture}/wine/example.c"
git -C "${fixture}" add wine/example.c
expect_fail "incorrect Wine license" "wine/example.c: expected SPDX-License-Identifier: LGPL-2.1-or-later"

make_fixture wrong-bpf-license
printf '%s\n' '/* SPDX-License-Identifier: Apache-2.0 */' >"${fixture}/bpf/example.bpf.c"
git -C "${fixture}" add bpf/example.bpf.c
expect_fail "incorrect BPF license" "bpf/example.bpf.c: expected SPDX-License-Identifier: GPL-2.0-only"

fixture="${fixture_root}/bare.git"
git init --bare -q "${fixture}"
expect_fail "bare repository" "repository metadata check requires a Git worktree"

make_fixture corrupt-index
printf '%s\n' 'corrupt-index' >"${fixture}/.git/index"
expect_fail "corrupt Git index" "repository metadata check failed to search tracked content"

if ((failures > 0)); then
  printf '%d repository metadata test(s) failed\n' "${failures}" >&2
  exit 1
fi

echo "All repository metadata tests passed."
