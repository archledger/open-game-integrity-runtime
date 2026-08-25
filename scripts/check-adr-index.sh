#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

write_markdown_structure() {
  local input="$1"
  local output="$2"
  local label="$3"
  local awk_status

  if awk '
    function leading_run(text, character, count) {
      count = 0
      while (substr(text, count + 1, 1) == character) {
        count++
      }
      return count
    }

    function is_indented_code(text) {
      return text ~ /^(\t| \t|  \t|   \t|    )/
    }

    function fence_probe(text) {
      if (is_indented_code(text)) {
        return ""
      }
      if (substr(text, 1, 3) == "   ") {
        return substr(text, 4)
      }
      if (substr(text, 1, 2) == "  ") {
        return substr(text, 3)
      }
      if (substr(text, 1, 1) == " ") {
        return substr(text, 2)
      }
      return text
    }

    {
      raw_probe = fence_probe($0)

      if (fence_character != "") {
        if (substr(raw_probe, 1, 1) == fence_character) {
          run = leading_run(raw_probe, fence_character)
          suffix = substr(raw_probe, run + 1)
          if (run >= fence_length && suffix ~ /^[[:space:]]*$/) {
            fence_character = ""
            fence_length = 0
          }
        }
        next
      }

      visible = ""
      remaining = $0

      while (1) {
        if (inside_comment) {
          comment_end = index(remaining, "-->")
          if (comment_end == 0) {
            remaining = ""
            break
          }
          remaining = substr(remaining, comment_end + 3)
          inside_comment = 0
          continue
        }

        comment_start = index(remaining, "<!--")
        if (comment_start == 0) {
          visible = visible remaining
          break
        }

        visible = visible substr(remaining, 1, comment_start - 1)
        remaining = substr(remaining, comment_start + 4)
        inside_comment = 1
      }

      line = visible
      if (is_indented_code(line)) {
        next
      }
      probe = fence_probe(line)

      if (probe ~ /^<\/?[[:alpha:]][[:alnum:]-]*([[:space:]]|\/?>)/ ||
          probe ~ /^<\?/ || probe ~ /^<![[:alpha:]]/ ||
          probe ~ /^<!\[/) {
        invalid_html = 1
        exit 42
      }

      first_character = substr(probe, 1, 1)
      if (first_character == "`" || first_character == "~") {
        run = leading_run(probe, first_character)
        if (run >= 3) {
          fence_character = first_character
          fence_length = run
          next
        }
      }

      print line
    }

    END {
      if (invalid_html) {
        exit 42
      }
      if (inside_comment || fence_character != "") {
        exit 43
      }
    }
  ' "${input}" >"${output}"; then
    return 0
  else
    awk_status=$?
  fi

  if ((awk_status == 42)); then
    printf '%s: raw HTML is not allowed outside code blocks\n' \
      "${label}" >&2
  elif ((awk_status == 43)); then
    printf '%s: unclosed HTML comment or fenced code block\n' \
      "${label}" >&2
  else
    printf '%s: failed to parse staged Markdown structure\n' \
      "${label}" >&2
  fi
  return 1
}

has_inline_markdown_link() {
  local input="$1"
  local target="$2"

  awk -v target="${target}" '
    function is_escaped(text, position, count, cursor) {
      count = 0
      for (cursor = position - 1;
           cursor >= 1 && substr(text, cursor, 1) == "\\";
           cursor--) {
        count++
      }
      return count % 2 == 1
    }

    function backtick_run(text, position, count) {
      count = 0
      while (substr(text, position + count, 1) == "`") {
        count++
      }
      return count
    }

    {
      line = $0
      for (start = 1; start <= length(line); start++) {
        character = substr(line, start, 1)
        if (character == "`") {
          run = backtick_run(line, start)
          if (code_ticks != 0) {
            if (run == code_ticks) {
              code_ticks = 0
            }
          } else if (!is_escaped(line, start)) {
            code_ticks = run
          }
          start += run - 1
          continue
        }
        if (code_ticks != 0 || character != "[") {
          continue
        }
        if (is_escaped(line, start)) {
          continue
        }
        if (start > 1 && substr(line, start - 1, 1) == "!") {
          continue
        }

        remainder = substr(line, start + 1)
        closing_bracket = index(remainder, "]")
        if (closing_bracket <= 1) {
          continue
        }
        label = substr(remainder, 1, closing_bracket - 1)
        if (index(label, "[") != 0) {
          continue
        }
        destination = substr(line, start + closing_bracket + 1, length(target) + 2)
        if (destination == "(" target ")") {
          found = 1
          exit
        }
      }
    }

    END {
      exit(found ? 0 : 1)
    }
  ' "${input}"
}

require_staged_regular_file() {
  local root="$1"
  local path="$2"
  local staged_entry entry_metadata entry_mode entry_stage

  if ! git -C "${root}" ls-files --error-unmatch -- \
    "${path}" >/dev/null 2>&1; then
    printf '%s is missing from staged files\n' "${path}" >&2
    return 1
  fi
  if ! staged_entry="$(
    git -C "${root}" ls-files --stage -- "${path}"
  )"; then
    printf 'ADR index check failed to inspect staged mode for %s\n' \
      "${path}" >&2
    return 2
  fi

  if [[ -z "${staged_entry}" || "${staged_entry}" == *$'\n'* ]]; then
    printf '%s must be a regular non-executable staged file\n' \
      "${path}" >&2
    return 1
  fi

  entry_metadata="${staged_entry%%$'\t'*}"
  IFS=' ' read -r entry_mode _ entry_stage <<<"${entry_metadata}"
  if [[ "${entry_mode}" != "100644" || "${entry_stage}" != "0" ]]; then
    printf '%s must be a regular non-executable staged file\n' \
      "${path}" >&2
    return 1
  fi
}

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
structure_file="$(mktemp)"
index_structure_file="$(mktemp)"
trap 'rm -f -- "${tracked_paths_file}" "${index_file}" "${adr_file}" "${structure_file}" "${index_structure_file}"' EXIT

if ! git -C "${repository_root}" ls-files --stage -z -- docs/adr \
  >"${tracked_paths_file}"; then
  echo "ADR index check failed to enumerate staged ADR files" >&2
  exit 2
fi

require_staged_regular_file "${repository_root}" \
  "docs/adr/template.md" || exit $?
require_staged_regular_file "${repository_root}" \
  "docs/adr/README.md" || exit $?
if ! git -C "${repository_root}" show :docs/adr/README.md >"${adr_file}"; then
  echo "ADR index check failed to read staged docs/adr/README.md" >&2
  exit 2
fi
if ! write_markdown_structure "${adr_file}" "${structure_file}" \
  "docs/adr/README.md"; then
  exit 1
fi
if ! has_inline_markdown_link "${structure_file}" "index.md" ||
  ! has_inline_markdown_link "${structure_file}" "template.md"; then
  echo "docs/adr/README.md must link to index.md and template.md" >&2
  exit 1
fi
if ! git -C "${repository_root}" show :docs/adr/template.md >"${adr_file}"; then
  echo "ADR index check failed to read staged docs/adr/template.md" >&2
  exit 2
fi
if ! write_markdown_structure "${adr_file}" "${structure_file}" \
  "docs/adr/template.md"; then
  exit 1
fi
for required_section in "${required_sections[@]}"; do
  section_count="$(
    grep -a -Fxc -- "## ${required_section}" "${structure_file}" || true
  )"
  if ((section_count == 0)); then
    printf 'docs/adr/template.md: missing required ADR section: %s\n' \
      "${required_section}" >&2
    exit 1
  fi
  if ((section_count > 1)); then
    printf 'docs/adr/template.md: duplicate required ADR section: %s\n' \
      "${required_section}" >&2
    exit 1
  fi
  if ! awk -v heading="## ${required_section}" '
    $0 == heading { inside = 1; next }
    inside && /^## / { exit 1 }
    inside && $0 !~ /^[[:space:]]*$/ { found = 1; exit 0 }
    END { if (!found) exit 1 }
  ' "${structure_file}"; then
    printf 'docs/adr/template.md: empty required ADR section: %s\n' \
      "${required_section}" >&2
    exit 1
  fi
done
require_staged_regular_file "${repository_root}" \
  "docs/adr/index.md" || exit $?
if ! git -C "${repository_root}" show :docs/adr/index.md >"${index_file}"; then
  echo "ADR index check failed to read staged docs/adr/index.md" >&2
  exit 2
fi
if ! write_markdown_structure "${index_file}" "${index_structure_file}" \
  "docs/adr/index.md"; then
  exit 1
fi

declare -A adr_paths=()
declare -A adr_statuses=()
declare -A adr_supersedes=()
declare -A adr_superseded_by=()
declare -A index_paths=()
declare -A index_statuses=()
declare -A index_supersedes=()
declare -A index_superseded_by=()
declare -A supersedes_edges=()
declare -A superseded_by_edges=()
status=0

record_relation_edges() {
  local source_id="$1"
  local field_label="$2"
  local relation_value="$3"
  local direction="$4"
  local remaining target_id target_path expected_path edge_key
  local relation_pattern='^\[ADR-([0-9]{4})\]\(([^)]+)\)(,[[:space:]]*(.*))?$'

  if [[ "${relation_value}" == "None" ]]; then
    return 0
  fi

  remaining="${relation_value}"
  while [[ -n "${remaining}" ]]; do
    if [[ ! "${remaining}" =~ ${relation_pattern} ]]; then
      printf 'ADR-%s has invalid %s metadata: %s\n' \
        "${source_id}" "${field_label}" "${relation_value}" >&2
      return 1
    fi

    target_id="${BASH_REMATCH[1]}"
    target_path="${BASH_REMATCH[2]}"
    remaining="${BASH_REMATCH[4]}"
    expected_path="${adr_paths[${target_id}]:-}"

    if [[ -z "${expected_path}" ]]; then
      printf 'ADR-%s %s references missing ADR-%s\n' \
        "${source_id}" "${field_label}" "${target_id}" >&2
      return 1
    fi
    if [[ "${expected_path}" != "docs/adr/${target_path}" ]]; then
      printf 'ADR-%s %s path does not match ADR-%s staged file\n' \
        "${source_id}" "${field_label}" "${target_id}" >&2
      return 1
    fi
    if [[ "${source_id}" == "${target_id}" ]]; then
      printf 'ADR-%s cannot reference itself in %s\n' \
        "${source_id}" "${field_label}" >&2
      return 1
    fi

    edge_key="${source_id}:${target_id}"
    if [[ "${direction}" == "supersedes" ]]; then
      if [[ -n "${supersedes_edges[${edge_key}]:-}" ]]; then
        printf 'ADR-%s repeats ADR-%s in %s\n' \
          "${source_id}" "${target_id}" "${field_label}" >&2
        return 1
      fi
      supersedes_edges["${edge_key}"]=1
    else
      if [[ -n "${superseded_by_edges[${edge_key}]:-}" ]]; then
        printf 'ADR-%s repeats ADR-%s in %s\n' \
          "${source_id}" "${target_id}" "${field_label}" >&2
        return 1
      fi
      superseded_by_edges["${edge_key}"]=1
    fi
  done
}

while IFS= read -r -d '' tracked_entry; do
  path="${tracked_entry#*$'\t'}"
  case "${path}" in
    docs/adr/[0-9][0-9][0-9][0-9]-*.md) ;;
    *) continue ;;
  esac

  entry_metadata="${tracked_entry%%$'\t'*}"
  IFS=' ' read -r entry_mode _ entry_stage <<<"${entry_metadata}"
  if [[ "${entry_mode}" != "100644" || "${entry_stage}" != "0" ]]; then
    printf '%s must be a regular non-executable staged file\n' \
      "${path}" >&2
    status=1
    continue
  fi

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
  if ! write_markdown_structure "${adr_file}" "${structure_file}" \
    "${path}"; then
    exit 1
  fi

  title_line=""
  IFS= read -r title_line <"${structure_file}" || true
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

  adr_status="$(grep -a -E '^- Status: [^[:space:]].*$' "${structure_file}" || true)"
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

  supersedes_count="$(
    grep -a -Ec '^- Supersedes: [^[:space:]].*$' \
      "${structure_file}" || true
  )"
  if ((supersedes_count != 1)); then
    printf '%s: expected exactly one Supersedes metadata field\n' \
      "${path}" >&2
    status=1
    continue
  fi
  supersedes_line="$(
    grep -a -E '^- Supersedes: [^[:space:]].*$' "${structure_file}"
  )"
  adr_supersedes["${adr_id}"]="${supersedes_line#- Supersedes: }"

  superseded_by_count="$(
    grep -a -Ec '^- Superseded by: [^[:space:]].*$' \
      "${structure_file}" || true
  )"
  if ((superseded_by_count != 1)); then
    printf '%s: expected exactly one Superseded by metadata field\n' \
      "${path}" >&2
    status=1
    continue
  fi
  superseded_by_line="$(
    grep -a -E '^- Superseded by: [^[:space:]].*$' "${structure_file}"
  )"
  adr_superseded_by["${adr_id}"]="${superseded_by_line#- Superseded by: }"

  if [[ "${adr_status}" == "Superseded" ]] &&
    [[ "${adr_superseded_by[${adr_id}]}" == "None" ]]; then
    printf 'ADR-%s has Superseded status without Superseded by metadata\n' \
      "${adr_id}" >&2
    status=1
  elif [[ "${adr_status}" != "Superseded" ]] &&
    [[ "${adr_superseded_by[${adr_id}]}" != "None" ]]; then
    printf 'ADR-%s has Superseded by metadata without Superseded status\n' \
      "${adr_id}" >&2
    status=1
  fi

  for required_section in "${required_sections[@]}"; do
    section_count="$(
      grep -a -Fxc -- "## ${required_section}" "${structure_file}" || true
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
    ' "${structure_file}"; then
      printf '%s: empty required ADR section: %s\n' \
        "${path}" "${required_section}" >&2
      status=1
    fi
  done
done <"${tracked_paths_file}"

for adr_id in "${!adr_paths[@]}"; do
  if [[ -n "${adr_supersedes[${adr_id}]:-}" ]] &&
    ! record_relation_edges "${adr_id}" "Supersedes" \
      "${adr_supersedes[${adr_id}]}" "supersedes"; then
    status=1
  fi
  if [[ -n "${adr_superseded_by[${adr_id}]:-}" ]] &&
    ! record_relation_edges "${adr_id}" "Superseded by" \
      "${adr_superseded_by[${adr_id}]}" "superseded_by"; then
    status=1
  fi
done

for edge_key in "${!superseded_by_edges[@]}"; do
  source_id="${edge_key%%:*}"
  target_id="${edge_key##*:}"
  reciprocal_key="${target_id}:${source_id}"
  if [[ -z "${supersedes_edges[${reciprocal_key}]:-}" ]]; then
    printf 'ADR-%s Superseded by ADR-%s lacks reciprocal Supersedes metadata\n' \
      "${source_id}" "${target_id}" >&2
    status=1
  fi
done

for edge_key in "${!supersedes_edges[@]}"; do
  source_id="${edge_key%%:*}"
  target_id="${edge_key##*:}"
  reciprocal_key="${target_id}:${source_id}"
  if [[ -z "${superseded_by_edges[${reciprocal_key}]:-}" ]]; then
    printf 'ADR-%s Supersedes ADR-%s lacks reciprocal Superseded by metadata\n' \
      "${source_id}" "${target_id}" >&2
    status=1
  fi
done

index_row_pattern='^[[:space:]]*\|[[:space:]]*\[ADR-([0-9]{4})\]\(([^)]+)\)[[:space:]]*\|[[:space:]]*([^|]+)[[:space:]]*\|[[:space:]]*([^|]+)[[:space:]]*\|[[:space:]]*([^|]+)[[:space:]]*\|[[:space:]]*([^|]+)[[:space:]]*\|[[:space:]]*$'
while IFS= read -r index_line; do
  if [[ ! "${index_line}" =~ ${index_row_pattern} ]]; then
    continue
  fi

  index_id="${BASH_REMATCH[1]}"
  index_path="${BASH_REMATCH[2]}"
  index_status="${BASH_REMATCH[3]}"
  index_supersedes_value="${BASH_REMATCH[5]}"
  index_superseded_by_value="${BASH_REMATCH[6]}"
  index_status="${index_status#"${index_status%%[![:space:]]*}"}"
  index_status="${index_status%"${index_status##*[![:space:]]}"}"
  index_supersedes_value="${index_supersedes_value#"${index_supersedes_value%%[![:space:]]*}"}"
  index_supersedes_value="${index_supersedes_value%"${index_supersedes_value##*[![:space:]]}"}"
  index_superseded_by_value="${index_superseded_by_value#"${index_superseded_by_value%%[![:space:]]*}"}"
  index_superseded_by_value="${index_superseded_by_value%"${index_superseded_by_value##*[![:space:]]}"}"

  if [[ -n "${index_paths[${index_id}]:-}" ]]; then
    printf 'ADR-%s has duplicate entries in docs/adr/index.md\n' \
      "${index_id}" >&2
    status=1
    continue
  fi

  index_paths["${index_id}"]="${index_path}"
  index_statuses["${index_id}"]="${index_status}"
  index_supersedes["${index_id}"]="${index_supersedes_value}"
  index_superseded_by["${index_id}"]="${index_superseded_by_value}"
  full_index_path="docs/adr/${index_path}"
  if [[ "${adr_paths[${index_id}]:-}" != "${full_index_path}" ]]; then
    printf 'ADR-%s index entry references missing %s\n' \
      "${index_id}" "${full_index_path}" >&2
    status=1
  fi
done <"${index_structure_file}"

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
  if [[ "${index_supersedes[${adr_id}]}" != "${adr_supersedes[${adr_id}]}" ]]; then
    printf 'ADR-%s index Supersedes does not match staged ADR metadata\n' \
      "${adr_id}" >&2
    status=1
  fi
  if [[ "${index_superseded_by[${adr_id}]}" != "${adr_superseded_by[${adr_id}]}" ]]; then
    printf 'ADR-%s index Superseded by does not match staged ADR metadata\n' \
      "${adr_id}" >&2
    status=1
  fi
done

if ((status != 0)); then
  exit 1
fi

printf 'ADR index check passed for %d decision record(s).\n' "${#adr_paths[@]}"
