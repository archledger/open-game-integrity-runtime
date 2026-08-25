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

if [[ "${repository}" != */* ]]; then
  echo "Repository must be in owner/name form: ${repository}" >&2
  exit 1
fi

create_label() {
  local name="$1"
  local color="$2"
  local description="$3"
  gh label create "${name}" \
    --repo "${repository}" \
    --color "${color}" \
    --description "${description}" \
    --force >/dev/null
}

# Type labels.
create_label "type: architecture" "5319E7" "Durable trust, protocol, privilege, or component decision"
create_label "type: research" "1D76DB" "Evidence-gathering spike that unblocks a decision"
create_label "type: implementation" "0E8A16" "Scoped implementation work"
create_label "type: test" "BFDADC" "Unit, integration, conformance, or regression testing"
create_label "type: fuzzing" "D4C5F9" "Fuzz, property, mutation, or parser hardening"
create_label "type: documentation" "0075CA" "Documentation-only change"
create_label "type: security-hardening" "B60205" "Defense-in-depth or attack-surface reduction"
create_label "type: dependency" "0366D6" "Dependency or toolchain review"
create_label "type: release" "FBCA04" "Release, provenance, signing, or lifecycle work"

# Area labels.
create_label "area: model" "C5DEF5" "Pure domain model and invariants"
create_label "area: protocol" "C5DEF5" "Challenge, evidence, permit, renewal, and revocation protocol"
create_label "area: verifier" "C5DEF5" "Publisher verifier and relying-party boundary"
create_label "area: agent" "C5DEF5" "Local portal and attestation agent"
create_label "area: tpm" "C5DEF5" "TPM backend, identity, quote, and enrollment"
create_label "area: measured-boot" "C5DEF5" "Measured boot, UKI, PCR, and reference values"
create_label "area: proton-bridge" "C5DEF5" "Windows ABI, Wine/Proton transport, and caller binding"
create_label "area: session" "C5DEF5" "Protected-session lifecycle, observation, and enforcement"
create_label "area: wine-tpm" "C5DEF5" "Separate Wine TPM compatibility workstream"
create_label "area: attack-lab" "C5DEF5" "Executable adversarial scenarios and test infrastructure"
create_label "area: supply-chain" "C5DEF5" "Build, dependency, provenance, update, and release security"
create_label "area: privacy" "C5DEF5" "Disclosure minimization, identity scope, and privacy controls"

# Risk labels.
create_label "risk: trusted-computing-base" "B60205" "Changes trusted code or a trust decision"
create_label "risk: privileged" "B60205" "Changes privileged operations or service isolation"
create_label "risk: cryptography" "B60205" "Changes signature, key, transcript, or cryptographic behavior"
create_label "risk: parser" "D93F0B" "Processes attacker-controlled structured input"
create_label "risk: privacy" "D93F0B" "Changes claims, identifiers, logs, or disclosed data"
create_label "risk: compatibility" "FBCA04" "May affect supported platforms, Wine, or Proton"

# Status labels.
create_label "status: needs-research" "EDEDED" "Blocked on primary-source research or experiment"
create_label "status: blocked" "000000" "Cannot proceed until a named dependency is resolved"
create_label "status: ready" "0E8A16" "Specification and acceptance criteria are implementation-ready"
create_label "status: needs-review" "FBCA04" "Awaiting adversarial or human review"
create_label "status: experimental" "D4C5F9" "Research behavior without production guarantees"
create_label "status: do-not-merge" "B60205" "Must not merge until the blocker is removed"

milestones=(
  "M0 Repository Foundation"
  "M1 Domain Model"
  "M2 Mock End-to-End Proof"
  "M3 TPM Backend"
  "M4 Measured Boot Profile"
  "M5 Proton Bridge"
  "M6 Publisher SDK and Verifier"
  "M7 Session Observation"
  "M8 Scoped Enforcement"
  "M9 Attack Laboratory"
  "M10 Wine TPM Compatibility"
  "M11 Publisher Pilot"
  "M12 Production Candidate"
)
milestone_descriptions=(
  "Create a public, reviewable project where unsafe process choices are difficult from the first commit."
  "Define what OGIR means before deciding how bytes are encoded or which libraries implement it."
  "Prove challenge, evidence, verifier, permit, and session-key binding without involving TPM complexity."
  "Replace the mock attester with real TPM-backed freshness and key possession while keeping the rest of the system backend-agnostic."
  "Prove one narrow, documented Linux platform profile rather than claiming generic Linux trust."
  "Allow a Windows sample game under stock Proton to invoke OGIR without trusting Windows-provided identity fields."
  "Make the integration experience credible for a game studio while retaining publisher control."
  "Bind the attestation report to the actual live game process tree before enforcing restrictions."
  "Add only the minimum game-scoped controls needed for a clearly defined threat class."
  "Turn the threat model into executable, repeatable adversarial testing."
  "Improve ordinary Windows TPM API compatibility under Wine without conflating it with physical-host attestation."
  "Earn justified trust rather than asking publishers to trust project reputation alone."
  "Offer one supportable, versioned profile with explicit lifecycle and residual risk."
)

existing_milestones="$(
  gh api --paginate "repos/${repository}/milestones?state=all&per_page=100" \
    --jq '.[] | [.number, .title, .state, (.description // ""), (.due_on // "")] | @tsv'
)"
for milestone_index in "${!milestones[@]}"; do
  title="${milestones[${milestone_index}]}"
  milestone_description="${milestone_descriptions[${milestone_index}]}"
  milestone_match_count="$(
    awk -F '\t' -v title="${title}" \
      '$2 == title { count++ } END { print count + 0 }' \
      <<<"${existing_milestones}"
  )"
  if ((milestone_match_count > 1)); then
    printf 'duplicate milestone title: %s\n' "${title}" >&2
    exit 1
  fi
  existing_milestone="$(
    awk -F '\t' -v title="${title}" '$2 == title { print; exit }' \
      <<<"${existing_milestones}"
  )"
  if [[ -z "${existing_milestone}" ]]; then
    gh api --method POST "repos/${repository}/milestones" \
      -f title="${title}" \
      -f state="open" \
      -f description="${milestone_description}" >/dev/null
    continue
  fi

  IFS=$'\t' read -r milestone_number _ existing_state \
    existing_description existing_due_on <<<"${existing_milestone}"
  if [[ "${existing_state}" != "open" ||
    "${existing_description}" != "${milestone_description}" ||
    -n "${existing_due_on}" ]]; then
    gh api --method PATCH \
      "repos/${repository}/milestones/${milestone_number}" \
      -f state="open" \
      -f description="${milestone_description}" \
      -F due_on=null >/dev/null
  fi
done

printf 'Created or updated OGIR labels and milestones in %s.\n' "${repository}"
printf 'Complete the manual security settings in docs/GITHUB_SETUP.md next.\n'
