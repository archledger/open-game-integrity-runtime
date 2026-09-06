# M3-024: Publisher-scoped identity, recovery, and the credential-activation prototype
<!-- labels: type: implementation,area: tpm,area: privacy,risk: trusted-computing-base,status: needs-review -->
<!-- milestone: M3 TPM Backend -->

Status: Local integration candidate; no live GitHub issue yet. Completes roadmap spikes 3-5.

## Problem

M3's three remaining research-spike decisions need artifacts: the
publisher-scoped identity/privacy rule (spike 4), the recovery-after-
TPM-state-loss semantics (spike 5), and the EK-bound AK
credential-activation enrollment prototype (spike 3).

## Scope

- ADR-0021 (identity/privacy): per-scope keys, no cross-publisher
  linkability, documented intra-scope linkability, EK never exposed.
- ADR-0022 (recovery): fail-closed on TPM clear / motherboard
  replacement / firmware update / agent reinstallation; recovery is
  always explicit re-enrollment with per-cause events.
- `activation.rs`: the prototype - client-side EK+AK primaries under
  Endorsement (empty auth), the activation request (marshaled EK public
  + AK name), verifier-side `seal_credential` (MakeCredential), and
  client-side `activate` (ActivateCredential with dual password
  sessions), recovering the exact token.
- Three integration tests: genuine round trip; foreign-client
  rejection; EK/AK-confusion rejection.

## Acceptance criteria

- All house gates green; the activation suite green on real swtpm.
- ADR metadata exact; both ADR gates green.

## Current state

- 2026-09-06: Implemented in `research/m3-024-identity-recovery-enrollment`
  from `4b583bf`; awaiting human review and the signed-commit gate.
