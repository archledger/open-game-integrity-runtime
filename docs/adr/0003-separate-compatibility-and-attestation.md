# ADR-0003: Separate TPM compatibility from physical attestation

- Status: Accepted
- Date: 2026-08-24
- Owners: Initial maintainer
- Related issues: None recorded
- Supersedes: None
- Superseded by: None

## Context

Windows TBS compatibility and hardware-rooted Linux platform attestation solve different problems. Forwarding raw Windows TPM commands to the physical host TPM would expose an unsafe and overly broad interface.

## Decision drivers

- Preserve Windows TBS compatibility without granting games arbitrary physical
  TPM command access.
- Distinguish compatibility state from hardware-rooted assurance.
- Keep privileged operations narrow, policy-controlled, and independently
  attributable.
- Avoid exposing a stable platform identifier or unrelated TPM state to games.

## Options considered

### Forward Windows TPM commands to the physical host TPM

Rejected because an attacker-controlled game or Wine prefix would gain an
overly broad privileged interface and compatibility results could be mistaken
for trusted platform evidence.

### Use one virtual TPM for compatibility and hardware assurance

Rejected because software-backed virtual state cannot silently satisfy a
hardware-ranked assurance profile.

### Separate virtual compatibility from narrow physical attestation

Selected because each path can expose only the semantics, authorization, and
assurance class required for its distinct purpose.

## Decision

- Windows TPM compatibility uses an isolated per-prefix virtual TPM.
- Physical platform attestation uses a narrow high-level OGIR operation controlled by the local agent.
- A virtual TPM cannot satisfy a hardware-ranked profile unless that assurance class is explicitly accepted.

## Consequences

Wine TPM work remains a separate workstream and license boundary. The publisher verifier can distinguish evidence assurance classes.

## Threat-model impact

This decision constrains attacker-controlled game, bridge, prefix, and
same-user processes (A1) from using compatibility APIs as arbitrary physical
TPM access. It makes custom-platform and software-backed evidence distinguishable
for A2–A3 policy decisions. Compromise of the trusted agent, TPM stack, or
firmware remains an A4/A7 residual risk.

## Privacy impact

Compatibility state does not expose the physical Endorsement Key or become a
universal game identifier. Physical attestation remains limited to the fixed
claim vocabulary, publisher-scoped identities where practical, and explicit
local privacy policy.

## Dependency and license impact

No TPM or serialization library is selected by this ADR. Future choices require
their own dependency review. Wine-targeted implementation remains under the
Wine/LGPL boundary, while the high-level agent and evidence model remain in the
Apache-2.0 core.

## Validation

- Add a negative test proving no raw TBS command reaches the physical TPM.
- Demonstrate that virtual TPM evidence cannot satisfy a hardware-only profile.
- Test explicit assurance-class encoding and verifier discrimination.
- Review the physical operation allowlist and caller authorization before any
  hardware-backed implementation.

## Rollback

If physical attestation is unavailable or invalid, deny the hardware-required
mode rather than falling back to virtual TPM assurance. Recombining the two
paths requires a superseding ADR and new threat/privacy analysis.

## Primary sources

- [TCG TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [Wine TBS upstream source](https://github.com/wine-mirror/wine/tree/master/dlls/tbs)
- [OGIR architecture](../ARCHITECTURE.md#42-windows-tpm-compatibility-plane)
- [OGIR threat model](../THREAT_MODEL.md)
- [OGIR security invariants](../SECURITY_INVARIANTS.md), especially invariants
  16–22 and 29–38
