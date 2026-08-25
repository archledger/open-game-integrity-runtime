# ADR-0003: Separate TPM compatibility from physical attestation

- Status: Accepted
- Date: 2026-08-24
- Owners: Initial maintainer

## Context

Windows TBS compatibility and hardware-rooted Linux platform attestation solve different problems. Forwarding raw Windows TPM commands to the physical host TPM would expose an unsafe and overly broad interface.

## Decision

- Windows TPM compatibility uses an isolated per-prefix virtual TPM.
- Physical platform attestation uses a narrow high-level OGIR operation controlled by the local agent.
- A virtual TPM cannot satisfy a hardware-ranked profile unless that assurance class is explicitly accepted.

## Consequences

Wine TPM work remains a separate workstream and license boundary. The publisher verifier can distinguish evidence assurance classes.
