// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
//! TPM-backed attestation backends behind the `ogir-attest` seam
//! (ADR-0018). This crate is the only place raw TPM material may be
//! handled; nothing it exposes is a raw TPM command. The software-TPM
//! backend (`swtpm`) is assurance class `software-tpm` and must never be
//! presented where hardware is required: the seam's strict-equality
//! class gate enforces that at admission.

pub mod enrollment;
pub mod swtpm;
pub mod validation;
