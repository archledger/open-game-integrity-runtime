// SPDX-License-Identifier: Apache-2.0

//! Reference-manifest signature verification (ADR-0025). The
//! manifest's structural and policy layers live in `ogir-bootlog`;
//! this module is the cryptographic leg: the RSASSA-SHA256 signature
//! over the manifest's exact payload bytes, verified against a
//! verifier-PINNED anchor modulus through the same audited TPM path
//! as quote verification (ADR-0020). The anchor is never read from
//! the manifest itself.

use ogir_bootlog::manifest::ReferenceManifest;

use crate::validation::{QuoteVerifier, ValidationError};

/// Verifies a parsed reference manifest's signature against the
/// verifier-pinned anchor modulus. `anchor_modulus` is the RSA-2048
/// modulus of the manifest signing key held in verifier
/// configuration (in production, reviewed distribution; in tests,
/// the committed TEST-ONLY anchor fixture).
pub fn verify_reference_manifest_signature(
    verifier: &mut QuoteVerifier,
    anchor_modulus: &[u8],
    manifest: &ReferenceManifest,
) -> Result<(), ValidationError> {
    verifier.verify_signature(anchor_modulus, &manifest.signature, &manifest.payload_bytes)
}
