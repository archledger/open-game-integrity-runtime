// SPDX-License-Identifier: Apache-2.0

//! The measured-boot admission point (M4-030, ADR-0026): ONE function
//! that decides whether a boot's evidence admits against the signed
//! reference manifest. The order of the legs is the M4 exit criteria
//! made code: profile identity and Secure Boot state are checked
//! BEFORE measurements, but no leg alone can ever admit - "Secure
//! Boot enabled" is a necessary input, never a sufficient one, and
//! the component signing root must be explicitly accepted (the
//! custom-key distinction from ADR-0025).

use std::collections::HashMap;

use crate::BootlogError;
use crate::manifest::ReferenceManifest;

/// The boot evidence an admission decision runs over. The replay
/// values come from the event-log replay validated against the live
/// read and the quote (the M4-028c triangle); the Secure Boot flag
/// comes from the EFI variable read at collection; the component
/// root fingerprint is the verified signer of the booted components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootEvidence {
    /// The profile name the evidence bundle claims.
    pub claimed_profile: String,
    /// Replayed SHA-256 PCR values (already triangle-validated).
    pub replay_values: HashMap<u32, [u8; 32]>,
    /// Whether the platform reported Secure Boot enabled.
    pub secure_boot_enabled: bool,
    /// The SHA-256 fingerprint of the signing root that signed the
    /// booted components, when the signature was verified.
    pub component_root_fingerprint: Option<[u8; 32]>,
}

/// Admits a boot against the manifest. Every leg must hold:
///
/// 1. the claimed profile matches (an unknown profile is
///    UNSUPPORTED, never an attack verdict);
/// 2. Secure Boot is enabled when the profile requires it (a
///    disabled Secure Boot is its own distinguishable state);
/// 3. the component signing root is present and accepted;
/// 4. every manifest PCR expectation is reproduced exactly by the
///    replay (a changed measurement is a mismatch, whatever the
///    Secure Boot state).
pub fn admit_boot(
    manifest: &ReferenceManifest,
    evidence: &BootEvidence,
) -> Result<(), BootlogError> {
    manifest.matches_profile(&evidence.claimed_profile)?;
    if manifest.profile.secure_boot_required && !evidence.secure_boot_enabled {
        return Err(BootlogError::SecureBootDisabled);
    }
    match evidence.component_root_fingerprint {
        Some(fingerprint) if manifest.accepts_signing_root(&fingerprint) => {}
        Some(_) => return Err(BootlogError::SigningRootRejected),
        None => return Err(BootlogError::SigningRootNotValidated),
    }
    for (index, expectation) in &manifest.profile.pcr_expectations {
        if evidence.replay_values.get(index) != Some(expectation) {
            return Err(BootlogError::PcrMismatch);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> BootEvidence {
        BootEvidence {
            claimed_profile: "test-image-efi-capture-v1".to_string(),
            replay_values: [(7u32, [7u8; 32])].into_iter().collect(),
            secure_boot_enabled: true,
            component_root_fingerprint: Some([1u8; 32]),
        }
    }

    fn manifest_with(root: [u8; 32]) -> ReferenceManifest {
        ReferenceManifest {
            manifest_version: 1,
            profile: crate::profile::PlatformProfile {
                name: "test-image-efi-capture-v1".to_string(),
                revision: 1,
                pcr_expectations: [(7u32, [7u8; 32])].into_iter().collect(),
                secure_boot_required: true,
                minimum_versions: [("uki".to_string(), "1".to_string())].into_iter().collect(),
            },
            signing_roots: vec![crate::manifest::SigningRoot {
                name: "image-key".to_string(),
                fingerprint: root,
            }],
            revocations: vec![],
            payload_bytes: b"payload".to_vec(),
            signature: [0u8; 256],
        }
    }

    #[test]
    fn matching_evidence_admits() {
        assert_eq!(admit_boot(&manifest_with([1u8; 32]), &evidence()), Ok(()));
    }

    #[test]
    fn no_leg_alones_admits() {
        let manifest = manifest_with([1u8; 32]);
        let mut wrong_profile = evidence();
        wrong_profile.claimed_profile = "other".to_string();
        assert_eq!(
            admit_boot(&manifest, &wrong_profile),
            Err(BootlogError::UnsupportedProfile)
        );
        let mut sb_off = evidence();
        sb_off.secure_boot_enabled = false;
        assert_eq!(
            admit_boot(&manifest, &sb_off),
            Err(BootlogError::SecureBootDisabled)
        );
        let mut foreign_root = evidence();
        foreign_root.component_root_fingerprint = Some([9u8; 32]);
        assert_eq!(
            admit_boot(&manifest, &foreign_root),
            Err(BootlogError::SigningRootRejected)
        );
        let mut unvalidated_root = evidence();
        unvalidated_root.component_root_fingerprint = None;
        assert_eq!(
            admit_boot(&manifest, &unvalidated_root),
            Err(BootlogError::SigningRootNotValidated)
        );
        let mut wrong_pcr = evidence();
        wrong_pcr.replay_values.insert(7, [9u8; 32]);
        assert_eq!(
            admit_boot(&manifest, &wrong_pcr),
            Err(BootlogError::PcrMismatch)
        );
    }

    #[test]
    fn secure_boot_alone_is_never_sufficient() {
        // The M4 exit criterion as a direct negative: every
        // non-measurement leg green, one expectation missing from the
        // replay still rejects.
        let manifest = manifest_with([1u8; 32]);
        let mut short = evidence();
        short.replay_values.clear();
        assert_eq!(
            admit_boot(&manifest, &short),
            Err(BootlogError::PcrMismatch)
        );
    }
}
