// SPDX-License-Identifier: Apache-2.0

//! The platform-profile schema (ADR-0023): the narrow, documented
//! contract for ONE measured Linux boot profile. A profile is signed
//! reference data (ADR-0014 non-weakening transitions apply); the
//! in-memory type validates shape, not authenticity - authenticity is
//! the manifest layer's duty in M4-029.

use std::collections::HashMap;

use crate::BootlogError;

/// One measured-boot profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformProfile {
    /// Canonical profile name (e.g. `test-image-efi-v1`).
    pub name: String,
    /// Monotonic profile revision; updates must be non-weakening.
    pub revision: u64,
    /// Expected SHA-256 PCR values after replay, per index.
    pub pcr_expectations: HashMap<u32, [u8; 32]>,
    /// Whether Secure Boot must be enabled in the boot path.
    pub secure_boot_required: bool,
    /// The minimum accepted firmware/manifest versions (revocation
    /// floor); component names map to version strings.
    pub minimum_versions: HashMap<String, String>,
}

impl PlatformProfile {
    /// Validates the profile's shape.
    pub fn validate(&self) -> Result<(), BootlogError> {
        if self.name.is_empty() || self.name.len() > 128 {
            return Err(BootlogError::InvalidProfile("name"));
        }
        if self.pcr_expectations.is_empty() {
            return Err(BootlogError::InvalidProfile("no PCR expectations"));
        }
        if self.pcr_expectations.keys().any(|index| *index > 23) {
            return Err(BootlogError::InvalidProfile("PCR index out of range"));
        }
        Ok(())
    }

    /// Whether `other` is an accepted non-weakening successor of this
    /// profile per the ADR-0014 transition relation: the revision must
    /// increase, and no expectation may be removed or loosened (each
    /// old expectation must be carried forward unchanged; new
    /// expectations may be added, and minimum versions may only rise).
    pub fn is_non_weakening_successor(&self, other: &PlatformProfile) -> bool {
        if other.revision <= self.revision || other.name != self.name {
            return false;
        }
        for (index, value) in &self.pcr_expectations {
            if other.pcr_expectations.get(index) != Some(value) {
                return false;
            }
        }
        for (component, floor) in &self.minimum_versions {
            match other.minimum_versions.get(component) {
                Some(other_floor) if other_floor >= floor => {}
                _ => return false,
            }
        }
        if !other.secure_boot_required && self.secure_boot_required {
            return false;
        }
        true
    }
}
