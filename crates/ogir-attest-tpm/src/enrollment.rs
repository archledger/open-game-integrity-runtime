// SPDX-License-Identifier: Apache-2.0

//! Publisher-scoped attestation-key enrollment records (ADR-0019).
//!
//! Enrollment binds one AK public modulus to one publisher scope and an
//! assurance-class expectation. Statements carrying an AK modulus that
//! is not enrolled for the exact publisher scope never validate. This
//! is the enrollment RECORD model; the credential-activation protocol
//! prototype (EK-bound MakeCredential/ActivateCredential) is deferred
//! and re-chartered (see the roadmap M3-022 boundary).

use ogir_attest::AssuranceClass;

/// One enrolled attestation key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkEnrollment {
    /// Publisher scope the key is enrolled for (canonical text).
    pub publisher_scope: String,
    /// The AK's RSA public modulus.
    pub ak_modulus: Vec<u8>,
    /// The assurance class this enrollment was made under.
    pub assurance_class: AssuranceClass,
}

/// A publisher-scoped registry of enrolled AKs.
#[derive(Debug, Default, Clone)]
pub struct EnrollmentRegistry {
    records: Vec<AkEnrollment>,
}

impl EnrollmentRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enrolls one AK for one publisher scope. A modulus may serve at
    /// most one scope: re-enrolling the same modulus under a different
    /// scope rejects, which is the cross-publisher AK-reuse guard.
    pub fn enroll(&mut self, enrollment: AkEnrollment) -> Result<(), EnrollmentError> {
        if enrollment.publisher_scope.is_empty() || enrollment.ak_modulus.is_empty() {
            return Err(EnrollmentError::InvalidRecord);
        }
        if self
            .records
            .iter()
            .any(|record| record.ak_modulus == enrollment.ak_modulus)
        {
            return Err(EnrollmentError::ModulusAlreadyEnrolled);
        }
        self.records.push(enrollment);
        Ok(())
    }

    /// Looks up the enrollment for a publisher scope, if any.
    pub fn find(&self, publisher_scope: &str) -> Option<&AkEnrollment> {
        self.records
            .iter()
            .find(|record| record.publisher_scope == publisher_scope)
    }

    /// The number of enrolled records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Enrollment failures. Non-disciplinary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentError {
    /// The record was malformed.
    InvalidRecord,
    /// The modulus is already enrolled (possibly under another scope).
    ModulusAlreadyEnrolled,
}

impl std::fmt::Display for EnrollmentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRecord => formatter.write_str("enrollment record is invalid"),
            Self::ModulusAlreadyEnrolled => formatter.write_str("AK modulus is already enrolled"),
        }
    }
}

impl std::error::Error for EnrollmentError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(scope: &str) -> AkEnrollment {
        AkEnrollment {
            publisher_scope: scope.to_string(),
            ak_modulus: vec![7; 256],
            assurance_class: AssuranceClass::SoftwareTpm,
        }
    }

    #[test]
    fn enroll_find_roundtrip() {
        let mut registry = EnrollmentRegistry::new();
        assert!(registry.is_empty());
        registry
            .enroll(record("pub.one"))
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.find("pub.one").map(|r| r.assurance_class),
            Some(AssuranceClass::SoftwareTpm)
        );
        assert!(registry.find("pub.other").is_none());
    }

    #[test]
    fn one_modulus_one_scope() {
        let mut registry = EnrollmentRegistry::new();
        registry
            .enroll(record("pub.one"))
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            registry.enroll(record("pub.two")),
            Err(EnrollmentError::ModulusAlreadyEnrolled)
        );
    }

    #[test]
    fn invalid_records_reject() {
        let mut registry = EnrollmentRegistry::new();
        let mut empty_scope = record("pub.one");
        empty_scope.publisher_scope = String::new();
        assert_eq!(
            registry.enroll(empty_scope),
            Err(EnrollmentError::InvalidRecord)
        );
        let mut empty_modulus = record("pub.one");
        empty_modulus.ak_modulus = Vec::new();
        assert_eq!(
            registry.enroll(empty_modulus),
            Err(EnrollmentError::InvalidRecord)
        );
    }
}
