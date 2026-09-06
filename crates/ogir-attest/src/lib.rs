// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
//! Backend-agnostic attestation seam (ADR-0017).
//!
//! An [`AttestationBackend`] produces attestation statements for a
//! backend-defined quote payload bound to caller qualifying data. The
//! trait is a provisional contract: it hardens in M3-021 when the first
//! real TPM backend exercises it. Statements are candidate inputs, never
//! authority. Assurance classes are strict: a verifier expecting one
//! class rejects every other class, so test, software-TPM, and
//! hardware-TPM evidence cannot be confused. No raw physical-TPM
//! command is exposed here or may be exposed by any backend outside its
//! own boundary.

use std::error::Error;
use std::fmt;

/// Maximum accepted qualifying-data length in bytes.
pub const MAX_QUALIFYING_DATA_LENGTH: usize = 1024;

/// Maximum accepted quote-payload length in bytes, aligned with the
/// protocol frame bound.
pub const MAX_QUOTE_PAYLOAD_LENGTH: usize = 1024 * 1024;

/// Assurance class of an attestation backend and its statements.
///
/// Classes are disjoint by construction: the acceptance gate compares
/// for exact equality only, so a verifier expecting hardware evidence
/// cannot be satisfied by software or test evidence, and vice versa
/// (M3 exit criterion).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssuranceClass {
    /// Deterministic test substrate; no TPM of any kind.
    Test,
    /// Software TPM (for example swtpm); real TPM 2.0 command
    /// semantics, no hardware protection.
    SoftwareTpm,
    /// Hardware or firmware TPM (for example a discrete TPM or a
    /// platform fTPM); hardware-protected key material.
    HardwareFirmwareTpm,
}

impl AssuranceClass {
    /// Stable, public, non-disciplinary class label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Test => "test",
            Self::SoftwareTpm => "software-tpm",
            Self::HardwareFirmwareTpm => "hardware-ftpm",
        }
    }
}

impl fmt::Display for AssuranceClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// Fail-closed, diagnosable backend failures. None of these carries key
/// material or statement bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendError {
    /// The request violated a contract invariant (for example size).
    InvalidRequest,
    /// The backend cannot currently produce a statement.
    Unavailable,
    /// The backend does not implement the requested operation.
    Unsupported,
    /// The backend is busy; a retry may succeed.
    Busy,
    /// An internal backend condition failed closed.
    Internal,
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => formatter.write_str("attestation request is invalid"),
            Self::Unavailable => formatter.write_str("attestation backend is unavailable"),
            Self::Unsupported => formatter.write_str("attestation backend does not support this"),
            Self::Busy => formatter.write_str("attestation backend is busy"),
            Self::Internal => formatter.write_str("attestation backend failed closed"),
        }
    }
}

impl Error for BackendError {}

/// A quote request: caller-supplied qualifying data (challenge/session
/// binding material) that the backend must bind into its statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteRequest {
    /// Opaque qualifying bytes, 1 to [`MAX_QUALIFYING_DATA_LENGTH`].
    pub qualifying_data: Vec<u8>,
}

impl QuoteRequest {
    /// Validates the request against the seam's bounds.
    pub fn validate(&self) -> Result<(), BackendError> {
        if self.qualifying_data.is_empty()
            || self.qualifying_data.len() > MAX_QUALIFYING_DATA_LENGTH
        {
            return Err(BackendError::InvalidRequest);
        }
        Ok(())
    }
}

/// One attestation statement: candidate input, never authority.
///
/// The payload is opaque and class-defined; the qualifying digest is the
/// backend's binding of the request's qualifying data (each class
/// defines its derivation). Construction enforces shape invariants;
/// correspondence between digest and request is the verifier's check
/// against its own derivation of the same request.
#[derive(Clone, PartialEq, Eq)]
pub struct AttestationStatement {
    assurance_class: AssuranceClass,
    backend_id: String,
    qualifying_digest: [u8; 32],
    quote_payload: Vec<u8>,
}

impl fmt::Debug for AttestationStatement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttestationStatement([PAYLOAD REDACTED])")
    }
}

impl AttestationStatement {
    /// Constructs a statement, enforcing the seam's shape invariants.
    pub fn new(
        assurance_class: AssuranceClass,
        backend_id: &str,
        qualifying_digest: [u8; 32],
        quote_payload: Vec<u8>,
    ) -> Result<Self, BackendError> {
        if backend_id.is_empty() || backend_id.len() > 128 {
            return Err(BackendError::InvalidRequest);
        }
        if quote_payload.is_empty() || quote_payload.len() > MAX_QUOTE_PAYLOAD_LENGTH {
            return Err(BackendError::InvalidRequest);
        }
        Ok(Self {
            assurance_class,
            backend_id: backend_id.to_string(),
            qualifying_digest,
            quote_payload,
        })
    }

    /// The statement's assurance class.
    pub fn assurance_class(&self) -> AssuranceClass {
        self.assurance_class
    }

    /// The labeled backend identifier.
    pub fn backend_id(&self) -> &str {
        &self.backend_id
    }

    /// The backend's binding of the request's qualifying data.
    pub fn qualifying_digest(&self) -> &[u8; 32] {
        &self.qualifying_digest
    }

    /// The opaque, class-defined quote payload.
    pub fn quote_payload(&self) -> &[u8] {
        &self.quote_payload
    }
}

/// The backend-agnostic attestation seam (ADR-0017). Implementations
/// must never expose raw physical-TPM commands through this trait.
pub trait AttestationBackend {
    /// The implementation's assurance class; it labels every statement.
    fn assurance_class(&self) -> AssuranceClass;

    /// A stable, labeled backend identifier (for example
    /// `ogir-mock-attester-v1`).
    fn backend_id(&self) -> &str;

    /// Produces a statement binding the request's qualifying data, or
    /// fails closed with a diagnosable error.
    fn quote(&mut self, request: &QuoteRequest) -> Result<AttestationStatement, BackendError>;
}

/// The class-confusion gate: only exact class equality admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassMismatch {
    /// The class the verifier required.
    pub expected: AssuranceClass,
    /// The class the presented statement carried.
    pub presented: AssuranceClass,
}

impl fmt::Display for ClassMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "assurance class mismatch: expected {}, presented {}",
            self.expected.label(),
            self.presented.label()
        )
    }
}

impl Error for ClassMismatch {}

/// Accepts a presented class against an expected class. Strict
/// equality only: this is the M3 exit criterion's enforcement point.
pub fn accept_class(
    expected: AssuranceClass,
    presented: AssuranceClass,
) -> Result<(), ClassMismatch> {
    if expected == presented {
        Ok(())
    } else {
        Err(ClassMismatch {
            expected,
            presented,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_gate_is_strict_across_every_pairing() {
        let classes = [
            AssuranceClass::Test,
            AssuranceClass::SoftwareTpm,
            AssuranceClass::HardwareFirmwareTpm,
        ];
        for expected in classes {
            for presented in classes {
                let result = accept_class(expected, presented);
                if expected == presented {
                    assert_eq!(result, Ok(()));
                } else {
                    assert_eq!(
                        result,
                        Err(ClassMismatch {
                            expected,
                            presented
                        })
                    );
                }
            }
        }
    }

    #[test]
    fn statement_construction_enforces_shape_invariants() {
        let digest = [7u8; 32];
        assert!(
            AttestationStatement::new(AssuranceClass::Test, "backend.v1", digest, vec![1]).is_ok()
        );
        assert_eq!(
            AttestationStatement::new(AssuranceClass::Test, "", digest, vec![1]).err(),
            Some(BackendError::InvalidRequest)
        );
        assert_eq!(
            AttestationStatement::new(AssuranceClass::Test, "b", digest, vec![]).err(),
            Some(BackendError::InvalidRequest)
        );
        let long_id = "x".repeat(129);
        assert_eq!(
            AttestationStatement::new(AssuranceClass::Test, &long_id, digest, vec![1]).err(),
            Some(BackendError::InvalidRequest)
        );
    }

    #[test]
    fn request_bounds_reject_empty_and_oversized() {
        assert_eq!(
            QuoteRequest {
                qualifying_data: Vec::new()
            }
            .validate()
            .err(),
            Some(BackendError::InvalidRequest)
        );
        assert_eq!(
            QuoteRequest {
                qualifying_data: vec![0; MAX_QUALIFYING_DATA_LENGTH + 1]
            }
            .validate()
            .err(),
            Some(BackendError::InvalidRequest)
        );
        assert!(
            QuoteRequest {
                qualifying_data: vec![1; MAX_QUALIFYING_DATA_LENGTH]
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn debug_redacts_payload_and_labels_are_stable() {
        let statement = AttestationStatement::new(
            AssuranceClass::SoftwareTpm,
            "swtpm.v1",
            [1; 32],
            vec![9; 16],
        )
        .unwrap_or_else(|error| panic!("{error:?}"));
        assert_eq!(
            format!("{statement:?}"),
            "AttestationStatement([PAYLOAD REDACTED])"
        );
        assert_eq!(AssuranceClass::Test.label(), "test");
        assert_eq!(AssuranceClass::SoftwareTpm.label(), "software-tpm");
        assert_eq!(AssuranceClass::HardwareFirmwareTpm.label(), "hardware-ftpm");
    }
}
