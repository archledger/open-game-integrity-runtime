// SPDX-License-Identifier: Apache-2.0

//! Verifier-side semantic validation of attestation statements
//! (ADR-0019): strict class gate, backend identity, payload structure,
//! AK enrollment binding, TPM-echoed qualifying-data equality, and
//! digest consistency.
//!
//! Deferred by design: cryptographic verification of the RSA signature
//! over the attestation structure requires the raw marshaled
//! TPMS_ATTEST bytes, and the only available marshaling path
//! (`Tss2_MU_TPMS_ATTEST_Marshal` via tss-esapi-sys) requires `unsafe`,
//! which the workspace forbids outright. Until a reviewed lint-policy
//! decision or a marshaling-safe dependency lands, the signature bytes
//! are carried but not verified, and the copied-public-AK forgery class
//! is NOT covered by this validator. The deferral and its blocker are
//! recorded in ADR-0019 and the roadmap M3-022 boundary.

use ogir_attest::{AssuranceClass, AttestationStatement, QuoteRequest, accept_class};

use crate::enrollment::EnrollmentRegistry;

/// The number of length-prefixed payload fields in statement v2.
const PAYLOAD_FIELDS: usize = 4;

/// Why validation failed. Deterministic and non-disciplinary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// The statement's class did not equal the expected class exactly.
    ClassMismatch(String),
    /// The statement came from an unexpected backend.
    UnknownBackend,
    /// The payload did not have the v2 structure.
    MalformedPayload,
    /// No AK is enrolled for the publisher scope.
    NotEnrolled,
    /// The statement's AK modulus does not match the enrollment.
    AkMismatch,
    /// The echoed qualifying data differs from the request.
    QualifyingDataMismatch,
    /// The statement digest does not match the payload's PCR digest.
    DigestMismatch,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClassMismatch(detail) => write!(formatter, "class mismatch: {detail}"),
            Self::UnknownBackend => formatter.write_str("unknown attestation backend"),
            Self::MalformedPayload => formatter.write_str("malformed statement payload"),
            Self::NotEnrolled => formatter.write_str("publisher scope has no enrolled AK"),
            Self::AkMismatch => formatter.write_str("statement AK does not match enrollment"),
            Self::QualifyingDataMismatch => {
                formatter.write_str("qualifying data does not match the quote echo")
            }
            Self::DigestMismatch => {
                formatter.write_str("statement digest does not match the PCR digest")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// A semantically validated quote, ready for policy (never authority).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedQuote {
    /// The assurance class, exact-matched.
    pub assurance_class: AssuranceClass,
    /// The enrolled AK's public modulus.
    pub ak_modulus: Vec<u8>,
    /// The attested PCR digest carried by the statement.
    pub pcr_digest: [u8; 32],
}

/// Splits a v2 payload into its fields, or fails closed.
fn payload_fields(payload: &[u8]) -> Result<[&[u8]; PAYLOAD_FIELDS], ValidationError> {
    let mut fields: Vec<&[u8]> = Vec::with_capacity(PAYLOAD_FIELDS);
    let mut offset = 0;
    while offset < payload.len() {
        if offset + 4 > payload.len() {
            return Err(ValidationError::MalformedPayload);
        }
        let length = u32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]) as usize;
        offset += 4;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= payload.len())
            .ok_or(ValidationError::MalformedPayload)?;
        fields.push(&payload[offset..end]);
        offset = end;
    }
    if fields.len() != PAYLOAD_FIELDS {
        return Err(ValidationError::MalformedPayload);
    }
    let [a, b, c, d] = fields.as_slice() else {
        return Err(ValidationError::MalformedPayload);
    };
    Ok([a, b, c, d])
}

/// Validates a statement for a publisher scope under an expected
/// assurance class against the enrollment registry and the original
/// request. Fails closed on every mismatch.
pub fn validate_quote(
    registry: &EnrollmentRegistry,
    publisher_scope: &str,
    expected_class: AssuranceClass,
    request: &QuoteRequest,
    statement: &AttestationStatement,
) -> Result<ValidatedQuote, ValidationError> {
    accept_class(expected_class, statement.assurance_class())
        .map_err(|error| ValidationError::ClassMismatch(error.to_string()))?;
    if statement.backend_id() != crate::swtpm::BACKEND_ID {
        return Err(ValidationError::UnknownBackend);
    }
    let [echoed, pcr_digest, _signature, ak_modulus] = payload_fields(statement.quote_payload())?;
    let enrollment = registry
        .find(publisher_scope)
        .ok_or(ValidationError::NotEnrolled)?;
    if enrollment.ak_modulus != ak_modulus {
        return Err(ValidationError::AkMismatch);
    }
    if echoed != request.qualifying_data.as_slice() {
        return Err(ValidationError::QualifyingDataMismatch);
    }
    let digest: [u8; 32] = pcr_digest
        .try_into()
        .map_err(|_| ValidationError::MalformedPayload)?;
    if statement.qualifying_digest() != &digest {
        return Err(ValidationError::DigestMismatch);
    }
    Ok(ValidatedQuote {
        assurance_class: statement.assurance_class(),
        ak_modulus: ak_modulus.to_vec(),
        pcr_digest: digest,
    })
}
