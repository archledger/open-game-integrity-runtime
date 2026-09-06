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

/// The number of length-prefixed payload fields in statement v3.
const PAYLOAD_FIELDS: usize = 5;

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
    /// The RSA signature over the attestation bytes failed verification.
    SignatureInvalid,
    /// The verifier-side TPM context could not be established or used.
    VerifierUnavailable,
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
            Self::SignatureInvalid => {
                formatter.write_str("quote signature failed cryptographic verification")
            }
            Self::VerifierUnavailable => formatter.write_str("verifier-side TPM is unavailable"),
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
    let [a, b, c, d, e] = fields.as_slice() else {
        return Err(ValidationError::MalformedPayload);
    };
    Ok([a, b, c, d, e])
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
    let [echoed, pcr_digest, _signature, ak_modulus, _attest_bytes] =
        payload_fields(statement.quote_payload())?;
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

/// A verifier-side TPM context for cryptographic quote verification
/// (ADR-0020). The verifier loads the ENROLLED public key (never key
/// material from the statement) and asks the TPM to verify the RSA
/// signature over the SHA-256 digest of the marshaled attestation
/// bytes. This closes the copied-public-AK exposure: a forger without
/// the enrolled AK's private key cannot produce a valid signature,
/// even with the modulus and payload fields in hand.
pub struct QuoteVerifier {
    context: tss_esapi::Context,
}

impl std::fmt::Debug for QuoteVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("QuoteVerifier([TPM CONTEXT REDACTED])")
    }
}

impl QuoteVerifier {
    /// Connects to the verifier-side swtpm instance.
    pub fn connect(host: &str, port: u16) -> Result<Self, ValidationError> {
        use std::str::FromStr;
        let config =
            tss_esapi::tcti_ldr::NetworkTPMConfig::from_str(&format!("host={host},port={port}"))
                .map_err(|_| ValidationError::VerifierUnavailable)?;
        let context = tss_esapi::Context::new(tss_esapi::tcti_ldr::TctiNameConf::Swtpm(config))
            .map_err(|_| ValidationError::VerifierUnavailable)?;
        Ok(Self { context })
    }

    fn enrolled_public(modulus: &[u8]) -> Result<tss_esapi::structures::Public, ValidationError> {
        use tss_esapi::attributes::ObjectAttributesBuilder;
        use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
        use tss_esapi::interface_types::key_bits::RsaKeyBits;
        use tss_esapi::structures::{
            HashScheme, PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaScheme,
        };
        let attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(false)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .with_decrypt(false)
            .with_restricted(false)
            .build()
            .map_err(|_| ValidationError::VerifierUnavailable)?;
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_rsa_unique_identifier(
                PublicKeyRsa::try_from(modulus.to_vec())
                    .map_err(|_| ValidationError::MalformedPayload)?,
            )
            .with_object_attributes(attributes)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new()
                    .with_scheme(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256)))
                    .with_key_bits(RsaKeyBits::Rsa2048)
                    .with_exponent(tss_esapi::structures::RsaExponent::default())
                    .with_is_signing_key(true)
                    .with_is_decryption_key(false)
                    .with_restricted(false)
                    .build()
                    .map_err(|_| ValidationError::VerifierUnavailable)?,
            )
            .build()
            .map_err(|_| ValidationError::VerifierUnavailable)
    }

    /// Verifies the statement's RSA signature over the marshaled
    /// attestation bytes against the enrolled modulus.
    pub fn verify_signature(
        &mut self,
        enrolled_modulus: &[u8],
        signature_bytes: &[u8],
        attest_bytes: &[u8],
    ) -> Result<(), ValidationError> {
        use tss_esapi::interface_types::algorithm::HashingAlgorithm;
        use tss_esapi::interface_types::resource_handles::Hierarchy;
        use tss_esapi::structures::{Digest, PublicKeyRsa, RsaSignature, Signature};
        let public = Self::enrolled_public(enrolled_modulus)?;
        let handle = self
            .context
            .load_external_public(public, Hierarchy::Null)
            .map_err(|_| ValidationError::VerifierUnavailable)?;
        let digest_bytes = ogir_attest::sha256::sha256(attest_bytes);
        let digest = Digest::try_from(digest_bytes.to_vec())
            .map_err(|_| ValidationError::MalformedPayload)?;
        let signature = Signature::RsaSsa(
            RsaSignature::create(
                HashingAlgorithm::Sha256,
                PublicKeyRsa::try_from(signature_bytes.to_vec())
                    .map_err(|_| ValidationError::MalformedPayload)?,
            )
            .map_err(|_| ValidationError::MalformedPayload)?,
        );
        let verdict = self.context.verify_signature(handle, digest, signature);
        let _ = self.context.flush_context(handle.into());
        match verdict {
            Ok(_) => Ok(()),
            Err(_) => Err(ValidationError::SignatureInvalid),
        }
    }
}

/// Full validation: semantic checks (as [`validate_quote`]) followed by
/// cryptographic verification of the quote signature against the
/// enrolled AK public key.
pub fn validate_quote_cryptographic(
    registry: &EnrollmentRegistry,
    publisher_scope: &str,
    expected_class: AssuranceClass,
    request: &QuoteRequest,
    statement: &AttestationStatement,
    verifier: &mut QuoteVerifier,
) -> Result<ValidatedQuote, ValidationError> {
    let validated = validate_quote(
        registry,
        publisher_scope,
        expected_class,
        request,
        statement,
    )?;
    let [_echoed, _digest, signature, _modulus, attest_bytes] =
        payload_fields(statement.quote_payload())?;
    verifier.verify_signature(&validated.ak_modulus, signature, attest_bytes)?;
    Ok(validated)
}
