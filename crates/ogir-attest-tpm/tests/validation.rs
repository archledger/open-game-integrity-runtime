// SPDX-License-Identifier: Apache-2.0

//! Integration suite for ADR-0019 enrollment and semantic validation:
//! real swtpm instances producing real quotes, validated end to end,
//! plus every rejection path.

mod common;

use common::SwtpmInstance;
use ogir_attest::{AssuranceClass, AttestationBackend, AttestationStatement, QuoteRequest};
use ogir_attest_tpm::enrollment::{AkEnrollment, EnrollmentRegistry};
use ogir_attest_tpm::swtpm::SwtpmBackend;
use ogir_attest_tpm::validation::{ValidationError, validate_quote};

const SCOPE: &str = "pub.m3-022";

fn world() -> (
    SwtpmInstance,
    SwtpmBackend,
    EnrollmentRegistry,
    QuoteRequest,
) {
    let instance = SwtpmInstance::start();
    let backend = SwtpmBackend::connect("127.0.0.1", instance.port())
        .unwrap_or_else(|error| panic!("{error:?}"));
    let mut registry = EnrollmentRegistry::new();
    registry
        .enroll(AkEnrollment {
            publisher_scope: SCOPE.to_string(),
            ak_modulus: backend.ak_modulus().to_vec(),
            assurance_class: AssuranceClass::SoftwareTpm,
        })
        .unwrap_or_else(|error| panic!("{error:?}"));
    let request = QuoteRequest {
        qualifying_data: b"m3-022-qualifying".to_vec(),
    };
    (instance, backend, registry, request)
}

#[test]
fn enrolled_real_quote_validates_end_to_end() {
    let (_instance, mut backend, registry, request) = world();
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    let validated = validate_quote(
        &registry,
        SCOPE,
        AssuranceClass::SoftwareTpm,
        &request,
        &statement,
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(validated.assurance_class, AssuranceClass::SoftwareTpm);
    assert_eq!(validated.ak_modulus, backend.ak_modulus());
    assert_eq!(validated.pcr_digest, *statement.qualifying_digest());
}

#[test]
fn unenrolled_publisher_scope_rejects() {
    let (_instance, mut backend, registry, request) = world();
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        validate_quote(
            &registry,
            "pub.stranger",
            AssuranceClass::SoftwareTpm,
            &request,
            &statement
        )
        .err(),
        Some(ValidationError::NotEnrolled)
    );
}

#[test]
fn foreign_ak_statement_rejects() {
    // A second backend (different AK) produces a statement whose
    // modulus is not the one enrolled for the scope.
    let instance = SwtpmInstance::start();
    let mut stranger = SwtpmBackend::connect("127.0.0.1", instance.port())
        .unwrap_or_else(|error| panic!("{error:?}"));
    let (_own_instance, own_backend, registry, request) = world();
    let _ = own_backend;
    let statement = stranger.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        validate_quote(
            &registry,
            SCOPE,
            AssuranceClass::SoftwareTpm,
            &request,
            &statement
        )
        .err(),
        Some(ValidationError::AkMismatch)
    );
}

#[test]
fn wrong_qualifying_data_rejects() {
    let (_instance, mut backend, registry, request) = world();
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    let other = QuoteRequest {
        qualifying_data: b"tampered".to_vec(),
    };
    assert_eq!(
        validate_quote(
            &registry,
            SCOPE,
            AssuranceClass::SoftwareTpm,
            &other,
            &statement
        )
        .err(),
        Some(ValidationError::QualifyingDataMismatch)
    );
}

#[test]
fn class_mismatch_rejects() {
    let (_instance, mut backend, registry, request) = world();
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    assert!(matches!(
        validate_quote(
            &registry,
            SCOPE,
            AssuranceClass::HardwareFirmwareTpm,
            &request,
            &statement
        )
        .err(),
        Some(ValidationError::ClassMismatch(_))
    ));
}

#[test]
fn tampered_payload_and_digest_reject() {
    let (_instance, mut backend, registry, request) = world();
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));

    // Truncate the payload: structure check fails.
    let truncated = AttestationStatement::new(
        statement.assurance_class(),
        statement.backend_id(),
        *statement.qualifying_digest(),
        statement.quote_payload()[..20].to_vec(),
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        validate_quote(
            &registry,
            SCOPE,
            AssuranceClass::SoftwareTpm,
            &request,
            &truncated
        )
        .err(),
        Some(ValidationError::MalformedPayload)
    );

    // A statement whose digest field disagrees with the payload's PCR
    // digest: consistency check fails.
    let payload = statement.quote_payload().to_vec();
    let mutated = AttestationStatement::new(
        statement.assurance_class(),
        statement.backend_id(),
        [0xAA; 32],
        payload,
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        validate_quote(
            &registry,
            SCOPE,
            AssuranceClass::SoftwareTpm,
            &request,
            &mutated
        )
        .err(),
        Some(ValidationError::DigestMismatch)
    );
}

#[test]
fn unknown_backend_rejects() {
    let (_instance, mut backend, registry, request) = world();
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    let foreign = AttestationStatement::new(
        statement.assurance_class(),
        "rogue-backend-v1",
        *statement.qualifying_digest(),
        statement.quote_payload().to_vec(),
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        validate_quote(
            &registry,
            SCOPE,
            AssuranceClass::SoftwareTpm,
            &request,
            &foreign
        )
        .err(),
        Some(ValidationError::UnknownBackend)
    );
}

#[test]
fn enrolled_quote_verifies_cryptographically() {
    use ogir_attest_tpm::validation::{QuoteVerifier, validate_quote_cryptographic};

    let (instance, mut backend, registry, request) = world();
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    let mut verifier =
        QuoteVerifier::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    let validated = validate_quote_cryptographic(
        &registry,
        SCOPE,
        AssuranceClass::SoftwareTpm,
        &request,
        &statement,
        &mut verifier,
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(validated.ak_modulus, backend.ak_modulus());
}

#[test]
fn tampered_attestation_bytes_fail_cryptographic_verification() {
    use ogir_attest_tpm::validation::{QuoteVerifier, validate_quote_cryptographic};

    let (instance, mut backend, registry, request) = world();
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));

    // Flip one bit inside the marshaled attestation bytes (the fifth
    // payload field) and rebuild a well-formed statement: the semantic
    // checks still pass, but the signature no longer covers the bytes.
    let payload = statement.quote_payload();
    let mut fields: Vec<Vec<u8>> = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let length = u32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]) as usize;
        offset += 4;
        fields.push(payload[offset..offset + length].to_vec());
        offset += length;
    }
    let last = fields[4].len() - 1;
    fields[4][last] ^= 0x01;
    let mut forged = Vec::new();
    for field in &fields {
        forged.extend_from_slice(&(field.len() as u32).to_be_bytes());
        forged.extend_from_slice(field);
    }
    let tampered = ogir_attest::AttestationStatement::new(
        statement.assurance_class(),
        statement.backend_id(),
        *statement.qualifying_digest(),
        forged,
    )
    .unwrap_or_else(|e| panic!("{e:?}"));

    let mut verifier =
        QuoteVerifier::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        validate_quote_cryptographic(
            &registry,
            SCOPE,
            AssuranceClass::SoftwareTpm,
            &request,
            &tampered,
            &mut verifier,
        )
        .err(),
        Some(ogir_attest_tpm::validation::ValidationError::SignatureInvalid)
    );
}

#[test]
fn copied_modulus_without_private_key_cannot_forged_verify() {
    // A forger enrolls the victim's modulus under their own scope and
    // crafts payload fields; without the private key, no signature they
    // produce verifies. Modeled by swapping the signature bytes for
    // garbage while keeping the enrolled modulus.
    use ogir_attest_tpm::validation::{QuoteVerifier, validate_quote_cryptographic};

    let (instance, mut backend, registry, request) = world();
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    let payload = statement.quote_payload();
    let mut fields: Vec<Vec<u8>> = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let length = u32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]) as usize;
        offset += 4;
        fields.push(payload[offset..offset + length].to_vec());
        offset += length;
    }
    fields[2] = vec![0x55; 256]; // garbage "signature"
    let mut forged = Vec::new();
    for field in &fields {
        forged.extend_from_slice(&(field.len() as u32).to_be_bytes());
        forged.extend_from_slice(field);
    }
    let tampered = ogir_attest::AttestationStatement::new(
        statement.assurance_class(),
        statement.backend_id(),
        *statement.qualifying_digest(),
        forged,
    )
    .unwrap_or_else(|e| panic!("{e:?}"));

    let mut verifier =
        QuoteVerifier::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        validate_quote_cryptographic(
            &registry,
            SCOPE,
            AssuranceClass::SoftwareTpm,
            &request,
            &tampered,
            &mut verifier,
        )
        .err(),
        Some(ogir_attest_tpm::validation::ValidationError::SignatureInvalid)
    );
}
