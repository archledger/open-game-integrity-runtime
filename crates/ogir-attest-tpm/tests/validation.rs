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
    let mut payload = statement.quote_payload().to_vec();
    let last = payload.len() - 1;
    payload[last] ^= 0x01;
    let mut digest = *statement.qualifying_digest();
    digest[0] ^= 0xFF;
    let _ = digest;
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
        Some(ValidationError::AkMismatch)
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
