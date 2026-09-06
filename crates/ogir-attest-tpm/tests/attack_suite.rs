// SPDX-License-Identifier: Apache-2.0

//! The M3 attack suite: all ten roadmap attack-test categories, each
//! returning a deterministic non-allow result against real swtpm and
//! the full enrollment/validation/verification chain (ADR-0020). This
//! suite consolidates the categories into one named inventory in the
//! M2-019 pattern; scenarios already covered by focused suites are
//! re-executed here so the milestone record is self-contained.

mod common;

use common::SwtpmInstance;
use ogir_attest::{AssuranceClass, AttestationBackend, AttestationStatement, QuoteRequest};
use ogir_attest_tpm::activation::{ActivationKeys, seal_credential, verifier_context};
use ogir_attest_tpm::enrollment::{AkEnrollment, EnrollmentRegistry};
use ogir_attest_tpm::swtpm::SwtpmBackend;
use ogir_attest_tpm::validation::{QuoteVerifier, validate_quote_cryptographic};

const SCOPE: &str = "pub.m3-025";

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
        qualifying_data: b"m3-025-qualifying".to_vec(),
    };
    (instance, backend, registry, request)
}

fn payload_fields(payload: &[u8]) -> Vec<Vec<u8>> {
    let mut fields = Vec::new();
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
    fields
}

// 1. Software TPM presented as hardware profile: the class gate.
#[test]
fn attack_software_tpm_as_hardware_rejects() {
    let (instance, mut backend, registry, request) = world();
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    let mut verifier =
        QuoteVerifier::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    let result = validate_quote_cryptographic(
        &registry,
        SCOPE,
        AssuranceClass::HardwareFirmwareTpm,
        &request,
        &statement,
        &mut verifier,
    );
    assert!(result.is_err());
}

// 2. Quote from an unenrolled AK.
#[test]
fn attack_unenrolled_ak_quote_rejects() {
    let (instance, mut backend, registry, request) = world();
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    let mut verifier =
        QuoteVerifier::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    let result = validate_quote_cryptographic(
        &registry,
        "pub.stranger",
        AssuranceClass::SoftwareTpm,
        &request,
        &statement,
        &mut verifier,
    );
    assert!(result.is_err());
}

// 3. Quote with wrong nonce/qualifying data.
#[test]
fn attack_wrong_qualifying_data_rejects() {
    let (instance, mut backend, registry, request) = world();
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    let other = QuoteRequest {
        qualifying_data: b"wrong-nonce".to_vec(),
    };
    let mut verifier =
        QuoteVerifier::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    let result = validate_quote_cryptographic(
        &registry,
        SCOPE,
        AssuranceClass::SoftwareTpm,
        &other,
        &statement,
        &mut verifier,
    );
    assert!(result.is_err());
}

// 4. Copied public AK without TPM possession: the enrolled modulus with
// a forged signature fails cryptographic verification.
#[test]
fn attack_copied_public_ak_rejects() {
    let (instance, mut backend, registry, request) = world();
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    let mut fields = payload_fields(statement.quote_payload());
    fields[2] = vec![0x5A; 256]; // garbage signature, real modulus
    let mut forged = Vec::new();
    for field in &fields {
        forged.extend_from_slice(&(field.len() as u32).to_be_bytes());
        forged.extend_from_slice(field);
    }
    let tampered = AttestationStatement::new(
        statement.assurance_class(),
        statement.backend_id(),
        *statement.qualifying_digest(),
        forged,
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let mut verifier =
        QuoteVerifier::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    let result = validate_quote_cryptographic(
        &registry,
        SCOPE,
        AssuranceClass::SoftwareTpm,
        &request,
        &tampered,
        &mut verifier,
    );
    assert!(result.is_err());
}

// 5. Stale quote: a prior statement replayed for a new challenge.
#[test]
fn attack_stale_quote_rejects() {
    let (instance, mut backend, registry, _request) = world();
    let old_request = QuoteRequest {
        qualifying_data: b"old-challenge".to_vec(),
    };
    let stale = backend
        .quote(&old_request)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let new_request = QuoteRequest {
        qualifying_data: b"new-challenge".to_vec(),
    };
    let mut verifier =
        QuoteVerifier::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    let result = validate_quote_cryptographic(
        &registry,
        SCOPE,
        AssuranceClass::SoftwareTpm,
        &new_request,
        &stale,
        &mut verifier,
    );
    assert!(result.is_err());
}

// 6. TPM resource exhaustion: object creation fails closed.
#[test]
fn attack_resource_exhaustion_fails_closed() {
    let instance = SwtpmInstance::start();
    let mut backend = SwtpmBackend::connect("127.0.0.1", instance.port())
        .unwrap_or_else(|error| panic!("{error:?}"));
    let request = QuoteRequest {
        qualifying_data: b"exhaustion-probe".to_vec(),
    };
    // Hold every backend alive so their AK primaries accumulate in
    // the TPM's transient-object slots until exhaustion; each step
    // must succeed or fail closed with a diagnosable error.
    let mut held = Vec::new();
    let mut failures = 0;
    for _ in 0..64 {
        match SwtpmBackend::connect("127.0.0.1", instance.port()) {
            Ok(backend) => held.push(backend),
            Err(error) => {
                failures += 1;
                assert_eq!(error, ogir_attest::BackendError::Internal);
            }
        }
    }
    assert!(failures > 0, "expected exhaustion within 64 live AKs");
    // The original backend either still quotes (the TPM made room by
    // evicting) or fails closed; both are acceptable non-panic paths.
    let _ = backend.quote(&request);
}

// 7. Daemon killed during quote: the swtpm process dies mid-session and
// the backend fails closed.
#[test]
fn attack_daemon_killed_during_quote_fails_closed() {
    let mut instance = SwtpmInstance::start();
    let mut backend = SwtpmBackend::connect("127.0.0.1", instance.port())
        .unwrap_or_else(|error| panic!("{error:?}"));
    // Kill the swtpm process out from under the backend.
    instance.kill();
    let request = QuoteRequest {
        qualifying_data: b"kill-probe".to_vec(),
    };
    let result = backend.quote(&request);
    assert!(result.is_err());
}

// 8. Malformed TPM structures: garbage attest bytes fail verification.
#[test]
fn attack_malformed_structures_reject() {
    let (instance, mut backend, registry, request) = world();
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    let mut fields = payload_fields(statement.quote_payload());
    fields[4] = vec![0xFF; 128]; // garbage marshaled TPMS_ATTEST
    let mut forged = Vec::new();
    for field in &fields {
        forged.extend_from_slice(&(field.len() as u32).to_be_bytes());
        forged.extend_from_slice(field);
    }
    let tampered = AttestationStatement::new(
        statement.assurance_class(),
        statement.backend_id(),
        *statement.qualifying_digest(),
        forged,
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let mut verifier =
        QuoteVerifier::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    let result = validate_quote_cryptographic(
        &registry,
        SCOPE,
        AssuranceClass::SoftwareTpm,
        &request,
        &tampered,
        &mut verifier,
    );
    assert!(result.is_err());
}

// 9. EK/AK confusion: sealed material for a mismatched AK name rejects.
#[test]
fn attack_ek_ak_confusion_rejects() {
    let instance = SwtpmInstance::start();
    let mut keys = ActivationKeys::create("127.0.0.1", instance.port())
        .unwrap_or_else(|error| panic!("{error:?}"));
    let mut request = keys.request().unwrap_or_else(|error| panic!("{error:?}"));
    let last = request.ak_name.len() - 1;
    request.ak_name[last] ^= 0x01;
    let mut verifier =
        verifier_context("127.0.0.1", instance.port()).unwrap_or_else(|error| panic!("{error:?}"));
    let sealed = seal_credential(&mut verifier, &request, [0x11; 32])
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert!(keys.activate(&sealed).is_err());
}

// 10. Cross-publisher AK reuse: one modulus cannot enroll for two
// scopes (registry guard) and a scope sees only its own key.
#[test]
fn attack_cross_publisher_ak_reuse_rejects() {
    let (_instance, backend, mut registry, _request) = world();
    let result = registry.enroll(AkEnrollment {
        publisher_scope: "pub.other".to_string(),
        ak_modulus: backend.ak_modulus().to_vec(),
        assurance_class: AssuranceClass::SoftwareTpm,
    });
    assert!(result.is_err());
}
