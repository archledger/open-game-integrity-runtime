// SPDX-License-Identifier: Apache-2.0

//! Integration suite for the swtpm software-TPM backend (ADR-0018/0019
//! statement contract v2).

mod common;

use common::SwtpmInstance;
use ogir_attest::{AssuranceClass, AttestationBackend, QuoteRequest, accept_class};
use ogir_attest_tpm::swtpm::SwtpmBackend;

fn payload_field(payload: &[u8], index: usize) -> &[u8] {
    let mut offset = 0;
    for current in 0..=index {
        let length = u32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]) as usize;
        offset += 4;
        if current == index {
            return &payload[offset..offset + length];
        }
        offset += length;
    }
    panic!("field {index} not found");
}

#[test]
fn swtpm_backend_produces_real_quotes_bound_to_qualifying_data() {
    let instance = SwtpmInstance::start();
    let mut backend = SwtpmBackend::connect("127.0.0.1", instance.port())
        .unwrap_or_else(|error| panic!("{error:?}"));

    assert_eq!(backend.assurance_class(), AssuranceClass::SoftwareTpm);
    assert_eq!(backend.backend_id(), "swtpm-tpm2-v1");

    let request = QuoteRequest {
        qualifying_data: b"ogir-m3-021-qualifying".to_vec(),
    };
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(statement.assurance_class(), AssuranceClass::SoftwareTpm);
    assert_eq!(statement.backend_id(), "swtpm-tpm2-v1");
    assert_eq!(statement.qualifying_digest().len(), 32);

    assert_eq!(
        payload_field(statement.quote_payload(), 0),
        b"ogir-m3-021-qualifying"
    );
    assert_eq!(
        payload_field(statement.quote_payload(), 1),
        statement.qualifying_digest()
    );
    assert_eq!(payload_field(statement.quote_payload(), 2).len(), 256);
    // Contract v2: the fourth field is the AK modulus, matching the
    // backend's accessor.
    assert_eq!(
        payload_field(statement.quote_payload(), 3),
        backend.ak_modulus()
    );
    assert_eq!(backend.ak_modulus().len(), 256);
}

#[test]
fn different_qualifying_data_changes_the_quote_payload() {
    let instance = SwtpmInstance::start();
    let mut backend = SwtpmBackend::connect("127.0.0.1", instance.port())
        .unwrap_or_else(|error| panic!("{error:?}"));
    let left = backend
        .quote(&QuoteRequest {
            qualifying_data: b"first".to_vec(),
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
    let right = backend
        .quote(&QuoteRequest {
            qualifying_data: b"second".to_vec(),
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_ne!(left.quote_payload(), right.quote_payload());
    assert_eq!(payload_field(left.quote_payload(), 0), b"first");
    assert_eq!(payload_field(right.quote_payload(), 0), b"second");
}

#[test]
fn software_class_statements_are_rejected_under_hardware_expectations() {
    let instance = SwtpmInstance::start();
    let mut backend = SwtpmBackend::connect("127.0.0.1", instance.port())
        .unwrap_or_else(|error| panic!("{error:?}"));
    let statement = backend
        .quote(&QuoteRequest {
            qualifying_data: b"class-check".to_vec(),
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(accept_class(AssuranceClass::SoftwareTpm, statement.assurance_class()).is_ok());
    assert!(
        accept_class(
            AssuranceClass::HardwareFirmwareTpm,
            statement.assurance_class()
        )
        .is_err()
    );
    assert!(accept_class(AssuranceClass::Test, statement.assurance_class()).is_err());
}

#[test]
fn invalid_requests_fail_closed_without_tpm_state() {
    let instance = SwtpmInstance::start();
    let mut backend = SwtpmBackend::connect("127.0.0.1", instance.port())
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(
        backend
            .quote(&QuoteRequest {
                qualifying_data: Vec::new()
            })
            .err(),
        Some(ogir_attest::BackendError::InvalidRequest)
    );
}

#[test]
fn unreachable_instance_fails_closed() {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e:?}"));
    let port = probe
        .local_addr()
        .unwrap_or_else(|e| panic!("{e:?}"))
        .port();
    drop(probe);
    assert!(SwtpmBackend::connect("127.0.0.1", port).is_err());
}
