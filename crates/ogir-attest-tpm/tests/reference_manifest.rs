// SPDX-License-Identifier: Apache-2.0

//! The M4-029 reference-manifest suite (ADR-0025). The committed
//! fixtures must satisfy four legs:
//!   1. COHERENCE: the accepted manifest's PCR expectations equal the
//!      replay of the committed M4-028c capture event log (and the
//!      in-guest live read it shipped with) - the reference data is
//!      the measured truth, not an aspiration;
//!   2. ROOT: the manifest's accepted signing root is exactly the
//!      committed TEST-ONLY image key (SHA-256 of its DER bytes);
//!   3. SIGNATURE: the manifest verifies against the verifier-pinned
//!      TEST-ONLY anchor through the TPM-backed verifier; tampered
//!      payloads, tampered signatures, and the wrong anchor all
//!      reject;
//!   4. REVOCATION: the successor fixture (revision 2) is a
//!      non-weakening successor, verifies, and enforces its floors
//!      and revocations with distinguishable reasons.

mod common;

use common::SwtpmInstance;
use ogir_attest::sha256::sha256;
use ogir_attest_tpm::manifest::verify_reference_manifest_signature;
use ogir_attest_tpm::validation::QuoteVerifier;
use ogir_bootlog::BootlogError;
use ogir_bootlog::manifest::parse_manifest;
use ogir_bootlog::parser::parse;
use ogir_bootlog::replay::Replay;

const MANIFEST: &[u8] = include_bytes!("fixtures/manifest/manifest.txt");
const MANIFEST_REVOKED: &[u8] = include_bytes!("fixtures/manifest/manifest-revoked.txt");
const ANCHOR_MODULUS_HEX: &str = include_str!("fixtures/manifest/anchor-modulus.hex");
const IMAGE_KEY_MODULUS_HEX: &str = include_str!("fixtures/manifest/image-key-modulus.hex");
const IMAGE_KEY_DER: &[u8] = include_bytes!("../../../image/keys/test-image-key.der");
const EVENT_LOG: &[u8] = include_bytes!("fixtures/uki-tcg2/event-log.bin");

fn decode_hex(text: &str) -> Vec<u8> {
    let clean: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&clean[i..i + 2], 16).unwrap_or_else(|_| panic!("hex digit at {i}"))
        })
        .collect()
}

fn connected_verifier() -> (SwtpmInstance, QuoteVerifier) {
    let instance = SwtpmInstance::start();
    let verifier =
        QuoteVerifier::connect("127.0.0.1", instance.port()).unwrap_or_else(|e| panic!("{e:?}"));
    (instance, verifier)
}

#[test]
fn accepted_manifest_is_the_measured_truth() {
    let manifest = parse_manifest(MANIFEST).unwrap_or_else(|e| panic!("{e:?}"));

    // Leg 1 - COHERENCE: the pinned expectations equal the replay of
    // the committed capture log for every captured slot.
    let log = parse(EVENT_LOG).unwrap_or_else(|e| panic!("{e:?}"));
    let replay = Replay::sha256(&log).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(manifest.profile.pcr_expectations.len(), 10);
    for index in [0u32, 1, 2, 3, 4, 5, 6, 7, 9, 11] {
        let replayed = replay
            .pcr(index)
            .unwrap_or_else(|| panic!("replayed PCR value for {index}"));
        assert_eq!(
            manifest.profile.pcr_expectations.get(&index),
            Some(replayed),
            "PCR {index} expectation must equal the capture replay"
        );
    }

    // Leg 2 - ROOT: the accepted signing root is the committed image
    // key, by DER fingerprint.
    let fingerprint = sha256(IMAGE_KEY_DER);
    assert!(manifest.accepts_signing_root(&fingerprint));
}

#[test]
fn manifest_signature_verifies_via_tpm() {
    let manifest = parse_manifest(MANIFEST).unwrap_or_else(|e| panic!("{e:?}"));
    let (_instance, mut verifier) = connected_verifier();
    verify_reference_manifest_signature(&mut verifier, &decode_hex(ANCHOR_MODULUS_HEX), &manifest)
        .unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn tampered_payload_rejects() {
    let manifest = parse_manifest(MANIFEST).unwrap_or_else(|e| panic!("{e:?}"));
    let (_instance, mut verifier) = connected_verifier();

    // Same signature, one flipped payload byte (a floor edit).
    let mut forged = manifest.clone();
    forged.payload_bytes[0] ^= 0x01;
    assert!(
        verify_reference_manifest_signature(
            &mut verifier,
            &decode_hex(ANCHOR_MODULUS_HEX),
            &forged,
        )
        .is_err()
    );

    // A structurally valid manifest whose payload was re-signed by
    // the WRONG key (the image key, not the anchor) is exercised in
    // wrong_anchor_rejects below.
}

#[test]
fn tampered_signature_rejects() {
    let mut manifest = parse_manifest(MANIFEST).unwrap_or_else(|e| panic!("{e:?}"));
    manifest.signature[0] ^= 0xFF;
    let (_instance, mut verifier) = connected_verifier();
    assert!(
        verify_reference_manifest_signature(
            &mut verifier,
            &decode_hex(ANCHOR_MODULUS_HEX),
            &manifest,
        )
        .is_err()
    );
}

#[test]
fn wrong_anchor_rejects() {
    // Verifying with the IMAGE key as the anchor: the manifest is
    // signed by the manifest anchor, so this must reject - a pinned
    // anchor that does not match is never accepted.
    let manifest = parse_manifest(MANIFEST).unwrap_or_else(|e| panic!("{e:?}"));
    let (_instance, mut verifier) = connected_verifier();
    assert!(
        verify_reference_manifest_signature(
            &mut verifier,
            &decode_hex(IMAGE_KEY_MODULUS_HEX),
            &manifest,
        )
        .is_err()
    );
}

#[test]
fn revocation_fixture_is_signed_successor_and_enforces() {
    let v1 = parse_manifest(MANIFEST).unwrap_or_else(|e| panic!("{e:?}"));
    let v2 = parse_manifest(MANIFEST_REVOKED).unwrap_or_else(|e| panic!("{e:?}"));

    // The successor relation holds: revision rose, floors rose, the
    // revocation was added, nothing was removed.
    assert!(v1.is_non_weakening_successor(&v2));

    // It is signed by the same anchor.
    let (_instance, mut verifier) = connected_verifier();
    verify_reference_manifest_signature(&mut verifier, &decode_hex(ANCHOR_MODULUS_HEX), &v2)
        .unwrap_or_else(|e| panic!("{e:?}"));

    // Floors and revocations enforce with distinguishable reasons.
    assert_eq!(
        v2.check_component("test-uki", "1"),
        Err(BootlogError::ComponentRevoked)
    );
    assert_eq!(v2.check_component("test-uki", "2"), Ok(()));
    assert_eq!(v2.check_component("capture-uki", "1"), Ok(()));
    assert_eq!(v2.check_component("ovmf-generic", "2026.05"), Ok(()));
    assert_eq!(
        v2.check_component("ovmf-generic", "2026.04"),
        Err(BootlogError::BelowMinimumVersion)
    );
    assert_eq!(
        v2.check_component("undeclared", "1"),
        Err(BootlogError::UnknownComponent)
    );

    // v1 still accepts what v2 revokes: revocation is a manifest
    // revision, not a time travel.
    assert_eq!(v1.check_component("test-uki", "1"), Ok(()));
}
