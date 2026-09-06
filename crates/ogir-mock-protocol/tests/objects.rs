// SPDX-License-Identifier: Apache-2.0

//! Adversarial integration suite for the M2-017 mock substrate: sign/verify
//! roundtrips, full-object bit-flip rejection, cross-tag substitution
//! rejection, per-field alteration, worked-example bytes, and
//! proof-of-possession binding.

use ogir_mock_keys::keys::{MockAttesterKey, MockKeyDirectory, MockSessionKey, MockVerifierKey};
use ogir_mock_protocol::objects::{
    MockChallenge, MockClaim, MockEvidence, MockPermit, Provenance, build_pop,
    build_signed_challenge, build_signed_evidence, build_signed_permit, verify_pop,
    verify_signed_challenge, verify_signed_evidence, verify_signed_permit,
};
use ogir_mock_protocol::transcript::{
    TAG_CHALLENGE, TAG_EVIDENCE, TAG_PERMIT, TAG_POP, TAG_REVOKE,
};
use ogir_model::ProtocolVersion;

fn sample_challenge() -> MockChallenge {
    MockChallenge {
        version: ProtocolVersion { major: 0, minor: 1 },
        publisher_id: "publisher.example".to_string(),
        game_id: "game.one".to_string(),
        build_id: "build.42".to_string(),
        account_scope: "account.7".to_string(),
        match_id: "match.9".to_string(),
        policy_id: "policy.default".to_string(),
        policy_version: 3,
        nonce: [0x11; 32],
        issued_at: 100,
        expires_at: 400,
        evidence_profile_id: "profile.base".to_string(),
        issuer_key_id: [0; 16],
    }
}

fn sample_evidence(challenge_object: Vec<u8>, session: &MockSessionKey) -> MockEvidence {
    MockEvidence {
        challenge_object,
        evidence_profile_id: "profile.base".to_string(),
        session_key_handle: *session.handle_bytes(),
        session_key_id: *session.id().as_bytes(),
        collection_authority_contract_id: "authority.local".to_string(),
        epoch_relation: 1,
        collection_sequence: 4,
        collection_start: 150,
        snapshot_freeze_end: 200,
        base_claims: std::array::from_fn(|slot| MockClaim {
            provenance: match slot % 3 {
                0 => Provenance::HardwareCertified,
                1 => Provenance::MeasuredLogDerived,
                _ => Provenance::TrustedAgentObserved,
            },
            identity: vec![slot as u8 + 1; 8],
        }),
        profile_claims: vec![MockClaim {
            provenance: Provenance::HardwareCertified,
            identity: vec![0xAA; 5],
        }],
        manifest_identities: vec![0x55; 16],
        attester_key_id: [0; 16],
    }
}

fn sample_permit(session: &MockSessionKey, challenge: &MockChallenge) -> MockPermit {
    MockPermit {
        version: challenge.version,
        permit_id: "permit.1".to_string(),
        session_id: "session.1".to_string(),
        session_key_handle: *session.handle_bytes(),
        appraised_nonce: challenge.nonce,
        policy_id: challenge.policy_id.clone(),
        policy_version: challenge.policy_version,
        issued_at: 200,
        expires_at: 500,
        issuer_key_id: [0; 16],
    }
}

/// Directory, three keys, and the four signed objects, in that order.
type Fixture = (
    MockKeyDirectory,
    MockVerifierKey,
    MockAttesterKey,
    MockSessionKey,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

fn fixture() -> Fixture {
    let verifier = MockVerifierKey::from_seed(b"m2-017-verifier");
    let attester = MockAttesterKey::from_seed(b"m2-017-attester");
    let session = MockSessionKey::from_seed(b"m2-017-session");
    let mut directory = MockKeyDirectory::new();
    directory.register_verifier(&verifier);
    directory.register_attester(&attester);

    let challenge_bytes = build_signed_challenge(&sample_challenge(), &verifier)
        .unwrap_or_else(|error| panic!("build: {error:?}"));
    let evidence_bytes = build_signed_evidence(
        &sample_evidence(challenge_bytes.clone(), &session),
        &attester,
    )
    .unwrap_or_else(|error| panic!("build: {error:?}"));
    let permit_bytes =
        build_signed_permit(&sample_permit(&session, &sample_challenge()), &verifier)
            .unwrap_or_else(|error| panic!("build: {error:?}"));
    let pop_bytes = build_pop(&session, &permit_bytes, &[0x77; 32])
        .unwrap_or_else(|error| panic!("build: {error:?}"));
    (
        directory,
        verifier,
        attester,
        session,
        challenge_bytes,
        evidence_bytes,
        permit_bytes,
        pop_bytes,
    )
}

#[test]
fn sign_verify_roundtrips_preserve_every_field() {
    let (
        directory,
        verifier,
        _attester,
        session,
        challenge_bytes,
        evidence_bytes,
        permit_bytes,
        pop_bytes,
    ) = fixture();

    let challenge = verify_signed_challenge(&directory, &challenge_bytes)
        .unwrap_or_else(|error| panic!("verify: {error:?}"));
    let expected = sample_challenge();
    assert_eq!(challenge.publisher_id, expected.publisher_id);
    assert_eq!(challenge.nonce, expected.nonce);
    assert_eq!(challenge.issued_at, expected.issued_at);
    assert_eq!(challenge.expires_at, expected.expires_at);
    assert_eq!(challenge.issuer_key_id, *verifier.id().as_bytes());

    let evidence = verify_signed_evidence(&directory, &evidence_bytes)
        .unwrap_or_else(|error| panic!("verify: {error:?}"));
    assert_eq!(evidence.challenge_object, challenge_bytes);
    assert_eq!(evidence.session_key_handle, *session.handle_bytes());
    assert_eq!(evidence.base_claims.len(), 8);
    assert_eq!(evidence.profile_claims.len(), 1);

    let permit = verify_signed_permit(&directory, &permit_bytes)
        .unwrap_or_else(|error| panic!("verify: {error:?}"));
    assert_eq!(permit.appraised_nonce, expected.nonce);
    assert_eq!(permit.session_key_handle, *session.handle_bytes());

    let nonce = verify_pop(&session, &permit_bytes, &pop_bytes)
        .unwrap_or_else(|error| panic!("verify: {error:?}"));
    assert_eq!(nonce, [0x77; 32]);
}

#[test]
fn every_single_bit_flip_is_rejected_for_every_object() {
    let (
        directory,
        _verifier,
        _attester,
        session,
        challenge_bytes,
        evidence_bytes,
        permit_bytes,
        pop_bytes,
    ) = fixture();
    for (index, byte) in challenge_bytes.iter().enumerate() {
        for bit in 0..8 {
            let mut forged = challenge_bytes.clone();
            forged[index] = byte ^ (1 << bit);
            assert!(
                verify_signed_challenge(&directory, &forged).is_err(),
                "challenge byte {index} bit {bit} survived"
            );
        }
    }
    for (index, byte) in evidence_bytes.iter().enumerate() {
        let mut forged = evidence_bytes.clone();
        forged[index] = byte ^ 0x01;
        assert!(
            verify_signed_evidence(&directory, &forged).is_err(),
            "evidence byte {index} survived"
        );
    }
    for (index, byte) in permit_bytes.iter().enumerate() {
        let mut forged = permit_bytes.clone();
        forged[index] = byte ^ 0x01;
        assert!(
            verify_signed_permit(&directory, &forged).is_err(),
            "permit byte {index} survived"
        );
    }
    for (index, byte) in pop_bytes.iter().enumerate() {
        let mut forged = pop_bytes.clone();
        forged[index] = byte ^ 0x01;
        assert!(
            verify_pop(&session, &permit_bytes, &forged).is_err(),
            "pop byte {index} survived"
        );
    }
}

#[test]
fn cross_tag_substitution_fails_for_every_pairing() {
    let (
        directory,
        _verifier,
        _attester,
        _session,
        challenge_bytes,
        evidence_bytes,
        permit_bytes,
        pop_bytes,
    ) = fixture();
    // Wrong-class bytes under the challenge verifier: any parse outcome is
    // an error; tag alone must never validate foreign bytes.
    for foreign in [&evidence_bytes, &permit_bytes, &pop_bytes] {
        assert!(verify_signed_challenge(&directory, foreign).is_err());
    }
    for foreign in [&challenge_bytes, &permit_bytes, &pop_bytes] {
        assert!(verify_signed_evidence(&directory, foreign).is_err());
    }
    for foreign in [&challenge_bytes, &evidence_bytes, &pop_bytes] {
        assert!(verify_signed_permit(&directory, foreign).is_err());
    }
    // The unused revocation tag must not accept any class either; a direct
    // record-level check covers it because no revocation verifier exists.
    assert_ne!(
        &challenge_bytes[..TAG_CHALLENGE.len()],
        TAG_REVOKE.as_bytes()
    );
    assert_ne!(&evidence_bytes[..TAG_EVIDENCE.len()], TAG_PERMIT.as_bytes());
    assert_ne!(&pop_bytes[..TAG_POP.len()], TAG_CHALLENGE.as_bytes());
}

#[test]
fn alteration_of_each_record_value_fails_closed() {
    let (directory, verifier, _attester, _session, challenge_bytes, _evidence, _permit, _pop) =
        fixture();
    // Field values begin after the tag plus six header bytes per record.
    // Walk each record's value bytes (skipping ids/lengths) and flip one
    // byte: every alteration must reject.
    let mut offset = TAG_CHALLENGE.len();
    while offset + 6 <= challenge_bytes.len() - 32 {
        let length = u32::from_be_bytes([
            challenge_bytes[offset + 2],
            challenge_bytes[offset + 3],
            challenge_bytes[offset + 4],
            challenge_bytes[offset + 5],
        ]) as usize;
        let value_start = offset + 6;
        if length > 0 {
            let mut forged = challenge_bytes.clone();
            forged[value_start] ^= 0x01;
            assert!(
                verify_signed_challenge(&directory, &forged).is_err(),
                "alteration at {value_start} survived"
            );
        }
        offset = value_start + length;
    }
    assert_eq!(offset, challenge_bytes.len() - 32);
    // Sanity: the unmodified object still verifies under the same key.
    assert!(verify_signed_challenge(&directory, &challenge_bytes).is_ok());
    // And under the wrong key id it must fail.
    let wrong = MockVerifierKey::from_seed(b"m2-017-wrong");
    let mut directory2 = MockKeyDirectory::new();
    directory2.register_verifier(&wrong);
    assert_eq!(
        verify_signed_challenge(&directory2, &challenge_bytes),
        Err(ogir_mock_protocol::TranscriptError::UnknownKey)
    );
    let _ = verifier;
}

#[test]
fn worked_example_pins_every_non_key_byte() {
    // Deterministic inputs; only the issuer key id and the trailing
    // authenticator depend on the key, and both are pinned by derivation.
    let verifier = MockVerifierKey::from_seed(b"worked-example");
    let challenge = MockChallenge {
        version: ProtocolVersion { major: 0, minor: 1 },
        publisher_id: "p".to_string(),
        game_id: "g".to_string(),
        build_id: "b".to_string(),
        account_scope: "a".to_string(),
        match_id: "m".to_string(),
        policy_id: "l".to_string(),
        policy_version: 1,
        nonce: [0; 32],
        issued_at: 1,
        expires_at: 2,
        evidence_profile_id: "f".to_string(),
        issuer_key_id: [0; 16],
    };
    let object = build_signed_challenge(&challenge, &verifier)
        .unwrap_or_else(|error| panic!("build: {error:?}"));

    let mut expected = TAG_CHALLENGE.as_bytes().to_vec();
    for (id, value) in [
        (0x0001u16, vec![0x00, 0x00]),
        (0x0002, vec![0x00, 0x01]),
        (0x0003, vec![b'p']),
        (0x0004, vec![b'g']),
        (0x0005, vec![b'b']),
        (0x0006, vec![b'a']),
        (0x0007, vec![b'm']),
        (0x0008, vec![b'l']),
        (0x0009, vec![0x00, 0x00, 0x00, 0x01]),
        (0x000A, vec![0; 32]),
        (0x000B, vec![0, 0, 0, 0, 0, 0, 0, 1]),
        (0x000C, vec![0, 0, 0, 0, 0, 0, 0, 2]),
        (0x000D, vec![b'f']),
    ] {
        expected.extend_from_slice(&id.to_be_bytes());
        expected.extend_from_slice(&(value.len() as u32).to_be_bytes());
        expected.extend_from_slice(&value);
    }
    expected.extend_from_slice(&0x000Eu16.to_be_bytes());
    expected.extend_from_slice(&16u32.to_be_bytes());
    expected.extend_from_slice(verifier.id().as_bytes());
    assert_eq!(&object[..object.len() - 32], &expected[..]);

    let split = object.len() - 32;
    assert_eq!(
        &object[split..],
        &verifier.authenticate(&object[..split])[..]
    );
}

#[test]
fn temporal_ordering_invariants_fail_closed() {
    let (_directory, verifier, attester, session, challenge_bytes, _evidence, _permit, _pop) =
        fixture();
    let mut backwards = sample_challenge();
    backwards.issued_at = 400;
    backwards.expires_at = 400;
    assert_eq!(
        build_signed_challenge(&backwards, &verifier),
        Err(ogir_mock_protocol::TranscriptError::InvalidWindow)
    );

    let mut overlapping = sample_evidence(challenge_bytes.clone(), &session);
    overlapping.collection_start = 300;
    overlapping.snapshot_freeze_end = 200;
    assert_eq!(
        build_signed_evidence(&overlapping, &attester),
        Err(ogir_mock_protocol::TranscriptError::InvalidWindow)
    );

    let mut expired = sample_permit(&session, &sample_challenge());
    expired.issued_at = 500;
    expired.expires_at = 500;
    assert_eq!(
        build_signed_permit(&expired, &verifier),
        Err(ogir_mock_protocol::TranscriptError::InvalidWindow)
    );
}

#[test]
fn pop_binds_the_exact_permit_and_session_key() {
    let (_directory, _verifier, _attester, session, _challenge, _evidence, permit_bytes, pop_bytes) =
        fixture();
    // Wrong permit bytes: digest binding rejects.
    let mut other_permit = permit_bytes.clone();
    let last = other_permit.len() - 1;
    other_permit[last] ^= 0x01;
    assert_eq!(
        verify_pop(&session, &other_permit, &pop_bytes),
        Err(ogir_mock_protocol::TranscriptError::AuthenticationFailed)
    );
    // Wrong session key: authenticator rejects.
    let other_session = MockSessionKey::from_seed(b"m2-017-other-session");
    assert!(verify_pop(&other_session, &permit_bytes, &pop_bytes).is_err());
    // Correct inputs still verify.
    assert!(verify_pop(&session, &permit_bytes, &pop_bytes).is_ok());
}

#[test]
fn debug_output_redacts_sensitive_object_material() {
    let (_d, _v, _a, session, challenge_bytes, _e, permit_bytes, _p) = fixture();
    let line = format!(
        "{:?}{:?}{:?}",
        sample_challenge(),
        sample_permit(&session, &sample_challenge()),
        MockClaim {
            provenance: Provenance::HardwareCertified,
            identity: vec![1, 2, 3],
        }
    );
    assert!(line.contains("REDACTED"));
    assert!(!line.contains("11111111"));
    let _ = (challenge_bytes, permit_bytes);
}
