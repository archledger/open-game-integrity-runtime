// SPDX-License-Identifier: Apache-2.0

//! End-to-end and adversarial suite for the M2-018 mock verifier and
//! relying party: the five attack categories this slice hosts (patched
//! client, evidence replay, permit replay, expired permit, verifier key
//! mismatch) plus the happy path and denial paths.

use ogir_mock_keys::keys::{MockAttesterKey, MockKeyDirectory, MockSessionKey, MockVerifierKey};
use ogir_mock_protocol::admission::{AdmissionError, MockRelyingParty};
use ogir_mock_protocol::objects::{
    MockChallenge, MockClaim, MockEvidence, Provenance, build_pop, build_signed_challenge,
    build_signed_evidence,
};
use ogir_mock_protocol::policy::{ContextMatchPolicy, MockExpectedContext};
use ogir_mock_protocol::service::{MockVerdict, MockVerifierService};
use ogir_model::{ProtocolVersion, ReasonCode};

const MAX_LIFETIME: u64 = 3600;

fn challenge(issued_at: u64, expires_at: u64) -> MockChallenge {
    MockChallenge {
        version: ProtocolVersion { major: 0, minor: 1 },
        publisher_id: "pub.one".to_string(),
        game_id: "game.one".to_string(),
        build_id: "build.1".to_string(),
        account_scope: "acct.1".to_string(),
        match_id: "match.1".to_string(),
        policy_id: "policy.1".to_string(),
        policy_version: 2,
        nonce: [0x42; 32],
        issued_at,
        expires_at,
        evidence_profile_id: "profile.1".to_string(),
        issuer_key_id: [0; 16],
    }
}

fn evidence(challenge_object: Vec<u8>, handle: [u8; 32]) -> MockEvidence {
    MockEvidence {
        challenge_object,
        evidence_profile_id: "profile.1".to_string(),
        session_key_handle: handle,
        session_key_id: [0; 16],
        collection_authority_contract_id: "authority.1".to_string(),
        epoch_relation: 1,
        collection_sequence: 1,
        collection_start: 20,
        snapshot_freeze_end: 40,
        base_claims: std::array::from_fn(|slot| MockClaim {
            provenance: if slot % 2 == 0 {
                Provenance::HardwareCertified
            } else {
                Provenance::TrustedAgentObserved
            },
            identity: vec![slot as u8 + 1; 4],
        }),
        profile_claims: Vec::new(),
        manifest_identities: vec![9; 8],
        attester_key_id: [0; 16],
    }
}

struct World {
    directory: MockKeyDirectory,
    service: MockVerifierService<ContextMatchPolicy>,
    verifier: MockVerifierKey,
    session: MockSessionKey,
    challenge_bytes: Vec<u8>,
    evidence_bytes: Vec<u8>,
}

fn world() -> World {
    let verifier = MockVerifierKey::from_seed(b"m2-018-verifier");
    let attester = MockAttesterKey::from_seed(b"m2-018-attester");
    let session = MockSessionKey::from_seed(b"m2-018-session");

    let mut directory = MockKeyDirectory::new();
    directory.register_verifier(&verifier);
    directory.register_attester(&attester);
    directory.register_session(&session);

    let policy = ContextMatchPolicy {
        expected: MockExpectedContext {
            publisher_id: "pub.one".to_string(),
            game_id: "game.one".to_string(),
            build_id: "build.1".to_string(),
            account_scope: "acct.1".to_string(),
            match_id: "match.1".to_string(),
            policy_id: "policy.1".to_string(),
            policy_version: 2,
        },
        permit_id: "permit.1".to_string(),
        session_id: "session.1".to_string(),
        lifetime_seconds: 500,
    };
    let service = MockVerifierService::new(
        MockVerifierKey::from_seed(b"m2-018-verifier"),
        policy,
        MAX_LIFETIME,
    )
    .unwrap_or_else(|error| panic!("service construction: {error:?}"));

    let challenge_bytes =
        build_signed_challenge(&challenge(10, 600), &verifier).unwrap_or_else(|e| panic!("{e:?}"));
    let evidence_bytes = build_signed_evidence(
        &evidence(challenge_bytes.clone(), *session.handle_bytes()),
        &attester,
    )
    .unwrap_or_else(|e| panic!("{e:?}"));

    World {
        directory,
        service,
        verifier,
        session,
        challenge_bytes,
        evidence_bytes,
    }
}

#[test]
fn happy_path_issues_a_permit_the_relying_party_admits() {
    let world = world();
    let verdict = world.service.process(
        100,
        &world.challenge_bytes,
        &world.evidence_bytes,
        &world.directory,
    );
    let MockVerdict::Admit {
        permit_bytes,
        permit,
    } = verdict
    else {
        panic!("expected admission, got {verdict:?}");
    };
    assert_eq!(permit.issued_at, 100);
    assert_eq!(permit.expires_at, 600);
    assert_eq!(permit.session_key_handle, *world.session.handle_bytes());

    let mut relying_party = MockRelyingParty::new(world.directory.clone());
    let pop =
        build_pop(&world.session, &permit_bytes, &[0x99; 32]).unwrap_or_else(|e| panic!("{e:?}"));
    let admitted = relying_party
        .admit(200, &permit_bytes, &pop)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(admitted.permit.permit_id, "permit.1");
    assert_eq!(admitted.rechallenge_nonce, [0x99; 32]);
}

#[test]
fn patched_client_success_is_impossible_without_valid_artifacts() {
    // A client that simply claims success has no artifact path: admission
    // requires the verifier-signed permit plus a valid proof. Forged or
    // empty inputs fail deterministically.
    let world = world();
    let verdict = world.service.process(
        100,
        &world.challenge_bytes,
        &world.evidence_bytes,
        &world.directory,
    );
    let MockVerdict::Admit { permit_bytes, .. } = verdict else {
        panic!("expected admission");
    };
    let mut relying_party = MockRelyingParty::new(world.directory.clone());

    // No proof at all.
    assert!(matches!(
        relying_party.admit(200, &permit_bytes, &[]),
        Err(AdmissionError::Transcript(_))
    ));
    // A proof built under the wrong session key.
    let impostor = MockSessionKey::from_seed(b"m2-018-impostor");
    let forged_pop =
        build_pop(&impostor, &permit_bytes, &[0x99; 32]).unwrap_or_else(|e| panic!("{e:?}"));
    assert!(matches!(
        relying_party.admit(200, &permit_bytes, &forged_pop),
        Err(AdmissionError::Transcript(_))
    ));
    // A permit the verifier never signed.
    let mut forged = permit_bytes.clone();
    let last = forged.len() - 1;
    forged[last] ^= 0x01;
    let pop =
        build_pop(&world.session, &permit_bytes, &[0x99; 32]).unwrap_or_else(|e| panic!("{e:?}"));
    assert!(matches!(
        relying_party.admit(200, &forged, &pop),
        Err(AdmissionError::Transcript(_))
    ));
}

#[test]
fn evidence_replay_is_detected_by_the_replay_cache() {
    let world = world();
    let first = world.service.process(
        100,
        &world.challenge_bytes,
        &world.evidence_bytes,
        &world.directory,
    );
    assert!(matches!(first, MockVerdict::Admit { .. }));
    let second = world.service.process(
        101,
        &world.challenge_bytes,
        &world.evidence_bytes,
        &world.directory,
    );
    assert_eq!(
        second,
        MockVerdict::Deny {
            reason: ReasonCode::ReplayDetected
        }
    );
}

#[test]
fn expired_challenge_is_denied_before_replay_state_changes() {
    let world = world();
    let verdict = world.service.process(
        600,
        &world.challenge_bytes,
        &world.evidence_bytes,
        &world.directory,
    );
    assert_eq!(
        verdict,
        MockVerdict::Deny {
            reason: ReasonCode::Expired
        }
    );
    let not_yet = world.service.process(
        5,
        &world.challenge_bytes,
        &world.evidence_bytes,
        &world.directory,
    );
    assert_eq!(
        not_yet,
        MockVerdict::Deny {
            reason: ReasonCode::NotYetValid
        }
    );
}

#[test]
fn permit_replay_at_the_relying_party_is_rejected() {
    let world = world();
    let verdict = world.service.process(
        100,
        &world.challenge_bytes,
        &world.evidence_bytes,
        &world.directory,
    );
    let MockVerdict::Admit { permit_bytes, .. } = verdict else {
        panic!("expected admission");
    };
    let pop =
        build_pop(&world.session, &permit_bytes, &[0x99; 32]).unwrap_or_else(|e| panic!("{e:?}"));
    let mut relying_party = MockRelyingParty::new(world.directory.clone());
    assert!(relying_party.admit(200, &permit_bytes, &pop).is_ok());
    assert_eq!(
        relying_party.admit(201, &permit_bytes, &pop),
        Err(AdmissionError::PermitReplay)
    );
}

#[test]
fn expired_permit_is_rejected_at_admission() {
    let world = world();
    let verdict = world.service.process(
        100,
        &world.challenge_bytes,
        &world.evidence_bytes,
        &world.directory,
    );
    let MockVerdict::Admit {
        permit_bytes,
        permit,
    } = verdict
    else {
        panic!("expected admission");
    };
    assert_eq!(permit.expires_at, 600);
    let pop =
        build_pop(&world.session, &permit_bytes, &[0x99; 32]).unwrap_or_else(|e| panic!("{e:?}"));
    let mut relying_party = MockRelyingParty::new(world.directory.clone());
    assert_eq!(
        relying_party.admit(600, &permit_bytes, &pop),
        Err(AdmissionError::PermitExpired)
    );
    assert_eq!(
        relying_party.admit(700, &permit_bytes, &pop),
        Err(AdmissionError::PermitExpired)
    );
}

#[test]
fn verifier_key_mismatch_is_rejected_by_the_relying_party() {
    let world = world();
    let verdict = world.service.process(
        100,
        &world.challenge_bytes,
        &world.evidence_bytes,
        &world.directory,
    );
    let MockVerdict::Admit { permit_bytes, .. } = verdict else {
        panic!("expected admission");
    };
    // A relying party that trusts a different verifier key set.
    let mut stranger_directory = MockKeyDirectory::new();
    let stranger_key = MockVerifierKey::from_seed(b"m2-018-stranger");
    stranger_directory.register_verifier(&stranger_key);
    stranger_directory.register_session(&world.session);
    let mut relying_party = MockRelyingParty::new(stranger_directory);
    let pop =
        build_pop(&world.session, &permit_bytes, &[0x99; 32]).unwrap_or_else(|e| panic!("{e:?}"));
    assert!(matches!(
        relying_party.admit(200, &permit_bytes, &pop),
        Err(AdmissionError::Transcript(
            ogir_mock_protocol::TranscriptError::UnknownKey
        ))
    ));
}

#[test]
fn unknown_session_key_is_rejected_at_admission() {
    let world = world();
    let verdict = world.service.process(
        100,
        &world.challenge_bytes,
        &world.evidence_bytes,
        &world.directory,
    );
    let MockVerdict::Admit { permit_bytes, .. } = verdict else {
        panic!("expected admission");
    };
    // Directory without the session registered.
    let mut stranger_directory = MockKeyDirectory::new();
    stranger_directory.register_verifier(&world.verifier);
    let mut relying_party = MockRelyingParty::new(stranger_directory);
    let pop =
        build_pop(&world.session, &permit_bytes, &[0x99; 32]).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        relying_party.admit(200, &permit_bytes, &pop),
        Err(AdmissionError::UnknownSession)
    );
}

#[test]
fn evidence_for_a_different_challenge_object_is_denied() {
    let world = world();
    // Evidence whose embedded challenge is not the presented one.
    let other_challenge = build_signed_challenge(&challenge(10, 700), &world.verifier)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let attester = MockAttesterKey::from_seed(b"m2-018-attester");
    let mismatched = build_signed_evidence(
        &evidence(other_challenge, *world.session.handle_bytes()),
        &attester,
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let verdict = world
        .service
        .process(100, &world.challenge_bytes, &mismatched, &world.directory);
    assert_eq!(
        verdict,
        MockVerdict::Deny {
            reason: ReasonCode::ContextBindingMismatch
        }
    );
}

#[test]
fn non_canonical_challenge_text_is_denied_malformed() {
    let world = world();
    let mut raw = challenge(10, 600);
    raw.game_id = "Not Canonical!".to_string();
    let signed = build_signed_challenge(&raw, &world.verifier).unwrap_or_else(|e| panic!("{e:?}"));
    let attester = MockAttesterKey::from_seed(b"m2-018-attester");
    let bytes = build_signed_evidence(
        &evidence(signed.clone(), *world.session.handle_bytes()),
        &attester,
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let verdict = world
        .service
        .process(100, &signed, &bytes, &world.directory);
    assert_eq!(
        verdict,
        MockVerdict::Deny {
            reason: ReasonCode::Malformed
        }
    );
}
