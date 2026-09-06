// SPDX-License-Identifier: Apache-2.0

//! The full M2 attack suite: every roadmap attack-test category executed
//! adversarially against the M2-017/018/019 substrate. Every category
//! returns a deterministic non-allow result.

use ogir_mock_keys::keys::{MockAttesterKey, MockKeyDirectory, MockSessionKey, MockVerifierKey};
use ogir_mock_protocol::admission::MockRelyingParty;
use ogir_mock_protocol::frame::{encode_frame, parse_frame};
use ogir_mock_protocol::objects::{
    MockChallenge, MockClaim, MockEvidence, Provenance, build_pop, build_signed_challenge,
    build_signed_evidence,
};
use ogir_mock_protocol::policy::{ContextMatchPolicy, MockExpectedContext};
use ogir_mock_protocol::service::MockVerdict;
use ogir_mock_protocol::service::MockVerifierService;
use ogir_mock_protocol::transcript::TAG_CHALLENGE;
use ogir_model::{ProtocolVersion, ReasonCode};

struct Suite {
    directory: MockKeyDirectory,
    service: MockVerifierService<ContextMatchPolicy>,
    verifier: MockVerifierKey,
    attester: MockAttesterKey,
    session: MockSessionKey,
    challenge_bytes: Vec<u8>,
    evidence_bytes: Vec<u8>,
    permit_bytes: Vec<u8>,
}

fn base_challenge() -> MockChallenge {
    MockChallenge {
        version: ProtocolVersion { major: 0, minor: 1 },
        publisher_id: "pub.atk".to_string(),
        game_id: "game.atk".to_string(),
        build_id: "build.atk".to_string(),
        account_scope: "acct.atk".to_string(),
        match_id: "match.atk".to_string(),
        policy_id: "policy.atk".to_string(),
        policy_version: 4,
        nonce: [0x7A; 32],
        issued_at: 100,
        expires_at: 900,
        evidence_profile_id: "profile.atk".to_string(),
        issuer_key_id: [0; 16],
    }
}

fn evidence_for(challenge_object: Vec<u8>, handle: [u8; 32]) -> MockEvidence {
    MockEvidence {
        challenge_object,
        evidence_profile_id: "profile.atk".to_string(),
        session_key_handle: handle,
        session_key_id: [0; 16],
        collection_authority_contract_id: "authority.atk".to_string(),
        epoch_relation: 1,
        collection_sequence: 2,
        collection_start: 120,
        snapshot_freeze_end: 160,
        base_claims: std::array::from_fn(|slot| MockClaim {
            provenance: Provenance::TrustedAgentObserved,
            identity: vec![slot as u8 + 1; 2],
        }),
        profile_claims: Vec::new(),
        manifest_identities: vec![0x33; 4],
        attester_key_id: [0; 16],
    }
}

fn suite() -> Suite {
    let verifier = MockVerifierKey::from_seed(b"m2-019-attack-verifier");
    let attester = MockAttesterKey::from_seed(b"m2-019-attack-attester");
    let session = MockSessionKey::from_seed(b"m2-019-attack-session");
    let mut directory = MockKeyDirectory::new();
    directory.register_verifier(&verifier);
    directory.register_attester(&attester);
    directory.register_session(&session);

    let policy = ContextMatchPolicy {
        expected: MockExpectedContext {
            publisher_id: "pub.atk".to_string(),
            game_id: "game.atk".to_string(),
            build_id: "build.atk".to_string(),
            account_scope: "acct.atk".to_string(),
            match_id: "match.atk".to_string(),
            policy_id: "policy.atk".to_string(),
            policy_version: 4,
        },
        permit_id: "permit.atk".to_string(),
        session_id: "session.atk".to_string(),
        lifetime_seconds: 300,
    };
    let service = MockVerifierService::new(
        MockVerifierKey::from_seed(b"m2-019-attack-verifier"),
        policy,
        3_600,
    )
    .unwrap_or_else(|error| panic!("service: {error:?}"));

    let challenge_bytes =
        build_signed_challenge(&base_challenge(), &verifier).unwrap_or_else(|e| panic!("{e:?}"));
    let evidence_bytes = build_signed_evidence(
        &evidence_for(challenge_bytes.clone(), *session.handle_bytes()),
        &attester,
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let verdict = service.process(200, &challenge_bytes, &evidence_bytes, &directory);
    let permit_bytes = match verdict {
        MockVerdict::Admit { permit_bytes, .. } => permit_bytes,
        MockVerdict::Deny { reason } => panic!("setup denied: {reason:?}"),
    };

    Suite {
        directory,
        service,
        verifier,
        attester,
        session,
        challenge_bytes,
        evidence_bytes,
        permit_bytes,
    }
}

fn deny_reason(verdict: MockVerdict) -> ReasonCode {
    match verdict {
        MockVerdict::Deny { reason } => reason,
        MockVerdict::Admit { .. } => panic!("attack unexpectedly allowed"),
    }
}

// 1. Patch client to return success: no artifact path exists.
#[test]
fn attack_patched_client_returns_success() {
    let suite = suite();
    let mut relying_party = MockRelyingParty::new(suite.directory.clone());
    let proof = build_pop(&suite.session, &suite.permit_bytes, &[0x11; 32])
        .unwrap_or_else(|e| panic!("{e:?}"));
    // A "successful" client that submits nothing, garbage, or someone
    // else's artifacts never gains admission.
    assert!(relying_party.admit(300, &[], &[]).is_err());
    assert!(
        relying_party
            .admit(300, b"i am allowed", b"trust me")
            .is_err()
    );
    let impostor = MockSessionKey::from_seed(b"m2-019-impostor");
    let forged =
        build_pop(&impostor, &suite.permit_bytes, &[0x11; 32]).unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        relying_party
            .admit(300, &suite.permit_bytes, &forged)
            .is_err()
    );
    // Only the honest artifacts admit.
    assert!(
        relying_party
            .admit(300, &suite.permit_bytes, &proof)
            .is_ok()
    );
}

// 2. Alter each challenge field: authenticator coverage rejects.
#[test]
fn attack_alter_each_challenge_field() {
    let suite = suite();
    let mut offset = TAG_CHALLENGE.len();
    while offset + 6 <= suite.challenge_bytes.len() - 32 {
        let length = u32::from_be_bytes([
            suite.challenge_bytes[offset + 2],
            suite.challenge_bytes[offset + 3],
            suite.challenge_bytes[offset + 4],
            suite.challenge_bytes[offset + 5],
        ]) as usize;
        let value_start = offset + 6;
        if length > 0 {
            let mut altered = suite.challenge_bytes.clone();
            altered[value_start] ^= 0x01;
            let verdict =
                suite
                    .service
                    .process(200, &altered, &suite.evidence_bytes, &suite.directory);
            assert_eq!(
                deny_reason(verdict),
                ReasonCode::ChallengeAuthenticationFailed
            );
        }
        offset = value_start + length;
    }
}

// 3. Replay evidence: the ADR-0013 cache rejects the second use.
#[test]
fn attack_replay_evidence() {
    let suite = suite();
    let verdict = suite.service.process(
        300,
        &suite.challenge_bytes,
        &suite.evidence_bytes,
        &suite.directory,
    );
    assert_eq!(deny_reason(verdict), ReasonCode::ReplayDetected);
}

// 4. Replay permit: one-use initial admission rejects the second use.
#[test]
fn attack_replay_permit() {
    let suite = suite();
    let proof = build_pop(&suite.session, &suite.permit_bytes, &[0x11; 32])
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut relying_party = MockRelyingParty::new(suite.directory.clone());
    assert!(
        relying_party
            .admit(300, &suite.permit_bytes, &proof)
            .is_ok()
    );
    assert_eq!(
        relying_party.admit(301, &suite.permit_bytes, &proof),
        Err(ogir_mock_protocol::admission::AdmissionError::PermitReplay)
    );
}

// 5. Cross-match, cross-game, cross-account, cross-policy reuse.
#[test]
fn attack_cross_context_reuse() {
    let suite = suite();
    let mut nonce_counter = 0x51u8;
    let mut variants = Vec::new();
    for mutated in [
        MockChallenge {
            match_id: "match.other".to_string(),
            ..base_challenge()
        },
        MockChallenge {
            game_id: "game.other".to_string(),
            ..base_challenge()
        },
        MockChallenge {
            account_scope: "acct.other".to_string(),
            ..base_challenge()
        },
        MockChallenge {
            policy_id: "policy.other".to_string(),
            ..base_challenge()
        },
    ] {
        // Fresh nonce per variant so the replay cache stays silent and the
        // attack lands on the context comparison it targets.
        nonce_counter += 1;
        variants.push(MockChallenge {
            nonce: [nonce_counter; 32],
            ..mutated
        });
    }
    for mutated in variants {
        let bytes =
            build_signed_challenge(&mutated, &suite.verifier).unwrap_or_else(|e| panic!("{e:?}"));
        let evidence = build_signed_evidence(
            &evidence_for(bytes.clone(), *suite.session.handle_bytes()),
            &suite.attester,
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
        let verdict = suite
            .service
            .process(200, &bytes, &evidence, &suite.directory);
        assert_eq!(deny_reason(verdict), ReasonCode::ContextBindingMismatch);
    }
}

// 6. Expired challenge and expired permit.
#[test]
fn attack_expired_challenge_and_permit() {
    let suite = suite();
    let verdict = suite.service.process(
        900,
        &suite.challenge_bytes,
        &suite.evidence_bytes,
        &suite.directory,
    );
    assert_eq!(deny_reason(verdict), ReasonCode::Expired);
    let proof = build_pop(&suite.session, &suite.permit_bytes, &[0x11; 32])
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut relying_party = MockRelyingParty::new(suite.directory.clone());
    assert_eq!(
        relying_party.admit(500, &suite.permit_bytes, &proof),
        Err(ogir_mock_protocol::admission::AdmissionError::PermitExpired)
    );
}

// 7. Unknown critical field: injected record id rejects fail closed.
#[test]
fn attack_unknown_critical_field() {
    let suite = suite();
    let mut forged = suite.challenge_bytes.clone();
    let split = forged.len() - 32;
    let mut injected = forged[..split].to_vec();
    // A record with an unregistered id (0x0064) and empty value appended
    // before the authenticator; the authenticator is now misaligned too,
    // so rejection is guaranteed either as unknown field or bad auth.
    injected.extend_from_slice(&0x0064u16.to_be_bytes());
    injected.extend_from_slice(&0u32.to_be_bytes());
    injected.extend_from_slice(&forged[split..]);
    forged = injected;
    let verdict = suite
        .service
        .process(200, &forged, &suite.evidence_bytes, &suite.directory);
    assert_eq!(deny_reason(verdict), ReasonCode::Malformed);
}

// 8. Oversized and truncated messages: frame and record bounds reject.
#[test]
fn attack_oversized_and_truncated_messages() {
    let suite = suite();
    let version = ProtocolVersion { major: 0, minor: 1 };
    // Oversized payload is refused at the frame layer.
    let huge = vec![0u8; 1024 * 1024 + 1];
    assert!(encode_frame(version, ogir_protocol::MessageKind::MockPermit, &huge).is_err());
    // Truncated object bytes reject at the service.
    let truncated = &suite.challenge_bytes[..suite.challenge_bytes.len() - 1];
    let verdict = suite
        .service
        .process(200, truncated, &suite.evidence_bytes, &suite.directory);
    assert_eq!(deny_reason(verdict), ReasonCode::Malformed);
    // Truncated frame rejects at the frame layer.
    let framed = encode_frame(
        version,
        ogir_protocol::MessageKind::MockChallenge,
        &suite.challenge_bytes,
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(parse_frame(&framed[..framed.len() - 1]).is_err());
}

// 9. Duplicate security-critical field: repeated record id rejects.
#[test]
fn attack_duplicate_security_critical_field() {
    let suite = suite();
    let mut bytes = suite.challenge_bytes.clone();
    let split = bytes.len() - 32;
    // Duplicate the first record (id 0x0001, 6 + 2 bytes) after the tag,
    // breaking canonical order; rejection is guaranteed as duplicate,
    // out-of-order, or authentication failure.
    let tag = TAG_CHALLENGE.len();
    let record: Vec<u8> = bytes[tag..tag + 8].to_vec();
    let mut forged = bytes[..split].to_vec();
    let mut spliced = forged[..tag + 8].to_vec();
    spliced.extend_from_slice(&record);
    spliced.extend_from_slice(&forged[tag + 8..]);
    forged = spliced;
    forged.extend_from_slice(&bytes[split..]);
    bytes = forged;
    let verdict = suite
        .service
        .process(200, &bytes, &suite.evidence_bytes, &suite.directory);
    assert_eq!(deny_reason(verdict), ReasonCode::Malformed);
}

// 10. Protocol downgrade: unknown kind rejects before payload parse.
#[test]
fn attack_protocol_downgrade() {
    let suite = suite();
    let version = ProtocolVersion { major: 0, minor: 1 };
    let mut framed = encode_frame(
        version,
        ogir_protocol::MessageKind::MockChallenge,
        &suite.challenge_bytes,
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    for kind in [9u16, 64, 0xFFFF] {
        framed[8] = (kind >> 8) as u8;
        framed[9] = (kind & 0xFF) as u8;
        assert!(parse_frame(&framed).is_err());
    }
}

// 11. Verifier key mismatch: stranger trust view rejects the permit.
#[test]
fn attack_verifier_key_mismatch() {
    let suite = suite();
    let mut stranger = MockKeyDirectory::new();
    stranger.register_verifier(&MockVerifierKey::from_seed(b"m2-019-stranger"));
    stranger.register_session(&suite.session);
    let mut relying_party = MockRelyingParty::new(stranger);
    let proof = build_pop(&suite.session, &suite.permit_bytes, &[0x11; 32])
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(matches!(
        relying_party.admit(300, &suite.permit_bytes, &proof),
        Err(ogir_mock_protocol::admission::AdmissionError::Transcript(
            ogir_mock_protocol::TranscriptError::UnknownKey
        ))
    ));
}

// 12. Session-key mismatch: proof under the wrong key rejects.
#[test]
fn attack_session_key_mismatch() {
    let suite = suite();
    let wrong = MockSessionKey::from_seed(b"m2-019-wrong-session");
    let proof =
        build_pop(&wrong, &suite.permit_bytes, &[0x11; 32]).unwrap_or_else(|e| panic!("{e:?}"));
    let mut relying_party = MockRelyingParty::new(suite.directory.clone());
    assert!(
        relying_party
            .admit(300, &suite.permit_bytes, &proof)
            .is_err()
    );
}
