// SPDX-License-Identifier: Apache-2.0

//! M2 CLI demonstration of the mock attestation protocol.
//!
//! Runs the full flow deterministically from fixed seeds: signed
//! challenge, signed evidence, replay-fenced appraisal, permit issuance,
//! frame-wrapped transport, proof of possession, and relying-party
//! admission, then a fenced renewal. The demonstration never returns a
//! trusted local boolean: every admission decision comes from the
//! relying party validating signed artifacts, and the client side exposes
//! no "am I allowed" call at all. All sensitive values print as digests
//! or redacted markers only.

use ogir_mock_keys::keys::{MockAttesterKey, MockKeyDirectory, MockSessionKey, MockVerifierKey};
use ogir_mock_keys::sha256::sha256;
use ogir_mock_protocol::admission::MockRelyingParty;
use ogir_mock_protocol::frame::{encode_frame, parse_frame};
use ogir_mock_protocol::objects::{
    MockChallenge, MockClaim, MockEvidence, Provenance, build_pop, build_signed_challenge,
    build_signed_evidence,
};
use ogir_mock_protocol::policy::{ContextMatchPolicy, MockExpectedContext};
use ogir_mock_protocol::renewal::{InstallOutcome, MockSessionOwner};
use ogir_mock_protocol::service::MockVerdict;
use ogir_mock_protocol::service::MockVerifierService;
use ogir_protocol::MessageKind;

fn short_digest(bytes: &[u8]) -> String {
    let digest = sha256(bytes);
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn challenge() -> MockChallenge {
    MockChallenge {
        version: ogir_model::ProtocolVersion { major: 0, minor: 1 },
        publisher_id: "pub.demo".to_string(),
        game_id: "game.demo".to_string(),
        build_id: "build.demo".to_string(),
        account_scope: "acct.demo".to_string(),
        match_id: "match.demo".to_string(),
        policy_id: "policy.demo".to_string(),
        policy_version: 1,
        nonce: [0xD1; 32],
        issued_at: 1_000,
        expires_at: 1_600,
        evidence_profile_id: "profile.demo".to_string(),
        issuer_key_id: [0; 16],
    }
}

fn evidence(challenge_object: Vec<u8>, handle: [u8; 32]) -> MockEvidence {
    MockEvidence {
        challenge_object,
        evidence_profile_id: "profile.demo".to_string(),
        session_key_handle: handle,
        session_key_id: [0; 16],
        collection_authority_contract_id: "authority.demo".to_string(),
        epoch_relation: 7,
        collection_sequence: 12,
        collection_start: 1_050,
        snapshot_freeze_end: 1_100,
        base_claims: std::array::from_fn(|slot| MockClaim {
            provenance: if slot % 2 == 0 {
                Provenance::HardwareCertified
            } else {
                Provenance::MeasuredLogDerived
            },
            identity: format!("claim.{slot}").into_bytes(),
        }),
        profile_claims: vec![MockClaim {
            provenance: Provenance::TrustedAgentObserved,
            identity: b"profile.only".to_vec(),
        }],
        manifest_identities: vec![0xEE; 12],
        attester_key_id: [0; 16],
    }
}

fn main() {
    println!("OGIR M2 mock protocol demonstration (test-only; ADR-0015/0016)");

    let verifier = MockVerifierKey::from_seed(b"m2-019-demo-verifier");
    let attester = MockAttesterKey::from_seed(b"m2-019-demo-attester");
    let session = MockSessionKey::from_seed(b"m2-019-demo-session");

    let mut directory = MockKeyDirectory::new();
    directory.register_verifier(&verifier);
    directory.register_attester(&attester);
    directory.register_session(&session);

    let policy = ContextMatchPolicy {
        expected: MockExpectedContext {
            publisher_id: "pub.demo".to_string(),
            game_id: "game.demo".to_string(),
            build_id: "build.demo".to_string(),
            account_scope: "acct.demo".to_string(),
            match_id: "match.demo".to_string(),
            policy_id: "policy.demo".to_string(),
            policy_version: 1,
        },
        permit_id: "permit.demo.1".to_string(),
        session_id: "session.demo.1".to_string(),
        lifetime_seconds: 400,
    };
    let service = match MockVerifierService::new(
        MockVerifierKey::from_seed(b"m2-019-demo-verifier"),
        policy,
        3_600,
    ) {
        Ok(service) => service,
        Err(error) => panic!("service construction failed: {error:?}"),
    };

    let challenge_bytes = match build_signed_challenge(&challenge(), &verifier) {
        Ok(bytes) => bytes,
        Err(error) => panic!("challenge build failed: {error:?}"),
    };
    println!(
        "[1] signed challenge: {} bytes, digest {}...",
        challenge_bytes.len(),
        short_digest(&challenge_bytes)
    );

    let evidence_bytes = match build_signed_evidence(
        &evidence(challenge_bytes.clone(), *session.handle_bytes()),
        &attester,
    ) {
        Ok(bytes) => bytes,
        Err(error) => panic!("evidence build failed: {error:?}"),
    };
    println!(
        "[2] signed evidence: {} bytes, digest {}...",
        evidence_bytes.len(),
        short_digest(&evidence_bytes)
    );

    // Transport both objects in test-only frames.
    let version = ogir_model::ProtocolVersion { major: 0, minor: 1 };
    let framed_challenge = match encode_frame(version, MessageKind::MockChallenge, &challenge_bytes)
    {
        Ok(bytes) => bytes,
        Err(error) => panic!("challenge framing failed: {error:?}"),
    };
    let framed_evidence = match encode_frame(version, MessageKind::MockEvidence, &evidence_bytes) {
        Ok(bytes) => bytes,
        Err(error) => panic!("evidence framing failed: {error:?}"),
    };
    let parsed_challenge = match parse_frame(&framed_challenge) {
        Ok(frame) => frame,
        Err(error) => panic!("challenge frame rejected: {error:?}"),
    };
    let parsed_evidence = match parse_frame(&framed_evidence) {
        Ok(frame) => frame,
        Err(error) => panic!("evidence frame rejected: {error:?}"),
    };
    println!(
        "[3] frames parsed: kinds {:?}/{:?}, payloads {}/{} bytes",
        parsed_challenge.kind,
        parsed_evidence.kind,
        parsed_challenge.payload.len(),
        parsed_evidence.payload.len()
    );

    let verdict = service.process(
        1_200,
        &parsed_challenge.payload,
        &parsed_evidence.payload,
        &directory,
    );
    let permit_bytes = match verdict {
        MockVerdict::Admit { permit_bytes, .. } => {
            println!(
                "[4] appraisal admitted; permit: {} bytes, digest {}...",
                permit_bytes.len(),
                short_digest(&permit_bytes)
            );
            permit_bytes
        }
        MockVerdict::Deny { reason } => {
            panic!("appraisal denied: {reason:?}");
        }
    };

    let proof = match build_pop(&session, &permit_bytes, &[0xAB; 32]) {
        Ok(bytes) => bytes,
        Err(error) => panic!("proof build failed: {error:?}"),
    };

    // The relying party decides from signed artifacts alone; the client
    // exposes no trusted local boolean anywhere in this flow.
    let mut relying_party = MockRelyingParty::new(directory.clone());
    match relying_party.admit(1_300, &permit_bytes, &proof) {
        Ok(admitted) => {
            println!(
                "[5] relying party admitted permit {} (session key handle [REDACTED], nonce [REDACTED])",
                admitted.permit.permit_id
            );
        }
        Err(error) => panic!("admission failed: {error:?}"),
    }

    // Fenced renewal: stage one successor, install it, redeliver exactly.
    let renewal_challenge = match build_signed_challenge(
        &MockChallenge {
            issued_at: 1_400,
            expires_at: 2_000,
            nonce: [0xD2; 32],
            ..challenge()
        },
        &verifier,
    ) {
        Ok(bytes) => bytes,
        Err(error) => panic!("renewal challenge build failed: {error:?}"),
    };
    let renewal_evidence = match build_signed_evidence(
        &evidence(renewal_challenge.clone(), *session.handle_bytes()),
        &attester,
    ) {
        Ok(bytes) => bytes,
        Err(error) => panic!("renewal evidence build failed: {error:?}"),
    };
    let successor = match service.process(
        1_500,
        renewal_challenge.as_slice(),
        &renewal_evidence,
        &directory,
    ) {
        MockVerdict::Admit {
            permit_bytes: successor,
            ..
        } => successor,
        MockVerdict::Deny { reason } => panic!("renewal appraisal denied: {reason:?}"),
    };
    let mut owner = MockSessionOwner::new(permit_bytes);
    let predecessor = owner.current().to_vec();
    match owner.stage_pending(&predecessor, &successor) {
        Ok(()) => println!("[6] renewal staged (pending grants nothing)"),
        Err(error) => panic!("staging failed: {error:?}"),
    }
    match owner.install_successor(&predecessor, &successor) {
        Ok(InstallOutcome::New) => println!(
            "[7] successor fenced and installed, generation {}",
            owner.generation()
        ),
        Ok(InstallOutcome::IdempotentRedelivery) => {
            panic!("unexpected idempotent redelivery on first install")
        }
        Err(error) => panic!("installation failed: {error:?}"),
    }

    println!("done: admission came only from relying-party validation of signed artifacts");
}
