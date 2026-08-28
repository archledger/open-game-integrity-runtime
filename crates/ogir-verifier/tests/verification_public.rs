// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::num::NonZeroU64;

use ogir_model::{
    AccountScope, BuildId, ChallengeLifetime, ChallengeWindow, Decision, EvidenceProfile, GameId,
    IdentifierError, MatchId, Nonce, PolicyId, PolicyVersion, ProtocolVersion, PublisherChallenge,
    PublisherId, ReasonCode, UnixTime,
};
use ogir_protocol::EvidenceBundle;
use ogir_verifier::{
    AcceptedClaims, AppraisalResult, AppraisalResultView, ExpectedContext, TransitionError,
    VerificationPhase, VerificationRequest, VerifiedAttestation, VerifierFlow,
};

fn identifier<T>(value: &str) -> T
where
    T: Debug,
    for<'a> T: TryFrom<&'a str, Error = IdentifierError>,
{
    match T::try_from(value) {
        Ok(value) => value,
        Err(error) => panic!("valid fixture rejected: {error:?}"),
    }
}

fn request_fixture() -> VerificationRequest {
    let maximum = match NonZeroU64::new(100) {
        Some(value) => ChallengeLifetime::new(value),
        None => panic!("fixture maximum must be nonzero"),
    };
    let window = match ChallengeWindow::new(UnixTime::new(100), UnixTime::new(200), maximum) {
        Ok(value) => value,
        Err(error) => panic!("valid window rejected: {error:?}"),
    };
    VerificationRequest {
        challenge: PublisherChallenge {
            version: ProtocolVersion { major: 0, minor: 1 },
            publisher_id: identifier::<PublisherId>("example.publisher"),
            game_id: identifier::<GameId>("example.game"),
            build_id: identifier::<BuildId>("build-1"),
            account_scope: identifier::<AccountScope>("account-1"),
            match_id: identifier::<MatchId>("match-1"),
            policy_id: identifier::<PolicyId>("research-v0"),
            policy_version: PolicyVersion::new(1),
            nonce: Nonce::from_bytes([7; 32]),
            window,
        },
        evidence: EvidenceBundle {
            profile_id: identifier::<EvidenceProfile>("mock-v0"),
            payload: b"synthetic-public-fixture".to_vec(),
        },
        expected: ExpectedContext {
            publisher_id: identifier::<PublisherId>("example.publisher"),
            game_id: identifier::<GameId>("example.game"),
            build_id: identifier::<BuildId>("build-1"),
            account_scope: identifier::<AccountScope>("account-1"),
            match_id: identifier::<MatchId>("match-1"),
            policy_id: identifier::<PolicyId>("research-v0"),
            policy_version: PolicyVersion::new(1),
        },
        now: UnixTime::new(100),
    }
}

#[test]
fn appraisal_result_public_accessors_type_check() {
    fn inspect_claims(claims: &AcceptedClaims) {
        let _ = claims.accepted_profile();
        let _ = claims.session_public_key_id();
    }

    fn inspect(result: &AppraisalResult) {
        let _: &ExpectedContext = result.context();
        let _: Decision = result.decision();
        let _: Option<ReasonCode> = result.reason();
        match result.view() {
            AppraisalResultView::Allow(claims) | AppraisalResultView::AllowRestricted(claims) => {
                inspect_claims(claims)
            }
            AppraisalResultView::Failure { decision, reason } => {
                let _: Decision = decision;
                let _: ReasonCode = reason;
            }
        }
    }

    let _: fn(&AppraisalResult) = inspect;
    let _: fn(&AcceptedClaims) = inspect_claims;
    let _: fn(&mut VerifierFlow) -> Result<VerifiedAttestation, TransitionError> =
        VerifierFlow::complete;
    let _: fn(VerifiedAttestation) -> AppraisalResult = VerifiedAttestation::into_appraisal_result;
}

#[test]
fn new_flow_exposes_only_received_phase_and_no_outcome() {
    let flow = VerifierFlow::begin(request_fixture());
    assert_eq!(flow.phase(), VerificationPhase::EvidenceReceived);
    assert_eq!(flow.outcome(), None);
    assert!(
        format!("{flow:?}") == "VerifierFlow { phase: EvidenceReceived, outcome: None }",
        "private diagnostic mismatch"
    );
}
