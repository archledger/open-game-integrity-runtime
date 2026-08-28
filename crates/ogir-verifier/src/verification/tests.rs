// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::num::NonZeroU64;

use ogir_model::{
    AccountScope, BuildId, ChallengeLifetime, ChallengeWindow, Decision, EvidenceProfile, GameId,
    IdentifierError, MatchId, Nonce, PolicyId, PolicyVersion, ProtocolVersion, PublisherChallenge,
    PublisherId, ReasonCode, SessionPublicKeyId, UnixTime,
};
use ogir_protocol::EvidenceBundle;

use super::*;

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

fn request_fixture(seed: u8) -> VerificationRequest {
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
            policy_version: PolicyVersion::new(3_141_592_653),
            nonce: Nonce::from_bytes([seed; 32]),
            window,
        },
        evidence: EvidenceBundle {
            profile_id: identifier::<EvidenceProfile>("mock-v0"),
            payload: vec![seed; 8],
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

fn flow_fixture(seed: u8) -> VerifierFlow {
    VerifierFlow::begin(request_fixture(seed))
}

fn request_fixture_with_context_tag(seed: u8, tag: u8) -> VerificationRequest {
    let mut request = request_fixture(seed);
    let publisher = format!("publisher-{tag}");
    let game = format!("game-{tag}");
    let build = format!("build-{tag}");
    let account = format!("account-{tag}");
    let match_id = format!("match-{tag}");
    let policy = format!("policy-{tag}");
    let policy_version = PolicyVersion::new(u32::from(tag) + 1);

    request.challenge.publisher_id = identifier(&publisher);
    request.challenge.game_id = identifier(&game);
    request.challenge.build_id = identifier(&build);
    request.challenge.account_scope = identifier(&account);
    request.challenge.match_id = identifier(&match_id);
    request.challenge.policy_id = identifier(&policy);
    request.challenge.policy_version = policy_version;
    request.expected.publisher_id = identifier(&publisher);
    request.expected.game_id = identifier(&game);
    request.expected.build_id = identifier(&build);
    request.expected.account_scope = identifier(&account);
    request.expected.match_id = identifier(&match_id);
    request.expected.policy_id = identifier(&policy);
    request.expected.policy_version = policy_version;
    request
}

fn flow_fixture_with_context_tag(seed: u8, tag: u8) -> VerifierFlow {
    VerifierFlow::begin(request_fixture_with_context_tag(seed, tag))
}

fn accepted_profile() -> EvidenceProfile {
    identifier("accepted-profile-v1")
}

fn session_key_id(seed: u8) -> SessionPublicKeyId {
    SessionPublicKeyId::from_bytes(std::array::from_fn(|index| seed ^ index as u8))
}

fn advance_to_identity_checked(flow: &mut VerifierFlow) {
    let binding = flow.binding.clone();
    assert_eq!(
        flow.record_challenge_authenticated(ChallengeAuthenticated {
            binding: binding.clone(),
        }),
        Ok(())
    );
    assert_eq!(
        flow.record_freshness_checked(crate::freshness::test_freshness_checked(binding.clone())),
        Ok(())
    );
    assert_eq!(
        flow.record_identity_checked(IdentityChecked { binding }),
        Ok(())
    );
}

fn advance_to_policy_ready(
    flow: &mut VerifierFlow,
    accepted_profile: EvidenceProfile,
    session_public_key_id: SessionPublicKeyId,
    allowed: AllowedClass,
) {
    let binding = flow.binding.clone();
    assert_eq!(
        flow.record_challenge_authenticated(ChallengeAuthenticated {
            binding: binding.clone(),
        }),
        Ok(())
    );
    assert_eq!(
        flow.record_freshness_checked(crate::freshness::test_freshness_checked(binding.clone())),
        Ok(())
    );
    assert_eq!(
        flow.record_identity_checked(IdentityChecked {
            binding: binding.clone(),
        }),
        Ok(())
    );
    assert_eq!(
        flow.record_evidence_appraised(EvidenceAppraised {
            binding: binding.clone(),
            accepted_profile,
        }),
        Ok(())
    );
    assert_eq!(
        flow.record_session_bound(SessionBound {
            binding: binding.clone(),
            session_public_key_id,
        }),
        Ok(())
    );
    assert_eq!(
        flow.record_revocation_checked(RevocationChecked {
            binding: binding.clone(),
        }),
        Ok(())
    );
    assert_eq!(
        flow.record_policy_satisfied(PolicySatisfied { binding, allowed }),
        Ok(())
    );
}

fn policy_ready_flow(
    seed: u8,
    accepted_profile: EvidenceProfile,
    session_public_key_id: SessionPublicKeyId,
    allowed: AllowedClass,
) -> VerifierFlow {
    let mut flow = flow_fixture(seed);
    advance_to_policy_ready(&mut flow, accepted_profile, session_public_key_id, allowed);
    flow
}

fn policy_ready_flow_with_context_tag(
    seed: u8,
    tag: u8,
    accepted_profile: EvidenceProfile,
    session_public_key_id: SessionPublicKeyId,
    allowed: AllowedClass,
) -> VerifierFlow {
    let mut flow = flow_fixture_with_context_tag(seed, tag);
    advance_to_policy_ready(&mut flow, accepted_profile, session_public_key_id, allowed);
    flow
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ActionResult {
    NoResult,
    Allow {
        context: ExpectedContext,
        decision: Decision,
        reason: Option<ReasonCode>,
        allowed: AllowedClass,
        accepted_profile: EvidenceProfile,
        session_public_key_id: SessionPublicKeyId,
    },
    Failure {
        context: ExpectedContext,
        decision: Decision,
        reason: Option<ReasonCode>,
        view_decision: Decision,
        view_reason: ReasonCode,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingMode {
    Matching,
    OtherFlow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestAction {
    Challenge(BindingMode),
    Freshness(BindingMode),
    Identity(BindingMode),
    Evidence(BindingMode),
    Session(BindingMode),
    Revocation(BindingMode),
    Policy(AllowedClass, BindingMode),
    Complete,
    MarkMalformed,
    MarkUnsupported(UnsupportedRequirement),
    MarkRetryable(RetryReason),
    Deny(DenialReason),
    MarkRevoked,
}

impl TestAction {
    fn public(self) -> VerificationAction {
        match self {
            Self::Challenge(_) => VerificationAction::RecordChallengeAuthenticated,
            Self::Freshness(_) => VerificationAction::RecordFreshnessChecked,
            Self::Identity(_) => VerificationAction::RecordIdentityChecked,
            Self::Evidence(_) => VerificationAction::RecordEvidenceAppraised,
            Self::Session(_) => VerificationAction::RecordSessionBound,
            Self::Revocation(_) => VerificationAction::RecordRevocationChecked,
            Self::Policy(_, _) => VerificationAction::RecordPolicySatisfied,
            Self::Complete => VerificationAction::Complete,
            Self::MarkMalformed => VerificationAction::MarkMalformed,
            Self::MarkUnsupported(_) => VerificationAction::MarkUnsupported,
            Self::MarkRetryable(_) => VerificationAction::MarkRetryable,
            Self::Deny(_) => VerificationAction::Deny,
            Self::MarkRevoked => VerificationAction::MarkRevoked,
        }
    }

    fn binding_mode(self) -> Option<BindingMode> {
        match self {
            Self::Challenge(mode)
            | Self::Freshness(mode)
            | Self::Identity(mode)
            | Self::Evidence(mode)
            | Self::Session(mode)
            | Self::Revocation(mode)
            | Self::Policy(_, mode) => Some(mode),
            Self::Complete
            | Self::MarkMalformed
            | Self::MarkUnsupported(_)
            | Self::MarkRetryable(_)
            | Self::Deny(_)
            | Self::MarkRevoked => None,
        }
    }

    fn required_phase(self) -> Option<VerificationPhase> {
        match self {
            Self::Challenge(_) => Some(VerificationPhase::EvidenceReceived),
            Self::Freshness(_) => Some(VerificationPhase::ChallengeAuthenticated),
            Self::Identity(_) => Some(VerificationPhase::FreshnessChecked),
            Self::Evidence(_) => Some(VerificationPhase::IdentityChecked),
            Self::Session(_) => Some(VerificationPhase::EvidenceAppraised),
            Self::Revocation(_) => Some(VerificationPhase::SessionBound),
            Self::Policy(_, _) => Some(VerificationPhase::RevocationChecked),
            Self::Complete => Some(VerificationPhase::PolicySatisfied),
            Self::MarkMalformed
            | Self::MarkUnsupported(_)
            | Self::MarkRetryable(_)
            | Self::Deny(_)
            | Self::MarkRevoked => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FlowSnapshot {
    phase: VerificationPhase,
    outcome: Option<VerificationOutcome>,
    request: Option<VerificationRequest>,
    context: Option<ExpectedContext>,
    accepted_profile: Option<EvidenceProfile>,
    session_public_key_id: Option<SessionPublicKeyId>,
    allowed: Option<AllowedClass>,
    has_request: bool,
    has_profile: bool,
    has_session_key: bool,
    has_allowed_class: bool,
}

fn flow_snapshot(flow: &VerifierFlow) -> FlowSnapshot {
    let (request, context, accepted_profile, session_public_key_id, allowed) = match &flow.state {
        VerificationState::EvidenceReceived { request }
        | VerificationState::ChallengeAuthenticated { request }
        | VerificationState::FreshnessChecked { request }
        | VerificationState::IdentityChecked { request } => (
            Some(request.clone()),
            Some(request.expected.clone()),
            None,
            None,
            None,
        ),
        VerificationState::EvidenceAppraised {
            request,
            accepted_profile,
        } => (
            Some(request.clone()),
            Some(request.expected.clone()),
            Some(accepted_profile.clone()),
            None,
            None,
        ),
        VerificationState::SessionBound {
            request,
            accepted_profile,
            session_public_key_id,
        }
        | VerificationState::RevocationChecked {
            request,
            accepted_profile,
            session_public_key_id,
        } => (
            Some(request.clone()),
            Some(request.expected.clone()),
            Some(accepted_profile.clone()),
            Some(*session_public_key_id),
            None,
        ),
        VerificationState::PolicySatisfied {
            request,
            accepted_profile,
            session_public_key_id,
            allowed,
        } => (
            Some(request.clone()),
            Some(request.expected.clone()),
            Some(accepted_profile.clone()),
            Some(*session_public_key_id),
            Some(*allowed),
        ),
        VerificationState::Verified { .. }
        | VerificationState::Malformed { .. }
        | VerificationState::Unsupported { .. }
        | VerificationState::Retryable { .. }
        | VerificationState::Denied { .. }
        | VerificationState::Revoked { .. } => (None, None, None, None, None),
    };
    FlowSnapshot {
        phase: flow.phase(),
        outcome: flow.outcome(),
        has_request: request.is_some(),
        has_profile: accepted_profile.is_some(),
        has_session_key: session_public_key_id.is_some(),
        has_allowed_class: allowed.is_some(),
        request,
        context,
        accepted_profile,
        session_public_key_id,
        allowed,
    }
}

const ALL_24_MATRIX_ACTIONS: [TestAction; 24] = [
    TestAction::Challenge(BindingMode::Matching),
    TestAction::Freshness(BindingMode::Matching),
    TestAction::Identity(BindingMode::Matching),
    TestAction::Evidence(BindingMode::Matching),
    TestAction::Session(BindingMode::Matching),
    TestAction::Revocation(BindingMode::Matching),
    TestAction::Policy(AllowedClass::Full, BindingMode::Matching),
    TestAction::Policy(AllowedClass::Restricted, BindingMode::Matching),
    TestAction::Complete,
    TestAction::MarkMalformed,
    TestAction::MarkUnsupported(UnsupportedRequirement::VersionOrProfile),
    TestAction::MarkUnsupported(UnsupportedRequirement::Platform),
    TestAction::MarkUnsupported(UnsupportedRequirement::UnknownCriticalRequirement),
    TestAction::MarkRetryable(RetryReason::AttestationUnavailable),
    TestAction::MarkRetryable(RetryReason::TransientFailure),
    TestAction::Deny(DenialReason::ChallengeAuthenticationFailed),
    TestAction::Deny(DenialReason::NotYetValid),
    TestAction::Deny(DenialReason::Expired),
    TestAction::Deny(DenialReason::ReplayDetected),
    TestAction::Deny(DenialReason::ContextBindingMismatch),
    TestAction::Deny(DenialReason::EvidenceInvalid),
    TestAction::Deny(DenialReason::PolicyDenied),
    TestAction::Deny(DenialReason::ProtectedSessionLost),
    TestAction::MarkRevoked,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateKind {
    Challenge,
    Freshness,
    Identity,
    Evidence,
    Session,
    Revocation,
    Policy,
}

const ALL_7_GATE_KINDS: [GateKind; 7] = [
    GateKind::Challenge,
    GateKind::Freshness,
    GateKind::Identity,
    GateKind::Evidence,
    GateKind::Session,
    GateKind::Revocation,
    GateKind::Policy,
];

impl GateKind {
    fn action(self) -> VerificationAction {
        match self {
            Self::Challenge => VerificationAction::RecordChallengeAuthenticated,
            Self::Freshness => VerificationAction::RecordFreshnessChecked,
            Self::Identity => VerificationAction::RecordIdentityChecked,
            Self::Evidence => VerificationAction::RecordEvidenceAppraised,
            Self::Session => VerificationAction::RecordSessionBound,
            Self::Revocation => VerificationAction::RecordRevocationChecked,
            Self::Policy => VerificationAction::RecordPolicySatisfied,
        }
    }

    fn matching_action(self, allowed: AllowedClass) -> TestAction {
        match self {
            Self::Challenge => TestAction::Challenge(BindingMode::Matching),
            Self::Freshness => TestAction::Freshness(BindingMode::Matching),
            Self::Identity => TestAction::Identity(BindingMode::Matching),
            Self::Evidence => TestAction::Evidence(BindingMode::Matching),
            Self::Session => TestAction::Session(BindingMode::Matching),
            Self::Revocation => TestAction::Revocation(BindingMode::Matching),
            Self::Policy => TestAction::Policy(allowed, BindingMode::Matching),
        }
    }

    fn required_phase(self) -> VerificationPhase {
        match self {
            Self::Challenge => VerificationPhase::EvidenceReceived,
            Self::Freshness => VerificationPhase::ChallengeAuthenticated,
            Self::Identity => VerificationPhase::FreshnessChecked,
            Self::Evidence => VerificationPhase::IdentityChecked,
            Self::Session => VerificationPhase::EvidenceAppraised,
            Self::Revocation => VerificationPhase::SessionBound,
            Self::Policy => VerificationPhase::RevocationChecked,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModelState {
    EvidenceReceived,
    ChallengeAuthenticated,
    FreshnessChecked,
    IdentityChecked,
    EvidenceAppraised,
    SessionBound,
    RevocationChecked,
    PolicySatisfied(AllowedClass),
    Verified(AllowedClass),
    Malformed,
    Unsupported(UnsupportedRequirement),
    Retryable(RetryReason),
    Denied(DenialReason),
    Revoked,
}

const ALL_14_MODEL_STATES: [ModelState; 14] = [
    ModelState::EvidenceReceived,
    ModelState::ChallengeAuthenticated,
    ModelState::FreshnessChecked,
    ModelState::IdentityChecked,
    ModelState::EvidenceAppraised,
    ModelState::SessionBound,
    ModelState::RevocationChecked,
    ModelState::PolicySatisfied(AllowedClass::Full),
    ModelState::Verified(AllowedClass::Full),
    ModelState::Malformed,
    ModelState::Unsupported(UnsupportedRequirement::VersionOrProfile),
    ModelState::Retryable(RetryReason::AttestationUnavailable),
    ModelState::Denied(DenialReason::PolicyDenied),
    ModelState::Revoked,
];

fn model_transition(state: ModelState, action: TestAction) -> Option<ModelState> {
    match (state, action) {
        (ModelState::EvidenceReceived, TestAction::Challenge(BindingMode::Matching)) => {
            Some(ModelState::ChallengeAuthenticated)
        }
        (ModelState::ChallengeAuthenticated, TestAction::Freshness(BindingMode::Matching)) => {
            Some(ModelState::FreshnessChecked)
        }
        (ModelState::FreshnessChecked, TestAction::Identity(BindingMode::Matching)) => {
            Some(ModelState::IdentityChecked)
        }
        (ModelState::IdentityChecked, TestAction::Evidence(BindingMode::Matching)) => {
            Some(ModelState::EvidenceAppraised)
        }
        (ModelState::EvidenceAppraised, TestAction::Session(BindingMode::Matching)) => {
            Some(ModelState::SessionBound)
        }
        (ModelState::SessionBound, TestAction::Revocation(BindingMode::Matching)) => {
            Some(ModelState::RevocationChecked)
        }
        (
            ModelState::RevocationChecked,
            TestAction::Policy(AllowedClass::Full, BindingMode::Matching),
        ) => Some(ModelState::PolicySatisfied(AllowedClass::Full)),
        (
            ModelState::RevocationChecked,
            TestAction::Policy(AllowedClass::Restricted, BindingMode::Matching),
        ) => Some(ModelState::PolicySatisfied(AllowedClass::Restricted)),
        (ModelState::PolicySatisfied(class), TestAction::Complete) => {
            Some(ModelState::Verified(class))
        }
        (
            ModelState::EvidenceReceived,
            action @ (TestAction::MarkMalformed
            | TestAction::Deny(DenialReason::ChallengeAuthenticationFailed)
            | TestAction::MarkRetryable(
                RetryReason::AttestationUnavailable | RetryReason::TransientFailure,
            )
            | TestAction::MarkUnsupported(
                UnsupportedRequirement::UnknownCriticalRequirement,
            )),
        ) => Some(model_failure_terminal(action)),
        (
            ModelState::ChallengeAuthenticated,
            action @ (TestAction::MarkUnsupported(
                UnsupportedRequirement::VersionOrProfile
                | UnsupportedRequirement::UnknownCriticalRequirement,
            )
            | TestAction::Deny(
                DenialReason::NotYetValid
                | DenialReason::Expired
                | DenialReason::ReplayDetected
                | DenialReason::ContextBindingMismatch,
            )
            | TestAction::MarkRetryable(
                RetryReason::AttestationUnavailable | RetryReason::TransientFailure,
            )),
        ) => Some(model_failure_terminal(action)),
        (
            ModelState::FreshnessChecked,
            action @ (TestAction::Deny(DenialReason::ContextBindingMismatch)
            | TestAction::MarkRetryable(
                RetryReason::AttestationUnavailable | RetryReason::TransientFailure,
            )
            | TestAction::MarkUnsupported(
                UnsupportedRequirement::UnknownCriticalRequirement,
            )),
        ) => Some(model_failure_terminal(action)),
        (
            ModelState::IdentityChecked,
            action @ (TestAction::MarkUnsupported(
                UnsupportedRequirement::Platform
                | UnsupportedRequirement::UnknownCriticalRequirement,
            )
            | TestAction::Deny(DenialReason::EvidenceInvalid)
            | TestAction::MarkRetryable(
                RetryReason::AttestationUnavailable | RetryReason::TransientFailure,
            )),
        ) => Some(model_failure_terminal(action)),
        (
            ModelState::EvidenceAppraised,
            action @ (TestAction::Deny(
                DenialReason::ContextBindingMismatch | DenialReason::ProtectedSessionLost,
            )
            | TestAction::MarkRetryable(
                RetryReason::AttestationUnavailable | RetryReason::TransientFailure,
            )
            | TestAction::MarkUnsupported(
                UnsupportedRequirement::UnknownCriticalRequirement,
            )),
        ) => Some(model_failure_terminal(action)),
        (
            ModelState::SessionBound,
            action @ (TestAction::MarkRevoked
            | TestAction::Deny(DenialReason::ProtectedSessionLost)
            | TestAction::MarkRetryable(
                RetryReason::AttestationUnavailable | RetryReason::TransientFailure,
            )
            | TestAction::MarkUnsupported(
                UnsupportedRequirement::UnknownCriticalRequirement,
            )),
        ) => Some(model_failure_terminal(action)),
        (
            ModelState::RevocationChecked,
            action @ (TestAction::Deny(
                DenialReason::PolicyDenied | DenialReason::ProtectedSessionLost,
            )
            | TestAction::MarkRetryable(
                RetryReason::AttestationUnavailable | RetryReason::TransientFailure,
            )
            | TestAction::MarkUnsupported(
                UnsupportedRequirement::UnknownCriticalRequirement,
            )),
        ) => Some(model_failure_terminal(action)),
        (
            ModelState::PolicySatisfied(_),
            action @ (TestAction::Deny(DenialReason::ProtectedSessionLost)
            | TestAction::MarkRetryable(
                RetryReason::AttestationUnavailable | RetryReason::TransientFailure,
            )
            | TestAction::MarkUnsupported(
                UnsupportedRequirement::UnknownCriticalRequirement,
            )),
        ) => Some(model_failure_terminal(action)),
        _ => None,
    }
}

fn model_failure_terminal(action: TestAction) -> ModelState {
    match action {
        TestAction::MarkMalformed => ModelState::Malformed,
        TestAction::MarkUnsupported(requirement) => ModelState::Unsupported(requirement),
        TestAction::MarkRetryable(reason) => ModelState::Retryable(reason),
        TestAction::Deny(reason) => ModelState::Denied(reason),
        TestAction::MarkRevoked => ModelState::Revoked,
        TestAction::Challenge(_)
        | TestAction::Freshness(_)
        | TestAction::Identity(_)
        | TestAction::Evidence(_)
        | TestAction::Session(_)
        | TestAction::Revocation(_)
        | TestAction::Policy(_, _)
        | TestAction::Complete => panic!("non-failure action in model failure mapping: {action:?}"),
    }
}

fn model_is_nonterminal(state: ModelState) -> bool {
    match state {
        ModelState::EvidenceReceived
        | ModelState::ChallengeAuthenticated
        | ModelState::FreshnessChecked
        | ModelState::IdentityChecked
        | ModelState::EvidenceAppraised
        | ModelState::SessionBound
        | ModelState::RevocationChecked
        | ModelState::PolicySatisfied(_) => true,
        ModelState::Verified(_)
        | ModelState::Malformed
        | ModelState::Unsupported(_)
        | ModelState::Retryable(_)
        | ModelState::Denied(_)
        | ModelState::Revoked => false,
    }
}

fn model_has_profile(state: ModelState) -> bool {
    match state {
        ModelState::EvidenceAppraised
        | ModelState::SessionBound
        | ModelState::RevocationChecked
        | ModelState::PolicySatisfied(_) => true,
        ModelState::EvidenceReceived
        | ModelState::ChallengeAuthenticated
        | ModelState::FreshnessChecked
        | ModelState::IdentityChecked
        | ModelState::Verified(_)
        | ModelState::Malformed
        | ModelState::Unsupported(_)
        | ModelState::Retryable(_)
        | ModelState::Denied(_)
        | ModelState::Revoked => false,
    }
}

fn model_has_session_key(state: ModelState) -> bool {
    match state {
        ModelState::SessionBound
        | ModelState::RevocationChecked
        | ModelState::PolicySatisfied(_) => true,
        ModelState::EvidenceReceived
        | ModelState::ChallengeAuthenticated
        | ModelState::FreshnessChecked
        | ModelState::IdentityChecked
        | ModelState::EvidenceAppraised
        | ModelState::Verified(_)
        | ModelState::Malformed
        | ModelState::Unsupported(_)
        | ModelState::Retryable(_)
        | ModelState::Denied(_)
        | ModelState::Revoked => false,
    }
}

fn model_has_allowed_class(state: ModelState) -> bool {
    match state {
        ModelState::PolicySatisfied(_) => true,
        ModelState::EvidenceReceived
        | ModelState::ChallengeAuthenticated
        | ModelState::FreshnessChecked
        | ModelState::IdentityChecked
        | ModelState::EvidenceAppraised
        | ModelState::SessionBound
        | ModelState::RevocationChecked
        | ModelState::Verified(_)
        | ModelState::Malformed
        | ModelState::Unsupported(_)
        | ModelState::Retryable(_)
        | ModelState::Denied(_)
        | ModelState::Revoked => false,
    }
}

fn model_phase(state: ModelState) -> VerificationPhase {
    match state {
        ModelState::EvidenceReceived => VerificationPhase::EvidenceReceived,
        ModelState::ChallengeAuthenticated => VerificationPhase::ChallengeAuthenticated,
        ModelState::FreshnessChecked => VerificationPhase::FreshnessChecked,
        ModelState::IdentityChecked => VerificationPhase::IdentityChecked,
        ModelState::EvidenceAppraised => VerificationPhase::EvidenceAppraised,
        ModelState::SessionBound => VerificationPhase::SessionBound,
        ModelState::RevocationChecked => VerificationPhase::RevocationChecked,
        ModelState::PolicySatisfied(_) => VerificationPhase::PolicySatisfied,
        ModelState::Verified(_) => VerificationPhase::Verified,
        ModelState::Malformed => VerificationPhase::Malformed,
        ModelState::Unsupported(_) => VerificationPhase::Unsupported,
        ModelState::Retryable(_) => VerificationPhase::Retryable,
        ModelState::Denied(_) => VerificationPhase::Denied,
        ModelState::Revoked => VerificationPhase::Revoked,
    }
}

#[test]
fn report_reason_is_absent_only_for_allows() {
    assert_eq!(VerificationOutcome::allowed_full().reason(), None);
    assert_eq!(VerificationOutcome::allowed_restricted().reason(), None);
    assert_eq!(
        VerificationOutcome::malformed().reason(),
        Some(ReasonCode::Malformed)
    );
}

#[test]
fn claim_capabilities_move_payload_only_after_phase_and_binding_checks() {
    let mut flow = flow_fixture_with_context_tag(7, 1);
    advance_to_identity_checked(&mut flow);
    let other = flow_fixture_with_context_tag(7, 1);
    let before_evidence = flow_snapshot(&flow);
    assert_eq!(
        flow.record_evidence_appraised(EvidenceAppraised {
            binding: other.binding.clone(),
            accepted_profile: identifier("other-flow-profile"),
        }),
        Err(TransitionError::CapabilityRejected {
            action: VerificationAction::RecordEvidenceAppraised,
        })
    );
    assert_eq!(flow_snapshot(&flow), before_evidence);

    let profile = accepted_profile();
    assert_eq!(
        flow.record_evidence_appraised(EvidenceAppraised {
            binding: flow.binding.clone(),
            accepted_profile: profile.clone(),
        }),
        Ok(())
    );
    let after_evidence = flow_snapshot(&flow);
    assert_eq!(after_evidence.accepted_profile, Some(profile.clone()));
    assert_eq!(after_evidence.session_public_key_id, None);

    let before_session = flow_snapshot(&flow);
    assert_eq!(
        flow.record_session_bound(SessionBound {
            binding: other.binding,
            session_public_key_id: session_key_id(251),
        }),
        Err(TransitionError::CapabilityRejected {
            action: VerificationAction::RecordSessionBound,
        })
    );
    assert_eq!(flow_snapshot(&flow), before_session);

    let key_id = session_key_id(7);
    assert_eq!(
        flow.record_session_bound(SessionBound {
            binding: flow.binding.clone(),
            session_public_key_id: key_id,
        }),
        Ok(())
    );
    let after_session = flow_snapshot(&flow);
    assert_eq!(after_session.accepted_profile, Some(profile));
    assert_eq!(after_session.session_public_key_id, Some(key_id));

    let tagged_policy = policy_ready_flow_with_context_tag(
        8,
        1,
        accepted_profile(),
        session_key_id(8),
        AllowedClass::Full,
    );
    let tagged_snapshot = flow_snapshot(&tagged_policy);
    let context = match tagged_snapshot.context.as_ref() {
        Some(value) => value,
        None => panic!("policy-ready state must retain exact context"),
    };
    assert_ne!(context.policy_version, PolicyVersion::new(u32::MAX));
    assert_eq!(tagged_snapshot.allowed, Some(AllowedClass::Full));
}

#[test]
fn correct_binding_does_not_claim_cryptographic_payload_provenance() {
    let profiles = [
        identifier::<EvidenceProfile>("trusted-producer-profile-a"),
        identifier::<EvidenceProfile>("trusted-producer-profile-b"),
    ];

    for (seed, supplied_profile) in (21_u8..).zip(profiles) {
        let mut flow = flow_fixture(seed);
        advance_to_identity_checked(&mut flow);
        let capability = EvidenceAppraised {
            binding: flow.binding.clone(),
            accepted_profile: supplied_profile.clone(),
        };

        assert_eq!(flow.record_evidence_appraised(capability), Ok(()));
        assert_eq!(
            flow_snapshot(&flow).accepted_profile,
            Some(supplied_profile)
        );
    }
}

#[test]
fn every_failure_reason_has_one_report_mapping() {
    let mappings = [
        (
            VerificationOutcome::malformed(),
            Decision::Deny,
            ReasonCode::Malformed,
        ),
        (
            VerificationOutcome::denied(DenialReason::ChallengeAuthenticationFailed),
            Decision::Deny,
            ReasonCode::ChallengeAuthenticationFailed,
        ),
        (
            VerificationOutcome::denied(DenialReason::NotYetValid),
            Decision::Deny,
            ReasonCode::NotYetValid,
        ),
        (
            VerificationOutcome::denied(DenialReason::Expired),
            Decision::Deny,
            ReasonCode::Expired,
        ),
        (
            VerificationOutcome::denied(DenialReason::ReplayDetected),
            Decision::Deny,
            ReasonCode::ReplayDetected,
        ),
        (
            VerificationOutcome::denied(DenialReason::ContextBindingMismatch),
            Decision::Deny,
            ReasonCode::ContextBindingMismatch,
        ),
        (
            VerificationOutcome::denied(DenialReason::EvidenceInvalid),
            Decision::Deny,
            ReasonCode::EvidenceInvalid,
        ),
        (
            VerificationOutcome::denied(DenialReason::PolicyDenied),
            Decision::Deny,
            ReasonCode::PolicyDenied,
        ),
        (
            VerificationOutcome::revoked(),
            Decision::Deny,
            ReasonCode::Revoked,
        ),
        (
            VerificationOutcome::denied(DenialReason::ProtectedSessionLost),
            Decision::Deny,
            ReasonCode::ProtectedSessionLost,
        ),
        (
            VerificationOutcome::unsupported(UnsupportedRequirement::VersionOrProfile),
            Decision::Unsupported,
            ReasonCode::UnsupportedVersionOrProfile,
        ),
        (
            VerificationOutcome::unsupported(UnsupportedRequirement::Platform),
            Decision::Unsupported,
            ReasonCode::UnsupportedPlatform,
        ),
        (
            VerificationOutcome::unsupported(UnsupportedRequirement::UnknownCriticalRequirement),
            Decision::Unsupported,
            ReasonCode::UnsupportedCriticalRequirement,
        ),
        (
            VerificationOutcome::retryable(RetryReason::AttestationUnavailable),
            Decision::Retry,
            ReasonCode::AttestationUnavailable,
        ),
        (
            VerificationOutcome::retryable(RetryReason::TransientFailure),
            Decision::Retry,
            ReasonCode::TransientFailure,
        ),
    ];
    assert_eq!(mappings.len(), 15);

    for (outcome, expected_decision, expected_reason) in mappings {
        assert_eq!(outcome.decision(), expected_decision);
        let actual_reason = match outcome.reason() {
            Some(reason) => reason,
            None => panic!("failure report omitted its reason"),
        };
        match actual_reason {
            ReasonCode::Malformed
            | ReasonCode::ChallengeAuthenticationFailed
            | ReasonCode::NotYetValid
            | ReasonCode::Expired
            | ReasonCode::ReplayDetected
            | ReasonCode::ContextBindingMismatch
            | ReasonCode::EvidenceInvalid
            | ReasonCode::PolicyDenied
            | ReasonCode::Revoked
            | ReasonCode::ProtectedSessionLost
            | ReasonCode::UnsupportedVersionOrProfile
            | ReasonCode::UnsupportedPlatform
            | ReasonCode::UnsupportedCriticalRequirement
            | ReasonCode::AttestationUnavailable
            | ReasonCode::TransientFailure => {}
        }
        assert_eq!(actual_reason, expected_reason);
    }
}

fn model_denial_reason(reason: DenialReason) -> ReasonCode {
    match reason {
        DenialReason::ChallengeAuthenticationFailed => ReasonCode::ChallengeAuthenticationFailed,
        DenialReason::NotYetValid => ReasonCode::NotYetValid,
        DenialReason::Expired => ReasonCode::Expired,
        DenialReason::ReplayDetected => ReasonCode::ReplayDetected,
        DenialReason::ContextBindingMismatch => ReasonCode::ContextBindingMismatch,
        DenialReason::EvidenceInvalid => ReasonCode::EvidenceInvalid,
        DenialReason::PolicyDenied => ReasonCode::PolicyDenied,
        DenialReason::ProtectedSessionLost => ReasonCode::ProtectedSessionLost,
    }
}

fn model_unsupported_reason(requirement: UnsupportedRequirement) -> ReasonCode {
    match requirement {
        UnsupportedRequirement::VersionOrProfile => ReasonCode::UnsupportedVersionOrProfile,
        UnsupportedRequirement::Platform => ReasonCode::UnsupportedPlatform,
        UnsupportedRequirement::UnknownCriticalRequirement => {
            ReasonCode::UnsupportedCriticalRequirement
        }
    }
}

fn model_retry_reason(reason: RetryReason) -> ReasonCode {
    match reason {
        RetryReason::AttestationUnavailable => ReasonCode::AttestationUnavailable,
        RetryReason::TransientFailure => ReasonCode::TransientFailure,
    }
}

fn model_report(state: ModelState) -> Option<(Decision, Option<ReasonCode>)> {
    match state {
        ModelState::Verified(AllowedClass::Full) => Some((Decision::Allow, None)),
        ModelState::Verified(AllowedClass::Restricted) => Some((Decision::AllowRestricted, None)),
        ModelState::Malformed => Some((Decision::Deny, Some(ReasonCode::Malformed))),
        ModelState::Unsupported(requirement) => Some((
            Decision::Unsupported,
            Some(model_unsupported_reason(requirement)),
        )),
        ModelState::Retryable(reason) => Some((Decision::Retry, Some(model_retry_reason(reason)))),
        ModelState::Denied(reason) => Some((Decision::Deny, Some(model_denial_reason(reason)))),
        ModelState::Revoked => Some((Decision::Deny, Some(ReasonCode::Revoked))),
        ModelState::EvidenceReceived
        | ModelState::ChallengeAuthenticated
        | ModelState::FreshnessChecked
        | ModelState::IdentityChecked
        | ModelState::EvidenceAppraised
        | ModelState::SessionBound
        | ModelState::RevocationChecked
        | ModelState::PolicySatisfied(_) => None,
    }
}

fn expected_action_result(
    before: &FlowSnapshot,
    next: ModelState,
    action: TestAction,
) -> ActionResult {
    match next {
        ModelState::EvidenceReceived
        | ModelState::ChallengeAuthenticated
        | ModelState::FreshnessChecked
        | ModelState::IdentityChecked
        | ModelState::EvidenceAppraised
        | ModelState::SessionBound
        | ModelState::RevocationChecked
        | ModelState::PolicySatisfied(_) => ActionResult::NoResult,
        ModelState::Verified(allowed) => {
            assert_eq!(action, TestAction::Complete);
            ActionResult::Allow {
                context: before
                    .context
                    .clone()
                    .unwrap_or_else(|| panic!("completion lacked pre-action context")),
                decision: match allowed {
                    AllowedClass::Full => Decision::Allow,
                    AllowedClass::Restricted => Decision::AllowRestricted,
                },
                reason: None,
                allowed,
                accepted_profile: before
                    .accepted_profile
                    .clone()
                    .unwrap_or_else(|| panic!("completion lacked pre-action profile")),
                session_public_key_id: before
                    .session_public_key_id
                    .unwrap_or_else(|| panic!("completion lacked pre-action session key")),
            }
        }
        ModelState::Malformed
        | ModelState::Unsupported(_)
        | ModelState::Retryable(_)
        | ModelState::Denied(_)
        | ModelState::Revoked => {
            let (terminal, decision, reason) = failure_mapping(action);
            assert_eq!(terminal, model_phase(next));
            ActionResult::Failure {
                context: before
                    .context
                    .clone()
                    .unwrap_or_else(|| panic!("failure lacked pre-action context")),
                decision,
                reason: Some(reason),
                view_decision: decision,
                view_reason: reason,
            }
        }
    }
}

fn expected_outcome_diagnostic(state: ModelState) -> Option<String> {
    model_report(state).map(|(decision, reason)| {
        format!("VerificationOutcome {{ decision: {decision:?}, reason: {reason:?} }}")
    })
}

fn expected_flow_diagnostic(state: ModelState) -> String {
    let outcome = match expected_outcome_diagnostic(state) {
        Some(value) => format!("Some({value})"),
        None => String::from("None"),
    };
    format!(
        "VerifierFlow {{ phase: {:?}, outcome: {outcome} }}",
        model_phase(state)
    )
}

fn selected_binding(
    flow: &VerifierFlow,
    other_binding: &VerificationBinding,
    mode: BindingMode,
) -> VerificationBinding {
    match mode {
        BindingMode::Matching => flow.binding.clone(),
        BindingMode::OtherFlow => other_binding.clone(),
    }
}

fn appraisal_action_result(result: AppraisalResult) -> ActionResult {
    let context = result.context().clone();
    let decision = result.decision();
    let reason = result.reason();
    match result.view() {
        AppraisalResultView::Allow(claims) => ActionResult::Allow {
            context,
            decision,
            reason,
            allowed: AllowedClass::Full,
            accepted_profile: claims.accepted_profile().clone(),
            session_public_key_id: *claims.session_public_key_id(),
        },
        AppraisalResultView::AllowRestricted(claims) => ActionResult::Allow {
            context,
            decision,
            reason,
            allowed: AllowedClass::Restricted,
            accepted_profile: claims.accepted_profile().clone(),
            session_public_key_id: *claims.session_public_key_id(),
        },
        AppraisalResultView::Failure {
            decision: view_decision,
            reason: view_reason,
        } => ActionResult::Failure {
            context,
            decision,
            reason,
            view_decision,
            view_reason,
        },
    }
}

fn apply_action(
    flow: &mut VerifierFlow,
    other_binding: &VerificationBinding,
    action: TestAction,
) -> Result<ActionResult, TransitionError> {
    match action {
        TestAction::Challenge(mode) => {
            let binding = selected_binding(flow, other_binding, mode);
            flow.record_challenge_authenticated(ChallengeAuthenticated { binding })?;
            Ok(ActionResult::NoResult)
        }
        TestAction::Freshness(mode) => {
            let binding = selected_binding(flow, other_binding, mode);
            flow.record_freshness_checked(crate::freshness::test_freshness_checked(binding))?;
            Ok(ActionResult::NoResult)
        }
        TestAction::Identity(mode) => {
            let binding = selected_binding(flow, other_binding, mode);
            flow.record_identity_checked(IdentityChecked { binding })?;
            Ok(ActionResult::NoResult)
        }
        TestAction::Evidence(mode) => {
            let binding = selected_binding(flow, other_binding, mode);
            let accepted_profile = match mode {
                BindingMode::Matching => accepted_profile(),
                BindingMode::OtherFlow => identifier("other-flow-profile"),
            };
            flow.record_evidence_appraised(EvidenceAppraised {
                binding,
                accepted_profile,
            })?;
            Ok(ActionResult::NoResult)
        }
        TestAction::Session(mode) => {
            let binding = selected_binding(flow, other_binding, mode);
            let session_public_key_id = match mode {
                BindingMode::Matching => session_key_id(7),
                BindingMode::OtherFlow => session_key_id(251),
            };
            flow.record_session_bound(SessionBound {
                binding,
                session_public_key_id,
            })?;
            Ok(ActionResult::NoResult)
        }
        TestAction::Revocation(mode) => {
            let binding = selected_binding(flow, other_binding, mode);
            flow.record_revocation_checked(RevocationChecked { binding })?;
            Ok(ActionResult::NoResult)
        }
        TestAction::Policy(allowed, mode) => {
            let binding = selected_binding(flow, other_binding, mode);
            flow.record_policy_satisfied(PolicySatisfied { binding, allowed })?;
            Ok(ActionResult::NoResult)
        }
        TestAction::Complete => {
            let verified = flow.complete()?;
            Ok(appraisal_action_result(verified.into_appraisal_result()))
        }
        TestAction::MarkMalformed => {
            let result = flow.mark_malformed()?;
            Ok(appraisal_action_result(result))
        }
        TestAction::MarkUnsupported(requirement) => {
            let result = flow.mark_unsupported(requirement)?;
            Ok(appraisal_action_result(result))
        }
        TestAction::MarkRetryable(retry_reason) => {
            let result = flow.mark_retryable(retry_reason)?;
            Ok(appraisal_action_result(result))
        }
        TestAction::Deny(reason) => {
            let result = flow.deny(reason)?;
            Ok(appraisal_action_result(result))
        }
        TestAction::MarkRevoked => {
            let result = flow.mark_revoked()?;
            Ok(appraisal_action_result(result))
        }
    }
}

fn advance_flow_to_model_state(
    mut flow: VerifierFlow,
    state: ModelState,
    other_binding: &VerificationBinding,
) -> VerifierFlow {
    match state {
        ModelState::Malformed => {
            match flow.mark_malformed() {
                Ok(value) => drop(value),
                Err(error) => panic!("malformed fixture rejected: {error:?}"),
            }
            return flow;
        }
        ModelState::Unsupported(requirement) => {
            let gate_count = match requirement {
                UnsupportedRequirement::VersionOrProfile => 1,
                UnsupportedRequirement::Platform => 3,
                UnsupportedRequirement::UnknownCriticalRequirement => 0,
            };
            for gate in ALL_7_GATE_KINDS.into_iter().take(gate_count) {
                assert_eq!(
                    apply_action(
                        &mut flow,
                        other_binding,
                        gate.matching_action(AllowedClass::Full),
                    ),
                    Ok(ActionResult::NoResult)
                );
            }
            match flow.mark_unsupported(requirement) {
                Ok(value) => drop(value),
                Err(error) => panic!("unsupported fixture rejected: {error:?}"),
            }
            return flow;
        }
        ModelState::Retryable(reason) => {
            match flow.mark_retryable(reason) {
                Ok(value) => drop(value),
                Err(error) => panic!("retryable fixture rejected: {error:?}"),
            }
            return flow;
        }
        ModelState::Denied(reason) => {
            let gate_count = match reason {
                DenialReason::ChallengeAuthenticationFailed => 0,
                DenialReason::NotYetValid
                | DenialReason::Expired
                | DenialReason::ReplayDetected
                | DenialReason::ContextBindingMismatch => 1,
                DenialReason::EvidenceInvalid => 3,
                DenialReason::PolicyDenied => 6,
                DenialReason::ProtectedSessionLost => 4,
            };
            for gate in ALL_7_GATE_KINDS.into_iter().take(gate_count) {
                assert_eq!(
                    apply_action(
                        &mut flow,
                        other_binding,
                        gate.matching_action(AllowedClass::Full),
                    ),
                    Ok(ActionResult::NoResult)
                );
            }
            match flow.deny(reason) {
                Ok(value) => drop(value),
                Err(error) => panic!("denied fixture rejected: {error:?}"),
            }
            return flow;
        }
        ModelState::Revoked => {
            for gate in ALL_7_GATE_KINDS.into_iter().take(5) {
                assert_eq!(
                    apply_action(
                        &mut flow,
                        other_binding,
                        gate.matching_action(AllowedClass::Full),
                    ),
                    Ok(ActionResult::NoResult)
                );
            }
            match flow.mark_revoked() {
                Ok(value) => drop(value),
                Err(error) => panic!("revoked fixture rejected: {error:?}"),
            }
            return flow;
        }
        ModelState::EvidenceReceived
        | ModelState::ChallengeAuthenticated
        | ModelState::FreshnessChecked
        | ModelState::IdentityChecked
        | ModelState::EvidenceAppraised
        | ModelState::SessionBound
        | ModelState::RevocationChecked
        | ModelState::PolicySatisfied(_)
        | ModelState::Verified(_) => {}
    }

    let (gate_count, allowed, should_complete) = match state {
        ModelState::EvidenceReceived => (0, AllowedClass::Full, false),
        ModelState::ChallengeAuthenticated => (1, AllowedClass::Full, false),
        ModelState::FreshnessChecked => (2, AllowedClass::Full, false),
        ModelState::IdentityChecked => (3, AllowedClass::Full, false),
        ModelState::EvidenceAppraised => (4, AllowedClass::Full, false),
        ModelState::SessionBound => (5, AllowedClass::Full, false),
        ModelState::RevocationChecked => (6, AllowedClass::Full, false),
        ModelState::PolicySatisfied(allowed) => (7, allowed, false),
        ModelState::Verified(allowed) => (7, allowed, true),
        ModelState::Malformed
        | ModelState::Unsupported(_)
        | ModelState::Retryable(_)
        | ModelState::Denied(_)
        | ModelState::Revoked => unreachable!("failure states returned above"),
    };
    for gate in ALL_7_GATE_KINDS.into_iter().take(gate_count) {
        let action = gate.matching_action(allowed);
        assert_eq!(action.public(), gate.action());
        assert_eq!(
            apply_action(&mut flow, other_binding, action),
            Ok(ActionResult::NoResult)
        );
    }
    if should_complete {
        let before = flow_snapshot(&flow);
        assert_eq!(
            apply_action(&mut flow, other_binding, TestAction::Complete),
            Ok(expected_action_result(
                &before,
                ModelState::Verified(allowed),
                TestAction::Complete,
            ))
        );
    }
    flow
}

fn flow_for_model_state(state: ModelState, seed: u8) -> VerifierFlow {
    let flow = flow_fixture(seed);
    let other_binding = flow_fixture(seed.wrapping_add(1)).binding;
    advance_flow_to_model_state(flow, state, &other_binding)
}

fn assert_flow_matches_model(flow: &VerifierFlow, state: ModelState) {
    assert_eq!(flow.phase(), model_phase(state));
    assert_eq!(
        flow.outcome()
            .map(|outcome| (outcome.decision(), outcome.reason())),
        model_report(state)
    );
    let snapshot = flow_snapshot(flow);
    assert_eq!(snapshot.has_request, model_is_nonterminal(state));
    assert_eq!(snapshot.has_profile, model_has_profile(state));
    assert_eq!(snapshot.has_session_key, model_has_session_key(state));
    assert_eq!(snapshot.has_allowed_class, model_has_allowed_class(state));
}

fn expected_success_snapshot(
    before: &FlowSnapshot,
    next: ModelState,
    action: TestAction,
) -> FlowSnapshot {
    let mut expected = before.clone();
    expected.phase = model_phase(next);
    expected.outcome =
        model_report(next).map(|(decision, reason)| VerificationOutcome { decision, reason });

    if model_is_terminal(next) {
        expected.request = None;
        expected.context = None;
        expected.accepted_profile = None;
        expected.session_public_key_id = None;
        expected.allowed = None;
    } else {
        match action {
            TestAction::Evidence(BindingMode::Matching) => {
                expected.accepted_profile = Some(accepted_profile());
            }
            TestAction::Session(BindingMode::Matching) => {
                expected.session_public_key_id = Some(session_key_id(7));
            }
            TestAction::Policy(allowed, BindingMode::Matching) => {
                expected.allowed = Some(allowed);
            }
            TestAction::Challenge(BindingMode::Matching)
            | TestAction::Freshness(BindingMode::Matching)
            | TestAction::Identity(BindingMode::Matching)
            | TestAction::Revocation(BindingMode::Matching) => {}
            TestAction::Challenge(BindingMode::OtherFlow)
            | TestAction::Freshness(BindingMode::OtherFlow)
            | TestAction::Identity(BindingMode::OtherFlow)
            | TestAction::Evidence(BindingMode::OtherFlow)
            | TestAction::Session(BindingMode::OtherFlow)
            | TestAction::Revocation(BindingMode::OtherFlow)
            | TestAction::Policy(_, BindingMode::OtherFlow)
            | TestAction::Complete
            | TestAction::MarkMalformed
            | TestAction::MarkUnsupported(_)
            | TestAction::MarkRetryable(_)
            | TestAction::Deny(_)
            | TestAction::MarkRevoked => {
                panic!("non-active-success action produced active state: {action:?} {next:?}")
            }
        }
    }

    expected.has_request = expected.request.is_some();
    expected.has_profile = expected.accepted_profile.is_some();
    expected.has_session_key = expected.session_public_key_id.is_some();
    expected.has_allowed_class = expected.allowed.is_some();
    expected
}

fn equal_flows_at_gate(gate: GateKind, seed: u8) -> (VerifierFlow, VerifierFlow) {
    let request = request_fixture(seed);
    let equal_request = request.clone();
    assert_eq!(request, equal_request);
    let mut source = VerifierFlow::begin(request);
    let mut target = VerifierFlow::begin(equal_request);
    assert_eq!(
        flow_snapshot(&source).request,
        flow_snapshot(&target).request
    );
    assert!(!source.binding.matches(&target.binding));

    let prefix_length = match gate {
        GateKind::Challenge => 0,
        GateKind::Freshness => 1,
        GateKind::Identity => 2,
        GateKind::Evidence => 3,
        GateKind::Session => 4,
        GateKind::Revocation => 5,
        GateKind::Policy => 6,
    };
    for prefix_gate in ALL_7_GATE_KINDS.into_iter().take(prefix_length) {
        let action = prefix_gate.matching_action(AllowedClass::Full);
        assert_eq!(
            apply_action(&mut source, &target.binding.clone(), action),
            Ok(ActionResult::NoResult)
        );
        assert_eq!(
            apply_action(&mut target, &source.binding.clone(), action),
            Ok(ActionResult::NoResult)
        );
    }
    assert_eq!(source.phase(), gate.required_phase());
    assert_eq!(target.phase(), gate.required_phase());
    assert_eq!(flow_snapshot(&source), flow_snapshot(&target));
    (source, target)
}

fn apply_capability_from_other_flow(
    gate: GateKind,
    source: &VerifierFlow,
    target: &mut VerifierFlow,
) -> Result<(), TransitionError> {
    let binding = source.binding.clone();
    match gate {
        GateKind::Challenge => {
            target.record_challenge_authenticated(ChallengeAuthenticated { binding })
        }
        GateKind::Freshness => {
            target.record_freshness_checked(crate::freshness::test_freshness_checked(binding))
        }
        GateKind::Identity => target.record_identity_checked(IdentityChecked { binding }),
        GateKind::Evidence => target.record_evidence_appraised(EvidenceAppraised {
            binding,
            accepted_profile: accepted_profile(),
        }),
        GateKind::Session => target.record_session_bound(SessionBound {
            binding,
            session_public_key_id: session_key_id(7),
        }),
        GateKind::Revocation => target.record_revocation_checked(RevocationChecked { binding }),
        GateKind::Policy => target.record_policy_satisfied(PolicySatisfied {
            binding,
            allowed: AllowedClass::Full,
        }),
    }
}

fn flow_with_private_sentinels() -> VerifierFlow {
    let maximum = match NonZeroU64::new(100) {
        Some(value) => ChallengeLifetime::new(value),
        None => panic!("fixture maximum must be nonzero"),
    };
    let window = match ChallengeWindow::new(UnixTime::new(4_242), UnixTime::new(4_342), maximum) {
        Ok(value) => value,
        Err(error) => panic!("valid private window rejected: {error:?}"),
    };
    VerifierFlow::begin(VerificationRequest {
        challenge: PublisherChallenge {
            version: ProtocolVersion { major: 0, minor: 1 },
            publisher_id: identifier::<PublisherId>("private.publisher"),
            game_id: identifier::<GameId>("private.game"),
            build_id: identifier::<BuildId>("private-build"),
            account_scope: identifier::<AccountScope>("private-account"),
            match_id: identifier::<MatchId>("private-match"),
            policy_id: identifier::<PolicyId>("private-policy"),
            policy_version: PolicyVersion::new(1),
            nonce: Nonce::from_bytes([0xA5; 32]),
            window,
        },
        evidence: EvidenceBundle {
            profile_id: identifier::<EvidenceProfile>("private-profile"),
            payload: b"private-evidence-payload".to_vec(),
        },
        expected: ExpectedContext {
            publisher_id: identifier::<PublisherId>("private.publisher"),
            game_id: identifier::<GameId>("private.game"),
            build_id: identifier::<BuildId>("private-build"),
            account_scope: identifier::<AccountScope>("private-account"),
            match_id: identifier::<MatchId>("private-match"),
            policy_id: identifier::<PolicyId>("private-policy"),
            policy_version: PolicyVersion::new(3_141_592_653),
        },
        now: UnixTime::new(4_243),
    })
}

fn private_flow_for_model_state(state: ModelState) -> VerifierFlow {
    let flow = flow_with_private_sentinels();
    let other_binding = flow_fixture(86).binding;
    advance_flow_to_model_state(flow, state, &other_binding)
}

fn push_result_diagnostics(result: &AppraisalResult, diagnostics: &mut Vec<String>) {
    let diagnostic = format!("{result:?}");
    assert_eq!(diagnostic, "AppraisalResult([REDACTED])");
    diagnostics.push(diagnostic);

    let view = result.view();
    let diagnostic = format!("{view:?}");
    assert_eq!(diagnostic, "AppraisalResultView([REDACTED])");
    diagnostics.push(diagnostic);

    if let AppraisalResultView::Allow(claims) | AppraisalResultView::AllowRestricted(claims) = view
    {
        let diagnostic = format!("{claims:?}");
        assert_eq!(diagnostic, "AcceptedClaims([REDACTED])");
        diagnostics.push(diagnostic);
    }
}

fn diagnostics_for_every_surface(flow: &mut VerifierFlow) -> Vec<String> {
    let mut diagnostics = Vec::new();
    let binding = flow.binding.clone();

    let binding_diagnostic = format!("{binding:?}");
    assert!(
        binding_diagnostic == "VerificationBinding([REDACTED])",
        "private diagnostic mismatch"
    );
    diagnostics.push(binding_diagnostic);

    let challenge = ChallengeAuthenticated {
        binding: binding.clone(),
    };
    let diagnostic = format!("{challenge:?}");
    assert!(
        diagnostic == "ChallengeAuthenticated([REDACTED])",
        "private diagnostic mismatch"
    );
    diagnostics.push(diagnostic);

    let freshness = crate::freshness::test_freshness_checked(binding.clone());
    let diagnostic = format!("{freshness:?}");
    assert!(
        diagnostic == "FreshnessChecked([REDACTED])",
        "private diagnostic mismatch"
    );
    diagnostics.push(diagnostic);

    let identity = IdentityChecked {
        binding: binding.clone(),
    };
    let diagnostic = format!("{identity:?}");
    assert!(
        diagnostic == "IdentityChecked([REDACTED])",
        "private diagnostic mismatch"
    );
    diagnostics.push(diagnostic);

    let evidence = EvidenceAppraised {
        binding: binding.clone(),
        accepted_profile: identifier("private-accepted-profile"),
    };
    let diagnostic = format!("{evidence:?}");
    assert!(
        diagnostic == "EvidenceAppraised([REDACTED])",
        "private diagnostic mismatch"
    );
    diagnostics.push(diagnostic);

    let session = SessionBound {
        binding: binding.clone(),
        session_public_key_id: session_key_id(0xA5),
    };
    let diagnostic = format!("{session:?}");
    assert!(
        diagnostic == "SessionBound([REDACTED])",
        "private diagnostic mismatch"
    );
    diagnostics.push(diagnostic);

    let revocation = RevocationChecked {
        binding: binding.clone(),
    };
    let diagnostic = format!("{revocation:?}");
    assert!(
        diagnostic == "RevocationChecked([REDACTED])",
        "private diagnostic mismatch"
    );
    diagnostics.push(diagnostic);

    let policy = PolicySatisfied {
        binding: binding.clone(),
        allowed: AllowedClass::Full,
    };
    let diagnostic = format!("{policy:?}");
    assert!(
        diagnostic == "PolicySatisfied([REDACTED])",
        "private diagnostic mismatch"
    );
    diagnostics.push(diagnostic);

    let private_context = match &flow.state {
        VerificationState::EvidenceReceived { request } => request.expected.clone(),
        _ => panic!("sentinel flow unexpectedly left its initial active state"),
    };
    let verified = VerifiedAttestation {
        binding,
        context: private_context.clone(),
        accepted_profile: identifier("private-accepted-profile"),
        session_public_key_id: SessionPublicKeyId::from_bytes([0xD7; 32]),
        allowed: AllowedClass::Full,
    };
    let diagnostic = format!("{verified:?}");
    assert!(
        diagnostic == "VerifiedAttestation([REDACTED])",
        "private diagnostic mismatch"
    );
    diagnostics.push(diagnostic);

    let full = verified.into_appraisal_result();
    push_result_diagnostics(&full, &mut diagnostics);
    let restricted = AppraisalResult {
        context: private_context.clone(),
        payload: AppraisalPayload::AllowRestricted(AcceptedClaims {
            accepted_profile: identifier("private-accepted-profile"),
            session_public_key_id: SessionPublicKeyId::from_bytes([0xD7; 32]),
        }),
    };
    push_result_diagnostics(&restricted, &mut diagnostics);
    let failure = AppraisalResult {
        context: private_context,
        payload: AppraisalPayload::Failure(FailurePayload {
            decision: FailureDecision::Deny,
            reason: ReasonCode::EvidenceInvalid,
        }),
    };
    push_result_diagnostics(&failure, &mut diagnostics);

    let request = match &flow.state {
        VerificationState::EvidenceReceived { request } => request,
        _ => panic!("sentinel flow unexpectedly left its initial active state"),
    };
    let diagnostic = format!("{request:?}");
    assert!(
        diagnostic == "VerificationRequest([REDACTED])",
        "private diagnostic mismatch"
    );
    diagnostics.push(diagnostic);
    let diagnostic = format!("{:?}", request.expected);
    assert!(
        diagnostic == "ExpectedContext([REDACTED])",
        "private diagnostic mismatch"
    );
    diagnostics.push(diagnostic);
    let diagnostic = format!("{:?}", request.evidence);
    assert!(
        diagnostic == "EvidenceBundle([REDACTED])",
        "private diagnostic mismatch"
    );
    diagnostics.push(diagnostic);

    let invalid = TransitionError::InvalidTransition {
        phase: VerificationPhase::EvidenceReceived,
        action: VerificationAction::Complete,
    };
    let diagnostic = invalid.to_string();
    assert_eq!(diagnostic, "verifier transition is not allowed");
    diagnostics.push(diagnostic);
    let diagnostic = format!("{invalid:?}");
    assert_eq!(diagnostic, "TransitionError::InvalidTransition([REDACTED])");
    diagnostics.push(diagnostic);
    let rejected = TransitionError::CapabilityRejected {
        action: VerificationAction::RecordChallengeAuthenticated,
    };
    let diagnostic = rejected.to_string();
    assert_eq!(diagnostic, "verifier capability was rejected");
    diagnostics.push(diagnostic);
    let diagnostic = format!("{rejected:?}");
    assert_eq!(
        diagnostic,
        "TransitionError::CapabilityRejected([REDACTED])"
    );
    diagnostics.push(diagnostic);

    let diagnostic = format!("{flow:?}");
    assert!(
        diagnostic == "VerifierFlow { phase: EvidenceReceived, outcome: None }",
        "private diagnostic mismatch"
    );
    diagnostics.push(diagnostic);

    for state in ALL_14_MODEL_STATES {
        let state_flow = private_flow_for_model_state(state);
        let diagnostic = format!("{state_flow:?}");
        assert!(
            diagnostic == expected_flow_diagnostic(state),
            "private diagnostic mismatch"
        );
        diagnostics.push(diagnostic);
    }

    for state in [
        ModelState::Verified(AllowedClass::Full),
        ModelState::Verified(AllowedClass::Restricted),
        ModelState::Malformed,
        ModelState::Unsupported(UnsupportedRequirement::Platform),
        ModelState::Unsupported(UnsupportedRequirement::UnknownCriticalRequirement),
        ModelState::Retryable(RetryReason::TransientFailure),
        ModelState::Denied(DenialReason::ChallengeAuthenticationFailed),
        ModelState::Denied(DenialReason::NotYetValid),
        ModelState::Denied(DenialReason::Expired),
        ModelState::Denied(DenialReason::ReplayDetected),
        ModelState::Denied(DenialReason::ContextBindingMismatch),
        ModelState::Denied(DenialReason::EvidenceInvalid),
        ModelState::Denied(DenialReason::PolicyDenied),
        ModelState::Denied(DenialReason::ProtectedSessionLost),
        ModelState::Revoked,
    ] {
        let outcome_flow = flow_for_model_state(state, 85);
        let outcome = match outcome_flow.outcome() {
            Some(value) => value,
            None => panic!("terminal model state produced no report: {state:?}"),
        };
        let diagnostic = format!("{outcome:?}");
        let expected = match expected_outcome_diagnostic(state) {
            Some(value) => value,
            None => panic!("terminal model state lacked expected report: {state:?}"),
        };
        assert_eq!(diagnostic, expected);
        diagnostics.push(diagnostic);
    }

    diagnostics
}

fn assert_every_action_rejected(flow: &mut VerifierFlow) {
    let other_binding = flow_fixture(250).binding;
    let current_phase = flow.phase();
    for action in ALL_24_MATRIX_ACTIONS {
        let before = flow_snapshot(flow);
        assert_eq!(
            apply_action(flow, &other_binding, action),
            Err(TransitionError::InvalidTransition {
                phase: current_phase,
                action: action.public(),
            })
        );
        assert_eq!(flow_snapshot(flow), before);
    }
}

fn permute_gates(gates: &mut [GateKind], start: usize, visit: &mut impl FnMut(&[GateKind])) {
    if start == gates.len() {
        visit(gates);
        return;
    }
    for index in start..gates.len() {
        gates.swap(start, index);
        permute_gates(gates, start + 1, visit);
        gates.swap(start, index);
    }
}

const TOTAL_ACTIONS: usize = 1_048_576;
const SCHEDULED_ACTIONS: usize = 2_048;
const ARBITRARY_ACTIONS: usize = 1_046_528;
const CANONICAL_COMPLETION_ACTIONS: usize = 256;
const ACTIVE_PAIR_ACTIONS: usize = 864;
const TERMINAL_PAIR_ACTIONS: usize = 576;
const CROSS_FLOW_ACTIONS: usize = 35;
const EXTRA_COMPLETION_ACTIONS: usize = 312;
const FILLER_ACTIONS: usize = 5;
const MIN_FULL_COMPLETIONS: usize = 61;
const MIN_RESTRICTED_COMPLETIONS: usize = 35;
const ARBITRARY_MATCHING_GATES: usize = 175_120;
const ARBITRARY_OTHER_FLOW_GATES: usize = 174_585;
const ARBITRARY_ACTIVE_ADVANCES: usize = 21_965;

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        self.0
    }

    fn action(&mut self) -> TestAction {
        let action_index = ((self.next() >> 32) % 24) as usize;
        let selector = self.next();
        arbitrary_action_from_index(action_index, selector)
    }
}

fn seed_for_index(index: usize) -> u8 {
    (index % 200) as u8 + 1
}

fn arbitrary_action_from_index(index: usize, selector: u64) -> TestAction {
    // Bit 32 of the second draw is not parity-locked by the two-draw LCG cadence.
    let mode = if selector & (1 << 32) == 0 {
        BindingMode::Matching
    } else {
        BindingMode::OtherFlow
    };
    match index {
        0 => TestAction::Challenge(mode),
        1 => TestAction::Freshness(mode),
        2 => TestAction::Identity(mode),
        3 => TestAction::Evidence(mode),
        4 => TestAction::Session(mode),
        5 => TestAction::Revocation(mode),
        6 => TestAction::Policy(AllowedClass::Full, mode),
        7 => TestAction::Policy(AllowedClass::Restricted, mode),
        8 => TestAction::Complete,
        9 => TestAction::MarkMalformed,
        10 => TestAction::MarkUnsupported(UnsupportedRequirement::VersionOrProfile),
        11 => TestAction::MarkUnsupported(UnsupportedRequirement::Platform),
        12 => TestAction::MarkUnsupported(UnsupportedRequirement::UnknownCriticalRequirement),
        13 => TestAction::MarkRetryable(RetryReason::AttestationUnavailable),
        14 => TestAction::MarkRetryable(RetryReason::TransientFailure),
        15 => TestAction::Deny(DenialReason::ChallengeAuthenticationFailed),
        16 => TestAction::Deny(DenialReason::NotYetValid),
        17 => TestAction::Deny(DenialReason::Expired),
        18 => TestAction::Deny(DenialReason::ReplayDetected),
        19 => TestAction::Deny(DenialReason::ContextBindingMismatch),
        20 => TestAction::Deny(DenialReason::EvidenceInvalid),
        21 => TestAction::Deny(DenialReason::PolicyDenied),
        22 => TestAction::Deny(DenialReason::ProtectedSessionLost),
        23 => TestAction::MarkRevoked,
        _ => panic!("arbitrary action index outside fixed domain: {index}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScheduledStep {
    reset_before: bool,
    action: TestAction,
}

fn push_sequence(schedule: &mut Vec<ScheduledStep>, actions: &[TestAction]) {
    for (index, action) in actions.iter().copied().enumerate() {
        schedule.push(ScheduledStep {
            reset_before: index == 0,
            action,
        });
    }
}

const MATCHING_GATE_PREFIX: [TestAction; 7] = [
    TestAction::Challenge(BindingMode::Matching),
    TestAction::Freshness(BindingMode::Matching),
    TestAction::Identity(BindingMode::Matching),
    TestAction::Evidence(BindingMode::Matching),
    TestAction::Session(BindingMode::Matching),
    TestAction::Revocation(BindingMode::Matching),
    TestAction::Policy(AllowedClass::Full, BindingMode::Matching),
];

fn canonical_completion(allowed: AllowedClass) -> [TestAction; 8] {
    let mut actions = [TestAction::Complete; 8];
    actions[..6].copy_from_slice(&MATCHING_GATE_PREFIX[..6]);
    actions[6] = TestAction::Policy(allowed, BindingMode::Matching);
    actions[7] = TestAction::Complete;
    actions
}

fn scheduled_actions() -> Vec<ScheduledStep> {
    let mut schedule = Vec::with_capacity(SCHEDULED_ACTIONS);
    let mut named_full = 0usize;
    let mut named_restricted = 0usize;
    for _ in 0..16 {
        push_sequence(&mut schedule, &canonical_completion(AllowedClass::Full));
        named_full += 1;
        push_sequence(
            &mut schedule,
            &canonical_completion(AllowedClass::Restricted),
        );
        named_restricted += 1;
    }
    assert_eq!(named_full, 16);
    assert_eq!(named_restricted, 16);
    assert_eq!(schedule.len(), CANONICAL_COMPLETION_ACTIONS);

    let active_start = schedule.len();
    for phase_index in 0..8 {
        for action in ALL_24_MATRIX_ACTIONS {
            let mut sequence = MATCHING_GATE_PREFIX[..phase_index].to_vec();
            sequence.push(action);
            push_sequence(&mut schedule, &sequence);
        }
    }
    assert_eq!(schedule.len() - active_start, ACTIVE_PAIR_ACTIONS);

    let terminal_start = schedule.len();
    for attempted in ALL_24_MATRIX_ACTIONS {
        let mut verified = canonical_completion(AllowedClass::Full).to_vec();
        verified.push(attempted);
        push_sequence(&mut schedule, &verified);
        push_sequence(&mut schedule, &[TestAction::MarkMalformed, attempted]);
        push_sequence(
            &mut schedule,
            &[
                TestAction::MarkUnsupported(UnsupportedRequirement::UnknownCriticalRequirement),
                attempted,
            ],
        );
        push_sequence(
            &mut schedule,
            &[
                TestAction::MarkRetryable(RetryReason::AttestationUnavailable),
                attempted,
            ],
        );
        push_sequence(
            &mut schedule,
            &[
                TestAction::Deny(DenialReason::ChallengeAuthenticationFailed),
                attempted,
            ],
        );
        let mut revoked = MATCHING_GATE_PREFIX[..5].to_vec();
        revoked.push(TestAction::MarkRevoked);
        revoked.push(attempted);
        push_sequence(&mut schedule, &revoked);
    }
    assert_eq!(schedule.len() - terminal_start, TERMINAL_PAIR_ACTIONS);

    let cross_flow_start = schedule.len();
    let mut cross_flow_sequences = 0usize;
    for (gate_index, gate) in ALL_7_GATE_KINDS.into_iter().enumerate() {
        let mut sequence = MATCHING_GATE_PREFIX[..gate_index].to_vec();
        let mismatched = match gate {
            GateKind::Challenge => TestAction::Challenge(BindingMode::OtherFlow),
            GateKind::Freshness => TestAction::Freshness(BindingMode::OtherFlow),
            GateKind::Identity => TestAction::Identity(BindingMode::OtherFlow),
            GateKind::Evidence => TestAction::Evidence(BindingMode::OtherFlow),
            GateKind::Session => TestAction::Session(BindingMode::OtherFlow),
            GateKind::Revocation => TestAction::Revocation(BindingMode::OtherFlow),
            GateKind::Policy => TestAction::Policy(AllowedClass::Full, BindingMode::OtherFlow),
        };
        sequence.push(mismatched);
        sequence.push(TestAction::MarkRetryable(RetryReason::TransientFailure));
        push_sequence(&mut schedule, &sequence);
        cross_flow_sequences += 1;
    }
    assert_eq!(cross_flow_sequences, 7);
    assert_eq!(schedule.len() - cross_flow_start, CROSS_FLOW_ACTIONS);

    let extra_start = schedule.len();
    let mut extra_completions = 0usize;
    while extra_completions < 39 {
        let allowed = if extra_completions.is_multiple_of(2) {
            AllowedClass::Full
        } else {
            AllowedClass::Restricted
        };
        push_sequence(&mut schedule, &canonical_completion(allowed));
        extra_completions += 1;
    }
    assert_eq!(extra_completions, 39);
    assert_eq!(schedule.len() - extra_start, EXTRA_COMPLETION_ACTIONS);

    let filler_start = schedule.len();
    let mut filler_sequences = 0usize;
    while filler_sequences < 5 {
        push_sequence(&mut schedule, &[TestAction::MarkMalformed]);
        filler_sequences += 1;
    }
    assert_eq!(filler_sequences, 5);
    assert_eq!(schedule.len() - filler_start, FILLER_ACTIONS);
    assert_eq!(
        CANONICAL_COMPLETION_ACTIONS
            + ACTIVE_PAIR_ACTIONS
            + TERMINAL_PAIR_ACTIONS
            + CROSS_FLOW_ACTIONS
            + EXTRA_COMPLETION_ACTIONS
            + FILLER_ACTIONS,
        SCHEDULED_ACTIONS
    );
    assert_eq!(schedule.len(), SCHEDULED_ACTIONS);
    schedule
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedAction {
    Allowed(ModelState),
    InvalidTransition,
    CapabilityRejected,
}

fn model_is_terminal(state: ModelState) -> bool {
    !model_is_nonterminal(state)
}

fn expected_history_action(state: ModelState, action: TestAction) -> ExpectedAction {
    if let Some(next) = model_transition(state, action) {
        return ExpectedAction::Allowed(next);
    }
    if action.binding_mode() == Some(BindingMode::OtherFlow)
        && action.required_phase() == Some(model_phase(state))
    {
        return ExpectedAction::CapabilityRejected;
    }
    ExpectedAction::InvalidTransition
}

fn nonterminal_index(state: ModelState) -> Option<usize> {
    match state {
        ModelState::EvidenceReceived => Some(0),
        ModelState::ChallengeAuthenticated => Some(1),
        ModelState::FreshnessChecked => Some(2),
        ModelState::IdentityChecked => Some(3),
        ModelState::EvidenceAppraised => Some(4),
        ModelState::SessionBound => Some(5),
        ModelState::RevocationChecked => Some(6),
        ModelState::PolicySatisfied(_) => Some(7),
        ModelState::Verified(_)
        | ModelState::Malformed
        | ModelState::Unsupported(_)
        | ModelState::Retryable(_)
        | ModelState::Denied(_)
        | ModelState::Revoked => None,
    }
}

fn terminal_index(state: ModelState) -> Option<usize> {
    match state {
        ModelState::Verified(_) => Some(0),
        ModelState::Malformed => Some(1),
        ModelState::Unsupported(_) => Some(2),
        ModelState::Retryable(_) => Some(3),
        ModelState::Denied(_) => Some(4),
        ModelState::Revoked => Some(5),
        ModelState::EvidenceReceived
        | ModelState::ChallengeAuthenticated
        | ModelState::FreshnessChecked
        | ModelState::IdentityChecked
        | ModelState::EvidenceAppraised
        | ModelState::SessionBound
        | ModelState::RevocationChecked
        | ModelState::PolicySatisfied(_) => None,
    }
}

fn failure_index(action: TestAction) -> Option<usize> {
    match action {
        TestAction::MarkMalformed => Some(0),
        TestAction::MarkUnsupported(UnsupportedRequirement::VersionOrProfile) => Some(1),
        TestAction::MarkUnsupported(UnsupportedRequirement::Platform) => Some(2),
        TestAction::MarkUnsupported(UnsupportedRequirement::UnknownCriticalRequirement) => Some(3),
        TestAction::MarkRetryable(RetryReason::AttestationUnavailable) => Some(4),
        TestAction::MarkRetryable(RetryReason::TransientFailure) => Some(5),
        TestAction::Deny(DenialReason::ChallengeAuthenticationFailed) => Some(6),
        TestAction::Deny(DenialReason::NotYetValid) => Some(7),
        TestAction::Deny(DenialReason::Expired) => Some(8),
        TestAction::Deny(DenialReason::ReplayDetected) => Some(9),
        TestAction::Deny(DenialReason::ContextBindingMismatch) => Some(10),
        TestAction::Deny(DenialReason::EvidenceInvalid) => Some(11),
        TestAction::Deny(DenialReason::PolicyDenied) => Some(12),
        TestAction::Deny(DenialReason::ProtectedSessionLost) => Some(13),
        TestAction::MarkRevoked => Some(14),
        TestAction::Challenge(_)
        | TestAction::Freshness(_)
        | TestAction::Identity(_)
        | TestAction::Evidence(_)
        | TestAction::Session(_)
        | TestAction::Revocation(_)
        | TestAction::Policy(_, _)
        | TestAction::Complete => None,
    }
}

fn gate_index(action: TestAction) -> Option<usize> {
    match action {
        TestAction::Challenge(_) => Some(0),
        TestAction::Freshness(_) => Some(1),
        TestAction::Identity(_) => Some(2),
        TestAction::Evidence(_) => Some(3),
        TestAction::Session(_) => Some(4),
        TestAction::Revocation(_) => Some(5),
        TestAction::Policy(_, _) => Some(6),
        TestAction::Complete
        | TestAction::MarkMalformed
        | TestAction::MarkUnsupported(_)
        | TestAction::MarkRetryable(_)
        | TestAction::Deny(_)
        | TestAction::MarkRevoked => None,
    }
}

fn action_index(action: TestAction) -> usize {
    match action {
        TestAction::Challenge(_) => 0,
        TestAction::Freshness(_) => 1,
        TestAction::Identity(_) => 2,
        TestAction::Evidence(_) => 3,
        TestAction::Session(_) => 4,
        TestAction::Revocation(_) => 5,
        TestAction::Policy(AllowedClass::Full, _) => 6,
        TestAction::Policy(AllowedClass::Restricted, _) => 7,
        TestAction::Complete => 8,
        TestAction::MarkMalformed => 9,
        TestAction::MarkUnsupported(UnsupportedRequirement::VersionOrProfile) => 10,
        TestAction::MarkUnsupported(UnsupportedRequirement::Platform) => 11,
        TestAction::MarkUnsupported(UnsupportedRequirement::UnknownCriticalRequirement) => 12,
        TestAction::MarkRetryable(RetryReason::AttestationUnavailable) => 13,
        TestAction::MarkRetryable(RetryReason::TransientFailure) => 14,
        TestAction::Deny(DenialReason::ChallengeAuthenticationFailed) => 15,
        TestAction::Deny(DenialReason::NotYetValid) => 16,
        TestAction::Deny(DenialReason::Expired) => 17,
        TestAction::Deny(DenialReason::ReplayDetected) => 18,
        TestAction::Deny(DenialReason::ContextBindingMismatch) => 19,
        TestAction::Deny(DenialReason::EvidenceInvalid) => 20,
        TestAction::Deny(DenialReason::PolicyDenied) => 21,
        TestAction::Deny(DenialReason::ProtectedSessionLost) => 22,
        TestAction::MarkRevoked => 23,
    }
}

fn success_edge_index(before: ModelState, action: TestAction, next: ModelState) -> usize {
    match (before, action, next) {
        (
            ModelState::EvidenceReceived,
            TestAction::Challenge(BindingMode::Matching),
            ModelState::ChallengeAuthenticated,
        ) => 0,
        (
            ModelState::ChallengeAuthenticated,
            TestAction::Freshness(BindingMode::Matching),
            ModelState::FreshnessChecked,
        ) => 1,
        (
            ModelState::FreshnessChecked,
            TestAction::Identity(BindingMode::Matching),
            ModelState::IdentityChecked,
        ) => 2,
        (
            ModelState::IdentityChecked,
            TestAction::Evidence(BindingMode::Matching),
            ModelState::EvidenceAppraised,
        ) => 3,
        (
            ModelState::EvidenceAppraised,
            TestAction::Session(BindingMode::Matching),
            ModelState::SessionBound,
        ) => 4,
        (
            ModelState::SessionBound,
            TestAction::Revocation(BindingMode::Matching),
            ModelState::RevocationChecked,
        ) => 5,
        (
            ModelState::RevocationChecked,
            TestAction::Policy(AllowedClass::Full, BindingMode::Matching),
            ModelState::PolicySatisfied(AllowedClass::Full),
        ) => 6,
        (
            ModelState::RevocationChecked,
            TestAction::Policy(AllowedClass::Restricted, BindingMode::Matching),
            ModelState::PolicySatisfied(AllowedClass::Restricted),
        ) => 7,
        (ModelState::PolicySatisfied(_), TestAction::Complete, ModelState::Verified(_)) => 8,
        _ => panic!("unknown success edge: {before:?} {action:?} {next:?}"),
    }
}

#[derive(Default)]
struct Coverage {
    full_completions: usize,
    restricted_completions: usize,
    success_edges: [usize; 9],
    eligible_failures: [[usize; 15]; 8],
    ineligible_failures: [[usize; 15]; 8],
    matching_gates: [usize; 7],
    mismatched_gates: [usize; 7],
    terminal_rejections: [[usize; 24]; 6],
}

impl Coverage {
    fn observe(
        &mut self,
        index: usize,
        before: ModelState,
        action: TestAction,
        expected: ExpectedAction,
        snapshots: (&FlowSnapshot, &FlowSnapshot),
        actual: &Result<ActionResult, TransitionError>,
    ) {
        let (before_snapshot, after_snapshot) = snapshots;
        assert_action_matches_model(
            index,
            action,
            expected,
            before_snapshot,
            after_snapshot,
            actual,
        );

        if let ExpectedAction::Allowed(next) = expected {
            match (before, action, next) {
                (
                    ModelState::PolicySatisfied(AllowedClass::Full),
                    TestAction::Complete,
                    ModelState::Verified(AllowedClass::Full),
                ) => self.full_completions += 1,
                (
                    ModelState::PolicySatisfied(AllowedClass::Restricted),
                    TestAction::Complete,
                    ModelState::Verified(AllowedClass::Restricted),
                ) => self.restricted_completions += 1,
                _ => {}
            }
            if let (Some(phase), Some(failure)) = (nonterminal_index(before), failure_index(action))
            {
                self.eligible_failures[phase][failure] += 1;
            } else if failure_index(action).is_none() {
                self.success_edges[success_edge_index(before, action, next)] += 1;
            }
            if action.binding_mode() == Some(BindingMode::Matching)
                && let Some(gate) = gate_index(action)
            {
                self.matching_gates[gate] += 1;
            }
        }

        if expected == ExpectedAction::CapabilityRejected {
            let gate = match gate_index(action) {
                Some(value) => value,
                None => panic!("capability rejection lacked a gate action: {action:?}"),
            };
            self.mismatched_gates[gate] += 1;
        }

        if expected == ExpectedAction::InvalidTransition
            && let Some(terminal) = terminal_index(before)
        {
            self.terminal_rejections[terminal][action_index(action)] += 1;
        } else if expected == ExpectedAction::InvalidTransition
            && let (Some(phase), Some(failure)) = (nonterminal_index(before), failure_index(action))
        {
            self.ineligible_failures[phase][failure] += 1;
        }
    }

    fn assert_non_vacuous(&self) {
        assert!(self.full_completions >= MIN_FULL_COMPLETIONS);
        assert!(self.restricted_completions >= MIN_RESTRICTED_COMPLETIONS);
        assert!(self.success_edges.iter().all(|count| *count > 0));
        assert_eq!(
            self.eligible_failures
                .iter()
                .flatten()
                .filter(|count| **count > 0)
                .count(),
            41
        );
        assert_eq!(
            self.ineligible_failures
                .iter()
                .flatten()
                .filter(|count| **count > 0)
                .count(),
            79
        );
        assert!(self.matching_gates.iter().all(|count| *count > 0));
        assert!(self.mismatched_gates.iter().all(|count| *count > 0));
        assert!(
            self.terminal_rejections
                .iter()
                .flatten()
                .all(|count| *count > 0)
        );
    }
}

fn assert_action_matches_model(
    index: usize,
    action: TestAction,
    expected: ExpectedAction,
    before: &FlowSnapshot,
    after: &FlowSnapshot,
    actual: &Result<ActionResult, TransitionError>,
) {
    match expected {
        ExpectedAction::Allowed(next) => {
            let expected_result = expected_action_result(before, next, action);
            assert_eq!(
                actual,
                &Ok(expected_result),
                "allowed history action failed at index {index}: {action:?}"
            );
            assert_eq!(
                after,
                &expected_success_snapshot(before, next, action),
                "allowed history state mismatch at index {index}: {action:?}"
            );
        }
        ExpectedAction::InvalidTransition => {
            assert_eq!(
                actual,
                &Err(TransitionError::InvalidTransition {
                    phase: before.phase,
                    action: action.public(),
                }),
                "invalid-transition mismatch at index {index}: {action:?}"
            );
            assert_eq!(after, before);
        }
        ExpectedAction::CapabilityRejected => {
            assert_eq!(
                actual,
                &Err(TransitionError::CapabilityRejected {
                    action: action.public(),
                }),
                "capability-rejection mismatch at index {index}: {action:?}"
            );
            assert_eq!(after, before);
        }
    }
}

#[test]
fn canonical_full_path_returns_one_bound_verified_capability() {
    let mut flow = flow_fixture(7);
    let binding = flow.binding.clone();
    assert_eq!(
        flow.record_challenge_authenticated(ChallengeAuthenticated {
            binding: binding.clone(),
        }),
        Ok(())
    );
    assert_eq!(
        flow.record_freshness_checked(crate::freshness::test_freshness_checked(binding.clone())),
        Ok(())
    );
    assert_eq!(
        flow.record_identity_checked(IdentityChecked {
            binding: binding.clone(),
        }),
        Ok(())
    );
    assert_eq!(
        flow.record_evidence_appraised(EvidenceAppraised {
            binding: binding.clone(),
            accepted_profile: accepted_profile(),
        }),
        Ok(())
    );
    assert_eq!(
        flow.record_session_bound(SessionBound {
            binding: binding.clone(),
            session_public_key_id: session_key_id(7),
        }),
        Ok(())
    );
    assert_eq!(
        flow.record_revocation_checked(RevocationChecked {
            binding: binding.clone(),
        }),
        Ok(())
    );
    assert_eq!(
        flow.record_policy_satisfied(PolicySatisfied {
            binding,
            allowed: AllowedClass::Full,
        }),
        Ok(())
    );

    let verified = match flow.complete() {
        Ok(value) => value,
        Err(error) => panic!("canonical path rejected: {error:?}"),
    };
    assert!(verified.binding.matches(&flow.binding));
    assert_eq!(verified.allowed, AllowedClass::Full);
    assert_eq!(flow.phase(), VerificationPhase::Verified);
    assert_eq!(
        flow.outcome().map(VerificationOutcome::decision),
        Some(Decision::Allow)
    );
    assert_eq!(flow.outcome().map(VerificationOutcome::reason), Some(None));
    assert!(
        format!("{verified:?}") == "VerifiedAttestation([REDACTED])",
        "private diagnostic mismatch"
    );
}

#[test]
fn completed_capability_converts_once_to_exact_full_result() {
    let expected_context = request_fixture_with_context_tag(7, 1).expected;
    let expected_profile = accepted_profile();
    let expected_key = session_key_id(7);
    let mut flow = policy_ready_flow_with_context_tag(
        7,
        1,
        expected_profile.clone(),
        expected_key,
        AllowedClass::Full,
    );
    let verified = match flow.complete() {
        Ok(value) => value,
        Err(error) => panic!("canonical test path rejected: {error:?}"),
    };
    let result = verified.into_appraisal_result();
    assert_eq!(result.context(), &expected_context);
    assert_eq!(result.decision(), Decision::Allow);
    assert_eq!(result.reason(), None);
    match result.view() {
        AppraisalResultView::Allow(claims) => {
            assert_eq!(claims.accepted_profile(), &expected_profile);
            assert_eq!(claims.session_public_key_id(), &expected_key);
        }
        _ => panic!("full completion returned the wrong view"),
    }
}

#[test]
fn complete_before_policy_satisfaction_rejects_without_releasing_request() {
    let mut flow = flow_fixture(8);
    match flow.complete() {
        Err(error) => assert_eq!(
            error,
            TransitionError::InvalidTransition {
                phase: VerificationPhase::EvidenceReceived,
                action: VerificationAction::Complete,
            }
        ),
        Ok(_) => panic!("early completion unexpectedly succeeded"),
    }
    assert_eq!(flow.phase(), VerificationPhase::EvidenceReceived);
    assert!(flow_snapshot(&flow).request.is_some());
}

#[test]
fn completed_flow_rejects_second_complete_without_result() {
    let mut flow = policy_ready_flow(8, accepted_profile(), session_key_id(8), AllowedClass::Full);
    let first = match flow.complete() {
        Ok(value) => value,
        Err(error) => panic!("canonical test path rejected: {error:?}"),
    };
    drop(first);
    assert!(matches!(
        flow.complete(),
        Err(TransitionError::InvalidTransition {
            phase: VerificationPhase::Verified,
            action: VerificationAction::Complete,
        })
    ));
}

#[test]
fn equal_request_from_another_flow_rejects_challenge_capability() {
    let source = flow_fixture(8);
    let mut target = flow_fixture(8);
    assert_eq!(
        flow_snapshot(&source).request,
        flow_snapshot(&target).request
    );
    let before_phase = target.phase();
    let before_request = flow_snapshot(&target).request;

    let action = TestAction::Challenge(BindingMode::OtherFlow);
    assert_eq!(action.binding_mode(), Some(BindingMode::OtherFlow));

    assert_eq!(
        apply_action(&mut target, &source.binding, action),
        Err(TransitionError::CapabilityRejected {
            action: VerificationAction::RecordChallengeAuthenticated,
        })
    );
    assert_eq!(target.phase(), before_phase);
    assert_eq!(flow_snapshot(&target).request, before_request);
}

#[test]
fn restricted_success_uses_the_same_complete_gate() {
    let expected_context = request_fixture_with_context_tag(9, 1).expected;
    let expected_profile = accepted_profile();
    let expected_key = session_key_id(9);
    let mut flow = policy_ready_flow_with_context_tag(
        9,
        1,
        expected_profile.clone(),
        expected_key,
        AllowedClass::Restricted,
    );
    let verified = match flow.complete() {
        Ok(value) => value,
        Err(error) => panic!("restricted test path rejected: {error:?}"),
    };
    let result = verified.into_appraisal_result();
    assert_eq!(result.context(), &expected_context);
    assert_eq!(result.decision(), Decision::AllowRestricted);
    assert_eq!(result.reason(), None);
    match result.view() {
        AppraisalResultView::AllowRestricted(claims) => {
            assert_eq!(claims.accepted_profile(), &expected_profile);
            assert_eq!(claims.session_public_key_id(), &expected_key);
        }
        _ => panic!("restricted completion returned the wrong view"),
    }
}

#[test]
fn every_failure_class_is_terminal_and_releases_the_request() {
    for (state, action, expected_phase, expected_decision, expected_reason) in [
        (
            ModelState::EvidenceReceived,
            TestAction::MarkMalformed,
            VerificationPhase::Malformed,
            Decision::Deny,
            ReasonCode::Malformed,
        ),
        (
            ModelState::ChallengeAuthenticated,
            TestAction::MarkUnsupported(UnsupportedRequirement::VersionOrProfile),
            VerificationPhase::Unsupported,
            Decision::Unsupported,
            ReasonCode::UnsupportedVersionOrProfile,
        ),
        (
            ModelState::EvidenceReceived,
            TestAction::MarkRetryable(RetryReason::AttestationUnavailable),
            VerificationPhase::Retryable,
            Decision::Retry,
            ReasonCode::AttestationUnavailable,
        ),
        (
            ModelState::RevocationChecked,
            TestAction::Deny(DenialReason::PolicyDenied),
            VerificationPhase::Denied,
            Decision::Deny,
            ReasonCode::PolicyDenied,
        ),
        (
            ModelState::SessionBound,
            TestAction::MarkRevoked,
            VerificationPhase::Revoked,
            Decision::Deny,
            ReasonCode::Revoked,
        ),
    ] {
        let mut flow = flow_for_model_state(state, 31);
        let other_binding = flow_fixture(31).binding;
        let before = flow_snapshot(&flow);
        assert_eq!(
            apply_action(&mut flow, &other_binding, action),
            Ok(expected_action_result(
                &before,
                model_transition(state, action).unwrap_or_else(|| {
                    panic!("failure fixture was ineligible: {state:?} {action:?}")
                }),
                action,
            ))
        );
        assert_eq!(flow.phase(), expected_phase);
        assert_eq!(
            flow.outcome().map(VerificationOutcome::decision),
            Some(expected_decision)
        );
        assert_eq!(
            flow.outcome().map(VerificationOutcome::reason),
            Some(Some(expected_reason))
        );
        assert!(flow_snapshot(&flow).request.is_none());
        assert_every_action_rejected(&mut flow);
    }
}

#[test]
fn every_denial_reason_has_its_only_valid_reporting_mapping() {
    for (index, (reason, expected)) in [
        (
            DenialReason::ChallengeAuthenticationFailed,
            ReasonCode::ChallengeAuthenticationFailed,
        ),
        (DenialReason::NotYetValid, ReasonCode::NotYetValid),
        (DenialReason::Expired, ReasonCode::Expired),
        (DenialReason::ReplayDetected, ReasonCode::ReplayDetected),
        (
            DenialReason::ContextBindingMismatch,
            ReasonCode::ContextBindingMismatch,
        ),
        (DenialReason::EvidenceInvalid, ReasonCode::EvidenceInvalid),
        (DenialReason::PolicyDenied, ReasonCode::PolicyDenied),
        (
            DenialReason::ProtectedSessionLost,
            ReasonCode::ProtectedSessionLost,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let action = TestAction::Deny(reason);
        let state = match eligible_failure_edges()
            .into_iter()
            .find_map(|(state, candidate)| (candidate == action).then_some(state))
        {
            Some(value) => value,
            None => panic!("denial reason has no eligible phase: {reason:?}"),
        };
        let mut flow = flow_for_model_state(state, 32 + index as u8);
        let result = match flow.deny(reason) {
            Ok(value) => value,
            Err(error) => panic!("eligible denial rejected: {error:?}"),
        };
        assert_eq!(result.decision(), Decision::Deny);
        assert_eq!(result.reason(), Some(expected));
        assert_eq!(
            flow.outcome().map(VerificationOutcome::decision),
            Some(Decision::Deny)
        );
        assert_eq!(
            flow.outcome().map(VerificationOutcome::reason),
            Some(Some(expected))
        );
    }
}

#[test]
fn unknown_mandatory_gate_maps_to_unsupported() {
    let mut flow = flow_fixture(44);
    let result = match flow.mark_unsupported(UnsupportedRequirement::UnknownCriticalRequirement) {
        Ok(value) => value,
        Err(error) => panic!("eligible unknown critical requirement rejected: {error:?}"),
    };
    assert_eq!(result.decision(), Decision::Unsupported);
    assert_eq!(
        result.reason(),
        Some(ReasonCode::UnsupportedCriticalRequirement)
    );
    assert_eq!(flow.phase(), VerificationPhase::Unsupported);
    assert_eq!(
        flow.outcome().map(VerificationOutcome::reason),
        Some(Some(ReasonCode::UnsupportedCriticalRequirement))
    );
}

#[test]
fn all_336_phase_action_pairs_match_the_independent_model() {
    let mut succeeded = 0usize;
    let mut rejected = 0usize;
    for state in ALL_14_MODEL_STATES {
        for action in ALL_24_MATRIX_ACTIONS {
            assert_ne!(action.binding_mode(), Some(BindingMode::OtherFlow));
            let mut flow = flow_for_model_state(state, 53);
            assert_flow_matches_model(&flow, state);
            let before = flow_snapshot(&flow);
            let expected = model_transition(state, action);
            if let Some(required_phase) = action.required_phase() {
                assert_eq!(
                    expected.is_some(),
                    model_phase(state) == required_phase,
                    "required-phase oracle mismatch: {state:?} {action:?}"
                );
            }
            let other_binding = flow_fixture(54).binding;
            let actual = apply_action(&mut flow, &other_binding, action);
            let after = flow_snapshot(&flow);
            match expected {
                Some(next) => {
                    assert_action_matches_model(
                        0,
                        action,
                        ExpectedAction::Allowed(next),
                        &before,
                        &after,
                        &actual,
                    );
                    succeeded += 1;
                }
                None => {
                    assert_action_matches_model(
                        0,
                        action,
                        ExpectedAction::InvalidTransition,
                        &before,
                        &after,
                        &actual,
                    );
                    rejected += 1;
                }
            }
        }
    }
    assert_eq!(ALL_14_MODEL_STATES.len(), 14);
    assert_eq!(ALL_24_MATRIX_ACTIONS.len(), 24);
    assert_eq!(succeeded, 50);
    assert_eq!(rejected, 286);
    assert_eq!(succeeded + rejected, 336);
}

#[test]
fn omitting_each_gate_prevents_completion() {
    let mut omissions = 0usize;
    for (index, omitted) in ALL_7_GATE_KINDS.into_iter().enumerate() {
        let mut flow = flow_fixture(70 + index as u8);
        let other_binding = flow_fixture(90 + index as u8).binding;
        for gate in ALL_7_GATE_KINDS {
            if gate == omitted {
                continue;
            }
            let action = gate.matching_action(AllowedClass::Full);
            assert_eq!(action.public(), gate.action());
            let _result = apply_action(&mut flow, &other_binding, action);
        }

        let before = flow_snapshot(&flow);
        match flow.complete() {
            Err(error) => assert_eq!(
                error,
                TransitionError::InvalidTransition {
                    phase: before.phase,
                    action: VerificationAction::Complete,
                }
            ),
            Ok(_) => panic!("completion succeeded with omitted gate {omitted:?}"),
        }
        assert_eq!(flow_snapshot(&flow), before);
        assert!(flow_snapshot(&flow).request.is_some());
        assert_eq!(flow.outcome(), None);
        omissions += 1;
    }
    assert_eq!(omissions, 7);
}

#[test]
fn gate_permutations_require_the_one_canonical_order() {
    let mut gates = ALL_7_GATE_KINDS;
    let mut permutations = 0usize;
    let mut canonical = 0usize;
    let mut noncanonical = 0usize;

    permute_gates(&mut gates, 0, &mut |ordering| {
        let mut flow = flow_fixture(101);
        let other_binding = flow_fixture(102).binding;
        for gate in ordering.iter().copied() {
            let action = gate.matching_action(AllowedClass::Full);
            assert_eq!(action.public(), gate.action());
            let _result = apply_action(&mut flow, &other_binding, action);
        }

        permutations += 1;
        if ordering == ALL_7_GATE_KINDS {
            assert_eq!(flow.phase(), VerificationPhase::PolicySatisfied);
            assert_eq!(flow.outcome(), None);
            assert!(flow_snapshot(&flow).request.is_some());
            let verified = match flow.complete() {
                Ok(value) => value,
                Err(error) => panic!("canonical ordering rejected: {error:?}"),
            };
            drop(verified);
            assert_eq!(flow.phase(), VerificationPhase::Verified);
            assert_eq!(
                flow.outcome().map(VerificationOutcome::decision),
                Some(Decision::Allow)
            );
            assert!(flow_snapshot(&flow).request.is_none());
            canonical += 1;
        } else {
            assert_ne!(flow.phase(), VerificationPhase::PolicySatisfied);
            assert_ne!(flow.phase(), VerificationPhase::Verified);
            assert_eq!(flow.outcome(), None);
            assert!(flow_snapshot(&flow).request.is_some());
            let before = flow_snapshot(&flow);
            match flow.complete() {
                Err(error) => assert_eq!(
                    error,
                    TransitionError::InvalidTransition {
                        phase: before.phase,
                        action: VerificationAction::Complete,
                    }
                ),
                Ok(_) => panic!("noncanonical ordering completed: {ordering:?}"),
            }
            assert_eq!(flow_snapshot(&flow), before);
            noncanonical += 1;
        }
    });

    assert_eq!(permutations, 5_040);
    assert_eq!(canonical, 1);
    assert_eq!(noncanonical, 5_039);
}

#[test]
fn every_capability_rejects_an_equal_request_from_another_flow() {
    for gate in ALL_7_GATE_KINDS {
        let (source, mut target) = equal_flows_at_gate(gate, 71);
        let before = flow_snapshot(&target);
        let result = apply_capability_from_other_flow(gate, &source, &mut target);
        assert_eq!(
            result,
            Err(TransitionError::CapabilityRejected {
                action: gate.action(),
            })
        );
        assert_eq!(flow_snapshot(&target), before);
    }
}

#[test]
fn mismatched_capabilities_preserve_phase_before_binding_error_precedence() {
    for state in ALL_14_MODEL_STATES {
        for gate in ALL_7_GATE_KINDS {
            let source = flow_fixture(72);
            let mut target = flow_for_model_state(state, 72);
            let before = flow_snapshot(&target);
            let actual = apply_capability_from_other_flow(gate, &source, &mut target);
            let expected = if gate.required_phase() == model_phase(state) {
                TransitionError::CapabilityRejected {
                    action: gate.action(),
                }
            } else {
                TransitionError::InvalidTransition {
                    phase: model_phase(state),
                    action: gate.action(),
                }
            };
            assert_eq!(actual, Err(expected));
            assert_eq!(flow_snapshot(&target), before);
        }
    }
}

#[test]
fn every_flow_result_claim_view_and_error_diagnostic_is_redacted() {
    let mut flow = flow_with_private_sentinels();
    let diagnostics = diagnostics_for_every_surface(&mut flow);
    for required in [
        "AppraisalResult([REDACTED])",
        "AcceptedClaims([REDACTED])",
        "AppraisalResultView([REDACTED])",
    ] {
        assert!(diagnostics.iter().any(|diagnostic| diagnostic == required));
    }
    let forbidden = [
        "private.publisher",
        "private.game",
        "private-build",
        "private-account",
        "private-match",
        "private-policy",
        "private-profile",
        "private-accepted-profile",
        "private-evidence-payload",
        "3141592653",
        "4242",
        "4243",
        "4342",
        "d7",
        "D7",
        "215",
        "/home/",
        "::error::",
        "\n",
        "0x",
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
    ];

    for diagnostic in diagnostics {
        for sentinel in forbidden {
            assert!(
                !diagnostic.contains(sentinel),
                "private diagnostic exposed a forbidden value"
            );
        }
    }
}

#[test]
fn request_and_claims_exist_only_in_active_states() {
    for state in ALL_14_MODEL_STATES {
        let flow = flow_for_model_state(state, 83);
        let snapshot = flow_snapshot(&flow);
        assert_eq!(snapshot.has_request, model_is_nonterminal(state));
        assert_eq!(snapshot.has_profile, model_has_profile(state));
        assert_eq!(snapshot.has_session_key, model_has_session_key(state));
        assert_eq!(snapshot.has_allowed_class, model_has_allowed_class(state));
    }
}

fn raw_string_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut cursor = start;
    if matches!(bytes.get(cursor), Some(b'b' | b'c')) {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;

    let mut hashes = 0;
    while bytes.get(cursor) == Some(&b'#') {
        hashes += 1;
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }
    cursor += 1;

    while cursor < bytes.len() {
        if bytes[cursor] == b'"' {
            let end = cursor + 1 + hashes;
            if end <= bytes.len() && bytes[cursor + 1..end].iter().all(|byte| *byte == b'#') {
                return Some(end);
            }
        }
        cursor += 1;
    }
    panic!("unterminated raw string at byte {start}")
}

fn quoted_string_end(source: &str, quote: usize) -> usize {
    let bytes = source.as_bytes();
    let mut cursor = quote + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => cursor += 2,
            b'"' => return cursor + 1,
            _ => cursor += 1,
        }
    }
    panic!("unterminated string at byte {quote}")
}

fn char_literal_end(source: &str, quote: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut cursor = quote + 1;
    let first = *bytes.get(cursor)?;
    if first == b'\\' {
        cursor += 1;
        match *bytes.get(cursor)? {
            b'x' => cursor += 3,
            b'u' => {
                cursor += 1;
                if bytes.get(cursor) != Some(&b'{') {
                    return None;
                }
                cursor += 1;
                while bytes.get(cursor) != Some(&b'}') {
                    cursor += 1;
                    if cursor >= bytes.len() {
                        return None;
                    }
                }
                cursor += 1;
            }
            _ => cursor += 1,
        }
    } else {
        let character = source[cursor..].chars().next()?;
        if matches!(character, '\'' | '\n' | '\r') {
            return None;
        }
        cursor += character.len_utf8();
    }
    (bytes.get(cursor) == Some(&b'\'')).then_some(cursor + 1)
}

fn is_rust_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'
            ..='\u{000d}'
                | '\u{0020}'
                | '\u{0085}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
    )
}

fn is_identifier_start(character: char) -> bool {
    !is_rust_whitespace(character)
        && (character == '_' || character.is_ascii_alphabetic() || !character.is_ascii())
}

fn is_identifier_continue(character: char) -> bool {
    !is_rust_whitespace(character)
        && (character == '_' || character.is_ascii_alphanumeric() || !character.is_ascii())
}

fn identifier_end(source: &str, start: usize) -> Option<usize> {
    let character = source.get(start..)?.chars().next()?;
    if !is_identifier_start(character) {
        return None;
    }
    let mut cursor = start + character.len_utf8();
    while cursor < source.len() {
        let next = source[cursor..].chars().next()?;
        if !is_identifier_continue(next) {
            break;
        }
        cursor += next.len_utf8();
    }
    Some(cursor)
}

fn rust_tokens(source: &str) -> Vec<String> {
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = 0;

    while cursor < bytes.len() {
        let character = source[cursor..]
            .chars()
            .next()
            .unwrap_or_else(|| panic!("token cursor {cursor} is not a character boundary"));
        if is_rust_whitespace(character) {
            cursor += character.len_utf8();
        } else if bytes[cursor..].starts_with(b"//") {
            cursor += 2;
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor += 1;
            }
        } else if bytes[cursor..].starts_with(b"/*") {
            cursor += 2;
            let mut depth = 1_usize;
            while depth > 0 {
                assert!(cursor < bytes.len(), "unterminated block comment");
                if bytes[cursor..].starts_with(b"/*") {
                    depth += 1;
                    cursor += 2;
                } else if bytes[cursor..].starts_with(b"*/") {
                    depth -= 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
        } else if let Some(end) = raw_string_end(source, cursor) {
            cursor = identifier_end(source, end).unwrap_or(end);
        } else if bytes[cursor] == b'"' {
            let end = quoted_string_end(source, cursor);
            cursor = identifier_end(source, end).unwrap_or(end);
        } else if matches!(bytes.get(cursor), Some(b'b' | b'c'))
            && bytes.get(cursor + 1) == Some(&b'"')
        {
            let end = quoted_string_end(source, cursor + 1);
            cursor = identifier_end(source, end).unwrap_or(end);
        } else if bytes[cursor] == b'b' && bytes.get(cursor + 1) == Some(&b'\'') {
            let end = char_literal_end(source, cursor + 1)
                .unwrap_or_else(|| panic!("invalid byte character at byte {cursor}"));
            cursor = identifier_end(source, end).unwrap_or(end);
        } else if bytes[cursor] == b'\'' {
            if let Some(end) = char_literal_end(source, cursor) {
                cursor = identifier_end(source, end).unwrap_or(end);
            } else if bytes
                .get(cursor + 1..)
                .is_some_and(|tail| tail.starts_with(b"r#"))
            {
                let end = identifier_end(source, cursor + 3)
                    .unwrap_or_else(|| panic!("invalid raw lifetime at byte {cursor}"));
                tokens.push(source[cursor..end].to_owned());
                cursor = end;
            } else if let Some(end) = identifier_end(source, cursor + 1) {
                tokens.push(source[cursor..end].to_owned());
                cursor = end;
            } else {
                tokens.push("'".to_owned());
                cursor += 1;
            }
        } else if bytes[cursor..].starts_with(b"r#") {
            if let Some(end) = identifier_end(source, cursor + 2) {
                tokens.push(source[cursor + 2..end].to_owned());
                cursor = end;
            } else {
                tokens.push(character.to_string());
                cursor += character.len_utf8();
            }
        } else if is_identifier_start(character) {
            let end = identifier_end(source, cursor)
                .unwrap_or_else(|| panic!("identifier at byte {cursor} has no end"));
            tokens.push(source[cursor..end].to_owned());
            cursor = end;
        } else if character.is_ascii_digit() {
            let start = cursor;
            cursor += 1;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || matches!(bytes[cursor], b'_' | b'.'))
            {
                cursor += 1;
            }
            tokens.push(source[start..cursor].to_owned());
        } else {
            tokens.push(character.to_string());
            cursor += character.len_utf8();
        }
    }
    tokens
}

fn matching_delimiter(tokens: &[String], open: usize) -> Option<usize> {
    let expected = match tokens.get(open).map(String::as_str) {
        Some("(") => ")",
        Some("[") => "]",
        Some("{") => "}",
        _ => return None,
    };
    let mut stack = vec![expected];
    for (index, token) in tokens.iter().enumerate().skip(open + 1) {
        match token.as_str() {
            "(" => stack.push(")"),
            "[" => stack.push("]"),
            "{" => stack.push("}"),
            ")" | "]" | "}" => {
                if stack.pop() != Some(token.as_str()) {
                    return None;
                }
                if stack.is_empty() {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn item_visibility_start(tokens: &[String], keyword: usize) -> usize {
    if keyword > 0 && tokens[keyword - 1] == "pub" {
        return keyword - 1;
    }
    if keyword > 0 && tokens[keyword - 1] == ")" {
        let mut depth = 1_usize;
        let mut cursor = keyword - 1;
        while cursor > 0 {
            cursor -= 1;
            match tokens[cursor].as_str() {
                ")" => depth += 1,
                "(" => {
                    depth -= 1;
                    if depth == 0 {
                        return if cursor > 0 && tokens[cursor - 1] == "pub" {
                            cursor - 1
                        } else {
                            keyword
                        };
                    }
                }
                _ => {}
            }
        }
    }
    keyword
}

fn named_item_tokens<'a>(
    tokens: &'a [String],
    keyword: &str,
    name: &str,
) -> Result<&'a [String], String> {
    let starts = tokens
        .windows(2)
        .enumerate()
        .filter_map(|(index, window)| (window == [keyword, name]).then_some(index))
        .collect::<Vec<_>>();
    if starts.len() != 1 {
        return Err(format!(
            "expected one {keyword} {name} item, found {}",
            starts.len()
        ));
    }
    let keyword_start = starts[0];
    let start = item_visibility_start(tokens, keyword_start);
    let delimiter = tokens
        .iter()
        .enumerate()
        .skip(keyword_start + 2)
        .find_map(|(index, token)| matches!(token.as_str(), "(" | "{" | ";").then_some(index))
        .ok_or_else(|| format!("{keyword} {name} has no item delimiter"))?;
    let end = if tokens[delimiter] == ";" {
        delimiter + 1
    } else {
        let close = matching_delimiter(tokens, delimiter)
            .ok_or_else(|| format!("{keyword} {name} has unbalanced delimiters"))?;
        if tokens[delimiter] == "(" {
            if tokens.get(close + 1).map(String::as_str) != Some(";") {
                return Err(format!("tuple {keyword} {name} lacks a semicolon"));
            }
            close + 2
        } else {
            close + 1
        }
    };
    Ok(&tokens[start..end])
}

fn require_exact_item(
    tokens: &[String],
    keyword: &str,
    name: &str,
    expected_source: &str,
) -> Result<(), String> {
    let actual = named_item_tokens(tokens, keyword, name)?;
    let expected = rust_tokens(expected_source);
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{keyword} {name} token inventory drifted; expected {expected:?}, found {actual:?}"
        ))
    }
}

fn validate_authority_structure(verification: &str, freshness: &str) -> Result<(), String> {
    let tokens = rust_tokens(verification);
    for (keyword, name, expected) in [
        (
            "struct",
            "AttemptRecord",
            "struct AttemptRecord { _registration: ReplayRegistration, }",
        ),
        (
            "struct",
            "VerificationBinding",
            "pub(crate) struct VerificationBinding(Arc<AttemptRecord>);",
        ),
        (
            "struct",
            "VerificationOutcome",
            "pub struct VerificationOutcome { decision: Decision, reason: Option<ReasonCode>, }",
        ),
        (
            "struct",
            "ChallengeAuthenticated",
            "pub struct ChallengeAuthenticated { binding: VerificationBinding, }",
        ),
        (
            "struct",
            "IdentityChecked",
            "pub struct IdentityChecked { binding: VerificationBinding, }",
        ),
        (
            "struct",
            "EvidenceAppraised",
            "pub struct EvidenceAppraised { binding: VerificationBinding, accepted_profile: EvidenceProfile, }",
        ),
        (
            "struct",
            "SessionBound",
            "pub struct SessionBound { binding: VerificationBinding, session_public_key_id: SessionPublicKeyId, }",
        ),
        (
            "struct",
            "RevocationChecked",
            "pub struct RevocationChecked { binding: VerificationBinding, }",
        ),
        (
            "struct",
            "PolicySatisfied",
            "pub struct PolicySatisfied { binding: VerificationBinding, allowed: AllowedClass, }",
        ),
        (
            "struct",
            "AppraisalResult",
            "pub struct AppraisalResult { context: ExpectedContext, payload: AppraisalPayload, }",
        ),
        (
            "enum",
            "AllowedClass",
            "enum AllowedClass { Full, Restricted, }",
        ),
        (
            "enum",
            "AppraisalPayload",
            "enum AppraisalPayload { Allow(AcceptedClaims), AllowRestricted(AcceptedClaims), Failure(FailurePayload), }",
        ),
        (
            "struct",
            "AcceptedClaims",
            "pub struct AcceptedClaims { accepted_profile: EvidenceProfile, session_public_key_id: SessionPublicKeyId, }",
        ),
        (
            "enum",
            "FailureDecision",
            "enum FailureDecision { Deny, Unsupported, Retry, }",
        ),
        (
            "enum",
            "FailureKind",
            "enum FailureKind { Malformed, Unsupported(UnsupportedRequirement), Retry(RetryReason), Deny(DenialReason), Revoked, }",
        ),
        (
            "enum",
            "AppraisalResultView",
            "pub enum AppraisalResultView<'a> { Allow(&'a AcceptedClaims), AllowRestricted(&'a AcceptedClaims), Failure { decision: Decision, reason: ReasonCode, }, }",
        ),
        (
            "struct",
            "VerifiedAttestation",
            "pub struct VerifiedAttestation { binding: VerificationBinding, context: ExpectedContext, accepted_profile: EvidenceProfile, session_public_key_id: SessionPublicKeyId, allowed: AllowedClass, }",
        ),
        (
            "struct",
            "VerifierFlow",
            "pub struct VerifierFlow { binding: VerificationBinding, state: VerificationState, }",
        ),
        (
            "struct",
            "FailurePayload",
            "struct FailurePayload { decision: FailureDecision, reason: ReasonCode, }",
        ),
        (
            "enum",
            "VerificationState",
            r#"
                enum VerificationState {
                    EvidenceReceived { request: VerificationRequest, },
                    ChallengeAuthenticated { request: VerificationRequest, },
                    FreshnessChecked { request: VerificationRequest, },
                    IdentityChecked { request: VerificationRequest, },
                    EvidenceAppraised { request: VerificationRequest, accepted_profile: EvidenceProfile, },
                    SessionBound { request: VerificationRequest, accepted_profile: EvidenceProfile, session_public_key_id: SessionPublicKeyId, },
                    RevocationChecked { request: VerificationRequest, accepted_profile: EvidenceProfile, session_public_key_id: SessionPublicKeyId, },
                    PolicySatisfied { request: VerificationRequest, accepted_profile: EvidenceProfile, session_public_key_id: SessionPublicKeyId, allowed: AllowedClass, },
                    Verified { outcome: VerificationOutcome, },
                    Malformed { outcome: VerificationOutcome, },
                    Unsupported { outcome: VerificationOutcome, },
                    Retryable { outcome: VerificationOutcome, },
                    Denied { outcome: VerificationOutcome, },
                    Revoked { outcome: VerificationOutcome, },
                }
            "#,
        ),
    ] {
        require_exact_item(&tokens, keyword, name, expected)?;
    }

    for forbidden in [
        &["request", ":", "Option"][..],
        &["accepted_profile", ":", "Option"][..],
        &["session_public_key_id", ":", "Option"][..],
        &["pub", "fn", "new"][..],
        &["pub", "const", "fn", "new"][..],
        &["fn", "builder"][..],
        &[
            "impl",
            "From",
            "<",
            "VerificationOutcome",
            ">",
            "for",
            "AppraisalResult",
        ][..],
        &["impl", "From", "<", "AppraisalResultView"][..],
        &["fn", "sign"][..],
        &["fn", "permit"][..],
        &["fn", "proof"][..],
        &["fn", "admit"][..],
    ] {
        if sequence_start(&tokens, forbidden).is_some() {
            return Err(format!(
                "forbidden authority expansion tokens: {forbidden:?}"
            ));
        }
    }

    let freshness_tokens = rust_tokens(freshness);
    require_exact_item(
        &freshness_tokens,
        "struct",
        "FreshnessChecked",
        "pub struct FreshnessChecked { binding: VerificationBinding, }",
    )
}

fn sequence_start(tokens: &[String], expected: &[&str]) -> Option<usize> {
    tokens.windows(expected.len()).position(|window| {
        window
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual == expected)
    })
}

fn outer_attribute_start(tokens: &[String], item_start: usize) -> usize {
    let mut start = item_start;
    while start >= 3 && tokens[start - 1] == "]" {
        let mut depth = 1_usize;
        let mut cursor = start - 1;
        let mut open = None;
        while cursor > 0 {
            cursor -= 1;
            match tokens[cursor].as_str() {
                "]" => depth += 1,
                "[" => {
                    depth -= 1;
                    if depth == 0 {
                        open = Some(cursor);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(open) = open else {
            break;
        };
        if open == 0 || tokens[open - 1] != "#" {
            break;
        }
        start = open - 1;
    }
    start
}

fn function_tokens<'a>(tokens: &'a [String], name: &str) -> Result<&'a [String], String> {
    let marker = ["pub", "fn", name];
    let starts = tokens
        .windows(marker.len())
        .enumerate()
        .filter_map(|(index, window)| {
            window
                .iter()
                .zip(marker)
                .all(|(actual, expected)| actual == expected)
                .then_some(index)
        })
        .collect::<Vec<_>>();
    if starts.len() != 1 {
        return Err(format!(
            "expected one public function {name}, found {}",
            starts.len()
        ));
    }
    let function_start = starts[0];
    let body = tokens
        .iter()
        .enumerate()
        .skip(function_start + marker.len())
        .find_map(|(index, token)| (token == "{").then_some(index))
        .ok_or_else(|| format!("function {name} has no body"))?;
    let end = matching_delimiter(tokens, body)
        .ok_or_else(|| format!("function {name} has an unbalanced body"))?;
    let start = outer_attribute_start(tokens, function_start);
    Ok(&tokens[start..=end])
}

fn function_body_tokens<'a>(tokens: &'a [String], name: &str) -> Result<&'a [String], String> {
    let function = function_tokens(tokens, name)?;
    let marker = ["pub", "fn", name];
    let function_start = sequence_start(function, &marker)
        .ok_or_else(|| format!("function {name} has no isolated signature"))?;
    let body = function
        .iter()
        .enumerate()
        .skip(function_start + marker.len())
        .find_map(|(index, token)| (token == "{").then_some(index))
        .ok_or_else(|| format!("function {name} has no isolated body"))?;
    let end = matching_delimiter(function, body)
        .ok_or_else(|| format!("function {name} has an unbalanced isolated body"))?;
    Ok(&function[body + 1..end])
}

fn private_function_body_tokens<'a>(
    tokens: &'a [String],
    name: &str,
) -> Result<&'a [String], String> {
    let marker = ["fn", name];
    let starts = tokens
        .windows(marker.len())
        .enumerate()
        .filter_map(|(index, window)| (window == marker).then_some(index))
        .collect::<Vec<_>>();
    if starts.len() != 1 {
        return Err(format!(
            "expected one private function {name}, found {}",
            starts.len()
        ));
    }
    let body = tokens
        .iter()
        .enumerate()
        .skip(starts[0] + marker.len())
        .find_map(|(index, token)| (token == "{").then_some(index))
        .ok_or_else(|| format!("private function {name} has no body"))?;
    let end = matching_delimiter(tokens, body)
        .ok_or_else(|| format!("private function {name} has an unbalanced body"))?;
    Ok(&tokens[body + 1..end])
}

fn require_exact_private_function(
    tokens: &[String],
    name: &str,
    expected_source: &str,
) -> Result<(), String> {
    let marker = ["fn", name];
    let starts = tokens
        .windows(marker.len())
        .enumerate()
        .filter_map(|(index, window)| (window == marker).then_some(index))
        .collect::<Vec<_>>();
    if starts.len() != 1 {
        return Err(format!(
            "expected one private function {name}, found {}",
            starts.len()
        ));
    }
    let start = starts[0];
    let body = tokens
        .iter()
        .enumerate()
        .skip(start + marker.len())
        .find_map(|(index, token)| (token == "{").then_some(index))
        .ok_or_else(|| format!("private function {name} has no body"))?;
    let end = matching_delimiter(tokens, body)
        .ok_or_else(|| format!("private function {name} has an unbalanced body"))?;
    let actual = &tokens[start..=end];
    let expected = rust_tokens(expected_source);
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "private function {name} token inventory drifted; expected {expected:?}, found {actual:?}"
        ))
    }
}

fn validate_failure_eligibility(verification: &str) -> Result<(), String> {
    let tokens = rust_tokens(verification);
    require_exact_private_function(
        &tokens,
        "is_active_phase",
        r#"fn is_active_phase(phase: VerificationPhase) -> bool {
            matches!(phase, VerificationPhase::EvidenceReceived
                | VerificationPhase::ChallengeAuthenticated
                | VerificationPhase::FreshnessChecked
                | VerificationPhase::IdentityChecked
                | VerificationPhase::EvidenceAppraised
                | VerificationPhase::SessionBound
                | VerificationPhase::RevocationChecked
                | VerificationPhase::PolicySatisfied)
        }"#,
    )?;
    require_exact_private_function(
        &tokens,
        "failure_is_eligible",
        r#"fn failure_is_eligible(phase: VerificationPhase, failure: FailureKind) -> bool {
            match failure {
                FailureKind::Malformed => phase == VerificationPhase::EvidenceReceived,
                FailureKind::Unsupported(UnsupportedRequirement::VersionOrProfile) => {
                    phase == VerificationPhase::ChallengeAuthenticated
                }
                FailureKind::Unsupported(UnsupportedRequirement::Platform) => {
                    phase == VerificationPhase::IdentityChecked
                }
                FailureKind::Unsupported(UnsupportedRequirement::UnknownCriticalRequirement) | FailureKind::Retry(_) => is_active_phase(phase),
                FailureKind::Deny(DenialReason::ChallengeAuthenticationFailed) => {
                    phase == VerificationPhase::EvidenceReceived
                }
                FailureKind::Deny(DenialReason::NotYetValid | DenialReason::Expired | DenialReason::ReplayDetected,) => phase == VerificationPhase::ChallengeAuthenticated,
                FailureKind::Deny(DenialReason::ContextBindingMismatch) => matches!(phase, VerificationPhase::ChallengeAuthenticated | VerificationPhase::FreshnessChecked | VerificationPhase::EvidenceAppraised),
                FailureKind::Deny(DenialReason::EvidenceInvalid) => {
                    phase == VerificationPhase::IdentityChecked
                }
                FailureKind::Deny(DenialReason::PolicyDenied) => {
                    phase == VerificationPhase::RevocationChecked
                }
                FailureKind::Deny(DenialReason::ProtectedSessionLost) => matches!(phase, VerificationPhase::EvidenceAppraised | VerificationPhase::SessionBound | VerificationPhase::RevocationChecked | VerificationPhase::PolicySatisfied),
                FailureKind::Revoked => phase == VerificationPhase::SessionBound,
            }
        }"#,
    )
}

fn top_level_statements(tokens: &[String]) -> Result<Vec<&[String]>, String> {
    let mut statements = Vec::new();
    let mut delimiters = Vec::new();
    let mut start = 0;

    for (index, token) in tokens.iter().enumerate() {
        match token.as_str() {
            "(" => delimiters.push(")"),
            "[" => delimiters.push("]"),
            "{" => delimiters.push("}"),
            ")" | "]" | "}" if delimiters.pop() != Some(token.as_str()) => {
                return Err(format!(
                    "mismatched delimiter {token} at body token {index}"
                ));
            }
            _ => {}
        }

        let ends_block_statement = delimiters.is_empty()
            && token == "}"
            && matches!(
                tokens.get(start).map(String::as_str),
                Some("if" | "match" | "while" | "for" | "loop" | "{" | "unsafe")
            )
            && !matches!(
                tokens.get(index + 1).map(String::as_str),
                Some(";" | "else")
            );
        if (delimiters.is_empty() && token == ";") || ends_block_statement {
            statements.push(&tokens[start..=index]);
            start = index + 1;
        }
    }

    if !delimiters.is_empty() {
        return Err("unclosed delimiter in function body".to_owned());
    }
    if start < tokens.len() {
        statements.push(&tokens[start..]);
    }
    Ok(statements)
}

fn validate_active_state_replacement(verification: &str) -> Result<(), String> {
    let tokens = rust_tokens(verification);
    for forbidden in [
        &["Option", "<", "VerificationState", ">"][..],
        &["self", ".", "state", ".", "take", "(", ")"][..],
        &[
            "std", ":", ":", "mem", ":", ":", "take", "(", "&", "mut", "self", ".", "state",
        ][..],
    ] {
        if sequence_start(&tokens, forbidden).is_some() {
            return Err(format!("forbidden state extraction tokens: {forbidden:?}"));
        }
    }

    let replacement = r#"
        let previous = std::mem::replace(
            &mut self.state,
            VerificationState::Retryable {
                outcome: VerificationOutcome::retryable(RetryReason::TransientFailure),
            },
        );
    "#;
    for (method_name, phase, binding, extraction, assignment) in [
        (
            "record_challenge_authenticated",
            "if !matches!(&self.state, VerificationState::EvidenceReceived { .. }) { return Err(self.invalid_transition(VerificationAction::RecordChallengeAuthenticated)); }",
            "self.ensure_binding(VerificationAction::RecordChallengeAuthenticated, &capability.binding,)?;",
            "let VerificationState::EvidenceReceived { request } = previous else { unreachable!(\"phase was checked before active-state replacement\") };",
            "self.state = VerificationState::ChallengeAuthenticated { request };",
        ),
        (
            "record_freshness_checked",
            "if !matches!(&self.state, VerificationState::ChallengeAuthenticated { .. }) { return Err(self.invalid_transition(VerificationAction::RecordFreshnessChecked)); }",
            "self.ensure_binding(VerificationAction::RecordFreshnessChecked, capability.binding(),)?;",
            "let VerificationState::ChallengeAuthenticated { request } = previous else { unreachable!(\"phase was checked before active-state replacement\") };",
            "self.state = VerificationState::FreshnessChecked { request };",
        ),
        (
            "record_identity_checked",
            "if !matches!(&self.state, VerificationState::FreshnessChecked { .. }) { return Err(self.invalid_transition(VerificationAction::RecordIdentityChecked)); }",
            "self.ensure_binding(VerificationAction::RecordIdentityChecked, &capability.binding,)?;",
            "let VerificationState::FreshnessChecked { request } = previous else { unreachable!(\"phase was checked before active-state replacement\") };",
            "self.state = VerificationState::IdentityChecked { request };",
        ),
        (
            "record_evidence_appraised",
            "if !matches!(&self.state, VerificationState::IdentityChecked { .. }) { return Err(self.invalid_transition(VerificationAction::RecordEvidenceAppraised)); }",
            "self.ensure_binding(VerificationAction::RecordEvidenceAppraised, &capability.binding,)?;",
            "let VerificationState::IdentityChecked { request } = previous else { unreachable!(\"phase was checked before active-state replacement\") };",
            "self.state = VerificationState::EvidenceAppraised { request, accepted_profile: capability.accepted_profile, };",
        ),
        (
            "record_session_bound",
            "if !matches!(&self.state, VerificationState::EvidenceAppraised { .. }) { return Err(self.invalid_transition(VerificationAction::RecordSessionBound)); }",
            "self.ensure_binding(VerificationAction::RecordSessionBound, &capability.binding)?;",
            "let VerificationState::EvidenceAppraised { request, accepted_profile, } = previous else { unreachable!(\"phase was checked before active-state replacement\") };",
            "self.state = VerificationState::SessionBound { request, accepted_profile, session_public_key_id: capability.session_public_key_id, };",
        ),
        (
            "record_revocation_checked",
            "if !matches!(&self.state, VerificationState::SessionBound { .. }) { return Err(self.invalid_transition(VerificationAction::RecordRevocationChecked)); }",
            "self.ensure_binding(VerificationAction::RecordRevocationChecked, &capability.binding,)?;",
            "let VerificationState::SessionBound { request, accepted_profile, session_public_key_id, } = previous else { unreachable!(\"phase was checked before active-state replacement\") };",
            "self.state = VerificationState::RevocationChecked { request, accepted_profile, session_public_key_id, };",
        ),
        (
            "record_policy_satisfied",
            "if !matches!(&self.state, VerificationState::RevocationChecked { .. }) { return Err(self.invalid_transition(VerificationAction::RecordPolicySatisfied)); }",
            "self.ensure_binding(VerificationAction::RecordPolicySatisfied, &capability.binding,)?;",
            "let VerificationState::RevocationChecked { request, accepted_profile, session_public_key_id, } = previous else { unreachable!(\"phase was checked before active-state replacement\") };",
            "self.state = VerificationState::PolicySatisfied { request, accepted_profile, session_public_key_id, allowed: capability.allowed, };",
        ),
    ] {
        let body = function_body_tokens(&tokens, method_name)?;
        let actual = top_level_statements(body)?;
        let expected = [
            rust_tokens(phase),
            rust_tokens(binding),
            rust_tokens(replacement),
            rust_tokens(extraction),
            rust_tokens(assignment),
            rust_tokens("Ok(())"),
        ];
        if actual.len() != expected.len()
            || actual
                .iter()
                .zip(&expected)
                .any(|(actual, expected)| *actual != expected)
        {
            return Err(format!(
                "{method_name} top-level transition statements drifted; expected {expected:?}, found {actual:?}"
            ));
        }
    }

    let failure_body = private_function_body_tokens(&tokens, "emit_failure")?;
    let actual = top_level_statements(failure_body)?;
    let expected = [
        rust_tokens("let action = failure.action();"),
        rust_tokens(
            "if !failure_is_eligible(self.phase(), failure) { return Err(self.invalid_transition(action)); }",
        ),
        rust_tokens(
            r#"let (decision, reason, terminal) = match failure {
                FailureKind::Malformed => (FailureDecision::Deny, ReasonCode::Malformed, VerificationState::Malformed { outcome: VerificationOutcome::malformed(), },),
                FailureKind::Unsupported(requirement) => (FailureDecision::Unsupported, requirement.as_reason_code(), VerificationState::Unsupported { outcome: VerificationOutcome::unsupported(requirement), },),
                FailureKind::Retry(retry_reason) => (FailureDecision::Retry, retry_reason.as_reason_code(), VerificationState::Retryable { outcome: VerificationOutcome::retryable(retry_reason), },),
                FailureKind::Deny(denial_reason) => (FailureDecision::Deny, denial_reason.as_reason_code(), VerificationState::Denied { outcome: VerificationOutcome::denied(denial_reason), },),
                FailureKind::Revoked => (FailureDecision::Deny, ReasonCode::Revoked, VerificationState::Revoked { outcome: VerificationOutcome::revoked(), },),
            };"#,
        ),
        rust_tokens("let previous = std::mem::replace(&mut self.state, terminal);"),
        rust_tokens(
            r#"let request = match previous {
                VerificationState::EvidenceReceived { request }
                | VerificationState::ChallengeAuthenticated { request }
                | VerificationState::FreshnessChecked { request }
                | VerificationState::IdentityChecked { request }
                | VerificationState::EvidenceAppraised { request, .. }
                | VerificationState::SessionBound { request, .. }
                | VerificationState::RevocationChecked { request, .. }
                | VerificationState::PolicySatisfied { request, .. } => request,
                VerificationState::Verified { .. }
                | VerificationState::Malformed { .. }
                | VerificationState::Unsupported { .. }
                | VerificationState::Retryable { .. }
                | VerificationState::Denied { .. }
                | VerificationState::Revoked { .. } => { unreachable!("eligibility excluded terminal state before replacement") }
            };"#,
        ),
        rust_tokens(
            "Ok(AppraisalResult { context: request.expected, payload: AppraisalPayload::Failure(FailurePayload { decision, reason }), })",
        ),
    ];
    if actual.len() != expected.len()
        || actual
            .iter()
            .zip(&expected)
            .any(|(actual, expected)| *actual != expected)
    {
        return Err(format!(
            "emit_failure top-level statements drifted; expected {expected:?}, found {actual:?}"
        ));
    }
    Ok(())
}

fn inherent_impl_tokens<'a>(tokens: &'a [String], type_name: &str) -> Result<&'a [String], String> {
    let mut delimiters = Vec::new();
    let mut starts = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if delimiters.is_empty()
            && tokens.get(index).map(String::as_str) == Some("impl")
            && tokens.get(index + 1).map(String::as_str) == Some(type_name)
            && tokens.get(index + 2).map(String::as_str) == Some("{")
        {
            starts.push(index);
        }
        match token.as_str() {
            "(" => delimiters.push(")"),
            "[" => delimiters.push("]"),
            "{" => delimiters.push("}"),
            ")" | "]" | "}" if delimiters.pop() != Some(token.as_str()) => {
                return Err(format!(
                    "mismatched source delimiter {token} at token {index}"
                ));
            }
            _ => {}
        }
    }
    if !delimiters.is_empty() {
        return Err("unclosed delimiter in verification source".to_owned());
    }
    if starts.len() != 1 {
        return Err(format!(
            "expected one top-level inherent impl {type_name}, found {}",
            starts.len()
        ));
    }
    let start = starts[0];
    let end = matching_delimiter(tokens, start + 2)
        .ok_or_else(|| format!("impl {type_name} has an unbalanced body"))?;
    Ok(&tokens[start..=end])
}

fn validate_exact_method_statements(
    tokens: &[String],
    type_name: &str,
    method_name: &str,
    attributes: &str,
    signature: &str,
    statements: &[&str],
) -> Result<(), String> {
    let implementation = inherent_impl_tokens(tokens, type_name)?;
    let function = function_tokens(implementation, method_name)?;
    let marker = ["pub", "fn", method_name];
    let function_start = sequence_start(function, &marker)
        .ok_or_else(|| format!("function {method_name} has no isolated signature"))?;
    let actual_attributes = &function[..function_start];
    let expected_attributes = rust_tokens(attributes);
    if actual_attributes != expected_attributes {
        return Err(format!(
            "{type_name}::{method_name} outer attributes drifted; expected {expected_attributes:?}, found {actual_attributes:?}"
        ));
    }
    let body = function
        .iter()
        .enumerate()
        .skip(function_start + marker.len())
        .find_map(|(index, token)| (token == "{").then_some(index))
        .ok_or_else(|| format!("function {method_name} has no isolated body"))?;
    let actual_signature = &function[function_start..=body];
    let expected_signature = rust_tokens(signature);
    if actual_signature != expected_signature {
        return Err(format!(
            "{type_name}::{method_name} signature drifted; expected {expected_signature:?}, found {actual_signature:?}"
        ));
    }
    let end = matching_delimiter(function, body)
        .ok_or_else(|| format!("function {method_name} has an unbalanced isolated body"))?;
    let actual = top_level_statements(&function[body + 1..end])?;
    let expected = statements
        .iter()
        .map(|statement| rust_tokens(statement))
        .collect::<Vec<_>>();
    if actual.len() != expected.len()
        || actual
            .iter()
            .zip(&expected)
            .any(|(actual, expected)| *actual != expected)
    {
        return Err(format!(
            "{type_name}::{method_name} top-level statements drifted; expected {expected:?}, found {actual:?}"
        ));
    }
    Ok(())
}

fn validate_appraisal_allow_construction(verification: &str) -> Result<(), String> {
    let tokens = rust_tokens(verification);
    validate_exact_method_statements(
        &tokens,
        "VerifierFlow",
        "complete",
        "",
        "pub fn complete(&mut self) -> Result<VerifiedAttestation, TransitionError> {",
        &[
            r#"let outcome = match &self.state {
                VerificationState::PolicySatisfied { allowed: AllowedClass::FULL, .. } => VerificationOutcome::allowed_full(),
                VerificationState::PolicySatisfied { allowed: AllowedClass::RESTRICTED, .. } => VerificationOutcome::allowed_restricted(),
                _ => return Err(self.invalid_transition(VerificationAction::Complete)),
            };"#,
            "let previous = std::mem::replace(&mut self.state, VerificationState::Verified { outcome });",
            r#"let VerificationState::PolicySatisfied {
                request,
                accepted_profile,
                session_public_key_id,
                allowed,
            } = previous else {
                unreachable!("phase was checked before terminal replacement")
            };"#,
            r#"Ok(VerifiedAttestation {
                binding: self.binding.clone(),
                context: request.expected,
                accepted_profile,
                session_public_key_id,
                allowed,
            })"#,
        ],
    )?;
    validate_exact_method_statements(
        &tokens,
        "VerifiedAttestation",
        "into_appraisal_result",
        r#"#[must_use = "the appraisal result carries the completed verifier outcome"]"#,
        "pub fn into_appraisal_result(self) -> AppraisalResult {",
        &[
            r#"let Self {
                binding,
                context,
                accepted_profile,
                session_public_key_id,
                allowed,
            } = self;"#,
            "drop(binding);",
            r#"let claims = AcceptedClaims {
                accepted_profile,
                session_public_key_id,
            };"#,
            r#"let payload = match allowed {
                AllowedClass::FULL => AppraisalPayload::Allow(claims),
                AllowedClass::RESTRICTED => AppraisalPayload::AllowRestricted(claims),
            };"#,
            "AppraisalResult { context, payload }",
        ],
    )
}

fn validate_appraisal_failure_methods(verification: &str) -> Result<(), String> {
    let tokens = rust_tokens(verification);
    for (method_name, signature, statement) in [
        (
            "mark_malformed",
            "pub fn mark_malformed(&mut self) -> Result<AppraisalResult, TransitionError> {",
            "self.emit_failure(FailureKind::Malformed)",
        ),
        (
            "mark_unsupported",
            "pub fn mark_unsupported(&mut self, requirement: UnsupportedRequirement,) -> Result<AppraisalResult, TransitionError> {",
            "self.emit_failure(FailureKind::Unsupported(requirement))",
        ),
        (
            "mark_retryable",
            "pub fn mark_retryable(&mut self, reason: RetryReason,) -> Result<AppraisalResult, TransitionError> {",
            "self.emit_failure(FailureKind::Retry(reason))",
        ),
        (
            "deny",
            "pub fn deny(&mut self, reason: DenialReason) -> Result<AppraisalResult, TransitionError> {",
            "self.emit_failure(FailureKind::Deny(reason))",
        ),
        (
            "mark_revoked",
            "pub fn mark_revoked(&mut self) -> Result<AppraisalResult, TransitionError> {",
            "self.emit_failure(FailureKind::Revoked)",
        ),
    ] {
        validate_exact_method_statements(
            &tokens,
            "VerifierFlow",
            method_name,
            "",
            signature,
            &[statement],
        )?;
    }
    Ok(())
}

#[test]
fn structural_rust_tokens_ignore_decoys_and_preserve_lifetimes() {
    let source = r###"
        // enum VerificationState { Decoy { pub(in crate) request: VerificationRequest } }
        /* outer /* nested pub state: VerificationState */ comment */
        const NORMAL: &str = "std::mem::replace(&mut self.state, terminal)";
        const BYTE: &[u8] = b"let VerificationState::Decoy = previous";
        const RAW: &str = r#"pub(in crate) allowed: AllowedClass"#;
        const BYTE_RAW: &[u8] = br##"Option<VerificationState>"##;
        const CHARACTER: char = 'x';
        const BYTE_CHARACTER: u8 = b'x';
        fn borrow<'a>(value: &'a str) -> &'a str { value }
        fn raw<'r#scope>() {}
    "###;

    assert_eq!(
        rust_tokens(source),
        [
            "const",
            "NORMAL",
            ":",
            "&",
            "str",
            "=",
            ";",
            "const",
            "BYTE",
            ":",
            "&",
            "[",
            "u8",
            "]",
            "=",
            ";",
            "const",
            "RAW",
            ":",
            "&",
            "str",
            "=",
            ";",
            "const",
            "BYTE_RAW",
            ":",
            "&",
            "[",
            "u8",
            "]",
            "=",
            ";",
            "const",
            "CHARACTER",
            ":",
            "char",
            "=",
            ";",
            "const",
            "BYTE_CHARACTER",
            ":",
            "u8",
            "=",
            ";",
            "fn",
            "borrow",
            "<",
            "'a",
            ">",
            "(",
            "value",
            ":",
            "&",
            "'a",
            "str",
            ")",
            "-",
            ">",
            "&",
            "'a",
            "str",
            "{",
            "value",
            "}",
            "fn",
            "raw",
            "<",
            "'r#scope",
            ">",
            "(",
            ")",
            "{",
            "}",
        ]
    );
}

#[test]
fn authority_structure_rejects_comment_and_string_declaration_decoys() {
    let source = include_str!("../verification.rs");
    let correct = "EvidenceReceived {\n        request: VerificationRequest,\n    }";
    let wrong = "EvidenceReceived {}";
    let mutated = source.replacen(correct, wrong, 1)
        + &format!("\n// {correct}\nconst DECOY: &str = {correct:?};\n");
    assert_ne!(mutated, source);
    assert!(validate_authority_structure(&mutated, include_str!("../freshness.rs")).is_err());
}

#[test]
fn authority_structure_rejects_restricted_field_visibility() {
    let source = include_str!("../verification.rs");
    let mutated = source.replacen(
        "    binding: VerificationBinding,\n    accepted_profile: EvidenceProfile,",
        "    pub(in crate) binding: VerificationBinding,\n    accepted_profile: EvidenceProfile,",
        1,
    );
    assert_ne!(mutated, source);
    assert!(validate_authority_structure(&mutated, include_str!("../freshness.rs")).is_err());
}

#[test]
fn authority_structure_rejects_an_extra_requestless_active_variant() {
    let source = include_str!("../verification.rs");
    let mutated = source.replacen(
        "    Verified {\n        outcome: VerificationOutcome,\n    },",
        "    InjectedActive,\n    Verified {\n        outcome: VerificationOutcome,\n    },",
        1,
    );
    assert_ne!(mutated, source);
    assert!(validate_authority_structure(&mutated, include_str!("../freshness.rs")).is_err());
}

#[test]
fn authority_structure_rejects_claims_retained_by_a_terminal_variant() {
    let source = include_str!("../verification.rs");
    let mutated = source.replacen(
        "    Verified {\n        outcome: VerificationOutcome,\n    },",
        "    Verified {\n        outcome: VerificationOutcome,\n        accepted_profile: EvidenceProfile,\n    },",
        1,
    );
    assert_ne!(mutated, source);
    assert!(validate_authority_structure(&mutated, include_str!("../freshness.rs")).is_err());
}

#[test]
fn active_replacement_rejects_option_take_and_comment_order_decoys() {
    let source = include_str!("../verification.rs");
    let replacement = "std::mem::replace(\n            &mut self.state,\n            VerificationState::Retryable";
    let mutated = source.replacen(
        replacement,
        "/* std::mem::replace(&mut self.state, VerificationState::Retryable) */\n        self.state.take();\n        std::mem::replace(\n            &mut self.state,\n            VerificationState::EvidenceReceived",
        1,
    );
    assert_ne!(mutated, source);
    assert!(validate_active_state_replacement(&mutated).is_err());
}

#[test]
fn active_replacement_rejects_direct_assignment_with_stringify_sequence_decoy() {
    let source = include_str!("../verification.rs");
    let correct = r#"        let previous = std::mem::replace(
            &mut self.state,
            VerificationState::Retryable {
                outcome: VerificationOutcome::retryable(RetryReason::TransientFailure),
            },
        );
        let VerificationState::EvidenceReceived { request } = previous else {
            unreachable!("phase was checked before active-state replacement")
        };
        self.state = VerificationState::ChallengeAuthenticated { request };"#;
    let bypass = r#"        self.state = match &self.state {
            VerificationState::EvidenceReceived { request } => {
                VerificationState::ChallengeAuthenticated {
                    request: request.clone(),
                }
            }
            _ => unreachable!(),
        };
        stringify!(
            let previous = std::mem::replace(
                &mut self.state,
                VerificationState::Retryable {
                    outcome: VerificationOutcome::retryable(RetryReason::TransientFailure),
                },
            );
            let VerificationState::EvidenceReceived { request } = previous else {
                unreachable!()
            };
            self.state = VerificationState::ChallengeAuthenticated { request };
        );"#;
    let mutated = source.replacen(correct, bypass, 1);

    assert_ne!(mutated, source);
    assert!(validate_active_state_replacement(&mutated).is_err());
}

#[test]
fn active_replacement_rejects_sequence_nested_under_unreachable_block() {
    let source = include_str!("../verification.rs");
    let correct = r#"        let previous = std::mem::replace(
            &mut self.state,
            VerificationState::Retryable {
                outcome: VerificationOutcome::retryable(RetryReason::TransientFailure),
            },
        );
        let VerificationState::EvidenceReceived { request } = previous else {
            unreachable!("phase was checked before active-state replacement")
        };
        self.state = VerificationState::ChallengeAuthenticated { request };"#;
    let nested = format!("        if false {{\n{correct}\n        }}");
    let mutated = source.replacen(correct, &nested, 1);

    assert_ne!(mutated, source);
    assert!(validate_active_state_replacement(&mutated).is_err());
}

#[test]
fn active_replacement_accepts_production_shaped_top_level_sequence() {
    assert!(validate_active_state_replacement(include_str!("../verification.rs")).is_ok());
}

#[test]
fn appraisal_allow_structure_rejects_complete_order_and_decoy_bypasses() {
    let source = include_str!("../verification.rs");
    let outcome = r#"let outcome = match &self.state {
            VerificationState::PolicySatisfied {
                allowed: AllowedClass::FULL,
                ..
            } => VerificationOutcome::allowed_full(),
            VerificationState::PolicySatisfied {
                allowed: AllowedClass::RESTRICTED,
                ..
            } => VerificationOutcome::allowed_restricted(),
            _ => return Err(self.invalid_transition(VerificationAction::Complete)),
        };"#;
    let terminal = "let previous = std::mem::replace(&mut self.state, VerificationState::Verified { outcome });";
    let ordered = format!("{outcome}\n        {terminal}");
    let reordered = source.replacen(&ordered, &format!("{terminal}\n        {outcome}"), 1);
    assert_ne!(reordered, source);
    assert!(validate_appraisal_allow_construction(&reordered).is_err());

    let intermediate = source.replacen(
        terminal,
        "let terminal = VerificationState::Verified { outcome };\n        let previous = std::mem::replace(&mut self.state, terminal);",
        1,
    );
    assert_ne!(intermediate, source);
    assert!(validate_appraisal_allow_construction(&intermediate).is_err());

    let cloned = source.replacen(
        "context: request.expected,",
        "context: request.expected.clone(),",
        1,
    );
    assert_ne!(cloned, source);
    assert!(validate_appraisal_allow_construction(&cloned).is_err());

    let result = "Ok(VerifiedAttestation {";
    let extra = source.replacen(
        result,
        "let extra = VerifiedAttestation { binding: self.binding.clone(), context: request.expected.clone(), accepted_profile: accepted_profile.clone(), session_public_key_id, allowed };\n        drop(extra);\n        Ok(VerifiedAttestation {",
        1,
    );
    assert_ne!(extra, source);
    assert!(validate_appraisal_allow_construction(&extra).is_err());

    let correct = function_tokens(&rust_tokens(source), "complete")
        .unwrap_or_else(|error| panic!("failed to isolate production complete: {error}"))
        .join(" ");
    let decoy = format!(
        "{source}\n/// `{correct}`\nimpl CompleteDecoy {{ pub fn complete(&mut self) {{ stringify!({correct}); if false {{ {correct} }} }} }}"
    );
    let bypass = decoy.replacen(terminal, "let previous = self.take_policy_state();", 1);
    assert_ne!(bypass, decoy);
    assert!(validate_appraisal_allow_construction(&bypass).is_err());
}

#[test]
fn appraisal_allow_structure_rejects_conversion_refill_and_decoy_bypasses() {
    let source = include_str!("../verification.rs");
    let ordered = r#"drop(binding);
        let claims = AcceptedClaims {
            accepted_profile,
            session_public_key_id,
        };"#;
    let reordered = source.replacen(
        ordered,
        r#"let claims = AcceptedClaims {
            accepted_profile,
            session_public_key_id,
        };
        drop(binding);"#,
        1,
    );
    assert_ne!(reordered, source);
    assert!(validate_appraisal_allow_construction(&reordered).is_err());

    let claims = r#"let claims = AcceptedClaims {
            accepted_profile,
            session_public_key_id,
        };"#;
    assert_eq!(source.matches(claims).count(), 1);
    let cloned = source.replacen(
        claims,
        r#"let claims = AcceptedClaims {
            accepted_profile: accepted_profile.clone(),
            session_public_key_id,
        };"#,
        1,
    );
    assert_ne!(cloned, source);
    assert!(validate_appraisal_allow_construction(&cloned).is_err());

    let result = "AppraisalResult { context, payload }";
    let extra = source.replacen(
        result,
        "let extra = AppraisalResult { context: context.clone(), payload };\n        drop(extra);\n        AppraisalResult { context, payload: AppraisalPayload::Allow(claims) }",
        1,
    );
    assert_ne!(extra, source);
    assert!(validate_appraisal_allow_construction(&extra).is_err());

    let correct = function_tokens(&rust_tokens(source), "into_appraisal_result")
        .unwrap_or_else(|error| panic!("failed to isolate production conversion: {error}"))
        .join(" ");
    let decoy = format!(
        "{source}\n/// `{correct}`\nimpl ConversionDecoy {{ pub fn into_appraisal_result(self) {{ stringify!({correct}); if false {{ {correct} }} }} }}"
    );
    let bypass = decoy.replacen(result, "self.refill_appraisal_result()", 1);
    assert_ne!(bypass, decoy);
    assert!(validate_appraisal_allow_construction(&bypass).is_err());
}

#[test]
fn appraisal_allow_structure_rejects_target_method_attribute_drift() {
    let source = include_str!("../verification.rs");
    let complete =
        "    pub fn complete(&mut self) -> Result<VerifiedAttestation, TransitionError> {";
    let cfg_complete = source.replacen(complete, &format!("    #[cfg(test)]\n{complete}"), 1);
    assert_ne!(cfg_complete, source);
    assert!(validate_appraisal_allow_construction(&cfg_complete).is_err());

    let must_use =
        "    #[must_use = \"the appraisal result carries the completed verifier outcome\"]\n";
    let missing_must_use = source.replacen(must_use, "", 1);
    assert_ne!(missing_must_use, source);
    assert!(validate_appraisal_allow_construction(&missing_must_use).is_err());

    let cfg_conversion = source.replacen(must_use, &format!("    #[cfg(test)]\n{must_use}"), 1);
    assert_ne!(cfg_conversion, source);
    assert!(validate_appraisal_allow_construction(&cfg_conversion).is_err());
}

#[test]
fn appraisal_allow_structure_does_not_misattribute_neighbor_attributes() {
    let source = include_str!("../verification.rs");
    let complete_docs =
        "    /// Completes the fully gated path and releases the owned raw request.";
    let neighboring = source.replacen(
        complete_docs,
        &format!("    #[inline]\n    fn attributed_neighbor() {{}}\n\n{complete_docs}"),
        1,
    );
    assert_ne!(neighboring, source);
    let decoys = neighboring
        + "\nimpl CompleteAttributeDecoy { #[cfg(test)] pub fn complete(&mut self) {} }"
        + "\nimpl ConversionAttributeDecoy { #[inline] pub fn into_appraisal_result(self) {} }";
    assert!(validate_appraisal_allow_construction(&decoys).is_ok());
}

#[test]
fn appraisal_allow_structure_accepts_production_methods() {
    if let Err(error) = validate_appraisal_allow_construction(include_str!("../verification.rs")) {
        panic!("appraisal allow construction drifted: {error}");
    }
}

#[test]
fn appraisal_failure_structure_rejects_attribute_signature_and_delegation_drift() {
    let source = include_str!("../verification.rs");
    let malformed =
        "    pub fn mark_malformed(&mut self) -> Result<AppraisalResult, TransitionError> {";
    let cfg_malformed = source.replacen(malformed, &format!("    #[cfg(test)]\n{malformed}"), 1);
    assert_ne!(cfg_malformed, source);
    assert!(validate_appraisal_failure_methods(&cfg_malformed).is_err());

    let deny = "pub fn deny(&mut self, reason: DenialReason) -> Result<AppraisalResult, TransitionError> {";
    let raw_decision = source.replacen(deny, &deny.replace("DenialReason", "Decision"), 1);
    assert_ne!(raw_decision, source);
    assert!(validate_appraisal_failure_methods(&raw_decision).is_err());

    let retry = "reason: RetryReason,";
    let raw_reason = source.replacen(retry, "reason: ReasonCode,", 1);
    assert_ne!(raw_reason, source);
    assert!(validate_appraisal_failure_methods(&raw_reason).is_err());

    let typed = "self.emit_failure(FailureKind::Unsupported(requirement))";
    let alternate = source.replacen(
        typed,
        "self.emit_failure(FailureKind::Unsupported(UnsupportedRequirement::UnknownCriticalRequirement))",
        1,
    );
    assert_ne!(alternate, source);
    assert!(validate_appraisal_failure_methods(&alternate).is_err());

    let revoked = "self.emit_failure(FailureKind::Revoked)";
    let extra = source.replacen(
        revoked,
        "let action = VerificationAction::MarkRevoked;\n        drop(action);\n        self.emit_failure(FailureKind::Revoked)",
        1,
    );
    assert_ne!(extra, source);
    assert!(validate_appraisal_failure_methods(&extra).is_err());

    let indirect = source.replacen(
        "self.emit_failure(FailureKind::Malformed)",
        "self.emit_malformed_failure()",
        1,
    );
    assert_ne!(indirect, source);
    assert!(validate_appraisal_failure_methods(&indirect).is_err());
}

#[test]
fn appraisal_failure_structure_rejects_target_decoys_but_ignores_neighbors() {
    let source = include_str!("../verification.rs");
    let retry = "self.emit_failure(FailureKind::Retry(reason))";
    let nested = source.replacen(
        retry,
        "if false { self.emit_failure(FailureKind::Retry(reason)); }\n        self.emit_failure(FailureKind::Retry(reason))",
        1,
    );
    assert_ne!(nested, source);
    assert!(validate_appraisal_failure_methods(&nested).is_err());

    let same_name = source.replacen(
        "impl VerifierFlow {",
        "impl VerifierFlow { pub fn mark_revoked(&mut self) -> Result<AppraisalResult, TransitionError> { stringify!(self.emit_failure(FailureKind::Revoked)); unreachable!() }",
        1,
    );
    assert_ne!(same_name, source);
    assert!(validate_appraisal_failure_methods(&same_name).is_err());

    let neighbors = format!(
        "{source}\n/// `#[cfg(test)] pub fn mark_malformed(&mut self) {{ self.emit_failure(FailureKind::Malformed) }}`\nimpl FailureMethodDecoy {{ #[cfg(test)] pub fn mark_malformed(&mut self) {{ stringify!(self.emit_failure(FailureKind::Malformed)); }} }}"
    );
    if let Err(error) = validate_appraisal_failure_methods(&neighbors) {
        panic!("neighbor failure-method decoys were misattributed: {error}");
    }
}

#[test]
fn appraisal_failure_structure_accepts_production_methods() {
    if let Err(error) = validate_appraisal_failure_methods(include_str!("../verification.rs")) {
        panic!("appraisal failure methods drifted: {error}");
    }
}

#[test]
fn top_level_statement_splitter_keeps_nested_constructs_together() {
    let tokens = rust_tokens(
        r#"
            let value = inspect(
                stringify!(first(); second()),
                || { first(); second(); },
                if condition { left() } else { right() },
            );
            if other { nested(); } else { nested_else(); }
            Ok(())
        "#,
    );
    let statements = top_level_statements(&tokens)
        .unwrap_or_else(|error| panic!("failed to split fixture statements: {error}"));
    let actual = statements
        .into_iter()
        .map(<[String]>::to_vec)
        .collect::<Vec<_>>();

    assert_eq!(
        actual,
        [
            rust_tokens(
                "let value = inspect(stringify!(first(); second()), || { first(); second(); }, if condition { left() } else { right() },);",
            ),
            rust_tokens("if other { nested(); } else { nested_else(); }"),
            rust_tokens("Ok(())"),
        ]
    );
}

#[test]
fn authority_fields_remain_private_by_structure() {
    let verification = include_str!("../verification.rs");
    if let Err(error) = validate_authority_structure(verification, include_str!("../freshness.rs"))
    {
        panic!("verification authority structure drifted: {error}");
    }
    if let Err(error) = validate_active_state_replacement(verification) {
        panic!("whole-state replacement drifted: {error}");
    }
    if let Err(error) = validate_appraisal_allow_construction(verification) {
        panic!("sole allow construction drifted: {error}");
    }
    if let Err(error) = validate_appraisal_failure_methods(verification) {
        panic!("failure method authority drifted: {error}");
    }
    if let Err(error) = validate_failure_eligibility(verification) {
        panic!("failure eligibility drifted: {error}");
    }
}

#[test]
fn authority_structure_rejects_result_authority_expansion_and_decoys() {
    let source = include_str!("../verification.rs");
    let result = "pub struct AppraisalResult {\n    context: ExpectedContext,\n    payload: AppraisalPayload,\n}";
    let public_context = source.replacen(result, &result.replace("context:", "pub context:"), 1);
    assert_ne!(public_context, source);
    assert!(
        validate_authority_structure(&public_context, include_str!("../freshness.rs")).is_err()
    );

    for mutation in [
        source.replacen(
            "payload: AppraisalPayload,",
            "payload: AppraisalPayload,\n    accepted_profile: Option<EvidenceProfile>,",
            1,
        ),
        format!(
            "{source}\nimpl AppraisalResult {{ pub fn builder() -> Self {{ unreachable!() }} }}"
        ),
        format!(
            "{source}\nimpl From<VerificationOutcome> for AppraisalResult {{ fn from(_: VerificationOutcome) -> Self {{ unreachable!() }} }}"
        ),
        format!("{source}\nimpl AppraisalResult {{ pub fn sign(self) {{}} }}"),
    ] {
        assert_ne!(mutation, source);
        assert!(validate_authority_structure(&mutation, include_str!("../freshness.rs")).is_err());
    }

    let decoys = format!(
        "{source}\n// pub fn sign(self) {{}}\nconst DECOY: &str = \"impl From<VerificationOutcome> for AppraisalResult\";"
    );
    assert!(validate_authority_structure(&decoys, include_str!("../freshness.rs")).is_ok());
}

#[test]
fn failure_eligibility_structure_rejects_macro_and_unreachable_decoys() {
    let source = include_str!("../verification.rs");
    let exact = "FailureKind::Malformed => phase == VerificationPhase::EvidenceReceived,";
    let bypass = source.replacen(
        exact,
        &format!(
            "FailureKind::Malformed => is_active_phase(phase),\n                FailureKind::Revoked if false => {{ stringify!({exact}); false }},"
        ),
        1,
    );
    assert_ne!(bypass, source);
    assert!(validate_failure_eligibility(&bypass).is_err());

    let decoys =
        format!("{source}\n// {exact}\nconst FAILURE_ELIGIBILITY_DECOY: &str = \"{exact}\";");
    assert!(validate_failure_eligibility(&decoys).is_ok());
}

#[test]
fn active_state_replacement_is_terminal_first_and_never_taken_from_option() {
    if let Err(error) = validate_active_state_replacement(include_str!("../verification.rs")) {
        panic!("active replacement structure drifted: {error}");
    }
}

#[test]
fn one_million_actions_match_the_independent_verifier_model() {
    let schedule = scheduled_actions();
    assert_eq!(schedule.len(), SCHEDULED_ACTIONS);
    let mut rng = Lcg(0x4f47_4952_4d31_3031);
    let mut coverage = Coverage::default();
    let mut flow = flow_fixture(101);
    let mut other_binding = flow_fixture(101).binding;
    let mut model = ModelState::EvidenceReceived;
    let mut arbitrary_action_counts = [0usize; 24];
    let mut arbitrary_terminal_resets = 0usize;
    let mut arbitrary_matching_gates = 0usize;
    let mut arbitrary_other_flow_gates = 0usize;
    let mut arbitrary_active_advances = 0usize;

    let action_stream = schedule
        .iter()
        .copied()
        .map(Some)
        .chain(std::iter::repeat_n(None, ARBITRARY_ACTIONS));
    let mut executed = 0usize;
    for (index, scheduled) in action_stream.enumerate() {
        let is_arbitrary = scheduled.is_none();
        let should_reset_arbitrary = is_arbitrary && model_is_terminal(model);
        let (reset_before, action) = match scheduled {
            Some(step) => (step.reset_before, step.action),
            None => (model_is_terminal(model), rng.action()),
        };
        if is_arbitrary {
            assert_eq!(reset_before, should_reset_arbitrary);
            arbitrary_action_counts[action_index(action)] += 1;
            match action.binding_mode() {
                Some(BindingMode::Matching) => arbitrary_matching_gates += 1,
                Some(BindingMode::OtherFlow) => arbitrary_other_flow_gates += 1,
                None => {}
            }
            if reset_before {
                arbitrary_terminal_resets += 1;
            }
        }
        if reset_before {
            let seed = seed_for_index(index);
            flow = flow_fixture(seed);
            other_binding = flow_fixture(seed).binding;
            model = ModelState::EvidenceReceived;
        }
        let model_before = model;
        let expected = expected_history_action(model, action);
        let before = flow_snapshot(&flow);
        let actual = apply_action(&mut flow, &other_binding, action);
        let after = flow_snapshot(&flow);
        if let ExpectedAction::Allowed(next) = expected {
            model = next;
        }
        coverage.observe(
            index,
            model_before,
            action,
            expected,
            (&before, &after),
            &actual,
        );
        if is_arbitrary
            && let ExpectedAction::Allowed(next) = expected
            && model_is_nonterminal(next)
            && next != model_before
        {
            arbitrary_active_advances += 1;
        }
        executed += 1;
    }

    assert_eq!(executed, TOTAL_ACTIONS);
    assert_eq!(executed, 1_048_576);
    assert_eq!(SCHEDULED_ACTIONS, 2_048);
    assert_eq!(ARBITRARY_ACTIONS, 1_046_528);
    assert_eq!(SCHEDULED_ACTIONS + ARBITRARY_ACTIONS, TOTAL_ACTIONS);
    assert!(
        arbitrary_action_counts.iter().all(|count| *count > 0),
        "arbitrary action counts: {arbitrary_action_counts:?}"
    );
    assert!(arbitrary_terminal_resets > 0);
    assert_eq!(arbitrary_matching_gates, ARBITRARY_MATCHING_GATES);
    assert_eq!(arbitrary_other_flow_gates, ARBITRARY_OTHER_FLOW_GATES);
    assert_eq!(arbitrary_active_advances, ARBITRARY_ACTIVE_ADVANCES);
    coverage.assert_non_vacuous();
}

#[test]
fn arbitrary_tail_uses_both_binding_modes_and_advances_active_state() {
    let mut rng = Lcg(0x4f47_4952_4d31_3031);
    let mut model = ModelState::EvidenceReceived;
    let mut matching_gates = 0usize;
    let mut other_flow_gates = 0usize;
    let mut active_advances = 0usize;

    for _ in 0..ARBITRARY_ACTIONS {
        if model_is_terminal(model) {
            model = ModelState::EvidenceReceived;
        }
        let action = rng.action();
        match action.binding_mode() {
            Some(BindingMode::Matching) => matching_gates += 1,
            Some(BindingMode::OtherFlow) => other_flow_gates += 1,
            None => {}
        }
        if let ExpectedAction::Allowed(next) = expected_history_action(model, action) {
            if model_is_nonterminal(next) && next != model {
                active_advances += 1;
            }
            model = next;
        }
    }

    assert_eq!(matching_gates, ARBITRARY_MATCHING_GATES);
    assert_eq!(other_flow_gates, ARBITRARY_OTHER_FLOW_GATES);
    assert_eq!(active_advances, ARBITRARY_ACTIVE_ADVANCES);
}

#[test]
fn history_projection_captures_exact_failure_context_and_view() {
    let mut flow = flow_fixture_with_context_tag(90, 9);
    let before = flow_snapshot(&flow);
    let other_binding = flow_fixture(91).binding;
    let action = TestAction::MarkMalformed;
    let actual = apply_action(&mut flow, &other_binding, action);

    assert_eq!(
        actual,
        Ok(expected_action_result(
            &before,
            ModelState::Malformed,
            action,
        ))
    );
}

#[test]
fn history_projection_captures_exact_full_and_restricted_allows() {
    for allowed in [AllowedClass::Full, AllowedClass::Restricted] {
        let mut flow = policy_ready_flow_with_context_tag(
            92,
            10,
            accepted_profile(),
            session_key_id(7),
            allowed,
        );
        let before = flow_snapshot(&flow);
        let other_binding = flow_fixture(93).binding;
        let action = TestAction::Complete;
        let actual = apply_action(&mut flow, &other_binding, action);

        assert_eq!(
            actual,
            Ok(expected_action_result(
                &before,
                ModelState::Verified(allowed),
                action,
            ))
        );
    }
}

#[test]
fn successful_history_transitions_carry_and_add_exact_values() {
    let mut flow = flow_fixture_with_context_tag(94, 11);
    let other_binding = flow_fixture(95).binding;
    let mut model = ModelState::EvidenceReceived;

    for action in MATCHING_GATE_PREFIX {
        let before = flow_snapshot(&flow);
        let next = match model_transition(model, action) {
            Some(value) => value,
            None => panic!("canonical action rejected by model: {model:?} {action:?}"),
        };
        let actual = apply_action(&mut flow, &other_binding, action);
        let after = flow_snapshot(&flow);
        assert_action_matches_model(
            0,
            action,
            ExpectedAction::Allowed(next),
            &before,
            &after,
            &actual,
        );
        model = next;
    }
}

const ALL_8_ACTIVE_MODEL_STATES: [ModelState; 8] = [
    ModelState::EvidenceReceived,
    ModelState::ChallengeAuthenticated,
    ModelState::FreshnessChecked,
    ModelState::IdentityChecked,
    ModelState::EvidenceAppraised,
    ModelState::SessionBound,
    ModelState::RevocationChecked,
    ModelState::PolicySatisfied(AllowedClass::Full),
];

const ALL_15_FAILURE_ACTIONS: [TestAction; 15] = [
    TestAction::MarkMalformed,
    TestAction::MarkUnsupported(UnsupportedRequirement::VersionOrProfile),
    TestAction::MarkUnsupported(UnsupportedRequirement::Platform),
    TestAction::MarkUnsupported(UnsupportedRequirement::UnknownCriticalRequirement),
    TestAction::MarkRetryable(RetryReason::AttestationUnavailable),
    TestAction::MarkRetryable(RetryReason::TransientFailure),
    TestAction::Deny(DenialReason::ChallengeAuthenticationFailed),
    TestAction::Deny(DenialReason::NotYetValid),
    TestAction::Deny(DenialReason::Expired),
    TestAction::Deny(DenialReason::ReplayDetected),
    TestAction::Deny(DenialReason::ContextBindingMismatch),
    TestAction::Deny(DenialReason::EvidenceInvalid),
    TestAction::Deny(DenialReason::PolicyDenied),
    TestAction::Deny(DenialReason::ProtectedSessionLost),
    TestAction::MarkRevoked,
];

fn eligible_failure_edges() -> Vec<(ModelState, TestAction)> {
    use DenialReason::{
        ChallengeAuthenticationFailed, ContextBindingMismatch, EvidenceInvalid, Expired,
        NotYetValid, PolicyDenied, ProtectedSessionLost, ReplayDetected,
    };
    use ModelState::{
        ChallengeAuthenticated, EvidenceAppraised, EvidenceReceived, FreshnessChecked,
        IdentityChecked, RevocationChecked, SessionBound,
    };
    use RetryReason::{AttestationUnavailable, TransientFailure};
    use TestAction::{Deny, MarkMalformed, MarkRetryable, MarkRevoked, MarkUnsupported};
    use UnsupportedRequirement::{Platform, UnknownCriticalRequirement, VersionOrProfile};

    let retry = [
        MarkRetryable(AttestationUnavailable),
        MarkRetryable(TransientFailure),
    ];
    let unknown = MarkUnsupported(UnknownCriticalRequirement);
    let mut edges = vec![
        (EvidenceReceived, MarkMalformed),
        (EvidenceReceived, Deny(ChallengeAuthenticationFailed)),
        (EvidenceReceived, retry[0]),
        (EvidenceReceived, retry[1]),
        (EvidenceReceived, unknown),
        (ChallengeAuthenticated, MarkUnsupported(VersionOrProfile)),
        (ChallengeAuthenticated, Deny(NotYetValid)),
        (ChallengeAuthenticated, Deny(Expired)),
        (ChallengeAuthenticated, Deny(ReplayDetected)),
        (ChallengeAuthenticated, Deny(ContextBindingMismatch)),
        (ChallengeAuthenticated, retry[0]),
        (ChallengeAuthenticated, retry[1]),
        (ChallengeAuthenticated, unknown),
        (FreshnessChecked, Deny(ContextBindingMismatch)),
        (FreshnessChecked, retry[0]),
        (FreshnessChecked, retry[1]),
        (FreshnessChecked, unknown),
        (IdentityChecked, MarkUnsupported(Platform)),
        (IdentityChecked, Deny(EvidenceInvalid)),
        (IdentityChecked, retry[0]),
        (IdentityChecked, retry[1]),
        (IdentityChecked, unknown),
        (EvidenceAppraised, Deny(ContextBindingMismatch)),
        (EvidenceAppraised, Deny(ProtectedSessionLost)),
        (EvidenceAppraised, retry[0]),
        (EvidenceAppraised, retry[1]),
        (EvidenceAppraised, unknown),
        (SessionBound, MarkRevoked),
        (SessionBound, Deny(ProtectedSessionLost)),
        (SessionBound, retry[0]),
        (SessionBound, retry[1]),
        (SessionBound, unknown),
        (RevocationChecked, Deny(PolicyDenied)),
        (RevocationChecked, Deny(ProtectedSessionLost)),
        (RevocationChecked, retry[0]),
        (RevocationChecked, retry[1]),
        (RevocationChecked, unknown),
    ];
    for action in [Deny(ProtectedSessionLost), retry[0], retry[1], unknown] {
        edges.push((ModelState::PolicySatisfied(AllowedClass::Full), action));
    }
    edges
}

fn failure_mapping(action: TestAction) -> (VerificationPhase, Decision, ReasonCode) {
    match action {
        TestAction::MarkMalformed => (
            VerificationPhase::Malformed,
            Decision::Deny,
            ReasonCode::Malformed,
        ),
        TestAction::MarkUnsupported(requirement) => (
            VerificationPhase::Unsupported,
            Decision::Unsupported,
            match requirement {
                UnsupportedRequirement::VersionOrProfile => ReasonCode::UnsupportedVersionOrProfile,
                UnsupportedRequirement::Platform => ReasonCode::UnsupportedPlatform,
                UnsupportedRequirement::UnknownCriticalRequirement => {
                    ReasonCode::UnsupportedCriticalRequirement
                }
            },
        ),
        TestAction::MarkRetryable(reason) => (
            VerificationPhase::Retryable,
            Decision::Retry,
            match reason {
                RetryReason::AttestationUnavailable => ReasonCode::AttestationUnavailable,
                RetryReason::TransientFailure => ReasonCode::TransientFailure,
            },
        ),
        TestAction::Deny(reason) => (
            VerificationPhase::Denied,
            Decision::Deny,
            model_denial_reason(reason),
        ),
        TestAction::MarkRevoked => (
            VerificationPhase::Revoked,
            Decision::Deny,
            ReasonCode::Revoked,
        ),
        _ => panic!("non-failure action in failure mapping: {action:?}"),
    }
}

fn flow_for_active_state_with_context(state: ModelState, seed: u8, tag: u8) -> VerifierFlow {
    let flow = VerifierFlow::begin(request_fixture_with_context_tag(seed, tag));
    let other_binding = flow_fixture(seed.wrapping_add(1)).binding;
    advance_flow_to_model_state(flow, state, &other_binding)
}

fn emit_test_failure(
    flow: &mut VerifierFlow,
    action: TestAction,
) -> Result<AppraisalResult, TransitionError> {
    match action {
        TestAction::MarkMalformed => flow.mark_malformed(),
        TestAction::MarkUnsupported(requirement) => flow.mark_unsupported(requirement),
        TestAction::MarkRetryable(reason) => flow.mark_retryable(reason),
        TestAction::Deny(reason) => flow.deny(reason),
        TestAction::MarkRevoked => flow.mark_revoked(),
        _ => panic!("non-failure action passed to failure emitter: {action:?}"),
    }
}

fn assert_exact_failure_result(
    result: &AppraisalResult,
    expected_context: &ExpectedContext,
    expected_decision: Decision,
    expected_reason: ReasonCode,
) {
    assert_eq!(result.context(), expected_context);
    assert_eq!(result.decision(), expected_decision);
    assert_eq!(result.reason(), Some(expected_reason));
    assert!(matches!(
        result.view(),
        AppraisalResultView::Failure { decision, reason }
            if decision == expected_decision && reason == expected_reason
    ));
}

#[test]
fn failure_after_session_binding_discards_all_accepted_claims() {
    let state = ModelState::SessionBound;
    let mut flow = flow_for_active_state_with_context(state, 41, 1);
    let expected_context = request_fixture_with_context_tag(41, 1).expected;
    let result = match flow.mark_revoked() {
        Ok(value) => value,
        Err(error) => panic!("eligible revocation rejected: {error:?}"),
    };
    assert_exact_failure_result(
        &result,
        &expected_context,
        Decision::Deny,
        ReasonCode::Revoked,
    );
    assert_eq!(flow.phase(), VerificationPhase::Revoked);
    assert_eq!(flow_snapshot(&flow).accepted_profile, None);
    assert_eq!(flow_snapshot(&flow).session_public_key_id, None);
}

#[test]
fn policy_denial_before_revocation_check_is_rejected_unchanged() {
    let mut flow = flow_for_model_state(ModelState::IdentityChecked, 42);
    let before = flow_snapshot(&flow);
    match flow.deny(DenialReason::PolicyDenied) {
        Err(error) => assert_eq!(
            error,
            TransitionError::InvalidTransition {
                phase: VerificationPhase::IdentityChecked,
                action: VerificationAction::Deny,
            }
        ),
        Ok(_) => panic!("policy denial succeeded before revocation checking"),
    }
    assert_eq!(flow_snapshot(&flow), before);
}

#[test]
fn all_41_phase_eligible_failure_edges_emit_exact_results() {
    let edges = eligible_failure_edges();
    assert_eq!(edges.len(), 41);
    for (index, (state, action)) in edges.into_iter().enumerate() {
        let seed = 60 + index as u8;
        let mut flow = flow_for_active_state_with_context(state, seed, 2);
        let expected_context = request_fixture_with_context_tag(seed, 2).expected;
        let (terminal, decision, reason) = failure_mapping(action);
        let result = match emit_test_failure(&mut flow, action) {
            Ok(value) => value,
            Err(error) => panic!("eligible edge rejected: {state:?} {action:?}: {error:?}"),
        };
        assert_exact_failure_result(&result, &expected_context, decision, reason);
        assert_eq!(flow.phase(), terminal);
    }
}

#[test]
fn all_phase_ineligible_failures_reject_without_mutation() {
    let eligible = eligible_failure_edges();
    let mut rejected = 0;
    for state in ALL_8_ACTIVE_MODEL_STATES {
        for action in ALL_15_FAILURE_ACTIONS {
            if eligible.contains(&(state, action)) {
                continue;
            }
            let mut flow = flow_for_model_state(state, 120);
            let before = flow_snapshot(&flow);
            match emit_test_failure(&mut flow, action) {
                Err(error) => assert_eq!(
                    error,
                    TransitionError::InvalidTransition {
                        phase: model_phase(state),
                        action: action.public(),
                    }
                ),
                Ok(_) => panic!("ineligible edge emitted a result: {state:?} {action:?}"),
            }
            assert_eq!(flow_snapshot(&flow), before);
            rejected += 1;
        }
    }
    assert_eq!(rejected, 79);
}

#[test]
fn failure_terminals_store_no_claims_from_every_claim_bearing_phase() {
    for (state, action) in [
        (
            ModelState::EvidenceAppraised,
            TestAction::Deny(DenialReason::ProtectedSessionLost),
        ),
        (ModelState::SessionBound, TestAction::MarkRevoked),
        (
            ModelState::RevocationChecked,
            TestAction::Deny(DenialReason::PolicyDenied),
        ),
        (
            ModelState::PolicySatisfied(AllowedClass::Full),
            TestAction::Deny(DenialReason::ProtectedSessionLost),
        ),
    ] {
        let mut flow = flow_for_model_state(state, 43);
        let result = emit_test_failure(&mut flow, action);
        assert!(result.is_ok());
        let snapshot = flow_snapshot(&flow);
        assert!(snapshot.request.is_none());
        assert!(snapshot.accepted_profile.is_none());
        assert!(snapshot.session_public_key_id.is_none());
        assert!(snapshot.allowed.is_none());
        assert!(matches!(
            &flow.state,
            VerificationState::Denied { .. } | VerificationState::Revoked { .. }
        ));
    }
}

#[test]
fn every_failure_terminal_rejects_repeat_emission() {
    for (state, first) in [
        (ModelState::EvidenceReceived, TestAction::MarkMalformed),
        (
            ModelState::ChallengeAuthenticated,
            TestAction::MarkUnsupported(UnsupportedRequirement::VersionOrProfile),
        ),
        (
            ModelState::EvidenceReceived,
            TestAction::MarkRetryable(RetryReason::AttestationUnavailable),
        ),
        (
            ModelState::EvidenceReceived,
            TestAction::Deny(DenialReason::ChallengeAuthenticationFailed),
        ),
        (ModelState::SessionBound, TestAction::MarkRevoked),
    ] {
        let mut flow = flow_for_model_state(state, 44);
        let first_result = match emit_test_failure(&mut flow, first) {
            Ok(value) => value,
            Err(error) => panic!("first failure emission rejected: {error:?}"),
        };
        drop(first_result);
        let terminal = flow.phase();
        for repeated in ALL_15_FAILURE_ACTIONS {
            match emit_test_failure(&mut flow, repeated) {
                Err(error) => assert_eq!(
                    error,
                    TransitionError::InvalidTransition {
                        phase: terminal,
                        action: repeated.public(),
                    }
                ),
                Ok(_) => panic!("terminal emitted a repeated result: {terminal:?} {repeated:?}"),
            }
        }
    }
}

#[test]
fn every_failure_reason_has_its_only_valid_reporting_mapping() {
    let eligible = eligible_failure_edges();
    for action in ALL_15_FAILURE_ACTIONS {
        let state = match eligible.iter().find(|(_, candidate)| *candidate == action) {
            Some((state, _)) => *state,
            None => panic!("failure action has no eligible phase: {action:?}"),
        };
        let mut flow = flow_for_model_state(state, 45);
        let (_, decision, reason) = failure_mapping(action);
        let result = match emit_test_failure(&mut flow, action) {
            Ok(value) => value,
            Err(error) => panic!("mapped failure rejected: {action:?}: {error:?}"),
        };
        assert_eq!(result.decision(), decision);
        assert_eq!(result.reason(), Some(reason));
    }
}

#[test]
fn every_result_accessor_and_view_mapping_is_exact() {
    for allowed in [AllowedClass::Full, AllowedClass::Restricted] {
        let expected_profile = accepted_profile();
        let expected_key = session_key_id(46);
        let mut flow = policy_ready_flow_with_context_tag(
            46,
            3,
            expected_profile.clone(),
            expected_key,
            allowed,
        );
        let expected_context = request_fixture_with_context_tag(46, 3).expected;
        let verified = match flow.complete() {
            Ok(value) => value,
            Err(error) => panic!("allow completion rejected: {error:?}"),
        };
        let result = verified.into_appraisal_result();
        assert_eq!(result.context(), &expected_context);
        assert_eq!(
            result.decision(),
            match allowed {
                AllowedClass::Full => Decision::Allow,
                AllowedClass::Restricted => Decision::AllowRestricted,
            }
        );
        assert_eq!(result.reason(), None);
        match (allowed, result.view()) {
            (AllowedClass::Full, AppraisalResultView::Allow(claims))
            | (AllowedClass::Restricted, AppraisalResultView::AllowRestricted(claims)) => {
                assert_eq!(claims.accepted_profile(), &expected_profile);
                assert_eq!(claims.session_public_key_id(), &expected_key);
            }
            _ => panic!("allow result view did not match its selected class"),
        }
    }

    let eligible = eligible_failure_edges();
    for action in ALL_15_FAILURE_ACTIONS {
        let state = match eligible.iter().find(|(_, candidate)| *candidate == action) {
            Some((state, _)) => *state,
            None => panic!("failure action has no eligible phase: {action:?}"),
        };
        let mut flow = flow_for_model_state(state, 47);
        let (_, decision, reason) = failure_mapping(action);
        let result = match emit_test_failure(&mut flow, action) {
            Ok(value) => value,
            Err(error) => panic!("failure result rejected: {action:?}: {error:?}"),
        };
        assert_eq!(result.decision(), decision);
        assert_eq!(result.reason(), Some(reason));
        assert!(matches!(
            result.view(),
            AppraisalResultView::Failure {
                decision: actual_decision,
                reason: actual_reason,
            } if actual_decision == decision && actual_reason == reason
        ));
    }
}
