// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::num::NonZeroU64;

use ogir_model::{
    AccountScope, BuildId, ChallengeLifetime, ChallengeWindow, Decision, EvidenceProfile, GameId,
    IdentifierError, MatchId, Nonce, PolicyId, PolicyVersion, ProtocolVersion, PublisherChallenge,
    PublisherId, ReasonCode, UnixTime,
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
            policy_version: PolicyVersion::new(1),
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

fn advance_to_policy_ready(flow: &mut VerifierFlow, allowed: AllowedClass) {
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
        }),
        Ok(())
    );
    assert_eq!(
        flow.record_session_bound(SessionBound {
            binding: binding.clone(),
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

fn policy_ready_flow(seed: u8, allowed: AllowedClass) -> VerifierFlow {
    let mut flow = flow_fixture(seed);
    advance_to_policy_ready(&mut flow, allowed);
    flow
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionResult {
    NoCapability,
    Verified,
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
    MarkUnsupported,
    MarkRetryable,
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
            Self::MarkUnsupported => VerificationAction::MarkUnsupported,
            Self::MarkRetryable => VerificationAction::MarkRetryable,
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
            | Self::MarkUnsupported
            | Self::MarkRetryable
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
            | Self::MarkUnsupported
            | Self::MarkRetryable
            | Self::Deny(_)
            | Self::MarkRevoked => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlowSnapshot {
    phase: VerificationPhase,
    outcome: Option<VerificationOutcome>,
    has_request: bool,
}

fn flow_snapshot(flow: &VerifierFlow) -> FlowSnapshot {
    FlowSnapshot {
        phase: flow.phase(),
        outcome: flow.outcome(),
        has_request: flow.request.is_some(),
    }
}

const ALL_13_MATRIX_ACTIONS: [TestAction; 13] = [
    TestAction::Challenge(BindingMode::Matching),
    TestAction::Freshness(BindingMode::Matching),
    TestAction::Identity(BindingMode::Matching),
    TestAction::Evidence(BindingMode::Matching),
    TestAction::Session(BindingMode::Matching),
    TestAction::Revocation(BindingMode::Matching),
    TestAction::Policy(AllowedClass::Full, BindingMode::Matching),
    TestAction::Complete,
    TestAction::MarkMalformed,
    TestAction::MarkUnsupported,
    TestAction::MarkRetryable,
    TestAction::Deny(DenialReason::PolicyDenied),
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
    Unsupported,
    Retryable,
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
    ModelState::Unsupported,
    ModelState::Retryable,
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
        (ModelState::RevocationChecked, TestAction::Policy(class, BindingMode::Matching)) => {
            Some(ModelState::PolicySatisfied(class))
        }
        (ModelState::PolicySatisfied(class), TestAction::Complete) => {
            Some(ModelState::Verified(class))
        }
        (state, TestAction::MarkMalformed) if model_is_nonterminal(state) => {
            Some(ModelState::Malformed)
        }
        (state, TestAction::MarkUnsupported) if model_is_nonterminal(state) => {
            Some(ModelState::Unsupported)
        }
        (state, TestAction::MarkRetryable) if model_is_nonterminal(state) => {
            Some(ModelState::Retryable)
        }
        (state, TestAction::Deny(reason)) if model_is_nonterminal(state) => {
            Some(ModelState::Denied(reason))
        }
        (state, TestAction::MarkRevoked) if model_is_nonterminal(state) => {
            Some(ModelState::Revoked)
        }
        _ => None,
    }
}

fn model_is_nonterminal(state: ModelState) -> bool {
    matches!(
        state,
        ModelState::EvidenceReceived
            | ModelState::ChallengeAuthenticated
            | ModelState::FreshnessChecked
            | ModelState::IdentityChecked
            | ModelState::EvidenceAppraised
            | ModelState::SessionBound
            | ModelState::RevocationChecked
            | ModelState::PolicySatisfied(_)
    )
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
        ModelState::Unsupported => VerificationPhase::Unsupported,
        ModelState::Retryable => VerificationPhase::Retryable,
        ModelState::Denied(_) => VerificationPhase::Denied,
        ModelState::Revoked => VerificationPhase::Revoked,
    }
}

fn model_denial_reason(reason: DenialReason) -> ReasonCode {
    match reason {
        DenialReason::NotYetValid => ReasonCode::NotYetValid,
        DenialReason::Expired => ReasonCode::Expired,
        DenialReason::ReplayDetected => ReasonCode::ReplayDetected,
        DenialReason::SessionBindingMismatch => ReasonCode::SessionBindingMismatch,
        DenialReason::EvidenceInvalid => ReasonCode::EvidenceInvalid,
        DenialReason::PolicyDenied => ReasonCode::PolicyDenied,
        DenialReason::ProtectedSessionLost => ReasonCode::ProtectedSessionLost,
    }
}

fn model_report(state: ModelState) -> Option<(Decision, ReasonCode)> {
    match state {
        ModelState::Verified(AllowedClass::Full) => Some((Decision::Allow, ReasonCode::None)),
        ModelState::Verified(AllowedClass::Restricted) => {
            Some((Decision::AllowRestricted, ReasonCode::None))
        }
        ModelState::Malformed => Some((Decision::Deny, ReasonCode::Malformed)),
        ModelState::Unsupported => Some((Decision::Unsupported, ReasonCode::UnsupportedVersion)),
        ModelState::Retryable => Some((Decision::Retry, ReasonCode::AttestationUnavailable)),
        ModelState::Denied(reason) => Some((Decision::Deny, model_denial_reason(reason))),
        ModelState::Revoked => Some((Decision::Deny, ReasonCode::Revoked)),
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

fn apply_action(
    flow: &mut VerifierFlow,
    other_binding: &VerificationBinding,
    action: TestAction,
) -> Result<ActionResult, TransitionError> {
    match action {
        TestAction::Challenge(mode) => {
            let binding = selected_binding(flow, other_binding, mode);
            flow.record_challenge_authenticated(ChallengeAuthenticated { binding })?;
            Ok(ActionResult::NoCapability)
        }
        TestAction::Freshness(mode) => {
            let binding = selected_binding(flow, other_binding, mode);
            flow.record_freshness_checked(crate::freshness::test_freshness_checked(binding))?;
            Ok(ActionResult::NoCapability)
        }
        TestAction::Identity(mode) => {
            let binding = selected_binding(flow, other_binding, mode);
            flow.record_identity_checked(IdentityChecked { binding })?;
            Ok(ActionResult::NoCapability)
        }
        TestAction::Evidence(mode) => {
            let binding = selected_binding(flow, other_binding, mode);
            flow.record_evidence_appraised(EvidenceAppraised { binding })?;
            Ok(ActionResult::NoCapability)
        }
        TestAction::Session(mode) => {
            let binding = selected_binding(flow, other_binding, mode);
            flow.record_session_bound(SessionBound { binding })?;
            Ok(ActionResult::NoCapability)
        }
        TestAction::Revocation(mode) => {
            let binding = selected_binding(flow, other_binding, mode);
            flow.record_revocation_checked(RevocationChecked { binding })?;
            Ok(ActionResult::NoCapability)
        }
        TestAction::Policy(allowed, mode) => {
            let binding = selected_binding(flow, other_binding, mode);
            flow.record_policy_satisfied(PolicySatisfied { binding, allowed })?;
            Ok(ActionResult::NoCapability)
        }
        TestAction::Complete => {
            let verified = flow.complete()?;
            drop(verified);
            Ok(ActionResult::Verified)
        }
        TestAction::MarkMalformed => {
            flow.mark_malformed()?;
            Ok(ActionResult::NoCapability)
        }
        TestAction::MarkUnsupported => {
            flow.mark_unsupported()?;
            Ok(ActionResult::NoCapability)
        }
        TestAction::MarkRetryable => {
            flow.mark_retryable()?;
            Ok(ActionResult::NoCapability)
        }
        TestAction::Deny(reason) => {
            flow.deny(reason)?;
            Ok(ActionResult::NoCapability)
        }
        TestAction::MarkRevoked => {
            flow.mark_revoked()?;
            Ok(ActionResult::NoCapability)
        }
    }
}

fn flow_for_model_state(state: ModelState, seed: u8) -> VerifierFlow {
    let mut flow = flow_fixture(seed);
    match state {
        ModelState::Malformed => {
            assert_eq!(flow.mark_malformed(), Ok(()));
            return flow;
        }
        ModelState::Unsupported => {
            assert_eq!(flow.mark_unsupported(), Ok(()));
            return flow;
        }
        ModelState::Retryable => {
            assert_eq!(flow.mark_retryable(), Ok(()));
            return flow;
        }
        ModelState::Denied(reason) => {
            assert_eq!(flow.deny(reason), Ok(()));
            return flow;
        }
        ModelState::Revoked => {
            assert_eq!(flow.mark_revoked(), Ok(()));
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
        | ModelState::Unsupported
        | ModelState::Retryable
        | ModelState::Denied(_)
        | ModelState::Revoked => unreachable!("failure states returned above"),
    };
    let other_binding = flow_fixture(seed.wrapping_add(1)).binding;
    for gate in ALL_7_GATE_KINDS.into_iter().take(gate_count) {
        let action = gate.matching_action(allowed);
        assert_eq!(action.public(), gate.action());
        assert_eq!(
            apply_action(&mut flow, &other_binding, action),
            Ok(ActionResult::NoCapability)
        );
    }
    if should_complete {
        assert_eq!(
            apply_action(&mut flow, &other_binding, TestAction::Complete),
            Ok(ActionResult::Verified)
        );
    }
    flow
}

fn assert_flow_matches_model(flow: &VerifierFlow, state: ModelState) {
    assert_eq!(flow.phase(), model_phase(state));
    assert_eq!(
        flow.outcome()
            .map(|outcome| (outcome.decision(), outcome.reason())),
        model_report(state)
    );
    assert_eq!(flow.request.is_some(), model_is_nonterminal(state));
}

fn assert_every_action_rejected(flow: &mut VerifierFlow) {
    let other_binding = flow_fixture(250).binding;
    let current_phase = flow.phase();
    for action in ALL_13_MATRIX_ACTIONS {
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
        }),
        Ok(())
    );
    assert_eq!(
        flow.record_session_bound(SessionBound {
            binding: binding.clone(),
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
    assert_eq!(flow.phase(), VerificationPhase::Verified);
    assert_eq!(
        flow.outcome().map(VerificationOutcome::decision),
        Some(Decision::Allow)
    );
    assert_eq!(
        flow.outcome().map(VerificationOutcome::reason),
        Some(ReasonCode::None)
    );
    assert_eq!(format!("{verified:?}"), "VerifiedAttestation([REDACTED])");
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
    assert!(flow.request.is_some());
}

#[test]
fn equal_request_from_another_flow_rejects_challenge_capability() {
    let source = flow_fixture(8);
    let mut target = flow_fixture(8);
    assert_eq!(source.request.as_ref(), target.request.as_ref());
    let before_phase = target.phase();
    let before_request = target.request.clone();

    let action = TestAction::Challenge(BindingMode::OtherFlow);
    assert_eq!(action.binding_mode(), Some(BindingMode::OtherFlow));

    assert_eq!(
        apply_action(&mut target, &source.binding, action),
        Err(TransitionError::CapabilityRejected {
            action: VerificationAction::RecordChallengeAuthenticated,
        })
    );
    assert_eq!(target.phase(), before_phase);
    assert_eq!(target.request, before_request);
}

#[test]
fn restricted_success_uses_the_same_complete_gate() {
    let mut flow = policy_ready_flow(9, AllowedClass::Restricted);
    assert!(flow.complete().is_ok());
    assert_eq!(
        flow.outcome().map(VerificationOutcome::decision),
        Some(Decision::AllowRestricted)
    );
    assert_eq!(
        flow.outcome().map(VerificationOutcome::reason),
        Some(ReasonCode::None)
    );
}

#[test]
fn every_failure_class_is_terminal_and_releases_the_request() {
    for (action, expected_phase, expected_decision, expected_reason) in [
        (
            TestAction::MarkMalformed,
            VerificationPhase::Malformed,
            Decision::Deny,
            ReasonCode::Malformed,
        ),
        (
            TestAction::MarkUnsupported,
            VerificationPhase::Unsupported,
            Decision::Unsupported,
            ReasonCode::UnsupportedVersion,
        ),
        (
            TestAction::MarkRetryable,
            VerificationPhase::Retryable,
            Decision::Retry,
            ReasonCode::AttestationUnavailable,
        ),
        (
            TestAction::Deny(DenialReason::PolicyDenied),
            VerificationPhase::Denied,
            Decision::Deny,
            ReasonCode::PolicyDenied,
        ),
        (
            TestAction::MarkRevoked,
            VerificationPhase::Revoked,
            Decision::Deny,
            ReasonCode::Revoked,
        ),
    ] {
        let mut flow = flow_fixture(31);
        let other_binding = flow_fixture(31).binding;
        assert_eq!(
            apply_action(&mut flow, &other_binding, action),
            Ok(ActionResult::NoCapability)
        );
        assert_eq!(flow.phase(), expected_phase);
        assert_eq!(
            flow.outcome().map(VerificationOutcome::decision),
            Some(expected_decision)
        );
        assert_eq!(
            flow.outcome().map(VerificationOutcome::reason),
            Some(expected_reason)
        );
        assert!(flow.request.is_none());
        assert_every_action_rejected(&mut flow);
    }
}

#[test]
fn every_denial_reason_has_its_only_valid_reporting_mapping() {
    for (index, (reason, expected)) in [
        (DenialReason::NotYetValid, ReasonCode::NotYetValid),
        (DenialReason::Expired, ReasonCode::Expired),
        (DenialReason::ReplayDetected, ReasonCode::ReplayDetected),
        (
            DenialReason::SessionBindingMismatch,
            ReasonCode::SessionBindingMismatch,
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
        let mut flow = flow_fixture(32 + index as u8);
        assert_eq!(flow.deny(reason), Ok(()));
        assert_eq!(
            flow.outcome().map(VerificationOutcome::decision),
            Some(Decision::Deny)
        );
        assert_eq!(
            flow.outcome().map(VerificationOutcome::reason),
            Some(expected)
        );
    }
}

#[test]
fn unknown_mandatory_gate_maps_to_unsupported() {
    let mut flow = flow_fixture(44);
    assert_eq!(flow.mark_unsupported(), Ok(()));
    assert_eq!(flow.phase(), VerificationPhase::Unsupported);
    assert_eq!(
        flow.outcome().map(VerificationOutcome::reason),
        Some(ReasonCode::UnsupportedVersion)
    );
}

#[test]
fn all_182_phase_action_pairs_match_the_independent_model() {
    let mut succeeded = 0usize;
    let mut rejected = 0usize;
    for state in ALL_14_MODEL_STATES {
        for action in ALL_13_MATRIX_ACTIONS {
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
            match expected {
                Some(next) => {
                    let expected_result = if matches!(action, TestAction::Complete) {
                        ActionResult::Verified
                    } else {
                        ActionResult::NoCapability
                    };
                    assert_eq!(
                        actual,
                        Ok(expected_result),
                        "allowed pair rejected: {state:?} {action:?}"
                    );
                    assert_flow_matches_model(&flow, next);
                    succeeded += 1;
                }
                None => {
                    assert_eq!(
                        actual,
                        Err(TransitionError::InvalidTransition {
                            phase: model_phase(state),
                            action: action.public(),
                        })
                    );
                    assert_eq!(flow_snapshot(&flow), before);
                    rejected += 1;
                }
            }
        }
    }
    assert_eq!(succeeded, 48);
    assert_eq!(rejected, 134);
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
        assert!(flow.request.is_some());
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
            assert!(flow.request.is_some());
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
            assert!(flow.request.is_none());
            canonical += 1;
        } else {
            assert_ne!(flow.phase(), VerificationPhase::PolicySatisfied);
            assert_ne!(flow.phase(), VerificationPhase::Verified);
            assert_eq!(flow.outcome(), None);
            assert!(flow.request.is_some());
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
