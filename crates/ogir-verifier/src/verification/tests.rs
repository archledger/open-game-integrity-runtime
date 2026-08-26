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

fn equal_flows_at_gate(gate: GateKind, seed: u8) -> (VerifierFlow, VerifierFlow) {
    let request = request_fixture(seed);
    let equal_request = request.clone();
    assert_eq!(request, equal_request);
    let mut source = VerifierFlow::begin(request);
    let mut target = VerifierFlow::begin(equal_request);
    assert_eq!(source.request.as_ref(), target.request.as_ref());
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
            Ok(ActionResult::NoCapability)
        );
        assert_eq!(
            apply_action(&mut target, &source.binding.clone(), action),
            Ok(ActionResult::NoCapability)
        );
    }
    assert_eq!(source.phase(), gate.required_phase());
    assert_eq!(target.phase(), gate.required_phase());
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
        GateKind::Evidence => target.record_evidence_appraised(EvidenceAppraised { binding }),
        GateKind::Session => target.record_session_bound(SessionBound { binding }),
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
            policy_version: PolicyVersion::new(1),
        },
        now: UnixTime::new(4_242),
    })
}

fn diagnostics_for_every_surface(flow: &mut VerifierFlow) -> Vec<String> {
    let mut diagnostics = Vec::new();
    let binding = flow.binding.clone();

    let binding_diagnostic = format!("{binding:?}");
    assert_eq!(binding_diagnostic, "VerificationBinding([REDACTED])");
    diagnostics.push(binding_diagnostic);

    let challenge = ChallengeAuthenticated {
        binding: binding.clone(),
    };
    let diagnostic = format!("{challenge:?}");
    assert_eq!(diagnostic, "ChallengeAuthenticated([REDACTED])");
    diagnostics.push(diagnostic);

    let freshness = crate::freshness::test_freshness_checked(binding.clone());
    let diagnostic = format!("{freshness:?}");
    assert_eq!(diagnostic, "FreshnessChecked([REDACTED])");
    diagnostics.push(diagnostic);

    let identity = IdentityChecked {
        binding: binding.clone(),
    };
    let diagnostic = format!("{identity:?}");
    assert_eq!(diagnostic, "IdentityChecked([REDACTED])");
    diagnostics.push(diagnostic);

    let evidence = EvidenceAppraised {
        binding: binding.clone(),
    };
    let diagnostic = format!("{evidence:?}");
    assert_eq!(diagnostic, "EvidenceAppraised([REDACTED])");
    diagnostics.push(diagnostic);

    let session = SessionBound {
        binding: binding.clone(),
    };
    let diagnostic = format!("{session:?}");
    assert_eq!(diagnostic, "SessionBound([REDACTED])");
    diagnostics.push(diagnostic);

    let revocation = RevocationChecked {
        binding: binding.clone(),
    };
    let diagnostic = format!("{revocation:?}");
    assert_eq!(diagnostic, "RevocationChecked([REDACTED])");
    diagnostics.push(diagnostic);

    let policy = PolicySatisfied {
        binding: binding.clone(),
        allowed: AllowedClass::Full,
    };
    let diagnostic = format!("{policy:?}");
    assert_eq!(diagnostic, "PolicySatisfied([REDACTED])");
    diagnostics.push(diagnostic);

    let verified = VerifiedAttestation {
        binding,
        allowed: AllowedClass::Full,
    };
    let diagnostic = format!("{verified:?}");
    assert_eq!(diagnostic, "VerifiedAttestation([REDACTED])");
    diagnostics.push(diagnostic);

    let request = match flow.request.as_ref() {
        Some(value) => value,
        None => panic!("active sentinel flow unexpectedly released its request"),
    };
    let diagnostic = format!("{request:?}");
    assert_eq!(diagnostic, "VerificationRequest([REDACTED])");
    diagnostics.push(diagnostic);
    let diagnostic = format!("{:?}", request.evidence);
    assert_eq!(diagnostic, "EvidenceBundle([REDACTED])");
    diagnostics.push(diagnostic);

    let invalid = TransitionError::InvalidTransition {
        phase: VerificationPhase::EvidenceReceived,
        action: VerificationAction::Complete,
    };
    let diagnostic = invalid.to_string();
    assert_eq!(diagnostic, "verifier transition is not allowed");
    diagnostics.push(diagnostic);
    let rejected = TransitionError::CapabilityRejected {
        action: VerificationAction::RecordChallengeAuthenticated,
    };
    let diagnostic = rejected.to_string();
    assert_eq!(diagnostic, "verifier capability was rejected");
    diagnostics.push(diagnostic);

    let diagnostic = format!("{flow:?}");
    assert_eq!(
        diagnostic,
        "VerifierFlow { phase: EvidenceReceived, outcome: None }"
    );
    diagnostics.push(diagnostic);

    for state in ALL_14_MODEL_STATES {
        let state_flow = flow_for_model_state(state, 84);
        let diagnostic = format!("{state_flow:?}");
        assert!(diagnostic.starts_with("VerifierFlow { phase: "));
        assert!(diagnostic.ends_with(" }"));
        diagnostics.push(diagnostic);
    }

    for state in [
        ModelState::Verified(AllowedClass::Full),
        ModelState::Verified(AllowedClass::Restricted),
        ModelState::Malformed,
        ModelState::Unsupported,
        ModelState::Retryable,
        ModelState::Denied(DenialReason::NotYetValid),
        ModelState::Denied(DenialReason::Expired),
        ModelState::Denied(DenialReason::ReplayDetected),
        ModelState::Denied(DenialReason::SessionBindingMismatch),
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
        assert!(diagnostic.starts_with("VerificationOutcome { decision: "));
        assert!(diagnostic.ends_with(" }"));
        diagnostics.push(diagnostic);
    }

    diagnostics
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

const TOTAL_ACTIONS: usize = 1_048_576;
const SCHEDULED_ACTIONS: usize = 2_048;
const ARBITRARY_ACTIONS: usize = TOTAL_ACTIONS - SCHEDULED_ACTIONS;

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
        let action_index = (self.next() % 13) as usize;
        let selector = self.next();
        arbitrary_action_from_index(action_index, selector)
    }
}

fn seed_for_index(index: usize) -> u8 {
    (index % 200) as u8 + 1
}

const ALL_7_DENIAL_REASONS: [DenialReason; 7] = [
    DenialReason::NotYetValid,
    DenialReason::Expired,
    DenialReason::ReplayDetected,
    DenialReason::SessionBindingMismatch,
    DenialReason::EvidenceInvalid,
    DenialReason::PolicyDenied,
    DenialReason::ProtectedSessionLost,
];

fn arbitrary_action_from_index(index: usize, selector: u64) -> TestAction {
    let mode = if selector & 1 == 0 {
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
        6 => TestAction::Policy(
            if selector & 2 == 0 {
                AllowedClass::Full
            } else {
                AllowedClass::Restricted
            },
            mode,
        ),
        7 => TestAction::Complete,
        8 => TestAction::MarkMalformed,
        9 => TestAction::MarkUnsupported,
        10 => TestAction::MarkRetryable,
        11 => TestAction::Deny(
            ALL_7_DENIAL_REASONS[(selector % ALL_7_DENIAL_REASONS.len() as u64) as usize],
        ),
        12 => TestAction::MarkRevoked,
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

const ALL_5_FAILURE_ACTIONS: [TestAction; 5] = [
    TestAction::MarkMalformed,
    TestAction::MarkUnsupported,
    TestAction::MarkRetryable,
    TestAction::Deny(DenialReason::PolicyDenied),
    TestAction::MarkRevoked,
];

const ALL_6_TERMINAL_CONSTRUCTORS: [TestAction; 6] = [
    TestAction::Complete,
    TestAction::MarkMalformed,
    TestAction::MarkUnsupported,
    TestAction::MarkRetryable,
    TestAction::Deny(DenialReason::PolicyDenied),
    TestAction::MarkRevoked,
];

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
    assert_eq!(schedule.len(), 256);

    let mut failure_sequences = 0usize;
    for phase_index in 0..8 {
        for failure in ALL_5_FAILURE_ACTIONS {
            let mut sequence = MATCHING_GATE_PREFIX[..phase_index].to_vec();
            sequence.push(failure);
            push_sequence(&mut schedule, &sequence);
            failure_sequences += 1;
        }
    }
    assert_eq!(failure_sequences, 40);
    assert_eq!(schedule.len(), 436);

    let mut denial_sequences = 0usize;
    for phase_index in 0..8 {
        for reason in ALL_7_DENIAL_REASONS {
            let mut sequence = MATCHING_GATE_PREFIX[..phase_index].to_vec();
            sequence.push(TestAction::Deny(reason));
            push_sequence(&mut schedule, &sequence);
            denial_sequences += 1;
        }
    }
    assert_eq!(denial_sequences, 56);
    assert_eq!(schedule.len(), 688);

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
        sequence.push(TestAction::MarkMalformed);
        push_sequence(&mut schedule, &sequence);
        cross_flow_sequences += 1;
    }
    assert_eq!(cross_flow_sequences, 7);
    assert_eq!(schedule.len(), 723);

    let mut terminal_sequences = 0usize;
    for constructor in ALL_6_TERMINAL_CONSTRUCTORS {
        for attempted in ALL_13_MATRIX_ACTIONS {
            let mut sequence = if constructor == TestAction::Complete {
                canonical_completion(AllowedClass::Full).to_vec()
            } else {
                vec![constructor]
            };
            sequence.push(attempted);
            push_sequence(&mut schedule, &sequence);
            terminal_sequences += 1;
        }
    }
    assert_eq!(terminal_sequences, 78);
    assert_eq!(schedule.len(), 970);

    push_sequence(&mut schedule, &[TestAction::MarkUnsupported]);
    let unknown_gate_sequences = 1usize;
    assert_eq!(unknown_gate_sequences, 1);
    assert_eq!(schedule.len(), 971);

    let mut extra_completions = 0usize;
    while schedule.len() + 8 <= SCHEDULED_ACTIONS {
        let allowed = if extra_completions.is_multiple_of(2) {
            AllowedClass::Full
        } else {
            AllowedClass::Restricted
        };
        push_sequence(&mut schedule, &canonical_completion(allowed));
        extra_completions += 1;
    }
    assert_eq!(extra_completions, 134);
    assert_eq!(schedule.len(), 2_043);

    let mut filler_sequences = 0usize;
    while schedule.len() < SCHEDULED_ACTIONS {
        push_sequence(&mut schedule, &[TestAction::MarkMalformed]);
        filler_sequences += 1;
    }
    assert_eq!(filler_sequences, 5);
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
        | ModelState::Unsupported
        | ModelState::Retryable
        | ModelState::Denied(_)
        | ModelState::Revoked => None,
    }
}

fn terminal_index(state: ModelState) -> Option<usize> {
    match state {
        ModelState::Verified(_) => Some(0),
        ModelState::Malformed => Some(1),
        ModelState::Unsupported => Some(2),
        ModelState::Retryable => Some(3),
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
        TestAction::MarkUnsupported => Some(1),
        TestAction::MarkRetryable => Some(2),
        TestAction::Deny(_) => Some(3),
        TestAction::MarkRevoked => Some(4),
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

fn denial_index(reason: DenialReason) -> usize {
    match reason {
        DenialReason::NotYetValid => 0,
        DenialReason::Expired => 1,
        DenialReason::ReplayDetected => 2,
        DenialReason::SessionBindingMismatch => 3,
        DenialReason::EvidenceInvalid => 4,
        DenialReason::PolicyDenied => 5,
        DenialReason::ProtectedSessionLost => 6,
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
        | TestAction::MarkUnsupported
        | TestAction::MarkRetryable
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
        TestAction::Policy(_, _) => 6,
        TestAction::Complete => 7,
        TestAction::MarkMalformed => 8,
        TestAction::MarkUnsupported => 9,
        TestAction::MarkRetryable => 10,
        TestAction::Deny(_) => 11,
        TestAction::MarkRevoked => 12,
    }
}

#[derive(Default)]
struct Coverage {
    full_completions: usize,
    restricted_completions: usize,
    failure_edges: [[usize; 5]; 8],
    denial_reasons: [usize; 7],
    matching_gates: [usize; 7],
    mismatched_gates: [usize; 7],
    terminal_rejections: [[usize; 13]; 6],
    unknown_gate: usize,
}

impl Coverage {
    fn observe(
        &mut self,
        before: ModelState,
        action: TestAction,
        expected: ExpectedAction,
        actual: &Result<ActionResult, TransitionError>,
    ) {
        let result_matches = match expected {
            ExpectedAction::Allowed(next) => {
                let expected_result = if matches!(next, ModelState::Verified(_)) {
                    ActionResult::Verified
                } else {
                    ActionResult::NoCapability
                };
                actual == &Ok(expected_result)
            }
            ExpectedAction::InvalidTransition => {
                actual
                    == &Err(TransitionError::InvalidTransition {
                        phase: model_phase(before),
                        action: action.public(),
                    })
            }
            ExpectedAction::CapabilityRejected => {
                actual
                    == &Err(TransitionError::CapabilityRejected {
                        action: action.public(),
                    })
            }
        };
        assert!(
            result_matches,
            "coverage observed a mismatched result for {before:?} {action:?}"
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
                self.failure_edges[phase][failure] += 1;
            }
            if let TestAction::Deny(reason) = action {
                self.denial_reasons[denial_index(reason)] += 1;
            }
            if action.binding_mode() == Some(BindingMode::Matching)
                && let Some(gate) = gate_index(action)
            {
                self.matching_gates[gate] += 1;
            }
            if before == ModelState::EvidenceReceived
                && action == TestAction::MarkUnsupported
                && next == ModelState::Unsupported
            {
                self.unknown_gate += 1;
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
        }
    }

    fn assert_non_vacuous(&self) {
        assert!(self.full_completions >= 16);
        assert!(self.restricted_completions >= 16);
        assert!(self.failure_edges.iter().flatten().all(|count| *count > 0));
        assert!(self.denial_reasons.iter().all(|count| *count > 0));
        assert!(self.matching_gates.iter().all(|count| *count > 0));
        assert!(self.mismatched_gates.iter().all(|count| *count > 0));
        assert!(
            self.terminal_rejections
                .iter()
                .flatten()
                .all(|count| *count > 0)
        );
        assert!(self.unknown_gate > 0);
    }
}

fn assert_action_matches_model(
    index: usize,
    action: TestAction,
    expected: ExpectedAction,
    before: FlowSnapshot,
    flow: &VerifierFlow,
    actual: &Result<ActionResult, TransitionError>,
) {
    match expected {
        ExpectedAction::Allowed(next) => {
            let expected_result = if matches!(next, ModelState::Verified(_)) {
                ActionResult::Verified
            } else {
                ActionResult::NoCapability
            };
            assert_eq!(
                actual,
                &Ok(expected_result),
                "allowed history action failed at index {index}: {action:?}"
            );
            assert_flow_matches_model(flow, next);
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
            assert_eq!(flow_snapshot(flow), before);
        }
        ExpectedAction::CapabilityRejected => {
            assert_eq!(
                actual,
                &Err(TransitionError::CapabilityRejected {
                    action: action.public(),
                }),
                "capability-rejection mismatch at index {index}: {action:?}"
            );
            assert_eq!(flow_snapshot(flow), before);
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
fn every_flow_capability_outcome_and_error_diagnostic_is_redacted() {
    let mut flow = flow_with_private_sentinels();
    let diagnostics = diagnostics_for_every_surface(&mut flow);
    let forbidden = [
        "private.publisher",
        "private.game",
        "private-build",
        "private-account",
        "private-match",
        "private-policy",
        "private-profile",
        "private-evidence-payload",
        "/home/",
        "::error::",
        "\n",
        "0x",
    ];

    for diagnostic in diagnostics {
        for sentinel in forbidden {
            assert!(
                !diagnostic.contains(sentinel),
                "diagnostic leaked {sentinel:?}: {diagnostic:?}"
            );
        }
    }
}

#[test]
fn request_exists_only_while_flow_is_nonterminal() {
    for state in ALL_14_MODEL_STATES {
        let flow = flow_for_model_state(state, 83);
        assert_eq!(flow.request.is_some(), model_is_nonterminal(state));
    }
}

#[test]
fn authority_fields_remain_private_by_structure() {
    let verification = include_str!("../verification.rs").replace("\r\n", "\n");
    let freshness = include_str!("../freshness.rs").replace("\r\n", "\n");

    for declaration in [
        "struct AttemptRecord {\n    _registration: ReplayRegistration,\n}",
        "pub struct VerificationOutcome {\n    decision: Decision,\n    reason: ReasonCode,\n}",
        "pub struct ChallengeAuthenticated {\n    binding: VerificationBinding,\n}",
        "pub struct IdentityChecked {\n    binding: VerificationBinding,\n}",
        "pub struct EvidenceAppraised {\n    binding: VerificationBinding,\n}",
        "pub struct SessionBound {\n    binding: VerificationBinding,\n}",
        "pub struct RevocationChecked {\n    binding: VerificationBinding,\n}",
        "pub struct PolicySatisfied {\n    binding: VerificationBinding,\n    allowed: AllowedClass,\n}",
        "pub struct VerifiedAttestation {\n    binding: VerificationBinding,\n    allowed: AllowedClass,\n}",
        "pub struct VerifierFlow {\n    binding: VerificationBinding,\n    request: Option<VerificationRequest>,\n    state: VerificationState,\n}",
    ] {
        assert!(
            verification.contains(declaration),
            "verification authority declaration drifted: {declaration:?}"
        );
    }
    assert!(
        verification.contains(
            "#[derive(Clone)]\npub(crate) struct VerificationBinding(Arc<AttemptRecord>);"
        )
    );
    assert!(
        freshness.contains("pub struct FreshnessChecked {\n    binding: VerificationBinding,\n}")
    );

    let verification_lines: Vec<&str> = verification.lines().collect();
    for private_line in [
        "    _registration: ReplayRegistration,",
        "    binding: VerificationBinding,",
        "    request: Option<VerificationRequest>,",
        "    state: VerificationState,",
        "    allowed: AllowedClass,",
        "    decision: Decision,",
        "    reason: ReasonCode,",
    ] {
        assert!(verification_lines.contains(&private_line));
        let field = match private_line.strip_prefix("    ") {
            Some(value) => value,
            None => panic!("private field fixture lost exact indentation"),
        };
        for visibility in ["pub ", "pub(crate) ", "pub(super) "] {
            let forbidden = format!("    {visibility}{field}");
            assert!(
                !verification_lines.contains(&forbidden.as_str()),
                "verification authority field became visible: {forbidden:?}"
            );
        }
    }

    let freshness_lines: Vec<&str> = freshness.lines().collect();
    let freshness_field = "    binding: VerificationBinding,";
    assert!(freshness_lines.contains(&freshness_field));
    for visibility in ["pub ", "pub(crate) ", "pub(super) "] {
        let forbidden = format!("    {visibility}binding: VerificationBinding,");
        assert!(
            !freshness_lines.contains(&forbidden.as_str()),
            "freshness authority field became visible: {forbidden:?}"
        );
    }

    for forbidden in [
        "pub(crate) struct VerificationBinding(pub Arc<AttemptRecord>);",
        "pub(crate) struct VerificationBinding(pub(crate) Arc<AttemptRecord>);",
        "pub(crate) struct VerificationBinding(pub(super) Arc<AttemptRecord>);",
    ] {
        assert!(!verification.contains(forbidden));
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

    let action_stream = schedule
        .iter()
        .copied()
        .map(Some)
        .chain(std::iter::repeat_n(None, ARBITRARY_ACTIONS));
    let mut executed = 0usize;
    for (index, scheduled) in action_stream.enumerate() {
        let (reset_before, action) = match scheduled {
            Some(step) => (step.reset_before, step.action),
            None => (model_is_terminal(model), rng.action()),
        };
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
        assert_action_matches_model(index, action, expected, before, &flow, &actual);
        if let ExpectedAction::Allowed(next) = expected {
            model = next;
        }
        coverage.observe(model_before, action, expected, &actual);
        executed += 1;
    }

    assert_eq!(executed, TOTAL_ACTIONS);
    assert_eq!(TOTAL_ACTIONS - SCHEDULED_ACTIONS, ARBITRARY_ACTIONS);
    coverage.assert_non_vacuous();
}
