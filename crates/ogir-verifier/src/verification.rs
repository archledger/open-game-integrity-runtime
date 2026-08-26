// SPDX-License-Identifier: Apache-2.0

//! Checked verifier-flow and report-only outcome contracts.

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use ogir_model::{
    AccountScope, BuildId, Decision, FreshnessError, GameId, MatchId, PolicyId, PolicyVersion,
    PublisherChallenge, PublisherId, ReasonCode, UnixTime,
};
use ogir_protocol::EvidenceBundle;

use crate::freshness::{FreshnessChecked, FreshnessGuard, ReplayRegistration, ReplayStore};

/// Expected relying-party context supplied independently of client evidence.
#[derive(Clone, PartialEq, Eq)]
pub struct ExpectedContext {
    /// Expected publisher.
    pub publisher_id: PublisherId,
    /// Expected game.
    pub game_id: GameId,
    /// Expected build.
    pub build_id: BuildId,
    /// Expected account scope.
    pub account_scope: AccountScope,
    /// Expected match.
    pub match_id: MatchId,
    /// Expected policy.
    pub policy_id: PolicyId,
    /// Expected policy version.
    pub policy_version: PolicyVersion,
}

impl fmt::Debug for ExpectedContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedContext([REDACTED])")
    }
}

/// Input to the verifier.
#[derive(Clone, PartialEq, Eq)]
pub struct VerificationRequest {
    /// Publisher challenge retained by the verifier.
    pub challenge: PublisherChallenge,
    /// Evidence received from the attester.
    pub evidence: EvidenceBundle,
    /// Context supplied by the relying party, not by the client.
    pub expected: ExpectedContext,
    /// Publisher-verifier authoritative current Unix time.
    pub now: UnixTime,
}

impl fmt::Debug for VerificationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerificationRequest([REDACTED])")
    }
}

/// Report-only view of a verifier terminal.
///
/// ```compile_fail
/// use ogir_model::{Decision, ReasonCode};
/// use ogir_verifier::VerificationOutcome;
///
/// let forged = VerificationOutcome {
///     decision: Decision::Allow,
///     reason: ReasonCode::None,
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationOutcome {
    decision: Decision,
    reason: ReasonCode,
}

impl VerificationOutcome {
    /// Returns the non-authoritative decision report.
    #[must_use]
    pub const fn decision(self) -> Decision {
        self.decision
    }

    /// Returns the structured non-disciplinary reason report.
    #[must_use]
    pub const fn reason(self) -> ReasonCode {
        self.reason
    }

    const fn allowed_full() -> Self {
        Self {
            decision: Decision::Allow,
            reason: ReasonCode::None,
        }
    }

    const fn allowed_restricted() -> Self {
        Self {
            decision: Decision::AllowRestricted,
            reason: ReasonCode::None,
        }
    }

    const fn malformed() -> Self {
        Self {
            decision: Decision::Deny,
            reason: ReasonCode::Malformed,
        }
    }

    const fn unsupported() -> Self {
        Self {
            decision: Decision::Unsupported,
            reason: ReasonCode::UnsupportedVersion,
        }
    }

    const fn retryable() -> Self {
        Self {
            decision: Decision::Retry,
            reason: ReasonCode::AttestationUnavailable,
        }
    }

    const fn revoked() -> Self {
        Self {
            decision: Decision::Deny,
            reason: ReasonCode::Revoked,
        }
    }

    const fn denied(reason: DenialReason) -> Self {
        Self {
            decision: Decision::Deny,
            reason: reason.as_reason_code(),
        }
    }
}

/// Redacted public view of the verifier's current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationPhase {
    /// Evidence has been received and no gate has completed.
    EvidenceReceived,
    /// The publisher challenge has been authenticated.
    ChallengeAuthenticated,
    /// Freshness and single-use claim checks have completed.
    FreshnessChecked,
    /// Trusted identity checks have completed.
    IdentityChecked,
    /// Evidence appraisal has completed.
    EvidenceAppraised,
    /// The live session has been bound to the verification attempt.
    SessionBound,
    /// Revocation checks have completed.
    RevocationChecked,
    /// Policy has selected an allowed class.
    PolicySatisfied,
    /// Every success gate has completed.
    Verified,
    /// Input was malformed.
    Malformed,
    /// A mandatory feature or profile was unsupported.
    Unsupported,
    /// Verification ended in a retryable failure.
    Retryable,
    /// Verification was denied.
    Denied,
    /// Verification encountered a revoked input or policy.
    Revoked,
}

/// Public action names used by redacted transition errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationAction {
    /// Record publisher challenge authentication.
    RecordChallengeAuthenticated,
    /// Record freshness and replay checks.
    RecordFreshnessChecked,
    /// Record trusted identity checks.
    RecordIdentityChecked,
    /// Record evidence appraisal.
    RecordEvidenceAppraised,
    /// Record live-session binding.
    RecordSessionBound,
    /// Record revocation checks.
    RecordRevocationChecked,
    /// Record policy satisfaction.
    RecordPolicySatisfied,
    /// Complete the successful verification path.
    Complete,
    /// Enter the malformed terminal.
    MarkMalformed,
    /// Enter the unsupported terminal.
    MarkUnsupported,
    /// Enter the retryable terminal.
    MarkRetryable,
    /// Enter the denied terminal.
    Deny,
    /// Enter the revoked terminal.
    MarkRevoked,
}

/// Fixed non-disciplinary reasons accepted by the denied terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenialReason {
    /// The request predates its validity window.
    NotYetValid,
    /// The request has expired.
    Expired,
    /// The challenge has already been used.
    ReplayDetected,
    /// The relying-party or session binding did not match.
    SessionBindingMismatch,
    /// Evidence appraisal failed.
    EvidenceInvalid,
    /// The selected policy denied the request.
    PolicyDenied,
    /// Required protected-session properties were lost.
    ProtectedSessionLost,
}

impl DenialReason {
    const fn as_reason_code(self) -> ReasonCode {
        match self {
            Self::NotYetValid => ReasonCode::NotYetValid,
            Self::Expired => ReasonCode::Expired,
            Self::ReplayDetected => ReasonCode::ReplayDetected,
            Self::SessionBindingMismatch => ReasonCode::SessionBindingMismatch,
            Self::EvidenceInvalid => ReasonCode::EvidenceInvalid,
            Self::PolicyDenied => ReasonCode::PolicyDenied,
            Self::ProtectedSessionLost => ReasonCode::ProtectedSessionLost,
        }
    }
}

struct AttemptRecord {
    _registration: ReplayRegistration,
}

#[derive(Clone)]
pub(crate) struct VerificationBinding(Arc<AttemptRecord>);

impl VerificationBinding {
    fn new(challenge: &PublisherChallenge) -> Self {
        Self(Arc::new(AttemptRecord {
            _registration: ReplayRegistration::from_challenge(challenge),
        }))
    }

    fn matches(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for VerificationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerificationBinding([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllowedClass {
    Full,
    Restricted,
}

impl AllowedClass {
    const FULL: Self = Self::Full;
    const RESTRICTED: Self = Self::Restricted;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VerificationState {
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

/// Opaque proof that the publisher challenge was authenticated for one attempt.
#[must_use]
pub struct ChallengeAuthenticated {
    binding: VerificationBinding,
}

/// Opaque proof that trusted identity checks passed for one attempt.
#[must_use]
pub struct IdentityChecked {
    binding: VerificationBinding,
}

/// Opaque proof that evidence appraisal passed for one attempt.
#[must_use]
pub struct EvidenceAppraised {
    binding: VerificationBinding,
}

/// Opaque proof that the live session was bound to one attempt.
#[must_use]
pub struct SessionBound {
    binding: VerificationBinding,
}

/// Opaque proof that revocation checks passed for one attempt.
#[must_use]
pub struct RevocationChecked {
    binding: VerificationBinding,
}

/// Opaque proof that policy selected an allowed class for one attempt.
#[must_use]
pub struct PolicySatisfied {
    binding: VerificationBinding,
    allowed: AllowedClass,
}

/// Opaque non-cloneable proof that every verifier success gate completed.
#[must_use]
pub struct VerifiedAttestation {
    binding: VerificationBinding,
    allowed: AllowedClass,
}

macro_rules! impl_redacted_debug {
    ($type_name:ty, $text:literal) => {
        impl fmt::Debug for $type_name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($text)
            }
        }
    };
}

impl_redacted_debug!(ChallengeAuthenticated, "ChallengeAuthenticated([REDACTED])");
impl_redacted_debug!(IdentityChecked, "IdentityChecked([REDACTED])");
impl_redacted_debug!(EvidenceAppraised, "EvidenceAppraised([REDACTED])");
impl_redacted_debug!(SessionBound, "SessionBound([REDACTED])");
impl_redacted_debug!(RevocationChecked, "RevocationChecked([REDACTED])");
impl_redacted_debug!(PolicySatisfied, "PolicySatisfied([REDACTED])");

impl fmt::Debug for VerifiedAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _redacted_binding = &self.binding;
        let _redacted_allowed = self.allowed;
        formatter.write_str("VerifiedAttestation([REDACTED])")
    }
}

/// A deterministic, non-secret verifier transition failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    /// The action is not valid from the current phase.
    InvalidTransition {
        /// Redacted public phase view.
        phase: VerificationPhase,
        /// Rejected public action.
        action: VerificationAction,
    },
    /// The submitted capability belongs to another verification attempt.
    CapabilityRejected {
        /// Rejected public action.
        action: VerificationAction,
    },
}

impl fmt::Display for TransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { .. } => {
                formatter.write_str("verifier transition is not allowed")
            }
            Self::CapabilityRejected { .. } => {
                formatter.write_str("verifier capability was rejected")
            }
        }
    }
}

impl Error for TransitionError {}

/// One checked verifier attempt over an owned request.
///
/// The reviewed public authority surface is available to downstream code:
///
/// ```
/// use ogir_verifier::{
///     ChallengeAuthenticated, DenialReason, EvidenceAppraised,
///     FreshnessChecked, IdentityChecked, PolicySatisfied,
///     RevocationChecked, SessionBound, TransitionError,
///     VerificationAction, VerificationOutcome, VerificationPhase,
///     VerificationRequest, VerifiedAttestation, VerifierFlow,
/// };
///
/// fn assert_public<T>() {}
/// assert_public::<ChallengeAuthenticated>();
/// assert_public::<FreshnessChecked>();
/// assert_public::<IdentityChecked>();
/// assert_public::<EvidenceAppraised>();
/// assert_public::<SessionBound>();
/// assert_public::<RevocationChecked>();
/// assert_public::<PolicySatisfied>();
/// assert_public::<VerifiedAttestation>();
/// assert_public::<VerifierFlow>();
/// assert_public::<VerificationRequest>();
/// assert_public::<VerificationOutcome>();
/// assert_public::<VerificationPhase>();
/// assert_public::<VerificationAction>();
/// assert_public::<DenialReason>();
/// assert_public::<TransitionError>();
///
/// fn inspect(flow: &VerifierFlow) {
///     let _phase = flow.phase();
///     let _outcome = flow.outcome();
/// }
/// ```
///
/// Gate capabilities cannot be constructed outside the crate:
///
/// ```compile_fail
/// use ogir_verifier::ChallengeAuthenticated;
/// let _ = ChallengeAuthenticated::new();
/// ```
///
/// ```compile_fail
/// use ogir_verifier::FreshnessChecked;
/// let _ = FreshnessChecked::new();
/// ```
///
/// ```compile_fail
/// use ogir_verifier::IdentityChecked;
/// let _ = IdentityChecked::new();
/// ```
///
/// ```compile_fail
/// use ogir_verifier::EvidenceAppraised;
/// let _ = EvidenceAppraised::new();
/// ```
///
/// ```compile_fail
/// use ogir_verifier::SessionBound;
/// let _ = SessionBound::new();
/// ```
///
/// ```compile_fail
/// use ogir_verifier::RevocationChecked;
/// let _ = RevocationChecked::new();
/// ```
///
/// ```compile_fail
/// use ogir_verifier::PolicySatisfied;
/// let _ = PolicySatisfied::new();
/// ```
///
/// ```compile_fail
/// use ogir_verifier::VerifiedAttestation;
/// let _ = VerifiedAttestation::new();
/// ```
///
/// The flow and every authority capability are non-cloneable:
///
/// ```compile_fail
/// use ogir_verifier::VerifierFlow;
/// fn clone_flow(value: VerifierFlow) { let _copy = value.clone(); }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::ChallengeAuthenticated;
/// fn clone_capability(value: ChallengeAuthenticated) { let _copy = value.clone(); }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::FreshnessChecked;
/// fn clone_capability(value: FreshnessChecked) { let _copy = value.clone(); }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::IdentityChecked;
/// fn clone_capability(value: IdentityChecked) { let _copy = value.clone(); }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::EvidenceAppraised;
/// fn clone_capability(value: EvidenceAppraised) { let _copy = value.clone(); }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::SessionBound;
/// fn clone_capability(value: SessionBound) { let _copy = value.clone(); }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::RevocationChecked;
/// fn clone_capability(value: RevocationChecked) { let _copy = value.clone(); }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::PolicySatisfied;
/// fn clone_capability(value: PolicySatisfied) { let _copy = value.clone(); }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::VerifiedAttestation;
/// fn clone_capability(value: VerifiedAttestation) { let _copy = value.clone(); }
/// ```
///
/// Flow authority and retained request fields are private:
///
/// ```compile_fail
/// use ogir_verifier::VerifierFlow;
/// fn read_binding(value: VerifierFlow) { let _ = value.binding; }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::VerifierFlow;
/// fn read_request(value: VerifierFlow) { let _ = value.request; }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::VerifierFlow;
/// fn read_state(value: VerifierFlow) { let _ = value.state; }
/// ```
///
/// Every capability binding is private:
///
/// ```compile_fail
/// use ogir_verifier::ChallengeAuthenticated;
/// fn read_binding(value: ChallengeAuthenticated) { let _ = value.binding; }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::FreshnessChecked;
/// fn read_binding(value: FreshnessChecked) { let _ = value.binding; }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::IdentityChecked;
/// fn read_binding(value: IdentityChecked) { let _ = value.binding; }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::EvidenceAppraised;
/// fn read_binding(value: EvidenceAppraised) { let _ = value.binding; }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::SessionBound;
/// fn read_binding(value: SessionBound) { let _ = value.binding; }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::RevocationChecked;
/// fn read_binding(value: RevocationChecked) { let _ = value.binding; }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::PolicySatisfied;
/// fn read_binding(value: PolicySatisfied) { let _ = value.binding; }
/// ```
///
/// Policy and verified-result authority fields are private:
///
/// ```compile_fail
/// use ogir_verifier::PolicySatisfied;
/// fn read_allowed(value: PolicySatisfied) { let _ = value.allowed; }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::VerifiedAttestation;
/// fn read_binding(value: VerifiedAttestation) { let _ = value.binding; }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::VerifiedAttestation;
/// fn read_allowed(value: VerifiedAttestation) { let _ = value.allowed; }
/// ```
///
/// Report fields remain read-only:
///
/// ```compile_fail
/// use ogir_verifier::VerificationOutcome;
/// fn read_decision(value: VerificationOutcome) { let _ = value.decision; }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::VerificationOutcome;
/// fn read_reason(value: VerificationOutcome) { let _ = value.reason; }
/// ```
///
/// A decision or report cannot substitute for verified authority:
///
/// ```compile_fail
/// use ogir_model::Decision;
/// use ogir_verifier::VerifiedAttestation;
/// fn consume(_: VerifiedAttestation) {}
/// consume(Decision::Allow);
/// ```
///
/// ```compile_fail
/// use ogir_verifier::{VerificationOutcome, VerifiedAttestation};
/// fn consume(_: VerifiedAttestation) {}
/// fn substitute(value: VerificationOutcome) { consume(value); }
/// ```
///
/// No report-to-authority shortcut exists:
///
/// ```compile_fail
/// use ogir_model::Decision;
/// use ogir_verifier::VerifiedAttestation;
/// let _ = VerifiedAttestation::from_decision(Decision::Allow);
/// ```
///
/// ```compile_fail
/// use ogir_verifier::{VerificationOutcome, VerifiedAttestation};
/// fn substitute(value: VerificationOutcome) {
///     let _ = VerifiedAttestation::from_outcome(value);
/// }
/// ```
#[must_use]
pub struct VerifierFlow {
    binding: VerificationBinding,
    request: Option<VerificationRequest>,
    state: VerificationState,
}

impl VerifierFlow {
    /// Begins one verification attempt and owns its exact request.
    pub fn begin(request: VerificationRequest) -> Self {
        let binding = VerificationBinding::new(&request.challenge);
        Self {
            binding,
            request: Some(request),
            state: VerificationState::EvidenceReceived,
        }
    }

    /// Returns the redacted current phase.
    #[must_use]
    pub const fn phase(&self) -> VerificationPhase {
        match self.state {
            VerificationState::EvidenceReceived => VerificationPhase::EvidenceReceived,
            VerificationState::ChallengeAuthenticated => VerificationPhase::ChallengeAuthenticated,
            VerificationState::FreshnessChecked => VerificationPhase::FreshnessChecked,
            VerificationState::IdentityChecked => VerificationPhase::IdentityChecked,
            VerificationState::EvidenceAppraised => VerificationPhase::EvidenceAppraised,
            VerificationState::SessionBound => VerificationPhase::SessionBound,
            VerificationState::RevocationChecked => VerificationPhase::RevocationChecked,
            VerificationState::PolicySatisfied(_) => VerificationPhase::PolicySatisfied,
            VerificationState::Verified(_) => VerificationPhase::Verified,
            VerificationState::Malformed => VerificationPhase::Malformed,
            VerificationState::Unsupported => VerificationPhase::Unsupported,
            VerificationState::Retryable => VerificationPhase::Retryable,
            VerificationState::Denied(_) => VerificationPhase::Denied,
            VerificationState::Revoked => VerificationPhase::Revoked,
        }
    }

    /// Returns a report only after the flow reaches a terminal.
    #[must_use]
    pub const fn outcome(&self) -> Option<VerificationOutcome> {
        match self.state {
            VerificationState::Verified(AllowedClass::FULL) => {
                Some(VerificationOutcome::allowed_full())
            }
            VerificationState::Verified(AllowedClass::RESTRICTED) => {
                Some(VerificationOutcome::allowed_restricted())
            }
            VerificationState::Malformed => Some(VerificationOutcome::malformed()),
            VerificationState::Unsupported => Some(VerificationOutcome::unsupported()),
            VerificationState::Retryable => Some(VerificationOutcome::retryable()),
            VerificationState::Denied(reason) => Some(VerificationOutcome::denied(reason)),
            VerificationState::Revoked => Some(VerificationOutcome::revoked()),
            VerificationState::EvidenceReceived
            | VerificationState::ChallengeAuthenticated
            | VerificationState::FreshnessChecked
            | VerificationState::IdentityChecked
            | VerificationState::EvidenceAppraised
            | VerificationState::SessionBound
            | VerificationState::RevocationChecked
            | VerificationState::PolicySatisfied(_) => None,
        }
    }

    /// Records authenticated challenge handling for this attempt.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the phase is wrong or the capability is
    /// bound to another attempt.
    pub fn record_challenge_authenticated(
        &mut self,
        capability: ChallengeAuthenticated,
    ) -> Result<(), TransitionError> {
        if self.state != VerificationState::EvidenceReceived {
            return Err(self.invalid_transition(VerificationAction::RecordChallengeAuthenticated));
        }
        self.ensure_binding(
            VerificationAction::RecordChallengeAuthenticated,
            &capability.binding,
        )?;
        self.state = VerificationState::ChallengeAuthenticated;
        Ok(())
    }

    /// Records freshness and replay checks for this attempt.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the phase is wrong or the capability is
    /// bound to another attempt.
    pub fn record_freshness_checked(
        &mut self,
        capability: FreshnessChecked,
    ) -> Result<(), TransitionError> {
        if self.state != VerificationState::ChallengeAuthenticated {
            return Err(self.invalid_transition(VerificationAction::RecordFreshnessChecked));
        }
        self.ensure_binding(
            VerificationAction::RecordFreshnessChecked,
            capability.binding(),
        )?;
        self.state = VerificationState::FreshnessChecked;
        Ok(())
    }

    /// Records trusted identity checks for this attempt.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the phase is wrong or the capability is
    /// bound to another attempt.
    pub fn record_identity_checked(
        &mut self,
        capability: IdentityChecked,
    ) -> Result<(), TransitionError> {
        if self.state != VerificationState::FreshnessChecked {
            return Err(self.invalid_transition(VerificationAction::RecordIdentityChecked));
        }
        self.ensure_binding(
            VerificationAction::RecordIdentityChecked,
            &capability.binding,
        )?;
        self.state = VerificationState::IdentityChecked;
        Ok(())
    }

    /// Records evidence appraisal for this attempt.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the phase is wrong or the capability is
    /// bound to another attempt.
    pub fn record_evidence_appraised(
        &mut self,
        capability: EvidenceAppraised,
    ) -> Result<(), TransitionError> {
        if self.state != VerificationState::IdentityChecked {
            return Err(self.invalid_transition(VerificationAction::RecordEvidenceAppraised));
        }
        self.ensure_binding(
            VerificationAction::RecordEvidenceAppraised,
            &capability.binding,
        )?;
        self.state = VerificationState::EvidenceAppraised;
        Ok(())
    }

    /// Records live-session binding for this attempt.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the phase is wrong or the capability is
    /// bound to another attempt.
    pub fn record_session_bound(
        &mut self,
        capability: SessionBound,
    ) -> Result<(), TransitionError> {
        if self.state != VerificationState::EvidenceAppraised {
            return Err(self.invalid_transition(VerificationAction::RecordSessionBound));
        }
        self.ensure_binding(VerificationAction::RecordSessionBound, &capability.binding)?;
        self.state = VerificationState::SessionBound;
        Ok(())
    }

    /// Records revocation checks for this attempt.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the phase is wrong or the capability is
    /// bound to another attempt.
    pub fn record_revocation_checked(
        &mut self,
        capability: RevocationChecked,
    ) -> Result<(), TransitionError> {
        if self.state != VerificationState::SessionBound {
            return Err(self.invalid_transition(VerificationAction::RecordRevocationChecked));
        }
        self.ensure_binding(
            VerificationAction::RecordRevocationChecked,
            &capability.binding,
        )?;
        self.state = VerificationState::RevocationChecked;
        Ok(())
    }

    /// Records policy satisfaction and the selected allowed class.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the phase is wrong or the capability is
    /// bound to another attempt.
    pub fn record_policy_satisfied(
        &mut self,
        capability: PolicySatisfied,
    ) -> Result<(), TransitionError> {
        if self.state != VerificationState::RevocationChecked {
            return Err(self.invalid_transition(VerificationAction::RecordPolicySatisfied));
        }
        self.ensure_binding(
            VerificationAction::RecordPolicySatisfied,
            &capability.binding,
        )?;
        self.state = VerificationState::PolicySatisfied(capability.allowed);
        Ok(())
    }

    /// Completes the fully gated path and releases the owned raw request.
    ///
    /// # Errors
    ///
    /// Returns a redacted invalid-transition error unless policy satisfaction
    /// is the current phase.
    pub fn complete(&mut self) -> Result<VerifiedAttestation, TransitionError> {
        let allowed = match self.state {
            VerificationState::PolicySatisfied(allowed) => allowed,
            _ => return Err(self.invalid_transition(VerificationAction::Complete)),
        };
        self.state = VerificationState::Verified(allowed);
        self.request = None;
        Ok(VerifiedAttestation {
            binding: self.binding.clone(),
            allowed,
        })
    }

    /// Terminates this attempt because its input was malformed.
    ///
    /// # Errors
    ///
    /// Returns a redacted invalid-transition error when the flow is already
    /// terminal.
    pub fn mark_malformed(&mut self) -> Result<(), TransitionError> {
        self.enter_failure(
            VerificationAction::MarkMalformed,
            VerificationState::Malformed,
        )
    }

    /// Terminates this attempt because a mandatory feature was unsupported.
    ///
    /// # Errors
    ///
    /// Returns a redacted invalid-transition error when the flow is already
    /// terminal.
    pub fn mark_unsupported(&mut self) -> Result<(), TransitionError> {
        self.enter_failure(
            VerificationAction::MarkUnsupported,
            VerificationState::Unsupported,
        )
    }

    /// Terminates this attempt with a retryable unavailable result.
    ///
    /// # Errors
    ///
    /// Returns a redacted invalid-transition error when the flow is already
    /// terminal.
    pub fn mark_retryable(&mut self) -> Result<(), TransitionError> {
        self.enter_failure(
            VerificationAction::MarkRetryable,
            VerificationState::Retryable,
        )
    }

    /// Terminates this attempt with one fixed typed denial reason.
    ///
    /// # Errors
    ///
    /// Returns a redacted invalid-transition error when the flow is already
    /// terminal.
    pub fn deny(&mut self, reason: DenialReason) -> Result<(), TransitionError> {
        self.enter_failure(VerificationAction::Deny, VerificationState::Denied(reason))
    }

    /// Terminates this attempt because a required input was revoked.
    ///
    /// # Errors
    ///
    /// Returns a redacted invalid-transition error when the flow is already
    /// terminal.
    pub fn mark_revoked(&mut self) -> Result<(), TransitionError> {
        self.enter_failure(VerificationAction::MarkRevoked, VerificationState::Revoked)
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            VerificationState::Verified(_)
                | VerificationState::Malformed
                | VerificationState::Unsupported
                | VerificationState::Retryable
                | VerificationState::Denied(_)
                | VerificationState::Revoked
        )
    }

    fn enter_failure(
        &mut self,
        action: VerificationAction,
        next: VerificationState,
    ) -> Result<(), TransitionError> {
        if self.is_terminal() {
            return Err(self.invalid_transition(action));
        }
        self.request = None;
        self.state = next;
        Ok(())
    }

    fn invalid_transition(&self, action: VerificationAction) -> TransitionError {
        TransitionError::InvalidTransition {
            phase: self.phase(),
            action,
        }
    }

    fn ensure_binding(
        &self,
        action: VerificationAction,
        candidate: &VerificationBinding,
    ) -> Result<(), TransitionError> {
        if self.binding.matches(candidate) {
            Ok(())
        } else {
            Err(TransitionError::CapabilityRejected { action })
        }
    }
}

impl fmt::Debug for VerifierFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifierFlow")
            .field("phase", &self.phase())
            .field("outcome", &self.outcome())
            .finish()
    }
}

/// Performs the implemented freshness and relying-party context checks.
///
/// Publisher-signature authentication, TPM evidence appraisal, and policy
/// evaluation are not implemented in this research scaffold, so this function
/// never returns [`Decision::Allow`]. A production pipeline must authenticate
/// the publisher challenge before entering this window/context/claim segment.
#[must_use]
pub fn verify_research_structure<Store: ReplayStore + ?Sized>(
    request: &VerificationRequest,
    freshness: &FreshnessGuard<'_, Store>,
) -> VerificationOutcome {
    if let Err(error) = freshness.evaluate_window(request.now, &request.challenge) {
        return freshness_failure(error);
    }

    let expected = &request.expected;
    let challenge = &request.challenge;
    let binding_matches = expected.publisher_id == challenge.publisher_id
        && expected.game_id == challenge.game_id
        && expected.build_id == challenge.build_id
        && expected.account_scope == challenge.account_scope
        && expected.match_id == challenge.match_id
        && expected.policy_id == challenge.policy_id
        && expected.policy_version == challenge.policy_version;

    if !binding_matches {
        return VerificationOutcome::denied(DenialReason::SessionBindingMismatch);
    }

    if let Err(error) = freshness.claim(request.now, &request.challenge) {
        return freshness_failure(error);
    }

    // Deliberate fail-closed scaffold until cryptographic and policy verification exists.
    VerificationOutcome::denied(DenialReason::EvidenceInvalid)
}

fn freshness_failure(error: FreshnessError) -> VerificationOutcome {
    match error {
        FreshnessError::InvalidWindow | FreshnessError::LifetimeExceeded => {
            VerificationOutcome::malformed()
        }
        FreshnessError::NotYetValid => VerificationOutcome::denied(DenialReason::NotYetValid),
        FreshnessError::Expired => VerificationOutcome::denied(DenialReason::Expired),
        FreshnessError::ReplayDetected => VerificationOutcome::denied(DenialReason::ReplayDetected),
        FreshnessError::ClockRollback
        | FreshnessError::StateUnavailable
        | FreshnessError::CapacityExceeded => VerificationOutcome::retryable(),
    }
}

#[cfg(test)]
mod tests;
