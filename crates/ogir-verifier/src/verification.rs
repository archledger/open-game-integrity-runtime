// SPDX-License-Identifier: Apache-2.0

//! Checked verifier-flow and report-only outcome contracts.
//!
//! Appraisal results have no public constructor:
//!
//! ```compile_fail
//! use ogir_verifier::{AppraisalResult, ExpectedContext};
//! fn forbidden(context: ExpectedContext) {
//!     let _ = AppraisalResult::new(context);
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::AppraisalResult;
//! fn forbidden() {
//!     let _ = AppraisalResult::builder();
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::AppraisalResult;
//! fn forbidden() {
//!     let _ = AppraisalResult::default();
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::AppraisalResult;
//! fn forbidden(result: AppraisalResult) {
//!     let _ = result.clone();
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::AppraisalResult;
//! fn forbidden(result: AppraisalResult) {
//!     let _first = result;
//!     let _second = result;
//! }
//! ```
//!
//! Accepted claims cannot be constructed outside the verifier:
//!
//! ```compile_fail
//! use ogir_model::{EvidenceProfile, SessionPublicKeyId};
//! use ogir_verifier::AcceptedClaims;
//! fn forbidden(profile: EvidenceProfile, key_id: SessionPublicKeyId) {
//!     let _ = AcceptedClaims::new(profile, key_id);
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_model::{EvidenceProfile, SessionPublicKeyId};
//! use ogir_verifier::{AcceptedClaims, AppraisalResultView};
//! fn forbidden(profile: EvidenceProfile, session_public_key_id: SessionPublicKeyId) {
//!     let claims = AcceptedClaims { accepted_profile: profile, session_public_key_id };
//!     let _ = AppraisalResultView::Allow(&claims);
//! }
//! ```
//!
//! Reports cannot be converted into appraisal results:
//!
//! ```compile_fail
//! use ogir_verifier::{AppraisalResult, VerificationOutcome};
//! fn forbidden(outcome: VerificationOutcome) {
//!     let _ = AppraisalResult::from_outcome(outcome);
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::{AppraisalResult, VerificationOutcome};
//! fn forbidden(report: VerificationOutcome) {
//!     let _: AppraisalResult = report.into();
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::{AppraisalResult, VerificationRequest};
//! fn forbidden(request: VerificationRequest) {
//!     let _: AppraisalResult = request.into();
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::{AppraisalResult, ExpectedContext};
//! fn forbidden(mut result: AppraisalResult, replacement: ExpectedContext) {
//!     result.set_context(replacement);
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::{AppraisalResult, AppraisalResultView};
//! fn forbidden(view: AppraisalResultView<'_>) {
//!     let _: AppraisalResult = view.into();
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_model::Decision;
//! use ogir_verifier::AppraisalResult;
//! fn forbidden() {
//!     let _ = AppraisalResult::from_decision(Decision::Allow);
//! }
//! ```
//!
//! Appraisal results grant no signing, permit, or admission authority:
//!
//! ```compile_fail
//! use ogir_verifier::AppraisalResult;
//! struct TestSigner;
//! fn forbidden(result: AppraisalResult, signer: TestSigner) {
//!     let _ = result.sign(signer);
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::AppraisalResult;
//! struct ValidatedPermit;
//! fn forbidden(result: AppraisalResult) -> ValidatedPermit {
//!     result.into_permit()
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::AppraisalResult;
//! struct Admission;
//! fn forbidden(result: AppraisalResult) -> Admission {
//!     result.admit()
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::AppraisalResult;
//! struct ProtectedResult;
//! fn forbidden(result: AppraisalResult) -> ProtectedResult {
//!     result.into_protected_result()
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::AppraisalResult;
//! struct ProofOfPossession;
//! fn forbidden(result: AppraisalResult) -> ProofOfPossession {
//!     result.into_proof_of_possession()
//! }
//! ```
//!
//! Result and accepted-claim fields remain private:
//!
//! ```compile_fail
//! use ogir_verifier::{AppraisalResult, ExpectedContext};
//! fn forbidden(context: ExpectedContext) {
//!     let _ = AppraisalResult { context, payload: unreachable!() };
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_model::{EvidenceProfile, SessionPublicKeyId};
//! use ogir_verifier::AcceptedClaims;
//! fn forbidden(profile: EvidenceProfile, session_public_key_id: SessionPublicKeyId) {
//!     let _ = AcceptedClaims { accepted_profile: profile, session_public_key_id };
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::AppraisalResult;
//! fn forbidden(result: AppraisalResult) {
//!     let _ = result.context;
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::AppraisalResult;
//! fn forbidden(result: AppraisalResult) {
//!     let _ = result.payload;
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::{AppraisalResult, ExpectedContext};
//! fn forbidden(result: &AppraisalResult, replacement: ExpectedContext) {
//!     *result.context() = replacement;
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::AcceptedClaims;
//! fn forbidden(claims: AcceptedClaims) {
//!     let _ = claims.accepted_profile;
//! }
//! ```
//!
//! ```compile_fail
//! use ogir_verifier::AcceptedClaims;
//! fn forbidden(claims: AcceptedClaims) {
//!     let _ = claims.session_public_key_id;
//! }
//! ```

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use ogir_model::{
    AccountScope, BuildId, Decision, EvidenceProfile, FreshnessError, GameId, MatchId, PolicyId,
    PolicyVersion, PublisherChallenge, PublisherId, ReasonCode, SessionPublicKeyId, UnixTime,
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
///     reason: None,
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationOutcome {
    decision: Decision,
    reason: Option<ReasonCode>,
}

impl VerificationOutcome {
    /// Returns the non-authoritative decision report.
    #[must_use]
    pub const fn decision(self) -> Decision {
        self.decision
    }

    /// Returns the structured non-disciplinary reason report.
    #[must_use]
    pub const fn reason(self) -> Option<ReasonCode> {
        self.reason
    }

    const fn allowed_full() -> Self {
        Self {
            decision: Decision::Allow,
            reason: None,
        }
    }

    const fn allowed_restricted() -> Self {
        Self {
            decision: Decision::AllowRestricted,
            reason: None,
        }
    }

    const fn malformed() -> Self {
        Self {
            decision: Decision::Deny,
            reason: Some(ReasonCode::Malformed),
        }
    }

    const fn unsupported(requirement: UnsupportedRequirement) -> Self {
        Self {
            decision: Decision::Unsupported,
            reason: Some(requirement.as_reason_code()),
        }
    }

    const fn retryable(reason: RetryReason) -> Self {
        Self {
            decision: Decision::Retry,
            reason: Some(reason.as_reason_code()),
        }
    }

    const fn revoked() -> Self {
        Self {
            decision: Decision::Deny,
            reason: Some(ReasonCode::Revoked),
        }
    }

    const fn denied(reason: DenialReason) -> Self {
        Self {
            decision: Decision::Deny,
            reason: Some(reason.as_reason_code()),
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
    /// Publisher challenge authentication failed.
    ChallengeAuthenticationFailed,
    /// The request predates its validity window.
    NotYetValid,
    /// The request has expired.
    Expired,
    /// The challenge has already been used.
    ReplayDetected,
    /// The relying-party, identity, or session context did not match.
    ContextBindingMismatch,
    /// Evidence appraisal failed.
    EvidenceInvalid,
    /// The selected policy denied the request.
    PolicyDenied,
    /// Required protected-session properties were lost.
    ProtectedSessionLost,
}

/// Typed cause for entering the non-disciplinary unsupported terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnsupportedRequirement {
    /// A protocol version or evidence profile is not implemented.
    VersionOrProfile,
    /// The platform is not supported for the selected policy.
    Platform,
    /// A critical requirement is unknown and cannot be safely skipped.
    UnknownCriticalRequirement,
}

/// Typed causes accepted by the non-disciplinary retry terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetryReason {
    /// A required attestation service or resource was unavailable.
    AttestationUnavailable,
    /// A transient verifier failure may be retried.
    TransientFailure,
}

impl UnsupportedRequirement {
    const fn as_reason_code(self) -> ReasonCode {
        match self {
            Self::VersionOrProfile => ReasonCode::UnsupportedVersionOrProfile,
            Self::Platform => ReasonCode::UnsupportedPlatform,
            Self::UnknownCriticalRequirement => ReasonCode::UnsupportedCriticalRequirement,
        }
    }
}

impl RetryReason {
    const fn as_reason_code(self) -> ReasonCode {
        match self {
            Self::AttestationUnavailable => ReasonCode::AttestationUnavailable,
            Self::TransientFailure => ReasonCode::TransientFailure,
        }
    }
}

impl DenialReason {
    const fn as_reason_code(self) -> ReasonCode {
        match self {
            Self::ChallengeAuthenticationFailed => ReasonCode::ChallengeAuthenticationFailed,
            Self::NotYetValid => ReasonCode::NotYetValid,
            Self::Expired => ReasonCode::Expired,
            Self::ReplayDetected => ReasonCode::ReplayDetected,
            Self::ContextBindingMismatch => ReasonCode::ContextBindingMismatch,
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

enum VerificationState {
    EvidenceReceived {
        request: VerificationRequest,
    },
    ChallengeAuthenticated {
        request: VerificationRequest,
    },
    FreshnessChecked {
        request: VerificationRequest,
    },
    IdentityChecked {
        request: VerificationRequest,
    },
    EvidenceAppraised {
        request: VerificationRequest,
        accepted_profile: EvidenceProfile,
    },
    SessionBound {
        request: VerificationRequest,
        accepted_profile: EvidenceProfile,
        session_public_key_id: SessionPublicKeyId,
    },
    RevocationChecked {
        request: VerificationRequest,
        accepted_profile: EvidenceProfile,
        session_public_key_id: SessionPublicKeyId,
    },
    PolicySatisfied {
        request: VerificationRequest,
        accepted_profile: EvidenceProfile,
        session_public_key_id: SessionPublicKeyId,
        allowed: AllowedClass,
    },
    Verified {
        outcome: VerificationOutcome,
    },
    Malformed {
        outcome: VerificationOutcome,
    },
    Unsupported {
        outcome: VerificationOutcome,
    },
    Retryable {
        outcome: VerificationOutcome,
    },
    Denied {
        outcome: VerificationOutcome,
    },
    Revoked {
        outcome: VerificationOutcome,
    },
}

/// Opaque unsigned semantic result of one verifier appraisal.
///
/// ```compile_fail
/// use ogir_verifier::AppraisalResult;
/// fn forbidden(result: AppraisalResult) {
///     let _ = result.clone();
/// }
/// ```
#[must_use]
pub struct AppraisalResult {
    context: ExpectedContext,
    payload: AppraisalPayload,
}

enum AppraisalPayload {
    Allow(AcceptedClaims),
    AllowRestricted(AcceptedClaims),
    Failure(FailurePayload),
}

/// Accepted claims retained only by an allowed appraisal result.
///
/// ```compile_fail
/// use ogir_verifier::AcceptedClaims;
/// fn forbidden(claims: AcceptedClaims) {
///     let _ = claims.clone();
/// }
/// ```
#[must_use]
pub struct AcceptedClaims {
    accepted_profile: EvidenceProfile,
    session_public_key_id: SessionPublicKeyId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FailurePayload {
    decision: FailureDecision,
    reason: ReasonCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FailureDecision {
    Deny,
    Unsupported,
    Retry,
}

impl FailureDecision {
    const fn as_decision(self) -> Decision {
        match self {
            Self::Deny => Decision::Deny,
            Self::Unsupported => Decision::Unsupported,
            Self::Retry => Decision::Retry,
        }
    }
}

/// Private normalized failure action used for eligibility and terminal mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FailureKind {
    /// Malformed evidence.
    Malformed,
    /// A typed unsupported requirement.
    Unsupported(UnsupportedRequirement),
    /// A typed retryable failure.
    Retry(RetryReason),
    /// A typed denial.
    Deny(DenialReason),
    /// Revocation discovered at the approved phase.
    Revoked,
}

impl FailureKind {
    const fn action(self) -> VerificationAction {
        match self {
            Self::Malformed => VerificationAction::MarkMalformed,
            Self::Unsupported(_) => VerificationAction::MarkUnsupported,
            Self::Retry(_) => VerificationAction::MarkRetryable,
            Self::Deny(_) => VerificationAction::Deny,
            Self::Revoked => VerificationAction::MarkRevoked,
        }
    }
}

fn is_active_phase(phase: VerificationPhase) -> bool {
    std::matches!(
        phase,
        VerificationPhase::EvidenceReceived
            | VerificationPhase::ChallengeAuthenticated
            | VerificationPhase::FreshnessChecked
            | VerificationPhase::IdentityChecked
            | VerificationPhase::EvidenceAppraised
            | VerificationPhase::SessionBound
            | VerificationPhase::RevocationChecked
            | VerificationPhase::PolicySatisfied
    )
}

fn failure_is_eligible(phase: VerificationPhase, failure: FailureKind) -> bool {
    match failure {
        FailureKind::Malformed => phase == VerificationPhase::EvidenceReceived,
        FailureKind::Unsupported(UnsupportedRequirement::VersionOrProfile) => {
            phase == VerificationPhase::ChallengeAuthenticated
        }
        FailureKind::Unsupported(UnsupportedRequirement::Platform) => {
            phase == VerificationPhase::IdentityChecked
        }
        FailureKind::Unsupported(UnsupportedRequirement::UnknownCriticalRequirement)
        | FailureKind::Retry(_) => is_active_phase(phase),
        FailureKind::Deny(DenialReason::ChallengeAuthenticationFailed) => {
            phase == VerificationPhase::EvidenceReceived
        }
        FailureKind::Deny(
            DenialReason::NotYetValid | DenialReason::Expired | DenialReason::ReplayDetected,
        ) => phase == VerificationPhase::ChallengeAuthenticated,
        FailureKind::Deny(DenialReason::ContextBindingMismatch) => std::matches!(
            phase,
            VerificationPhase::ChallengeAuthenticated
                | VerificationPhase::FreshnessChecked
                | VerificationPhase::EvidenceAppraised
        ),
        FailureKind::Deny(DenialReason::EvidenceInvalid) => {
            phase == VerificationPhase::IdentityChecked
        }
        FailureKind::Deny(DenialReason::PolicyDenied) => {
            phase == VerificationPhase::RevocationChecked
        }
        FailureKind::Deny(DenialReason::ProtectedSessionLost) => std::matches!(
            phase,
            VerificationPhase::EvidenceAppraised
                | VerificationPhase::SessionBound
                | VerificationPhase::RevocationChecked
                | VerificationPhase::PolicySatisfied
        ),
        FailureKind::Revoked => phase == VerificationPhase::SessionBound,
    }
}

/// Borrowed report-only view of an appraisal result.
pub enum AppraisalResultView<'a> {
    /// Full-policy allow with opaque accepted claims.
    Allow(&'a AcceptedClaims),
    /// Restricted-policy allow with opaque accepted claims.
    AllowRestricted(&'a AcceptedClaims),
    /// Unsuccessful report with one coarse reason.
    Failure {
        /// Non-authoritative unsuccessful decision report.
        decision: Decision,
        /// Non-disciplinary reason report.
        reason: ReasonCode,
    },
}

impl AppraisalResult {
    /// Returns the exact relying-party context retained by this result.
    #[must_use]
    pub const fn context(&self) -> &ExpectedContext {
        &self.context
    }

    /// Returns the non-authoritative decision report.
    #[must_use]
    pub const fn decision(&self) -> Decision {
        match &self.payload {
            AppraisalPayload::Allow(_) => Decision::Allow,
            AppraisalPayload::AllowRestricted(_) => Decision::AllowRestricted,
            AppraisalPayload::Failure(failure) => failure.decision.as_decision(),
        }
    }

    /// Returns no reason for allows and one coarse reason for failures.
    #[must_use]
    pub const fn reason(&self) -> Option<ReasonCode> {
        match &self.payload {
            AppraisalPayload::Allow(_) | AppraisalPayload::AllowRestricted(_) => None,
            AppraisalPayload::Failure(failure) => Some(failure.reason),
        }
    }

    /// Returns a borrowed report-only view of this result.
    #[must_use]
    pub const fn view(&self) -> AppraisalResultView<'_> {
        match &self.payload {
            AppraisalPayload::Allow(claims) => AppraisalResultView::Allow(claims),
            AppraisalPayload::AllowRestricted(claims) => {
                AppraisalResultView::AllowRestricted(claims)
            }
            AppraisalPayload::Failure(failure) => AppraisalResultView::Failure {
                decision: failure.decision.as_decision(),
                reason: failure.reason,
            },
        }
    }
}

impl AcceptedClaims {
    /// Returns the accepted evidence profile.
    #[must_use]
    pub const fn accepted_profile(&self) -> &EvidenceProfile {
        &self.accepted_profile
    }

    /// Returns the accepted session public-key lookup handle.
    #[must_use]
    pub const fn session_public_key_id(&self) -> &SessionPublicKeyId {
        &self.session_public_key_id
    }
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
///
/// Attempt binding proves flow association, not the truth of the profile
/// supplied by the trusted producer.
#[must_use]
pub struct EvidenceAppraised {
    binding: VerificationBinding,
    accepted_profile: EvidenceProfile,
}

/// Opaque proof that the live session was bound to one attempt.
///
/// Attempt binding proves flow association, not the truth of the key handle
/// supplied by the trusted producer.
#[must_use]
pub struct SessionBound {
    binding: VerificationBinding,
    session_public_key_id: SessionPublicKeyId,
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
    context: ExpectedContext,
    accepted_profile: EvidenceProfile,
    session_public_key_id: SessionPublicKeyId,
    allowed: AllowedClass,
}

/// Completed authority can be converted only once because conversion consumes it:
///
/// ```compile_fail
/// use ogir_verifier::{AppraisalResult, VerifiedAttestation};
/// fn forbidden(value: VerifiedAttestation) {
///     let _: AppraisalResult = value.into_appraisal_result();
///     let _: AppraisalResult = value.into_appraisal_result();
/// }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::VerifiedAttestation;
/// fn forbidden(verified: VerifiedAttestation) {
///     let _first = verified.into_appraisal_result();
///     let _second = verified.into_appraisal_result();
/// }
/// ```
///
/// ```compile_fail
/// use ogir_verifier::VerifiedAttestation;
/// fn forbidden(verified: VerifiedAttestation) {
///     let _ = verified.clone();
/// }
/// ```
impl VerifiedAttestation {
    /// Consumes completed verifier authority to create the only allowed result shape.
    #[must_use = "the appraisal result carries the completed verifier outcome"]
    pub fn into_appraisal_result(self) -> AppraisalResult {
        let Self {
            binding,
            context,
            accepted_profile,
            session_public_key_id,
            allowed,
        } = self;
        drop(binding);
        let claims = AcceptedClaims {
            accepted_profile,
            session_public_key_id,
        };
        let payload = match allowed {
            AllowedClass::FULL => AppraisalPayload::Allow(claims),
            AllowedClass::RESTRICTED => AppraisalPayload::AllowRestricted(claims),
        };
        AppraisalResult { context, payload }
    }
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
impl_redacted_debug!(AppraisalResult, "AppraisalResult([REDACTED])");
impl_redacted_debug!(AcceptedClaims, "AcceptedClaims([REDACTED])");
impl_redacted_debug!(AppraisalResultView<'_>, "AppraisalResultView([REDACTED])");

impl fmt::Debug for VerifiedAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _redacted_binding = &self.binding;
        let _redacted_allowed = self.allowed;
        formatter.write_str("VerifiedAttestation([REDACTED])")
    }
}

/// A deterministic, non-secret verifier transition failure.
#[derive(Clone, Copy, PartialEq, Eq)]
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

impl fmt::Debug for TransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { .. } => {
                formatter.write_str("TransitionError::InvalidTransition([REDACTED])")
            }
            Self::CapabilityRejected { .. } => {
                formatter.write_str("TransitionError::CapabilityRejected([REDACTED])")
            }
        }
    }
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
///     UnsupportedRequirement,
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
/// assert_public::<UnsupportedRequirement>();
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
    state: VerificationState,
}

impl VerifierFlow {
    /// Begins one verification attempt and owns its exact request.
    pub fn begin(request: VerificationRequest) -> Self {
        let binding = VerificationBinding::new(&request.challenge);
        Self {
            binding,
            state: VerificationState::EvidenceReceived { request },
        }
    }

    /// Returns the redacted current phase.
    #[must_use]
    pub const fn phase(&self) -> VerificationPhase {
        match &self.state {
            VerificationState::EvidenceReceived { .. } => VerificationPhase::EvidenceReceived,
            VerificationState::ChallengeAuthenticated { .. } => {
                VerificationPhase::ChallengeAuthenticated
            }
            VerificationState::FreshnessChecked { .. } => VerificationPhase::FreshnessChecked,
            VerificationState::IdentityChecked { .. } => VerificationPhase::IdentityChecked,
            VerificationState::EvidenceAppraised { .. } => VerificationPhase::EvidenceAppraised,
            VerificationState::SessionBound { .. } => VerificationPhase::SessionBound,
            VerificationState::RevocationChecked { .. } => VerificationPhase::RevocationChecked,
            VerificationState::PolicySatisfied { .. } => VerificationPhase::PolicySatisfied,
            VerificationState::Verified { .. } => VerificationPhase::Verified,
            VerificationState::Malformed { .. } => VerificationPhase::Malformed,
            VerificationState::Unsupported { .. } => VerificationPhase::Unsupported,
            VerificationState::Retryable { .. } => VerificationPhase::Retryable,
            VerificationState::Denied { .. } => VerificationPhase::Denied,
            VerificationState::Revoked { .. } => VerificationPhase::Revoked,
        }
    }

    /// Returns a report only after the flow reaches a terminal.
    #[must_use]
    pub const fn outcome(&self) -> Option<VerificationOutcome> {
        match &self.state {
            VerificationState::Verified { outcome }
            | VerificationState::Malformed { outcome }
            | VerificationState::Unsupported { outcome }
            | VerificationState::Retryable { outcome }
            | VerificationState::Denied { outcome }
            | VerificationState::Revoked { outcome } => Some(*outcome),
            VerificationState::EvidenceReceived { .. }
            | VerificationState::ChallengeAuthenticated { .. }
            | VerificationState::FreshnessChecked { .. }
            | VerificationState::IdentityChecked { .. }
            | VerificationState::EvidenceAppraised { .. }
            | VerificationState::SessionBound { .. }
            | VerificationState::RevocationChecked { .. }
            | VerificationState::PolicySatisfied { .. } => None,
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
        if !std::matches!(&self.state, VerificationState::EvidenceReceived { .. }) {
            return Err(self.invalid_transition(VerificationAction::RecordChallengeAuthenticated));
        }
        self.ensure_binding(
            VerificationAction::RecordChallengeAuthenticated,
            &capability.binding,
        )?;
        let previous = std::mem::replace(
            &mut self.state,
            VerificationState::Retryable {
                outcome: VerificationOutcome::retryable(RetryReason::TransientFailure),
            },
        );
        let VerificationState::EvidenceReceived { request } = previous else {
            std::unreachable!("phase was checked before active-state replacement")
        };
        self.state = VerificationState::ChallengeAuthenticated { request };
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
        if !std::matches!(
            &self.state,
            VerificationState::ChallengeAuthenticated { .. }
        ) {
            return Err(self.invalid_transition(VerificationAction::RecordFreshnessChecked));
        }
        self.ensure_binding(
            VerificationAction::RecordFreshnessChecked,
            capability.binding(),
        )?;
        let previous = std::mem::replace(
            &mut self.state,
            VerificationState::Retryable {
                outcome: VerificationOutcome::retryable(RetryReason::TransientFailure),
            },
        );
        let VerificationState::ChallengeAuthenticated { request } = previous else {
            std::unreachable!("phase was checked before active-state replacement")
        };
        self.state = VerificationState::FreshnessChecked { request };
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
        if !std::matches!(&self.state, VerificationState::FreshnessChecked { .. }) {
            return Err(self.invalid_transition(VerificationAction::RecordIdentityChecked));
        }
        self.ensure_binding(
            VerificationAction::RecordIdentityChecked,
            &capability.binding,
        )?;
        let previous = std::mem::replace(
            &mut self.state,
            VerificationState::Retryable {
                outcome: VerificationOutcome::retryable(RetryReason::TransientFailure),
            },
        );
        let VerificationState::FreshnessChecked { request } = previous else {
            std::unreachable!("phase was checked before active-state replacement")
        };
        self.state = VerificationState::IdentityChecked { request };
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
        if !std::matches!(&self.state, VerificationState::IdentityChecked { .. }) {
            return Err(self.invalid_transition(VerificationAction::RecordEvidenceAppraised));
        }
        self.ensure_binding(
            VerificationAction::RecordEvidenceAppraised,
            &capability.binding,
        )?;
        let previous = std::mem::replace(
            &mut self.state,
            VerificationState::Retryable {
                outcome: VerificationOutcome::retryable(RetryReason::TransientFailure),
            },
        );
        let VerificationState::IdentityChecked { request } = previous else {
            std::unreachable!("phase was checked before active-state replacement")
        };
        self.state = VerificationState::EvidenceAppraised {
            request,
            accepted_profile: capability.accepted_profile,
        };
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
        if !std::matches!(&self.state, VerificationState::EvidenceAppraised { .. }) {
            return Err(self.invalid_transition(VerificationAction::RecordSessionBound));
        }
        self.ensure_binding(VerificationAction::RecordSessionBound, &capability.binding)?;
        let previous = std::mem::replace(
            &mut self.state,
            VerificationState::Retryable {
                outcome: VerificationOutcome::retryable(RetryReason::TransientFailure),
            },
        );
        let VerificationState::EvidenceAppraised {
            request,
            accepted_profile,
        } = previous
        else {
            std::unreachable!("phase was checked before active-state replacement")
        };
        self.state = VerificationState::SessionBound {
            request,
            accepted_profile,
            session_public_key_id: capability.session_public_key_id,
        };
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
        if !std::matches!(&self.state, VerificationState::SessionBound { .. }) {
            return Err(self.invalid_transition(VerificationAction::RecordRevocationChecked));
        }
        self.ensure_binding(
            VerificationAction::RecordRevocationChecked,
            &capability.binding,
        )?;
        let previous = std::mem::replace(
            &mut self.state,
            VerificationState::Retryable {
                outcome: VerificationOutcome::retryable(RetryReason::TransientFailure),
            },
        );
        let VerificationState::SessionBound {
            request,
            accepted_profile,
            session_public_key_id,
        } = previous
        else {
            std::unreachable!("phase was checked before active-state replacement")
        };
        self.state = VerificationState::RevocationChecked {
            request,
            accepted_profile,
            session_public_key_id,
        };
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
        if !std::matches!(&self.state, VerificationState::RevocationChecked { .. }) {
            return Err(self.invalid_transition(VerificationAction::RecordPolicySatisfied));
        }
        self.ensure_binding(
            VerificationAction::RecordPolicySatisfied,
            &capability.binding,
        )?;
        let previous = std::mem::replace(
            &mut self.state,
            VerificationState::Retryable {
                outcome: VerificationOutcome::retryable(RetryReason::TransientFailure),
            },
        );
        let VerificationState::RevocationChecked {
            request,
            accepted_profile,
            session_public_key_id,
        } = previous
        else {
            std::unreachable!("phase was checked before active-state replacement")
        };
        self.state = VerificationState::PolicySatisfied {
            request,
            accepted_profile,
            session_public_key_id,
            allowed: capability.allowed,
        };
        Ok(())
    }

    /// Completes the fully gated path and releases the owned raw request.
    ///
    /// # Errors
    ///
    /// Returns a redacted invalid-transition error unless policy satisfaction
    /// is the current phase.
    pub fn complete(&mut self) -> Result<VerifiedAttestation, TransitionError> {
        let outcome = match &self.state {
            VerificationState::PolicySatisfied {
                allowed: AllowedClass::FULL,
                ..
            } => VerificationOutcome::allowed_full(),
            VerificationState::PolicySatisfied {
                allowed: AllowedClass::RESTRICTED,
                ..
            } => VerificationOutcome::allowed_restricted(),
            _ => return Err(self.invalid_transition(VerificationAction::Complete)),
        };
        let previous = std::mem::replace(&mut self.state, VerificationState::Verified { outcome });
        let VerificationState::PolicySatisfied {
            request,
            accepted_profile,
            session_public_key_id,
            allowed,
        } = previous
        else {
            std::unreachable!("phase was checked before terminal replacement")
        };
        Ok(VerifiedAttestation {
            binding: self.binding.clone(),
            context: request.expected,
            accepted_profile,
            session_public_key_id,
            allowed,
        })
    }

    /// Terminates this attempt because its input was malformed.
    ///
    /// # Errors
    ///
    /// Returns a redacted invalid-transition error when malformed input is not
    /// eligible in the current phase.
    pub fn mark_malformed(&mut self) -> Result<AppraisalResult, TransitionError> {
        self.emit_failure(FailureKind::Malformed)
    }

    /// Terminates this attempt because a mandatory feature was unsupported.
    ///
    /// # Errors
    ///
    /// Returns a redacted invalid-transition error when the requirement is not
    /// eligible in the current phase.
    pub fn mark_unsupported(
        &mut self,
        requirement: UnsupportedRequirement,
    ) -> Result<AppraisalResult, TransitionError> {
        self.emit_failure(FailureKind::Unsupported(requirement))
    }

    /// Terminates this attempt with a retryable unavailable result.
    ///
    /// # Errors
    ///
    /// Returns a redacted invalid-transition error when the retry reason is not
    /// eligible in the current phase.
    pub fn mark_retryable(
        &mut self,
        reason: RetryReason,
    ) -> Result<AppraisalResult, TransitionError> {
        self.emit_failure(FailureKind::Retry(reason))
    }

    /// Terminates this attempt with one fixed typed denial reason.
    ///
    /// # Errors
    ///
    /// Returns a redacted invalid-transition error when the denial reason is
    /// not eligible in the current phase.
    pub fn deny(&mut self, reason: DenialReason) -> Result<AppraisalResult, TransitionError> {
        self.emit_failure(FailureKind::Deny(reason))
    }

    /// Terminates this attempt because a required input was revoked.
    ///
    /// # Errors
    ///
    /// Returns a redacted invalid-transition error when revocation is not
    /// eligible in the current phase.
    pub fn mark_revoked(&mut self) -> Result<AppraisalResult, TransitionError> {
        self.emit_failure(FailureKind::Revoked)
    }

    fn emit_failure(&mut self, failure: FailureKind) -> Result<AppraisalResult, TransitionError> {
        let action = failure.action();
        if !failure_is_eligible(self.phase(), failure) {
            return Err(self.invalid_transition(action));
        }

        let (decision, reason, terminal) = match failure {
            FailureKind::Malformed => (
                FailureDecision::Deny,
                ReasonCode::Malformed,
                VerificationState::Malformed {
                    outcome: VerificationOutcome::malformed(),
                },
            ),
            FailureKind::Unsupported(requirement) => (
                FailureDecision::Unsupported,
                requirement.as_reason_code(),
                VerificationState::Unsupported {
                    outcome: VerificationOutcome::unsupported(requirement),
                },
            ),
            FailureKind::Retry(retry_reason) => (
                FailureDecision::Retry,
                retry_reason.as_reason_code(),
                VerificationState::Retryable {
                    outcome: VerificationOutcome::retryable(retry_reason),
                },
            ),
            FailureKind::Deny(denial_reason) => (
                FailureDecision::Deny,
                denial_reason.as_reason_code(),
                VerificationState::Denied {
                    outcome: VerificationOutcome::denied(denial_reason),
                },
            ),
            FailureKind::Revoked => (
                FailureDecision::Deny,
                ReasonCode::Revoked,
                VerificationState::Revoked {
                    outcome: VerificationOutcome::revoked(),
                },
            ),
        };

        let previous = std::mem::replace(&mut self.state, terminal);
        let request = match previous {
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
            | VerificationState::Revoked { .. } => {
                std::unreachable!("eligibility excluded terminal state before replacement")
            }
        };

        Ok(AppraisalResult {
            context: request.expected,
            payload: AppraisalPayload::Failure(FailurePayload { decision, reason }),
        })
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
        return VerificationOutcome::denied(DenialReason::ContextBindingMismatch);
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
        | FreshnessError::CapacityExceeded => {
            VerificationOutcome::retryable(RetryReason::AttestationUnavailable)
        }
    }
}

#[cfg(test)]
mod tests;
