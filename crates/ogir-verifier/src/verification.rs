// SPDX-License-Identifier: Apache-2.0

//! Checked verifier-flow and report-only outcome contracts.

use std::fmt;

use ogir_model::{
    AccountScope, BuildId, Decision, FreshnessError, GameId, MatchId, PolicyId, PolicyVersion,
    PublisherChallenge, PublisherId, ReasonCode, UnixTime,
};
use ogir_protocol::EvidenceBundle;

use crate::freshness::{FreshnessGuard, ReplayStore};

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
        return denied(ReasonCode::SessionBindingMismatch);
    }

    if let Err(error) = freshness.claim(request.now, &request.challenge) {
        return freshness_failure(error);
    }

    // Deliberate fail-closed scaffold until cryptographic and policy verification exists.
    denied(ReasonCode::EvidenceInvalid)
}

const fn denied(reason: ReasonCode) -> VerificationOutcome {
    VerificationOutcome {
        decision: Decision::Deny,
        reason,
    }
}

const fn retry_unavailable() -> VerificationOutcome {
    VerificationOutcome {
        decision: Decision::Retry,
        reason: ReasonCode::AttestationUnavailable,
    }
}

fn freshness_failure(error: FreshnessError) -> VerificationOutcome {
    match error {
        FreshnessError::InvalidWindow | FreshnessError::LifetimeExceeded => {
            denied(ReasonCode::Malformed)
        }
        FreshnessError::NotYetValid => denied(ReasonCode::NotYetValid),
        FreshnessError::Expired => denied(ReasonCode::Expired),
        FreshnessError::ReplayDetected => denied(ReasonCode::ReplayDetected),
        FreshnessError::ClockRollback
        | FreshnessError::StateUnavailable
        | FreshnessError::CapacityExceeded => retry_unavailable(),
    }
}
