// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
//! Deterministic verifier interfaces. Cryptographic verification is not implemented yet.

mod freshness;

pub use freshness::{
    ChallengeBinding, FreshnessChecked, FreshnessGuard, ReplayKey, ReplayRegistration, ReplayStore,
};

use ogir_model::{
    AccountScope, BuildId, Decision, FreshnessError, GameId, MatchId, PolicyId, PolicyVersion,
    PublisherChallenge, PublisherId, ReasonCode, UnixTime,
};
use ogir_protocol::EvidenceBundle;

/// Expected relying-party context supplied independently of client evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Input to the verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Deterministic high-level outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationOutcome {
    /// Authorization class.
    pub decision: Decision,
    /// Structured non-disciplinary reason.
    pub reason: ReasonCode,
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
    if let Err(error) = request.challenge.window.evaluate(request.now) {
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

    let _freshness_checked = match freshness.claim(request.now, &request.challenge) {
        Ok(capability) => capability,
        Err(error) => return freshness_failure(error),
    };

    // Deliberate fail-closed scaffold until cryptographic and policy verification exists.
    denied(ReasonCode::EvidenceInvalid)
}

const fn denied(reason: ReasonCode) -> VerificationOutcome {
    VerificationOutcome {
        decision: Decision::Deny,
        reason,
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
        | FreshnessError::CapacityExceeded => VerificationOutcome {
            decision: Decision::Retry,
            reason: ReasonCode::AttestationUnavailable,
        },
    }
}
