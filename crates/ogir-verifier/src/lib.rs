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

/// Performs only structural and relying-party context checks.
///
/// This scaffold does not perform signature, TPM, replay, or policy verification and therefore
/// never returns `Decision::Allow`.
#[must_use]
pub fn verify_research_structure(request: &VerificationRequest) -> VerificationOutcome {
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

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::num::NonZeroU64;

    use super::{ExpectedContext, VerificationRequest, verify_research_structure};
    use ogir_model::{
        AccountScope, BuildId, ChallengeLifetime, ChallengeWindow, Decision, EvidenceProfile,
        GameId, IdentifierError, MatchId, Nonce, PolicyId, PolicyVersion, ProtocolVersion,
        PublisherChallenge, PublisherId, ReasonCode, UnixTime,
    };
    use ogir_protocol::EvidenceBundle;

    fn identifier<T>(value: &str) -> T
    where
        T: Debug,
        for<'a> T: TryFrom<&'a str, Error = IdentifierError>,
    {
        match T::try_from(value) {
            Ok(identifier) => identifier,
            Err(error) => panic!("valid fixture rejected: {error:?}"),
        }
    }

    fn challenge() -> PublisherChallenge {
        let maximum = match NonZeroU64::new(100) {
            Some(value) => ChallengeLifetime::new(value),
            None => panic!("fixture lifetime must be nonzero"),
        };
        let window = match ChallengeWindow::new(UnixTime::new(100), UnixTime::new(200), maximum) {
            Ok(value) => value,
            Err(error) => panic!("valid fixture window rejected: {error:?}"),
        };
        PublisherChallenge {
            version: ProtocolVersion { major: 0, minor: 1 },
            publisher_id: identifier::<PublisherId>("example.publisher"),
            game_id: identifier::<GameId>("example.game"),
            build_id: identifier::<BuildId>("build-1"),
            account_scope: identifier::<AccountScope>("account-1"),
            match_id: identifier::<MatchId>("match-1"),
            policy_id: identifier::<PolicyId>("research-v0"),
            policy_version: PolicyVersion::new(1),
            nonce: Nonce::from_bytes([1; 32]),
            window,
        }
    }

    fn expected() -> ExpectedContext {
        ExpectedContext {
            publisher_id: identifier::<PublisherId>("example.publisher"),
            game_id: identifier::<GameId>("example.game"),
            build_id: identifier::<BuildId>("build-1"),
            account_scope: identifier::<AccountScope>("account-1"),
            match_id: identifier::<MatchId>("match-1"),
            policy_id: identifier::<PolicyId>("research-v0"),
            policy_version: PolicyVersion::new(1),
        }
    }

    fn evidence() -> EvidenceBundle {
        EvidenceBundle {
            profile_id: identifier::<EvidenceProfile>("mock-v0"),
            payload: Vec::new(),
        }
    }

    #[test]
    fn scaffold_never_allows_unverified_evidence() {
        let request = VerificationRequest {
            challenge: challenge(),
            evidence: evidence(),
            expected: expected(),
            now: UnixTime::new(150),
        };
        let outcome = verify_research_structure(&request);
        assert_eq!(outcome.decision, Decision::Deny);
        assert_eq!(outcome.reason, ReasonCode::EvidenceInvalid);
    }

    #[test]
    fn challenge_is_rejected_at_exact_expiry() {
        let request = VerificationRequest {
            challenge: challenge(),
            evidence: evidence(),
            expected: expected(),
            now: UnixTime::new(200),
        };
        let outcome = verify_research_structure(&request);
        assert_eq!(outcome.reason, ReasonCode::Expired);
    }

    #[test]
    fn challenge_is_rejected_before_issue_time() {
        let request = VerificationRequest {
            challenge: challenge(),
            evidence: evidence(),
            expected: expected(),
            now: UnixTime::new(99),
        };
        let outcome = verify_research_structure(&request);
        assert_eq!(outcome.reason, ReasonCode::NotYetValid);
    }

    #[test]
    fn cross_match_context_is_rejected() {
        let mut context = expected();
        context.match_id = identifier::<MatchId>("different-match");
        let request = VerificationRequest {
            challenge: challenge(),
            evidence: evidence(),
            expected: context,
            now: UnixTime::new(150),
        };
        let outcome = verify_research_structure(&request);
        assert_eq!(outcome.reason, ReasonCode::SessionBindingMismatch);
    }

    #[test]
    fn cross_policy_version_context_is_rejected() {
        let mut context = expected();
        context.policy_version = PolicyVersion::new(2);
        let request = VerificationRequest {
            challenge: challenge(),
            evidence: evidence(),
            expected: context,
            now: UnixTime::new(150),
        };
        let outcome = verify_research_structure(&request);
        assert_eq!(outcome.reason, ReasonCode::SessionBindingMismatch);
    }

    #[test]
    fn verifier_accepts_freshness_boundaries_before_failing_closed_on_evidence() {
        for now in [100, 199] {
            let request = VerificationRequest {
                challenge: challenge(),
                evidence: evidence(),
                expected: expected(),
                now: UnixTime::new(now),
            };
            let outcome = verify_research_structure(&request);
            assert_eq!(outcome.reason, ReasonCode::EvidenceInvalid);
        }
    }
}
