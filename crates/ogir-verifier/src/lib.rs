// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
//! Deterministic verifier interfaces. Cryptographic verification is not implemented yet.

use ogir_model::{
    AccountScope, BuildId, Decision, GameId, MatchId, PolicyId, PolicyVersion, PublisherChallenge,
    PublisherId, ReasonCode,
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
    /// Verifier's current Unix time.
    pub now_unix_seconds: u64,
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
    if request.challenge.validate_structure().is_err() {
        return denied(ReasonCode::Malformed);
    }

    if request.now_unix_seconds < request.challenge.issued_at_unix_seconds {
        return denied(ReasonCode::NotYetValid);
    }

    if request.now_unix_seconds >= request.challenge.expires_at_unix_seconds {
        return denied(ReasonCode::Expired);
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

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use super::{ExpectedContext, VerificationRequest, verify_research_structure};
    use ogir_model::{
        AccountScope, BuildId, Decision, EvidenceProfile, GameId, IdentifierError, MatchId, Nonce,
        PolicyId, PolicyVersion, ProtocolVersion, PublisherChallenge, PublisherId, ReasonCode,
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
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
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
            now_unix_seconds: 150,
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
            now_unix_seconds: 200,
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
            now_unix_seconds: 99,
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
            now_unix_seconds: 150,
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
            now_unix_seconds: 150,
        };
        let outcome = verify_research_structure(&request);
        assert_eq!(outcome.reason, ReasonCode::SessionBindingMismatch);
    }
}
