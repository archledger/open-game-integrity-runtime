// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
//! Deterministic verifier interfaces. Cryptographic verification is not implemented yet.

use ogir_model::{Decision, PublisherChallenge, ReasonCode};
use ogir_protocol::EvidenceBundle;

/// Expected relying-party context supplied independently of client evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedContext {
    /// Expected publisher.
    pub publisher_id: String,
    /// Expected game.
    pub game_id: String,
    /// Expected build.
    pub build_id: String,
    /// Expected account scope.
    pub account_scope: String,
    /// Expected match.
    pub match_id: String,
    /// Expected policy.
    pub policy_id: String,
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
        && expected.policy_id == challenge.policy_id;

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
    use super::{ExpectedContext, VerificationRequest, verify_research_structure};
    use ogir_model::{Decision, Nonce, ProtocolVersion, PublisherChallenge, ReasonCode};
    use ogir_protocol::EvidenceBundle;

    fn challenge() -> PublisherChallenge {
        PublisherChallenge {
            version: ProtocolVersion { major: 0, minor: 1 },
            publisher_id: "example.publisher".to_owned(),
            game_id: "example.game".to_owned(),
            build_id: "build-1".to_owned(),
            account_scope: "account-1".to_owned(),
            match_id: "match-1".to_owned(),
            policy_id: "research-v0".to_owned(),
            policy_version: 1,
            nonce: Nonce::from_bytes([1; 32]),
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
        }
    }

    fn expected() -> ExpectedContext {
        ExpectedContext {
            publisher_id: "example.publisher".to_owned(),
            game_id: "example.game".to_owned(),
            build_id: "build-1".to_owned(),
            account_scope: "account-1".to_owned(),
            match_id: "match-1".to_owned(),
            policy_id: "research-v0".to_owned(),
        }
    }

    fn evidence() -> EvidenceBundle {
        EvidenceBundle {
            profile_id: "mock-v0".to_owned(),
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
        context.match_id = "different-match".to_owned();
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
