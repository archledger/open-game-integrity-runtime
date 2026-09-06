// SPDX-License-Identifier: Apache-2.0

//! Test-only verifier policy interface for the M2 mock protocol.
//!
//! A policy turns a verified challenge plus verified evidence into a
//! non-disciplinary decision. It never sees key material and never gains
//! issuance authority: the mock verifier service consumes the decision and
//! remains the only permit signer.

use ogir_model::ReasonCode;

use crate::objects::{MockChallenge, MockEvidence};

/// The exact relying-party context a policy compares against, mirroring
/// the verifier crate's `ExpectedContext` authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockExpectedContext {
    /// Expected publisher identifier text.
    pub publisher_id: String,
    /// Expected game identifier text.
    pub game_id: String,
    /// Expected build identifier text.
    pub build_id: String,
    /// Expected account scope text.
    pub account_scope: String,
    /// Expected match identifier text.
    pub match_id: String,
    /// Expected policy identifier text.
    pub policy_id: String,
    /// Expected policy version.
    pub policy_version: u32,
}

/// What a policy tells the mock verifier to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockDecision {
    /// Appraise to allow and issue a permit with these parameters.
    Admit {
        /// Permit identifier text for the issued permit.
        permit_id: String,
        /// Session identifier text for the issued permit.
        session_id: String,
        /// Permit lifetime in seconds; strictly positive.
        lifetime_seconds: u64,
    },
    /// Deny with a non-disciplinary reason.
    Deny(ReasonCode),
}

/// The policy evaluation input: verified objects only, no key material.
#[derive(Debug)]
pub struct PolicyRequest<'a> {
    /// The verified signed challenge object.
    pub challenge: &'a MockChallenge,
    /// The verified signed evidence object.
    pub evidence: &'a MockEvidence,
}

/// Test-only policy interface exercised by the mock verifier.
pub trait MockPolicy {
    /// Evaluates verified inputs to a decision.
    fn evaluate(&self, request: &PolicyRequest<'_>) -> MockDecision;
}

/// Exact-context policy: admits only when every context field of the
/// challenge equals the expected value, with a fixed permit lifetime.
#[derive(Debug, Clone)]
pub struct ContextMatchPolicy {
    /// The authoritative expected context.
    pub expected: MockExpectedContext,
    /// Permit identifier text used on admission.
    pub permit_id: String,
    /// Session identifier text used on admission.
    pub session_id: String,
    /// Permit lifetime in seconds; strictly positive.
    pub lifetime_seconds: u64,
}

impl MockPolicy for ContextMatchPolicy {
    fn evaluate(&self, request: &PolicyRequest<'_>) -> MockDecision {
        let challenge = request.challenge;
        let expected = &self.expected;
        if challenge.publisher_id != expected.publisher_id
            || challenge.game_id != expected.game_id
            || challenge.build_id != expected.build_id
            || challenge.account_scope != expected.account_scope
            || challenge.match_id != expected.match_id
            || challenge.policy_id != expected.policy_id
            || challenge.policy_version != expected.policy_version
        {
            return MockDecision::Deny(ReasonCode::ContextBindingMismatch);
        }
        if request.evidence.challenge_object.is_empty() || request.evidence.base_claims.len() != 8 {
            return MockDecision::Deny(ReasonCode::EvidenceInvalid);
        }
        if self.lifetime_seconds == 0 {
            return MockDecision::Deny(ReasonCode::UnsupportedVersionOrProfile);
        }
        MockDecision::Admit {
            permit_id: self.permit_id.clone(),
            session_id: self.session_id.clone(),
            lifetime_seconds: self.lifetime_seconds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::MockClaim;
    use ogir_model::ProtocolVersion;

    fn challenge() -> MockChallenge {
        MockChallenge {
            version: ProtocolVersion { major: 0, minor: 1 },
            publisher_id: "pub.one".to_string(),
            game_id: "game.one".to_string(),
            build_id: "build.1".to_string(),
            account_scope: "acct.1".to_string(),
            match_id: "match.1".to_string(),
            policy_id: "policy.1".to_string(),
            policy_version: 2,
            nonce: [3; 32],
            issued_at: 10,
            expires_at: 60,
            evidence_profile_id: "profile.1".to_string(),
            issuer_key_id: [0; 16],
        }
    }

    fn evidence() -> MockEvidence {
        MockEvidence {
            challenge_object: vec![1, 2, 3],
            evidence_profile_id: "profile.1".to_string(),
            session_key_handle: [4; 32],
            session_key_id: [0; 16],
            collection_authority_contract_id: "authority.1".to_string(),
            epoch_relation: 1,
            collection_sequence: 1,
            collection_start: 20,
            snapshot_freeze_end: 30,
            base_claims: std::array::from_fn(|_| MockClaim {
                provenance: crate::objects::Provenance::TrustedAgentObserved,
                identity: vec![1],
            }),
            profile_claims: Vec::new(),
            manifest_identities: vec![1, 2],
            attester_key_id: [0; 16],
        }
    }

    fn expected() -> MockExpectedContext {
        MockExpectedContext {
            publisher_id: "pub.one".to_string(),
            game_id: "game.one".to_string(),
            build_id: "build.1".to_string(),
            account_scope: "acct.1".to_string(),
            match_id: "match.1".to_string(),
            policy_id: "policy.1".to_string(),
            policy_version: 2,
        }
    }

    fn policy() -> ContextMatchPolicy {
        ContextMatchPolicy {
            expected: expected(),
            permit_id: "permit.1".to_string(),
            session_id: "session.1".to_string(),
            lifetime_seconds: 100,
        }
    }

    #[test]
    fn matching_context_admits() {
        let request = PolicyRequest {
            challenge: &challenge(),
            evidence: &evidence(),
        };
        assert_eq!(
            policy().evaluate(&request),
            MockDecision::Admit {
                permit_id: "permit.1".to_string(),
                session_id: "session.1".to_string(),
                lifetime_seconds: 100,
            }
        );
    }

    #[test]
    fn every_single_context_field_mismatch_denies() {
        let base = challenge();
        for mutated in [
            MockChallenge {
                game_id: "game.two".to_string(),
                ..base.clone()
            },
            MockChallenge {
                build_id: "build.2".to_string(),
                ..base.clone()
            },
            MockChallenge {
                account_scope: "acct.2".to_string(),
                ..base.clone()
            },
            MockChallenge {
                match_id: "match.2".to_string(),
                ..base.clone()
            },
            MockChallenge {
                policy_id: "policy.2".to_string(),
                ..base.clone()
            },
            MockChallenge {
                policy_version: 3,
                ..base.clone()
            },
        ] {
            let request = PolicyRequest {
                challenge: &mutated,
                evidence: &evidence(),
            };
            assert_eq!(
                policy().evaluate(&request),
                MockDecision::Deny(ReasonCode::ContextBindingMismatch)
            );
        }
    }
}
