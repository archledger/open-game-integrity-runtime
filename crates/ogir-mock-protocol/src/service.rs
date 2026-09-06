// SPDX-License-Identifier: Apache-2.0

//! Test-only mock verifier service: wires the ADR-0015 signed objects,
//! the ADR-0016 key directory, the verifier crate's isolated replay cache
//! (ADR-0013), and a policy into the challenge -> evidence -> permit
//! appraisal path. Nothing here is a production verifier.

use std::num::{NonZeroU64, NonZeroUsize};

use ogir_mock_keys::keys::MockVerifierKey;
use ogir_model::{
    AccountScope, BuildId, ChallengeLifetime, ChallengeWindow, FreshnessError, FreshnessLimits,
    GameId, MatchId, Nonce, PolicyId, PolicyVersion, PublisherChallenge, PublisherId, ReasonCode,
    UnixTime,
};
use ogir_verifier::ReplayRegistration;
use ogir_verifier::mock_replay::{MockReplayCache, MockReplayLimits};

use crate::TranscriptError;
use crate::objects::{
    MockPermit, build_signed_permit, verify_signed_challenge, verify_signed_evidence,
};
use crate::policy::{MockPolicy, PolicyRequest};

/// The mock verifier's appraisal result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockVerdict {
    /// The policy admitted; `permit_bytes` is the signed permit object.
    Admit {
        /// Signed permit object bytes (tag, records, authenticator).
        permit_bytes: Vec<u8>,
        /// The parsed permit for caller inspection.
        permit: MockPermit,
    },
    /// Deterministic non-disciplinary denial; never a permit artifact.
    Deny {
        /// Public, non-disciplinary reason code.
        reason: ReasonCode,
    },
}

/// Failures specific to service setup or permit issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    /// A transcript-layer rejection occurred before appraisal.
    Transcript(TranscriptError),
    /// The verified challenge could not be mapped to model types.
    ModelMapping,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transcript(error) => write!(formatter, "transcript rejected: {error}"),
            Self::ModelMapping => formatter.write_str("verified challenge fails model invariants"),
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<TranscriptError> for ServiceError {
    fn from(error: TranscriptError) -> Self {
        Self::Transcript(error)
    }
}

fn freshness_reason(error: FreshnessError) -> ReasonCode {
    match error {
        FreshnessError::NotYetValid => ReasonCode::NotYetValid,
        FreshnessError::Expired => ReasonCode::Expired,
        FreshnessError::ReplayDetected => ReasonCode::ReplayDetected,
        _ => ReasonCode::TransientFailure,
    }
}

/// A mock verifier service bound to one signing key, one policy, and one
/// isolated replay-cache experiment.
#[derive(Debug)]
pub struct MockVerifierService<P> {
    signing_key: MockVerifierKey,
    policy: P,
    cache: MockReplayCache,
    max_challenge_lifetime: ChallengeLifetime,
}

impl<P: MockPolicy> MockVerifierService<P> {
    /// Creates a service with an isolated replay-cache experiment sized
    /// for tests; `max_challenge_lifetime_seconds` bounds accepted
    /// challenge windows and must be strictly positive.
    pub fn new(
        signing_key: MockVerifierKey,
        policy: P,
        max_challenge_lifetime_seconds: u64,
    ) -> Result<Self, ServiceError> {
        let maximum =
            NonZeroU64::new(max_challenge_lifetime_seconds).ok_or(ServiceError::ModelMapping)?;
        let limits = FreshnessLimits::new(
            ChallengeLifetime::new(maximum),
            NonZeroUsize::new(1024).ok_or(ServiceError::ModelMapping)?,
            NonZeroUsize::new(1024).ok_or(ServiceError::ModelMapping)?,
            NonZeroUsize::new(1024).ok_or(ServiceError::ModelMapping)?,
            maximum,
            NonZeroUsize::new(1024).ok_or(ServiceError::ModelMapping)?,
        );
        let cache = MockReplayCache::new_research_run(MockReplayLimits::new(
            limits,
            NonZeroUsize::new(1024).ok_or(ServiceError::ModelMapping)?,
        ))
        .map_err(|_| ServiceError::ModelMapping)?;
        Ok(Self {
            signing_key,
            policy,
            cache,
            max_challenge_lifetime: ChallengeLifetime::new(maximum),
        })
    }

    /// Processes one signed challenge plus signed evidence at decision
    /// time `now`: verifies both objects, enforces the half-open challenge
    /// window, registers and claims the nonce in the isolated replay
    /// cache (evidence replay rejects deterministically), applies the
    /// policy, and issues a signed permit on admission.
    pub fn process(
        &self,
        now: u64,
        challenge_bytes: &[u8],
        evidence_bytes: &[u8],
        directory: &ogir_mock_keys::keys::MockKeyDirectory,
    ) -> MockVerdict {
        let challenge = match verify_signed_challenge(directory, challenge_bytes) {
            Ok(challenge) => challenge,
            Err(error) => return deny_transcript(error),
        };
        let evidence = match verify_signed_evidence(directory, evidence_bytes) {
            Ok(evidence) => evidence,
            Err(error) => return deny_transcript(error),
        };

        // Binding by construction: the evidence must embed the exact
        // challenge object it answers.
        if evidence.challenge_object != challenge_bytes {
            return MockVerdict::Deny {
                reason: ReasonCode::ContextBindingMismatch,
            };
        }

        let typed = match to_model_challenge(&challenge, self.max_challenge_lifetime) {
            Ok(typed) => typed,
            Err(_) => {
                return MockVerdict::Deny {
                    reason: ReasonCode::Malformed,
                };
            }
        };

        let moment = UnixTime::new(now);
        let registration = ReplayRegistration::from_challenge(&typed);
        if let Err(error) = typed.window.evaluate(moment) {
            return MockVerdict::Deny {
                reason: freshness_reason(error),
            };
        }
        if let Err(error) = self.cache.register(moment, &registration) {
            return MockVerdict::Deny {
                reason: freshness_reason(error),
            };
        }
        if let Err(error) = self.cache.claim(moment, &registration) {
            return MockVerdict::Deny {
                reason: freshness_reason(error),
            };
        }

        let request = PolicyRequest {
            challenge: &challenge,
            evidence: &evidence,
        };
        match self.policy.evaluate(&request) {
            crate::policy::MockDecision::Admit {
                permit_id,
                session_id,
                lifetime_seconds,
            } => {
                let lifetime = match NonZeroU64::new(lifetime_seconds) {
                    Some(lifetime) => lifetime,
                    None => {
                        return MockVerdict::Deny {
                            reason: ReasonCode::UnsupportedVersionOrProfile,
                        };
                    }
                };
                let permit = MockPermit {
                    version: challenge.version,
                    permit_id,
                    session_id,
                    session_key_handle: evidence.session_key_handle,
                    appraised_nonce: challenge.nonce,
                    policy_id: challenge.policy_id.clone(),
                    policy_version: challenge.policy_version,
                    issued_at: now,
                    expires_at: now.saturating_add(lifetime.get()),
                    issuer_key_id: *self.signing_key.id().as_bytes(),
                };
                match build_signed_permit(&permit, &self.signing_key) {
                    Ok(permit_bytes) => MockVerdict::Admit {
                        permit_bytes,
                        permit,
                    },
                    Err(_) => MockVerdict::Deny {
                        reason: ReasonCode::TransientFailure,
                    },
                }
            }
            crate::policy::MockDecision::Deny(reason) => MockVerdict::Deny { reason },
        }
    }
}

fn deny_transcript(error: TranscriptError) -> MockVerdict {
    let reason = match &error {
        TranscriptError::UnknownKey | TranscriptError::AuthenticationFailed => {
            ReasonCode::ChallengeAuthenticationFailed
        }
        TranscriptError::Truncated
        | TranscriptError::TagMismatch
        | TranscriptError::DuplicateField { .. }
        | TranscriptError::UnknownField { .. }
        | TranscriptError::OutOfOrder { .. }
        | TranscriptError::BadFieldLength { .. }
        | TranscriptError::MissingField { .. }
        | TranscriptError::ObjectTooLarge
        | TranscriptError::InvalidWindow => ReasonCode::Malformed,
        TranscriptError::Frame(_) => ReasonCode::UnsupportedVersionOrProfile,
    };
    MockVerdict::Deny { reason }
}

fn to_model_challenge(
    challenge: &crate::objects::MockChallenge,
    maximum: ChallengeLifetime,
) -> Result<PublisherChallenge, ()> {
    let publisher_id = PublisherId::new(&challenge.publisher_id).map_err(|_| ())?;
    let game_id = GameId::new(&challenge.game_id).map_err(|_| ())?;
    let build_id = BuildId::new(&challenge.build_id).map_err(|_| ())?;
    let account_scope = AccountScope::new(&challenge.account_scope).map_err(|_| ())?;
    let match_id = MatchId::new(&challenge.match_id).map_err(|_| ())?;
    let policy_id = PolicyId::new(&challenge.policy_id).map_err(|_| ())?;
    let window = ChallengeWindow::new(
        UnixTime::new(challenge.issued_at),
        UnixTime::new(challenge.expires_at),
        maximum,
    )
    .map_err(|_| ())?;
    Ok(PublisherChallenge {
        version: challenge.version,
        publisher_id,
        game_id,
        build_id,
        account_scope,
        match_id,
        policy_id,
        policy_version: PolicyVersion::new(challenge.policy_version),
        nonce: Nonce::from_bytes(challenge.nonce),
        window,
    })
}
