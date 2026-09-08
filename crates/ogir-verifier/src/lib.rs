// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
//! Deterministic verifier interfaces. Cryptographic verification is not implemented yet.

pub mod bjson;
mod freshness;
pub mod http;
#[cfg(feature = "research-mock-replay")]
pub mod mock_replay;
pub mod service;
mod verification;

pub use freshness::{
    ChallengeBinding, FreshnessChecked, FreshnessGuard, ReplayKey, ReplayRegistration, ReplayStore,
};
pub use verification::{
    AcceptedClaims, AppraisalResult, AppraisalResultView, ChallengeAuthenticated, DenialReason,
    EvidenceAppraised, ExpectedContext, IdentityChecked, PolicySatisfied, RetryReason,
    RevocationChecked, SessionBound, TransitionError, UnsupportedRequirement, VerificationAction,
    VerificationOutcome, VerificationPhase, VerificationRequest, VerifiedAttestation, VerifierFlow,
    verify_research_structure,
};
