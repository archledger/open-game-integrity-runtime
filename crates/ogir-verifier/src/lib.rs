// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
//! Deterministic verifier interfaces. Cryptographic verification is not implemented yet.

mod freshness;
mod verification;

pub use freshness::{
    ChallengeBinding, FreshnessChecked, FreshnessGuard, ReplayKey, ReplayRegistration, ReplayStore,
};
pub use verification::{
    ChallengeAuthenticated, DenialReason, EvidenceAppraised, ExpectedContext, IdentityChecked,
    PolicySatisfied, RevocationChecked, SessionBound, TransitionError, VerificationAction,
    VerificationOutcome, VerificationPhase, VerificationRequest, VerifiedAttestation, VerifierFlow,
    verify_research_structure,
};
