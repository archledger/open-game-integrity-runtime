// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
//! Backend-neutral interfaces for the local OGIR agent.

mod session;

pub use session::{
    BoundCaller, CleanupStatus, CreatedEvidence, LocalSession, PreparedSession, SessionAction,
    SessionPhase, TransitionError, ValidatedChallenge, ValidatedPermit,
};

use std::error::Error;
use std::fmt;

use ogir_model::{PublisherChallenge, SessionId};
use ogir_protocol::EvidenceBundle;

/// A race-resistant local session identity supplied by the trusted portal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    /// Opaque local session identifier.
    pub local_session_id: SessionId,
    /// Digest of the independently derived game manifest.
    pub game_manifest_digest: Vec<u8>,
    /// Digest of the independently derived runtime manifest.
    pub runtime_manifest_digest: Vec<u8>,
}

/// Request passed to an attestation backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRequest {
    /// Publisher challenge.
    pub challenge: PublisherChallenge,
    /// Trusted local session identity.
    pub session: SessionIdentity,
}

/// Backend boundary for test, software-TPM, and hardware-TPM implementations.
pub trait AttestationBackend: fmt::Debug + Send {
    /// Creates fresh evidence for the exact request.
    fn create_evidence(&mut self, request: &EvidenceRequest) -> Result<EvidenceBundle, AgentError>;
}

/// Local-agent error. It intentionally does not classify the player as cheating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentError {
    /// Challenge failed structural validation.
    InvalidChallenge,
    /// Caller/session identity could not be established.
    SessionBindingFailed,
    /// Required attestation backend was unavailable.
    BackendUnavailable,
    /// Evidence generation failed.
    EvidenceGenerationFailed,
}

impl fmt::Display for AgentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChallenge => formatter.write_str("invalid challenge"),
            Self::SessionBindingFailed => formatter.write_str("session binding failed"),
            Self::BackendUnavailable => formatter.write_str("attestation backend unavailable"),
            Self::EvidenceGenerationFailed => formatter.write_str("evidence generation failed"),
        }
    }
}

impl Error for AgentError {}
