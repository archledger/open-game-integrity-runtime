// SPDX-License-Identifier: Apache-2.0

//! Private local-session state tracks ordered, session-bound admission gates.
//!
//! Trusted production construction is deferred to a future adapter with a real
//! caller; this module deliberately provides no constructor in M1.

use std::error::Error;
use std::fmt;

use ogir_model::SessionId;

/// Public view of a local session's lifecycle phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionPhase {
    /// The session has not accepted an admission gate.
    New,
    /// The publisher challenge was validated for this session.
    ChallengeValidated,
    /// The caller was bound to this session.
    CallerBound,
    /// The protected session was prepared.
    SessionPrepared,
    /// Session evidence was created.
    EvidenceCreated,
    /// A validated permit was received for this session.
    PermitReceived,
    /// The protected session is active.
    Active,
    /// The active session is awaiting renewal.
    RenewalPending,
    /// The session ended normally.
    Ended,
    /// The session was invalidated.
    Invalidated,
}

/// Public view of the cleanup obligation for a local session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CleanupStatus {
    /// The session has no cleanup obligation.
    NotRequired,
    /// The session requires trusted cleanup.
    Required,
    /// Trusted cleanup completed.
    Complete,
}

/// A requested local-session lifecycle action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionAction {
    /// Record successful publisher-challenge validation.
    RecordChallengeValidated,
    /// Record successful caller binding.
    RecordCallerBound,
    /// Record successful protected-session preparation.
    RecordSessionPrepared,
    /// Record successful evidence creation.
    RecordEvidenceCreated,
    /// Record receipt of a validated permit.
    RecordPermitReceived,
    /// Activate the session after permit receipt.
    Activate,
    /// Begin session renewal.
    BeginRenewal,
    /// End the session.
    End,
    /// Invalidate the session.
    Invalidate,
    /// Record trusted cleanup completion.
    RecordCleanupCompleted,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionState {
    New,
    ChallengeValidated,
    CallerBound,
    SessionPrepared,
    EvidenceCreated,
    PermitReceived,
    Active,
}

struct SessionBinding(SessionId);

impl SessionBinding {
    fn matches(&self, session_id: &SessionId) -> bool {
        self.0.eq(session_id)
    }
}

/// Opaque proof that the publisher challenge was validated for one session.
#[must_use = "validated challenge capability must be consumed by its session transition"]
pub struct ValidatedChallenge {
    binding: SessionBinding,
}

impl fmt::Debug for ValidatedChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedChallenge([REDACTED])")
    }
}

/// Opaque proof that the caller was bound to one session.
#[must_use = "caller binding capability must be consumed by its session transition"]
pub struct BoundCaller {
    binding: SessionBinding,
}

impl fmt::Debug for BoundCaller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundCaller([REDACTED])")
    }
}

/// Opaque proof that the protected session was prepared for one session.
#[must_use = "prepared-session capability must be consumed by its session transition"]
pub struct PreparedSession {
    binding: SessionBinding,
}

impl fmt::Debug for PreparedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedSession([REDACTED])")
    }
}

/// Opaque proof that evidence was created for one session.
#[must_use = "created-evidence capability must be consumed by its session transition"]
pub struct CreatedEvidence {
    binding: SessionBinding,
}

impl fmt::Debug for CreatedEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CreatedEvidence([REDACTED])")
    }
}

/// Opaque proof that a permit was validated for one session.
#[must_use = "validated permit capability must be consumed by its session transition"]
pub struct ValidatedPermit {
    binding: SessionBinding,
}

impl fmt::Debug for ValidatedPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedPermit([REDACTED])")
    }
}

/// A rejected local-session transition or capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    /// The action is not valid in the session's current state.
    InvalidTransition {
        /// The public lifecycle phase when the action was attempted.
        phase: SessionPhase,
        /// The public cleanup status when the action was attempted.
        cleanup_status: CleanupStatus,
        /// The requested action.
        action: SessionAction,
    },
    /// The capability is not bound to this local session.
    CapabilityRejected {
        /// The action that rejected the capability.
        action: SessionAction,
    },
}

impl fmt::Display for TransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { .. } => {
                formatter.write_str("local session transition is not allowed")
            }
            Self::CapabilityRejected { .. } => {
                formatter.write_str("local session capability rejected")
            }
        }
    }
}

impl Error for TransitionError {}

/// A trusted owner's local session lifecycle state.
#[must_use = "local session lifecycle state must be retained by its trusted owner"]
pub struct LocalSession {
    session_id: SessionId,
    state: SessionState,
}

impl LocalSession {
    /// Returns the public lifecycle phase.
    pub fn phase(&self) -> SessionPhase {
        match self.state {
            SessionState::New => SessionPhase::New,
            SessionState::ChallengeValidated => SessionPhase::ChallengeValidated,
            SessionState::CallerBound => SessionPhase::CallerBound,
            SessionState::SessionPrepared => SessionPhase::SessionPrepared,
            SessionState::EvidenceCreated => SessionPhase::EvidenceCreated,
            SessionState::PermitReceived => SessionPhase::PermitReceived,
            SessionState::Active => SessionPhase::Active,
        }
    }

    /// Returns the public cleanup obligation status.
    pub fn cleanup_status(&self) -> CleanupStatus {
        match self.state {
            SessionState::New => CleanupStatus::NotRequired,
            SessionState::ChallengeValidated => CleanupStatus::NotRequired,
            SessionState::CallerBound => CleanupStatus::NotRequired,
            SessionState::SessionPrepared => CleanupStatus::NotRequired,
            SessionState::EvidenceCreated => CleanupStatus::NotRequired,
            SessionState::PermitReceived => CleanupStatus::NotRequired,
            SessionState::Active => CleanupStatus::NotRequired,
        }
    }

    fn invalid_transition(&self, action: SessionAction) -> TransitionError {
        TransitionError::InvalidTransition {
            phase: self.phase(),
            cleanup_status: self.cleanup_status(),
            action,
        }
    }

    fn ensure_binding(
        &self,
        action: SessionAction,
        binding: &SessionBinding,
    ) -> Result<(), TransitionError> {
        if binding.matches(&self.session_id) {
            Ok(())
        } else {
            Err(TransitionError::CapabilityRejected { action })
        }
    }

    /// Records a validated publisher challenge for this session.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::InvalidTransition`] unless the session is
    /// [`SessionPhase::New`], or [`TransitionError::CapabilityRejected`] when
    /// the capability is bound to another session.
    pub fn record_challenge_validated(
        &mut self,
        capability: ValidatedChallenge,
    ) -> Result<(), TransitionError> {
        if self.state != SessionState::New {
            return Err(self.invalid_transition(SessionAction::RecordChallengeValidated));
        }
        self.ensure_binding(SessionAction::RecordChallengeValidated, &capability.binding)?;
        self.state = SessionState::ChallengeValidated;
        Ok(())
    }

    /// Records a caller binding for this session.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::InvalidTransition`] unless the session is
    /// [`SessionPhase::ChallengeValidated`], or
    /// [`TransitionError::CapabilityRejected`] when the capability is bound to
    /// another session.
    pub fn record_caller_bound(&mut self, capability: BoundCaller) -> Result<(), TransitionError> {
        if self.state != SessionState::ChallengeValidated {
            return Err(self.invalid_transition(SessionAction::RecordCallerBound));
        }
        self.ensure_binding(SessionAction::RecordCallerBound, &capability.binding)?;
        self.state = SessionState::CallerBound;
        Ok(())
    }

    /// Records protected-session preparation for this session.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::InvalidTransition`] unless the session is
    /// [`SessionPhase::CallerBound`], or [`TransitionError::CapabilityRejected`]
    /// when the capability is bound to another session.
    pub fn record_session_prepared(
        &mut self,
        capability: PreparedSession,
    ) -> Result<(), TransitionError> {
        if self.state != SessionState::CallerBound {
            return Err(self.invalid_transition(SessionAction::RecordSessionPrepared));
        }
        self.ensure_binding(SessionAction::RecordSessionPrepared, &capability.binding)?;
        self.state = SessionState::SessionPrepared;
        Ok(())
    }

    /// Records evidence creation for this session.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::InvalidTransition`] unless the session is
    /// [`SessionPhase::SessionPrepared`], or
    /// [`TransitionError::CapabilityRejected`] when the capability is bound to
    /// another session.
    pub fn record_evidence_created(
        &mut self,
        capability: CreatedEvidence,
    ) -> Result<(), TransitionError> {
        if self.state != SessionState::SessionPrepared {
            return Err(self.invalid_transition(SessionAction::RecordEvidenceCreated));
        }
        self.ensure_binding(SessionAction::RecordEvidenceCreated, &capability.binding)?;
        self.state = SessionState::EvidenceCreated;
        Ok(())
    }

    /// Records a validated permit for this session.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::InvalidTransition`] unless the session is
    /// [`SessionPhase::EvidenceCreated`], or
    /// [`TransitionError::CapabilityRejected`] when the capability is bound to
    /// another session.
    pub fn record_permit_received(
        &mut self,
        capability: ValidatedPermit,
    ) -> Result<(), TransitionError> {
        if self.state != SessionState::EvidenceCreated {
            return Err(self.invalid_transition(SessionAction::RecordPermitReceived));
        }
        self.ensure_binding(SessionAction::RecordPermitReceived, &capability.binding)?;
        self.state = SessionState::PermitReceived;
        Ok(())
    }

    /// Activates the session after it has received a validated permit.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::InvalidTransition`] unless the session is
    /// [`SessionPhase::PermitReceived`].
    pub fn activate(&mut self) -> Result<(), TransitionError> {
        if self.state != SessionState::PermitReceived {
            return Err(self.invalid_transition(SessionAction::Activate));
        }
        self.state = SessionState::Active;
        Ok(())
    }
}

impl fmt::Debug for LocalSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalSession")
            .field("phase", &self.phase())
            .field("cleanup_status", &self.cleanup_status())
            .finish()
    }
}

#[cfg(test)]
mod tests;
