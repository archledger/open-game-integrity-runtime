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
enum TerminalCleanup {
    Required,
    Complete,
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
    RenewalPending,
    Ended(TerminalCleanup),
    Invalidated(TerminalCleanup),
}

impl SessionState {
    fn is_terminal(self) -> bool {
        match self {
            Self::New
            | Self::ChallengeValidated
            | Self::CallerBound
            | Self::SessionPrepared
            | Self::EvidenceCreated
            | Self::PermitReceived
            | Self::Active
            | Self::RenewalPending => false,
            Self::Ended(TerminalCleanup::Required)
            | Self::Ended(TerminalCleanup::Complete)
            | Self::Invalidated(TerminalCleanup::Required)
            | Self::Invalidated(TerminalCleanup::Complete) => true,
        }
    }
}

struct SessionBinding(SessionId);

impl SessionBinding {
    fn matches(&self, session_id: &SessionId) -> bool {
        self.0.eq(session_id)
    }
}

/// Opaque proof that the publisher challenge was validated for one session.
///
/// ```compile_fail
/// use ogir_agent::ValidatedChallenge;
///
/// fn duplicate(value: ValidatedChallenge) { let _copy = value.clone(); }
/// ```
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
///
/// ```compile_fail
/// use ogir_agent::BoundCaller;
///
/// fn duplicate(value: BoundCaller) { let _copy = value.clone(); }
/// ```
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
///
/// ```compile_fail
/// use ogir_agent::PreparedSession;
///
/// fn duplicate(value: PreparedSession) { let _copy = value.clone(); }
/// ```
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
///
/// ```compile_fail
/// use ogir_agent::CreatedEvidence;
///
/// fn duplicate(value: CreatedEvidence) { let _copy = value.clone(); }
/// ```
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
///
/// ```compile_fail
/// use ogir_agent::ValidatedPermit;
///
/// fn duplicate(value: ValidatedPermit) { let _copy = value.clone(); }
/// ```
///
/// ```compile_fail
/// use ogir_agent::ValidatedPermit;
///
/// fn unavailable<T>() -> T { loop {} }
///
/// fn forge() -> ValidatedPermit {
///     ValidatedPermit { binding: unavailable() }
/// }
/// ```
///
/// ```compile_fail
/// use ogir_agent::ValidatedPermit;
///
/// fn reveal(permit: ValidatedPermit) {
///     let _binding = permit.binding;
/// }
/// ```
#[must_use = "validated permit capability must be consumed by its session transition"]
#[deny(private_interfaces)]
pub struct ValidatedPermit {
    binding: SessionBinding,
}

impl fmt::Debug for ValidatedPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedPermit([REDACTED])")
    }
}

/// Opaque request for retryable terminal-session cleanup.
///
/// Dropping a request does not complete cleanup. While cleanup remains
/// required, [`LocalSession::cleanup_request`] can issue another request for
/// an idempotent trusted cleanup adapter.
///
/// ```compile_fail
/// use ogir_agent::CleanupRequest;
///
/// fn duplicate(value: CleanupRequest) { let _copy = value.clone(); }
/// ```
#[must_use = "terminal session cleanup remains required until acknowledged"]
pub struct CleanupRequest {
    binding: SessionBinding,
}

impl fmt::Debug for CleanupRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _redacted_binding = &self.binding;
        formatter.write_str("CleanupRequest([REDACTED])")
    }
}

/// Opaque proof that trusted cleanup completed for one terminal session.
///
/// ```compile_fail
/// use ogir_agent::CleanupCompleted;
///
/// fn duplicate(value: CleanupCompleted) { let _copy = value.clone(); }
/// ```
///
/// ```compile_fail
/// use ogir_agent::CleanupCompleted;
///
/// fn unavailable<T>() -> T { loop {} }
///
/// fn forge() -> CleanupCompleted {
///     CleanupCompleted { binding: unavailable() }
/// }
/// ```
#[must_use = "cleanup completion capability must be consumed by its session transition"]
pub struct CleanupCompleted {
    binding: SessionBinding,
}

impl fmt::Debug for CleanupCompleted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CleanupCompleted([REDACTED])")
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
///
/// ```rust
/// use ogir_agent::{
///     BoundCaller, CleanupCompleted, CleanupRequest, CreatedEvidence, LocalSession,
///     PreparedSession, ValidatedChallenge, ValidatedPermit,
/// };
///
/// fn assert_public_type<T>() {}
///
/// assert_public_type::<LocalSession>();
/// assert_public_type::<ValidatedChallenge>();
/// assert_public_type::<BoundCaller>();
/// assert_public_type::<PreparedSession>();
/// assert_public_type::<CreatedEvidence>();
/// assert_public_type::<ValidatedPermit>();
/// assert_public_type::<CleanupRequest>();
/// assert_public_type::<CleanupCompleted>();
/// ```
///
/// ```compile_fail
/// use ogir_agent::LocalSession;
/// use ogir_model::SessionId;
///
/// let id = SessionId::try_from("session-a")?;
/// let _session = LocalSession::new(id);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ```compile_fail
/// use ogir_agent::LocalSession;
///
/// fn duplicate(value: LocalSession) { let _copy = value.clone(); }
/// ```
///
/// ```compile_fail
/// use ogir_agent::LocalSession;
///
/// fn unavailable<T>() -> T { loop {} }
///
/// fn force_state(session: &mut LocalSession) {
///     session.state = unavailable();
/// }
/// ```
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
            SessionState::RenewalPending => SessionPhase::RenewalPending,
            SessionState::Ended(TerminalCleanup::Required)
            | SessionState::Ended(TerminalCleanup::Complete) => SessionPhase::Ended,
            SessionState::Invalidated(TerminalCleanup::Required)
            | SessionState::Invalidated(TerminalCleanup::Complete) => SessionPhase::Invalidated,
        }
    }

    /// Returns the public cleanup obligation status.
    pub fn cleanup_status(&self) -> CleanupStatus {
        match self.state {
            SessionState::New
            | SessionState::ChallengeValidated
            | SessionState::CallerBound
            | SessionState::SessionPrepared
            | SessionState::EvidenceCreated
            | SessionState::PermitReceived
            | SessionState::Active
            | SessionState::RenewalPending => CleanupStatus::NotRequired,
            SessionState::Ended(TerminalCleanup::Required)
            | SessionState::Invalidated(TerminalCleanup::Required) => CleanupStatus::Required,
            SessionState::Ended(TerminalCleanup::Complete)
            | SessionState::Invalidated(TerminalCleanup::Complete) => CleanupStatus::Complete,
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
    /// [`SessionPhase::EvidenceCreated`] or [`SessionPhase::RenewalPending`], or
    /// [`TransitionError::CapabilityRejected`] when the capability is bound to
    /// another session.
    pub fn record_permit_received(
        &mut self,
        capability: ValidatedPermit,
    ) -> Result<(), TransitionError> {
        if self.state != SessionState::EvidenceCreated && self.state != SessionState::RenewalPending
        {
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

    /// Begins renewal of an active session.
    ///
    /// A fresh matching [`ValidatedPermit`] must be recorded before the
    /// session can become active again.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::InvalidTransition`] unless the session is
    /// [`SessionPhase::Active`].
    pub fn begin_renewal(&mut self) -> Result<(), TransitionError> {
        if self.state != SessionState::Active {
            return Err(self.invalid_transition(SessionAction::BeginRenewal));
        }
        self.state = SessionState::RenewalPending;
        Ok(())
    }

    /// Ends a nonterminal session and records cleanup as required.
    ///
    /// Dropping the returned request does not change the cleanup obligation;
    /// [`Self::cleanup_request`] reissues it for crash-safe, idempotent retry.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::InvalidTransition`] when the session is
    /// already ended or invalidated, regardless of cleanup status.
    pub fn end(&mut self) -> Result<CleanupRequest, TransitionError> {
        if self.state.is_terminal() {
            return Err(self.invalid_transition(SessionAction::End));
        }
        self.state = SessionState::Ended(TerminalCleanup::Required);
        Ok(CleanupRequest {
            binding: SessionBinding(self.session_id.clone()),
        })
    }

    /// Invalidates a nonterminal session and records cleanup as required.
    ///
    /// Dropping the returned request does not change the cleanup obligation;
    /// [`Self::cleanup_request`] reissues it for crash-safe, idempotent retry.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::InvalidTransition`] when the session is
    /// already ended or invalidated, regardless of cleanup status.
    pub fn invalidate(&mut self) -> Result<CleanupRequest, TransitionError> {
        if self.state.is_terminal() {
            return Err(self.invalid_transition(SessionAction::Invalidate));
        }
        self.state = SessionState::Invalidated(TerminalCleanup::Required);
        Ok(CleanupRequest {
            binding: SessionBinding(self.session_id.clone()),
        })
    }

    /// Reissues a cleanup request while terminal cleanup remains required.
    ///
    /// The eventual trusted adapter must make cleanup idempotent so retries
    /// after a dropped response or crash are safe. Request issuance never
    /// changes lifecycle phase or cleanup status.
    pub fn cleanup_request(&self) -> Option<CleanupRequest> {
        match self.state {
            SessionState::Ended(TerminalCleanup::Required)
            | SessionState::Invalidated(TerminalCleanup::Required) => Some(CleanupRequest {
                binding: SessionBinding(self.session_id.clone()),
            }),
            SessionState::New
            | SessionState::ChallengeValidated
            | SessionState::CallerBound
            | SessionState::SessionPrepared
            | SessionState::EvidenceCreated
            | SessionState::PermitReceived
            | SessionState::Active
            | SessionState::RenewalPending
            | SessionState::Ended(TerminalCleanup::Complete)
            | SessionState::Invalidated(TerminalCleanup::Complete) => None,
        }
    }

    /// Records trusted cleanup completion without changing terminal disposition.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::InvalidTransition`] unless cleanup is
    /// required for an ended or invalidated session, or
    /// [`TransitionError::CapabilityRejected`] when the capability is bound to
    /// another session. A rejected capability leaves cleanup required.
    pub fn record_cleanup_completed(
        &mut self,
        capability: CleanupCompleted,
    ) -> Result<(), TransitionError> {
        let next_state = match self.state {
            SessionState::Ended(TerminalCleanup::Required) => {
                SessionState::Ended(TerminalCleanup::Complete)
            }
            SessionState::Invalidated(TerminalCleanup::Required) => {
                SessionState::Invalidated(TerminalCleanup::Complete)
            }
            SessionState::New
            | SessionState::ChallengeValidated
            | SessionState::CallerBound
            | SessionState::SessionPrepared
            | SessionState::EvidenceCreated
            | SessionState::PermitReceived
            | SessionState::Active
            | SessionState::RenewalPending
            | SessionState::Ended(TerminalCleanup::Complete)
            | SessionState::Invalidated(TerminalCleanup::Complete) => {
                return Err(self.invalid_transition(SessionAction::RecordCleanupCompleted));
            }
        };
        self.ensure_binding(SessionAction::RecordCleanupCompleted, &capability.binding)?;
        self.state = next_state;
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
