// SPDX-License-Identifier: Apache-2.0

use super::*;

fn session_id(value: &str) -> SessionId {
    match SessionId::try_from(value) {
        Ok(value) => value,
        Err(error) => panic!("valid test session identifier rejected: {error:?}"),
    }
}

fn binding(value: &str) -> SessionBinding {
    SessionBinding(session_id(value))
}

fn session(value: &str) -> LocalSession {
    LocalSession {
        session_id: session_id(value),
        state: SessionState::New,
    }
}

#[test]
fn new_session_starts_without_cleanup() {
    let session = session("session-a");
    assert_eq!(session.phase(), SessionPhase::New);
    assert_eq!(session.cleanup_status(), CleanupStatus::NotRequired);
}

#[test]
fn initial_path_requires_every_gate_in_order() {
    let mut session = session("session-a");

    assert_eq!(
        session.record_challenge_validated(ValidatedChallenge {
            binding: binding("session-a"),
        }),
        Ok(())
    );
    assert_eq!(session.phase(), SessionPhase::ChallengeValidated);
    assert_eq!(
        session.record_caller_bound(BoundCaller {
            binding: binding("session-a"),
        }),
        Ok(())
    );
    assert_eq!(session.phase(), SessionPhase::CallerBound);
    assert_eq!(
        session.record_session_prepared(PreparedSession {
            binding: binding("session-a"),
        }),
        Ok(())
    );
    assert_eq!(session.phase(), SessionPhase::SessionPrepared);
    assert_eq!(
        session.record_evidence_created(CreatedEvidence {
            binding: binding("session-a"),
        }),
        Ok(())
    );
    assert_eq!(session.phase(), SessionPhase::EvidenceCreated);
    assert_eq!(
        session.record_permit_received(ValidatedPermit {
            binding: binding("session-a"),
        }),
        Ok(())
    );
    assert_eq!(session.phase(), SessionPhase::PermitReceived);
    assert_eq!(session.activate(), Ok(()));
    assert_eq!(session.phase(), SessionPhase::Active);
}

#[test]
fn skipped_gate_returns_exact_error_without_mutation() {
    let mut session = session("session-a");
    let error = session.activate();
    assert_eq!(
        error,
        Err(TransitionError::InvalidTransition {
            phase: SessionPhase::New,
            cleanup_status: CleanupStatus::NotRequired,
            action: SessionAction::Activate,
        })
    );
    assert_eq!(session.phase(), SessionPhase::New);
}

#[test]
fn cross_session_capability_is_rejected_without_mutation() {
    let mut session = session("session-a");
    let error = session.record_challenge_validated(ValidatedChallenge {
        binding: binding("session-b"),
    });
    assert_eq!(
        error,
        Err(TransitionError::CapabilityRejected {
            action: SessionAction::RecordChallengeValidated,
        })
    );
    assert_eq!(session.phase(), SessionPhase::New);
}
