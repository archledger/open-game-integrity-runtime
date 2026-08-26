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

const NONTERMINAL_PHASES: [SessionPhase; 8] = [
    SessionPhase::New,
    SessionPhase::ChallengeValidated,
    SessionPhase::CallerBound,
    SessionPhase::SessionPrepared,
    SessionPhase::EvidenceCreated,
    SessionPhase::PermitReceived,
    SessionPhase::Active,
    SessionPhase::RenewalPending,
];

fn challenge_validated_session(value: &str) -> LocalSession {
    let mut session = session(value);
    assert_eq!(
        session.record_challenge_validated(ValidatedChallenge {
            binding: binding(value),
        }),
        Ok(())
    );
    session
}

fn caller_bound_session(value: &str) -> LocalSession {
    let mut session = challenge_validated_session(value);
    assert_eq!(
        session.record_caller_bound(BoundCaller {
            binding: binding(value),
        }),
        Ok(())
    );
    session
}

fn prepared_session(value: &str) -> LocalSession {
    let mut session = caller_bound_session(value);
    assert_eq!(
        session.record_session_prepared(PreparedSession {
            binding: binding(value),
        }),
        Ok(())
    );
    session
}

fn evidence_created_session(value: &str) -> LocalSession {
    let mut session = prepared_session(value);
    assert_eq!(
        session.record_evidence_created(CreatedEvidence {
            binding: binding(value),
        }),
        Ok(())
    );
    session
}

fn permit_received_session(value: &str) -> LocalSession {
    let mut session = evidence_created_session(value);
    assert_eq!(
        session.record_permit_received(ValidatedPermit {
            binding: binding(value),
        }),
        Ok(())
    );
    session
}

fn active_session(value: &str) -> LocalSession {
    let mut session = permit_received_session(value);
    assert_eq!(session.activate(), Ok(()));
    session
}

fn session_at(value: &str, phase: SessionPhase) -> LocalSession {
    match phase {
        SessionPhase::New => session(value),
        SessionPhase::ChallengeValidated => challenge_validated_session(value),
        SessionPhase::CallerBound => caller_bound_session(value),
        SessionPhase::SessionPrepared => prepared_session(value),
        SessionPhase::EvidenceCreated => evidence_created_session(value),
        SessionPhase::PermitReceived => permit_received_session(value),
        SessionPhase::Active => active_session(value),
        SessionPhase::RenewalPending => {
            let mut session = active_session(value);
            assert_eq!(session.begin_renewal(), Ok(()));
            session
        }
        SessionPhase::Ended => panic!("terminal phase cannot initialize a nonterminal fixture"),
        SessionPhase::Invalidated => {
            panic!("terminal phase cannot initialize a nonterminal fixture")
        }
    }
}

fn terminal_session(value: &str, phase: SessionPhase, cleanup_complete: bool) -> LocalSession {
    let mut session = active_session(value);
    match phase {
        SessionPhase::Ended => assert!(session.end().is_ok()),
        SessionPhase::Invalidated => assert!(session.invalidate().is_ok()),
        SessionPhase::New
        | SessionPhase::ChallengeValidated
        | SessionPhase::CallerBound
        | SessionPhase::SessionPrepared
        | SessionPhase::EvidenceCreated
        | SessionPhase::PermitReceived
        | SessionPhase::Active
        | SessionPhase::RenewalPending => {
            panic!("nonterminal phase cannot initialize a terminal fixture")
        }
    }
    if cleanup_complete {
        assert_eq!(
            session.record_cleanup_completed(CleanupCompleted {
                binding: binding(value),
            }),
            Ok(())
        );
    }
    session
}

fn assert_all_lifecycle_actions_rejected(session: &mut LocalSession) {
    let phase = session.phase();
    let cleanup_status = session.cleanup_status();

    assert_eq!(
        session.record_challenge_validated(ValidatedChallenge {
            binding: binding("session-a"),
        }),
        Err(TransitionError::InvalidTransition {
            phase,
            cleanup_status,
            action: SessionAction::RecordChallengeValidated,
        })
    );
    assert_eq!(
        session.record_caller_bound(BoundCaller {
            binding: binding("session-a"),
        }),
        Err(TransitionError::InvalidTransition {
            phase,
            cleanup_status,
            action: SessionAction::RecordCallerBound,
        })
    );
    assert_eq!(
        session.record_session_prepared(PreparedSession {
            binding: binding("session-a"),
        }),
        Err(TransitionError::InvalidTransition {
            phase,
            cleanup_status,
            action: SessionAction::RecordSessionPrepared,
        })
    );
    assert_eq!(
        session.record_evidence_created(CreatedEvidence {
            binding: binding("session-a"),
        }),
        Err(TransitionError::InvalidTransition {
            phase,
            cleanup_status,
            action: SessionAction::RecordEvidenceCreated,
        })
    );
    assert_eq!(
        session.record_permit_received(ValidatedPermit {
            binding: binding("session-a"),
        }),
        Err(TransitionError::InvalidTransition {
            phase,
            cleanup_status,
            action: SessionAction::RecordPermitReceived,
        })
    );
    assert_eq!(
        session.activate(),
        Err(TransitionError::InvalidTransition {
            phase,
            cleanup_status,
            action: SessionAction::Activate,
        })
    );
    assert_eq!(
        session.begin_renewal(),
        Err(TransitionError::InvalidTransition {
            phase,
            cleanup_status,
            action: SessionAction::BeginRenewal,
        })
    );
    assert_eq!(
        session.end().map(|_request| ()),
        Err(TransitionError::InvalidTransition {
            phase,
            cleanup_status,
            action: SessionAction::End,
        })
    );
    assert_eq!(
        session.invalidate().map(|_request| ()),
        Err(TransitionError::InvalidTransition {
            phase,
            cleanup_status,
            action: SessionAction::Invalidate,
        })
    );
    assert_eq!(session.phase(), phase);
    assert_eq!(session.cleanup_status(), cleanup_status);
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

#[test]
fn renewal_requires_a_fresh_matching_permit_before_reactivation() {
    let mut session = active_session("session-a");
    assert_eq!(session.begin_renewal(), Ok(()));
    assert_eq!(session.phase(), SessionPhase::RenewalPending);
    assert_eq!(
        session.activate(),
        Err(TransitionError::InvalidTransition {
            phase: SessionPhase::RenewalPending,
            cleanup_status: CleanupStatus::NotRequired,
            action: SessionAction::Activate,
        })
    );
    assert_eq!(
        session.record_permit_received(ValidatedPermit {
            binding: binding("session-a"),
        }),
        Ok(())
    );
    assert_eq!(session.activate(), Ok(()));
    assert_eq!(session.phase(), SessionPhase::Active);
}

#[test]
fn every_nonterminal_phase_can_end_with_cleanup_required() {
    for phase in NONTERMINAL_PHASES {
        let mut session = session_at("session-a", phase);
        let request = session.end();
        assert!(request.is_ok(), "end failed from {phase:?}: {request:?}");
        assert_eq!(session.phase(), SessionPhase::Ended);
        assert_eq!(session.cleanup_status(), CleanupStatus::Required);
    }
}

#[test]
fn every_nonterminal_phase_can_invalidate_with_cleanup_required() {
    for phase in NONTERMINAL_PHASES {
        let mut session = session_at("session-a", phase);
        let request = session.invalidate();
        assert!(
            request.is_ok(),
            "invalidation failed from {phase:?}: {request:?}"
        );
        assert_eq!(session.phase(), SessionPhase::Invalidated);
        assert_eq!(session.cleanup_status(), CleanupStatus::Required);
    }
}

#[test]
fn matching_cleanup_completion_preserves_terminal_disposition() {
    let mut session = active_session("session-a");
    assert!(session.invalidate().is_ok());
    assert!(session.cleanup_request().is_some());
    assert_eq!(
        session.record_cleanup_completed(CleanupCompleted {
            binding: binding("session-a"),
        }),
        Ok(())
    );
    assert_eq!(session.phase(), SessionPhase::Invalidated);
    assert_eq!(session.cleanup_status(), CleanupStatus::Complete);
    assert!(session.cleanup_request().is_none());
}

#[test]
fn terminal_sessions_reject_every_lifecycle_action() {
    for phase in [SessionPhase::Ended, SessionPhase::Invalidated] {
        for cleanup_complete in [false, true] {
            let mut session = terminal_session("session-a", phase, cleanup_complete);
            assert_all_lifecycle_actions_rejected(&mut session);
            assert_eq!(session.phase(), phase);
        }
    }
}
