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

fn require_type<T>() {}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModelState {
    New,
    ChallengeValidated,
    CallerBound,
    SessionPrepared,
    EvidenceCreated,
    PermitReceived,
    Active,
    RenewalPending,
    EndedRequired,
    EndedComplete,
    InvalidatedRequired,
    InvalidatedComplete,
}

impl ModelState {
    fn phase(self) -> SessionPhase {
        match self {
            Self::New => SessionPhase::New,
            Self::ChallengeValidated => SessionPhase::ChallengeValidated,
            Self::CallerBound => SessionPhase::CallerBound,
            Self::SessionPrepared => SessionPhase::SessionPrepared,
            Self::EvidenceCreated => SessionPhase::EvidenceCreated,
            Self::PermitReceived => SessionPhase::PermitReceived,
            Self::Active => SessionPhase::Active,
            Self::RenewalPending => SessionPhase::RenewalPending,
            Self::EndedRequired | Self::EndedComplete => SessionPhase::Ended,
            Self::InvalidatedRequired | Self::InvalidatedComplete => SessionPhase::Invalidated,
        }
    }

    fn cleanup_status(self) -> CleanupStatus {
        match self {
            Self::New
            | Self::ChallengeValidated
            | Self::CallerBound
            | Self::SessionPrepared
            | Self::EvidenceCreated
            | Self::PermitReceived
            | Self::Active
            | Self::RenewalPending => CleanupStatus::NotRequired,
            Self::EndedRequired | Self::InvalidatedRequired => CleanupStatus::Required,
            Self::EndedComplete | Self::InvalidatedComplete => CleanupStatus::Complete,
        }
    }

    fn is_nonterminal(self) -> bool {
        match self {
            Self::New
            | Self::ChallengeValidated
            | Self::CallerBound
            | Self::SessionPrepared
            | Self::EvidenceCreated
            | Self::PermitReceived
            | Self::Active
            | Self::RenewalPending => true,
            Self::EndedRequired
            | Self::EndedComplete
            | Self::InvalidatedRequired
            | Self::InvalidatedComplete => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestAction {
    Challenge,
    Caller,
    Preparation,
    Evidence,
    Permit,
    Activate,
    Renewal,
    End,
    Invalidate,
    CleanupComplete,
}

impl TestAction {
    fn public(self) -> SessionAction {
        match self {
            Self::Challenge => SessionAction::RecordChallengeValidated,
            Self::Caller => SessionAction::RecordCallerBound,
            Self::Preparation => SessionAction::RecordSessionPrepared,
            Self::Evidence => SessionAction::RecordEvidenceCreated,
            Self::Permit => SessionAction::RecordPermitReceived,
            Self::Activate => SessionAction::Activate,
            Self::Renewal => SessionAction::BeginRenewal,
            Self::End => SessionAction::End,
            Self::Invalidate => SessionAction::Invalidate,
            Self::CleanupComplete => SessionAction::RecordCleanupCompleted,
        }
    }

    fn uses_capability(self) -> bool {
        match self {
            Self::Challenge
            | Self::Caller
            | Self::Preparation
            | Self::Evidence
            | Self::Permit
            | Self::CleanupComplete => true,
            Self::Activate | Self::Renewal | Self::End | Self::Invalidate => false,
        }
    }
}

const MODEL_STATES: [ModelState; 12] = [
    ModelState::New,
    ModelState::ChallengeValidated,
    ModelState::CallerBound,
    ModelState::SessionPrepared,
    ModelState::EvidenceCreated,
    ModelState::PermitReceived,
    ModelState::Active,
    ModelState::RenewalPending,
    ModelState::EndedRequired,
    ModelState::EndedComplete,
    ModelState::InvalidatedRequired,
    ModelState::InvalidatedComplete,
];

const TEST_ACTIONS: [TestAction; 10] = [
    TestAction::Challenge,
    TestAction::Caller,
    TestAction::Preparation,
    TestAction::Evidence,
    TestAction::Permit,
    TestAction::Activate,
    TestAction::Renewal,
    TestAction::End,
    TestAction::Invalidate,
    TestAction::CleanupComplete,
];

const DEEP_PATH_ACTIONS: [TestAction; 10] = [
    TestAction::Challenge,
    TestAction::Caller,
    TestAction::Preparation,
    TestAction::Evidence,
    TestAction::Permit,
    TestAction::Activate,
    TestAction::Renewal,
    TestAction::Activate,
    TestAction::Permit,
    TestAction::Activate,
];

fn deep_path_action(seed: u64, action_index: usize) -> Option<TestAction> {
    if seed.is_multiple_of(512) {
        DEEP_PATH_ACTIONS.get(action_index).copied()
    } else {
        None
    }
}

struct GateHistory {
    initial_mask: u8,
    renewal_pending: bool,
    renewal_permit: bool,
}

#[derive(Debug, Default)]
struct DeepHistoryCoverage {
    initial_permits: usize,
    initial_activations: usize,
    renewal_entries: usize,
    renewal_permits: usize,
    renewed_activations: usize,
}

const CHALLENGE_GATE: u8 = 1 << 0;
const CALLER_GATE: u8 = 1 << 1;
const PREPARATION_GATE: u8 = 1 << 2;
const EVIDENCE_GATE: u8 = 1 << 3;
const PERMIT_GATE: u8 = 1 << 4;
const ALL_INITIAL_GATES: u8 =
    CHALLENGE_GATE | CALLER_GATE | PREPARATION_GATE | EVIDENCE_GATE | PERMIT_GATE;

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn model_transition(state: ModelState, action: TestAction) -> Option<ModelState> {
    match (state, action) {
        (ModelState::New, TestAction::Challenge) => Some(ModelState::ChallengeValidated),
        (ModelState::ChallengeValidated, TestAction::Caller) => Some(ModelState::CallerBound),
        (ModelState::CallerBound, TestAction::Preparation) => Some(ModelState::SessionPrepared),
        (ModelState::SessionPrepared, TestAction::Evidence) => Some(ModelState::EvidenceCreated),
        (ModelState::EvidenceCreated | ModelState::RenewalPending, TestAction::Permit) => {
            Some(ModelState::PermitReceived)
        }
        (ModelState::PermitReceived, TestAction::Activate) => Some(ModelState::Active),
        (ModelState::Active, TestAction::Renewal) => Some(ModelState::RenewalPending),
        (state, TestAction::End) if state.is_nonterminal() => Some(ModelState::EndedRequired),
        (state, TestAction::Invalidate) if state.is_nonterminal() => {
            Some(ModelState::InvalidatedRequired)
        }
        (ModelState::EndedRequired, TestAction::CleanupComplete) => Some(ModelState::EndedComplete),
        (ModelState::InvalidatedRequired, TestAction::CleanupComplete) => {
            Some(ModelState::InvalidatedComplete)
        }
        (
            ModelState::New
            | ModelState::ChallengeValidated
            | ModelState::CallerBound
            | ModelState::SessionPrepared
            | ModelState::EvidenceCreated
            | ModelState::PermitReceived
            | ModelState::Active
            | ModelState::RenewalPending
            | ModelState::EndedRequired
            | ModelState::EndedComplete
            | ModelState::InvalidatedRequired
            | ModelState::InvalidatedComplete,
            TestAction::Challenge
            | TestAction::Caller
            | TestAction::Preparation
            | TestAction::Evidence
            | TestAction::Permit
            | TestAction::Activate
            | TestAction::Renewal
            | TestAction::End
            | TestAction::Invalidate
            | TestAction::CleanupComplete,
        ) => None,
    }
}

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

fn session_for_model_state(value: &str, state: ModelState) -> LocalSession {
    match state {
        ModelState::New => session(value),
        ModelState::ChallengeValidated => challenge_validated_session(value),
        ModelState::CallerBound => caller_bound_session(value),
        ModelState::SessionPrepared => prepared_session(value),
        ModelState::EvidenceCreated => evidence_created_session(value),
        ModelState::PermitReceived => permit_received_session(value),
        ModelState::Active => active_session(value),
        ModelState::RenewalPending => {
            let mut session = active_session(value);
            assert_eq!(session.begin_renewal(), Ok(()));
            session
        }
        ModelState::EndedRequired => terminal_session(value, SessionPhase::Ended, false),
        ModelState::EndedComplete => terminal_session(value, SessionPhase::Ended, true),
        ModelState::InvalidatedRequired => {
            terminal_session(value, SessionPhase::Invalidated, false)
        }
        ModelState::InvalidatedComplete => terminal_session(value, SessionPhase::Invalidated, true),
    }
}

fn apply_action(
    session: &mut LocalSession,
    action: TestAction,
    capability_session: &str,
) -> Result<(), TransitionError> {
    match action {
        TestAction::Challenge => session.record_challenge_validated(ValidatedChallenge {
            binding: binding(capability_session),
        }),
        TestAction::Caller => session.record_caller_bound(BoundCaller {
            binding: binding(capability_session),
        }),
        TestAction::Preparation => session.record_session_prepared(PreparedSession {
            binding: binding(capability_session),
        }),
        TestAction::Evidence => session.record_evidence_created(CreatedEvidence {
            binding: binding(capability_session),
        }),
        TestAction::Permit => session.record_permit_received(ValidatedPermit {
            binding: binding(capability_session),
        }),
        TestAction::Activate => session.activate(),
        TestAction::Renewal => session.begin_renewal(),
        TestAction::End => session.end().map(|_request| ()),
        TestAction::Invalidate => session.invalidate().map(|_request| ()),
        TestAction::CleanupComplete => session.record_cleanup_completed(CleanupCompleted {
            binding: binding(capability_session),
        }),
    }
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
fn all_120_state_action_pairs_match_the_independent_model() {
    let mut allowed = 0usize;
    let mut rejected = 0usize;

    for state in MODEL_STATES {
        for action in TEST_ACTIONS {
            let mut session = session_for_model_state("session-a", state);
            let before_phase = session.phase();
            let before_cleanup = session.cleanup_status();
            let expected_phase = state.phase();
            let expected_cleanup = state.cleanup_status();
            assert_eq!(before_phase, expected_phase, "fixture state={state:?}");
            assert_eq!(before_cleanup, expected_cleanup, "fixture state={state:?}");
            let expected = model_transition(state, action);
            let actual = apply_action(&mut session, action, "session-a");

            match expected {
                Some(next) => {
                    allowed += 1;
                    assert_eq!(actual, Ok(()), "state={state:?} action={action:?}");
                    assert_eq!(session.phase(), next.phase());
                    assert_eq!(session.cleanup_status(), next.cleanup_status());
                }
                None => {
                    rejected += 1;
                    assert_eq!(
                        actual,
                        Err(TransitionError::InvalidTransition {
                            phase: expected_phase,
                            cleanup_status: expected_cleanup,
                            action: action.public(),
                        }),
                        "state={state:?} action={action:?}"
                    );
                    assert_eq!(session.phase(), before_phase);
                    assert_eq!(session.cleanup_status(), before_cleanup);
                }
            }
        }
    }

    assert_eq!(allowed, 26);
    assert_eq!(rejected, 94);
}

#[test]
fn cleanup_request_exists_for_exactly_the_two_required_terminal_states() {
    let mut count = 0usize;
    for state in MODEL_STATES {
        let actual = session_for_model_state("session-a", state)
            .cleanup_request()
            .is_some();
        let expected = matches!(
            state,
            ModelState::EndedRequired | ModelState::InvalidatedRequired
        );
        assert_eq!(actual, expected, "state={state:?}");
        if actual {
            count += 1;
        }
    }
    assert_eq!(count, 2);
}

#[test]
fn one_million_deterministic_actions_preserve_session_invariants() {
    let mut operations = 0usize;
    let mut scheduled_operations = 0usize;
    let mut coverage = DeepHistoryCoverage::default();

    for seed in 1..=4_096u64 {
        let mut random = seed;
        let mut session = session("session-a");
        let mut model = ModelState::New;
        let mut history = GateHistory {
            initial_mask: 0,
            renewal_pending: false,
            renewal_permit: false,
        };

        for action_index in 0..256usize {
            let (action, mismatched_capability) = match deep_path_action(seed, action_index) {
                Some(action) => {
                    scheduled_operations += 1;
                    (action, false)
                }
                None => {
                    let action = TEST_ACTIONS[(next_random(&mut random) % 10) as usize];
                    let mismatched = action.uses_capability() && next_random(&mut random) & 1 == 1;
                    (action, mismatched)
                }
            };
            let capability_session = if mismatched_capability {
                "session-b"
            } else {
                "session-a"
            };
            let prior_model = model;
            let expected = model_transition(model, action);
            let actual = apply_action(&mut session, action, capability_session);

            match expected {
                None => assert_eq!(
                    actual,
                    Err(TransitionError::InvalidTransition {
                        phase: model.phase(),
                        cleanup_status: model.cleanup_status(),
                        action: action.public(),
                    }),
                    "seed={seed} action_index={action_index} state={model:?} action={action:?}"
                ),
                Some(_next) if mismatched_capability => assert_eq!(
                    actual,
                    Err(TransitionError::CapabilityRejected {
                        action: action.public(),
                    }),
                    "seed={seed} action_index={action_index} state={model:?} action={action:?}"
                ),
                Some(next) => {
                    assert_eq!(
                        actual,
                        Ok(()),
                        "seed={seed} action_index={action_index} state={model:?} action={action:?}"
                    );

                    match action {
                        TestAction::Challenge => history.initial_mask |= CHALLENGE_GATE,
                        TestAction::Caller => history.initial_mask |= CALLER_GATE,
                        TestAction::Preparation => history.initial_mask |= PREPARATION_GATE,
                        TestAction::Evidence => history.initial_mask |= EVIDENCE_GATE,
                        TestAction::Permit => match prior_model {
                            ModelState::EvidenceCreated => {
                                history.initial_mask |= PERMIT_GATE;
                                coverage.initial_permits += 1;
                            }
                            ModelState::RenewalPending => {
                                history.renewal_permit = true;
                                coverage.renewal_permits += 1;
                            }
                            ModelState::New
                            | ModelState::ChallengeValidated
                            | ModelState::CallerBound
                            | ModelState::SessionPrepared
                            | ModelState::PermitReceived
                            | ModelState::Active
                            | ModelState::EndedRequired
                            | ModelState::EndedComplete
                            | ModelState::InvalidatedRequired
                            | ModelState::InvalidatedComplete => {
                                panic!(
                                    "seed={seed} action_index={action_index} state={prior_model:?} action={action:?}"
                                )
                            }
                        },
                        TestAction::Activate => {
                            assert_eq!(
                                history.initial_mask, ALL_INITIAL_GATES,
                                "seed={seed} action_index={action_index} state={prior_model:?} action={action:?}"
                            );
                            if history.renewal_pending {
                                assert!(
                                    history.renewal_permit,
                                    "seed={seed} action_index={action_index} state={prior_model:?} action={action:?}"
                                );
                                coverage.renewed_activations += 1;
                            } else {
                                coverage.initial_activations += 1;
                            }
                            history.renewal_pending = false;
                        }
                        TestAction::Renewal => {
                            history.renewal_pending = true;
                            history.renewal_permit = false;
                            coverage.renewal_entries += 1;
                        }
                        TestAction::End | TestAction::Invalidate | TestAction::CleanupComplete => {}
                    }

                    model = next;
                }
            }

            assert_eq!(
                session.phase(),
                model.phase(),
                "seed={seed} action_index={action_index} state={model:?} action={action:?}"
            );
            assert_eq!(
                session.cleanup_status(),
                model.cleanup_status(),
                "seed={seed} action_index={action_index} state={model:?} action={action:?}"
            );
            operations += 1;
        }
    }

    assert_eq!(operations, 1_048_576);
    assert_eq!(scheduled_operations, 80);
    assert_eq!(operations - scheduled_operations, 1_048_496);
    println!(
        "history operations: total={operations} scheduled={scheduled_operations} random={} coverage={coverage:?}",
        operations - scheduled_operations
    );
    assert!(coverage.initial_permits > 0, "no initial permit executed");
    assert!(
        coverage.initial_activations > 0,
        "no initial activation executed"
    );
    assert!(coverage.renewal_entries > 0, "no renewal entry executed");
    assert!(coverage.renewal_permits > 0, "no renewal permit executed");
    assert!(
        coverage.renewed_activations > 0,
        "no renewed activation executed"
    );
}

#[test]
fn every_capability_rejects_a_different_session_without_mutation() {
    let cases = [
        (ModelState::New, TestAction::Challenge),
        (ModelState::ChallengeValidated, TestAction::Caller),
        (ModelState::CallerBound, TestAction::Preparation),
        (ModelState::SessionPrepared, TestAction::Evidence),
        (ModelState::EvidenceCreated, TestAction::Permit),
        (ModelState::RenewalPending, TestAction::Permit),
        (ModelState::EndedRequired, TestAction::CleanupComplete),
        (ModelState::InvalidatedRequired, TestAction::CleanupComplete),
    ];

    assert_eq!(cases.len(), 8);
    for (state, action) in cases {
        assert!(model_transition(state, action).is_some());
        assert!(action.uses_capability());
        let mut session = session_for_model_state("session-a", state);
        let before_phase = session.phase();
        let before_cleanup = session.cleanup_status();

        let actual = apply_action(&mut session, action, "session-b");

        assert_eq!(
            actual,
            Err(TransitionError::CapabilityRejected {
                action: action.public(),
            }),
            "state={state:?} action={action:?}"
        );
        assert_eq!(session.phase(), before_phase);
        assert_eq!(session.cleanup_status(), before_cleanup);
    }
}

#[test]
fn every_session_diagnostic_is_context_free_and_redacted() {
    let session = session("private-session-a");
    let values = [
        format!("{session:?}"),
        format!(
            "{:?}",
            ValidatedChallenge {
                binding: binding("private-session-a"),
            }
        ),
        format!(
            "{:?}",
            BoundCaller {
                binding: binding("private-session-a"),
            }
        ),
        format!(
            "{:?}",
            PreparedSession {
                binding: binding("private-session-a"),
            }
        ),
        format!(
            "{:?}",
            CreatedEvidence {
                binding: binding("private-session-a"),
            }
        ),
        format!(
            "{:?}",
            ValidatedPermit {
                binding: binding("private-session-a"),
            }
        ),
        format!(
            "{:?}",
            CleanupRequest {
                binding: binding("private-session-a"),
            }
        ),
        format!(
            "{:?}",
            CleanupCompleted {
                binding: binding("private-session-b"),
            }
        ),
        format!(
            "{:?}",
            TransitionError::InvalidTransition {
                phase: SessionPhase::New,
                cleanup_status: CleanupStatus::NotRequired,
                action: SessionAction::Activate,
            }
        ),
        format!(
            "{:?}",
            TransitionError::CapabilityRejected {
                action: SessionAction::RecordPermitReceived,
            }
        ),
        TransitionError::InvalidTransition {
            phase: SessionPhase::New,
            cleanup_status: CleanupStatus::NotRequired,
            action: SessionAction::Activate,
        }
        .to_string(),
        TransitionError::CapabilityRejected {
            action: SessionAction::RecordPermitReceived,
        }
        .to_string(),
    ];

    let expected = [
        "LocalSession { phase: New, cleanup_status: NotRequired }",
        "ValidatedChallenge([REDACTED])",
        "BoundCaller([REDACTED])",
        "PreparedSession([REDACTED])",
        "CreatedEvidence([REDACTED])",
        "ValidatedPermit([REDACTED])",
        "CleanupRequest([REDACTED])",
        "CleanupCompleted([REDACTED])",
        "InvalidTransition { phase: New, cleanup_status: NotRequired, action: Activate }",
        "CapabilityRejected { action: RecordPermitReceived }",
        "local session transition is not allowed",
        "local session capability rejected",
    ];
    assert_eq!(values, expected);

    for value in values {
        for forbidden in [
            "private-session-a",
            "private-session-b",
            "\n",
            "\r",
            "\u{1b}",
            "/home/",
            "::error",
            "::warning",
        ] {
            assert!(
                !value.contains(forbidden),
                "forbidden diagnostic value: {forbidden:?}"
            );
        }
    }
}

#[test]
fn every_authority_bearing_public_type_exists() {
    require_type::<LocalSession>();
    require_type::<ValidatedChallenge>();
    require_type::<BoundCaller>();
    require_type::<PreparedSession>();
    require_type::<CreatedEvidence>();
    require_type::<ValidatedPermit>();
    require_type::<CleanupRequest>();
    require_type::<CleanupCompleted>();
}

#[test]
fn every_authority_field_is_structurally_private() {
    let source = include_str!("../session.rs");

    for type_name in [
        "ValidatedChallenge",
        "BoundCaller",
        "PreparedSession",
        "CreatedEvidence",
        "ValidatedPermit",
        "CleanupRequest",
        "CleanupCompleted",
    ] {
        let expected = format!("pub struct {type_name} {{\n    binding: SessionBinding,\n}}");
        assert!(
            source.contains(&expected),
            "authority field visibility changed for {type_name}"
        );
    }

    assert!(
        source.contains(
            "pub struct LocalSession {\n    session_id: SessionId,\n    state: SessionState,\n}"
        ),
        "local session authority or state field visibility changed"
    );
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
    for (end_normally, expected_phase) in [
        (true, SessionPhase::Ended),
        (false, SessionPhase::Invalidated),
    ] {
        let mut session = active_session("session-a");
        let terminal_entry = if end_normally {
            session.end()
        } else {
            session.invalidate()
        };
        assert!(terminal_entry.is_ok());
        assert!(session.cleanup_request().is_some());
        assert_eq!(
            session.record_cleanup_completed(CleanupCompleted {
                binding: binding("session-a"),
            }),
            Ok(())
        );
        assert_eq!(session.phase(), expected_phase);
        assert_eq!(session.cleanup_status(), CleanupStatus::Complete);
        assert!(session.cleanup_request().is_none());
    }
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
