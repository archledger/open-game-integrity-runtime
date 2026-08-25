// SPDX-License-Identifier: Apache-2.0

mod support;

use std::fmt::Debug;
use std::num::{NonZeroU64, NonZeroUsize};

use ogir_model::{
    AccountScope, BuildId, ChallengeLifetime, ChallengeWindow, Decision, EvidenceProfile,
    FreshnessError, FreshnessLimits, GameId, IdentifierError, MatchId, Nonce, PolicyId,
    PolicyVersion, ProtocolVersion, PublisherChallenge, PublisherId, ReasonCode, UnixTime,
};
use ogir_protocol::EvidenceBundle;
use ogir_verifier::{
    ExpectedContext, FreshnessGuard, VerificationRequest, verify_research_structure,
};
use support::ReferenceReplayStore;

fn identifier<T>(value: &str) -> T
where
    T: Debug,
    for<'a> T: TryFrom<&'a str, Error = IdentifierError>,
{
    match T::try_from(value) {
        Ok(value) => value,
        Err(error) => panic!("valid fixture rejected: {error:?}"),
    }
}

fn nonzero_u64(value: u64) -> NonZeroU64 {
    match NonZeroU64::new(value) {
        Some(value) => value,
        None => panic!("fixture must be nonzero"),
    }
}

fn nonzero_usize(value: usize) -> NonZeroUsize {
    match NonZeroUsize::new(value) {
        Some(value) => value,
        None => panic!("fixture must be nonzero"),
    }
}

fn limits() -> FreshnessLimits {
    FreshnessLimits::new(
        ChallengeLifetime::new(nonzero_u64(100)),
        nonzero_usize(16),
        nonzero_usize(8),
        nonzero_usize(2),
        nonzero_u64(60),
        nonzero_usize(8),
    )
}

fn valid_window(issued_at: u64, expires_at: u64) -> ChallengeWindow {
    match ChallengeWindow::new(
        UnixTime::new(issued_at),
        UnixTime::new(expires_at),
        ChallengeLifetime::new(nonzero_u64(100)),
    ) {
        Ok(window) => window,
        Err(error) => panic!("valid window rejected: {error:?}"),
    }
}

fn challenge_for_publisher(publisher: &str, nonce: [u8; 32]) -> PublisherChallenge {
    PublisherChallenge {
        version: ProtocolVersion { major: 0, minor: 1 },
        publisher_id: identifier::<PublisherId>(publisher),
        game_id: identifier::<GameId>("example.game"),
        build_id: identifier::<BuildId>("build-1"),
        account_scope: identifier::<AccountScope>("account-1"),
        match_id: identifier::<MatchId>("match-1"),
        policy_id: identifier::<PolicyId>("research-v0"),
        policy_version: PolicyVersion::new(1),
        nonce: Nonce::from_bytes(nonce),
        window: valid_window(100, 200),
    }
}

fn challenge(game: &str, nonce: [u8; 32]) -> PublisherChallenge {
    let mut challenge = challenge_for_publisher("example.publisher", nonce);
    challenge.game_id = identifier::<GameId>(game);
    challenge
}

fn expected() -> ExpectedContext {
    ExpectedContext {
        publisher_id: identifier::<PublisherId>("example.publisher"),
        game_id: identifier::<GameId>("example.game"),
        build_id: identifier::<BuildId>("build-1"),
        account_scope: identifier::<AccountScope>("account-1"),
        match_id: identifier::<MatchId>("match-1"),
        policy_id: identifier::<PolicyId>("research-v0"),
        policy_version: PolicyVersion::new(1),
    }
}

fn request_with_expected(
    challenge: PublisherChallenge,
    now: u64,
    expected: ExpectedContext,
) -> VerificationRequest {
    VerificationRequest {
        challenge,
        evidence: EvidenceBundle {
            profile_id: identifier::<EvidenceProfile>("mock-v0"),
            payload: Vec::new(),
        },
        expected,
        now: UnixTime::new(now),
    }
}

fn request(challenge: PublisherChallenge, now: u64) -> VerificationRequest {
    request_with_expected(challenge, now, expected())
}

#[test]
fn same_publisher_nonce_is_single_use_across_bindings() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits());
    let first = challenge("example.game", [7; 32]);
    let changed = challenge("other.game", [7; 32]);

    assert_eq!(guard.register(UnixTime::new(100), &first), Ok(()));
    assert_eq!(
        guard.register(UnixTime::new(100), &changed),
        Err(FreshnessError::ReplayDetected)
    );
    assert!(guard.claim(UnixTime::new(100), &first).is_ok());
    assert_eq!(
        guard.claim(UnixTime::new(100), &changed),
        Err(FreshnessError::ReplayDetected)
    );
}

#[test]
fn identical_nonce_bytes_are_independent_across_publishers() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits());
    let first = challenge_for_publisher("publisher-one", [9; 32]);
    let second = challenge_for_publisher("publisher-two", [9; 32]);

    assert_eq!(guard.register(UnixTime::new(100), &first), Ok(()));
    assert_eq!(guard.register(UnixTime::new(100), &second), Ok(()));
    assert!(guard.claim(UnixTime::new(100), &first).is_ok());
    assert!(guard.claim(UnixTime::new(100), &second).is_ok());
}

#[test]
fn unavailable_store_never_returns_freshness_capability() {
    let store = ReferenceReplayStore::unavailable();
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(
        guard.register(UnixTime::new(100), &challenge("example.game", [3; 32])),
        Err(FreshnessError::StateUnavailable)
    );
}

#[test]
fn first_fresh_request_reaches_fail_closed_evidence_result() {
    for now in [100, 199] {
        let store = ReferenceReplayStore::available();
        let guard = FreshnessGuard::new(&store, limits());
        let challenge = challenge("example.game", [1; 32]);
        assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));
        let outcome = verify_research_structure(&request(challenge, now), &guard);
        assert_eq!(outcome.decision, Decision::Deny);
        assert_eq!(outcome.reason, ReasonCode::EvidenceInvalid);
    }
}

#[test]
fn verifier_maps_strict_window_failures_before_claim() {
    for (now, expected_reason) in [
        (99, ReasonCode::NotYetValid),
        (200, ReasonCode::Expired),
        (201, ReasonCode::Expired),
    ] {
        let store = ReferenceReplayStore::available();
        let guard = FreshnessGuard::new(&store, limits());
        let challenge = challenge("example.game", [12; 32]);
        assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));
        let outcome = verify_research_structure(&request(challenge, now), &guard);
        assert_eq!(outcome.decision, Decision::Deny);
        assert_eq!(outcome.reason, expected_reason);
    }
}

#[test]
fn second_request_with_same_nonce_is_replay() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits());
    let challenge = challenge("example.game", [2; 32]);
    assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));
    let first = verify_research_structure(&request(challenge.clone(), 100), &guard);
    let second = verify_research_structure(&request(challenge, 100), &guard);
    assert_eq!(first.reason, ReasonCode::EvidenceInvalid);
    assert_eq!(second.reason, ReasonCode::ReplayDetected);
}

#[test]
fn every_context_mismatch_rejects_without_consuming_registered_nonce() {
    let mut mismatches = Vec::new();
    let mut mismatch = expected();
    mismatch.publisher_id = identifier::<PublisherId>("other.publisher");
    mismatches.push(mismatch);
    let mut mismatch = expected();
    mismatch.game_id = identifier::<GameId>("other.game");
    mismatches.push(mismatch);
    let mut mismatch = expected();
    mismatch.build_id = identifier::<BuildId>("build-2");
    mismatches.push(mismatch);
    let mut mismatch = expected();
    mismatch.account_scope = identifier::<AccountScope>("account-2");
    mismatches.push(mismatch);
    let mut mismatch = expected();
    mismatch.match_id = identifier::<MatchId>("match-2");
    mismatches.push(mismatch);
    let mut mismatch = expected();
    mismatch.policy_id = identifier::<PolicyId>("research-v1");
    mismatches.push(mismatch);
    let mut mismatch = expected();
    mismatch.policy_version = PolicyVersion::new(2);
    mismatches.push(mismatch);

    for (nonce, mismatch) in (3_u8..).zip(mismatches) {
        let store = ReferenceReplayStore::available();
        let guard = FreshnessGuard::new(&store, limits());
        let challenge = challenge("example.game", [nonce; 32]);
        assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));
        assert_eq!(
            verify_research_structure(
                &request_with_expected(challenge.clone(), 100, mismatch),
                &guard,
            )
            .reason,
            ReasonCode::SessionBindingMismatch
        );
        assert_eq!(
            verify_research_structure(&request(challenge, 100), &guard).reason,
            ReasonCode::EvidenceInvalid
        );
    }
}

#[test]
fn unavailable_state_returns_retry_without_allow() {
    let store = ReferenceReplayStore::unavailable();
    let guard = FreshnessGuard::new(&store, limits());
    let outcome =
        verify_research_structure(&request(challenge("example.game", [10; 32]), 100), &guard);
    assert_eq!(outcome.decision, Decision::Retry);
    assert_eq!(outcome.reason, ReasonCode::AttestationUnavailable);
}

#[test]
fn clock_rollback_returns_retry_without_allow() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits());
    let challenge = challenge("example.game", [11; 32]);
    assert_eq!(guard.register(UnixTime::new(150), &challenge), Ok(()));
    let outcome = verify_research_structure(&request(challenge, 140), &guard);
    assert_eq!(outcome.decision, Decision::Retry);
    assert_eq!(outcome.reason, ReasonCode::AttestationUnavailable);
}
