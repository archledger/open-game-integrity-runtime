// SPDX-License-Identifier: Apache-2.0

mod support;

#[cfg(feature = "research-mock-replay")]
#[path = "support/mock_replay_reference.rs"]
mod mock_replay_reference;

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::{Arc, Barrier};
use std::thread;

use ogir_model::{
    AccountScope, BuildId, ChallengeLifetime, ChallengeWindow, Decision, EvidenceProfile,
    FreshnessError, FreshnessLimits, GameId, IdentifierError, MatchId, Nonce, PolicyId,
    PolicyVersion, ProtocolVersion, PublisherChallenge, PublisherId, ReasonCode, UnixTime,
};
use ogir_protocol::EvidenceBundle;
use ogir_verifier::{
    ExpectedContext, FreshnessGuard, ReplayKey, ReplayRegistration, VerificationRequest,
    verify_research_structure,
};
use support::{ReferenceReplayStore, Snapshot};

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

fn test_nonce(seed: u8) -> Nonce {
    Nonce::from_bytes(std::array::from_fn(|index| seed ^ index as u8))
}

#[test]
fn synthetic_nonce_fixtures_cover_every_seed_without_collision() {
    let mut seen = HashSet::new();

    for seed in u8::MIN..=u8::MAX {
        let first: Nonce = test_nonce(seed);
        let second: Nonce = test_nonce(seed);

        assert_eq!(first, second);
        for (index, byte) in first.as_bytes().iter().copied().enumerate() {
            assert_eq!(byte, seed ^ index as u8);
        }
        assert!(seen.insert(first));
    }

    assert_eq!(seen.len(), 256);
}

fn challenge_for_publisher(publisher: &str, nonce_seed: u8) -> PublisherChallenge {
    PublisherChallenge {
        version: ProtocolVersion { major: 0, minor: 1 },
        publisher_id: identifier::<PublisherId>(publisher),
        game_id: identifier::<GameId>("example.game"),
        build_id: identifier::<BuildId>("build-1"),
        account_scope: identifier::<AccountScope>("account-1"),
        match_id: identifier::<MatchId>("match-1"),
        policy_id: identifier::<PolicyId>("research-v0"),
        policy_version: PolicyVersion::new(1),
        nonce: test_nonce(nonce_seed),
        window: valid_window(100, 200),
    }
}

fn challenge(game: &str, nonce_seed: u8) -> PublisherChallenge {
    let mut challenge = challenge_for_publisher("example.publisher", nonce_seed);
    challenge.game_id = identifier::<GameId>(game);
    challenge
}

fn challenge_for_account(publisher: &str, account: &str, nonce_seed: u8) -> PublisherChallenge {
    let mut challenge = challenge_for_publisher(publisher, nonce_seed);
    challenge.account_scope = identifier::<AccountScope>(account);
    challenge
}

fn challenge_with_window(
    publisher: &str,
    nonce_seed: u8,
    issued_at: u64,
    expires_at: u64,
) -> PublisherChallenge {
    let mut challenge = challenge_for_publisher(publisher, nonce_seed);
    challenge.window = valid_window(issued_at, expires_at);
    challenge
}

fn limits_for(
    total: usize,
    publisher: usize,
    account: usize,
    rate_window: u64,
    rate_maximum: usize,
) -> FreshnessLimits {
    FreshnessLimits::new(
        ChallengeLifetime::new(nonzero_u64(100)),
        nonzero_usize(total),
        nonzero_usize(publisher),
        nonzero_usize(account),
        nonzero_u64(rate_window),
        nonzero_usize(rate_maximum),
    )
}

fn limits_with_lifetime(seconds: u64) -> FreshnessLimits {
    FreshnessLimits::new(
        ChallengeLifetime::new(nonzero_u64(seconds)),
        nonzero_usize(16),
        nonzero_usize(16),
        nonzero_usize(16),
        nonzero_u64(60),
        nonzero_usize(16),
    )
}

fn snapshot(store: &ReferenceReplayStore) -> Snapshot {
    match store.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("available reference store did not snapshot: {error:?}"),
    }
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
    let first = challenge("example.game", 7);
    let changed = challenge("other.game", 7);

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
    let first = challenge_for_publisher("publisher-one", 9);
    let second = challenge_for_publisher("publisher-two", 9);

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
        guard.register(UnixTime::new(100), &challenge("example.game", 3)),
        Err(FreshnessError::StateUnavailable)
    );
}

#[test]
fn first_fresh_request_reaches_fail_closed_evidence_result() {
    for now in [100, 199] {
        let store = ReferenceReplayStore::available();
        let guard = FreshnessGuard::new(&store, limits());
        let challenge = challenge("example.game", 1);
        assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));
        let outcome = verify_research_structure(&request(challenge, now), &guard);
        assert_eq!(outcome.decision(), Decision::Deny);
        assert_eq!(outcome.reason(), Some(ReasonCode::EvidenceInvalid));
    }
}

#[test]
fn research_scaffold_reports_without_authority() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits());
    let challenge = challenge("example.game", 91);
    assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));

    let outcome = verify_research_structure(&request(challenge, 100), &guard);
    assert_eq!(outcome.decision(), Decision::Deny);
    assert_eq!(outcome.reason(), Some(ReasonCode::EvidenceInvalid));
}

#[test]
fn verifier_maps_strict_window_failures_before_claim() {
    let not_yet_store = ReferenceReplayStore::available();
    let not_yet_guard = FreshnessGuard::new(&not_yet_store, limits());
    let not_yet =
        verify_research_structure(&request(challenge("example.game", 12), 99), &not_yet_guard);
    assert_eq!(not_yet.decision(), Decision::Deny);
    assert_eq!(not_yet.reason(), Some(ReasonCode::NotYetValid));
    assert_eq!(not_yet_store.high_water(), Ok(Some(UnixTime::new(99))));

    for now in [200, 201] {
        let store = ReferenceReplayStore::available();
        let guard = FreshnessGuard::new(&store, limits());
        let challenge = challenge("example.game", 12);
        assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));
        let outcome = verify_research_structure(&request(challenge, now), &guard);
        assert_eq!(outcome.decision(), Decision::Deny);
        assert_eq!(outcome.reason(), Some(ReasonCode::Expired));
        assert_eq!(store.high_water(), Ok(Some(UnixTime::new(now))));
    }
}

#[test]
fn second_request_with_same_nonce_is_replay() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits());
    let challenge = challenge("example.game", 2);
    assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));
    let first = verify_research_structure(&request(challenge.clone(), 100), &guard);
    let second = verify_research_structure(&request(challenge, 100), &guard);
    assert_eq!(first.reason(), Some(ReasonCode::EvidenceInvalid));
    assert_eq!(second.reason(), Some(ReasonCode::ReplayDetected));
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
        let challenge = challenge("example.game", nonce);
        assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));
        assert_eq!(
            verify_research_structure(
                &request_with_expected(challenge.clone(), 100, mismatch),
                &guard,
            )
            .reason(),
            Some(ReasonCode::ContextBindingMismatch)
        );
        assert_eq!(
            verify_research_structure(&request(challenge, 100), &guard).reason(),
            Some(ReasonCode::EvidenceInvalid)
        );
    }
}

#[test]
fn context_mismatch_observes_time_before_rejection_and_preserves_issued_state() {
    let store = ReferenceReplayStore::available();
    let challenge = challenge("example.game", 45);
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));

    let mut mismatch = expected();
    mismatch.game_id = identifier::<GameId>("other.game");
    let rejected = verify_research_structure(
        &request_with_expected(challenge.clone(), 150, mismatch),
        &guard,
    );
    assert_eq!(rejected.decision(), Decision::Deny);
    assert_eq!(rejected.reason(), Some(ReasonCode::ContextBindingMismatch));
    assert_eq!(store.high_water(), Ok(Some(UnixTime::new(150))));

    let reopened = ReferenceReplayStore::reopen(snapshot(&store));
    let reopened_guard = FreshnessGuard::new(&reopened, limits());
    let rolled_back = verify_research_structure(&request(challenge.clone(), 140), &reopened_guard);
    assert_eq!(rolled_back.decision(), Decision::Retry);
    assert_eq!(
        rolled_back.reason(),
        Some(ReasonCode::AttestationUnavailable)
    );

    let original = verify_research_structure(&request(challenge, 150), &reopened_guard);
    assert_eq!(original.decision(), Decision::Deny);
    assert_eq!(original.reason(), Some(ReasonCode::EvidenceInvalid));
}

#[test]
fn unavailable_state_returns_retry_without_allow() {
    let store = ReferenceReplayStore::unavailable();
    let guard = FreshnessGuard::new(&store, limits());
    let outcome = verify_research_structure(&request(challenge("example.game", 10), 100), &guard);
    assert_eq!(outcome.decision(), Decision::Retry);
    assert_eq!(outcome.reason(), Some(ReasonCode::AttestationUnavailable));
}

#[test]
fn clock_rollback_returns_retry_without_allow() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits());
    let challenge = challenge("example.game", 11);
    assert_eq!(guard.register(UnixTime::new(150), &challenge), Ok(()));
    let outcome = verify_research_structure(&request(challenge, 140), &guard);
    assert_eq!(outcome.decision(), Decision::Retry);
    assert_eq!(outcome.reason(), Some(ReasonCode::AttestationUnavailable));
}

#[test]
fn rejected_future_time_persists_floor_across_restart() {
    let store = ReferenceReplayStore::available();
    let challenge = challenge("example.game", 13);
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));

    let expired = verify_research_structure(&request(challenge.clone(), 300), &guard);
    assert_eq!(expired.decision(), Decision::Deny);
    assert_eq!(expired.reason(), Some(ReasonCode::Expired));
    assert_eq!(store.high_water(), Ok(Some(UnixTime::new(300))));

    let reopened = ReferenceReplayStore::reopen(snapshot(&store));
    let reopened_guard = FreshnessGuard::new(&reopened, limits());
    let rolled_back = verify_research_structure(&request(challenge, 150), &reopened_guard);
    assert_eq!(rolled_back.decision(), Decision::Retry);
    assert_eq!(
        rolled_back.reason(),
        Some(ReasonCode::AttestationUnavailable)
    );
}

#[test]
fn clock_rollback_and_restart_never_reset_security_state() {
    let store = ReferenceReplayStore::available();
    let challenge = challenge("example.game", 20);
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(guard.register(UnixTime::new(150), &challenge), Ok(()));

    let reopened = ReferenceReplayStore::reopen(snapshot(&store));
    let reopened_guard = FreshnessGuard::new(&reopened, limits());
    assert_eq!(
        reopened_guard.claim(UnixTime::new(149), &challenge),
        Err(FreshnessError::ClockRollback)
    );
    assert_eq!(reopened.high_water(), Ok(Some(UnixTime::new(150))));
}

#[test]
fn consumed_state_survives_snapshot_and_reopen() {
    let store = ReferenceReplayStore::available();
    let challenge = challenge("example.game", 21);
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));
    assert!(guard.claim(UnixTime::new(100), &challenge).is_ok());

    let reopened = ReferenceReplayStore::reopen(snapshot(&store));
    let reopened_guard = FreshnessGuard::new(&reopened, limits());
    assert_eq!(
        reopened_guard.claim(UnixTime::new(100), &challenge),
        Err(FreshnessError::ReplayDetected)
    );
}

#[test]
fn issuance_rate_state_survives_snapshot_and_reopen() {
    let store = ReferenceReplayStore::available();
    let rate_limits = limits_for(8, 8, 8, 60, 2);
    let guard = FreshnessGuard::new(&store, rate_limits);
    for nonce in [42, 43] {
        assert_eq!(
            guard.register(UnixTime::new(100), &challenge("example.game", nonce),),
            Ok(())
        );
    }

    let reopened = ReferenceReplayStore::reopen(snapshot(&store));
    let reopened_guard = FreshnessGuard::new(&reopened, rate_limits);
    assert_eq!(
        reopened_guard.register(UnixTime::new(100), &challenge("example.game", 44),),
        Err(FreshnessError::CapacityExceeded)
    );
}

#[test]
fn missing_or_corrupt_snapshot_fails_closed() {
    let challenge = challenge("example.game", 22);
    for store in [
        ReferenceReplayStore::missing(),
        ReferenceReplayStore::corrupt(),
    ] {
        let guard = FreshnessGuard::new(&store, limits());
        assert_eq!(
            guard.register(UnixTime::new(100), &challenge),
            Err(FreshnessError::StateUnavailable)
        );
        assert_eq!(
            guard.claim(UnixTime::new(100), &challenge),
            Err(FreshnessError::StateUnavailable)
        );
        assert_eq!(
            guard.purge_expired(UnixTime::new(200)),
            Err(FreshnessError::StateUnavailable)
        );
    }
}

#[test]
fn poisoned_replay_store_locks_fail_closed_without_allow() {
    let availability_poisoned = ReferenceReplayStore::available();
    availability_poisoned.poison_availability_lock();
    let state_poisoned = ReferenceReplayStore::available();
    state_poisoned.poison_state_lock();

    for (nonce, store) in [50_u8, 51]
        .into_iter()
        .zip([availability_poisoned, state_poisoned])
    {
        let challenge = challenge("example.game", nonce);
        let guard = FreshnessGuard::new(&store, limits());
        assert_eq!(
            guard.register(UnixTime::new(100), &challenge),
            Err(FreshnessError::StateUnavailable)
        );
        assert_eq!(
            guard.claim(UnixTime::new(100), &challenge),
            Err(FreshnessError::StateUnavailable)
        );
        assert_eq!(
            guard.purge_expired(UnixTime::new(200)),
            Err(FreshnessError::StateUnavailable)
        );
        assert!(matches!(
            store.snapshot(),
            Err(FreshnessError::StateUnavailable)
        ));

        let outcome = verify_research_structure(&request(challenge, 100), &guard);
        assert_eq!(outcome.decision(), Decision::Retry);
        assert_eq!(outcome.reason(), Some(ReasonCode::AttestationUnavailable));
    }
}

#[test]
fn capacity_refuses_issuance_without_evicting_unexpired_records() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits_for(2, 2, 1, 60, 2));
    let first = challenge_for_publisher("publisher-one", 23);
    let second = challenge_for_publisher("publisher-two", 24);
    let rejected = challenge_for_publisher("publisher-three", 25);
    let first_key = ReplayRegistration::from_challenge(&first).key().clone();
    let second_key = ReplayRegistration::from_challenge(&second).key().clone();

    assert_eq!(guard.register(UnixTime::new(100), &first), Ok(()));
    assert_eq!(guard.register(UnixTime::new(100), &second), Ok(()));
    assert_eq!(
        guard.register(UnixTime::new(100), &rejected),
        Err(FreshnessError::CapacityExceeded)
    );
    assert_eq!(store.record_count(), Ok(2));
    assert_eq!(store.contains(&first_key), Ok(true));
    assert_eq!(store.contains(&second_key), Ok(true));
}

#[test]
fn consumed_unexpired_records_still_count_toward_capacity() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits_for(2, 2, 1, 60, 2));
    let first = challenge("example.game", 45);
    let second = challenge("example.game", 46);
    assert_eq!(guard.register(UnixTime::new(100), &first), Ok(()));
    assert!(guard.claim(UnixTime::new(100), &first).is_ok());
    assert_eq!(
        guard.register(UnixTime::new(100), &second),
        Err(FreshnessError::CapacityExceeded)
    );
}

#[test]
fn registration_reclaims_only_records_expired_at_the_time_floor() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits_for(1, 1, 1, 60, 2));
    let old = challenge("example.game", 47);
    let replacement = challenge_with_window("example.publisher", 48, 200, 300);
    let old_key = ReplayRegistration::from_challenge(&old).key().clone();
    let replacement_key = ReplayRegistration::from_challenge(&replacement)
        .key()
        .clone();

    assert_eq!(guard.register(UnixTime::new(100), &old), Ok(()));
    assert_eq!(guard.register(UnixTime::new(200), &replacement), Ok(()));
    assert_eq!(store.contains(&old_key), Ok(false));
    assert_eq!(store.contains(&replacement_key), Ok(true));
}

#[test]
fn registration_rechecks_active_lifetime_policy_atomically() {
    let challenge = challenge("example.game", 41);

    let exact_store = ReferenceReplayStore::available();
    let exact_guard = FreshnessGuard::new(&exact_store, limits_with_lifetime(100));
    assert_eq!(exact_guard.register(UnixTime::new(100), &challenge), Ok(()));

    let over_store = ReferenceReplayStore::available();
    let over_guard = FreshnessGuard::new(&over_store, limits_with_lifetime(99));
    assert_eq!(
        over_guard.register(UnixTime::new(100), &challenge),
        Err(FreshnessError::LifetimeExceeded)
    );
    assert_eq!(over_store.record_count(), Ok(0));
}

#[test]
fn publisher_account_and_rate_limits_accept_limit_and_reject_one_over() {
    let publisher_store = ReferenceReplayStore::available();
    let publisher_guard = FreshnessGuard::new(&publisher_store, limits_for(4, 2, 2, 60, 4));
    for (account, nonce) in [("account-one", 26), ("account-two", 27)] {
        let challenge = challenge_for_account("publisher-one", account, nonce);
        assert_eq!(
            publisher_guard.register(UnixTime::new(100), &challenge),
            Ok(())
        );
    }
    let publisher_over = challenge_for_account("publisher-one", "account-three", 28);
    assert_eq!(
        publisher_guard.register(UnixTime::new(100), &publisher_over),
        Err(FreshnessError::CapacityExceeded)
    );

    let account_store = ReferenceReplayStore::available();
    let account_guard = FreshnessGuard::new(&account_store, limits_for(4, 4, 2, 60, 4));
    for nonce in [29, 30] {
        let challenge = challenge("example.game", nonce);
        assert_eq!(
            account_guard.register(UnixTime::new(100), &challenge),
            Ok(())
        );
    }
    assert_eq!(
        account_guard.register(UnixTime::new(100), &challenge("example.game", 31),),
        Err(FreshnessError::CapacityExceeded)
    );

    let rate_store = ReferenceReplayStore::available();
    let rate_guard = FreshnessGuard::new(&rate_store, limits_for(4, 4, 4, 60, 2));
    for nonce in [32, 33] {
        let challenge = challenge("example.game", nonce);
        assert_eq!(rate_guard.register(UnixTime::new(100), &challenge), Ok(()));
    }
    let after_limit = challenge("example.game", 34);
    assert_eq!(
        rate_guard.register(UnixTime::new(100), &after_limit),
        Err(FreshnessError::CapacityExceeded)
    );
    assert_eq!(
        rate_guard.register(UnixTime::new(160), &after_limit),
        Ok(())
    );
}

#[test]
fn gc_keeps_record_before_expiry_and_removes_it_at_expiry() {
    let store = ReferenceReplayStore::available();
    let challenge = challenge("example.game", 35);
    let key = ReplayRegistration::from_challenge(&challenge).key().clone();
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));
    assert!(guard.claim(UnixTime::new(100), &challenge).is_ok());
    assert_eq!(guard.purge_expired(UnixTime::new(199)), Ok(0));
    assert_eq!(store.contains(&key), Ok(true));
    assert_eq!(guard.purge_expired(UnixTime::new(200)), Ok(1));
    assert_eq!(store.contains(&key), Ok(false));
    assert_eq!(
        guard.claim(UnixTime::new(200), &challenge),
        Err(FreshnessError::Expired)
    );
}

#[test]
fn gc_bounds_rate_history_and_scrubs_every_durable_state_handle() {
    let store = ReferenceReplayStore::available();
    let challenge = challenge("example.game", 46);
    let key = ReplayRegistration::from_challenge(&challenge).key().clone();
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));
    assert_eq!(store.issuance_event_count(), Ok(1));

    let before_rate_gc = snapshot(&store);
    let reopened_before_rate_gc = ReferenceReplayStore::reopen(before_rate_gc);
    assert_eq!(guard.purge_expired(UnixTime::new(160)), Ok(0));
    assert_eq!(store.issuance_event_count(), Ok(0));
    assert_eq!(reopened_before_rate_gc.issuance_event_count(), Ok(0));
    assert_eq!(reopened_before_rate_gc.contains(&key), Ok(true));

    let before_record_gc = snapshot(&store);
    let reopened_before_record_gc = ReferenceReplayStore::reopen(before_record_gc);
    assert_eq!(guard.purge_expired(UnixTime::new(200)), Ok(1));
    assert_eq!(store.contains(&key), Ok(false));
    assert_eq!(reopened_before_record_gc.record_count(), Ok(0));
    assert_eq!(reopened_before_record_gc.issuance_event_count(), Ok(0));
}

#[test]
fn rollback_or_unavailable_state_blocks_gc() {
    let store = ReferenceReplayStore::available();
    let challenge = challenge("example.game", 36);
    let key = ReplayRegistration::from_challenge(&challenge).key().clone();
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(guard.register(UnixTime::new(150), &challenge), Ok(()));
    assert_eq!(
        guard.purge_expired(UnixTime::new(149)),
        Err(FreshnessError::ClockRollback)
    );
    assert_eq!(store.contains(&key), Ok(true));

    let unavailable = ReferenceReplayStore::unavailable();
    let unavailable_guard = FreshnessGuard::new(&unavailable, limits());
    assert_eq!(
        unavailable_guard.purge_expired(UnixTime::new(200)),
        Err(FreshnessError::StateUnavailable)
    );
}

#[test]
fn missing_registration_fails_closed() {
    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(
        guard.claim(UnixTime::new(100), &challenge("example.game", 37),),
        Err(FreshnessError::StateUnavailable)
    );
}

#[test]
fn replay_identity_ignores_every_context_and_window_field() {
    let baseline = challenge("example.game", 38);
    let mut variants = Vec::new();

    let mut changed = baseline.clone();
    changed.game_id = identifier::<GameId>("other.game");
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.build_id = identifier::<BuildId>("build-2");
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.account_scope = identifier::<AccountScope>("account-2");
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.match_id = identifier::<MatchId>("match-2");
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.policy_id = identifier::<PolicyId>("research-v1");
    variants.push(changed);
    let mut changed = baseline.clone();
    changed.policy_version = PolicyVersion::new(2);
    variants.push(changed);
    variants.push(challenge_with_window("example.publisher", 38, 100, 199));

    for changed in variants {
        let store = ReferenceReplayStore::available();
        let guard = FreshnessGuard::new(&store, limits());
        assert_eq!(guard.register(UnixTime::new(100), &baseline), Ok(()));
        assert_eq!(
            guard.claim(UnixTime::new(100), &changed),
            Err(FreshnessError::ReplayDetected)
        );
        assert_eq!(guard.claim(UnixTime::new(100), &baseline), Ok(()));
        assert_eq!(
            guard.claim(UnixTime::new(100), &baseline),
            Err(FreshnessError::ReplayDetected)
        );
    }
}

#[test]
fn replay_debug_and_errors_redact_every_binding_and_timestamp() {
    let mut challenge = challenge_for_publisher("private.publisher", 39);
    challenge.game_id = identifier::<GameId>("private.game");
    challenge.build_id = identifier::<BuildId>("private-build-424242");
    challenge.account_scope = identifier::<AccountScope>("private-account-424242");
    challenge.match_id = identifier::<MatchId>("private-match-424242");
    challenge.policy_id = identifier::<PolicyId>("private-policy-424242");
    challenge.policy_version = PolicyVersion::new(424_242);
    challenge.window = valid_window(4_242_400, 4_242_499);

    let registration = ReplayRegistration::from_challenge(&challenge);
    let private_expected = ExpectedContext {
        publisher_id: challenge.publisher_id.clone(),
        game_id: challenge.game_id.clone(),
        build_id: challenge.build_id.clone(),
        account_scope: challenge.account_scope.clone(),
        match_id: challenge.match_id.clone(),
        policy_id: challenge.policy_id.clone(),
        policy_version: challenge.policy_version,
    };
    let verification_request =
        request_with_expected(challenge.clone(), 4_242_400, private_expected.clone());

    let store = ReferenceReplayStore::available();
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(guard.register(UnixTime::new(4_242_400), &challenge), Ok(()));

    assert!(
        format!("{private_expected:?}") == "ExpectedContext([REDACTED])",
        "private diagnostic mismatch"
    );
    assert!(
        format!("{verification_request:?}") == "VerificationRequest([REDACTED])",
        "private diagnostic mismatch"
    );

    let debug_surfaces = [
        format!("{challenge:?}"),
        format!("{private_expected:?}"),
        format!("{verification_request:?}"),
        format!("{registration:?}"),
        format!("{:?}", registration.key()),
        format!("{:?}", registration.key().publisher_id()),
        format!("{:?}", registration.key().nonce()),
        format!("{:?}", registration.binding()),
        format!("{:?}", registration.binding().game_id()),
        format!("{:?}", registration.binding().build_id()),
        format!("{:?}", registration.binding().account_scope()),
        format!("{:?}", registration.binding().match_id()),
        format!("{:?}", registration.binding().policy_id()),
        format!("{:?}", registration.binding().policy_version()),
        format!("{:?}", registration.window()),
        format!("{:?}", registration.window().issued_at()),
        format!("{:?}", registration.window().expires_at()),
        format!("{store:?}"),
        format!("{guard:?}"),
        format!("{:?}", snapshot(&store)),
    ];
    let nonce_bytes = format!("{:?}", challenge.nonce.as_bytes());
    let sensitive_values = [
        "private.publisher",
        "private.game",
        "private-build-424242",
        "private-account-424242",
        "private-match-424242",
        "private-policy-424242",
        "424242",
        "4242400",
        "4242499",
        nonce_bytes.as_str(),
    ];

    for debug in debug_surfaces {
        assert!(
            debug.contains("REDACTED"),
            "private diagnostic missing redaction marker"
        );
        for sensitive in sensitive_values {
            assert!(
                !debug.contains(sensitive),
                "private diagnostic exposed a forbidden value"
            );
        }
    }

    for error in [
        FreshnessError::ReplayDetected,
        FreshnessError::ClockRollback,
        FreshnessError::StateUnavailable,
        FreshnessError::CapacityExceeded,
    ] {
        let rendered = format!("{error:?} {error}");
        for sensitive in sensitive_values {
            assert!(!rendered.contains(sensitive));
        }
    }
}

#[test]
fn two_concurrent_claims_produce_exactly_one_capability() {
    let store = ReferenceReplayStore::available();
    let challenge = challenge("example.game", 40);
    let guard = FreshnessGuard::new(&store, limits());
    assert_eq!(guard.register(UnixTime::new(100), &challenge), Ok(()));

    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let thread_store = store.clone();
        let thread_challenge = challenge.clone();
        let thread_barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let thread_guard = FreshnessGuard::new(&thread_store, limits());
            thread_barrier.wait();
            thread_guard.claim(UnixTime::new(100), &thread_challenge)
        }));
    }
    barrier.wait();

    let mut successes = 0;
    let mut replays = 0;
    for handle in handles {
        match handle.join() {
            Ok(Ok(_capability)) => successes += 1,
            Ok(Err(FreshnessError::ReplayDetected)) => replays += 1,
            Ok(Err(error)) => panic!("unexpected claim error: {error:?}"),
            Err(_) => panic!("claim worker panicked"),
        }
    }
    assert_eq!(successes, 1);
    assert_eq!(replays, 1);
}

#[derive(Debug, Clone, Copy)]
enum Action {
    Register { publisher: u8, nonce: u8 },
    Claim { publisher: u8, nonce: u8 },
    Advance(u8),
    Rollback(u8),
    Restart,
    SetUnavailable,
    Purge,
}

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn action(&mut self) -> Action {
        let value = self.next();
        let bytes = value.to_le_bytes();
        let publisher = bytes[1];
        let nonce = bytes[2];
        let delta = (bytes[3] % 16) + 1;
        match value % 7 {
            0 => Action::Register { publisher, nonce },
            1 => Action::Claim { publisher, nonce },
            2 => Action::Advance(delta),
            3 => Action::Rollback(delta),
            4 => Action::Restart,
            5 => Action::SetUnavailable,
            6 => Action::Purge,
            _ => unreachable!("modulo seven is exhaustive"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OracleRecordState {
    Issued,
    Consumed,
}

#[derive(Debug, Clone, Copy)]
struct OracleRecord {
    issued_at: u64,
    expires_at: u64,
    state: OracleRecordState,
}

type OracleKey = (u8, u8);

#[derive(Debug, Clone)]
struct OracleState {
    available: bool,
    high_water: Option<u64>,
    records: HashMap<OracleKey, OracleRecord>,
    challenges: HashMap<OracleKey, PublisherChallenge>,
    replay_keys: HashMap<OracleKey, ReplayKey>,
    windows: HashMap<OracleKey, (u64, u64)>,
    ever_issued: HashSet<OracleKey>,
    capability_counts: HashMap<OracleKey, usize>,
}

impl OracleState {
    fn initialized() -> Self {
        Self {
            available: true,
            high_water: None,
            records: HashMap::new(),
            challenges: HashMap::new(),
            replay_keys: HashMap::new(),
            windows: HashMap::new(),
            ever_issued: HashSet::new(),
            capability_counts: HashMap::new(),
        }
    }
}

fn property_expiry(now: u64) -> u64 {
    match now.checked_add(100) {
        Some(value) => value,
        None => panic!("property clock overflowed"),
    }
}

fn property_challenge(publisher: u8, nonce_seed: u8, now: u64) -> PublisherChallenge {
    let publisher_id = format!("publisher-{publisher}");
    let account = format!("account-{publisher}");
    let expires_at = property_expiry(now);
    let mut challenge = challenge_for_account(&publisher_id, &account, nonce_seed);
    challenge.window = valid_window(now, expires_at);
    challenge
}

fn next_unused_property_key(
    publisher: u8,
    nonce_seed: u8,
    ever_issued: &HashSet<OracleKey>,
) -> OracleKey {
    let start = u16::from_be_bytes([publisher, nonce_seed]);
    let mut candidate = start;
    loop {
        let bytes = candidate.to_be_bytes();
        let key = (bytes[0], bytes[1]);
        if !ever_issued.contains(&key) {
            return key;
        }
        candidate = candidate.wrapping_add(1);
        if candidate == start {
            panic!("property replay-key space exhausted");
        }
    }
}

#[test]
fn deterministic_arbitrary_sequences_preserve_freshness_invariants() {
    let property_limits = limits_for(65_535, 65_535, 65_535, 1, 65_535);

    for seed in 0_u64..64 {
        let mut rng = Lcg(seed);
        let mut now = 100_u64;
        let mut store = ReferenceReplayStore::available();
        let mut oracle = OracleState::initialized();
        let mut last_good_store = snapshot(&store);
        let mut last_good_oracle = oracle.clone();

        for action_index in 0_usize..256 {
            let action = rng.action();
            let prior_high_water = oracle.high_water;

            match action {
                Action::Register { publisher, nonce } => {
                    let key = next_unused_property_key(publisher, nonce, &oracle.ever_issued);
                    let challenge = property_challenge(key.0, key.1, now);
                    let expires_at = property_expiry(now);
                    let actual = FreshnessGuard::new(&store, property_limits)
                        .register(UnixTime::new(now), &challenge);
                    let expected = if !oracle.available {
                        Err(FreshnessError::StateUnavailable)
                    } else if oracle.high_water.is_some_and(|high_water| now < high_water) {
                        Err(FreshnessError::ClockRollback)
                    } else {
                        oracle.high_water = Some(now);
                        oracle.records.retain(|_, record| record.expires_at > now);
                        oracle.records.insert(
                            key,
                            OracleRecord {
                                issued_at: now,
                                expires_at,
                                state: OracleRecordState::Issued,
                            },
                        );
                        oracle.challenges.insert(key, challenge.clone());
                        oracle.replay_keys.insert(
                            key,
                            ReplayRegistration::from_challenge(&challenge).key().clone(),
                        );
                        oracle.windows.insert(key, (now, expires_at));
                        oracle.ever_issued.insert(key);
                        Ok(())
                    };
                    assert_eq!(
                        actual, expected,
                        "seed={seed} action={action_index} {action:?}"
                    );
                }
                Action::Claim { publisher, nonce } => {
                    let key = (publisher, nonce);
                    let challenge = match oracle.challenges.get(&key) {
                        Some(challenge) => challenge.clone(),
                        None => property_challenge(publisher, nonce, now),
                    };
                    let (issued_at, expires_at) = match oracle.windows.get(&key) {
                        Some(window) => *window,
                        None => (now, property_expiry(now)),
                    };
                    let actual = FreshnessGuard::new(&store, property_limits)
                        .claim(UnixTime::new(now), &challenge);
                    let expected = if !oracle.available {
                        Err(FreshnessError::StateUnavailable)
                    } else if oracle.high_water.is_some_and(|high_water| now < high_water) {
                        Err(FreshnessError::ClockRollback)
                    } else {
                        oracle.high_water = Some(now);
                        if now < issued_at {
                            Err(FreshnessError::NotYetValid)
                        } else if now >= expires_at {
                            Err(FreshnessError::Expired)
                        } else {
                            match oracle.records.get_mut(&key) {
                                None => Err(FreshnessError::StateUnavailable),
                                Some(record) if record.state == OracleRecordState::Consumed => {
                                    Err(FreshnessError::ReplayDetected)
                                }
                                Some(record) => {
                                    record.state = OracleRecordState::Consumed;
                                    let count = oracle.capability_counts.entry(key).or_insert(0);
                                    *count = match count.checked_add(1) {
                                        Some(value) => value,
                                        None => panic!("capability count overflowed"),
                                    };
                                    assert!(
                                        now >= record.issued_at && now < record.expires_at,
                                        "capability outside window: seed={seed} action={action_index}"
                                    );
                                    Ok(())
                                }
                            }
                        }
                    };
                    assert_eq!(
                        actual, expected,
                        "seed={seed} action={action_index} {action:?}"
                    );
                }
                Action::Advance(delta) => {
                    now = match now.checked_add(u64::from(delta)) {
                        Some(value) => value,
                        None => {
                            panic!("property clock overflow: seed={seed} action={action_index}")
                        }
                    };
                }
                Action::Rollback(delta) => {
                    now = now.saturating_sub(u64::from(delta));
                }
                Action::Restart => {
                    if oracle.available {
                        store = ReferenceReplayStore::reopen(snapshot(&store));
                    } else {
                        store = ReferenceReplayStore::reopen(last_good_store.clone());
                        oracle = last_good_oracle.clone();
                    }
                }
                Action::SetUnavailable => {
                    assert_eq!(
                        store.set_unavailable(),
                        Ok(()),
                        "seed={seed} action={action_index} {action:?}"
                    );
                    oracle.available = false;
                }
                Action::Purge => {
                    let actual = FreshnessGuard::new(&store, property_limits)
                        .purge_expired(UnixTime::new(now));
                    let expected = if !oracle.available {
                        Err(FreshnessError::StateUnavailable)
                    } else if oracle.high_water.is_some_and(|high_water| now < high_water) {
                        Err(FreshnessError::ClockRollback)
                    } else {
                        oracle.high_water = Some(now);
                        let before = oracle.records.len();
                        oracle.records.retain(|_, record| record.expires_at > now);
                        match before.checked_sub(oracle.records.len()) {
                            Some(removed) => Ok(removed),
                            None => panic!("purge increased oracle record count"),
                        }
                    };
                    assert_eq!(
                        actual, expected,
                        "seed={seed} action={action_index} {action:?}"
                    );
                }
            }

            if let (Some(previous), Some(current)) = (prior_high_water, oracle.high_water) {
                assert!(
                    current >= previous,
                    "high-water decreased: seed={seed} action={action_index} {action:?}"
                );
            }
            for (key, count) in &oracle.capability_counts {
                assert!(
                    *count <= 1,
                    "multiple capabilities for {key:?}: seed={seed} action={action_index}"
                );
            }

            match store.snapshot() {
                Ok(store_snapshot) => {
                    assert!(oracle.available, "store available while oracle unavailable");
                    assert_eq!(
                        store.high_water(),
                        Ok(oracle.high_water.map(UnixTime::new)),
                        "high-water mismatch: seed={seed} action={action_index}"
                    );
                    assert_eq!(
                        store.record_count(),
                        Ok(oracle.records.len()),
                        "record-count mismatch: seed={seed} action={action_index}"
                    );
                    for key in oracle.records.keys() {
                        let replay_key = match oracle.replay_keys.get(key) {
                            Some(replay_key) => replay_key,
                            None => panic!("missing replay key for oracle record {key:?}"),
                        };
                        assert_eq!(
                            store.contains(replay_key),
                            Ok(true),
                            "unexpired record disappeared: seed={seed} action={action_index} key={key:?}"
                        );
                    }
                    last_good_store = store_snapshot;
                    last_good_oracle = oracle.clone();
                }
                Err(FreshnessError::StateUnavailable) => {
                    assert!(!oracle.available, "available oracle had unavailable store");
                }
                Err(error) => {
                    panic!("unexpected snapshot error {error:?}: seed={seed} action={action_index}")
                }
            }
        }
    }
}
