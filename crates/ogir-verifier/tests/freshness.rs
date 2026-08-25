// SPDX-License-Identifier: Apache-2.0

mod support;

use std::fmt::Debug;
use std::num::{NonZeroU64, NonZeroUsize};

use ogir_model::{
    AccountScope, BuildId, ChallengeLifetime, ChallengeWindow, FreshnessError, FreshnessLimits,
    GameId, IdentifierError, MatchId, Nonce, PolicyId, PolicyVersion, ProtocolVersion,
    PublisherChallenge, PublisherId, UnixTime,
};
use ogir_verifier::FreshnessGuard;
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
