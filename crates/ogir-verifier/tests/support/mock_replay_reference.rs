// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "research-mock-replay")]

use crate::support;

use ogir_model::{
    AccountScope, BuildId, ChallengeLifetime, ChallengeWindow, GameId, IdentifierError, MatchId,
    Nonce, PolicyId, PolicyVersion, ProtocolVersion, PublisherChallenge,
};
use ogir_model::{FreshnessError, FreshnessLimits, PublisherId, UnixTime};
use ogir_verifier::mock_replay::{MockReplayCache, MockReplayLimits};
use ogir_verifier::{ReplayRegistration, ReplayStore};
use std::num::NonZeroU64;
use std::num::NonZeroUsize;

fn take<T>(result: Result<T, FreshnessError>) -> T {
    match result {
        Ok(value) => value,
        Err(_) => panic!("mock fixture failed"),
    }
}
fn nz(n: usize) -> NonZeroUsize {
    match NonZeroUsize::new(n) {
        Some(n) => n,
        None => panic!("invalid fixture limit"),
    }
}
fn nz64(n: u64) -> NonZeroU64 {
    match NonZeroU64::new(n) {
        Some(n) => n,
        None => panic!("invalid fixture limit"),
    }
}
fn id<T>(text: &str) -> T
where
    for<'a> T: TryFrom<&'a str, Error = IdentifierError>,
{
    match T::try_from(text) {
        Ok(value) => value,
        Err(_) => panic!("invalid fixture id"),
    }
}
fn policy(total: usize, publisher: usize, account: usize, rate: usize) -> FreshnessLimits {
    FreshnessLimits::new(
        ChallengeLifetime::new(nz64(100)),
        nz(total),
        nz(publisher),
        nz(account),
        nz64(60),
        nz(rate),
    )
}
fn cache(
    total: usize,
    publisher: usize,
    account: usize,
    rate: usize,
    events: usize,
) -> MockReplayCache {
    take(MockReplayCache::new_research_run(MockReplayLimits::new(
        policy(total, publisher, account, rate),
        nz(events),
    )))
}
fn challenge(publisher: &str, seed: u8, issue: u64, expiry: u64) -> PublisherChallenge {
    PublisherChallenge {
        version: ProtocolVersion { major: 0, minor: 1 },
        publisher_id: id::<PublisherId>(publisher),
        game_id: id::<GameId>("example.game"),
        build_id: id::<BuildId>("build-1"),
        account_scope: id::<AccountScope>("account-1"),
        match_id: id::<MatchId>("match-1"),
        policy_id: id::<PolicyId>("research-v0"),
        policy_version: PolicyVersion::new(1),
        nonce: Nonce::from_bytes(std::array::from_fn(|i| seed ^ i as u8)),
        window: take(ChallengeWindow::new(
            UnixTime::new(issue),
            UnixTime::new(expiry),
            ChallengeLifetime::new(nz64(u64::MAX)),
        )),
    }
}
fn reg(publisher: &str, seed: u8, issue: u64, expiry: u64) -> ReplayRegistration {
    ReplayRegistration::from_challenge(&challenge(publisher, seed, issue, expiry))
}
fn counts(cache: &MockReplayCache) -> (usize, usize) {
    let stats = take(cache.stats());
    (stats.retained_records(), stats.retained_issuances())
}

#[test]
fn case_x08() {
    let model = cache(4, 4, 4, 4, 8);
    let reference = support::ReferenceReplayStore::available();
    let fixed = policy(4, 4, 4, 4);
    let first = reg("example.publisher", 1, 100, 200);
    let second = reg("example.publisher", 2, 100, 200);
    let mut changed = challenge("example.publisher", 1, 100, 200);
    changed.game_id = id::<GameId>("other.game");
    let wrong = ReplayRegistration::from_challenge(&changed);
    macro_rules! compare {
        ($candidate:expr, $reference:expr, $expected:expr, $records:expr, $events:expr) => {{
            let observed = $candidate;
            let reference_observed = $reference;
            assert!(
                observed == $expected && reference_observed == $expected,
                "literal replay result differs"
            );
            assert!(counts(&model) == ($records, $events), "mock counts differ");
            assert!(
                reference.record_count() == Ok($records),
                "reference record count differs"
            );
            assert!(
                reference.issuance_event_count() == Ok($events),
                "reference event count differs"
            );
        }};
    }
    compare!(
        model.observe_time(UnixTime::new(100)),
        reference.observe_time(UnixTime::new(100)),
        Ok(()),
        0,
        0
    );
    compare!(
        model.register(UnixTime::new(100), &first),
        reference.register(UnixTime::new(100), &first, fixed),
        Ok(()),
        1,
        1
    );
    compare!(
        model.claim(UnixTime::new(150), &wrong),
        reference.claim(UnixTime::new(150), &wrong),
        Err(FreshnessError::ReplayDetected),
        1,
        1
    );
    compare!(
        model.observe_time(UnixTime::new(149)),
        reference.observe_time(UnixTime::new(149)),
        Err(FreshnessError::ClockRollback),
        1,
        1
    );
    compare!(
        model.claim(UnixTime::new(150), &first),
        reference.claim(UnixTime::new(150), &first),
        Ok(()),
        1,
        1
    );
    compare!(
        model.claim(UnixTime::new(150), &first),
        reference.claim(UnixTime::new(150), &first),
        Err(FreshnessError::ReplayDetected),
        1,
        1
    );
    compare!(
        model.register(UnixTime::new(150), &second),
        reference.register(UnixTime::new(150), &second, fixed),
        Ok(()),
        2,
        2
    );
    compare!(
        model.purge_expired(UnixTime::new(160)),
        reference.purge_expired(UnixTime::new(160)),
        Ok(0),
        2,
        1
    );
    compare!(
        model.purge_expired(UnixTime::new(200)),
        reference.purge_expired(UnixTime::new(200)),
        Ok(2),
        0,
        1
    );
    compare!(
        model.claim(UnixTime::new(200), &first),
        reference.claim(UnixTime::new(200), &first),
        Err(FreshnessError::Expired),
        0,
        1
    );
}
