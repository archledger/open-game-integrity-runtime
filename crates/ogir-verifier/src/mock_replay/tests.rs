// SPDX-License-Identifier: Apache-2.0

use super::*;
use ogir_model::{
    AccountScope, BuildId, ChallengeLifetime, ChallengeWindow, GameId, IdentifierError, MatchId,
    Nonce, PolicyId, PolicyVersion, ProtocolVersion, PublisherChallenge,
};
use std::num::NonZeroU64;

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
fn case_a01() {
    let model = cache(4, 4, 4, 4, 8);
    assert!(counts(&model) == (0, 0), "new cache retained state");
    inspect(&model, |active| {
        assert!(active.floor.is_none(), "new cache has a floor")
    });
}

fn inspect<T>(model: &MockReplayCache, check: impl FnOnce(&mut Active) -> T) -> T {
    let mut state = take(model.lock_state());
    match &mut *state {
        State::Available(active) => check(active),
        State::Lost => panic!("fixture state unavailable"),
    }
}

#[test]
fn case_a02() {
    let model = cache(4, 4, 4, 4, 8);
    let other = model.clone();
    take(other.simulate_state_loss());
    assert!(
        model.stats() == Err(FreshnessError::StateUnavailable),
        "loss not shared"
    );
    assert!(
        other.stats() == Err(FreshnessError::StateUnavailable),
        "loss not terminal"
    );
    take(model.simulate_state_loss());
}

#[test]
fn case_a03() {
    let freshness = policy(7, 5, 3, 2);
    let limits = MockReplayLimits::new(freshness, nz(9));
    assert!(limits.freshness() == freshness, "policy changed");
    assert!(
        limits.max_retained_issuances() == nz(9),
        "event policy changed"
    );
    let model = take(MockReplayCache::new_research_run(limits));
    let mut copied = limits;
    assert!(copied.freshness() == freshness, "copied policy changed");
    copied = MockReplayLimits::new(policy(1, 1, 1, 1), nz(1));
    assert!(
        copied.max_retained_issuances() == nz(1),
        "replacement fixture failed"
    );
    assert!(
        model.shared.limits.freshness() == freshness,
        "cache policy was mutable"
    );
    assert!(
        model.shared.limits.max_retained_issuances() == nz(9),
        "cache event policy was mutable"
    );
}

fn clone_value<T: Clone>(value: &T) -> T {
    value.clone()
}

#[test]
fn case_a04() {
    let model = cache(4, 4, 4, 4, 8);
    let first = take(model.stats());
    let copied = first;
    let cloned = clone_value(&first);
    assert!(
        first == copied && first == cloned,
        "stats copy changed counts"
    );
    assert!(first == take(model.stats()), "stats mutated state");
}

#[test]
fn case_a05() {
    assert!(
        matches!(
            MockReplayCache::new_research_run(MockReplayLimits::new(
                policy(usize::MAX, 1, 1, 1),
                nz(1)
            )),
            Err(FreshnessError::CapacityExceeded)
        ),
        "record budget overflow accepted"
    );
}

#[test]
fn case_a06() {
    assert!(
        matches!(
            MockReplayCache::new_research_run(MockReplayLimits::new(
                policy(1, 1, 1, 1),
                nz(usize::MAX)
            )),
            Err(FreshnessError::CapacityExceeded)
        ),
        "event budget overflow accepted"
    );
}

// Private installation isolates formatting/time/collection from registration.
fn install(
    model: &MockReplayCache,
    slot: usize,
    input: ReplayRegistration,
    consumed: bool,
    observed: u64,
) {
    inspect(model, |active| {
        assert!(
            active.records[slot].is_none() && active.events[slot].is_none(),
            "fixture slot occupied"
        );
        active.events[slot] = Some(Event {
            publisher: input.key().publisher_id().clone(),
            observed_at: UnixTime::new(observed),
        });
        active.records[slot] = Some(Record {
            registration: input,
            consumed,
        });
    });
}

#[test]
fn case_p01() {
    let model = cache(4, 4, 4, 4, 8);
    for phase in 0..3 {
        if phase == 1 {
            install(&model, 0, reg("example.publisher", 1, 100, 200), false, 100);
        }
        if phase == 2 {
            inspect(&model, |active| {
                if let Some(record) = &mut active.records[0] {
                    record.consumed = true;
                }
            });
        }
        assert!(
            format!("{:?}", model.shared.limits) == "MockReplayLimits([REDACTED])",
            "limits diagnostic disclosed state"
        );
        assert!(
            format!("{model:?}") == "MockReplayCache([REDACTED])",
            "cache diagnostic disclosed state"
        );
        assert!(
            format!("{:?}", take(model.stats())) == "MockReplayStats([REDACTED])",
            "stats diagnostic disclosed state"
        );
    }
}

#[test]
fn case_p02() {
    let model = cache(4, 4, 4, 4, 8);
    // Holding the mutex proves Debug must not acquire it again.
    {
        let _guard = take(model.lock_state());
        assert!(
            format!("{model:?}") == "MockReplayCache([REDACTED])",
            "locked diagnostic changed"
        );
    }
    take(model.simulate_state_loss());
    assert!(
        format!("{model:?}") == "MockReplayCache([REDACTED])",
        "lost diagnostic changed"
    );
    let worker = model.clone();
    let result = std::thread::spawn(move || {
        let _guard = take(worker.lock_state());
        panic!("intentional mock cache poison");
    })
    .join();
    assert!(result.is_err(), "poison fixture did not panic");
    assert!(
        format!("{model:?}") == "MockReplayCache([REDACTED])",
        "poison diagnostic changed"
    );
}

fn floor(model: &MockReplayCache, expected: Option<u64>) {
    inspect(model, |active| {
        assert!(
            active.floor == expected.map(UnixTime::new),
            "time floor differs"
        )
    });
}

#[test]
fn case_t01() {
    let model = cache(4, 4, 4, 4, 8);
    take(model.observe_time(UnixTime::new(100)));
    floor(&model, Some(100));
    assert!(counts(&model) == (0, 0), "observation changed slots");
}

#[test]
fn case_t02() {
    let model = cache(4, 4, 4, 4, 8);
    take(model.observe_time(UnixTime::new(100)));
    take(model.observe_time(UnixTime::new(100)));
    floor(&model, Some(100));
    assert!(counts(&model) == (0, 0), "equal observation changed slots");
}

#[test]
fn case_t03() {
    let model = cache(4, 4, 4, 4, 8);
    let input = reg("example.publisher", 1, 100, 200);
    install(&model, 0, input.clone(), false, 100);
    take(model.observe_time(UnixTime::new(150)));
    assert!(
        model.observe_time(UnixTime::new(149)) == Err(FreshnessError::ClockRollback),
        "rollback accepted"
    );
    floor(&model, Some(150));
    inspect(&model, |active| {
        assert!(
            active.records[0]
                .as_ref()
                .is_some_and(|r| r.registration == input && !r.consumed),
            "rollback changed record"
        );
        assert!(
            active.events[0]
                .as_ref()
                .is_some_and(|e| e.publisher == *input.key().publisher_id()
                    && e.observed_at == UnixTime::new(100)),
            "rollback changed event"
        );
    });
    take(model.observe_time(UnixTime::new(150)));
}

#[test]
fn case_t06() {
    let model = cache(4, 4, 4, 4, 8);
    install(&model, 0, reg("example.publisher", 1, 100, 200), false, 100);
    take(model.observe_time(UnixTime::new(200)));
    assert!(counts(&model) == (1, 1), "observe or stats collected state");
    floor(&model, Some(200));
}

#[test]
fn case_t07() {
    let model = cache(4, 4, 4, 4, 8);
    take(model.observe_time(UnixTime::new(u64::MAX)));
    assert!(
        model.observe_time(UnixTime::new(u64::MAX - 1)) == Err(FreshnessError::ClockRollback),
        "large floor rolled back"
    );
    floor(&model, Some(u64::MAX));
}

#[test]
fn case_g01() {
    let model = cache(4, 4, 4, 4, 8);
    install(&model, 0, reg("example.publisher", 1, 100, 200), false, 100);
    assert!(
        take(model.purge_expired(UnixTime::new(199))) == 0,
        "record removed before expiry"
    );
    assert!(counts(&model) == (1, 0), "wrong pre-expiry retention");
    assert!(
        take(model.purge_expired(UnixTime::new(200))) == 1,
        "record retained at expiry"
    );
    assert!(
        take(model.purge_expired(UnixTime::new(200))) == 0,
        "repeat purge removed record"
    );
    assert!(counts(&model) == (0, 0), "purge retained expired slots");
}

#[test]
fn case_g02() {
    for consumed in [false, true] {
        let model = cache(4, 4, 4, 4, 8);
        install(
            &model,
            0,
            reg("example.publisher", 1, 100, 200),
            consumed,
            100,
        );
        assert!(
            take(model.purge_expired(UnixTime::new(199))) == 0,
            "state removed early"
        );
        assert!(counts(&model) == (1, 0), "state tag changed retention");
        assert!(
            take(model.purge_expired(UnixTime::new(200))) == 1,
            "state tag blocked expiry"
        );
        assert!(counts(&model) == (0, 0), "expired state retained");
    }
}

#[test]
fn case_g03() {
    let model = cache(4, 4, 4, 4, 8);
    install(&model, 0, reg("example.publisher", 1, 100, 200), false, 100);
    assert!(
        take(model.purge_expired(UnixTime::new(159))) == 0,
        "purge count includes live state"
    );
    assert!(counts(&model) == (1, 1), "event removed before boundary");
    assert!(
        take(model.purge_expired(UnixTime::new(160))) == 0,
        "purge count includes events"
    );
    assert!(counts(&model) == (1, 0), "event retained at boundary");
}

#[test]
fn case_g04() {
    let model = cache(4, 4, 4, 4, 8);
    install(&model, 0, reg("example.publisher", 1, 100, 200), false, 100);
    let other = model.clone();
    assert!(
        take(model.purge_expired(UnixTime::new(200))) == 1,
        "purge count differs"
    );
    assert!(
        counts(&other) == (0, 0),
        "old handle retained deleted state"
    );
}

#[test]
fn case_g05() {
    let model = cache(4, 4, 4, 4, 8);
    install(&model, 0, reg("example.publisher", 1, 100, 200), true, 100);
    take(model.observe_time(UnixTime::new(201)));
    assert!(
        model.purge_expired(UnixTime::new(200)) == Err(FreshnessError::ClockRollback),
        "purge accepted rollback"
    );
    assert!(counts(&model) == (1, 1), "rollback purged slots");
    floor(&model, Some(201));
}

#[test]
fn case_g06() {
    let model = cache(4, 4, 4, 4, 8);
    let start = u64::MAX - 80;
    install(
        &model,
        0,
        reg("example.publisher", 1, start, u64::MAX),
        false,
        start,
    );
    assert!(
        take(model.purge_expired(UnixTime::new(u64::MAX - 21))) == 0,
        "large timestamp purge removed record"
    );
    assert!(counts(&model) == (1, 1), "large event removed early");
    assert!(
        take(model.purge_expired(UnixTime::new(u64::MAX - 20))) == 0,
        "large event included in removal count"
    );
    assert!(counts(&model) == (1, 0), "large event retained at boundary");
    assert!(
        take(model.purge_expired(UnixTime::new(u64::MAX))) == 1,
        "maximum expiry retained"
    );
    let near = cache(4, 4, 4, 4, 8);
    install(
        &near,
        0,
        reg("example.publisher", 1, u64::MAX - 10, u64::MAX),
        false,
        u64::MAX - 10,
    );
    assert!(
        take(near.purge_expired(UnixTime::new(u64::MAX))) == 1,
        "near-maximum record retained"
    );
    assert!(
        counts(&near) == (0, 1),
        "overflowing addition shortened event lifetime"
    );
}

#[test]
fn case_g07() {
    let model = cache(4, 4, 4, 4, 8);
    install(&model, 0, reg("example.publisher", 1, 100, 180), false, 100);
    install(&model, 1, reg("example.publisher", 2, 120, 200), true, 120);
    let live = reg("example.publisher", 3, 150, 250);
    install(&model, 2, live.clone(), false, 150);
    assert!(
        take(model.purge_expired(UnixTime::new(200))) == 2,
        "mixed removal count differs"
    );
    assert!(counts(&model) == (1, 1), "mixed slots incorrectly purged");
    inspect(&model, |active| {
        assert!(
            active.records[0].is_none() && active.records[1].is_none(),
            "expired slots not vacant"
        );
        assert!(
            active.records[2]
                .as_ref()
                .is_some_and(|r| r.registration == live),
            "live record altered"
        );
        assert!(
            active.events[2]
                .as_ref()
                .is_some_and(|e| e.observed_at == UnixTime::new(150)),
            "live event altered"
        );
    });
    install(&model, 0, reg("other.publisher", 4, 200, 250), false, 200);
    assert!(counts(&model) == (2, 2), "vacant slots unusable");
}

fn dimensions(model: &MockReplayCache, records: usize, events: usize) {
    inspect(model, |active| {
        assert!(
            active.records.len() == records && active.events.len() == events,
            "configured slot lengths changed"
        )
    });
}

#[test]
fn case_a07() {
    let model = cache(1, 1, 1, 4, 2);
    dimensions(&model, 1, 2);
    let input = reg("example.publisher", 1, 100, 200);
    take(model.register(UnixTime::new(100), &input));
    dimensions(&model, 1, 2);
    take(model.claim(UnixTime::new(150), &input));
    inspect(&model, |active| {
        assert!(
            active.records[0].as_ref().is_some_and(|r| r.consumed),
            "slot reuse fixture did not consume"
        )
    });
    dimensions(&model, 1, 2);
    assert!(
        take(model.purge_expired(UnixTime::new(200))) == 1,
        "slot not purged"
    );
    dimensions(&model, 1, 2);
    take(model.register(UnixTime::new(200), &reg("example.publisher", 2, 200, 300)));
    dimensions(&model, 1, 2);
    assert!(counts(&model) == (1, 1), "vacant slots not reused");
}

#[test]
fn case_a08() {
    for (records, events) in [(1, 4), (4, 1)] {
        let model = cache(records, 4, 4, 4, events);
        inspect(&model, |active| {
            active.records.reserve(8);
            active.events.reserve(8);
            assert!(
                active.records.capacity() > records && active.events.capacity() > events,
                "spare-capacity fixture failed"
            );
        });
        take(model.register(UnixTime::new(100), &reg("example.publisher", 1, 100, 200)));
        assert!(
            model.register(UnixTime::new(100), &reg("other.publisher", 2, 100, 200))
                == Err(FreshnessError::CapacityExceeded),
            "spare allocation admitted extra state"
        );
        dimensions(&model, records, events);
        assert!(
            counts(&model) == (1, 1),
            "rejected registration changed counts"
        );
    }
}

#[test]
fn case_t04() {
    let model = cache(4, 4, 4, 4, 8);
    install(&model, 0, reg("other.publisher", 2, 100, 200), false, 100);
    assert!(
        model.register(UnixTime::new(250), &reg("example.publisher", 1, 100, 200))
            == Err(FreshnessError::Expired),
        "expired registration accepted"
    );
    floor(&model, Some(250));
    assert!(counts(&model) == (1, 1), "window rejection cleaned state");
    assert!(
        model.observe_time(UnixTime::new(249)) == Err(FreshnessError::ClockRollback),
        "expired rejection lost floor"
    );
}

#[test]
fn case_t08() {
    let model = cache(4, 4, 4, 4, 8);
    assert!(
        model.register(UnixTime::new(99), &reg("example.publisher", 1, 100, 200))
            == Err(FreshnessError::NotYetValid),
        "early registration accepted"
    );
    floor(&model, Some(99));
    assert!(
        counts(&model) == (0, 0),
        "early registration inserted state"
    );
    assert!(
        model.observe_time(UnixTime::new(98)) == Err(FreshnessError::ClockRollback),
        "early rejection lost floor"
    );
}

#[test]
fn case_r01() {
    let model = cache(4, 4, 4, 4, 8);
    let other = model.clone();
    let input = reg("example.publisher", 1, 100, 200);
    take(model.register(UnixTime::new(100), &input));
    assert!(
        counts(&model) == (1, 1) && counts(&other) == (1, 1),
        "registration not shared"
    );
    floor(&model, Some(100));
    inspect(&model, |active| {
        assert!(
            active
                .records
                .iter()
                .flatten()
                .any(|r| r.registration == input && !r.consumed),
            "registration contents differ"
        );
        assert!(
            active
                .events
                .iter()
                .flatten()
                .any(|e| e.publisher == *input.key().publisher_id()
                    && e.observed_at == UnixTime::new(100)),
            "issuance event differs"
        );
    });
}

#[test]
fn case_r02() {
    let model = cache(4, 4, 4, 4, 8);
    install(&model, 0, reg("other.publisher", 2, 100, 150), false, 100);
    assert!(
        model.register(UnixTime::new(160), &reg("example.publisher", 1, 100, 201))
            == Err(FreshnessError::LifetimeExceeded),
        "cache lifetime bypassed"
    );
    floor(&model, Some(160));
    assert!(
        counts(&model) == (1, 1),
        "lifetime rejection cleaned or inserted state"
    );
    assert!(
        model.observe_time(UnixTime::new(159)) == Err(FreshnessError::ClockRollback),
        "lifetime rejection lost floor"
    );
}

#[test]
fn case_r03() {
    for consumed in [false, true] {
        let model = cache(1, 1, 1, 1, 1);
        let input = reg("example.publisher", 1, 100, 200);
        take(model.register(UnixTime::new(100), &input));
        inspect(&model, |active| {
            if let Some(record) = &mut active.records[0] {
                record.consumed = consumed;
            }
        });
        assert!(
            model.register(UnixTime::new(150), &input) == Err(FreshnessError::ReplayDetected),
            "duplicate admitted or masked by capacity"
        );
        assert!(counts(&model) == (1, 1), "duplicate created event");
        floor(&model, Some(150));
    }
}

fn substitutions() -> Vec<ReplayRegistration> {
    (0..7)
        .map(|field| {
            let mut input = challenge("example.publisher", 1, 100, 200);
            match field {
                0 => input.game_id = id("other.game"),
                1 => input.build_id = id("other-build"),
                2 => input.account_scope = id("other-account"),
                3 => input.match_id = id("other-match"),
                4 => input.policy_id = id("other-policy"),
                5 => input.policy_version = PolicyVersion::new(2),
                6 => {
                    input.window = take(ChallengeWindow::new(
                        UnixTime::new(100),
                        UnixTime::new(199),
                        ChallengeLifetime::new(nz64(100)),
                    ))
                }
                _ => panic!("invalid substitution fixture"),
            }
            ReplayRegistration::from_challenge(&input)
        })
        .collect()
}

#[test]
fn case_r04() {
    let model = cache(8, 8, 8, 8, 8);
    let original = reg("example.publisher", 1, 100, 200);
    take(model.register(UnixTime::new(100), &original));
    for variant in substitutions() {
        assert!(
            variant.key() == original.key(),
            "substitution fixture changed key"
        );
        assert!(
            model.register(UnixTime::new(150), &variant) == Err(FreshnessError::ReplayDetected),
            "changed context widened key"
        );
        assert!(counts(&model) == (1, 1), "substitution created event");
    }
}

#[test]
fn case_r05() {
    let model = cache(4, 4, 4, 4, 8);
    take(model.register(UnixTime::new(100), &reg("example.publisher", 1, 100, 200)));
    take(model.register(UnixTime::new(100), &reg("other.publisher", 1, 100, 200)));
    assert!(
        counts(&model) == (2, 2),
        "independent publisher nonce rejected"
    );
}

#[test]
fn case_r06() {
    let model = cache(2, 4, 4, 4, 8);
    let first = reg("example.publisher", 1, 100, 200);
    let second = reg("other.publisher", 2, 100, 200);
    take(model.register(UnixTime::new(100), &first));
    take(model.register(UnixTime::new(100), &second));
    assert!(
        model.register(UnixTime::new(150), &reg("third.publisher", 3, 100, 200))
            == Err(FreshnessError::CapacityExceeded),
        "total cap bypassed"
    );
    assert!(
        counts(&model) == (2, 2),
        "capacity rejection changed counts"
    );
    inspect(&model, |active| {
        assert!(
            active
                .records
                .iter()
                .flatten()
                .any(|r| r.registration == first),
            "first live record evicted"
        );
        assert!(
            active
                .records
                .iter()
                .flatten()
                .any(|r| r.registration == second),
            "second live record evicted"
        );
    });
    floor(&model, Some(150));
}

#[test]
fn case_r07() {
    let model = cache(4, 2, 4, 4, 8);
    for seed in [1, 2] {
        take(model.register(
            UnixTime::new(100),
            &reg("example.publisher", seed, 100, 200),
        ));
    }
    assert!(
        model.register(UnixTime::new(100), &reg("example.publisher", 3, 100, 200))
            == Err(FreshnessError::CapacityExceeded),
        "publisher cap bypassed"
    );
    assert!(
        counts(&model) == (2, 2),
        "publisher rejection inserted state"
    );
    take(model.register(UnixTime::new(100), &reg("other.publisher", 3, 100, 200)));
    assert!(
        counts(&model) == (3, 3),
        "publisher cap leaked across namespaces"
    );
}

#[test]
fn case_r08() {
    let model = cache(4, 4, 1, 4, 8);
    take(model.register(UnixTime::new(100), &reg("example.publisher", 1, 100, 200)));
    assert!(
        model.register(UnixTime::new(100), &reg("example.publisher", 2, 100, 200))
            == Err(FreshnessError::CapacityExceeded),
        "account cap bypassed"
    );
    assert!(counts(&model) == (1, 1), "account rejection inserted state");
    let mut input = challenge("example.publisher", 2, 100, 200);
    input.account_scope = id("account-2");
    take(model.register(
        UnixTime::new(100),
        &ReplayRegistration::from_challenge(&input),
    ));
    take(model.register(UnixTime::new(100), &reg("other.publisher", 3, 100, 200)));
    assert!(counts(&model) == (3, 3), "account cap scoped incorrectly");
}

#[test]
fn case_r09() {
    for (total, publisher, account) in [(4, 4, 1), (4, 1, 4), (1, 4, 4)] {
        let model = cache(total, publisher, account, 4, 8);
        let input = reg("example.publisher", 1, 100, 200);
        take(model.register(UnixTime::new(100), &input));
        take(model.claim(UnixTime::new(150), &input));
        inspect(&model, |active| {
            assert!(
                active.records[0].as_ref().is_some_and(|r| r.consumed),
                "quota fixture did not consume"
            )
        });
        assert!(
            model.register(UnixTime::new(150), &reg("example.publisher", 2, 100, 200))
                == Err(FreshnessError::CapacityExceeded),
            "consumed record released quota"
        );
        assert!(
            counts(&model) == (1, 1),
            "consumed quota rejection inserted state"
        );
    }
}

#[test]
fn case_r10() {
    let model = cache(4, 4, 4, 2, 8);
    for seed in [1, 2] {
        take(model.register(
            UnixTime::new(100),
            &reg("example.publisher", seed, 100, 200),
        ));
    }
    let next = reg("example.publisher", 3, 100, 200);
    assert!(
        model.register(UnixTime::new(159), &next) == Err(FreshnessError::CapacityExceeded),
        "publisher rate expired early"
    );
    assert!(counts(&model) == (2, 2), "rate rejection inserted state");
    floor(&model, Some(159));
    take(model.register(UnixTime::new(160), &next));
    assert!(counts(&model) == (3, 1), "publisher rate boundary differs");
}

#[test]
fn case_r11() {
    let model = cache(1, 1, 1, 4, 2);
    take(model.register(UnixTime::new(100), &reg("publisher-one", 1, 100, 101)));
    take(model.register(UnixTime::new(101), &reg("publisher-two", 2, 101, 102)));
    assert!(
        model.register(UnixTime::new(102), &reg("publisher-three", 3, 102, 103))
            == Err(FreshnessError::CapacityExceeded),
        "global event bound bypassed"
    );
    assert!(
        counts(&model) == (0, 2),
        "global rejection side effects differ"
    );
    floor(&model, Some(102));
}

#[test]
fn case_r12() {
    for duplicate in [false, true] {
        let model = cache(2, 1, 2, 4, 8);
        take(model.register(UnixTime::new(100), &reg("old.publisher", 1, 100, 150)));
        let live = reg("example.publisher", 2, 120, 220);
        take(model.register(UnixTime::new(120), &live));
        let attempted = if duplicate {
            live
        } else {
            reg("example.publisher", 3, 120, 220)
        };
        let error = if duplicate {
            FreshnessError::ReplayDetected
        } else {
            FreshnessError::CapacityExceeded
        };
        assert!(
            model.register(UnixTime::new(160), &attempted) == Err(error),
            "post-cleanup rejection differs"
        );
        assert!(
            counts(&model) == (1, 1),
            "rejection reverted cleanup or inserted event"
        );
        floor(&model, Some(160));
        assert!(
            model.observe_time(UnixTime::new(159)) == Err(FreshnessError::ClockRollback),
            "post-cleanup rejection lost floor"
        );
    }
}

#[test]
fn case_t05() {
    let model = cache(4, 4, 4, 4, 8);
    take(model.register(UnixTime::new(100), &reg("example.publisher", 1, 100, 200)));
    let mut changed = challenge("example.publisher", 1, 100, 200);
    changed.game_id = id("other.game");
    assert!(
        model.claim(
            UnixTime::new(150),
            &ReplayRegistration::from_challenge(&changed)
        ) == Err(FreshnessError::ReplayDetected),
        "claim substitution accepted"
    );
    floor(&model, Some(150));
    assert!(
        model.observe_time(UnixTime::new(149)) == Err(FreshnessError::ClockRollback),
        "claim rejection lost floor"
    );
    take(model.claim(UnixTime::new(150), &reg("example.publisher", 1, 100, 200)));
}

#[test]
fn case_c01() {
    let model = cache(4, 4, 4, 4, 8);
    let input = reg("example.publisher", 1, 100, 200);
    take(model.register(UnixTime::new(100), &input));
    inspect(&model, |active| {
        assert!(
            active.records[0].as_ref().is_some_and(|r| !r.consumed),
            "registration initially consumed"
        )
    });
    let result: Result<(), FreshnessError> = model.claim(UnixTime::new(150), &input);
    take(result);
    inspect(&model, |active| {
        assert!(
            active.records[0]
                .as_ref()
                .is_some_and(|r| r.consumed && r.registration == input),
            "claim did not retain consumed registration"
        )
    });
    assert!(counts(&model) == (1, 1), "claim changed occupied counts");
    floor(&model, Some(150));
}

#[test]
fn case_c02() {
    let model = cache(4, 4, 4, 4, 8);
    let input = reg("example.publisher", 1, 100, 200);
    take(model.register(UnixTime::new(100), &input));
    take(model.claim(UnixTime::new(150), &input));
    assert!(
        model.claim(UnixTime::new(150), &input) == Err(FreshnessError::ReplayDetected),
        "consumed registration reusable"
    );
    assert!(counts(&model) == (1, 1), "claim removed enforcement state");
}

#[test]
fn case_c03() {
    let original = reg("example.publisher", 1, 100, 200);
    for variant in substitutions() {
        let model = cache(4, 4, 4, 4, 8);
        take(model.register(UnixTime::new(100), &original));
        assert!(variant.key() == original.key(), "claim fixture changed key");
        assert!(
            model.claim(UnixTime::new(150), &variant) == Err(FreshnessError::ReplayDetected),
            "claim context not checked"
        );
        assert!(counts(&model) == (1, 1), "wrong claim changed counts");
        inspect(&model, |active| {
            assert!(
                active.records[0].as_ref().is_some_and(|r| !r.consumed),
                "wrong claim burned original"
            )
        });
        take(model.claim(UnixTime::new(150), &original));
    }
}

#[test]
fn case_c04() {
    let model = cache(4, 4, 4, 4, 8);
    let original = reg("example.publisher", 1, 100, 200);
    take(model.register(UnixTime::new(100), &original));
    for missing in [
        reg("example.publisher", 2, 100, 200),
        reg("other.publisher", 1, 100, 200),
    ] {
        assert!(
            model.claim(UnixTime::new(150), &missing) == Err(FreshnessError::StateUnavailable),
            "missing key claim accepted"
        );
        assert!(
            counts(&model) == (1, 1),
            "missing key invalidated unrelated state"
        );
    }
    take(model.claim(UnixTime::new(150), &original));
}

#[test]
fn case_c05() {
    let input = reg("example.publisher", 1, 100, 200);
    for now in [100, 199] {
        let model = cache(4, 4, 4, 4, 8);
        take(model.register(UnixTime::new(100), &input));
        take(model.claim(UnixTime::new(now), &input));
    }
    for now in [200, 201] {
        for registered in [false, true] {
            let model = cache(4, 4, 4, 4, 8);
            if registered {
                take(model.register(UnixTime::new(100), &input));
            }
            assert!(
                model.claim(UnixTime::new(now), &input) == Err(FreshnessError::Expired),
                "expiry did not precede lookup"
            );
            floor(&model, Some(now));
        }
    }
}

#[test]
fn case_c06() {
    let model = cache(4, 4, 4, 4, 8);
    assert!(
        model.claim(UnixTime::new(99), &reg("example.publisher", 1, 100, 200))
            == Err(FreshnessError::NotYetValid),
        "before-issue claim reached lookup"
    );
    floor(&model, Some(99));
    assert!(counts(&model) == (0, 0), "early claim inserted state");
    assert!(
        model.observe_time(UnixTime::new(98)) == Err(FreshnessError::ClockRollback),
        "early claim lost floor"
    );
}

#[test]
fn case_c07() {
    let model = cache(1, 1, 1, 4, 8);
    let input = reg("example.publisher", 1, 100, 200);
    take(model.register(UnixTime::new(100), &input));
    take(model.claim(UnixTime::new(150), &input));
    assert!(
        model.register(UnixTime::new(150), &reg("other.publisher", 2, 100, 200))
            == Err(FreshnessError::CapacityExceeded),
        "unrelated failure fixture accepted"
    );
    assert!(
        model.claim(UnixTime::new(150), &reg("example.publisher", 3, 100, 200))
            == Err(FreshnessError::StateUnavailable),
        "missing claim fixture accepted"
    );
    assert!(
        model.claim(UnixTime::new(150), &input) == Err(FreshnessError::ReplayDetected),
        "later failure released claim"
    );
    assert!(
        counts(&model) == (1, 1),
        "later failure discarded consumed record"
    );
}

#[test]
fn case_c08() {
    let model = cache(4, 4, 4, 4, 8);
    take(model.register(UnixTime::new(100), &reg("old.publisher", 1, 100, 150)));
    let live = reg("example.publisher", 2, 120, 220);
    take(model.register(UnixTime::new(120), &live));
    take(model.claim(UnixTime::new(160), &live));
    inspect(&model, |active| {
        assert!(
            active
                .records
                .iter()
                .flatten()
                .any(|r| r.registration == live && r.consumed),
            "non-collecting claim did not consume"
        )
    });
    assert!(
        counts(&model) == (2, 2),
        "claim secretly collected expired state"
    );
    assert!(
        take(model.purge_expired(UnixTime::new(160))) == 1,
        "explicit purge missed old record"
    );
    assert!(counts(&model) == (1, 1), "explicit cleanup differs");
}

#[test]
fn case_g08() {
    let model = cache(1, 1, 1, 4, 8);
    let old = reg("example.publisher", 1, 100, 200);
    take(model.register(UnixTime::new(100), &old));
    take(model.claim(UnixTime::new(150), &old));
    assert!(
        take(model.purge_expired(UnixTime::new(200))) == 1,
        "consumed registration not purged"
    );
    assert!(
        model.claim(UnixTime::new(200), &old) == Err(FreshnessError::Expired),
        "old input revived after purge"
    );
    assert!(
        model.register(UnixTime::new(200), &old) == Err(FreshnessError::Expired),
        "old input registered after purge"
    );
    let new = reg("example.publisher", 1, 200, 300);
    assert!(old.key() == new.key(), "forgotten-key fixture differs");
    take(model.register(UnixTime::new(200), &new));
    take(model.claim(UnixTime::new(200), &new));
    assert!(
        model.claim(UnixTime::new(200), &new) == Err(FreshnessError::ReplayDetected),
        "new window consumed twice"
    );
}

// Task 6 fragment appended to private tests after the core gate.

fn claim_pair(
    model: &MockReplayCache,
    input: &ReplayRegistration,
) -> Vec<Result<(), FreshnessError>> {
    let start = Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let model = model.clone();
        let input = input.clone();
        let start = start.clone();
        workers.push(std::thread::spawn(move || {
            start.wait();
            model.claim(UnixTime::new(150), &input)
        }));
    }
    start.wait();
    workers
        .into_iter()
        .map(|worker| match worker.join() {
            Ok(result) => result,
            Err(_) => panic!("mock worker failed"),
        })
        .collect()
}

fn check_pair(results: &[Result<(), FreshnessError>], rejection: FreshnessError) {
    assert!(results.len() == 2, "worker count differs");
    assert!(
        results.iter().filter(|r| r.is_ok()).count() == 1,
        "winner count differs"
    );
    assert!(
        results.iter().filter(|r| **r == Err(rejection)).count() == 1,
        "loser classification differs"
    );
}

#[test]
fn case_x01() {
    let model = cache(4, 4, 4, 4, 8);
    let input = reg("example.publisher", 1, 100, 200);
    take(model.register(UnixTime::new(100), &input));
    check_pair(&claim_pair(&model, &input), FreshnessError::ReplayDetected);
    assert!(counts(&model) == (1, 1), "racing claim changed retention");
}

fn registration_pair(model: &MockReplayCache, same_key: bool) -> Vec<Result<(), FreshnessError>> {
    let start = Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for seed in 1..=2 {
        let model = model.clone();
        let start = start.clone();
        let input = reg(
            "example.publisher",
            if same_key { 1 } else { seed },
            100,
            200,
        );
        workers.push(std::thread::spawn(move || {
            start.wait();
            model.register(UnixTime::new(100), &input)
        }));
    }
    start.wait();
    workers
        .into_iter()
        .map(|worker| match worker.join() {
            Ok(result) => result,
            Err(_) => panic!("mock worker failed"),
        })
        .collect()
}

#[test]
fn case_x02() {
    let model = cache(4, 4, 4, 4, 8);
    check_pair(
        &registration_pair(&model, true),
        FreshnessError::ReplayDetected,
    );
    assert!(
        counts(&model) == (1, 1),
        "duplicate registration added quota"
    );
}

#[test]
fn case_x03() {
    for (total, publisher, account, rate, events) in [
        (1, 4, 4, 4, 8),
        (4, 1, 4, 4, 8),
        (4, 4, 1, 4, 8),
        (4, 4, 4, 1, 8),
        (4, 4, 4, 4, 1),
    ] {
        let model = cache(total, publisher, account, rate, events);
        check_pair(
            &registration_pair(&model, false),
            FreshnessError::CapacityExceeded,
        );
        assert!(counts(&model) == (1, 1), "race exceeded admission limit");
    }
}

fn assert_unavailable(model: &MockReplayCache) {
    let input = reg("example.publisher", 1, 100, 200);
    assert!(
        model.observe_time(UnixTime::new(0)) == Err(FreshnessError::StateUnavailable),
        "lost observation resumed"
    );
    assert!(
        model.register(UnixTime::new(0), &input) == Err(FreshnessError::StateUnavailable),
        "lost registration resumed"
    );
    assert!(
        model.claim(UnixTime::new(0), &input) == Err(FreshnessError::StateUnavailable),
        "lost claim resumed"
    );
    assert!(
        model.purge_expired(UnixTime::new(0)) == Err(FreshnessError::StateUnavailable),
        "lost collection resumed"
    );
    assert!(
        model.stats() == Err(FreshnessError::StateUnavailable),
        "lost stats resumed"
    );
}

#[test]
fn case_x04() {
    let model = cache(4, 4, 4, 4, 8);
    let old = model.clone();
    take(model.register(UnixTime::new(100), &reg("example.publisher", 1, 100, 200)));
    take(model.simulate_state_loss());
    assert_unavailable(&model);
    assert_unavailable(&old);
    let guard = take(model.lock_state());
    assert!(
        matches!(*guard, State::Lost),
        "loss retained available state"
    );
}

#[test]
fn case_x05() {
    let model = cache(4, 4, 4, 4, 8);
    let old = model.clone();
    let input = reg("example.publisher", 1, 100, 200);
    take(model.register(UnixTime::new(100), &input));
    take(model.claim(UnixTime::new(150), &input));
    take(model.simulate_state_loss());
    take(old.simulate_state_loss());
    let independent = cache(4, 4, 4, 4, 8);
    take(independent.register(UnixTime::new(100), &input));
    take(independent.claim(UnixTime::new(150), &input));
    assert_unavailable(&old);
    assert_unavailable(&model);
}

fn poison_mock(model: &MockReplayCache) {
    let model = model.clone();
    let worker = std::thread::spawn(move || {
        let _guard = take(model.lock_state());
        panic!("mock poison probe");
    });
    assert!(worker.join().is_err(), "poison probe did not fail");
}

#[test]
fn case_x06() {
    for operation in 0..6 {
        let model = cache(4, 4, 4, 4, 8);
        let input = reg("example.publisher", 1, 100, 200);
        take(model.register(UnixTime::new(100), &input));
        poison_mock(&model);
        let result = match operation {
            0 => model.observe_time(UnixTime::new(150)),
            1 => model.register(UnixTime::new(150), &input),
            2 => model.claim(UnixTime::new(150), &input),
            3 => model.purge_expired(UnixTime::new(150)).map(|_| ()),
            4 => model.stats().map(|_| ()),
            _ => model.simulate_state_loss(),
        };
        assert!(
            result == Err(FreshnessError::StateUnavailable),
            "poison resumed state"
        );
        let guard = match model.shared.state.lock() {
            Err(poisoned) => poisoned.into_inner(),
            Ok(_) => panic!("poison was cleared"),
        };
        assert!(matches!(*guard, State::Lost), "poison retained state");
        drop(guard);
        assert_unavailable(&model);
    }
    let model = cache(4, 4, 4, 4, 8);
    take(model.register(UnixTime::new(99), &reg("example.publisher", 1, 99, 100)));
    inspect(&model, |active| {
        active.floor = Some(UnixTime::new(100));
        let event = match active.events[0].as_mut() {
            Some(event) => event,
            None => panic!("event fixture missing"),
        };
        event.observed_at = UnixTime::new(101);
        assert!(
            collect(active, nz64(60)) == Err(FreshnessError::StateUnavailable),
            "future event was accepted"
        );
        assert!(
            active.records.iter().flatten().count() == 1,
            "corruption check happened after deletion"
        );
    });
    assert!(
        model.purge_expired(UnixTime::new(100)) == Err(FreshnessError::StateUnavailable),
        "corrupt collection succeeded"
    );
    assert_unavailable(&model);
}

#[test]
fn case_x07() {
    for _ in 0..16 {
        let model = cache(4, 4, 4, 4, 8);
        let input = reg("example.publisher", 1, 100, 200);
        take(model.register(UnixTime::new(100), &input));
        let start = Arc::new(std::sync::Barrier::new(3));
        let claim_model = model.clone();
        let claim_start = start.clone();
        let claim = std::thread::spawn(move || {
            claim_start.wait();
            claim_model.claim(UnixTime::new(150), &input)
        });
        let loss_model = model.clone();
        let loss_start = start.clone();
        let loss = std::thread::spawn(move || {
            loss_start.wait();
            loss_model.simulate_state_loss()
        });
        start.wait();
        let claimed = match claim.join() {
            Ok(result) => result,
            Err(_) => panic!("claim worker failed"),
        };
        let lost = match loss.join() {
            Ok(result) => result,
            Err(_) => panic!("loss worker failed"),
        };
        assert!(
            claimed.is_ok() || claimed == Err(FreshnessError::StateUnavailable),
            "claim loss ordering differs"
        );
        take(lost);
        assert_unavailable(&model);
    }
    for loss_first in [true, false] {
        let model = cache(4, 4, 4, 4, 8);
        let input = reg("example.publisher", 1, 100, 200);
        take(model.register(UnixTime::new(100), &input));
        if loss_first {
            take(model.simulate_state_loss());
            assert!(
                model.claim(UnixTime::new(150), &input) == Err(FreshnessError::StateUnavailable),
                "ordered loss resumed"
            );
        } else {
            take(model.claim(UnixTime::new(150), &input));
            take(model.simulate_state_loss());
        }
        assert_unavailable(&model);
    }
}

#[test]
fn case_p03() {
    for (error, debug, display) in [
        (
            FreshnessError::InvalidWindow,
            "InvalidWindow",
            "challenge window is invalid",
        ),
        (
            FreshnessError::LifetimeExceeded,
            "LifetimeExceeded",
            "challenge lifetime exceeds policy",
        ),
        (
            FreshnessError::NotYetValid,
            "NotYetValid",
            "challenge is not yet valid",
        ),
        (FreshnessError::Expired, "Expired", "challenge is expired"),
        (
            FreshnessError::ReplayDetected,
            "ReplayDetected",
            "challenge nonce is already registered or consumed",
        ),
        (
            FreshnessError::ClockRollback,
            "ClockRollback",
            "authoritative clock moved backward",
        ),
        (
            FreshnessError::StateUnavailable,
            "StateUnavailable",
            "freshness state is unavailable",
        ),
        (
            FreshnessError::CapacityExceeded,
            "CapacityExceeded",
            "freshness state capacity is exhausted",
        ),
    ] {
        assert!(format!("{error:?}") == debug, "error debug changed");
        assert!(error.to_string() == display, "error display changed");
        assert!(
            std::error::Error::source(&error).is_none(),
            "error source added"
        );
    }
}

fn diagnostic_model() -> MockReplayCache {
    let model = cache(4, 4, 4, 4, 8);
    let input = reg(
        "mock-publisher-sentinel-7ac91",
        213,
        81985529216486000,
        81985529216486100,
    );
    take(model.register(UnixTime::new(81985529216486000), &input));
    model
}

fn child_output(selector: &str, variable: &str) -> std::process::Output {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(_) => panic!("probe executable missing"),
    };
    match std::process::Command::new(exe)
        .args([selector, "--exact", "--nocapture"])
        .env(variable, "child")
        .output()
    {
        Ok(output) => output,
        Err(_) => panic!("output probe failed"),
    }
}

fn assert_private_output(output: &std::process::Output, expected_code: i32, marker: &str) {
    assert!(
        output.status.code() == Some(expected_code),
        "child status differs"
    );
    let captured = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(captured.contains(marker), "probe marker absent");
    let nonce = challenge(
        "mock-publisher-sentinel-7ac91",
        213,
        81985529216486000,
        81985529216486100,
    )
    .nonce;
    for representation in [
        format!("{:?}", nonce.as_bytes()),
        format!("{:x?}", nonce.as_bytes()),
        nonce
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    ] {
        assert!(
            !captured.contains(&representation),
            "mock output exposed nonce bytes"
        );
    }
    for forbidden in [
        "mock-publisher-sentinel-7ac91",
        "example.game",
        "build-1",
        "account-1",
        "match-1",
        "research-v0",
        "81985529216486000",
        "81985529216486100",
    ] {
        assert!(
            !captured.contains(forbidden),
            "mock output exposed a fixture value"
        );
    }
}

#[test]
fn case_p04() {
    const VARIABLE: &str = "OGIR_M014_P04_CHILD";
    if std::env::var(VARIABLE).ok().as_deref() == Some("child") {
        let model = diagnostic_model();
        println!(
            "{:?} {:?} {:?}",
            model,
            model.shared.limits,
            take(model.stats())
        );
        let denied = model.claim(
            UnixTime::new(81985529216486100),
            &reg(
                "mock-publisher-sentinel-7ac91",
                213,
                81985529216486000,
                81985529216486100,
            ),
        );
        if let Err(error) = denied {
            println!("{error:?} {error}");
        }
        assert!(denied.is_ok(), "mock diagnostic probe");
        return;
    }
    let output = child_output("mock_replay::tests::case_p04", VARIABLE);
    assert_private_output(&output, 101, "mock diagnostic probe");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("MockReplayCache([REDACTED])"),
        "mock formatting was not exercised"
    );
}

#[test]
fn case_p05() {
    const VARIABLE: &str = "OGIR_M014_P05_CHILD";
    if std::env::var(VARIABLE).ok().as_deref() == Some("child") {
        let model = diagnostic_model();
        poison_mock(&model);
        assert_unavailable(&model);
        println!("{model:?}");
        return;
    }
    let output = child_output("mock_replay::tests::case_p05", VARIABLE);
    assert_private_output(&output, 0, "mock poison probe");
}
