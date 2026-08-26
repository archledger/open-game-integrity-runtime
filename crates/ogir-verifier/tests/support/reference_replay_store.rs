// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::thread;

use ogir_model::{ChallengeWindow, FreshnessError, FreshnessLimits, PublisherId, UnixTime};
use ogir_verifier::{ChallengeBinding, ReplayKey, ReplayRegistration, ReplayStore};

#[derive(Clone)]
pub struct ReferenceReplayStore {
    availability: Arc<Mutex<Availability>>,
    state: Arc<Mutex<State>>,
}

struct State {
    high_water: Option<UnixTime>,
    records: HashMap<ReplayKey, StoredRecord>,
    issuance_events: Vec<IssuanceEvent>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Availability {
    Available,
    Unavailable,
    Missing,
    Corrupt,
}

#[derive(Clone, PartialEq, Eq)]
enum StoredState {
    Issued,
    Consumed,
}

#[derive(Clone, PartialEq, Eq)]
struct StoredRecord {
    binding: ChallengeBinding,
    window: ChallengeWindow,
    state: StoredState,
}

struct IssuanceEvent {
    observed_at: UnixTime,
    publisher_id: PublisherId,
    retain_for_seconds: u64,
}

#[derive(Clone)]
pub struct Snapshot {
    state: Arc<Mutex<State>>,
}

impl fmt::Debug for ReferenceReplayStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReferenceReplayStore([REDACTED])")
    }
}

impl fmt::Debug for Snapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Snapshot([REDACTED])")
    }
}

impl ReferenceReplayStore {
    fn with_availability(availability: Availability) -> Self {
        Self {
            availability: Arc::new(Mutex::new(availability)),
            state: Arc::new(Mutex::new(State {
                high_water: None,
                records: HashMap::new(),
                issuance_events: Vec::new(),
            })),
        }
    }

    pub fn available() -> Self {
        Self::with_availability(Availability::Available)
    }

    pub fn unavailable() -> Self {
        Self::with_availability(Availability::Unavailable)
    }

    pub fn missing() -> Self {
        Self::with_availability(Availability::Missing)
    }

    pub fn corrupt() -> Self {
        Self::with_availability(Availability::Corrupt)
    }

    pub fn reopen(snapshot: Snapshot) -> Self {
        Self {
            availability: Arc::new(Mutex::new(Availability::Available)),
            state: snapshot.state,
        }
    }

    pub fn snapshot(&self) -> Result<Snapshot, FreshnessError> {
        self.with_state(|_| {
            Ok(Snapshot {
                state: Arc::clone(&self.state),
            })
        })
    }

    pub fn set_unavailable(&self) -> Result<(), FreshnessError> {
        let mut availability = self
            .availability
            .lock()
            .map_err(|_| FreshnessError::StateUnavailable)?;
        *availability = Availability::Unavailable;
        Ok(())
    }

    pub fn poison_availability_lock(&self) {
        poison_mutex(&self.availability);
    }

    pub fn poison_state_lock(&self) {
        poison_mutex(&self.state);
    }

    pub fn high_water(&self) -> Result<Option<UnixTime>, FreshnessError> {
        self.with_state(|state| Ok(state.high_water))
    }

    pub fn record_count(&self) -> Result<usize, FreshnessError> {
        self.with_state(|state| Ok(state.records.len()))
    }

    pub fn issuance_event_count(&self) -> Result<usize, FreshnessError> {
        self.with_state(|state| Ok(state.issuance_events.len()))
    }

    pub fn contains(&self, key: &ReplayKey) -> Result<bool, FreshnessError> {
        self.with_state(|state| Ok(state.records.contains_key(key)))
    }

    fn with_state<T>(
        &self,
        operation: impl FnOnce(&mut State) -> Result<T, FreshnessError>,
    ) -> Result<T, FreshnessError> {
        let availability = self
            .availability
            .lock()
            .map_err(|_| FreshnessError::StateUnavailable)?;
        if *availability != Availability::Available {
            return Err(FreshnessError::StateUnavailable);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| FreshnessError::StateUnavailable)?;
        operation(&mut state)
    }
}

fn poison_mutex<Value: Send + 'static>(mutex: &Arc<Mutex<Value>>) {
    let mutex = Arc::clone(mutex);
    let handle = thread::spawn(move || {
        let _guard = match mutex.lock() {
            Ok(guard) => guard,
            Err(_) => panic!("fixture mutex was already poisoned"),
        };
        panic!("intentional replay-store lock poison");
    });
    assert!(
        handle.join().is_err(),
        "intentional poison worker unexpectedly succeeded"
    );
}

fn observe_time(state: &mut State, now: UnixTime) -> Result<(), FreshnessError> {
    if state.high_water.is_some_and(|high_water| now < high_water) {
        return Err(FreshnessError::ClockRollback);
    }
    state.high_water = Some(now);
    Ok(())
}

fn purge_expired_state(state: &mut State) -> Result<usize, FreshnessError> {
    let high_water = state.high_water.ok_or(FreshnessError::StateUnavailable)?;
    if state
        .issuance_events
        .iter()
        .any(|event| event.observed_at > high_water)
    {
        return Err(FreshnessError::StateUnavailable);
    }
    state.issuance_events.retain(|event| {
        high_water
            .seconds()
            .checked_sub(event.observed_at.seconds())
            .is_some_and(|age| age < event.retain_for_seconds)
    });

    let before = state.records.len();
    state
        .records
        .retain(|_, record| record.window.expires_at() > high_water);
    before
        .checked_sub(state.records.len())
        .ok_or(FreshnessError::StateUnavailable)
}

impl ReplayStore for ReferenceReplayStore {
    fn observe_time(&self, now: UnixTime) -> Result<(), FreshnessError> {
        self.with_state(|state| observe_time(state, now))
    }

    fn register(
        &self,
        now: UnixTime,
        registration: &ReplayRegistration,
        limits: FreshnessLimits,
    ) -> Result<(), FreshnessError> {
        self.with_state(|state| {
            observe_time(state, now)?;

            let window = registration.window();
            let duration = window
                .expires_at()
                .seconds()
                .checked_sub(window.issued_at().seconds())
                .ok_or(FreshnessError::InvalidWindow)?;
            if duration == 0 {
                return Err(FreshnessError::InvalidWindow);
            }
            if duration > limits.max_lifetime().seconds().get() {
                return Err(FreshnessError::LifetimeExceeded);
            }
            window.evaluate(now)?;

            let _removed = purge_expired_state(state)?;
            if state.records.contains_key(registration.key()) {
                return Err(FreshnessError::ReplayDetected);
            }

            let total = state.records.len();
            let publisher = registration.key().publisher_id();
            let account = registration.binding().account_scope();
            let publisher_total = state
                .records
                .keys()
                .filter(|key| key.publisher_id() == publisher)
                .count();
            let account_total = state
                .records
                .iter()
                .filter(|(key, record)| {
                    key.publisher_id() == publisher && record.binding.account_scope() == account
                })
                .count();
            let issuance_total = state
                .issuance_events
                .iter()
                .filter(|event| &event.publisher_id == publisher)
                .count();

            if total >= limits.max_outstanding_total().get()
                || publisher_total >= limits.max_outstanding_per_publisher().get()
                || account_total >= limits.max_outstanding_per_account().get()
                || issuance_total >= limits.max_issuances_per_publisher().get()
            {
                return Err(FreshnessError::CapacityExceeded);
            }

            match state.records.entry(registration.key().clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(StoredRecord {
                        binding: registration.binding().clone(),
                        window,
                        state: StoredState::Issued,
                    });
                }
                Entry::Occupied(_) => return Err(FreshnessError::ReplayDetected),
            }
            state.issuance_events.push(IssuanceEvent {
                observed_at: now,
                publisher_id: registration.key().publisher_id().clone(),
                retain_for_seconds: limits.issuance_rate_window_seconds().get(),
            });
            Ok(())
        })
    }

    fn claim(
        &self,
        now: UnixTime,
        registration: &ReplayRegistration,
    ) -> Result<(), FreshnessError> {
        self.with_state(|state| {
            observe_time(state, now)?;
            registration.window().evaluate(now)?;

            let record = state
                .records
                .get_mut(registration.key())
                .ok_or(FreshnessError::StateUnavailable)?;
            if &record.binding != registration.binding()
                || record.window != registration.window()
                || record.state == StoredState::Consumed
            {
                return Err(FreshnessError::ReplayDetected);
            }

            record.state = StoredState::Consumed;
            Ok(())
        })
    }

    fn purge_expired(&self, now: UnixTime) -> Result<usize, FreshnessError> {
        self.with_state(|state| {
            observe_time(state, now)?;
            purge_expired_state(state)
        })
    }
}
