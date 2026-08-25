// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Arc, Mutex};

use ogir_model::{ChallengeWindow, FreshnessError, FreshnessLimits, PublisherId, UnixTime};
use ogir_verifier::{ChallengeBinding, ReplayKey, ReplayRegistration, ReplayStore};

#[derive(Debug, Clone)]
pub struct ReferenceReplayStore {
    state: Arc<Mutex<State>>,
}

#[derive(Debug, Clone)]
struct State {
    availability: Availability,
    high_water: Option<UnixTime>,
    records: HashMap<ReplayKey, StoredRecord>,
    issuance_events: Vec<(UnixTime, PublisherId)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Availability {
    Available,
    Unavailable,
    Missing,
    Corrupt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StoredState {
    Issued,
    Consumed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredRecord {
    binding: ChallengeBinding,
    window: ChallengeWindow,
    state: StoredState,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    high_water: Option<UnixTime>,
    records: HashMap<ReplayKey, StoredRecord>,
    issuance_events: Vec<(UnixTime, PublisherId)>,
}

impl ReferenceReplayStore {
    fn with_availability(availability: Availability) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                availability,
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
            state: Arc::new(Mutex::new(State {
                availability: Availability::Available,
                high_water: snapshot.high_water,
                records: snapshot.records,
                issuance_events: snapshot.issuance_events,
            })),
        }
    }

    pub fn snapshot(&self) -> Result<Snapshot, FreshnessError> {
        self.with_state(|state| {
            Ok(Snapshot {
                high_water: state.high_water,
                records: state.records.clone(),
                issuance_events: state.issuance_events.clone(),
            })
        })
    }

    pub fn set_unavailable(&self) -> Result<(), FreshnessError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| FreshnessError::StateUnavailable)?;
        state.availability = Availability::Unavailable;
        Ok(())
    }

    pub fn high_water(&self) -> Result<Option<UnixTime>, FreshnessError> {
        self.with_state(|state| Ok(state.high_water))
    }

    pub fn record_count(&self) -> Result<usize, FreshnessError> {
        self.with_state(|state| Ok(state.records.len()))
    }

    pub fn contains(&self, key: &ReplayKey) -> Result<bool, FreshnessError> {
        self.with_state(|state| Ok(state.records.contains_key(key)))
    }

    fn with_state<T>(
        &self,
        operation: impl FnOnce(&mut State) -> Result<T, FreshnessError>,
    ) -> Result<T, FreshnessError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| FreshnessError::StateUnavailable)?;
        if state.availability != Availability::Available {
            return Err(FreshnessError::StateUnavailable);
        }
        operation(&mut state)
    }
}

fn observe_time(state: &mut State, now: UnixTime) -> Result<(), FreshnessError> {
    if state.high_water.is_some_and(|high_water| now < high_water) {
        return Err(FreshnessError::ClockRollback);
    }
    state.high_water = Some(now);
    Ok(())
}

fn purge_expired_records(state: &mut State) -> Result<usize, FreshnessError> {
    let high_water = state.high_water.ok_or(FreshnessError::StateUnavailable)?;
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

            let _removed = purge_expired_records(state)?;
            if state.records.contains_key(registration.key()) {
                return Err(FreshnessError::ReplayDetected);
            }

            for (event_time, _) in &state.issuance_events {
                if now.seconds().checked_sub(event_time.seconds()).is_none() {
                    return Err(FreshnessError::ClockRollback);
                }
            }
            let rate_window = limits.issuance_rate_window_seconds().get();
            state.issuance_events.retain(|(event_time, _)| {
                now.seconds()
                    .checked_sub(event_time.seconds())
                    .is_some_and(|age| age < rate_window)
            });

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
                .filter(|(_, event_publisher)| event_publisher == publisher)
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
            state
                .issuance_events
                .push((now, registration.key().publisher_id().clone()));
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
            purge_expired_records(state)
        })
    }
}
