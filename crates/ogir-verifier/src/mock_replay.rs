// SPDX-License-Identifier: Apache-2.0

//! Bounded, volatile replay transitions for isolated research runs.
//!
//! This module grants no verifier capability and does not implement the durable
//! replay-store contract. Callers supply validated inputs and modeled time.
//!
//! A fresh cache is an isolated experiment and exposes only raw mock results:
//!
//! ```
//! use std::num::{NonZeroU64, NonZeroUsize};
//! use ogir_model::{ChallengeLifetime, FreshnessLimits};
//! use ogir_verifier::mock_replay::{MockReplayCache, MockReplayLimits};
//! let policy = FreshnessLimits::new(
//!     ChallengeLifetime::new(NonZeroU64::MIN),
//!     NonZeroUsize::MIN, NonZeroUsize::MIN, NonZeroUsize::MIN,
//!     NonZeroU64::MIN, NonZeroUsize::MIN,
//! );
//! let cache = MockReplayCache::new_research_run(
//!     MockReplayLimits::new(policy, NonZeroUsize::MIN),
//! )?;
//! assert!(cache.stats()?.retained_records() == 0);
//! # Ok::<(), ogir_model::FreshnessError>(())
//! ```
//!
//! This volatile model cannot satisfy the durable replay-store bound:
//!
//! ```compile_fail
//! use ogir_verifier::{ReplayStore, mock_replay::MockReplayCache};
//! fn requires_durable<T: ReplayStore>() {}
//! requires_durable::<MockReplayCache>();
//! ```
//!
//! Raw mock success cannot produce a freshness capability:
//!
//! ```compile_fail
//! use ogir_model::{FreshnessError, UnixTime};
//! use ogir_verifier::{FreshnessChecked, ReplayRegistration, mock_replay::MockReplayCache};
//! fn forged(cache: &MockReplayCache, registration: &ReplayRegistration)
//!     -> Result<FreshnessChecked, FreshnessError> {
//!     cache.claim(UnixTime::new(100), registration)
//! }
//! ```

use std::fmt;
use std::mem::size_of;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::{Arc, Mutex, MutexGuard};

use ogir_model::{FreshnessError, FreshnessLimits, PublisherId, UnixTime};

use crate::ReplayRegistration;

/// Immutable policy for one research run, without implicit defaults.
#[derive(Clone, Copy)]
pub struct MockReplayLimits {
    freshness: FreshnessLimits,
    max_retained_issuances: NonZeroUsize,
}

impl MockReplayLimits {
    /// Selects all freshness limits and the global retained-event bound.
    #[must_use]
    pub const fn new(freshness: FreshnessLimits, max_retained_issuances: NonZeroUsize) -> Self {
        Self {
            freshness,
            max_retained_issuances,
        }
    }
    /// Returns the immutable freshness policy.
    #[must_use]
    pub const fn freshness(&self) -> FreshnessLimits {
        self.freshness
    }
    /// Returns the global retained issuance-event bound.
    #[must_use]
    pub const fn max_retained_issuances(&self) -> NonZeroUsize {
        self.max_retained_issuances
    }
}

impl fmt::Debug for MockReplayLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MockReplayLimits([REDACTED])")
    }
}

/// Shared in-process model; cloning never snapshots or restores state.
#[derive(Clone)]
pub struct MockReplayCache {
    shared: Arc<Shared>,
}

impl fmt::Debug for MockReplayCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MockReplayCache([REDACTED])")
    }
}

/// Aggregate occupied-slot counts, including entries awaiting modeled cleanup.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MockReplayStats {
    retained_records: usize,
    retained_issuances: usize,
}

impl MockReplayStats {
    /// Returns the number of retained issued and consumed registrations.
    #[must_use]
    pub const fn retained_records(&self) -> usize {
        self.retained_records
    }
    /// Returns the number of retained issuance events.
    #[must_use]
    pub const fn retained_issuances(&self) -> usize {
        self.retained_issuances
    }
}

impl fmt::Debug for MockReplayStats {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MockReplayStats([REDACTED])")
    }
}

struct Shared {
    limits: MockReplayLimits,
    state: Mutex<State>,
}
enum State {
    Available(Active),
    Lost,
}
struct Active {
    floor: Option<UnixTime>,
    records: Vec<Option<Record>>,
    events: Vec<Option<Event>>,
}
struct Record {
    registration: ReplayRegistration,
    consumed: bool,
}
struct Event {
    publisher: PublisherId,
    observed_at: UnixTime,
}

impl MockReplayCache {
    /// Starts an independent volatile experiment, never a recovery operation.
    ///
    /// # Errors
    /// Returns `CapacityExceeded` for checked-budget or slot-reservation failure.
    /// Ordinary Arc and string allocation failures are not recoverable here.
    pub fn new_research_run(limits: MockReplayLimits) -> Result<Self, FreshnessError> {
        let r = limits.freshness().max_outstanding_total().get();
        let e = limits.max_retained_issuances().get();
        checked_budget(r, e)?;
        let records = slots(r)?;
        let events = slots(e)?;
        Ok(Self {
            shared: Arc::new(Shared {
                limits,
                state: Mutex::new(State::Available(Active {
                    floor: None,
                    records,
                    events,
                })),
            }),
        })
    }

    /// Reads aggregates without observing time or collecting expired state.
    ///
    /// # Errors
    /// Returns `StateUnavailable` for lost or poisoned state.
    pub fn stats(&self) -> Result<MockReplayStats, FreshnessError> {
        let state = self.lock_state()?;
        match &*state {
            State::Available(active) => Ok(MockReplayStats {
                retained_records: active.records.iter().flatten().count(),
                retained_issuances: active.events.iter().flatten().count(),
            }),
            State::Lost => Err(FreshnessError::StateUnavailable),
        }
    }

    /// Drops shared state permanently; repeated unpoisoned loss is harmless.
    ///
    /// # Errors
    /// Returns `StateUnavailable` when the mutex is poisoned.
    pub fn simulate_state_loss(&self) -> Result<(), FreshnessError> {
        *self.lock_state()? = State::Lost;
        Ok(())
    }

    /// Observes modeled time without expiry collection.
    ///
    /// # Errors
    /// Returns `ClockRollback` or `StateUnavailable` when the run cannot advance.
    pub fn observe_time(&self, now: UnixTime) -> Result<(), FreshnessError> {
        let mut state = self.lock_state()?;
        let State::Available(active) = &mut *state else {
            return Err(FreshnessError::StateUnavailable);
        };
        advance(active, now)
    }

    /// Collects expired slots and returns only the removed registration count.
    ///
    /// # Errors
    /// Returns `ClockRollback` or `StateUnavailable` for lost, poisoned or
    /// internally inconsistent state.
    pub fn purge_expired(&self, now: UnixTime) -> Result<usize, FreshnessError> {
        let mut state = self.lock_state()?;
        let State::Available(active) = &mut *state else {
            return Err(FreshnessError::StateUnavailable);
        };
        advance(active, now)?;
        match collect(
            active,
            self.shared
                .limits
                .freshness()
                .issuance_rate_window_seconds(),
        ) {
            Ok(removed) => Ok(removed),
            Err(error) => {
                *state = State::Lost;
                Err(error)
            }
        }
    }

    /// Registers one exact input and issuance event under the fixed policy.
    ///
    /// # Errors
    /// Returns freshness window, rollback, duplicate, capacity or unavailable
    /// errors. Time observation precedes all later rejection; eligible cleanup
    /// precedes duplicate and quota checks and remains applied on rejection.
    pub fn register(
        &self,
        now: UnixTime,
        registration: &ReplayRegistration,
    ) -> Result<(), FreshnessError> {
        let mut state = self.lock_state()?;
        let State::Available(active) = &mut *state else {
            return Err(FreshnessError::StateUnavailable);
        };
        let limits = self.shared.limits.freshness();
        advance(active, now)?;
        let lifetime = registration
            .window()
            .expires_at()
            .seconds()
            .checked_sub(registration.window().issued_at().seconds())
            .filter(|duration| *duration != 0)
            .ok_or(FreshnessError::InvalidWindow)?;
        if lifetime > limits.max_lifetime().seconds().get() {
            return Err(FreshnessError::LifetimeExceeded);
        }
        registration.window().evaluate(now)?;
        if let Err(error) = collect(active, limits.issuance_rate_window_seconds()) {
            *state = State::Lost;
            return Err(error);
        }
        if active
            .records
            .iter()
            .flatten()
            .any(|r| r.registration.key() == registration.key())
        {
            return Err(FreshnessError::ReplayDetected);
        }
        if active.records.iter().flatten().count() >= limits.max_outstanding_total().get() {
            return Err(FreshnessError::CapacityExceeded);
        }
        let publisher = registration.key().publisher_id();
        if active
            .records
            .iter()
            .flatten()
            .filter(|r| r.registration.key().publisher_id() == publisher)
            .count()
            >= limits.max_outstanding_per_publisher().get()
        {
            return Err(FreshnessError::CapacityExceeded);
        }
        if active
            .records
            .iter()
            .flatten()
            .filter(|r| {
                r.registration.key().publisher_id() == publisher
                    && r.registration.binding().account_scope()
                        == registration.binding().account_scope()
            })
            .count()
            >= limits.max_outstanding_per_account().get()
        {
            return Err(FreshnessError::CapacityExceeded);
        }
        if active
            .events
            .iter()
            .flatten()
            .filter(|e| &e.publisher == publisher)
            .count()
            >= limits.max_issuances_per_publisher().get()
        {
            return Err(FreshnessError::CapacityExceeded);
        }
        if active.events.iter().flatten().count()
            >= self.shared.limits.max_retained_issuances().get()
        {
            return Err(FreshnessError::CapacityExceeded);
        }
        let record_index = active
            .records
            .iter()
            .position(Option::is_none)
            .ok_or(FreshnessError::StateUnavailable)?;
        let event_index = active
            .events
            .iter()
            .position(Option::is_none)
            .ok_or(FreshnessError::StateUnavailable)?;
        // Prepare both owned payloads before either occupied-slot write.
        let record = Record {
            registration: registration.clone(),
            consumed: false,
        };
        let event = Event {
            publisher: publisher.clone(),
            observed_at: now,
        };
        active.records[record_index] = Some(record);
        active.events[event_index] = Some(event);
        Ok(())
    }

    /// Irreversibly consumes an exact registration, returning only a mock result.
    /// No expiry cleanup or verifier-capability construction occurs.
    ///
    /// # Errors
    /// Returns rollback/window errors before lookup, `StateUnavailable` for
    /// missing/lost/poisoned state, or `ReplayDetected` for mismatched or
    /// consumed registrations. Later failure never releases a claim.
    pub fn claim(
        &self,
        now: UnixTime,
        registration: &ReplayRegistration,
    ) -> Result<(), FreshnessError> {
        let mut state = self.lock_state()?;
        let State::Available(active) = &mut *state else {
            return Err(FreshnessError::StateUnavailable);
        };
        advance(active, now)?;
        registration.window().evaluate(now)?;
        let record = active
            .records
            .iter_mut()
            .flatten()
            .find(|r| r.registration.key() == registration.key())
            .ok_or(FreshnessError::StateUnavailable)?;
        if record.registration.binding() != registration.binding()
            || record.registration.window() != registration.window()
            || record.consumed
        {
            return Err(FreshnessError::ReplayDetected);
        }
        record.consumed = true;
        Ok(())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, State>, FreshnessError> {
        match self.shared.state.lock() {
            Ok(guard) => Ok(guard),
            Err(poisoned) => {
                *poisoned.into_inner() = State::Lost;
                Err(FreshnessError::StateUnavailable)
            }
        }
    }
}

fn advance(active: &mut Active, now: UnixTime) -> Result<(), FreshnessError> {
    if active.floor.is_some_and(|floor| now < floor) {
        return Err(FreshnessError::ClockRollback);
    }
    active.floor = Some(now);
    Ok(())
}

fn collect(active: &mut Active, rate_window: NonZeroU64) -> Result<usize, FreshnessError> {
    let floor = active.floor.ok_or(FreshnessError::StateUnavailable)?;
    if active
        .events
        .iter()
        .flatten()
        .any(|event| event.observed_at > floor)
    {
        return Err(FreshnessError::StateUnavailable);
    }
    let mut removed = 0;
    for slot in &mut active.records {
        if slot
            .as_ref()
            .is_some_and(|r| r.registration.window().expires_at() <= floor)
        {
            *slot = None;
            removed += 1;
        }
    }
    for slot in &mut active.events {
        if slot.as_ref().is_some_and(|event| {
            floor
                .seconds()
                .checked_sub(event.observed_at.seconds())
                .is_some_and(|age| age >= rate_window.get())
        }) {
            *slot = None;
        }
    }
    Ok(removed)
}

fn slots<T>(n: usize) -> Result<Vec<Option<T>>, FreshnessError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(n)
        .map_err(|_| FreshnessError::CapacityExceeded)?;
    result.resize_with(n, || None);
    Ok(result)
}

fn checked_budget(r: usize, e: usize) -> Result<(), FreshnessError> {
    let storage = r.checked_mul(size_of::<Option<Record>>()).and_then(|a| {
        e.checked_mul(size_of::<Option<Event>>())
            .and_then(|b| a.checked_add(b))
    });
    let payload = r
        .checked_mul(768)
        .and_then(|a| e.checked_mul(128).and_then(|b| a.checked_add(b)));
    match (storage, payload) {
        (Some(_), Some(_)) => Ok(()),
        _ => Err(FreshnessError::CapacityExceeded),
    }
}

#[cfg(test)]
mod tests;
