// SPDX-License-Identifier: Apache-2.0

//! Atomic challenge registration and replay-claim contracts.

use std::fmt;

use ogir_model::{
    AccountScope, BuildId, ChallengeWindow, FreshnessError, FreshnessLimits, GameId, MatchId,
    Nonce, PolicyId, PolicyVersion, PublisherChallenge, PublisherId, UnixTime,
};

use crate::verification::VerificationBinding;

/// Publisher-scoped replay identity for one challenge nonce.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ReplayKey {
    publisher_id: PublisherId,
    nonce: Nonce,
}

impl fmt::Debug for ReplayKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReplayKey([REDACTED])")
    }
}

impl ReplayKey {
    /// Returns the authenticated publisher namespace.
    #[must_use]
    pub fn publisher_id(&self) -> &PublisherId {
        &self.publisher_id
    }

    /// Returns the fixed-size nonce value.
    #[must_use]
    pub const fn nonce(&self) -> Nonce {
        self.nonce
    }
}

/// Context retained with a replay record but excluded from replay identity.
#[derive(Clone, PartialEq, Eq)]
pub struct ChallengeBinding {
    game_id: GameId,
    build_id: BuildId,
    account_scope: AccountScope,
    match_id: MatchId,
    policy_id: PolicyId,
    policy_version: PolicyVersion,
}

impl fmt::Debug for ChallengeBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChallengeBinding([REDACTED])")
    }
}

impl ChallengeBinding {
    /// Returns the bound game identifier.
    #[must_use]
    pub fn game_id(&self) -> &GameId {
        &self.game_id
    }

    /// Returns the bound build identifier.
    #[must_use]
    pub fn build_id(&self) -> &BuildId {
        &self.build_id
    }

    /// Returns the privacy-sensitive publisher account scope.
    #[must_use]
    pub fn account_scope(&self) -> &AccountScope {
        &self.account_scope
    }

    /// Returns the privacy-sensitive match identifier.
    #[must_use]
    pub fn match_id(&self) -> &MatchId {
        &self.match_id
    }

    /// Returns the bound policy identifier.
    #[must_use]
    pub fn policy_id(&self) -> &PolicyId {
        &self.policy_id
    }

    /// Returns the bound policy version.
    #[must_use]
    pub const fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }
}

/// Complete replay-state registration derived from a publisher challenge.
#[derive(Clone, PartialEq, Eq)]
pub struct ReplayRegistration {
    key: ReplayKey,
    binding: ChallengeBinding,
    window: ChallengeWindow,
}

impl fmt::Debug for ReplayRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReplayRegistration([REDACTED])")
    }
}

impl ReplayRegistration {
    /// Copies replay identity, binding, and window fields from `challenge`.
    #[must_use]
    pub fn from_challenge(challenge: &PublisherChallenge) -> Self {
        Self {
            key: ReplayKey {
                publisher_id: challenge.publisher_id.clone(),
                nonce: challenge.nonce,
            },
            binding: ChallengeBinding {
                game_id: challenge.game_id.clone(),
                build_id: challenge.build_id.clone(),
                account_scope: challenge.account_scope.clone(),
                match_id: challenge.match_id.clone(),
                policy_id: challenge.policy_id.clone(),
                policy_version: challenge.policy_version,
            },
            window: challenge.window,
        }
    }

    /// Returns the exact publisher/nonce replay key.
    #[must_use]
    pub fn key(&self) -> &ReplayKey {
        &self.key
    }

    /// Returns the context that must match during claim.
    #[must_use]
    pub fn binding(&self) -> &ChallengeBinding {
        &self.binding
    }

    /// Returns the registered validity window.
    #[must_use]
    pub const fn window(&self) -> ChallengeWindow {
        self.window
    }
}

/// Atomic persistence boundary for challenge issuance and replay claims.
///
/// Implementations are publisher-controlled trusted infrastructure. Each
/// method must update/check its authoritative-time high-water mark and complete
/// its state transition atomically and durably before returning success.
pub trait ReplayStore: Send + Sync {
    /// Atomically checks and advances the authoritative-time high-water mark.
    ///
    /// # Errors
    ///
    /// Returns [`FreshnessError::ClockRollback`] when `now` is below the
    /// persisted floor, or [`FreshnessError::StateUnavailable`] when the floor
    /// cannot be trusted or durably advanced.
    fn observe_time(&self, now: UnixTime) -> Result<(), FreshnessError>;

    /// Atomically validates limits and registers an issued challenge.
    ///
    /// # Errors
    ///
    /// Returns a [`FreshnessError`] when time rolls back, state is unavailable,
    /// the key already exists, the window violates policy, or capacity/rate
    /// bounds are exhausted. Failure never permits stateless fallback.
    fn register(
        &self,
        now: UnixTime,
        registration: &ReplayRegistration,
        limits: FreshnessLimits,
    ) -> Result<(), FreshnessError>;

    /// Atomically changes one matching issued record to consumed.
    ///
    /// # Errors
    ///
    /// Returns a [`FreshnessError`] for rollback, unavailable/missing state,
    /// window failure, binding mismatch, or an already-consumed key. A
    /// successful claim is irreversible.
    fn claim(&self, now: UnixTime, registration: &ReplayRegistration)
    -> Result<(), FreshnessError>;

    /// Atomically removes replay records and issuance-rate history whose
    /// enforcement windows ended at the persisted time floor.
    ///
    /// The returned count includes removed replay records, not rate events.
    ///
    /// # Errors
    ///
    /// Returns [`FreshnessError::ClockRollback`] or
    /// [`FreshnessError::StateUnavailable`] without deleting state when time or
    /// storage cannot be trusted.
    fn purge_expired(&self, now: UnixTime) -> Result<usize, FreshnessError>;
}

/// Proof that one registered challenge passed the ordered verifier freshness
/// and relying-party-context gates plus the atomic claim.
///
/// ```compile_fail
/// use ogir_verifier::FreshnessChecked;
///
/// let forged = FreshnessChecked {
///     binding: panic!("cannot forge verifier binding"),
/// };
/// ```
///
/// A raw store claim cannot be used as a capability-producing shortcut:
///
/// ```compile_fail
/// use ogir_model::{FreshnessError, PublisherChallenge, UnixTime};
/// use ogir_verifier::{FreshnessChecked, FreshnessGuard, ReplayStore};
///
/// fn bypass<S: ReplayStore + ?Sized>(
///     guard: &FreshnessGuard<'_, S>,
///     now: UnixTime,
///     challenge: &PublisherChallenge,
/// ) -> Result<FreshnessChecked, FreshnessError> {
///     guard.claim(now, challenge)
/// }
/// ```
#[must_use]
pub struct FreshnessChecked {
    binding: VerificationBinding,
}

impl FreshnessChecked {
    pub(crate) fn binding(&self) -> &VerificationBinding {
        &self.binding
    }
}

impl fmt::Debug for FreshnessChecked {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FreshnessChecked([REDACTED])")
    }
}

#[cfg(test)]
pub(crate) fn test_freshness_checked(binding: VerificationBinding) -> FreshnessChecked {
    FreshnessChecked { binding }
}

/// Deep freshness boundary over one trusted replay-store implementation.
pub struct FreshnessGuard<'store, Store: ?Sized> {
    store: &'store Store,
    limits: FreshnessLimits,
}

impl<Store: ?Sized> fmt::Debug for FreshnessGuard<'_, Store> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FreshnessGuard([REDACTED])")
    }
}

impl<'store, Store: ReplayStore + ?Sized> FreshnessGuard<'store, Store> {
    /// Binds a replay store to an explicit freshness policy.
    #[must_use]
    pub const fn new(store: &'store Store, limits: FreshnessLimits) -> Self {
        Self { store, limits }
    }

    /// Durably observes authoritative time, then evaluates a challenge window.
    ///
    /// # Errors
    ///
    /// Propagates time-floor/store failures before returning strict window
    /// errors. The observed time remains persisted even when the window fails.
    pub fn evaluate_window(
        &self,
        now: UnixTime,
        challenge: &PublisherChallenge,
    ) -> Result<(), FreshnessError> {
        self.store.observe_time(now)?;
        challenge.window.evaluate(now)
    }

    /// Validates and atomically registers a challenge before it is returned.
    ///
    /// # Errors
    ///
    /// Propagates strict window failures and every error returned by
    /// [`ReplayStore::register`].
    pub fn register(
        &self,
        now: UnixTime,
        challenge: &PublisherChallenge,
    ) -> Result<(), FreshnessError> {
        self.store.register(
            now,
            &ReplayRegistration::from_challenge(challenge),
            self.limits,
        )
    }

    /// Atomically consumes a registered challenge without creating a capability.
    ///
    /// # Errors
    ///
    /// Propagates strict window failures and every error returned by
    /// [`ReplayStore::claim`]. External callers cannot use this raw operation
    /// to mint [`FreshnessChecked`].
    pub fn claim(
        &self,
        now: UnixTime,
        challenge: &PublisherChallenge,
    ) -> Result<(), FreshnessError> {
        self.store
            .claim(now, &ReplayRegistration::from_challenge(challenge))
    }

    /// Removes only replay and rate-limit state whose enforcement windows ended
    /// at the replay store's time floor.
    ///
    /// The returned count includes removed replay records, not rate events.
    ///
    /// # Errors
    ///
    /// Propagates rollback or state failures from
    /// [`ReplayStore::purge_expired`].
    pub fn purge_expired(&self, now: UnixTime) -> Result<usize, FreshnessError> {
        self.store.purge_expired(now)
    }
}
