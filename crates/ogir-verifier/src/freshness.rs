// SPDX-License-Identifier: Apache-2.0

//! Atomic challenge registration and replay-claim contracts.

use std::fmt;

use ogir_model::{
    AccountScope, BuildId, ChallengeWindow, FreshnessError, FreshnessLimits, GameId, MatchId,
    Nonce, PolicyId, PolicyVersion, PublisherChallenge, PublisherId, UnixTime,
};

/// Publisher-scoped replay identity for one challenge nonce.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ReplayKey {
    publisher_id: PublisherId,
    nonce: Nonce,
}

impl fmt::Debug for ReplayKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayKey")
            .field("publisher_id", &self.publisher_id)
            .field("nonce", &self.nonce)
            .finish()
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeBinding {
    game_id: GameId,
    build_id: BuildId,
    account_scope: AccountScope,
    match_id: MatchId,
    policy_id: PolicyId,
    policy_version: PolicyVersion,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRegistration {
    key: ReplayKey,
    binding: ChallengeBinding,
    window: ChallengeWindow,
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
pub trait ReplayStore: fmt::Debug + Send + Sync {
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

    /// Atomically removes records expired at the persisted time floor.
    ///
    /// # Errors
    ///
    /// Returns [`FreshnessError::ClockRollback`] or
    /// [`FreshnessError::StateUnavailable`] without deleting state when time or
    /// storage cannot be trusted.
    fn purge_expired(&self, now: UnixTime) -> Result<usize, FreshnessError>;
}

/// Proof that one registered challenge passed the atomic freshness claim.
///
/// ```compile_fail
/// use ogir_verifier::FreshnessChecked;
///
/// let forged = FreshnessChecked { _private: () };
/// ```
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub struct FreshnessChecked {
    _private: (),
}

/// Deep freshness boundary over one trusted replay-store implementation.
#[derive(Debug)]
pub struct FreshnessGuard<'store, Store: ?Sized> {
    store: &'store Store,
    limits: FreshnessLimits,
}

impl<'store, Store: ReplayStore + ?Sized> FreshnessGuard<'store, Store> {
    /// Binds a replay store to an explicit freshness policy.
    #[must_use]
    pub const fn new(store: &'store Store, limits: FreshnessLimits) -> Self {
        Self { store, limits }
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
        challenge.window.evaluate(now)?;
        self.store.register(
            now,
            &ReplayRegistration::from_challenge(challenge),
            self.limits,
        )
    }

    /// Atomically claims a registered challenge and returns unforgeable proof.
    ///
    /// # Errors
    ///
    /// Propagates strict window failures and every error returned by
    /// [`ReplayStore::claim`]. No error path creates a capability.
    pub fn claim(
        &self,
        now: UnixTime,
        challenge: &PublisherChallenge,
    ) -> Result<FreshnessChecked, FreshnessError> {
        challenge.window.evaluate(now)?;
        self.store
            .claim(now, &ReplayRegistration::from_challenge(challenge))?;
        Ok(FreshnessChecked { _private: () })
    }

    /// Removes only records expired at the replay store's time floor.
    ///
    /// # Errors
    ///
    /// Propagates rollback or state failures from
    /// [`ReplayStore::purge_expired`].
    pub fn purge_expired(&self, now: UnixTime) -> Result<usize, FreshnessError> {
        self.store.purge_expired(now)
    }
}
