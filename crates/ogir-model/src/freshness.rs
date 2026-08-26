// SPDX-License-Identifier: Apache-2.0

//! Pure challenge-freshness value types and invariants.

use std::error::Error;
use std::fmt;
use std::num::{NonZeroU64, NonZeroUsize};

/// Whole seconds since the Unix epoch from a publisher-authoritative clock.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(u64);

impl fmt::Debug for UnixTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnixTime([REDACTED])")
    }
}

impl UnixTime {
    /// Creates a typed Unix timestamp.
    #[must_use]
    pub const fn new(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Returns the whole Unix-seconds value.
    #[must_use]
    pub const fn seconds(self) -> u64 {
        self.0
    }
}

/// Finite, nonzero maximum duration permitted for a challenge window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeLifetime(NonZeroU64);

impl ChallengeLifetime {
    /// Creates a challenge-lifetime policy from a nonzero number of seconds.
    #[must_use]
    pub const fn new(seconds: NonZeroU64) -> Self {
        Self(seconds)
    }

    /// Returns the configured nonzero duration in seconds.
    #[must_use]
    pub const fn seconds(self) -> NonZeroU64 {
        self.0
    }
}

/// Validated half-open challenge interval `[issued_at, expires_at)`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChallengeWindow {
    issued_at: UnixTime,
    expires_at: UnixTime,
}

impl fmt::Debug for ChallengeWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChallengeWindow([REDACTED])")
    }
}

impl ChallengeWindow {
    /// Constructs an ordered window within an explicit lifetime policy.
    ///
    /// # Errors
    ///
    /// Returns [`FreshnessError::InvalidWindow`] when expiry is not after
    /// issuance, or [`FreshnessError::LifetimeExceeded`] when the duration is
    /// greater than `maximum`.
    pub fn new(
        issued_at: UnixTime,
        expires_at: UnixTime,
        maximum: ChallengeLifetime,
    ) -> Result<Self, FreshnessError> {
        let duration = expires_at
            .seconds()
            .checked_sub(issued_at.seconds())
            .ok_or(FreshnessError::InvalidWindow)?;
        if duration == 0 {
            return Err(FreshnessError::InvalidWindow);
        }
        if duration > maximum.seconds().get() {
            return Err(FreshnessError::LifetimeExceeded);
        }

        Ok(Self {
            issued_at,
            expires_at,
        })
    }

    /// Evaluates `now` against the strict half-open interval.
    ///
    /// # Errors
    ///
    /// Returns [`FreshnessError::NotYetValid`] before issuance and
    /// [`FreshnessError::Expired`] at or after expiry.
    pub fn evaluate(self, now: UnixTime) -> Result<(), FreshnessError> {
        if now < self.issued_at {
            return Err(FreshnessError::NotYetValid);
        }
        if now >= self.expires_at {
            return Err(FreshnessError::Expired);
        }

        Ok(())
    }

    /// Returns the inclusive issuance boundary.
    #[must_use]
    pub const fn issued_at(self) -> UnixTime {
        self.issued_at
    }

    /// Returns the exclusive expiry boundary.
    #[must_use]
    pub const fn expires_at(self) -> UnixTime {
        self.expires_at
    }
}

/// Explicit finite policy limits for challenge issuance and replay state.
///
/// This type intentionally has no [`Default`] implementation; each deployment
/// must select every limit deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessLimits {
    max_lifetime: ChallengeLifetime,
    max_outstanding_total: NonZeroUsize,
    max_outstanding_per_publisher: NonZeroUsize,
    max_outstanding_per_account: NonZeroUsize,
    issuance_rate_window_seconds: NonZeroU64,
    max_issuances_per_publisher: NonZeroUsize,
}

impl FreshnessLimits {
    /// Creates a complete freshness policy with no implicit values.
    #[must_use]
    pub const fn new(
        max_lifetime: ChallengeLifetime,
        max_outstanding_total: NonZeroUsize,
        max_outstanding_per_publisher: NonZeroUsize,
        max_outstanding_per_account: NonZeroUsize,
        issuance_rate_window_seconds: NonZeroU64,
        max_issuances_per_publisher: NonZeroUsize,
    ) -> Self {
        Self {
            max_lifetime,
            max_outstanding_total,
            max_outstanding_per_publisher,
            max_outstanding_per_account,
            issuance_rate_window_seconds,
            max_issuances_per_publisher,
        }
    }

    /// Returns the maximum permitted challenge lifetime.
    #[must_use]
    pub const fn max_lifetime(self) -> ChallengeLifetime {
        self.max_lifetime
    }

    /// Returns the maximum number of outstanding challenges across publishers.
    #[must_use]
    pub const fn max_outstanding_total(self) -> NonZeroUsize {
        self.max_outstanding_total
    }

    /// Returns the maximum outstanding challenges for one publisher.
    #[must_use]
    pub const fn max_outstanding_per_publisher(self) -> NonZeroUsize {
        self.max_outstanding_per_publisher
    }

    /// Returns the maximum outstanding challenges for one publisher account.
    #[must_use]
    pub const fn max_outstanding_per_account(self) -> NonZeroUsize {
        self.max_outstanding_per_account
    }

    /// Returns the per-publisher sliding issuance-window duration.
    #[must_use]
    pub const fn issuance_rate_window_seconds(self) -> NonZeroU64 {
        self.issuance_rate_window_seconds
    }

    /// Returns the maximum publisher issuances inside one rate window.
    #[must_use]
    pub const fn max_issuances_per_publisher(self) -> NonZeroUsize {
        self.max_issuances_per_publisher
    }
}

/// Failure to construct, evaluate, or persist challenge freshness state.
///
/// Variants intentionally contain no nonce or account-scoped context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessError {
    /// Challenge expiry was not strictly after issuance.
    InvalidWindow,
    /// Challenge duration exceeded the active lifetime policy.
    LifetimeExceeded,
    /// Authoritative verifier time was before challenge issuance.
    NotYetValid,
    /// Authoritative verifier time was at or after challenge expiry.
    Expired,
    /// The publisher-scoped nonce was already registered or consumed.
    ReplayDetected,
    /// Authoritative time was lower than the persisted high-water mark.
    ClockRollback,
    /// Required replay or time-floor state could not be trusted or accessed.
    StateUnavailable,
    /// An explicit freshness-state or issuance-rate limit was exhausted.
    CapacityExceeded,
}

impl fmt::Display for FreshnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidWindow => "challenge window is invalid",
            Self::LifetimeExceeded => "challenge lifetime exceeds policy",
            Self::NotYetValid => "challenge is not yet valid",
            Self::Expired => "challenge is expired",
            Self::ReplayDetected => "challenge nonce is already registered or consumed",
            Self::ClockRollback => "authoritative clock moved backward",
            Self::StateUnavailable => "freshness state is unavailable",
            Self::CapacityExceeded => "freshness state capacity is exhausted",
        })
    }
}

impl Error for FreshnessError {}
