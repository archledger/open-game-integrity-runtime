// SPDX-License-Identifier: Apache-2.0

use std::num::{NonZeroU64, NonZeroUsize};

use ogir_model::{ChallengeLifetime, ChallengeWindow, FreshnessError, FreshnessLimits, UnixTime};

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

fn window(issued: u64, expires: u64, maximum: u64) -> ChallengeWindow {
    match ChallengeWindow::new(
        UnixTime::new(issued),
        UnixTime::new(expires),
        ChallengeLifetime::new(nonzero_u64(maximum)),
    ) {
        Ok(window) => window,
        Err(error) => panic!("valid fixture rejected: {error:?}"),
    }
}

#[test]
fn half_open_window_has_zero_leeway() {
    let window = window(100, 200, 100);
    assert_eq!(
        window.evaluate(UnixTime::new(99)),
        Err(FreshnessError::NotYetValid)
    );
    assert_eq!(window.evaluate(UnixTime::new(100)), Ok(()));
    assert_eq!(window.evaluate(UnixTime::new(199)), Ok(()));
    assert_eq!(
        window.evaluate(UnixTime::new(200)),
        Err(FreshnessError::Expired)
    );
    assert_eq!(
        window.evaluate(UnixTime::new(201)),
        Err(FreshnessError::Expired)
    );
}

#[test]
fn invalid_and_excessive_windows_fail_without_overflow() {
    let maximum = ChallengeLifetime::new(nonzero_u64(100));
    assert_eq!(
        ChallengeWindow::new(UnixTime::new(100), UnixTime::new(100), maximum),
        Err(FreshnessError::InvalidWindow)
    );
    assert_eq!(
        ChallengeWindow::new(UnixTime::new(101), UnixTime::new(100), maximum),
        Err(FreshnessError::InvalidWindow)
    );
    assert_eq!(
        ChallengeWindow::new(UnixTime::new(100), UnixTime::new(201), maximum),
        Err(FreshnessError::LifetimeExceeded)
    );
    let extreme = match ChallengeWindow::new(
        UnixTime::new(u64::MAX - 1),
        UnixTime::new(u64::MAX),
        maximum,
    ) {
        Ok(window) => window,
        Err(error) => panic!("ordered near-maximum window rejected: {error:?}"),
    };
    assert_eq!(extreme.issued_at().seconds(), u64::MAX - 1);
    assert_eq!(extreme.expires_at().seconds(), u64::MAX);
    assert_eq!(
        extreme.evaluate(UnixTime::new(150)),
        Err(FreshnessError::NotYetValid)
    );
}

#[test]
fn limits_are_explicit_and_nonzero() {
    let limits = FreshnessLimits::new(
        ChallengeLifetime::new(nonzero_u64(120)),
        nonzero_usize(1_000),
        nonzero_usize(100),
        nonzero_usize(4),
        nonzero_u64(60),
        nonzero_usize(20),
    );
    assert_eq!(limits.max_lifetime().seconds().get(), 120);
    assert_eq!(limits.max_outstanding_total().get(), 1_000);
    assert_eq!(limits.max_outstanding_per_publisher().get(), 100);
    assert_eq!(limits.max_outstanding_per_account().get(), 4);
    assert_eq!(limits.issuance_rate_window_seconds().get(), 60);
    assert_eq!(limits.max_issuances_per_publisher().get(), 20);
}
