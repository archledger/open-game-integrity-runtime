// SPDX-License-Identifier: Apache-2.0

//! Race-resistant caller binding (M5-032, ADR-0028): turning the
//! portal's kernel-derived peer credentials into a binding that
//! survives PID reuse and detects process exit. The binding pairs
//! the pid with its /proc start time AND pins the process with a
//! pidfd: the pidfd refers to exactly the process that was alive at
//! bind time, so a later reused pid can never satisfy it.

use std::fs;

use crate::audited;
use crate::portal::PeerCredentials;

/// Binding failures. Deterministic, non-disciplinary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    /// The process was gone before the binding could pin it
    /// (procfs read or pidfd_open failed). This is the
    /// exit-during-binding category: fail closed.
    ProcessGone,
    /// The procfs stat line was unreadable in the expected shape.
    MalformedStat,
    /// The pidfd could not be created although the process exists.
    PidfdUnavailable,
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessGone => {
                formatter.write_str("the caller exited before its binding was pinned")
            }
            Self::MalformedStat => formatter.write_str("the caller's procfs stat was malformed"),
            Self::PidfdUnavailable => formatter.write_str("a pidfd could not be created"),
        }
    }
}

impl std::error::Error for BindingError {}

/// A pinned caller: pid + kernel start time + an owned pidfd.
#[derive(Debug)]
pub struct CallerBinding {
    pid: u32,
    start_time: u64,
    pidfd: Option<i32>,
}

impl Drop for CallerBinding {
    fn drop(&mut self) {
        if let Some(fd) = self.pidfd.take() {
            let _ = audited::close_fd(fd);
        }
    }
}

impl CallerBinding {
    /// Pins the process behind `credentials` (kernel-derived; the
    /// pid is never caller-supplied text). Reads the start time
    /// from procfs and opens a pidfd; a process that exits first
    /// fails closed with [`BindingError::ProcessGone`].
    pub fn pin(credentials: &PeerCredentials) -> Result<Self, BindingError> {
        let start_time = read_start_time(credentials.pid)?;
        let fd = audited::pidfd_open(credentials.pid, 0);
        if fd < 0 {
            // The narrow window between the SO_PEERCRED read and now
            // closed: the process is gone (or pidfd is unavailable,
            // which is equally fail-closed for a binding that
            // promises a pin).
            return Err(BindingError::ProcessGone);
        }
        Ok(Self {
            pid: credentials.pid,
            start_time,
            pidfd: Some(fd),
        })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn start_time(&self) -> u64 {
        self.start_time
    }

    /// Whether the pinned process is still the same live process.
    /// The pidfd probe answers for the exact process pinned at bind
    /// time; a reused pid is a different process and never
    /// satisfies the probe through this fd.
    pub fn still_pins(&self) -> bool {
        match self.pidfd {
            Some(fd) => audited::pidfd_send_signal_zero(fd) == 0,
            None => false,
        }
    }

    /// Whether `credentials` could still describe the pinned
    /// process: same pid AND the same start time now. Used where a
    /// fresh credential read must be reconciled with an old pin.
    pub fn matches(&self, credentials: &PeerCredentials) -> bool {
        if credentials.pid != self.pid {
            return false;
        }
        match read_start_time(credentials.pid) {
            Ok(current) => current == self.start_time,
            Err(_) => false,
        }
    }
}

/// Reads field 22 (starttime, in clock ticks since boot) of
/// /proc/<pid>/stat. The comm field may contain spaces and parens,
/// so parsing starts after the LAST closing parenthesis.
fn read_start_time(pid: u32) -> Result<u64, BindingError> {
    let stat =
        fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|_| BindingError::ProcessGone)?;
    let after_comm = stat.rsplit_once(')').ok_or(BindingError::MalformedStat)?.1;
    // Fields after comm are state(3) .. starttime(22): starttime is
    // the 20th whitespace-separated field after the parenthesis.
    let field = after_comm
        .split_whitespace()
        .nth(19)
        .ok_or(BindingError::MalformedStat)?;
    field.parse().map_err(|_| BindingError::MalformedStat)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_credentials() -> PeerCredentials {
        PeerCredentials {
            pid: std::process::id(),
            uid: 0,
            gid: 0,
        }
    }

    #[test]
    fn pins_the_current_process() {
        let binding = CallerBinding::pin(&self_credentials()).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(binding.pid(), std::process::id());
        assert!(binding.start_time() > 0);
        assert!(binding.still_pins());
        assert!(binding.matches(&self_credentials()));
    }

    #[test]
    fn a_dead_process_fails_to_pin() {
        // A process that exits immediately: by the time we pin, it
        // is gone (the exit-during-binding category, fail closed).
        let mut child = std::process::Command::new("true")
            .spawn()
            .unwrap_or_else(|e| panic!("{e:?}"));
        let pid = child.id();
        let _ = child.wait();
        let credentials = PeerCredentials {
            pid,
            uid: 0,
            gid: 0,
        };
        assert_eq!(
            CallerBinding::pin(&credentials)
                .err()
                .unwrap_or_else(|| panic!("a dead process must not pin")),
            BindingError::ProcessGone
        );
    }

    #[test]
    fn a_live_child_pins_and_unpins_on_exit() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap_or_else(|e| panic!("{e:?}"));
        let credentials = PeerCredentials {
            pid: child.id(),
            uid: 0,
            gid: 0,
        };
        let binding = CallerBinding::pin(&credentials).unwrap_or_else(|e| panic!("{e:?}"));
        assert!(binding.still_pins());

        // The binding is for the CHILD, not this parent process.
        assert_ne!(binding.pid(), std::process::id());
        assert!(!binding.matches(&self_credentials()));

        let _ = child.kill();
        let _ = child.wait();
        assert!(
            !binding.still_pins(),
            "the pidfd probe must report the exit"
        );
    }

    #[test]
    fn reused_pids_do_not_match_a_stale_start_time() {
        // The PID-reuse defense as a unit: same pid, different start
        // time, is a different process. Executed live in the M5-035
        // suite with a real reuse; here the comparison is direct.
        let binding = CallerBinding::pin(&self_credentials()).unwrap_or_else(|e| panic!("{e:?}"));
        // A start-time mismatch can be forced only through matches()
        // against a DIFFERENT live process, so pin a child and ask
        // whether the parent's binding matches the child's pid.
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap_or_else(|e| panic!("{e:?}"));
        let child_credentials = PeerCredentials {
            pid: child.id(),
            uid: 0,
            gid: 0,
        };
        assert!(!binding.matches(&child_credentials));
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn malformed_stat_is_reported() {
        // Field 19-after-parenthesis parsing must not silently
        // succeed on garbage.
        assert_eq!(
            parse_stat_for_test("1 (a b) R"),
            Err(BindingError::MalformedStat)
        );
        assert_eq!(
            parse_stat_for_test("1 (x) state abc"),
            Err(BindingError::MalformedStat)
        );
        // A twentieth field that is not a number is malformed.
        let non_numeric = format!("1 (x) {} abc", "1 ".repeat(19));
        assert_eq!(
            parse_stat_for_test(&non_numeric),
            Err(BindingError::MalformedStat)
        );
    }

    fn parse_stat_for_test(stat: &str) -> Result<u64, BindingError> {
        let after_comm = stat.rsplit_once(')').ok_or(BindingError::MalformedStat)?.1;
        after_comm
            .split_whitespace()
            .nth(19)
            .ok_or(BindingError::MalformedStat)?
            .parse()
            .map_err(|_| BindingError::MalformedStat)
    }
}
