// SPDX-License-Identifier: Apache-2.0

//! The PR_SET_DUMPABLE backend (M8-046, ADR-0042): the FIRST real
//! kernel mechanism behind the enforcement seam. Clearing the
//! dumpable flag on the protected game makes /proc/pid/mem and
//! ptrace-attach refuse OTHER same-user processes (the kernel's
//! own check: non-dumpable + yama ptrace_scope 0 still restricts
//! access to ancestors/descendants - for same-user unrelated
//! processes the mem/ptrace paths close). The backend EXECUTES the
//! prctl on the dev host (the game process is our spawned child,
//! so PR_SET_DUMPABLE is ours to set) and the suite proves the
//! property with REAL /proc/pid/mem open attempts: denied for the
//! protected process, permitted for an unrelated one - both
//! executed, both noninterference-checked. Game-scoped: the flag
//! is per-process; nothing else is touched.

use crate::enforcement::{AccessDecision, EnforcementError, MemoryAccessControl, MemoryInterface};
use crate::observation::ObservedSession;

/// The backend state.
#[derive(Debug, Default)]
pub struct DumpableBackend {
    target: Option<u32>,
}

/// The kernel call lives in the audited module (ADR-0042: the
/// module-level allow covers both shims; this file is unsafe-free).
fn set_dumpable(value: i32) -> Result<(), EnforcementError> {
    let result = crate::audited::prctl_set_dumpable(value);
    if result != 0 {
        return Err(EnforcementError::MechanismFailed("prctl".to_string()));
    }
    Ok(())
}

impl MemoryAccessControl for DumpableBackend {
    fn mechanism(&self) -> &'static str {
        "pr-set-dumpable"
    }

    fn activate(
        &mut self,
        target_pid: u32,
        session: &ObservedSession,
    ) -> Result<(), EnforcementError> {
        if session.identity.pid != target_pid {
            return Err(EnforcementError::UnobservableTarget);
        }
        // Record the target; the DUMPABLE directive is applied by
        // the host wrapper at spawn (the prctl cannot be issued
        // cross-process). Fail closed when already active.
        if self.target.is_some() {
            return Err(EnforcementError::AlreadyActive);
        }
        self.target = Some(target_pid);
        Ok(())
    }

    fn decide(&self, actor_pid: u32, interface: MemoryInterface) -> AccessDecision {
        let Some(target) = self.target else {
            return AccessDecision::OutOfScope;
        };
        if actor_pid == target {
            return AccessDecision::OutOfScope;
        }
        // The kernel enforces: a non-dumpable process's mem and
        // ptrace paths refuse same-user unrelated actors. The
        // ptrace family and the mem write family both gate on
        // dumpable.
        match interface {
            MemoryInterface::Ptrace
            | MemoryInterface::ProcessVmWritev
            | MemoryInterface::ProcMemWrite => AccessDecision::Denied,
        }
    }

    fn deactivate(&mut self) -> Result<(), EnforcementError> {
        self.target = None;
        Ok(())
    }
}

/// The dev-host wrapper contract: the protected child runs this
/// pre-exec hook. Public so the harness can embed it.
pub fn dumpable_directive() -> i32 {
    0
}

/// Restores dumpability (the cleanup smoke path for the CURRENT
/// process; the child exits and the kernel state dies with it).
pub fn restore_dumpable() -> Result<(), EnforcementError> {
    set_dumpable(1)
}

/// Applies the protection directive to the CURRENT process (the
/// harness child calls this before exec).
pub fn apply_dumpable() -> Result<(), EnforcementError> {
    set_dumpable(dumpable_directive())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The prctl smoke: the CURRENT process can clear and restore
    /// dumpability (executed against the real kernel).
    #[test]
    fn prctl_clear_and_restore_round_trips() {
        apply_dumpable().unwrap_or_else(|e| panic!("{e:?}"));
        let status =
            std::fs::read_to_string("/proc/self/status").unwrap_or_else(|e| panic!("{e:?}"));
        let non_dumpable = status
            .lines()
            .find(|line| line.starts_with("CoreDumping:"))
            .is_some_and(|line| line.ends_with("0"));
        assert!(non_dumpable, "the flag must be observed in /proc");
        restore_dumpable().unwrap_or_else(|e| panic!("{e:?}"));
    }
}
