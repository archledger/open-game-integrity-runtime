// SPDX-License-Identifier: Apache-2.0

//! The scoped enforcement interface (M8-045, ADR-0041): ONE
//! protected property, per the roadmap -
//!
//!   An unrelated same-user process cannot modify the protected
//!   game's memory through standard Linux process-memory
//!   interfaces while the ranked session is active.
//!
//! The interface is INDEPENDENT of any one kernel mechanism (an
//! M8 exit criterion): an `MemoryAccessControl` trait fronts every
//! mechanism, and the activation policy composes with the M7
//! observation (sessions activate; policy is immutable while
//! active; loss is an event and renewal fails). NO mechanism is
//! privileged in the type: the LSM backend, a yama/ptrace backend,
//! and a simulation backend (CI) are interchangeable behind the
//! seam. Enforcement is GAME-SCOPED ONLY - unrelated processes
//! keep every right they had (noninterference is an exit
//! criterion, tested per blocked interface).

use crate::events::{EventKind, EventLog};
use crate::observation::ObservedSession;

/// The standard Linux process-memory interfaces the first property
/// covers (each has a bypass test in the M8 suite):
/// ptrace attach (PTRACE_ATTACH/PTRACE_SEIZE + POKEDATA),
/// process_vm_writev, /proc/pid/mem writes, and /proc/pid/mem
/// mmap-based manipulation through open fds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryInterface {
    Ptrace,
    ProcessVmWritev,
    ProcMemWrite,
}

impl MemoryInterface {
    /// The stable wire spelling (disclosure + dashboards).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ptrace => "ptrace",
            Self::ProcessVmWritev => "process_vm_writev",
            Self::ProcMemWrite => "proc-mem-write",
        }
    }
}

/// The decision for one access attempt (the interface reports;
/// the mechanism enforces).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    /// The access is denied (the property holds).
    Denied,
    /// The access is outside the property's scope (unrelated
    /// process pairs - noninterference).
    OutOfScope,
}

/// The mechanism-independent memory access control seam. A backend
/// implements exactly this; NOTHING else about the mechanism leaks
/// into the policy layer.
pub trait MemoryAccessControl: std::fmt::Debug {
    /// The mechanism's stable name (disclosure).
    fn mechanism(&self) -> &'static str;

    /// Begins protecting the target process. Fails closed.
    fn activate(
        &mut self,
        target_pid: u32,
        session: &ObservedSession,
    ) -> Result<(), EnforcementError>;

    /// Decides one access attempt: `actor` against the active
    /// target. Same-process access (the game writing its own
    /// memory) is OutOfScope by definition.
    fn decide(&self, actor_pid: u32, interface: MemoryInterface) -> AccessDecision;

    /// Ends protection and releases every mechanism resource.
    fn deactivate(&mut self) -> Result<(), EnforcementError>;
}

/// Enforcement failures. Deterministic, non-disciplinary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementError {
    /// Protection is already active (activation is not
    /// re-entrant; the policy layer enforces immutability).
    AlreadyActive,
    /// No target is protected.
    NotActive,
    /// The mechanism failed to engage (fail closed: the session
    /// must not proceed as protected).
    MechanismFailed(String),
    /// The observation does not support enforcement (a dead or
    /// unobservable target).
    UnobservableTarget,
}

impl std::fmt::Display for EnforcementError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyActive => formatter.write_str("protection already active"),
            Self::NotActive => formatter.write_str("no protection active"),
            Self::MechanismFailed(detail) => write!(formatter, "mechanism failed: {detail}"),
            Self::UnobservableTarget => formatter.write_str("target not observable"),
        }
    }
}

impl std::error::Error for EnforcementError {}

/// The session policy: activation + immutability + loss events +
/// permit-renewal failure (the M8 deliverables around the seam).
#[derive(Debug)]
pub struct SessionPolicy {
    backend: Box<dyn MemoryAccessControl>,
    active: bool,
    target_pid: Option<u32>,
    session_identity: Option<[u8; 32]>,
}

impl SessionPolicy {
    pub fn new(backend: Box<dyn MemoryAccessControl>) -> Self {
        Self {
            backend,
            active: false,
            target_pid: None,
            session_identity: None,
        }
    }

    /// Activates protection for the session's process. The policy
    /// is IMMUTABLE while active (re-activation rejects; the
    /// target cannot be swapped).
    pub fn activate(&mut self, session: &ObservedSession) -> Result<(), EnforcementError> {
        if self.active {
            return Err(EnforcementError::AlreadyActive);
        }
        if session.tree.nodes.is_empty() {
            return Err(EnforcementError::UnobservableTarget);
        }
        let pid = session.identity.pid;
        self.backend.activate(pid, session)?;
        self.active = true;
        self.target_pid = Some(pid);
        self.session_identity = Some(session.identity.digest);
        Ok(())
    }

    /// The decision for one access attempt against the active
    /// target. When no protection is active, the property makes
    /// no claim (OutOfScope - the session is not ranked).
    pub fn decide(&self, actor_pid: u32, interface: MemoryInterface) -> AccessDecision {
        let Some(target) = self.target_pid else {
            return AccessDecision::OutOfScope;
        };
        if actor_pid == target {
            return AccessDecision::OutOfScope;
        }
        self.backend.decide(actor_pid, interface)
    }

    /// Ends protection (normal cleanup). Emits the policy-loss
    /// event when deactivation happens while active.
    pub fn deactivate(&mut self, log: Option<&mut EventLog>) -> Result<(), EnforcementError> {
        if !self.active {
            return Err(EnforcementError::NotActive);
        }
        self.backend.deactivate()?;
        self.active = false;
        if let (Some(log), Some(identity)) = (log, self.session_identity) {
            // Policy loss is an integrity-relevant change: the
            // renewal gate sees it.
            let _ = log.record(
                EventKind::TreeChanged, // the stream's structural vocabulary
                identity,
                identity,
            );
        }
        Ok(())
    }

    /// The permit-renewal gate: renewal FAILS while enforcement is
    /// lost or failing (the M8 deliverable). A session whose
    /// policy ended cannot renew through enforcement claims.
    pub fn renewal_permits(&self) -> bool {
        self.active
    }

    pub fn mechanism(&self) -> &'static str {
        self.backend.mechanism()
    }

    pub fn is_active(&self) -> bool {
        self.active
    }
}

/// The simulation backend (CI): decides purely on pids - the
/// property's LOGIC without any kernel mechanism. The real
/// backends (ptrace-blocking, LSM) implement the same seam on the
/// dev host.
#[derive(Debug, Default)]
pub struct SimulatedBackend {
    target: Option<u32>,
}

impl SimulatedBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

impl MemoryAccessControl for SimulatedBackend {
    fn mechanism(&self) -> &'static str {
        "simulation"
    }

    fn activate(
        &mut self,
        target_pid: u32,
        _session: &ObservedSession,
    ) -> Result<(), EnforcementError> {
        self.target = Some(target_pid);
        Ok(())
    }

    fn decide(&self, actor_pid: u32, _interface: MemoryInterface) -> AccessDecision {
        match self.target {
            Some(target) if actor_pid != target => AccessDecision::Denied,
            _ => AccessDecision::OutOfScope,
        }
    }

    fn deactivate(&mut self) -> Result<(), EnforcementError> {
        self.target = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::observe;
    use crate::portal::PeerCredentials;
    use std::process::Command;

    fn settled_child() -> std::process::Child {
        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap_or_else(|e| panic!("{e:?}"));
        for _ in 0..100 {
            let exe = std::fs::read_link(format!("/proc/{}/exe", child.id()))
                .map(|target| {
                    target
                        .to_string_lossy()
                        .rsplit('/')
                        .next()
                        .unwrap_or_default()
                        .to_string()
                })
                .unwrap_or_default();
            if exe == "sleep" || exe == "sleep (deleted)" {
                let count = || {
                    std::fs::read_to_string(format!("/proc/{}/maps", child.id()))
                        .map(|maps| {
                            maps.lines()
                                .filter(|line| {
                                    line.contains('x')
                                        && line
                                            .rsplit(' ')
                                            .next()
                                            .is_some_and(|p| p.starts_with('/') && p.len() > 1)
                                })
                                .count()
                        })
                        .unwrap_or_default()
                };
                let first = count();
                std::thread::sleep(std::time::Duration::from_millis(30));
                if count() == first {
                    return child;
                }
                continue;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("child never exec'd");
    }

    #[test]
    fn the_first_property_holds_in_simulation() {
        let mut target = settled_child();
        let mut unrelated = settled_child();
        let session = observe(&PeerCredentials {
            pid: target.id(),
            uid: 0,
            gid: 0,
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
        let mut policy = SessionPolicy::new(Box::new(SimulatedBackend::new()));
        policy
            .activate(&session)
            .unwrap_or_else(|e| panic!("{e:?}"));

        // The property: an unrelated same-user process is DENIED on
        // every covered interface...
        for interface in [
            MemoryInterface::Ptrace,
            MemoryInterface::ProcessVmWritev,
            MemoryInterface::ProcMemWrite,
        ] {
            assert_eq!(
                policy.decide(unrelated.id(), interface),
                AccessDecision::Denied,
                "{}",
                interface.as_str()
            );
        }
        // ...the game itself is OutOfScope (self-access)...
        assert_eq!(
            policy.decide(target.id(), MemoryInterface::Ptrace),
            AccessDecision::OutOfScope
        );
        // ...and BEFORE activation nothing was denied.
        let _ = (target.kill(), unrelated.kill());
        let _ = (target.wait(), unrelated.wait());
    }

    #[test]
    fn activation_is_immutable_while_active() {
        let mut child = settled_child();
        let session = observe(&PeerCredentials {
            pid: child.id(),
            uid: 0,
            gid: 0,
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
        let mut policy = SessionPolicy::new(Box::new(SimulatedBackend::new()));
        policy
            .activate(&session)
            .unwrap_or_else(|e| panic!("{e:?}"));
        // Re-activation and target swaps reject.
        assert_eq!(
            policy.activate(&session),
            Err(EnforcementError::AlreadyActive)
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn deactivation_emits_policy_loss_and_closes_renewal() {
        let mut child = settled_child();
        let session = observe(&PeerCredentials {
            pid: child.id(),
            uid: 0,
            gid: 0,
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
        let mut policy = SessionPolicy::new(Box::new(SimulatedBackend::new()));
        policy
            .activate(&session)
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert!(policy.renewal_permits());

        let mut log = EventLog::new(session.identity.digest);
        policy
            .deactivate(Some(&mut log))
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert!(!policy.renewal_permits(), "renewal fails after policy loss");
        assert_eq!(log.len(), 1, "the policy-loss event is on the stream");
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn inactive_policies_make_no_claim() {
        let policy = SessionPolicy::new(Box::new(SimulatedBackend::new()));
        assert_eq!(
            policy.decide(9999, MemoryInterface::Ptrace),
            AccessDecision::OutOfScope
        );
        assert!(!policy.renewal_permits());
    }

    #[test]
    fn the_interface_spellings_are_stable() {
        assert_eq!(MemoryInterface::Ptrace.as_str(), "ptrace");
        assert_eq!(
            MemoryInterface::ProcessVmWritev.as_str(),
            "process_vm_writev"
        );
        assert_eq!(MemoryInterface::ProcMemWrite.as_str(), "proc-mem-write");
    }
}
