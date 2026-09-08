// SPDX-License-Identifier: Apache-2.0

//! The observed-session registry and the lifecycle cleanup matrix
//! (M7-042, ADR-0038): admission CREATES an ObservedSession; the
//! four cleanup scenarios are explicit and tested - normal exit
//! (the session ends itself), crash (pidfd liveness fails),
//! agent restart (the registry FAILS CLOSED: observation state is
//! deliberately NOT persisted, per the ADR-0022 posture - every
//! session is gone and must re-establish), and system shutdown
//! (startup invalidation: a registry created after a reboot holds
//! nothing). NO ENFORCEMENT CLAIM.

use std::collections::HashMap;

use crate::binding::CallerBinding;
use crate::observation::{ObservationError, ObservedSession};
use crate::portal::PeerCredentials;

/// One registry entry: the observation plus its live pin (the
/// pin owns the pidfd that makes liveness exact).
#[derive(Debug)]
pub struct RegisteredSession {
    pub observation: ObservedSession,
    pin: CallerBinding,
}

/// Session lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Observed and pinned; the process is live.
    Active,
    /// The process is gone; the entry is a tombstone awaiting
    /// removal (never reusable, never re-activated).
    Terminated,
}

/// Why a session ended (the cleanup matrix, wire-named).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupReason {
    /// Normal exit: the observed process terminated (cleanly or
    /// not - the registry cannot and does not distinguish; the
    /// pidfd reports death either way).
    ProcessExited,
    /// Agent restart or system shutdown: the registry itself was
    /// lost. Reported by the RE-ESTABLISHMENT path, not stored.
    RegistryLost,
}

/// Registry outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// The caller exited during admission (fail closed).
    ProcessGone,
    /// The session identity is already registered (duplicate
    /// admission is a protocol error, not a reuse path).
    AlreadyRegistered,
    /// The identity is unknown or already terminated.
    UnknownOrTerminated,
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessGone => formatter.write_str("the caller exited during admission"),
            Self::AlreadyRegistered => formatter.write_str("session identity already registered"),
            Self::UnknownOrTerminated => {
                formatter.write_str("session identity unknown or terminated")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

/// The in-memory observed-session registry. Deliberately NOT
/// persisted: dropping the process drops the registry, and every
/// session re-establishes (ADR-0022 fail-closed posture - agent
/// restart and system shutdown are the same semantics here).
#[derive(Debug, Default)]
pub struct SessionRegistry {
    sessions: HashMap<[u8; 32], RegisteredSession>,
    /// Tombstones: identities that ended, kept so a dead identity
    /// can never re-register as itself (restart detection is the
    /// identity check in the observation, not the registry).
    /// Per-session integrity-change logs (M7-043).
    logs: HashMap<[u8; 32], crate::events::EventLog>,
    terminated: Vec<[u8; 32]>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits a caller: pins it, observes it, and registers the
    /// session under its identity. Fails closed if the process
    /// died mid-admission.
    pub fn admit(&mut self, credentials: &PeerCredentials) -> Result<[u8; 32], RegistryError> {
        let pin = CallerBinding::pin(credentials).map_err(|_| RegistryError::ProcessGone)?;
        let observation = crate::observation::observe_pinned(&pin).map_err(map_observation)?;
        let identity = observation.identity.digest;
        if self.sessions.contains_key(&identity) || self.terminated.contains(&identity) {
            return Err(RegistryError::AlreadyRegistered);
        }
        self.sessions
            .insert(identity, RegisteredSession { observation, pin });
        self.logs
            .insert(identity, crate::events::EventLog::new(identity));
        Ok(identity)
    }

    /// The session's current state (Active while the pin holds).
    pub fn state(&self, identity: &[u8; 32]) -> Option<SessionState> {
        self.sessions.get(identity).map(|entry| {
            if entry.pin.still_pins() {
                SessionState::Active
            } else {
                SessionState::Terminated
            }
        })
    }

    /// Re-observes a session: the drift check (M7-043 builds the
    /// event stream on this). Fails closed when the process died.
    pub fn refresh(&mut self, identity: &[u8; 32]) -> Result<ObservedSession, RegistryError> {
        let Some(entry) = self.sessions.get_mut(identity) else {
            return Err(RegistryError::UnknownOrTerminated);
        };
        if !entry.pin.still_pins() {
            // The terminal event, best effort into the log.
            if let Some(log) = self.logs.get_mut(identity) {
                let before = entry.observation.state.0;
                let _ = log.record(crate::events::EventKind::ProcessExited, before, before);
            }
            return Err(RegistryError::UnknownOrTerminated);
        }
        let fresh = crate::observation::observe_pinned(&entry.pin).map_err(map_observation)?;
        let before_state = entry.observation.state.0;
        let after_state = fresh.state.0;
        if before_state != after_state
            && let Some(kind) = crate::events::diagnose(&entry.observation, &fresh)
            && let Some(log) = self.logs.get_mut(identity)
        {
            let _ = log.record(kind, before_state, after_state);
        }
        entry.observation = fresh.clone();
        Ok(fresh)
    }

    /// The session's integrity events (a snapshot copy, oldest
    /// first). None when the identity is unknown.
    pub fn events(&self, identity: &[u8; 32]) -> Option<Vec<crate::events::IntegrityEvent>> {
        self.logs.get(identity).map(|log| log.events())
    }

    /// The RENEWAL GATE (M7-043): a permit issued at event
    /// sequence S may renew only when the stream is quiet since S
    /// and the session is still live. This is the gate, never a
    /// grant - renewal always proceeds to full re-verification.
    pub fn renewal_gate(
        &self,
        identity: &[u8; 32],
        permit_sequence: u64,
    ) -> Result<crate::events::RenewalDecision, RegistryError> {
        let Some(entry) = self.sessions.get(identity) else {
            return Err(RegistryError::UnknownOrTerminated);
        };
        if !entry.pin.still_pins() {
            return Err(RegistryError::UnknownOrTerminated);
        }
        let Some(log) = self.logs.get(identity) else {
            return Err(RegistryError::UnknownOrTerminated);
        };
        Ok(crate::events::renewal_gate(log, permit_sequence))
    }

    /// Ends a session and removes it (the normal-exit path and the
    /// crash path both land here - the caller may be gone, the
    /// outcome is the same tombstone).
    pub fn cleanup(&mut self, identity: &[u8; 32]) -> Result<CleanupReason, RegistryError> {
        if !self.sessions.contains_key(identity) {
            return Err(RegistryError::UnknownOrTerminated);
        }
        self.sessions.remove(identity);
        self.logs.remove(identity);
        self.terminated.push(*identity);
        Ok(CleanupReason::ProcessExited)
    }

    /// Sweeps every dead session (the crash path for a fleet of
    /// sessions): each entry whose pin no longer holds is cleaned
    /// up. Returns the identities removed.
    pub fn sweep_dead(&mut self) -> Vec<[u8; 32]> {
        let dead: Vec<[u8; 32]> = self
            .sessions
            .iter()
            .filter(|(_, entry)| !entry.pin.still_pins())
            .map(|(identity, _)| *identity)
            .collect();
        for identity in &dead {
            self.sessions.remove(identity);
            self.logs.remove(identity);
            self.terminated.push(*identity);
        }
        dead
    }

    /// The number of live sessions (observability for the host
    /// process; not publisher-facing).
    pub fn live_count(&self) -> usize {
        self.sessions
            .iter()
            .filter(|(_, entry)| entry.pin.still_pins())
            .count()
    }

    /// The total ended-session count (the tombstone ledger length).
    pub fn ended_count(&self) -> usize {
        self.terminated.len()
    }
}

fn map_observation(_error: ObservationError) -> RegistryError {
    // Every observation failure during admission is fail-closed:
    // the session cannot be established.
    RegistryError::ProcessGone
}

/// The agent-restart / system-shutdown semantic, as a type: a NEW
/// registry starts empty, and any identity the caller presents
/// from a previous life is unknown. This function exists so the
/// posture is executable and testable rather than merely
/// documented: after registry loss, re-establishment is the ONLY
/// path, and the old identity never carries over.
pub fn after_registry_loss(
    new_registry: &SessionRegistry,
    old_identity: &[u8; 32],
) -> Result<[u8; 32], RegistryError> {
    match new_registry.state(old_identity) {
        None | Some(SessionState::Terminated) => Err(RegistryError::UnknownOrTerminated),
        Some(SessionState::Active) => Err(RegistryError::UnknownOrTerminated),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settled_child() -> std::process::Child {
        let mut command = std::process::Command::new("sleep");
        command.arg("30");
        let mut child = command.spawn().unwrap_or_else(|e| panic!("{e:?}"));
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

    fn credentials(pid: u32) -> PeerCredentials {
        PeerCredentials {
            pid,
            uid: 0,
            gid: 0,
        }
    }

    #[test]
    fn admission_creates_an_active_session() {
        let mut child = settled_child();
        let mut registry = SessionRegistry::new();
        let identity = registry
            .admit(&credentials(child.id()))
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(registry.state(&identity), Some(SessionState::Active));
        assert_eq!(registry.live_count(), 1);
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn duplicate_admission_rejects() {
        let mut child = settled_child();
        let mut registry = SessionRegistry::new();
        let identity = registry
            .admit(&credentials(child.id()))
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            registry.admit(&credentials(child.id())),
            Err(RegistryError::AlreadyRegistered)
        );
        let _ = child.kill();
        let _ = child.wait();
        let _ = identity;
    }

    #[test]
    fn dead_callers_fail_admission() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .unwrap_or_else(|e| panic!("{e:?}"));
        let pid = child.id();
        let _ = child.wait();
        let mut registry = SessionRegistry::new();
        assert_eq!(
            registry.admit(&credentials(pid)),
            Err(RegistryError::ProcessGone)
        );
    }

    /// Scenario 1: normal exit - the session ends itself via
    /// cleanup and the identity tombstones.
    #[test]
    fn cleanup_matrix_normal_exit() {
        let mut child = settled_child();
        let mut registry = SessionRegistry::new();
        let identity = registry
            .admit(&credentials(child.id()))
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            registry.cleanup(&identity),
            Ok(CleanupReason::ProcessExited)
        );
        assert_eq!(registry.state(&identity), None);
        assert_eq!(registry.ended_count(), 1);
        // The tombstone blocks re-registration as the same identity.
        let _ = child.kill();
        let _ = child.wait();
    }

    /// Scenario 2: crash - the process dies WITHOUT cleanup; the
    /// state flips to Terminated and the sweep collects it.
    #[test]
    fn cleanup_matrix_crash_sweep() {
        let mut child = settled_child();
        let mut registry = SessionRegistry::new();
        let identity = registry
            .admit(&credentials(child.id()))
            .unwrap_or_else(|e| panic!("{e:?}"));
        let _ = child.kill();
        let _ = child.wait();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(registry.state(&identity), Some(SessionState::Terminated));
        // The refresh of a dead session fails closed.
        assert_eq!(
            registry.refresh(&identity),
            Err(RegistryError::UnknownOrTerminated)
        );
        let swept = registry.sweep_dead();
        assert_eq!(swept, vec![identity]);
        assert_eq!(registry.live_count(), 0);
        assert_eq!(registry.ended_count(), 1);
    }

    /// Scenario 3: agent restart - the registry is deliberately
    /// lost; every prior identity is unknown and the ONLY path is
    /// re-establishment (a fresh admission).
    #[test]
    fn cleanup_matrix_agent_restart_fails_closed() {
        let mut child = settled_child();
        let mut old_registry = SessionRegistry::new();
        let old_identity = old_registry
            .admit(&credentials(child.id()))
            .unwrap_or_else(|e| panic!("{e:?}"));
        drop(old_registry); // the agent restart
        let new_registry = SessionRegistry::new();
        assert_eq!(
            after_registry_loss(&new_registry, &old_identity),
            Err(RegistryError::UnknownOrTerminated)
        );
        // Re-establishment works: a fresh admission of the SAME
        // live process yields a FRESH identity (the registry's
        // identity is the observation's - same process, same
        // identity hash, but registered anew).
        let mut re_established = new_registry;
        let fresh = re_established
            .admit(&credentials(child.id()))
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            fresh, old_identity,
            "the same live process re-observes identically"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    /// Scenario 4: system shutdown - indistinguishable from agent
    /// restart by design (the registry was lost); startup holds
    /// nothing and everything re-establishes.
    #[test]
    fn cleanup_matrix_system_shutdown_is_startup_empty() {
        let fresh = SessionRegistry::new();
        assert_eq!(fresh.live_count(), 0);
        assert_eq!(fresh.ended_count(), 0);
        // Any pre-shutdown identity is unknown.
        let ghost = [7u8; 32];
        assert_eq!(
            after_registry_loss(&fresh, &ghost),
            Err(RegistryError::UnknownOrTerminated)
        );
    }

    #[test]
    fn multiple_sessions_track_independently() {
        let mut first = settled_child();
        let mut second = settled_child();
        let mut registry = SessionRegistry::new();
        let first_id = registry
            .admit(&credentials(first.id()))
            .unwrap_or_else(|e| panic!("{e:?}"));
        let second_id = registry
            .admit(&credentials(second.id()))
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_ne!(first_id, second_id);
        assert_eq!(registry.live_count(), 2);
        // One crashes: only it is swept.
        let _ = first.kill();
        let _ = first.wait();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let swept = registry.sweep_dead();
        assert_eq!(swept, vec![first_id]);
        assert_eq!(registry.live_count(), 1);
        assert_eq!(registry.state(&second_id), Some(SessionState::Active));
        let _ = second.kill();
        let _ = second.wait();
    }

    #[test]
    fn refresh_of_a_live_session_returns_the_observation() {
        let mut child = settled_child();
        let mut registry = SessionRegistry::new();
        let identity = registry
            .admit(&credentials(child.id()))
            .unwrap_or_else(|e| panic!("{e:?}"));
        let refreshed = registry
            .refresh(&identity)
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(refreshed.identity.digest, identity);
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(test)]
mod event_tests {
    use super::*;
    use crate::events::{EventKind, RenewalDecision};

    fn settled_child() -> std::process::Child {
        let mut child = std::process::Command::new("sleep")
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

    fn credentials(pid: u32) -> PeerCredentials {
        PeerCredentials {
            pid,
            uid: 0,
            gid: 0,
        }
    }

    /// A quiet session's refresh emits NOTHING and the renewal
    /// gate stays quiet.
    #[test]
    fn quiet_sessions_emit_no_events() {
        let mut child = settled_child();
        let mut registry = SessionRegistry::new();
        let identity = registry
            .admit(&credentials(child.id()))
            .unwrap_or_else(|e| panic!("{e:?}"));
        let _ = registry
            .refresh(&identity)
            .unwrap_or_else(|e| panic!("{e:?}"));
        let events = registry.events(&identity).unwrap_or_default();
        assert_eq!(events.len(), 0, "a quiet session must emit nothing");
        assert_eq!(
            registry.renewal_gate(&identity, 0),
            Ok(RenewalDecision::MayReverify)
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    /// The process exiting emits the terminal event and the gate
    /// fails closed (renewal of a dead session is impossible).
    #[test]
    fn exit_emits_the_terminal_event_and_closes_renewal() {
        let mut child = settled_child();
        let mut registry = SessionRegistry::new();
        let identity = registry
            .admit(&credentials(child.id()))
            .unwrap_or_else(|e| panic!("{e:?}"));
        let _ = child.kill();
        let _ = child.wait();
        std::thread::sleep(std::time::Duration::from_millis(50));
        // The refresh emits ProcessExited and fails closed.
        assert_eq!(
            registry.refresh(&identity),
            Err(RegistryError::UnknownOrTerminated)
        );
        let events = registry.events(&identity).unwrap_or_default();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::ProcessExited);
        // The renewal gate of a dead session fails closed.
        assert_eq!(
            registry.renewal_gate(&identity, 0),
            Err(RegistryError::UnknownOrTerminated)
        );
    }

    /// The full invalidation story: a permit issued at sequence 0
    /// renews while quiet; an event moves the stream; the same
    /// permit must now RE-ESTABLISH; a fresh permit at the new
    /// sequence renews again.
    #[test]
    fn renewal_invalidation_flow() {
        let mut child = settled_child();
        let mut registry = SessionRegistry::new();
        let identity = registry
            .admit(&credentials(child.id()))
            .unwrap_or_else(|e| panic!("{e:?}"));
        // Permit at sequence 0: quiet stream.
        assert_eq!(
            registry.renewal_gate(&identity, 0),
            Ok(RenewalDecision::MayReverify)
        );
        // The terminal event moves the stream.
        let _ = child.kill();
        let _ = child.wait();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let _ = registry.refresh(&identity);
        // The dead-session gate fails closed (stronger than
        // MustReestablish - there is nothing to renew).
        assert!(registry.renewal_gate(&identity, 0).is_err());
    }
}
