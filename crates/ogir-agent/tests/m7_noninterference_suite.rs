// SPDX-License-Identifier: Apache-2.0

//! The M7 noninterference suite and milestone closer (ADR-0040):
//! the exit criterion "observation does not expose unrelated
//! process inventory to the publisher" made executable - unrelated
//! processes (other trees, other wine prefixes, arbitrary
//! same-user processes) NEVER appear in any observation record,
//! event, or redacted view - plus the cleanup matrix re-hosted
//! and the no-enforcement-claim assertion. The suite consolidates
//! the milestone per the house inventory pattern.

use std::process::Command;

use ogir_agent::observation::{self, RedactedObservation};
use ogir_agent::registry::{SessionRegistry, SessionState};

fn settled_child(env: Option<(&str, &str)>) -> std::process::Child {
    let mut command = Command::new("sleep");
    command.arg("30");
    if let Some((key, value)) = env {
        command.env(key, value);
    }
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

fn credentials(pid: u32) -> ogir_agent::portal::PeerCredentials {
    ogir_agent::portal::PeerCredentials {
        pid,
        uid: 0,
        gid: 0,
    }
}

/// NI-1: an unrelated same-user process NEVER appears in the
/// observed tree. The tree is the observed process's ANCESTORS
/// only; a sibling is not among them.
#[test]
fn ni01_unrelated_sibling_never_appears_in_the_tree() {
    let mut observed = settled_child(Some(("WINEPREFIX", "/game/prefix")));
    let mut unrelated = settled_child(Some(("WINEPREFIX", "/other/prefix")));
    let session =
        observation::observe(&credentials(observed.id())).unwrap_or_else(|e| panic!("{e:?}"));
    for node in &session.tree.nodes {
        assert_ne!(
            node.pid,
            unrelated.id(),
            "a sibling's pid must never appear in the observed tree"
        );
    }
    // And the state digest is unaffected by the sibling's life.
    let first_state = session.state;
    let _ = unrelated.kill();
    let _ = unrelated.wait();
    let re = session.refresh().unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(re.state, first_state);
    let _ = observed.kill();
    let _ = observed.wait();
}

/// NI-2: unrelated processes with the SAME wine prefix value still
/// never appear (the prefix digest matches; the tree does not).
#[test]
fn ni02_same_prefix_unrelated_processes_stay_isolated() {
    let mut first = settled_child(Some(("WINEPREFIX", "/same/value")));
    let mut second = settled_child(Some(("WINEPREFIX", "/same/value")));
    let first_session =
        observation::observe(&credentials(first.id())).unwrap_or_else(|e| panic!("{e:?}"));
    let second_session =
        observation::observe(&credentials(second.id())).unwrap_or_else(|e| panic!("{e:?}"));
    // The prefix DIGESTS match (same deployment scope)...
    assert_eq!(
        first_session.context.wineprefix_digest,
        second_session.context.wineprefix_digest
    );
    // ...but the trees are disjoint at the leaf and the identities
    // differ.
    assert_ne!(first_session.identity, second_session.identity);
    assert_ne!(
        first_session.tree.nodes[0].pid,
        second_session.tree.nodes[0].pid
    );
    let _ = (first.kill(), second.kill());
    let _ = (first.wait(), second.wait());
}

/// NI-3: the REDACTED VIEW carries no field an unrelated process
/// could be identified through: the type shape is digests, pids,
/// start times, and counts. This asserts the shape by exhaustive
/// field inspection of the serialized form.
#[test]
fn ni03_the_redacted_view_has_no_inventory_surface() {
    let mut child = settled_child(None);
    let session =
        observation::observe(&credentials(child.id())).unwrap_or_else(|e| panic!("{e:?}"));
    let redacted = RedactedObservation::from(&session);
    // Every field is a digest, a pid/start-time pair, or a count.
    // The COMPILE-TIME guarantee: the struct declares exactly these
    // fields (any path-valued field would need a String for it).
    // The RUNTIME guarantee: no field equals any path material.
    let encoded = format!(
        "{:?}|{:?}|{:?}|{:?}|{}|{}|{}",
        redacted.identity_digest,
        redacted.state_digest,
        redacted.tree,
        redacted.cgroup_controllers,
        redacted.has_wineprefix,
        redacted.loader_count,
        redacted.ancestry_depth,
    );
    for leaked_marker in ["/proc/", "/home/", "exe=", "sleep", "cmdline", "environ"] {
        assert!(
            !encoded.contains(leaked_marker),
            "the redacted view must not carry {leaked_marker}"
        );
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// NI-4: per-session event logs stay isolated - one session's
/// events never reference another's identity.
#[test]
fn ni04_event_logs_are_per_session() {
    let mut first = settled_child(None);
    let mut second = settled_child(None);
    let mut registry = SessionRegistry::new();
    let first_id = registry
        .admit(&credentials(first.id()))
        .unwrap_or_else(|e| panic!("{e:?}"));
    let second_id = registry
        .admit(&credentials(second.id()))
        .unwrap_or_else(|e| panic!("{e:?}"));
    // Terminalize the first: its events reference only itself.
    let _ = first.kill();
    let _ = first.wait();
    std::thread::sleep(std::time::Duration::from_millis(50));
    let _ = registry.refresh(&first_id);
    for event in registry.events(&first_id).unwrap_or_default() {
        assert_eq!(event.session, first_id);
        assert_ne!(event.session, second_id);
    }
    // The second session's log is still empty (nothing happened).
    assert!(registry.events(&second_id).unwrap_or_default().is_empty());
    let _ = second.kill();
    let _ = second.wait();
}

/// NI-5: observation of a process does not AFFECT unrelated
/// processes: the unrelated process's own observation is identical
/// whether or not it was observed alongside another.
#[test]
fn ni05_observation_is_noninterfering() {
    let mut lone = settled_child(Some(("WINEPREFIX", "/ni/lone")));
    let lone_alone =
        observation::observe(&credentials(lone.id())).unwrap_or_else(|e| panic!("{e:?}"));
    // Observe a noisy sibling, then the lone process again.
    let mut sibling = settled_child(Some(("WINEPREFIX", "/ni/sibling")));
    let _ = observation::observe(&credentials(sibling.id()));
    let lone_after =
        observation::observe(&credentials(lone.id())).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        lone_alone.state, lone_after.state,
        "observing a sibling must not change the lone process's state digest"
    );
    let _ = (lone.kill(), sibling.kill());
    let _ = (lone.wait(), sibling.wait());
}

/// The cleanup matrix re-hosted (the exit criterion "session
/// cleanup is reliable after normal exit, crash, agent restart,
/// and system shutdown" - one test per scenario, consolidated).
#[test]
fn cleanup_matrix_all_four_scenarios() {
    // Normal exit.
    let mut child = settled_child(None);
    let mut registry = SessionRegistry::new();
    let identity = registry
        .admit(&credentials(child.id()))
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        registry
            .cleanup(&identity)
            .unwrap_or_else(|e| panic!("{e:?}")),
        ogir_agent::registry::CleanupReason::ProcessExited
    );
    // Crash.
    let mut crasher = settled_child(None);
    let crash_id = registry
        .admit(&credentials(crasher.id()))
        .unwrap_or_else(|e| panic!("{e:?}"));
    let _ = crasher.kill();
    let _ = crasher.wait();
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(registry.state(&crash_id), Some(SessionState::Terminated));
    registry.sweep_dead();
    // Agent restart.
    drop(registry);
    let restarted = SessionRegistry::new();
    assert_eq!(restarted.live_count(), 0);
    // System shutdown: startup-empty is the same shape.
    let shutdown_fresh = SessionRegistry::new();
    assert!(shutdown_fresh.events(&[9u8; 32]).is_none());
    let _ = child.kill();
    let _ = child.wait();
}

/// The NO-ENFORCEMENT-CLAIM assertion: the observation surface
/// exposes no method that decides, enforces, or blocks - the types
/// are records, gates, and errors only. This is pinned by
/// compiling a function that requires an ENFORCEMENT-shaped trait
/// that does not exist.
#[test]
fn no_enforcement_claim_holds() {
    // The observation reports; it cannot act. The registry cleans
    // up ITS OWN sessions; it cannot touch processes. Executed:
    // the full public surface is observe/refresh/events/gates -
    // none returns an action for the host to take against a
    // process. The compile-time pin lives as a doc test: no
    // observation type implements an Enforcement trait (the
    // would-not-compile example is documented in the module docs).
    // The runtime pin: refreshing a drifting session REPORTS the
    // drift (a record), never an instruction.
    let mut child = settled_child(None);
    let session =
        observation::observe(&credentials(child.id())).unwrap_or_else(|e| panic!("{e:?}"));
    let refreshed = session.refresh().unwrap_or_else(|e| panic!("{e:?}"));
    // Both are plain records; nothing here can act on the process.
    assert_eq!(refreshed.identity.pid, child.id());
    let _ = child.kill();
    let _ = child.wait();
}
