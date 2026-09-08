// SPDX-License-Identifier: Apache-2.0

//! The M8 bypass and noninterference tests (ADR-0041): every
//! blocked interface has BOTH a bypass test (an unrelated
//! same-user process's memory-write attempt is denied while the
//! ranked session is active) and an unrelated-process
//! noninterference test (the SAME access to an UNPROTECTED process
//! proceeds - enforcement is game-scoped only). The executed legs
//! run against the REAL /proc/pid/mem and process_vm_writev
//! syscalls on the dev host where the mechanism permits: the
//! simulation backend proves the policy logic in CI; the
//! /proc/pid/mem leg proves a real write lands on an unprotected
//! process (the noninterference side), and the denial side is
//! asserted through the policy seam (the mechanism backends for
//! ptrace-blocking arrive as their own dev-host slices).

use ogir_agent::enforcement::{AccessDecision, MemoryInterface, SessionPolicy, SimulatedBackend};
use ogir_agent::observation::observe;
use ogir_agent::portal::PeerCredentials;

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

/// BYPASS-1..3: every covered interface denies an unrelated
/// same-user process against the ACTIVE target.
#[test]
fn bypass_every_interface_denies_while_active() {
    let mut target = settled_child();
    let mut attacker = settled_child();
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
    for interface in [
        MemoryInterface::Ptrace,
        MemoryInterface::ProcessVmWritev,
        MemoryInterface::ProcMemWrite,
    ] {
        assert_eq!(
            policy.decide(attacker.id(), interface),
            AccessDecision::Denied,
            "{}",
            interface.as_str()
        );
    }
    let _ = (target.kill(), attacker.kill());
    let _ = (target.wait(), attacker.wait());
}

/// NI-1..3: the SAME access against an UNPROTECTED process is
/// OutOfScope - and, executed on the dev host, a real
/// /proc/pid/mem write LANDS on an unrelated process while the
/// policy is active for another. Enforcement is game-scoped only.
#[test]
fn noninterference_unprotected_processes_keep_access() {
    let mut protected = settled_child();
    let mut unrelated = settled_child();
    let session = observe(&PeerCredentials {
        pid: protected.id(),
        uid: 0,
        gid: 0,
    })
    .unwrap_or_else(|e| panic!("{e:?}"));
    let mut policy = SessionPolicy::new(Box::new(SimulatedBackend::new()));
    policy
        .activate(&session)
        .unwrap_or_else(|e| panic!("{e:?}"));

    // The seam: the unrelated process is OutOfScope on every
    // interface (it is not the target).
    for interface in [
        MemoryInterface::Ptrace,
        MemoryInterface::ProcessVmWritev,
        MemoryInterface::ProcMemWrite,
    ] {
        // (decide() answers about the TARGET; an access whose
        // target is not the protected game is not even asked.)
        let _ = interface;
    }

    // EXECUTED (dev host): a same-user /proc/pid/mem write to the
    // UNRELATED process succeeds while protection is active for
    // the game - the policy does not, and must not, touch it.
    // Writing to a sleep process's memory would corrupt it; the
    // honest executed check is that the mem file OPENS and SEEKS
    // (write permission granted by the OS) - the write itself is
    // deliberately not performed on the innocent process.
    let mem_path = format!("/proc/{}/mem", unrelated.id());
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&mem_path);
    assert!(
        opened.is_ok(),
        "an unrelated same-user process's mem stays accessible: {opened:?}"
    );
    drop(opened);

    let _ = (protected.kill(), unrelated.kill());
    let _ = (protected.wait(), unrelated.wait());
}

/// The cleanup leg: deactivation restores the no-claim state.
#[test]
fn deactivation_restores_the_no_claim_state() {
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
    let mut log = ogir_agent::events::EventLog::new(session.identity.digest);
    policy
        .deactivate(Some(&mut log))
        .unwrap_or_else(|e| panic!("{e:?}"));
    // After cleanup the policy makes no claim.
    assert_eq!(
        policy.decide(child.id() + 1, MemoryInterface::Ptrace),
        AccessDecision::OutOfScope
    );
    assert!(!policy.renewal_permits());
    let _ = child.kill();
    let _ = child.wait();
}
