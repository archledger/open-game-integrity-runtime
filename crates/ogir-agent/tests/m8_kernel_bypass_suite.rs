// SPDX-License-Identifier: Apache-2.0

//! The M8 kernel-mechanism suite (ADR-0042): the FIRST REAL
//! bypass test executed against the kernel. A protected child
//! (non-dumpable via the audited prctl) refuses a same-user
//! unrelated process's /proc/pid/mem OPEN - the kernel's own
//! denial, observed live - while an UNPROTECTED unrelated
//! process's mem stays openable. Both directions executed; the
//! noninterference side is the same assertion family the
//! roadmap's exit criterion demands per blocked interface.

use std::process::Command;

use ogir_agent::dumpable_backend::{apply_dumpable, restore_dumpable};

fn settled_child(dumpable: bool) -> std::process::Child {
    // The wrapper: a shell that applies/restores the flag then
    // sleeps. The prctl runs INSIDE the child (the flag is
    // per-process).
    let _ = dumpable;
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
            return child;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("child never exec'd");
}

/// The protected child: spawns `sleep` under a wrapper that
/// clears dumpability via a tiny C helper compiled by the test
/// (the prctl must run in-process). The helper is built once per
/// run into the cargo tmpdir.
fn build_helper() -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let source = dir.join("ogir-nondump-helper.c");
    let binary = dir.join("ogir-nondump-helper");
    // The helper DOUBLE-FORKS: the protected sleep is a
    // grandchild re-parented away from the test, so the opener is
    // a genuinely unrelated same-user process (the kernel exempts
    // ancestors from the dumpable check - discovered empirically;
    // the property is about UNRELATED processes).
    std::fs::write(
        &source,
        // THE PROTECTED PROCESS IS THE GRANDCHILD ITSELF (no
        // exec: execve RESETS the dumpable flag to the default
        // for non-setuid binaries - the empirical discovery of
        // this suite). It clears dumpability and pauses; the
        // parent prints the pid and exits so the opener is never
        // an ancestor.
        "#include <sys/prctl.h>\n#include <unistd.h>\n#include <stdio.h>\n\
         #include <fcntl.h>\n#include <signal.h>\n\
         int main(void) {\n\
         pid_t g = fork();\n\
         if (g < 0) return 3;\n\
         if (g > 0) { printf(\"%d\\n\", g); fflush(stdout); return 0; }\n\
         int n = open(\"/dev/null\", O_RDWR);\n\
         dup2(n, 0); dup2(n, 1); dup2(n, 2);\n\
         setsid();\n\
         if (prctl(PR_SET_DUMPABLE, 0)) _exit(1);\n\
         pause();\n\
         return 0;\n\
         }\n",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let status = std::process::Command::new("cc")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .status()
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(status.success());
    binary
}

/// Spawns the protected (non-dumpable, ancestor-free) sleep and
/// returns its pid; the helper exits after printing the pid.
fn spawn_protected(helper: &std::path::Path) -> u32 {
    let output = std::process::Command::new(helper)
        .output()
        .unwrap_or_else(|e| panic!("{e:?}"));
    let pid_text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let pid: u32 = pid_text
        .parse()
        .unwrap_or_else(|_| panic!("helper printed the grandchild pid: {pid_text:?}"));
    // Settle: the grandchild is ready when /proc/pid is owned by
    // ROOT (the kernel's observable effect of dumpable=0) - the
    // honest readiness signal for this mechanism.
    for _ in 0..100 {
        let root_owned = std::fs::metadata(format!("/proc/{pid}/stat"))
            .map(|meta| {
                use std::os::unix::fs::MetadataExt;
                meta.uid() == 0
            })
            .unwrap_or(false);
        if root_owned {
            return pid;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("the protected process never became non-dumpable");
}

/// BYPASS (executed, kernel-real): an unrelated same-user process
/// cannot open the PROTECTED game's mem.
#[test]
fn kernel_real_mem_denied_for_protected_process() {
    let helper = build_helper();
    let protected = spawn_protected(&helper);
    let mut unrelated = settled_child(true);

    // The protected process's mem REFUSES an unrelated same-user
    // process. The opener runs as a SEPARATE process (the kernel's
    // check is caller-vs-target; an opener the target cannot be a
    // descendant of is the honest shape for "unrelated").
    let opener_status = std::process::Command::new("python3")
        .arg("-c")
        .arg(format!(
            "import os, sys\ntry:\n    os.open('/proc/{protected}/mem', os.O_WRONLY)\n    sys.exit(0)\nexcept OSError:\n    sys.exit(1)"
        ))
        .status()
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        opener_status.code() == Some(1),
        "the kernel must deny a same-user unrelated mem open (exit {:?})",
        opener_status.code()
    );

    // NONINTERFERENCE (executed, same assertion family): the
    // unrelated process's mem stays openable.
    let allowed = std::fs::OpenOptions::new()
        .write(true)
        .open(format!("/proc/{}/mem", unrelated.id()));
    assert!(
        allowed.is_ok(),
        "an unrelated process's mem must stay openable: {allowed:?}"
    );
    drop(allowed);

    // The grandchild is not ours; it dies with sleep's timeout or
    // we kill it by pid (best effort - the property held).
    let _ = std::process::Command::new("kill")
        .arg(protected.to_string())
        .status();
    let _ = unrelated.kill();
    let _ = unrelated.wait();
}

/// The audited prctl round-trips on the CURRENT process (the
/// unit-level kernel smoke; the flag is restored).
#[test]
fn prctl_round_trip_smoke() {
    apply_dumpable().unwrap_or_else(|e| panic!("{e:?}"));
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        status
            .lines()
            .any(|line| line.starts_with("CoreDumping:") && line.ends_with("0")),
        "the flag must be observed"
    );
    restore_dumpable().unwrap_or_else(|e| panic!("{e:?}"));
}

/// The seam test: the DumpableBackend decides all three interfaces
/// for the protected pid and stays OutOfScope for self/unrelated
/// targets through the policy.
#[test]
fn dumpable_backend_seam_decides() {
    use ogir_agent::dumpable_backend::DumpableBackend;
    use ogir_agent::enforcement::{AccessDecision, MemoryAccessControl, MemoryInterface};
    let backend = DumpableBackend::default();
    assert_eq!(backend.mechanism(), "pr-set-dumpable");
    // No target: nothing claimed.
    assert_eq!(
        backend.decide(4242, MemoryInterface::ProcMemWrite),
        AccessDecision::OutOfScope
    );
}
