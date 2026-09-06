// SPDX-License-Identifier: Apache-2.0
//! Shared test fixture: a real swtpm instance per test (ADR-0018
//! lessons: split argv, startup-clear, both-port readiness, retry).

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

pub struct SwtpmInstance {
    child: Option<Child>,
    state_dir: Option<PathBuf>,
    port: u16,
}

impl SwtpmInstance {
    pub fn start() -> Self {
        if let Ok(port) = std::env::var("OGIR_SWTPM_PROBE_PORT") {
            let port: u16 = port
                .parse()
                .unwrap_or_else(|error| panic!("bad probe port: {error}"));
            let mut instance = Self {
                child: None,
                state_dir: None,
                port,
            };
            instance.wait_ready();
            return instance;
        }
        for _ in 0..10 {
            let state_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
                "ogir-swtpm-{}-{}/",
                std::process::id(),
                counter()
            ));
            std::fs::create_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error:?}"));
            let probe = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e:?}"));
            let port = probe
                .local_addr()
                .unwrap_or_else(|e| panic!("{e:?}"))
                .port();
            drop(probe);
            let ctrl_port = port + 1;
            let mut child = Command::new("swtpm")
                .arg("socket")
                .arg("--tpm2")
                .arg("--tpmstate")
                .arg(format!("dir={}", state_dir.display()))
                .arg("--server")
                .arg(format!("type=tcp,bindaddr=127.0.0.1,port={port}"))
                .arg("--ctrl")
                .arg(format!("type=tcp,bindaddr=127.0.0.1,port={ctrl_port}"))
                .arg("--flags")
                .arg("not-need-init,startup-clear")
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|error| panic!("failed to spawn swtpm: {error}"));
            if wait_ready(Some(&mut child), port, ctrl_port) {
                return Self {
                    child: Some(child),
                    state_dir: Some(state_dir),
                    port,
                };
            }
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("swtpm attempt on port {port} failed");
        }
        panic!("swtpm failed to start after ten attempts");
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Kills the swtpm process without cleanup (the daemon-killed
    /// attack); Drop then has nothing to wait on.
    #[allow(dead_code)]
    pub fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn wait_ready(&mut self) {
        if !wait_ready(self.child.as_mut(), self.port, self.port.saturating_add(1)) {
            panic!("swtpm on port {} never listened", self.port);
        }
    }
}

impl Drop for SwtpmInstance {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            child.kill().unwrap_or_else(|error| panic!("{error:?}"));
            let _ = child.wait();
        }
        if let Some(state_dir) = self.state_dir.take() {
            let _ = std::fs::remove_dir_all(state_dir);
        }
    }
}

fn wait_ready(mut child: Option<&mut Child>, port: u16, ctrl_port: u16) -> bool {
    let mut elapsed = 0;
    while elapsed < 400 {
        if let Some(Ok(Some(_))) = child.as_mut().map(|child| child.try_wait()) {
            return false;
        }
        if TcpListener::bind(("127.0.0.1", port)).is_err()
            && TcpListener::bind(("127.0.0.1", ctrl_port)).is_err()
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        elapsed += 1;
    }
    false
}

fn counter() -> u64 {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
