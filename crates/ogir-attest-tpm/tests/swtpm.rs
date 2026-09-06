// SPDX-License-Identifier: Apache-2.0

//! Integration suite for the swtpm software-TPM backend: a real swtpm
//! instance per test, real AK creation, real TPM 2.0 quotes, and the
//! class-gate behavior. Requires `swtpm` on PATH (CI installs it; the
//! development host has 0.10.2). `OGIR_SWTPM_PROBE_PORT` points the
//! suite at an already-running instance instead of spawning one.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use ogir_attest::{AssuranceClass, AttestationBackend, QuoteRequest, accept_class};

struct SwtpmInstance {
    child: Option<Child>,
    state_dir: Option<PathBuf>,
    port: u16,
}

impl SwtpmInstance {
    fn start() -> Self {
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
        // Parallel tests race for ports: retry so a server/ctrl port
        // collision cannot fail the suite.
        for _ in 0..10 {
            let state_dir = std::env::temp_dir().join(format!(
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
            eprintln!("swtpm attempt on port {port} failed; stderr follows:");
            if let Some(mut stderr) = child.stderr.take() {
                use std::io::Read;
                let mut buffer = String::new();
                let _ = stderr.read_to_string(&mut buffer);
                eprintln!("{buffer}");
            }
        }
        panic!("swtpm failed to start after ten attempts");
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
            // Both the server and ctrl channels listen: the TCTI
            // handshake can proceed.
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        elapsed += 1;
    }
    false
}

// A cheap unique suffix without a crate dependency.
fn counter() -> u64 {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn payload_field(payload: &[u8], index: usize) -> &[u8] {
    let mut offset = 0;
    for current in 0..=index {
        let length = u32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]) as usize;
        offset += 4;
        if current == index {
            return &payload[offset..offset + length];
        }
        offset += length;
    }
    panic!("field {index} not found");
}

#[test]
fn swtpm_backend_produces_real_quotes_bound_to_qualifying_data() {
    let instance = SwtpmInstance::start();
    let mut backend = ogir_attest_tpm::swtpm::SwtpmBackend::connect("127.0.0.1", instance.port)
        .unwrap_or_else(|error| panic!("{error:?}"));

    assert_eq!(backend.assurance_class(), AssuranceClass::SoftwareTpm);
    assert_eq!(backend.backend_id(), "swtpm-tpm2-v1");

    let request = QuoteRequest {
        qualifying_data: b"ogir-m3-021-qualifying".to_vec(),
    };
    let statement = backend.quote(&request).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(statement.assurance_class(), AssuranceClass::SoftwareTpm);
    assert_eq!(statement.backend_id(), "swtpm-tpm2-v1");
    assert_eq!(statement.qualifying_digest().len(), 32);

    // The TPM echoes the qualifying data in the quote payload.
    assert_eq!(
        payload_field(statement.quote_payload(), 0),
        b"ogir-m3-021-qualifying"
    );
    // The attested PCR digest appears both as the statement digest and
    // as the second payload field.
    assert_eq!(
        payload_field(statement.quote_payload(), 1),
        statement.qualifying_digest()
    );
    // An RSA-2048 signature is 256 bytes.
    assert_eq!(payload_field(statement.quote_payload(), 2).len(), 256);
}

#[test]
fn different_qualifying_data_changes_the_quote_payload() {
    let instance = SwtpmInstance::start();
    let mut backend = ogir_attest_tpm::swtpm::SwtpmBackend::connect("127.0.0.1", instance.port)
        .unwrap_or_else(|error| panic!("{error:?}"));
    let left = backend
        .quote(&QuoteRequest {
            qualifying_data: b"first".to_vec(),
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
    let right = backend
        .quote(&QuoteRequest {
            qualifying_data: b"second".to_vec(),
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_ne!(left.quote_payload(), right.quote_payload());
    assert_eq!(payload_field(left.quote_payload(), 0), b"first");
    assert_eq!(payload_field(right.quote_payload(), 0), b"second");
}

#[test]
fn software_class_statements_are_rejected_under_hardware_expectations() {
    let instance = SwtpmInstance::start();
    let mut backend = ogir_attest_tpm::swtpm::SwtpmBackend::connect("127.0.0.1", instance.port)
        .unwrap_or_else(|error| panic!("{error:?}"));
    let statement = backend
        .quote(&QuoteRequest {
            qualifying_data: b"class-check".to_vec(),
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(accept_class(AssuranceClass::SoftwareTpm, statement.assurance_class()).is_ok());
    assert!(
        accept_class(
            AssuranceClass::HardwareFirmwareTpm,
            statement.assurance_class()
        )
        .is_err()
    );
    assert!(accept_class(AssuranceClass::Test, statement.assurance_class()).is_err());
}

#[test]
fn invalid_requests_fail_closed_without_tpm_state() {
    let instance = SwtpmInstance::start();
    let mut backend = ogir_attest_tpm::swtpm::SwtpmBackend::connect("127.0.0.1", instance.port)
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(
        backend
            .quote(&QuoteRequest {
                qualifying_data: Vec::new()
            })
            .err(),
        Some(ogir_attest::BackendError::InvalidRequest)
    );
}

#[test]
fn unreachable_instance_fails_closed() {
    // Grab a free port with nothing listening.
    let probe = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e:?}"));
    let port = probe
        .local_addr()
        .unwrap_or_else(|e| panic!("{e:?}"))
        .port();
    drop(probe);
    assert!(ogir_attest_tpm::swtpm::SwtpmBackend::connect("127.0.0.1", port).is_err());
}
