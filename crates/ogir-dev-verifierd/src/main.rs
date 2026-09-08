// SPDX-License-Identifier: Apache-2.0

//! The developer-mode verifier daemon binary (M6-036): serves the
//! test-substrate verifier on the given address (default
//! 127.0.0.1:8080 - the no-TLS, localhost-by-default posture of
//! ADR-0032). Usage: ogir-dev-verifierd [address]

#![forbid(unsafe_code)]

fn main() {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());
    println!("ogir-dev-verifierd: developer mode (test keys, simulated profiles)");
    println!("listening on http://{address} (no TLS: bind localhost or front with your proxy)");
    if let Err(error) = ogir_dev_verifierd::run_dev_daemon(&address, unix_now) {
        eprintln!("daemon failed: {error}");
        std::process::exit(1);
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
