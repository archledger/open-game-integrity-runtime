// SPDX-License-Identifier: Apache-2.0

//! A minimal unprivileged portal host for development and bridge
//! testing (M5-033/034): binds the portal socket, accepts
//! connections, reads kernel credentials, pins the caller, and
//! serves the bounded v1 protocol. Run with:
//!   cargo run -p ogir-agent --example portal-serve -- [socket-path]

use std::time::Duration;

use ogir_agent::binding::CallerBinding;
use ogir_agent::portal::{Portal, serve_connection};

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/ogir-portal.sock".to_string());
    let portal = match Portal::bind(std::path::Path::new(&path)) {
        Ok(portal) => portal,
        Err(error) => {
            // Never echo the caller-supplied path.
            eprintln!("cannot bind the requested portal socket: {error}");
            std::process::exit(1);
        }
    };
    println!("portal listening on {}", portal.path().display());

    for round in 0..8 {
        let (mut stream, credentials) = match portal.accept() {
            Ok(pair) => pair,
            Err(error) => {
                eprintln!("accept failed: {error}");
                std::process::exit(1);
            }
        };
        let binding = CallerBinding::pin(&credentials);
        // pid and start time only; uid/gid are sensitive-adjacent
        // and add nothing for development.
        println!("round {round}: peer pid={}", credentials.pid);
        match binding {
            Ok(binding) => {
                println!(
                    "  pinned: start_time={} alive={}",
                    binding.start_time(),
                    binding.still_pins()
                );
            }
            Err(error) => println!("  pin failed (fail closed): {error}"),
        }
        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        match serve_connection(&mut stream, credentials) {
            Ok(()) => println!("  connection served"),
            Err(error) => println!("  connection ended: {error}"),
        }
    }
    println!("portal closing after 8 rounds");
}
