// SPDX-License-Identifier: Apache-2.0

//! The native Linux sample client (M5-031, roadmap implementation
//! order step 1): connects to the local portal, sends one Hello,
//! and prints the credentials the portal observed for THIS process.
//! Run with:
//!   cargo run -p ogir-agent --example portal-client -- [socket-path]

use std::os::unix::net::UnixStream;

use ogir_agent::portal::{read_frame, write_frame};

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/run/user/1000/ogir/portal.sock".to_string());
    let mut stream = match UnixStream::connect(&path) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!("cannot connect to {path}: {error}");
            std::process::exit(1);
        }
    };

    let mut hello = vec![b'H'];
    hello.extend_from_slice(&1u32.to_be_bytes());
    hello.extend_from_slice(b"native-sample");
    if let Err(error) = write_frame(&mut stream, &hello) {
        eprintln!("send failed: {error}");
        std::process::exit(1);
    }

    let frame = match read_frame(&mut stream) {
        Ok(frame) => frame,
        Err(error) => {
            eprintln!("receive failed: {error}");
            std::process::exit(1);
        }
    };
    if frame.first() == Some(&b'H') && frame.len() == 17 {
        let value = |offset: usize| {
            u32::from_be_bytes([
                frame[offset],
                frame[offset + 1],
                frame[offset + 2],
                frame[offset + 3],
            ])
        };
        println!(
            "portal v{} observed: pid={} uid={} gid={}",
            value(1),
            value(5),
            value(9),
            value(13)
        );
    } else {
        eprintln!("portal rejected the greeting");
        std::process::exit(1);
    }
}
