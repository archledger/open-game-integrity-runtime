// SPDX-License-Identifier: Apache-2.0

//! The M5-031 portal integration suite: the full local-portal legs
//! against real sockets - the credential round trip (kernel-observed,
//! never caller-supplied), the normalized framing, and the attack
//! legs that belong to this slice (request flood, oversized and
//! malformed input).

use std::io::Write;
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use ogir_agent::portal::PortalResponse;
use ogir_agent::portal::{
    MAX_FRAMES_PER_CONNECTION, PeerCredentials, Portal, PortalError, PortalRequest, decode_request,
    encode_response, peer_credentials, read_frame, serve_connection, write_frame,
};

fn socket_path(name: &str) -> PathBuf {
    // Short paths: sun_path is 108 bytes and cargo's tmpdir under a
    // deep worktree overflows it.
    PathBuf::from(format!("/tmp/ogpt-{}-{name}.sock", std::process::id()))
}

fn hello_frame(version: u32, name: &str) -> Vec<u8> {
    let mut body = vec![b'H'];
    body.extend_from_slice(&version.to_be_bytes());
    body.extend_from_slice(name.as_bytes());
    body
}

fn real_uid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_else(|e| panic!("{e:?}"));
    status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("uid value"))
}

fn decode_response(frame: &[u8]) -> PortalResponse {
    match frame.split_first() {
        Some((b'H', rest)) if rest.len() == 16 => PortalResponse::HelloAck {
            version: u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]),
            observed: PeerCredentials {
                pid: u32::from_be_bytes([rest[4], rest[5], rest[6], rest[7]]),
                uid: u32::from_be_bytes([rest[8], rest[9], rest[10], rest[11]]),
                gid: u32::from_be_bytes([rest[12], rest[13], rest[14], rest[15]]),
            },
        },
        // Rejected reasons are static strings on the wire; a foreign
        // payload is not a reason we repeat.
        Some((b'R', _)) => PortalResponse::Rejected { reason: "rejected" },
        _ => panic!("undecodable response frame"),
    }
}

#[test]
fn portal_socket_is_private_and_self_cleaning() {
    let path = socket_path("permissions");
    let portal = Portal::bind(&path).unwrap_or_else(|e| panic!("{e:?}"));
    let mode = std::fs::metadata(portal.path())
        .unwrap_or_else(|e| panic!("{e:?}"))
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "only the same UID may connect");
    drop(portal);
    assert!(!path.exists(), "the portal removes its socket");
}

#[test]
fn credentials_come_from_the_kernel_not_the_client() {
    let path = socket_path("creds");
    let portal = Portal::bind(&path).unwrap_or_else(|e| panic!("{e:?}"));

    let mut client = UnixStream::connect(&path).unwrap_or_else(|e| panic!("{e:?}"));
    let (mut server, observed) = portal.accept().unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(observed.pid, std::process::id());
    assert_eq!(observed.uid, real_uid());

    // The client may CLAIM anything in its payload; the answer must
    // carry the kernel-observed credentials of THIS test process.
    write_frame(&mut client, &hello_frame(1, "i-am-totally-the-game"))
        .unwrap_or_else(|e| panic!("{e:?}"));
    client
        .shutdown(Shutdown::Write)
        .unwrap_or_else(|e| panic!("{e:?}"));
    serve_connection(&mut server, observed).unwrap_or_else(|e| panic!("{e:?}"));

    let frame = read_frame(&mut client).unwrap_or_else(|e| panic!("{e:?}"));
    let PortalResponse::HelloAck { version, observed } = decode_response(&frame) else {
        panic!("expected HelloAck, got {:?}", decode_response(&frame))
    };
    assert_eq!(version, 1);
    assert_eq!(observed.pid, std::process::id());
    assert_eq!(observed.uid, real_uid());
}

/// The request-flood leg: a connection that exceeds its frame budget
/// is reported as a flood, not served forever.
#[test]
fn request_flood_is_bounded() {
    let (mut client, server) = UnixStream::pair().unwrap_or_else(|e| panic!("{e:?}"));
    let observed = peer_credentials(&server).unwrap_or_else(|e| panic!("{e:?}"));

    let frame = hello_frame(1, "flooder");
    // The server runs concurrently: the client interacts live.
    let server_handle = std::thread::spawn(move || {
        let mut server = server;
        serve_connection(&mut server, observed)
    });
    for _ in 0..MAX_FRAMES_PER_CONNECTION {
        write_frame(&mut client, &frame).unwrap_or_else(|e| panic!("{e:?}"));
        let _ = read_frame(&mut client);
    }
    // One more frame past the budget: the verdict must be Flooded.
    write_frame(&mut client, &frame).unwrap_or_else(|e| panic!("{e:?}"));
    client.flush().unwrap_or_else(|e| panic!("{e:?}"));
    client
        .shutdown(Shutdown::Write)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        server_handle
            .join()
            .unwrap_or_else(|_| panic!("server thread panicked")),
        Err(PortalError::Flooded)
    );
}

/// The oversized leg: a length prefix beyond the ceiling rejects
/// without reading (or allocating) the body.
#[test]
fn oversized_requests_fail_closed() {
    let (mut client, mut server) = UnixStream::pair().unwrap_or_else(|e| panic!("{e:?}"));
    let observed = peer_credentials(&server).unwrap_or_else(|e| panic!("{e:?}"));

    // A 2048-byte promise, then close: the portal must refuse it
    // without trying to drain 2048 bytes.
    client
        .write_all(&2048u32.to_be_bytes())
        .unwrap_or_else(|e| panic!("{e:?}"));
    client.flush().unwrap_or_else(|e| panic!("{e:?}"));
    client
        .shutdown(Shutdown::Write)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        serve_connection(&mut server, observed),
        Err(PortalError::OversizedFrame)
    );
}

/// Unknown and malformed messages produce normalized rejections on
/// the wire, never crashes or sessions.
#[test]
fn malformed_requests_get_normalized_rejections() {
    let (mut client, mut server) = UnixStream::pair().unwrap_or_else(|e| panic!("{e:?}"));
    let observed = peer_credentials(&server).unwrap_or_else(|e| panic!("{e:?}"));

    write_frame(&mut client, b"Zunknown-kind").unwrap_or_else(|e| panic!("{e:?}"));
    client
        .shutdown(Shutdown::Write)
        .unwrap_or_else(|e| panic!("{e:?}"));
    serve_connection(&mut server, observed).unwrap_or_else(|e| panic!("{e:?}"));

    let frame = read_frame(&mut client).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(frame, b"Rmalformed message");
}

#[test]
fn requests_decode_fail_closed() {
    assert_eq!(
        decode_request(b""),
        Err(PortalError::Malformed("empty frame"))
    );
    assert_eq!(
        decode_request(b"H\x00"),
        Err(PortalError::Malformed("short hello"))
    );
    let non_utf8 = {
        let mut body = vec![b'H'];
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&[0xff, 0xfe]);
        body
    };
    assert_eq!(
        decode_request(&non_utf8),
        Err(PortalError::Malformed("client name"))
    );
}

#[test]
fn hello_round_trip_through_the_wire_format() {
    let (mut client, mut server) = UnixStream::pair().unwrap_or_else(|e| panic!("{e:?}"));
    write_frame(&mut client, &hello_frame(7, "sample-client")).unwrap_or_else(|e| panic!("{e:?}"));
    let frame = read_frame(&mut server).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        decode_request(&frame).unwrap_or_else(|e| panic!("{e:?}")),
        PortalRequest::Hello {
            version: 7,
            client_name: "sample-client".to_string(),
        }
    );

    let response = PortalResponse::HelloAck {
        version: 7,
        observed: PeerCredentials {
            pid: 1,
            uid: 2,
            gid: 3,
        },
    };
    let body = encode_response(&response).unwrap_or_else(|e| panic!("{e:?}"));
    write_frame(&mut server, &body).unwrap_or_else(|e| panic!("{e:?}"));
    let echoed = read_frame(&mut client).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(decode_response(&echoed), response);
}
