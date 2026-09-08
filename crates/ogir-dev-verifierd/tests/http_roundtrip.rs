// SPDX-License-Identifier: Apache-2.0

//! The M6-036 end-to-end service test: the developer-mode daemon
//! serves REAL HTTP over TCP on an ephemeral port, and the full
//! three-step integration target runs against it - issue a
//! challenge, simulate the client's evidence, submit - plus the
//! first server-side attack legs (replay, no-challenge-yet,
//! malformed bodies, unknown routes, oversized bodies).

use std::io::{Read, Write};
use std::net::TcpStream;

use ogir_dev_verifierd::DevBackend;
use ogir_verifier::http::Listener;
use ogir_verifier::service::{ChallengeRequest, serve_one};

fn post(stream: &mut TcpStream, path: &str, body: &str) -> (String, String) {
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .unwrap_or_else(|e| panic!("{e:?}"));
    stream.flush().unwrap_or_else(|e| panic!("{e:?}"));
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let text = String::from_utf8_lossy(&response).to_string();
    let status = text
        .lines()
        .next()
        .unwrap_or_default()
        .split(' ')
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, rest)| rest.to_string())
        .unwrap_or_default();
    (status, body)
}

fn connect(port: u16) -> TcpStream {
    TcpStream::connect(("127.0.0.1", port)).unwrap_or_else(|e| panic!("{e:?}"))
}

fn issue_body() -> String {
    "{\"publisher_id\":\"pub.example\",\"game_id\":\"game.1\",\"build_id\":\"build.9\",\"account_scope\":\"account.7\",\"match_id\":\"match.3\",\"policy_id\":\"policy.default\",\"policy_version\":\"3\"}"
        .to_string()
}

#[test]
fn full_three_step_flow_admits() {
    let backend = DevBackend::new();
    let listener = Listener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e:?}"));
    let port = listener
        .local_address()
        .unwrap_or_else(|e| panic!("{e:?}"))
        .port();
    let server = std::thread::spawn(move || {
        for _ in 0..3 {
            let mut stream = listener.accept().unwrap_or_else(|e| panic!("{e:?}"));
            serve_one(&mut stream, 1_000, &backend, Some(&backend), &backend)
                .unwrap_or_else(|e| panic!("{e:?}"));
        }
    });

    // Step 1: the game's server requests a challenge.
    let (status, body) = post(&mut connect(port), "/v1/challenge", &issue_body());
    assert_eq!(status, "200", "{body}");
    let challenge_hex = extract_hex(&body, "challenge_hex");
    assert!(!challenge_hex.is_empty());

    // Step 2: developer mode simulates the client's evidence.
    let (status, body) = post(
        &mut connect(port),
        "/v1/dev/evidence",
        &format!("{{\"challenge_hex\":\"{challenge_hex}\"}}"),
    );
    assert_eq!(status, "200", "{body}");
    let evidence_hex = extract_hex(&body, "evidence_hex");

    // Step 3: the submission is processed and ADMITS with a permit.
    let (status, body) = post(
        &mut connect(port),
        "/v1/evidence",
        &format!("{{\"challenge_hex\":\"{challenge_hex}\",\"evidence_hex\":\"{evidence_hex}\"}}"),
    );
    assert_eq!(status, "200", "{body}");
    assert!(body.contains("\"verdict\":\"allow\""), "{body}");
    assert!(!extract_hex(&body, "permit_hex").is_empty());

    server.join().unwrap_or_else(|_| panic!("server panicked"));
}

#[test]
fn duplicate_submission_is_replayed_away() {
    let backend = DevBackend::new();
    let listener = Listener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e:?}"));
    let port = listener
        .local_address()
        .unwrap_or_else(|e| panic!("{e:?}"))
        .port();
    let server = std::thread::spawn(move || {
        for _ in 0..4 {
            let mut stream = listener.accept().unwrap_or_else(|e| panic!("{e:?}"));
            serve_one(&mut stream, 1_000, &backend, Some(&backend), &backend)
                .unwrap_or_else(|e| panic!("{e:?}"));
        }
    });

    let (_, body) = post(&mut connect(port), "/v1/challenge", &issue_body());
    let challenge_hex = extract_hex(&body, "challenge_hex");
    let (_, body) = post(
        &mut connect(port),
        "/v1/dev/evidence",
        &format!("{{\"challenge_hex\":\"{challenge_hex}\"}}"),
    );
    let evidence_hex = extract_hex(&body, "evidence_hex");
    let submission =
        format!("{{\"challenge_hex\":\"{challenge_hex}\",\"evidence_hex\":\"{evidence_hex}\"}}");

    let (status, first) = post(&mut connect(port), "/v1/evidence", &submission);
    assert_eq!(status, "200");
    assert!(first.contains("\"verdict\":\"allow\""), "{first}");

    // The SAME submission again: the replay cache denies it.
    let (status, second) = post(&mut connect(port), "/v1/evidence", &submission);
    assert_eq!(status, "200");
    assert!(second.contains("\"verdict\":\"deny\""), "{second}");
    assert!(second.contains("ReplayDetected"), "{second}");

    server.join().unwrap_or_else(|_| panic!("server panicked"));
}

#[test]
fn submission_before_any_challenge_denies_cleanly() {
    let backend = DevBackend::new();
    let listener = Listener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e:?}"));
    let port = listener
        .local_address()
        .unwrap_or_else(|e| panic!("{e:?}"))
        .port();
    let server = std::thread::spawn(move || {
        let mut stream = listener.accept().unwrap_or_else(|e| panic!("{e:?}"));
        serve_one(&mut stream, 1_000, &backend, Some(&backend), &backend)
            .unwrap_or_else(|e| panic!("{e:?}"));
    });

    // Evidence for a challenge that was never issued: the inner
    // verification fails before the no-challenge state matters;
    // either way it is a clean denial, never a permit.
    let (status, body) = post(
        &mut connect(port),
        "/v1/evidence",
        "{\"challenge_hex\":\"00\",\"evidence_hex\":\"00\"}",
    );
    assert_eq!(status, "200", "{body}");
    assert!(body.contains("\"verdict\":\"deny\""), "{body}");

    server.join().unwrap_or_else(|_| panic!("server panicked"));
}

#[test]
fn malformed_bodies_and_routes_reject_with_400() {
    let backend = DevBackend::new();
    let listener = Listener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e:?}"));
    let port = listener
        .local_address()
        .unwrap_or_else(|e| panic!("{e:?}"))
        .port();
    let server = std::thread::spawn(move || {
        for _ in 0..4 {
            let mut stream = listener.accept().unwrap_or_else(|e| panic!("{e:?}"));
            let _ = serve_one(&mut stream, 1_000, &backend, Some(&backend), &backend);
        }
    });

    let (status, _) = post(&mut connect(port), "/v1/evidence", "{\"nope\":1}");
    assert_eq!(status, "400");
    let (status, _) = post(&mut connect(port), "/v1/absent", "{}");
    assert_eq!(status, "400");
    let (status, _) = post(
        &mut connect(port),
        "/v1/challenge",
        "{\"publisher_id\":\"only-one-field\"}",
    );
    assert_eq!(status, "400");
    let (status, _) = post(&mut connect(port), "/v1/evidence", "{}");
    assert_eq!(status, "400");

    server.join().unwrap_or_else(|_| panic!("server panicked"));
}

#[test]
fn oversized_bodies_are_refused() {
    let backend = DevBackend::new();
    let listener = Listener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e:?}"));
    let port = listener
        .local_address()
        .unwrap_or_else(|e| panic!("{e:?}"))
        .port();
    let server = std::thread::spawn(move || {
        let mut stream = listener.accept().unwrap_or_else(|e| panic!("{e:?}"));
        // The oversized request fails at read time; the handler
        // returns the error without a response body.
        let _ = serve_one(&mut stream, 1_000, &backend, Some(&backend), &backend);
    });

    let mut stream = connect(port);
    let huge = "x".repeat(70 * 1024);
    let request = format!(
        "POST /v1/evidence HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{huge}",
        huge.len()
    );
    stream
        .write_all(request.as_bytes())
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    // The server closed without a 200: the ceiling held.
    let text = String::from_utf8_lossy(&response);
    assert!(!text.starts_with("HTTP/1.1 200"), "{text}");

    server.join().unwrap_or_else(|_| panic!("server panicked"));
}

/// Extracts a hex member from a flat response body.
fn extract_hex(body: &str, key: &str) -> String {
    let needle = format!("\"{key}\":\"");
    let start = body
        .find(&needle)
        .unwrap_or_else(|| panic!("member {key} in {body}"))
        + needle.len();
    let rest = &body[start..];
    let end = rest.find('"').unwrap_or(rest.len());
    rest[..end].to_string()
}

/// The issuer trait's request shape is directly constructible (the
/// library-level smoke the daemon wraps).
#[test]
fn challenge_request_shape_is_public() {
    let request = ChallengeRequest {
        publisher_id: "p".to_string(),
        game_id: "g".to_string(),
        build_id: "b".to_string(),
        account_scope: "a".to_string(),
        match_id: "m".to_string(),
        policy_id: "pol".to_string(),
        policy_version: 1,
    };
    assert_eq!(request.publisher_id, "p");
}
