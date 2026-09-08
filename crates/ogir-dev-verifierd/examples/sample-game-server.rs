// SPDX-License-Identifier: Apache-2.0

//! The sample game backend (M6-039, ADR-0035): a publisher's game
//! server demonstrating the roadmap's five-step integration target
//! against the developer-mode verifier daemon:
//!
//!   1. the server requests a challenge from the verifier;
//!   2. the (simulated) client passes the challenge to OGIR;
//!   3. the client submits the opaque permit and session proof;
//!   4. the server handles allow / restricted / unsupported / retry
//!      / deny - WITHOUT ever parsing TPM logs or making a local
//!      trust decision of its own.
//!
//! Run the daemon first (cargo run -p ogir-dev-verifierd --bin
//! ogir-dev-verifierd), then:
//!   cargo run -p ogir-dev-verifierd --example sample-game-server
//!
//! The server keeps its own policy: which verdict families it maps
//! to which gameplay states is THE PUBLISHER'S choice; the kit and
//! the no-ban documentation (docs/CASUAL_FALLBACK.md) show the
//! intended mapping.

use std::io::{Read, Write};
use std::net::TcpStream;

/// One verdict family mapped to a gameplay state - the publisher's
/// policy table, in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GameplayState {
    /// Full protected-session features.
    Admit,
    /// Admission with reduced-scope features.
    AdmitRestricted,
    /// The casual-fallback path: full game, no protected extras.
    CasualFallback,
    /// Retry the flow after a backoff; never punitive.
    RetryLater,
    /// The server's own decision to end the flow; NOT a ban and
    /// never an accusation (the no-ban rule).
    EndGracefully,
}

fn policy_for(verdict: &str, reason_code: &str) -> GameplayState {
    match verdict {
        "allow" => GameplayState::Admit,
        "restricted" => GameplayState::AdmitRestricted,
        "unsupported" => GameplayState::CasualFallback,
        "retry" => GameplayState::RetryLater,
        // deny: the publisher server's own relayed decision. The
        // demo maps it to a graceful end; a real title decides its
        // own response. It is never a cheating accusation.
        _ => {
            let _ = reason_code;
            GameplayState::EndGracefully
        }
    }
}

fn post(path: &str, body: &str) -> (String, String) {
    let mut stream = TcpStream::connect("127.0.0.1:8080")
        .unwrap_or_else(|e| panic!("is ogir-dev-verifierd running? {e}"));
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

fn extract(body: &str, key: &str) -> String {
    let needle = format!("\"{key}\":\"");
    let start = body
        .find(&needle)
        .unwrap_or_else(|| panic!("member {key} in {body}"))
        + needle.len();
    let rest = &body[start..];
    let end = rest.find('"').unwrap_or(rest.len());
    rest[..end].to_string()
}

fn main() {
    println!("=== OGIR sample game backend (the five-step target) ===");

    // Step 1: the SERVER requests a challenge from the verifier for
    // this match's context. In production the verifier is the
    // publisher's own service; here, the dev daemon.
    println!("[1/4] server requests challenge...");
    let (status, body) = post(
        "/v1/challenge",
        "{\"publisher_id\":\"pub.example\",\"game_id\":\"game.1\",\"build_id\":\"build.9\",\
         \"account_scope\":\"account.7\",\"match_id\":\"match.demo\",\
         \"policy_id\":\"policy.default\",\"policy_version\":\"3\"}",
    );
    assert_eq!(status, "200", "daemon unreachable or unhappy: {body}");
    let challenge_hex = extract(&body, "challenge_hex");
    println!("     challenge issued ({} hex chars)", challenge_hex.len());

    // Step 2: the CLIENT passes the challenge to OGIR. In
    // production this is the ogir-client.dll transport inside the
    // game; in developer mode, the daemon's simulation route.
    println!("[2/4] client passes challenge to OGIR (dev simulation)...");
    let (status, body) = post(
        "/v1/dev/evidence",
        &format!("{{\"challenge_hex\":\"{challenge_hex}\"}}"),
    );
    assert_eq!(status, "200", "{body}");
    let evidence_hex = extract(&body, "evidence_hex");
    println!("     evidence prepared ({} hex chars)", evidence_hex.len());

    // Step 3: the client submits the opaque evidence; the verifier
    // answers with the STRUCTURED verdict and, on admission, the
    // opaque permit. The server never parses the evidence or the
    // permit internals - it relays the permit where its own policy
    // needs it.
    println!("[3/4] client submits; server relays...");
    let (status, body) = post(
        "/v1/evidence",
        &format!("{{\"challenge_hex\":\"{challenge_hex}\",\"evidence_hex\":\"{evidence_hex}\"}}"),
    );
    assert_eq!(status, "200", "{body}");
    let verdict = extract(&body, "verdict");
    let reason_code = extract(&body, "reason_code");
    println!("     verdict: {verdict} (reason: {reason_code})");

    // Step 4: the SERVER maps the family to a gameplay state per
    // ITS OWN policy - and never treats unsupported as cheating.
    let state = policy_for(&verdict, &reason_code);
    println!("[4/4] server policy maps to: {state:?}");
    match state {
        GameplayState::Admit | GameplayState::AdmitRestricted => {
            let permit = extract(&body, "permit_hex");
            println!(
                "     permit on file ({} hex chars) - protected session proceeds",
                permit.len()
            );
        }
        GameplayState::CasualFallback => {
            println!("     casual fallback: full game, no protected extras - no ban, no flag");
        }
        GameplayState::RetryLater => {
            println!("     retry after backoff - transient, never punitive");
        }
        GameplayState::EndGracefully => {
            println!("     flow ends gracefully - the server's decision, not an accusation");
        }
    }

    // The renewal leg: the server demonstrates ADR-0014 renewal and
    // the revocation leg: the server retires the permit.
    if matches!(state, GameplayState::Admit | GameplayState::AdmitRestricted) {
        let permit = extract(&body, "permit_hex");
        println!("\n=== lifecycle: renewal then revocation ===");
        let (_, renew_body) = post(
            "/v1/renew",
            &format!("{{\"permit_hex\":\"{permit}\",\"evidence_hex\":\"{evidence_hex}\"}}"),
        );
        println!(
            "renewal with stale evidence: {} ({})",
            extract(&renew_body, "verdict"),
            extract(&renew_body, "reason_code")
        );
        let (_, revoke_body) = post("/v1/revoke", &format!("{{\"target_hex\":\"{permit}\"}}"));
        println!("revocation: {}", extract(&revoke_body, "revoked"));
    }

    println!("\nsample backend complete.");
}
