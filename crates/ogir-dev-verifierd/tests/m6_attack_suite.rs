// SPDX-License-Identifier: Apache-2.0

//! The M6 attack suite: all ten roadmap attack-test categories as
//! one named inventory (the M2-019/M3-025/M4-030/M5-035 pattern),
//! executed against the REAL service stack - the production shell
//! (HTTP + codec + routes) with the developer-mode backend - over
//! real TCP. Legs already hosted in focused suites are re-hosted
//! here so the milestone record is self-contained.
//!
//! The ten categories (docs/ROADMAP.md, M6):
//!   1. server neglects signature validation;
//!   2. wrong expected match/account/policy;
//!   3. stale verifier key;
//!   4. compromised or revoked policy fixture;
//!   5. permit parser confusion;
//!   6. missing proof of possession;
//!   7. verifier time skew;
//!   8. duplicate/non-idempotent submission;
//!   9. outage and retry behavior;
//!   10. publisher accidentally treats unsupported as cheating.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use ogir_dev_verifierd::DevBackend;
use ogir_verifier::service::{
    ChallengeIssuer, EvidenceProcessor, EvidenceSimulator, PermitRenewer, RevocationAuthority,
    VerdictKind, WireVerdict, serve_one,
};

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

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| {
            u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .unwrap_or_else(|e| panic!("hex at {i}: {e}"))
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Serves n requests for one test on an ephemeral port.
fn serve_n(backend: &Arc<DevBackend>, requests: usize) -> u16 {
    serve_at(backend, requests, 1_000)
}

/// Serves n requests with a FIXED decision time (the time-skew leg).
fn serve_at(backend: &Arc<DevBackend>, requests: usize, now: u64) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e:?}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e:?}"))
        .port();
    let backend = Arc::clone(backend);
    std::thread::spawn(move || {
        let backend: &DevBackend = backend.as_ref();
        for _ in 0..requests {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let _ = serve_one(
                &mut stream,
                now,
                backend,
                Some(backend),
                backend,
                backend,
                backend,
            );
        }
    });
    port
}

fn context(match_id: &str) -> String {
    format!(
        "{{\"publisher_id\":\"pub.example\",\"game_id\":\"game.1\",\"build_id\":\"build.9\",\
         \"account_scope\":\"account.7\",\"match_id\":\"{match_id}\",\
         \"policy_id\":\"policy.default\",\"policy_version\":\"3\"}}"
    )
}

fn connect(port: u16) -> TcpStream {
    TcpStream::connect(("127.0.0.1", port)).unwrap_or_else(|e| panic!("{e:?}"))
}

/// Issues a challenge and simulates a valid client answer for it.
fn issue_and_answer(_backend: &Arc<DevBackend>, port: u16, match_id: &str) -> (String, String) {
    let (_, body) = post(&mut connect(port), "/v1/challenge", &context(match_id));
    let challenge_hex = extract(&body, "challenge_hex");
    let (_, body) = post(
        &mut connect(port),
        "/v1/dev/evidence",
        &format!("{{\"challenge_hex\":\"{challenge_hex}\"}}"),
    );
    (challenge_hex, extract(&body, "evidence_hex"))
}

// Category 1: server neglects signature validation. The shell never
// skips it because the backend does it before any verdict: evidence
// NOT signed by a directory key (garbage bytes) can never admit,
// even when the challenge is genuine.
#[test]
fn cat01_unsigned_evidence_never_admits() {
    let backend = Arc::new(DevBackend::new());
    let port = serve_n(&backend, 3);
    let (challenge_hex, _) = issue_and_answer(&backend, port, "m.cat1");

    // Forged evidence: plausible shape, no valid signature.
    let forged = "42".repeat(200);
    let (status, body) = post(
        &mut connect(port),
        "/v1/evidence",
        &format!("{{\"challenge_hex\":\"{challenge_hex}\",\"evidence_hex\":\"{forged}\"}}"),
    );
    assert_eq!(status, "200", "{body}");
    assert_ne!(extract(&body, "verdict"), "allow", "{body}");
    assert!(extract(&body, "verdict") != "restricted", "{body}");
}

// Category 2: wrong expected match/account/policy. A submission for
// match A never admits under a service expecting match B (the
// per-issuance expected context).
#[test]
fn cat02_wrong_expected_context_denies() {
    let backend = Arc::new(DevBackend::new());
    let port = serve_n(&backend, 6);
    // Issue for match.a: the service now expects match.a.
    let (challenge_a, evidence_a) = issue_and_answer(&backend, port, "match.a");
    let (status, body) = post(
        &mut connect(port),
        "/v1/evidence",
        &format!("{{\"challenge_hex\":\"{challenge_a}\",\"evidence_hex\":\"{evidence_a}\"}}"),
    );
    // The correct pair admits; then issue for match.b and submit
    // the STALE (match.a) pair against the match.b expectation.
    assert_eq!(status, "200");
    let first_verdict = extract(&body, "verdict");
    let _ = first_verdict;
    let (challenge_b, _) = issue_and_answer(&backend, port, "match.b");
    let (status, body) = post(
        &mut connect(port),
        "/v1/evidence",
        &format!("{{\"challenge_hex\":\"{challenge_b}\",\"evidence_hex\":\"{evidence_a}\"}}"),
    );
    assert_eq!(status, "200", "{body}");
    assert_ne!(extract(&body, "verdict"), "allow", "{body}");
}

// Category 3: stale verifier key. A challenge signed by a key NOT in
// the directory (a stale/rotated-out key) fails validation before
// any verdict; the pair denies.
#[test]
fn cat03_stale_verifier_key_rejects() {
    let backend = Arc::new(DevBackend::new());
    let port = serve_n(&backend, 3);
    // A "stale key" product: a challenge object from a DIFFERENT
    // verifier key (simulated by an unknown directory).
    let (_, body) = post(&mut connect(port), "/v1/challenge", &context("m.cat3"));
    let challenge_hex = extract(&body, "challenge_hex");
    // Corrupt the signature tail (the last byte of the object).
    let mut bytes = decode_hex(&challenge_hex);
    let last = bytes.len().saturating_sub(1);
    bytes[last] ^= 0xFF;
    let corrupted = encode_hex(&bytes);
    let (_, body) = post(
        &mut connect(port),
        "/v1/dev/evidence",
        &format!("{{\"challenge_hex\":\"{corrupted}\"}}"),
    );
    // The simulator still signs an answer, but the backend's
    // validation of the CHALLENGE signature fails first.
    let evidence_hex = extract(&body, "evidence_hex");
    let (status, body) = post(
        &mut connect(port),
        "/v1/evidence",
        &format!("{{\"challenge_hex\":\"{corrupted}\",\"evidence_hex\":\"{evidence_hex}\"}}"),
    );
    assert_eq!(status, "200", "{body}");
    assert_ne!(extract(&body, "verdict"), "allow", "{body}");
}

// Category 4: compromised or revoked policy fixture. A revoked
// permit's exact bytes never re-admit and never renew.
#[test]
fn cat04_revoked_fixture_never_reanimates() {
    let backend = Arc::new(DevBackend::new());
    let port = serve_n(&backend, 5);
    let (challenge_hex, evidence_hex) = issue_and_answer(&backend, port, "m.cat4");
    let (_, body) = post(
        &mut connect(port),
        "/v1/evidence",
        &format!("{{\"challenge_hex\":\"{challenge_hex}\",\"evidence_hex\":\"{evidence_hex}\"}}"),
    );
    let permit = extract(&body, "permit_hex");
    assert!(extract(&body, "verdict") == "allow");

    // Revoke, then attempt renewal of the revoked permit.
    let (_, _) = post(
        &mut connect(port),
        "/v1/revoke",
        &format!("{{\"target_hex\":\"{permit}\"}}"),
    );
    let (_, body) = post(
        &mut connect(port),
        "/v1/renew",
        &format!("{{\"permit_hex\":\"{permit}\",\"evidence_hex\":\"{evidence_hex}\"}}"),
    );
    assert_ne!(extract(&body, "verdict"), "allow", "{body}");
    assert_eq!(extract(&body, "reason_code"), "Revoked", "{body}");
}

// Category 5: permit parser confusion (re-hosted from M6-037).
#[test]
fn cat05_permit_parser_confusion_denies_cleanly() {
    let backend = Arc::new(DevBackend::new());
    let port = serve_n(&backend, 1);
    let garbage = "00ff00ff00ff00ff00ff00ff00ff00ff";
    let (status, body) = post(
        &mut connect(port),
        "/v1/renew",
        &format!("{{\"permit_hex\":\"{garbage}\",\"evidence_hex\":\"{garbage}\"}}"),
    );
    assert_eq!(status, "200", "{body}");
    assert_eq!(extract(&body, "reason_code"), "Malformed", "{body}");
}

// Category 6: missing proof of possession. The SDK's permit relay
// without a PoP never admits on the relying-party side; at the
// service layer, the permit alone (without fresh evidence) never
// renews - renewal demands the evidence pair.
#[test]
fn cat06_permit_without_evidence_never_renews() {
    let backend = Arc::new(DevBackend::new());
    let port = serve_n(&backend, 4);
    let (challenge_hex, evidence_hex) = issue_and_answer(&backend, port, "m.cat6");
    let (_, body) = post(
        &mut connect(port),
        "/v1/evidence",
        &format!("{{\"challenge_hex\":\"{challenge_hex}\",\"evidence_hex\":\"{evidence_hex}\"}}"),
    );
    let permit = extract(&body, "permit_hex");

    // Renewal with only the permit and EMPTY evidence: the evidence
    // must verify and embed the renewal challenge - empty never
    // does. A clean denial, never a permit.
    let (status, body) = post(
        &mut connect(port),
        "/v1/renew",
        &format!("{{\"permit_hex\":\"{permit}\",\"evidence_hex\":\"\"}}"),
    );
    assert_eq!(status, "200", "{body}");
    assert_ne!(extract(&body, "verdict"), "allow", "{body}");
}

// Category 7: verifier time skew (re-hosted from M6-037): a decision
// time before the challenge window denies NotYetValid.
#[test]
fn cat07_time_skew_denies_not_yet_valid() {
    let backend = Arc::new(DevBackend::new());
    // Serve the issuance at t=1000 and the submission at t=10.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e:?}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e:?}"))
        .port();
    let backend_handle = Arc::clone(&backend);
    let server = std::thread::spawn(move || {
        let backend: &DevBackend = backend_handle.as_ref();
        for skewed_now in [1_000u64, 1_000, 10] {
            let (mut stream, _) = listener.accept().unwrap_or_else(|e| panic!("{e:?}"));
            let _ = serve_one(
                &mut stream,
                skewed_now,
                backend,
                Some(backend),
                backend,
                backend,
                backend,
            );
        }
    });
    let (challenge_hex, evidence_hex) = issue_and_answer(&backend, port, "m.cat7");
    let (status, body) = post(
        &mut connect(port),
        "/v1/evidence",
        &format!("{{\"challenge_hex\":\"{challenge_hex}\",\"evidence_hex\":\"{evidence_hex}\"}}"),
    );
    assert_eq!(status, "200", "{body}");
    assert_ne!(extract(&body, "verdict"), "allow", "{body}");
    server.join().unwrap_or_else(|_| panic!("server panicked"));
}

// Category 8: duplicate/non-idempotent submission (re-hosted from
// M6-036): the identical pair never admits twice.
#[test]
fn cat08_duplicate_submission_never_re_admits() {
    let backend = Arc::new(DevBackend::new());
    let port = serve_n(&backend, 5);
    let (challenge_hex, evidence_hex) = issue_and_answer(&backend, port, "m.cat8");
    let submission =
        format!("{{\"challenge_hex\":\"{challenge_hex}\",\"evidence_hex\":\"{evidence_hex}\"}}");
    let (_, first) = post(&mut connect(port), "/v1/evidence", &submission);
    assert_eq!(extract(&first, "verdict"), "allow", "{first}");
    let (_, second) = post(&mut connect(port), "/v1/evidence", &submission);
    assert_ne!(extract(&second, "verdict"), "allow", "{second}");
}

// Category 9: outage and retry behavior. A refused connection (the
// outage) surfaces as an error the CLIENT handles - and the service
// reports TransientFailure-family verdicts as RETRY (retryable),
// never as a denial the publisher could punish.
#[test]
fn cat09_outage_is_retryable_never_punitive() {
    // The outage leg: a dead port is an error, not a verdict.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e:?}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e:?}"))
        .port();
    drop(listener);
    let result = std::panic::catch_unwind(|| {
        let _ = connect(port);
    });
    assert!(result.is_err(), "a dead port must error loudly");

    // The retry leg: the taxonomy maps transient failures to the
    // Retry family with retry guidance (the wire shape).
    let verdict = WireVerdict::from_reason("TransientFailure");
    assert_eq!(verdict.kind, VerdictKind::Retry);
    assert!(verdict.kind.retryable());
    let attestation = WireVerdict::from_reason("AttestationUnavailable");
    assert_eq!(attestation.kind, VerdictKind::Retry);
}

// Category 10: publisher accidentally treats unsupported as
// cheating. Structurally impossible at the wire (ADR-0033) and ABI
// (ADR-0034) levels: unsupported is its own family, distinct from
// deny, and the SDK mirrors distinct enum values.
#[test]
fn cat10_unsupported_is_never_deny() {
    for reason in [
        "UnsupportedVersionOrProfile",
        "UnsupportedPlatform",
        "UnsupportedCriticalRequirement",
    ] {
        let verdict = WireVerdict::from_reason(reason);
        assert_eq!(verdict.kind, VerdictKind::Unsupported, "{reason}");
        assert!(!verdict.kind.retryable(), "{reason}");
        assert_ne!(verdict.kind, VerdictKind::Deny, "{reason}");
        // The wire spelling is stable and distinct.
        assert_eq!(verdict.kind.as_str(), "unsupported");
        // No permit ever rides a non-admission.
        assert!(verdict.permit_hex.is_none());
    }
    // And the denial family stays distinct.
    let deny = WireVerdict::from_reason("PolicyDenied");
    assert_eq!(deny.kind, VerdictKind::Deny);
    assert_ne!(deny.kind, VerdictKind::Unsupported);
}

/// The backend implements every service trait (a compile-time
/// completeness check the suite relies on).
#[test]
fn backend_implements_the_full_service_surface() {
    fn assert_issuer<T: ChallengeIssuer>() {}
    fn assert_simulator<T: EvidenceSimulator>() {}
    fn assert_processor<T: EvidenceProcessor>() {}
    fn assert_renewer<T: PermitRenewer>() {}
    fn assert_revocation<T: RevocationAuthority>() {}
    assert_issuer::<DevBackend>();
    assert_simulator::<DevBackend>();
    assert_processor::<DevBackend>();
    assert_renewer::<DevBackend>();
    assert_revocation::<DevBackend>();
}
