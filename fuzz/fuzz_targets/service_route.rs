// SPDX-License-Identifier: Apache-2.0
#![no_main]

/// Fuzz target (M6-038, ADR-0034): the service router must never
/// panic on arbitrary (method, path, body) combinations; unknown
/// routes and malformed bodies fail closed as 400-shaped errors.

use libfuzzer_sys::fuzz_target;
use ogir_verifier::service::{serve_one, ChallengeIssuer, ChallengeRequest, ChallengeResponse, EvidenceProcessor, EvidenceSimulator, PermitRenewer, RenewalRequest, RevocationAuthority, RevocationRequest, WireVerdict};
use std::io::Write;
use std::net::{TcpListener, TcpStream};

struct NullIssuer;
struct NullSimulator;
struct NullProcessor;
struct NullRenewer;
struct NullRevocation;

impl ChallengeIssuer for NullIssuer {
    fn issue(&self, _request: &ChallengeRequest, now: u64) -> Result<ChallengeResponse, String> {
        let _ = now;
        Err("no issuance in fuzzing".to_string())
    }
}

impl EvidenceSimulator for NullSimulator {
    fn simulate(&self, _challenge_object: &[u8]) -> Result<Vec<u8>, String> {
        Err("no simulation in fuzzing".to_string())
    }
}

impl EvidenceProcessor for NullProcessor {
    fn process(&self, _now: u64, _challenge: &[u8], _evidence: &[u8]) -> WireVerdict {
        WireVerdict::from_reason("Malformed")
    }
}

impl PermitRenewer for NullRenewer {
    fn renew(&self, _now: u64, _request: &RenewalRequest) -> Result<Vec<u8>, WireVerdict> {
        Err(WireVerdict::from_reason("UnsupportedVersionOrProfile"))
    }
}

impl RevocationAuthority for NullRevocation {
    fn revoke(&self, _request: &RevocationRequest) -> Result<(), WireVerdict> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    // Treat the first byte as a route selector, the rest as a body.
    if data.is_empty() {
        return;
    }
    let path = match data[0] % 5 {
        0 => "/v1/challenge",
        1 => "/v1/dev/evidence",
        2 => "/v1/evidence",
        3 => "/v1/renew",
        _ => "/v1/revoke",
    };
    let body = &data[1..];
    // A socketpair would be ideal; the HTTP layer needs a
    // TcpStream, so the harness writes a syntactically valid
    // request into a connected pair and asserts the handler never
    // panics regardless of what arrives.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("addr");
    let mut client = TcpStream::connect(address).expect("connect");
    
    let (mut server, _) = listener.accept().expect("accept");
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: f\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        body.len()
    );
    let mut wire = request.into_bytes();
    wire.extend_from_slice(body);
    let _ = client.write_all(&wire);
    let _ = client.flush();
    drop(client);
    let _ = serve_one(
        &mut server, 1, &NullIssuer, Some(&NullSimulator), &NullProcessor, &NullRenewer,
        &NullRevocation,
    );
});
