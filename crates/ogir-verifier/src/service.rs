// SPDX-License-Identifier: Apache-2.0

//! The verifier service shell (M6-036, ADR-0032): routes, wire
//! codec, and the bounded HTTP listener, with the semantics
//! injected through narrow traits so the production crate stays
//! free of every substrate. The developer-mode daemon composes the
// mock substrate into this shell (ADR-0016/0017 posture); the
// authoritative backend composes the real chain later.

use std::net::TcpStream;

use crate::bjson::{
    JsonError, MAX_STRING, MAX_WIRE, Value, decode_object, encode_object, require_hex, require_str,
};
use crate::http::{
    HttpError, Listener, MAX_BODY, Request, STATUS_BAD_REQUEST, STATUS_METHOD_NOT_ALLOWED,
    STATUS_OK, write_response,
};

/// The wire-level verdict: everything a relying party needs, and
/// nothing it should not parse further.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireVerdict {
    /// Admission with the opaque signed permit.
    Allow { permit_hex: Vec<u8> },
    /// A deterministic, non-disciplinary denial with its public
    /// reason code.
    Deny { reason: String },
}

/// Challenge issuance requests (flat, bounded text fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeRequest {
    pub publisher_id: String,
    pub game_id: String,
    pub build_id: String,
    pub account_scope: String,
    pub match_id: String,
    pub policy_id: String,
    pub policy_version: u32,
}

/// The issued challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeResponse {
    pub challenge_hex: Vec<u8>,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Issues signed challenges. Implemented by the developer-mode
/// daemon with test keys today and by the authoritative service
/// later.
pub trait ChallengeIssuer {
    fn issue(&self, request: &ChallengeRequest, now: u64) -> Result<ChallengeResponse, String>;
}

/// Simulates a client answering a challenge (developer mode only:
/// the simulated profiles deliverable).
pub trait EvidenceSimulator {
    fn simulate(&self, challenge_object: &[u8]) -> Result<Vec<u8>, String>;
}

/// Processes a submitted (challenge, evidence) pair at decision
/// time. The verdict is the wire verdict; the implementation maps
/// its own semantics into it.
pub trait EvidenceProcessor {
    fn process(&self, now: u64, challenge_object: &[u8], evidence_object: &[u8]) -> WireVerdict;
}

/// Service-level failures surfaced as HTTP error bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    Bad(JsonError),
    Http(HttpError),
    Internal(String),
}

fn error_body(detail: &str) -> String {
    encode_object(&[("error", Value::Str(detail.to_string()))])
}

/// Serves exactly one request. `now` is supplied by the caller so
/// the service stays deterministic and testable.
pub fn serve_one(
    stream: &mut TcpStream,
    now: u64,
    issuer: &dyn ChallengeIssuer,
    simulator: Option<&dyn EvidenceSimulator>,
    processor: &dyn EvidenceProcessor,
) -> Result<(), RouteError> {
    let request = crate::http::read_request(stream).map_err(RouteError::Http)?;

    if request.method != "POST" {
        write_response(stream, STATUS_METHOD_NOT_ALLOWED, &error_body("post only"))
            .map_err(RouteError::Http)?;
        return Ok(());
    }

    let response = route(&request, now, issuer, simulator, processor);
    let (status, body) = match response {
        Ok(body) => (STATUS_OK, body),
        Err(detail) => (STATUS_BAD_REQUEST, error_body(&detail)),
    };
    write_response(stream, status, &body).map_err(RouteError::Http)?;
    Ok(())
}

fn route(
    request: &Request,
    now: u64,
    issuer: &dyn ChallengeIssuer,
    simulator: Option<&dyn EvidenceSimulator>,
    processor: &dyn EvidenceProcessor,
) -> Result<String, String> {
    match request.path.as_str() {
        "/v1/challenge" => {
            let members = decode_object(&request.body).map_err(|e| e.to_string())?;
            let parsed = ChallengeRequest {
                publisher_id: require_str(&members, "publisher_id")
                    .map_err(|e| e.to_string())?
                    .to_string(),
                game_id: require_str(&members, "game_id")
                    .map_err(|e| e.to_string())?
                    .to_string(),
                build_id: require_str(&members, "build_id")
                    .map_err(|e| e.to_string())?
                    .to_string(),
                account_scope: require_str(&members, "account_scope")
                    .map_err(|e| e.to_string())?
                    .to_string(),
                match_id: require_str(&members, "match_id")
                    .map_err(|e| e.to_string())?
                    .to_string(),
                policy_id: require_str(&members, "policy_id")
                    .map_err(|e| e.to_string())?
                    .to_string(),
                policy_version: require_str(&members, "policy_version")
                    .map_err(|e| e.to_string())?
                    .parse()
                    .map_err(|_| "policy_version must be a number")?,
            };
            let issued = issuer.issue(&parsed, now)?;
            Ok(encode_object(&[
                ("challenge_hex", Value::Hex(issued.challenge_hex)),
                ("issued_at", Value::Str(issued.issued_at.to_string())),
                ("expires_at", Value::Str(issued.expires_at.to_string())),
            ]))
        }
        "/v1/dev/evidence" => {
            let simulator = simulator.ok_or("developer mode is not enabled")?;
            let members = decode_object(&request.body).map_err(|e| e.to_string())?;
            let challenge = require_hex(&members, "challenge_hex").map_err(|e| e.to_string())?;
            let evidence = simulator.simulate(challenge)?;
            Ok(encode_object(&[("evidence_hex", Value::Hex(evidence))]))
        }
        "/v1/evidence" => {
            let members = decode_object(&request.body).map_err(|e| e.to_string())?;
            let challenge = require_hex(&members, "challenge_hex").map_err(|e| e.to_string())?;
            let evidence = require_hex(&members, "evidence_hex").map_err(|e| e.to_string())?;
            let verdict = processor.process(now, challenge, evidence);
            Ok(match verdict {
                WireVerdict::Allow { permit_hex } => encode_object(&[
                    ("verdict", Value::Str("allow".to_string())),
                    ("permit_hex", Value::Hex(permit_hex)),
                ]),
                WireVerdict::Deny { reason } => encode_object(&[
                    ("verdict", Value::Str("deny".to_string())),
                    ("reason", Value::Str(reason)),
                ]),
            })
        }
        _ => Err("unknown route".to_string()),
    }
}

/// Runs the service loop until the process is stopped. Each
/// connection serves one request and closes.
pub fn serve_forever(
    listener: Listener,
    now_source: impl Fn() -> u64,
    issuer: &dyn ChallengeIssuer,
    simulator: Option<&dyn EvidenceSimulator>,
    processor: &dyn EvidenceProcessor,
) -> Result<(), RouteError> {
    loop {
        let mut stream = listener
            .accept()
            .map_err(|e| RouteError::Internal(e.to_string()))?;
        let now = now_source();
        let _ = serve_one(&mut stream, now, issuer, simulator, processor);
    }
}

/// The public ceilings, re-exported for callers that gate bodies
/// before the codec sees them.
pub const SERVICE_LIMITS: (usize, usize, usize, usize) = (
    MAX_WIRE,
    MAX_BODY,
    MAX_STRING,
    crate::http::MAX_HEADER_BLOCK,
);

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedIssuer;
    struct FixedSimulator;
    struct FixedProcessor;

    impl ChallengeIssuer for FixedIssuer {
        fn issue(
            &self,
            _request: &ChallengeRequest,
            now: u64,
        ) -> Result<ChallengeResponse, String> {
            Ok(ChallengeResponse {
                challenge_hex: vec![0x01, 0x02],
                issued_at: now,
                expires_at: now + 300,
            })
        }
    }

    impl EvidenceSimulator for FixedSimulator {
        fn simulate(&self, challenge_object: &[u8]) -> Result<Vec<u8>, String> {
            Ok(challenge_object.to_vec())
        }
    }

    impl EvidenceProcessor for FixedProcessor {
        fn process(&self, _now: u64, challenge: &[u8], evidence: &[u8]) -> WireVerdict {
            if evidence == challenge {
                WireVerdict::Allow {
                    permit_hex: vec![0xAA],
                }
            } else {
                WireVerdict::Deny {
                    reason: "EvidenceInvalid".to_string(),
                }
            }
        }
    }

    fn request(path: &str, body: &str) -> Request {
        Request {
            method: "POST".to_string(),
            path: path.to_string(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn challenge_route_issues() {
        let body = route(
            &request(
                "/v1/challenge",
                "{\"publisher_id\":\"p\",\"game_id\":\"g\",\"build_id\":\"b\",\"account_scope\":\"a\",\"match_id\":\"m\",\"policy_id\":\"pol\",\"policy_version\":\"3\"}",
            ),
            1000,
            &FixedIssuer,
            None,
            &FixedProcessor,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(body.contains("\"challenge_hex\":\"0102\""));
        assert!(body.contains("\"expires_at\":\"1300\""));
    }

    #[test]
    fn evidence_route_maps_verdicts() {
        let allow = route(
            &request(
                "/v1/evidence",
                "{\"challenge_hex\":\"0102\",\"evidence_hex\":\"0102\"}",
            ),
            1000,
            &FixedIssuer,
            None,
            &FixedProcessor,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(allow.contains("\"verdict\":\"allow\""));
        assert!(allow.contains("\"permit_hex\":\"aa\""));

        let deny = route(
            &request(
                "/v1/evidence",
                "{\"challenge_hex\":\"0102\",\"evidence_hex\":\"0304\"}",
            ),
            1000,
            &FixedIssuer,
            None,
            &FixedProcessor,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(deny.contains("\"verdict\":\"deny\""));
        assert!(deny.contains("\"reason\":\"EvidenceInvalid\""));
    }

    #[test]
    fn dev_route_simulates_when_enabled() {
        let body = route(
            &request("/v1/dev/evidence", "{\"challenge_hex\":\"0102\"}"),
            1000,
            &FixedIssuer,
            Some(&FixedSimulator),
            &FixedProcessor,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(body.contains("\"evidence_hex\":\"0102\""), "{body}");
    }

    #[test]
    fn dev_route_requires_enabled_mode() {
        assert_eq!(
            route(
                &request("/v1/dev/evidence", "{\"challenge_hex\":\"01\"}"),
                1000,
                &FixedIssuer,
                None,
                &FixedProcessor,
            ),
            Err("developer mode is not enabled".to_string())
        );
    }

    #[test]
    fn unknown_routes_and_malformed_bodies_reject() {
        assert_eq!(
            route(
                &request("/v1/nope", "{}"),
                1000,
                &FixedIssuer,
                None,
                &FixedProcessor,
            ),
            Err("unknown route".to_string())
        );
        assert!(
            route(
                &request("/v1/evidence", "{\"challenge_hex\":\"01\"}"),
                1000,
                &FixedIssuer,
                None,
                &FixedProcessor,
            )
            .is_err()
        );
    }
}
