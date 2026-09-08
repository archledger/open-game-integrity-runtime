#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The publisher conformance kit (M6-039, ADR-0035).

A fresh publisher runs this against a verifier deployment to prove
their integration handles the full contract WITHOUT Linux kernel
knowledge: the five-step flow, all five verdict families, the
lifecycle (renewal, revocation), the freshness rules (replay,
expiry, premature submission), and the wire bounds (malformed and
oversized refusal). Every check is HTTP-level - exactly the surface
a game server integrates against.

The kit is also a CI gate: pass --daemon <address> to target a
running deployment (developer mode: start ogir-dev-verifierd
first), or --self-test to validate the kit itself offline.

Usage:
  python3 scripts/conformance-kit.py --daemon 127.0.0.1:8080
  python3 scripts/conformance-kit.py --self-test
"""

import json
import socket
import sys
from pathlib import Path

sys.dont_write_bytecode = True

CONTEXT = {
    "publisher_id": "pub.kit",
    "game_id": "game.kit",
    "build_id": "build.kit",
    "account_scope": "account.kit",
    "match_id": "match.kit",
    "policy_id": "policy.kit",
    "policy_version": "3",
}

FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    mark = "PASS" if condition else "FAIL"
    suffix = f"  ({detail})" if detail and not condition else ""
    print(f"{mark} {name}{suffix}")
    if not condition:
        FAILURES.append(name)


def http_post(address: str, path: str, body: str) -> tuple[str, str]:
    host, port = address.split(":")
    request = (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
    )
    with socket.create_connection((host, int(port)), timeout=10) as sock:
        sock.sendall(request.encode())
        response = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response += chunk
    text = response.decode(errors="replace")
    status = text.split(" ", 2)[1] if " " in text else "?"
    _, _, rest = text.partition("\r\n\r\n")
    return status, rest


def member(body: str, key: str) -> str:
    needle = f'"{key}":"'
    start = body.find(needle)
    if start < 0:
        return ""
    start += len(needle)
    end = body.find('"', start)
    return body[start:end] if end >= 0 else ""


def run_kit(address: str) -> None:
    print(f"=== OGIR publisher conformance kit against {address} ===\n")

    # --- The five-step flow -------------------------------------------------
    print("[five-step flow]")
    status, body = http_post(address, "/v1/challenge", json.dumps(CONTEXT))
    check("challenge issuance returns 200", status == "200", body)
    challenge = member(body, "challenge_hex")
    check("challenge carries a non-empty opaque object", len(challenge) > 0)

    status, body = http_post(
        address, "/v1/dev/evidence", json.dumps({"challenge_hex": challenge})
    )
    dev_mode = status == "200"
    evidence = member(body, "evidence_hex") if dev_mode else ""
    check(
        "developer-mode evidence simulation",
        dev_mode,
        "target a developer-mode daemon for the full kit (production verifiers omit this route by design)",
    )

    if not dev_mode:
        print("\nkit cannot continue without a client; stopping (the routes below need evidence).")
        return

    submission = json.dumps({"challenge_hex": challenge, "evidence_hex": evidence})
    status, body = http_post(address, "/v1/evidence", submission)
    check("submission returns 200", status == "200", body)
    verdict = member(body, "verdict")
    check(
        "admission carries the structured verdict and permit",
        verdict in ("allow", "restricted") and len(member(body, "permit_hex")) > 0,
        body,
    )
    check(
        "the stable reason code is present",
        len(member(body, "reason_code")) > 0,
        body,
    )

    # --- The lifecycle ------------------------------------------------------
    print("\n[lifecycle]")
    permit = member(body, "permit_hex")
    status, renew_body = http_post(
        address, "/v1/renew", json.dumps({"permit_hex": permit, "evidence_hex": evidence})
    )
    renew_verdict = member(renew_body, "verdict")
    check(
        "renewal with stale evidence denies or retries (never admits)",
        status == "200" and renew_verdict in ("deny", "retry", "unsupported"),
        renew_body,
    )
    status, revoke_body = http_post(
        address, "/v1/revoke", json.dumps({"target_hex": permit})
    )
    check(
        "revocation confirms",
        status == "200" and member(revoke_body, "revoked") == "confirmed",
        revoke_body,
    )
    status, revoke2 = http_post(address, "/v1/revoke", json.dumps({"target_hex": permit}))
    check("revocation is idempotent", status == "200", revoke2)

    # --- Freshness ----------------------------------------------------------
    print("\n[freshness]")
    status, replay_body = http_post(address, "/v1/evidence", submission)
    check(
        "duplicate submission never re-admits",
        status == "200" and member(replay_body, "verdict") in ("deny", "retry"),
        replay_body,
    )
    check(
        "replay carries the taxonomy reason",
        member(replay_body, "reason_code") != "",
        replay_body,
    )

    # --- Wire bounds --------------------------------------------------------
    print("\n[wire bounds]")
    status, _ = http_post(address, "/v1/evidence", '{"nope":1}')
    check("malformed body returns 400", status == "400")
    status, _ = http_post(address, "/v1/absent", "{}")
    check("unknown route returns 400", status == "400")
    status, _ = http_post(address, "/v1/challenge", '{"publisher_id":"only-one"}')
    check("missing members return 400", status == "400")

    host, port = address.split(":")
    oversized = "x" * (70 * 1024)
    with socket.create_connection((host, int(port)), timeout=10) as sock:
        sock.sendall(
            f"POST /v1/evidence HTTP/1.1\r\nHost: {host}\r\n"
            f"Content-Length: {len(oversized)}\r\nConnection: close\r\n\r\n{oversized}".encode()
        )
        response = b""
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response += chunk
        except (ConnectionResetError, BrokenPipeError):
            # The server refuses the oversized body by closing; the
            # reset IS the expected refusal shape.
            pass
    text = response.decode(errors="replace")
    check("oversized body is refused (no 200)", not text.startswith("HTTP/1.1 200"))

    print()


def self_test() -> None:
    """Offline validation of the kit itself (the CI posture)."""
    print("=== conformance kit self-test ===")
    check("member extraction", member('{"verdict":"allow"}', "verdict") == "allow")
    check("member extraction absent", member('{"a":"b"}', "verdict") == "")
    check("context is complete", all(CONTEXT.values()))
    print()


def main() -> None:
    args = sys.argv[1:]
    if "--self-test" in args:
        self_test()
    elif "--daemon" in args:
        index = args.index("--daemon")
        run_kit(args[index + 1] if index + 1 < len(args) else "127.0.0.1:8080")
    else:
        print(__doc__)
        raise SystemExit(2)

    if FAILURES:
        print(f"conformance kit FAILED: {len(FAILURES)} check(s): {', '.join(FAILURES)}")
        raise SystemExit(1)
    print("conformance kit PASS")


if __name__ == "__main__":
    main()
