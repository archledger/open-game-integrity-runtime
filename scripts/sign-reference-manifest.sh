#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Sign an OGIR reference manifest payload with the TEST-ONLY manifest
# anchor key (ADR-0025). The input file must contain the payload only
# (every canonical line EXCEPT the signature line, ending with one
# newline). The signature line is appended, producing the final
# committed manifest. Verification lives in the Rust suite
# (crates/ogir-attest-tpm/tests/reference_manifest.rs) through the
# TPM-backed verifier; this script exists so the fixture is
# reproducible byte for byte.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <manifest-payload-file>" >&2
    exit 2
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
payload="$1"
key="$root/image/keys/ogir-manifest.key"

if [[ ! -f "$key" ]]; then
    echo "manifest anchor key missing: $key" >&2
    echo "generate it with image/keys/generate-test-manifest-key.sh" >&2
    exit 1
fi
if [[ ! -s "$payload" ]]; then
    echo "payload file missing or empty: $payload" >&2
    exit 1
fi
if tail -c 1 "$payload" | od -An -tx1 | grep -qv ' 0a$'; then
    echo "payload must end with exactly one newline" >&2
    exit 1
fi
if grep -q '^signature: ' "$payload"; then
    echo "payload must not already contain a signature line" >&2
    exit 1
fi

signature_hex="$(openssl dgst -sha256 -sign "$key" "$payload" | od -An -v -tx1 | tr -d ' \n')"

if [[ ${#signature_hex} -ne 512 ]]; then
    echo "unexpected signature length: ${#signature_hex}" >&2
    exit 1
fi

cp "$payload" "$payload.signed"
printf 'signature: %s\n' "$signature_hex" >>"$payload.signed"
mv "$payload.signed" "$payload"
echo "signed manifest written to $payload"
