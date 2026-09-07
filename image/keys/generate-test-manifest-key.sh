#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Generate the TEST-ONLY reference-manifest anchor key pair (ADR-0025).
# The output is committed for deterministic fixtures. NEVER use these
# keys for production: the subject brands them as test-only.
set -euo pipefail
cd "$(dirname "$0")"

if [[ -f ogir-manifest.crt && -f ogir-manifest.key ]]; then
    echo "manifest anchor keys already present; refusing to overwrite" >&2
    exit 0
fi

openssl req -new -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -subj "/CN=OGIR TEST-ONLY Manifest Anchor Key DO NOT TRUST/" \
    -keyout ogir-manifest.key -out ogir-manifest.crt
openssl x509 -in ogir-manifest.crt -outform DER -out manifest-anchor-key.der
chmod 0644 ogir-manifest.crt manifest-anchor-key.der
chmod 0600 ogir-manifest.key
echo "generated OGIR TEST-ONLY manifest anchor key pair"
