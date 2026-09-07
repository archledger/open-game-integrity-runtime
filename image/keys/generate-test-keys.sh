#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Generate the TEST-ONLY Secure Boot key pair for the OGIR test image.
# The output is committed for deterministic fixture builds. NEVER use
# these keys for production: the subject brands them as test-only.
set -euo pipefail
cd "$(dirname "$0")"

if [[ -f ogir-test.crt && -f ogir-test.key ]]; then
    echo "test keys already present; refusing to overwrite" >&2
    exit 0
fi

openssl req -new -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -subj "/CN=OGIR TEST-ONLY Image Key DO NOT TRUST/" \
    -keyout ogir-test.key -out ogir-test.crt
openssl x509 -in ogir-test.crt -outform DER -out test-image-key.der
chmod 0644 ogir-test.crt test-image-key.der
chmod 0600 ogir-test.key
echo "generated OGIR TEST-ONLY key pair"
