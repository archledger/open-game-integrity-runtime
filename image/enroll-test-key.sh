#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Enroll the TEST-ONLY image key into an OVMF varstore (M4-030,
# ADR-0026): PK = KEK = db = the committed test key, everything else
# empty. The output varstore pairs with the TCG2-enabled
# OVMF_CODE_4M.secboot.fd from image/fetch-ovmf-tcg2.sh and makes
# Secure Boot ENFORCE the test key: the test UKI boots (signature
# verifies), a modified UKI is rejected by the firmware.
#
# Requires virt-fw-vars (pip install virt-firmware) on the dev host.
# The varstore is a derived build input (gitignored), never committed.
set -euo pipefail
cd "$(dirname "$0")"

OUT="${1:-build/ovmf-tcg2/OVMF_VARS_enrolled.fd}"
TEMPLATE="${OGIR_OVMF_VARS_TEMPLATE:-build/ovmf-tcg2/OVMF_VARS_4M.fd}"
KEY="keys/ogir-test.crt"
# A fixed owner GUID for the enrolled entries (arbitrary but stable
# so the varstore is byte-deterministic for a given template+key).
GUID="7c0e2a1b-4d3f-4f5e-9a6b-8c1d2e3f4a5b"

command -v virt-fw-vars >/dev/null || {
    echo "missing tool: virt-fw-vars (pip install virt-firmware)" >&2
    exit 1
}
[[ -f "$TEMPLATE" ]] || { echo "varstore template missing: $TEMPLATE" >&2; exit 1; }
[[ -f "$KEY" ]] || { echo "test key missing: $KEY" >&2; exit 1; }

virt-fw-vars -i "$TEMPLATE" -o "$OUT" \
    --set-pk-cert "$GUID" "$KEY" \
    --add-kek-cert "$GUID" "$KEY" \
    --add-db-cert "$GUID" "$KEY" >/dev/null

# Fail closed: the written store must actually carry PK, KEK, and db.
for variable in PK KEK db; do
    virt-fw-vars -i "$OUT" --print 2>/dev/null | grep -q "^${variable} " \
        || { echo "FAIL: $variable missing from $OUT" >&2; exit 1; }
done
echo "enrolled TEST-ONLY varstore written to $OUT"
