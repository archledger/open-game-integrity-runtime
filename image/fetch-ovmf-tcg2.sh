#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fetch the TCG2-enabled OVMF the measured-boot capture requires
# (M4-028c, ADR-0024).
#
# Fedora's edk2-ovmf ships no TCG2/TPM2 measurement support (verified
# empirically: a full boot leaves PCRs 0-7 at zero and publishes no
# event log - see image/boot-findings.md). Ubuntu's ovmf-generic
# package does: OVMF boots with Tcg2Dxe active, measures the firmware
# and UKI phases, and publishes the TCG2 event log the kernel exposes
# at /sys/kernel/security/tpm0/binary_bios_measurements.
#
# The package URL and every hash below are pinned. Any mismatch fails
# closed; nothing from the download is used until all hashes verify.
set -euo pipefail
cd "$(dirname "$0")"

OVMF_URL="${OGIR_OVMF_URL:-http://archive.ubuntu.com/ubuntu/pool/main/e/edk2/ovmf-generic_2026.05-2ubuntu2_all.deb}"
DEB_SHA256="4f43e95662f943c8b4e302d4af9ccca4e9afa7b4ecdcf07c03195c5f42fbd9b5"
CODE_SHA256="4cebd799c072b1e0aba86714dbf3f5b8ee3cdfc17f31d923155f743f6ce9c32a"
VARS_SHA256="5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e"
OUT="build/ovmf-tcg2"

command -v curl >/dev/null || { echo "missing tool: curl" >&2; exit 1; }
command -v ar >/dev/null || { echo "missing tool: ar (binutils)" >&2; exit 1; }
tar --help 2>/dev/null | grep -q zstd || { echo "missing tool: tar with zstd support" >&2; exit 1; }
sha256() { sha256sum "$1" | cut -d' ' -f1; }

mkdir -p "$OUT"
CODE="$OUT/OVMF_CODE_4M.fd"
VARS="$OUT/OVMF_VARS_4M.fd"

if [[ -f "$CODE" && -f "$VARS" ]] \
    && [[ "$(sha256 "$CODE")" == "$CODE_SHA256" ]] \
    && [[ "$(sha256 "$VARS")" == "$VARS_SHA256" ]]; then
    echo "TCG2 OVMF already present and verified in $OUT"
    exit 0
fi

DEB="$OUT/ovmf-generic.deb"
echo "downloading $OVMF_URL"
curl -fsSL -o "$DEB" "$OVMF_URL"
if [[ "$(sha256 "$DEB")" != "$DEB_SHA256" ]]; then
    echo "FAIL: package sha256 mismatch (pinned $DEB_SHA256)" >&2
    exit 1
fi

EXTRACT="$OUT/extract"
rm -rf "$EXTRACT"
mkdir -p "$EXTRACT"
ar x --output "$OUT" "$DEB" data.tar.zst
tar --zstd -xf "$OUT/data.tar.zst" -C "$EXTRACT" \
    --wildcards '*/share/OVMF/OVMF_CODE_4M.fd' '*/share/OVMF/OVMF_VARS_4M.fd'
cp "$EXTRACT/usr/share/OVMF/OVMF_CODE_4M.fd" "$CODE"
cp "$EXTRACT/usr/share/OVMF/OVMF_VARS_4M.fd" "$VARS"
rm -rf "$EXTRACT" "$OUT/data.tar.zst"

[[ "$(sha256 "$CODE")" == "$CODE_SHA256" ]] || { echo "FAIL: OVMF_CODE_4M.fd sha256 mismatch" >&2; exit 1; }
[[ "$(sha256 "$VARS")" == "$VARS_SHA256" ]] || { echo "FAIL: OVMF_VARS_4M.fd sha256 mismatch" >&2; exit 1; }

echo "verified TCG2 OVMF in $OUT"
