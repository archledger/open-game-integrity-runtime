#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Boot the OGIR test image under QEMU + OVMF + swtpm (M4-028b harness).
#
# The chassis works (QEMU + swtpm + OVMF + the built ESP; the UKI
# boots; Secure Boot enforcement rejects the test-key UKI). Fedora's
# OVMF lacks TCG2/TPM2 measurement support (see boot-findings.md), so
# PCR capture requires a TCG2-enabled OVMF override (OGIR_OVMF_CODE).
set -euo pipefail
cd "$(dirname "$0")"

OVMF_CODE="${OGIR_OVMF_CODE:-/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd}"
OVMF_VARS_TEMPLATE="${OGIR_OVMF_VARS:-/usr/share/edk2/ovmf/OVMF_VARS.secboot.fd}"
ESP="${OGIR_ESP:-build/ogir-test.esp}"
WORKDIR="build/boot"
TIMEOUT="${OGIR_BOOT_TIMEOUT:-240}"

for tool in qemu-system-x86_64 swtpm; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done
for input in "$OVMF_CODE" "$OVMF_VARS_TEMPLATE" "$ESP"; do
    [[ -f "$input" ]] || { echo "missing input: $input" >&2; exit 1; }
done

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/tpmstate"
cp "$OVMF_VARS_TEMPLATE" "$WORKDIR/OVMF_VARS.fd"

# swtpm: UNIX ctrl socket (QEMU's emulator backend protocol).
swtpm socket --tpm2 \
    --tpmstate "dir=$WORKDIR/tpmstate" \
    --ctrl "type=unixio,path=$WORKDIR/swtpm.sock" \
    --flags not-need-init,startup-clear &
SWTPM_PID=$!
trap 'kill $SWTPM_PID 2>/dev/null || true' EXIT
sleep 2
kill -0 "$SWTPM_PID" || { echo "swtpm failed to start" >&2; exit 1; }
[[ -S "$WORKDIR/swtpm.sock" ]] || { echo "swtpm ctrl socket missing" >&2; exit 1; }
echo "swtpm started (pid $SWTPM_PID)"

# QEMU: OVMF + the ESP + the swtpm emulator (TCG for portability).
timeout "$TIMEOUT" qemu-system-x86_64 \
    -machine q35 -m 2048 -display none -no-reboot \
    -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE" \
    -drive "if=pflash,format=raw,file=$WORKDIR/OVMF_VARS.fd" \
    -drive "file=$ESP,format=raw,if=virtio" \
    -net none \
    -serial "file:$WORKDIR/serial.log" \
    -device tpm-crb,tpmdev=tpm0 \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -chardev "socket,id=chrtpm,path=$WORKDIR/swtpm.sock" \
    2>&1 | tail -5
echo "=== serial (tail) ==="
tail -5 "$WORKDIR/serial.log" 2>/dev/null || echo "(no serial log)"
echo "=== TPM state ==="
ls -la "$WORKDIR/tpmstate/"
echo "=== OVMF varstore ==="
ls -la "$WORKDIR/OVMF_VARS.fd"
