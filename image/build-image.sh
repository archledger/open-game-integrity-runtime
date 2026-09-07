#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build the OGIR test image: ukify -> sbsign -> FAT ESP (M4-028a).
set -euo pipefail
cd "$(dirname "$0")"

KERNEL="${OGIR_KERNEL:-$(ls /boot/vmlinuz-* | sort -V | tail -1)}"
INITRD="${OGIR_INITRD:-$(ls /boot/initramfs-*.img | sort -V | tail -1)}"
STUB="${OGIR_STUB:-/usr/lib/systemd/boot/efi/linuxx64.efi.stub}"
CMDLINE_FILE="${OGIR_CMDLINE_FILE:-cmdline.test}"
OUTDIR="build"
UKI="$OUTDIR/ogir-test.uki"
ESP="$OUTDIR/ogir-test.esp"
ESP_SIZE_MB=100

for tool in ukify sbsign mkfs.vfat mcopy; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done
[[ -f "$STUB" ]] || { echo "missing systemd-stub: $STUB" >&2; exit 1; }
[[ -f "keys/ogir-test.crt" ]] || { ./keys/generate-test-keys.sh; }
for input in "$KERNEL" "$INITRD" "$STUB" "$CMDLINE_FILE"; do
    [[ -f "$input" ]] || { echo "missing input: $input" >&2; exit 1; }
done

mkdir -p "$OUTDIR"

# 1. Assemble the UKI: the stub measures kernel, initrd, cmdline, and
#    the unified sections into PCR 11 (and the security sections into
#    PCR 9) when OVMF loads it.
ukify build \
    --linux="$KERNEL" \
    --initrd="$INITRD" \
    --cmdline=@"$CMDLINE_FILE" \
    --stub="$STUB" \
    --efi-arch=x64 \
    --output="$OUTDIR/ogir-test.unsigned.uki"

# 2. Sign the UKI PE with the TEST-ONLY key.
sbsign \
    --key keys/ogir-test.key \
    --cert keys/ogir-test.crt \
    --output "$UKI" \
    "$OUTDIR/ogir-test.unsigned.uki"
rm -f "$OUTDIR/ogir-test.unsigned.uki"

# 3. Pack the UKI into a FAT ESP image (no rootfs: UKI-only image).
rm -f "$ESP"
mkfs.vfat -C "$ESP" "$((ESP_SIZE_MB * 1024))Ki" >/dev/null
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$UKI" ::/EFI/BOOT/BOOTX64.EFI

echo "built $UKI and $ESP"
