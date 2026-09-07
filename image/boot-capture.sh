#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The measured-boot CAPTURE (M4-028c): boot a second signed UKI (the
# capture init embedded) under the TCG2-enabled OVMF + swtpm, and
# export the full evidence set from inside the guest:
#   - the binary TCG2 event log the firmware published,
#   - the live PCR values (tpm2 pcrread), and
#   - a TPM2 quote over the replayable banks with a recorded nonce.
#
# This is the UKI-phase measured-boot proof: the artifacts land in
# build/capture/artifacts and the committed fixture is validated by
# the ogir-bootlog + ogir-attest-tpm triangle test.
#
# Everything is a dev-host gate: QEMU boots are not wired into CI yet.
set -euo pipefail
cd "$(dirname "$0")"

OUT="$PWD/build/capture"
ART="$OUT/artifacts"
TIMEOUT="${OGIR_BOOT_TIMEOUT:-480}"

for tool in qemu-system-x86_64 swtpm ukify cpio python3; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

# 1. The pinned TCG2 OVMF (ADR-0024).
./fetch-ovmf-tcg2.sh
OVMF_CODE="${OGIR_OVMF_CODE:-build/ovmf-tcg2/OVMF_CODE_4M.fd}"
OVMF_VARS_TEMPLATE="${OGIR_OVMF_VARS:-build/ovmf-tcg2/OVMF_VARS_4M.fd}"

# 2. The base image inputs.
KERNEL="${OGIR_KERNEL:-$(ls /boot/vmlinuz-* | sort -V | tail -1)}"
INITRD="${OGIR_INITRD:-$(ls /boot/initramfs-*.img | sort -V | tail -1)}"
[[ -r "$INITRD" ]] || { echo "initramfs not readable: $INITRD" >&2; exit 1; }

# 3. The capture initrd: the host initramfs with the capture /init
#    appended as a second cpio (later archives win, so this init runs).
rm -rf "$OUT" && mkdir -p "$OUT/init" "$ART"
NONCE_HEX="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
echo "$NONCE_HEX" > "$ART/nonce.txt"
sed "s/@NONCE_HEX@/$NONCE_HEX/" capture-init.sh > "$OUT/init/init"
chmod +x "$OUT/init/init"
( cd "$OUT/init" && echo init | cpio -o -H newc --quiet > "$OUT/capture.cpio" )
cat "$INITRD" "$OUT/capture.cpio" > "$OUT/capture-initrd"

# 4. The capture UKI: same TEST-ONLY signing key as the base image, so
#    systemd-stub measures the capture boot into PCR 11 through the
#    TCG2 protocol exactly as it would any UKI.
OGIR_KERNEL="$KERNEL" \
OGIR_INITRD="$OUT/capture-initrd" \
OGIR_CMDLINE_FILE=cmdline.capture \
OGIR_UKI="$OUT/ogir-capture.uki" \
OGIR_ESP="$OUT/ogir-capture.esp" \
./build-image.sh

# 5. Boot: TCG2 OVMF + the capture ESP + swtpm + an IDE scratch disk
#    (the guest has no virtio modules; ata_piix is builtin). The guest
#    takes the evidence, dumps it, and powers off.
rm -rf "$OUT/tpmstate" && mkdir "$OUT/tpmstate"
cp "$OVMF_VARS_TEMPLATE" "$OUT/OVMF_VARS.fd"
truncate -s 16M "$OUT/scratch.img"
swtpm socket --tpm2 \
    --tpmstate "dir=$OUT/tpmstate" \
    --ctrl "type=unixio,path=$OUT/swtpm.sock" \
    --flags not-need-init,startup-clear &
SWTPM_PID=$!
trap 'kill $SWTPM_PID 2>/dev/null || true' EXIT
sleep 2
kill -0 "$SWTPM_PID" || { echo "swtpm failed to start" >&2; exit 1; }
echo "swtpm started (pid $SWTPM_PID), nonce $NONCE_HEX"

timeout "$TIMEOUT" qemu-system-x86_64 \
    -machine q35 -m 2048 -display none -no-reboot \
    -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE" \
    -drive "if=pflash,format=raw,file=$OUT/OVMF_VARS.fd" \
    -drive "file=$OUT/ogir-capture.esp,format=raw,if=virtio" \
    -drive "file=$OUT/scratch.img,format=raw,if=ide" \
    -net none \
    -serial "file:$OUT/serial.log" \
    -device tpm-crb,tpmdev=tpm0 \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -chardev "socket,id=chrtpm,path=$OUT/swtpm.sock" \
    || echo "note: QEMU exited nonzero or timed out; artifacts may be partial" >&2

# 6. Split the evidence stream from the scratch disk on the capture
#    magic. Every section but the last is exactly bounded; the last
#    (report) is text, so trailing disk zeros strip safely.
python3 - "$OUT/scratch.img" "$ART" << 'PYEOF'
import sys

MAGIC = b"__OGIR_BOUNDARY_3f9d2c81a7b4e650__\n"
NAMES = [
    "event-log.bin", "pcrs.txt", "quote.msg", "quote.sig",
    "quote.pcrs", "ak.pem", "nonce.slot.txt", "report.txt",
]

scratch, art = sys.argv[1], sys.argv[2]
data = open(scratch, "rb").read(16 * 1024 * 1024)

# The stream ends with MAGIC followed by unwritten zeros; everything
# after the final magic is padding.
end = data.rfind(MAGIC)
if end < 0:
    sys.exit("FAIL: no capture magic on the scratch disk (dump never ran)")
stream = data[: end + len(MAGIC)]
sections = stream.split(MAGIC)
if len(sections) != len(NAMES) + 1 or sections[-1] != b"":
    sys.exit(f"FAIL: expected {len(NAMES)} sections, split produced {len(sections) - 1}")

for name, body in zip(NAMES, sections):
    with open(f"{art}/{name}", "wb") as fh:
        fh.write(body)

import os
for name in NAMES:
    size = os.path.getsize(f"{art}/{name}")
    print(f"{name}: {size} bytes")
    if size == 0:
        sys.exit(f"FAIL: {name} is empty")
PYEOF

echo "=== capture report ==="
cat "$ART/report.txt"
echo "=== artifacts in $ART ==="
ls -la "$ART"
echo "next: PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-measured-capture.py"
