#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# The in-guest capture init (M4-028c). This file is a TEMPLATE: the
# host script substitutes @NONCE_HEX@ before packing it as the /init
# cpio appended to the initramfs, so the signed UKI embeds it and
# systemd-stub measures it into PCR 11 like every other section.
#
# The guest boots with no virtio modules loaded (the host initramfs
# omits them) and ships no dd/wc/awk, so evidence is written to the
# IDE scratch disk (/dev/sda via the builtin ata_piix + sd drivers) as
# ONE sequential stream of cat-ed files separated by a 64-bit-random
# magic line; the host splits the stream on the magic. The binary
# event log is exactly bounded by the following magic, never guessed.
#
# The quote needs tpm2-tools' canonical EK/AK pair (createek's
# policy-auth EK is what createak's policy session satisfies; a
# password-created primary is not), and the EK context is flushed
# before quoting because swtpm holds only two object slots.
set -u
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
NONCE_HEX="@NONCE_HEX@"
R=/dev/sda

mkdir -p /proc /sys /dev /tmp
mount -t proc none /proc
mount -t devtmpfs none /dev
mount -t sysfs none /sys
mount -t securityfs none /sys/kernel/security

# Wait for the TPM, the event log, and the scratch disk (CRB and IDE
# probes under TCG are slow; the capture must not race them).
i=0
while [ $i -lt 60 ]; do
    [ -c /dev/tpmrm0 ] && [ -r /sys/kernel/security/tpm0/binary_bios_measurements ] \
        && [ -b "$R" ] && break
    sleep 1; i=$((i + 1))
done

LOG=/sys/kernel/security/tpm0/binary_bios_measurements
{
echo "=== dmesg tpm ==="
dmesg | grep -i 'tpm\|TPMEventLog'
echo "=== TPM ready ==="
[ -c /dev/tpmrm0 ] && echo tpmrm0-present || echo TPM-MISSING
[ -r "$LOG" ] && echo eventlog-present || echo EVENTLOG-MISSING
ls -la "$LOG" 2>&1
} > /tmp/report 2>&1

# Live PCR values, both banks. PCR 8 stays zero on this platform and
# PCR 10 carries runtime IMA churn (not replayable from the log), so
# both are excluded everywhere in the capture by design.
tpm2 pcrread sha256:0,1,2,3,4,5,6,7,9,11 > /tmp/pcrs.txt 2>>/tmp/report
tpm2 pcrread sha1:0,2,7,11 >> /tmp/pcrs.txt 2>>/tmp/report

# The EK/AK pair and the quote over the same banks.
TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2 createek -c /tmp/ek.ctx -G rsa \
    >>/tmp/report 2>&1
TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2 createak -C /tmp/ek.ctx -G rsa \
    -g sha256 -s rsassa -c /tmp/ak.ctx -u /tmp/ak.pem -f pem \
    >>/tmp/report 2>&1
TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2 flushcontext /tmp/ek.ctx \
    >>/tmp/report 2>&1
TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2 quote -c /tmp/ak.ctx \
    -g sha256 -l sha256:0,1,2,3,4,5,6,7,9,11 -q "$NONCE_HEX" \
    -m /tmp/quote.msg -s /tmp/quote.sig -o /tmp/quote.pcrs \
    >>/tmp/report 2>&1

echo "=== capture status ===" >> /tmp/report
for f in pcrs.txt quote.msg quote.sig quote.pcrs ak.pem; do
    [ -s "/tmp/$f" ] && echo "$f ok" >> /tmp/report \
        || echo "$f MISSING" >> /tmp/report
done
echo "nonce $NONCE_HEX" > /tmp/nonce.txt

# Freeze the report (the dump branch notes its outcome below).
BOUNDARY='__OGIR_BOUNDARY_3f9d2c81a7b4e650__'
if [ -b "$R" ]; then
    echo "=== dumping to $R ===" >> /tmp/report
else
    echo "=== SCRATCH DISK MISSING: dump skipped ===" >> /tmp/report
fi
cp /tmp/report /tmp/report.txt

# The evidence stream: each file followed by the magic line; the
# report goes last so a truncated stream is detectable.
if [ -b "$R" ]; then
    {
    cat "$LOG"            2>>/tmp/report
    echo "$BOUNDARY"
    cat /tmp/pcrs.txt     2>>/tmp/report
    echo "$BOUNDARY"
    cat /tmp/quote.msg    2>>/tmp/report
    echo "$BOUNDARY"
    cat /tmp/quote.sig    2>>/tmp/report
    echo "$BOUNDARY"
    cat /tmp/quote.pcrs   2>>/tmp/report
    echo "$BOUNDARY"
    cat /tmp/ak.pem       2>>/tmp/report
    echo "$BOUNDARY"
    cat /tmp/nonce.txt    2>>/tmp/report
    echo "$BOUNDARY"
    cat /tmp/report.txt   2>>/tmp/report
    echo "$BOUNDARY"
    } > "$R" 2>>/tmp/report
    echo s > /proc/sysrq-trigger
    sleep 2
fi

# Print the report on serial as a backup channel, then power off.
cat /tmp/report > /dev/console 2>&1
echo o > /proc/sysrq-trigger
sleep 15
