#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# The per-prefix virtual TPM manager (M10-048, ADR-0044): one
# swtpm instance per wine prefix, state under the prefix's own
# vtpm/ directory, isolation by construction (no shared state
# path, per-prefix sockets under $XDG_RUNTIME_DIR/ogir-vtpm/<hash>).
#
# The capability contract: the vTPM is NOT hardware-host
# attestation (invariant 17; the ogir-attest assurance classes
# rank it software-tpm and the class gate enforces the
# distinction).
#
# Usage:
#   vtpm-manager.sh start <prefix-dir>   # start (idempotent)
#   vtpm-manager.sh stop <prefix-dir>    # stop + clean sockets
#   vtpm-manager.sh reset <prefix-dir>   # stop, WIPE state, start
#   vtpm-manager.sh status <prefix-dir>  # running|stopped
set -euo pipefail

ACTION="${1:?start|stop|reset|status}"
PREFIX_DIR="${2:?prefix directory}"
command -v swtpm >/dev/null || { echo "missing tool: swtpm" >&2; exit 1; }
[[ -d "$PREFIX_DIR" ]] || { echo "not a prefix: $PREFIX_DIR" >&2; exit 1; }

STATE_DIR="$PREFIX_DIR/vtpm"
RUN_ROOT="${XDG_RUNTIME_DIR:-/tmp}/ogir-vtpm"
# The per-prefix hash: one prefix can never collide with another.
# -P (the PHYSICAL path): the same resolution the tests and the
# TBS layer use, so symlinked prefixes cannot diverge.
PREFIX_HASH="$(printf '%s' "$(cd -P "$PREFIX_DIR" && pwd -P)" | sha256sum | cut -c1-16)"
SOCKET="$RUN_ROOT/$PREFIX_HASH/swtpm.sock"
# The data channel (raw TPM command/response; M10-049). The
# disconnect option makes swtpm serve each client per command and
# close it, so concurrent TBS contexts cannot deadlock on the
# one-client-at-a-time data socket (probed, swtpm 0.10.2).
DATA_SOCKET="$RUN_ROOT/$PREFIX_HASH/tpm.sock"
PID_FILE="$RUN_ROOT/$PREFIX_HASH/swtpm.pid"
SOCKETS_LINK="$STATE_DIR/sockets"

is_running() {
    [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

do_stop() {
    if is_running; then
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
        for _ in $(seq 1 50); do
            is_running || break
            sleep 0.1
        done
        if is_running; then
            kill -9 "$(cat "$PID_FILE")" 2>/dev/null || true
        fi
    fi
    rm -f "$PID_FILE" "$SOCKET" "$DATA_SOCKET"
    rm -f "$SOCKETS_LINK"
    [[ -d "$RUN_ROOT/$PREFIX_HASH" ]] && rmdir "$RUN_ROOT/$PREFIX_HASH" 2>/dev/null || true
}

do_start() {
    if is_running; then
        echo "already running (pid $(cat "$PID_FILE"))"
        return 0
    fi
    mkdir -p "$STATE_DIR" "$RUN_ROOT/$PREFIX_HASH"
    chmod 0700 "$STATE_DIR" "$RUN_ROOT/$PREFIX_HASH"
    # The sockets symlink is the discovery path the TBS layer
    # follows (<prefix>/vtpm/sockets/tpm.sock): no runtime-dir
    # layout knowledge needs to live in the DLL.
    ln -sfn "$RUN_ROOT/$PREFIX_HASH" "$SOCKETS_LINK"
    swtpm socket --tpm2 \
        --tpmstate "dir=$STATE_DIR" \
        --ctrl "type=unixio,path=$SOCKET" \
        --server "type=unixio,path=$DATA_SOCKET,disconnect" \
        --flags not-need-init,startup-clear \
        >"$RUN_ROOT/$PREFIX_HASH/swtpm.log" 2>&1 &
    echo $! >"$PID_FILE"
    for _ in $(seq 1 50); do
        [[ -S "$SOCKET" && -S "$DATA_SOCKET" ]] && break
        sleep 0.1
    done
    [[ -S "$SOCKET" && -S "$DATA_SOCKET" ]] || { echo "swtpm socket never appeared" >&2; do_stop; exit 1; }
    echo "vtpm running for $PREFIX_DIR (pid $(cat "$PID_FILE"))"
}

case "$ACTION" in
    start) do_start ;;
    stop) do_stop; echo "vtpm stopped" ;;
    reset) do_stop; rm -rf "$STATE_DIR"; do_start; echo "vtpm state wiped and restarted" ;;
    status) is_running && echo "running" || echo "stopped" ;;
    *) echo "unknown action: $ACTION" >&2; exit 2 ;;
esac
