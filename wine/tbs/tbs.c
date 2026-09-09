/*
 * Trusted Platform Module Base Services over the per-prefix
 * virtual TPM (OGIR M10-049, ADR-0045).
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/*
 * Shape: a drop-in candidate for upstream dlls/tbs/tbs.c. The
 * compat surface is the five documented entry points; everything
 * else in tbs.spec stays stubbed. The transport is the per-prefix
 * virtual TPM (wine/vtpm/vtpm-manager.sh): raw TPM 2.0
 * command/response over the prefix's data socket, control
 * commands over its ctrl socket. THE CAPABILITY CONTRACT: this is
 * ordinary Windows TPM API compatibility, never hardware-host
 * attestation (invariant 17; the vTPM is the software-tpm class).
 *
 * There is NO physical TPM path in this file: the only transport
 * is the socket pair the per-prefix manager creates under
 * <prefix>/vtpm/sockets (a symlink into the user's own runtime
 * dir; wine/tests/test-tbs.py greps this file for host-TPM
 * references mechanically).
 *
 * Connection model (probed against swtpm 0.10.2): the manager
 * starts the data channel with the server `disconnect` option, so
 * each command uses ONE fresh connection (connect, send, receive,
 * close). Without it a second concurrent client hangs - swtpm
 * serves one data client at a time - which would deadlock any
 * application opening two TBS contexts.
 *
 * Standalone builds: the dev-host gate compiles this file with
 * -DOGIR_TBS_STANDALONE (POSIX-only dependencies); inside Wine
 * the same code paths run against windef.h types.
 */

#ifdef OGIR_TBS_STANDALONE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
typedef int HRESULT; /* winerror types, standalone builds only */
#define E_NOTIMPL 0x80004001
#else
#include <windef.h>
#include <wine/debug.h>
WINE_DEFAULT_DEBUG_CHANNEL(tbs);
#endif

#include "tbs.h"

/* swtpm's default TPM command/response buffer is 4096 bytes
 * (swtpm_ioctl -b); larger buffers are refused before any IO. */
#define TBS_MAX_BUFFER 4096

/* A TPM 2.0 command/response header is tag(2) + size(4) + code(4). */
#define TPM2_HEADER_SIZE 10

/* swtpm control-channel commands are big-endian u32s
 * (include/swtpm/tpm_ioctl.h, non-CUSE CMD_* enum). */
#define SWTPM_CMD_CANCEL_TPM_CMD 9

/* Per-command IO budget: a wedged vTPM surfaces as IOERROR
 * instead of hanging the caller forever. Windows TBS documents
 * no timeout; this is the compat layer's own bound. */
#define TBS_IO_TIMEOUT_SECONDS 30

#define TBS_CONTEXT_MAGIC 0x54425331 /* "TBS1" */

/* struct sockaddr_un's path limit, including the NUL. */
#define TBS_UNIX_PATH_MAX 108

struct tbs_context
{
    UINT32 magic;
    char data_path[TBS_UNIX_PATH_MAX];
    char ctrl_path[TBS_UNIX_PATH_MAX];
};

static UINT32 load_be32(const BYTE *p)
{
    return ((UINT32)p[0] << 24) | ((UINT32)p[1] << 16) | ((UINT32)p[2] << 8) | (UINT32)p[3];
}

static void store_be32(BYTE *p, UINT32 v)
{
    p[0] = (BYTE)(v >> 24);
    p[1] = (BYTE)(v >> 16);
    p[2] = (BYTE)(v >> 8);
    p[3] = (BYTE)v;
}

static int write_full(int fd, const BYTE *buf, UINT32 len)
{
    UINT32 done = 0;
    while (done < len)
    {
        ssize_t n = write(fd, buf + done, len - done);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return 0;
        }
        done += (UINT32)n;
    }
    return 1;
}

static int read_full(int fd, BYTE *buf, UINT32 len)
{
    UINT32 done = 0;
    while (done < len)
    {
        ssize_t n = read(fd, buf + done, len - done);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return 0;
        }
        if (n == 0)
            return 0;
        done += (UINT32)n;
    }
    return 1;
}

/* Discard len bytes (draining a response the caller could not
 * accept, so the vTPM is not left mid-stream). */
static int drain_full(int fd, UINT32 len)
{
    BYTE scratch[256];
    while (len > 0)
    {
        UINT32 want = len < sizeof(scratch) ? len : sizeof(scratch);
        if (!read_full(fd, scratch, want))
            return 0;
        len -= want;
    }
    return 1;
}

static int connect_unix(const char *path)
{
    struct sockaddr_un addr;
    int fd;

    if (strlen(path) >= sizeof(addr.sun_path))
        return -1;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

static int mark_timeouts(int fd)
{
    struct timeval tv;
    tv.tv_sec = TBS_IO_TIMEOUT_SECONDS;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        return 0;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
        return 0;
    return 1;
}

/* Resolve the prefix's socket pair: <prefix>/vtpm/sockets is a
 * symlink the per-prefix manager maintains into the runtime dir,
 * so no hashing (and no runtime-dir layout knowledge) lives in C. */
static BOOL build_paths(struct tbs_context *ctx)
{
    const char *prefix = getenv("WINEPREFIX");
    char path[TBS_UNIX_PATH_MAX * 2];
    size_t len;

    if (!prefix || !*prefix)
    {
        const char *home = getenv("HOME");
        if (!home || !*home)
            return 0;
        if (snprintf(path, sizeof(path), "%s/.wine", home) >= (int)sizeof(path))
            return 0;
        prefix = path;
    }
    len = strlen(prefix);
    while (len > 1 && prefix[len - 1] == '/')
        len--; /* the manager hashes the physical path; match it */
    if (snprintf(ctx->data_path, sizeof(ctx->data_path), "%.*s/vtpm/sockets/tpm.sock", (int)len, prefix)
        >= (int)sizeof(ctx->data_path))
        return 0;
    if (snprintf(ctx->ctrl_path, sizeof(ctx->ctrl_path), "%.*s/vtpm/sockets/swtpm.sock", (int)len, prefix)
        >= (int)sizeof(ctx->ctrl_path))
        return 0;
    return 1;
}

/* Live-context registry: handles handed to the API are validated
 * against it BEFORE any dereference, so a bogus handle is an
 * error return, not a crash. The registry is plain storage (no
 * lock): the compat layer documents single-threaded callers per
 * context as its bounded posture - a Wine-side submission would
 * add serialization here. */
#define TBS_MAX_CONTEXTS 64
static struct tbs_context *live_contexts[TBS_MAX_CONTEXTS];

static BOOL context_register(struct tbs_context *ctx)
{
    for (int i = 0; i < TBS_MAX_CONTEXTS; i++)
    {
        if (!live_contexts[i])
        {
            live_contexts[i] = ctx;
            return 1;
        }
    }
    return 0;
}

static void context_unregister(struct tbs_context *ctx)
{
    for (int i = 0; i < TBS_MAX_CONTEXTS; i++)
    {
        if (live_contexts[i] == ctx)
        {
            live_contexts[i] = NULL;
            return;
        }
    }
}

static BOOL context_is_valid(const struct tbs_context *ctx)
{
    if (!ctx)
        return 0;
    for (int i = 0; i < TBS_MAX_CONTEXTS; i++)
    {
        if (live_contexts[i] == ctx)
            return ctx->magic == TBS_CONTEXT_MAGIC;
    }
    return 0;
}

TBS_RESULT WINAPI Tbsi_Context_Create(const TBS_CONTEXT_PARAMS *params, TBS_HCONTEXT *out)
{
    struct tbs_context *ctx;
    int fd;

    if (!out)
        return TBS_E_INVALID_OUTPUT_POINTER;
    if (!params)
        return TBS_E_BAD_PARAMETER;
    if (params->version == TPM_VERSION_12)
        return TBS_E_TPM_NOT_FOUND; /* only a 2.0 vTPM is offered */
    if (params->version != TPM_VERSION_20)
        return TBS_E_INVALID_CONTEXT_PARAM;
    {
        const TBS_CONTEXT_PARAMS2 *params2 = (const TBS_CONTEXT_PARAMS2 *)params;
        /* includeTpm20 is bit 2 (TBS_CONTEXT_PARAMS2); a caller
         * asking only for 1.2 finds no TPM here. requestRaw is
         * accepted and ignored (compat). */
        if (!(params2->asUINT32 & 4u))
            return TBS_E_TPM_NOT_FOUND;
    }

    ctx = malloc(sizeof(*ctx));
    if (!ctx)
        return TBS_E_INTERNAL_ERROR;
    memset(ctx, 0, sizeof(*ctx));
    if (!build_paths(ctx))
    {
        free(ctx);
        return TBS_E_INTERNAL_ERROR;
    }
    fd = connect_unix(ctx->data_path);
    if (fd < 0)
    {
        free(ctx);
        return TBS_E_TPM_NOT_FOUND;
    }
    close(fd); /* presence probe; each submit opens its own connection */

    ctx->magic = TBS_CONTEXT_MAGIC;
    if (!context_register(ctx))
    {
        memset(ctx, 0, sizeof(*ctx));
        free(ctx);
        return TBS_E_TOO_MANY_TBS_CONTEXTS;
    }
    *out = (TBS_HCONTEXT)ctx;
    return TBS_SUCCESS;
}

TBS_RESULT WINAPI Tbsip_Submit_Command(TBS_HCONTEXT context, TBS_COMMAND_LOCALITY locality,
                                       TBS_COMMAND_PRIORITY priority, PCBYTE command, UINT32 command_size,
                                       PBYTE result, UINT32 *result_size)
{
    struct tbs_context *ctx = context;
    BYTE header[TPM2_HEADER_SIZE];
    UINT32 response_size;
    int fd;

    if (!context_is_valid(ctx))
        return TBS_E_INVALID_CONTEXT;
    if (!command || command_size < TPM2_HEADER_SIZE)
        return TBS_E_BAD_PARAMETER;
    if (!result_size)
        return TBS_E_INVALID_OUTPUT_POINTER;
    if (!result && *result_size != 0)
        return TBS_E_INVALID_OUTPUT_POINTER;
    /* Windows documents locality ZERO as "the only locality
     * currently supported"; the five priorities are the
     * documented set. The socket transport has no queue, so the
     * priority is validated and then immaterial. */
    if (locality != TBS_COMMAND_LOCALITY_ZERO)
        return TBS_E_BAD_PARAMETER;
    if (priority != TBS_COMMAND_PRIORITY_LOW && priority != TBS_COMMAND_PRIORITY_NORMAL
        && priority != TBS_COMMAND_PRIORITY_HIGH && priority != TBS_COMMAND_PRIORITY_SYSTEM
        && priority != TBS_COMMAND_PRIORITY_MAX)
        return TBS_E_BAD_PARAMETER;
    if (command_size > TBS_MAX_BUFFER)
        return TBS_E_BUFFER_TOO_LARGE;

    fd = connect_unix(ctx->data_path);
    if (fd < 0)
        return TBS_E_IOERROR;
    if (!mark_timeouts(fd))
    {
        close(fd);
        return TBS_E_IOERROR;
    }
    /* The command is fully sent before the response is read, so
     * result may alias command (documented as allowed). */
    if (!write_full(fd, command, command_size))
    {
        close(fd);
        return TBS_E_IOERROR;
    }
    if (!read_full(fd, header, sizeof(header)))
    {
        close(fd);
        return TBS_E_IOERROR;
    }
    response_size = load_be32(header + 2);
    if (response_size < TPM2_HEADER_SIZE || response_size > TBS_MAX_BUFFER)
    {
        close(fd);
        return TBS_E_IOERROR;
    }
    if (*result_size < response_size)
    {
        drain_full(fd, response_size - sizeof(header));
        close(fd);
        *result_size = response_size; /* the documented too-small contract */
        return TBS_E_INSUFFICIENT_BUFFER;
    }
    memcpy(result, header, sizeof(header));
    if (response_size > sizeof(header)
        && !read_full(fd, result + sizeof(header), response_size - sizeof(header)))
    {
        close(fd);
        return TBS_E_IOERROR;
    }
    close(fd);
    *result_size = response_size;
    /* Success here means TRANSPORT success: a TPM-level failure
     * is in the response buffer, never synthesized by this layer. */
    return TBS_SUCCESS;
}

TBS_RESULT WINAPI Tbsip_Cancel_Commands(TBS_HCONTEXT context)
{
    struct tbs_context *ctx = context;
    BYTE request[4], response[4];
    int fd;

    if (!context_is_valid(ctx))
        return TBS_E_INVALID_CONTEXT;

    /* Transient control connection: swtpm's cancel cannot
     * interrupt a synchronous in-flight command (its own ctrl
     * channel notes the TPM would need a polling thread); the
     * API is present for compatibility and bounded to what the
     * vTPM reports. */
    fd = connect_unix(ctx->ctrl_path);
    if (fd < 0)
        return TBS_E_IOERROR;
    if (!mark_timeouts(fd))
    {
        close(fd);
        return TBS_E_IOERROR;
    }
    store_be32(request, SWTPM_CMD_CANCEL_TPM_CMD);
    if (!write_full(fd, request, sizeof(request)) || !read_full(fd, response, sizeof(response)))
    {
        close(fd);
        return TBS_E_IOERROR;
    }
    close(fd);
    return load_be32(response) == 0 ? TBS_SUCCESS : TBS_E_IOERROR;
}

TBS_RESULT WINAPI Tbsip_Context_Close(TBS_HCONTEXT context)
{
    struct tbs_context *ctx = context;

    if (!context_is_valid(ctx))
        return TBS_E_INVALID_CONTEXT;
    /* Documented zeroing semantics: the freed handle cannot be
     * reused successfully afterwards. */
    context_unregister(ctx);
    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
    return TBS_SUCCESS;
}

TBS_RESULT WINAPI Tbsi_GetDeviceInfo(UINT32 size, void *info)
{
    TPM_DEVICE_INFO *device_info = info;
    struct tbs_context ctx;
    int fd;

    if (!info || size < sizeof(TPM_DEVICE_INFO))
        return TBS_E_BAD_PARAMETER;
    memset(&ctx, 0, sizeof(ctx));
    if (!build_paths(&ctx))
        return TBS_E_INTERNAL_ERROR;
    fd = connect_unix(ctx.data_path);
    if (fd < 0)
        return TBS_E_TPM_NOT_FOUND;
    close(fd);

    memset(device_info, 0, sizeof(*device_info));
    device_info->structVersion = TPM_VERSION_20;
    device_info->tpmVersion = TPM_VERSION_20;
    /* tpmInterfaceType and tpmImpRevision are reserved (0). */
    return TBS_SUCCESS;
}

/* Unchanged from upstream Wine (out of scope for M10-049): the
 * device-ID surface stays E_NOTIMPL rather than inventing an
 * identity the vTPM does not have. */
HRESULT WINAPI GetDeviceIDString(WCHAR *out, UINT32 size, UINT32 *used, BOOL *tpm)
{
    (void)out;
    (void)size;
    (void)used;
    (void)tpm;
    return E_NOTIMPL;
}
