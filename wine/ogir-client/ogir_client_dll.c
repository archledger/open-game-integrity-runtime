/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ogir-client.dll prototype, winelib form (M5-033, ADR-0029): ONE
 * artifact (ogir-client.dll.so) that Wine resolves as ogir-client.dll
 * when it sits beside the game executable - the deployment model
 * Proton uses for its own bridges, proven by the M5 entry spike.
 * The PE-visible C ABI (sdk/include/ogir.h) is exported through the
 * winebuild spec bound to ms_abi implementations (the PE caller
 * passes the first argument in RCX; native SysV code reads RDI);
 * the implementation is native Unix code in this same process,
 * owning the AF_UNIX transport to the local portal and the bounded
 * frame codec mirroring crates/ogir-agent/src/portal.rs (u32 BE
 * length prefix, 1024-byte frame ceiling, Hello handshake whose
 * answer must be the HelloAck shape).
 *
 * Rules honored from wine/README.md: no TPM call, no privileged
 * operation, no raw TBS forwarding - only the unprivileged portal
 * socket. No windows.h in this translation unit (it clashes with
 * the Unix headers).
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

#include "ogir.h"

#define OGIR_PORTAL_MAX_FRAME 1024u
#define OGIR_HELLO_VERSION 1u
#define OGIR_ABI_MAX_BLOB 4096u
#define OGIR_SUN_PATH_LIMIT 107u

struct ogir_client_impl
{
    int fd;
};

struct ogir_session_impl
{
    int reserved;
};

/* The public opaque types alias the implementations. */
typedef struct ogir_client_impl client_t;
typedef struct ogir_session_impl session_t;

static int read_exact( int fd, void *buffer, size_t length )
{
    uint8_t *cursor = buffer;
    size_t done = 0;
    while (done < length)
    {
        ssize_t chunk = read( fd, cursor + done, length - done );
        if (chunk < 0)
        {
            if (errno == EINTR) continue;
            return -1;
        }
        if (chunk == 0) return -1;
        done += (size_t)chunk;
    }
    return 0;
}

static int write_exact( int fd, const void *buffer, size_t length )
{
    const uint8_t *cursor = buffer;
    size_t done = 0;
    while (done < length)
    {
        ssize_t chunk = write( fd, cursor + done, length - done );
        if (chunk < 0)
        {
            if (errno == EINTR) continue;
            return -1;
        }
        done += (size_t)chunk;
    }
    return 0;
}

static int send_frame( int fd, const uint8_t *body, uint32_t length )
{
    uint8_t prefix[4];
    if (length > OGIR_PORTAL_MAX_FRAME) return -1;
    prefix[0] = (uint8_t)(length >> 24);
    prefix[1] = (uint8_t)(length >> 16);
    prefix[2] = (uint8_t)(length >> 8);
    prefix[3] = (uint8_t)length;
    if (write_exact( fd, prefix, sizeof( prefix ) )) return -1;
    return write_exact( fd, body, length );
}

static int recv_frame( int fd, uint8_t *body, uint32_t body_capacity, uint32_t *out_length )
{
    uint8_t prefix[4];
    uint32_t length;
    if (read_exact( fd, prefix, sizeof( prefix ) )) return -1;
    length = ((uint32_t)prefix[0] << 24) | ((uint32_t)prefix[1] << 16)
           | ((uint32_t)prefix[2] << 8) | (uint32_t)prefix[3];
    if (length > OGIR_PORTAL_MAX_FRAME || length > body_capacity) return -1;
    if (length && read_exact( fd, body, length )) return -1;
    *out_length = length;
    return 0;
}

static int portal_handshake( int fd )
{
    uint8_t frame[OGIR_PORTAL_MAX_FRAME];
    uint8_t body[20];
    uint32_t received = 0;

    body[0] = 'H';
    body[1] = 0;
    body[2] = 0;
    body[3] = 0;
    body[4] = (uint8_t)OGIR_HELLO_VERSION;
    memcpy( body + 5, "ogir-client-dll", 15 );
    if (send_frame( fd, body, sizeof( body ) )) return -1;
    if (shutdown( fd, SHUT_WR )) return -1;
    if (recv_frame( fd, frame, sizeof( frame ), &received )) return -1;
    if (received != 17 || frame[0] != 'H'
        || frame[1] != 0 || frame[2] != 0 || frame[3] != 0
        || frame[4] != (uint8_t)OGIR_HELLO_VERSION)
        return -1;
    return 0;
}

static int pointer_length_valid( const uint8_t *data, size_t length )
{
    if (length == 0) return data == NULL;
    if (length > OGIR_ABI_MAX_BLOB) return 0;
    return data != NULL;
}

static ogir_status ogir_client_open_impl( ogir_client **out_client )
{
    const char *socket_path;
    struct sockaddr_un address;
    size_t path_length;
    client_t *client;
    int fd;

    if (out_client == NULL) return OGIR_STATUS_INVALID_ARGUMENT;
    *out_client = NULL;

    socket_path = getenv( "OGIR_PORTAL_SOCKET" );
    if (socket_path == NULL || socket_path[0] == '\0') return OGIR_STATUS_UNAVAILABLE;
    path_length = strlen( socket_path );
    if (path_length > OGIR_SUN_PATH_LIMIT) return OGIR_STATUS_UNAVAILABLE;

    fd = socket( AF_UNIX, SOCK_STREAM, 0 );
    if (fd < 0) return OGIR_STATUS_UNAVAILABLE;

    memset( &address, 0, sizeof( address ) );
    address.sun_family = AF_UNIX;
    memcpy( address.sun_path, socket_path, path_length + 1 );

    if (connect( fd, (struct sockaddr *)&address, sizeof( address ) ) < 0
        || portal_handshake( fd ))
    {
        close( fd );
        return OGIR_STATUS_UNAVAILABLE;
    }

    client = calloc( 1, sizeof( *client ) );
    if (client == NULL)
    {
        close( fd );
        return OGIR_STATUS_INTERNAL_ERROR;
    }
    client->fd = fd;
    *out_client = (ogir_client *)client;
    return OGIR_STATUS_OK;
}

static void ogir_client_close_impl( ogir_client *client )
{
    client_t *impl = (client_t *)client;
    if (impl == NULL) return;
    if (impl->fd >= 0) close( impl->fd );
    free( impl );
}

static ogir_status ogir_session_begin_impl(
    ogir_client *client,
    ogir_bytes challenge,
    ogir_session **out_session )
{
    if (client == NULL || out_session == NULL) return OGIR_STATUS_INVALID_ARGUMENT;
    *out_session = NULL;
    if (!pointer_length_valid( challenge.data, challenge.length ))
        return OGIR_STATUS_INVALID_ARGUMENT;
    /* Session establishment arrives with the M5-034/035 set. */
    return OGIR_STATUS_UNSUPPORTED;
}

static ogir_status ogir_session_get_permit_impl(
    ogir_session *session,
    ogir_mut_bytes *out_permit )
{
    if (session == NULL || out_permit == NULL) return OGIR_STATUS_INVALID_ARGUMENT;
    if (out_permit->data == NULL || out_permit->capacity == 0)
        return OGIR_STATUS_INVALID_ARGUMENT;
    return OGIR_STATUS_UNSUPPORTED;
}

static ogir_status ogir_session_sign_binding_impl(
    ogir_session *session,
    ogir_bytes binding,
    ogir_mut_bytes *out_signature )
{
    if (session == NULL || out_signature == NULL) return OGIR_STATUS_INVALID_ARGUMENT;
    if (!pointer_length_valid( binding.data, binding.length ))
        return OGIR_STATUS_INVALID_ARGUMENT;
    if (out_signature->data == NULL || out_signature->capacity < binding.length)
        return OGIR_STATUS_INVALID_ARGUMENT;
    return OGIR_STATUS_UNSUPPORTED;
}

static void ogir_session_close_impl( ogir_session *session )
{
    (void)session;
}

/* The dispatch entries (codes 0/1, mirrored by pe/ogir_client.c):
 * when this .so serves as the UNIXLIB of the native PE DLL, the
 * PE's WINE_UNIX_CALL arrives here. */
struct ogir_unix_open_args
{
    const char *socket_path;
    long fd;
};

struct ogir_unix_close_args
{
    long fd;
};

static long ogir_unix_open_entry( void *args )
{
    struct ogir_unix_open_args *open_args = args;
    ogir_client *client = NULL;
    ogir_status status;

    if (open_args == NULL) return -1;
    /* The PE side validated the path; the implementation re-reads
     * the environment exactly like the direct export does. */
    status = ogir_client_open_impl( &client );
    if (status != OGIR_STATUS_OK) return -1;
    open_args->fd = ((client_t *)client)->fd;
    /* The fd is now owned by the caller; release the wrapper only. */
    free( client );
    return 0;
}

static long ogir_unix_close_entry( void *args )
{
    struct ogir_unix_close_args *close_args = args;
    if (close_args == NULL || close_args->fd < 0) return -1;
    return close( (int)close_args->fd );
}

/* Wine's loader contract for this artifact class: the PE export
 * table comes from ogir_client.spec; both dispatch tables must
 * carry real entries for the attach path. */
const void *__wine_unix_call_funcs[2] =
{
    (void *)ogir_unix_open_entry,
    (void *)ogir_unix_close_entry,
};

const void *__wine_unix_call_wow64_funcs[2] =
{
    (void *)ogir_unix_open_entry,
    (void *)ogir_unix_close_entry,
};

/* ms_abi wrappers: the PE callers use the Windows x64 convention;
 * the spec binds these names. */
#ifdef __x86_64__

#define OGIR_MS_ABI __attribute__((ms_abi))

OGIR_MS_ABI ogir_status ogir_client_open_msabi( ogir_client **out_client )
{
    return ogir_client_open_impl( out_client );
}

OGIR_MS_ABI void ogir_client_close_msabi( ogir_client *client )
{
    ogir_client_close_impl( client );
}

OGIR_MS_ABI ogir_status ogir_session_begin_msabi(
    ogir_client *client, ogir_bytes challenge, ogir_session **out_session )
{
    return ogir_session_begin_impl( client, challenge, out_session );
}

OGIR_MS_ABI ogir_status ogir_session_get_permit_msabi(
    ogir_session *session, ogir_mut_bytes *out_permit )
{
    return ogir_session_get_permit_impl( session, out_permit );
}

OGIR_MS_ABI ogir_status ogir_session_sign_binding_msabi(
    ogir_session *session, ogir_bytes binding, ogir_mut_bytes *out_signature )
{
    return ogir_session_sign_binding_impl( session, binding, out_signature );
}

OGIR_MS_ABI void ogir_session_close_msabi( ogir_session *session )
{
    ogir_session_close_impl( session );
}

#endif /* __x86_64__ */
