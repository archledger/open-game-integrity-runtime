/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ogir-client.dll (M5-033, ADR-0029): the stable C ABI surface from
 * sdk/include/ogir.h as a real Windows PE DLL built by mingw. This
 * side owns ARGUMENT VALIDATION ONLY; the AF_UNIX transport lives
 * in the unixlib companion (unix/ogir_client.c), reached through
 * ntdll's unix-call dispatch exactly as Wine's own split drivers
 * work. Deployment: x86_64-windows/ogir-client.dll beside
 * x86_64-unix/ogir-client.dll.so on the WINEDLLPATH. No TPM call
 * and no privileged operation ever happens here.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "ogir.h"
#include "wine/unixlib.h"

enum ogir_unix_code
{
    OGIR_UNIX_OPEN = 0,
    OGIR_UNIX_CLOSE = 1
};

struct ogir_unix_open_args
{
    const char *socket_path;
    long fd;
};

struct ogir_unix_close_args
{
    long fd;
};

struct ogir_client
{
    long fd;
};

struct ogir_session
{
    int reserved;
};

#define OGIR_ABI_MAX_BLOB 4096

extern unixlib_handle_t __wine_unixlib_handle;
extern NTSTATUS (WINAPI *__wine_unix_call_dispatcher)( unixlib_handle_t, unsigned int, void * );

#define OGIR_UNIX_CALL( code, args ) \
    __wine_unix_call_dispatcher( __wine_unixlib_handle, (code), (args) )

static int pointer_length_valid( const uint8_t *data, size_t length )
{
    if (length == 0) return data == NULL;
    if (length > OGIR_ABI_MAX_BLOB) return 0;
    return data != NULL;
}

ogir_status ogir_client_open( ogir_client **out_client )
{
    const char *socket_path;
    struct ogir_unix_open_args args;
    ogir_client *client;

    if (out_client == NULL) return OGIR_STATUS_INVALID_ARGUMENT;
    *out_client = NULL;

    socket_path = getenv( "OGIR_PORTAL_SOCKET" );
    if (socket_path == NULL || socket_path[0] == '\0' || strlen( socket_path ) > 107)
        return OGIR_STATUS_UNAVAILABLE;

    memset( &args, 0, sizeof( args ) );
    args.socket_path = socket_path;
    if (OGIR_UNIX_CALL( OGIR_UNIX_OPEN, &args ))
        return OGIR_STATUS_UNAVAILABLE;

    client = calloc( 1, sizeof( *client ) );
    if (client == NULL)
    {
        struct ogir_unix_close_args close_args;
        memset( &close_args, 0, sizeof( close_args ) );
        close_args.fd = args.fd;
        (void)OGIR_UNIX_CALL( OGIR_UNIX_CLOSE, &close_args );
        return OGIR_STATUS_INTERNAL_ERROR;
    }
    client->fd = args.fd;
    *out_client = client;
    return OGIR_STATUS_OK;
}

void ogir_client_close( ogir_client *client )
{
    if (client == NULL) return;
    if (client->fd >= 0)
    {
        struct ogir_unix_close_args args;
        memset( &args, 0, sizeof( args ) );
        args.fd = client->fd;
        (void)OGIR_UNIX_CALL( OGIR_UNIX_CLOSE, &args );
    }
    free( client );
}

ogir_status ogir_session_begin(
    ogir_client *client,
    ogir_bytes challenge,
    ogir_session **out_session )
{
    if (client == NULL || out_session == NULL)
        return OGIR_STATUS_INVALID_ARGUMENT;
    *out_session = NULL;
    if (!pointer_length_valid( challenge.data, challenge.length ))
        return OGIR_STATUS_INVALID_ARGUMENT;
    /* Session establishment arrives with the M5-034/035 set. */
    return OGIR_STATUS_UNSUPPORTED;
}

ogir_status ogir_session_get_permit(
    ogir_session *session,
    ogir_mut_bytes *out_permit )
{
    if (session == NULL || out_permit == NULL)
        return OGIR_STATUS_INVALID_ARGUMENT;
    if (out_permit->data == NULL || out_permit->capacity == 0)
        return OGIR_STATUS_INVALID_ARGUMENT;
    return OGIR_STATUS_UNSUPPORTED;
}

ogir_status ogir_session_sign_binding(
    ogir_session *session,
    ogir_bytes binding,
    ogir_mut_bytes *out_signature )
{
    if (session == NULL || out_signature == NULL)
        return OGIR_STATUS_INVALID_ARGUMENT;
    if (!pointer_length_valid( binding.data, binding.length ))
        return OGIR_STATUS_INVALID_ARGUMENT;
    if (out_signature->data == NULL || out_signature->capacity < binding.length)
        return OGIR_STATUS_INVALID_ARGUMENT;
    return OGIR_STATUS_UNSUPPORTED;
}

void ogir_session_close( ogir_session *session )
{
    (void)session;
}
