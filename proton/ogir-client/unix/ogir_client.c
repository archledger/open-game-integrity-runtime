/* SPDX-License-Identifier: Apache-2.0 */
/*
 * The ogir-client unixlib companion (M5-033, ADR-0029): native Unix
 * code Wine loads into the game process to serve the PE DLL's
 * dispatch calls. It owns the AF_UNIX transport to the local portal
 * and the bounded frame codec mirroring
 * crates/ogir-agent/src/portal.rs: u32 big-endian length prefix, a
 * 1024-byte frame ceiling, and a Hello handshake whose answer must
 * be the HelloAck shape (the credentials the PORTAL observed - per
 * the M5 entry spike, this wine process's own). Pure Unix C: no
 * windows.h in this translation unit (it clashes with the Unix
 * headers).
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

#define OGIR_PORTAL_MAX_FRAME 1024u
#define OGIR_HELLO_VERSION 1u

struct ogir_unix_open_args
{
    const char *socket_path;
    long fd;
};

struct ogir_unix_close_args
{
    long fd;
};

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

static long ogir_unix_open( void *args )
{
    struct ogir_unix_open_args *open_args = args;
    struct sockaddr_un address;
    uint8_t frame[OGIR_PORTAL_MAX_FRAME];
    uint8_t body[20];
    uint32_t received = 0;
    size_t path_length;
    int fd;

    if (open_args == NULL || open_args->socket_path == NULL) return -1;
    path_length = strlen( open_args->socket_path );
    if (path_length == 0 || path_length >= sizeof( address.sun_path )) return -1;

    fd = socket( AF_UNIX, SOCK_STREAM, 0 );
    if (fd < 0) return -1;

    memset( &address, 0, sizeof( address ) );
    address.sun_family = AF_UNIX;
    memcpy( address.sun_path, open_args->socket_path, path_length + 1 );

    if (connect( fd, (struct sockaddr *)&address, sizeof( address ) ) < 0)
    {
        close( fd );
        return -1;
    }

    /* Hello: 'H' + version(u32 BE) + bounded client name. */
    body[0] = 'H';
    body[1] = 0;
    body[2] = 0;
    body[3] = 0;
    body[4] = (uint8_t)OGIR_HELLO_VERSION;
    memcpy( body + 5, "ogir-client-dll", 15 );
    if (send_frame( fd, body, sizeof( body ) ) || shutdown( fd, SHUT_WR ))
    {
        close( fd );
        return -1;
    }
    if (recv_frame( fd, frame, sizeof( frame ), &received ))
    {
        close( fd );
        return -1;
    }
    /* HelloAck: 'H' + version(u32 BE) + observed pid/uid/gid. A
     * normalized rejection (or anything else) fails closed. */
    if (received != 17 || frame[0] != 'H'
        || frame[1] != 0 || frame[2] != 0 || frame[3] != 0
        || frame[4] != (uint8_t)OGIR_HELLO_VERSION)
    {
        close( fd );
        return -1;
    }

    open_args->fd = fd;
    return 0;
}

static long ogir_unix_close( void *args )
{
    struct ogir_unix_close_args *close_args = args;
    if (close_args == NULL || close_args->fd < 0) return -1;
    return close( (int)close_args->fd );
}

const void *__wine_unix_call_funcs[2] =
{
    (void *)ogir_unix_open,
    (void *)ogir_unix_close,
};

const void *__wine_unix_call_wow64_funcs[2] =
{
    (void *)ogir_unix_open,
    (void *)ogir_unix_close,
};
