/* SPDX-License-Identifier: Apache-2.0 */
/*
 * The ogir-client ABI test harness (M5-033): a plain Windows console
 * program compiled by mingw against the public header, IMPORTING
 * ogir-client.dll at link time (the loader's import pass is what
 * resolves the winelib artifact in the application directory). It
 * covers every ABI function's validation paths - the attack
 * categories that live at the ABI layer: null pointers, invalid
 * pointer/length combinations, oversized blobs - and, when
 * OGIR_PORTAL_SOCKET names a live portal, the real open/handshake
 * path. Compiled for both 64-bit and 32-bit (WoW64) PE.
 *
 * Exit code: the number of failures (0 = all green).
 */

#include <stdio.h>
#include <string.h>

#include "ogir.h"

static int failures = 0;

static void check( const char *name, int condition )
{
    if (condition)
        printf( "PASS %s\n", name );
    else
    {
        printf( "FAIL %s\n", name );
        failures++;
    }
}

int main( void )
{
    ogir_client *client = NULL;
    ogir_session *session = NULL;
    ogir_status status;
    uint8_t big[8192];
    uint8_t buffer[64];
    ogir_bytes empty = { NULL, 0 };
    ogir_bytes null_data_with_length = { NULL, 16 };
    ogir_bytes oversized = { big, sizeof( big ) };
    ogir_bytes binding;
    ogir_mut_bytes small = { buffer, sizeof( buffer ), 0 };
    ogir_mut_bytes no_capacity = { buffer, 0, 0 };

    memset( big, 0x41, sizeof( big ) );

    check( "null out_client rejects",
           ogir_client_open( NULL ) == OGIR_STATUS_INVALID_ARGUMENT );

    check( "null client rejects for begin",
           ogir_session_begin( NULL, empty, &session )
               == OGIR_STATUS_INVALID_ARGUMENT );

    status = ogir_client_open( &client );
    if (status == OGIR_STATUS_OK && client != NULL)
    {
        check( "open succeeded against the portal", 1 );

        check( "null data with nonzero length rejects",
               ogir_session_begin( client, null_data_with_length, &session )
                   == OGIR_STATUS_INVALID_ARGUMENT );
        check( "oversized challenge rejects",
               ogir_session_begin( client, oversized, &session )
                   == OGIR_STATUS_INVALID_ARGUMENT );
        check( "null out_session rejects",
               ogir_session_begin( client, empty, NULL )
                   == OGIR_STATUS_INVALID_ARGUMENT );
        status = ogir_session_begin( client, empty, &session );
        check( "well-formed begin is UNSUPPORTED in the prototype",
               status == OGIR_STATUS_UNSUPPORTED && session == NULL );

        check( "null session rejects for permit",
               ogir_session_get_permit( NULL, &small )
                   == OGIR_STATUS_INVALID_ARGUMENT );
        check( "zero-capacity out rejects",
               ogir_session_get_permit( session, &no_capacity )
                   == OGIR_STATUS_INVALID_ARGUMENT );

        binding.data = big;
        binding.length = 128;
        check( "null session rejects for sign",
               ogir_session_sign_binding( NULL, binding, &small )
                   == OGIR_STATUS_INVALID_ARGUMENT );
        check( "oversized binding rejects",
               ogir_session_sign_binding( session, oversized, &small )
                   == OGIR_STATUS_INVALID_ARGUMENT );
        check( "short capacity rejects",
               ogir_session_sign_binding( session, binding, &no_capacity )
                   == OGIR_STATUS_INVALID_ARGUMENT );

        ogir_client_close( client );
        ogir_client_close( NULL );
        check( "close is null-tolerant", 1 );
    }
    else
    {
        check( "open reports UNAVAILABLE without a portal",
               status == OGIR_STATUS_UNAVAILABLE && client == NULL );
    }

    printf( "failures: %d\n", failures );
    return failures;
}
