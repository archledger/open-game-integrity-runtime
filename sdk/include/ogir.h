/* SPDX-License-Identifier: Apache-2.0 */

#ifndef OGIR_H
#define OGIR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Experimental ABI. No source or binary compatibility is promised before a versioned release. */

typedef enum ogir_status {
    OGIR_STATUS_OK = 0,
    OGIR_STATUS_INVALID_ARGUMENT = 1,
    OGIR_STATUS_UNSUPPORTED = 2,
    OGIR_STATUS_UNAVAILABLE = 3,
    OGIR_STATUS_PROTOCOL_ERROR = 4,
    OGIR_STATUS_INTERNAL_ERROR = 5
} ogir_status;

typedef struct ogir_bytes {
    const uint8_t *data;
    size_t length;
} ogir_bytes;

typedef struct ogir_mut_bytes {
    uint8_t *data;
    size_t capacity;
    size_t length;
} ogir_mut_bytes;

typedef struct ogir_client ogir_client;
typedef struct ogir_session ogir_session;

/*
 * Opens the unprivileged local OGIR client transport.
 * This function does not make a trust decision.
 */
ogir_status ogir_client_open(ogir_client **out_client);

/*
 * Begins a session using an opaque publisher-signed challenge.
 * The returned session is not authorization; the publisher server must validate its permit.
 */
ogir_status ogir_session_begin(
    ogir_client *client,
    ogir_bytes challenge,
    ogir_session **out_session
);

/* Copies the opaque publisher permit when available. */
ogir_status ogir_session_get_permit(
    ogir_session *session,
    ogir_mut_bytes *out_permit
);

/* Signs publisher-provided channel-binding material with the attested session key. */
ogir_status ogir_session_sign_binding(
    ogir_session *session,
    ogir_bytes binding,
    ogir_mut_bytes *out_signature
);

/* Ends local session state and releases resources. */
void ogir_session_close(ogir_session *session);

/* Closes the client transport. */
void ogir_client_close(ogir_client *client);

#ifdef __cplusplus
}
#endif

#endif /* OGIR_H */
