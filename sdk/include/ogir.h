/* SPDX-License-Identifier: Apache-2.0 */

#ifndef OGIR_H
#define OGIR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * OGIR client SDK, ABI v1 (frozen for the M6 conformance kit).
 *
 * The client API never exposes an authoritative local trust
 * decision: it transports a publisher challenge, receives an
 * opaque publisher-signed permit, and supports proof of
 * possession of the attested session key. Verdict interpretation
 * belongs to the publisher's server.
 *
 * Compatibility: the ABI_VERSION macro and the function set below
 * are frozen for v1. The conformance kit (M6-039) verifies every
 * export exists with these exact signatures; a future v2 adds a
 * new header rather than changing these declarations.
 */

#define OGIR_ABI_VERSION_MAJOR 1
#define OGIR_ABI_VERSION_MINOR 0

typedef enum ogir_status {
    OGIR_STATUS_OK = 0,
    OGIR_STATUS_INVALID_ARGUMENT = 1,
    OGIR_STATUS_UNSUPPORTED = 2,
    OGIR_STATUS_UNAVAILABLE = 3,
    OGIR_STATUS_PROTOCOL_ERROR = 4,
    OGIR_STATUS_INTERNAL_ERROR = 5
} ogir_status;

/*
 * The structured verdict families a relying party must handle.
 * Mirrors the verifier's wire kinds (ADR-0033): UNSUPPORTED and
 * RETRY are never failures of the player, and RESTRICTED carries
 * an admission with reduced scope. The SDK never decides policy;
 * the publisher server does.
 */
typedef enum ogir_verdict {
    OGIR_VERDICT_ALLOW = 0,
    OGIR_VERDICT_RESTRICTED = 1,
    OGIR_VERDICT_UNSUPPORTED = 2,
    OGIR_VERDICT_RETRY = 3,
    OGIR_VERDICT_DENY = 4
} ogir_verdict;

typedef struct ogir_bytes {
    const uint8_t *data;
    size_t length;
} ogir_bytes;

typedef struct ogir_mut_bytes {
    uint8_t *data;
    size_t capacity;
    size_t length;
} ogir_mut_bytes;

/*
 * One structured decision result (ADR-0033 made client-visible).
 * reason_code is a stable, NUL-terminated taxonomy name owned by
 * the permit's issuer; retryable mirrors the verdict family. The
 * permit view is only valid while the session is open.
 */
typedef struct ogir_result {
    ogir_verdict verdict;
    int retryable;
    const char *reason_code;
    ogir_bytes permit;
} ogir_result;

typedef struct ogir_client ogir_client;
typedef struct ogir_session ogir_session;

/*
 * Returns the ABI version this SDK was built against, so
 * integrations can guard their dlopen/dlsym probes. Always a
 * compile-time constant for static links.
 */
uint32_t ogir_abi_version(void);

/*
 * Opens the unprivileged local OGIR client transport.
 * This function does not make a trust decision.
 */
ogir_status ogir_client_open(ogir_client **out_client);

/*
 * Begins a session using an opaque publisher-signed challenge.
 * The returned session is not authorization; the publisher server
 * must validate its permit.
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

/*
 * Reads the structured result for the session's last submission:
 * the verdict family, retry guidance, the stable reason code, and
 * the permit view (empty for non-admissions). The struct borrows
 * session-owned memory; callers copy anything they keep.
 */
ogir_status ogir_session_get_result(
    ogir_session *session,
    ogir_result *out_result
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
