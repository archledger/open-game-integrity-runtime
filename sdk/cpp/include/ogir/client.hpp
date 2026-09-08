/* SPDX-License-Identifier: Apache-2.0 */
#ifndef OGIR_CPP_CLIENT_HPP
#define OGIR_CPP_CLIENT_HPP

/*
 * OGIR C++ wrapper (M6-038, ADR-0034): a header-only RAII skin
 * over the v1 C ABI. It owns nothing but the handles, decides
 * nothing about policy, and keeps the verdict semantics of
 * ADR-0033 intact: Unsupported and Retry are surfaced as their own
 * families, never exceptions, never failures of the player.
 *
 * Usage:
 *   ogir::Client client;                  // throws ogir::Error on transport failure
 *   auto session = client.begin(challenge);
 *   ogir_result result{};
 *   session.result(&result);
 *   switch (result.verdict) { ... }        // the game server's job
 */

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "ogir.h"

namespace ogir {

class Error : public std::runtime_error {
public:
    explicit Error(ogir_status status, const char *what)
        : std::runtime_error(std::string(what ? what : "ogir error") +
                             " (status " + std::to_string(static_cast<int>(status)) + ")"),
          status_(status) {}

    ogir_status status() const noexcept { return status_; }

private:
    ogir_status status_;
};

namespace detail {

inline void check(ogir_status status, const char *what) {
    if (status != OGIR_STATUS_OK) {
        throw Error(status, what);
    }
}

} // namespace detail

/// The structured verdict as a value type (ADR-0033 families).
enum class Verdict { Allow, Restricted, Unsupported, Retry, Deny };

inline Verdict to_verdict(ogir_verdict verdict) noexcept {
    switch (verdict) {
    case OGIR_VERDICT_ALLOW: return Verdict::Allow;
    case OGIR_VERDICT_RESTRICTED: return Verdict::Restricted;
    case OGIR_VERDICT_UNSUPPORTED: return Verdict::Unsupported;
    case OGIR_VERDICT_RETRY: return Verdict::Retry;
    case OGIR_VERDICT_DENY: return Verdict::Deny;
    }
    return Verdict::Deny; // unknown families fail closed
}

/// One decision result: the family, retry guidance, the stable
/// reason code, and the permit bytes copied out of session memory.
struct Result {
    Verdict verdict = Verdict::Deny;
    bool retryable = false;
    std::string reason_code;
    std::vector<std::uint8_t> permit;
};

/// An attested session. Move-only; closing releases the resources.
class Session {
public:
    Session() noexcept = default;

    explicit Session(ogir_session *session) noexcept : session_(session) {}

    Session(Session &&other) noexcept : session_(other.session_) {
        other.session_ = nullptr;
    }

    Session &operator=(Session &&other) noexcept {
        if (this != &other) {
            close();
            session_ = other.session_;
            other.session_ = nullptr;
        }
        return *this;
    }

    Session(const Session &) = delete;
    Session &operator=(const Session &) = delete;

    ~Session() { close(); }

    /// Reads the structured result, copying permit bytes out of
    /// session-owned memory.
    Result result() const {
        ogir_result raw{};
        detail::check(ogir_session_get_result(session_, &raw),
                      "ogir_session_get_result");
        Result out;
        out.verdict = to_verdict(raw.verdict);
        out.retryable = raw.retryable != 0;
        out.reason_code = raw.reason_code ? raw.reason_code : "";
        out.permit.assign(raw.permit.data, raw.permit.data + raw.permit.length);
        return out;
    }

    /// Signs publisher channel-binding material with the attested
    /// session key; the buffer grows to the signature size.
    std::vector<std::uint8_t> sign_binding(const std::uint8_t *data, std::size_t length) {
        std::vector<std::uint8_t> signature(4096);
        ogir_mut_bytes out{signature.data(), signature.size(), 0};
        detail::check(
            ogir_session_sign_binding(session_, ogir_bytes{data, length}, &out),
            "ogir_session_sign_binding");
        signature.resize(out.length);
        return signature;
    }

    void close() noexcept {
        if (session_ != nullptr) {
            ogir_session_close(session_);
            session_ = nullptr;
        }
    }

private:
    ogir_session *session_ = nullptr;
};

/// The client transport. Move-only.
class Client {
public:
    Client() {
        ogir_client *raw = nullptr;
        detail::check(ogir_client_open(&raw), "ogir_client_open");
        client_ = raw;
    }

    Client(Client &&other) noexcept : client_(other.client_) {
        other.client_ = nullptr;
    }

    Client &operator=(Client &&other) noexcept {
        if (this != &other) {
            close();
            client_ = other.client_;
            other.client_ = nullptr;
        }
        return *this;
    }

    Client(const Client &) = delete;
    Client &operator=(const Client &) = delete;

    ~Client() { close(); }

    /// Begins a session for an opaque publisher-signed challenge.
    Session begin(const std::uint8_t *data, std::size_t length) {
        ogir_session *raw = nullptr;
        detail::check(
            ogir_session_begin(client_, ogir_bytes{data, length}, &raw),
            "ogir_session_begin");
        return Session(raw);
    }

    Session begin(const std::vector<std::uint8_t> &challenge) {
        return begin(challenge.data(), challenge.size());
    }

    void close() noexcept {
        if (client_ != nullptr) {
            ogir_client_close(client_);
            client_ = nullptr;
        }
    }

private:
    ogir_client *client_ = nullptr;
};

} // namespace ogir

#endif /* OGIR_CPP_CLIENT_HPP */
