#pragma once

#include "rut/common/upstream_tls.h"
#include "rut/runtime/chunked_parser.h"
#include "rut/runtime/http_parser.h"
#include "rut/runtime/tls.h"

namespace rut {
inline constexpr u32 kJwksDnsMessageLimit = 512;
// Trusted, pointer-free HTTP/1.1-over-TLS endpoint. A fixed IP address avoids
// blocking DNS and request-driven resolution. Hostname/CA always authenticate TLS.
struct HttpsEndpoint {
    static constexpr u32 kAddressCapacity = 46;
    char address[kAddressCapacity]{};
    u16 port = 443;
    char path[1024]{};
    UpstreamTlsSpec tls{};
    bool allow_ipv6 = false;
    bool valid() const;
};

// Bounded response-consuming profile, reusable outside JWT policy. No redirects,
// compression or informational responses. Default: 200 JSON. The explicit auth
// profile admits 200/401/403 without a JSON requirement; framing stays strict.
class BoundedJsonResponse {
public:
    enum class Result : u8 { More, Complete, Error };
    static constexpr u32 kMaxBody = 8192;
    static constexpr u32 kMaxWire = 16384;
    void reset(bool authorization = false);
    void reset_callout();
    void reset_jwks(bool conditional, bool retry_after = false);
    void reset_dns();
    u16 status() const { return status_; }
    Str unique_header(Str name) const;
    bool headers(ParsedResponse& response) const;
    Result append(Str bytes);
    Result finish();  // authenticated TLS close_notify, not a bare TCP EOF
    Result result() const { return result_; }
    Str body() const { return result_ == Result::Complete ? Str{body_, body_len_} : Str{}; }

private:
    char wire_[kMaxWire]{};
    char body_[kMaxBody]{};
    u32 wire_len_ = 0;
    u32 body_len_ = 0;
    u32 offset_ = 0;
    u32 expected_ = 0;
    bool authorization_ = false;
    bool callout_ = false;
    bool conditional_jwks_ = false;
    bool retry_after_jwks_ = false;
    bool dns_ = false;
    u16 status_ = 0;
    bool headers_ = false;
    bool chunked_ = false;
    bool sized_ = false;
    ChunkedParser chunks_{};
    Result result_ = Result::More;
    Result consume();
};

// Cold maintenance task; advance never waits for network readiness. It performs
// at most 16 nonblocking steps per call, using function-pointer callbacks. No
// kernel operation retains a buffer between calls, for either gateway backend.
class HttpsFetch {
public:
    enum class State : u8 { Idle, Busy, Done, Failed, Cancelled };
    HttpsFetch() = default;
    HttpsFetch(const HttpsFetch&) = delete;
    HttpsFetch& operator=(const HttpsFetch&) = delete;
    ~HttpsFetch();
    bool init(const HttpsEndpoint& endpoint, bool retry_after_jwks = false);
    // Authorization profile: caller supplies a complete bounded HTTP request.
    bool init_authorization(const HttpsEndpoint& endpoint, Str request);
    bool init_callout(const HttpsEndpoint& endpoint, Str request);
    bool init_dns(const HttpsEndpoint& endpoint);
    bool set_dns_query(Str query);
    bool headers(ParsedResponse& response) const { return response_.headers(response); }
    u16 status() const { return state_ == State::Done ? response_.status() : 0; }
    Str unique_header(Str name) const { return response_.unique_header(name); }
    bool start(u64 monotonic_ms, u32 timeout_ms);
    bool set_address(Str address);
    bool set_jwks_condition(Str entity_tag);
    void advance(u64 monotonic_ms);
    void cancel();
    State state() const { return state_; }
    // A definitive network error from TCP establishment.
    bool connect_failed() const { return state_ == State::Failed && connect_failed_; }
    Str body() const { return state_ == State::Done ? response_.body() : Str{}; }

private:
    HttpsEndpoint endpoint_{};
    TlsClientContext context_{};
    SSL* ssl_ = nullptr;
    i32 fd_ = -1;
    bool authorization_ = false;
    bool callout_ = false;
    bool conditional_jwks_ = false;
    bool retry_after_jwks_ = false;
    bool dns_ = false;
    bool connect_failed_ = false;
    char request_[6144]{};
    u32 request_len_ = 0;
    u32 sent_ = 0;
    u64 started_ = 0;
    u32 timeout_ms_ = 0;
    State state_ = State::Idle;
    BoundedJsonResponse response_{};
    bool (*step_)(HttpsFetch&) = nullptr;
    void close();
    bool fail();
    bool fail_connect(int error);
    bool prepare_jwks_request(Str entity_tag);
    static bool connected(HttpsFetch& self);
    static bool start_tls(HttpsFetch& self);
    static bool handshake(HttpsFetch& self);
    static bool write(HttpsFetch& self);
    static bool read(HttpsFetch& self);
};

// Strong quoted ASCII entity-tag; bounded for owned JWKS validator storage.
bool strong_etag_valid(Str value);

// Zero on invalid/failed clock. Callers fail closed on zero or time reversal.
u64 jwt_monotonic_ms();
}  // namespace rut
