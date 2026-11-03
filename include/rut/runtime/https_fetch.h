#pragma once

#include "rut/common/upstream_tls.h"
#include "rut/runtime/chunked_parser.h"
#include "rut/runtime/http_parser.h"
#include "rut/runtime/tls.h"

namespace rut {
// Trusted, pointer-free HTTP/1.1-over-TLS endpoint. A fixed IPv4 address avoids
// blocking DNS and request-driven resolution. Hostname/CA always authenticate TLS.
struct HttpsEndpoint {
    char address[16]{};
    u16 port = 443;
    char path[1024]{};
    UpstreamTlsSpec tls{};
    bool valid() const;
};

// Bounded response-consuming profile, reusable outside JWT policy. No redirects,
// compression or informational responses. Only 200 JSON with unambiguous framing.
class BoundedJsonResponse {
public:
    enum class Result : u8 { More, Complete, Error };
    static constexpr u32 kMaxBody = 8192;
    static constexpr u32 kMaxWire = 16384;
    void reset();
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
    bool init(const HttpsEndpoint& endpoint);
    bool start(u64 monotonic_ms, u32 timeout_ms);
    void advance(u64 monotonic_ms);
    void cancel();
    State state() const { return state_; }
    Str body() const { return state_ == State::Done ? response_.body() : Str{}; }

private:
    HttpsEndpoint endpoint_{};
    TlsClientContext context_{};
    SSL* ssl_ = nullptr;
    i32 fd_ = -1;
    char request_[1536]{};
    u32 request_len_ = 0;
    u32 sent_ = 0;
    u64 started_ = 0;
    u32 timeout_ms_ = 0;
    State state_ = State::Idle;
    BoundedJsonResponse response_{};
    bool (*step_)(HttpsFetch&) = nullptr;
    void close();
    bool fail();
    static bool connected(HttpsFetch& self);
    static bool handshake(HttpsFetch& self);
    static bool write(HttpsFetch& self);
    static bool read(HttpsFetch& self);
};

// Zero on invalid/failed clock. Callers fail closed on zero or time reversal.
u64 jwt_monotonic_ms();
}  // namespace rut
