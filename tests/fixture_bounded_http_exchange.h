#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rut::test::bounded_http_exchange {

inline constexpr std::size_t kResponseByteLimit = 4096u;

enum class Outcome : std::uint8_t {
    None,
    Complete,
    InvalidArgument,
    SocketCreateFailed,
    ConnectFailed,
    SendFailed,
    WriteShutdownFailed,
    ReadFailed,
    DeadlineExceeded,
    ResponseLimitExceeded,
    ResponseMalformed,
    ResponseTruncated,
};

struct Header {
    std::string name;
    std::string value;
};

struct ParsedResponse {
    std::string version;
    std::uint16_t status = 0;
    std::string reason;
    std::vector<Header> headers;
    std::string body;
};

struct Observation {
    Outcome outcome = Outcome::None;
    bool attempted = false;
    bool terminal_frozen = false;
    bool connect_started = false;
    bool connect_completed = false;
    bool send_started = false;
    bool send_completed = false;
    bool write_shutdown_started = false;
    bool write_shutdown_completed = false;
    bool read_started = false;
    bool eof_observed = false;
    std::int64_t start_nanoseconds = 0;
    std::int64_t connect_completed_nanoseconds = 0;
    std::int64_t send_completed_nanoseconds = 0;
    std::int64_t write_shutdown_completed_nanoseconds = 0;
    std::int64_t completion_nanoseconds = 0;
    int error_number = 0;
    std::string request;
    std::string raw_response;
    ParsedResponse parsed;
    std::string diagnostic;
};

// Parse one complete HTTP/1 response. The input must contain the complete
// response through the declared Content-Length and no trailing bytes.
bool parse_response(const std::string& raw,
                    ParsedResponse& parsed,
                    std::string& error,
                    std::size_t limit = kResponseByteLimit);

// Perform exactly one bounded IPv4 request/response exchange. deadline_ns is
// an absolute CLOCK_MONOTONIC/steady_clock-compatible nanosecond deadline.
bool exchange(const std::string& ipv4,
              std::uint16_t port,
              const std::string& request,
              std::int64_t deadline_ns,
              Observation& observation,
              std::size_t limit = kResponseByteLimit,
              bool shutdown_write_after_send = true);

#ifdef RUT_BOUNDED_HTTP_EXCHANGE_TEST_SEAM
namespace test_seam {

using ClockFunction = std::int64_t (*)();
using ShutdownFunction = int (*)(int, int);

void install(ClockFunction clock, ShutdownFunction shutdown);
void reset();

}  // namespace test_seam
#endif

}  // namespace rut::test::bounded_http_exchange
