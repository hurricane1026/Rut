#include "rut/runtime/https_fetch.h"

#include "rut/common/checked_arithmetic.h"
#include "rut/common/http_header_validation.h"
#include "rut/common/range_int.h"
#include "rut/platform/socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

namespace rut {
namespace {
constexpr u32 kMaxStrongEtagLength = 128;
using EtagLength = range_int<0, i64{kMaxStrongEtagLength} + 1>;

bool terminated(const char* value, u32 capacity) {
    for (u32 i = 0; i < capacity; ++i)
        if (!value[i]) return true;
    return false;
}
bool equal_ci(Str a, Str b) {
    return a.len == b.len && http_header_name_eq_ci(a.ptr, a.len, b.ptr, b.len);
}
bool retry_ssl(SSL* ssl, int result) {
    const int kError = SSL_get_error(ssl, result);
    return kError == SSL_ERROR_WANT_READ || kError == SSL_ERROR_WANT_WRITE;
}
}  // namespace

[[nodiscard]] u64 jwt_monotonic_ms() {
    using WholeSeconds = range_int<0, (UINT64_MAX - 999) / 1000 + 1>;
    using Nanoseconds = range_int<0, 1'000'000'000>;
    timespec now{};
    WholeSeconds seconds;
    Nanoseconds nanos;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
        !WholeSeconds::try_from_i64(now.tv_sec, &seconds) ||
        !Nanoseconds::try_from_i64(now.tv_nsec, &nanos))
        return 0;
    u64 result = 0;
    if (mul_overflow(seconds.to_u64(), u64{1000}, &result)) return 0;
    if (!try_add_to(&result, nanos.divided_by<1'000'000>().to_u64())) return 0;
    return result;
}

bool HttpsEndpoint::valid() const {
    sockaddr_storage parsed{};
    if (!port || !tls.enabled || !valid_upstream_tls(tls) ||
        !terminated(address, sizeof(address)) ||
        !platform::ip_socket_address(address, port, parsed) ||
        (!allow_ipv6 && parsed.ss_family == AF_INET6) || !terminated(path, sizeof(path)) ||
        path[0] != '/')
        return false;
    for (u32 i = 0; path[i]; ++i) {
        const u8 kByte = byte_value(path[i]);
        if (kByte <= 32 || kByte >= 127 || kByte == '#' || kByte == '\\') return false;
    }
    return true;
}

void BoundedJsonResponse::reset(bool authorization) {
    authorization_ = authorization;
    callout_ = false;
    conditional_jwks_ = false;
    retry_after_jwks_ = false;
    dns_ = false;
    status_ = 0;
    wire_len_ = body_len_ = offset_ = expected_ = 0;
    headers_ = chunked_ = sized_ = false;
    chunks_.reset();
    result_ = Result::More;
}
void BoundedJsonResponse::reset_callout() {
    reset(true);
    callout_ = true;
}
void BoundedJsonResponse::reset_jwks(bool conditional, bool retry_after) {
    reset();
    conditional_jwks_ = conditional;
    retry_after_jwks_ = retry_after;
}
void BoundedJsonResponse::reset_dns() {
    reset();
    dns_ = true;
}

bool strong_etag_valid(Str value) {
    range_int<2, i64{kMaxStrongEtagLength} + 1> length;
    if (!value.ptr || !decltype(length)::try_from_u64(value.len, &length) || value.ptr[0] != '"')
        return false;
    const auto last = length - range_int<1, 2>{};
    if (value.ptr[last.index()] != '"') return false;
    for (u32 i = 1; i < last.to<u32>(); ++i) {
        const auto kByte = byte_value(value.ptr[i]);
        if (kByte != 0x21 && (kByte < 0x23 || kByte > 0x7e)) return false;
    }
    return true;
}

BoundedJsonResponse::Result BoundedJsonResponse::append(Str bytes) {
    const auto cursor = range_int{wire_len_};
    using WireLength = range_int<0, i64{kMaxWire} + 1>;
    WireLength end;
    if (result_ != Result::More || (bytes.len && !bytes.ptr) ||
        !WireLength::try_from_i64((cursor + range_int{bytes.len}).value(), &end))
        return result_ = Result::Error;
    if (bytes.len) __builtin_memcpy(wire_ + cursor.index(), bytes.ptr, bytes.len);
    wire_len_ = end.to<u32>();
    return result_ = consume();
}

BoundedJsonResponse::Result BoundedJsonResponse::consume() {
    const auto body_limit = range_int{dns_ ? kJwksDnsMessageLimit : kMaxBody};
    if (!headers_) {
        HttpResponseParser parser{};
        ParsedResponse response{};
        response.reset();
        const auto kStatus = parser.parse(reinterpret_cast<const u8*>(wire_), wire_len_, &response);
        if (kStatus == ParseStatus::Error) return Result::Error;
        if (kStatus == ParseStatus::Incomplete)
            return wire_len_ >= 8192 ? Result::Error : Result::More;
        const bool kNotModified = conditional_jwks_ && response.status_code == 304;
        const bool kThrottled =
            retry_after_jwks_ && (response.status_code == 429 || response.status_code == 503);
        const bool kNeedsType = !authorization_ && !kNotModified && !kThrottled;
        if (parser.header_end > 8192 || (kNeedsType && response.status_code != 200) ||
            (callout_ && (response.status_code < 200 || response.status_code > 599)) ||
            (authorization_ && !callout_ && response.status_code != 200 &&
             response.status_code != 401 && response.status_code != 403) ||
            response.headers_truncated || response.content_length_count > 1 ||
            (response.content_length > body_limit.value() &&
             !((callout_ || conditional_jwks_) && response.status_code == 304)))
            return Result::Error;
        u32 transfer_count = 0, type_count = 0, encoding_count = 0;
        for (u32 i = 0; i < response.header_count; ++i) {
            const auto& header = response.headers[i];
            if (authorization_ && equal_ci(header.name, lit_str("Connection")) &&
                !equal_ci(header.value, lit_str("close")) &&
                !equal_ci(header.value, lit_str("keep-alive")))
                return Result::Error;
            if (equal_ci(header.name, lit_str("Transfer-Encoding"))) {
                if (++transfer_count != 1 || !equal_ci(header.value, lit_str("chunked")))
                    return Result::Error;
            } else if (equal_ci(header.name, lit_str("Content-Encoding"))) {
                if (++encoding_count != 1 || !equal_ci(header.value, lit_str("identity")))
                    return Result::Error;
            } else if (equal_ci(header.name, lit_str("Content-Type"))) {
                if (++type_count != 1) return Result::Error;
                u32 end = 0;
                while (end < header.value.len && header.value.ptr[end] != ';') ++end;
                while (end) {
                    const char last = *(header.value.ptr + range_int{end}.index() - 1);
                    if (last != ' ' && last != '\t') break;
                    --end;
                }
                const Str kType{header.value.ptr, end};
                if (dns_ && !equal_ci(header.value, lit_str("application/dns-message")))
                    return Result::Error;
                if (kNeedsType && !dns_ && !equal_ci(kType, lit_str("application/json")) &&
                    !equal_ci(kType, lit_str("application/jwk-set+json")))
                    return Result::Error;
            }
        }
        if ((kNeedsType && type_count != 1) || (transfer_count && response.has_content_length))
            return Result::Error;
        status_ = response.status_code;
        headers_ = true;
        chunked_ = transfer_count != 0;
        sized_ = response.has_content_length;
        expected_ = response.content_length;
        if ((callout_ && (status_ == 204 || status_ == 205 || status_ == 304)) ||
            (conditional_jwks_ && status_ == 304)) {
            if (chunked_ || (status_ != 304 && expected_ != 0)) return Result::Error;
            sized_ = true;
            expected_ = 0;
        }
        offset_ = parser.header_end;
        chunks_.reset();
    }
    const auto wire_size = range_int{wire_len_};
    if (chunked_) {
        // A zero-input step is needed to recognize a just-finished data region.
        for (u32 steps = 0; steps <= kMaxWire; ++steps) {
            const auto cursor = range_int{offset_};
            u32 available;
            if (!(wire_size - cursor).to(&available)) return Result::Error;
            const char* const input = wire_ + cursor.index();
            u32 consumed = 0, start = 0, length = 0;
            const auto kStatus = chunks_.feed(
                reinterpret_cast<const u8*>(input), available, &consumed, &start, &length);
            if (kStatus == ChunkStatus::Error) return Result::Error;
            const auto body_cursor = range_int{body_len_};
            const auto source_start = range_int{start};
            const auto copied = range_int{length};
            auto next_body = body_cursor;
            auto next_input = cursor;
            if (!body_limit.try_count((body_cursor + copied).value(), &next_body) ||
                !wire_size.try_count((cursor + range_int{consumed}).value(), &next_input) ||
                (length && (source_start + copied).value() > consumed))
                return Result::Error;
            if (length)
                __builtin_memcpy(body_ + body_cursor.index(), input + source_start.index(), length);
            body_len_ = next_body.to<u32>();
            offset_ = next_input.to<u32>();
            if (kStatus == ChunkStatus::Done)
                return offset_ == wire_len_ ? Result::Complete : Result::Error;
            if (kStatus == ChunkStatus::NeedMore) return Result::More;
            if (!consumed) return Result::Error;
        }
        return Result::Error;
    }
    const auto input_cursor = range_int{offset_};
    const auto body_cursor = range_int{body_len_};
    u32 available;
    if (!(wire_size - input_cursor).to(&available)) return Result::Error;
    const auto limit = sized_ ? body_limit.min(range_int{expected_}) : body_limit;
    auto next_body = body_cursor;
    if (!limit.try_count((body_cursor + range_int{available}).value(), &next_body))
        return Result::Error;
    if (available)
        __builtin_memcpy(body_ + body_cursor.index(), wire_ + input_cursor.index(), available);
    body_len_ = next_body.to<u32>();
    offset_ = wire_len_;
    return sized_ && body_len_ == expected_ ? Result::Complete : Result::More;
}

BoundedJsonResponse::Result BoundedJsonResponse::finish() {
    if (result_ == Result::Complete) return result_;
    return result_ = result_ == Result::More && headers_ && !sized_ && !chunked_ ? Result::Complete
                                                                                 : Result::Error;
}

Str BoundedJsonResponse::unique_header(Str name) const {
    if (result_ != Result::Complete) return {};
    HttpResponseParser parser{};
    ParsedResponse response{};
    response.reset();
    if (parser.parse(reinterpret_cast<const u8*>(wire_), wire_len_, &response) !=
        ParseStatus::Complete)
        return {};
    Str value{};
    u32 count = 0;
    for (u32 i = 0; i < response.header_count; ++i) {
        if (!equal_ci(response.headers[i].name, name)) continue;
        value = response.headers[i].value;
        ++count;
    }
    return count == 1 ? value : Str{};
}
bool BoundedJsonResponse::headers(ParsedResponse& response) const {
    response.reset();
    HttpResponseParser parser{};
    return result_ == Result::Complete &&
           parser.parse(reinterpret_cast<const u8*>(wire_), wire_len_, &response) ==
               ParseStatus::Complete;
}

HttpsFetch::~HttpsFetch() {
    close();
    destroy_tls_client_context(context_);
    if (authorization_) OPENSSL_cleanse(request_, sizeof(request_));
}
void HttpsFetch::close() {
    if (ssl_) SSL_free(ssl_);
    ssl_ = nullptr;
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
    step_ = nullptr;
}
bool HttpsFetch::fail() {
    close();
    response_.reset();
    state_ = State::Failed;
    return false;
}
bool HttpsFetch::fail_connect(int error) {
    connect_failed_ = error == ECONNREFUSED || error == ECONNRESET || error == ETIMEDOUT ||
                      error == EHOSTUNREACH || error == ENETUNREACH || error == EHOSTDOWN ||
                      error == ENETDOWN;
    return fail();
}
void HttpsFetch::cancel() {
    close();
    response_.reset();
    state_ = State::Cancelled;
}
bool HttpsFetch::init(const HttpsEndpoint& endpoint, bool retry_after_jwks) {
    if (context_.ssl_ctx || !endpoint.valid()) return false;
    if (!init_tls_client_context(context_, endpoint.tls)) return false;
    endpoint_ = endpoint;
    retry_after_jwks_ = retry_after_jwks;
    if (!prepare_jwks_request({})) {
        destroy_tls_client_context(context_);
        return false;
    }
    return true;
}
bool HttpsFetch::prepare_jwks_request(Str entity_tag) {
    EtagLength tag_length;
    if (!EtagLength::try_from_u64(entity_tag.len, &tag_length)) return false;
    const int kSize = snprintf(
        request_,
        sizeof(request_),
        "GET %s HTTP/1.1\r\nHost: %s:%u\r\nAccept: application/jwk-set+json, application/json\r\n"
        "Accept-Encoding: identity\r\nConnection: close\r\n%s%.*s%s\r\n",
        endpoint_.path,
        endpoint_.tls.server_name,
        range_int{endpoint_.port}.to<u32>(),
        entity_tag.len ? "If-None-Match: " : "",
        tag_length.to<i32>(),
        entity_tag.ptr ? entity_tag.ptr : "",
        entity_tag.len ? "\r\n" : "");
    using FormattedLength = range_int<1, sizeof(request_)>;
    FormattedLength length;
    if (!FormattedLength::try_from_i64(kSize, &length)) return false;
    request_len_ = length.to<u32>();
    return true;
}
bool HttpsFetch::set_jwks_condition(Str entity_tag) {
    if (!context_.ssl_ctx || state_ == State::Busy || authorization_ || dns_ ||
        (entity_tag.len && !strong_etag_valid(entity_tag)) || !prepare_jwks_request(entity_tag))
        return false;
    conditional_jwks_ = true;
    return true;
}

bool HttpsFetch::init_authorization(const HttpsEndpoint& endpoint, Str request) {
    if (!request.ptr || !request.len || request.len > sizeof(request_) || !init(endpoint))
        return false;
    __builtin_memcpy(request_, request.ptr, request.len);
    request_len_ = request.len;
    authorization_ = true;
    return true;
}
bool HttpsFetch::init_callout(const HttpsEndpoint& endpoint, Str request) {
    if (!init_authorization(endpoint, request)) return false;
    callout_ = true;
    return true;
}
bool HttpsFetch::init_dns(const HttpsEndpoint& endpoint) {
    if (context_.ssl_ctx || !endpoint.valid() || !init_tls_client_context(context_, endpoint.tls))
        return false;
    endpoint_ = endpoint;
    dns_ = true;
    return true;
}
bool HttpsFetch::set_dns_query(Str query) {
    if (!dns_ || state_ == State::Busy || !query.ptr || !query.len ||
        query.len > kJwksDnsMessageLimit)
        return false;
    request_len_ = 0;
    const int kHeaderLength = snprintf(
        request_,
        sizeof(request_),
        "POST %s HTTP/1.1\r\nHost: %s:%u\r\nAccept: application/dns-message\r\n"
        "Content-Type: application/dns-message\r\nContent-Length: %u\r\n"
        "Accept-Encoding: identity\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
        endpoint_.path,
        endpoint_.tls.server_name,
        range_int{endpoint_.port}.to<u32>(),
        query.len);
    using HeaderLength = range_int<1, sizeof(request_)>;
    using RequestLength = range_int<1, sizeof(request_) + 1>;
    HeaderLength header;
    RequestLength length;
    if (!HeaderLength::try_from_i64(kHeaderLength, &header) ||
        !RequestLength::try_from_i64((header + range_int{query.len}).value(), &length))
        return false;
    __builtin_memcpy(request_ + header.index(), query.ptr, query.len);
    request_len_ = length.to<u32>();
    return true;
}
bool HttpsFetch::set_address(Str address) {
    if (!context_.ssl_ctx || state_ == State::Busy || !address.ptr || !address.len ||
        address.len >= sizeof(endpoint_.address))
        return false;
    for (u32 i = 0; i < address.len; ++i)
        if (!address.ptr[i]) return false;
    HttpsEndpoint candidate = endpoint_;
    __builtin_memcpy(candidate.address, address.ptr, address.len);
    candidate.address[address.len] = 0;
    if (!candidate.valid()) return false;
    endpoint_ = candidate;
    return true;
}

bool HttpsFetch::start(u64 monotonic_ms, u32 timeout_ms) {
    if (!context_.ssl_ctx || state_ == State::Busy || !request_len_ || !monotonic_ms || !timeout_ms)
        return false;
    close();
    response_.reset(authorization_);
    if (callout_) response_.reset_callout();
    if (dns_) response_.reset_dns();
    if (conditional_jwks_ || retry_after_jwks_)
        response_.reset_jwks(conditional_jwks_, retry_after_jwks_);
    started_ = monotonic_ms;
    timeout_ms_ = timeout_ms;
    sent_ = 0;
    connect_failed_ = false;
    state_ = State::Busy;
    sockaddr_storage address{};
    const socklen_t length =
        platform::ip_socket_address(endpoint_.address, endpoint_.port, address);
    if (!length) return fail();
    fd_ = platform::stream_socket(address.ss_family);
    if (fd_ < 0) return fail();
    const int kResult = connect(fd_, reinterpret_cast<const sockaddr*>(&address), length);
    if (kResult != 0 && errno != EINPROGRESS) return fail_connect(errno);
    step_ = kResult == 0 ? start_tls : connected;
    return true;
}
void HttpsFetch::advance(u64 monotonic_ms) {
    if (state_ != State::Busy) return;
    u64 elapsed = 0;
    if (!monotonic_ms || monotonic_ms < started_ ||
        sub_overflow(monotonic_ms, started_, &elapsed) || elapsed >= timeout_ms_) {
        (void)fail();
        return;
    }
    for (u32 i = 0; i < 16 && step_; ++i)
        if (!step_(*this)) break;
}
bool HttpsFetch::connected(HttpsFetch& self) {
    pollfd ready{self.fd_, POLLOUT, 0};
    const int kReady = poll(&ready, 1, 0);
    if (kReady < 0) return errno == EINTR ? false : self.fail();
    if (!kReady) return false;
    int error = 0;
    socklen_t length = sizeof(error);
    if (getsockopt(self.fd_, SOL_SOCKET, SO_ERROR, &error, &length) != 0) return self.fail();
    if (error) return self.fail_connect(error);
    return start_tls(self);
}
bool HttpsFetch::start_tls(HttpsFetch& self) {
    auto ssl = create_tls_client_ssl(self.context_, self.fd_, self.endpoint_.tls.server_name);
    if (!ssl) return self.fail();
    self.ssl_ = ssl.value();
    static constexpr unsigned char kHttp11[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    if (SSL_set_alpn_protos(self.ssl_, kHttp11, sizeof(kHttp11)) != 0) return self.fail();
    self.step_ = handshake;
    return true;
}
bool HttpsFetch::handshake(HttpsFetch& self) {
    ERR_clear_error();
    const int kResult = SSL_connect(self.ssl_);
    if (kResult != 1) return retry_ssl(self.ssl_, kResult) ? false : self.fail();
    const auto kProtocol = tls_negotiated_protocol(self.ssl_);
    if (SSL_get_verify_result(self.ssl_) != X509_V_OK ||
        (kProtocol != AlpnProtocol::None && kProtocol != AlpnProtocol::Http11))
        return self.fail();
    self.step_ = write;
    return true;
}
bool HttpsFetch::write(HttpsFetch& self) {
    using RequestLength = range_int<0, sizeof(self.request_) + 1>;
    RequestLength length;
    if (!RequestLength::try_from_u64(self.request_len_, &length)) return self.fail();
    const auto cursor = range_int{self.sent_};
    RequestLength remaining;
    if (!RequestLength::try_from_i64((length - cursor).value(), &remaining) ||
        remaining.value() == 0)
        return self.fail();
    ERR_clear_error();
    const int kResult = SSL_write(self.ssl_, self.request_ + cursor.index(), remaining.to<i32>());
    if (kResult <= 0) return retry_ssl(self.ssl_, kResult) ? false : self.fail();
    const auto end = cursor + range_int{kResult};
    RequestLength sent;
    if (!length.try_count(end.value(), &sent)) return self.fail();
    self.sent_ = sent.to<u32>();
    if (self.sent_ == self.request_len_) self.step_ = read;
    return true;
}
bool HttpsFetch::read(HttpsFetch& self) {
    char bytes[4096];
    constexpr auto kCapacity = range_int<sizeof(bytes), sizeof(bytes) + 1>{};
    ERR_clear_error();
    const int kResult = SSL_read(self.ssl_, bytes, kCapacity.to<i32>());
    BoundedJsonResponse::Result result;
    if (kResult > 0) {
        using ReadLength = range_int<1, sizeof(bytes) + 1>;
        ReadLength length;
        if (!ReadLength::try_from_i64(kResult, &length)) return self.fail();
        result = self.response_.append({bytes, length.to<u32>()});
    } else {
        const int kError = SSL_get_error(self.ssl_, kResult);
        if (kError == SSL_ERROR_WANT_READ || kError == SSL_ERROR_WANT_WRITE) return false;
        if (kError != SSL_ERROR_ZERO_RETURN) return self.fail();
        result = self.response_.finish();
    }
    if (result == BoundedJsonResponse::Result::Error) return self.fail();
    if (result == BoundedJsonResponse::Result::Complete) {
        self.close();
        self.state_ = State::Done;
        return false;
    }
    return true;
}
}  // namespace rut
