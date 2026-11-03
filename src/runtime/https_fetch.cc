#include "rut/runtime/https_fetch.h"

#include "rut/common/http_header_validation.h"
#include "rut/platform/socket.h"

#include <arpa/inet.h>
#include <errno.h>
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

u64 jwt_monotonic_ms() {
    timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0 || now.tv_nsec < 0 ||
        now.tv_nsec >= 1000000000 || static_cast<u64>(now.tv_sec) > (~u64{0} - 999) / 1000)
        return 0;
    return static_cast<u64>(now.tv_sec) * 1000 + static_cast<u64>(now.tv_nsec) / 1000000;
}

bool HttpsEndpoint::valid() const {
    in_addr parsed{};
    if (!port || !tls.enabled || !valid_upstream_tls(tls) ||
        !terminated(address, sizeof(address)) || inet_pton(AF_INET, address, &parsed) != 1 ||
        !terminated(path, sizeof(path)) || path[0] != '/')
        return false;
    for (u32 i = 0; path[i]; ++i) {
        const u8 kByte = static_cast<u8>(path[i]);
        if (kByte <= 32 || kByte >= 127 || kByte == '#' || kByte == '\\') return false;
    }
    return true;
}

void BoundedJsonResponse::reset() {
    wire_len_ = body_len_ = offset_ = expected_ = 0;
    headers_ = chunked_ = sized_ = false;
    chunks_.reset();
    result_ = Result::More;
}

BoundedJsonResponse::Result BoundedJsonResponse::append(Str bytes) {
    if (result_ != Result::More || (bytes.len && !bytes.ptr) || bytes.len > kMaxWire - wire_len_)
        return result_ = Result::Error;
    if (bytes.len) __builtin_memcpy(wire_ + wire_len_, bytes.ptr, bytes.len);
    wire_len_ += bytes.len;
    return result_ = consume();
}

BoundedJsonResponse::Result BoundedJsonResponse::consume() {
    if (!headers_) {
        HttpResponseParser parser{};
        ParsedResponse response{};
        response.reset();
        const auto kStatus = parser.parse(reinterpret_cast<const u8*>(wire_), wire_len_, &response);
        if (kStatus == ParseStatus::Error) return Result::Error;
        if (kStatus == ParseStatus::Incomplete)
            return wire_len_ >= 8192 ? Result::Error : Result::More;
        if (parser.header_end > 8192 || response.status_code != 200 || response.headers_truncated ||
            response.content_length_count > 1 || response.content_length > kMaxBody)
            return Result::Error;
        u32 transfer_count = 0, type_count = 0, encoding_count = 0;
        for (u32 i = 0; i < response.header_count; ++i) {
            const auto& header = response.headers[i];
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
                while (end &&
                       (header.value.ptr[end - 1] == ' ' || header.value.ptr[end - 1] == '\t'))
                    --end;
                const Str kType{header.value.ptr, end};
                if (!equal_ci(kType, lit_str("application/json")) &&
                    !equal_ci(kType, lit_str("application/jwk-set+json")))
                    return Result::Error;
            }
        }
        if (type_count != 1 || (transfer_count && response.has_content_length))
            return Result::Error;
        headers_ = true;
        chunked_ = transfer_count != 0;
        sized_ = response.has_content_length;
        expected_ = response.content_length;
        offset_ = parser.header_end;
        chunks_.reset();
    }
    if (chunked_) {
        // A zero-input step is needed to recognize a just-finished data region.
        for (u32 steps = 0; steps <= kMaxWire; ++steps) {
            u32 consumed = 0, start = 0, length = 0;
            const auto kStatus = chunks_.feed(reinterpret_cast<const u8*>(wire_ + offset_),
                                              wire_len_ - offset_,
                                              &consumed,
                                              &start,
                                              &length);
            if (length > kMaxBody - body_len_) return Result::Error;
            if (length) __builtin_memcpy(body_ + body_len_, wire_ + offset_ + start, length);
            body_len_ += length;
            offset_ += consumed;
            if (kStatus == ChunkStatus::Error) return Result::Error;
            if (kStatus == ChunkStatus::Done)
                return offset_ == wire_len_ ? Result::Complete : Result::Error;
            if (kStatus == ChunkStatus::NeedMore) return Result::More;
            if (!consumed) return Result::Error;
        }
        return Result::Error;
    }
    const u32 kAvailable = wire_len_ - offset_;
    if (kAvailable > kMaxBody - body_len_ || (sized_ && kAvailable > expected_ - body_len_))
        return Result::Error;
    if (kAvailable) __builtin_memcpy(body_ + body_len_, wire_ + offset_, kAvailable);
    body_len_ += kAvailable;
    offset_ = wire_len_;
    return sized_ && body_len_ == expected_ ? Result::Complete : Result::More;
}

BoundedJsonResponse::Result BoundedJsonResponse::finish() {
    if (result_ == Result::Complete) return result_;
    return result_ = result_ == Result::More && headers_ && !sized_ && !chunked_ ? Result::Complete
                                                                                 : Result::Error;
}

HttpsFetch::~HttpsFetch() {
    close();
    destroy_tls_client_context(context_);
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
void HttpsFetch::cancel() {
    close();
    response_.reset();
    state_ = State::Cancelled;
}
bool HttpsFetch::init(const HttpsEndpoint& endpoint) {
    if (context_.ssl_ctx || !endpoint.valid()) return false;
    if (!init_tls_client_context(context_, endpoint.tls)) return false;
    endpoint_ = endpoint;
    const int kSize = snprintf(
        request_,
        sizeof(request_),
        "GET %s HTTP/1.1\r\nHost: %s:%u\r\nAccept: application/jwk-set+json, application/json\r\n"
        "Accept-Encoding: identity\r\nConnection: close\r\n\r\n",
        endpoint.path,
        endpoint.tls.server_name,
        endpoint.port);
    if (kSize <= 0 || static_cast<u32>(kSize) >= sizeof(request_)) {
        destroy_tls_client_context(context_);
        return false;
    }
    request_len_ = static_cast<u32>(kSize);
    return true;
}
bool HttpsFetch::start(u64 monotonic_ms, u32 timeout_ms) {
    if (!context_.ssl_ctx || state_ == State::Busy || !monotonic_ms || !timeout_ms) return false;
    close();
    response_.reset();
    started_ = monotonic_ms;
    timeout_ms_ = timeout_ms;
    sent_ = 0;
    state_ = State::Busy;
    fd_ = platform::stream_socket();
    if (fd_ < 0) return fail();
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(endpoint_.port);
    if (inet_pton(AF_INET, endpoint_.address, &address.sin_addr) != 1) return fail();
    const int kResult = connect(fd_, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
    if (kResult != 0 && errno != EINPROGRESS) return fail();
    step_ = connected;
    return true;
}
void HttpsFetch::advance(u64 monotonic_ms) {
    if (state_ != State::Busy) return;
    if (!monotonic_ms || monotonic_ms < started_ || monotonic_ms - started_ >= timeout_ms_) {
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
    if (getsockopt(self.fd_, SOL_SOCKET, SO_ERROR, &error, &length) != 0 || error)
        return self.fail();
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
    ERR_clear_error();
    const int kResult = SSL_write(
        self.ssl_, self.request_ + self.sent_, static_cast<int>(self.request_len_ - self.sent_));
    if (kResult <= 0) return retry_ssl(self.ssl_, kResult) ? false : self.fail();
    self.sent_ += static_cast<u32>(kResult);
    if (self.sent_ == self.request_len_) self.step_ = read;
    return true;
}
bool HttpsFetch::read(HttpsFetch& self) {
    char bytes[4096];
    ERR_clear_error();
    const int kResult = SSL_read(self.ssl_, bytes, sizeof(bytes));
    BoundedJsonResponse::Result result;
    if (kResult > 0) {
        result = self.response_.append({bytes, static_cast<u32>(kResult)});
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
