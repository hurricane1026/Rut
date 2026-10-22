#pragma once

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <openssl/err.h>

namespace {

inline void grpc_web_test_init_raw_request(
    rut::Connection& conn, u8* storage, u32 cap, const char* request, u32 request_len) {
    conn.reset();
    conn.bind_request_receive_buffer(storage, cap);
    __builtin_memcpy(storage, request, request_len);
    conn.recv_buf.commit(request_len);
    for (u32 i = 3; i < request_len; i++) {
        if (storage[i - 3] == '\r' && storage[i - 2] == '\n' && storage[i - 1] == '\r' &&
            storage[i] == '\n') {
            conn.req_header_end = i + 1;
            return;
        }
    }
}

inline void grpc_web_test_init_request(rut::Connection& conn, u8* storage, u32 cap) {
    static constexpr char kRequest[] =
        "POST /test.Echo/Call HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/grpc-web\r\n"
        "Content-Length: 0\r\n\r\n";
    grpc_web_test_init_raw_request(conn, storage, cap, kRequest, sizeof(kRequest) - 1);
}

template <typename Call>
// Retry only syscall interruption reported by OpenSSL, within the caller's
// original absolute timeout budget for this SSL operation.
inline bool grpc_web_test_ssl_call(SSL* ssl,
                                   int fd,
                                   u64 deadline_us,
                                   int* result,
                                   int* error_number,
                                   int* ssl_error,
                                   unsigned long* openssl_error,
                                   std::atomic<u32>* retry_count,
                                   Call&& call) {
    for (;;) {
        const u64 now = monotonic_us();
        if (now >= deadline_us) {
            *error_number = ETIMEDOUT;
            *ssl_error = SSL_ERROR_SYSCALL;
            *openssl_error = ERR_peek_error();
            *result = -1;
            return false;
        }
        const u64 remaining = deadline_us - now;
        timeval timeout{static_cast<time_t>(remaining / 1000000),
                        static_cast<suseconds_t>(remaining % 1000000)};
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
            *error_number = errno;
            *ssl_error = SSL_ERROR_SYSCALL;
            *openssl_error = ERR_peek_error();
            *result = -1;
            return false;
        }
        ERR_clear_error();
        errno = 0;
        *result = call();
        if (*result > 0) return true;
        *error_number = errno;
        *ssl_error = SSL_get_error(ssl, *result);
        *openssl_error = ERR_peek_error();
        const bool interrupted = *error_number == EINTR && (*ssl_error == SSL_ERROR_WANT_READ ||
                                                            *ssl_error == SSL_ERROR_WANT_WRITE ||
                                                            *ssl_error == SSL_ERROR_SYSCALL);
        if (!interrupted) return false;
        if (retry_count) retry_count->fetch_add(1, std::memory_order_relaxed);
    }
}

struct GrpcWebTestResponseFraming {
    bool headers_complete = false;
    bool valid = true;
    bool has_content_length = false;
    bool web = false;
    bool text = false;
    size_t body_offset = 0;
    size_t content_length = 0;
};

inline GrpcWebTestResponseFraming grpc_web_test_response_framing(const u8* bytes, size_t length) {
    GrpcWebTestResponseFraming result;
    if (length == 0) return result;
    const auto* boundary = std::search(bytes, bytes + length, "\r\n\r\n", "\r\n\r\n" + 4);
    if (boundary == bytes + length) return result;
    result.headers_complete = true;
    result.body_offset = static_cast<size_t>(boundary - bytes) + 4;
    const u8* line = static_cast<const u8*>(std::memchr(bytes, '\n', result.body_offset));
    if (!line) {
        result.valid = false;
        return result;
    }
    line++;
    while (line < boundary) {
        const u8* line_end = static_cast<const u8*>(std::memchr(line, '\n', boundary + 2 - line));
        if (!line_end || line_end == line || line_end[-1] != '\r') {
            result.valid = false;
            return result;
        }
        const u32 line_len = static_cast<u32>(line_end - line - 1);
        const u8* colon = static_cast<const u8*>(std::memchr(line, ':', line_len));
        if (!colon) {
            result.valid = false;
            return result;
        }
        Str name{reinterpret_cast<const char*>(line), static_cast<u32>(colon - line)};
        const u8* value = colon + 1;
        const u8* line_limit = line + line_len;
        while (value < line_limit && (*value == ' ' || *value == '\t')) value++;
        while (line_limit > value && (line_limit[-1] == ' ' || line_limit[-1] == '\t'))
            line_limit--;
        Str header_value{reinterpret_cast<const char*>(value),
                         static_cast<u32>(line_limit - value)};
        if (http_header_name_eq_ci(name.ptr, name.len, "content-length", 14)) {
            if (result.has_content_length || !header_value.len) {
                result.valid = false;
                return result;
            }
            size_t parsed = 0;
            for (u32 i = 0; i < header_value.len; i++) {
                const char c = header_value.ptr[i];
                if (c < '0' || c > '9' ||
                    parsed > (static_cast<size_t>(-1) - static_cast<size_t>(c - '0')) / 10) {
                    result.valid = false;
                    return result;
                }
                parsed = parsed * 10 + static_cast<size_t>(c - '0');
            }
            result.has_content_length = true;
            result.content_length = parsed;
        } else if (http_header_name_eq_ci(name.ptr, name.len, "content-type", 12)) {
            const auto mode = grpc_web_content_type(header_value);
            result.web = mode == GrpcWebContentType::Binary || mode == GrpcWebContentType::Text;
            result.text = mode == GrpcWebContentType::Text;
        }
        line = line_end + 1;
    }
    return result;
}

inline bool grpc_web_test_complete_envelope(const u8* body, size_t length, bool text) {
    std::vector<u8> decoded;
    if (text) {
        decoded.resize(length);
        GrpcWebBase64Decoder decoder;
        decoder.init();
        u32 consumed = 0, written = 0;
        if (decoder.feed(body,
                         static_cast<u32>(length),
                         consumed,
                         decoded.data(),
                         static_cast<u32>(decoded.size()),
                         written) != GrpcWebCodecStatus::Ok ||
            consumed != length || decoder.finish() != GrpcWebCodecStatus::Ok)
            return false;
        decoded.resize(written);
        body = decoded.data();
        length = decoded.size();
    }
    size_t offset = 0;
    while (offset < length) {
        if (length - offset < 5) return false;
        const u8 flags = body[offset];
        const u32 message_len = (static_cast<u32>(body[offset + 1]) << 24) |
                                (static_cast<u32>(body[offset + 2]) << 16) |
                                (static_cast<u32>(body[offset + 3]) << 8) |
                                static_cast<u32>(body[offset + 4]);
        if (message_len > length - offset - 5) return false;
        if (flags == 0x80) {
            const u8* trailer = body + offset + 5;
            const u8* trailer_end = trailer + message_len;
            bool has_status = false;
            while (trailer < trailer_end) {
                const u8* line_end = static_cast<const u8*>(
                    std::memchr(trailer, '\n', static_cast<size_t>(trailer_end - trailer)));
                if (!line_end || line_end == trailer || line_end[-1] != '\r') return false;
                const u32 line_len = static_cast<u32>(line_end - trailer - 1);
                const u8* colon = static_cast<const u8*>(std::memchr(trailer, ':', line_len));
                if (!colon) return false;
                if (http_header_name_eq_ci(reinterpret_cast<const char*>(trailer),
                                           static_cast<u32>(colon - trailer),
                                           "grpc-status",
                                           11))
                    has_status = true;
                trailer = line_end + 1;
            }
            return has_status && offset + 5 + message_len == length;
        }
        if (flags > 1) return false;
        offset += 5 + message_len;
    }
    return false;
}

inline std::vector<u8> grpc_web_test_base64(const std::vector<u8>& input) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<u8> output;
    output.reserve(((input.size() + 2) / 3) * 4);
    for (size_t i = 0; i < input.size(); i += 3) {
        const u32 left = static_cast<u32>(input.size() - i);
        const u8 a = input[i];
        const u8 b = left > 1 ? input[i + 1] : 0;
        const u8 c = left > 2 ? input[i + 2] : 0;
        output.push_back(kAlphabet[a >> 2]);
        output.push_back(kAlphabet[((a & 3) << 4) | (b >> 4)]);
        output.push_back(left > 1 ? kAlphabet[((b & 15) << 2) | (c >> 6)] : '=');
        output.push_back(left > 2 ? kAlphabet[c & 63] : '=');
    }
    return output;
}

inline bool grpc_web_test_decode_text_response(const std::vector<u8>& response,
                                               std::vector<u8>& decoded) {
    static constexpr char kBoundary[] = "\r\n\r\n";
    const auto boundary =
        std::search(response.begin(), response.end(), kBoundary, kBoundary + sizeof(kBoundary) - 1);
    if (boundary == response.end()) return false;
    const auto body_offset =
        static_cast<size_t>(boundary - response.begin()) + sizeof(kBoundary) - 1;
    if (body_offset > response.size()) return false;
    const u8* body = response.data() + body_offset;
    const u32 body_len = static_cast<u32>(response.size() - body_offset);
    decoded.resize(body_len);
    GrpcWebBase64Decoder decoder{};
    decoder.init();
    u32 consumed = 0, written = 0;
    if (decoder.feed(body, body_len, consumed, decoded.data(), body_len, written) !=
            GrpcWebCodecStatus::Ok ||
        consumed != body_len || decoder.finish() != GrpcWebCodecStatus::Ok)
        return false;
    decoded.resize(written);
    return true;
}

inline bool grpc_web_test_h1_abort_partial_upload(EchoServer& server, u16 port) {
    const int fd = connect_test_loopback(port);
    if (fd < 0) return false;
    set_socket_timeouts(fd, 5);
    static constexpr char kRequest[] =
        "POST /test.Echo/Call HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/grpc-web\r\n"
        "Content-Length: 12\r\n"
        "Connection: close\r\n\r\n";
    static constexpr u8 kPartialBody[] = {0, 0, 0, 0, 7, 0xaa};
    const bool sent =
        write_all_fd(fd, reinterpret_cast<const u8*>(kRequest), sizeof(kRequest) - 1) &&
        write_all_fd(fd, kPartialBody, sizeof(kPartialBody));
    const u64 deadline = monotonic_us() + 3000000;
    while (sent && !server.requests.load() && monotonic_us() < deadline) usleep(1000);
    const bool reached_backend = server.requests.load() != 0;
    shutdown(fd, SHUT_RDWR);
    close(fd);
    return sent && reached_backend;
}

inline bool grpc_web_test_h1_exchange(u16 port,
                                      bool text,
                                      bool chunked,
                                      const std::vector<u8>& body,
                                      std::vector<u8>& response,
                                      bool tls = false,
                                      const std::vector<u8>* expected_body = nullptr,
                                      const char* extra_headers = "",
                                      std::atomic<u32>* tls_retry_count = nullptr) {
    const int fd = connect_test_loopback(port);
    if (fd < 0) {
        fprintf(stderr,
                "grpc_web_test_h1_exchange failed stage=connect errno=%d rc=%d ssl_error=%d "
                "openssl_error=%lu wrote=0 read=0\n",
                errno,
                -1,
                0,
                0ul);
        return false;
    }
    SSL_CTX* tls_context = nullptr;
    SSL* ssl = nullptr;
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    auto fail = [&](const char* stage,
                    int error_number,
                    int result,
                    int ssl_error,
                    unsigned long openssl_error) {
        fprintf(stderr,
                "grpc_web_test_h1_exchange failed stage=%s errno=%d rc=%d ssl_error=%d "
                "openssl_error=%lu wrote=%zu read=%zu\n",
                stage,
                error_number,
                result,
                ssl_error,
                openssl_error,
                bytes_written,
                bytes_read);
        if (ssl) SSL_free(ssl);
        if (tls_context) SSL_CTX_free(tls_context);
        close(fd);
        return false;
    };
    set_socket_timeouts(fd, 5);
    if (tls) {
        ERR_clear_error();
        errno = 0;
        tls_context = SSL_CTX_new(TLS_client_method());
        if (!tls_context) {
            const int error_number = errno;
            const unsigned long openssl_error = ERR_peek_error();
            return fail("ctx", error_number, 0, 0, openssl_error);
        }
        SSL_CTX_set_verify(tls_context, SSL_VERIFY_NONE, nullptr);
        ERR_clear_error();
        errno = 0;
        ssl = SSL_new(tls_context);
        if (!ssl) {
            const int error_number = errno;
            const unsigned long openssl_error = ERR_peek_error();
            return fail("new", error_number, 0, 0, openssl_error);
        }
        ERR_clear_error();
        errno = 0;
        if (!SSL_set_fd(ssl, fd)) {
            const int error_number = errno;
            const unsigned long openssl_error = ERR_peek_error();
            return fail("setfd", error_number, 0, 0, openssl_error);
        }
        const u64 tls_deadline = monotonic_us() + 5000000;
        int connect_result = 0, error_number = 0, ssl_error = 0;
        unsigned long openssl_error = 0;
        if (!grpc_web_test_ssl_call(ssl,
                                    fd,
                                    tls_deadline,
                                    &connect_result,
                                    &error_number,
                                    &ssl_error,
                                    &openssl_error,
                                    tls_retry_count,
                                    [&] { return SSL_connect(ssl); })) {
            return fail("SSL_connect", error_number, connect_result, ssl_error, openssl_error);
        }
    }

    std::vector<u8> wire;
    const char* content_type = text ? "Application/Grpc-Web-Text" : "Application/Grpc-Web";
    char header[512];
    const int header_len =
        snprintf(header,
                 sizeof(header),
                 "POST /test.Echo/Call HTTP/1.1\r\n"
                 "Host: localhost\r\n"
                 "%s"
                 "Content-Type: %s\r\n"
                 "%s"
                 "Connection: close\r\n\r\n",
                 extra_headers,
                 content_type,
                 chunked ? "Transfer-Encoding: chunked\r\n" : "Content-Length: 0\r\n");
    if (header_len <= 0 || static_cast<size_t>(header_len) >= sizeof(header)) {
        return fail("request_format", 0, header_len, 0, 0);
    }
    wire.insert(wire.end(), header, header + header_len);
    if (!chunked) {
        // Replace the placeholder Content-Length line before appending body.
        static constexpr char kPlaceholder[] = "Content-Length: 0\r\n";
        const auto found = std::search(
            wire.begin(), wire.end(), kPlaceholder, kPlaceholder + sizeof(kPlaceholder) - 1);
        if (found == wire.end()) {
            return fail("request_format", 0, -1, 0, 0);
        }
        const size_t offset = static_cast<size_t>(found - wire.begin());
        char actual[48];
        const int actual_len =
            snprintf(actual, sizeof(actual), "Content-Length: %zu\r\n", body.size());
        wire.erase(wire.begin() + offset, wire.begin() + offset + sizeof(kPlaceholder) - 1);
        wire.insert(wire.begin() + offset, actual, actual + actual_len);
        wire.insert(wire.end(), body.begin(), body.end());
    } else {
        constexpr size_t kChunk = 1024;
        for (size_t offset = 0; offset < body.size();) {
            const size_t n = std::min(kChunk, body.size() - offset);
            char size[24];
            const int size_len = snprintf(size, sizeof(size), "%zx\r\n", n);
            wire.insert(wire.end(), size, size + size_len);
            wire.insert(wire.end(), body.begin() + offset, body.begin() + offset + n);
            wire.push_back('\r');
            wire.push_back('\n');
            offset += n;
        }
        static constexpr char kEnd[] = "0\r\n\r\n";
        wire.insert(wire.end(), kEnd, kEnd + sizeof(kEnd) - 1);
    }
    if (!tls) {
        while (bytes_written < wire.size()) {
            const ssize_t n =
                send(fd, wire.data() + bytes_written, wire.size() - bytes_written, MSG_NOSIGNAL);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) {
                const int error_number = errno;
                return fail("write", error_number, static_cast<int>(n), 0, 0);
            }
            bytes_written += static_cast<size_t>(n);
        }
    } else {
        while (bytes_written < wire.size()) {
            const u64 operation_deadline = monotonic_us() + 5000000;
            int n = 0, error_number = 0, ssl_error = 0;
            unsigned long openssl_error = 0;
            if (!grpc_web_test_ssl_call(ssl,
                                        fd,
                                        operation_deadline,
                                        &n,
                                        &error_number,
                                        &ssl_error,
                                        &openssl_error,
                                        tls_retry_count,
                                        [&] {
                                            return SSL_write(
                                                ssl,
                                                wire.data() + bytes_written,
                                                static_cast<int>(wire.size() - bytes_written));
                                        }))
                return fail("write", error_number, n, ssl_error, openssl_error);
            bytes_written += static_cast<size_t>(n);
        }
    }
    u8 buf[8192];
    bool tls_eof = false;
    for (;;) {
        ssize_t n = 0;
        if (!tls) {
            n = recv(fd, buf, sizeof(buf), 0);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) {
                const int error_number = errno;
                return fail("read", error_number, static_cast<int>(n), 0, 0);
            }
            if (n == 0) break;
        } else {
            const u64 operation_deadline = monotonic_us() + 5000000;
            int result = 0, error_number = 0, ssl_error = 0;
            unsigned long openssl_error = 0;
            const bool read_ok =
                grpc_web_test_ssl_call(ssl,
                                       fd,
                                       operation_deadline,
                                       &result,
                                       &error_number,
                                       &ssl_error,
                                       &openssl_error,
                                       tls_retry_count,
                                       [&] { return SSL_read(ssl, buf, sizeof(buf)); });
            if (!read_ok) {
                if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                    tls_eof = true;
                    break;
                }
                if ((ssl_error == SSL_ERROR_SSL &&
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
                     ERR_GET_REASON(openssl_error) == SSL_R_UNEXPECTED_EOF_WHILE_READING
#else
                     false
#endif
                     ) ||
                    (ssl_error == SSL_ERROR_SYSCALL && error_number == 0)) {
                    const auto framing =
                        grpc_web_test_response_framing(response.data(), response.size());
                    const bool complete_content_length =
                        framing.headers_complete && framing.valid && framing.has_content_length &&
                        response.size() >= framing.body_offset &&
                        response.size() - framing.body_offset == framing.content_length;
                    const bool complete_connection_delimited_web =
                        framing.headers_complete && framing.valid && framing.web &&
                        !framing.has_content_length && response.size() >= framing.body_offset &&
                        grpc_web_test_complete_envelope(response.data() + framing.body_offset,
                                                        response.size() - framing.body_offset,
                                                        framing.text);
                    if (complete_content_length || complete_connection_delimited_web) {
                        tls_eof = true;
                        break;
                    }
                }
                return fail("read", error_number, result, ssl_error, openssl_error);
            }
            n = result;
        }
        response.insert(response.end(), buf, buf + n);
        bytes_read += static_cast<size_t>(n);
        const auto framing = grpc_web_test_response_framing(response.data(), response.size());
        if (framing.headers_complete) {
            if (!framing.valid) return fail("response_headers", 0, 0, 0, 0);
            if (framing.has_content_length) {
                if (response.size() - framing.body_offset > framing.content_length)
                    return fail("response_length", 0, static_cast<int>(response.size()), 0, 0);
                if (response.size() - framing.body_offset == framing.content_length) break;
            }
        }
        if (expected_body && std::search(response.begin(),
                                         response.end(),
                                         expected_body->begin(),
                                         expected_body->end()) != response.end())
            break;
        if (response.size() > 256 * 1024) {
            return fail("sizecap", 0, static_cast<int>(response.size()), 0, 0);
        }
    }
    const auto final_framing = grpc_web_test_response_framing(response.data(), response.size());
    if (tls && tls_eof) {
        if (!final_framing.headers_complete || !final_framing.valid)
            return fail("response_truncated", 0, static_cast<int>(response.size()), 0, 0);
        if (final_framing.web && !final_framing.has_content_length &&
            (response.size() < final_framing.body_offset ||
             !grpc_web_test_complete_envelope(response.data() + final_framing.body_offset,
                                              response.size() - final_framing.body_offset,
                                              final_framing.text)))
            return fail("response_truncated", 0, static_cast<int>(response.size()), 0, 0);
    }
    if (final_framing.headers_complete && final_framing.valid && final_framing.has_content_length &&
        response.size() - final_framing.body_offset != final_framing.content_length)
        return fail("response_truncated", 0, static_cast<int>(response.size()), 0, 0);
    if (ssl) SSL_free(ssl);
    if (tls_context) SSL_CTX_free(tls_context);
    close(fd);
    return true;
}

struct GrpcWebTlsGateServer {
    TlsServerContext* tls_context = nullptr;
    int listen_fd = -1;
    int gate[2] = {-1, -1};
    u16 port = 0;
    pthread_t thread{};
    std::atomic<bool> client_hello_waiting{false};
    std::atomic<bool> served{false};
    bool pause_handshake = false;
    bool truncate_response = false;
    bool clean_close_truncated_response = false;
    bool unclean_close_response = false;
    bool started = false;

    static void* run(void* ptr) {
        auto* self = static_cast<GrpcWebTlsGateServer*>(ptr);
        pollfd listener{self->listen_fd, POLLIN, 0};
        if (poll(&listener, 1, 5000) <= 0) return nullptr;
        const int fd = accept(self->listen_fd, nullptr, nullptr);
        if (fd < 0) return nullptr;
        set_socket_timeouts(fd, 5);
        auto created = create_tls_server_ssl(self->tls_context, fd);
        SSL* ssl = created ? created.value() : nullptr;
        if (ssl && self->pause_handshake) {
            pollfd hello{fd, POLLIN, 0};
            if (poll(&hello, 1, 5000) > 0 && (hello.revents & POLLIN)) {
                u8 byte = 0;
                if (recv(fd, &byte, 1, MSG_PEEK) == 1) {
                    self->client_hello_waiting.store(true, std::memory_order_release);
                    u8 release = 0;
                    while (read(self->gate[0], &release, 1) < 0 && errno == EINTR) {
                    }
                    self->client_hello_waiting.store(false, std::memory_order_release);
                }
            }
        }
        if (ssl && SSL_accept(ssl) == 1) {
            u8 request[8192];
            u32 request_len = 0;
            for (;;) {
                if (request_len == sizeof(request)) break;
                const int n = SSL_read(ssl, request + request_len, sizeof(request) - request_len);
                if (n <= 0 || static_cast<u32>(n) > sizeof(request) - request_len) break;
                request_len += static_cast<u32>(n);
                const auto end =
                    std::search(request, request + request_len, "\r\n\r\n", "\r\n\r\n" + 4);
                if (end != request + request_len &&
                    request_len - static_cast<u32>(end - request) - 4 >= 6)
                    break;
                if (request_len == sizeof(request)) break;
            }
            if (request_len) {
                static constexpr u8 body[] = {0,   0,   0,   0,   1,   0x7f, 0x80, 0,    0,
                                              0,   16,  'g', 'r', 'p', 'c',  '-',  's',  't',
                                              'a', 't', 'u', 's', ':', ' ',  '0',  '\r', '\n'};
                char headers[160];
                const int header_len =
                    self->clean_close_truncated_response
                        ? snprintf(headers,
                                   sizeof(headers),
                                   "HTTP/1.1 200 OK\r\nConnection: close\r\n"
                                   "Content-Type: application/grpc-web\r\n\r\n")
                        : snprintf(headers,
                                   sizeof(headers),
                                   "HTTP/1.1 200 OK\r\nConnection: close\r\n"
                                   "Content-Type: application/grpc-web\r\n"
                                   "Content-Length: %zu\r\n\r\n",
                                   sizeof(body) + (self->truncate_response ? 7 : 0));
                bool ok = header_len > 0 && static_cast<size_t>(header_len) < sizeof(headers);
                for (size_t offset = 0; ok && offset < static_cast<size_t>(header_len);) {
                    const int n = SSL_write(ssl, headers + offset, header_len - offset);
                    if (n <= 0)
                        ok = false;
                    else
                        offset += static_cast<size_t>(n);
                }
                const size_t body_to_send =
                    self->truncate_response ? sizeof(body) / 2 : sizeof(body);
                for (size_t offset = 0; ok && offset < body_to_send;) {
                    const int n = SSL_write(ssl, body + offset, body_to_send - offset);
                    if (n <= 0)
                        ok = false;
                    else
                        offset += static_cast<size_t>(n);
                }
                self->served.store(ok, std::memory_order_release);
                if ((!self->truncate_response && !self->unclean_close_response) ||
                    self->clean_close_truncated_response)
                    SSL_shutdown(ssl);
            }
        }
        if (ssl) SSL_free(ssl);
        close(fd);
        return nullptr;
    }

    bool start() {
        auto context = create_tls_server_context(RUT_GRPC_FIXTURES "/localhost_cert.pem",
                                                 RUT_GRPC_FIXTURES "/localhost_key.pem");
        if (!context) return false;
        tls_context = context.value();
        listen_fd = create_listen_socket(0).value_or(-1);
        if (listen_fd < 0 || pipe(gate) != 0) return false;
        port = get_port(listen_fd);
        started = pthread_create(&thread, nullptr, &run, this) == 0;
        return started;
    }
    ~GrpcWebTlsGateServer() {
        if (gate[1] >= 0) {
            const u8 release = 1;
            (void)write(gate[1], &release, 1);
        }
        if (started) pthread_join(thread, nullptr);
        if (listen_fd >= 0) close(listen_fd);
        if (gate[0] >= 0) close(gate[0]);
        if (gate[1] >= 0) close(gate[1]);
        destroy_tls_server_context(tls_context);
    }
};

template <typename Loop>
void grpc_web_h1_streaming_text_message_case(rut::test::TestCase* _tc,
                                             u32 native_len,
                                             bool partial_next) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    server->stream_response_len = native_len;
    server->stream_response_partial_next = partial_next;
    server->reply_mode = 5;
    auto shard = std::make_unique<Shard<Loop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    REQUIRE(shard->init_access_log());
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    std::vector<u8> message(native_len);
    message[0] = 0;
    const u32 payload_len = native_len - 5;
    message[1] = static_cast<u8>(payload_len >> 24);
    message[2] = static_cast<u8>(payload_len >> 16);
    message[3] = static_cast<u8>(payload_len >> 8);
    message[4] = static_cast<u8>(payload_len);
    for (u32 i = 5; i < native_len; i++) message[i] = static_cast<u8>(0xa0 + i);
    const auto expected = grpc_web_test_base64(message);
    const std::vector<u8> empty;
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(
        get_port(listener), true, false, empty, response, false, &expected));
    CHECK(std::search(response.begin(), response.end(), expected.begin(), expected.end()) !=
          response.end());

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
    CHECK_EQ(server->requests.load(), 1u);
}

void grpc_web_h1_trailers_only_case(rut::test::TestCase* _tc) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    server->reply_mode = 1;
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    const std::vector<u8> rpc_body{0, 0, 0, 0, 1, 0};
    const auto request_body = grpc_web_test_base64(rpc_body);
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(get_port(listener), true, false, request_body, response));
    std::vector<u8> decoded;
    CHECK(grpc_web_test_decode_text_response(response, decoded));
    CHECK_GE(decoded.size(), 5u);
    if (decoded.size() >= 5) {
        CHECK_EQ(decoded[0], 0x80u);
        const u32 payload_len = (static_cast<u32>(decoded[1]) << 24) |
                                (static_cast<u32>(decoded[2]) << 16) |
                                (static_cast<u32>(decoded[3]) << 8) | decoded[4];
        CHECK_EQ(payload_len, decoded.size() - 5);
        CHECK(std::search(
                  decoded.begin() + 5, decoded.end(), "grpc-status: 7", "grpc-status: 7" + 14) !=
              decoded.end());
    }
    CHECK_EQ(server->requests.load(), 1u);

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

template <typename Loop>
void grpc_web_h1_retry_case(rut::test::TestCase* _tc, bool text) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    server->reply_mode = 1;
    auto shard = std::make_unique<Shard<Loop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    config.upstreams[0].grpc_retry = {2, 1024, 1u << 7, 0};
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    const std::vector<u8> native_request{0, 0, 0, 0, 1, 0};
    const auto request_body = text ? grpc_web_test_base64(native_request) : native_request;
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(get_port(listener), text, false, request_body, response));
    std::vector<u8> decoded;
    if (text) {
        CHECK(grpc_web_test_decode_text_response(response, decoded));
    } else {
        static constexpr char kBoundary[] = "\r\n\r\n";
        const auto boundary = std::search(
            response.begin(), response.end(), kBoundary, kBoundary + sizeof(kBoundary) - 1);
        CHECK(boundary != response.end());
        if (boundary != response.end())
            decoded.assign(boundary + sizeof(kBoundary) - 1, response.end());
    }
    u8 expected_trailers[128];
    u32 expected_trailers_len = 0;
    GrpcWebTrailer trailers[] = {{{"grpc-status", 11}, {"0", 1}},
                                 {{"x-trailer", 9}, {"present", 7}}};
    REQUIRE(grpc_web_encode_trailer_envelope(
        trailers, 2, expected_trailers, sizeof(expected_trailers), expected_trailers_len));
    CHECK_EQ(server->requests.load(), 2u);
    CHECK_EQ(decoded.size(), native_request.size() + expected_trailers_len);
    if (decoded.size() == native_request.size() + expected_trailers_len) {
        CHECK(memcmp(decoded.data(), native_request.data(), native_request.size()) == 0);
        CHECK(memcmp(decoded.data() + native_request.size(),
                     expected_trailers,
                     expected_trailers_len) == 0);
    }

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

void grpc_web_h1_decoded_request_limit_case(rut::test::TestCase* _tc) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    config.upstreams[0].max_request_message_bytes = 1;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    const std::vector<u8> native_request{0, 0, 0, 0, 2, 0xaa, 0xbb};
    const auto request_body = grpc_web_test_base64(native_request);
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(get_port(listener), true, false, request_body, response));
    std::vector<u8> decoded;
    CHECK(grpc_web_test_decode_text_response(response, decoded));
    CHECK_GE(decoded.size(), 5u);
    if (decoded.size() >= 5) {
        CHECK_EQ(decoded[0], 0x80u);
        CHECK_EQ(decoded[4], 16u);
        CHECK(std::search(
                  decoded.begin() + 5, decoded.end(), "grpc-status: 8", "grpc-status: 8" + 14) !=
              decoded.end());
    }
    CHECK_EQ(server->requests.load(), 0u);

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

void grpc_web_h1_deadline_case(rut::test::TestCase* _tc) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    server->reply_mode = 6;
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    const std::vector<u8> native_request{0, 0, 0, 0, 1, 0};
    const auto request_body = grpc_web_test_base64(native_request);
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(get_port(listener),
                                    true,
                                    false,
                                    request_body,
                                    response,
                                    false,
                                    nullptr,
                                    "grpc-timeout: 1n\r\n"));
    std::vector<u8> decoded;
    CHECK(grpc_web_test_decode_text_response(response, decoded));
    CHECK_GE(decoded.size(), 5u);
    if (decoded.size() >= 5) {
        CHECK_EQ(decoded[0], 0x80u);
        CHECK(std::search(
                  decoded.begin() + 5, decoded.end(), "grpc-status: 4", "grpc-status: 4" + 14) !=
              decoded.end());
    }

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

void grpc_web_h1_decoded_response_limit_case(rut::test::TestCase* _tc) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    config.upstreams[0].max_response_message_bytes = 1;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    const std::vector<u8> native_request{0, 0, 0, 0, 2, 0xaa, 0xbb};
    const auto request_body = grpc_web_test_base64(native_request);
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(get_port(listener), true, false, request_body, response));
    std::vector<u8> decoded;
    CHECK(grpc_web_test_decode_text_response(response, decoded));
    CHECK_GE(decoded.size(), 5u);
    if (decoded.size() >= 5) {
        CHECK_EQ(decoded[0], 0x80u);
        CHECK_EQ(decoded[4], 16u);
        CHECK(std::search(
                  decoded.begin() + 5, decoded.end(), "grpc-status: 8", "grpc-status: 8" + 14) !=
              decoded.end());
    }
    CHECK_EQ(server->requests.load(), 1u);

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

void grpc_web_h1_json_response_rejected_case(rut::test::TestCase* _tc, u32 response_mode) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    server->reply_mode = response_mode;
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    const std::vector<u8> native_request{0, 0, 0, 0, 1, 0};
    const auto request_body = grpc_web_test_base64(native_request);
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(get_port(listener), true, false, request_body, response));
    std::vector<u8> decoded;
    CHECK(grpc_web_test_decode_text_response(response, decoded));
    CHECK_GE(decoded.size(), 5u);
    if (decoded.size() >= 5) {
        CHECK_EQ(decoded[0], 0x80u);
        CHECK(std::search(
                  decoded.begin() + 5, decoded.end(), "grpc-status: 13", "grpc-status: 13" + 15) !=
              decoded.end());
    }
    CHECK_EQ(server->requests.load(), 1u);

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

void grpc_web_h1_abort_case(rut::test::TestCase* _tc) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    server->reply_mode = 6;
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    REQUIRE(shard->init_access_log());
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    CHECK(grpc_web_test_h1_abort_partial_upload(*server, get_port(listener)));
    const u64 deadline = monotonic_us() + 3000000;
    while (!server->resets.load() && monotonic_us() < deadline) usleep(1000);
    CHECK_GT(server->resets.load(), 0u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    AccessLogEntry entry{};
    CHECK(shard->log_ring->pop(entry));
    CHECK_EQ(entry.grpc_status_plus_one, 2u);
    CHECK(!shard->log_ring->pop(entry));

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}

template <typename Loop>
void grpc_web_h1_roundtrip_case(rut::test::TestCase* _tc,
                                bool text,
                                bool chunked,
                                u32 payload_len,
                                i32 response_text_override = -1) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    auto shard = std::make_unique<Shard<Loop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    std::vector<u8> rpc_body(5 + payload_len);
    rpc_body[0] = 0;
    rpc_body[1] = static_cast<u8>(payload_len >> 24);
    rpc_body[2] = static_cast<u8>(payload_len >> 16);
    rpc_body[3] = static_cast<u8>(payload_len >> 8);
    rpc_body[4] = static_cast<u8>(payload_len);
    for (u32 i = 0; i < payload_len; i++) rpc_body[5 + i] = static_cast<u8>((i * 17u) & 0xff);
    std::vector<u8> request_body = text ? grpc_web_test_base64(rpc_body) : rpc_body;
    std::vector<u8> response;
    const bool response_text = response_text_override < 0 ? text : response_text_override != 0;
    const char* accept = response_text_override < 0
                             ? ""
                             : (response_text ? "Accept: application/grpc-web-text\r\n"
                                              : "Accept: application/grpc-web\r\n");
    const bool exchanged = grpc_web_test_h1_exchange(
        get_port(listener), text, chunked, request_body, response, false, nullptr, accept);
    if (!exchanged) {
        std::fprintf(stderr,
                     "H1 failed: text=%u chunked=%u len=%zu backend=%u response=%zu\n",
                     (u32)text,
                     (u32)chunked,
                     request_body.size(),
                     server->requests.load(),
                     response.size());
        if (!response.empty()) {
            std::fprintf(stderr,
                         "response prefix: %.*s\n",
                         static_cast<int>(std::min<size_t>(response.size(), 250)),
                         response.data());
            for (u8 b : response) std::fprintf(stderr, "%02x ", b);
            std::fprintf(stderr, "\n");
        }
    }
    CHECK(exchanged);
    if (exchanged) {
        static constexpr char kBoundary[] = "\r\n\r\n";
        const auto boundary = std::search(
            response.begin(), response.end(), kBoundary, kBoundary + sizeof(kBoundary) - 1);
        CHECK(boundary != response.end());
        if (boundary != response.end()) {
            const size_t body_offset = static_cast<size_t>(boundary - response.begin()) + 4;
            CHECK(response.size() >= body_offset);
            CHECK(std::search(response.begin(), boundary, "HTTP/1.1 200", "HTTP/1.1 200" + 12) !=
                  boundary);
            const auto headers_end = boundary;
            const std::string headers(response.begin(), headers_end);
            CHECK(headers.find(response_text ? "application/grpc-web-text"
                                             : "application/grpc-web") != std::string::npos);
            std::vector<u8> decoded;
            if (response_text) {
                decoded.resize(response.size() - body_offset);
                GrpcWebBase64Decoder decoder;
                decoder.init();
                u32 consumed = 0, written = 0;
                const auto status = decoder.feed(response.data() + body_offset,
                                                 static_cast<u32>(response.size() - body_offset),
                                                 consumed,
                                                 decoded.data(),
                                                 static_cast<u32>(decoded.size()),
                                                 written);
                CHECK_EQ(static_cast<u32>(status), static_cast<u32>(GrpcWebCodecStatus::Ok));
                CHECK_EQ(consumed, static_cast<u32>(response.size() - body_offset));
                CHECK_EQ(static_cast<u32>(decoder.finish()),
                         static_cast<u32>(GrpcWebCodecStatus::Ok));
                decoded.resize(written);
            } else {
                decoded.assign(response.begin() + body_offset, response.end());
            }
            CHECK(decoded.size() >= rpc_body.size() + 5);
            if (decoded.size() >= rpc_body.size() + 5) {
                CHECK(std::equal(rpc_body.begin(), rpc_body.end(), decoded.begin()));
                const size_t trailer_offset = rpc_body.size();
                CHECK_EQ(decoded[trailer_offset], 0x80u);
                const u32 trailer_len = (static_cast<u32>(decoded[trailer_offset + 1]) << 24) |
                                        (static_cast<u32>(decoded[trailer_offset + 2]) << 16) |
                                        (static_cast<u32>(decoded[trailer_offset + 3]) << 8) |
                                        static_cast<u32>(decoded[trailer_offset + 4]);
                CHECK_EQ(trailer_offset + 5 + trailer_len, decoded.size());
                const std::string trailers(decoded.begin() + trailer_offset + 5, decoded.end());
                CHECK(trailers.find("grpc-status: 0\r\n") != std::string::npos);
                CHECK(trailers.find("x-trailer: present\r\n") != std::string::npos);
            }
        }
    }

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
    CHECK_EQ(server->requests.load(), 1u);
}

template <typename Loop>
void grpc_web_h1_tls_roundtrip_case(rut::test::TestCase* _tc, bool text) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    auto shard = std::make_unique<Shard<Loop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    auto tls_result = create_tls_server_context(
        RUT_GRPC_FIXTURES "/localhost_cert.pem", RUT_GRPC_FIXTURES "/localhost_key.pem", false);
    REQUIRE(tls_result);
    TlsServerContext* tls_server = tls_result.value();
    shard->loop->tls_server = tls_server;
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    const std::vector<u8> rpc_body{0, 0, 0, 0, 1, 0x7f};
    const std::vector<u8> request_body = text ? grpc_web_test_base64(rpc_body) : rpc_body;
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(get_port(listener), text, false, request_body, response, true));
    CHECK(std::search(response.begin(), response.end(), "HTTP/1.1 200", "HTTP/1.1 200" + 12) !=
          response.end());
    CHECK(std::search(response.begin(), response.end(), "grpc-web", "grpc-web" + 8) !=
          response.end());

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
    destroy_tls_server_context(tls_server);
    CHECK_EQ(server->requests.load(), 1u);
}

}  // namespace

TEST(grpc_proxy, h1_content_type_override_fails_closed) {
    Connection conn;
    u8 storage[256]{};
    grpc_web_test_init_request(conn, storage, sizeof(storage));
    conn.req_header_override_count = 1;
    conn.req_header_overrides[0] = {{"cOnTeNt-TyPe", 12}, {"application/grpc", 16}};
    CHECK_EQ(static_cast<u32>(grpc_web_h1_start<EpollEventLoop>(nullptr, conn, nullptr, 0, true)),
             static_cast<u32>(GrpcWebH1Start::Rejected));
}

TEST(grpc_proxy, h1_accept_override_selects_final_response_mode) {
    EpollEventLoop loop;
    REQUIRE(loop.init(0, -1).has_value());
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, 1));
    config.upstreams[0].http2 = true;
    Connection* conn = loop.alloc_conn();
    REQUIRE(conn != nullptr);
    u8 storage[512]{};
    static constexpr char request[] =
        "POST /test.Echo/Call HTTP/1.1\r\nHost: localhost\r\n"
        "Content-Type: application/grpc-web\r\nAccept: application/grpc-web\r\n"
        "Content-Length: 0\r\n\r\n";
    grpc_web_test_init_raw_request(*conn, storage, sizeof(storage), request, sizeof(request) - 1);
    conn->req_header_override_count = 1;
    conn->req_header_overrides[0] = {lit_str("Accept"), lit_str("application/grpc-web-text")};

    CHECK_EQ(static_cast<u32>(grpc_web_h1_start<EpollEventLoop>(&loop, *conn, &config, 0, true)),
             static_cast<u32>(GrpcWebH1Start::Started));
    REQUIRE(conn->h2 != nullptr);
    GrpcExchange* exchange = grpc_find(*conn->h2, 1);
    REQUIRE(exchange != nullptr);
    CHECK_EQ(exchange->web_mode, GrpcWebContentType::Binary);
    CHECK_EQ(exchange->web_response_mode, GrpcWebContentType::Text);
    loop.force_close_all();
    loop.shutdown();
}

TEST(grpc_proxy, h1_duplicate_web_family_content_types_fail_closed_in_both_orders) {
    const char* requests[] = {
        "POST /test.Echo/Call HTTP/1.1\r\nHost: localhost\r\n"
        "Content-Type: application/grpc-web\r\nContent-Type: application/grpc\r\n"
        "Content-Length: 0\r\n\r\n",
        "POST /test.Echo/Call HTTP/1.1\r\nHost: localhost\r\n"
        "Content-Type: application/grpc\r\nContent-Type: application/grpc-web\r\n"
        "Content-Length: 0\r\n\r\n",
        "POST /test.Echo/Call HTTP/1.1\r\nHost: localhost\r\n"
        "Content-Type: application/grpc-web+json\r\n"
        "Content-Type: application/grpc-web-text\r\nContent-Length: 0\r\n\r\n",
        "POST /test.Echo/Call HTTP/1.1\r\nHost: localhost\r\n"
        "Content-Type: application/grpc-web-text\r\n"
        "Content-Type: application/grpc-web+json\r\nContent-Length: 0\r\n\r\n",
    };
    for (const char* request : requests) {
        Connection conn;
        u8 storage[512]{};
        grpc_web_test_init_raw_request(
            conn, storage, sizeof(storage), request, static_cast<u32>(strlen(request)));
        CHECK_EQ(
            static_cast<u32>(grpc_web_h1_start<EpollEventLoop>(nullptr, conn, nullptr, 0, true)),
            static_cast<u32>(GrpcWebH1Start::Rejected));
    }
}

TEST(grpc_proxy, h1_throttled_grpc_web_route_rejects_before_rpc_admission) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    REQUIRE(shard->init_access_log());
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    config.routes[0].throttle_down_bps = 1;
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(get_port(listener), false, false, {}, response));
    CHECK(std::search(response.begin(), response.end(), "HTTP/1.1 503", "HTTP/1.1 503" + 12) !=
          response.end());
    CHECK_EQ(shard->shard_metrics.grpc_started, 0u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    CHECK_EQ(server->requests.load(), 0u);

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
    CHECK_EQ(shard->shard_metrics.grpc_started, 0u);
    CHECK_EQ(server->requests.load(), 0u);
}

TEST(grpc_proxy, h1_expect_continue_body_is_rejected_before_rpc) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    REQUIRE(shard->init_access_log());
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    const int fd = connect_test_loopback(get_port(listener));
    REQUIRE(fd >= 0);
    set_socket_timeouts(fd, 5);
    static constexpr char kHeaders[] =
        "POST /test.Echo/Call HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/grpc-web\r\n"
        "Content-Length: 5\r\n"
        "Expect: 100-continue\r\n"
        "Connection: close\r\n\r\n";
    REQUIRE(write_all_fd(fd, reinterpret_cast<const u8*>(kHeaders), sizeof(kHeaders) - 1));
    u8 response[1024]{};
    const ssize_t received = recv(fd, response, sizeof(response), 0);
    CHECK_GT(received, 0);
    if (received > 0) {
        CHECK(std::search(response, response + received, "HTTP/1.1 503", "HTTP/1.1 503" + 12) !=
              response + received);
        CHECK(std::search(response, response + received, "100 Continue", "100 Continue" + 12) ==
              response + received);
    }
    shutdown(fd, SHUT_RDWR);
    close(fd);

    CHECK_EQ(shard->shard_metrics.grpc_started, 0u);
    CHECK_EQ(server->requests.load(), 0u);
    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
    CHECK_EQ(shard->shard_metrics.grpc_started, 0u);
    CHECK_EQ(server->requests.load(), 0u);
}

TEST(grpc_proxy, h1_http1_policy_fails_closed) {
    Connection conn;
    u8 storage[256]{};
    grpc_web_test_init_request(conn, storage, sizeof(storage));
    CHECK_EQ(static_cast<u32>(grpc_web_h1_start<EpollEventLoop>(nullptr, conn, nullptr, 0, false)),
             static_cast<u32>(GrpcWebH1Start::Rejected));
}

TEST(grpc_proxy, h1_transfer_encoding_chain_fails_closed) {
    Connection conn;
    u8 storage[256]{};
    static constexpr char kRequest[] =
        "POST /test.Echo/Call HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/grpc-web\r\n"
        "Transfer-Encoding: chunked, gzip\r\n\r\n"
        "0\r\n\r\n";
    grpc_web_test_init_raw_request(conn, storage, sizeof(storage), kRequest, sizeof(kRequest) - 1);
    CHECK_EQ(static_cast<u32>(grpc_web_h1_start<EpollEventLoop>(nullptr, conn, nullptr, 0, true)),
             static_cast<u32>(GrpcWebH1Start::Rejected));
}

void grpc_web_h1_local_failure_case(rut::test::TestCase* _tc, bool invalid_base64) {
    auto server = std::make_unique<EchoServer>();
    REQUIRE(server->start());
    auto shard = std::make_unique<Shard<EpollEventLoop>>();
    const int listener = create_listen_socket(0).value_or(-1);
    REQUIRE(listener >= 0);
    if (!shard->init(0, listener)) {
        close(listener);
        SKIP("backend unavailable");
    }
    REQUIRE(shard->init_access_log());
    RouteConfig config;
    REQUIRE(config.add_upstream("grpc", 0x7f000001, get_port(server->listen_fd)));
    config.upstreams[0].http2 = true;
    REQUIRE(config.add_proxy("/test.Echo/", 'P', 0));
    shard->route_config = &config;
    REQUIRE(shard->spawn(-1));

    const std::vector<u8> invalid = invalid_base64
                                        ? std::vector<u8>{'A', 'B', '=', 'C'}
                                        : grpc_web_test_base64(std::vector<u8>{2, 0, 0, 0, 0});
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(get_port(listener), true, false, invalid, response));
    std::vector<u8> decoded;
    CHECK(grpc_web_test_decode_text_response(response, decoded));
    CHECK_GE(decoded.size(), 5u);
    if (decoded.size() >= 5) {
        CHECK_EQ(decoded[0], 0x80u);
        CHECK_EQ(decoded[4], 17u);
        CHECK(std::search(
                  decoded.begin() + 5, decoded.end(), "grpc-status: 13", "grpc-status: 13" + 15) !=
              decoded.end());
    }
    CHECK_EQ(server->requests.load(), 0u);
    CHECK_EQ(shard->shard_metrics.grpc_started, 1u);
    CHECK_EQ(shard->shard_metrics.grpc_active, 0u);
    CHECK_EQ(shard->shard_metrics.grpc_completed[13], 1u);
    AccessLogEntry entry{};
    u32 log_count = 0;
    while (shard->log_ring->pop(entry)) {
        log_count++;
        CHECK_EQ(entry.grpc_status_plus_one, 14u);
        CHECK_EQ(entry.status, 200u);
    }
    CHECK_EQ(log_count, 1u);

    shard->stop();
    shard->join();
    shard->loop->force_close_all();
    if (shard->loop->listen_fd >= 0) {
        close(shard->loop->listen_fd);
        shard->loop->listen_fd = -1;
    }
    shard->shutdown();
}
TEST(grpc_proxy, h1_invalid_text_base64_returns_grpc_status) {
    grpc_web_h1_local_failure_case(_tc, true);
}
TEST(grpc_proxy, h1_invalid_native_request_framing_returns_status) {
    grpc_web_h1_local_failure_case(_tc, false);
}
TEST(grpc_proxy, h1_trailers_only_backend_response) {
    grpc_web_h1_trailers_only_case(_tc);
}
TEST(grpc_proxy, h1_decoded_request_message_limit) {
    grpc_web_h1_decoded_request_limit_case(_tc);
}
TEST(grpc_proxy, h1_deadline_returns_status) {
    grpc_web_h1_deadline_case(_tc);
}
TEST(grpc_proxy, h1_decoded_response_message_limit) {
    grpc_web_h1_decoded_response_limit_case(_tc);
}
TEST(grpc_proxy, h1_json_response_rejected) {
    grpc_web_h1_json_response_rejected_case(_tc, 7);
}
TEST(grpc_proxy, h1_duplicate_json_proto_response_rejected) {
    grpc_web_h1_json_response_rejected_case(_tc, 8);
}
TEST(grpc_proxy, h1_duplicate_proto_json_response_rejected) {
    grpc_web_h1_json_response_rejected_case(_tc, 9);
}
TEST(grpc_proxy, h1_client_abort_cancels_upstream_once) {
    grpc_web_h1_abort_case(_tc);
}

TEST(grpc_proxy, h1_path_and_safe_header_overrides_remain_supported) {
    Connection conn;
    u8 storage[256]{};
    grpc_web_test_init_request(conn, storage, sizeof(storage));
    static constexpr char kPath[] = "/rewritten";
    conn.req_path_overridden = true;
    conn.req_path_override = {kPath, sizeof(kPath) - 1};
    conn.req_header_override_count = 1;
    conn.req_header_overrides[0] = {{"X-Trace", 7}, {"kept", 4}};
    REQUIRE(h2_apply_forward_request_overrides(conn));
    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    req.reset();
    REQUIRE(parser.parse(conn.recv_buf.data(), conn.recv_buf.len(), &req) == ParseStatus::Complete);
    CHECK(req.path.eq({kPath, sizeof(kPath) - 1}));
    bool found = false;
    for (u32 i = 0; i < req.header_count; i++)
        if (http_header_name_eq_ci(
                req.headers[i].name.ptr, req.headers[i].name.len, "x-trace", 7) &&
            req.headers[i].value.eq({"kept", 4}))
            found = true;
    CHECK(found);
}

TEST(grpc_proxy, h1_tls_response_framing_single_header) {
    static constexpr u8 response[] =
        "HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web\r\n"
        "Content-Length: 6\r\n\r\nabcdef";
    const auto framing = grpc_web_test_response_framing(response, sizeof(response) - 1);
    CHECK(framing.headers_complete);
    CHECK(framing.valid);
    CHECK(framing.web);
    CHECK(framing.has_content_length);
    CHECK_EQ(framing.content_length, 6u);
    CHECK_EQ(sizeof(response) - 1 - framing.body_offset, 6u);
}
TEST(grpc_proxy, h1_tls_response_framing_multiple_headers) {
    static constexpr u8 response[] =
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: "
        "application/grpc-web-text\r\nContent-Length: 4\r\n\r\nAAAA";
    const auto framing = grpc_web_test_response_framing(response, sizeof(response) - 1);
    CHECK(framing.headers_complete);
    CHECK(framing.valid);
    CHECK(framing.web);
    CHECK(framing.text);
    CHECK(framing.has_content_length);
    CHECK_EQ(framing.content_length, 4u);
}
TEST(grpc_proxy, h1_tls_response_framing_partial_headers) {
    static constexpr u8 response[] = "HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web\r\n";
    const auto framing = grpc_web_test_response_framing(response, sizeof(response) - 1);
    CHECK(!framing.headers_complete);
    CHECK(framing.valid);
}
TEST(grpc_proxy, h1_binary_coalesced_content_length_epoll) {
    grpc_web_h1_roundtrip_case<EpollEventLoop>(_tc, false, false, 1);
}
TEST(grpc_proxy, h1_text_chunked_large_response_epoll) {
    grpc_web_h1_roundtrip_case<EpollEventLoop>(_tc, true, true, 130000);
}
TEST(grpc_proxy, h1_text_coalesced_content_length_epoll) {
    grpc_web_h1_roundtrip_case<EpollEventLoop>(_tc, true, false, 17);
}
TEST(grpc_proxy, h1_binary_chunked_large_epoll) {
    grpc_web_h1_roundtrip_case<EpollEventLoop>(_tc, false, true, 130000);
}
TEST(grpc_proxy, h1_binary_request_text_accept_response) {
    grpc_web_h1_roundtrip_case<EpollEventLoop>(_tc, false, false, 17, 1);
}
TEST(grpc_proxy, h1_text_request_binary_accept_response) {
    grpc_web_h1_roundtrip_case<EpollEventLoop>(_tc, true, false, 17, 0);
}
TEST(grpc_proxy, h1_binary_coalesced_content_length_iouring) {
    grpc_web_h1_roundtrip_case<IoUringEventLoop>(_tc, false, false, 1);
}
TEST(grpc_proxy, h1_text_chunked_large_iouring) {
    grpc_web_h1_roundtrip_case<IoUringEventLoop>(_tc, true, true, 130000);
}
TEST(grpc_proxy, h1_binary_tls_epoll) {
    grpc_web_h1_tls_roundtrip_case<EpollEventLoop>(_tc, false);
}
TEST(grpc_proxy, h1_binary_tls_handshake_retries_eintr) {
    GrpcWebTlsGateServer server;
    server.pause_handshake = true;
    REQUIRE(server.start());

    struct ClientCall {
        u16 port;
        std::atomic<u32> retries{0};
        bool ok = false;
        bool rpc_ok = false;
    } client{server.port};
    auto run_client = +[](void* ptr) -> void* {
        auto* call = static_cast<ClientCall*>(ptr);
        const std::vector<u8> body{0, 0, 0, 0, 1, 0};
        std::vector<u8> response;
        call->ok = grpc_web_test_h1_exchange(
            call->port, false, false, body, response, true, nullptr, "", &call->retries);
        const std::string wire(response.begin(), response.end());
        call->rpc_ok = call->ok && wire.find("HTTP/1.1 200 OK") != std::string::npos &&
                       wire.find("grpc-status: 0\r\n") != std::string::npos;
        return nullptr;
    };
    struct sigaction action{}, old_action{};
    action.sa_handler = grpc_test_signal_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    grpc_test_signal_count = 0;
    REQUIRE(sigaction(SIGUSR1, &action, &old_action) == 0);
    pthread_t client_thread{};
    const int thread_result = pthread_create(&client_thread, nullptr, run_client, &client);
    if (thread_result != 0) {
        sigaction(SIGUSR1, &old_action, nullptr);
        CHECK_EQ(thread_result, 0);
    } else {
        const u64 waiting_deadline = monotonic_us() + 3000000;
        while (!server.client_hello_waiting.load(std::memory_order_acquire) &&
               monotonic_us() < waiting_deadline)
            sched_yield();
        const bool hello_arrived = server.client_hello_waiting.load(std::memory_order_acquire);
        CHECK(hello_arrived);
        const u64 signal_deadline = monotonic_us() + 2000000;
        while (hello_arrived && !client.retries.load(std::memory_order_relaxed) &&
               monotonic_us() < signal_deadline) {
            pthread_kill(client_thread, SIGUSR1);
            sched_yield();
        }
        CHECK_GT(client.retries.load(std::memory_order_relaxed), 0u);
        const u8 release = 1;
        CHECK_EQ(write(server.gate[1], &release, 1), 1);
        pthread_join(client_thread, nullptr);
        CHECK_GT(grpc_test_signal_count, 0);
        CHECK(client.ok);
        CHECK(client.rpc_ok);
    }
    sigaction(SIGUSR1, &old_action, nullptr);
    CHECK(server.served.load(std::memory_order_acquire));
}
TEST(grpc_proxy, test_loopback_connect_retries_eintr) {
    const int listener = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(listener >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    REQUIRE(bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    REQUIRE(listen(listener, 1) == 0);
    loopback_connect_retry_probe = {};
    const int fd = connect_test_loopback(get_port(listener), 5000, &connect_eintr_then_real);
    CHECK(fd >= 0);
    CHECK_EQ(loopback_connect_retry_probe.calls, 2);
    if (fd >= 0) {
        const int accepted = accept(listener, nullptr, nullptr);
        CHECK(accepted >= 0);
        if (accepted >= 0) close(accepted);
        close(fd);
    }
    close(listener);
}
TEST(grpc_proxy, h1_binary_tls_truncated_content_length_fails) {
    GrpcWebTlsGateServer server;
    server.truncate_response = true;
    REQUIRE(server.start());
    const std::vector<u8> body{0, 0, 0, 0, 1, 0};
    std::vector<u8> response;
    CHECK(!grpc_web_test_h1_exchange(server.port, false, false, body, response, true));
    CHECK(server.served.load(std::memory_order_acquire));
}
TEST(grpc_proxy, h1_binary_tls_complete_content_length_unclean_close_succeeds) {
    GrpcWebTlsGateServer server;
    server.unclean_close_response = true;
    REQUIRE(server.start());
    const std::vector<u8> body{0, 0, 0, 0, 1, 0};
    std::vector<u8> response;
    CHECK(grpc_web_test_h1_exchange(server.port, false, false, body, response, true));
    CHECK(server.served.load(std::memory_order_acquire));
}
TEST(grpc_proxy, h1_binary_tls_clean_close_missing_terminal_trailer_fails) {
    GrpcWebTlsGateServer server;
    server.truncate_response = true;
    server.clean_close_truncated_response = true;
    REQUIRE(server.start());
    const std::vector<u8> body{0, 0, 0, 0, 1, 0};
    std::vector<u8> response;
    CHECK(!grpc_web_test_h1_exchange(server.port, false, false, body, response, true));
    CHECK(server.served.load(std::memory_order_acquire));
}
TEST(grpc_proxy, h1_text_tls_epoll) {
    grpc_web_h1_tls_roundtrip_case<EpollEventLoop>(_tc, true);
}
TEST(grpc_proxy, h1_binary_retry_epoll) {
    grpc_web_h1_retry_case<EpollEventLoop>(_tc, false);
}
TEST(grpc_proxy, h1_text_retry_epoll) {
    grpc_web_h1_retry_case<EpollEventLoop>(_tc, true);
}
TEST(grpc_proxy, h1_text_streaming_message_mod3_zero) {
    grpc_web_h1_streaming_text_message_case<EpollEventLoop>(_tc, 6, false);
}
TEST(grpc_proxy, h1_text_streaming_message_mod3_one) {
    grpc_web_h1_streaming_text_message_case<EpollEventLoop>(_tc, 7, false);
}
TEST(grpc_proxy, h1_text_streaming_message_mod3_two) {
    grpc_web_h1_streaming_text_message_case<EpollEventLoop>(_tc, 8, false);
}
TEST(grpc_proxy, h1_text_streaming_message_then_partial_next_same_data) {
    grpc_web_h1_streaming_text_message_case<EpollEventLoop>(_tc, 7, true);
}
