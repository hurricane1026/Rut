#include "rut/runtime/http_parser.h"
#include "rut/runtime/simd/simd.h"
#include "test.h"
#include <string>

#include <string.h>

using namespace rut;

// ============================================================================
// Helpers
// ============================================================================

static ParseStatus parse_one(const char* raw, ParsedRequest* req, HttpParser* parser) {
    parser->reset();
    auto len = static_cast<u32>(__builtin_strlen(raw));
    return parser->parse(reinterpret_cast<const u8*>(raw), len, req);
}

// Parse from raw bytes (for embedded NUL / escape sequences).
static ParseStatus parse_raw(const u8* raw, u32 len, ParsedRequest* req, HttpParser* parser) {
    parser->reset();
    return parser->parse(raw, len, req);
}

// Feed data byte-by-byte, calling parse() after each byte.
// Returns final status.
static ParseStatus parse_incremental(const u8* raw,
                                     u32 len,
                                     ParsedRequest* req,
                                     HttpParser* parser) {
    parser->reset();
    for (u32 i = 1; i <= len; i++) {
        ParseStatus s = parser->parse(raw, i, req);
        if (s != ParseStatus::Incomplete) return s;
    }
    return ParseStatus::Incomplete;
}

// Check if a header with given name exists and return its value.
static bool find_header(const ParsedRequest& req, const char* name, Str* out_value) {
    u32 name_len = 0;
    while (name[name_len]) name_len++;
    for (u32 i = 0; i < req.header_count; i++) {
        if (req.headers[i].name.len == name_len) {
            bool match = true;
            for (u32 j = 0; j < name_len; j++) {
                if (req.headers[i].name.ptr[j] != name[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                *out_value = req.headers[i].value;
                return true;
            }
        }
    }
    return false;
}

TEST(Util, ScanUriNoSpaceReturnsEnd) {
    const u8 uri[] = "/hello/world?mode=fast";
    u32 canon_end = 0xffffffffu;
    CHECK_EQ(simd::scan_uri(uri,
                            0,
                            static_cast<u32>(__builtin_strlen(reinterpret_cast<const char*>(uri))),
                            &canon_end),
             static_cast<u32>(__builtin_strlen(reinterpret_cast<const char*>(uri))));
    CHECK_EQ(canon_end, 12u);
}

TEST(Util, ScanUriNoSpaceWithoutQueryReturnsEnd) {
    const u8 uri[] = "/hello/world";
    u32 canon_end = 0xffffffffu;
    const u32 len = static_cast<u32>(__builtin_strlen(reinterpret_cast<const char*>(uri)));
    CHECK_EQ(simd::scan_uri(uri, 0, len, &canon_end), len);
    CHECK_EQ(canon_end, len);
}

// ============================================================================
// Test vector structures for data-driven tests
// ============================================================================

struct ValidRequestVec {
    const char* name;
    const char* raw;
    HttpMethod method;
    const char* path;
    HttpVersion version;
    u32 header_count;
    u32 content_length;
    bool keep_alive;
    bool chunked;
};

struct InvalidRequestVec {
    const char* name;
    const u8* raw;
    u32 len;
};

// Convenience macro for invalid test vectors with string literals
#define INVALID_STR(name_str, raw_str) \
    {name_str, reinterpret_cast<const u8*>(raw_str), static_cast<u32>(sizeof(raw_str) - 1)}

// ============================================================================
// Valid request corpus — ported from llhttp sample.md, method.md, uri.md,
// connection.md, content-length.md
// ============================================================================

static const ValidRequestVec kValidRequests[] = {
    // --- sample.md ---
    {"simple_options",
     "OPTIONS /url HTTP/1.1\r\nHeader1: Value1\r\nHeader2:\tValue2\r\n\r\n",
     HttpMethod::OPTIONS,
     "/url",
     HttpVersion::Http11,
     2,
     0,
     true,
     false},

    {"head_method",
     "HEAD /url HTTP/1.1\r\n\r\n",
     HttpMethod::HEAD,
     "/url",
     HttpVersion::Http11,
     0,
     0,
     true,
     false},

    {"curl_get",
     "GET /test HTTP/1.1\r\n"
     "User-Agent: curl/7.18.0 (i486-pc-linux-gnu) libcurl/7.18.0 OpenSSL/0.9.8g zlib/1.2.3.3 "
     "libidn/1.1\r\n"
     "Host: 0.0.0.0=5000\r\n"
     "Accept: */*\r\n"
     "\r\n",
     HttpMethod::GET,
     "/test",
     HttpVersion::Http11,
     3,
     0,
     true,
     false},

    {"firefox_get",
     "GET /favicon.ico HTTP/1.1\r\n"
     "Host: 0.0.0.0=5000\r\n"
     "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9) Gecko/2008061015 Firefox/3.0\r\n"
     "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
     "Accept-Language: en-us,en;q=0.5\r\n"
     "Accept-Encoding: gzip,deflate\r\n"
     "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
     "Keep-Alive: 300\r\n"
     "Connection: keep-alive\r\n"
     "\r\n",
     HttpMethod::GET,
     "/favicon.ico",
     HttpVersion::Http11,
     8,
     0,
     true,
     false},

    {"dumbpack",
     "GET /dumbpack HTTP/1.1\r\naaaaaaaaaaaaa:++++++++++\r\n\r\n",
     HttpMethod::GET,
     "/dumbpack",
     HttpVersion::Http11,
     1,
     0,
     true,
     false},

    {"no_headers_no_body",
     "GET /get_no_headers_no_body/world HTTP/1.1\r\n\r\n",
     HttpMethod::GET,
     "/get_no_headers_no_body/world",
     HttpVersion::Http11,
     0,
     0,
     true,
     false},

    {"one_header_no_body",
     "GET /get_one_header_no_body HTTP/1.1\r\nAccept: */*\r\n\r\n",
     HttpMethod::GET,
     "/get_one_header_no_body",
     HttpVersion::Http11,
     1,
     0,
     true,
     false},

    {"apache_bench_get",
     "GET /test HTTP/1.0\r\n"
     "Host: 0.0.0.0:5000\r\n"
     "User-Agent: ApacheBench/2.3\r\n"
     "Accept: */*\r\n"
     "\r\n",
     HttpMethod::GET,
     "/test",
     HttpVersion::Http10,
     3,
     0,
     false,
     false},

    // --- method.md ---
    {"connect_request",
     "CONNECT 0-home0.netscape.com:443 HTTP/1.0\r\n"
     "User-agent: Mozilla/1.1N\r\n"
     "Proxy-authorization: basic aGVsbG86d29ybGQ=\r\n"
     "\r\n",
     HttpMethod::CONNECT,
     "0-home0.netscape.com:443",
     HttpVersion::Http10,
     2,
     0,
     false,
     false},

    {"connect_caps",
     "CONNECT HOME0.NETSCAPE.COM:443 HTTP/1.0\r\n"
     "User-agent: Mozilla/1.1N\r\n"
     "Proxy-authorization: basic aGVsbG86d29ybGQ=\r\n"
     "\r\n",
     HttpMethod::CONNECT,
     "HOME0.NETSCAPE.COM:443",
     HttpVersion::Http10,
     2,
     0,
     false,
     false},

    {"connect_body",
     "CONNECT foo.bar.com:443 HTTP/1.0\r\n"
     "User-agent: Mozilla/1.1N\r\n"
     "Proxy-authorization: basic aGVsbG86d29ybGQ=\r\n"
     "Content-Length: 10\r\n"
     "\r\n",
     HttpMethod::CONNECT,
     "foo.bar.com:443",
     HttpVersion::Http10,
     3,
     10,
     false,
     false},

    {"patch_request",
     "PATCH /file.txt HTTP/1.1\r\n"
     "Host: www.example.com\r\n"
     "Content-Type: application/example\r\n"
     "If-Match: \"e0023aa4e\"\r\n"
     "Content-Length: 10\r\n"
     "\r\n",
     HttpMethod::PATCH,
     "/file.txt",
     HttpVersion::Http11,
     4,
     10,
     true,
     false},

    {"trace_request",
     "TRACE /path HTTP/1.1\r\n\r\n",
     HttpMethod::TRACE,
     "/path",
     HttpVersion::Http11,
     0,
     0,
     true,
     false},

    // --- uri.md ---
    {"uri_quotes",
     "GET /with_\"lovely\"_quotes?foo=\"bar\" HTTP/1.1\r\n\r\n",
     HttpMethod::GET,
     "/with_\"lovely\"_quotes?foo=\"bar\"",
     HttpVersion::Http11,
     0,
     0,
     true,
     false},

    {"uri_double_question_mark",
     "GET /test.cgi?foo=bar?baz HTTP/1.1\r\n\r\n",
     HttpMethod::GET,
     "/test.cgi?foo=bar?baz",
     HttpVersion::Http11,
     0,
     0,
     true,
     false},

    {"uri_host_query",
     "GET http://hypnotoad.org?hail=all HTTP/1.1\r\n\r\n",
     HttpMethod::GET,
     "http://hypnotoad.org?hail=all",
     HttpVersion::Http11,
     0,
     0,
     true,
     false},

    {"uri_host_port_query",
     "GET http://hypnotoad.org:1234?hail=all HTTP/1.1\r\n\r\n",
     HttpMethod::GET,
     "http://hypnotoad.org:1234?hail=all",
     HttpVersion::Http11,
     0,
     0,
     true,
     false},

    {"uri_pipe",
     "GET /test.cgi?query=| HTTP/1.1\r\n\r\n",
     HttpMethod::GET,
     "/test.cgi?query=|",
     HttpVersion::Http11,
     0,
     0,
     true,
     false},

    {"uri_host_port",
     "GET http://hypnotoad.org:1234 HTTP/1.1\r\n\r\n",
     HttpMethod::GET,
     "http://hypnotoad.org:1234",
     HttpVersion::Http11,
     0,
     0,
     true,
     false},

    {"uri_fragment",
     "GET /forums/1/topics/2375?page=1#posts-17408 HTTP/1.1\r\n\r\n",
     HttpMethod::GET,
     "/forums/1/topics/2375?page=1#posts-17408",
     HttpVersion::Http11,
     0,
     0,
     true,
     false},

    {"uri_underscore_host",
     "CONNECT home_0.netscape.com:443 HTTP/1.0\r\n"
     "User-agent: Mozilla/1.1N\r\n"
     "Proxy-authorization: basic aGVsbG86d29ybGQ=\r\n"
     "\r\n",
     HttpMethod::CONNECT,
     "home_0.netscape.com:443",
     HttpVersion::Http10,
     2,
     0,
     false,
     false},

    {"uri_basic_auth",
     "GET http://a%12:b!&*$@hypnotoad.org:1234/toto HTTP/1.1\r\n\r\n",
     HttpMethod::GET,
     "http://a%12:b!&*$@hypnotoad.org:1234/toto",
     HttpVersion::Http11,
     0,
     0,
     true,
     false},

    // --- connection.md ---
    {"conn_keep_alive",
     "PUT /url HTTP/1.1\r\nConnection: keep-alive\r\n\r\n",
     HttpMethod::PUT,
     "/url",
     HttpVersion::Http11,
     1,
     0,
     true,
     false},

    {"conn_close",
     "PUT /url HTTP/1.1\r\nConnection: close\r\n\r\n",
     HttpMethod::PUT,
     "/url",
     HttpVersion::Http11,
     1,
     0,
     false,
     false},

    {"conn_upgrade",
     "PUT /url HTTP/1.1\r\n"
     "Connection: upgrade\r\n"
     "Upgrade: ws\r\n"
     "\r\n",
     HttpMethod::PUT,
     "/url",
     HttpVersion::Http11,
     2,
     0,
     true,
     false},

    {"conn_upgrade_content",
     "PUT /url HTTP/1.1\r\n"
     "Connection: upgrade\r\n"
     "Content-Length: 4\r\n"
     "Upgrade: ws\r\n"
     "\r\n",
     HttpMethod::PUT,
     "/url",
     HttpVersion::Http11,
     3,
     4,
     true,
     false},

    {"websocket_upgrade",
     "GET /demo HTTP/1.1\r\n"
     "Host: example.com\r\n"
     "Connection: Upgrade\r\n"
     "Sec-WebSocket-Key2: 12998 5 Y3 1  .P00\r\n"
     "Sec-WebSocket-Protocol: sample\r\n"
     "Upgrade: WebSocket\r\n"
     "Sec-WebSocket-Key1: 4 @1  46546xW%0l 1 5\r\n"
     "Origin: http://example.com\r\n"
     "\r\n",
     HttpMethod::GET,
     "/demo",
     HttpVersion::Http11,
     7,
     0,
     true,
     false},

    {"upgrade_post",
     "POST /demo HTTP/1.1\r\n"
     "Host: example.com\r\n"
     "Connection: Upgrade\r\n"
     "Upgrade: HTTP/2.0\r\n"
     "Content-Length: 15\r\n"
     "\r\n",
     HttpMethod::POST,
     "/demo",
     HttpVersion::Http11,
     4,
     15,
     true,
     false},

    // --- content-length.md ---
    {"cl_with_zeroes",
     "PUT /url HTTP/1.1\r\nContent-Length: 003\r\n\r\n",
     HttpMethod::PUT,
     "/url",
     HttpVersion::Http11,
     1,
     3,
     true,
     false},

    {"cl_with_followup",
     "PUT /url HTTP/1.1\r\nContent-Length: 003\r\nOhai: world\r\n\r\n",
     HttpMethod::PUT,
     "/url",
     HttpVersion::Http11,
     2,
     3,
     true,
     false},

    {"cl_funky_case",
     "GET /get_funky_content_length_body_hello HTTP/1.0\r\nconTENT-Length: 5\r\n\r\n",
     HttpMethod::GET,
     "/get_funky_content_length_body_hello",
     HttpVersion::Http10,
     1,
     5,
     false,
     false},

    {"cl_spaces_surrounding",
     "POST / HTTP/1.1\r\nContent-Length:  42 \r\n\r\n",
     HttpMethod::POST,
     "/",
     HttpVersion::Http11,
     1,
     42,
     true,
     false},

    // --- transfer-encoding.md ---
    {"te_chunked",
     "POST /chunked HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
     HttpMethod::POST,
     "/chunked",
     HttpVersion::Http11,
     1,
     0,
     true,
     true},

    // --- Multi-value Connection header ---
    {"conn_multi_tokens",
     "PUT /url HTTP/1.1\r\nConnection: close, token, upgrade, token, keep-alive\r\n\r\n",
     HttpMethod::PUT,
     "/url",
     HttpVersion::Http11,
     1,
     0,
     false,  // close is sticky — overrides subsequent keep-alive
     false},

    // --- Realistic requests ---
    {"post_form",
     "POST /login HTTP/1.1\r\n"
     "Host: example.com\r\n"
     "Content-Type: application/x-www-form-urlencoded\r\n"
     "Content-Length: 27\r\n"
     "Connection: close\r\n"
     "\r\n",
     HttpMethod::POST,
     "/login",
     HttpVersion::Http11,
     4,
     27,
     false,
     false},

    {"post_json",
     "POST /api/data HTTP/1.1\r\n"
     "Host: api.example.com\r\n"
     "Content-Type: application/json\r\n"
     "Content-Length: 100\r\n"
     "\r\n",
     HttpMethod::POST,
     "/api/data",
     HttpVersion::Http11,
     3,
     100,
     true,
     false},

    {"delete_resource",
     "DELETE /api/users/42 HTTP/1.1\r\n"
     "Host: api.example.com\r\n"
     "Authorization: Bearer token123\r\n"
     "\r\n",
     HttpMethod::DELETE,
     "/api/users/42",
     HttpVersion::Http11,
     2,
     0,
     true,
     false},

    {"options_cors",
     "OPTIONS /api/data HTTP/1.1\r\n"
     "Host: api.example.com\r\n"
     "Origin: http://frontend.example.com\r\n"
     "Access-Control-Request-Method: POST\r\n"
     "Access-Control-Request-Headers: Content-Type\r\n"
     "\r\n",
     HttpMethod::OPTIONS,
     "/api/data",
     HttpVersion::Http11,
     4,
     0,
     true,
     false},

    {"get_many_headers",
     "GET /complex HTTP/1.1\r\n"
     "Host: example.com\r\n"
     "Accept: text/html\r\n"
     "Accept-Language: en-US,en;q=0.9\r\n"
     "Accept-Encoding: gzip, deflate, br\r\n"
     "Cache-Control: no-cache\r\n"
     "Pragma: no-cache\r\n"
     "Cookie: session=abc123; theme=dark\r\n"
     "Referer: http://example.com/page\r\n"
     "X-Forwarded-For: 192.168.1.1\r\n"
     "X-Request-ID: req-001\r\n"
     "\r\n",
     HttpMethod::GET,
     "/complex",
     HttpVersion::Http11,
     10,
     0,
     true,
     false},
};

static constexpr u32 kNumValidRequests = sizeof(kValidRequests) / sizeof(kValidRequests[0]);

// ============================================================================
// Invalid request corpus — ported from llhttp invalid.md, content-length.md
// ============================================================================

// Helper: build invalid vector from string literal (auto-strlen)
static const char* const kInvalidRequestStrs[] = {
    // invalid.md: ICE protocol
    "GET /music/sweet/music ICE/1.0\r\nHost: example.com\r\n\r\n",
    // invalid.md: IHTTP
    "GET /music/sweet/music IHTTP/1.0\r\nHost: example.com\r\n\r\n",
    // invalid.md: RTSP protocol with PUT
    "PUT /music/sweet/music RTSP/1.0\r\nHost: example.com\r\n\r\n",
    // invalid.md: invalid header token @
    "GET / HTTP/1.1\r\nFo@: Failure\r\n\r\n",
    // invalid.md: invalid header token \x01
    "GET / HTTP/1.1\r\nFoo\x01test: Bar\r\n\r\n",
    // invalid.md: empty header name (colon first)
    "GET / HTTP/1.1\r\n: Bar\r\n\r\n",
    // invalid.md: invalid HTTP version 5.6
    "GET / HTTP/5.6\r\n\r\n",
    // invalid.md: space before header
    "GET / HTTP/1.1\r\n Host: foo\r\n\r\n",
    // content-length.md: overflow
    "PUT /url HTTP/1.1\r\nContent-Length: 1000000000000000000000\r\n\r\n",
    // content-length.md: spaces in middle "4 2"
    "POST / HTTP/1.1\r\nContent-Length: 4 2\r\n\r\n",
    // content-length.md: spaces "13 37"
    "POST / HTTP/1.1\r\nContent-Length: 13 37\r\n\r\n",
    // invalid method
    "FOOBAR / HTTP/1.1\r\n\r\n",
    // no version
    "GET /\r\n\r\n",
    // HTTP/2.0 version
    "GET / HTTP/2.0\r\n\r\n",
    // HTTP/0.9 version
    "GET / HTTP/0.9\r\n\r\n",
    // empty method
    " / HTTP/1.1\r\n\r\n",
    // control char in URI
    "GET /\x01path HTTP/1.1\r\n\r\n",
    // control char in header name
    "GET / HTTP/1.1\r\nBad\x01Name: value\r\n\r\n",
    // header name with space
    "GET / HTTP/1.1\r\nBad Name: value\r\n\r\n",
    // Content-Length negative
    "POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
    // Content-Length not a number
    "POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
    // Content-Length overflow u32
    "POST / HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n",
    // Missing URI (double space)
    "GET  HTTP/1.1\r\n\r\n",
    // Truncated version string
    "GET / HTTP/1.\r\n\r\n",
    // Missing HTTP prefix
    "GET / XTTP/1.1\r\n\r\n",
    // version with letters
    "GET / HTTP/a.b\r\n\r\n",
    // Tab in method
    "GE\tT / HTTP/1.1\r\n\r\n",
    // Only method, no path
    "GET\r\n\r\n",
    // Header value with NUL
    // (can't embed \x00 in string literal, handled separately below)
    // ANNOUNCE (not a valid HTTP method)
    "ANNOUNCE /test HTTP/1.0\r\n\r\n",
    // REPORT (not a valid HTTP method for our parser)
    "REPORT /test HTTP/1.1\r\n\r\n",
    // M-SEARCH (not a valid HTTP method for our parser)
    "M-SEARCH * HTTP/1.1\r\n\r\n",
    // PURGE (not a valid HTTP method for our parser)
    "PURGE /file.txt HTTP/1.1\r\n\r\n",
    // SEARCH (not a valid HTTP method for our parser)
    "SEARCH / HTTP/1.1\r\n\r\n",
    // LINK (not a valid HTTP method for our parser)
    "LINK /images/my_dog.jpg HTTP/1.1\r\n\r\n",
    // UNLINK (not a valid HTTP method for our parser)
    "UNLINK /images/my_dog.jpg HTTP/1.1\r\n\r\n",
    // SOURCE (not a valid HTTP method for our parser)
    "SOURCE /music HTTP/1.1\r\n\r\n",
    // QUERY (not a valid HTTP method for our parser)
    "QUERY /contacts HTTP/1.1\r\n\r\n",
    // PRI (not a valid HTTP method)
    "PRI * HTTP/1.1\r\n\r\n",
    // MKCOL → MKCOLA mismatch
    "MKCOLA / HTTP/1.1\r\n\r\n",
};

static constexpr u32 kNumInvalidStrs = sizeof(kInvalidRequestStrs) / sizeof(kInvalidRequestStrs[0]);

// ============================================================================
// TEST SUITE 1: Valid request corpus
// ============================================================================

TEST(Corpus, ValidRequests) {
    HttpParser parser;
    ParsedRequest req;

    for (u32 i = 0; i < kNumValidRequests; i++) {
        const auto& v = kValidRequests[i];
        auto s = parse_one(v.raw, &req, &parser);

        if (s != ParseStatus::Complete) {
            rut::test::out("  FAIL vector: ");
            rut::test::out(v.name);
            rut::test::out(" (expected Complete)\n");
        }
        CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
        CHECK_EQ(static_cast<u8>(req.method), static_cast<u8>(v.method));

        // Check path
        u32 path_len = 0;
        while (v.path[path_len]) path_len++;
        if (!req.path.eq(Str{v.path, path_len})) {
            rut::test::out("  FAIL vector: ");
            rut::test::out(v.name);
            rut::test::out(" (path mismatch)\n");
        }
        CHECK(req.path.eq(Str{v.path, path_len}));

        CHECK_EQ(static_cast<u8>(req.version), static_cast<u8>(v.version));
        CHECK_EQ(req.header_count, v.header_count);
        CHECK_EQ(req.content_length, v.content_length);
        CHECK_EQ(req.keep_alive, v.keep_alive);
        CHECK_EQ(req.chunked, v.chunked);
    }
}

// ============================================================================
// TEST SUITE 2: Invalid request corpus
// ============================================================================

TEST(Corpus, InvalidRequests) {
    HttpParser parser;
    ParsedRequest req;

    for (u32 i = 0; i < kNumInvalidStrs; i++) {
        auto len = static_cast<u32>(__builtin_strlen(kInvalidRequestStrs[i]));
        auto s = parse_raw(reinterpret_cast<const u8*>(kInvalidRequestStrs[i]), len, &req, &parser);
        if (s != ParseStatus::Error) {
            rut::test::out("  FAIL invalid[");
            // Print index
            char idx[8];
            int n = 0;
            u32 tmp = i;
            do {
                idx[n++] = static_cast<char>('0' + tmp % 10);
                tmp /= 10;
            } while (tmp > 0);
            for (int j = n - 1; j >= 0; j--) {
                char buf[2] = {idx[j], 0};
                rut::test::out(buf);
            }
            rut::test::out("] expected Error\n");
        }
        CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
    }
}

// Control char in header value (can't use string literal due to \x00 truncation)
TEST(Corpus, InvalidControlCharHeaderValue) {
    HttpParser parser;
    ParsedRequest req;

    const u8 raw[] =
        "GET / HTTP/1.1\r\n"
        "Host: bad\x01value\r\n"
        "\r\n";
    auto s = parse_raw(raw, sizeof(raw) - 1, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

// A valid upgrade needs BOTH Connection: upgrade AND an Upgrade header — the
// Connection token alone (hop-by-hop) must not gate the WebSocket 101 tunnel.
TEST(Corpus, ConnectionUpgradeSetsFlag) {
    HttpParser parser;
    ParsedRequest req;
    const u8 up[] =
        "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    REQUIRE_EQ(static_cast<u8>(parse_raw(up, sizeof(up) - 1, &req, &parser)),
               static_cast<u8>(ParseStatus::Complete));
    CHECK(req.upgrade);
    CHECK(req.has_upgrade_header);    // gate = upgrade && has_upgrade_header
    CHECK(req.upgrade_is_websocket);  // the token is specifically "websocket"

    // A non-WebSocket upgrade (e.g. h2c) sets has_upgrade_header but NOT upgrade_is_websocket,
    // so terminate mode won't arm on it.
    parser.reset();
    req.reset();
    const u8 h2c[] = "GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n";
    REQUIRE_EQ(static_cast<u8>(parse_raw(h2c, sizeof(h2c) - 1, &req, &parser)),
               static_cast<u8>(ParseStatus::Complete));
    CHECK(req.has_upgrade_header);
    CHECK(!req.upgrade_is_websocket);

    // "websocket" later in a comma-separated Upgrade list is still detected.
    parser.reset();
    req.reset();
    const u8 list[] =
        "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: h2c, websocket\r\n\r\n";
    REQUIRE_EQ(static_cast<u8>(parse_raw(list, sizeof(list) - 1, &req, &parser)),
               static_cast<u8>(ParseStatus::Complete));
    CHECK(req.has_upgrade_header);
    CHECK(req.upgrade_is_websocket);

    // Connection: upgrade with NO Upgrade header → not a valid upgrade.
    parser.reset();
    req.reset();
    const u8 conn_only[] = "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\n\r\n";
    REQUIRE_EQ(static_cast<u8>(parse_raw(conn_only, sizeof(conn_only) - 1, &req, &parser)),
               static_cast<u8>(ParseStatus::Complete));
    CHECK(req.upgrade);
    CHECK(!req.has_upgrade_header);

    // "close, upgrade" is contradictory — close clears the upgrade intent.
    parser.reset();
    req.reset();
    const u8 close_up[] =
        "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: upgrade, close\r\nUpgrade: websocket\r\n\r\n";
    REQUIRE_EQ(static_cast<u8>(parse_raw(close_up, sizeof(close_up) - 1, &req, &parser)),
               static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.upgrade);  // close wins
    CHECK(!req.keep_alive);

    // close split into a separate Connection field still suppresses upgrade.
    parser.reset();
    req.reset();
    const u8 split[] =
        "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: close\r\nConnection: Upgrade\r\n"
        "Upgrade: websocket\r\n\r\n";
    REQUIRE_EQ(static_cast<u8>(parse_raw(split, sizeof(split) - 1, &req, &parser)),
               static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.upgrade);  // close is sticky across Connection fields

    // An empty / whitespace-only Upgrade header requests no protocol.
    parser.reset();
    req.reset();
    const u8 empty_up[] =
        "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: upgrade\r\nUpgrade:  \r\n\r\n";
    REQUIRE_EQ(static_cast<u8>(parse_raw(empty_up, sizeof(empty_up) - 1, &req, &parser)),
               static_cast<u8>(ParseStatus::Complete));
    CHECK(req.upgrade);
    CHECK(!req.has_upgrade_header);  // empty Upgrade value → not a valid upgrade

    parser.reset();
    req.reset();
    const u8 normal[] = "GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n";
    REQUIRE_EQ(static_cast<u8>(parse_raw(normal, sizeof(normal) - 1, &req, &parser)),
               static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.upgrade);
    CHECK(!req.has_upgrade_header);
}

// ============================================================================
// TEST SUITE 3: Incremental parsing — feed byte-by-byte for every valid vector
// ============================================================================

TEST(Incremental, ValidByteByByte) {
    HttpParser parser;
    ParsedRequest req;

    for (u32 i = 0; i < kNumValidRequests; i++) {
        const auto& v = kValidRequests[i];
        auto len = static_cast<u32>(__builtin_strlen(v.raw));
        auto s = parse_incremental(reinterpret_cast<const u8*>(v.raw), len, &req, &parser);
        if (s != ParseStatus::Complete) {
            rut::test::out("  FAIL incremental: ");
            rut::test::out(v.name);
            rut::test::out("\n");
        }
        CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
        CHECK_EQ(static_cast<u8>(req.method), static_cast<u8>(v.method));
    }
}

// ============================================================================
// TEST SUITE 4: Split at every position for valid vectors
// (Feed first N bytes, then full buffer — tests incremental reparse)
// ============================================================================

TEST(Split, ValidSplitAtEveryPosition) {
    HttpParser parser;
    ParsedRequest req;
    u32 tested = 0;

    // Test first 10 vectors (each generates len-1 sub-tests)
    u32 limit = kNumValidRequests < 10 ? kNumValidRequests : 10;
    for (u32 i = 0; i < limit; i++) {
        const auto& v = kValidRequests[i];
        auto len = static_cast<u32>(__builtin_strlen(v.raw));

        for (u32 split = 1; split < len; split++) {
            parser.reset();
            // First feed: partial
            auto s1 = parser.parse(reinterpret_cast<const u8*>(v.raw), split, &req);
            if (s1 == ParseStatus::Complete) {
                // Split was after the headers — that's fine
                tested++;
                continue;
            }
            CHECK_EQ(static_cast<u8>(s1), static_cast<u8>(ParseStatus::Incomplete));

            // Second feed: full buffer
            auto s2 = parser.parse(reinterpret_cast<const u8*>(v.raw), len, &req);
            if (s2 != ParseStatus::Complete) {
                rut::test::out("  FAIL split: ");
                rut::test::out(v.name);
                rut::test::out("\n");
            }
            CHECK_EQ(static_cast<u8>(s2), static_cast<u8>(ParseStatus::Complete));
            tested++;
        }
    }
    // Should have tested hundreds of split points
    CHECK_GT(tested, 100u);
}

// ============================================================================
// TEST SUITE 5: Method × Version combinatorial
// ============================================================================

TEST(Combinatorial, MethodVersion) {
    const char* methods[] = {
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"};
    const HttpMethod method_enums[] = {HttpMethod::GET,
                                       HttpMethod::POST,
                                       HttpMethod::PUT,
                                       HttpMethod::DELETE,
                                       HttpMethod::PATCH,
                                       HttpMethod::HEAD,
                                       HttpMethod::OPTIONS,
                                       HttpMethod::CONNECT,
                                       HttpMethod::TRACE};
    const char* versions[] = {"HTTP/1.0", "HTTP/1.1"};
    const HttpVersion version_enums[] = {HttpVersion::Http10, HttpVersion::Http11};

    HttpParser parser;
    ParsedRequest req;
    u8 buf[256];
    u32 tested = 0;

    for (u32 m = 0; m < 9; m++) {
        for (u32 v = 0; v < 2; v++) {
            // Build: "METHOD /path VERSION\r\n\r\n"
            u32 pos = 0;
            const char* method = methods[m];
            while (*method) buf[pos++] = static_cast<u8>(*method++);
            buf[pos++] = ' ';
            buf[pos++] = '/';
            buf[pos++] = 'p';
            buf[pos++] = ' ';
            const char* ver = versions[v];
            while (*ver) buf[pos++] = static_cast<u8>(*ver++);
            buf[pos++] = '\r';
            buf[pos++] = '\n';
            buf[pos++] = '\r';
            buf[pos++] = '\n';

            auto s = parse_raw(buf, pos, &req, &parser);
            CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
            CHECK_EQ(static_cast<u8>(req.method), static_cast<u8>(method_enums[m]));
            CHECK_EQ(static_cast<u8>(req.version), static_cast<u8>(version_enums[v]));
            tested++;
        }
    }
    CHECK_EQ(tested, 18u);
}

// ============================================================================
// TEST SUITE 6: Method × Version × N headers combinatorial
// ============================================================================

TEST(Combinatorial, MethodVersionHeaders) {
    const char* methods[] = {
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"};
    const HttpMethod method_enums[] = {HttpMethod::GET,
                                       HttpMethod::POST,
                                       HttpMethod::PUT,
                                       HttpMethod::DELETE,
                                       HttpMethod::PATCH,
                                       HttpMethod::HEAD,
                                       HttpMethod::OPTIONS,
                                       HttpMethod::CONNECT,
                                       HttpMethod::TRACE};

    HttpParser parser;
    ParsedRequest req;
    u8 buf[4096];

    // For each method, test with 0, 1, 5, 10, 32 headers
    u32 header_counts[] = {0, 1, 5, 10, 32};
    u32 tested = 0;

    for (u32 m = 0; m < 9; m++) {
        for (u32 hc = 0; hc < 5; hc++) {
            u32 pos = 0;
            // Request line
            const char* method = methods[m];
            while (*method) buf[pos++] = static_cast<u8>(*method++);
            const char* rest = " /test HTTP/1.1\r\n";
            while (*rest) buf[pos++] = static_cast<u8>(*rest++);

            // Headers
            u32 num_headers = header_counts[hc];
            for (u32 h = 0; h < num_headers; h++) {
                buf[pos++] = 'X';
                buf[pos++] = '-';
                buf[pos++] = static_cast<u8>('A' + (h / 26));
                buf[pos++] = static_cast<u8>('A' + (h % 26));
                buf[pos++] = ':';
                buf[pos++] = ' ';
                buf[pos++] = 'v';
                buf[pos++] = static_cast<u8>('0' + (h % 10));
                buf[pos++] = '\r';
                buf[pos++] = '\n';
            }
            buf[pos++] = '\r';
            buf[pos++] = '\n';

            auto s = parse_raw(buf, pos, &req, &parser);
            CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
            CHECK_EQ(static_cast<u8>(req.method), static_cast<u8>(method_enums[m]));
            CHECK_EQ(req.header_count, num_headers);
            tested++;
        }
    }
    CHECK_EQ(tested, 45u);
}

// ============================================================================
// TEST SUITE 7: Header value edge cases from llhttp
// ============================================================================

TEST(HeaderValue, ExtendedChars) {
    // obs-text (0x80-0xFF) should be valid in header values
    HttpParser parser;
    ParsedRequest req;

    // "Test: Düsseldorf" — UTF-8 ü = 0xC3 0xBC
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "Test: D\xC3\xBCsseldorf\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.header_count, 1u);
}

TEST(HeaderValue, Byte0xFF) {
    // 0xFF in header value (from llhttp sample.md)
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one(
        "OPTIONS /url HTTP/1.1\r\n"
        "Header1: Value1\r\n"
        "Header2: \xFFValue2\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.header_count, 2u);
}

TEST(HeaderValue, TabInValue) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "X-Tab: \tvalue\t \r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.headers[0].value.eq(Str{"value", 5}));
}

TEST(HeaderValue, EmptyValue) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "X-Empty:\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.headers[0].value.eq(Str{"", 0}));
}

TEST(HeaderValue, LeadingTrailingOWS) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "Host:   example.com  \r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.headers[0].value.eq(Str{"example.com", 11}));
}

TEST(HeaderValue, PlusChars) {
    // From llhttp DUMBPACK test
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one(
        "GET /dumbpack HTTP/1.1\r\n"
        "aaaaaaaaaaaaa:++++++++++\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.headers[0].value.eq(Str{"++++++++++", 10}));
}

// ============================================================================
// TEST SUITE 8: Content-Length edge cases from llhttp
// ============================================================================

TEST(ContentLength, WithLeadingZeroes) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("PUT /url HTTP/1.1\r\nContent-Length: 003\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.content_length, 3u);
}

TEST(ContentLength, Zero) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.content_length, 0u);
}

TEST(ContentLength, MaxU32) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("POST / HTTP/1.1\r\nContent-Length: 4294967295\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.content_length, 4294967295u);
}

TEST(ContentLength, Overflow) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one(
        "PUT /url HTTP/1.1\r\nContent-Length: 1000000000000000000000\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(ContentLength, MaxU32PlusOne) {
    HttpParser parser;
    ParsedRequest req;
    // 4294967296 = UINT32_MAX + 1 — must overflow
    auto s = parse_one("POST / HTTP/1.1\r\nContent-Length: 4294967296\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(ContentLength, MaxU32PlusFive) {
    HttpParser parser;
    ParsedRequest req;
    // 4294967300 — overflows u32
    auto s = parse_one("POST / HTTP/1.1\r\nContent-Length: 4294967300\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(ContentLength, ElevenDigits) {
    HttpParser parser;
    ParsedRequest req;
    // 42949672950 — 11 digits, overflows
    auto s = parse_one("POST / HTTP/1.1\r\nContent-Length: 42949672950\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(ContentLength, MaxU32MinusOne) {
    HttpParser parser;
    ParsedRequest req;
    // 4294967294 = UINT32_MAX - 1 — valid
    auto s = parse_one("POST / HTTP/1.1\r\nContent-Length: 4294967294\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.content_length, 4294967294u);
}

TEST(ContentLength, ManyLeadingZeroes) {
    HttpParser parser;
    ParsedRequest req;
    // Many leading zeroes — valid, parses to 1
    auto s = parse_one("POST / HTTP/1.1\r\nContent-Length: 00000000001\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.content_length, 1u);
}

TEST(ContentLength, AllZeroes) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("POST / HTTP/1.1\r\nContent-Length: 0000000000\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.content_length, 0u);
}

TEST(ContentLength, SpacesInMiddle) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("POST / HTTP/1.1\r\nContent-Length: 4 2\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(ContentLength, Negative) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(ContentLength, NonNumeric) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(ContentLength, CaseInsensitive) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("POST / HTTP/1.1\r\ncontent-length: 42\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.content_length, 42u);
}

TEST(ContentLength, FunkyCase) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("GET / HTTP/1.0\r\nconTENT-Length: 5\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.content_length, 5u);
}

// ============================================================================
// TEST SUITE 9: Connection header edge cases
// ============================================================================

TEST(Connection, Http11DefaultKeepAlive) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("GET / HTTP/1.1\r\nHost: x\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.keep_alive);
}

TEST(Connection, Http10DefaultClose) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("GET / HTTP/1.0\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.keep_alive);
}

TEST(Connection, Http10ExplicitKeepAlive) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.keep_alive);
}

TEST(Connection, Http11ExplicitClose) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("GET / HTTP/1.1\r\nConnection: close\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.keep_alive);
}

TEST(Connection, CaseInsensitive) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("GET / HTTP/1.1\r\nconnection: CLOSE\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.keep_alive);
}

// ============================================================================
// TEST SUITE 10: Transfer-Encoding
// ============================================================================

TEST(TransferEncoding, Chunked) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.chunked);
}

TEST(TransferEncoding, ChunkedCaseInsensitive) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("POST / HTTP/1.1\r\ntransfer-encoding: CHUNKED\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.chunked);
}

TEST(TransferEncoding, NotChunked) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.chunked);
}

// ============================================================================
// TEST SUITE 11: Header end offset
// ============================================================================

TEST(HeaderEnd, SimpleRequest) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one("GET / HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(parser.header_end, 18u);
}

TEST(HeaderEnd, WithHeaders) {
    HttpParser parser;
    ParsedRequest req;

    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "Host: x\r\n"
        "\r\n"
        "body here",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(parser.header_end, 27u);
}

TEST(HeaderEnd, WithContentLength) {
    HttpParser parser;
    ParsedRequest req;

    const char* raw =
        "POST /data HTTP/1.1\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello";
    auto s = parse_one(raw, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    // "POST /data HTTP/1.1\r\nContent-Length: 5\r\n\r\n" = 42 bytes
    CHECK_EQ(parser.header_end, 42u);
}

// ============================================================================
// TEST SUITE 12: Parser reset / reuse
// ============================================================================

TEST(Reuse, AcrossRequests) {
    HttpParser parser;
    ParsedRequest req;

    auto s1 = parse_one("GET /first HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s1), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"/first", 6}));

    auto s2 = parse_one("POST /second HTTP/1.1\r\nContent-Length: 5\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s2), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(static_cast<u8>(req.method), static_cast<u8>(HttpMethod::POST));
    CHECK(req.path.eq(Str{"/second", 7}));
    CHECK_EQ(req.content_length, 5u);
}

TEST(Reuse, AfterError) {
    HttpParser parser;
    ParsedRequest req;

    // First: error
    auto s1 = parse_one("FOOBAR / HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s1), static_cast<u8>(ParseStatus::Error));

    // Second: should work fine after reset
    auto s2 = parse_one("GET / HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s2), static_cast<u8>(ParseStatus::Complete));
}

// ============================================================================
// TEST SUITE 13: Incomplete (partial) requests
// ============================================================================

TEST(Incomplete, EmptyBuffer) {
    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    auto s = parser.parse(reinterpret_cast<const u8*>(""), 0, &req);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Incomplete));
}

TEST(Incomplete, PartialMethod) {
    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    auto s = parser.parse(reinterpret_cast<const u8*>("GE"), 2, &req);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Incomplete));
}

TEST(Incomplete, PartialRequestLine) {
    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    auto s = parser.parse(reinterpret_cast<const u8*>("GET / HTTP/1.1"), 14, &req);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Incomplete));
}

TEST(Incomplete, PartialHeaders) {
    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    const char* partial =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n";
    auto len = static_cast<u32>(__builtin_strlen(partial));
    auto s = parser.parse(reinterpret_cast<const u8*>(partial), len, &req);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Incomplete));
}

TEST(Incomplete, OneCRLF) {
    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    const char* partial = "GET / HTTP/1.1\r\n";
    auto len = static_cast<u32>(__builtin_strlen(partial));
    auto s = parser.parse(reinterpret_cast<const u8*>(partial), len, &req);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Incomplete));
}

TEST(Incomplete, HeaderNoFinalCRLF) {
    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    const char* partial =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r";
    auto len = static_cast<u32>(__builtin_strlen(partial));
    auto s = parser.parse(reinterpret_cast<const u8*>(partial), len, &req);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Incomplete));
}

// ============================================================================
// TEST SUITE 14: Edge cases
// ============================================================================

TEST(Edge, LongUri) {
    u8 buf[2048];
    u32 pos = 0;
    const char method[] = "GET /";
    __builtin_memcpy(buf + pos, method, 5);
    pos += 5;
    for (u32 i = 0; i < 1000; i++) buf[pos++] = 'a';
    const char rest[] = " HTTP/1.1\r\n\r\n";
    __builtin_memcpy(buf + pos, rest, 13);
    pos += 13;

    HttpParser parser;
    ParsedRequest req;
    auto s = parse_raw(buf, pos, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.path.len, 1001u);
}

TEST(Edge, MaxHeaders) {
    u8 buf[8192];
    u32 pos = 0;
    const char rl[] = "GET / HTTP/1.1\r\n";
    u32 rl_len = sizeof(rl) - 1;
    __builtin_memcpy(buf + pos, rl, rl_len);
    pos += rl_len;

    for (u32 i = 0; i < 64; i++) {
        buf[pos++] = 'X';
        buf[pos++] = '-';
        buf[pos++] = 'H';
        buf[pos++] = static_cast<u8>('0' + (i / 10));
        buf[pos++] = static_cast<u8>('0' + (i % 10));
        buf[pos++] = ':';
        buf[pos++] = ' ';
        buf[pos++] = 'v';
        buf[pos++] = '\r';
        buf[pos++] = '\n';
    }
    buf[pos++] = '\r';
    buf[pos++] = '\n';

    HttpParser parser;
    ParsedRequest req;
    auto s = parse_raw(buf, pos, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.header_count, 64u);
}

TEST(Edge, TooManyHeaders) {
    u8 buf[8192];
    u32 pos = 0;
    const char rl[] = "GET / HTTP/1.1\r\n";
    u32 rl_len = sizeof(rl) - 1;
    __builtin_memcpy(buf + pos, rl, rl_len);
    pos += rl_len;

    for (u32 i = 0; i < 65; i++) {
        buf[pos++] = 'X';
        buf[pos++] = '-';
        buf[pos++] = 'H';
        buf[pos++] = static_cast<u8>('0' + (i / 10));
        buf[pos++] = static_cast<u8>('0' + (i % 10));
        buf[pos++] = ':';
        buf[pos++] = ' ';
        buf[pos++] = 'v';
        buf[pos++] = '\r';
        buf[pos++] = '\n';
    }
    buf[pos++] = '\r';
    buf[pos++] = '\n';

    HttpParser parser;
    ParsedRequest req;
    auto s = parse_raw(buf, pos, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(Edge, PercentEncoded) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET /path%20with%20spaces HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"/path%20with%20spaces", 21}));
}

TEST(Edge, LongHeaderValue) {
    // Header value of 500 chars
    u8 buf[2048];
    u32 pos = 0;
    const char rl[] = "GET / HTTP/1.1\r\nX-Long: ";
    u32 rl_len = sizeof(rl) - 1;
    __builtin_memcpy(buf + pos, rl, rl_len);
    pos += rl_len;

    for (u32 i = 0; i < 500; i++) buf[pos++] = 'x';
    buf[pos++] = '\r';
    buf[pos++] = '\n';
    buf[pos++] = '\r';
    buf[pos++] = '\n';

    HttpParser parser;
    ParsedRequest req;
    auto s = parse_raw(buf, pos, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.headers[0].value.len, 500u);
}

TEST(Edge, LongHeaderName) {
    // Header name of 200 chars
    u8 buf[2048];
    u32 pos = 0;
    const char rl[] = "GET / HTTP/1.1\r\n";
    u32 rl_len = sizeof(rl) - 1;
    __builtin_memcpy(buf + pos, rl, rl_len);
    pos += rl_len;

    for (u32 i = 0; i < 200; i++) buf[pos++] = 'x';
    buf[pos++] = ':';
    buf[pos++] = ' ';
    buf[pos++] = 'v';
    buf[pos++] = '\r';
    buf[pos++] = '\n';
    buf[pos++] = '\r';
    buf[pos++] = '\n';

    HttpParser parser;
    ParsedRequest req;
    auto s = parse_raw(buf, pos, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.headers[0].name.len, 200u);
}

// ============================================================================
// TEST SUITE 15: Invalid request line variations
// ============================================================================

TEST(InvalidRL, EmptyMethod) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(" / HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(InvalidRL, DoubleSpace) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET  HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(InvalidRL, NoPath) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(InvalidRL, TruncatedVersion) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET / HTTP/1.\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(InvalidRL, WrongProtocol) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET / XTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(InvalidRL, VersionLetters) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET / HTTP/a.b\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

// ============================================================================
// TEST SUITE 16: Systematic invalid header name chars
// ============================================================================

TEST(InvalidHeader, SystematicBadTokens) {
    HttpParser parser;
    ParsedRequest req;
    // Characters that are NOT valid in header names per RFC 7230
    const u8 bad_chars[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x22,  // SP, "
        0x28, 0x29, 0x2C, 0x2F,                                      // ( ) , /
        0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,                          // ; < = > ? @
        0x5B, 0x5C, 0x5D,                                            // [ \ ]
        0x7B, 0x7D, 0x7F,                                            // { } DEL
    };
    u32 tested = 0;

    for (u32 i = 0; i < sizeof(bad_chars); i++) {
        u8 buf[64];
        u32 pos = 0;
        const char prefix[] = "GET / HTTP/1.1\r\nX";
        __builtin_memcpy(buf + pos, prefix, sizeof(prefix) - 1);
        pos += sizeof(prefix) - 1;
        buf[pos++] = bad_chars[i];
        const char suffix[] = "Y: val\r\n\r\n";
        __builtin_memcpy(buf + pos, suffix, sizeof(suffix) - 1);
        pos += sizeof(suffix) - 1;

        auto s = parse_raw(buf, pos, &req, &parser);
        // Should be Error (invalid token in header name)
        // Some chars like \r or \n might cause different parse paths
        // but should still not return Complete
        CHECK_NE(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
        tested++;
    }
    CHECK_GT(tested, 40u);
}

// ============================================================================
// TEST SUITE 17: URI path systematic validation
// ============================================================================

TEST(URI, ValidPathChars) {
    HttpParser parser;
    ParsedRequest req;
    // All printable ASCII except SP and DEL should be valid in URI
    u32 tested = 0;

    for (u8 c = 0x21; c < 0x7F; c++) {
        u8 buf[64];
        u32 pos = 0;
        const char prefix[] = "GET /";
        __builtin_memcpy(buf + pos, prefix, 5);
        pos += 5;
        buf[pos++] = c;
        const char suffix[] = " HTTP/1.1\r\n\r\n";
        __builtin_memcpy(buf + pos, suffix, sizeof(suffix) - 1);
        pos += sizeof(suffix) - 1;

        auto s = parse_raw(buf, pos, &req, &parser);
        CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
        tested++;
    }
    CHECK_EQ(tested, 94u);
}

TEST(URI, ControlCharsInvalid) {
    HttpParser parser;
    ParsedRequest req;
    u32 tested = 0;

    // Control chars 0x01-0x1F should be invalid in URI (0x00 truncates strlen)
    for (u8 c = 0x01; c < 0x20; c++) {
        u8 buf[64];
        u32 pos = 0;
        const char prefix[] = "GET /";
        __builtin_memcpy(buf + pos, prefix, 5);
        pos += 5;
        buf[pos++] = c;
        const char suffix[] = "x HTTP/1.1\r\n\r\n";
        __builtin_memcpy(buf + pos, suffix, sizeof(suffix) - 1);
        pos += sizeof(suffix) - 1;

        auto s = parse_raw(buf, pos, &req, &parser);
        // Should be Error or Incomplete (not Complete with invalid char in URI)
        CHECK_NE(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
        tested++;
    }
    CHECK_EQ(tested, 31u);
}

// ============================================================================
// TEST SUITE 18: Utility functions
// ============================================================================

TEST(Utility, MethodStr) {
    CHECK(http_method_str(HttpMethod::GET).eq(Str{"GET", 3}));
    CHECK(http_method_str(HttpMethod::POST).eq(Str{"POST", 4}));
    CHECK(http_method_str(HttpMethod::PUT).eq(Str{"PUT", 3}));
    CHECK(http_method_str(HttpMethod::DELETE).eq(Str{"DELETE", 6}));
    CHECK(http_method_str(HttpMethod::PATCH).eq(Str{"PATCH", 5}));
    CHECK(http_method_str(HttpMethod::HEAD).eq(Str{"HEAD", 4}));
    CHECK(http_method_str(HttpMethod::OPTIONS).eq(Str{"OPTIONS", 7}));
    CHECK(http_method_str(HttpMethod::CONNECT).eq(Str{"CONNECT", 7}));
    CHECK(http_method_str(HttpMethod::TRACE).eq(Str{"TRACE", 5}));
    CHECK(http_method_str(HttpMethod::Unknown).eq(Str{"UNKNOWN", 7}));
}

// ============================================================================
// TEST SUITE 19: Header-specific parsing from llhttp corpus
// ============================================================================

TEST(HeaderParsing, MultipleHeaders) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Accept: text/html\r\n"
        "User-Agent: test/1.0\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.header_count, 3u);
    CHECK(req.headers[0].name.eq(Str{"Host", 4}));
    CHECK(req.headers[0].value.eq(Str{"example.com", 11}));
    CHECK(req.headers[1].name.eq(Str{"Accept", 6}));
    CHECK(req.headers[1].value.eq(Str{"text/html", 9}));
    CHECK(req.headers[2].name.eq(Str{"User-Agent", 10}));
    CHECK(req.headers[2].value.eq(Str{"test/1.0", 8}));
}

TEST(HeaderParsing, LongUserAgent) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET /test HTTP/1.1\r\n"
        "User-Agent: curl/7.18.0 (i486-pc-linux-gnu) libcurl/7.18.0 OpenSSL/0.9.8g zlib/1.2.3.3 "
        "libidn/1.1\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    Str ua_val;
    CHECK(find_header(req, "User-Agent", &ua_val));
    CHECK_EQ(ua_val.len, 85u);
}

TEST(HeaderParsing, QuotesInValue) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "If-Match: \"e0023aa4e\"\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    Str val;
    CHECK(find_header(req, "If-Match", &val));
    CHECK(val.eq(Str{"\"e0023aa4e\"", 11}));
}

TEST(HeaderParsing, ProxyAuth) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "CONNECT foo:443 HTTP/1.0\r\n"
        "Proxy-authorization: basic aGVsbG86d29ybGQ=\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    Str val;
    CHECK(find_header(req, "Proxy-authorization", &val));
    CHECK(val.eq(Str{"basic aGVsbG86d29ybGQ=", 22}));
}

// ============================================================================
// TEST SUITE 20: Method enumeration exhaustive
// ============================================================================

TEST(Methods, AllNine) {
    struct MethodTestVec {
        const char* raw;
        HttpMethod expected;
    };
    const MethodTestVec vecs[] = {
        {"GET / HTTP/1.1\r\n\r\n", HttpMethod::GET},
        {"POST / HTTP/1.1\r\n\r\n", HttpMethod::POST},
        {"PUT / HTTP/1.1\r\n\r\n", HttpMethod::PUT},
        {"DELETE / HTTP/1.1\r\n\r\n", HttpMethod::DELETE},
        {"PATCH / HTTP/1.1\r\n\r\n", HttpMethod::PATCH},
        {"HEAD / HTTP/1.1\r\n\r\n", HttpMethod::HEAD},
        {"OPTIONS / HTTP/1.1\r\n\r\n", HttpMethod::OPTIONS},
        {"CONNECT host:443 HTTP/1.1\r\n\r\n", HttpMethod::CONNECT},
        {"TRACE / HTTP/1.1\r\n\r\n", HttpMethod::TRACE},
    };

    HttpParser parser;
    ParsedRequest req;
    for (const auto& v : vecs) {
        auto s = parse_one(v.raw, &req, &parser);
        CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
        CHECK_EQ(static_cast<u8>(req.method), static_cast<u8>(v.expected));
    }
}

// ============================================================================
// TEST SUITE 21: nginx test vectors — URI edge cases (http_uri.t)
// ============================================================================

TEST(NginxURI, IncompletePercentEncoding) {
    HttpParser parser;
    ParsedRequest req;
    // nginx rejects /foo/bar% — we accept (permissive URI, let router validate)
    auto s = parse_one("GET /foo/bar% HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"/foo/bar%", 9}));
}

TEST(NginxURI, IncompletePercentOneDigit) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET /foo/bar%1 HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"/foo/bar%1", 10}));
}

TEST(NginxURI, AbsoluteFormSimple) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET http://localhost/ HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"http://localhost/", 17}));
}

TEST(NginxURI, AbsoluteFormWithPort) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET http://localhost:8080/path HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"http://localhost:8080/path", 26}));
}

TEST(NginxURI, AbsoluteFormWithQuery) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET http://localhost?args HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"http://localhost?args", 21}));
}

TEST(NginxURI, AbsoluteFormWithQueryAndFragment) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET http://localhost?args#frag HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"http://localhost?args#frag", 26}));
}

TEST(NginxURI, AbsoluteFormPortQuery) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET http://localhost:8080?args HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"http://localhost:8080?args", 26}));
}

TEST(NginxURI, DotSegments) {
    HttpParser parser;
    ParsedRequest req;
    // We pass through dot segments un-normalized (router handles it)
    auto s = parse_one("GET /foo/bar/.. HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"/foo/bar/..", 11}));
}

TEST(NginxURI, DotSegmentSingle) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET /foo/bar/. HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"/foo/bar/.", 10}));
}

TEST(NginxURI, PercentEncodedControl) {
    HttpParser parser;
    ParsedRequest req;
    // /%02 — percent-encoded control char is valid in URI
    auto s = parse_one("GET /%02 HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"/%02", 4}));
}

TEST(NginxURI, RawControlCharInvalid) {
    HttpParser parser;
    ParsedRequest req;
    // Raw \x02 in URI — invalid
    auto s = parse_one("GET /\x02 HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(NginxURI, DELCharInvalid) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET /\x7f HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

// ============================================================================
// TEST SUITE 22: nginx test vectors — duplicate headers (http_headers_multi.t)
// ============================================================================

TEST(NginxHeaders, DuplicateContentLength) {
    HttpParser parser;
    ParsedRequest req;
    // Duplicate Content-Length with different values must be rejected
    // to prevent request-smuggling (RFC 7230 §3.3.3).
    auto s = parse_one(
        "PUT /url HTTP/1.1\r\n"
        "Content-Length: 1\r\n"
        "Content-Length: 2\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(NginxHeaders, DuplicateContentLengthSameValue) {
    HttpParser parser;
    ParsedRequest req;
    // Duplicate Content-Length with the same value is allowed.
    auto s = parse_one(
        "PUT /url HTTP/1.1\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 5\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.content_length, 5u);
}

TEST(NginxHeaders, ContentLengthAndTransferEncodingConflict) {
    HttpParser parser;
    ParsedRequest req;
    // Both Content-Length and Transfer-Encoding: chunked is rejected
    // to prevent request-smuggling (RFC 7230 §3.3.3).
    auto s = parse_one(
        "POST /url HTTP/1.1\r\n"
        "Content-Length: 10\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

// --- Duplicate Content-Length: more edge cases ---

TEST(NginxHeaders, DuplicateContentLengthZeroZero) {
    HttpParser parser;
    ParsedRequest req;
    // Two CL: 0 headers — same value, should be accepted
    auto s = parse_one(
        "POST /url HTTP/1.1\r\n"
        "Content-Length: 0\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.content_length, 0u);
}

TEST(NginxHeaders, DuplicateContentLengthZeroNonzero) {
    HttpParser parser;
    ParsedRequest req;
    // CL: 0 then CL: 5 — different values, must reject
    auto s = parse_one(
        "POST /url HTTP/1.1\r\n"
        "Content-Length: 0\r\n"
        "Content-Length: 5\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(NginxHeaders, TripleDuplicateContentLength) {
    HttpParser parser;
    ParsedRequest req;
    // Three identical CL headers — allowed
    auto s = parse_one(
        "POST /url HTTP/1.1\r\n"
        "Content-Length: 42\r\n"
        "Content-Length: 42\r\n"
        "Content-Length: 42\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.content_length, 42u);
}

TEST(NginxHeaders, TripleDuplicateContentLengthMismatch) {
    HttpParser parser;
    ParsedRequest req;
    // Two same, one different — must reject
    auto s = parse_one(
        "POST /url HTTP/1.1\r\n"
        "Content-Length: 42\r\n"
        "Content-Length: 42\r\n"
        "Content-Length: 43\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(NginxHeaders, ContentLengthAfterOtherHeaders) {
    HttpParser parser;
    ParsedRequest req;
    // CL after other headers, duplicate with mismatch
    auto s = parse_one(
        "POST /url HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Length: 10\r\n"
        "Accept: */*\r\n"
        "Content-Length: 20\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

// --- Content-Length + Transfer-Encoding conflict: more cases ---

TEST(NginxHeaders, TransferEncodingThenContentLength) {
    HttpParser parser;
    ParsedRequest req;
    // TE first, CL second — also rejected
    auto s = parse_one(
        "POST /url HTTP/1.1\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 10\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(NginxHeaders, ContentLengthZeroWithChunked) {
    HttpParser parser;
    ParsedRequest req;
    // CL: 0 + chunked — still a conflict per RFC
    auto s = parse_one(
        "POST /url HTTP/1.1\r\n"
        "Content-Length: 0\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(NginxHeaders, TransferEncodingNonChunkedWithCL) {
    HttpParser parser;
    ParsedRequest req;
    // TE: gzip (not chunked) + CL — no conflict (chunked flag not set)
    auto s = parse_one(
        "POST /url HTTP/1.1\r\n"
        "Transfer-Encoding: gzip\r\n"
        "Content-Length: 10\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.chunked);
    CHECK_EQ(req.content_length, 10u);
}

TEST(NginxHeaders, ChunkedInTokenList) {
    HttpParser parser;
    ParsedRequest req;
    // TE: gzip, chunked — chunked is in the token list
    auto s = parse_one(
        "POST /url HTTP/1.1\r\n"
        "Transfer-Encoding: gzip, chunked\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.chunked);
}

TEST(NginxHeaders, ChunkedInTokenListWithCL) {
    HttpParser parser;
    ParsedRequest req;
    // TE with chunked in list + CL — conflict
    auto s = parse_one(
        "POST /url HTTP/1.1\r\n"
        "Transfer-Encoding: gzip, chunked\r\n"
        "Content-Length: 10\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

// --- Connection header token parsing edge cases ---

TEST(NginxHeaders, ConnectionCloseUpgrade) {
    HttpParser parser;
    ParsedRequest req;
    // "close, upgrade" — close takes precedence
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "Connection: close, upgrade\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.keep_alive);
}

TEST(NginxHeaders, ConnectionKeepAliveUpgrade) {
    HttpParser parser;
    ParsedRequest req;
    // "keep-alive, upgrade"
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "Connection: keep-alive, upgrade\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.keep_alive);
}

TEST(NginxHeaders, ConnectionTokenWithSpaces) {
    HttpParser parser;
    ParsedRequest req;
    // Extra spaces around tokens
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "Connection:  close , upgrade \r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.keep_alive);
}

TEST(NginxHeaders, ConnectionEmptyTokens) {
    HttpParser parser;
    ParsedRequest req;
    // Empty tokens between commas should be skipped
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "Connection: ,,close,,\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.keep_alive);
}

TEST(NginxHeaders, ConnectionCloseThenKeepAlive) {
    HttpParser parser;
    ParsedRequest req;
    // "close" then "keep-alive" — close is sticky per RFC 7230
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "Connection: close, keep-alive\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.keep_alive);  // close overrides keep-alive
}

TEST(NginxHeaders, ConnectionKeepAliveThenClose) {
    HttpParser parser;
    ParsedRequest req;
    // "keep-alive" then "close" — close wins
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "Connection: keep-alive, close\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.keep_alive);
}

TEST(NginxHeaders, DuplicateHost) {
    HttpParser parser;
    ParsedRequest req;
    // nginx rejects duplicate Host headers. We just store both.
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "Host: a.com\r\n"
        "Host: b.com\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.header_count, 2u);
}

TEST(NginxHeaders, UnderscoreInHeaderName) {
    HttpParser parser;
    ParsedRequest req;
    // nginx has allow_underscores config. We accept underscores always
    // (underscore is a valid RFC 7230 token character).
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "X_Custom_Header: value\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.headers[0].name.eq(Str{"X_Custom_Header", 15}));
}

TEST(NginxHeaders, HyphenInHeaderName) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "X-Custom-Header: value\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.headers[0].name.eq(Str{"X-Custom-Header", 15}));
}

TEST(NginxHeaders, NulInHeaderValue) {
    HttpParser parser;
    ParsedRequest req;
    // nginx rejects NUL in header value
    u8 raw[] =
        "GET / HTTP/1.1\r\n"
        "Host: bad\x00val\r\n"
        "\r\n";
    auto s = parse_raw(raw, sizeof(raw) - 1, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(NginxHeaders, LargeNumberOfHeaders) {
    HttpParser parser;
    ParsedRequest req;
    // nginx default large_client_header_buffers: 4 × 8k
    // Test with 50 headers (within our 64 limit)
    u8 buf[8192];
    u32 pos = 0;
    const char rl[] = "GET / HTTP/1.1\r\n";
    __builtin_memcpy(buf + pos, rl, sizeof(rl) - 1);
    pos += sizeof(rl) - 1;

    for (u32 i = 0; i < 50; i++) {
        buf[pos++] = 'X';
        buf[pos++] = '-';
        buf[pos++] = static_cast<u8>('A' + (i / 26));
        buf[pos++] = static_cast<u8>('A' + (i % 26));
        const char val[] = ": some-value-here\r\n";
        __builtin_memcpy(buf + pos, val, sizeof(val) - 1);
        pos += sizeof(val) - 1;
    }
    buf[pos++] = '\r';
    buf[pos++] = '\n';

    auto s = parse_raw(buf, pos, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.header_count, 50u);
}

// ============================================================================
// TEST SUITE 23: nginx test vectors — version parsing
// ============================================================================

TEST(NginxVersion, Http10) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET / HTTP/1.0\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(static_cast<u8>(req.version), static_cast<u8>(HttpVersion::Http10));
}

TEST(NginxVersion, Http11) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET / HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(static_cast<u8>(req.version), static_cast<u8>(HttpVersion::Http11));
}

TEST(NginxVersion, MajorVersion2) {
    HttpParser parser;
    ParsedRequest req;
    // nginx rejects major version > 1
    auto s = parse_one("GET / HTTP/2.0\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(NginxVersion, MajorVersion5) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET / HTTP/5.6\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(NginxVersion, MajorVersion0) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET / HTTP/0.9\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(NginxVersion, VersionLetters) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET / HTTP/a.b\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(NginxVersion, MissingSlash) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET / HTTP1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(NginxVersion, MissingDot) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET / HTTP/11\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(NginxVersion, ExtraDigits) {
    HttpParser parser;
    ParsedRequest req;
    // HTTP/1.12 — we reject (only accept 1.0 and 1.1)
    auto s = parse_one("GET / HTTP/1.12\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

// ============================================================================
// TEST SUITE 24: nginx test vectors — method edge cases
// ============================================================================

TEST(NginxMethod, NginxMethods) {
    HttpParser parser;
    ParsedRequest req;
    // nginx accepts MKCOL, PROPFIND, PROPPATCH, etc. We don't — verify rejection.
    const char* nginx_only_methods[] = {
        "MKCOL",
        "PROPFIND",
        "PROPPATCH",
        "COPY",
        "MOVE",
        "LOCK",
        "UNLOCK",
        "REPORT",
        "SEARCH",
        "PURGE",
        "LINK",
        "UNLINK",
        "SOURCE",
        "ANNOUNCE",
        "QUERY",
    };
    u32 tested = 0;
    for (const char* method : nginx_only_methods) {
        u8 buf[128];
        u32 pos = 0;
        while (*method) buf[pos++] = static_cast<u8>(*method++);
        const char rest[] = " / HTTP/1.1\r\n\r\n";
        __builtin_memcpy(buf + pos, rest, sizeof(rest) - 1);
        pos += sizeof(rest) - 1;

        auto s = parse_raw(buf, pos, &req, &parser);
        CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
        tested++;
    }
    CHECK_EQ(tested, 15u);
}

TEST(NginxMethod, MethodCaseSensitive) {
    HttpParser parser;
    ParsedRequest req;
    // HTTP methods are case-sensitive — "get" should be rejected
    const char* wrong_case[] = {"get",
                                "Get",
                                "gET",
                                "post",
                                "Post",
                                "put",
                                "Put",
                                "delete",
                                "head",
                                "options",
                                "patch",
                                "connect",
                                "trace"};
    u32 tested = 0;
    for (const char* method : wrong_case) {
        u8 buf[128];
        u32 pos = 0;
        const char* m = method;
        while (*m) buf[pos++] = static_cast<u8>(*m++);
        const char rest[] = " / HTTP/1.1\r\n\r\n";
        __builtin_memcpy(buf + pos, rest, sizeof(rest) - 1);
        pos += sizeof(rest) - 1;

        auto s = parse_raw(buf, pos, &req, &parser);
        CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
        tested++;
    }
    CHECK_EQ(tested, 13u);
}

// ============================================================================
// TEST SUITE 25: nginx test vectors — CONNECT method specifics
// ============================================================================

TEST(NginxConnect, AuthorityForm) {
    HttpParser parser;
    ParsedRequest req;
    // CONNECT uses authority-form URI: host:port
    auto s = parse_one("CONNECT example.com:443 HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"example.com:443", 15}));
}

TEST(NginxConnect, WithHeaders) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "CONNECT proxy.example.com:8080 HTTP/1.1\r\n"
        "Host: proxy.example.com:8080\r\n"
        "Proxy-Authorization: basic dXNlcjpwYXNz\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.header_count, 2u);
}

TEST(NginxConnect, IPAddress) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("CONNECT 192.168.1.1:443 HTTP/1.0\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"192.168.1.1:443", 15}));
}

// ============================================================================
// TEST SUITE 26: nginx test vectors — long request lines
// ============================================================================

TEST(NginxLong, RequestLine200Chars) {
    // nginx tests: GET /foo{200 chars}bar HTTP/1.0
    u8 buf[512];
    u32 pos = 0;
    const char prefix[] = "GET /foo";
    __builtin_memcpy(buf + pos, prefix, sizeof(prefix) - 1);
    pos += sizeof(prefix) - 1;
    for (u32 i = 0; i < 200; i++) buf[pos++] = 'x';
    const char suffix[] = "bar HTTP/1.0\r\n\r\n";
    __builtin_memcpy(buf + pos, suffix, sizeof(suffix) - 1);
    pos += sizeof(suffix) - 1;

    HttpParser parser;
    ParsedRequest req;
    auto s = parse_raw(buf, pos, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.path.len, 207u);  // /foo + 200x + bar
}

TEST(NginxLong, HeaderValue200Chars) {
    // nginx tests: X-Foo: foo{200 chars}bar
    u8 buf[512];
    u32 pos = 0;
    const char prefix[] = "GET / HTTP/1.1\r\nX-Foo: foo";
    __builtin_memcpy(buf + pos, prefix, sizeof(prefix) - 1);
    pos += sizeof(prefix) - 1;
    for (u32 i = 0; i < 200; i++) buf[pos++] = 'x';
    const char suffix[] = "bar\r\n\r\n";
    __builtin_memcpy(buf + pos, suffix, sizeof(suffix) - 1);
    pos += sizeof(suffix) - 1;

    HttpParser parser;
    ParsedRequest req;
    auto s = parse_raw(buf, pos, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.headers[0].value.len, 206u);  // foo + 200x + bar
}

TEST(NginxLong, RequestLine2000Chars) {
    u8 buf[4096];
    u32 pos = 0;
    const char prefix[] = "GET /";
    __builtin_memcpy(buf + pos, prefix, sizeof(prefix) - 1);
    pos += sizeof(prefix) - 1;
    for (u32 i = 0; i < 2000; i++) buf[pos++] = 'a';
    const char suffix[] = " HTTP/1.1\r\n\r\n";
    __builtin_memcpy(buf + pos, suffix, sizeof(suffix) - 1);
    pos += sizeof(suffix) - 1;

    HttpParser parser;
    ParsedRequest req;
    auto s = parse_raw(buf, pos, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.path.len, 2001u);
}

// ============================================================================
// TEST SUITE 27: nginx test vectors — header name token chars
// ============================================================================

TEST(NginxToken, ValidTokenChars) {
    HttpParser parser;
    ParsedRequest req;
    // RFC 7230 token: !#$%&'*+-.^_`|~ plus DIGIT and ALPHA
    // Test each valid non-alphanumeric token char in header name
    const char valid_specials[] = "!#$%&'*+-.^_`|~";
    u32 tested = 0;

    for (u32 i = 0; valid_specials[i]; i++) {
        u8 buf[128];
        u32 pos = 0;
        const char prefix[] = "GET / HTTP/1.1\r\nX";
        __builtin_memcpy(buf + pos, prefix, sizeof(prefix) - 1);
        pos += sizeof(prefix) - 1;
        buf[pos++] = static_cast<u8>(valid_specials[i]);
        const char suffix[] = "Y: val\r\n\r\n";
        __builtin_memcpy(buf + pos, suffix, sizeof(suffix) - 1);
        pos += sizeof(suffix) - 1;

        auto s = parse_raw(buf, pos, &req, &parser);
        CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
        tested++;
    }
    CHECK_EQ(tested, 15u);
}

TEST(NginxToken, DigitsInHeaderName) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "X-123-Header: value\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.headers[0].name.eq(Str{"X-123-Header", 12}));
}

TEST(NginxToken, AllLowercase) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "x-lowercase: value\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.headers[0].name.eq(Str{"x-lowercase", 11}));
}

TEST(NginxToken, AllUppercase) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "X-UPPERCASE: value\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.headers[0].name.eq(Str{"X-UPPERCASE", 11}));
}

// ============================================================================
// TEST SUITE 28: nginx test vectors — keepalive / Connection semantics
// ============================================================================

TEST(NginxKeepalive, Http10NoConnectionHeader) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET /test HTTP/1.0\r\n"
        "Host: localhost\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.keep_alive);  // HTTP/1.0 default
}

TEST(NginxKeepalive, Http10WithKeepAlive) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET /test HTTP/1.0\r\n"
        "Host: localhost\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.keep_alive);
}

TEST(NginxKeepalive, Http11NoConnectionHeader) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET /test HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.keep_alive);  // HTTP/1.1 default
}

TEST(NginxKeepalive, Http11WithClose) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET /test HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: close\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.keep_alive);
}

// ============================================================================
// TEST SUITE 29: nginx-style realistic requests
// ============================================================================

TEST(NginxRealistic, ProxyRequest) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET http://backend.example.com/api/v1/users HTTP/1.1\r\n"
        "Host: backend.example.com\r\n"
        "X-Forwarded-For: 10.0.0.1\r\n"
        "X-Real-IP: 10.0.0.1\r\n"
        "Accept: application/json\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.header_count, 4u);
}

TEST(NginxRealistic, MultipartUpload) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "POST /upload HTTP/1.1\r\n"
        "Host: files.example.com\r\n"
        "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary\r\n"
        "Content-Length: 1048576\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.content_length, 1048576u);
    CHECK(req.keep_alive);
}

TEST(NginxRealistic, WebSocketUpgrade) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET /ws HTTP/1.1\r\n"
        "Host: echo.websocket.org\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Origin: http://example.com\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.header_count, 6u);
}

TEST(NginxRealistic, HealthCheck) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "HEAD /health HTTP/1.1\r\n"
        "Host: backend:8080\r\n"
        "User-Agent: nginx-health-check\r\n"
        "Connection: close\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(static_cast<u8>(req.method), static_cast<u8>(HttpMethod::HEAD));
    CHECK(!req.keep_alive);
}

TEST(NginxRealistic, GrpcRequest) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "POST /service.Method HTTP/1.1\r\n"
        "Host: grpc.example.com\r\n"
        "Content-Type: application/grpc\r\n"
        "Content-Length: 256\r\n"
        "TE: trailers\r\n"
        "Grpc-Timeout: 5S\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.content_length, 256u);
    CHECK_EQ(req.header_count, 5u);
}

TEST(NginxRealistic, HSTSPreload) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Accept: text/html\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Cache-Control: max-age=0\r\n"
        "If-None-Match: \"abc123\"\r\n"
        "If-Modified-Since: Mon, 01 Jan 2024 00:00:00 GMT\r\n"
        "Sec-Fetch-Dest: document\r\n"
        "Sec-Fetch-Mode: navigate\r\n"
        "Sec-Fetch-Site: none\r\n"
        "Sec-Fetch-User: ?1\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.header_count, 12u);
}

// ============================================================================
// TEST SUITE 30: Incremental for nginx vectors
// ============================================================================

TEST(NginxIncremental, ProxyRequestByteByByte) {
    HttpParser parser;
    ParsedRequest req;
    const char* raw =
        "GET http://backend.example.com/api/v1/users HTTP/1.1\r\n"
        "Host: backend.example.com\r\n"
        "X-Forwarded-For: 10.0.0.1\r\n"
        "\r\n";
    auto len = static_cast<u32>(__builtin_strlen(raw));
    auto s = parse_incremental(reinterpret_cast<const u8*>(raw), len, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.header_count, 2u);
}

TEST(NginxIncremental, WebSocketByteByByte) {
    HttpParser parser;
    ParsedRequest req;
    const char* raw =
        "GET /ws HTTP/1.1\r\n"
        "Host: echo.websocket.org\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n";
    auto len = static_cast<u32>(__builtin_strlen(raw));
    auto s = parse_incremental(reinterpret_cast<const u8*>(raw), len, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.header_count, 5u);
}

// ============================================================================
// TEST SUITE: Request smuggling attack vectors
// ============================================================================

TEST(Smuggling, CLCLDifferent) {
    HttpParser parser;
    ParsedRequest req;
    // Classic CL-CL smuggling: two different Content-Length values
    auto s = parse_one(
        "POST / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Length: 6\r\n"
        "Content-Length: 5\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(Smuggling, CLTEChunked) {
    HttpParser parser;
    ParsedRequest req;
    // CL-TE smuggling: Content-Length + Transfer-Encoding: chunked
    auto s = parse_one(
        "POST / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Length: 13\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(Smuggling, TECLChunked) {
    HttpParser parser;
    ParsedRequest req;
    // TE-CL smuggling: Transfer-Encoding first, then Content-Length
    auto s = parse_one(
        "POST / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 6\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(Smuggling, CLTEWithOtherHeaders) {
    HttpParser parser;
    ParsedRequest req;
    // CL-TE hidden among many headers
    auto s = parse_one(
        "POST /api HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Accept: */*\r\n"
        "Content-Length: 100\r\n"
        "X-Custom: foo\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Cookie: session=abc\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(Smuggling, CLZeroTEChunked) {
    HttpParser parser;
    ParsedRequest req;
    // CL:0 + TE:chunked — still a conflict
    auto s = parse_one(
        "POST / HTTP/1.1\r\n"
        "Content-Length: 0\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(Smuggling, TEChunkedInList) {
    HttpParser parser;
    ParsedRequest req;
    // chunked buried in a TE token list + CL
    auto s = parse_one(
        "POST / HTTP/1.1\r\n"
        "Transfer-Encoding: gzip, chunked\r\n"
        "Content-Length: 5\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

// ============================================================================
// TEST SUITE: Transfer-Encoding token parsing edge cases
// ============================================================================

TEST(TETokens, ChunkedOnly) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.chunked);
}

TEST(TETokens, GzipChunked) {
    HttpParser parser;
    ParsedRequest req;
    auto s =
        parse_one("POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.chunked);
}

TEST(TETokens, ChunkedGzip) {
    HttpParser parser;
    ParsedRequest req;
    // chunked first, then gzip — chunked still detected
    auto s =
        parse_one("POST / HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.chunked);
}

TEST(TETokens, GzipOnly) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.chunked);
}

TEST(TETokens, DeflateIdentity) {
    HttpParser parser;
    ParsedRequest req;
    auto s =
        parse_one("POST / HTTP/1.1\r\nTransfer-Encoding: deflate, identity\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.chunked);
}

TEST(TETokens, ChunkedWithSpaces) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("POST / HTTP/1.1\r\nTransfer-Encoding:  chunked \r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.chunked);
}

TEST(TETokens, ChunkedCaseMixed) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("POST / HTTP/1.1\r\nTransfer-Encoding: Chunked\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.chunked);
}

TEST(TETokens, NotchunkedSubstring) {
    HttpParser parser;
    ParsedRequest req;
    // "notchunked" must NOT be detected as chunked (suffix match would fail here)
    auto s = parse_one("POST / HTTP/1.1\r\nTransfer-Encoding: notchunked\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.chunked);
}

TEST(TETokens, ChunkedExtSuffix) {
    HttpParser parser;
    ParsedRequest req;
    // "chunkedx" is not "chunked"
    auto s = parse_one("POST / HTTP/1.1\r\nTransfer-Encoding: chunkedx\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.chunked);
}

TEST(TEFraming, ConservativeOrderedClassificationAndReset) {
    struct Case {
        const char* raw;
        ParseStatus status;
        RequestTransferEncoding framing;
        bool legacy_chunked;
    };
    const Case cases[] = {
        {"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
         ParseStatus::Complete,
         RequestTransferEncoding::None,
         false},
        {"GET / HTTP/1.1\r\nTE: trailers\r\n\r\n",
         ParseStatus::Complete,
         RequestTransferEncoding::None,
         false},
        {"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
         ParseStatus::Complete,
         RequestTransferEncoding::FinalChunked,
         true},
        {"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
         ParseStatus::Complete,
         RequestTransferEncoding::Unsupported,
         false},
        {"POST / HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
         ParseStatus::Complete,
         RequestTransferEncoding::Unsupported,
         true},
        {"POST / HTTP/1.1\r\nTransfer-Encoding: chunked, chunked\r\n\r\n",
         ParseStatus::Complete,
         RequestTransferEncoding::Unsupported,
         true},
        {"POST / HTTP/1.1\r\nTransfer-Encoding: chunked;foo=bar\r\n\r\n",
         ParseStatus::Complete,
         RequestTransferEncoding::Unsupported,
         false},
        {"POST / HTTP/1.1\r\nTransfer-Encoding:\r\n\r\n",
         ParseStatus::Complete,
         RequestTransferEncoding::Unsupported,
         false},
        {"POST / HTTP/1.1\r\nTransfer-Encoding: ,chunked\r\n\r\n",
         ParseStatus::Complete,
         RequestTransferEncoding::Unsupported,
         true},
        {"POST / HTTP/1.1\r\nTransfer-Encoding: chunked,\r\n\r\n",
         ParseStatus::Complete,
         RequestTransferEncoding::Unsupported,
         true},
        {"POST / HTTP/1.1\r\nTransfer-Encoding: gzip,,chunked\r\n\r\n",
         ParseStatus::Complete,
         RequestTransferEncoding::Unsupported,
         true},
        {"POST / HTTP/1.1\r\nTransfer-Encoding: bad/token\r\n\r\n",
         ParseStatus::Complete,
         RequestTransferEncoding::Unsupported,
         false},
        {"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n",
         ParseStatus::Complete,
         RequestTransferEncoding::Unsupported,
         true},
        {"POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: gzip\r\n\r\nx",
         ParseStatus::Complete,
         RequestTransferEncoding::Unsupported,
         false},
        {"POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
         ParseStatus::Error,
         RequestTransferEncoding::FinalChunked,
         true},
    };

    HttpParser parser;
    ParsedRequest req;
    req.transfer_encoding = RequestTransferEncoding::FinalChunked;
    for (const auto& tc : cases) {
        const auto status = parse_one(tc.raw, &req, &parser);
        CHECK_EQ(static_cast<u8>(status), static_cast<u8>(tc.status));
        CHECK_EQ(static_cast<u8>(req.transfer_encoding), static_cast<u8>(tc.framing));
        CHECK_EQ(req.chunked, tc.legacy_chunked);
    }
    req.reset();
    CHECK_EQ(static_cast<u8>(req.transfer_encoding),
             static_cast<u8>(RequestTransferEncoding::Unparsed));
    CHECK(parse_raw(reinterpret_cast<const u8*>("G"), 1, &req, &parser) == ParseStatus::Incomplete);
    CHECK_EQ(static_cast<u8>(req.transfer_encoding),
             static_cast<u8>(RequestTransferEncoding::Unparsed));
}

// ============================================================================
// TEST SUITE: obs-text (0x80-0xFF) in header values
// ============================================================================

TEST(ObsText, Latin1InValue) {
    HttpParser parser;
    ParsedRequest req;
    // Düsseldorf — UTF-8: D\xC3\xBCsseldorf
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "City: D\xC3\xBCsseldorf\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
}

TEST(ObsText, AllHighBytes) {
    // Every byte 0x80-0xFF should be valid in header value
    HttpParser parser;
    ParsedRequest req;
    u32 tested = 0;
    for (u32 c = 0x80; c <= 0xFF; c++) {
        u8 buf[64];
        u32 pos = 0;
        const char prefix[] = "GET / HTTP/1.1\r\nX: ";
        __builtin_memcpy(buf + pos, prefix, sizeof(prefix) - 1);
        pos += sizeof(prefix) - 1;
        buf[pos++] = static_cast<u8>(c);
        const char suffix[] = "\r\n\r\n";
        __builtin_memcpy(buf + pos, suffix, sizeof(suffix) - 1);
        pos += sizeof(suffix) - 1;

        auto s = parse_raw(buf, pos, &req, &parser);
        CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
        tested++;
    }
    CHECK_EQ(tested, 128u);
}

TEST(ObsText, HighBytesInUriRejected) {
    // Bytes 0x80-0xFF must be rejected in URI
    HttpParser parser;
    ParsedRequest req;
    u32 tested = 0;
    for (u32 c = 0x80; c <= 0xFF; c++) {
        u8 buf[64];
        u32 pos = 0;
        const char prefix[] = "GET /";
        __builtin_memcpy(buf + pos, prefix, sizeof(prefix) - 1);
        pos += sizeof(prefix) - 1;
        buf[pos++] = static_cast<u8>(c);
        const char suffix[] = " HTTP/1.1\r\n\r\n";
        __builtin_memcpy(buf + pos, suffix, sizeof(suffix) - 1);
        pos += sizeof(suffix) - 1;

        auto s = parse_raw(buf, pos, &req, &parser);
        CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
        tested++;
    }
    CHECK_EQ(tested, 128u);
}

// ============================================================================
// TEST SUITE: Incremental parsing — precise split points
// ============================================================================

TEST(IncrSplit, SplitInCRLFCRLF) {
    HttpParser parser;
    ParsedRequest req;
    const char* raw = "GET / HTTP/1.1\r\n\r\n";
    auto len = static_cast<u32>(__builtin_strlen(raw));

    // Split right before final \r\n (at the \r of \r\n\r\n)
    for (u32 split = len - 4; split <= len - 1; split++) {
        parser.reset();
        auto s1 = parser.parse(reinterpret_cast<const u8*>(raw), split, &req);
        CHECK_EQ(static_cast<u8>(s1), static_cast<u8>(ParseStatus::Incomplete));

        auto s2 = parser.parse(reinterpret_cast<const u8*>(raw), len, &req);
        CHECK_EQ(static_cast<u8>(s2), static_cast<u8>(ParseStatus::Complete));
    }
}

TEST(IncrSplit, SplitInVersion) {
    HttpParser parser;
    ParsedRequest req;
    const char* raw = "GET / HTTP/1.1\r\n\r\n";
    auto len = static_cast<u32>(__builtin_strlen(raw));

    // Split in the middle of "HTTP/1.1"
    for (u32 split = 6; split <= 13; split++) {
        parser.reset();
        auto s1 = parser.parse(reinterpret_cast<const u8*>(raw), split, &req);
        CHECK_EQ(static_cast<u8>(s1), static_cast<u8>(ParseStatus::Incomplete));

        auto s2 = parser.parse(reinterpret_cast<const u8*>(raw), len, &req);
        CHECK_EQ(static_cast<u8>(s2), static_cast<u8>(ParseStatus::Complete));
    }
}

TEST(IncrSplit, SplitInHeaderValue) {
    HttpParser parser;
    ParsedRequest req;
    const char* raw =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r\n";
    auto len = static_cast<u32>(__builtin_strlen(raw));

    // Split at every position within the header value "example.com"
    for (u32 split = 22; split <= 33; split++) {
        parser.reset();
        auto s1 = parser.parse(reinterpret_cast<const u8*>(raw), split, &req);
        CHECK_EQ(static_cast<u8>(s1), static_cast<u8>(ParseStatus::Incomplete));

        auto s2 = parser.parse(reinterpret_cast<const u8*>(raw), len, &req);
        CHECK_EQ(static_cast<u8>(s2), static_cast<u8>(ParseStatus::Complete));
    }
}

TEST(IncrSplit, SplitBetweenHeaders) {
    HttpParser parser;
    ParsedRequest req;
    const char* raw =
        "GET / HTTP/1.1\r\n"
        "Host: a\r\n"
        "Accept: b\r\n"
        "\r\n";
    auto len = static_cast<u32>(__builtin_strlen(raw));

    // Split between the two headers (at the \r\n boundary)
    // "GET / HTTP/1.1\r\nHost: a\r\n" = 27 bytes
    parser.reset();
    auto s1 = parser.parse(reinterpret_cast<const u8*>(raw), 27, &req);
    CHECK_EQ(static_cast<u8>(s1), static_cast<u8>(ParseStatus::Incomplete));

    auto s2 = parser.parse(reinterpret_cast<const u8*>(raw), len, &req);
    CHECK_EQ(static_cast<u8>(s2), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.header_count, 2u);
}

// ============================================================================
// TEST SUITE: Header value edge cases
// ============================================================================

TEST(HeaderValueEdge, SingleChar) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET / HTTP/1.1\r\nX: a\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.headers[0].value.eq(Str{"a", 1}));
}

TEST(HeaderValueEdge, OnlySpaces) {
    HttpParser parser;
    ParsedRequest req;
    // Value "   " should be trimmed to empty
    auto s = parse_one("GET / HTTP/1.1\r\nX:   \r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.headers[0].value.eq(Str{"", 0}));
}

TEST(HeaderValueEdge, EqualsInValue) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "Authorization: Basic dXNlcjpwYXNz\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.headers[0].value.eq(Str{"Basic dXNlcjpwYXNz", 18}));
}

TEST(HeaderValueEdge, SemicolonInValue) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "Cookie: a=1; b=2; c=3\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.headers[0].value.eq(Str{"a=1; b=2; c=3", 13}));
}

TEST(HeaderValueEdge, ColonInValue) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "GET / HTTP/1.1\r\n"
        "Host: example.com:8080\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.headers[0].value.eq(Str{"example.com:8080", 16}));
}

TEST(HeaderValueEdge, VeryLongValue) {
    // Header value of exactly 1000 chars
    u8 buf[2048];
    u32 pos = 0;
    const char prefix[] = "GET / HTTP/1.1\r\nX-Big: ";
    __builtin_memcpy(buf + pos, prefix, sizeof(prefix) - 1);
    pos += sizeof(prefix) - 1;
    for (u32 i = 0; i < 1000; i++) buf[pos++] = static_cast<u8>('a' + (i % 26));
    const char suffix[] = "\r\n\r\n";
    __builtin_memcpy(buf + pos, suffix, sizeof(suffix) - 1);
    pos += sizeof(suffix) - 1;

    HttpParser parser;
    ParsedRequest req;
    auto s = parse_raw(buf, pos, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.headers[0].value.len, 1000u);
}

// ============================================================================
// TEST SUITE: Multiple semantic headers interaction
// ============================================================================

TEST(MultiSemantic, CLThenConnection) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "POST / HTTP/1.1\r\n"
        "Content-Length: 10\r\n"
        "Connection: close\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.content_length, 10u);
    CHECK(!req.keep_alive);
}

TEST(MultiSemantic, ConnectionThenCL) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one(
        "POST / HTTP/1.1\r\n"
        "Connection: keep-alive\r\n"
        "Content-Length: 42\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.keep_alive);
    CHECK_EQ(req.content_length, 42u);
}

TEST(MultiSemantic, TEGzipWithCLAllowed) {
    HttpParser parser;
    ParsedRequest req;
    // TE: gzip (not chunked) + CL is fine
    auto s = parse_one(
        "POST / HTTP/1.1\r\n"
        "Transfer-Encoding: gzip\r\n"
        "Content-Length: 100\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(!req.chunked);
    CHECK_EQ(req.content_length, 100u);
}

TEST(MultiSemantic, AllThreeNonConflicting) {
    HttpParser parser;
    ParsedRequest req;
    // CL + Connection + non-chunked TE — no conflict
    auto s = parse_one(
        "POST / HTTP/1.1\r\n"
        "Content-Length: 50\r\n"
        "Connection: keep-alive\r\n"
        "Transfer-Encoding: identity\r\n"
        "\r\n",
        &req,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.content_length, 50u);
    CHECK(req.keep_alive);
    CHECK(!req.chunked);
}

// ============================================================================
// TEST SUITE: URI high-byte and special char coverage
// ============================================================================

TEST(URIChars, AtSign) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET /user@host HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"/user@host", 10}));
}

TEST(URIChars, Tilde) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET /~user HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"/~user", 6}));
}

TEST(URIChars, Semicolons) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET /path;params HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"/path;params", 12}));
}

TEST(URIChars, Brackets) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET /path[0] HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
}

TEST(URIChars, Braces) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET /path{id} HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
}

TEST(URIChars, BackslashInURI) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET /path\\file HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
}

TEST(URIChars, DoubleSlash) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET //path HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"//path", 6}));
}

TEST(URIChars, JustSlash) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("GET / HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"/", 1}));
}

TEST(URIChars, Asterisk) {
    HttpParser parser;
    ParsedRequest req;
    auto s = parse_one("OPTIONS * HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"*", 1}));
}

TEST(URIChars, LongQueryString) {
    u8 buf[512];
    u32 pos = 0;
    const char prefix[] = "GET /search?q=";
    __builtin_memcpy(buf + pos, prefix, sizeof(prefix) - 1);
    pos += sizeof(prefix) - 1;
    for (u32 i = 0; i < 200; i++) buf[pos++] = static_cast<u8>('a' + (i % 26));
    const char suffix[] = "&page=1 HTTP/1.1\r\n\r\n";
    __builtin_memcpy(buf + pos, suffix, sizeof(suffix) - 1);
    pos += sizeof(suffix) - 1;

    HttpParser parser;
    ParsedRequest req;
    auto s = parse_raw(buf, pos, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.path.len, 217u);  // /search?q= (10) + 200 + &page=1 (7)
}

// ============================================================================
// TEST SUITE: Header count boundary
// ============================================================================

TEST(HeaderCount, Exactly63) {
    u8 buf[8192];
    u32 pos = 0;
    const char rl[] = "GET / HTTP/1.1\r\n";
    __builtin_memcpy(buf + pos, rl, sizeof(rl) - 1);
    pos += sizeof(rl) - 1;
    for (u32 i = 0; i < 63; i++) {
        buf[pos++] = 'X';
        buf[pos++] = '-';
        buf[pos++] = static_cast<u8>('A' + (i / 26));
        buf[pos++] = static_cast<u8>('A' + (i % 26));
        const char val[] = ": v\r\n";
        __builtin_memcpy(buf + pos, val, sizeof(val) - 1);
        pos += sizeof(val) - 1;
    }
    buf[pos++] = '\r';
    buf[pos++] = '\n';

    HttpParser parser;
    ParsedRequest req;
    auto s = parse_raw(buf, pos, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.header_count, 63u);
}

TEST(HeaderCount, Exactly64) {
    u8 buf[8192];
    u32 pos = 0;
    const char rl[] = "GET / HTTP/1.1\r\n";
    __builtin_memcpy(buf + pos, rl, sizeof(rl) - 1);
    pos += sizeof(rl) - 1;
    for (u32 i = 0; i < 64; i++) {
        buf[pos++] = 'X';
        buf[pos++] = '-';
        buf[pos++] = static_cast<u8>('A' + (i / 26));
        buf[pos++] = static_cast<u8>('A' + (i % 26));
        const char val[] = ": v\r\n";
        __builtin_memcpy(buf + pos, val, sizeof(val) - 1);
        pos += sizeof(val) - 1;
    }
    buf[pos++] = '\r';
    buf[pos++] = '\n';

    HttpParser parser;
    ParsedRequest req;
    auto s = parse_raw(buf, pos, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(req.header_count, 64u);
}

TEST(HeaderCount, Exactly65Rejected) {
    u8 buf[8192];
    u32 pos = 0;
    const char rl[] = "GET / HTTP/1.1\r\n";
    __builtin_memcpy(buf + pos, rl, sizeof(rl) - 1);
    pos += sizeof(rl) - 1;
    for (u32 i = 0; i < 65; i++) {
        buf[pos++] = 'X';
        buf[pos++] = '-';
        buf[pos++] = static_cast<u8>('A' + (i / 26));
        buf[pos++] = static_cast<u8>('A' + (i % 26));
        const char val[] = ": v\r\n";
        __builtin_memcpy(buf + pos, val, sizeof(val) - 1);
        pos += sizeof(val) - 1;
    }
    buf[pos++] = '\r';
    buf[pos++] = '\n';

    HttpParser parser;
    ParsedRequest req;
    auto s = parse_raw(buf, pos, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

// ============================================================================
// Response parser helpers
// ============================================================================

static ParseStatus parse_response(const char* raw,
                                  ParsedResponse* resp,
                                  HttpResponseParser* parser) {
    parser->reset();
    auto len = static_cast<u32>(__builtin_strlen(raw));
    return parser->parse(reinterpret_cast<const u8*>(raw), len, resp);
}

static ParseStatus parse_response_raw(const u8* raw,
                                      u32 len,
                                      ParsedResponse* resp,
                                      HttpResponseParser* parser) {
    parser->reset();
    return parser->parse(raw, len, resp);
}

static bool find_resp_header(const ParsedResponse& resp, const char* name, Str* out_value) {
    u32 name_len = 0;
    while (name[name_len]) name_len++;
    for (u32 i = 0; i < resp.header_count; i++) {
        if (resp.headers[i].name.len == name_len) {
            bool match = true;
            for (u32 j = 0; j < name_len; j++) {
                if (resp.headers[i].name.ptr[j] != name[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                *out_value = resp.headers[i].value;
                return true;
            }
        }
    }
    return false;
}

// ============================================================================
// Response parser tests
// ============================================================================

TEST(response_parser, basic_200) {
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(resp.status_code, 200);
    CHECK_EQ(resp.header_count, 1u);
    CHECK(resp.has_content_length);
    CHECK_EQ(resp.content_length, 5u);
    CHECK(resp.keep_alive);  // HTTP/1.1 default
    CHECK(!resp.chunked);
    CHECK(!resp.connection_close);

    // header_end should point to first body byte
    Str val;
    CHECK(find_resp_header(resp, "Content-Length", &val));
    CHECK_EQ(val.len, 1u);  // "5"

    // Verify body starts at header_end
    const char* raw =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello";
    CHECK_EQ(raw[parser.header_end], 'h');
}

TEST(response_parser, preserves_version_reason_raw_ows_and_cl_count) {
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "HTTP/1.1 200 Custom Reason\r\n"
        "X-TrAcE:  one \t\r\n"
        "Content-Length: 2\r\n"
        "Content-Length: 2\r\n"
        "\r\nok",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(static_cast<u8>(resp.version), static_cast<u8>(HttpVersion::Http11));
    CHECK_EQ(resp.reason.len, 13u);
    CHECK(memcmp(resp.reason.ptr, "Custom Reason", 13) == 0);
    CHECK_EQ(resp.content_length_count, 2u);
    CHECK_EQ(resp.headers[0].raw_value.len, 7u);
    CHECK(memcmp(resp.headers[0].raw_value.ptr, "  one \t", 7) == 0);
}

TEST(response_parser, 404) {
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Length: 9\r\n"
        "\r\n"
        "Not Found",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(resp.status_code, 404);
    CHECK_EQ(resp.content_length, 9u);
    CHECK(resp.has_content_length);
}

TEST(response_parser, chunked) {
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(resp.status_code, 200);
    CHECK(resp.chunked);
    CHECK(!resp.has_content_length);
}

TEST(response_parser, connection_close) {
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "HTTP/1.1 200 OK\r\n"
        "Connection: close\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(resp.status_code, 200);
    CHECK(resp.connection_close);
    CHECK(!resp.keep_alive);
    CHECK_EQ(resp.content_length, 2u);
}

TEST(response_parser, incomplete) {
    HttpResponseParser parser;
    ParsedResponse resp;

    // Partial status line
    auto s = parse_response("HTTP/1.1 20", &resp, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Incomplete));

    // Status line complete but no header terminator
    s = parse_response("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n", &resp, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Incomplete));

    // Very short input
    s = parse_response("HTTP", &resp, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Incomplete));
}

TEST(response_parser, no_headers) {
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "HTTP/1.1 200 OK\r\n"
        "\r\n",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(resp.status_code, 200);
    CHECK_EQ(resp.header_count, 0u);
    CHECK(!resp.has_content_length);
    CHECK(!resp.chunked);
    CHECK(resp.keep_alive);
}

TEST(response_parser, content_length_body_split) {
    // Headers complete but body not fully in buffer — parser should still
    // return Complete (it only parses headers, not body).
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 100\r\n"
        "\r\n"
        "partial",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(resp.status_code, 200);
    CHECK_EQ(resp.content_length, 100u);
    CHECK(resp.has_content_length);
    // header_end should be valid — body starts after \r\n\r\n
    CHECK_GT(parser.header_end, 0u);
}

TEST(response_parser, http10_no_keepalive) {
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "HTTP/1.0 200 OK\r\n"
        "Content-Length: 2\r\n"
        "\r\n"
        "OK",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(resp.status_code, 200);
    CHECK(!resp.keep_alive);  // HTTP/1.0 default
}

TEST(response_parser, connection_keepalive_explicit) {
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "HTTP/1.0 200 OK\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(resp.keep_alive);
    CHECK(!resp.connection_close);
}

TEST(response_parser, multiple_headers) {
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "HTTP/1.1 301 Moved Permanently\r\n"
        "Location: /new-path\r\n"
        "Content-Length: 0\r\n"
        "X-Custom: value\r\n"
        "\r\n",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK_EQ(resp.status_code, 301);
    CHECK_EQ(resp.header_count, 3u);
    CHECK_EQ(resp.content_length, 0u);
    CHECK(resp.has_content_length);
}

TEST(response_parser, duplicate_content_length_same_value) {
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(resp.has_content_length);
    CHECK_EQ(resp.content_length, 5u);
}

TEST(response_parser, duplicate_content_length_mismatch) {
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "hello!",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(response_parser, invalid_version_prefix) {
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "XHTTP/1.1 200 OK\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(response_parser, invalid_version_digit) {
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "HTTP/1.2 200 OK\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(response_parser, malformed_status_codes_rejected) {
    struct Case {
        const char* raw;
    };
    static const Case cases[] = {
        {"HTTP/1.1 XYZ Bad\r\n\r\n"},
        {"HTTP/1.1 20X Bad\r\n\r\n"},
        {"HTTP/1.1 099 Low\r\n\r\n"},
        {"HTTP/1.1 600 High\r\n\r\n"},
    };

    HttpResponseParser parser;
    ParsedResponse resp;
    for (const auto& tc : cases) {
        auto s = parse_response(tc.raw, &resp, &parser);
        CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
    }
}

TEST(response_parser, empty_content_length_rejected) {
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length:\r\n"
        "\r\n",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(response_parser, trims_trailing_ows_in_header_value) {
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5 \t \r\n"
        "\r\n"
        "hello",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    CHECK(resp.has_content_length);
    CHECK_EQ(resp.content_length, 5u);

    Str val;
    CHECK(find_resp_header(resp, "Content-Length", &val));
    CHECK_EQ(val.len, 1u);
    CHECK_EQ(val.ptr[0], '5');
}

TEST(response_parser, malformed_reason_phrase_cr_without_lf) {
    HttpResponseParser parser;
    ParsedResponse resp;
    static const u8 raw[] = "HTTP/1.1 200 OK\rX";
    auto s = parse_response_raw(raw, sizeof(raw) - 1, &resp, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(response_parser, malformed_header_terminator_cr_without_lf) {
    HttpResponseParser parser;
    ParsedResponse resp;
    static const u8 raw[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5\rX";
    auto s = parse_response_raw(raw, sizeof(raw) - 1, &resp, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

TEST(response_parser, invalid_header_name_with_full_terminator_errors) {
    HttpResponseParser parser;
    ParsedResponse resp;
    auto s = parse_response(
        "HTTP/1.1 200 OK\r\n"
        "Bad Header\r\n"
        "\r\n",
        &resp,
        &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Error));
}

// ============================================================================
// TEST SUITE: path_canon — PR #50 round 7 path A
// The parser now produces path_canon (canonical-for-routing view) as a
// free byproduct of the URI SIMD scan. RouteConfig::match_canonical
// consumes it directly. Verify the canon shape for several URI patterns.
// ============================================================================

namespace {

struct CanonCase {
    const char* name;
    const char* raw;        // full request bytes
    const char* path_exp;   // expected req.path (raw URI as-is)
    const char* canon_exp;  // expected req.path_canon (post-canon view)
};

constexpr CanonCase kPathCanonCases[] = {
    {"plain", "GET /api/v1/users HTTP/1.1\r\n\r\n", "/api/v1/users", "api/v1/users"},
    {"trailing-slash", "GET /admin/ HTTP/1.1\r\n\r\n", "/admin/", "admin"},
    {"trailing-slash-run", "GET /a/b/// HTTP/1.1\r\n\r\n", "/a/b///", "a/b"},
    {"with-query", "GET /search?q=abc HTTP/1.1\r\n\r\n", "/search?q=abc", "search"},
    {"with-fragment", "GET /page#anchor HTTP/1.1\r\n\r\n", "/page#anchor", "page"},
    {"query-and-fragment",
     "GET /forum/1/topic/2?p=3#post-4 HTTP/1.1\r\n\r\n",
     "/forum/1/topic/2?p=3#post-4",
     "forum/1/topic/2"},
    {"query-with-trailing-slash",
     "GET /admin/?token=x HTTP/1.1\r\n\r\n",
     "/admin/?token=x",
     "admin"},
    {"root-only", "GET / HTTP/1.1\r\n\r\n", "/", ""},
    {"nested-deep",
     "GET /api/v1/teams/42/members/alice HTTP/1.1\r\n\r\n",
     "/api/v1/teams/42/members/alice",
     "api/v1/teams/42/members/alice"},
};

}  // namespace

TEST(PathCanon, canonical_view_matches_expected) {
    HttpParser parser;
    ParsedRequest req;
    for (const auto& c : kPathCanonCases) {
        auto s = parse_one(c.raw, &req, &parser);
        if (s != ParseStatus::Complete) {
            rut::test::out("  FAIL canon case: ");
            rut::test::out(c.name);
            rut::test::out(" (parse incomplete)\n");
        }
        CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));

        u32 path_len = 0;
        while (c.path_exp[path_len]) path_len++;
        u32 canon_len = 0;
        while (c.canon_exp[canon_len]) canon_len++;

        if (!req.path.eq(Str{c.path_exp, path_len})) {
            rut::test::out("  FAIL canon case: ");
            rut::test::out(c.name);
            rut::test::out(" (raw path mismatch)\n");
        }
        CHECK(req.path.eq(Str{c.path_exp, path_len}));

        if (!req.path_canon.eq(Str{c.canon_exp, canon_len})) {
            rut::test::out("  FAIL canon case: ");
            rut::test::out(c.name);
            rut::test::out(" (canon path mismatch)\n");
        }
        CHECK(req.path_canon.eq(Str{c.canon_exp, canon_len}));
    }
}

TEST(PathCanon, canon_view_lives_inside_recv_buffer) {
    // path_canon must point into the same buffer as path — no allocations,
    // no temporaries that go out of scope. Verify the canon Str's bytes
    // are byte-identical to the corresponding slice of path.
    HttpParser parser;
    ParsedRequest req;
    static const char raw[] = "GET /admin/x?y=1 HTTP/1.1\r\n\r\n";
    auto s = parse_one(raw, &req, &parser);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
    // path = "/admin/x?y=1", path_canon should be "admin/x" — view at
    // offset 1 (skip leading '/') with len 7 (stop before '?'), and
    // the bytes must match the corresponding slice of path.
    CHECK_EQ(req.path_canon.ptr, req.path.ptr + 1);
    CHECK_EQ(req.path_canon.len, 7u);
    CHECK(req.path_canon.eq(Str{"admin/x", 7}));
    for (u32 i = 0; i < req.path_canon.len; i++) {
        CHECK_EQ(req.path_canon.ptr[i], req.path.ptr[i + 1]);
    }
}

TEST(PathCanon, leading_slash_run_collapsed) {
    // RFC 3986 leaves leading-slash count semantic, but the
    // match_canonical contract requires "no leading '/'" — so
    // canonicalize_request strips ALL leading slashes, not just one.
    HttpParser parser;
    ParsedRequest req;

    auto s1 = parse_one("GET //api/v1 HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s1), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path_canon.eq(Str{"api/v1", 6}));

    auto s2 = parse_one("GET ///api/v1/ HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s2), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path_canon.eq(Str{"api/v1", 6}));

    // Embedded multi-slashes are preserved (different route).
    auto s3 = parse_one("GET /api//v1 HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s3), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path_canon.eq(Str{"api//v1", 7}));
}

TEST(PathCanon, non_origin_form_leaves_canon_null) {
    // Asterisk-form ("OPTIONS *") and authority-form ("CONNECT host:port")
    // are valid HTTP/1.1 request-targets that don't represent paths. The
    // parser must NOT populate path_canon for them, otherwise the routing
    // hot path (RouteConfig::match_canonical) would route them via a
    // configured "/" catchall — a security regression that the older
    // RouteConfig::match() entry guarded against via origin-form rejection.
    HttpParser parser;
    ParsedRequest req;

    // asterisk-form
    auto s1 = parse_one("OPTIONS * HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s1), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path.eq(Str{"*", 1}));
    CHECK(req.path_canon.ptr == nullptr);
    CHECK_EQ(req.path_canon.len, 0u);

    // authority-form (CONNECT)
    auto s2 = parse_one("CONNECT example.com:443 HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s2), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path_canon.ptr == nullptr);
    CHECK_EQ(req.path_canon.len, 0u);

    // origin-form root "/" — canon is non-null but len 0 (legitimate)
    auto s3 = parse_one("GET / HTTP/1.1\r\n\r\n", &req, &parser);
    CHECK_EQ(static_cast<u8>(s3), static_cast<u8>(ParseStatus::Complete));
    CHECK(req.path_canon.ptr != nullptr);
    CHECK_EQ(req.path_canon.len, 0u);
}

TEST(request_parser, full_target_fragment_witness_survives_long_query_and_resets) {
    HttpParser parser;
    ParsedRequest req;
    std::string raw = "GET /static?";
    raw.append(96, 'x');
    raw += "#fragment HTTP/1.1\r\nHost: x\r\n\r\n";
    parser.reset();
    REQUIRE_EQ(
        parser.parse(reinterpret_cast<const u8*>(raw.data()), static_cast<u32>(raw.size()), &req),
        ParseStatus::Complete);
    CHECK(req.target_has_fragment);
    CHECK(req.path_canon.eq({"static", 6}));

    parser.reset();
    REQUIRE_EQ(parse_one("GET /static?x=1 HTTP/1.1\r\nHost: x\r\n\r\n", &req, &parser),
               ParseStatus::Complete);
    CHECK_FALSE(req.target_has_fragment);

    parser.reset();
    const char malformed[] = "GET /static#fragment HTTP/1.1\r\nBroken\r\n\r\n";
    CHECK_EQ(parser.parse(reinterpret_cast<const u8*>(malformed), sizeof(malformed) - 1, &req),
             ParseStatus::Error);
    CHECK(req.target_has_fragment);
}

// A response with exactly kMaxHeaders fields is fully stored and NOT flagged
// truncated; one more field saturates header_count at kMaxHeaders and sets the
// headers_truncated flag. The h2 proxy keys its hop-by-hop-safety 502 off this
// flag, so the exactly-full boundary must not be mistaken for truncation.
TEST(response_parser, headers_truncated_flag) {
    // Build "HTTP/1.1 200 OK\r\n" + n distinct "x-hN: v\r\n" headers + CRLF.
    auto build = [](char* out, u32 n) -> u32 {
        u32 o = 0;
        for (const char* p = "HTTP/1.1 200 OK\r\n"; *p != '\0'; p++) out[o++] = *p;
        for (u32 i = 0; i < n; i++) {
            out[o++] = 'x';
            out[o++] = '-';
            out[o++] = 'h';
            if (i >= 10) out[o++] = static_cast<char>('0' + i / 10);
            out[o++] = static_cast<char>('0' + i % 10);
            out[o++] = ':';
            out[o++] = ' ';
            out[o++] = 'v';
            out[o++] = '\r';
            out[o++] = '\n';
        }
        out[o++] = '\r';
        out[o++] = '\n';
        return o;
    };
    {
        HttpResponseParser parser;
        parser.reset();
        ParsedResponse resp;
        resp.reset();
        char raw[2048];
        u32 len = build(raw, kMaxHeaders);  // exactly full
        auto s = parser.parse(reinterpret_cast<const u8*>(raw), len, &resp);
        CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
        CHECK_EQ(resp.header_count, kMaxHeaders);
        CHECK(!resp.headers_truncated);  // all stored — a valid response
    }
    {
        HttpResponseParser parser;
        parser.reset();
        ParsedResponse resp;
        resp.reset();
        char raw[2048];
        u32 len = build(raw, kMaxHeaders + 1);  // one over capacity
        auto s = parser.parse(reinterpret_cast<const u8*>(raw), len, &resp);
        CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ParseStatus::Complete));
        CHECK_EQ(resp.header_count, kMaxHeaders);  // saturates
        CHECK(resp.headers_truncated);             // tail dropped from headers[]
    }
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
