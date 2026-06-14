/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

// Benchmark: rue HTTP parser vs llhttp (Node.js)
//
// Build:  ninja -C build bench_http_parser
// Run:    ./build/bench/bench_http_parser

#include "bench.h"
#include "rut/runtime/http_parser.h"

// llhttp (C library)
extern "C" {
#include "llhttp.h"
}

using namespace rut;

// ============================================================================
// Test payloads — representative HTTP requests
// ============================================================================

// Minimal GET
static const char kSimpleGet[] =
    "GET / HTTP/1.1\r\n"
    "\r\n";

// Typical browser GET
static const char kBrowserGet[] =
    "GET /favicon.ico HTTP/1.1\r\n"
    "Host: 0.0.0.0:5000\r\n"
    "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9) Gecko/2008061015 Firefox/3.0\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    "Accept-Language: en-us,en;q=0.5\r\n"
    "Accept-Encoding: gzip,deflate\r\n"
    "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
    "Keep-Alive: 300\r\n"
    "Connection: keep-alive\r\n"
    "\r\n";

// API POST with body indicator
static const char kApiPost[] =
    "POST /api/v1/users HTTP/1.1\r\n"
    "Host: api.example.com\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 128\r\n"
    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\r\n"
    "Accept: application/json\r\n"
    "Connection: keep-alive\r\n"
    "\r\n";

// curl-style GET
static const char kCurlGet[] =
    "GET /test HTTP/1.1\r\n"
    "User-Agent: curl/7.18.0 (i486-pc-linux-gnu) libcurl/7.18.0 OpenSSL/0.9.8g zlib/1.2.3.3 "
    "libidn/1.1\r\n"
    "Host: 0.0.0.0=5000\r\n"
    "Accept: */*\r\n"
    "\r\n";

// Chunked POST
static const char kChunkedPost[] =
    "POST /upload HTTP/1.1\r\n"
    "Host: files.example.com\r\n"
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n"
    "\r\n";

// ============================================================================
// Benchmark payloads
// ============================================================================

struct Payload {
    const char* name;
    const char* data;
    u32 len;
};

static Payload payloads[] = {
    {"simple_get", kSimpleGet, sizeof(kSimpleGet) - 1},
    {"browser_get", kBrowserGet, sizeof(kBrowserGet) - 1},
    {"api_post", kApiPost, sizeof(kApiPost) - 1},
    {"curl_get", kCurlGet, sizeof(kCurlGet) - 1},
    {"chunked_post", kChunkedPost, sizeof(kChunkedPost) - 1},
};
static constexpr u32 kNumPayloads = sizeof(payloads) / sizeof(payloads[0]);

// ============================================================================
// llhttp helpers
// ============================================================================

static llhttp_settings_t llhttp_settings;

static void init_llhttp_settings() {
    llhttp_settings_init(&llhttp_settings);
    // No callbacks — we just want to measure raw parsing speed.
    // llhttp still does all the work internally.
}

// ============================================================================
// Main
// ============================================================================

int main() {
    init_llhttp_settings();

    bench::out("\n");

    for (u32 p = 0; p < kNumPayloads; p++) {
        const auto& payload = payloads[p];

        bench::Bench b;
        b.title(payload.name);
        b.min_iterations(2000000);
        b.warmup(100000);
        b.epochs(11);
        b.bytes_per_op(payload.len);

        b.print_header();

        // --- rue parser ---
        HttpParser rue_parser;
        ParsedRequest rue_req;

        b.run("rue", [&] {
            rue_parser.reset();
            auto s =
                rue_parser.parse(reinterpret_cast<const u8*>(payload.data), payload.len, &rue_req);
            bench::do_not_optimize(&s);
            bench::do_not_optimize(&rue_req);
        });

        // --- llhttp parser ---
        llhttp_t llhttp_parser;
        llhttp_init(&llhttp_parser, HTTP_REQUEST, &llhttp_settings);

        b.run("llhttp", [&] {
            llhttp_reset(&llhttp_parser);
            auto err = llhttp_execute(&llhttp_parser, payload.data, payload.len);
            bench::do_not_optimize(&err);
            bench::do_not_optimize(&llhttp_parser);
        });

        b.compare();
        bench::out("\n");
    }

    return 0;
}
