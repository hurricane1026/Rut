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

// Microbench for parser SIMD URI scan — SIMD vs scalar reference.
//
// scan_uri is on every parsed request's hot path: the parser uses it to
// find the request-line space terminator, and PR #50 round 7 (path A)
// extended it to also report canon_end (first '?' or '#') in the same
// pass for free. This bench validates that the SIMD backends still
// pull their weight vs a scalar implementation across realistic URI
// length distributions.
//
// The selected SIMD backend is fixed at compile time via -DSIMD_ARCH.
// Build with -DSIMD_ARCH=avx512 (or avx2/sse2) to bench that backend
// against the scalar reference. CI runs this with avx512 on x86_64
// Ice Lake-class hardware.

#include "char_tables.h"  // kUriTable
#include "runtime/simd/simd.h"
#include "rut/common/types.h"
#include <chrono>
#include <cstdio>
#include <cstring>

using namespace rut;

namespace {

// Scalar reference — byte-for-byte equivalent to src/runtime/simd/scalar.cc's
// scan_uri. Kept as a separate symbol so it can be benched against the
// active SIMD backend in the same binary.
u32 scan_uri_scalar_ref(const u8* buf, u32 pos, u32 end, u32* canon_end_out) {
    u32 canon_end = end;
    while (pos < end) {
        u8 b = buf[pos];
        if (b == ' ') {
            *canon_end_out = (canon_end != end) ? canon_end : pos;
            return pos;
        }
        if (!kUriTable[b]) return static_cast<u32>(-1);
        if ((b == '?' || b == '#') && canon_end == end) canon_end = pos;
        pos++;
    }
    *canon_end_out = canon_end;
    return end;
}

// Build a buffer shaped like a real recv_buf at the moment scan_uri is
// called by the parser: METHOD has been consumed, pos sits at URI start,
// URI of `uri_len` bytes followed by SP, then version + CRLF + a few
// headers (so the SIMD loop has plenty of bytes after the SP — typical
// of post-recv state where the buffer contains the full request).
void make_buffer(u8* buf, u32 buf_size, u32 uri_len, bool with_qf) {
    // URI: '/' + rotating lowercase. Optionally insert '?' near the end
    // so canon_end detection has work to do.
    buf[0] = '/';
    for (u32 i = 1; i < uri_len; i++) {
        buf[i] = static_cast<u8>('a' + (i % 26));
    }
    if (with_qf && uri_len > 8) {
        buf[uri_len - 4] = '?';
    }
    buf[uri_len] = ' ';
    static constexpr char kTail[] =
        " HTTP/1.1\r\nHost: bench.example.com\r\nUser-Agent: rut-bench/1.0\r\n"
        "Accept: */*\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n\r\n";
    const u32 kTailLen = sizeof(kTail) - 1;
    const u32 kStart = uri_len + 1;
    u32 copy = kTailLen;
    if (kStart + copy > buf_size) copy = buf_size - kStart;
    std::memcpy(buf + kStart, kTail, copy);
}

template <typename Fn>
double bench_fn(Fn fn, const u8* buf, u32 pos, u32 end, u32 iters) {
    volatile u32 sink = 0;
    // Warmup
    for (u32 i = 0; i < 50000; i++) {
        u32 canon_end = 0;
        sink ^= fn(buf, pos, end, &canon_end);
    }
    auto start = std::chrono::high_resolution_clock::now();
    for (u32 i = 0; i < iters; i++) {
        u32 canon_end = 0;
        sink ^= fn(buf, pos, end, &canon_end);
    }
    auto end_t = std::chrono::high_resolution_clock::now();
    (void)sink;
    return std::chrono::duration<double, std::nano>(end_t - start).count() / iters;
}

// Backend label — fed by CMake via -DBENCH_SIMD_BACKEND="<arch>". Reading
// compiler predefines (__ARM_NEON / __SSE2__ / etc.) doesn't work because
// many of them are baseline on their target ISA: __ARM_NEON is always
// defined on aarch64 even when SIMD_ARCH=scalar, __SSE2__ is always
// defined on x86_64, etc. The CMake-provided string reflects the
// SIMD_ARCH the scan_uri linked into this binary was compiled with.
#ifndef BENCH_SIMD_BACKEND
#define BENCH_SIMD_BACKEND "unknown"
#endif

const char* simd_backend_name() {
    return BENCH_SIMD_BACKEND;
}

}  // namespace

int main() {
    constexpr u32 kBufSize = 8192;
    alignas(64) u8 buf[kBufSize];

    // URI length sweep — covers short (within first SIMD chunk),
    // medium (handful of chunks), and long (CDN-style URIs).
    constexpr u32 kUriLens[] = {8, 16, 32, 64, 128, 256, 512, 1024};

    std::printf("scan_uri microbench — ns per call (lower is better)\n");
    std::printf("Backend: %s   |   Reference: scalar (kUriTable validating)\n",
                simd_backend_name());
    std::printf("\n");
    std::printf("                       no '?'/'#'                  with '?'/'#' near end\n");
    std::printf("URI len |   SIMD   |  scalar  | speedup |   SIMD   |  scalar  | speedup\n");
    std::printf("--------+----------+----------+---------+----------+----------+--------\n");

    for (u32 uri_len : kUriLens) {
        // Scale iters down for long URIs to keep wall-clock reasonable.
        u32 iters = uri_len <= 64 ? 5'000'000u : (uri_len <= 256 ? 2'000'000u : 500'000u);

        double t_simd_plain;
        double t_scalar_plain;
        double t_simd_qf;
        double t_scalar_qf;

        make_buffer(buf, kBufSize, uri_len, /*with_qf=*/false);
        t_simd_plain = bench_fn(simd::scan_uri, buf, 0, kBufSize, iters);
        t_scalar_plain = bench_fn(scan_uri_scalar_ref, buf, 0, kBufSize, iters);

        make_buffer(buf, kBufSize, uri_len, /*with_qf=*/true);
        t_simd_qf = bench_fn(simd::scan_uri, buf, 0, kBufSize, iters);
        t_scalar_qf = bench_fn(scan_uri_scalar_ref, buf, 0, kBufSize, iters);

        std::printf(" %4u   | %6.2f ns | %6.2f ns | %5.2fx  | %6.2f ns | %6.2f ns | %5.2fx\n",
                    uri_len,
                    t_simd_plain,
                    t_scalar_plain,
                    t_scalar_plain / t_simd_plain,
                    t_simd_qf,
                    t_scalar_qf,
                    t_scalar_qf / t_simd_qf);
    }

    return 0;
}
