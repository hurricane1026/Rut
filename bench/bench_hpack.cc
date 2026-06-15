// Benchmark: HTTP/2 HPACK + framing hot paths.
//
// Build:  ninja -C build bench_hpack
// Run:    ./build/bench/bench_hpack
//
// Establishes absolute throughput for the inbound h2 hot path: Huffman
// encode/decode, HPACK prefix integers, full header-block decode (what every
// request pays), response header encode, and frame-header parse. Numbers guard
// against regressions; see bench_http_parser for the HTTP/1 comparison pattern.

#include "bench.h"
#include "rut/runtime/hpack.h"
#include "rut/runtime/http2_frame.h"

extern "C" {
#include <nghttp2/nghttp2.h>  // NGHTTP2_STATICLIB comes from the nghttp2_ref target
}

using namespace rut;

namespace {

// A representative browser request header set.
const hpack::Header kReqHeaders[] = {
    {{":method", 7}, {"GET", 3}},
    {{":scheme", 7}, {"https", 5}},
    {{":authority", 10}, {"www.example.com", 15}},
    {{":path", 5}, {"/index.html", 11}},
    {{"user-agent", 10},
     {"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/120.0 Safari/537.36",
      90}},
    {{"accept", 6},
     {"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", 72}},
    {{"accept-encoding", 15}, {"gzip, deflate, br", 17}},
    {{"accept-language", 15}, {"en-US,en;q=0.9", 14}},
    {{"cookie", 6}, {"session=abc123def456; theme=dark; lang=en", 41}},
    {{"referer", 7}, {"https://www.example.com/", 24}},
};
constexpr u32 kReqHeaderCount = sizeof(kReqHeaders) / sizeof(kReqHeaders[0]);

// A typical response header set.
const hpack::Header kRespHeaders[] = {
    {{":status", 7}, {"200", 3}},
    {{"content-type", 12}, {"text/html; charset=utf-8", 24}},
    {{"content-length", 14}, {"4096", 4}},
    {{"server", 6}, {"rut", 3}},
    {{"date", 4}, {"Mon, 21 Oct 2013 20:13:21 GMT", 29}},
    {{"cache-control", 13}, {"max-age=3600", 12}},
};
constexpr u32 kRespHeaderCount = sizeof(kRespHeaders) / sizeof(kRespHeaders[0]);

u32 header_bytes(const hpack::Header* hs, u32 n) {
    u32 t = 0;
    for (u32 i = 0; i < n; i++) t += hs[i].name.len + hs[i].value.len;
    return t;
}

}  // namespace

int main() {
    bench::out("\n");

    // Encode the request header block once (this is what a peer sends us).
    static u8 req_block[4096];
    u32 req_block_len = 0;
    for (u32 i = 0; i < kReqHeaderCount; i++)
        req_block_len += hpack::encode_header(
            req_block + req_block_len, kReqHeaders[i].name, kReqHeaders[i].value);

    const char* const kLongValue =
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0 Safari/537.36";
    const u32 kLongLen = 90;
    static u8 huff_enc[256];
    u32 huff_len =
        hpack::huffman_encode(huff_enc, reinterpret_cast<const u8*>(kLongValue), kLongLen);

    // --- Huffman ---
    {
        bench::Bench b;
        b.title("HPACK Huffman (90-byte User-Agent token)");
        b.min_iterations(2000000);
        b.warmup(100000);
        b.print_header();

        b.bytes_per_op(kLongLen);
        b.run("huffman_encode", [&] {
            u8 out[256];
            u32 n = hpack::huffman_encode(out, reinterpret_cast<const u8*>(kLongValue), kLongLen);
            bench::do_not_optimize(&n);
            bench::do_not_optimize(out);
        });
        b.bytes_per_op(huff_len);
        b.run("huffman_decode", [&] {
            u8 out[256];
            i32 n = hpack::huffman_decode(out, sizeof(out), huff_enc, huff_len);
            bench::do_not_optimize(&n);
            bench::do_not_optimize(out);
        });
        bench::out("\n");
    }

    // --- Prefix integers ---
    {
        bench::Bench b;
        b.title("HPACK prefix integer");
        b.min_iterations(5000000);
        b.warmup(100000);
        b.print_header();
        u8 enc[8];
        u32 enc_n = hpack::encode_integer(enc, 1337, 5, 0x00);
        b.run("encode_integer(1337)", [&] {
            u8 out[8];
            u32 n = hpack::encode_integer(out, 1337, 5, 0x00);
            bench::do_not_optimize(&n);
            bench::do_not_optimize(out);
        });
        b.run("decode_integer(1337)", [&] {
            u32 v = 0;
            u32 n = hpack::decode_integer(enc, enc_n, 5, &v);
            bench::do_not_optimize(&n);
            bench::do_not_optimize(&v);
        });
        bench::out("\n");
    }

    // --- Header block decode (inbound hot path) ---
    {
        bench::Bench b;
        b.title("HPACK header block — 10-header browser request");
        b.min_iterations(1000000);
        b.warmup(50000);
        b.bytes_per_op(req_block_len);
        b.print_header();

        b.run("rut decode_header_block", [&] {
            hpack::DynamicTable dyn;
            dyn.init(4096);
            u8 scratch[4096];
            hpack::Header hs[64];
            u32 nh = 0;
            bool ok = hpack::decode_header_block(
                dyn, req_block, req_block_len, scratch, sizeof(scratch), hs, 64, &nh);
            bench::do_not_optimize(&ok);
            bench::do_not_optimize(&nh);
        });

        // nghttp2 baseline: reuse one inflater, reset per block via end_headers.
        nghttp2_hd_inflater* inf = nullptr;
        nghttp2_hd_inflate_new(&inf);
        b.run("nghttp2 inflate", [&] {
            const u8* in = req_block;
            size_t inlen = req_block_len;
            for (;;) {
                nghttp2_nv nv;
                int flags = 0;
                ssize_t rv = nghttp2_hd_inflate_hd2(inf, &nv, &flags, in, inlen, 1);
                if (rv < 0) break;
                in += rv;
                inlen -= static_cast<size_t>(rv);
                bench::do_not_optimize(&nv);
                if (flags & NGHTTP2_HD_INFLATE_FINAL) break;
                if (rv == 0 && inlen == 0) break;
            }
            nghttp2_hd_inflate_end_headers(inf);
        });
        nghttp2_hd_inflate_del(inf);
        b.compare();
        bench::out("  (block encodes to ");
        bench::out_u64(req_block_len);
        bench::out(" bytes; ");
        bench::out_u64(header_bytes(kReqHeaders, kReqHeaderCount));
        bench::out(" raw header bytes)\n\n");
    }

    // --- Response header encode (outbound hot path) ---
    {
        bench::Bench b;
        b.title("HPACK encode — 6-header response");
        b.min_iterations(1000000);
        b.warmup(50000);
        b.bytes_per_op(header_bytes(kRespHeaders, kRespHeaderCount));
        b.print_header();
        b.run("rut encode_header x6", [&] {
            u8 out[1024];
            u32 o = 0;
            for (u32 i = 0; i < kRespHeaderCount; i++)
                o += hpack::encode_header(out + o, kRespHeaders[i].name, kRespHeaders[i].value);
            bench::do_not_optimize(&o);
            bench::do_not_optimize(out);
        });

        // nghttp2 deflate baseline. NOTE: not strictly apples-to-apples — rut's
        // first-cut encoder is stateless (no dynamic-table indexing), while
        // nghttp2 indexes into its dynamic table after the first call, so it
        // does less work (and emits fewer bytes) in steady state.
        nghttp2_nv nva[kRespHeaderCount];
        for (u32 i = 0; i < kRespHeaderCount; i++) {
            nva[i].name = const_cast<u8*>(reinterpret_cast<const u8*>(kRespHeaders[i].name.ptr));
            nva[i].value = const_cast<u8*>(reinterpret_cast<const u8*>(kRespHeaders[i].value.ptr));
            nva[i].namelen = kRespHeaders[i].name.len;
            nva[i].valuelen = kRespHeaders[i].value.len;
            nva[i].flags = NGHTTP2_NV_FLAG_NONE;
        }
        nghttp2_hd_deflater* def = nullptr;
        nghttp2_hd_deflate_new(&def, 4096);
        b.run("nghttp2 deflate", [&] {
            u8 out[1024];
            ssize_t o = nghttp2_hd_deflate_hd(def, out, sizeof(out), nva, kRespHeaderCount);
            bench::do_not_optimize(&o);
            bench::do_not_optimize(out);
        });
        nghttp2_hd_deflate_del(def);
        b.compare();
        bench::out("\n");
    }

    // --- Frame header parse ---
    {
        bench::Bench b;
        b.title("HTTP/2 frame header");
        b.min_iterations(5000000);
        b.warmup(100000);
        b.print_header();
        u8 fh[kFrameHeaderSize];
        Http2FrameHeader h;
        h.length = 16384;
        h.type = static_cast<u8>(Http2FrameType::Data);
        h.flags = http2_flag::kEndStream;
        h.stream_id = 5;
        write_frame_header(fh, h);
        b.run("parse_frame_header", [&] {
            Http2FrameHeader out;
            ParseStatus s = parse_frame_header(fh, kFrameHeaderSize, &out);
            bench::do_not_optimize(&s);
            bench::do_not_optimize(&out);
        });
        bench::out("\n");
    }

    return 0;
}
