// Tests for the HPACK primitives (src/runtime/hpack.cc): prefix integers,
// Huffman coding, and string literals (RFC 7541 §5). Validated against the
// official examples in RFC 7541 Appendix C plus structural round-trips that
// exercise every Huffman symbol.

#include "rut/runtime/hpack.h"
#include "test.h"

using namespace rut;

namespace {
bool bytes_eq(const u8* a, const u8* b, u32 n) {
    for (u32 i = 0; i < n; i++)
        if (a[i] != b[i]) return false;
    return true;
}
}  // namespace

// === Prefix integers (RFC 7541 §5.1, examples C.1) ===

TEST(hpack_int, c1_1_small_value_5bit) {
    // C.1.1: 10 encoded with a 5-bit prefix fits in the prefix → 0x0a.
    u8 buf[8];
    u32 n = hpack::encode_integer(buf, 10, 5, 0x00);
    CHECK_EQ(n, 1u);
    CHECK_EQ(buf[0], 0x0a);
    u32 v = 0;
    CHECK_EQ(hpack::decode_integer(buf, n, 5, &v), 1u);
    CHECK_EQ(v, 10u);
}

TEST(hpack_int, c1_2_multibyte_5bit) {
    // C.1.2: 1337 with a 5-bit prefix → 0x1f 0x9a 0x0a.
    u8 buf[8];
    u32 n = hpack::encode_integer(buf, 1337, 5, 0x00);
    CHECK_EQ(n, 3u);
    const u8 want[] = {0x1f, 0x9a, 0x0a};
    CHECK(bytes_eq(buf, want, 3));
    u32 v = 0;
    CHECK_EQ(hpack::decode_integer(buf, n, 5, &v), 3u);
    CHECK_EQ(v, 1337u);
}

TEST(hpack_int, c1_3_full_byte_prefix) {
    // C.1.3: 42 with an 8-bit prefix → 0x2a.
    u8 buf[8];
    u32 n = hpack::encode_integer(buf, 42, 8, 0x00);
    CHECK_EQ(n, 1u);
    CHECK_EQ(buf[0], 0x2a);
    u32 v = 0;
    CHECK_EQ(hpack::decode_integer(buf, n, 8, &v), 1u);
    CHECK_EQ(v, 42u);
}

TEST(hpack_int, prefix_flag_bits_preserved) {
    // The high (8 - prefix_bits) bits carry representation flags untouched.
    u8 buf[8];
    u32 n = hpack::encode_integer(buf, 2, 6, 0xc0);
    CHECK_EQ(n, 1u);
    CHECK_EQ(buf[0], 0xc2);
    u32 v = 0;
    CHECK_EQ(hpack::decode_integer(buf, n, 6, &v), 1u);
    CHECK_EQ(v, 2u);
}

TEST(hpack_int, roundtrip_boundaries) {
    const u32 vals[] = {0, 30, 31, 32, 127, 128, 16383, 16384, 0xfffffffeu, 0xffffffffu};
    for (u32 k = 0; k < sizeof(vals) / sizeof(vals[0]); k++) {
        u8 buf[8];
        u32 n = hpack::encode_integer(buf, vals[k], 5, 0x00);
        u32 v = 0;
        CHECK_EQ(hpack::decode_integer(buf, n, 5, &v), n);
        CHECK_EQ(v, vals[k]);
    }
}

TEST(hpack_int, decode_truncated_is_error) {
    // First octet says "continuation follows" but no more bytes.
    u8 buf[1] = {0x1f};
    u32 v = 0;
    CHECK_EQ(hpack::decode_integer(buf, 1, 5, &v), 0u);
}

TEST(hpack_int, decode_overflow_is_error) {
    // A continuation that pushes the value past 32 bits must fail.
    u8 buf[] = {0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x10};
    u32 v = 0;
    CHECK_EQ(hpack::decode_integer(buf, sizeof(buf), 5, &v), 0u);
}

// === Huffman (RFC 7541 §5.2 / App. B, examples C.4 / C.6) ===

TEST(hpack_huffman, every_symbol_roundtrips) {
    // Encoding then decoding each byte must reproduce it — proves every code in
    // the table decodes uniquely (no trie collisions).
    for (u32 s = 0; s < 256; s++) {
        const u8 in = static_cast<u8>(s);
        u8 enc[8];
        u32 n = hpack::huffman_encode(enc, &in, 1);
        u8 dec[8];
        i32 d = hpack::huffman_decode(dec, sizeof(dec), enc, n);
        CHECK_EQ(d, 1);
        CHECK_EQ(dec[0], in);
    }
}

TEST(hpack_huffman, all_bytes_stream_roundtrips) {
    u8 all[256];
    for (u32 i = 0; i < 256; i++) all[i] = static_cast<u8>(i);
    u8 enc[1024];
    u32 n = hpack::huffman_encode(enc, all, 256);
    u8 dec[256];
    i32 d = hpack::huffman_decode(dec, sizeof(dec), enc, n);
    CHECK_EQ(d, 256);
    CHECK(bytes_eq(dec, all, 256));
}

TEST(hpack_huffman, rfc_c4_1_www_example_com) {
    const char* s = "www.example.com";
    const u8 want[] = {0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    u8 enc[32];
    u32 n = hpack::huffman_encode(enc, reinterpret_cast<const u8*>(s), 15);
    CHECK_EQ(n, sizeof(want));
    CHECK(bytes_eq(enc, want, n));
    u8 dec[32];
    i32 d = hpack::huffman_decode(dec, sizeof(dec), want, sizeof(want));
    CHECK_EQ(d, 15);
    CHECK(bytes_eq(dec, reinterpret_cast<const u8*>(s), 15));
}

TEST(hpack_huffman, rfc_c4_2_no_cache) {
    const char* s = "no-cache";
    const u8 want[] = {0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf};
    u8 enc[16];
    u32 n = hpack::huffman_encode(enc, reinterpret_cast<const u8*>(s), 8);
    CHECK_EQ(n, sizeof(want));
    CHECK(bytes_eq(enc, want, n));
}

TEST(hpack_huffman, rfc_c6_1_private) {
    const char* s = "private";
    const u8 want[] = {0xae, 0xc3, 0x77, 0x1a, 0x4b};
    u8 enc[16];
    u32 n = hpack::huffman_encode(enc, reinterpret_cast<const u8*>(s), 7);
    CHECK_EQ(n, sizeof(want));
    CHECK(bytes_eq(enc, want, n));
    u8 dec[16];
    i32 d = hpack::huffman_decode(dec, sizeof(dec), want, sizeof(want));
    CHECK_EQ(d, 7);
    CHECK(bytes_eq(dec, reinterpret_cast<const u8*>(s), 7));
}

TEST(hpack_huffman, decode_eos_symbol_is_error) {
    // EOS code is 0x3fffffff/30 bits; a buffer of all-1 bits forms it and must
    // be rejected (EOS may not appear as a decoded symbol).
    const u8 buf[] = {0xff, 0xff, 0xff, 0xff, 0xff};
    u8 dec[16];
    CHECK_EQ(hpack::huffman_decode(dec, sizeof(dec), buf, sizeof(buf)), -1);
}

TEST(hpack_huffman, decode_overflow_is_error) {
    const u8 want[] = {0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    u8 dec[4];  // too small for "www.example.com"
    CHECK_EQ(hpack::huffman_decode(dec, sizeof(dec), want, sizeof(want)), -1);
}

// === String literals (RFC 7541 §5.2) ===

TEST(hpack_string, plain_roundtrip) {
    const char* s = "custom-key";
    u8 enc[32];
    u32 n = hpack::encode_string(enc, reinterpret_cast<const u8*>(s), 10);
    u8 out[32];
    u32 out_len = 0;
    u32 consumed = hpack::decode_string(enc, n, out, sizeof(out), &out_len);
    CHECK_EQ(consumed, n);
    CHECK_EQ(out_len, 10u);
    CHECK(bytes_eq(out, reinterpret_cast<const u8*>(s), 10));
}

TEST(hpack_string, chooses_huffman_when_shorter) {
    // "www.example.com" is 15 raw but 12 Huffman → encoder sets the H bit.
    const char* s = "www.example.com";
    u8 enc[32];
    u32 n = hpack::encode_string(enc, reinterpret_cast<const u8*>(s), 15);
    CHECK((enc[0] & 0x80) != 0);   // H flag set
    CHECK_EQ(enc[0] & 0x7f, 12u);  // Huffman length
    CHECK_EQ(n, 13u);              // 1 header + 12 payload
    u8 out[32];
    u32 out_len = 0;
    CHECK_EQ(hpack::decode_string(enc, n, out, sizeof(out), &out_len), n);
    CHECK_EQ(out_len, 15u);
    CHECK(bytes_eq(out, reinterpret_cast<const u8*>(s), 15));
}

TEST(hpack_string, decode_truncated_payload_is_error) {
    // Header claims length 5 but only 2 payload bytes follow.
    const u8 buf[] = {0x05, 'a', 'b'};
    u8 out[16];
    u32 out_len = 0;
    CHECK_EQ(hpack::decode_string(buf, sizeof(buf), out, sizeof(out), &out_len), 0u);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
