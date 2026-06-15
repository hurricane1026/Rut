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

// === Header field representations: decode / encode (RFC 7541 §6, App. C) ===

namespace {
u32 cstr_len(const char* s) {
    u32 n = 0;
    while (s[n]) n++;
    return n;
}
bool hdr_is(const hpack::Header& h, const char* name, const char* value) {
    return h.name.eq(Str{name, cstr_len(name)}) && h.value.eq(Str{value, cstr_len(value)});
}
Str cstr(const char* s) {
    return Str{s, cstr_len(s)};
}
}  // namespace

TEST(hpack_decode, c2_1_literal_incremental) {
    // C.2.1: custom-key: custom-header, added to the dynamic table.
    const u8 block[] = {0x40, 0x0a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y', 0x0d,
                        'c',  'u',  's', 't', 'o', 'm', '-', 'h', 'e', 'a', 'd', 'e', 'r'};
    hpack::DynamicTable dyn;
    dyn.init(4096);
    u8 out[256];
    hpack::Header hs[8];
    u32 n = 0;
    REQUIRE(hpack::decode_header_block(dyn, block, sizeof(block), out, sizeof(out), hs, 8, &n));
    CHECK_EQ(n, 1u);
    CHECK(hdr_is(hs[0], "custom-key", "custom-header"));
    CHECK_EQ(dyn.nent, 1u);
    CHECK_EQ(dyn.table_size, 10u + 13u + 32u);  // 55
}

TEST(hpack_decode, c2_4_indexed) {
    // C.2.4: 0x82 -> :method: GET (static index 2).
    const u8 block[] = {0x82};
    hpack::DynamicTable dyn;
    dyn.init(4096);
    u8 out[64];
    hpack::Header hs[4];
    u32 n = 0;
    REQUIRE(hpack::decode_header_block(dyn, block, sizeof(block), out, sizeof(out), hs, 4, &n));
    CHECK_EQ(n, 1u);
    CHECK(hdr_is(hs[0], ":method", "GET"));
}

TEST(hpack_decode, c3_request_sequence_shared_context) {
    // C.3.1/3.2/3.3: three requests sharing one decoding context. The dynamic
    // table built by earlier requests is referenced by later ones.
    hpack::DynamicTable dyn;
    dyn.init(4096);
    u8 out[512];
    hpack::Header hs[16];
    u32 n = 0;

    // C.3.1
    const u8 b1[] = {0x82, 0x86, 0x84, 0x41, 0x0f, 'w', 'w', 'w', '.', 'e',
                     'x',  'a',  'm',  'p',  'l',  'e', '.', 'c', 'o', 'm'};
    REQUIRE(hpack::decode_header_block(dyn, b1, sizeof(b1), out, sizeof(out), hs, 16, &n));
    CHECK_EQ(n, 4u);
    CHECK(hdr_is(hs[0], ":method", "GET"));
    CHECK(hdr_is(hs[1], ":scheme", "http"));
    CHECK(hdr_is(hs[2], ":path", "/"));
    CHECK(hdr_is(hs[3], ":authority", "www.example.com"));
    CHECK_EQ(dyn.nent, 1u);

    // C.3.2: 0xbe references dynamic[1] (:authority www.example.com); adds
    // cache-control: no-cache.
    const u8 b2[] = {0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 'n', 'o', '-', 'c', 'a', 'c', 'h', 'e'};
    REQUIRE(hpack::decode_header_block(dyn, b2, sizeof(b2), out, sizeof(out), hs, 16, &n));
    CHECK_EQ(n, 5u);
    CHECK(hdr_is(hs[3], ":authority", "www.example.com"));
    CHECK(hdr_is(hs[4], "cache-control", "no-cache"));
    CHECK_EQ(dyn.nent, 2u);

    // C.3.3: custom-key: custom-value (literal name), plus indexed lookups.
    const u8 b3[] = {0x82, 0x87, 0x85, 0xbf, 0x40, 0x0a, 'c',  'u', 's', 't',
                     'o',  'm',  '-',  'k',  'e',  'y',  0x0c, 'c', 'u', 's',
                     't',  'o',  'm',  '-',  'v',  'a',  'l',  'u', 'e'};
    REQUIRE(hpack::decode_header_block(dyn, b3, sizeof(b3), out, sizeof(out), hs, 16, &n));
    CHECK_EQ(n, 5u);
    CHECK(hdr_is(hs[0], ":method", "GET"));
    CHECK(hdr_is(hs[1], ":scheme", "https"));
    CHECK(hdr_is(hs[2], ":path", "/index.html"));
    CHECK(hdr_is(hs[3], ":authority", "www.example.com"));
    CHECK(hdr_is(hs[4], "custom-key", "custom-value"));
    CHECK_EQ(dyn.nent, 3u);
}

TEST(hpack_decode, huffman_literal_value) {
    // Literal incremental, name index 1 (:authority), Huffman value
    // "www.example.com" (C.4.1 payload). H bit set, length 12.
    const u8 block[] = {
        0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
    hpack::DynamicTable dyn;
    dyn.init(4096);
    u8 out[64];
    hpack::Header hs[4];
    u32 n = 0;
    REQUIRE(hpack::decode_header_block(dyn, block, sizeof(block), out, sizeof(out), hs, 4, &n));
    CHECK_EQ(n, 1u);
    CHECK(hdr_is(hs[0], ":authority", "www.example.com"));
}

TEST(hpack_decode, size_update_evicts) {
    hpack::DynamicTable dyn;
    dyn.init(4096);
    u8 out[256];
    hpack::Header hs[4];
    u32 n = 0;
    // Add custom-key: custom-header (size 55).
    const u8 add[] = {0x40, 0x0a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y', 0x0d,
                      'c',  'u',  's', 't', 'o', 'm', '-', 'h', 'e', 'a', 'd', 'e', 'r'};
    REQUIRE(hpack::decode_header_block(dyn, add, sizeof(add), out, sizeof(out), hs, 4, &n));
    CHECK_EQ(dyn.nent, 1u);
    // A size update to 0 (0x20) must evict everything.
    const u8 shrink[] = {0x20};
    REQUIRE(hpack::decode_header_block(dyn, shrink, sizeof(shrink), out, sizeof(out), hs, 4, &n));
    CHECK_EQ(n, 0u);
    CHECK_EQ(dyn.nent, 0u);
}

TEST(hpack_decode, eviction_drops_oldest) {
    hpack::DynamicTable dyn;
    dyn.init(60);  // room for one ~55-octet entry
    u8 out[256];
    hpack::Header hs[4];
    u32 n = 0;
    const u8 a[] = {0x40, 0x0a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y', 0x0d,
                    'c',  'u',  's', 't', 'o', 'm', '-', 'h', 'e', 'a', 'd', 'e', 'r'};  // 55
    REQUIRE(hpack::decode_header_block(dyn, a, sizeof(a), out, sizeof(out), hs, 4, &n));
    const u8 b[] = {0x40, 0x0a, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y', 0x0c,
                    'c',  'u',  's', 't', 'o', 'm', '-', 'v', 'a', 'l', 'u', 'e'};  // 54
    REQUIRE(hpack::decode_header_block(dyn, b, sizeof(b), out, sizeof(out), hs, 4, &n));
    CHECK_EQ(dyn.nent, 1u);  // A evicted to fit B
    // Index 62 = newest = B.
    const u8 ref62[] = {0xbe};
    REQUIRE(hpack::decode_header_block(dyn, ref62, sizeof(ref62), out, sizeof(out), hs, 4, &n));
    CHECK(hdr_is(hs[0], "custom-key", "custom-value"));
    // Index 63 no longer exists -> decode error.
    const u8 ref63[] = {0xbf};
    CHECK_FALSE(hpack::decode_header_block(dyn, ref63, sizeof(ref63), out, sizeof(out), hs, 4, &n));
}

TEST(hpack_decode, bad_index_is_error) {
    hpack::DynamicTable dyn;
    dyn.init(4096);
    u8 out[64];
    hpack::Header hs[4];
    u32 n = 0;
    const u8 block[] = {0xff, 0x00};  // indexed, index 62 with empty dynamic table
    CHECK_FALSE(hpack::decode_header_block(dyn, block, sizeof(block), out, sizeof(out), hs, 4, &n));
}

TEST(hpack_encode, exact_static_match_is_indexed) {
    u8 out[32];
    u32 n = hpack::encode_header(out, cstr(":method"), cstr("GET"));
    CHECK_EQ(n, 1u);
    CHECK_EQ(out[0], 0x82);
}

TEST(hpack_encode, roundtrip_static_name) {
    u8 out[64];
    u32 n = hpack::encode_header(out, cstr(":path"), cstr("/sample/path"));
    CHECK((out[0] & 0xf0) == 0x00);  // literal without indexing
    hpack::DynamicTable dyn;
    dyn.init(4096);
    u8 dbuf[64];
    hpack::Header hs[4];
    u32 c = 0;
    REQUIRE(hpack::decode_header_block(dyn, out, n, dbuf, sizeof(dbuf), hs, 4, &c));
    CHECK_EQ(c, 1u);
    CHECK(hdr_is(hs[0], ":path", "/sample/path"));
}

TEST(hpack_encode, roundtrip_literal_name_and_value) {
    u8 out[64];
    u32 n = hpack::encode_header(out, cstr("x-custom"), cstr("a-value"));
    hpack::DynamicTable dyn;
    dyn.init(4096);
    u8 dbuf[64];
    hpack::Header hs[4];
    u32 c = 0;
    REQUIRE(hpack::decode_header_block(dyn, out, n, dbuf, sizeof(dbuf), hs, 4, &c));
    CHECK_EQ(c, 1u);
    CHECK(hdr_is(hs[0], "x-custom", "a-value"));
    CHECK_EQ(dyn.nent, 0u);  // encoder never indexes -> decoder adds nothing
}

// === Deterministic round-trip fuzz (encode -> decode equality) ===

namespace {
u32 g_rng = 0x12345678u;
u32 next_rng() {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}
}  // namespace

TEST(hpack_fuzz, encode_decode_roundtrip) {
    g_rng = 0x9e3779b9u;
    u8 src[8192];  // generated header bytes
    u8 block[16384];
    u8 scratch[16384];
    hpack::Header out[64];

    for (u32 iter = 0; iter < 2000; iter++) {
        const u32 nh = 1 + (next_rng() % 8);
        // Generate `nh` headers into src, recording offsets.
        u32 sp = 0;
        u32 noff[8], nlen[8], voff[8], vlen[8];
        bool fit = true;
        for (u32 i = 0; i < nh; i++) {
            const u32 nl = 1 + (next_rng() % 20);
            const u32 vl = next_rng() % 60;
            if (sp + nl + vl > sizeof(src)) {
                fit = false;
                break;
            }
            noff[i] = sp;
            nlen[i] = nl;
            // Names: printable, lowercase-ish (avoids ':' pseudo-header ambiguity).
            for (u32 j = 0; j < nl; j++) src[sp++] = static_cast<u8>('a' + (next_rng() % 26));
            voff[i] = sp;
            vlen[i] = vl;
            // Values: full octet range to stress Huffman.
            for (u32 j = 0; j < vl; j++) src[sp++] = static_cast<u8>(next_rng() & 0xff);
        }
        if (!fit) continue;

        // Encode all headers into one block.
        u32 bp = 0;
        for (u32 i = 0; i < nh; i++) {
            const Str name{reinterpret_cast<const char*>(src + noff[i]), nlen[i]};
            const Str value{reinterpret_cast<const char*>(src + voff[i]), vlen[i]};
            bp += hpack::encode_header(block + bp, name, value);
        }

        hpack::DynamicTable dyn;
        dyn.init(4096);
        u32 dn = 0;
        REQUIRE(hpack::decode_header_block(dyn, block, bp, scratch, sizeof(scratch), out, 64, &dn));
        REQUIRE(dn == nh);
        for (u32 i = 0; i < nh; i++) {
            const Str name{reinterpret_cast<const char*>(src + noff[i]), nlen[i]};
            const Str value{reinterpret_cast<const char*>(src + voff[i]), vlen[i]};
            CHECK(out[i].name.eq(name));
            CHECK(out[i].value.eq(value));
        }
    }
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
