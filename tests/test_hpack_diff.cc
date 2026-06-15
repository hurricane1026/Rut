// Differential test: rut's HPACK codec vs nghttp2 (vendored reference).
//
// Two directions, the strongest correctness oracle we have:
//   1. rut encode  -> nghttp2 inflate  == original
//   2. nghttp2 deflate -> rut decode   == original   (exercises rut's decoder
//      on real-world compressed blocks: dynamic indexing + Huffman that
//      nghttp2's encoder emits)
// Plus a shared-dynamic-table sequence (nghttp2 encoder state vs rut decoder
// state must stay in sync across requests) and a randomized fuzz.

#include "rut/runtime/hpack.h"
#include "test.h"

extern "C" {
#include <nghttp2/nghttp2.h>  // NGHTTP2_STATICLIB comes from the nghttp2_ref target
}

using namespace rut;

namespace {

struct KV {
    const char* name;
    const char* value;
};

u32 slen(const char* s) {
    u32 n = 0;
    while (s[n]) n++;
    return n;
}

nghttp2_nv to_nv(const KV& kv) {
    nghttp2_nv nv;
    nv.name = reinterpret_cast<u8*>(const_cast<char*>(kv.name));
    nv.value = reinterpret_cast<u8*>(const_cast<char*>(kv.value));
    nv.namelen = slen(kv.name);
    nv.valuelen = slen(kv.value);
    nv.flags = NGHTTP2_NV_FLAG_NONE;
    return nv;
}

// Decode a header block with nghttp2; copy emitted (name,value) into out.
// Returns header count, or -1 on error.
i32 nghttp2_decode(const u8* block, u32 len, KV* out, char* arena, u32 arena_cap, u32 max_out) {
    nghttp2_hd_inflater* inf = nullptr;
    if (nghttp2_hd_inflate_new(&inf) != 0) return -1;
    const u8* in = block;
    size_t inlen = len;
    u32 nout = 0;
    u32 ap = 0;
    i32 result = -1;
    for (;;) {
        nghttp2_nv nv;
        int flags = 0;
        ssize_t rv = nghttp2_hd_inflate_hd2(inf, &nv, &flags, in, inlen, /*in_final=*/1);
        if (rv < 0) goto done;
        in += rv;
        inlen -= static_cast<size_t>(rv);
        if (flags & NGHTTP2_HD_INFLATE_EMIT) {
            if (nout >= max_out) goto done;
            if (ap + nv.namelen + nv.valuelen + 2 > arena_cap) goto done;
            char* nm = arena + ap;
            for (size_t i = 0; i < nv.namelen; i++) arena[ap++] = static_cast<char>(nv.name[i]);
            arena[ap++] = '\0';
            char* vl = arena + ap;
            for (size_t i = 0; i < nv.valuelen; i++) arena[ap++] = static_cast<char>(nv.value[i]);
            arena[ap++] = '\0';
            out[nout].name = nm;
            out[nout].value = vl;
            nout++;
        }
        if (flags & NGHTTP2_HD_INFLATE_FINAL) break;
        if (rv == 0 && inlen == 0) break;
    }
    nghttp2_hd_inflate_end_headers(inf);
    result = static_cast<i32>(nout);
done:
    nghttp2_hd_inflate_del(inf);
    return result;
}

bool kv_eq(const char* a, const char* b) {
    u32 i = 0;
    while (a[i] && b[i]) {
        if (a[i] != b[i]) return false;
        i++;
    }
    return a[i] == b[i];
}

bool hdr_eq_kv(const hpack::Header& h, const KV& kv) {
    return h.name.eq(Str{kv.name, slen(kv.name)}) && h.value.eq(Str{kv.value, slen(kv.value)});
}

}  // namespace

TEST(hpack_diff, our_encode_nghttp2_inflate) {
    const KV reqs[] = {
        {":method", "GET"},
        {":scheme", "https"},
        {":authority", "www.example.com"},
        {":path", "/index.html"},
        {"user-agent", "Mozilla/5.0 rut-test"},
        {"accept", "text/html,*/*;q=0.8"},
        {"x-custom-header", "some-arbitrary-value-123"},
    };
    constexpr u32 kN = sizeof(reqs) / sizeof(reqs[0]);

    u8 block[4096];
    u32 bp = 0;
    for (u32 i = 0; i < kN; i++)
        bp += hpack::encode_header(block + bp,
                                   Str{reqs[i].name, slen(reqs[i].name)},
                                   Str{reqs[i].value, slen(reqs[i].value)});

    KV out[32];
    char arena[4096];
    i32 n = nghttp2_decode(block, bp, out, arena, sizeof(arena), 32);
    REQUIRE(n == static_cast<i32>(kN));
    for (u32 i = 0; i < kN; i++) {
        CHECK(kv_eq(out[i].name, reqs[i].name));
        CHECK(kv_eq(out[i].value, reqs[i].value));
    }
}

TEST(hpack_diff, nghttp2_deflate_our_decode) {
    const KV reqs[] = {
        {":method", "POST"},
        {":scheme", "https"},
        {":authority", "api.example.com"},
        {":path", "/v1/resource?id=42"},
        {"content-type", "application/json"},
        {"content-length", "1024"},
        {"authorization", "Bearer abcdefghijklmnopqrstuvwxyz0123456789"},
        {"accept-encoding", "gzip, deflate, br"},
    };
    constexpr u32 kN = sizeof(reqs) / sizeof(reqs[0]);

    nghttp2_nv nva[kN];
    for (u32 i = 0; i < kN; i++) nva[i] = to_nv(reqs[i]);

    nghttp2_hd_deflater* def = nullptr;
    REQUIRE(nghttp2_hd_deflate_new(&def, 4096) == 0);
    u8 block[4096];
    size_t bound = nghttp2_hd_deflate_bound(def, nva, kN);
    REQUIRE(bound <= sizeof(block));
    ssize_t bp = nghttp2_hd_deflate_hd(def, block, sizeof(block), nva, kN);
    REQUIRE(bp > 0);

    hpack::DynamicTable dyn;
    dyn.init(4096);
    u8 scratch[8192];
    hpack::Header hs[64];
    u32 nh = 0;
    REQUIRE(hpack::decode_header_block(
        dyn, block, static_cast<u32>(bp), scratch, sizeof(scratch), hs, 64, &nh));
    REQUIRE(nh == kN);
    for (u32 i = 0; i < kN; i++) CHECK(hdr_eq_kv(hs[i], reqs[i]));

    nghttp2_hd_deflate_del(def);
}

TEST(hpack_diff, sequence_shared_dynamic_table) {
    // nghttp2 encoder keeps a dynamic table across requests; rut's decoder must
    // track the identical eviction/indexing decisions to stay in sync.
    nghttp2_hd_deflater* def = nullptr;
    REQUIRE(nghttp2_hd_deflate_new(&def, 4096) == 0);
    hpack::DynamicTable dyn;
    dyn.init(4096);

    const KV r1[] = {{":method", "GET"}, {":path", "/"}, {"cookie", "a=1; b=2"}};
    const KV r2[] = {{":method", "GET"}, {":path", "/"}, {"cookie", "a=1; b=2"}};  // all indexable
    const KV r3[] = {{":method", "GET"}, {":path", "/next"}, {"cookie", "a=1; b=2"}};
    const KV* reqs[] = {r1, r2, r3};
    const u32 counts[] = {3, 3, 3};

    for (u32 round = 0; round < 3; round++) {
        nghttp2_nv nva[8];
        for (u32 i = 0; i < counts[round]; i++) nva[i] = to_nv(reqs[round][i]);
        u8 block[2048];
        ssize_t bp = nghttp2_hd_deflate_hd(def, block, sizeof(block), nva, counts[round]);
        REQUIRE(bp > 0);
        u8 scratch[4096];
        hpack::Header hs[32];
        u32 nh = 0;
        REQUIRE(hpack::decode_header_block(
            dyn, block, static_cast<u32>(bp), scratch, sizeof(scratch), hs, 32, &nh));
        REQUIRE(nh == counts[round]);
        for (u32 i = 0; i < counts[round]; i++) CHECK(hdr_eq_kv(hs[i], reqs[round][i]));
    }
    nghttp2_hd_deflate_del(def);
}

namespace {
u32 g_rng = 0xdeadbeefu;
u32 rnd() {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}
}  // namespace

TEST(hpack_diff, fuzz_both_directions) {
    g_rng = 0x1f2e3d4cu;
    static char src[16384];  // backing store for generated name/value strings
    KV kvs[8];

    for (u32 iter = 0; iter < 500; iter++) {
        const u32 nh = 1 + (rnd() % 6);
        u32 sp = 0;
        bool fit = true;
        for (u32 i = 0; i < nh; i++) {
            const u32 nl = 1 + (rnd() % 16);
            const u32 vl = 1 + (rnd() % 48);
            if (sp + nl + vl + 2 > sizeof(src)) {
                fit = false;
                break;
            }
            char* nm = src + sp;
            for (u32 j = 0; j < nl; j++) src[sp++] = static_cast<char>('a' + (rnd() % 26));
            src[sp++] = '\0';
            char* vl_p = src + sp;
            // Printable values (nghttp2 validates header field values somewhat;
            // keep them clean so the differential is about HPACK, not validation).
            for (u32 j = 0; j < vl; j++) src[sp++] = static_cast<char>(0x20 + (rnd() % 0x5e));
            src[sp++] = '\0';
            kvs[i].name = nm;
            kvs[i].value = vl_p;
        }
        if (!fit) continue;

        // Direction A: rut encode -> nghttp2 inflate.
        u8 block[8192];
        u32 bp = 0;
        for (u32 i = 0; i < nh; i++)
            bp += hpack::encode_header(block + bp,
                                       Str{kvs[i].name, slen(kvs[i].name)},
                                       Str{kvs[i].value, slen(kvs[i].value)});
        KV out[8];
        char arena[8192];
        i32 dn = nghttp2_decode(block, bp, out, arena, sizeof(arena), 8);
        REQUIRE(dn == static_cast<i32>(nh));
        for (u32 i = 0; i < nh; i++) {
            CHECK(kv_eq(out[i].name, kvs[i].name));
            CHECK(kv_eq(out[i].value, kvs[i].value));
        }

        // Direction B: nghttp2 deflate -> rut decode.
        nghttp2_nv nva[8];
        for (u32 i = 0; i < nh; i++) nva[i] = to_nv(kvs[i]);
        nghttp2_hd_deflater* def = nullptr;
        REQUIRE(nghttp2_hd_deflate_new(&def, 4096) == 0);
        u8 nblock[8192];
        ssize_t nbp = nghttp2_hd_deflate_hd(def, nblock, sizeof(nblock), nva, nh);
        REQUIRE(nbp > 0);
        hpack::DynamicTable dyn;
        dyn.init(4096);
        u8 scratch[16384];
        hpack::Header hs[16];
        u32 dh = 0;
        REQUIRE(hpack::decode_header_block(
            dyn, nblock, static_cast<u32>(nbp), scratch, sizeof(scratch), hs, 16, &dh));
        REQUIRE(dh == nh);
        for (u32 i = 0; i < nh; i++) CHECK(hdr_eq_kv(hs[i], kvs[i]));
        nghttp2_hd_deflate_del(def);
    }
}

TEST(hpack_diff, our_indexing_encoder_vs_nghttp2_inflate) {
    // rut's stateful Encoder (dynamic indexing) must produce blocks nghttp2's
    // inflater decodes correctly across a multi-request sequence.
    const KV reqs[] = {
        {":method", "GET"},
        {":scheme", "https"},
        {":authority", "www.example.com"},
        {":path", "/"},
        {"cookie", "sid=abc123; theme=dark"},
        {"user-agent", "rut/1.0"},
    };
    constexpr u32 kN = sizeof(reqs) / sizeof(reqs[0]);

    hpack::Encoder enc;
    enc.init(4096);
    nghttp2_hd_inflater* inf = nullptr;
    REQUIRE(nghttp2_hd_inflate_new(&inf) == 0);

    for (u32 round = 0; round < 3; round++) {
        u8 block[1024];
        u32 bp = 0;
        for (u32 i = 0; i < kN; i++)
            bp += enc.encode(block + bp,
                             Str{reqs[i].name, slen(reqs[i].name)},
                             Str{reqs[i].value, slen(reqs[i].value)});
        // Decode this block with nghttp2.
        KV out[16];
        char arena[2048];
        u32 nout = 0;
        u32 ap = 0;
        const u8* in = block;
        size_t inlen = bp;
        bool ok = true;
        for (;;) {
            nghttp2_nv nv;
            int flags = 0;
            ssize_t rv = nghttp2_hd_inflate_hd2(inf, &nv, &flags, in, inlen, 1);
            if (rv < 0) {
                ok = false;
                break;
            }
            in += rv;
            inlen -= static_cast<size_t>(rv);
            if (flags & NGHTTP2_HD_INFLATE_EMIT) {
                char* nm = arena + ap;
                for (size_t k = 0; k < nv.namelen; k++) arena[ap++] = static_cast<char>(nv.name[k]);
                arena[ap++] = '\0';
                char* vl = arena + ap;
                for (size_t k = 0; k < nv.valuelen; k++)
                    arena[ap++] = static_cast<char>(nv.value[k]);
                arena[ap++] = '\0';
                out[nout].name = nm;
                out[nout].value = vl;
                nout++;
            }
            if (flags & NGHTTP2_HD_INFLATE_FINAL) break;
            if (rv == 0 && inlen == 0) break;
        }
        nghttp2_hd_inflate_end_headers(inf);
        REQUIRE(ok);
        REQUIRE(nout == kN);
        for (u32 i = 0; i < kN; i++) {
            CHECK(kv_eq(out[i].name, reqs[i].name));
            CHECK(kv_eq(out[i].value, reqs[i].value));
        }
    }
    nghttp2_hd_inflate_del(inf);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
