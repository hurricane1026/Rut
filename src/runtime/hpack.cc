#include "rut/runtime/hpack.h"

namespace rut::hpack {

namespace {

// HPACK Huffman code table (RFC 7541 Appendix B), indexed by symbol 0..256.
// code = the bit pattern (right-aligned), bits = its length. Symbol 256 is EOS.
struct HuffCode {
    u32 code;
    u8 bits;
};

constexpr u32 kSymCount = 257;  // 0..255 + EOS

constexpr HuffCode kHuff[kSymCount] = {
    {0x1ff8, 13},     {0x7fffd8, 23},   {0xfffffe2, 28},  {0xfffffe3, 28},  {0xfffffe4, 28},
    {0xfffffe5, 28},  {0xfffffe6, 28},  {0xfffffe7, 28},  {0xfffffe8, 28},  {0xffffea, 24},
    {0x3ffffffc, 30}, {0xfffffe9, 28},  {0xfffffea, 28},  {0x3ffffffd, 30}, {0xfffffeb, 28},
    {0xfffffec, 28},  {0xfffffed, 28},  {0xfffffee, 28},  {0xfffffef, 28},  {0xffffff0, 28},
    {0xffffff1, 28},  {0xffffff2, 28},  {0x3ffffffe, 30}, {0xffffff3, 28},  {0xffffff4, 28},
    {0xffffff5, 28},  {0xffffff6, 28},  {0xffffff7, 28},  {0xffffff8, 28},  {0xffffff9, 28},
    {0xffffffa, 28},  {0xffffffb, 28},  {0x14, 6},        {0x3f8, 10},      {0x3f9, 10},
    {0xffa, 12},      {0x1ff9, 13},     {0x15, 6},        {0xf8, 8},        {0x7fa, 11},
    {0x3fa, 10},      {0x3fb, 10},      {0xf9, 8},        {0x7fb, 11},      {0xfa, 8},
    {0x16, 6},        {0x17, 6},        {0x18, 6},        {0x0, 5},         {0x1, 5},
    {0x2, 5},         {0x19, 6},        {0x1a, 6},        {0x1b, 6},        {0x1c, 6},
    {0x1d, 6},        {0x1e, 6},        {0x1f, 6},        {0x5c, 7},        {0xfb, 8},
    {0x7ffc, 15},     {0x20, 6},        {0xffb, 12},      {0x3fc, 10},      {0x1ffa, 13},
    {0x21, 6},        {0x5d, 7},        {0x5e, 7},        {0x5f, 7},        {0x60, 7},
    {0x61, 7},        {0x62, 7},        {0x63, 7},        {0x64, 7},        {0x65, 7},
    {0x66, 7},        {0x67, 7},        {0x68, 7},        {0x69, 7},        {0x6a, 7},
    {0x6b, 7},        {0x6c, 7},        {0x6d, 7},        {0x6e, 7},        {0x6f, 7},
    {0x70, 7},        {0x71, 7},        {0x72, 7},        {0xfc, 8},        {0x73, 7},
    {0xfd, 8},        {0x1ffb, 13},     {0x7fff0, 19},    {0x1ffc, 13},     {0x3ffc, 14},
    {0x22, 6},        {0x7ffd, 15},     {0x3, 5},         {0x23, 6},        {0x4, 5},
    {0x24, 6},        {0x5, 5},         {0x25, 6},        {0x26, 6},        {0x27, 6},
    {0x6, 5},         {0x74, 7},        {0x75, 7},        {0x28, 6},        {0x29, 6},
    {0x2a, 6},        {0x7, 5},         {0x2b, 6},        {0x76, 7},        {0x2c, 6},
    {0x8, 5},         {0x9, 5},         {0x2d, 6},        {0x77, 7},        {0x78, 7},
    {0x79, 7},        {0x7a, 7},        {0x7b, 7},        {0x7ffe, 15},     {0x7fc, 11},
    {0x3ffd, 14},     {0x1ffd, 13},     {0xffffffc, 28},  {0xfffe6, 20},    {0x3fffd2, 22},
    {0xfffe7, 20},    {0xfffe8, 20},    {0x3fffd3, 22},   {0x3fffd4, 22},   {0x3fffd5, 22},
    {0x7fffd9, 23},   {0x3fffd6, 22},   {0x7fffda, 23},   {0x7fffdb, 23},   {0x7fffdc, 23},
    {0x7fffdd, 23},   {0x7fffde, 23},   {0xffffeb, 24},   {0x7fffdf, 23},   {0xffffec, 24},
    {0xffffed, 24},   {0x3fffd7, 22},   {0x7fffe0, 23},   {0xffffee, 24},   {0x7fffe1, 23},
    {0x7fffe2, 23},   {0x7fffe3, 23},   {0x7fffe4, 23},   {0x1fffdc, 21},   {0x3fffd8, 22},
    {0x7fffe5, 23},   {0x3fffd9, 22},   {0x7fffe6, 23},   {0x7fffe7, 23},   {0xffffef, 24},
    {0x3fffda, 22},   {0x1fffdd, 21},   {0xfffe9, 20},    {0x3fffdb, 22},   {0x3fffdc, 22},
    {0x7fffe8, 23},   {0x7fffe9, 23},   {0x1fffde, 21},   {0x7fffea, 23},   {0x3fffdd, 22},
    {0x3fffde, 22},   {0xfffff0, 24},   {0x1fffdf, 21},   {0x3fffdf, 22},   {0x7fffeb, 23},
    {0x7fffec, 23},   {0x1fffe0, 21},   {0x1fffe1, 21},   {0x3fffe0, 22},   {0x1fffe2, 21},
    {0x7fffed, 23},   {0x3fffe1, 22},   {0x7fffee, 23},   {0x7fffef, 23},   {0xfffea, 20},
    {0x3fffe2, 22},   {0x3fffe3, 22},   {0x3fffe4, 22},   {0x7ffff0, 23},   {0x3fffe5, 22},
    {0x3fffe6, 22},   {0x7ffff1, 23},   {0x3ffffe0, 26},  {0x3ffffe1, 26},  {0xfffeb, 20},
    {0x7fff1, 19},    {0x3fffe7, 22},   {0x7ffff2, 23},   {0x3fffe8, 22},   {0x1ffffec, 25},
    {0x3ffffe2, 26},  {0x3ffffe3, 26},  {0x3ffffe4, 26},  {0x7ffffde, 27},  {0x7ffffdf, 27},
    {0x3ffffe5, 26},  {0xfffff1, 24},   {0x1ffffed, 25},  {0x7fff2, 19},    {0x1fffe3, 21},
    {0x3ffffe6, 26},  {0x7ffffe0, 27},  {0x7ffffe1, 27},  {0x3ffffe7, 26},  {0x7ffffe2, 27},
    {0xfffff2, 24},   {0x1fffe4, 21},   {0x1fffe5, 21},   {0x3ffffe8, 26},  {0x3ffffe9, 26},
    {0xffffffd, 28},  {0x7ffffe3, 27},  {0x7ffffe4, 27},  {0x7ffffe5, 27},  {0xfffec, 20},
    {0xfffff3, 24},   {0xfffed, 20},    {0x1fffe6, 21},   {0x3fffe9, 22},   {0x1fffe7, 21},
    {0x1fffe8, 21},   {0x7ffff3, 23},   {0x3fffea, 22},   {0x3fffeb, 22},   {0x1ffffee, 25},
    {0x1ffffef, 25},  {0xfffff4, 24},   {0xfffff5, 24},   {0x3ffffea, 26},  {0x7ffff4, 23},
    {0x3ffffeb, 26},  {0x7ffffe6, 27},  {0x3ffffec, 26},  {0x3ffffed, 26},  {0x7ffffe7, 27},
    {0x7ffffe8, 27},  {0x7ffffe9, 27},  {0x7ffffea, 27},  {0x7ffffeb, 27},  {0xffffffe, 28},
    {0x7ffffec, 27},  {0x7ffffed, 27},  {0x7ffffee, 27},  {0x7ffffef, 27},  {0x7fffff0, 27},
    {0x3ffffee, 26},  {0x3fffffff, 30},
};

constexpr u32 kEosSym = 256;

// Compile-time decode trie. Each node has two children (bit 0 / bit 1); a leaf
// stores its symbol. Built once at compile time from kHuff — no runtime init,
// no allocation, inherently thread-safe (read-only).
constexpr u32 kMaxNodes = 600;  // <= 2*257-1 internal+leaf nodes
struct HuffTrie {
    i16 child[kMaxNodes][2];
    i16 sym[kMaxNodes];
    u16 node_count;
};

constexpr HuffTrie build_trie() {
    HuffTrie t{};
    for (u32 i = 0; i < kMaxNodes; i++) {
        t.child[i][0] = -1;
        t.child[i][1] = -1;
        t.sym[i] = -1;
    }
    t.node_count = 1;  // node 0 = root
    for (u32 s = 0; s < kSymCount; s++) {
        const u32 kCode = kHuff[s].code;
        const u8 kBits = kHuff[s].bits;
        i16 node = 0;
        for (i32 b = kBits - 1; b >= 0; b--) {
            const u32 kBit = (kCode >> static_cast<u32>(b)) & 1u;
            if (t.child[node][kBit] < 0) {
                t.child[node][kBit] = static_cast<i16>(t.node_count);
                t.node_count++;
            }
            node = t.child[node][kBit];
        }
        t.sym[node] = static_cast<i16>(s);
    }
    return t;
}

constexpr HuffTrie kTrie = build_trie();

}  // namespace

u32 decode_integer(const u8* in, u32 len, u8 prefix_bits, u32* out) {
    if (len == 0) return 0;
    const u32 kMask = (1u << prefix_bits) - 1u;
    u32 value = in[0] & kMask;
    if (value < kMask) {
        *out = value;
        return 1;
    }
    // Continuation octets: 7 bits each, low-order first; high bit = "more".
    u64 acc = kMask;
    u32 shift = 0;
    u32 i = 1;
    while (true) {
        if (i >= len) return 0;  // truncated
        const u8 kB = in[i++];
        acc += static_cast<u64>(kB & 0x7f) << shift;
        if (acc > 0xffffffffull) return 0;  // exceeds 32 bits
        if ((kB & 0x80) == 0) break;
        shift += 7;
        if (shift > 28) return 0;  // would overflow on next octet
    }
    *out = static_cast<u32>(acc);
    return i;
}

u32 encode_integer(u8* out, u32 value, u8 prefix_bits, u8 prefix_top) {
    const u32 kMask = (1u << prefix_bits) - 1u;
    if (value < kMask) {
        out[0] = static_cast<u8>(prefix_top | value);
        return 1;
    }
    out[0] = static_cast<u8>(prefix_top | kMask);
    value -= kMask;
    u32 i = 1;
    while (value >= 128) {
        out[i++] = static_cast<u8>((value & 0x7f) | 0x80);
        value >>= 7;
    }
    out[i++] = static_cast<u8>(value);
    return i;
}

u32 huffman_encoded_len(const u8* src, u32 len) {
    u64 bits = 0;
    for (u32 i = 0; i < len; i++) bits += kHuff[src[i]].bits;
    return static_cast<u32>((bits + 7) / 8);
}

u32 huffman_encode(u8* out, const u8* src, u32 len) {
    u64 acc = 0;    // bit accumulator, MSB-first
    u32 nbits = 0;  // valid bits in acc
    u32 o = 0;
    for (u32 i = 0; i < len; i++) {
        const HuffCode kEntry = kHuff[src[i]];
        acc = (acc << kEntry.bits) | kEntry.code;
        nbits += kEntry.bits;
        while (nbits >= 8) {
            nbits -= 8;
            out[o++] = static_cast<u8>((acc >> nbits) & 0xff);
        }
    }
    if (nbits > 0) {
        // Pad the remaining bits with the EOS prefix (all 1s) to an octet.
        const u32 kPad = 8 - nbits;
        acc = (acc << kPad) | ((1u << kPad) - 1u);
        out[o++] = static_cast<u8>(acc & 0xff);
    }
    return o;
}

i32 huffman_decode(u8* out, u32 cap, const u8* src, u32 len) {
    i16 node = 0;
    u32 partial = 0;       // bits walked since the last leaf (since root)
    bool all_ones = true;  // whether those bits are all 1 (valid EOS padding)
    u32 o = 0;
    for (u32 i = 0; i < len; i++) {
        const u8 kByte = src[i];
        for (i32 b = 7; b >= 0; b--) {
            const u32 kBit = (kByte >> static_cast<u32>(b)) & 1u;
            partial++;
            if (kBit == 0) all_ones = false;
            node = kTrie.child[node][kBit];
            if (node < 0) return -1;  // not a valid code path
            if (kTrie.sym[node] >= 0) {
                const i16 kSym = kTrie.sym[node];
                if (kSym == static_cast<i16>(kEosSym)) return -1;  // EOS in stream
                if (o >= cap) return -1;                           // overflow
                out[o++] = static_cast<u8>(kSym);
                node = 0;
                partial = 0;
                all_ones = true;
            }
        }
    }
    // Trailing bits must be a valid EOS-prefix padding: all 1s and <= 7 bits.
    if (partial > 7 || !all_ones) return -1;
    return static_cast<i32>(o);
}

u32 decode_string(const u8* in, u32 len, u8* out, u32 cap, u32* out_len) {
    if (len == 0) return 0;
    const bool kHuffman = (in[0] & 0x80) != 0;
    u32 slen = 0;
    const u32 kHdr = decode_integer(in, len, 7, &slen);
    if (kHdr == 0) return 0;
    if (kHdr + slen > len) return 0;  // truncated payload
    const u8* data = in + kHdr;
    if (kHuffman) {
        const i32 kN = huffman_decode(out, cap, data, slen);
        if (kN < 0) return 0;
        *out_len = static_cast<u32>(kN);
    } else {
        if (slen > cap) return 0;
        for (u32 i = 0; i < slen; i++) out[i] = data[i];
        *out_len = slen;
    }
    return kHdr + slen;
}

u32 encode_string(u8* out, const u8* src, u32 len) {
    const u32 kHlen = huffman_encoded_len(src, len);
    if (kHlen < len) {
        const u32 kHdr = encode_integer(out, kHlen, 7, 0x80);  // H=1
        const u32 kN = huffman_encode(out + kHdr, src, len);
        return kHdr + kN;
    }
    const u32 kHdr = encode_integer(out, len, 7, 0x00);  // H=0
    for (u32 i = 0; i < len; i++) out[kHdr + i] = src[i];
    return kHdr + len;
}

}  // namespace rut::hpack
