#include "rut/runtime/hpack.h"

#include "rut/common/range_int.h"

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

constexpr i16 kEosSym = 256;

// Compile-time decode trie. Each node has two children (bit 0 / bit 1); a leaf
// stores its symbol. Built once at compile time from kHuff — no runtime init,
// no allocation, inherently thread-safe (read-only).
constexpr u32 kMaxNodes = 600;  // <= 2*257-1 internal+leaf nodes
struct HuffTrie {
    i16 child[kMaxNodes][2];
    i16 sym[kMaxNodes];
    i16 node_count;
};

[[nodiscard]] consteval HuffTrie build_trie() {
    static_assert(kMaxNodes <= INT16_MAX && kSymCount <= INT16_MAX);
    HuffTrie t{};
    for (u32 i = 0; i < kMaxNodes; i++) {
        t.child[i][0] = -1;
        t.child[i][1] = -1;
        t.sym[i] = -1;
    }
    t.node_count = 1;  // node 0 = root
    for (i16 s = 0; s < i32{kSymCount}; s++) {
        const u32 kCode = kHuff[s].code;
        const u8 kBits = kHuff[s].bits;
        i16 node = 0;
        for (i32 b = i32{kBits} - 1; b >= 0; b--) {
            const u32 kBit = (kCode >> b) & 1u;
            if (t.child[node][kBit] < 0) {
                if (t.node_count == i32{kMaxNodes}) __builtin_trap();
                t.child[node][kBit] = t.node_count;
                t.node_count++;
            }
            node = t.child[node][kBit];
        }
        t.sym[node] = s;
    }
    return t;
}

constexpr HuffTrie kTrie = build_trie();

// Table-driven Huffman decode FSM (nghttp2-style), built at compile time from
// the bit trie. Each step consumes a 4-bit nibble: from state `node`, fsm_next
// is the resulting trie node and fsm_sym (>=0) the symbol completed during the
// nibble (at most one, since the shortest code is 5 bits). fsm_fail marks an
// EOS symbol completing in the stream (a decode error). pad_ok[node] marks a
// state that is a valid trailing-padding position (root, or 1..7 ones along the
// EOS prefix). The HPACK Huffman code is complete, so every nibble transition
// is valid mid-stream — no failure path except EOS and end-of-input padding.
struct HuffFsm {
    i16 next[kMaxNodes][16];
    i16 sym[kMaxNodes][16];
    u8 fail[kMaxNodes][16];
    u8 pad_ok[kMaxNodes];
};

[[nodiscard]] constexpr HuffFsm build_fsm() {
    HuffFsm f{};
    for (u32 n = 0; n < kMaxNodes; n++) {
        f.pad_ok[n] = 0;
        for (u32 v = 0; v < 16; v++) {
            f.next[n][v] = 0;
            f.sym[n][v] = -1;
            f.fail[n][v] = 0;
        }
    }
    for (i16 n = 0; n < kTrie.node_count; n++) {
        for (u32 v = 0; v < 16; v++) {
            i16 cur = n;
            i16 emitted = -1;
            u8 failed = 0;
            for (i32 b = 3; b >= 0; b--) {
                const u32 kBit = (v >> b) & 1u;
                cur = kTrie.child[cur][kBit];
                if (cur < 0) break;  // unreachable: code is complete
                if (kTrie.sym[cur] >= 0) {
                    if (kTrie.sym[cur] == kEosSym)
                        failed = 1;
                    else
                        emitted = kTrie.sym[cur];
                    cur = 0;  // back to root for the remaining bits
                }
            }
            f.next[n][v] = cur;
            f.sym[n][v] = emitted;
            f.fail[n][v] = failed;
        }
    }
    // Valid padding states: root and each node along the all-ones (EOS) prefix
    // at depth 1..7.
    f.pad_ok[0] = 1;
    i16 node = 0;
    for (u32 depth = 1; depth <= 7; depth++) {
        node = kTrie.child[node][1];
        if (node < 0) break;
        f.pad_ok[node] = 1;
    }
    return f;
}

constexpr HuffFsm kFsm = build_fsm();

}  // namespace

[[nodiscard]] u32 decode_integer(const u8* in, u32 len, u8 prefix_bits, u32* out) {
    if (len == 0 || prefix_bits == 0 || prefix_bits > 8) return 0;
    // RUT_INTEGER_RANGE: the validated prefix is at most one octet.
    const u32 kMask = ~(~u32{0} << prefix_bits);
    u32 value = in[0] & kMask;
    if (value < kMask) {
        *out = value;
        return 1;
    }
    // Continuation octets: 7 bits each, low-order first; high bit = "more".
    i64 acc = kMask;
    i64 shift = 0;
    u32 i = 1;
    while (true) {
        if (i >= len) return 0;  // truncated
        const u8 kB = in[i++];
        // RUT_INTEGER_RANGE: acc <= UINT32_MAX and at most 7 bits are added at shift <= 28.
        acc += static_cast<i64>(kB & 0x7f) << shift;
        if (acc > 0xffffffffLL) return 0;  // exceeds 32 bits
        if ((kB & 0x80) == 0) break;
        shift += 7;
        if (shift > 28) return 0;  // would overflow on next octet
    }
    if (!range_int(acc).to(out)) return 0;
    return i;
}

[[nodiscard]] u32 encode_integer(u8* out, u32 value, u8 prefix_bits, u8 prefix_top) {
    if (prefix_bits == 0 || prefix_bits > 8) return 0;
    // RUT_INTEGER_RANGE: the validated prefix is at most one octet.
    const u32 kMask = ~(~u32{0} << prefix_bits);
    if (value < kMask) {
        out[0] = bounded_remainder<256>(u64{prefix_top} | value).to<u8>();
        return 1;
    }
    out[0] = bounded_remainder<256>(u64{prefix_top} | kMask).to<u8>();
    const auto kRemainder = range_int(value) - range_int(kMask);
    u32 remainder = kRemainder.max(range_int<0, 1>{}).to<u32>();
    u32 i = 1;
    while (remainder >= 128) {
        out[i++] = (bounded_remainder<128>(remainder) + range_int<128, 129>{}).to<u8>();
        remainder >>= 7;
    }
    out[i++] = bounded_remainder<128>(remainder).to<u8>();
    return i;
}

[[nodiscard]] i64 huffman_encoded_len(const u8* src, u32 len) {
    // The longest HPACK code is 30 bits, so the full u32 input range fits in
    // signed 64-bit arithmetic: UINT32_MAX * 30 < INT64_MAX.
    i64 bits = 0;
    for (u32 i = 0; i < len; i++) bits += static_cast<i64>(kHuff[src[i]].bits);

    return huffman_encoded_bytes_from_bits(bits);
}

[[nodiscard]] i64 huffman_encode(u8* out, const u8* src, u32 len) {
    u64 acc = 0;    // bit accumulator, MSB-first
    i64 nbits = 0;  // valid bits in acc
    i64 o = 0;
    for (u32 i = 0; i < len; i++) {
        const HuffCode kEntry = kHuff[src[i]];
        acc = (acc << kEntry.bits) | kEntry.code;
        nbits += static_cast<i64>(kEntry.bits);
        while (nbits >= 8) {
            nbits -= 8;
            out[o++] = bounded_remainder<256>(acc >> nbits).to<u8>();
        }
    }
    if (nbits > 0) {
        // Pad the remaining bits with the EOS prefix (all 1s) to an octet.
        const i64 kPad = 8 - nbits;
        const u64 kMask = ~(~u64{0} << kPad);
        acc = (acc << kPad) | kMask;
        out[o++] = bounded_remainder<256>(acc).to<u8>();
    }
    return o;
}

[[nodiscard]] i32 huffman_decode(u8* out, u32 cap, const u8* src, u32 len) {
    // The signed result reports -1 on failure and otherwise carries the exact length.
    const i32 limit = range_int(cap).min(range_int<INT32_MAX, i64{INT32_MAX} + 1>{}).to<i32>();
    i16 node = 0;
    i32 o = 0;
    for (u32 i = 0; i < len; i++) {
        const u8 kByte = src[i];
        // High nibble then low nibble — one FSM step each.
        const u32 kHi = kByte >> 4;
        if (kFsm.fail[node][kHi]) return -1;  // EOS symbol in the stream
        const i16 kHiSymbol = kFsm.sym[node][kHi];
        if (kHiSymbol >= 0) {
            if (o >= limit) return -1;
            out[o++] = bounded_remainder<256>(__builtin_bit_cast(u16, kHiSymbol)).to<u8>();
        }
        node = kFsm.next[node][kHi];
        const u32 kLo = kByte & 0xf;
        if (kFsm.fail[node][kLo]) return -1;
        const i16 kLoSymbol = kFsm.sym[node][kLo];
        if (kLoSymbol >= 0) {
            if (o >= limit) return -1;
            out[o++] = bounded_remainder<256>(__builtin_bit_cast(u16, kLoSymbol)).to<u8>();
        }
        node = kFsm.next[node][kLo];
    }
    // Trailing bits must be a valid EOS-prefix padding (root or 1..7 ones).
    if (!kFsm.pad_ok[node]) return -1;
    return o;
}

[[nodiscard]] u32 decode_string(const u8* in, u32 len, u8* out, u32 cap, u32* out_len) {
    if (len == 0) return 0;
    const bool kHuffman = (in[0] & 0x80) != 0;
    u32 slen = 0;
    const u32 kHdr = decode_integer(in, len, 7, &slen);
    if (kHdr == 0) return 0;
    const auto kConsumed = range_int(kHdr) + range_int(slen);
    if (kConsumed.value() > len) return 0;  // truncated payload
    const u8* data = in + static_cast<i64>(kHdr);
    if (kHuffman) {
        const i32 kN = huffman_decode(out, cap, data, slen);
        if (!range_int(kN).to(out_len)) return 0;
    } else {
        if (slen > cap) return 0;
        for (i64 i = 0; i < slen; i++) out[i] = data[i];
        *out_len = slen;
    }
    return kConsumed.min(range_int(len)).to<u32>();
}

[[nodiscard]] i64 encode_string(u8* out, const u8* src, u32 len) {
    const i64 kHlen = huffman_encoded_len(src, len);
    u32 encoded_length;
    if (kHlen < len && range_int(kHlen).to(&encoded_length)) {
        const i64 kHdr = encode_integer(out, encoded_length, 7, 0x80);  // H=1
        const i64 kN = huffman_encode(out + kHdr, src, len);
        return kHdr + kN;
    }
    const i64 kHdr = encode_integer(out, len, 7, 0x00);  // H=0
    for (i64 i = 0; i < len; i++) out[kHdr + i] = src[i];
    return kHdr + static_cast<i64>(len);
}

namespace {

// Static table (RFC 7541 Appendix A), 1-based in the protocol. Entries with no
// predefined value carry an empty value string.
struct StaticEntry {
    const char* name;
    u16 nlen;
    const char* value;
    u16 vlen;
};

constexpr StaticEntry kStatic[] = {
    {":authority", 10, "", 0},
    {":method", 7, "GET", 3},
    {":method", 7, "POST", 4},
    {":path", 5, "/", 1},
    {":path", 5, "/index.html", 11},
    {":scheme", 7, "http", 4},
    {":scheme", 7, "https", 5},
    {":status", 7, "200", 3},
    {":status", 7, "204", 3},
    {":status", 7, "206", 3},
    {":status", 7, "304", 3},
    {":status", 7, "400", 3},
    {":status", 7, "404", 3},
    {":status", 7, "500", 3},
    {"accept-charset", 14, "", 0},
    {"accept-encoding", 15, "gzip, deflate", 13},
    {"accept-language", 15, "", 0},
    {"accept-ranges", 13, "", 0},
    {"accept", 6, "", 0},
    {"access-control-allow-origin", 27, "", 0},
    {"age", 3, "", 0},
    {"allow", 5, "", 0},
    {"authorization", 13, "", 0},
    {"cache-control", 13, "", 0},
    {"content-disposition", 19, "", 0},
    {"content-encoding", 16, "", 0},
    {"content-language", 16, "", 0},
    {"content-length", 14, "", 0},
    {"content-location", 16, "", 0},
    {"content-range", 13, "", 0},
    {"content-type", 12, "", 0},
    {"cookie", 6, "", 0},
    {"date", 4, "", 0},
    {"etag", 4, "", 0},
    {"expect", 6, "", 0},
    {"expires", 7, "", 0},
    {"from", 4, "", 0},
    {"host", 4, "", 0},
    {"if-match", 8, "", 0},
    {"if-modified-since", 17, "", 0},
    {"if-none-match", 13, "", 0},
    {"if-range", 8, "", 0},
    {"if-unmodified-since", 19, "", 0},
    {"last-modified", 13, "", 0},
    {"link", 4, "", 0},
    {"location", 8, "", 0},
    {"max-forwards", 12, "", 0},
    {"proxy-authenticate", 18, "", 0},
    {"proxy-authorization", 19, "", 0},
    {"range", 5, "", 0},
    {"referer", 7, "", 0},
    {"refresh", 7, "", 0},
    {"retry-after", 11, "", 0},
    {"server", 6, "", 0},
    {"set-cookie", 10, "", 0},
    {"strict-transport-security", 25, "", 0},
    {"transfer-encoding", 17, "", 0},
    {"user-agent", 10, "", 0},
    {"vary", 4, "", 0},
    {"via", 3, "", 0},
    {"www-authenticate", 16, "", 0},
};

constexpr u32 kStaticCount = sizeof(kStatic) / sizeof(kStatic[0]);  // 61

[[nodiscard]] bool str_eq(Str a, const char* b, u16 blen) {
    if (a.len != blen) return false;
    for (u32 i = 0; i < blen; i++)
        if (a.ptr[i] != b[i]) return false;
    return true;
}

// --- Dynamic table operations (bytes kept packed in insertion order) ---

void dyn_clear(DynamicTable& d) {
    d.nent = 0;
    d.byte_used = 0;
    d.table_size = 0;
}

[[nodiscard]] bool dyn_evict_oldest(DynamicTable& d) {
    if (d.nent == 0 || d.nent > DynamicTable::kMaxEntries || d.byte_used > DynamicTable::kByteCap)
        return false;
    const auto& oldest = d.ents[0];
    const auto payload = range_int(oldest.nlen) + range_int(oldest.vlen);
    const auto cost = payload + range_int<32, 33>{};
    u32 next_used;
    u32 next_size;
    if (!(range_int(d.byte_used) - payload).to(&next_used) ||
        !(range_int(d.table_size) - cost).to(&next_size))
        return false;
    for (u32 i = 1; i < d.nent; i++) {
        auto entry = d.ents[i];
        if (!(range_int(entry.off) - payload).to(&entry.off)) {
            // The metadata was inconsistent. Drop the partial compaction and
            // report failure so the caller stops using this HPACK context.
            dyn_clear(d);
            return false;
        }
        d.ents[i64{i} - 1] = entry;
    }
    __builtin_memmove(d.buf, d.buf + payload.index(), next_used);
    d.byte_used = next_used;
    d.table_size = next_size;
    --d.nent;
    return true;
}

[[nodiscard]] bool dyn_set_max_size(DynamicTable& d, u32 size) {
    while (d.table_size > size)
        if (!dyn_evict_oldest(d)) return false;
    d.max_size = size;
    return true;
}

// Add (name,value). Caller MUST ensure the source bytes do not alias d.buf.
[[nodiscard]] bool dyn_add(DynamicTable& d, Str name, Str value) {
    constexpr auto kByteCap = range_int<DynamicTable::kByteCap, i64{DynamicTable::kByteCap} + 1>{};
    const auto payload = range_int(name.len) + range_int(value.len);
    const auto cost = payload + range_int<32, 33>{};
    if (cost.value() > d.max_size || payload.value() > DynamicTable::kByteCap) {
        // §4.4: entry larger than the table empties it. The payload check also
        // keeps the u32 offsets and u16 entry lengths representable.
        dyn_clear(d);
        return true;
    }
    while ((range_int(d.table_size) + cost).value() > d.max_size ||
           d.nent >= DynamicTable::kMaxEntries)
        if (!dyn_evict_oldest(d)) return false;
    const auto offset = range_int(d.byte_used);
    const auto end = offset + payload;
    if (end.value() > kByteCap.value()) return false;
    const auto name_length = range_int(name.len).min(kByteCap);
    const auto value_length = range_int(value.len).min(kByteCap);
    __builtin_memcpy(d.buf + offset.index(), name.ptr, name_length.to<u16>());
    __builtin_memcpy(d.buf + (offset + name_length).index(), value.ptr, value_length.to<u16>());
    // The eviction loop reserves the entry's full cost, which includes its payload.
    d.byte_used = end.min(kByteCap).to<u32>();
    d.ents[d.nent++] = {offset.to<u32>(), name_length.to<u16>(), value_length.to<u16>()};
    d.table_size = (range_int(d.table_size) + cost).min(range_int(d.max_size)).to<u32>();
    return true;
}

[[nodiscard]] bool dyn_get(const DynamicTable& d, u32 i, Str* name, Str* value) {
    if (i >= d.nent) return false;
    const i64 kEntry = static_cast<i64>(d.nent) - 1 - static_cast<i64>(i);
    const DynamicTable::Entry& e = d.ents[kEntry];
    name->ptr = reinterpret_cast<const char*>(d.buf + static_cast<i64>(e.off));
    name->len = e.nlen;
    value->ptr =
        reinterpret_cast<const char*>(d.buf + static_cast<i64>(e.off) + static_cast<i64>(e.nlen));
    value->len = e.vlen;
    return true;
}

// Resolve a 1-based HPACK index to (name,value). idx 1..61 = static.
[[nodiscard]] bool resolve_full(const DynamicTable& d, u32 idx, Str* name, Str* value) {
    if (idx == 0) return false;
    if (idx <= kStaticCount) {
        const StaticEntry& e = kStatic[static_cast<i64>(idx) - 1];
        *name = {e.name, e.nlen};
        *value = {e.value, e.vlen};
        return true;
    }
    const auto entry =
        range_int(idx) - range_int<kStaticCount, i64{kStaticCount} + 1>{} - range_int<1, 2>{};
    return dyn_get(d, entry.max(range_int<0, 1>{}).to<u32>(), name, value);
}

[[nodiscard]] bool resolve_name(const DynamicTable& d, u32 idx, Str* name) {
    Str value;
    if (idx <= kStaticCount) {
        if (idx == 0) return false;
        const StaticEntry& e = kStatic[static_cast<i64>(idx) - 1];
        *name = {e.name, e.nlen};
        return true;
    }
    const auto entry =
        range_int(idx) - range_int<kStaticCount, i64{kStaticCount} + 1>{} - range_int<1, 2>{};
    return dyn_get(d, entry.max(range_int<0, 1>{}).to<u32>(), name, &value);
}

[[nodiscard]] u32 static_find_full(Str name, Str value) {
    u32 index = 1;
    for (const auto& entry : kStatic) {
        if (str_eq(name, entry.name, entry.nlen) && str_eq(value, entry.value, entry.vlen))
            return index;
        ++index;
    }
    return 0;
}

[[nodiscard]] u32 static_find_name(Str name) {
    u32 index = 1;
    for (const auto& entry : kStatic) {
        if (str_eq(name, entry.name, entry.nlen)) return index;
        ++index;
    }
    return 0;
}

// The table index starts at the newest dynamic entry, following all static entries.
constexpr auto kFirstDynamicIndex =
    range_int<kStaticCount, i64{kStaticCount} + 1>{} + range_int<1, 2>{};
constexpr auto kMaxDynamicEntries =
    range_int<DynamicTable::kMaxEntries, i64{DynamicTable::kMaxEntries} + 1>{};

[[nodiscard]] u32 dyn_find_full(const DynamicTable& d, Str name, Str value) {
    const auto entries = range_int(d.nent).min(kMaxDynamicEntries);
    const u32 end = (kFirstDynamicIndex + entries).to<u32>();
    for (u32 index = kFirstDynamicIndex.to<u32>(); index < end; ++index) {
        const auto& entry = d.ents[i64{end} - i64{index} - 1];
        const Str entry_name{reinterpret_cast<const char*>(d.buf + i64{entry.off}), entry.nlen};
        const Str entry_value{
            reinterpret_cast<const char*>(d.buf + i64{entry.off} + i64{entry.nlen}), entry.vlen};
        if (entry_name.eq(name) && entry_value.eq(value)) return index;
    }
    return 0;
}

[[nodiscard]] u32 dyn_find_name(const DynamicTable& d, Str name) {
    const auto entries = range_int(d.nent).min(kMaxDynamicEntries);
    const u32 end = (kFirstDynamicIndex + entries).to<u32>();
    for (u32 index = kFirstDynamicIndex.to<u32>(); index < end; ++index) {
        const auto& entry = d.ents[i64{end} - i64{index} - 1];
        const Str entry_name{reinterpret_cast<const char*>(d.buf + i64{entry.off}), entry.nlen};
        if (entry_name.eq(name)) return index;
    }
    return 0;
}

}  // namespace

void DynamicTable::init(u32 settings_max) {
    hard_max = settings_max <= kHardCap ? settings_max : kHardCap;
    max_size = hard_max;
    nent = 0;
    byte_used = 0;
    table_size = 0;
}

[[nodiscard]] bool decode_header_block(DynamicTable& dyn,
                                       const u8* in,
                                       u32 len,
                                       u8* out_buf,
                                       u32 out_cap,
                                       Header* headers,
                                       u32 max_headers,
                                       u32* count) {
    i64 pos = 0;
    i64 op = 0;  // out_buf write cursor
    u32 hc = 0;
    while (pos < len) {
        u32 input_length;
        if (!range_int(i64{len} - pos).to(&input_length)) return false;
        const u8 kByte = in[pos];
        if (kByte & 0x80) {
            // §6.1 Indexed Header Field.
            u32 idx = 0;
            const u32 kC = decode_integer(in + pos, input_length, 7, &idx);
            if (kC == 0 || idx == 0) return false;
            pos += static_cast<i64>(kC);
            Str name, value;
            if (!resolve_full(dyn, idx, &name, &value)) return false;
            if (hc >= max_headers) return false;
            headers[hc++] = {name, value};
            continue;
        }
        if (kByte & 0x20 && !(kByte & 0x40)) {
            // §6.3 Dynamic Table Size Update (001xxxxx).
            u32 sz = 0;
            const u32 kC = decode_integer(in + pos, input_length, 5, &sz);
            if (kC == 0 || sz > dyn.hard_max) return false;
            pos += static_cast<i64>(kC);
            if (!dyn_set_max_size(dyn, sz)) return false;
            continue;
        }
        // Literal field: incremental indexing (§6.2.1, 0x40, 6-bit name index)
        // or without/never indexing (§6.2.2/§6.2.3, 4-bit name index).
        const bool kIncremental = (kByte & 0x40) != 0;
        const u8 kPrefix = kIncremental ? 6 : 4;
        u32 nidx = 0;
        const u32 kNc = decode_integer(in + pos, input_length, kPrefix, &nidx);
        if (kNc == 0) return false;
        pos += static_cast<i64>(kNc);

        Str name;
        if (nidx == 0) {
            u32 nlen = 0;
            u32 output_length;
            if (!range_int(i64{len} - pos).to(&input_length) ||
                !range_int(i64{out_cap} - op).to(&output_length))
                return false;
            const u32 kSc =
                decode_string(in + pos, input_length, out_buf + op, output_length, &nlen);
            if (kSc == 0) return false;
            pos += static_cast<i64>(kSc);
            name = {reinterpret_cast<const char*>(out_buf + op), nlen};
            op += static_cast<i64>(nlen);
        } else if (!resolve_name(dyn, nidx, &name)) {
            return false;
        }
        // Value is always a literal string.
        u32 vlen = 0;
        u32 output_length;
        if (!range_int(i64{len} - pos).to(&input_length) ||
            !range_int(i64{out_cap} - op).to(&output_length))
            return false;
        const u32 kVc = decode_string(in + pos, input_length, out_buf + op, output_length, &vlen);
        if (kVc == 0) return false;
        pos += static_cast<i64>(kVc);
        Str value = {reinterpret_cast<const char*>(out_buf + op), vlen};
        op += static_cast<i64>(vlen);

        if (kIncremental) {
            // The name may alias dyn.buf (table reference); copy it into out_buf
            // so dyn_add's eviction/compaction can't corrupt the source.
            if (nidx != 0) {
                if (op + static_cast<i64>(name.len) > static_cast<i64>(out_cap)) return false;
                __builtin_memcpy(out_buf + op, name.ptr, name.len);
                name = {reinterpret_cast<const char*>(out_buf + op), name.len};
                op += static_cast<i64>(name.len);
            }
            if (!dyn_add(dyn, name, value)) return false;
        }
        if (hc >= max_headers) return false;
        headers[hc++] = {name, value};
    }
    *count = hc;
    return true;
}

[[nodiscard]] i64 encode_header(u8* out, Str name, Str value) {
    const u32 kFull = static_find_full(name, value);
    if (kFull > 0) return encode_integer(out, kFull, 7, 0x80);

    const u32 kNameIdx = static_find_name(name);
    // Literal without indexing (0000xxxx): name index (0 = literal name).
    i64 o = encode_integer(out, kNameIdx, 4, 0x00);
    if (kNameIdx == 0) o += encode_string(out + o, reinterpret_cast<const u8*>(name.ptr), name.len);
    o += encode_string(out + o, reinterpret_cast<const u8*>(value.ptr), value.len);
    return o;
}

[[nodiscard]] i64 Encoder::encode(u8* out, Str name, Str value) {
    // Exact (name,value) match → Indexed Header Field (§6.1, 1 byte for small
    // indices). Check the dynamic table first: in steady state most fields hit
    // it, and it is far smaller than the 61-entry static table, so this skips
    // the static scan on the common path. Either index is valid per §2.3.3.
    const u32 kDynFull = dyn_find_full(dyn, name, value);
    if (kDynFull > 0) return encode_integer(out, kDynFull, 7, 0x80);
    const u32 kStaticFull = static_find_full(name, value);
    if (kStaticFull > 0) return encode_integer(out, kStaticFull, 7, 0x80);

    // Otherwise Literal with Incremental Indexing (§6.2.1, 6-bit name index)
    // and add the field so the next occurrence indexes to 1 byte.
    u32 nidx = static_find_name(name);
    if (nidx == 0) nidx = dyn_find_name(dyn, name);
    i64 o = encode_integer(out, nidx, 6, 0x40);
    if (nidx == 0) o += encode_string(out + o, reinterpret_cast<const u8*>(name.ptr), name.len);
    o += encode_string(out + o, reinterpret_cast<const u8*>(value.ptr), value.len);
    // Index resolution above used the pre-add table — the same order the peer's
    // decoder sees — so adding now keeps both tables in sync.
    if (!dyn_add(dyn, name, value)) return -1;
    return o;
}

// React to the peer's advertised SETTINGS_HEADER_TABLE_SIZE (RFC 7541 §4.2).
//
// The table size we may index against is min(peer's advertised maximum, our own
// fixed dynamic-table buffer DynamicTable::kHardCap). Using less than the peer
// allows is always legal, so a peer offering more than kHardCap (e.g. browsers
// advertise 64KiB) simply leaves us at our budget — a no-op, since we start
// there. The case that *must* act is a peer advertising less than our current
// limit: we shrink to match (evicting entries that no longer fit) and arm a §6.3
// dynamic table size update so the next header block tells the peer's decoder the
// new size in lockstep. Without that the two tables desync and decoding breaks.
[[nodiscard]] bool Encoder::set_table_size(u32 settings_max) {
    constexpr auto kCap = range_int<DynamicTable::kHardCap, i64{DynamicTable::kHardCap} + 1>{};
    const auto size = range_int(settings_max).min(kCap);
    const i32 next = size.to<i32>();
    // The size currently in effect for the peer's decoder is the final pending
    // value if one is armed, else our live table limit. No net change → nothing
    // to do (avoids spurious size updates on duplicate SETTINGS).
    const i64 kCurrent = pending_size_update >= 0 ? pending_size_update : i64{dyn.max_size};
    if (next == kCurrent) return true;
    if (!dyn_set_max_size(dyn, size.to<u32>())) return false;
    // A shrink-then-grow between header blocks must signal the minimum first
    // so the decoder evicts identically (§4.2).
    if (pending_size_update < 0 || next < pending_min_size) pending_min_size = next;
    pending_size_update = next;
    return true;
}

[[nodiscard]] u32 Encoder::emit_pending_size_update(u8* out) {
    if (pending_size_update < 0) return 0;
    // §6.3 dynamic table size update: pattern 001 (0x20) + 5-bit prefix integer.
    // Signal the smallest size reached first (so the decoder evicts identically),
    // then the final size when it differs.
    const auto final_size = range_int(pending_size_update).max(range_int<0, 1>{});
    u32 first = 0;
    if (pending_min_size >= 0 && pending_min_size != pending_size_update) {
        const auto minimum_size = range_int(pending_min_size).max(range_int<0, 1>{});
        first = encode_integer(out, minimum_size.to<u32>(), 5, 0x20);
    }
    const u32 final = encode_integer(out + i64{first}, final_size.to<u32>(), 5, 0x20);
    pending_size_update = -1;
    pending_min_size = -1;
    // A 32-bit prefix integer uses at most six octets, including its first byte.
    constexpr auto kMaxPair = range_int<12, 13>{};
    return (range_int(first) + range_int(final)).min(kMaxPair).to<u32>();
}

}  // namespace rut::hpack
