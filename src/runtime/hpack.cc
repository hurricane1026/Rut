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

constexpr HuffFsm build_fsm() {
    HuffFsm f{};
    for (u32 n = 0; n < kMaxNodes; n++) {
        f.pad_ok[n] = 0;
        for (u32 v = 0; v < 16; v++) {
            f.next[n][v] = 0;
            f.sym[n][v] = -1;
            f.fail[n][v] = 0;
        }
    }
    for (u32 n = 0; n < kTrie.node_count; n++) {
        for (u32 v = 0; v < 16; v++) {
            i16 cur = static_cast<i16>(n);
            i16 emitted = -1;
            u8 failed = 0;
            for (i32 b = 3; b >= 0; b--) {
                const u32 kBit = (v >> static_cast<u32>(b)) & 1u;
                cur = kTrie.child[cur][kBit];
                if (cur < 0) break;  // unreachable: code is complete
                if (kTrie.sym[cur] >= 0) {
                    if (kTrie.sym[cur] == static_cast<i16>(kEosSym))
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
    u32 o = 0;
    for (u32 i = 0; i < len; i++) {
        const u8 kByte = src[i];
        // High nibble then low nibble — one FSM step each.
        const u32 kHi = kByte >> 4;
        if (kFsm.fail[node][kHi]) return -1;  // EOS symbol in the stream
        if (kFsm.sym[node][kHi] >= 0) {
            if (o >= cap) return -1;
            out[o++] = static_cast<u8>(kFsm.sym[node][kHi]);
        }
        node = kFsm.next[node][kHi];
        const u32 kLo = kByte & 0xf;
        if (kFsm.fail[node][kLo]) return -1;
        if (kFsm.sym[node][kLo] >= 0) {
            if (o >= cap) return -1;
            out[o++] = static_cast<u8>(kFsm.sym[node][kLo]);
        }
        node = kFsm.next[node][kLo];
    }
    // Trailing bits must be a valid EOS-prefix padding (root or 1..7 ones).
    if (!kFsm.pad_ok[node]) return -1;
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

bool str_eq(Str a, const char* b, u16 blen) {
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

void dyn_evict_oldest(DynamicTable& d) {
    if (d.nent == 0) return;
    const DynamicTable::Entry kOld = d.ents[0];
    const u32 kBlen = static_cast<u32>(kOld.nlen) + kOld.vlen;
    __builtin_memmove(d.buf, d.buf + kBlen, d.byte_used - kBlen);
    d.byte_used -= kBlen;
    d.table_size -= (static_cast<u32>(kOld.nlen) + kOld.vlen + 32u);
    for (u32 i = 1; i < d.nent; i++) {
        d.ents[i - 1] = d.ents[i];
        d.ents[i - 1].off -= kBlen;
    }
    d.nent--;
}

void dyn_set_max_size(DynamicTable& d, u32 m) {
    d.max_size = m;
    while (d.table_size > d.max_size) dyn_evict_oldest(d);
}

// Add (name,value). Caller MUST ensure the source bytes do not alias d.buf.
void dyn_add(DynamicTable& d, Str name, Str value) {
    const u32 kCost = name.len + value.len + 32u;
    if (kCost > d.max_size) {  // §4.4: entry larger than the table empties it
        dyn_clear(d);
        return;
    }
    while (d.table_size + kCost > d.max_size || d.nent >= DynamicTable::kMaxEntries)
        dyn_evict_oldest(d);
    const u32 kOff = d.byte_used;
    __builtin_memcpy(d.buf + kOff, name.ptr, name.len);
    __builtin_memcpy(d.buf + kOff + name.len, value.ptr, value.len);
    d.byte_used += name.len + value.len;
    d.ents[d.nent].off = kOff;
    d.ents[d.nent].nlen = static_cast<u16>(name.len);
    d.ents[d.nent].vlen = static_cast<u16>(value.len);
    d.nent++;
    d.table_size += kCost;
}

bool dyn_get(const DynamicTable& d, u32 i, Str* name, Str* value) {
    if (i >= d.nent) return false;
    const DynamicTable::Entry& e = d.ents[d.nent - 1 - i];
    name->ptr = reinterpret_cast<const char*>(d.buf + e.off);
    name->len = e.nlen;
    value->ptr = reinterpret_cast<const char*>(d.buf + e.off + e.nlen);
    value->len = e.vlen;
    return true;
}

// Resolve a 1-based HPACK index to (name,value). idx 1..61 = static.
bool resolve_full(const DynamicTable& d, u32 idx, Str* name, Str* value) {
    if (idx == 0) return false;
    if (idx <= kStaticCount) {
        const StaticEntry& e = kStatic[idx - 1];
        *name = {e.name, e.nlen};
        *value = {e.value, e.vlen};
        return true;
    }
    return dyn_get(d, idx - kStaticCount - 1, name, value);
}

bool resolve_name(const DynamicTable& d, u32 idx, Str* name) {
    Str value;
    if (idx <= kStaticCount) {
        if (idx == 0) return false;
        const StaticEntry& e = kStatic[idx - 1];
        *name = {e.name, e.nlen};
        return true;
    }
    return dyn_get(d, idx - kStaticCount - 1, name, &value);
}

i32 static_find_full(Str name, Str value) {
    for (u32 i = 0; i < kStaticCount; i++)
        if (str_eq(name, kStatic[i].name, kStatic[i].nlen) &&
            str_eq(value, kStatic[i].value, kStatic[i].vlen))
            return static_cast<i32>(i + 1);
    return 0;
}

i32 static_find_name(Str name) {
    for (u32 i = 0; i < kStaticCount; i++)
        if (str_eq(name, kStatic[i].name, kStatic[i].nlen)) return static_cast<i32>(i + 1);
    return 0;
}

// Encoder-side dynamic table lookups: return the 1-based HPACK index of a
// matching entry (dynamic indices follow the 61 static entries; newest = 62),
// or 0. j counts from the newest entry, matching the protocol index order.
i32 dyn_find_full(const DynamicTable& d, Str name, Str value) {
    for (u32 j = 0; j < d.nent; j++) {
        const DynamicTable::Entry& e = d.ents[d.nent - 1 - j];
        const Str kEn{reinterpret_cast<const char*>(d.buf + e.off), e.nlen};
        const Str kEv{reinterpret_cast<const char*>(d.buf + e.off + e.nlen), e.vlen};
        if (kEn.eq(name) && kEv.eq(value)) return static_cast<i32>(kStaticCount + 1 + j);
    }
    return 0;
}

i32 dyn_find_name(const DynamicTable& d, Str name) {
    for (u32 j = 0; j < d.nent; j++) {
        const DynamicTable::Entry& e = d.ents[d.nent - 1 - j];
        const Str kEn{reinterpret_cast<const char*>(d.buf + e.off), e.nlen};
        if (kEn.eq(name)) return static_cast<i32>(kStaticCount + 1 + j);
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

bool decode_header_block(DynamicTable& dyn,
                         const u8* in,
                         u32 len,
                         u8* out_buf,
                         u32 out_cap,
                         Header* headers,
                         u32 max_headers,
                         u32* count) {
    u32 pos = 0;
    u32 op = 0;  // out_buf write cursor
    u32 hc = 0;
    while (pos < len) {
        const u8 kByte = in[pos];
        if (kByte & 0x80) {
            // §6.1 Indexed Header Field.
            u32 idx = 0;
            const u32 kC = decode_integer(in + pos, len - pos, 7, &idx);
            if (kC == 0 || idx == 0) return false;
            pos += kC;
            Str name, value;
            if (!resolve_full(dyn, idx, &name, &value)) return false;
            if (hc >= max_headers) return false;
            headers[hc++] = {name, value};
            continue;
        }
        if (kByte & 0x20 && !(kByte & 0x40)) {
            // §6.3 Dynamic Table Size Update (001xxxxx).
            u32 sz = 0;
            const u32 kC = decode_integer(in + pos, len - pos, 5, &sz);
            if (kC == 0 || sz > dyn.hard_max) return false;
            pos += kC;
            dyn_set_max_size(dyn, sz);
            continue;
        }
        // Literal field: incremental indexing (§6.2.1, 0x40, 6-bit name index)
        // or without/never indexing (§6.2.2/§6.2.3, 4-bit name index).
        const bool kIncremental = (kByte & 0x40) != 0;
        const u8 kPrefix = kIncremental ? 6 : 4;
        u32 nidx = 0;
        const u32 kNc = decode_integer(in + pos, len - pos, kPrefix, &nidx);
        if (kNc == 0) return false;
        pos += kNc;

        Str name;
        if (nidx == 0) {
            u32 nlen = 0;
            const u32 kSc = decode_string(in + pos, len - pos, out_buf + op, out_cap - op, &nlen);
            if (kSc == 0) return false;
            pos += kSc;
            name = {reinterpret_cast<const char*>(out_buf + op), nlen};
            op += nlen;
        } else if (!resolve_name(dyn, nidx, &name)) {
            return false;
        }
        // Value is always a literal string.
        u32 vlen = 0;
        const u32 kVc = decode_string(in + pos, len - pos, out_buf + op, out_cap - op, &vlen);
        if (kVc == 0) return false;
        pos += kVc;
        Str value = {reinterpret_cast<const char*>(out_buf + op), vlen};
        op += vlen;

        if (kIncremental) {
            // The name may alias dyn.buf (table reference); copy it into out_buf
            // so dyn_add's eviction/compaction can't corrupt the source.
            if (nidx != 0) {
                if (op + name.len > out_cap) return false;
                __builtin_memcpy(out_buf + op, name.ptr, name.len);
                name = {reinterpret_cast<const char*>(out_buf + op), name.len};
                op += name.len;
            }
            dyn_add(dyn, name, value);
        }
        if (hc >= max_headers) return false;
        headers[hc++] = {name, value};
    }
    *count = hc;
    return true;
}

u32 encode_header(u8* out, Str name, Str value) {
    const i32 kFull = static_find_full(name, value);
    if (kFull > 0) return encode_integer(out, static_cast<u32>(kFull), 7, 0x80);

    const i32 kNameIdx = static_find_name(name);
    // Literal without indexing (0000xxxx): name index (0 = literal name).
    u32 o = encode_integer(out, static_cast<u32>(kNameIdx > 0 ? kNameIdx : 0), 4, 0x00);
    if (kNameIdx <= 0) o += encode_string(out + o, reinterpret_cast<const u8*>(name.ptr), name.len);
    o += encode_string(out + o, reinterpret_cast<const u8*>(value.ptr), value.len);
    return o;
}

u32 Encoder::encode(u8* out, Str name, Str value) {
    // Exact (name,value) match → Indexed Header Field (§6.1, 1 byte for small
    // indices). Check the dynamic table first: in steady state most fields hit
    // it, and it is far smaller than the 61-entry static table, so this skips
    // the static scan on the common path. Either index is valid per §2.3.3.
    const i32 kDynFull = dyn_find_full(dyn, name, value);
    if (kDynFull > 0) return encode_integer(out, static_cast<u32>(kDynFull), 7, 0x80);
    const i32 kStaticFull = static_find_full(name, value);
    if (kStaticFull > 0) return encode_integer(out, static_cast<u32>(kStaticFull), 7, 0x80);

    // Otherwise Literal with Incremental Indexing (§6.2.1, 6-bit name index)
    // and add the field so the next occurrence indexes to 1 byte.
    i32 nidx = static_find_name(name);
    if (nidx == 0) nidx = dyn_find_name(dyn, name);
    u32 o = encode_integer(out, static_cast<u32>(nidx > 0 ? nidx : 0), 6, 0x40);
    if (nidx <= 0) o += encode_string(out + o, reinterpret_cast<const u8*>(name.ptr), name.len);
    o += encode_string(out + o, reinterpret_cast<const u8*>(value.ptr), value.len);
    // Index resolution above used the pre-add table — the same order the peer's
    // decoder sees — so adding now keeps both tables in sync.
    dyn_add(dyn, name, value);
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
void Encoder::set_table_size(u32 settings_max) {
    const u32 kNew = settings_max < DynamicTable::kHardCap ? settings_max : DynamicTable::kHardCap;
    // The size currently in effect for the peer's decoder is the final pending
    // value if one is armed, else our live table limit. No net change → nothing
    // to do (avoids spurious size updates on duplicate SETTINGS).
    const i32 kCurrent =
        pending_size_update >= 0 ? pending_size_update : static_cast<i32>(dyn.max_size);
    if (static_cast<i32>(kNew) == kCurrent) return;
    dyn_set_max_size(dyn, kNew);  // shrinking evicts entries that no longer fit
    // Track the smallest size reached since the last emit. A shrink-then-grow
    // between header blocks must signal the minimum first (§4.2), otherwise the
    // peer decoder never evicts at the shrink and its table diverges from ours.
    if (pending_size_update < 0 || static_cast<i32>(kNew) < pending_min_size)
        pending_min_size = static_cast<i32>(kNew);
    pending_size_update = static_cast<i32>(kNew);
}

u32 Encoder::emit_pending_size_update(u8* out) {
    if (pending_size_update < 0) return 0;
    // §6.3 dynamic table size update: pattern 001 (0x20) + 5-bit prefix integer.
    // Signal the smallest size reached first (so the decoder evicts identically),
    // then the final size when it differs.
    u32 n = 0;
    if (pending_min_size >= 0 && pending_min_size != pending_size_update)
        n += encode_integer(out + n, static_cast<u32>(pending_min_size), 5, 0x20);
    n += encode_integer(out + n, static_cast<u32>(pending_size_update), 5, 0x20);
    pending_size_update = -1;
    pending_min_size = -1;
    return n;
}

}  // namespace rut::hpack
