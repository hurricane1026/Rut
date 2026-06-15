#pragma once

#include "rut/common/types.h"

// HPACK (RFC 7541) primitives: prefix integers (§5.1), Huffman coding
// (§5.2 / App. B), and string literals (§5.2). Higher layers (static/dynamic
// table, header-list decode/encode) build on these. All functions are pure and
// allocation-free; callers provide output buffers.
namespace rut::hpack {

// --- Prefix integer (§5.1) ---

// Decode a prefix-encoded integer from in[0..len). prefix_bits in [1,8] is the
// number of bits the integer occupies in the first octet. Stores the value in
// *out and returns the number of octets consumed. Returns 0 on error
// (truncated input or a value exceeding 32 bits).
u32 decode_integer(const u8* in, u32 len, u8 prefix_bits, u32* out);

// Encode `value` with prefix_bits into out (needs up to 6 octets). prefix_top
// supplies the high (8 - prefix_bits) flag bits OR'd into the first octet; its
// low prefix_bits MUST be zero. Returns octets written.
u32 encode_integer(u8* out, u32 value, u8 prefix_bits, u8 prefix_top);

// --- Huffman (§5.2 / App. B) ---

// Number of octets src[0..len) encodes to.
u32 huffman_encoded_len(const u8* src, u32 len);

// Huffman-encode src[0..len) into out (must hold huffman_encoded_len(src,len)).
// Pads the final octet with the EOS prefix (1-bits). Returns octets written.
u32 huffman_encode(u8* out, const u8* src, u32 len);

// Huffman-decode src[0..len) into out[0..cap). Returns the decoded length, or
// -1 on error: capacity overflow, an EOS symbol in the stream, padding longer
// than 7 bits, or padding that is not the EOS code prefix (§5.2).
i32 huffman_decode(u8* out, u32 cap, const u8* src, u32 len);

// --- String literal (§5.2) ---

// Decode a length-prefixed string from in[0..len): a 1-bit Huffman flag, a
// 7-bit-prefix length, then the data. Writes the literal (Huffman-decoded if
// flagged) into out[0..cap), sets *out_len, and returns octets consumed from
// `in`. Returns 0 on error (truncated, capacity overflow, bad Huffman).
u32 decode_string(const u8* in, u32 len, u8* out, u32 cap, u32* out_len);

// Encode src[0..len) as a string literal into out, choosing Huffman iff it is
// strictly shorter. out must hold worst case (len + 1 + integer prefix).
// Returns octets written.
u32 encode_string(u8* out, const u8* src, u32 len);

// --- Header field representations (§6) ---

// A decoded header field. name/value are non-owning views: into static storage
// for static-table references, otherwise into the caller's decode output buffer.
struct Header {
    Str name;
    Str value;
};

// Decoder dynamic table (§2.3): a FIFO of recently-seen (name,value) pairs,
// addressable after the 61 static entries. Bounded by the negotiated
// SETTINGS_HEADER_TABLE_SIZE; entry cost is name+value+32 octets (§4.1). Bytes
// are kept packed in insertion order; eviction drops the oldest. Owned per
// connection by the decoder side.
struct DynamicTable {
    static constexpr u32 kHardCap = 4096;      // max table size we ever allow
    static constexpr u32 kByteCap = kHardCap;  // packed name+value storage
    static constexpr u32 kMaxEntries = 128;    // kHardCap / min-entry-size(32)

    u8 buf[kByteCap];
    struct Entry {
        u32 off;   // start of name in buf
        u16 nlen;  // name length
        u16 vlen;  // value length
    };
    Entry ents[kMaxEntries];  // ents[0] = oldest, ents[nent-1] = newest
    u32 nent;
    u32 byte_used;   // packed bytes in buf
    u32 table_size;  // sum of entry costs (name+value+32)
    u32 max_size;    // current limit (<= hard_max)
    u32 hard_max;    // negotiated SETTINGS_HEADER_TABLE_SIZE (<= kHardCap)

    // settings_max = the peer's SETTINGS_HEADER_TABLE_SIZE.
    void init(u32 settings_max);
};

// Decode a complete header block from in[0..len) using/updating `dyn`. Decoded
// names/values are written into out_buf[0..out_cap) (static-table refs are not
// copied — they point at constant storage). Fills headers[0..max_headers] and
// sets *count. Returns true on success, false on any decoding error (bad index,
// truncation, capacity/entry overflow, invalid size update).
bool decode_header_block(DynamicTable& dyn,
                         const u8* in,
                         u32 len,
                         u8* out_buf,
                         u32 out_cap,
                         Header* headers,
                         u32 max_headers,
                         u32* count);

// Encode one header field into out without indexing (§6.2.2): an exact
// (name,value) static match becomes an indexed field; a name-only static match
// becomes a literal with the static name index; otherwise both are literals.
// Never mutates a dynamic table (we don't index on the encode side). Literal
// strings are Huffman-coded when shorter. Returns octets written. out must hold
// the worst case (~ name.len + value.len + a few prefix octets).
u32 encode_header(u8* out, Str name, Str value);

}  // namespace rut::hpack
