#pragma once

#include "rut/common/types.h"

namespace rut {
struct SlicePool;
struct WsDeflateCodec;

struct WsDeflateOptions {
    u8 receive_window = 15;
    u8 send_window = 15;
    bool receive_no_context_takeover = false;
};

enum class WsDeflateStatus : u8 { Ok, Limit, Error };

// A leg owns one existing bulk slice containing both codec states and all their
// allocation storage. The opaque codec never allocates from the process heap.
WsDeflateCodec* ws_deflate_create(SlicePool& pool, WsDeflateOptions options);
void ws_deflate_destroy(SlicePool& pool, WsDeflateCodec* codec);
u32 ws_deflate_storage_used(const WsDeflateCodec& codec);
bool ws_deflate_matches(const WsDeflateCodec& codec, WsDeflateOptions options);

// Wire work has its own bound, so streams made of empty blocks cannot bypass
// the decoded-message budget. It admits normal incompressible DEFLATE overhead.
constexpr u32 ws_deflate_wire_limit(u32 decoded_limit) {
    return decoded_limit + decoded_limit / 8 + 1024;
}

bool ws_inflate_begin(WsDeflateCodec& codec, u32 decoded_limit);
// Input may be a fragment or part of a fragment. Final appends RFC 7692's removed
// four-byte sync-flush tail and validates the block boundary. Output accumulates
// from offset zero in caller-owned message storage; output_len reports the total.
// An optional mask is applied using the offset within the current wire frame.
// A decode failure poisons this codec; the connection must retire it.
WsDeflateStatus ws_inflate_chunk(WsDeflateCodec& codec,
                                 const u8* input,
                                 u32 length,
                                 bool final,
                                 u8* output,
                                 u32 capacity,
                                 u32* output_len,
                                 const u8* mask_key = nullptr,
                                 u64 mask_offset = 0);

// Encoders start a fresh dictionary per message, which is also legal when
// context takeover is allowed. Limit leaves no published output: callers can
// choose an uncompressed frame without changing the payload-size contract.
WsDeflateStatus ws_deflate_payload(
    WsDeflateCodec& codec, const u8* input, u32 length, u8* output, u32 capacity, u32* output_len);
}  // namespace rut
