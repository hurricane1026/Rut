#include "rut/runtime/ws_deflate.h"

#include "rut/common/types.h"

#if RUT_ENABLE_WEBSOCKET
#include "rut/runtime/slice_pool.h"
#include "rut/runtime/ws_frame.h"
#include "rut/runtime/ws_terminate.h"

// Keep the pinned C codec's headers private, with the same ABI definitions as
// its static target. Z_SOLO removes its default malloc/calloc/free implementation.
#define Z_SOLO
#define Z_PREFIX
#define ZLIB_CONST
#include <string.h>
#include <zconf.h>
#include <zlib.h>

namespace rut {
struct WsDeflateCodec {
    z_stream decoder{};
    z_stream encoder{};
    WsDeflateOptions options{};
    u32 used = sizeof(WsDeflateCodec);
    u32 decoded = 0;
    u32 decoded_limit = 0;
    u32 wire_bytes = 0;
    bool decoding = false;
    bool failed = false;
    u8 scratch[4096]{};
};

namespace {
voidpf codec_alloc(voidpf opaque, uInt items, uInt size) {
    auto& codec = *static_cast<WsDeflateCodec*>(opaque);
    const u64 kBytes = static_cast<u64>(items) * size;
    const u32 kStart = (codec.used + 15u) & ~15u;
    if (kStart > SlicePool::kBulkSliceSize || kBytes > SlicePool::kBulkSliceSize - kStart)
        return nullptr;
    u8* const kResult = reinterpret_cast<u8*>(&codec) + kStart;
    memset(kResult, 0, kBytes);
    codec.used = kStart + static_cast<u32>(kBytes);
    return kResult;
}
void codec_free(voidpf, voidpf) {}

WsDeflateStatus inflate_bytes(
    WsDeflateCodec& codec, const u8* input, u32 length, u8* output, bool& boundary) {
    auto& stream = codec.decoder;
    stream.next_in = input;
    stream.avail_in = length;
    for (;;) {
        u8 excess = 0;
        const bool kAtLimit = codec.decoded == codec.decoded_limit;
        stream.next_out = kAtLimit ? &excess : output + codec.decoded;
        stream.avail_out = kAtLimit ? 1u : codec.decoded_limit - codec.decoded;
        const u32 kBeforeInput = stream.avail_in;
        const u32 kBeforeOutput = stream.avail_out;
        const int kStatus = inflate(&stream, Z_BLOCK);
        const u32 kProduced = kBeforeOutput - stream.avail_out;
        if (kAtLimit && kProduced) return WsDeflateStatus::Limit;
        codec.decoded += kProduced;
        boundary = (stream.data_type & 128) != 0 && (stream.data_type & 63) == 0;
        if (kStatus == Z_STREAM_END) {
            // RFC 7692 permits BFINAL=1 followed by further blocks. Keep the
            // received history while resetting the raw stream's framing state.
            if (inflateResetKeep(&stream) != Z_OK) return WsDeflateStatus::Error;
            boundary = false;
            if (stream.avail_in != 0) continue;
        } else if (kStatus != Z_OK && kStatus != Z_BUF_ERROR) {
            return WsDeflateStatus::Error;
        }
        if (stream.avail_in == 0 && (stream.avail_out != 0 || boundary)) return WsDeflateStatus::Ok;
        if (stream.avail_in == kBeforeInput && kProduced == 0)
            return stream.avail_in == 0 ? WsDeflateStatus::Ok : WsDeflateStatus::Error;
    }
}
}  // namespace

WsDeflateCodec* ws_deflate_create(SlicePool& pool, WsDeflateOptions options) {
    if (options.receive_window < 8 || options.receive_window > 15 || options.send_window < 8 ||
        options.send_window > 15)
        return nullptr;
    u8* const kStorage = pool.alloc_bulk();
    if (!kStorage) return nullptr;
    auto* codec = new (kStorage) WsDeflateCodec{};
    codec->options = options;
    codec->decoder.zalloc = codec_alloc;
    codec->decoder.zfree = codec_free;
    codec->decoder.opaque = codec;
    codec->encoder.zalloc = codec_alloc;
    codec->encoder.zfree = codec_free;
    codec->encoder.opaque = codec;
    const int kDecode = inflateInit2(&codec->decoder, -options.receive_window);
    if (kDecode != Z_OK) {
        pool.free(kStorage);
        return nullptr;
    }
    // zlib's encoder needs at least a 9-bit window. At negotiated 8 bits,
    // Huffman-only coding emits no backward distances and respects that bound.
    const int kWindow = options.send_window == 8 ? 9 : options.send_window;
    const int kStrategy = options.send_window == 8 ? Z_HUFFMAN_ONLY : Z_DEFAULT_STRATEGY;
    if (deflateInit2(&codec->encoder, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -kWindow, 5, kStrategy) !=
        Z_OK) {
        inflateEnd(&codec->decoder);
        pool.free(kStorage);
        return nullptr;
    }
    return codec;
}

void ws_deflate_destroy(SlicePool& pool, WsDeflateCodec* codec) {
    if (!codec) return;
    deflateEnd(&codec->encoder);
    inflateEnd(&codec->decoder);
    codec->~WsDeflateCodec();
    pool.free(reinterpret_cast<u8*>(codec));
}

u32 ws_deflate_storage_used(const WsDeflateCodec& codec) {
    return codec.used;
}

bool ws_deflate_matches(const WsDeflateCodec& codec, WsDeflateOptions options) {
    return !codec.failed && codec.options.receive_window == options.receive_window &&
           codec.options.send_window == options.send_window &&
           codec.options.receive_no_context_takeover == options.receive_no_context_takeover;
}

bool ws_inflate_begin(WsDeflateCodec& codec, u32 decoded_limit) {
    if (codec.failed || codec.decoding || !ws_valid_message_capacity(decoded_limit)) return false;
    if (codec.options.receive_no_context_takeover && inflateReset(&codec.decoder) != Z_OK)
        return false;
    codec.decoded = 0;
    codec.wire_bytes = 0;
    codec.decoded_limit = decoded_limit;
    codec.decoding = true;
    return true;
}

WsDeflateStatus ws_inflate_chunk(WsDeflateCodec& codec,
                                 const u8* input,
                                 u32 length,
                                 bool final,
                                 u8* output,
                                 u32 capacity,
                                 u32* output_len,
                                 const u8* mask_key,
                                 u64 mask_offset) {
    if (!output_len) return WsDeflateStatus::Error;
    *output_len = 0;
    if (!codec.decoding || !output || capacity < codec.decoded_limit || (!input && length))
        return WsDeflateStatus::Error;
    if (length > ws_deflate_wire_limit(codec.decoded_limit) - codec.wire_bytes) {
        codec.decoding = false;
        codec.failed = true;
        return WsDeflateStatus::Limit;
    }
    codec.wire_bytes += length;
    bool boundary = false;
    u32 offset = 0;
    do {
        const u32 kTake = length - offset < sizeof(codec.scratch)
                              ? length - offset
                              : static_cast<u32>(sizeof(codec.scratch));
        const u8* source = input ? input + offset : nullptr;
        if (mask_key && kTake) {
            memcpy(codec.scratch, source, kTake);
            ws_unmask_chunk(codec.scratch, kTake, mask_key, mask_offset + offset);
            source = codec.scratch;
        }
        const auto kStatus = inflate_bytes(codec, source, kTake, output, boundary);
        if (kStatus != WsDeflateStatus::Ok) {
            codec.decoding = false;
            codec.failed = true;
            return kStatus;
        }
        offset += kTake;
    } while (offset < length);
    if (final) {
        static constexpr u8 kTail[] = {0, 0, 0xff, 0xff};
        const auto kStatus = inflate_bytes(codec, kTail, sizeof(kTail), output, boundary);
        codec.decoding = false;
        if (kStatus != WsDeflateStatus::Ok || !boundary) {
            codec.failed = true;
            return kStatus != WsDeflateStatus::Ok ? kStatus : WsDeflateStatus::Error;
        }
    }
    *output_len = codec.decoded;
    return WsDeflateStatus::Ok;
}

WsDeflateStatus ws_deflate_payload(
    WsDeflateCodec& codec, const u8* input, u32 length, u8* output, u32 capacity, u32* output_len) {
    if (!output_len) return WsDeflateStatus::Error;
    *output_len = 0;
    if ((!input && length) || !output || length > kWsMaxMessageCapacity)
        return WsDeflateStatus::Error;
    if (capacity < 4) return WsDeflateStatus::Limit;
    auto& stream = codec.encoder;
    if (deflateReset(&stream) != Z_OK) return WsDeflateStatus::Error;
    stream.next_in = input;
    stream.avail_in = length;
    stream.next_out = output;
    stream.avail_out = capacity;
    const int kStatus = deflate(&stream, Z_SYNC_FLUSH);
    if (kStatus != Z_OK) return WsDeflateStatus::Error;
    if (stream.avail_in || stream.avail_out == 0) return WsDeflateStatus::Limit;
    const u32 kWritten = capacity - stream.avail_out;
    static constexpr u8 kTail[] = {0, 0, 0xff, 0xff};
    if (kWritten < sizeof(kTail) ||
        memcmp(output + kWritten - sizeof(kTail), kTail, sizeof(kTail)) != 0)
        return WsDeflateStatus::Error;
    *output_len = kWritten - sizeof(kTail);
    return WsDeflateStatus::Ok;
}
}  // namespace rut
#endif
