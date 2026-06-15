#pragma once

#include "rut/common/types.h"
#include "rut/runtime/http_parser.h"  // ParseStatus

// HTTP/2 framing primitives (RFC 7540 §4–6). Pure, zero-allocation
// parse/serialize helpers for the 9-octet frame header, the client connection
// preface, and SETTINGS. Stream multiplexing, flow control, and HPACK live in
// later layers; this file only deals with raw frames.
namespace rut {

// 9-octet frame header (RFC 7540 §4.1).
static constexpr u32 kFrameHeaderSize = 9;

// Default and bound values from RFC 7540 §6.5.2 / §6.9.
static constexpr u32 kDefaultHeaderTableSize = 4096;
static constexpr u32 kDefaultInitialWindowSize = 65535;
static constexpr u32 kDefaultMaxFrameSize = 16384;     // 2^14
static constexpr u32 kMaxAllowedFrameSize = 16777215;  // 2^24 - 1
static constexpr u32 kMaxWindowSize = 2147483647;      // 2^31 - 1

enum class Http2FrameType : u8 {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    Goaway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
};

// Frame flags (RFC 7540 §6). Values overlap across frame types by design
// (END_STREAM and ACK are both 0x1 on their respective frames).
namespace http2_flag {
static constexpr u8 kEndStream = 0x1;
static constexpr u8 kAck = 0x1;
static constexpr u8 kEndHeaders = 0x4;
static constexpr u8 kPadded = 0x8;
static constexpr u8 kPriority = 0x20;
}  // namespace http2_flag

// Error codes (RFC 7540 §7) used by GOAWAY / RST_STREAM. Base type mirrors the
// 32-bit on-wire field; never stored in bulk, so the size is immaterial.
// NOLINTNEXTLINE(performance-enum-size)
enum class Http2Error : u32 {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
};

// Settings identifiers (RFC 7540 §6.5.2). Unknown ids must be ignored. Base
// type mirrors the 16-bit on-wire field so casting a raw id never truncates.
// NOLINTNEXTLINE(performance-enum-size)
enum class Http2SettingId : u16 {
    HeaderTableSize = 0x1,
    EnablePush = 0x2,
    MaxConcurrentStreams = 0x3,
    InitialWindowSize = 0x4,
    MaxFrameSize = 0x5,
    MaxHeaderListSize = 0x6,
};

struct Http2FrameHeader {
    u32 length;     // 24-bit payload length (excludes the 9-octet header)
    u32 stream_id;  // 31-bit; reserved bit always masked off
    u8 type;        // Http2FrameType (kept as u8 — unknown types are valid)
    u8 flags;
};

// Parse a frame header from buf[0..len). Returns Incomplete if fewer than 9
// bytes are available, Complete on success. Never Error: any 9 bytes form a
// syntactically valid header (semantic checks happen at higher layers). The
// reserved bit of the stream id is masked off per §4.1.
ParseStatus parse_frame_header(const u8* buf, u32 len, Http2FrameHeader* out);

// Write a 9-octet frame header into out (must hold >= kFrameHeaderSize bytes).
// length is truncated to 24 bits and stream_id to 31 bits. Returns 9.
u32 write_frame_header(u8* out, const Http2FrameHeader& h);

// Client connection preface (RFC 7540 §3.5): the exact 24 bytes a client sends
// before its first frame.
static constexpr u32 kClientPrefaceLen = 24;
extern const u8 kClientPreface[kClientPrefaceLen];

// Match the client preface at buf[0..len). Complete = full 24-byte match,
// Incomplete = buf is a (shorter) prefix of the preface, Error = mismatch.
ParseStatus match_client_preface(const u8* buf, u32 len);

// Connection SETTINGS state (RFC 7540 §6.5.2). set_defaults() seeds the
// protocol defaults; parse_settings applies a peer's SETTINGS payload.
struct Http2Settings {
    u32 header_table_size;
    u32 enable_push;  // 0 or 1
    u32 max_concurrent_streams;
    u32 initial_window_size;
    u32 max_frame_size;
    u32 max_header_list_size;
    bool has_max_concurrent_streams;
    bool has_max_header_list_size;

    void set_defaults() {
        header_table_size = kDefaultHeaderTableSize;
        enable_push = 1;
        max_concurrent_streams = 0;
        initial_window_size = kDefaultInitialWindowSize;
        max_frame_size = kDefaultMaxFrameSize;
        max_header_list_size = 0;
        has_max_concurrent_streams = false;
        has_max_header_list_size = false;
    }
};

// Apply a SETTINGS frame payload (the bytes after the frame header) onto `s`.
// payload is a sequence of 6-octet (id:16, value:32) entries. Unknown ids are
// ignored per §6.5.2. Returns the connection error code: NoError on success,
// FrameSizeError if len is not a multiple of 6, ProtocolError/FlowControlError
// for out-of-range ENABLE_PUSH / INITIAL_WINDOW_SIZE / MAX_FRAME_SIZE values.
Http2Error parse_settings(const u8* payload, u32 len, Http2Settings* s);

// Serialize a SETTINGS frame (header + payload) advertising the given settings
// into out (must hold kFrameHeaderSize + 6*entries). Only non-default values we
// care to announce are written. Returns total bytes written.
u32 write_settings_frame(u8* out, const Http2Settings& s);

// Serialize an empty SETTINGS frame with the ACK flag (RFC 7540 §6.5.3) into
// out (must hold >= kFrameHeaderSize). Returns kFrameHeaderSize.
u32 write_settings_ack(u8* out);

// Serialize a GOAWAY frame (RFC 7540 §6.8) into out (must hold
// kFrameHeaderSize + 8). Returns total bytes written.
u32 write_goaway(u8* out, u32 last_stream_id, Http2Error error);

// Serialize a WINDOW_UPDATE frame (RFC 7540 §6.9) into out (must hold
// kFrameHeaderSize + 4). stream_id 0 targets the whole connection. Returns
// total bytes written.
u32 write_window_update(u8* out, u32 stream_id, u32 increment);

// Serialize an RST_STREAM frame (RFC 7540 §6.4) into out (must hold
// kFrameHeaderSize + 4). Returns total bytes written.
u32 write_rst_stream(u8* out, u32 stream_id, Http2Error error);

}  // namespace rut
