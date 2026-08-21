#pragma once

#include "rut/common/types.h"

namespace rut {

// I/O event types — shared by both io_uring and epoll backends
enum class IoEventType : u8 {
    Accept,
    Recv,
    Send,
    UpstreamConnect,
    UpstreamRecv,
    UpstreamSend,
    Timeout,       // 1-second TimerWheel tick (keepalive driver)
    HandlerTimer,  // JIT handler yield timer expired. Precise to ms.
                   // io_uring: IORING_OP_TIMEOUT — conn_id identifies the
                   //   target connection whose pending_handler_fn resumes.
                   // epoll:   shared one-shot timerfd — event is a global
                   //   notification; conn_id is unused, the event loop
                   //   drains its min-heap to find which conns to resume.
    Count,
};

static_assert(static_cast<u8>(IoEventType::Count) == 8u,
              "IoEventType should keep all runtime event tags and remain small");

// Future upstream-event token layout in the existing 64-bit user_data budget:
// [63:56] aux (8 bits) | [55:32] upstream episode (24 bits) |
// [31:8] conn_id (24 bits) | [7:0] event type.
// Non-upstream events retain the existing [63:32] full generation field. These
// helpers are used by both upstream transports (io_uring user_data and epoll
// event.data.u64); non-upstream events retain the legacy representation with
// a neutral episode. Episode zero is reserved; lifecycle counters must refuse
// advancement at max and quarantine their owner rather than reuse a token.
inline constexpr u32 kIoUserDataMaxConnId = 0x00FFFFFFu;
inline constexpr u32 kIoUserDataMaxUpstreamEpisode = 0x00FFFFFFu;
// Not representable in the 24-bit token field. Backend decoders use this
// nonzero value for a malformed upstream token so dispatch treats it as stale
// rather than falling back to a neutral legacy event.
inline constexpr u32 kInvalidUpstreamEventEpisode = kIoUserDataMaxUpstreamEpisode + 1u;
inline constexpr u64 kInvalidIoUserData = ~static_cast<u64>(0);

inline constexpr bool io_event_is_upstream(IoEventType type) {
    return type == IoEventType::UpstreamConnect || type == IoEventType::UpstreamRecv ||
           type == IoEventType::UpstreamSend;
}

struct UpstreamEventToken {
    u32 conn_id = 0;
    IoEventType type = IoEventType::Count;
    u32 episode = 0;
    u8 aux = 0;
};

struct NonUpstreamUserData {
    u32 conn_id = 0;
    IoEventType type = IoEventType::Count;
    u32 generation = 0;
};

inline constexpr bool valid_upstream_event_token(const UpstreamEventToken& token) {
    return token.conn_id <= kIoUserDataMaxConnId && io_event_is_upstream(token.type) &&
           token.episode != 0 && token.episode <= kIoUserDataMaxUpstreamEpisode;
}

inline constexpr bool valid_upstream_episode(u32 episode) {
    return episode != 0 && episode <= kIoUserDataMaxUpstreamEpisode;
}

inline constexpr u64 encode_upstream_event_token(const UpstreamEventToken& token) {
    if (!valid_upstream_event_token(token)) return kInvalidIoUserData;
    return static_cast<u64>(static_cast<u8>(token.type)) |
           (static_cast<u64>(token.conn_id) << 8) |
           (static_cast<u64>(token.episode) << 32) |
           (static_cast<u64>(token.aux) << 56);
}

inline constexpr bool decode_upstream_event_token(u64 data, UpstreamEventToken* out) {
    if (out == nullptr) return false;
    UpstreamEventToken token;
    token.type = static_cast<IoEventType>(data & 0xFFu);
    token.conn_id = static_cast<u32>((data >> 8) & kIoUserDataMaxConnId);
    token.episode = static_cast<u32>((data >> 32) & kIoUserDataMaxUpstreamEpisode);
    token.aux = static_cast<u8>(data >> 56);
    if (!valid_upstream_event_token(token)) return false;
    *out = token;
    return true;
}

inline constexpr bool valid_non_upstream_user_data(const NonUpstreamUserData& value) {
    return value.conn_id <= kIoUserDataMaxConnId &&
           static_cast<u8>(value.type) < static_cast<u8>(IoEventType::Count) &&
           !io_event_is_upstream(value.type);
}

inline constexpr u64 encode_non_upstream_user_data(const NonUpstreamUserData& value) {
    if (!valid_non_upstream_user_data(value)) return kInvalidIoUserData;
    return static_cast<u64>(static_cast<u8>(value.type)) |
           (static_cast<u64>(value.conn_id) << 8) |
           (static_cast<u64>(value.generation) << 32);
}

inline constexpr bool decode_non_upstream_user_data(u64 data, NonUpstreamUserData* out) {
    if (out == nullptr) return false;
    NonUpstreamUserData value;
    value.type = static_cast<IoEventType>(data & 0xFFu);
    value.conn_id = static_cast<u32>((data >> 8) & kIoUserDataMaxConnId);
    value.generation = static_cast<u32>(data >> 32);
    if (!valid_non_upstream_user_data(value)) return false;
    *out = value;
    return true;
}

// user_data aux tag marking a pause cancel's OWN completion (vs the recv CQE it
// cancels, aux 0). Shared by the io_uring backend (sets it) and the event loop
// (recognizes it via IoEvent::aux to re-arm only after the cancel has drained).
inline constexpr u8 kPauseCancelAux = 1;
// Local backend submission/registration failure. The completion is synthetic: real
// proxy paths fail closed, while health probes drop it without recording backend health.
inline constexpr u8 kLocalSubmitFailureAux = 2;
// The cancel SQE owned by strict upstream-episode retirement. It is distinct
// from the retiring recv target (aux 0) and from pause/rearm cancellation: its
// final CQE retires only the explicit C1 cancel ownership.
inline constexpr u8 kUpstreamRetirementCancelAux = 3;
// Close-path cancel ownership for a live successor episode. Unlike aux 0
// (the operation target), this completion owns the cancel SQE's pending-op
// count. Keeping it distinct prevents either record from stealing the other.
inline constexpr u8 kUpstreamCloseCancelAux = 4;

inline constexpr u8 kUpstreamOpConnect = 1u << 0;
inline constexpr u8 kUpstreamOpRecv = 1u << 1;
inline constexpr u8 kUpstreamOpSend = 1u << 2;

// Unified completion event — field order optimized for minimal padding.
struct IoEvent {
    u32 conn_id;
    i32 result;  // bytes transferred or error code
    u16 buf_id;  // provided buffer id (io_uring only; valid iff has_buf != 0)
    u8 has_buf;  // non-zero if this event owns a provided buffer in buf_id
    IoEventType type;
    u8 more;     // non-zero if the SQE will produce more CQEs (multishot recv)
    u8 aux = 0;  // decoded user_data aux tag; kPauseCancelAux marks a pause cancel's
                 // own completion (distinct from the recv CQE it cancels)
    u32 upstream_episode = 0;  // neutral for non-upstream/legacy backend events
};

inline constexpr bool io_event_is_tagged_stale(const IoEvent& event, u32 current_episode) {
    return io_event_is_upstream(event.type) &&
           (event.upstream_episode == kInvalidUpstreamEventEpisode ||
            (event.upstream_episode != 0 && event.upstream_episode != current_episode));
}

}  // namespace rut
