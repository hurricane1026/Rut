#pragma once

#include "rut/common/types.h"
#include "rut/runtime/route_params.h"

namespace rut {
namespace jit {

// ── Handler Action ─────────────────────────────────────────────────
// What the runtime should do after a JIT handler returns.

enum class HandlerAction : u8 {
    ReturnStatus = 0,     // Send HTTP response with status_code
    Forward = 1,          // Forward request to upstream_id
    Yield = 2,            // Suspend: initiate I/O, resume at next_state
    ForwardBuffered = 3,  // Buffer the complete upstream response before publishing it
};

// ── Yield Kind ─────────────────────────────────────────────────────
// Which I/O operation a Yield requests.

enum class YieldKind : u8 {
    HttpGet = 0,
    HttpPost = 1,
    Forward = 2,
    Timer = 3,  // sleep for N ms; payload packed across status_code +
                // upstream_id as a u32 (~49 days). See make_yield_payload /
                // yield_payload_u32.
    Any = 4,
    Recv = 5,
    Send = 6,
    UpstreamConnect = 7,
    UpstreamRecv = 8,
    UpstreamSend = 9,
};

// ── Handler Result ─────────────────────────────────────────────────
// Returned by every JIT handler call as a raw u64. Packed bit layout
// (little-endian byte order):
//
//   byte 0:   action       (HandlerAction)
//   byte 1-2: status_code  (u16, for ReturnStatus)
//   byte 3-4: upstream_id  (u16, for Forward / body-index on ReturnStatus)
//   byte 5-6: next_state   (u16, for Yield)
//   byte 7:   yield_kind   (YieldKind)
//
// Slot reuse by action:
//   - Yield:        status_code + upstream_id carry a packed u32
//                   payload (e.g. Timer ms). See make_yield_payload
//                   / yield_payload_u32.
//   - ReturnStatus: upstream_id carries a 1-based index into
//                   RouteConfig::response_bodies (0 = no custom body,
//                   runtime uses default status-reason phrase).
//   - Forward:      upstream_id is the real upstream index.
//
// IMPORTANT: We use u64 as the function return type (not a struct)
// because clang uses sret (hidden pointer) for packed structs even
// when they fit in a register. Returning u64 guarantees the value
// goes in RAX, matching the LLVM IR `ret i64`.

struct HandlerResult {
    // ReturnStatus reserves this body id for a body serialized at handler
    // runtime. The bytes are exposed through HandlerCtx::response_body_* and
    // must be consumed before the next handler invocation on the shard.
    static constexpr u16 kDynamicResponseBody = 0xffffu;
    HandlerAction action;
    u16 status_code;
    u16 upstream_id;
    u16 next_state;
    YieldKind yield_kind;

    // Pack into u64 for return from JIT.
    u64 pack() const {
        u64 v = 0;
        v |= static_cast<u64>(action);
        v |= static_cast<u64>(status_code) << 8;
        v |= static_cast<u64>(upstream_id) << 24;
        v |= static_cast<u64>(next_state) << 40;
        v |= static_cast<u64>(yield_kind) << 56;
        return v;
    }

    // Unpack from u64 returned by JIT.
    static HandlerResult unpack(u64 v) {
        HandlerResult r;
        r.action = static_cast<HandlerAction>(v & 0xFF);
        r.status_code = static_cast<u16>((v >> 8) & 0xFFFF);
        r.upstream_id = static_cast<u16>((v >> 24) & 0xFFFF);
        r.next_state = static_cast<u16>((v >> 40) & 0xFFFF);
        r.yield_kind = static_cast<YieldKind>((v >> 56) & 0xFF);
        return r;
    }

    static HandlerResult make_status(u16 code) {
        return {HandlerAction::ReturnStatus, code, 0, 0, YieldKind::HttpGet};
    }

    static HandlerResult make_forward(u16 upstream) {
        return {HandlerAction::Forward, 0, upstream, 0, YieldKind::HttpGet};
    }

    static HandlerResult make_buffered_forward(u16 upstream) {
        return {HandlerAction::ForwardBuffered, 0, upstream, 0, YieldKind::HttpGet};
    }

    static HandlerResult make_yield(u16 state, YieldKind kind) {
        return {HandlerAction::Yield, 0, 0, state, kind};
    }

    // Yield with 32-bit payload carried in (upstream_id << 16 | status_code).
    // For Timer kind, payload is milliseconds (u32 ≈ 49 days). Status_code
    // and upstream_id are unused for Yield actions so we co-opt them.
    static HandlerResult make_yield_payload(u16 state, YieldKind kind, u32 payload) {
        return {HandlerAction::Yield,
                static_cast<u16>(payload & 0xFFFFu),
                static_cast<u16>((payload >> 16) & 0xFFFFu),
                state,
                kind};
    }

    // Decode the 32-bit yield payload from a Yield HandlerResult. Caller
    // must have already checked action == Yield.
    u32 yield_payload_u32() const {
        return static_cast<u32>(status_code) | (static_cast<u32>(upstream_id) << 16);
    }
};

inline constexpr u32 kMaxResponseHeaderMutations = 16;
inline constexpr u32 kMaxResponseBodyMutationBytes = 4096;
inline constexpr u32 kMaxDynamicResponseBodyBytes = 7 * 1024;
inline constexpr u32 kMaxDynamicJsonResponseBytes = kMaxDynamicResponseBodyBytes;
inline constexpr u32 kMaxCapturedResponseHeaders = 64;
enum class ResponseHeaderMutationMode : u8 { Set, Add, Remove };
struct ResponseHeaderMutation {
    Str name;
    Str value;
    ResponseHeaderMutationMode mode;
};
struct CapturedResponseHeader {
    Str name;
    Str value;
};
struct ResponseBodySnapshotStorage;

// ── Handler Context ────────────────────────────────────────────────
// Per-request mutable context, allocated from the scratch Arena.
// Holds the state machine index and live-across-yield values.
//
// Layout: [HandlerCtx header + route params] [slot_0] [slot_1] ... [slot_N]
// Each slot is 8-byte aligned. The number and types of slots are
// determined at compile time by the state-splitting pass.

struct alignas(alignof(u64)) HandlerCtx {
    u16 state;                // current state machine state
    u16 handler_idx;          // index into CompiledHandlers::handlers[]
    u32 slot_count;           // number of 8-byte slots following this header
    u32 resume_event_kind;    // YieldKind value that resumed this handler
    i32 resume_event_result;  // IoEvent::result for event waits
    u32 route_param_count;    // number of populated route_params entries
    u32 reserved0;
    const char* response_body_data;  // shard-owned dynamic response bytes
    u32 response_body_len;
    u32 response_body_valid;  // 1 only after successful serialization
    // Lazily materialized upstream response for expression-form buffered
    // forwarding. String views point into Connection::response_capture_slice,
    // never into the reusable proxy receive buffer.
    bool captured_response_valid;
    u16 captured_response_status;
    const char* captured_response_body;
    u32 captured_response_body_len;
    u8 captured_response_header_count;
    CapturedResponseHeader captured_response_headers[kMaxCapturedResponseHeaders];
    // Builder-local mutation log. Pending entries are visible to resp.header();
    // commit publishes exactly this prefix to the terminal response. Keeping
    // it in HandlerCtx makes it survive yields without leaking across streams.
    ResponseHeaderMutation response_header_mutations[kMaxResponseHeaderMutations];
    u8 response_header_pending_count;
    bool response_header_pending_overflow;
    u8 response_header_count;
    bool response_header_overflow;
    // Bounded mutable response scalars. Setters update pending state; the
    // terminal commit publishes it atomically with the header mutation prefix.
    // Keep the raw assigned value so resp.status observes source semantics
    // even when the terminal commit will reject it as an invalid HTTP status.
    i32 response_status_pending;
    bool response_status_pending_set;
    bool response_status_pending_invalid;
    u16 response_status;
    bool response_status_set;
    bool response_status_invalid;
    u32 response_body_pending_len;
    bool response_body_pending_set;
    bool response_body_pending_overflow;
    // Snapshot allocation failure is terminal for this response and must not
    // be cleared by a later otherwise-valid body assignment.
    bool response_body_snapshot_failed;
    u32 response_body_mutation_len;
    bool response_body_mutation_set;
    bool response_body_mutation_overflow;
    RouteParam route_params[kMaxRouteParams];
    // Lazily acquired only when Response.body is assigned. The request owns
    // this pooled buffer until reset (or an H2 parked frame transfers it), so
    // mutable/temporary source bytes survive yields without adding 4 KiB to
    // every preallocated connection context.
    char* response_body_mutation_storage;
    // Immutable copies returned by resp.body. Kept outside HandlerCtx so saved
    // Str values survive later body assignments and yields without embedding
    // another body-sized arena in every preallocated connection.
    ResponseBodySnapshotStorage* response_body_snapshot_storage;

    // Access slot storage (8-byte aligned, immediately after header).
    u8* slots() { return reinterpret_cast<u8*>(this + 1); }
    const u8* slots() const { return reinterpret_cast<const u8*>(this + 1); }

    // Typed slot access.
    template <typename T>
    T load_slot(u32 idx) const {
        static_assert(sizeof(T) <= 8, "Slot values must be <= 8 bytes");
        T val{};
        const u8* src = slots() + static_cast<size_t>(idx) * 8;
        __builtin_memcpy(&val, src, sizeof(T));
        return val;
    }

    template <typename T>
    void store_slot(u32 idx, T val) {
        static_assert(sizeof(T) <= 8, "Slot values must be <= 8 bytes");
        u8* dst = slots() + static_cast<size_t>(idx) * 8;
        u64 zero = 0;
        __builtin_memcpy(dst, &zero, 8);
        __builtin_memcpy(dst, &val, sizeof(T));
    }
};

static_assert(sizeof(HandlerCtx) % alignof(RouteParam) == 0,
              "HandlerCtx route params must preserve alignment");
static_assert(alignof(HandlerCtx) >= alignof(u64), "HandlerCtx must be 8-byte aligned");
static_assert(sizeof(HandlerCtx) % alignof(u64) == 0,
              "HandlerCtx slots must start at an 8-byte-aligned offset");

// ── Handler Function Pointer ───────────────────────────────────────
// JIT-compiled handlers return u64 (not a struct) to guarantee
// RAX return on x86-64. Use HandlerResult::unpack() to interpret.
//
// Parameters:
//   conn      — the connection being processed (read peer_addr, etc.)
//   ctx       — per-request context with state + yield slots
//   req_data  — raw request bytes (recv_buf content)
//   req_len   — request buffer length
//   arena     — scratch arena for temporary allocations

using HandlerFn = u64 (*)(void* conn,  // opaque: Connection* at runtime
                          HandlerCtx* ctx,
                          const u8* req_data,
                          u32 req_len,
                          void* arena  // opaque: SliceArena* at runtime
);

}  // namespace jit
}  // namespace rut
