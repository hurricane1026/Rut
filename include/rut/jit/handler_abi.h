#pragma once

#include "rut/common/types.h"
#include "rut/runtime/route_params.h"

namespace rut {
namespace jit {

// ── Handler Action ─────────────────────────────────────────────────
// What the runtime should do after a JIT handler returns.

enum class HandlerAction : u8 {
    ReturnStatus = 0,  // Send HTTP response with status_code
    Forward = 1,       // Forward request to upstream_id
    Yield = 2,         // Suspend: initiate I/O, resume at next_state
    ForwardBundle = 3, // Forward with a 1-based response/failure bundle id
    Redirect = 4,      // Foundation redirect policy id in upstream_id
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
//   - Forward:      upstream_id is the real upstream index, status_code carries
//                   the request-policy id, and next_state carries the response-
//                   policy id. Both policy ids are zero when absent.
//
// IMPORTANT: We use u64 as the function return type (not a struct)
// because clang uses sret (hidden pointer) for packed structs even
// when they fit in a register. Returning u64 guarantees the value
// goes in RAX, matching the LLVM IR `ret i64`.

struct HandlerResult {
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

    static HandlerResult make_forward_with_policies(u16 upstream,
                                                    u16 request_policy,
                                                    u16 response_policy) {
        return {HandlerAction::Forward,
                request_policy,
                upstream,
                response_policy,
                YieldKind::HttpGet};
    }

    static HandlerResult make_forward_with_bundle(u16 upstream,
                                                  u16 request_policy,
                                                  u16 bundle_id) {
        return {HandlerAction::ForwardBundle,
                request_policy,
                upstream,
                bundle_id,
                YieldKind::HttpGet};
    }

    static HandlerResult make_redirect(u16 policy_id) {
        return {HandlerAction::Redirect, 0, policy_id, 0, YieldKind::HttpGet};
    }

    static bool redirect_fields_valid(const HandlerResult& result) {
        return result.action == HandlerAction::Redirect && result.upstream_id != 0 &&
               result.status_code == 0 && result.next_state == 0 &&
               result.yield_kind == YieldKind::HttpGet;
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
    RouteParam route_params[kMaxRouteParams];

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
