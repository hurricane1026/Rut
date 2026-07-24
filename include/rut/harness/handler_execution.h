#pragma once

#include "rut/harness/core.h"
#include "rut/harness/deterministic_environment.h"
#include "rut/jit/handler_abi.h"
#include "rut/runtime/connection_base.h"
#include <string>

namespace rut::harness {

struct HandlerFrame {
    jit::HandlerCtx context{};
    u64 slots[ConnectionBase::kMaxJitHandlerSlots]{};
};
static_assert(offsetof(HandlerFrame, slots) == sizeof(jit::HandlerCtx),
              "handler slots must immediately follow HandlerCtx");

// Copyable handler-level session. Copying a session forks only the compiled
// handler state; environment/Connection ownership remains with the caller.
struct HandlerExecution {
    HandlerFrame frame{};
    jit::HandlerFn handler = nullptr;
    void* connection = nullptr;
    const u8* request_data = nullptr;
    u32 request_len = 0;
    void* arena = nullptr;

    HandlerExecution() = default;
    HandlerExecution(const HandlerExecution& other);
    HandlerExecution& operator=(const HandlerExecution& other);
    ~HandlerExecution();

    void init(jit::HandlerFn fn,
              void* conn,
              const u8* req_data,
              u32 req_len,
              void* scratch_arena = nullptr);
    jit::HandlerResult invoke();
    void apply_resume(const jit::HandlerResult& yielded, jit::YieldKind kind, i32 result);
    jit::HandlerResult resume(const jit::HandlerResult& yielded, jit::YieldKind kind, i32 result);
};

struct DeterministicHandlerSpec {
    HandlerExecution execution{};
    DeterministicEnvironment* environment = nullptr;
    // Semantic observations already emitted by an outer adapter. This seeds
    // sequence numbers and keeps the run-wide event budget continuous.
    u32 initial_semantic_events = 0;
    // Absolute virtual clock value at handler entry. Completion timestamps and
    // time.nowMicros() share this clock; the run limit remains a duration.
    u64 initial_virtual_time_us = 0;
    // A Timer yield can always complete from its own payload. `Any` also has an
    // intrinsic timeout when its payload is non-zero; other yield kinds require
    // a matching declared event.
    bool auto_complete_timers = true;
};

struct HandlerExecutionResult {
    HarnessResult harness{};
    jit::HandlerResult terminal{};
    bool has_terminal = false;
    u32 consumed_events = 0;
    // Result-owned bytes: callers may inspect the body after the local
    // HandlerExecution frame used by drive_handler_deterministically is gone.
    char dynamic_response_body[jit::kMaxDynamicResponseBodyBytes]{};
    u32 dynamic_response_body_len = 0;
    bool dynamic_response_body_valid = false;
    // Captured upstream responses use the runtime capture-slice budget rather
    // than the smaller dynamic-JSON serializer budget. Keep their identity so
    // empty bodies and captured headers survive the connection adapter.
    char captured_response_body[jit::kMaxCapturedResponseStorageBytes -
                                jit::kCapturedResponseFramingReserve]{};
    u32 captured_response_body_len = 0;
    bool uses_captured_response = false;
    jit::CapturedResponseHeader captured_response_headers[jit::kMaxCapturedResponseHeaders]{};
    std::string captured_response_header_names[jit::kMaxCapturedResponseHeaders];
    std::string captured_response_header_values[jit::kMaxCapturedResponseHeaders];
    u8 captured_response_header_count = 0;
    jit::ResponseHeaderMutation response_header_mutations[jit::kMaxResponseHeaderMutations]{};
    // Header values are copied out of the temporary HandlerExecution so values
    // backed by resp.body snapshots remain valid through result consumption.
    std::string response_header_values[jit::kMaxResponseHeaderMutations];
    u8 response_header_count = 0;
    bool response_header_overflow = false;

    HandlerExecutionResult() = default;
    HandlerExecutionResult(const HandlerExecutionResult& other);
    HandlerExecutionResult& operator=(const HandlerExecutionResult& other);
    HandlerExecutionResult(HandlerExecutionResult&& other);
    HandlerExecutionResult& operator=(HandlerExecutionResult&& other);
};

HandlerExecutionResult drive_handler_deterministically(const DeterministicHandlerSpec& driver,
                                                       const HarnessSpec& harness);

}  // namespace rut::harness
