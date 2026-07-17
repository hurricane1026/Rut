#pragma once

#include "rut/harness/core.h"
#include "rut/harness/deterministic_environment.h"
#include "rut/jit/handler_abi.h"
#include "rut/runtime/connection_base.h"

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
};

HandlerExecutionResult drive_handler_deterministically(const DeterministicHandlerSpec& driver,
                                                       const HarnessSpec& harness);

}  // namespace rut::harness
