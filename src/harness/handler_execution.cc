#include "rut/harness/handler_execution.h"

#include "rut/jit/runtime_helpers.h"
#include "rut/runtime/response_body_storage.h"

namespace rut::harness {
namespace {

void copy_detail(char* dst, u32 cap, const char* src) {
    if (cap == 0) return;
    u32 i = 0;
    while (src[i] != '\0' && i + 1 < cap) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

struct EventPublisher {
    const HarnessSpec& spec;
    HarnessResult& result;

    bool emit(ObservationKind kind, u64 value0 = 0, u64 value1 = 0, Str label = {}) {
        if (result.semantic_events >= spec.limits.max_semantic_events) {
            result.outcome = Outcome::Failed;
            result.has_reached_limit = true;
            result.reached_limit = LimitKind::SemanticEvents;
            copy_detail(result.detail, sizeof(result.detail), "semantic-events limit reached");
            return false;
        }
        Observation event{};
        event.kind = kind;
        event.phase = Phase::Drive;
        event.sequence = result.semantic_events;
        event.timestamp_us = result.virtual_time_us;
        event.value0 = value0;
        event.value1 = value1;
        event.label = label;
        result.semantic_events++;
        if (!spec.observations.publish(event)) {
            result.outcome = Outcome::Mismatched;
            copy_detail(result.detail, sizeof(result.detail), "observation rejected by oracle");
            return false;
        }
        return true;
    }
};

}  // namespace

HandlerExecution::HandlerExecution(const HandlerExecution& other) {
    *this = other;
}

HandlerExecution& HandlerExecution::operator=(const HandlerExecution& other) {
    if (this == &other) return *this;
    rut_helper_resp_release_body_storage(&frame.context);
    frame = other.frame;
    jit::retain_response_body_snapshot_storage(&frame.context);
    frame.context.response_body_mutation_storage = nullptr;
    if (other.frame.context.response_body_mutation_storage != nullptr) {
        frame.context.response_body_mutation_storage =
            jit::acquire_response_body_mutation_storage();
        if (frame.context.response_body_mutation_storage == nullptr) {
            frame.context.response_body_pending_overflow = true;
            frame.context.response_body_mutation_overflow = true;
            frame.context.response_body_pending_len = 0;
            frame.context.response_body_mutation_len = 0;
        } else {
            const u32 copy_len = other.frame.context.response_body_pending_len >
                                         other.frame.context.response_body_mutation_len
                                     ? other.frame.context.response_body_pending_len
                                     : other.frame.context.response_body_mutation_len;
            if (copy_len > jit::kMaxResponseBodyMutationBytes) {
                frame.context.response_body_pending_overflow = true;
                frame.context.response_body_mutation_overflow = true;
                frame.context.response_body_pending_len = 0;
                frame.context.response_body_mutation_len = 0;
            } else if (copy_len != 0) {
                __builtin_memcpy(frame.context.response_body_mutation_storage,
                                 other.frame.context.response_body_mutation_storage,
                                 copy_len);
            }
        }
    }
    handler = other.handler;
    connection = other.connection;
    request_data = other.request_data;
    request_len = other.request_len;
    arena = other.arena;
    return *this;
}

HandlerExecution::~HandlerExecution() {
    rut_helper_resp_release_body_storage(&frame.context);
}

HandlerExecutionResult::HandlerExecutionResult(const HandlerExecutionResult& other) {
    *this = other;
}

HandlerExecutionResult& HandlerExecutionResult::operator=(const HandlerExecutionResult& other) {
    if (this == &other) return *this;
    harness = other.harness;
    terminal = other.terminal;
    has_terminal = other.has_terminal;
    consumed_events = other.consumed_events;
    __builtin_memcpy(
        dynamic_response_body, other.dynamic_response_body, sizeof(dynamic_response_body));
    dynamic_response_body_len = other.dynamic_response_body_len;
    dynamic_response_body_valid = other.dynamic_response_body_valid;
    response_header_count = other.response_header_count;
    response_header_overflow = other.response_header_overflow;
    for (u32 i = 0; i < jit::kMaxResponseHeaderMutations; i++) {
        response_header_mutations[i] = other.response_header_mutations[i];
        response_header_values[i] = other.response_header_values[i];
        if (response_header_mutations[i].value.ptr != nullptr) {
            response_header_mutations[i].value.ptr = response_header_values[i].data();
            response_header_mutations[i].value.len =
                static_cast<u32>(response_header_values[i].size());
        }
    }
    return *this;
}

HandlerExecutionResult::HandlerExecutionResult(HandlerExecutionResult&& other) {
    *this = other;
}

HandlerExecutionResult& HandlerExecutionResult::operator=(HandlerExecutionResult&& other) {
    return *this = static_cast<const HandlerExecutionResult&>(other);
}

void HandlerExecution::init(
    jit::HandlerFn fn, void* conn, const u8* req_data, u32 req_len, void* scratch_arena) {
    rut_helper_resp_release_body_storage(&frame.context);
    frame = HandlerFrame{};
    frame.context.state = 0;
    frame.context.handler_idx = 0;
    frame.context.slot_count = ConnectionBase::kMaxJitHandlerSlots;
    handler = fn;
    connection = conn;
    request_data = req_data;
    request_len = req_len;
    arena = scratch_arena;
}

jit::HandlerResult HandlerExecution::invoke() {
    if (handler == nullptr) return jit::HandlerResult::make_yield(0, jit::YieldKind::Any);
    return jit::HandlerResult::unpack(
        handler(connection, &frame.context, request_data, request_len, arena));
}

void HandlerExecution::apply_resume(const jit::HandlerResult& yielded,
                                    jit::YieldKind kind,
                                    i32 result) {
    frame.context.resume_event_kind = static_cast<u32>(kind);
    frame.context.resume_event_result = result;
    frame.context.state = yielded.next_state;
}

jit::HandlerResult HandlerExecution::resume(const jit::HandlerResult& yielded,
                                            jit::YieldKind kind,
                                            i32 result) {
    apply_resume(yielded, kind, result);
    return invoke();
}

HandlerExecutionResult drive_handler_deterministically(const DeterministicHandlerSpec& driver,
                                                       const HarnessSpec& harness) {
    HandlerExecutionResult out{};
    out.harness = validate_spec(harness);
    if (out.harness.outcome != Outcome::Passed) return out;
    out.harness.phase = Phase::Drive;
    out.harness.cleanup = CleanupOutcome::NotRun;
    out.harness.semantic_events = driver.initial_semantic_events;
    out.harness.virtual_time_us = driver.initial_virtual_time_us;
    struct CleanupMarker {
        HarnessResult& result;
        ~CleanupMarker() { result.cleanup = CleanupOutcome::Clean; }
    } cleanup{out.harness};

    if (harness.layer != ExecutionLayer::Handler) {
        out.harness.outcome = Outcome::Invalid;
        copy_detail(out.harness.detail,
                    sizeof(out.harness.detail),
                    "handler driver requires handler layer");
        return out;
    }
    if (driver.execution.handler == nullptr) {
        out.harness.outcome = Outcome::Invalid;
        copy_detail(out.harness.detail, sizeof(out.harness.detail), "handler is null");
        return out;
    }
    if (driver.execution.request_len > harness.limits.max_input_bytes) {
        out.harness.outcome = Outcome::Failed;
        out.harness.has_reached_limit = true;
        out.harness.reached_limit = LimitKind::InputBytes;
        copy_detail(out.harness.detail, sizeof(out.harness.detail), "input-bytes limit reached");
        return out;
    }
    out.harness.input_bytes = driver.execution.request_len;
    HandlerExecution execution = driver.execution;
    DeterministicEnvironment environment{};
    if (driver.environment != nullptr) {
        environment.reset(driver.environment->completions, driver.environment->completion_count);
        if (!environment.schedule_valid) {
            out.harness.outcome = Outcome::Invalid;
            copy_detail(out.harness.detail,
                        sizeof(out.harness.detail),
                        "deterministic completion schedule is invalid");
            return out;
        }
    }
    environment.now_us = driver.initial_virtual_time_us;
    const u64 virtual_deadline_us =
        harness.limits.max_virtual_time_us > ~u64{0} - driver.initial_virtual_time_us
            ? ~u64{0}
            : driver.initial_virtual_time_us + harness.limits.max_virtual_time_us;
    const u64* previous_virtual_clock = rut_helper_time_set_virtual_clock(&environment.now_us);
    struct VirtualClockRestore {
        const u64* previous;
        ~VirtualClockRestore() { (void)rut_helper_time_set_virtual_clock(previous); }
    } virtual_clock_restore{previous_virtual_clock};
    EventPublisher publisher{harness, out.harness};
    if (!publisher.emit(ObservationKind::HandlerEntered)) return out;
    jit::HandlerResult result = execution.invoke();

    while (result.action == jit::HandlerAction::Yield) {
        if (!publisher.emit(ObservationKind::HandlerYielded,
                            static_cast<u64>(result.yield_kind),
                            result.yield_payload_u32()))
            return out;

        if (out.harness.handler_resumes >= harness.limits.max_handler_resumes) {
            out.harness.outcome = Outcome::Failed;
            out.harness.has_reached_limit = true;
            out.harness.reached_limit = LimitKind::HandlerResumes;
            copy_detail(
                out.harness.detail, sizeof(out.harness.detail), "handler-resumes limit reached");
            (void)publisher.emit(ObservationKind::LimitReached,
                                 out.harness.handler_resumes,
                                 harness.limits.max_handler_resumes,
                                 {"handler-resumes", 15});
            return out;
        }

        DeterministicCompletion event{};
        u64 earliest_timer_at_us = environment.now_us;
        CompletionStatus completion = CompletionStatus::Ready;
        if (result.yield_kind == jit::YieldKind::Timer ||
            (result.yield_kind == jit::YieldKind::Any && result.yield_payload_u32() != 0)) {
            const u64 delay_us = static_cast<u64>(result.yield_payload_u32()) * 1000u;
            if (delay_us > virtual_deadline_us - environment.now_us)
                completion = CompletionStatus::TimeLimit;
            else
                earliest_timer_at_us += delay_us;
        }
        if (completion == CompletionStatus::Ready) {
            const u32 yielded_target = result.yield_kind == jit::YieldKind::Any ||
                                               result.yield_kind == jit::YieldKind::Timer
                                           ? DeterministicCompletion::kAnyTarget
                                           : result.yield_payload_u32();
            completion = environment.next(result.yield_kind,
                                          yielded_target,
                                          earliest_timer_at_us,
                                          virtual_deadline_us,
                                          event);
        }
        const bool has_intrinsic_timer =
            result.yield_kind == jit::YieldKind::Timer ||
            (result.yield_kind == jit::YieldKind::Any && result.yield_payload_u32() != 0);
        if ((completion == CompletionStatus::Empty ||
             completion == CompletionStatus::KindMismatch) &&
            driver.auto_complete_timers && has_intrinsic_timer) {
            completion =
                environment.complete_timer(result.yield_payload_u32(), virtual_deadline_us, event);
        }

        if (completion == CompletionStatus::Empty || completion == CompletionStatus::KindMismatch ||
            completion == CompletionStatus::TargetMismatch) {
            out.harness.outcome = Outcome::Stalled;
            copy_detail(out.harness.detail,
                        sizeof(out.harness.detail),
                        completion == CompletionStatus::Empty
                            ? "handler yielded without a matching completion"
                        : completion == CompletionStatus::TargetMismatch
                            ? "next completion targets a different resource"
                            : "next completion does not satisfy yielded operation");
            return out;
        }
        if (completion == CompletionStatus::InvalidSchedule) {
            out.harness.outcome = Outcome::Invalid;
            copy_detail(out.harness.detail,
                        sizeof(out.harness.detail),
                        "deterministic completion schedule is invalid");
            return out;
        }
        if (completion == CompletionStatus::TooEarly) {
            out.harness.outcome = Outcome::Invalid;
            copy_detail(out.harness.detail,
                        sizeof(out.harness.detail),
                        "completion is scheduled before the operation can finish");
            return out;
        }
        if (completion == CompletionStatus::TimeLimit) {
            out.harness.outcome = Outcome::Failed;
            out.harness.has_reached_limit = true;
            out.harness.reached_limit = LimitKind::VirtualDuration;
            copy_detail(
                out.harness.detail, sizeof(out.harness.detail), "virtual-duration limit reached");
            return out;
        }

        out.harness.virtual_time_us = environment.now_us;
        out.consumed_events = environment.cursor;
        if (event.data_len != 0 && event.kind != jit::YieldKind::Recv &&
            event.kind != jit::YieldKind::UpstreamRecv && event.kind != jit::YieldKind::Forward) {
            out.harness.outcome = Outcome::Invalid;
            copy_detail(out.harness.detail,
                        sizeof(out.harness.detail),
                        "scripted data requires a recv or forward completion");
            return out;
        }
        if (event.data_len != 0 && event.kind != jit::YieldKind::Forward &&
            event.result != static_cast<i32>(event.data_len)) {
            out.harness.outcome = Outcome::Invalid;
            copy_detail(out.harness.detail,
                        sizeof(out.harness.detail),
                        "recv result does not match scripted data length");
            return out;
        }
        if (event.kind == jit::YieldKind::Forward) {
            if (event.response_status < 100 || event.response_status > 599 ||
                event.response_header_count > jit::kMaxCapturedResponseHeaders ||
                (event.response_header_count != 0 && event.response_headers == nullptr) ||
                (event.data_len != 0 && event.data == nullptr)) {
                out.harness.outcome = Outcome::Invalid;
                copy_detail(out.harness.detail,
                            sizeof(out.harness.detail),
                            "forward completion requires a valid response fixture");
                return out;
            }
            auto& response = execution.frame.context;
            response.captured_response_valid = true;
            response.captured_response_status = event.response_status;
            response.captured_response_body = reinterpret_cast<const char*>(event.data);
            response.captured_response_body_len = event.data_len;
            response.captured_response_header_count = event.response_header_count;
            for (u32 i = 0; i < event.response_header_count; i++)
                response.captured_response_headers[i] = event.response_headers[i];
            event.result = event.response_status;
        }
        if (event.data_len > harness.limits.max_input_bytes - out.harness.input_bytes) {
            out.harness.outcome = Outcome::Failed;
            out.harness.has_reached_limit = true;
            out.harness.reached_limit = LimitKind::InputBytes;
            copy_detail(
                out.harness.detail, sizeof(out.harness.detail), "input-bytes limit reached");
            return out;
        }
        out.harness.input_bytes += event.data_len;
        if (out.harness.backend_completions >= harness.limits.max_backend_completions) {
            out.harness.outcome = Outcome::Failed;
            out.harness.has_reached_limit = true;
            out.harness.reached_limit = LimitKind::BackendCompletions;
            copy_detail(out.harness.detail,
                        sizeof(out.harness.detail),
                        "backend-completions limit reached");
            return out;
        }
        out.harness.backend_completions++;
        if (event.logical_fault_point) {
            out.harness.fault_points_reached++;
            if (!publisher.emit(
                    ObservationKind::FaultReached, static_cast<u64>(event.kind), event.target_id))
                return out;
        }
        if (event.injected_fault) out.harness.faults_injected++;
        if (event.injected_fault &&
            !publisher.emit(ObservationKind::FaultInjected,
                            static_cast<u64>(event.kind),
                            static_cast<u64>(static_cast<i64>(event.result))))
            return out;
        if (!publisher.emit(ObservationKind::WaitCompleted,
                            static_cast<u64>(event.kind),
                            static_cast<u64>(static_cast<i64>(event.result))))
            return out;
        out.harness.handler_resumes++;
        result = execution.resume(result, event.kind, event.result);
        if (!publisher.emit(ObservationKind::HandlerResumed,
                            static_cast<u64>(event.kind),
                            out.harness.handler_resumes))
            return out;
    }

    const auto& response = execution.frame.context;
    bool returned_captured_response = false;
    if (result.action == jit::HandlerAction::ReturnStatus) {
        returned_captured_response = result.status_code == 0;
        const bool returned_dynamic_json =
            result.upstream_id == jit::HandlerResult::kDynamicResponseBody;
        const bool dynamic_json_failed =
            returned_dynamic_json &&
            (response.response_body_valid == 0 || response.response_body_data == nullptr);
        if (response.response_status_invalid || response.response_body_mutation_overflow ||
            dynamic_json_failed ||
            (returned_captured_response && !response.captured_response_valid)) {
            result = jit::HandlerResult::make_status(500);
            returned_captured_response = false;
        } else {
            if (returned_captured_response)
                result.status_code = response.captured_response_status;
            if (response.response_status_set) result.status_code = response.response_status;
            if (response.response_body_mutation_set)
                result.upstream_id = jit::HandlerResult::kDynamicResponseBody;
        }
    }
    out.terminal = result;
    out.has_terminal = true;
    if (result.action == jit::HandlerAction::ReturnStatus &&
        (result.upstream_id == jit::HandlerResult::kDynamicResponseBody ||
         returned_captured_response)) {
        const char* body = nullptr;
        if (response.response_body_mutation_set) {
            body = response.response_body_mutation_storage;
            out.dynamic_response_body_len = response.response_body_mutation_len;
            out.dynamic_response_body_valid = !response.response_body_mutation_overflow;
        } else if (returned_captured_response) {
            body = response.captured_response_body;
            out.dynamic_response_body_len = response.captured_response_body_len;
            out.dynamic_response_body_valid = response.captured_response_valid;
        } else {
            body = response.response_body_data;
            out.dynamic_response_body_len = response.response_body_len;
            out.dynamic_response_body_valid = response.response_body_valid != 0;
        }
        if (body == nullptr || out.dynamic_response_body_len > jit::kMaxDynamicResponseBodyBytes) {
            out.dynamic_response_body_len = 0;
            out.dynamic_response_body_valid = false;
        } else if (out.dynamic_response_body_len != 0) {
            __builtin_memcpy(out.dynamic_response_body, body, out.dynamic_response_body_len);
        }
    }
    out.response_header_count = execution.frame.context.response_header_count;
    out.response_header_overflow = execution.frame.context.response_header_overflow;
    for (u32 i = 0; i < out.response_header_count; i++) {
        out.response_header_mutations[i] = execution.frame.context.response_header_mutations[i];
        auto& mutation = out.response_header_mutations[i];
        if (mutation.value.ptr != nullptr) {
            out.response_header_values[i].assign(mutation.value.ptr, mutation.value.len);
            mutation.value.ptr = out.response_header_values[i].data();
        }
    }
    if (!publisher.emit(ObservationKind::HandlerTerminated,
                        static_cast<u64>(result.action),
                        result.action == jit::HandlerAction::ReturnStatus ? result.status_code
                                                                          : result.upstream_id))
        return out;
    out.harness.outcome = Outcome::Passed;
    out.harness.phase = Phase::Observe;
    return out;
}

}  // namespace rut::harness
