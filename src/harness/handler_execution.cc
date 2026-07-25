#include "rut/harness/handler_execution.h"

#include "rut/common/http_header_validation.h"
#include "rut/jit/runtime_helpers.h"
#include "rut/runtime/jit_dispatch.h"
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

bool captured_response_header_is_valid(const jit::CapturedResponseHeader& header) {
    if (header.name.len == 0 || header.name.ptr == nullptr ||
        (header.value.len != 0 && header.value.ptr == nullptr))
        return false;
    for (u32 i = 0; i < header.name.len; i++)
        if (!is_http_tchar(static_cast<u8>(header.name.ptr[i]))) return false;
    for (u32 i = 0; i < header.value.len; i++) {
        const u8 c = static_cast<u8>(header.value.ptr[i]);
        if (c != '\t' && (c < 0x20 || c == 0x7f)) return false;
    }
    return true;
}

bool captured_response_header_is_hop_by_hop(const jit::CapturedResponseHeader& header) {
    const auto eq_ci = [&](const char* expected, u32 expected_len) {
        if (header.name.len != expected_len) return false;
        for (u32 i = 0; i < expected_len; i++) {
            char actual = header.name.ptr[i];
            if (actual >= 'A' && actual <= 'Z') actual = static_cast<char>(actual + ('a' - 'A'));
            if (actual != expected[i]) return false;
        }
        return true;
    };
    return eq_ci("connection", 10) || eq_ci("keep-alive", 10) || eq_ci("proxy-connection", 16) ||
           eq_ci("transfer-encoding", 17) || eq_ci("upgrade", 7) || eq_ci("trailer", 7) ||
           eq_ci("te", 2);
}

bool captured_response_header_name_is(const jit::CapturedResponseHeader& header,
                                      const char* expected,
                                      u32 expected_len) {
    if (header.name.len != expected_len) return false;
    for (u32 i = 0; i < expected_len; i++) {
        char actual = header.name.ptr[i];
        if (actual >= 'A' && actual <= 'Z') actual = static_cast<char>(actual + ('a' - 'A'));
        if (actual != expected[i]) return false;
    }
    return true;
}

bool parse_captured_content_length(Str value, u32* out) {
    if (value.len == 0 || value.ptr == nullptr) return false;
    u32 parsed = 0;
    for (u32 i = 0; i < value.len; i++) {
        const u32 digit = static_cast<u8>(value.ptr[i]) - static_cast<u8>('0');
        if (digit > 9 || parsed > (0xffffffffu - digit) / 10u) return false;
        parsed = parsed * 10u + digit;
    }
    *out = parsed;
    return true;
}

bool request_is_head(const HandlerExecution& execution) {
    static constexpr char kHeadPrefix[] = "HEAD ";
    return execution.request_len >= sizeof(kHeadPrefix) - 1 && execution.request_data != nullptr &&
           __builtin_memcmp(execution.request_data, kHeadPrefix, sizeof(kHeadPrefix) - 1) == 0;
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
    frame.context.control_plane = nullptr;
    if (other.frame.context.control_plane != nullptr) {
        auto* snapshot = jit::acquire_control_plane_snapshot(&frame.context);
        if (snapshot != nullptr) *snapshot = *other.frame.context.control_plane;
    }
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
    __builtin_memcpy(
        captured_response_body, other.captured_response_body, sizeof(captured_response_body));
    captured_response_body_len = other.captured_response_body_len;
    uses_captured_response = other.uses_captured_response;
    captured_response_body_mutated = other.captured_response_body_mutated;
    captured_response_header_count = other.captured_response_header_count;
    for (u32 i = 0; i < jit::kMaxCapturedResponseHeaders; i++) {
        captured_response_headers[i] = other.captured_response_headers[i];
        captured_response_header_names[i] = other.captured_response_header_names[i];
        captured_response_header_values[i] = other.captured_response_header_values[i];
        captured_response_headers[i].name = {
            captured_response_header_names[i].data(),
            static_cast<u32>(captured_response_header_names[i].size())};
        captured_response_headers[i].value = {
            captured_response_header_values[i].data(),
            static_cast<u32>(captured_response_header_values[i].size())};
    }
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
    jit::CapturedResponseHeader captured_response_headers[jit::kMaxCapturedResponseHeaders]{};
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
        u32 event_input_bytes = event.data_len;
        bool forward_failed = false;
        if (event.kind == jit::YieldKind::Forward) {
            forward_failed = event.injected_fault || event.result < 0;
        }
        if (event.kind == jit::YieldKind::Forward && !forward_failed) {
            if (event.response_status < 200 || event.response_status > 599 ||
                event.response_header_count > jit::kMaxCapturedResponseHeaders ||
                (event.response_header_count != 0 && event.response_headers == nullptr) ||
                (event.data_len != 0 && event.data == nullptr)) {
                out.harness.outcome = Outcome::Invalid;
                copy_detail(out.harness.detail,
                            sizeof(out.harness.detail),
                            "forward completion requires a valid response fixture");
                return out;
            }
            for (u32 i = 0; i < event.response_header_count; i++) {
                const auto& header = event.response_headers[i];
                if (!captured_response_header_is_valid(header)) {
                    out.harness.outcome = Outcome::Invalid;
                    copy_detail(out.harness.detail,
                                sizeof(out.harness.detail),
                                "forward completion requires valid response header views");
                    return out;
                }
            }
            if (event.data_len >
                jit::kMaxCapturedResponseStorageBytes - jit::kCapturedResponseFramingReserve) {
                out.harness.outcome = Outcome::Invalid;
                copy_detail(out.harness.detail,
                            sizeof(out.harness.detail),
                            "forward completion exceeds captured response storage");
                return out;
            }
            if (event.data_len != 0 &&
                (event.response_status == 204 || event.response_status == 205 ||
                 event.response_status == 304)) {
                out.harness.outcome = Outcome::Invalid;
                copy_detail(out.harness.detail,
                            sizeof(out.harness.detail),
                            "bodyless forward completion cannot include response data");
                return out;
            }
            u32 captured_bytes = event.data_len;
            bool has_content_length = false;
            u32 content_length = 0;
            for (u32 i = 0; i < event.response_header_count; i++) {
                const auto& header = event.response_headers[i];
                if (captured_response_header_is_hop_by_hop(header)) {
                    out.harness.outcome = Outcome::Invalid;
                    copy_detail(out.harness.detail,
                                sizeof(out.harness.detail),
                                "forward completion cannot include hop-by-hop response headers");
                    return out;
                }
                if (captured_response_header_name_is(header, "content-length", 14)) {
                    u32 parsed = 0;
                    if (!parse_captured_content_length(header.value, &parsed) ||
                        (has_content_length && parsed != content_length)) {
                        out.harness.outcome = Outcome::Invalid;
                        copy_detail(out.harness.detail,
                                    sizeof(out.harness.detail),
                                    "forward completion has invalid content-length headers");
                        return out;
                    }
                    has_content_length = true;
                    content_length = parsed;
                }
                if (header.name.len > jit::kMaxCapturedResponseStorageBytes - captured_bytes ||
                    header.value.len >
                        jit::kMaxCapturedResponseStorageBytes - captured_bytes - header.name.len) {
                    captured_bytes = jit::kMaxCapturedResponseStorageBytes;
                    break;
                }
                captured_bytes += header.name.len + header.value.len;
            }
            if (has_content_length && !request_is_head(execution) &&
                !response_status_forbids_body(event.response_status) &&
                content_length != event.data_len) {
                out.harness.outcome = Outcome::Invalid;
                copy_detail(out.harness.detail,
                            sizeof(out.harness.detail),
                            "forward completion content-length does not match response data");
                return out;
            }
            const u32 captured_header_storage_bytes =
                event.response_header_count * sizeof(jit::CapturedResponseHeader);
            if (captured_header_storage_bytes >
                    jit::kMaxCapturedResponseStorageBytes - jit::kCapturedResponseFramingReserve ||
                captured_bytes > jit::kMaxCapturedResponseStorageBytes -
                                     jit::kCapturedResponseFramingReserve -
                                     captured_header_storage_bytes) {
                out.harness.outcome = Outcome::Invalid;
                copy_detail(out.harness.detail,
                            sizeof(out.harness.detail),
                            "forward completion exceeds captured response storage");
                return out;
            }
            event_input_bytes = captured_bytes;
            auto& response = execution.frame.context;
            response.captured_response_valid = true;
            response.captured_response_status = event.response_status;
            response.captured_response_body = reinterpret_cast<const char*>(event.data);
            response.captured_response_body_len = event.data_len;
            response.captured_response_header_count = 0;
            response.captured_response_headers = captured_response_headers;
            const bool preserve_content_length =
                request_is_head(execution) || event.response_status == 304;
            for (u32 i = 0; i < event.response_header_count; i++) {
                const auto& header = event.response_headers[i];
                if (!preserve_content_length &&
                    captured_response_header_name_is(header, "content-length", 14))
                    continue;
                captured_response_headers[response.captured_response_header_count++] = header;
            }
            event.result = event.response_status;
        }
        if (event_input_bytes > harness.limits.max_input_bytes - out.harness.input_bytes) {
            out.harness.outcome = Outcome::Failed;
            out.harness.has_reached_limit = true;
            out.harness.reached_limit = LimitKind::InputBytes;
            copy_detail(
                out.harness.detail, sizeof(out.harness.detail), "input-bytes limit reached");
            return out;
        }
        out.harness.input_bytes += event_input_bytes;
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
        if (forward_failed) {
            result = jit::HandlerResult::make_status(502);
            break;
        }
        out.harness.handler_resumes++;
        result = execution.resume(result, event.kind, event.result);
        if (!publisher.emit(ObservationKind::HandlerResumed,
                            static_cast<u64>(event.kind),
                            out.harness.handler_resumes))
            return out;
    }

    const auto& response = execution.frame.context;
    bool returned_captured_response =
        result.action == jit::HandlerAction::ReturnStatus && result.status_code == 0;
    result = effective_return_result(result, response);
    if (returned_captured_response) {
        if (!response.captured_response_valid || response.response_status_invalid ||
            response.response_body_mutation_overflow) {
            result = jit::HandlerResult::make_status(500);
            returned_captured_response = false;
        } else {
            if (!response.response_status_set)
                result.status_code = response.captured_response_status;
            result.upstream_id = jit::HandlerResult::kDynamicResponseBody;
        }
    }
    out.terminal = result;
    out.has_terminal = true;
    out.uses_captured_response = returned_captured_response;
    out.captured_response_body_mutated =
        returned_captured_response && response.response_body_mutation_set;
    if (result.action == jit::HandlerAction::ReturnStatus &&
        (result.upstream_id == jit::HandlerResult::kDynamicResponseBody ||
         returned_captured_response)) {
        const char* body = nullptr;
        if (response.response_body_mutation_set) {
            body = response.response_body_mutation_storage;
            if (returned_captured_response) {
                out.captured_response_body_len = response.response_body_mutation_len;
            } else {
                out.dynamic_response_body_len = response.response_body_mutation_len;
                out.dynamic_response_body_valid = !response.response_body_mutation_overflow;
            }
        } else if (returned_captured_response) {
            body = response.captured_response_body;
            out.captured_response_body_len = response.captured_response_body_len;
        } else {
            body = response.response_body_data;
            out.dynamic_response_body_len = response.response_body_len;
            out.dynamic_response_body_valid = response.response_body_valid != 0;
        }
        if (returned_captured_response) {
            if ((body == nullptr && out.captured_response_body_len != 0) ||
                out.captured_response_body_len > sizeof(out.captured_response_body)) {
                out.uses_captured_response = false;
            } else if (out.captured_response_body_len != 0) {
                __builtin_memcpy(out.captured_response_body, body, out.captured_response_body_len);
            }
        } else if ((body == nullptr && out.dynamic_response_body_len != 0) ||
                   out.dynamic_response_body_len > jit::kMaxDynamicResponseBodyBytes) {
            out.dynamic_response_body_len = 0;
            out.dynamic_response_body_valid = false;
        } else if (out.dynamic_response_body_len != 0) {
            __builtin_memcpy(out.dynamic_response_body, body, out.dynamic_response_body_len);
        }
    }
    if (returned_captured_response && out.uses_captured_response) {
        out.captured_response_header_count = response.captured_response_header_count;
        for (u32 i = 0; i < out.captured_response_header_count; i++) {
            const auto& header = response.captured_response_headers[i];
            out.captured_response_header_names[i].assign(header.name.ptr, header.name.len);
            out.captured_response_header_values[i].assign(header.value.ptr, header.value.len);
            out.captured_response_headers[i] = {
                {out.captured_response_header_names[i].data(), header.name.len},
                {out.captured_response_header_values[i].data(), header.value.len}};
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
