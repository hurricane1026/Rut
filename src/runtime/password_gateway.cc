#include "rut/runtime/password_gateway.h"

#include "rut/common/types.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/connection_base.h"
#include "rut/runtime/http2_conn.h"
#include "rut/runtime/password_request.h"
#include "rut/runtime/password_worker.h"

namespace rut {
namespace {
thread_local PasswordGateway* current_gateway = nullptr;
thread_local void* current_connection = nullptr;
thread_local u32 current_stream = 0;
}  // namespace
PasswordHandlerScope::PasswordHandlerScope(PasswordGateway* gateway,
                                           void* connection,
                                           u32 stream_id)
    : previous_gateway(current_gateway),
      previous_connection(current_connection),
      previous_stream(current_stream) {
    if (!gateway && !current_gateway) return;
    engaged = true;
    current_gateway = gateway;
    current_connection = connection;
    current_stream = stream_id;
}
PasswordHandlerScope::~PasswordHandlerScope() {
    if (!engaged) return;
    current_gateway = previous_gateway;
    current_connection = previous_connection;
    current_stream = previous_stream;
}
void PasswordGateway::stop() {
    for (auto& entry : entries) {
        entry.request.reset();
        entry.active = false;
    }
    worker.stop();
}
void PasswordGateway::cancel(u32 connection) {
    for (auto& entry : entries) {
        if (!entry.active || entry.connection != connection) continue;
        entry.request.reset();
        entry.active = false;
    }
}
void PasswordGateway::cancel_request(u32 connection, u64 generation) {
    for (auto& entry : entries) {
        if (!entry.active || entry.connection != connection || entry.generation != generation)
            continue;
        entry.request.reset();
        entry.active = false;
    }
}
u32 PasswordGateway::active_requests() const {
    u32 count = 0;
    for (const auto& entry : entries)
        if (entry.active) ++count;
    return count;
}
PasswordGatewayReply PasswordGateway::verify(
    u32 connection, u64 generation, Str password, Str record, u64 now_ms, u32 timeout_ms) {
    if (generation == 0) return {};
    if (worker.completion_fd() >= 0 && !worker.drain_completions()) {
        cancel(connection);
        return {};
    }
    Entry* found = nullptr;
    for (auto& entry : entries) {
        if (!entry.active || entry.connection != connection) continue;
        if (entry.generation == generation)
            found = &entry;
        else {
            entry.request.reset();
            entry.active = false;
        }
    }
    if (!found) {
        for (auto& entry : entries) {
            if (entry.active) continue;
            if (!entry.request.begin(worker, password, record, now_ms, timeout_ms)) return {};
            entry.connection = connection;
            entry.generation = generation;
            entry.active = true;
            found = &entry;
            break;
        }
    }
    if (!found) return {};
    const auto kStatus = found->request.poll(now_ms);
    if (kStatus == PasswordRequestStatus::Pending) {
        const u64 kRemaining = found->request.deadline_ms() - now_ms;
        return {kStatus, static_cast<u32>(kRemaining < 10 ? kRemaining : 10)};
    }
    const auto kResult = found->request.take();
    found->active = false;
    return {kResult, 0};
}
PasswordGatewayReply verify_password_for_request(void* connection,
                                                 Str password,
                                                 Str record,
                                                 u32 timeout_ms) {
    if (!connection || !current_gateway || connection != current_connection) return {};
    auto& conn = *static_cast<ConnectionBase*>(connection);
    if (conn.fd < 0) return {};
    u64 generation = 0;
    if (conn.protocol == ConnProtocol::Http11) {
        if (current_stream != 0 || conn.state != ConnState::ExecHandler || conn.handler_gen == 0)
            return {};
        generation = conn.handler_gen;
    } else if (conn.protocol == ConnProtocol::Http2) {
        if (!conn.h2 || current_stream == 0 || (current_stream & 1u) == 0 ||
            current_stream > 0x7fffffffu ||
            (conn.h2->async_stream != 0 && conn.h2->async_stream != current_stream))
            return {};
        const auto* stream = conn.h2->find_stream(current_stream);
        if (!stream || stream->state == Http2StreamState::Closed) return {};
        generation = password_h2_generation(current_stream);
    } else
        return {};
    return current_gateway->verify(
        conn.id, generation, password, record, monotonic_us() / 1000, timeout_ms);
}
}  // namespace rut
