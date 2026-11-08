#include "rut/runtime/password_gateway.h"

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/connection_base.h"
#include "rut/runtime/error.h"
#include "rut/runtime/forward_auth.h"
#include "rut/runtime/http2_conn.h"
#include "rut/runtime/password_request.h"
#include "rut/runtime/password_worker.h"

namespace rut {
namespace {
thread_local PasswordGateway* current_gateway = nullptr;
thread_local void* current_connection = nullptr;
thread_local u32 current_stream = 0;
thread_local bool current_pending = false;
thread_local i32 current_net_error = 0;
}  // namespace
static u64 auth_request_generation(void* connection);
PasswordHandlerScope::PasswordHandlerScope(PasswordGateway* gateway,
                                           void* connection,
                                           u32 stream_id)
    : previous_gateway(current_gateway),
      previous_connection(current_connection),
      previous_stream(current_stream) {
    if (!gateway && !current_gateway) return;
    engaged = true;
    previous_pending = current_pending;
    previous_net_error = current_net_error;
    current_pending = false;
    current_net_error = 0;
    current_gateway = gateway;
    current_connection = connection;
    current_stream = stream_id;
}
PasswordHandlerScope::~PasswordHandlerScope() {
    if (!engaged) return;
    if (!current_pending && current_gateway && current_connection) {
        const auto generation = auth_request_generation(current_connection);
        if (generation)
            current_gateway->net_clients.cancel(
                static_cast<ConnectionBase*>(current_connection)->id, generation);
    }
    current_pending = previous_pending;
    current_net_error = previous_net_error;
    current_gateway = previous_gateway;
    current_connection = previous_connection;
    current_stream = previous_stream;
}
core::Expected<void, Error> PasswordGateway::start() {
    auto result = worker.start();
    if (!result) return result;
    auto auth = forward_auth.start();
    if (!auth) {
        worker.stop();
        return auth;
    }
    auto calls = http_calls.start();
    if (!calls) {
        forward_auth.stop();
        worker.stop();
    }
    if (!calls) return calls;
    auto net = net_clients.start();
    if (!net) {
        http_calls.stop();
        forward_auth.stop();
        worker.stop();
    }
    return net;
}
void PasswordGateway::stop() {
    net_clients.stop();
    http_calls.stop();
    forward_auth.stop();
    for (auto& entry : entries) {
        entry.request.reset();
        entry.active = false;
    }
    worker.stop();
}
void PasswordGateway::cancel(u32 connection) {
    net_clients.cancel(connection);
    http_calls.cancel(connection);
    forward_auth.cancel(connection);
    for (auto& entry : entries) {
        if (!entry.active || entry.connection != connection) continue;
        entry.request.reset();
        entry.active = false;
    }
}
void PasswordGateway::cancel_request(u32 connection, u64 generation) {
    net_clients.cancel(connection, generation);
    http_calls.cancel(connection, generation);
    forward_auth.cancel(connection, generation);
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
static u64 auth_request_generation(void* connection) {
    if (!connection || !current_gateway || connection != current_connection) return 0;
    auto& conn = *static_cast<ConnectionBase*>(connection);
    if (conn.fd < 0) return 0;
    u64 generation = 0;
    if (conn.protocol == ConnProtocol::Http11) {
        if (current_stream != 0 || conn.state != ConnState::ExecHandler || conn.handler_gen == 0)
            return 0;
        generation = conn.handler_gen;
    } else if (conn.protocol == ConnProtocol::Http2) {
        if (!conn.h2 || current_stream == 0 || (current_stream & 1u) == 0 ||
            current_stream > 0x7fffffffu ||
            (conn.h2->async_stream != 0 && conn.h2->async_stream != current_stream))
            return 0;
        const auto* stream = conn.h2->find_stream(current_stream);
        if (!stream || stream->state == Http2StreamState::Closed) return 0;
        generation = password_h2_generation(current_stream);
    } else
        return 0;
    return generation;
}
ForwardAuthReply forward_auth_for_request(void* connection,
                                          Str header,
                                          const ForwardAuthPolicy& policy,
                                          Str credential,
                                          Str method,
                                          Str target,
                                          u32 timeout_ms) {
    const auto kGeneration = auth_request_generation(connection);
    if (!kGeneration) return {};
    const auto& conn = *static_cast<ConnectionBase*>(connection);
    return current_gateway->forward_auth.authorize(conn.id,
                                                   kGeneration,
                                                   header,
                                                   policy,
                                                   credential,
                                                   method,
                                                   target,
                                                   monotonic_us() / 1000,
                                                   timeout_ms);
}
PasswordGatewayReply verify_password_for_request(void* connection,
                                                 Str password,
                                                 Str record,
                                                 u32 timeout_ms) {
    const auto kGeneration = auth_request_generation(connection);
    if (!kGeneration) return {};
    auto& conn = *static_cast<ConnectionBase*>(connection);
    return current_gateway->verify(
        conn.id, kGeneration, password, record, monotonic_us() / 1000, timeout_ms);
}
HttpCallReply http_call_for_request(void* connection,
                                    const HttpsEndpoint& endpoint,
                                    Str request,
                                    u32 timeout_ms) {
    const auto generation = auth_request_generation(connection);
    if (!generation) return {};
    const auto& conn = *static_cast<ConnectionBase*>(connection);
    auto reply = current_gateway->http_calls.call(
        conn.id, generation, endpoint, request, monotonic_us() / 1000, timeout_ms);
    if (reply.status == NetReply::kPending) current_pending = true;
    return reply;
}
NetReply net_call_for_request(void* connection,
                              NetOp operation,
                              u32 handle,
                              const NetEndpoint* endpoint,
                              Str bytes,
                              i32 amount,
                              u32 timeout_ms) {
    const auto generation = auth_request_generation(connection);
    if (!generation) {
        current_net_error = -4;
        return {};
    }
    auto reply =
        current_gateway->net_clients.call(static_cast<ConnectionBase*>(connection)->id,
                                          generation,
                                          operation,
                                          handle,
                                          endpoint,
                                          bytes,
                                          amount,
                                          monotonic_us() / 1000,
                                          timeout_ms,
                                          static_cast<ConnectionBase*>(connection)->request_config);
    if (reply.status == NetReply::kPending)
        current_pending = true;
    else
        current_net_error = reply.status;
    return reply;
}
i32 net_error_for_request(void* connection) {
    return auth_request_generation(connection) ? current_net_error : -4;
}
void net_set_error_for_request(void* connection, i32 status) {
    if (auth_request_generation(connection)) current_net_error = status;
}
}  // namespace rut
