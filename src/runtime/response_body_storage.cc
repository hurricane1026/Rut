#include "rut/runtime/response_body_storage.h"

#include <stddef.h>
#include <stdlib.h>

namespace rut::jit {

struct ResponseBodySnapshotStorage {
    ResponseBodySnapshotStorage* next;
    u32 refs;
    char data[1];
};

namespace {

// Keep the cache deliberately small: it removes allocator traffic after warm-up
// without retaining memory proportional to the number of connections.
struct ResponseBodyMutationPool {
    static constexpr u32 kMaxCached = 16;
    char* cached[kMaxCached]{};
    u32 count = 0;

    ~ResponseBodyMutationPool() {
        for (u32 i = 0; i < count; i++) free(cached[i]);
    }

    char* acquire() {
        if (count != 0) return cached[--count];
        return static_cast<char*>(malloc(kMaxResponseBodyMutationBytes));
    }

    void release(char* storage) {
        if (storage == nullptr) return;
        if (count < kMaxCached) {
            cached[count++] = storage;
            return;
        }
        free(storage);
    }
};

thread_local ResponseBodyMutationPool g_response_body_mutation_pool;

}  // namespace

char* acquire_response_body_mutation_storage() {
    return g_response_body_mutation_pool.acquire();
}

ControlPlaneSnapshot* acquire_control_plane_snapshot(HandlerCtx* ctx) {
    if (ctx == nullptr) return nullptr;
    if (ctx->control_plane == nullptr)
        ctx->control_plane =
            static_cast<ControlPlaneSnapshot*>(malloc(sizeof(ControlPlaneSnapshot)));
    if (ctx->control_plane != nullptr) *ctx->control_plane = {};
    return ctx->control_plane;
}

const char* snapshot_response_body(HandlerCtx* ctx, const char* body, u32 len) {
    if (ctx == nullptr || body == nullptr || len > kMaxResponseBodyMutationBytes) return nullptr;
    const size_t allocation_size =
        offsetof(ResponseBodySnapshotStorage, data) + (len == 0 ? 1 : len);
    auto* snapshot = static_cast<ResponseBodySnapshotStorage*>(malloc(allocation_size));
    if (snapshot == nullptr) return nullptr;
    snapshot->next = ctx->response_body_snapshot_storage;
    snapshot->refs = 1;
    if (len != 0) __builtin_memcpy(snapshot->data, body, len);
    ctx->response_body_snapshot_storage = snapshot;
    return snapshot->data;
}

void retain_response_body_snapshot_storage(HandlerCtx* ctx) {
    if (ctx != nullptr && ctx->response_body_snapshot_storage != nullptr)
        __atomic_add_fetch(&ctx->response_body_snapshot_storage->refs, 1u, __ATOMIC_RELAXED);
}

void release_response_body_mutation_storage(HandlerCtx* ctx) {
    if (ctx == nullptr) return;
    free(ctx->control_plane);
    ctx->control_plane = nullptr;
    g_response_body_mutation_pool.release(ctx->response_body_mutation_storage);
    ctx->response_body_mutation_storage = nullptr;
    auto* snapshot = ctx->response_body_snapshot_storage;
    ctx->response_body_snapshot_storage = nullptr;
    while (snapshot != nullptr) {
        if (__atomic_sub_fetch(&snapshot->refs, 1u, __ATOMIC_ACQ_REL) != 0) break;
        auto* next = snapshot->next;
        free(snapshot);
        snapshot = next;
    }
}

}  // namespace rut::jit

extern "C" void rut_helper_resp_release_body_storage(void* ctx) {
    rut::jit::release_response_body_mutation_storage(static_cast<rut::jit::HandlerCtx*>(ctx));
}
