#include "rut/runtime/response_body_storage.h"

#include <stdlib.h>

namespace rut::jit {
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

void release_response_body_mutation_storage(HandlerCtx* ctx) {
    if (ctx == nullptr) return;
    g_response_body_mutation_pool.release(ctx->response_body_mutation_storage);
    ctx->response_body_mutation_storage = nullptr;
}

}  // namespace rut::jit

extern "C" void rut_helper_resp_release_body_storage(void* ctx) {
    rut::jit::release_response_body_mutation_storage(static_cast<rut::jit::HandlerCtx*>(ctx));
}
