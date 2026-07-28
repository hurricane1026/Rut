#pragma once

#include "rut/jit/handler_abi.h"

namespace rut::jit {

// Lazily provisioned request-owned storage for Response.body mutations.
// Buffers are recycled per thread and are explicitly returned when a handler
// frame is reset, completed, or abandoned.
char* acquire_response_body_mutation_storage();
ControlPlaneSnapshot* acquire_control_plane_snapshot(HandlerCtx* ctx);
const char* snapshot_response_body(HandlerCtx* ctx, const char* body, u32 len);
void retain_response_body_snapshot_storage(HandlerCtx* ctx);
void release_response_body_mutation_storage(HandlerCtx* ctx);

// Keep mutation bytes alive while a terminal outcome is encoded, then return
// them immediately instead of retaining one buffer per idle keep-alive
// connection until its next JIT request.
class ScopedResponseBodyMutationStorageRelease {
public:
    explicit ScopedResponseBodyMutationStorageRelease(const HandlerCtx* ctx) : ctx_(ctx) {}
    ~ScopedResponseBodyMutationStorageRelease() {
        release_response_body_mutation_storage(const_cast<HandlerCtx*>(ctx_));
    }

    ScopedResponseBodyMutationStorageRelease(const ScopedResponseBodyMutationStorageRelease&) =
        delete;
    ScopedResponseBodyMutationStorageRelease& operator=(
        const ScopedResponseBodyMutationStorageRelease&) = delete;

private:
    const HandlerCtx* ctx_;
};

}  // namespace rut::jit

extern "C" void rut_helper_resp_release_body_storage(void* ctx);
