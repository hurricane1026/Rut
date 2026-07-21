#pragma once

#include "rut/jit/handler_abi.h"

namespace rut::jit {

// Lazily provisioned request-owned storage for Response.body mutations.
// Buffers are recycled per thread and are explicitly returned when a handler
// frame is reset, completed, or abandoned.
char* acquire_response_body_mutation_storage();
const char* snapshot_response_body(HandlerCtx* ctx, const char* body, u32 len);
void retain_response_body_snapshot_storage(HandlerCtx* ctx);
void release_response_body_mutation_storage(HandlerCtx* ctx);

}  // namespace rut::jit

extern "C" void rut_helper_resp_release_body_storage(void* ctx);
