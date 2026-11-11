#include "rut/jit/codegen.h"

#include "rut/common/types.h"
#include "rut/common/ws_control_flow.h"
#include "rut/common/ws_message.h"
#include "rut/compiler/call_liveness.h"
#include "rut/compiler/http_call_profile.h"
#include "rut/compiler/password_profile.h"
#include "rut/compiler/rir.h"
#include "rut/compiler/verifier.h"
#include "rut/jit/handler_abi.h"
#include "rut/runtime/cache_table.h"
#include "rut/runtime/hash.h"
#include "rut/runtime/json.h"
#include "rut/runtime/net_client.h"
#include "rut/runtime/ws_frame.h"
#include "rut/runtime/ws_terminate.h"
#include <atomic>
#include <cstddef>

#include <llvm-c/Core.h>
#include <llvm-c/Linker.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace rut::jit {

u32 format_handler_symbol(Str name, char* out, u32 out_size) {
    if (!out || out_size == 0) return 0;

    static constexpr char kPrefix[] = "handler_";
    u32 pos = 0;
    while (kPrefix[pos] && pos + 1 < out_size) {
        out[pos] = kPrefix[pos];
        pos++;
    }

    u32 max_pos = 0;
    if (out_size > 1) max_pos = out_size - 2;
    if (max_pos > 254) max_pos = 254;
    for (u32 i = 0; i < name.len && pos < max_pos; i++) {
        out[pos++] = name.ptr[i];
    }
    out[pos] = '\0';
    return pos;
}

// ── Codegen Context ────────────────────────────────────────────────
// Per-compilation state. Holds LLVM context, module, builder, and
// mapping tables from RIR IDs to LLVM values/blocks.

struct Ctx {
    LLVMContextRef llvm_ctx;
    LLVMModuleRef llvm_mod;
    LLVMBuilderRef builder;

    // Per-function maps (sized to function's value_cap / block_cap).
    LLVMValueRef* value_map;
    u32 value_map_cap;
    LLVMBasicBlockRef* block_map;
    u32 block_map_cap;

    // Cached LLVM types
    LLVMTypeRef i1_ty;
    LLVMTypeRef i8_ty;
    LLVMTypeRef i16_ty;
    LLVMTypeRef i32_ty;
    LLVMTypeRef i64_ty;
    LLVMTypeRef ptr_ty;
    LLVMTypeRef void_ty;

    // Str type: {ptr, i32} — matches rut::Str layout
    LLVMTypeRef str_ty;

    // Optional(Str): {i8, ptr, i32} — has_value byte + ptr + len
    LLVMTypeRef opt_str_ty;

    // Optional(I32): {i8, i32}
    LLVMTypeRef opt_i32_ty;

    // HandlerResult: i64 (packed 8-byte struct, passed as integer)
    LLVMTypeRef result_ty;

    // Handler function type: i64 (ptr, ptr, ptr, i32, ptr)
    LLVMTypeRef handler_fn_ty;
    bool ws_body_mode = false;
    LLVMValueRef param_ws_opcode = nullptr;
    LLVMValueRef param_ws_from_client = nullptr;

    // Current RIR function (set per-function, for type lookups).
    const rir::Function* cur_fn;
    const rir::Module* source_module;

    // Function parameters (set per-function)
    LLVMValueRef param_conn;
    LLVMValueRef param_ctx;
    LLVMValueRef param_req_data;
    LLVMValueRef param_req_len;
    LLVMValueRef param_arena;

    // Lazily declared runtime helpers
    LLVMValueRef fn_req_path;
    LLVMValueRef fn_req_path_only;
    LLVMValueRef fn_req_body;
    LLVMValueRef fn_req_http_version;
    LLVMValueRef fn_req_flag;
    LLVMValueRef fn_req_method;
    LLVMValueRef fn_req_unique_header;
    LLVMValueRef fn_req_header;
    LLVMValueRef fn_req_header_count;
    LLVMValueRef fn_req_cookie;
    LLVMValueRef fn_req_query;
    LLVMValueRef fn_req_query_string;
    LLVMValueRef fn_req_param;
    LLVMValueRef fn_req_remote_addr;
    LLVMValueRef fn_req_content_length;
    LLVMValueRef fn_cache_get;
    LLVMValueRef fn_cache_set;
    LLVMValueRef fn_time_now_micros;
    LLVMValueRef fn_parse_prime;
    LLVMValueRef fn_parse_unprime;
    LLVMValueRef fn_time_unlatch;

    // True while emitting a handler that reads the request (and therefore
    // primed the parse cache). Gates the parse-unprime calls at exits.
    bool cur_fn_needs_parse = false;
    LLVMValueRef fn_http_token_list_allows;
    LLVMValueRef fn_bearer_matches;
    LLVMValueRef fn_basic_matches;
    LLVMValueRef fn_hmac_sha256_matches;
    LLVMValueRef fn_standard_webhook_valid;
    LLVMValueRef fn_signed_request_valid;
    LLVMValueRef fn_jwt_claims_valid_with_lifetime;
    LLVMValueRef fn_str_constant_time_equal;
    LLVMValueRef fn_str_has_prefix;
    LLVMValueRef fn_str_eq;
    LLVMValueRef fn_str_cmp;
    LLVMValueRef fn_str_regex_match;
    LLVMValueRef fn_str_trim_prefix;

    // Scratch storage for conditional slot accesses when the handler frame
    // does not provide per-resume slots. This keeps codegen branchless
    // by redirecting disabled writes and missing-slot reads to an internal
    // i64 sink.
    LLVMValueRef ctx_store_sink = nullptr;
    // Only callout handlers use a request-owned value frame. It preserves SSA
    // values and the exact continuation without replaying earlier effects.
    LLVMValueRef call_frame = nullptr;
    LLVMTypeRef call_frame_type = nullptr;
    u32* call_frame_fields = nullptr;
    LLVMValueRef* call_phi_incoming = nullptr;
    LLVMValueRef call_dispatch = nullptr;
    u32 call_state = 0;
    u32 current_block = 0;

    // Cache for map_type: LLVM literal structs (Optional<composite>, Struct
    // with a StructDef) are identity-compared, so emitting a fresh
    // LLVMStructTypeInContext call per lookup produces *different* LLVM types
    // for the same RIR type — breaking PHIs, selects, and other operations
    // that require exact type equality. Key by the rir::Type pointer, which
    // is arena-allocated and stable for the module's lifetime.
    static constexpr u32 kMaxCachedTypes = 256;
    struct TypeCacheEntry {
        const rir::Type* key;
        LLVMTypeRef value;
    };
    TypeCacheEntry type_cache[kMaxCachedTypes];
    u32 type_cache_count;
    u32 regex_module_id;
    u32 regex_count;
    struct RegexGlobalEntry {
        Str pattern;
        LLVMValueRef db_global;
    };
    RegexGlobalEntry* regex_globals;
    u32 regex_global_count;
    u32 regex_global_cap;

    void init_types() {
        i1_ty = LLVMInt1TypeInContext(llvm_ctx);
        i8_ty = LLVMInt8TypeInContext(llvm_ctx);
        i16_ty = LLVMInt16TypeInContext(llvm_ctx);
        i32_ty = LLVMInt32TypeInContext(llvm_ctx);
        i64_ty = LLVMInt64TypeInContext(llvm_ctx);
        ptr_ty = LLVMPointerTypeInContext(llvm_ctx, 0);
        void_ty = LLVMVoidTypeInContext(llvm_ctx);

        // Str: {ptr, i32}
        LLVMTypeRef str_fields[] = {ptr_ty, i32_ty};
        str_ty = LLVMStructTypeInContext(llvm_ctx, str_fields, 2, 0);

        // Optional(Str): {i8, ptr, i32}
        LLVMTypeRef opt_str_fields[] = {i8_ty, ptr_ty, i32_ty};
        opt_str_ty = LLVMStructTypeInContext(llvm_ctx, opt_str_fields, 3, 0);

        // Optional(I32): {i8, i32}
        LLVMTypeRef opt_i32_fields[] = {i8_ty, i32_ty};
        opt_i32_ty = LLVMStructTypeInContext(llvm_ctx, opt_i32_fields, 2, 0);

        // HandlerResult is returned as i64 (8-byte packed struct)
        result_ty = i64_ty;

        // Handler fn: i64 (ptr %conn, ptr %ctx, ptr %req_data, i32 %req_len, ptr %arena)
        LLVMTypeRef param_types[] = {ptr_ty, ptr_ty, ptr_ty, i32_ty, ptr_ty, i8_ty, i8_ty};
        handler_fn_ty = LLVMFunctionType(result_ty, param_types, ws_body_mode ? 7 : 5, 0);
    }

    // ── Lazy Helper Declaration ────────────────────────────────────

    // void rut_helper_parse_prime(ptr, i32)
    LLVMValueRef get_parse_prime() {
        if (!fn_parse_prime) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 2, 0);
            fn_parse_prime = LLVMAddFunction(llvm_mod, "rut_helper_parse_prime", ft);
        }
        return fn_parse_prime;
    }

    // Emit the one-time parse-prime call for this handler invocation. The
    // builder must already be positioned in the handler's first executed
    // block so the call dominates every req_* helper call.
    void emit_parse_prime() {
        LLVMValueRef args[] = {param_req_data, param_req_len};
        LLVMBuildCall2(
            builder, LLVMGlobalGetValueType(get_parse_prime()), get_parse_prime(), args, 2, "");
    }

    // void rut_helper_parse_unprime()
    LLVMValueRef get_parse_unprime() {
        if (!fn_parse_unprime) {
            LLVMTypeRef ft = LLVMFunctionType(void_ty, nullptr, 0, 0);
            fn_parse_unprime = LLVMAddFunction(llvm_mod, "rut_helper_parse_unprime", ft);
        }
        return fn_parse_unprime;
    }

    // Clear the primed parse cache at a handler exit, so the primed parse
    // never outlives this invocation. No-op for handlers that don't read
    // the request (they never primed). Builder must be positioned just
    // before the terminal return.
    void emit_parse_unprime() {
        if (!cur_fn_needs_parse) return;
        LLVMBuildCall2(builder,
                       LLVMGlobalGetValueType(get_parse_unprime()),
                       get_parse_unprime(),
                       nullptr,
                       0,
                       "");
    }

    // void rut_helper_time_unlatch()
    LLVMValueRef get_time_unlatch() {
        if (!fn_time_unlatch) {
            LLVMTypeRef ft = LLVMFunctionType(void_ty, nullptr, 0, 0);
            fn_time_unlatch = LLVMAddFunction(llvm_mod, "rut_helper_time_unlatch", ft);
        }
        return fn_time_unlatch;
    }

    // Reset the per-invocation time latch at handler entry. parse_prime
    // already does this as a side effect, so this dedicated call is only
    // emitted for handlers that use time.nowMicros() WITHOUT reading the
    // request — otherwise their thread's latch would stay valid across
    // invocations and the clock would freeze at the first sampled value.
    void emit_time_unlatch() {
        LLVMBuildCall2(builder,
                       LLVMGlobalGetValueType(get_time_unlatch()),
                       get_time_unlatch(),
                       nullptr,
                       0,
                       "");
    }

    // void rut_helper_req_path(ptr, i32, ptr, ptr)
    LLVMValueRef get_req_path() {
        if (!fn_req_path) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 4, 0);
            fn_req_path = LLVMAddFunction(llvm_mod, "rut_helper_req_path", ft);
        }
        return fn_req_path;
    }

    // void rut_helper_req_path_only(ptr, i32, ptr, ptr)
    LLVMValueRef get_req_path_only() {
        if (!fn_req_path_only) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 4, 0);
            fn_req_path_only = LLVMAddFunction(llvm_mod, "rut_helper_req_path_only", ft);
        }
        return fn_req_path_only;
    }

    // void rut_helper_req_body(ptr, i32, ptr, ptr)
    LLVMValueRef get_req_body() {
        if (!fn_req_body) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 4, 0);
            fn_req_body = LLVMAddFunction(llvm_mod, "rut_helper_req_body", ft);
        }
        return fn_req_body;
    }

    // void rut_helper_req_http_version(ptr, i32, ptr, ptr)
    LLVMValueRef get_req_http_version() {
        if (!fn_req_http_version) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 4, 0);
            fn_req_http_version = LLVMAddFunction(llvm_mod, "rut_helper_req_http_version", ft);
        }
        return fn_req_http_version;
    }

    // u8 rut_helper_req_flag(ptr, i32, i8)
    LLVMValueRef get_req_flag() {
        if (!fn_req_flag) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, i8_ty};
            LLVMTypeRef ft = LLVMFunctionType(i8_ty, params, 3, 0);
            fn_req_flag = LLVMAddFunction(llvm_mod, "rut_helper_req_flag", ft);
        }
        return fn_req_flag;
    }

    // u8 rut_helper_req_method(ptr, i32)
    LLVMValueRef get_req_method() {
        if (!fn_req_method) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(i8_ty, params, 2, 0);
            fn_req_method = LLVMAddFunction(llvm_mod, "rut_helper_req_method", ft);
        }
        return fn_req_method;
    }

    // void rut_helper_req_header(ptr, i32, ptr, i32, ptr, ptr, ptr)
    LLVMValueRef get_req_header() {
        if (!fn_req_header) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty, ptr_ty, ptr_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 7, 0);
            fn_req_header = LLVMAddFunction(llvm_mod, "rut_helper_req_header", ft);
        }
        return fn_req_header;
    }

    LLVMValueRef get_req_header_count() {
        if (!fn_req_header_count) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(i32_ty, params, 4, 0);
            fn_req_header_count = LLVMAddFunction(llvm_mod, "rut_helper_req_header_count", ft);
        }
        return fn_req_header_count;
    }

    // void rut_helper_req_unique_header(ptr, i32, ptr, i32, ptr, ptr, ptr)
    LLVMValueRef get_req_unique_header() {
        if (!fn_req_unique_header) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty, ptr_ty, ptr_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 7, 0);
            fn_req_unique_header = LLVMAddFunction(llvm_mod, "rut_helper_req_unique_header", ft);
        }
        return fn_req_unique_header;
    }

    // void rut_helper_req_set_path(ptr conn, ptr path, i32 len)
    LLVMValueRef fn_req_set_path = nullptr;
    LLVMValueRef get_req_set_path() {
        if (!fn_req_set_path) {
            LLVMTypeRef params[] = {ptr_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 3, 0);
            fn_req_set_path = LLVMAddFunction(llvm_mod, "rut_helper_req_set_path", ft);
        }
        return fn_req_set_path;
    }

    // void rut_helper_req_set_load_balance(ptr conn, i32 id)
    LLVMValueRef fn_req_set_load_balance = nullptr;
    LLVMValueRef get_req_set_load_balance() {
        if (!fn_req_set_load_balance) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 2, 0);
            fn_req_set_load_balance =
                LLVMAddFunction(llvm_mod, "rut_helper_req_set_load_balance", ft);
        }
        return fn_req_set_load_balance;
    }
    // void rut_helper_req_set_target_transform(ptr conn, i32 id)
    LLVMValueRef fn_req_set_target_transform = nullptr;
    LLVMValueRef get_req_set_target_transform() {
        if (!fn_req_set_target_transform) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 2, 0);
            fn_req_set_target_transform =
                LLVMAddFunction(llvm_mod, "rut_helper_req_set_target_transform", ft);
        }
        return fn_req_set_target_transform;
    }

    // void rut_helper_req_set_header(ptr conn, ptr name, i32 nlen, ptr val, i32 vlen)
    LLVMValueRef fn_req_set_header = nullptr;
    LLVMValueRef get_req_set_header() {
        if (!fn_req_set_header) {
            LLVMTypeRef params[] = {ptr_ty, ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 5, 0);
            fn_req_set_header = LLVMAddFunction(llvm_mod, "rut_helper_req_set_header", ft);
        }
        return fn_req_set_header;
    }

    LLVMValueRef fn_req_set_owned_header = nullptr;
    LLVMValueRef get_req_set_owned_header() {
        if (!fn_req_set_owned_header) {
            LLVMTypeRef params[] = {ptr_ty, ptr_ty, ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 6, 0);
            fn_req_set_owned_header =
                LLVMAddFunction(llvm_mod, "rut_helper_req_set_owned_header", ft);
        }
        return fn_req_set_owned_header;
    }

    // void rut_helper_req_add_header(ptr conn, ptr name, i32 nlen, ptr val, i32 vlen)
    LLVMValueRef fn_req_add_header = nullptr;
    LLVMValueRef get_req_add_header() {
        if (!fn_req_add_header) {
            LLVMTypeRef params[] = {ptr_ty, ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 5, 0);
            fn_req_add_header = LLVMAddFunction(llvm_mod, "rut_helper_req_add_header", ft);
        }
        return fn_req_add_header;
    }

    LLVMValueRef fn_req_remove_header = nullptr;
    LLVMValueRef get_req_remove_header() {
        if (!fn_req_remove_header) {
            LLVMTypeRef params[] = {ptr_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 3, 0);
            fn_req_remove_header = LLVMAddFunction(llvm_mod, "rut_helper_req_remove_header", ft);
        }
        return fn_req_remove_header;
    }

    LLVMValueRef fn_resp_set_header = nullptr;
    LLVMValueRef fn_resp_add_header = nullptr;
    LLVMValueRef fn_resp_remove_header = nullptr;
    LLVMValueRef fn_resp_commit_headers = nullptr;
    LLVMValueRef fn_resp_header = nullptr;
    LLVMValueRef get_resp_set_header() {
        if (!fn_resp_set_header) {
            LLVMTypeRef params[] = {ptr_ty, ptr_ty, i32_ty, ptr_ty, i32_ty};
            fn_resp_set_header = LLVMAddFunction(
                llvm_mod, "rut_helper_resp_set_header", LLVMFunctionType(void_ty, params, 5, 0));
        }
        return fn_resp_set_header;
    }
    LLVMValueRef fn_resp_set_optional_header = nullptr;
    LLVMValueRef get_resp_set_optional_header() {
        if (!fn_resp_set_optional_header) {
            LLVMTypeRef params[] = {ptr_ty, ptr_ty, i32_ty, ptr_ty, i32_ty, i8_ty};
            fn_resp_set_optional_header = LLVMAddFunction(llvm_mod,
                                                          "rut_helper_resp_set_optional_header",
                                                          LLVMFunctionType(void_ty, params, 6, 0));
        }
        return fn_resp_set_optional_header;
    }
    LLVMValueRef get_resp_add_header() {
        if (!fn_resp_add_header) {
            LLVMTypeRef params[] = {ptr_ty, ptr_ty, i32_ty, ptr_ty, i32_ty};
            fn_resp_add_header = LLVMAddFunction(
                llvm_mod, "rut_helper_resp_add_header", LLVMFunctionType(void_ty, params, 5, 0));
        }
        return fn_resp_add_header;
    }
    LLVMValueRef get_resp_remove_header() {
        if (!fn_resp_remove_header) {
            LLVMTypeRef params[] = {ptr_ty, ptr_ty, i32_ty};
            fn_resp_remove_header = LLVMAddFunction(
                llvm_mod, "rut_helper_resp_remove_header", LLVMFunctionType(void_ty, params, 3, 0));
        }
        return fn_resp_remove_header;
    }
    LLVMValueRef get_resp_commit_headers() {
        if (!fn_resp_commit_headers) {
            LLVMTypeRef params[] = {ptr_ty};
            fn_resp_commit_headers = LLVMAddFunction(llvm_mod,
                                                     "rut_helper_resp_commit_headers",
                                                     LLVMFunctionType(void_ty, params, 1, 0));
        }
        return fn_resp_commit_headers;
    }
    LLVMValueRef get_resp_header() {
        if (!fn_resp_header) {
            LLVMTypeRef params[] = {
                ptr_ty, ptr_ty, i32_ty, i8_ty, ptr_ty, i32_ty, ptr_ty, ptr_ty, ptr_ty};
            fn_resp_header = LLVMAddFunction(
                llvm_mod, "rut_helper_resp_header", LLVMFunctionType(void_ty, params, 9, 0));
        }
        return fn_resp_header;
    }

    // void rut_helper_req_cookie(ptr, i32, ptr, i32, ptr, ptr, ptr)
    LLVMValueRef get_req_cookie() {
        if (!fn_req_cookie) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty, ptr_ty, ptr_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 7, 0);
            fn_req_cookie = LLVMAddFunction(llvm_mod, "rut_helper_req_cookie", ft);
        }
        return fn_req_cookie;
    }

    // void rut_helper_req_query(ptr, i32, ptr, i32, ptr, ptr, ptr)
    LLVMValueRef get_req_query() {
        if (!fn_req_query) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty, ptr_ty, ptr_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 7, 0);
            fn_req_query = LLVMAddFunction(llvm_mod, "rut_helper_req_query", ft);
        }
        return fn_req_query;
    }

    // void rut_helper_req_query_string(ptr, i32, ptr, ptr, ptr)
    LLVMValueRef get_req_query_string() {
        if (!fn_req_query_string) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, ptr_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 5, 0);
            fn_req_query_string = LLVMAddFunction(llvm_mod, "rut_helper_req_query_string", ft);
        }
        return fn_req_query_string;
    }

    // void rut_helper_req_param(ptr, ptr, i32, ptr, ptr)
    LLVMValueRef get_req_param() {
        if (!fn_req_param) {
            LLVMTypeRef params[] = {ptr_ty, ptr_ty, i32_ty, ptr_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 5, 0);
            fn_req_param = LLVMAddFunction(llvm_mod, "rut_helper_req_param", ft);
        }
        return fn_req_param;
    }

    // u32 rut_helper_req_remote_addr(ptr)
    LLVMValueRef get_req_remote_addr() {
        if (!fn_req_remote_addr) {
            LLVMTypeRef params[] = {ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(i32_ty, params, 1, 0);
            fn_req_remote_addr = LLVMAddFunction(llvm_mod, "rut_helper_req_remote_addr", ft);
        }
        return fn_req_remote_addr;
    }

    // void rut_helper_cache_get_bound(i32, i64 identity, i32, ptr, ptr)
    LLVMValueRef get_cache_get() {
        if (!fn_cache_get) {
            LLVMTypeRef params[] = {i32_ty, i64_ty, i32_ty, ptr_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 5, 0);
            fn_cache_get = LLVMAddFunction(llvm_mod, "rut_helper_cache_get_bound", ft);
        }
        return fn_cache_get;
    }

    // void rut_helper_cache_set_bound(i32, i64 identity, i32, i64)
    LLVMValueRef get_cache_set() {
        if (!fn_cache_set) {
            LLVMTypeRef params[] = {i32_ty, i64_ty, i32_ty, i64_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 4, 0);
            fn_cache_set = LLVMAddFunction(llvm_mod, "rut_helper_cache_set_bound", ft);
        }
        return fn_cache_set;
    }

    // i64 rut_helper_time_now_micros()
    LLVMValueRef get_time_now_micros() {
        if (!fn_time_now_micros) {
            LLVMTypeRef ft = LLVMFunctionType(i64_ty, nullptr, 0, 0);
            fn_time_now_micros = LLVMAddFunction(llvm_mod, "rut_helper_time_now_micros", ft);
        }
        return fn_time_now_micros;
    }

    // u64 rut_helper_req_content_length(ptr, i32)
    LLVMValueRef get_req_content_length() {
        if (!fn_req_content_length) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(i64_ty, params, 2, 0);
            fn_req_content_length = LLVMAddFunction(llvm_mod, "rut_helper_req_content_length", ft);
        }
        return fn_req_content_length;
    }

    // u32 rut_crypto_equal_bounded_v1(ptr, i32, ptr, i32)
    LLVMValueRef get_str_constant_time_equal() {
        if (!fn_str_constant_time_equal) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(i32_ty, params, 4, 0);
            fn_str_constant_time_equal =
                LLVMAddFunction(llvm_mod, "rut_crypto_equal_bounded_v1", ft);
        }
        return fn_str_constant_time_equal;
    }
    LLVMValueRef fn_http_origin_list_allows = nullptr;
    LLVMValueRef get_http_origin_list_allows() {
        if (!fn_http_origin_list_allows) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty, i8_ty};
            fn_http_origin_list_allows = LLVMAddFunction(llvm_mod,
                                                         "rut_helper_http_origin_list_allows",
                                                         LLVMFunctionType(i8_ty, params, 5, 0));
        }
        return fn_http_origin_list_allows;
    }
    LLVMValueRef get_http_token_list_allows() {
        if (!fn_http_token_list_allows) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty, i8_ty};
            LLVMTypeRef ft = LLVMFunctionType(i8_ty, params, 5, 0);
            fn_http_token_list_allows =
                LLVMAddFunction(llvm_mod, "rut_helper_http_token_list_allows", ft);
        }
        return fn_http_token_list_allows;
    }
    LLVMValueRef get_bearer_matches() {
        if (!fn_bearer_matches) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(i8_ty, params, 4, 0);
            fn_bearer_matches = LLVMAddFunction(llvm_mod, "rut_helper_bearer_matches", ft);
        }
        return fn_bearer_matches;
    }
    LLVMValueRef get_hmac_sha256_matches() {
        if (!fn_hmac_sha256_matches) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty, ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(i32_ty, params, 8, 0);
            fn_hmac_sha256_matches =
                LLVMAddFunction(llvm_mod, "rut_crypto_hmac_sha256_matches_v1", ft);
        }
        return fn_hmac_sha256_matches;
    }
    LLVMValueRef get_standard_webhook_valid() {
        if (!fn_standard_webhook_valid) {
            LLVMTypeRef params[] = {
                ptr_ty, i32_ty, ptr_ty, i32_ty, ptr_ty, i32_ty, ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(i8_ty, params, 10, 0);
            fn_standard_webhook_valid =
                LLVMAddFunction(llvm_mod, "rut_helper_standard_webhook_valid", ft);
        }
        return fn_standard_webhook_valid;
    }
    LLVMValueRef get_signed_request_valid() {
        if (!fn_signed_request_valid) {
            LLVMTypeRef params[] = {i8_ty,
                                    ptr_ty,
                                    i32_ty,
                                    ptr_ty,
                                    i32_ty,
                                    ptr_ty,
                                    i32_ty,
                                    ptr_ty,
                                    i32_ty,
                                    ptr_ty,
                                    i32_ty,
                                    ptr_ty,
                                    i32_ty,
                                    ptr_ty,
                                    i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(i8_ty, params, 15, 0);
            fn_signed_request_valid =
                LLVMAddFunction(llvm_mod, "rut_helper_signed_request_valid", ft);
        }
        return fn_signed_request_valid;
    }
    LLVMValueRef get_jwt_claims_valid_with_lifetime() {
        if (!fn_jwt_claims_valid_with_lifetime) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty, ptr_ty, i32_ty, i64_ty, i64_ty};
            LLVMTypeRef ft = LLVMFunctionType(i8_ty, params, 8, 0);
            fn_jwt_claims_valid_with_lifetime =
                LLVMAddFunction(llvm_mod, "rut_helper_jwt_claims_valid_with_lifetime", ft);
        }
        return fn_jwt_claims_valid_with_lifetime;
    }
    LLVMValueRef get_basic_matches() {
        if (!fn_basic_matches) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(i8_ty, params, 4, 0);
            fn_basic_matches = LLVMAddFunction(llvm_mod, "rut_helper_basic_matches", ft);
        }
        return fn_basic_matches;
    }

    // u8 rut_helper_str_has_prefix(ptr, i32, ptr, i32)
    LLVMValueRef get_str_has_prefix() {
        if (!fn_str_has_prefix) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(i8_ty, params, 4, 0);
            fn_str_has_prefix = LLVMAddFunction(llvm_mod, "rut_helper_str_has_prefix", ft);
        }
        return fn_str_has_prefix;
    }

    // u8 rut_helper_str_eq(ptr, i32, ptr, i32)
    LLVMValueRef get_str_eq() {
        if (!fn_str_eq) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(i8_ty, params, 4, 0);
            fn_str_eq = LLVMAddFunction(llvm_mod, "rut_helper_str_eq", ft);
        }
        return fn_str_eq;
    }

    // i32 rut_helper_str_cmp(ptr, i32, ptr, i32)
    LLVMValueRef get_str_cmp() {
        if (!fn_str_cmp) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(i32_ty, params, 4, 0);
            fn_str_cmp = LLVMAddFunction(llvm_mod, "rut_helper_str_cmp", ft);
        }
        return fn_str_cmp;
    }

    // u8 regex helper(ptr, i32, ptr); message mode retains scan failures.
    LLVMValueRef get_str_regex_match() {
        if (!fn_str_regex_match) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(i8_ty, params, 3, 0);
            fn_str_regex_match = LLVMAddFunction(
                llvm_mod,
                ws_body_mode ? "rut_helper_str_regex_result" : "rut_helper_str_regex_match",
                ft);
        }
        return fn_str_regex_match;
    }

    // void rut_helper_str_trim_prefix(ptr, i32, ptr, i32, ptr, ptr)
    LLVMValueRef get_str_trim_prefix() {
        if (!fn_str_trim_prefix) {
            LLVMTypeRef params[] = {ptr_ty, i32_ty, ptr_ty, i32_ty, ptr_ty, ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(void_ty, params, 6, 0);
            fn_str_trim_prefix = LLVMAddFunction(llvm_mod, "rut_helper_str_trim_prefix", ft);
        }
        return fn_str_trim_prefix;
    }

    // ── RIR Type Queries ─────────────────────────────────────────────

    // Check if an RIR value has unsigned integer semantics.
    // Used to select signed vs unsigned LLVM comparison predicates.
    bool is_unsigned_operand(rir::ValueId id) const {
        if (!cur_fn || id.id >= cur_fn->value_cap) return false;
        const rir::Type* ty = cur_fn->values[id.id].type;
        if (!ty) return false;
        switch (ty->kind) {
            case rir::TypeKind::U32:
            case rir::TypeKind::U64:
            case rir::TypeKind::ByteSize:
            case rir::TypeKind::Duration:
            case rir::TypeKind::Time:
            case rir::TypeKind::StatusCode:
            case rir::TypeKind::IP:
                return true;
            default:
                return false;
        }
    }

    // ── String Globals ──────────────────────────────────────────────
    // Create a global constant from a Str (which is NOT null-terminated).
    // Returns a pointer to the first character. Uses LLVMConstStringInContext
    // with explicit length instead of LLVMBuildGlobalStringPtr (which uses strlen).
    LLVMValueRef make_global_str(Str s, const char* name) {
        // Create constant with null terminator appended (for C compatibility)
        LLVMValueRef str_const =
            LLVMConstStringInContext(llvm_ctx, s.ptr, s.len, /*DontNullTerminate=*/0);
        LLVMValueRef global = LLVMAddGlobal(llvm_mod, LLVMTypeOf(str_const), name);
        LLVMSetInitializer(global, str_const);
        LLVMSetGlobalConstant(global, 1);
        LLVMSetLinkage(global, LLVMPrivateLinkage);
        LLVMSetUnnamedAddress(global, LLVMGlobalUnnamedAddr);
        // GEP to get ptr to first char
        LLVMValueRef zero = LLVMConstInt(i32_ty, 0, 0);
        LLVMValueRef indices[] = {zero, zero};
        return LLVMBuildInBoundsGEP2(builder, LLVMTypeOf(str_const), global, indices, 2, name);
    }

    LLVMValueRef make_regex_db_load(Str pattern) {
        for (u32 i = 0; i < regex_global_count; i++) {
            const Str cached = regex_globals[i].pattern;
            if (cached.len == pattern.len &&
                (pattern.len == 0 || memcmp(cached.ptr, pattern.ptr, pattern.len) == 0)) {
                return LLVMBuildLoad2(builder, ptr_ty, regex_globals[i].db_global, "regex.db");
            }
        }

        char pattern_name[96];
        char db_name[96];
        const u32 id = regex_count++;
        snprintf(
            pattern_name, sizeof(pattern_name), "__rut_regex_pattern_%u_%u", regex_module_id, id);
        snprintf(db_name, sizeof(db_name), "__rut_regex_db_%u_%u", regex_module_id, id);

        LLVMValueRef str_const =
            LLVMConstStringInContext(llvm_ctx, pattern.ptr, pattern.len, /*DontNullTerminate=*/0);
        LLVMValueRef pattern_global = LLVMAddGlobal(llvm_mod, LLVMTypeOf(str_const), pattern_name);
        LLVMSetInitializer(pattern_global, str_const);
        LLVMSetGlobalConstant(pattern_global, 1);
        LLVMSetLinkage(pattern_global, LLVMPrivateLinkage);
        LLVMSetUnnamedAddress(pattern_global, LLVMGlobalUnnamedAddr);

        LLVMValueRef db_global = LLVMAddGlobal(llvm_mod, ptr_ty, db_name);
        LLVMSetLinkage(db_global, LLVMExternalLinkage);
        if (regex_global_count == regex_global_cap) {
            u32 new_cap = regex_global_cap ? regex_global_cap * 2 : 32;
            void* p = realloc(regex_globals, sizeof(RegexGlobalEntry) * new_cap);
            if (p) {
                regex_globals = static_cast<RegexGlobalEntry*>(p);
                regex_global_cap = new_cap;
            }
        }
        if (regex_global_count < regex_global_cap) {
            regex_globals[regex_global_count++] = {pattern, db_global};
        }
        return LLVMBuildLoad2(builder, ptr_ty, db_global, "regex.db");
    }

    // ── Value / Block access ───────────────────────────────────────

    void set_value(rir::ValueId id, LLVMValueRef val) {
        if (id.id < value_map_cap) value_map[id.id] = val;
        if (call_frame && id.id < cur_fn->value_count && call_frame_fields[id.id] != 0) {
            auto ptr = LLVMBuildStructGEP2(
                builder, call_frame_type, call_frame, call_frame_fields[id.id], "call.value.ptr");
            LLVMBuildStore(builder, val, ptr);
        }
    }

    LLVMValueRef get_value(rir::ValueId id) {
        if (call_frame && id.id < cur_fn->value_count && call_frame_fields[id.id] != 0) {
            auto ptr = LLVMBuildStructGEP2(
                builder, call_frame_type, call_frame, call_frame_fields[id.id], "call.value.ptr");
            return LLVMBuildLoad2(builder, map_type(cur_fn->values[id.id].type), ptr, "call.value");
        }
        if (id.id < value_map_cap) return value_map[id.id];
        return nullptr;
    }

    LLVMBasicBlockRef get_block(rir::BlockId id) {
        if (id.id < block_map_cap) return block_map[id.id];
        return nullptr;
    }
    void call_edge_values(rir::BlockId target) {
        if (!call_frame) return;
        const auto& block = cur_fn->blocks[target.id];
        for (u32 i = 0; i < block.inst_count; ++i) {
            const auto& inst = block.insts[i];
            if (inst.op != rir::Opcode::Phi) continue;
            for (u32 incoming = 0; incoming < 2; ++incoming) {
                if (inst.imm.block_targets[incoming].id != current_block) continue;
                auto value = get_value(inst.operands[incoming]);
                if (call_frame_fields[inst.result.id])
                    set_value(inst.result, value);
                else
                    call_phi_incoming[static_cast<u64>(inst.result.id) * 2 + incoming] = value;
            }
        }
    }

    // ── HandlerResult construction ─────────────────────────────────
    // Build an i64 from packed fields: {action:8, status:16, upstream:16, next_state:16,
    // yield_kind:8} Layout (little-endian byte offsets): [0]=action [1-2]=status [3-4]=upstream
    // [5-6]=next_state [7]=yield_kind

    LLVMValueRef make_result_status(u16 code) {
        // Pack: action=ReturnStatus, status_code=code, rest=0
        u64 packed = 0;
        packed |= static_cast<u64>(HandlerAction::ReturnStatus);  // action
        packed |= static_cast<u64>(code) << 8;                    // status_code
        return LLVMConstInt(i64_ty, packed, 0);
    }

    LLVMValueRef make_result_forward(u16 upstream) {
        u64 packed = 0;
        packed |= static_cast<u64>(HandlerAction::Forward);  // action
        packed |= static_cast<u64>(upstream) << 24;          // upstream_id
        return LLVMConstInt(i64_ty, packed, 0);
    }

    // Build packed HandlerResult for a Yield. Payload spans bytes 1-4
    // (status_code + upstream_id), giving 32 bits for kinds like Timer
    // where ms can exceed u16. See HandlerResult::make_yield_payload.
    LLVMValueRef make_result_yield(u16 next_state, u8 yield_kind, u32 payload) {
        u64 packed = 0;
        packed |= static_cast<u64>(HandlerAction::Yield);  // action
        packed |= static_cast<u64>(payload) << 8;          // status + upstream slots
        packed |= static_cast<u64>(next_state) << 40;      // next_state
        packed |= static_cast<u64>(yield_kind) << 56;      // yield_kind
        return LLVMConstInt(i64_ty, packed, 0);
    }

    // ── Type mapping ───────────────────────────────────────────────

    LLVMTypeRef cache_type(const rir::Type* ty, LLVMTypeRef t) {
        if (type_cache_count < kMaxCachedTypes) {
            type_cache[type_cache_count++] = {ty, t};
        }
        return t;
    }

    LLVMTypeRef map_type(const rir::Type* ty) {
        if (!ty) return void_ty;
        for (u32 i = 0; i < type_cache_count; i++) {
            if (type_cache[i].key == ty) return type_cache[i].value;
        }
        switch (ty->kind) {
            case rir::TypeKind::Void:
                return void_ty;
            case rir::TypeKind::Bool:
                return i1_ty;
            case rir::TypeKind::I32:
                return i32_ty;
            case rir::TypeKind::I64:
                return i64_ty;
            case rir::TypeKind::U32:
                return i32_ty;
            case rir::TypeKind::U64:
                return i64_ty;
            case rir::TypeKind::F64:
                return LLVMDoubleTypeInContext(llvm_ctx);
            case rir::TypeKind::Str:
                return str_ty;
            case rir::TypeKind::ByteSize:
            case rir::TypeKind::Duration:
            case rir::TypeKind::Time:
                return i64_ty;
            case rir::TypeKind::IP:
            case rir::TypeKind::StatusCode:
                return i32_ty;
            case rir::TypeKind::Method:
                return i8_ty;
            case rir::TypeKind::Optional:
                if (ty->inner && ty->inner->kind == rir::TypeKind::I32) return opt_i32_ty;
                if (ty->inner && ty->inner->kind == rir::TypeKind::Str) return opt_str_ty;
                {
                    LLVMTypeRef payload = map_type(ty->inner);
                    LLVMTypeRef fields[] = {i8_ty, payload};
                    return cache_type(ty, LLVMStructTypeInContext(llvm_ctx, fields, 2, 0));
                }
            case rir::TypeKind::Struct:
                if (ty->struct_def) {
                    auto* sd = ty->struct_def;
                    // Stack buffer capped at 16 to avoid heap/arena plumbing in
                    // the type mapper. MirStruct::kMaxFields is 8 upstream, so
                    // 16 is 2x headroom; if frontend capacity ever grows, raise
                    // this in lockstep. Trap instead of silently truncating.
                    static constexpr u32 kMaxStructFields = 16;
                    if (sd->field_count > kMaxStructFields) __builtin_trap();
                    LLVMTypeRef fields[kMaxStructFields]{};
                    for (u32 i = 0; i < sd->field_count; i++) {
                        fields[i] = map_type(sd->fields()[i].type);
                    }
                    return cache_type(
                        ty, LLVMStructTypeInContext(llvm_ctx, fields, sd->field_count, 0));
                }
                return ptr_ty;
            default:
                return ptr_ty;
        }
    }

    LLVMValueRef build_select_value(LLVMValueRef cond, LLVMValueRef then_v, LLVMValueRef else_v) {
        LLVMTypeRef ty = LLVMTypeOf(then_v);
        if (LLVMGetTypeKind(ty) != LLVMStructTypeKind) {
            return LLVMBuildSelect(builder, cond, then_v, else_v, "sel");
        }

        LLVMValueRef out = LLVMGetUndef(ty);
        const u32 field_count = LLVMCountStructElementTypes(ty);
        for (u32 i = 0; i < field_count; i++) {
            LLVMValueRef then_field = LLVMBuildExtractValue(builder, then_v, i, "sel.then");
            LLVMValueRef else_field = LLVMBuildExtractValue(builder, else_v, i, "sel.else");
            LLVMValueRef selected = build_select_value(cond, then_field, else_field);
            out = LLVMBuildInsertValue(builder, out, selected, i, "sel.field");
        }
        return out;
    }
};

// ── Instruction Emission ───────────────────────────────────────────

static void emit_instruction(Ctx& c, const rir::Instruction& inst) {
    switch (inst.op) {
        // ── Constants ──
        case rir::Opcode::ConstI32: {
            LLVMValueRef v = LLVMConstInt(c.i32_ty, static_cast<u64>(inst.imm.i32_val), 1);
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ConstI64: {
            LLVMValueRef v = LLVMConstInt(c.i64_ty, static_cast<u64>(inst.imm.i64_val), 1);
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ConstBool: {
            LLVMValueRef v = LLVMConstInt(c.i1_ty, inst.imm.bool_val ? 1 : 0, 0);
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ConstStr: {
            // Create a global constant string, then build {ptr, i32} struct.
            // Uses make_global_str() with explicit length (Str is not null-terminated).
            Str s = inst.imm.str_val;
            LLVMValueRef gs = c.make_global_str(s, "str");
            LLVMValueRef len = LLVMConstInt(c.i32_ty, s.len, 0);
            LLVMValueRef strval = LLVMGetUndef(c.str_ty);
            strval = LLVMBuildInsertValue(c.builder, strval, gs, 0, "str.ptr");
            strval = LLVMBuildInsertValue(c.builder, strval, len, 1, "str.len");
            c.set_value(inst.result, strval);
            break;
        }
        case rir::Opcode::ConstDuration:
        case rir::Opcode::ConstByteSize: {
            LLVMValueRef v = LLVMConstInt(c.i64_ty, static_cast<u64>(inst.imm.i64_val), 1);
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ConstMethod: {
            LLVMValueRef v = LLVMConstInt(c.i8_ty, inst.imm.method_val, 0);
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ConstStatus: {
            LLVMValueRef v = LLVMConstInt(c.i32_ty, static_cast<u64>(inst.imm.i32_val), 0);
            c.set_value(inst.result, v);
            break;
        }

        // ── Request access ──
        case rir::Opcode::ReqPath: {
            // Alloca for out params, call helper, load result into Str struct.
            LLVMValueRef out_ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "path.ptr");
            LLVMValueRef out_len = LLVMBuildAlloca(c.builder, c.i32_ty, "path.len");
            LLVMValueRef args[] = {c.param_req_data, c.param_req_len, out_ptr, out_len};
            LLVMBuildCall2(
                c.builder, LLVMGlobalGetValueType(c.get_req_path()), c.get_req_path(), args, 4, "");
            LLVMValueRef p = LLVMBuildLoad2(c.builder, c.ptr_ty, out_ptr, "p");
            LLVMValueRef l = LLVMBuildLoad2(c.builder, c.i32_ty, out_len, "l");
            LLVMValueRef strval = LLVMGetUndef(c.str_ty);
            strval = LLVMBuildInsertValue(c.builder, strval, p, 0, "path.s.ptr");
            strval = LLVMBuildInsertValue(c.builder, strval, l, 1, "path.s.len");
            c.set_value(inst.result, strval);
            break;
        }
        case rir::Opcode::ReqPathOnly: {
            LLVMValueRef out_ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "path_only.ptr");
            LLVMValueRef out_len = LLVMBuildAlloca(c.builder, c.i32_ty, "path_only.len");
            LLVMValueRef args[] = {c.param_req_data, c.param_req_len, out_ptr, out_len};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_req_path_only()),
                           c.get_req_path_only(),
                           args,
                           4,
                           "");
            LLVMValueRef p = LLVMBuildLoad2(c.builder, c.ptr_ty, out_ptr, "path_only.p");
            LLVMValueRef l = LLVMBuildLoad2(c.builder, c.i32_ty, out_len, "path_only.l");
            LLVMValueRef strval = LLVMGetUndef(c.str_ty);
            strval = LLVMBuildInsertValue(c.builder, strval, p, 0, "path_only.s.ptr");
            strval = LLVMBuildInsertValue(c.builder, strval, l, 1, "path_only.s.len");
            c.set_value(inst.result, strval);
            break;
        }
        case rir::Opcode::WsForward:
        case rir::Opcode::WsClose: {
            const bool kForward = inst.op == rir::Opcode::WsForward;
            LLVMValueRef payload = c.get_value(inst.operands[kForward ? 0 : 1]);
            LLVMValueRef ptr = LLVMBuildExtractValue(c.builder, payload, 0, "ws.output.ptr");
            LLVMValueRef len = LLVMBuildExtractValue(c.builder, payload, 1, "ws.output.len");
            LLVMTypeRef params_forward[] = {c.ptr_ty, c.ptr_ty, c.i32_ty, c.i8_ty};
            LLVMTypeRef params_close[] = {c.ptr_ty, c.i32_ty, c.ptr_ty, c.i32_ty};
            LLVMTypeRef ft =
                LLVMFunctionType(c.i32_ty, kForward ? params_forward : params_close, 4, 0);
            const char* name = kForward ? "rut_helper_ws_forward" : "rut_helper_ws_close";
            LLVMValueRef fn = LLVMGetNamedFunction(c.llvm_mod, name);
            if (!fn) fn = LLVMAddFunction(c.llvm_mod, name, ft);
            LLVMValueRef args_forward[] = {
                c.param_conn, ptr, len, LLVMConstInt(c.i8_ty, inst.imm.i32_val, 0)};
            LLVMValueRef args_close[] = {
                c.param_conn, kForward ? nullptr : c.get_value(inst.operands[0]), ptr, len};
            c.set_value(
                inst.result,
                LLVMBuildCall2(
                    c.builder, ft, fn, kForward ? args_forward : args_close, 4, "ws.output"));
            break;
        }
        case rir::Opcode::WsMessageField: {
            const auto kField = static_cast<WsMessageFieldId>(inst.imm.i32_val);
            LLVMValueRef value = nullptr;
            if (kField == WsMessageFieldId::CloseReason ||
                kField == WsMessageFieldId::CloseUpstreamReason) {
                LLVMTypeRef params[] = {c.ptr_ty, c.i32_ty, c.ptr_ty, c.ptr_ty};
                LLVMTypeRef type =
                    LLVMFunctionType(LLVMVoidTypeInContext(c.llvm_ctx), params, 4, 0);
                LLVMValueRef helper =
                    LLVMGetNamedFunction(c.llvm_mod, "rut_helper_ws_close_reason");
                if (!helper)
                    helper = LLVMAddFunction(c.llvm_mod, "rut_helper_ws_close_reason", type);
                LLVMValueRef ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "close.reason.ptr");
                LLVMValueRef len = LLVMBuildAlloca(c.builder, c.i32_ty, "close.reason.len");
                LLVMValueRef args[] = {
                    c.param_conn, LLVMConstInt(c.i32_ty, static_cast<u32>(kField), 0), ptr, len};
                LLVMBuildCall2(c.builder, type, helper, args, 4, "");
                value = LLVMGetUndef(c.str_ty);
                value = LLVMBuildInsertValue(
                    c.builder,
                    value,
                    LLVMBuildLoad2(c.builder, c.ptr_ty, ptr, "close.reason.data"),
                    0,
                    "close.reason");
                value = LLVMBuildInsertValue(
                    c.builder,
                    value,
                    LLVMBuildLoad2(c.builder, c.i32_ty, len, "close.reason.size"),
                    1,
                    "close.reason");
            } else if (kField == WsMessageFieldId::ConnectionSubprotocol) {
                LLVMTypeRef params[] = {c.ptr_ty, c.ptr_ty, c.ptr_ty};
                LLVMTypeRef type =
                    LLVMFunctionType(LLVMVoidTypeInContext(c.llvm_ctx), params, 3, 0);
                LLVMValueRef helper =
                    LLVMGetNamedFunction(c.llvm_mod, "rut_helper_ws_connection_subprotocol");
                if (!helper)
                    helper =
                        LLVMAddFunction(c.llvm_mod, "rut_helper_ws_connection_subprotocol", type);
                LLVMValueRef ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "connection.protocol.ptr");
                LLVMValueRef len = LLVMBuildAlloca(c.builder, c.i32_ty, "connection.protocol.len");
                LLVMValueRef args[] = {c.param_conn, ptr, len};
                LLVMBuildCall2(c.builder, type, helper, args, 3, "");
                value = LLVMGetUndef(c.str_ty);
                value = LLVMBuildInsertValue(
                    c.builder,
                    value,
                    LLVMBuildLoad2(c.builder, c.ptr_ty, ptr, "connection.protocol.data"),
                    0,
                    "connection.protocol");
                value = LLVMBuildInsertValue(
                    c.builder,
                    value,
                    LLVMBuildLoad2(c.builder, c.i32_ty, len, "connection.protocol.size"),
                    1,
                    "connection.protocol");
            } else if (kField == WsMessageFieldId::ConnectionRemoteAddr ||
                       kField == WsMessageFieldId::ConnectionRemotePort ||
                       kField == WsMessageFieldId::ConnectionIsTls ||
                       kField == WsMessageFieldId::CloseCode ||
                       kField == WsMessageFieldId::CloseUpstreamCode ||
                       kField == WsMessageFieldId::CloseWasClean) {
                LLVMTypeRef params[] = {c.ptr_ty, c.i32_ty};
                LLVMTypeRef type = LLVMFunctionType(c.i32_ty, params, 2, 0);
                LLVMValueRef helper =
                    LLVMGetNamedFunction(c.llvm_mod, "rut_helper_ws_connection_scalar");
                if (!helper)
                    helper = LLVMAddFunction(c.llvm_mod, "rut_helper_ws_connection_scalar", type);
                LLVMValueRef args[] = {c.param_conn,
                                       LLVMConstInt(c.i32_ty, static_cast<u32>(kField), 0)};
                value = LLVMBuildCall2(c.builder, type, helper, args, 2, "connection.scalar");
                if (ws_message_field_is_bool(kField))
                    value = LLVMBuildICmp(c.builder,
                                          LLVMIntNE,
                                          value,
                                          LLVMConstInt(c.i32_ty, 0, 0),
                                          "connection.tls");
            } else if (kField == WsMessageFieldId::Payload) {
                value = LLVMGetUndef(c.str_ty);
                value = LLVMBuildInsertValue(c.builder, value, c.param_req_data, 0, "msg.ptr");
                value = LLVMBuildInsertValue(c.builder, value, c.param_req_len, 1, "msg.len");
            } else if (kField == WsMessageFieldId::Length) {
                value = c.param_req_len;
            } else {
                const bool kDirection =
                    kField == WsMessageFieldId::Direction || kField == WsMessageFieldId::FromClient;
                LLVMValueRef flag = LLVMBuildICmp(
                    c.builder,
                    kDirection ? LLVMIntNE : LLVMIntEQ,
                    kDirection ? c.param_ws_from_client : c.param_ws_opcode,
                    LLVMConstInt(
                        c.i8_ty, kDirection ? 0 : (kField == WsMessageFieldId::IsText ? 1 : 2), 0),
                    "msg.flag");
                if (kField == WsMessageFieldId::Kind || kField == WsMessageFieldId::Direction) {
                    value = LLVMBuildSelect(c.builder,
                                            flag,
                                            LLVMConstInt(c.i32_ty, kDirection ? 0 : 1, 0),
                                            LLVMConstInt(c.i32_ty, kDirection ? 1 : 0, 0),
                                            "msg.case");
                } else {
                    value = flag;
                }
            }
            c.set_value(inst.result, value);
            break;
        }
        case rir::Opcode::ReqBody: {
            LLVMValueRef out_ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "body.ptr");
            LLVMValueRef out_len = LLVMBuildAlloca(c.builder, c.i32_ty, "body.len");
            LLVMValueRef args[] = {c.param_req_data, c.param_req_len, out_ptr, out_len};
            LLVMBuildCall2(
                c.builder, LLVMGlobalGetValueType(c.get_req_body()), c.get_req_body(), args, 4, "");
            LLVMValueRef p = LLVMBuildLoad2(c.builder, c.ptr_ty, out_ptr, "body.p");
            LLVMValueRef l = LLVMBuildLoad2(c.builder, c.i32_ty, out_len, "body.l");
            LLVMValueRef strval = LLVMGetUndef(c.str_ty);
            strval = LLVMBuildInsertValue(c.builder, strval, p, 0, "body.s.ptr");
            strval = LLVMBuildInsertValue(c.builder, strval, l, 1, "body.s.len");
            c.set_value(inst.result, strval);
            break;
        }
        case rir::Opcode::ReqHttpVersion: {
            LLVMValueRef out_ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "http_version.ptr");
            LLVMValueRef out_len = LLVMBuildAlloca(c.builder, c.i32_ty, "http_version.len");
            LLVMValueRef args[] = {c.param_req_data, c.param_req_len, out_ptr, out_len};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_req_http_version()),
                           c.get_req_http_version(),
                           args,
                           4,
                           "");
            LLVMValueRef p = LLVMBuildLoad2(c.builder, c.ptr_ty, out_ptr, "http_version.p");
            LLVMValueRef l = LLVMBuildLoad2(c.builder, c.i32_ty, out_len, "http_version.l");
            LLVMValueRef strval = LLVMGetUndef(c.str_ty);
            strval = LLVMBuildInsertValue(c.builder, strval, p, 0, "http_version.s.ptr");
            strval = LLVMBuildInsertValue(c.builder, strval, l, 1, "http_version.s.len");
            c.set_value(inst.result, strval);
            break;
        }
        case rir::Opcode::ReqKeepAlive:
        case rir::Opcode::ReqChunked:
        case rir::Opcode::ReqHasContentLength:
        case rir::Opcode::ReqHttp10:
        case rir::Opcode::ReqHttp11: {
            const u8 flag = inst.op == rir::Opcode::ReqKeepAlive          ? 0
                            : inst.op == rir::Opcode::ReqChunked          ? 1
                            : inst.op == rir::Opcode::ReqHasContentLength ? 2
                            : inst.op == rir::Opcode::ReqHttp10           ? 3
                                                                          : 4;
            LLVMValueRef args[] = {
                c.param_req_data, c.param_req_len, LLVMConstInt(c.i8_ty, flag, 0)};
            LLVMValueRef v = LLVMBuildCall2(c.builder,
                                            LLVMGlobalGetValueType(c.get_req_flag()),
                                            c.get_req_flag(),
                                            args,
                                            3,
                                            flag == 0   ? "keep_alive"
                                            : flag == 1 ? "chunked"
                                            : flag == 2 ? "has_content_length"
                                            : flag == 3 ? "http10"
                                                        : "http11");
            LLVMValueRef b =
                LLVMBuildICmp(c.builder, LLVMIntNE, v, LLVMConstInt(c.i8_ty, 0, 0), "req.flag");
            c.set_value(inst.result, b);
            break;
        }
        case rir::Opcode::ReqMethod: {
            LLVMValueRef args[] = {c.param_req_data, c.param_req_len};
            LLVMValueRef v = LLVMBuildCall2(c.builder,
                                            LLVMGlobalGetValueType(c.get_req_method()),
                                            c.get_req_method(),
                                            args,
                                            2,
                                            "method");
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ResumeEventKind: {
            LLVMValueRef off = LLVMConstInt(
                c.i32_ty, static_cast<u32>(offsetof(HandlerCtx, resume_event_kind)), 0);
            LLVMValueRef ptr =
                LLVMBuildGEP2(c.builder, c.i8_ty, c.param_ctx, &off, 1, "ev.kind.ptr");
            LLVMValueRef v = LLVMBuildLoad2(c.builder, c.i32_ty, ptr, "ev.kind");
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ResumeEventResult: {
            LLVMValueRef off = LLVMConstInt(
                c.i32_ty, static_cast<u32>(offsetof(HandlerCtx, resume_event_result)), 0);
            LLVMValueRef ptr =
                LLVMBuildGEP2(c.builder, c.i8_ty, c.param_ctx, &off, 1, "ev.result.ptr");
            LLVMValueRef v = LLVMBuildLoad2(c.builder, c.i32_ty, ptr, "ev.result");
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::CtxLoadSlotI32: {
            const u32 slot = static_cast<u32>(inst.imm.i32_val);
            LLVMValueRef count_off =
                LLVMConstInt(c.i32_ty, static_cast<u32>(offsetof(HandlerCtx, slot_count)), 0);
            LLVMValueRef count_ptr =
                LLVMBuildGEP2(c.builder, c.i8_ty, c.param_ctx, &count_off, 1, "ctx.slot.count.ptr");
            LLVMValueRef count = LLVMBuildLoad2(c.builder, c.i32_ty, count_ptr, "ctx.slot.count");
            LLVMValueRef has_slot = LLVMBuildICmp(
                c.builder, LLVMIntUGT, count, LLVMConstInt(c.i32_ty, slot, 0), "ctx.has.slot");

            const u32 byte_offset = static_cast<u32>(sizeof(HandlerCtx)) + slot * 8u;
            LLVMValueRef off = LLVMConstInt(c.i32_ty, byte_offset, 0);
            LLVMValueRef ptr =
                LLVMBuildGEP2(c.builder, c.i8_ty, c.param_ctx, &off, 1, "ctx.slot.ptr");
            LLVMTypeRef slot_i64_ptr_ty = LLVMPointerType(c.i64_ty, 0);
            LLVMValueRef slot_i64_ptr =
                LLVMBuildBitCast(c.builder, ptr, slot_i64_ptr_ty, "ctx.slot.ptr64");

            LLVMTypeRef fallback_ptr_ty = LLVMPointerType(c.i32_ty, 0);
            LLVMValueRef fallback_ptr = nullptr;
            if ((slot & 1u) == 0) {
                LLVMValueRef kind_off = LLVMConstInt(
                    c.i32_ty, static_cast<u32>(offsetof(HandlerCtx, resume_event_kind)), 0);
                LLVMValueRef kind_ptr =
                    LLVMBuildGEP2(c.builder, c.i8_ty, c.param_ctx, &kind_off, 1, "ev.kind.ptr");
                fallback_ptr = LLVMBuildBitCast(
                    c.builder, kind_ptr, fallback_ptr_ty, "ctx.slot.fallback.ptr32");
            } else {
                LLVMValueRef result_off = LLVMConstInt(
                    c.i32_ty, static_cast<u32>(offsetof(HandlerCtx, resume_event_result)), 0);
                LLVMValueRef result_ptr =
                    LLVMBuildGEP2(c.builder, c.i8_ty, c.param_ctx, &result_off, 1, "ev.result.ptr");
                fallback_ptr = LLVMBuildBitCast(
                    c.builder, result_ptr, fallback_ptr_ty, "ctx.slot.fallback.ptr32");
            }
            LLVMValueRef fallback_i32 =
                LLVMBuildLoad2(c.builder, c.i32_ty, fallback_ptr, "ctx.slot.fallback");
            LLVMValueRef fallback_i64 =
                LLVMBuildZExt(c.builder, fallback_i32, c.i64_ty, "ctx.slot.fallback64");
            LLVMBuildStore(c.builder, fallback_i64, c.ctx_store_sink);
            LLVMValueRef selected_ptr = LLVMBuildSelect(
                c.builder, has_slot, slot_i64_ptr, c.ctx_store_sink, "ctx.slot.ptr.sel");
            LLVMValueRef slot_i64 = LLVMBuildLoad2(c.builder, c.i64_ty, selected_ptr, "ctx.slot64");
            LLVMValueRef v = LLVMBuildTrunc(c.builder, slot_i64, c.i32_ty, "ctx.slot.value");
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ReqHeaderCount: {
            LLVMValueRef name = c.make_global_str(inst.imm.str_val, "hdr.count.name");
            LLVMValueRef args[] = {c.param_req_data,
                                   c.param_req_len,
                                   name,
                                   LLVMConstInt(c.i32_ty, inst.imm.str_val.len, 0)};
            LLVMValueRef fn = c.get_req_header_count();
            c.set_value(
                inst.result,
                LLVMBuildCall2(c.builder, LLVMGlobalGetValueType(fn), fn, args, 4, "header.count"));
            break;
        }
        case rir::Opcode::ReqUniqueHeader:
        case rir::Opcode::ReqHeader: {
            Str name = inst.imm.str_val;
            LLVMValueRef name_ptr = c.make_global_str(name, "hdr.name");
            LLVMValueRef name_len = LLVMConstInt(c.i32_ty, name.len, 0);
            LLVMValueRef out_has = LLVMBuildAlloca(c.builder, c.i8_ty, "hdr.has");
            LLVMValueRef out_ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "hdr.ptr");
            LLVMValueRef out_len = LLVMBuildAlloca(c.builder, c.i32_ty, "hdr.len");
            LLVMValueRef args[] = {
                c.param_req_data, c.param_req_len, name_ptr, name_len, out_has, out_ptr, out_len};
            LLVMValueRef fn = inst.op == rir::Opcode::ReqUniqueHeader ? c.get_req_unique_header()
                                                                      : c.get_req_header();
            LLVMBuildCall2(c.builder, LLVMGlobalGetValueType(fn), fn, args, 7, "");
            LLVMValueRef h = LLVMBuildLoad2(c.builder, c.i8_ty, out_has, "h");
            LLVMValueRef p = LLVMBuildLoad2(c.builder, c.ptr_ty, out_ptr, "p");
            LLVMValueRef l = LLVMBuildLoad2(c.builder, c.i32_ty, out_len, "l");
            LLVMValueRef opt = LLVMGetUndef(c.opt_str_ty);
            opt = LLVMBuildInsertValue(c.builder, opt, h, 0, "opt.has");
            opt = LLVMBuildInsertValue(c.builder, opt, p, 1, "opt.ptr");
            opt = LLVMBuildInsertValue(c.builder, opt, l, 2, "opt.len");
            c.set_value(inst.result, opt);
            break;
        }
        case rir::Opcode::ReqSetPath: {
            // operands[0] is the new path (a Str value, e.g. a ConstStr). Record
            // it on the connection via the runtime helper; the proxy rewrites the
            // outbound request line from it before forwarding.
            LLVMValueRef path = c.get_value(inst.operands[0]);
            LLVMValueRef p = LLVMBuildExtractValue(c.builder, path, 0, "setpath.ptr");
            LLVMValueRef l = LLVMBuildExtractValue(c.builder, path, 1, "setpath.len");
            LLVMValueRef args[] = {c.param_conn, p, l};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_req_set_path()),
                           c.get_req_set_path(),
                           args,
                           3,
                           "");
            break;
        }
        case rir::Opcode::ReqSetTargetTransform: {
            // Preserve forged negative i32 immediates as unsigned bits; the
            // helper records them as a fail-closed sentinel rather than
            // collapsing them into the no-effect state.
            LLVMValueRef id =
                LLVMConstInt(c.i32_ty, static_cast<u32>(inst.imm.i32_val), /*SignExtend=*/0);
            LLVMValueRef args[] = {c.param_conn, id};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_req_set_target_transform()),
                           c.get_req_set_target_transform(),
                           args,
                           2,
                           "");
            break;
        }
        case rir::Opcode::ReqSetHeader:
        case rir::Opcode::ReqSetOwnedHeader: {
            // imm.str_val is the header name (a literal); operands[0] is the value
            // (a Str register). Record both on the connection; the proxy injects or
            // replaces the line in the outbound request before forwarding.
            Str name = inst.imm.str_val;
            LLVMValueRef name_ptr = c.make_global_str(name, "setheader.name");
            LLVMValueRef name_len = LLVMConstInt(c.i32_ty, name.len, 0);
            LLVMValueRef value = c.get_value(inst.operands[0]);
            LLVMValueRef vptr = LLVMBuildExtractValue(c.builder, value, 0, "setheader.vptr");
            LLVMValueRef vlen = LLVMBuildExtractValue(c.builder, value, 1, "setheader.vlen");
            if (inst.op == rir::Opcode::ReqSetOwnedHeader) {
                LLVMValueRef args[] = {c.param_conn, c.param_arena, name_ptr, name_len, vptr, vlen};
                LLVMBuildCall2(c.builder,
                               LLVMGlobalGetValueType(c.get_req_set_owned_header()),
                               c.get_req_set_owned_header(),
                               args,
                               6,
                               "");
            } else {
                LLVMValueRef args[] = {c.param_conn, name_ptr, name_len, vptr, vlen};
                LLVMBuildCall2(c.builder,
                               LLVMGlobalGetValueType(c.get_req_set_header()),
                               c.get_req_set_header(),
                               args,
                               5,
                               "");
            }
            break;
        }
        case rir::Opcode::ReqAddHeader: {
            Str name = inst.imm.str_val;
            LLVMValueRef name_ptr = c.make_global_str(name, "addheader.name");
            LLVMValueRef name_len = LLVMConstInt(c.i32_ty, name.len, 0);
            LLVMValueRef value = c.get_value(inst.operands[0]);
            LLVMValueRef vptr = LLVMBuildExtractValue(c.builder, value, 0, "addheader.vptr");
            LLVMValueRef vlen = LLVMBuildExtractValue(c.builder, value, 1, "addheader.vlen");
            LLVMValueRef args[] = {c.param_conn, name_ptr, name_len, vptr, vlen};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_req_add_header()),
                           c.get_req_add_header(),
                           args,
                           5,
                           "");
            break;
        }
        case rir::Opcode::ReqRemoveHeader: {
            const Str name = inst.imm.str_val;
            LLVMValueRef args[] = {c.param_conn,
                                   c.make_global_str(name, "removeheader.name"),
                                   LLVMConstInt(c.i32_ty, name.len, 0)};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_req_remove_header()),
                           c.get_req_remove_header(),
                           args,
                           3,
                           "");
            break;
        }
        case rir::Opcode::RespSetHeader:
        case rir::Opcode::RespAddHeader: {
            const bool add = inst.op == rir::Opcode::RespAddHeader;
            Str name = inst.imm.str_val;
            LLVMValueRef name_ptr = c.make_global_str(name, add ? "respadd.name" : "respset.name");
            LLVMValueRef name_len = LLVMConstInt(c.i32_ty, name.len, 0);
            LLVMValueRef value = c.get_value(inst.operands[0]);
            const bool optional =
                !add && c.cur_fn->values[inst.operands[0].id].type->kind == rir::TypeKind::Optional;
            if (optional) {
                LLVMValueRef args[] = {c.param_conn,
                                       name_ptr,
                                       name_len,
                                       LLVMBuildExtractValue(c.builder, value, 1, "resp.vptr"),
                                       LLVMBuildExtractValue(c.builder, value, 2, "resp.vlen"),
                                       LLVMBuildExtractValue(c.builder, value, 0, "resp.present")};
                LLVMValueRef helper = c.get_resp_set_optional_header();
                LLVMBuildCall2(c.builder, LLVMGlobalGetValueType(helper), helper, args, 6, "");
                break;
            }
            LLVMValueRef vptr = LLVMBuildExtractValue(c.builder, value, 0, "resp.vptr");
            LLVMValueRef vlen = LLVMBuildExtractValue(c.builder, value, 1, "resp.vlen");
            LLVMValueRef args[] = {c.param_conn, name_ptr, name_len, vptr, vlen};
            LLVMValueRef helper = add ? c.get_resp_add_header() : c.get_resp_set_header();
            LLVMBuildCall2(c.builder, LLVMGlobalGetValueType(helper), helper, args, 5, "");
            break;
        }
        case rir::Opcode::RespRemoveHeader: {
            Str name = inst.imm.str_val;
            LLVMValueRef name_ptr = c.make_global_str(name, "respremove.name");
            LLVMValueRef name_len = LLVMConstInt(c.i32_ty, name.len, 0);
            LLVMValueRef args[] = {c.param_conn, name_ptr, name_len};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_resp_remove_header()),
                           c.get_resp_remove_header(),
                           args,
                           3,
                           "");
            break;
        }
        case rir::Opcode::RespCommitHeaders: {
            LLVMValueRef args[] = {c.param_conn};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_resp_commit_headers()),
                           c.get_resp_commit_headers(),
                           args,
                           1,
                           "");
            break;
        }
        case rir::Opcode::RespHeader: {
            Str name = inst.imm.str_val;
            LLVMValueRef name_ptr = c.make_global_str(name, "respheader.name");
            LLVMValueRef name_len = LLVMConstInt(c.i32_ty, name.len, 0);
            LLVMValueRef fallback = c.get_value(inst.operands[0]);
            LLVMValueRef fallback_has =
                LLVMBuildExtractValue(c.builder, fallback, 0, "resp.fb.has");
            LLVMValueRef fallback_ptr =
                LLVMBuildExtractValue(c.builder, fallback, 1, "resp.fb.ptr");
            LLVMValueRef fallback_len =
                LLVMBuildExtractValue(c.builder, fallback, 2, "resp.fb.len");
            LLVMValueRef out_has = LLVMBuildAlloca(c.builder, c.i8_ty, "resp.hdr.has");
            LLVMValueRef out_ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "resp.hdr.ptr");
            LLVMValueRef out_len = LLVMBuildAlloca(c.builder, c.i32_ty, "resp.hdr.len");
            LLVMValueRef args[] = {c.param_conn,
                                   name_ptr,
                                   name_len,
                                   fallback_has,
                                   fallback_ptr,
                                   fallback_len,
                                   out_has,
                                   out_ptr,
                                   out_len};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_resp_header()),
                           c.get_resp_header(),
                           args,
                           9,
                           "");
            LLVMValueRef h = LLVMBuildLoad2(c.builder, c.i8_ty, out_has, "resp.h");
            LLVMValueRef p = LLVMBuildLoad2(c.builder, c.ptr_ty, out_ptr, "resp.p");
            LLVMValueRef l = LLVMBuildLoad2(c.builder, c.i32_ty, out_len, "resp.l");
            LLVMValueRef opt = LLVMGetUndef(c.opt_str_ty);
            opt = LLVMBuildInsertValue(c.builder, opt, h, 0, "resp.opt.has");
            opt = LLVMBuildInsertValue(c.builder, opt, p, 1, "resp.opt.ptr");
            opt = LLVMBuildInsertValue(c.builder, opt, l, 2, "resp.opt.len");
            c.set_value(inst.result, opt);
            break;
        }
        case rir::Opcode::ReqParam: {
            Str name = inst.imm.str_val;
            LLVMValueRef name_ptr = c.make_global_str(name, "param.name");
            LLVMValueRef name_len = LLVMConstInt(c.i32_ty, name.len, 0);
            LLVMValueRef out_ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "param.ptr");
            LLVMValueRef out_len = LLVMBuildAlloca(c.builder, c.i32_ty, "param.len");
            LLVMValueRef args[] = {c.param_ctx, name_ptr, name_len, out_ptr, out_len};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_req_param()),
                           c.get_req_param(),
                           args,
                           5,
                           "");
            LLVMValueRef p = LLVMBuildLoad2(c.builder, c.ptr_ty, out_ptr, "p");
            LLVMValueRef l = LLVMBuildLoad2(c.builder, c.i32_ty, out_len, "l");
            LLVMValueRef strval = LLVMGetUndef(c.str_ty);
            strval = LLVMBuildInsertValue(c.builder, strval, p, 0, "param.s.ptr");
            strval = LLVMBuildInsertValue(c.builder, strval, l, 1, "param.s.len");
            c.set_value(inst.result, strval);
            break;
        }
        case rir::Opcode::ReqCookie: {
            Str name = inst.imm.str_val;
            LLVMValueRef name_ptr = c.make_global_str(name, "cookie.name");
            LLVMValueRef name_len = LLVMConstInt(c.i32_ty, name.len, 0);
            LLVMValueRef out_has = LLVMBuildAlloca(c.builder, c.i8_ty, "cookie.has");
            LLVMValueRef out_ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "cookie.ptr");
            LLVMValueRef out_len = LLVMBuildAlloca(c.builder, c.i32_ty, "cookie.len");
            LLVMValueRef args[] = {
                c.param_req_data, c.param_req_len, name_ptr, name_len, out_has, out_ptr, out_len};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_req_cookie()),
                           c.get_req_cookie(),
                           args,
                           7,
                           "");
            LLVMValueRef h = LLVMBuildLoad2(c.builder, c.i8_ty, out_has, "cookie.h");
            LLVMValueRef p = LLVMBuildLoad2(c.builder, c.ptr_ty, out_ptr, "cookie.p");
            LLVMValueRef l = LLVMBuildLoad2(c.builder, c.i32_ty, out_len, "cookie.l");
            LLVMValueRef opt = LLVMGetUndef(c.opt_str_ty);
            opt = LLVMBuildInsertValue(c.builder, opt, h, 0, "cookie.opt.has");
            opt = LLVMBuildInsertValue(c.builder, opt, p, 1, "cookie.opt.ptr");
            opt = LLVMBuildInsertValue(c.builder, opt, l, 2, "cookie.opt.len");
            c.set_value(inst.result, opt);
            break;
        }
        case rir::Opcode::ReqQuery: {
            Str name = inst.imm.str_val;
            LLVMValueRef name_ptr = c.make_global_str(name, "query.name");
            LLVMValueRef name_len = LLVMConstInt(c.i32_ty, name.len, 0);
            LLVMValueRef out_has = LLVMBuildAlloca(c.builder, c.i8_ty, "query.has");
            LLVMValueRef out_ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "query.ptr");
            LLVMValueRef out_len = LLVMBuildAlloca(c.builder, c.i32_ty, "query.len");
            LLVMValueRef args[] = {
                c.param_req_data, c.param_req_len, name_ptr, name_len, out_has, out_ptr, out_len};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_req_query()),
                           c.get_req_query(),
                           args,
                           7,
                           "");
            LLVMValueRef h = LLVMBuildLoad2(c.builder, c.i8_ty, out_has, "query.h");
            LLVMValueRef p = LLVMBuildLoad2(c.builder, c.ptr_ty, out_ptr, "query.p");
            LLVMValueRef l = LLVMBuildLoad2(c.builder, c.i32_ty, out_len, "query.l");
            LLVMValueRef opt = LLVMGetUndef(c.opt_str_ty);
            opt = LLVMBuildInsertValue(c.builder, opt, h, 0, "query.opt.has");
            opt = LLVMBuildInsertValue(c.builder, opt, p, 1, "query.opt.ptr");
            opt = LLVMBuildInsertValue(c.builder, opt, l, 2, "query.opt.len");
            c.set_value(inst.result, opt);
            break;
        }
        case rir::Opcode::ReqQueryString: {
            LLVMValueRef out_has = LLVMBuildAlloca(c.builder, c.i8_ty, "query_string.has");
            LLVMValueRef out_ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "query_string.ptr");
            LLVMValueRef out_len = LLVMBuildAlloca(c.builder, c.i32_ty, "query_string.len");
            LLVMValueRef args[] = {c.param_req_data, c.param_req_len, out_has, out_ptr, out_len};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_req_query_string()),
                           c.get_req_query_string(),
                           args,
                           5,
                           "");
            LLVMValueRef h = LLVMBuildLoad2(c.builder, c.i8_ty, out_has, "query_string.h");
            LLVMValueRef p = LLVMBuildLoad2(c.builder, c.ptr_ty, out_ptr, "query_string.p");
            LLVMValueRef l = LLVMBuildLoad2(c.builder, c.i32_ty, out_len, "query_string.l");
            LLVMValueRef opt = LLVMGetUndef(c.opt_str_ty);
            opt = LLVMBuildInsertValue(c.builder, opt, h, 0, "query_string.opt.has");
            opt = LLVMBuildInsertValue(c.builder, opt, p, 1, "query_string.opt.ptr");
            opt = LLVMBuildInsertValue(c.builder, opt, l, 2, "query_string.opt.len");
            c.set_value(inst.result, opt);
            break;
        }
        case rir::Opcode::ReqTlsClientCertSha256: {
            LLVMTypeRef params[] = {c.ptr_ty, c.ptr_ty, c.ptr_ty, c.ptr_ty};
            LLVMTypeRef type = LLVMFunctionType(c.void_ty, params, 4, 0);
            LLVMValueRef fn =
                LLVMGetNamedFunction(c.llvm_mod, "rut_helper_req_tls_client_cert_sha256");
            if (fn == nullptr)
                fn = LLVMAddFunction(c.llvm_mod, "rut_helper_req_tls_client_cert_sha256", type);
            LLVMValueRef has = LLVMBuildAlloca(c.builder, c.i8_ty, "tls_fingerprint.has");
            LLVMValueRef ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "tls_fingerprint.ptr");
            LLVMValueRef len = LLVMBuildAlloca(c.builder, c.i32_ty, "tls_fingerprint.len");
            LLVMValueRef args[] = {c.param_conn, has, ptr, len};
            LLVMBuildCall2(c.builder, LLVMGlobalGetValueType(fn), fn, args, 4, "");
            LLVMValueRef opt = LLVMGetUndef(c.opt_str_ty);
            opt = LLVMBuildInsertValue(c.builder,
                                       opt,
                                       LLVMBuildLoad2(c.builder, c.i8_ty, has, "tls_fingerprint.h"),
                                       0,
                                       "tls_fingerprint.opt.has");
            opt =
                LLVMBuildInsertValue(c.builder,
                                     opt,
                                     LLVMBuildLoad2(c.builder, c.ptr_ty, ptr, "tls_fingerprint.p"),
                                     1,
                                     "tls_fingerprint.opt.ptr");
            opt =
                LLVMBuildInsertValue(c.builder,
                                     opt,
                                     LLVMBuildLoad2(c.builder, c.i32_ty, len, "tls_fingerprint.l"),
                                     2,
                                     "tls_fingerprint.opt.len");
            c.set_value(inst.result, opt);
            break;
        }
        case rir::Opcode::ReqRemoteAddr: {
            LLVMValueRef args[] = {c.param_conn};
            LLVMValueRef v = LLVMBuildCall2(c.builder,
                                            LLVMGlobalGetValueType(c.get_req_remote_addr()),
                                            c.get_req_remote_addr(),
                                            args,
                                            1,
                                            "addr");
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::ReqContentLength: {
            LLVMValueRef args[] = {c.param_req_data, c.param_req_len};
            LLVMValueRef v = LLVMBuildCall2(c.builder,
                                            LLVMGlobalGetValueType(c.get_req_content_length()),
                                            c.get_req_content_length(),
                                            args,
                                            2,
                                            "content_length");
            c.set_value(inst.result, v);
            break;
        }

        case rir::Opcode::HttpOriginListAllows:
        case rir::Opcode::HttpTokenListAllows: {
            LLVMValueRef allowed = c.get_value(inst.operand(0));
            LLVMValueRef requested = c.get_value(inst.operand(1));
            LLVMValueRef args[] = {
                LLVMBuildExtractValue(c.builder, allowed, 0, "tokens.ptr"),
                LLVMBuildExtractValue(c.builder, allowed, 1, "tokens.len"),
                LLVMBuildExtractValue(c.builder, requested, 0, "tokens.ptr"),
                LLVMBuildExtractValue(c.builder, requested, 1, "tokens.len"),
                LLVMBuildZExt(c.builder, c.get_value(inst.operand(2)), c.i8_ty, "tokens.case")};
            LLVMValueRef fn = inst.op == rir::Opcode::HttpOriginListAllows
                                  ? c.get_http_origin_list_allows()
                                  : c.get_http_token_list_allows();
            LLVMValueRef result =
                LLVMBuildCall2(c.builder, LLVMGlobalGetValueType(fn), fn, args, 5, "tokens");
            c.set_value(
                inst.result,
                LLVMBuildICmp(
                    c.builder, LLVMIntNE, result, LLVMConstInt(c.i8_ty, 0, 0), "tokens.bool"));
            break;
        }
        case rir::Opcode::HmacSha256Matches: {
            LLVMValueRef args[8];
            for (u32 i = 0; i < 4; ++i) {
                LLVMValueRef value = c.get_value(inst.operand(i));
                args[static_cast<size_t>(i) * 2] =
                    LLVMBuildExtractValue(c.builder, value, 0, "hmac.ptr");
                args[static_cast<size_t>(i) * 2 + 1] =
                    LLVMBuildExtractValue(c.builder, value, 1, "hmac.len");
            }
            LLVMValueRef fn = c.get_hmac_sha256_matches();
            LLVMValueRef result =
                LLVMBuildCall2(c.builder, LLVMGlobalGetValueType(fn), fn, args, 8, "hmac");
            c.set_value(
                inst.result,
                LLVMBuildICmp(
                    c.builder, LLVMIntNE, result, LLVMConstInt(c.i32_ty, 0, 0), "hmac.bool"));
            break;
        }
        case rir::Opcode::StandardWebhookValid: {
            LLVMValueRef args[10];
            for (u32 i = 0; i < 5; ++i) {
                LLVMValueRef value = c.get_value(inst.operand(i));
                args[static_cast<size_t>(i) * 2] =
                    LLVMBuildExtractValue(c.builder, value, 0, "hmac.ptr");
                args[static_cast<size_t>(i) * 2 + 1] =
                    LLVMBuildExtractValue(c.builder, value, 1, "hmac.len");
            }
            LLVMValueRef fn = c.get_standard_webhook_valid();
            LLVMValueRef result =
                LLVMBuildCall2(c.builder, LLVMGlobalGetValueType(fn), fn, args, 10, "hmac");
            c.set_value(
                inst.result,
                LLVMBuildICmp(
                    c.builder, LLVMIntNE, result, LLVMConstInt(c.i8_ty, 0, 0), "hmac.bool"));
            break;
        }
        case rir::Opcode::SignedRequestValid: {
            LLVMValueRef args[15];
            args[0] = c.get_value(inst.operand(0));
            for (u32 i = 1; i < 8; ++i) {
                LLVMValueRef value = c.get_value(inst.operand(i));
                args[1 + static_cast<size_t>(i - 1) * 2] =
                    LLVMBuildExtractValue(c.builder, value, 0, "signed_request.ptr");
                args[2 + static_cast<size_t>(i - 1) * 2] =
                    LLVMBuildExtractValue(c.builder, value, 1, "signed_request.len");
            }
            LLVMValueRef fn = c.get_signed_request_valid();
            LLVMValueRef result = LLVMBuildCall2(
                c.builder, LLVMGlobalGetValueType(fn), fn, args, 15, "signed_request");
            c.set_value(inst.result,
                        LLVMBuildICmp(c.builder,
                                      LLVMIntNE,
                                      result,
                                      LLVMConstInt(c.i8_ty, 0, 0),
                                      "signed_request.bool"));
            break;
        }
        case rir::Opcode::JwtClaimsValidWithLifetime: {
            LLVMValueRef args[8];
            for (u32 i = 0; i < 3; ++i) {
                LLVMValueRef value = c.get_value(inst.operand(i));
                const size_t kArgIndex = static_cast<size_t>(i) * 2;
                args[kArgIndex] = LLVMBuildExtractValue(c.builder, value, 0, "jwt.claims.ptr");
                args[kArgIndex + 1] = LLVMBuildExtractValue(c.builder, value, 1, "jwt.claims.len");
            }
            args[6] = c.get_value(inst.operand(3));
            args[7] = c.get_value(inst.operand(4));
            LLVMValueRef fn = c.get_jwt_claims_valid_with_lifetime();
            LLVMValueRef result =
                LLVMBuildCall2(c.builder, LLVMGlobalGetValueType(fn), fn, args, 8, "jwt.age");
            c.set_value(
                inst.result,
                LLVMBuildICmp(
                    c.builder, LLVMIntNE, result, LLVMConstInt(c.i8_ty, 0, 0), "jwt.age.bool"));
            break;
        }
        // ── String operations ──
        case rir::Opcode::StrLength:
            c.set_value(
                inst.result,
                LLVMBuildExtractValue(c.builder, c.get_value(inst.operand(0)), 1, "bytes.count"));
            break;
        case rir::Opcode::BearerMatches:
        case rir::Opcode::BasicMatches:
        case rir::Opcode::StrConstantTimeEqual: {
            LLVMValueRef s = c.get_value(inst.operands[0]);
            LLVMValueRef rhs = c.get_value(inst.operands[1]);
            LLVMValueRef s_ptr = LLVMBuildExtractValue(c.builder, s, 0, "s.ptr");
            LLVMValueRef s_len = LLVMBuildExtractValue(c.builder, s, 1, "s.len");
            LLVMValueRef p_ptr = LLVMBuildExtractValue(c.builder, rhs, 0, "p.ptr");
            LLVMValueRef p_len = LLVMBuildExtractValue(c.builder, rhs, 1, "p.len");
            LLVMValueRef args[] = {s_ptr, s_len, p_ptr, p_len};
            LLVMValueRef fn = inst.op == rir::Opcode::BearerMatches ? c.get_bearer_matches()
                              : inst.op == rir::Opcode::BasicMatches
                                  ? c.get_basic_matches()
                                  : c.get_str_constant_time_equal();
            LLVMValueRef r =
                LLVMBuildCall2(c.builder, LLVMGlobalGetValueType(fn), fn, args, 4, "cte");
            const auto return_type =
                inst.op == rir::Opcode::StrConstantTimeEqual ? c.i32_ty : c.i8_ty;
            LLVMValueRef b =
                LLVMBuildICmp(c.builder, LLVMIntNE, r, LLVMConstInt(return_type, 0, 0), "cte.bool");
            c.set_value(inst.result, b);
            break;
        }
        case rir::Opcode::StrPredicate:
        case rir::Opcode::StrHasPrefix: {
            LLVMValueRef s = c.get_value(inst.operands[0]);
            LLVMValueRef pfx = c.get_value(inst.operands[1]);
            LLVMValueRef s_ptr = LLVMBuildExtractValue(c.builder, s, 0, "s.ptr");
            LLVMValueRef s_len = LLVMBuildExtractValue(c.builder, s, 1, "s.len");
            LLVMValueRef p_ptr = LLVMBuildExtractValue(c.builder, pfx, 0, "p.ptr");
            LLVMValueRef p_len = LLVMBuildExtractValue(c.builder, pfx, 1, "p.len");
            LLVMValueRef args[] = {s_ptr, s_len, p_ptr, p_len};
            if (inst.op == rir::Opcode::StrPredicate && inst.imm.i32_val == 3) {
                c.set_value(
                    inst.result,
                    LLVMBuildICmp(
                        c.builder, LLVMIntEQ, s_len, LLVMConstInt(c.i32_ty, 0, 0), "str.empty"));
                break;
            }
            LLVMValueRef helper = c.get_str_has_prefix();
            if (inst.op == rir::Opcode::StrPredicate && inst.imm.i32_val != 0) {
                const char* name =
                    inst.imm.i32_val == 1 ? "rut_helper_str_has_suffix" : "rut_helper_str_contains";
                helper = LLVMGetNamedFunction(c.llvm_mod, name);
                if (!helper) {
                    LLVMTypeRef params[] = {c.ptr_ty, c.i32_ty, c.ptr_ty, c.i32_ty};
                    helper =
                        LLVMAddFunction(c.llvm_mod, name, LLVMFunctionType(c.i8_ty, params, 4, 0));
                }
            }
            LLVMValueRef r =
                LLVMBuildCall2(c.builder, LLVMGlobalGetValueType(helper), helper, args, 4, "hp");
            // Convert u8 result to i1 for branch usage
            LLVMValueRef b =
                LLVMBuildICmp(c.builder, LLVMIntNE, r, LLVMConstInt(c.i8_ty, 0, 0), "hp.bool");
            c.set_value(inst.result, b);
            break;
        }
        case rir::Opcode::StrInterpolate: {
            LLVMTypeRef array_ty = LLVMArrayType2(c.str_ty, inst.operand_count);
            LLVMValueRef parts = LLVMBuildAlloca(c.builder, array_ty, "concat.parts");
            for (u32 i = 0; i < inst.operand_count; ++i) {
                LLVMValueRef indices[] = {LLVMConstInt(c.i32_ty, 0, 0),
                                          LLVMConstInt(c.i32_ty, i, 0)};
                LLVMValueRef slot =
                    LLVMBuildGEP2(c.builder, array_ty, parts, indices, 2, "concat.part");
                LLVMBuildStore(c.builder, c.get_value(inst.operand(i)), slot);
            }
            LLVMTypeRef params[] = {c.ptr_ty, c.ptr_ty, c.ptr_ty, c.i32_ty, c.ptr_ty, c.ptr_ty};
            LLVMTypeRef type = LLVMFunctionType(c.i8_ty, params, 6, 0);
            LLVMValueRef helper = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_str_concat");
            if (!helper) helper = LLVMAddFunction(c.llvm_mod, "rut_helper_str_concat", type);
            LLVMValueRef ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "concat.ptr");
            LLVMValueRef len = LLVMBuildAlloca(c.builder, c.i32_ty, "concat.len");
            LLVMValueRef args[] = {c.param_conn,
                                   c.param_arena,
                                   parts,
                                   LLVMConstInt(c.i32_ty, inst.operand_count, 0),
                                   ptr,
                                   len};
            LLVMValueRef result = LLVMBuildCall2(c.builder, type, helper, args, 6, "concat.ok");
            LLVMValueRef function = LLVMGetBasicBlockParent(LLVMGetInsertBlock(c.builder));
            auto* success = LLVMAppendBasicBlockInContext(c.llvm_ctx, function, "concat.success");
            auto* failure = LLVMAppendBasicBlockInContext(c.llvm_ctx, function, "concat.failure");
            LLVMValueRef valid = LLVMBuildICmp(
                c.builder, LLVMIntNE, result, LLVMConstInt(c.i8_ty, 0, 0), "concat.valid");
            LLVMBuildCondBr(c.builder, valid, success, failure);
            LLVMPositionBuilderAtEnd(c.builder, failure);
            c.emit_parse_unprime();
            const u64 kFailed =
                static_cast<u64>(HandlerAction::ReturnStatus) |
                (static_cast<u64>(c.ws_body_mode ? static_cast<u32>(WsFrameAction::Close) : 500u)
                 << 8);
            LLVMBuildRet(c.builder, LLVMConstInt(c.i64_ty, kFailed, 0));
            LLVMPositionBuilderAtEnd(c.builder, success);
            LLVMValueRef text = LLVMGetUndef(c.str_ty);
            text = LLVMBuildInsertValue(c.builder,
                                        text,
                                        LLVMBuildLoad2(c.builder, c.ptr_ty, ptr, "concat.data"),
                                        0,
                                        "concat.text.ptr");
            text = LLVMBuildInsertValue(c.builder,
                                        text,
                                        LLVMBuildLoad2(c.builder, c.i32_ty, len, "concat.size"),
                                        1,
                                        "concat.text.len");
            c.set_value(inst.result, text);
            break;
        }
        case rir::Opcode::StrRegexMatch: {
            LLVMValueRef s = c.get_value(inst.operands[0]);
            LLVMValueRef s_ptr = LLVMBuildExtractValue(c.builder, s, 0, "s.ptr");
            LLVMValueRef s_len = LLVMBuildExtractValue(c.builder, s, 1, "s.len");
            LLVMValueRef db = c.make_regex_db_load(inst.imm.str_val);
            LLVMValueRef args[] = {s_ptr, s_len, db};
            LLVMValueRef fn = c.get_str_regex_match();
            LLVMValueRef r =
                LLVMBuildCall2(c.builder, LLVMGlobalGetValueType(fn), fn, args, 3, "rx");
            if (c.ws_body_mode) {
                LLVMValueRef function = LLVMGetBasicBlockParent(LLVMGetInsertBlock(c.builder));
                auto* scanned = LLVMAppendBasicBlockInContext(c.llvm_ctx, function, "rx.ok");
                auto* failed = LLVMAppendBasicBlockInContext(c.llvm_ctx, function, "rx.error");
                LLVMValueRef valid = LLVMBuildICmp(
                    c.builder, LLVMIntULE, r, LLVMConstInt(c.i8_ty, 1, 0), "rx.valid");
                LLVMBuildCondBr(c.builder, valid, scanned, failed);
                LLVMPositionBuilderAtEnd(c.builder, failed);
                // The private message body uses the ordinary packed return ABI.
                // Close before a negation or continuation can consume the result.
                const u64 kClosed = static_cast<u64>(HandlerAction::ReturnStatus) |
                                    (static_cast<u64>(WsFrameAction::Close) << 8);
                LLVMBuildRet(c.builder, LLVMConstInt(c.i64_ty, kClosed, 0));
                LLVMPositionBuilderAtEnd(c.builder, scanned);
            }
            LLVMValueRef b =
                LLVMBuildICmp(c.builder, LLVMIntEQ, r, LLVMConstInt(c.i8_ty, 1, 0), "rx.bool");
            c.set_value(inst.result, b);
            break;
        }
        case rir::Opcode::StrTrimPrefix: {
            LLVMValueRef s = c.get_value(inst.operands[0]);
            LLVMValueRef pfx = c.get_value(inst.operands[1]);
            LLVMValueRef s_ptr = LLVMBuildExtractValue(c.builder, s, 0, "s.ptr");
            LLVMValueRef s_len = LLVMBuildExtractValue(c.builder, s, 1, "s.len");
            LLVMValueRef p_ptr = LLVMBuildExtractValue(c.builder, pfx, 0, "p.ptr");
            LLVMValueRef p_len = LLVMBuildExtractValue(c.builder, pfx, 1, "p.len");
            LLVMValueRef out_ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "tp.ptr");
            LLVMValueRef out_len = LLVMBuildAlloca(c.builder, c.i32_ty, "tp.len");
            LLVMValueRef args[] = {s_ptr, s_len, p_ptr, p_len, out_ptr, out_len};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_str_trim_prefix()),
                           c.get_str_trim_prefix(),
                           args,
                           6,
                           "");
            LLVMValueRef rp = LLVMBuildLoad2(c.builder, c.ptr_ty, out_ptr, "tp.rp");
            LLVMValueRef rl = LLVMBuildLoad2(c.builder, c.i32_ty, out_len, "tp.rl");
            LLVMValueRef strval = LLVMGetUndef(c.str_ty);
            strval = LLVMBuildInsertValue(c.builder, strval, rp, 0, "tp.s.ptr");
            strval = LLVMBuildInsertValue(c.builder, strval, rl, 1, "tp.s.len");
            c.set_value(inst.result, strval);
            break;
        }

        // ── Bitwise ──
        case rir::Opcode::BitAnd:
        case rir::Opcode::BitOr:
        case rir::Opcode::BitXor: {
            LLVMValueRef a = c.get_value(inst.operands[0]);
            LLVMValueRef b = c.get_value(inst.operands[1]);
            LLVMValueRef r =
                inst.op == rir::Opcode::BitAnd
                    ? LLVMBuildAnd(c.builder, a, b, "bit.and")
                    : (inst.op == rir::Opcode::BitOr ? LLVMBuildOr(c.builder, a, b, "bit.or")
                                                     : LLVMBuildXor(c.builder, a, b, "bit.xor"));
            c.set_value(inst.result, r);
            break;
        }
        case rir::Opcode::BitShl:
        case rir::Opcode::BitShr: {
            // Shift amounts outside 0..width-1 saturate (0 for shl, sign
            // fill for arithmetic shr) instead of leaving LLVM poison /
            // hardware masking semantics. Width follows the operand type
            // (i32 or i64).
            LLVMValueRef a = c.get_value(inst.operands[0]);
            LLVMValueRef n = c.get_value(inst.operands[1]);
            const rir::Type* lhs_ty = c.cur_fn && inst.operands[0].id < c.cur_fn->value_cap
                                          ? c.cur_fn->values[inst.operands[0].id].type
                                          : nullptr;
            const bool is64 = lhs_ty && lhs_ty->kind == rir::TypeKind::I64;
            LLVMTypeRef w = is64 ? c.i64_ty : c.i32_ty;
            const u64 width = is64 ? 64 : 32;
            LLVMValueRef in_range = LLVMBuildICmp(
                c.builder, LLVMIntULT, n, LLVMConstInt(w, width, 0), "bit.shift.inrange");
            LLVMValueRef safe_n = LLVMBuildSelect(
                c.builder, in_range, n, LLVMConstInt(w, width - 1, 0), "bit.shift.n");
            if (inst.op == rir::Opcode::BitShl) {
                LLVMValueRef shifted = LLVMBuildShl(c.builder, a, safe_n, "bit.shl.raw");
                LLVMValueRef r =
                    LLVMBuildSelect(c.builder, in_range, shifted, LLVMConstInt(w, 0, 0), "bit.shl");
                c.set_value(inst.result, r);
            } else {
                LLVMValueRef shifted = LLVMBuildAShr(c.builder, a, safe_n, "bit.shr.raw");
                LLVMValueRef sign_fill =
                    LLVMBuildAShr(c.builder, a, LLVMConstInt(w, width - 1, 0), "bit.shr.sign");
                LLVMValueRef r =
                    LLVMBuildSelect(c.builder, in_range, shifted, sign_fill, "bit.shr");
                c.set_value(inst.result, r);
            }
            break;
        }

        // ── Arithmetic ──
        // Semantics must match the analyze-time literal fold in
        // analyze_arith_expr (analyze.cc): overflow wraps two's-complement,
        // x / 0 and x % 0 are 0, INT_MIN / -1 is INT_MIN, INT_MIN % -1 is 0.
        case rir::Opcode::Add:
        case rir::Opcode::Sub:
        case rir::Opcode::Mul: {
            LLVMValueRef a = c.get_value(inst.operands[0]);
            LLVMValueRef b = c.get_value(inst.operands[1]);
            // Plain wrap forms — deliberately NOT the NSW variants.
            LLVMValueRef r =
                inst.op == rir::Opcode::Add
                    ? LLVMBuildAdd(c.builder, a, b, "arith.add")
                    : (inst.op == rir::Opcode::Sub ? LLVMBuildSub(c.builder, a, b, "arith.sub")
                                                   : LLVMBuildMul(c.builder, a, b, "arith.mul"));
            c.set_value(inst.result, r);
            break;
        }
        case rir::Opcode::Div:
        case rir::Opcode::Mod: {
            // sdiv/srem are poison for b == 0 and INT_MIN / -1; feed them a
            // safe divisor and select the defined results instead. Guard
            // constants follow the operand width (i32 or i64).
            LLVMValueRef a = c.get_value(inst.operands[0]);
            LLVMValueRef b = c.get_value(inst.operands[1]);
            const rir::Type* lhs_ty = c.cur_fn && inst.operands[0].id < c.cur_fn->value_cap
                                          ? c.cur_fn->values[inst.operands[0].id].type
                                          : nullptr;
            const bool is64 = lhs_ty && lhs_ty->kind == rir::TypeKind::I64;
            LLVMTypeRef w = is64 ? c.i64_ty : c.i32_ty;
            LLVMValueRef zero = LLVMConstInt(w, 0, 0);
            LLVMValueRef int_min =
                LLVMConstInt(w, is64 ? 0x8000000000000000ull : static_cast<u64>(0x80000000u), 0);
            LLVMValueRef neg_one = LLVMConstAllOnes(w);
            LLVMValueRef is_zero = LLVMBuildICmp(c.builder, LLVMIntEQ, b, zero, "arith.div.zero");
            LLVMValueRef is_min = LLVMBuildICmp(c.builder, LLVMIntEQ, a, int_min, "arith.div.min");
            LLVMValueRef is_neg1 =
                LLVMBuildICmp(c.builder, LLVMIntEQ, b, neg_one, "arith.div.negone");
            LLVMValueRef ovf = LLVMBuildAnd(c.builder, is_min, is_neg1, "arith.div.ovf");
            LLVMValueRef bad = LLVMBuildOr(c.builder, is_zero, ovf, "arith.div.bad");
            LLVMValueRef safe_b =
                LLVMBuildSelect(c.builder, bad, LLVMConstInt(w, 1, 0), b, "arith.div.safeb");
            if (inst.op == rir::Opcode::Div) {
                LLVMValueRef raw = LLVMBuildSDiv(c.builder, a, safe_b, "arith.div.raw");
                LLVMValueRef ovf_val =
                    LLVMBuildSelect(c.builder, ovf, int_min, raw, "arith.div.ovfval");
                LLVMValueRef r = LLVMBuildSelect(c.builder, is_zero, zero, ovf_val, "arith.div");
                c.set_value(inst.result, r);
            } else {
                LLVMValueRef raw = LLVMBuildSRem(c.builder, a, safe_b, "arith.mod.raw");
                // Both guarded cases (b == 0 and INT_MIN % -1) yield 0.
                LLVMValueRef r = LLVMBuildSelect(c.builder, bad, zero, raw, "arith.mod");
                c.set_value(inst.result, r);
            }
            break;
        }

        case rir::Opcode::RespBody: {
            LLVMTypeRef params[] = {c.ptr_ty, c.ptr_ty, c.i32_ty, c.ptr_ty, c.i32_ty};
            LLVMTypeRef ft = LLVMFunctionType(c.void_ty, params, 5, 0);
            LLVMValueRef fn = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_resp_body");
            if (!fn) fn = LLVMAddFunction(c.llvm_mod, "rut_helper_resp_body", ft);
            const auto value = c.get_value(inst.operands[0]);
            LLVMValueRef args[] = {c.param_conn,
                                   LLVMBuildExtractValue(c.builder, value, 0, "body.ptr"),
                                   LLVMBuildExtractValue(c.builder, value, 1, "body.len"),
                                   c.param_req_data,
                                   c.param_req_len};
            LLVMBuildCall2(c.builder, ft, fn, args, 5, "");
            break;
        }
        case rir::Opcode::ArrayNew: {
            const auto* element = c.cur_fn->values[inst.result.id].type->inner->inner;
            const auto element_type = c.map_type(element);
            LLVMValueRef offsets[16]{};
            LLVMValueRef path[10]{};
            path[0] = LLVMConstInt(c.i32_ty, 0, 0);
            u32 strings = 0;
            const auto describe = [&](auto&& self, const rir::Type* type, u32 depth) -> bool {
                if (depth >= 10) return false;
                if (type->kind == rir::TypeKind::Str) {
                    if (strings == 16) return false;
                    const auto address =
                        LLVMConstGEP2(element_type, LLVMConstNull(c.ptr_ty), path, depth);
                    offsets[strings++] = LLVMConstPtrToInt(address, c.i32_ty);
                } else if (type->kind == rir::TypeKind::Struct) {
                    for (u32 i = 0; i < type->struct_def->field_count; ++i) {
                        path[depth] = LLVMConstInt(c.i32_ty, i, 0);
                        if (!self(self, type->struct_def->fields()[i].type, depth + 1))
                            return false;
                    }
                }
                return true;
            };
            LLVMValueRef offset_pointer = LLVMConstNull(c.ptr_ty);
            // Shapes with excessive text leaves fail allocation without
            // constructing a malformed descriptor or partially visible array.
            const bool described = describe(describe, element, 1);
            if (described && strings) {
                const auto type = LLVMArrayType(c.i32_ty, strings);
                offset_pointer = LLVMAddGlobal(c.llvm_mod, type, "collect.string.offsets");
                LLVMSetInitializer(offset_pointer, LLVMConstArray(c.i32_ty, offsets, strings));
                LLVMSetGlobalConstant(offset_pointer, 1);
                LLVMSetLinkage(offset_pointer, LLVMPrivateLinkage);
            }
            LLVMTypeRef parameters[] = {c.ptr_ty, c.ptr_ty, c.i32_ty, c.i32_ty, c.ptr_ty, c.i32_ty};
            const auto type = LLVMFunctionType(c.ptr_ty, parameters, 6, 0);
            auto helper = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_collect_new");
            if (!helper) helper = LLVMAddFunction(c.llvm_mod, "rut_helper_collect_new", type);
            LLVMValueRef arguments[] = {
                c.param_conn,
                c.param_arena,
                LLVMBuildIntCast2(c.builder, LLVMSizeOf(element_type), c.i32_ty, 0, ""),
                LLVMConstInt(c.i32_ty, inst.imm.i32_val, 0),
                offset_pointer,
                LLVMConstInt(c.i32_ty, described ? strings : 17, 0)};
            const auto pointer =
                LLVMBuildCall2(c.builder, type, helper, arguments, 6, "collect.new");
            const auto has = LLVMBuildICmp(
                c.builder, LLVMIntNE, pointer, LLVMConstNull(c.ptr_ty), "collect.allocated");
            auto result = LLVMGetUndef(c.map_type(c.cur_fn->values[inst.result.id].type));
            result = LLVMBuildInsertValue(
                c.builder, result, LLVMBuildZExt(c.builder, has, c.i8_ty, ""), 0, "");
            result = LLVMBuildInsertValue(c.builder, result, pointer, 1, "");
            c.set_value(inst.result, result);
            break;
        }
        case rir::Opcode::ArrayPush: {
            const auto* element = c.cur_fn->values[inst.operands[0].id].type->inner;
            const auto element_type = c.map_type(element);
            const auto temporary = LLVMBuildAlloca(c.builder, element_type, "collect.item");
            LLVMBuildStore(c.builder, c.get_value(inst.operands[1]), temporary);
            LLVMTypeRef parameters[] = {c.ptr_ty, c.ptr_ty, c.i32_ty};
            const auto type = LLVMFunctionType(c.i8_ty, parameters, 3, 0);
            auto helper = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_collect_push");
            if (!helper) helper = LLVMAddFunction(c.llvm_mod, "rut_helper_collect_push", type);
            LLVMValueRef arguments[] = {
                c.get_value(inst.operands[0]),
                temporary,
                LLVMBuildIntCast2(c.builder, LLVMSizeOf(element_type), c.i32_ty, 0, "")};
            const auto committed =
                LLVMBuildCall2(c.builder, type, helper, arguments, 3, "collect.push");
            c.set_value(inst.result,
                        LLVMBuildICmp(c.builder,
                                      LLVMIntNE,
                                      committed,
                                      LLVMConstInt(c.i8_ty, 0, 0),
                                      "collect.committed"));
            break;
        }
        case rir::Opcode::ArrayLen: {
            LLVMTypeRef parameters[] = {c.ptr_ty};
            const auto type = LLVMFunctionType(c.i32_ty, parameters, 1, 0);
            auto helper = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_collect_count");
            if (!helper) helper = LLVMAddFunction(c.llvm_mod, "rut_helper_collect_count", type);
            LLVMValueRef arguments[] = {c.get_value(inst.operands[0])};
            c.set_value(inst.result,
                        LLVMBuildCall2(c.builder, type, helper, arguments, 1, "collect.count"));
            break;
        }
        case rir::Opcode::ArrayGet: {
            const auto* result_type = c.cur_fn->values[inst.result.id].type;
            const auto element_type = c.map_type(result_type->inner);
            LLVMTypeRef parameters[] = {c.ptr_ty, c.i32_ty, c.i32_ty};
            const auto type = LLVMFunctionType(c.ptr_ty, parameters, 3, 0);
            auto helper = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_collect_get");
            if (!helper) helper = LLVMAddFunction(c.llvm_mod, "rut_helper_collect_get", type);
            LLVMValueRef arguments[] = {
                c.get_value(inst.operands[0]),
                c.get_value(inst.operands[1]),
                LLVMBuildIntCast2(c.builder, LLVMSizeOf(element_type), c.i32_ty, 0, "")};
            const auto pointer =
                LLVMBuildCall2(c.builder, type, helper, arguments, 3, "collect.get");
            const auto has = LLVMBuildICmp(
                c.builder, LLVMIntNE, pointer, LLVMConstNull(c.ptr_ty), "collect.present");
            const auto origin = LLVMGetInsertBlock(c.builder);
            const auto function = LLVMGetBasicBlockParent(origin);
            const auto load = LLVMAppendBasicBlockInContext(c.llvm_ctx, function, "collect.load");
            const auto merge =
                LLVMAppendBasicBlockInContext(c.llvm_ctx, function, "collect.get.merge");
            LLVMBuildCondBr(c.builder, has, load, merge);
            LLVMPositionBuilderAtEnd(c.builder, load);
            const auto loaded = LLVMBuildLoad2(c.builder, element_type, pointer, "collect.value");
            LLVMBuildBr(c.builder, merge);
            LLVMPositionBuilderAtEnd(c.builder, merge);
            const auto payload = LLVMBuildPhi(c.builder, element_type, "collect.result");
            LLVMValueRef values[] = {LLVMConstNull(element_type), loaded};
            LLVMBasicBlockRef blocks[] = {origin, load};
            LLVMAddIncoming(payload, values, blocks, 2);
            auto result = LLVMGetUndef(c.map_type(result_type));
            result = LLVMBuildInsertValue(
                c.builder, result, LLVMBuildZExt(c.builder, has, c.i8_ty, ""), 0, "");
            if (result_type->inner->kind == rir::TypeKind::Str) {
                result = LLVMBuildInsertValue(
                    c.builder, result, LLVMBuildExtractValue(c.builder, payload, 0, ""), 1, "");
                result = LLVMBuildInsertValue(
                    c.builder, result, LLVMBuildExtractValue(c.builder, payload, 1, ""), 2, "");
            } else {
                result = LLVMBuildInsertValue(c.builder, result, payload, 1, "");
            }
            c.set_value(inst.result, result);
            break;
        }
        case rir::Opcode::JsonOp: {
            const auto kJsonOp = static_cast<json::Op>(inst.imm.i32_val);
            if (kJsonOp == json::Op::BytesFromString) {
                c.set_value(inst.result, c.get_value(inst.operands[0]));
                break;
            }
            if (kJsonOp == json::Op::FormatInt) {
                auto value = c.get_value(inst.operands[0]);
                if (c.cur_fn->values[inst.operands[0].id].type->kind == rir::TypeKind::I32)
                    value = LLVMBuildSExt(c.builder, value, c.i64_ty, "format.i64");
                LLVMTypeRef params[] = {c.ptr_ty, c.ptr_ty, c.i64_ty, c.ptr_ty, c.ptr_ty};
                const auto kType = LLVMFunctionType(c.i8_ty, params, 5, 0);
                auto helper = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_format_int");
                if (!helper) helper = LLVMAddFunction(c.llvm_mod, "rut_helper_format_int", kType);
                const auto kPointer = LLVMBuildAlloca(c.builder, c.ptr_ty, "format.ptr");
                const auto kLength = LLVMBuildAlloca(c.builder, c.i32_ty, "format.len");
                LLVMValueRef args[] = {c.param_conn, c.param_arena, value, kPointer, kLength};
                const auto kHas = LLVMBuildCall2(c.builder, kType, helper, args, 5, "format.has");
                const auto* result_type = c.cur_fn->values[inst.result.id].type;
                auto result = LLVMGetUndef(c.map_type(result_type));
                result = LLVMBuildInsertValue(c.builder, result, kHas, 0, "");
                result = LLVMBuildInsertValue(
                    c.builder,
                    result,
                    LLVMBuildLoad2(c.builder, c.ptr_ty, kPointer, "format.data"),
                    1,
                    "");
                result = LLVMBuildInsertValue(
                    c.builder,
                    result,
                    LLVMBuildLoad2(c.builder, c.i32_ty, kLength, "format.size"),
                    2,
                    "");
                c.set_value(inst.result, result);
                break;
            }
            if (kJsonOp == json::Op::BytesConcat) {
                const auto left = c.get_value(inst.operands[0]);
                const auto right = c.get_value(inst.operands[1]);
                const auto left_len = LLVMBuildExtractValue(c.builder, left, 1, "concat.left.len");
                const auto right_len =
                    LLVMBuildExtractValue(c.builder, right, 1, "concat.right.len");
                LLVMTypeRef parameters[] = {
                    c.ptr_ty, c.ptr_ty, c.ptr_ty, c.i32_ty, c.ptr_ty, c.i32_ty, c.i32_ty};
                const auto type = LLVMFunctionType(c.ptr_ty, parameters, 7, 0);
                auto helper = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_bytes_concat");
                if (!helper) helper = LLVMAddFunction(c.llvm_mod, "rut_helper_bytes_concat", type);
                LLVMValueRef arguments[] = {c.param_conn,
                                            c.param_arena,
                                            LLVMBuildExtractValue(c.builder, left, 0, ""),
                                            left_len,
                                            LLVMBuildExtractValue(c.builder, right, 0, ""),
                                            right_len,
                                            c.get_value(inst.operands[2])};
                const auto pointer =
                    LLVMBuildCall2(c.builder, type, helper, arguments, 7, "concat.bytes");
                const auto has = LLVMBuildICmp(
                    c.builder, LLVMIntNE, pointer, LLVMConstNull(c.ptr_ty), "concat.has");
                auto result = LLVMGetUndef(c.map_type(c.cur_fn->values[inst.result.id].type));
                result = LLVMBuildInsertValue(
                    c.builder, result, LLVMBuildZExt(c.builder, has, c.i8_ty, ""), 0, "");
                result = LLVMBuildInsertValue(c.builder, result, pointer, 1, "");
                const auto length =
                    LLVMBuildSelect(c.builder,
                                    has,
                                    LLVMBuildAdd(c.builder, left_len, right_len, ""),
                                    LLVMConstInt(c.i32_ty, 0, 0),
                                    "concat.length");
                result = LLVMBuildInsertValue(c.builder, result, length, 2, "");
                c.set_value(inst.result, result);
                break;
            }
            if (kJsonOp == json::Op::BytesSlice) {
                const auto kBytes = c.get_value(inst.operands[0]);
                const auto kStart = c.get_value(inst.operands[1]);
                const auto kEnd = c.get_value(inst.operands[2]);
                const auto kPointer = LLVMBuildExtractValue(c.builder, kBytes, 0, "slice.ptr");
                const auto kLength = LLVMBuildExtractValue(c.builder, kBytes, 1, "slice.len");
                const auto kZero = LLVMConstInt(c.i32_ty, 0, 0);
                auto valid =
                    LLVMBuildICmp(c.builder, LLVMIntSGE, kStart, kZero, "slice.start.valid");
                valid = LLVMBuildAnd(
                    c.builder,
                    valid,
                    LLVMBuildICmp(c.builder, LLVMIntSGE, kEnd, kStart, "slice.ordered"),
                    "slice.range.valid");
                valid = LLVMBuildAnd(
                    c.builder,
                    valid,
                    LLVMBuildICmp(c.builder, LLVMIntULE, kEnd, kLength, "slice.end.valid"),
                    "slice.bounds");
                const auto kEmpty =
                    LLVMBuildICmp(c.builder, LLVMIntEQ, kLength, kZero, "slice.empty");
                const auto kNonnull = LLVMBuildICmp(
                    c.builder, LLVMIntNE, kPointer, LLVMConstNull(c.ptr_ty), "slice.nonnull");
                valid = LLVMBuildAnd(c.builder,
                                     valid,
                                     LLVMBuildOr(c.builder, kEmpty, kNonnull, "slice.storage"),
                                     "slice.valid");
                // Only form an offset address after checking the complete range.
                const auto kOrigin = LLVMGetInsertBlock(c.builder);
                const auto kFunction = LLVMGetBasicBlockParent(kOrigin);
                const auto kView =
                    LLVMAppendBasicBlockInContext(c.llvm_ctx, kFunction, "slice.view");
                const auto kMerge =
                    LLVMAppendBasicBlockInContext(c.llvm_ctx, kFunction, "slice.merge");
                LLVMBuildCondBr(c.builder, valid, kView, kMerge);
                LLVMPositionBuilderAtEnd(c.builder, kView);
                const auto kBase =
                    LLVMBuildSelect(c.builder,
                                    kNonnull,
                                    kPointer,
                                    c.make_global_str(lit_str(""), "slice.empty.data"),
                                    "slice.base");
                auto offset = kStart;
                const auto kAddress =
                    LLVMBuildGEP2(c.builder, c.i8_ty, kBase, &offset, 1, "slice.address");
                const auto kCount = LLVMBuildSub(c.builder, kEnd, kStart, "slice.count");
                LLVMBuildBr(c.builder, kMerge);
                LLVMPositionBuilderAtEnd(c.builder, kMerge);
                const auto kOutPtr = LLVMBuildPhi(c.builder, c.ptr_ty, "slice.result.ptr");
                const auto kOutLen = LLVMBuildPhi(c.builder, c.i32_ty, "slice.result.len");
                LLVMValueRef pointers[] = {LLVMConstNull(c.ptr_ty), kAddress};
                LLVMValueRef lengths[] = {kZero, kCount};
                LLVMBasicBlockRef blocks[] = {kOrigin, kView};
                LLVMAddIncoming(kOutPtr, pointers, blocks, 2);
                LLVMAddIncoming(kOutLen, lengths, blocks, 2);
                const auto* result_type = c.cur_fn->values[inst.result.id].type;
                auto result = LLVMGetUndef(c.map_type(result_type));
                result = LLVMBuildInsertValue(c.builder,
                                              result,
                                              LLVMBuildZExt(c.builder, valid, c.i8_ty, "slice.has"),
                                              0,
                                              "");
                result = LLVMBuildInsertValue(c.builder, result, kOutPtr, 1, "");
                result = LLVMBuildInsertValue(c.builder, result, kOutLen, 2, "");
                c.set_value(inst.result, result);
                break;
            }
            if (kJsonOp == json::Op::BytesFind) {
                const auto kBytes = c.get_value(inst.operands[0]);
                const auto kDelimiter = c.get_value(inst.operands[1]);
                LLVMTypeRef params[] = {c.ptr_ty, c.i32_ty, c.ptr_ty, c.i32_ty, c.i32_ty};
                const auto kType = LLVMFunctionType(c.i32_ty, params, 5, 0);
                auto helper = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_bytes_find");
                if (!helper) helper = LLVMAddFunction(c.llvm_mod, "rut_helper_bytes_find", kType);
                LLVMValueRef args[] = {
                    LLVMBuildExtractValue(c.builder, kBytes, 0, "find.ptr"),
                    LLVMBuildExtractValue(c.builder, kBytes, 1, "find.len"),
                    LLVMBuildExtractValue(c.builder, kDelimiter, 0, "find.delimiter"),
                    LLVMBuildExtractValue(c.builder, kDelimiter, 1, "find.width"),
                    c.get_value(inst.operands[2])};
                const auto kOffset =
                    LLVMBuildCall2(c.builder, kType, helper, args, 5, "find.offset");
                const auto kHas = LLVMBuildICmp(
                    c.builder, LLVMIntSGE, kOffset, LLVMConstInt(c.i32_ty, 0, 0), "find.present");
                const auto* result_type = c.cur_fn->values[inst.result.id].type;
                auto result = LLVMGetUndef(c.map_type(result_type));
                result = LLVMBuildInsertValue(
                    c.builder, result, LLVMBuildZExt(c.builder, kHas, c.i8_ty, "find.has"), 0, "");
                result = LLVMBuildInsertValue(c.builder, result, kOffset, 1, "");
                c.set_value(inst.result, result);
                break;
            }
            if (kJsonOp == json::Op::ParseInt || kJsonOp == json::Op::ParseInt64) {
                const bool wide = kJsonOp == json::Op::ParseInt64;
                const auto text = c.get_value(inst.operands[0]);
                LLVMTypeRef params[] = {c.ptr_ty, c.i32_ty, c.i32_ty, c.ptr_ty};
                const auto type = LLVMFunctionType(c.i8_ty, params, 4, 0);
                auto helper = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_parse_int");
                if (!helper) helper = LLVMAddFunction(c.llvm_mod, "rut_helper_parse_int", type);
                const auto output = LLVMBuildAlloca(c.builder, c.i64_ty, "integer.output");
                LLVMValueRef args[] = {LLVMBuildExtractValue(c.builder, text, 0, "integer.ptr"),
                                       LLVMBuildExtractValue(c.builder, text, 1, "integer.len"),
                                       LLVMConstInt(c.i32_ty, wide ? 64 : 32, 0),
                                       output};
                const auto has = LLVMBuildCall2(c.builder, type, helper, args, 4, "integer.has");
                auto payload = LLVMBuildLoad2(c.builder, c.i64_ty, output, "integer.value");
                if (!wide) payload = LLVMBuildTrunc(c.builder, payload, c.i32_ty, "integer.i32");
                const auto* result_type = c.cur_fn->values[inst.result.id].type;
                auto result = LLVMGetUndef(c.map_type(result_type));
                result = LLVMBuildInsertValue(c.builder, result, has, 0, "");
                result = LLVMBuildInsertValue(c.builder, result, payload, 1, "");
                c.set_value(inst.result, result);
                break;
            }
            const auto bytes_read = json::bytes_read_spec(kJsonOp);
            if (bytes_read.width) {
                auto bytes = c.get_value(inst.operands[0]);
                auto index = c.get_value(inst.operands[1]);
                auto pointer = LLVMBuildExtractValue(c.builder, bytes, 0, "bytes.ptr");
                auto length = LLVMBuildExtractValue(c.builder, bytes, 1, "bytes.len");
                auto width = LLVMConstInt(c.i32_ty, bytes_read.width, 0);
                auto enough = LLVMBuildICmp(c.builder, LLVMIntUGE, length, width, "bytes.enough");
                auto last = LLVMBuildSub(c.builder, length, width, "bytes.last");
                auto in_bounds = LLVMBuildICmp(c.builder, LLVMIntULE, index, last, "bytes.bounds");
                auto nonnegative = LLVMBuildICmp(c.builder,
                                                 LLVMIntSGE,
                                                 index,
                                                 LLVMConstInt(c.i32_ty, 0, 0),
                                                 "bytes.nonnegative");
                in_bounds = LLVMBuildAnd(c.builder, in_bounds, enough, "bytes.complete");
                in_bounds = LLVMBuildAnd(c.builder, in_bounds, nonnegative, "bytes.offset.valid");
                auto nonnull = LLVMBuildICmp(
                    c.builder, LLVMIntNE, pointer, LLVMConstNull(c.ptr_ty), "bytes.nonnull");
                auto valid = LLVMBuildAnd(c.builder, in_bounds, nonnull, "bytes.valid");
                auto origin = LLVMGetInsertBlock(c.builder);
                auto function = LLVMGetBasicBlockParent(origin);
                auto load = LLVMAppendBasicBlockInContext(c.llvm_ctx, function, "bytes.load");
                auto merge = LLVMAppendBasicBlockInContext(c.llvm_ctx, function, "bytes.merge");
                LLVMBuildCondBr(c.builder, valid, load, merge);
                LLVMPositionBuilderAtEnd(c.builder, load);
                auto address =
                    LLVMBuildGEP2(c.builder, c.i8_ty, pointer, &index, 1, "bytes.address");
                auto integer_type = bytes_read.wide ? c.i64_ty : c.i32_ty;
                auto number = LLVMConstInt(integer_type, 0, 0);
                for (u32 i = 0; i < bytes_read.width; ++i) {
                    auto byte_offset = LLVMConstInt(c.i32_ty, i, 0);
                    auto byte_address = LLVMBuildGEP2(
                        c.builder, c.i8_ty, address, &byte_offset, 1, "bytes.byte.address");
                    auto byte = LLVMBuildLoad2(c.builder, c.i8_ty, byte_address, "bytes.byte");
                    auto octet = LLVMBuildZExt(c.builder, byte, integer_type, "bytes.octet");
                    const u32 shift = (bytes_read.little_endian ? i : bytes_read.width - i - 1) * 8;
                    if (shift)
                        octet = LLVMBuildShl(c.builder,
                                             octet,
                                             LLVMConstInt(integer_type, shift, 0),
                                             "bytes.shifted");
                    number = LLVMBuildOr(c.builder, number, octet, "bytes.number");
                }
                if (bytes_read.is_signed && bytes_read.width == 2) {
                    auto narrow = LLVMIntTypeInContext(c.llvm_ctx, 16);
                    number =
                        LLVMBuildSExt(c.builder,
                                      LLVMBuildTrunc(c.builder, number, narrow, "bytes.signed16"),
                                      integer_type,
                                      "bytes.signed");
                }
                LLVMBuildBr(c.builder, merge);
                LLVMPositionBuilderAtEnd(c.builder, merge);
                auto payload = LLVMBuildPhi(c.builder, integer_type, "bytes.result");
                LLVMValueRef values[] = {LLVMConstInt(integer_type, 0, 0), number};
                LLVMBasicBlockRef blocks[] = {origin, load};
                LLVMAddIncoming(payload, values, blocks, 2);
                const auto* result_type = c.cur_fn->values[inst.result.id].type;
                auto result = LLVMGetUndef(c.map_type(result_type));
                result = LLVMBuildInsertValue(c.builder,
                                              result,
                                              LLVMBuildZExt(c.builder, valid, c.i8_ty, "bytes.has"),
                                              0,
                                              "");
                result = LLVMBuildInsertValue(c.builder, result, payload, 1, "");
                c.set_value(inst.result, result);
                break;
            }
            if (kJsonOp == json::Op::NetError) {
                LLVMTypeRef params[] = {c.ptr_ty};
                auto type = LLVMFunctionType(c.i32_ty, params, 1, 0);
                auto helper = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_net_error");
                if (!helper) helper = LLVMAddFunction(c.llvm_mod, "rut_helper_net_error", type);
                LLVMValueRef args[] = {c.param_conn};
                c.set_value(inst.result,
                            LLVMBuildCall2(c.builder, type, helper, args, 1, "net.error"));
                break;
            }
            if (rir::is_net_call(inst)) {
                const bool opening = kJsonOp == json::Op::NetTcp || kJsonOp == json::Op::NetUdp;
                const bool releasing = kJsonOp == json::Op::NetRelease;
                const bool closing = kJsonOp == json::Op::NetClose || releasing;
                const bool sending = kJsonOp == json::Op::NetSend;
                const bool scalar_result = opening || sending;
                auto parent = LLVMGetBasicBlockParent(LLVMGetInsertBlock(c.builder));
                auto poll = LLVMAppendBasicBlockInContext(c.llvm_ctx, parent, "net.poll");
                auto pending = LLVMAppendBasicBlockInContext(c.llvm_ctx, parent, "net.pending");
                auto ready = LLVMAppendBasicBlockInContext(c.llvm_ctx, parent, "net.ready");
                const u32 state = ++c.call_state;
                LLVMAddCase(c.call_dispatch, LLVMConstInt(c.i32_ty, state, 0), poll);
                LLVMBuildBr(c.builder, poll);
                LLVMPositionBuilderAtEnd(c.builder, poll);
                auto has = LLVMBuildAlloca(c.builder, c.i8_ty, "net.has");
                auto scalar = LLVMBuildAlloca(c.builder, c.i32_ty, "net.scalar");
                auto out = LLVMBuildAlloca(c.builder, c.ptr_ty, "net.bytes");
                auto length = LLVMBuildAlloca(c.builder, c.i32_ty, "net.length");
                auto data = opening   ? c.get_value(inst.operand(0))
                            : sending ? c.get_value(inst.operand(1))
                                      : LLVMGetUndef(c.str_ty);
                auto handle = opening ? LLVMConstInt(c.i32_ty, 0, 0) : c.get_value(inst.operand(0));
                auto timeout = closing ? LLVMConstInt(c.i32_ty, releasing ? 1000 : 1, 0)
                                       : c.get_value(inst.operand(opening ? 1 : 2));
                auto amount = opening || closing || sending ? LLVMConstInt(c.i32_ty, 0, 0)
                                                            : c.get_value(inst.operand(1));
                LLVMTypeRef params[] = {c.ptr_ty,
                                        c.i32_ty,
                                        c.i32_ty,
                                        c.ptr_ty,
                                        c.i32_ty,
                                        c.i32_ty,
                                        c.i32_ty,
                                        c.ptr_ty,
                                        c.ptr_ty,
                                        c.ptr_ty,
                                        c.ptr_ty};
                auto type = LLVMFunctionType(c.i64_ty, params, 11, 0);
                auto helper = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_net_call");
                if (!helper) helper = LLVMAddFunction(c.llvm_mod, "rut_helper_net_call", type);
                LLVMValueRef args[] = {
                    c.param_conn,
                    LLVMConstInt(
                        c.i32_ty,
                        releasing ? static_cast<u32>(rut::NetOp::Release)
                                  : static_cast<u32>(kJsonOp) - static_cast<u32>(json::Op::NetTcp),
                        0),
                    handle,
                    opening || sending ? LLVMBuildExtractValue(c.builder, data, 0, "net.data")
                                       : LLVMConstNull(c.ptr_ty),
                    opening || sending ? LLVMBuildExtractValue(c.builder, data, 1, "net.size")
                                       : LLVMConstInt(c.i32_ty, 0, 0),
                    amount,
                    timeout,
                    has,
                    scalar,
                    out,
                    length};
                auto reply = LLVMBuildCall2(c.builder, type, helper, args, 11, "net.reply");
                auto waiting =
                    LLVMBuildICmp(c.builder,
                                  LLVMIntEQ,
                                  LLVMBuildTrunc(c.builder, reply, c.i32_ty, "net.status"),
                                  LLVMConstInt(c.i32_ty, 0x80000000u, 0),
                                  "net.waiting");
                LLVMBuildCondBr(c.builder, waiting, pending, ready);
                LLVMPositionBuilderAtEnd(c.builder, pending);
                auto pc =
                    LLVMBuildStructGEP2(c.builder, c.call_frame_type, c.call_frame, 0, "net.pc");
                LLVMBuildStore(c.builder, LLVMConstInt(c.i32_ty, state, 0), pc);
                auto ms =
                    LLVMBuildLShr(c.builder, reply, LLVMConstInt(c.i64_ty, 32, 0), "net.retry");
                auto packed =
                    LLVMBuildOr(c.builder,
                                LLVMBuildShl(c.builder, ms, LLVMConstInt(c.i64_ty, 8, 0), "net.ms"),
                                c.make_result_yield(0, static_cast<u8>(YieldKind::Timer), 0),
                                "net.yield");
                c.emit_parse_unprime();
                c.emit_time_unlatch();
                LLVMBuildRet(c.builder, packed);
                LLVMPositionBuilderAtEnd(c.builder, ready);
                auto scalar_value = LLVMBuildLoad2(c.builder, c.i32_ty, scalar, "net.value");
                if (closing) {
                    c.set_value(inst.result,
                                LLVMBuildICmp(c.builder,
                                              LLVMIntNE,
                                              scalar_value,
                                              LLVMConstInt(c.i32_ty, 0, 0),
                                              "net.closed"));
                } else {
                    auto result = LLVMGetUndef(scalar_result ? c.opt_i32_ty : c.opt_str_ty);
                    result =
                        LLVMBuildInsertValue(c.builder,
                                             result,
                                             LLVMBuildLoad2(c.builder, c.i8_ty, has, "net.present"),
                                             0,
                                             "net.result");
                    result = LLVMBuildInsertValue(
                        c.builder,
                        result,
                        scalar_result ? scalar_value
                                      : LLVMBuildLoad2(c.builder, c.ptr_ty, out, "net.out"),
                        1,
                        "net.result");
                    if (!scalar_result)
                        result = LLVMBuildInsertValue(
                            c.builder,
                            result,
                            LLVMBuildLoad2(c.builder, c.i32_ty, length, "net.len"),
                            2,
                            "net.result");
                    c.set_value(inst.result, result);
                }
                break;
            }
            if (kJsonOp == json::Op::HttpCall) {
                auto parent = LLVMGetBasicBlockParent(LLVMGetInsertBlock(c.builder));
                auto poll = LLVMAppendBasicBlockInContext(c.llvm_ctx, parent, "http.call.poll");
                auto pending =
                    LLVMAppendBasicBlockInContext(c.llvm_ctx, parent, "http.call.pending");
                auto ready = LLVMAppendBasicBlockInContext(c.llvm_ctx, parent, "http.call.ready");
                const u32 state = ++c.call_state;
                LLVMAddCase(c.call_dispatch, LLVMConstInt(c.i32_ty, state, 0), poll);
                LLVMBuildBr(c.builder, poll);
                LLVMPositionBuilderAtEnd(c.builder, poll);
                auto policy = c.get_value(inst.operand(0));
                auto request = c.get_value(inst.operand(1));
                auto timeout = c.get_value(inst.operand(2));
                auto has = LLVMBuildAlloca(c.builder, c.i8_ty, "call.has");
                auto out = LLVMBuildAlloca(c.builder, c.ptr_ty, "call.out");
                auto length = LLVMBuildAlloca(c.builder, c.i32_ty, "call.length");
                LLVMTypeRef params[] = {c.ptr_ty,
                                        c.ptr_ty,
                                        c.i32_ty,
                                        c.ptr_ty,
                                        c.i32_ty,
                                        c.i32_ty,
                                        c.ptr_ty,
                                        c.ptr_ty,
                                        c.ptr_ty};
                auto type = LLVMFunctionType(c.i64_ty, params, 9, 0);
                auto helper = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_http_call");
                if (!helper) helper = LLVMAddFunction(c.llvm_mod, "rut_helper_http_call", type);
                LLVMValueRef args[] = {
                    c.param_conn,
                    LLVMBuildExtractValue(c.builder, policy, 0, "call.policy.ptr"),
                    LLVMBuildExtractValue(c.builder, policy, 1, "call.policy.len"),
                    LLVMBuildExtractValue(c.builder, request, 0, "call.request.ptr"),
                    LLVMBuildExtractValue(c.builder, request, 1, "call.request.len"),
                    timeout,
                    has,
                    out,
                    length};
                auto reply = LLVMBuildCall2(c.builder, type, helper, args, 9, "call.reply");
                auto status = LLVMBuildTrunc(c.builder, reply, c.i32_ty, "call.status");
                auto waiting = LLVMBuildICmp(c.builder,
                                             LLVMIntEQ,
                                             status,
                                             LLVMConstInt(c.i32_ty, 0x80000000u, 0),
                                             "call.waiting");
                LLVMBuildCondBr(c.builder, waiting, pending, ready);
                LLVMPositionBuilderAtEnd(c.builder, pending);
                auto pc =
                    LLVMBuildStructGEP2(c.builder, c.call_frame_type, c.call_frame, 0, "call.pc");
                LLVMBuildStore(c.builder, LLVMConstInt(c.i32_ty, state, 0), pc);
                auto ms =
                    LLVMBuildLShr(c.builder, reply, LLVMConstInt(c.i64_ty, 32, 0), "call.retry");
                auto packed = LLVMBuildOr(
                    c.builder,
                    LLVMBuildShl(c.builder, ms, LLVMConstInt(c.i64_ty, 8, 0), "call.ms"),
                    c.make_result_yield(0, static_cast<u8>(YieldKind::Timer), 0),
                    "call.yield");
                c.emit_parse_unprime();
                c.emit_time_unlatch();
                LLVMBuildRet(c.builder, packed);
                LLVMPositionBuilderAtEnd(c.builder, ready);
                auto result = LLVMGetUndef(c.opt_str_ty);
                result =
                    LLVMBuildInsertValue(c.builder,
                                         result,
                                         LLVMBuildLoad2(c.builder, c.i8_ty, has, "call.has.value"),
                                         0,
                                         "call.result");
                result =
                    LLVMBuildInsertValue(c.builder,
                                         result,
                                         LLVMBuildLoad2(c.builder, c.ptr_ty, out, "call.out.value"),
                                         1,
                                         "call.result");
                result = LLVMBuildInsertValue(
                    c.builder,
                    result,
                    LLVMBuildLoad2(c.builder, c.i32_ty, length, "call.length.value"),
                    2,
                    "call.result");
                c.set_value(inst.result, result);
                break;
            }
            if (kJsonOp == json::Op::PasswordVerifyHeader ||
                kJsonOp == json::Op::ForwardAuthHeader) {
                const char* helper_name = kJsonOp == json::Op::ForwardAuthHeader
                                              ? "rut_helper_forward_auth_header"
                                              : "rut_helper_password_verify_header";
                LLVMTypeRef params[] = {
                    c.ptr_ty, c.ptr_ty, c.i32_ty, c.ptr_ty, c.i32_ty, c.ptr_ty, c.i32_ty, c.i32_ty};
                LLVMTypeRef ft = LLVMFunctionType(c.i64_ty, params, 8, 0);
                auto helper = LLVMGetNamedFunction(c.llvm_mod, helper_name);
                if (!helper) helper = LLVMAddFunction(c.llvm_mod, helper_name, ft);
                const auto header = c.get_value(inst.operand(0));
                const auto record = c.get_value(inst.operand(1));
                LLVMValueRef args[] = {
                    c.param_conn,
                    c.param_req_data,
                    c.param_req_len,
                    LLVMBuildExtractValue(c.builder, header, 0, "password.header.ptr"),
                    LLVMBuildExtractValue(c.builder, header, 1, "password.header.len"),
                    LLVMBuildExtractValue(c.builder, record, 0, "password.record.ptr"),
                    LLVMBuildExtractValue(c.builder, record, 1, "password.record.len"),
                    c.get_value(inst.operand(2))};
                auto reply = LLVMBuildCall2(c.builder, ft, helper, args, 8, "password.reply");
                auto status = LLVMBuildTrunc(c.builder, reply, c.i32_ty, "password.status");
                auto pending = LLVMBuildICmp(c.builder,
                                             LLVMIntEQ,
                                             status,
                                             LLVMConstInt(c.i32_ty, 0x80000000u, 0),
                                             "password.pending");
                auto parent = LLVMGetBasicBlockParent(LLVMGetInsertBlock(c.builder));
                auto suspend =
                    LLVMAppendBasicBlockInContext(c.llvm_ctx, parent, "password.suspend");
                auto ready = LLVMAppendBasicBlockInContext(c.llvm_ctx, parent, "password.ready");
                LLVMBuildCondBr(c.builder, pending, suspend, ready);
                LLVMPositionBuilderAtEnd(c.builder, suspend);
                auto ms = LLVMBuildLShr(
                    c.builder, reply, LLVMConstInt(c.i64_ty, 32, 0), "password.retry");
                auto packed = LLVMBuildOr(
                    c.builder,
                    LLVMBuildShl(c.builder, ms, LLVMConstInt(c.i64_ty, 8, 0), "password.ms"),
                    c.make_result_yield(0, static_cast<u8>(YieldKind::Timer), 0),
                    "password.yield");
                c.emit_parse_unprime();
                c.emit_time_unlatch();
                LLVMBuildRet(c.builder, packed);
                LLVMPositionBuilderAtEnd(c.builder, ready);
                c.set_value(inst.result, status);
                break;
            }
            if (kJsonOp == json::Op::JwtIssueHs256 || kJsonOp == json::Op::JwtIssueHs256WithId ||
                kJsonOp == json::Op::JwtIssueHs256WithIdAndScope) {
                const bool kWithId = kJsonOp != json::Op::JwtIssueHs256;
                const bool kWithScope = kJsonOp == json::Op::JwtIssueHs256WithIdAndScope;
                const u32 kStringCount = kWithScope ? 6u : (kWithId ? 5u : 4u);
                const u32 kTtlIndex = 2u + kStringCount * 2u;
                const u32 kParamCount = kTtlIndex + 4u;
                LLVMValueRef output_has = LLVMBuildAlloca(c.builder, c.i8_ty, "jwt.issue.has");
                LLVMValueRef output_ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "jwt.issue.ptr");
                LLVMValueRef output_len = LLVMBuildAlloca(c.builder, c.i32_ty, "jwt.issue.len");
                LLVMTypeRef params[18]{};
                params[0] = c.ptr_ty;
                params[1] = c.ptr_ty;
                for (u32 i = 0; i < kStringCount; ++i) {
                    params[2 + i * 2] = c.ptr_ty;
                    params[3 + i * 2] = c.i32_ty;
                }
                params[kTtlIndex] = c.i32_ty;
                params[kTtlIndex + 1] = c.ptr_ty;
                params[kTtlIndex + 2] = c.ptr_ty;
                params[kTtlIndex + 3] = c.ptr_ty;
                LLVMTypeRef type = LLVMFunctionType(c.void_ty, params, kParamCount, 0);
                const char* helper_name = kWithScope
                                              ? "rut_helper_jwt_issue_hs256_with_id_and_scope"
                                              : (kWithId ? "rut_helper_jwt_issue_hs256_with_id"
                                                         : "rut_helper_jwt_issue_hs256");
                LLVMValueRef helper = LLVMGetNamedFunction(c.llvm_mod, helper_name);
                if (!helper) helper = LLVMAddFunction(c.llvm_mod, helper_name, type);
                LLVMValueRef args[18] = {c.param_conn, c.param_arena};
                for (u32 i = 0; i < kStringCount + 1; ++i) {
                    LLVMValueRef value = c.get_value(inst.operand(i));
                    if (i < kStringCount) {
                        args[2 + i * 2] = LLVMBuildExtractValue(c.builder, value, 0, "jwt.arg.ptr");
                        args[3 + i * 2] = LLVMBuildExtractValue(c.builder, value, 1, "jwt.arg.len");
                    } else {
                        args[kTtlIndex] = value;
                    }
                }
                args[kTtlIndex + 1] = output_has;
                args[kTtlIndex + 2] = output_ptr;
                args[kTtlIndex + 3] = output_len;
                LLVMBuildCall2(c.builder, type, helper, args, kParamCount, "");
                LLVMValueRef result =
                    LLVMGetUndef(c.map_type(c.cur_fn->values[inst.result.id].type));
                result =
                    LLVMBuildInsertValue(c.builder,
                                         result,
                                         LLVMBuildLoad2(c.builder, c.i8_ty, output_has, "jwt.has"),
                                         0,
                                         "");
                result =
                    LLVMBuildInsertValue(c.builder,
                                         result,
                                         LLVMBuildLoad2(c.builder, c.ptr_ty, output_ptr, "jwt.ptr"),
                                         1,
                                         "");
                result =
                    LLVMBuildInsertValue(c.builder,
                                         result,
                                         LLVMBuildLoad2(c.builder, c.i32_ty, output_len, "jwt.len"),
                                         2,
                                         "");
                c.set_value(inst.result, result);
                break;
            }
            LLVMTypeRef params[] = {c.ptr_ty,
                                    c.ptr_ty,
                                    c.i32_ty,
                                    c.ptr_ty,
                                    c.i32_ty,
                                    c.ptr_ty,
                                    c.i32_ty,
                                    c.ptr_ty,
                                    c.i32_ty,
                                    c.i64_ty,
                                    c.ptr_ty,
                                    c.ptr_ty,
                                    c.ptr_ty,
                                    c.ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(c.void_ty, params, 14, 0);
            LLVMValueRef fn = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_json");
            if (!fn) fn = LLVMAddFunction(c.llvm_mod, "rut_helper_json", ft);
            LLVMValueRef out_has = LLVMBuildAlloca(c.builder, c.i8_ty, "json.has");
            LLVMValueRef out_ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "json.ptr");
            LLVMValueRef out_len = LLVMBuildAlloca(c.builder, c.i32_ty, "json.len");
            LLVMValueRef out_num = LLVMBuildAlloca(c.builder, c.i64_ty, "json.num");
            LLVMValueRef args[] = {c.param_conn,
                                   c.param_arena,
                                   LLVMConstInt(c.i32_ty, static_cast<u32>(inst.imm.i32_val), 0),
                                   LLVMConstNull(c.ptr_ty),
                                   LLVMConstInt(c.i32_ty, 0, 0),
                                   LLVMConstNull(c.ptr_ty),
                                   LLVMConstInt(c.i32_ty, 0, 0),
                                   LLVMConstNull(c.ptr_ty),
                                   LLVMConstInt(c.i32_ty, 0, 0),
                                   LLVMConstInt(c.i64_ty, 0, 0),
                                   out_has,
                                   out_ptr,
                                   out_len,
                                   out_num};
            for (u32 i = 0; i < inst.operand_count; ++i) {
                auto val = c.get_value(inst.operands[i]);
                const auto* ty = c.cur_fn->values[inst.operands[i].id].type;
                if (ty->kind == rir::TypeKind::Str) {
                    args[3 + i * 2] = LLVMBuildExtractValue(c.builder, val, 0, "json.arg.ptr");
                    args[4 + i * 2] = LLVMBuildExtractValue(c.builder, val, 1, "json.arg.len");
                } else if (ty->kind == rir::TypeKind::I64)
                    args[9] = val;
                else if (ty->kind == rir::TypeKind::I32)
                    args[9] = LLVMBuildSExt(c.builder, val, c.i64_ty, "json.int");
                else
                    args[9] = LLVMBuildZExt(c.builder, val, c.i64_ty, "json.bool");
            }
            LLVMBuildCall2(c.builder, ft, fn, args, 14, "");
            const auto* result_type = c.cur_fn->values[inst.result.id].type;
            const bool optional = result_type->kind == rir::TypeKind::Optional;
            const auto* inner = optional ? result_type->inner : result_type;
            LLVMValueRef result;
            if (inner->kind == rir::TypeKind::Str) {
                result = LLVMGetUndef(c.str_ty);
                result = LLVMBuildInsertValue(
                    c.builder,
                    result,
                    LLVMBuildLoad2(c.builder, c.ptr_ty, out_ptr, "json.result.ptr"),
                    0,
                    "");
                result = LLVMBuildInsertValue(
                    c.builder,
                    result,
                    LLVMBuildLoad2(c.builder, c.i32_ty, out_len, "json.result.len"),
                    1,
                    "");
            } else {
                result = LLVMBuildLoad2(c.builder, c.i64_ty, out_num, "json.result.number");
                if (inner->kind == rir::TypeKind::I32)
                    result = LLVMBuildTrunc(c.builder, result, c.i32_ty, "json.count");
                if (inner->kind == rir::TypeKind::Bool)
                    result = LLVMBuildTrunc(c.builder, result, c.i1_ty, "json.boolean");
            }
            if (optional) {
                LLVMValueRef opt = LLVMGetUndef(c.map_type(result_type));
                opt = LLVMBuildInsertValue(
                    c.builder,
                    opt,
                    LLVMBuildLoad2(c.builder, c.i8_ty, out_has, "json.result.has"),
                    0,
                    "");
                if (inner->kind == rir::TypeKind::Str) {
                    opt = LLVMBuildInsertValue(
                        c.builder, opt, LLVMBuildExtractValue(c.builder, result, 0, ""), 1, "");
                    opt = LLVMBuildInsertValue(
                        c.builder, opt, LLVMBuildExtractValue(c.builder, result, 1, ""), 2, "");
                } else
                    opt = LLVMBuildInsertValue(c.builder, opt, result, 1, "");
                result = opt;
            }
            c.set_value(inst.result, result);
            break;
        }
        case rir::Opcode::HashDigest: {
            LLVMValueRef has = LLVMBuildAlloca(c.builder, c.i8_ty, "hash.has");
            LLVMValueRef ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "hash.ptr");
            LLVMValueRef len = LLVMBuildAlloca(c.builder, c.i32_ty, "hash.len");
            LLVMBuildStore(c.builder, LLVMConstInt(c.i8_ty, 0, 0), has);
            LLVMBuildStore(c.builder, LLVMConstNull(c.ptr_ty), ptr);
            LLVMBuildStore(c.builder, LLVMConstInt(c.i32_ty, 0, 0), len);
            LLVMValueRef input[4] = {LLVMConstNull(c.ptr_ty),
                                     LLVMConstInt(c.i32_ty, 0, 0),
                                     LLVMConstNull(c.ptr_ty),
                                     LLVMConstInt(c.i32_ty, 0, 0)};
            for (u32 i = 0; i < inst.operand_count; ++i) {
                LLVMValueRef value = c.get_value(inst.operand(i));
                const u32 kOffset = 2 * i;
                input[kOffset] = LLVMBuildExtractValue(c.builder, value, 0, "hash.input.ptr");
                input[kOffset + 1] = LLVMBuildExtractValue(c.builder, value, 1, "hash.input.len");
            }
            LLVMTypeRef available_params[] = {c.ptr_ty, c.ptr_ty};
            LLVMTypeRef available_type = LLVMFunctionType(c.i8_ty, available_params, 2, 0);
            LLVMValueRef available_fn =
                LLVMGetNamedFunction(c.llvm_mod, "rut_helper_hash_available");
            if (!available_fn)
                available_fn =
                    LLVMAddFunction(c.llvm_mod, "rut_helper_hash_available", available_type);
            LLVMValueRef available_args[] = {c.param_conn, c.param_arena};
            LLVMValueRef available = LLVMBuildCall2(
                c.builder, available_type, available_fn, available_args, 2, "hash.available");
            LLVMValueRef llvm_fn = LLVMGetBasicBlockParent(LLVMGetInsertBlock(c.builder));
            LLVMBasicBlockRef compute =
                LLVMAppendBasicBlockInContext(c.llvm_ctx, llvm_fn, "hash.compute");
            LLVMBasicBlockRef done =
                LLVMAppendBasicBlockInContext(c.llvm_ctx, llvm_fn, "hash.done");
            LLVMBuildCondBr(
                c.builder,
                LLVMBuildICmp(
                    c.builder, LLVMIntNE, available, LLVMConstInt(c.i8_ty, 0, 0), "hash.ready"),
                compute,
                done);
            // Place scratch in the entry block so a bounded loop cannot accumulate stack
            // allocations.
            LLVMBuilderRef entry_builder = LLVMCreateBuilderInContext(c.llvm_ctx);
            LLVMBasicBlockRef entry = LLVMGetEntryBasicBlock(llvm_fn);
            LLVMValueRef first = LLVMGetFirstInstruction(entry);
            if (first)
                LLVMPositionBuilderBefore(entry_builder, first);
            else
                LLVMPositionBuilderAtEnd(entry_builder, entry);
            LLVMValueRef scratch = LLVMBuildAlloca(
                entry_builder, LLVMArrayType(c.i8_ty, kMaxHashHexBytes), "hash.scratch");
            LLVMValueRef digest_len = LLVMBuildAlloca(entry_builder, c.i32_ty, "hash.digest.len");
            LLVMDisposeBuilder(entry_builder);
            LLVMPositionBuilderAtEnd(c.builder, compute);
            const u32 kOperation = static_cast<u32>(inst.imm.i32_val);
            const bool kKeyed = (kOperation & kHashHmacFlag) != 0;
            LLVMTypeRef digest_params[] = {c.i32_ty,
                                           c.ptr_ty,
                                           c.i32_ty,
                                           c.ptr_ty,
                                           c.i32_ty,
                                           c.i32_ty,
                                           c.ptr_ty,
                                           c.i32_ty,
                                           c.ptr_ty};
            LLVMTypeRef digest_type = LLVMFunctionType(c.i32_ty, digest_params, 9, 0);
            LLVMValueRef digest_fn = LLVMGetNamedFunction(c.llvm_mod, "rut_crypto_digest_hex_v1");
            if (!digest_fn)
                digest_fn = LLVMAddFunction(c.llvm_mod, "rut_crypto_digest_hex_v1", digest_type);
            LLVMValueRef digest_args[] = {LLVMConstInt(c.i32_ty, kOperation & ~kHashHmacFlag, 0),
                                          kKeyed ? input[2] : input[0],
                                          kKeyed ? input[3] : input[1],
                                          kKeyed ? input[0] : LLVMConstNull(c.ptr_ty),
                                          kKeyed ? input[1] : LLVMConstInt(c.i32_ty, 0, 0),
                                          LLVMConstInt(c.i32_ty, kKeyed ? 1 : 0, 0),
                                          scratch,
                                          LLVMConstInt(c.i32_ty, kMaxHashHexBytes, 0),
                                          digest_len};
            LLVMValueRef computed =
                LLVMBuildCall2(c.builder, digest_type, digest_fn, digest_args, 9, "hash.computed");
            LLVMTypeRef publish_params[] = {
                c.ptr_ty, c.ptr_ty, c.ptr_ty, c.i32_ty, c.i32_ty, c.ptr_ty, c.ptr_ty, c.ptr_ty};
            LLVMTypeRef publish_type = LLVMFunctionType(c.void_ty, publish_params, 8, 0);
            LLVMValueRef publish_fn = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_hash_publish");
            if (!publish_fn)
                publish_fn = LLVMAddFunction(c.llvm_mod, "rut_helper_hash_publish", publish_type);
            LLVMValueRef publish_args[] = {
                c.param_conn,
                c.param_arena,
                scratch,
                LLVMBuildLoad2(c.builder, c.i32_ty, digest_len, "hash.digest.length"),
                computed,
                has,
                ptr,
                len};
            LLVMBuildCall2(c.builder, publish_type, publish_fn, publish_args, 8, "");
            LLVMTypeRef clear_params[] = {c.ptr_ty, c.i32_ty};
            LLVMTypeRef clear_type = LLVMFunctionType(c.void_ty, clear_params, 2, 0);
            LLVMValueRef clear_fn = LLVMGetNamedFunction(c.llvm_mod, "rut_crypto_clear_v1");
            if (!clear_fn)
                clear_fn = LLVMAddFunction(c.llvm_mod, "rut_crypto_clear_v1", clear_type);
            LLVMValueRef clear_args[] = {scratch, LLVMConstInt(c.i32_ty, kMaxHashHexBytes, 0)};
            LLVMBuildCall2(c.builder, clear_type, clear_fn, clear_args, 2, "");
            LLVMBuildBr(c.builder, done);
            LLVMPositionBuilderAtEnd(c.builder, done);
            LLVMValueRef result = LLVMGetUndef(c.map_type(c.cur_fn->values[inst.result.id].type));
            result =
                LLVMBuildInsertValue(c.builder,
                                     result,
                                     LLVMBuildLoad2(c.builder, c.i8_ty, has, "hash.result.has"),
                                     0,
                                     "");
            result =
                LLVMBuildInsertValue(c.builder,
                                     result,
                                     LLVMBuildLoad2(c.builder, c.ptr_ty, ptr, "hash.result.ptr"),
                                     1,
                                     "");
            result =
                LLVMBuildInsertValue(c.builder,
                                     result,
                                     LLVMBuildLoad2(c.builder, c.i32_ty, len, "hash.result.len"),
                                     2,
                                     "");
            c.set_value(inst.result, result);
            break;
        }
        case rir::Opcode::Uuid: {
            LLVMTypeRef params[] = {c.ptr_ty, c.ptr_ty, c.ptr_ty, c.ptr_ty, c.ptr_ty};
            LLVMTypeRef ft = LLVMFunctionType(c.void_ty, params, 5, 0);
            LLVMValueRef fn = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_uuid");
            if (!fn) fn = LLVMAddFunction(c.llvm_mod, "rut_helper_uuid", ft);
            LLVMValueRef has = LLVMBuildAlloca(c.builder, c.i8_ty, "uuid.has");
            LLVMValueRef ptr = LLVMBuildAlloca(c.builder, c.ptr_ty, "uuid.ptr");
            LLVMValueRef len = LLVMBuildAlloca(c.builder, c.i32_ty, "uuid.len");
            LLVMValueRef args[] = {c.param_conn, c.param_arena, has, ptr, len};
            LLVMBuildCall2(c.builder, ft, fn, args, 5, "");
            LLVMValueRef result = LLVMGetUndef(c.map_type(c.cur_fn->values[inst.result.id].type));
            result =
                LLVMBuildInsertValue(c.builder,
                                     result,
                                     LLVMBuildLoad2(c.builder, c.i8_ty, has, "uuid.result.has"),
                                     0,
                                     "");
            result =
                LLVMBuildInsertValue(c.builder,
                                     result,
                                     LLVMBuildLoad2(c.builder, c.ptr_ty, ptr, "uuid.result.ptr"),
                                     1,
                                     "");
            result =
                LLVMBuildInsertValue(c.builder,
                                     result,
                                     LLVMBuildLoad2(c.builder, c.i32_ty, len, "uuid.result.len"),
                                     2,
                                     "");
            c.set_value(inst.result, result);
            break;
        }
        case rir::Opcode::TimeNowMicros: {
            LLVMValueRef v = LLVMBuildCall2(c.builder,
                                            LLVMGlobalGetValueType(c.get_time_now_micros()),
                                            c.get_time_now_micros(),
                                            nullptr,
                                            0,
                                            "time.now_micros");
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::MaxInt:
        case rir::Opcode::MinInt: {
            // Signed select at the operand width — single evaluation of both
            // operands (max/min are NOT an IfElse desugar: that would clone
            // the operand trees and re-execute any effectful expression).
            LLVMValueRef a = c.get_value(inst.operands[0]);
            LLVMValueRef b = c.get_value(inst.operands[1]);
            LLVMValueRef cond =
                LLVMBuildICmp(c.builder,
                              inst.op == rir::Opcode::MaxInt ? LLVMIntSGT : LLVMIntSLT,
                              a,
                              b,
                              "minmax.cmp");
            LLVMValueRef r = LLVMBuildSelect(c.builder, cond, a, b, "minmax");
            c.set_value(inst.result, r);
            break;
        }
        case rir::Opcode::SextI64: {
            LLVMValueRef v =
                LLVMBuildSExt(c.builder, c.get_value(inst.operands[0]), c.i64_ty, "sext.i64");
            c.set_value(inst.result, v);
            break;
        }

        // ── Cache state ──
        case rir::Opcode::CacheGet: {
            LLVMValueRef instance =
                LLVMConstInt(c.i32_ty, static_cast<u64>(static_cast<u32>(inst.imm.i32_val)), 0);
            const u32 kIndex = static_cast<u32>(inst.imm.i32_val);
            const Str kName = c.source_module->cache_instances[kIndex].name;
            LLVMValueRef identity =
                LLVMConstInt(c.i64_ty, cache_instance_identity(kName.ptr, kName.len), 0);
            LLVMValueRef key = c.get_value(inst.operands[0]);
            LLVMValueRef out_has = LLVMBuildAlloca(c.builder, c.i8_ty, "cache.has");
            LLVMValueRef out_val = LLVMBuildAlloca(c.builder, c.i64_ty, "cache.val");
            LLVMValueRef args[] = {instance, identity, key, out_has, out_val};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_cache_get()),
                           c.get_cache_get(),
                           args,
                           5,
                           "");
            LLVMValueRef h = LLVMBuildLoad2(c.builder, c.i8_ty, out_has, "cache.h");
            LLVMValueRef v = LLVMBuildLoad2(c.builder, c.i64_ty, out_val, "cache.v");
            // Optional(i64) uses map_type's generic {i8, payload} layout.
            LLVMTypeRef opt_ty = c.map_type(c.cur_fn->values[inst.result.id].type);
            LLVMValueRef opt = LLVMGetUndef(opt_ty);
            opt = LLVMBuildInsertValue(c.builder, opt, h, 0, "cache.opt.has");
            opt = LLVMBuildInsertValue(c.builder, opt, v, 1, "cache.opt.val");
            c.set_value(inst.result, opt);
            break;
        }
        case rir::Opcode::CacheSet: {
            LLVMValueRef instance =
                LLVMConstInt(c.i32_ty, static_cast<u64>(static_cast<u32>(inst.imm.i32_val)), 0);
            const u32 kIndex = static_cast<u32>(inst.imm.i32_val);
            const Str kName = c.source_module->cache_instances[kIndex].name;
            LLVMValueRef identity =
                LLVMConstInt(c.i64_ty, cache_instance_identity(kName.ptr, kName.len), 0);
            LLVMValueRef key = c.get_value(inst.operands[0]);
            LLVMValueRef val = c.get_value(inst.operands[1]);
            LLVMValueRef args[] = {instance, identity, key, val};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_cache_set()),
                           c.get_cache_set(),
                           args,
                           4,
                           "");
            // The instruction's value echoes the stored i64.
            c.set_value(inst.result, val);
            break;
        }

        // ── Comparisons ──
        case rir::Opcode::CmpEq:
        case rir::Opcode::CmpNe:
        case rir::Opcode::CmpLt:
        case rir::Opcode::CmpGt:
        case rir::Opcode::CmpLe:
        case rir::Opcode::CmpGe: {
            LLVMValueRef a = c.get_value(inst.operands[0]);
            LLVMValueRef b = c.get_value(inst.operands[1]);
            const rir::Type* lhs_ty = c.cur_fn && inst.operands[0].id < c.cur_fn->value_cap
                                          ? c.cur_fn->values[inst.operands[0].id].type
                                          : nullptr;
            if (lhs_ty && lhs_ty->kind == rir::TypeKind::Str) {
                LLVMValueRef a_ptr = LLVMBuildExtractValue(c.builder, a, 0, "cmp.s.a.ptr");
                LLVMValueRef a_len = LLVMBuildExtractValue(c.builder, a, 1, "cmp.s.a.len");
                LLVMValueRef b_ptr = LLVMBuildExtractValue(c.builder, b, 0, "cmp.s.b.ptr");
                LLVMValueRef b_len = LLVMBuildExtractValue(c.builder, b, 1, "cmp.s.b.len");
                LLVMValueRef args[] = {a_ptr, a_len, b_ptr, b_len};
                if (inst.op == rir::Opcode::CmpEq || inst.op == rir::Opcode::CmpNe) {
                    LLVMValueRef eq = LLVMBuildCall2(c.builder,
                                                     LLVMGlobalGetValueType(c.get_str_eq()),
                                                     c.get_str_eq(),
                                                     args,
                                                     4,
                                                     "str.eq");
                    LLVMValueRef as_bool = LLVMBuildICmp(
                        c.builder, LLVMIntNE, eq, LLVMConstInt(c.i8_ty, 0, 0), "str.eq.bool");
                    if (inst.op == rir::Opcode::CmpNe) {
                        as_bool = LLVMBuildNot(c.builder, as_bool, "str.ne.bool");
                    }
                    c.set_value(inst.result, as_bool);
                    break;
                }
                LLVMValueRef cmp = LLVMBuildCall2(c.builder,
                                                  LLVMGlobalGetValueType(c.get_str_cmp()),
                                                  c.get_str_cmp(),
                                                  args,
                                                  4,
                                                  "str.cmp");
                LLVMIntPredicate pred;
                switch (inst.op) {
                    case rir::Opcode::CmpLt:
                        pred = LLVMIntSLT;
                        break;
                    case rir::Opcode::CmpGt:
                        pred = LLVMIntSGT;
                        break;
                    case rir::Opcode::CmpLe:
                        pred = LLVMIntSLE;
                        break;
                    case rir::Opcode::CmpGe:
                        pred = LLVMIntSGE;
                        break;
                    default:
                        pred = LLVMIntEQ;
                        break;
                }
                LLVMValueRef as_bool = LLVMBuildICmp(
                    c.builder, pred, cmp, LLVMConstInt(c.i32_ty, 0, 0), "str.ord.bool");
                c.set_value(inst.result, as_bool);
                break;
            }
            // Eq/Ne are sign-agnostic. For ordered comparisons, pick
            // signed vs unsigned predicates based on the RIR operand type.
            bool uns = c.is_unsigned_operand(inst.operands[0]);
            LLVMIntPredicate pred;
            switch (inst.op) {
                case rir::Opcode::CmpEq:
                    pred = LLVMIntEQ;
                    break;
                case rir::Opcode::CmpNe:
                    pred = LLVMIntNE;
                    break;
                case rir::Opcode::CmpLt:
                    pred = uns ? LLVMIntULT : LLVMIntSLT;
                    break;
                case rir::Opcode::CmpGt:
                    pred = uns ? LLVMIntUGT : LLVMIntSGT;
                    break;
                case rir::Opcode::CmpLe:
                    pred = uns ? LLVMIntULE : LLVMIntSLE;
                    break;
                case rir::Opcode::CmpGe:
                    pred = uns ? LLVMIntUGE : LLVMIntSGE;
                    break;
                default:
                    pred = LLVMIntEQ;
                    break;
            }
            LLVMValueRef v = LLVMBuildICmp(c.builder, pred, a, b, "cmp");
            c.set_value(inst.result, v);
            break;
        }

        // ── Optional operations ──
        case rir::Opcode::OptNil: {
            LLVMTypeRef out_ty = c.map_type(c.cur_fn->values[inst.result.id].type);
            LLVMValueRef opt = LLVMGetUndef(out_ty);
            opt =
                LLVMBuildInsertValue(c.builder, opt, LLVMConstInt(c.i8_ty, 0, 0), 0, "opt.nil.has");
            if (out_ty == c.opt_i32_ty) {
                opt = LLVMBuildInsertValue(
                    c.builder, opt, LLVMConstInt(c.i32_ty, 0, 0), 1, "opt.nil.i32");
            } else if (out_ty == c.opt_str_ty) {
                opt =
                    LLVMBuildInsertValue(c.builder, opt, LLVMConstNull(c.ptr_ty), 1, "opt.nil.ptr");
                opt = LLVMBuildInsertValue(
                    c.builder, opt, LLVMConstInt(c.i32_ty, 0, 0), 2, "opt.nil.len");
            } else {
                LLVMTypeRef payload_ty = LLVMStructGetTypeAtIndex(out_ty, 1);
                opt = LLVMBuildInsertValue(
                    c.builder, opt, LLVMConstNull(payload_ty), 1, "opt.nil.payload");
            }
            c.set_value(inst.result, opt);
            break;
        }
        case rir::Opcode::OptWrap: {
            LLVMValueRef val = c.get_value(inst.operands[0]);
            LLVMTypeRef out_ty = c.map_type(c.cur_fn->values[inst.result.id].type);
            LLVMValueRef opt = LLVMGetUndef(out_ty);
            opt = LLVMBuildInsertValue(
                c.builder, opt, LLVMConstInt(c.i8_ty, 1, 0), 0, "opt.wrap.has");
            if (out_ty == c.opt_i32_ty) {
                opt = LLVMBuildInsertValue(c.builder, opt, val, 1, "opt.wrap.i32");
            } else if (out_ty == c.opt_str_ty) {
                LLVMValueRef p = LLVMBuildExtractValue(c.builder, val, 0, "opt.wrap.ptr");
                LLVMValueRef l = LLVMBuildExtractValue(c.builder, val, 1, "opt.wrap.len");
                opt = LLVMBuildInsertValue(c.builder, opt, p, 1, "opt.wrap.ptr.set");
                opt = LLVMBuildInsertValue(c.builder, opt, l, 2, "opt.wrap.len.set");
            } else {
                opt = LLVMBuildInsertValue(c.builder, opt, val, 1, "opt.wrap.payload");
            }
            c.set_value(inst.result, opt);
            break;
        }
        case rir::Opcode::OptIsNil: {
            LLVMValueRef opt = c.get_value(inst.operands[0]);
            LLVMValueRef has = LLVMBuildExtractValue(c.builder, opt, 0, "opt.has");
            LLVMValueRef is_nil =
                LLVMBuildICmp(c.builder, LLVMIntEQ, has, LLVMConstInt(c.i8_ty, 0, 0), "is_nil");
            c.set_value(inst.result, is_nil);
            break;
        }
        case rir::Opcode::OptUnwrap: {
            LLVMValueRef opt = c.get_value(inst.operands[0]);
            LLVMTypeRef out_ty = c.map_type(c.cur_fn->values[inst.result.id].type);
            if (out_ty == c.i32_ty) {
                LLVMValueRef v = LLVMBuildExtractValue(c.builder, opt, 1, "uw.i32");
                c.set_value(inst.result, v);
            } else if (out_ty == c.str_ty) {
                LLVMValueRef p = LLVMBuildExtractValue(c.builder, opt, 1, "uw.ptr");
                LLVMValueRef l = LLVMBuildExtractValue(c.builder, opt, 2, "uw.len");
                LLVMValueRef strval = LLVMGetUndef(c.str_ty);
                strval = LLVMBuildInsertValue(c.builder, strval, p, 0, "uw.s.ptr");
                strval = LLVMBuildInsertValue(c.builder, strval, l, 1, "uw.s.len");
                c.set_value(inst.result, strval);
            } else {
                LLVMValueRef v = LLVMBuildExtractValue(c.builder, opt, 1, "uw.payload");
                c.set_value(inst.result, v);
            }
            break;
        }
        case rir::Opcode::Phi: {
            if (c.call_frame && c.call_frame_fields[inst.result.id]) break;
            LLVMValueRef value = LLVMBuildPhi(
                c.builder, c.map_type(c.cur_fn->values[inst.result.id].type), "merge.value");
            c.set_value(inst.result, value);
            break;
        }
        case rir::Opcode::Select: {
            LLVMValueRef cond = c.get_value(inst.operands[0]);
            LLVMValueRef then_v = c.get_value(inst.operands[1]);
            LLVMValueRef else_v = c.get_value(inst.operands[2]);
            LLVMValueRef v = c.build_select_value(cond, then_v, else_v);
            c.set_value(inst.result, v);
            break;
        }
        case rir::Opcode::CtxStoreSlotI32: {
            const u32 slot = static_cast<u32>(inst.imm.i32_val);
            LLVMValueRef count_off =
                LLVMConstInt(c.i32_ty, static_cast<u32>(offsetof(HandlerCtx, slot_count)), 0);
            LLVMValueRef count_ptr =
                LLVMBuildGEP2(c.builder, c.i8_ty, c.param_ctx, &count_off, 1, "ctx.slot.count.ptr");
            LLVMValueRef count = LLVMBuildLoad2(c.builder, c.i32_ty, count_ptr, "ctx.slot.count");
            LLVMValueRef has_slot = LLVMBuildICmp(
                c.builder, LLVMIntUGT, count, LLVMConstInt(c.i32_ty, slot, 0), "ctx.has.slot");
            const u32 byte_offset = static_cast<u32>(sizeof(HandlerCtx)) + slot * 8u;
            LLVMValueRef off = LLVMConstInt(c.i32_ty, byte_offset, 0);
            LLVMValueRef ptr =
                LLVMBuildGEP2(c.builder, c.i8_ty, c.param_ctx, &off, 1, "ctx.slot.ptr");
            LLVMTypeRef slot_ptr_ty = LLVMPointerType(c.i64_ty, 0);
            LLVMValueRef slot_ptr = LLVMBuildBitCast(c.builder, ptr, slot_ptr_ty, "ctx.slot.ptr64");

            LLVMValueRef slot_store_ptr = LLVMBuildSelect(
                c.builder, has_slot, slot_ptr, c.ctx_store_sink, "ctx.slot.store.ptr");
            LLVMValueRef value64 =
                LLVMBuildZExt(c.builder, c.get_value(inst.operands[0]), c.i64_ty, "ctx.slot.value");
            LLVMBuildStore(c.builder, value64, slot_store_ptr);
            break;
        }
        case rir::Opcode::StructCreate: {
            LLVMTypeRef out_ty = c.map_type(c.cur_fn->values[inst.result.id].type);
            LLVMValueRef s = LLVMGetUndef(out_ty);
            for (u32 i = 0; i < inst.operand_count; i++) {
                s = LLVMBuildInsertValue(c.builder, s, c.get_value(inst.operand(i)), i, "st.ins");
            }
            c.set_value(inst.result, s);
            break;
        }
        case rir::Opcode::StructField: {
            LLVMValueRef s = c.get_value(inst.operands[0]);
            auto* struct_ty = c.cur_fn->values[inst.operands[0].id].type;
            u32 field_index =
                struct_ty && struct_ty->struct_def ? struct_ty->struct_def->field_count : 0;
            if (struct_ty && struct_ty->struct_def) {
                for (u32 i = 0; i < struct_ty->struct_def->field_count; i++) {
                    if (struct_ty->struct_def->fields()[i].name.eq(inst.imm.struct_ref.name)) {
                        field_index = i;
                        break;
                    }
                }
            }
            LLVMValueRef v = LLVMBuildExtractValue(c.builder, s, field_index, "st.field");
            c.set_value(inst.result, v);
            break;
        }

        // ── Terminators ──
        case rir::Opcode::Br: {
            LLVMValueRef cond = c.get_value(inst.operands[0]);
            LLVMBasicBlockRef then_bb = c.get_block(inst.imm.block_targets[0]);
            LLVMBasicBlockRef else_bb = c.get_block(inst.imm.block_targets[1]);
            c.call_edge_values(inst.imm.block_targets[0]);
            c.call_edge_values(inst.imm.block_targets[1]);
            LLVMBuildCondBr(c.builder, cond, then_bb, else_bb);
            break;
        }
        case rir::Opcode::Jmp: {
            LLVMBasicBlockRef target = c.get_block(inst.imm.block_targets[0]);
            c.call_edge_values(inst.imm.block_targets[0]);
            LLVMBuildBr(c.builder, target);
            break;
        }
        case rir::Opcode::RetStatus: {
            // Pack HandlerResult as i64: action=ReturnStatus,
            // status_code in bytes 1-2 (low 16 of status slot),
            // body_idx in bytes 3-4 (the "upstream_id" slot repurposed
            // per handler ABI — 1-based index into RouteConfig's
            // response_bodies; 0 = default status-reason body),
            // headers_idx in bytes 5-6 (the "next_state" slot repurposed
            // for ReturnStatus — 1-based index into RouteConfig's
            // response_header_sets; 0 = no custom headers).
            //
            // For the operand form (runtime-value status), both idx
            // fields are always 0 because that source path doesn't
            // support custom bodies/headers today. For the literal
            // form, RIR packs all three into imm.i64_val:
            //   bits [ 0:16): status
            //   bits [16:32): body_idx
            //   bits [32:48): headers_idx — decode all three here.
            LLVMValueRef status;
            u32 body_idx_imm = 0;
            u32 headers_idx_imm = 0;
            if (inst.operand_count > 0) {
                status = c.get_value(inst.operands[0]);
                if (LLVMTypeOf(status) != c.i32_ty) {
                    status = LLVMBuildZExt(c.builder, status, c.i32_ty, "code.ext");
                }
                // Mask to 16 bits so a runtime-produced status value
                // above 0xffff can't spill into the upstream_id slot
                // (which carries the body_idx for ReturnStatus). The
                // operand form doesn't carry idx fields today.
                status = LLVMBuildAnd(
                    c.builder, status, LLVMConstInt(c.i32_ty, 0xffffu, 0), "code.mask");
            } else {
                const u64 packed = static_cast<u64>(inst.imm.i64_val);
                const u32 status_u = static_cast<u32>(packed & 0xffffu);
                body_idx_imm = static_cast<u32>((packed >> 16) & 0xffffu);
                headers_idx_imm = static_cast<u32>((packed >> 32) & 0xffffu);
                status = LLVMConstInt(c.i32_ty, status_u, 0);
            }
            LLVMValueRef action =
                LLVMConstInt(c.i64_ty, static_cast<u64>(HandlerAction::ReturnStatus), 0);
            LLVMValueRef status_ext = LLVMBuildZExt(c.builder, status, c.i64_ty, "st.ext");
            LLVMValueRef status_shifted =
                LLVMBuildShl(c.builder, status_ext, LLVMConstInt(c.i64_ty, 8, 0), "st.shl");
            LLVMValueRef result = LLVMBuildOr(c.builder, action, status_shifted, "result.st");
            if (body_idx_imm != 0) {
                LLVMValueRef body_slot =
                    LLVMConstInt(c.i64_ty, static_cast<u64>(body_idx_imm) << 24, 0);
                result = LLVMBuildOr(c.builder, result, body_slot, "result.body");
            }
            if (headers_idx_imm != 0) {
                LLVMValueRef headers_slot =
                    LLVMConstInt(c.i64_ty, static_cast<u64>(headers_idx_imm) << 40, 0);
                result = LLVMBuildOr(c.builder, result, headers_slot, "result.headers");
            }
            c.emit_parse_unprime();
            LLVMBuildRet(c.builder, result);
            break;
        }
        case rir::Opcode::RetRedirect: {
            // The verifier rejects malformed redirect immediates. Keep the
            // codegen boundary fail-closed too: an unverified zero/negative/
            // wide value produces a Redirect with id 0, which dispatch rejects.
            const i64 raw_id = inst.imm.i32_val;
            const u64 policy_id = (raw_id > 0 && raw_id <= 0xffff) ? static_cast<u64>(raw_id) : 0;
            const u64 packed = static_cast<u64>(HandlerAction::Redirect) | (policy_id << 24);
            c.emit_parse_unprime();
            LLVMBuildRet(c.builder, LLVMConstInt(c.i64_ty, packed, 0));
            break;
        }
        case rir::Opcode::RetForward:
        case rir::Opcode::RetForwardBundle: {
            // Backend selection is terminal metadata; recording it here preserves
            // the existing request/response policy ABI and preflight proof shape.
            LLVMValueRef lb_args[] = {
                c.param_conn, LLVMConstInt(c.i32_ty, static_cast<u32>(inst.imm.i32_val), 0)};
            LLVMBuildCall2(c.builder,
                           LLVMGlobalGetValueType(c.get_req_set_load_balance()),
                           c.get_req_set_load_balance(),
                           lb_args,
                           2,
                           "");
            // Pack: action=Forward, upstream_id from operand. For the explicit
            // request-policy slice, operand 1 carries the compact policy id in
            // the otherwise-unused status slot.
            LLVMValueRef upstream;
            if (inst.operand_count > 0) {
                upstream = c.get_value(inst.operands[0]);
                if (LLVMTypeOf(upstream) != c.i32_ty) {
                    upstream = LLVMBuildZExt(c.builder, upstream, c.i32_ty, "up.ext");
                }
            } else {
                upstream = LLVMConstInt(c.i32_ty, 0, 0);
            }
            const bool is_bundle = inst.op == rir::Opcode::RetForwardBundle;
            LLVMValueRef action = LLVMConstInt(
                c.i64_ty,
                static_cast<u64>(is_bundle ? HandlerAction::ForwardBundle : HandlerAction::Forward),
                0);
            LLVMValueRef up_ext = LLVMBuildZExt(c.builder, upstream, c.i64_ty, "up.e");
            LLVMValueRef shifted =
                LLVMBuildShl(c.builder, up_ext, LLVMConstInt(c.i64_ty, 24, 0), "up.shl");
            LLVMValueRef result = LLVMBuildOr(c.builder, action, shifted, "result");
            if (inst.operand_count > 1) {
                // The policy occupies the full 16-bit status slot. Direct RIR
                // callers may provide signed or wider integer values, so do
                // not truncate before validating the range: 256 must remain
                // 256 (unsupported), and negative/wider values become the
                // invalid sentinel rather than transparent policy 0.
                LLVMValueRef policy_raw = c.get_value(inst.operands[1]);
                LLVMValueRef policy_ext = nullptr;
                const rir::Type* policy_ty =
                    c.cur_fn ? c.cur_fn->values[inst.operands[1].id].type : nullptr;
                if (policy_ty) {
                    switch (policy_ty->kind) {
                        case rir::TypeKind::I32:
                            policy_ext =
                                LLVMBuildSExt(c.builder, policy_raw, c.i64_ty, "policy.sext");
                            break;
                        case rir::TypeKind::U32:
                            policy_ext =
                                LLVMBuildZExt(c.builder, policy_raw, c.i64_ty, "policy.zext");
                            break;
                        case rir::TypeKind::I64:
                        case rir::TypeKind::U64:
                            policy_ext = policy_raw;
                            break;
                        default:
                            break;
                    }
                }
                if (!policy_ext) {
                    policy_ext = LLVMConstInt(c.i64_ty, 0xffffu, 0);
                }
                LLVMValueRef at_least_zero = LLVMBuildICmp(
                    c.builder, LLVMIntSGE, policy_ext, LLVMConstInt(c.i64_ty, 0, 0), "policy.ge0");
                LLVMValueRef at_most_u16 = LLVMBuildICmp(c.builder,
                                                         LLVMIntSLE,
                                                         policy_ext,
                                                         LLVMConstInt(c.i64_ty, 0xffffu, 0),
                                                         "policy.le16");
                LLVMValueRef in_range =
                    LLVMBuildAnd(c.builder, at_least_zero, at_most_u16, "policy.range");
                LLVMValueRef safe_policy = LLVMBuildSelect(c.builder,
                                                           in_range,
                                                           policy_ext,
                                                           LLVMConstInt(c.i64_ty, 0xffffu, 0),
                                                           "policy.clamped");
                // Keep the policy confined to the 16-bit status slot before
                // shifting it.  The range select above makes this redundant
                // for well-typed values, but the explicit mask is an ABI
                // boundary: no direct-RIR policy bits may reach upstream_id.
                safe_policy = LLVMBuildAnd(
                    c.builder, safe_policy, LLVMConstInt(c.i64_ty, 0xffffu, 0), "policy.mask");
                LLVMValueRef policy_shifted = LLVMBuildShl(
                    c.builder, safe_policy, LLVMConstInt(c.i64_ty, 8, 0), "policy.shl");
                result = LLVMBuildOr(c.builder, result, policy_shifted, "result.policy");
            }
            if (inst.operand_count > 2) {
                // Forward response policy occupies the ABI next_state slot.
                // Direct RIR callers may provide signed or wider integers; an
                // out-of-range value becomes the unsupported sentinel rather
                // than truncating to transparent policy 0 or spilling into a
                // different ABI field.
                LLVMValueRef response_raw = c.get_value(inst.operands[2]);
                LLVMValueRef response_ext = nullptr;
                const rir::Type* response_ty =
                    c.cur_fn ? c.cur_fn->values[inst.operands[2].id].type : nullptr;
                if (response_ty) {
                    switch (response_ty->kind) {
                        case rir::TypeKind::I32:
                            response_ext = LLVMBuildSExt(
                                c.builder, response_raw, c.i64_ty, "response_policy.sext");
                            break;
                        case rir::TypeKind::U32:
                            response_ext = LLVMBuildZExt(
                                c.builder, response_raw, c.i64_ty, "response_policy.zext");
                            break;
                        case rir::TypeKind::I64:
                        case rir::TypeKind::U64:
                            response_ext = response_raw;
                            break;
                        default:
                            break;
                    }
                }
                if (!response_ext) response_ext = LLVMConstInt(c.i64_ty, 0xffffu, 0);
                LLVMValueRef response_ge_zero = LLVMBuildICmp(c.builder,
                                                              LLVMIntSGE,
                                                              response_ext,
                                                              LLVMConstInt(c.i64_ty, 0, 0),
                                                              "response_policy.ge0");
                LLVMValueRef response_le_u16 = LLVMBuildICmp(c.builder,
                                                             LLVMIntSLE,
                                                             response_ext,
                                                             LLVMConstInt(c.i64_ty, 0xffffu, 0),
                                                             "response_policy.le16");
                LLVMValueRef response_in_range = LLVMBuildAnd(
                    c.builder, response_ge_zero, response_le_u16, "response_policy.range");
                LLVMValueRef safe_response = LLVMBuildSelect(c.builder,
                                                             response_in_range,
                                                             response_ext,
                                                             LLVMConstInt(c.i64_ty, 0xffffu, 0),
                                                             "response_policy.clamped");
                safe_response = LLVMBuildAnd(c.builder,
                                             safe_response,
                                             LLVMConstInt(c.i64_ty, 0xffffu, 0),
                                             "response_policy.mask");
                LLVMValueRef response_shifted = LLVMBuildShl(
                    c.builder, safe_response, LLVMConstInt(c.i64_ty, 40, 0), "response_policy.shl");
                result = LLVMBuildOr(c.builder, result, response_shifted, "result.response_policy");
            }
            c.emit_parse_unprime();
            LLVMBuildRet(c.builder, result);
            break;
        }
        case rir::Opcode::YieldTimer: {
            const u64 packed = static_cast<u64>(inst.imm.i64_val);
            const u32 payload = static_cast<u32>(packed & 0xffffffffu);
            const u16 next_state = static_cast<u16>((packed >> 32) & 0xffffu);
            u8 yield_kind = static_cast<u8>((packed >> 48) & 0xffu);
            if (yield_kind == 0) yield_kind = static_cast<u8>(YieldKind::Timer);
            // Clear the prime before suspending; the resume re-primes at entry.
            c.emit_parse_unprime();
            LLVMBuildRet(c.builder, c.make_result_yield(next_state, yield_kind, payload));
            break;
        }

        default:
            // Unhandled opcode in Phase 1 — emit unreachable as a placeholder.
            // The test should not exercise these paths.
            if (inst.is_terminator()) {
                LLVMBuildUnreachable(c.builder);
            }
            break;
    }
}

// ── Function Codegen ───────────────────────────────────────────────

// True when the function contains a request-access opcode that reads from
// the parse cache. Status-only / forward-only handlers (and ones that only
// touch route params or the peer address) don't, so they skip the
// parse-prime call entirely and pay no parse at entry.
static bool rir_function_uses_parse(const rir::Function& fn) {
    if (!fn.blocks) return false;
    for (u32 bi = 0; bi < fn.block_count; bi++) {
        const auto& blk = fn.blocks[bi];
        if (!blk.insts) continue;
        for (u32 ii = 0; ii < blk.inst_count; ii++) {
            if (rir::is_password_prefix(blk.insts[ii])) return true;
            switch (blk.insts[ii].op) {
                case rir::Opcode::ReqHeaderCount:
                case rir::Opcode::ReqUniqueHeader:
                case rir::Opcode::ReqHeader:
                case rir::Opcode::ReqQuery:
                case rir::Opcode::ReqQueryString:
                case rir::Opcode::ReqMethod:
                case rir::Opcode::ReqPath:
                case rir::Opcode::ReqPathOnly:
                case rir::Opcode::ReqBody:
                case rir::Opcode::ReqKeepAlive:
                case rir::Opcode::ReqChunked:
                case rir::Opcode::ReqHasContentLength:
                case rir::Opcode::ReqHttp10:
                case rir::Opcode::ReqHttp11:
                case rir::Opcode::ReqHttpVersion:
                case rir::Opcode::ReqContentLength:
                case rir::Opcode::ReqCookie:
                    return true;
                default:
                    break;
            }
        }
    }
    return false;
}

// Whether the handler samples the monotonic clock. Time-using handlers that
// never read the request get no parse_prime (which is what normally resets
// the per-invocation time latch), so they need a dedicated latch reset in
// the prologue — otherwise the thread's first sampled timestamp is returned
// forever (frozen clock, silently wrong for GCRA-style elapsed-time logic).
static bool rir_function_uses_time(const rir::Function& fn) {
    if (!fn.blocks) return false;
    for (u32 bi = 0; bi < fn.block_count; bi++) {
        const auto& blk = fn.blocks[bi];
        if (!blk.insts) continue;
        for (u32 ii = 0; ii < blk.inst_count; ii++) {
            if (blk.insts[ii].op == rir::Opcode::TimeNowMicros) return true;
        }
    }
    return false;
}

static bool emit_function(Ctx& c, const rir::Function& fn) {
    c.cur_fn = &fn;
    c.ctx_store_sink = nullptr;

    // Build function name: "handler_<name>"
    char fname[256];
    format_handler_symbol(fn.name, fname, sizeof(fname));

    LLVMValueRef func = LLVMAddFunction(c.llvm_mod, fname, c.handler_fn_ty);

    // Name parameters for readability
    c.param_conn = LLVMGetParam(func, 0);
    c.param_ctx = LLVMGetParam(func, 1);
    c.param_req_data = LLVMGetParam(func, 2);
    c.param_req_len = LLVMGetParam(func, 3);
    c.param_arena = LLVMGetParam(func, 4);
    LLVMSetValueName2(c.param_conn, "conn", 4);
    LLVMSetValueName2(c.param_ctx, "ctx", 3);
    LLVMSetValueName2(c.param_req_data, "req_data", 8);
    LLVMSetValueName2(c.param_req_len, "req_len", 7);
    LLVMSetValueName2(c.param_arena, "arena", 5);
    if (c.ws_body_mode) {
        c.param_ws_opcode = LLVMGetParam(func, 5);
        c.param_ws_from_client = LLVMGetParam(func, 6);
        LLVMSetValueName2(c.param_ws_opcode, "message_kind", 12);
        LLVMSetValueName2(c.param_ws_from_client, "from_client", 11);
    }

    // Reset per-function maps
    c.value_map_cap = fn.value_cap;
    c.block_map_cap = fn.block_cap;

    // Small functions use stack scratch space; larger RIR functions allocate
    // maps from the existing compiler arena instead of hitting a Phase 1 cap.
    LLVMValueRef small_values[512]{};
    LLVMBasicBlockRef small_blocks[64]{};
    // LLVM's opaque mutable block handles are required by LLVMAddIncoming.
    LLVMBasicBlockRef small_exits[64]{};  // NOLINT(misc-const-correctness)
    u8 small_emitted[64]{};
    struct MapStorage {
        MmapArena arena;
        ~MapStorage() { arena.destroy(); }
    } maps;
    const bool kHasCalls = rir::function_uses_http_call(fn);
    if ((fn.value_cap > 512 || fn.block_cap > 64 || kHasCalls) && !maps.arena.init(4096))
        return false;
    c.value_map =
        fn.value_cap <= 512 ? small_values : maps.arena.alloc_array<LLVMValueRef>(fn.value_cap);
    c.block_map =
        fn.block_cap <= 64 ? small_blocks : maps.arena.alloc_array<LLVMBasicBlockRef>(fn.block_cap);
    LLVMBasicBlockRef* exits =
        fn.block_cap <= 64 ? small_exits : maps.arena.alloc_array<LLVMBasicBlockRef>(fn.block_cap);
    if (!c.value_map || !c.block_map || !exits) return false;

    // Create all basic blocks upfront (forward references from Br/Jmp).
    for (u32 i = 0; i < fn.block_count; i++) {
        auto& blk = fn.blocks[i];
        const char* label = blk.label.ptr ? blk.label.ptr : "bb";
        c.block_map[blk.id.id] = LLVMAppendBasicBlockInContext(c.llvm_ctx, func, label);
    }

    // Whether this handler reads the request at all — gates the one-time
    // parse-prime call emitted in the prologue below and the parse-unprime
    // calls at the handler's returns.
    const bool kNeedsParse = rir_function_uses_parse(fn);
    c.cur_fn_needs_parse = kNeedsParse;
    // Time-only handlers still need their per-invocation latch reset; when
    // kNeedsParse is true, parse_prime already resets it (skip the extra call).
    const bool kNeedsTimeUnlatch = !kNeedsParse && rir_function_uses_time(fn);

    // State-machine prologue. When the RIR function has yield points, the
    // handler is called multiple times (once per state) and the first
    // LLVM basic block dispatches on HandlerCtx::state. The default mapping
    // uses state 0..N-1 for prologue yield blocks and any later state for
    // terminal execution:
    //
    //   dispatch:
    //     switch state {
    //       0 -> yield_0   // emit Yield(next=1, payload=payload[0])
    //       1 -> yield_1   // ... up to yield_{N-1}
    //       default -> <original entry block>   // terminal state
    //     }
    //
    // Each yield_k block returns a packed Yield HandlerResult without
    // running any of the original code; the terminal state runs the
    // original RIR blocks unchanged. Single-function model — no frame
    // needed for this slice (nothing lives across the yield).
    //
    // Decorated wait routes can set state_zero_enters_entry. In that mode,
    // state 0 enters the original entry block so decorator guards run before
    // the first timer yield, yield_0 is omitted from the prologue, and
    // resumed states dispatch to the recorded terminal block by default.
    c.call_frame = nullptr;
    c.call_frame_type = nullptr;
    c.call_dispatch = nullptr;
    c.call_state = 0;
    if (kHasCalls) {
        c.call_frame_fields = maps.arena.alloc_array<u32>(fn.value_count);
        c.call_phi_incoming = maps.arena.alloc_array<LLVMValueRef>(fn.value_count * 2);
        if (!c.call_frame_fields || !c.call_phi_incoming ||
            !rir::call_live_values(fn, maps.arena, c.call_frame_fields))
            return false;
        auto* fields = maps.arena.alloc_array<LLVMTypeRef>(1027);
        if (!fields) return false;
        fields[0] = c.i32_ty;
        fields[1] = c.ptr_ty;
        fields[2] = c.i32_ty;
        u32 field_count = 3;
        for (u32 vi = 0; vi < fn.value_count; ++vi) {
            if (c.call_frame_fields[vi] == 0) continue;
            if (field_count == 1027) return false;
            c.call_frame_fields[vi] = field_count;
            fields[field_count++] = c.map_type(fn.values[vi].type);
        }
        c.call_frame_type = LLVMStructTypeInContext(c.llvm_ctx, fields, field_count, 0);
        auto entry = LLVMAppendBasicBlockInContext(c.llvm_ctx, func, "call.entry");
        LLVMMoveBasicBlockBefore(entry, c.block_map[fn.blocks[0].id.id]);
        auto dispatch = LLVMAppendBasicBlockInContext(c.llvm_ctx, func, "call.dispatch");
        auto failed = LLVMAppendBasicBlockInContext(c.llvm_ctx, func, "call.frame.failed");
        LLVMPositionBuilderAtEnd(c.builder, entry);
        c.ctx_store_sink = LLVMBuildAlloca(c.builder, c.i64_ty, "ctx.slot.store.sink");
        LLVMTypeRef params[] = {c.ptr_ty, c.ptr_ty, c.i64_ty, c.ptr_ty, c.i32_ty};
        auto type = LLVMFunctionType(c.ptr_ty, params, 5, 0);
        auto helper = LLVMGetNamedFunction(c.llvm_mod, "rut_helper_http_call_frame");
        if (!helper) helper = LLVMAddFunction(c.llvm_mod, "rut_helper_http_call_frame", type);
        LLVMValueRef args[] = {c.param_conn,
                               c.param_ctx,
                               LLVMSizeOf(c.call_frame_type),
                               c.param_req_data,
                               c.param_req_len};
        c.call_frame = LLVMBuildCall2(c.builder, type, helper, args, 5, "call.frame");
        auto valid = LLVMBuildICmp(
            c.builder, LLVMIntNE, c.call_frame, LLVMConstNull(c.ptr_ty), "call.frame.valid");
        LLVMBuildCondBr(c.builder, valid, dispatch, failed);
        LLVMPositionBuilderAtEnd(c.builder, failed);
        LLVMBuildRet(c.builder, c.make_result_status(503));
        LLVMPositionBuilderAtEnd(c.builder, dispatch);
        auto request =
            LLVMBuildStructGEP2(c.builder, c.call_frame_type, c.call_frame, 1, "call.snapshot.ptr");
        auto length =
            LLVMBuildStructGEP2(c.builder, c.call_frame_type, c.call_frame, 2, "call.snapshot.len");
        c.param_req_data = LLVMBuildLoad2(c.builder, c.ptr_ty, request, "call.snapshot");
        c.param_req_len = LLVMBuildLoad2(c.builder, c.i32_ty, length, "call.snapshot.size");
        if (kNeedsParse) c.emit_parse_prime();
        if (kNeedsTimeUnlatch) c.emit_time_unlatch();
        auto pc = LLVMBuildStructGEP2(c.builder, c.call_frame_type, c.call_frame, 0, "call.pc");
        auto state = LLVMBuildLoad2(c.builder, c.i32_ty, pc, "call.state");
        c.call_dispatch = LLVMBuildSwitch(c.builder, state, failed, 17);
        LLVMAddCase(c.call_dispatch, LLVMConstInt(c.i32_ty, 0, 0), c.block_map[fn.blocks[0].id.id]);
    } else if (fn.yield_count > 0) {
        LLVMBasicBlockRef dispatch_bb = LLVMAppendBasicBlockInContext(c.llvm_ctx, func, "dispatch");
        // Move dispatch to be the first block; it will become the function's
        // entry point automatically because LLVM uses block-append order and
        // we append it AFTER the other blocks — so move it to the front.
        LLVMMoveBasicBlockBefore(dispatch_bb, c.block_map[fn.blocks[0].id.id]);

        LLVMPositionBuilderAtEnd(c.builder, dispatch_bb);
        c.ctx_store_sink = LLVMBuildAlloca(c.builder, c.i64_ty, "ctx.slot.store.sink");
        // Parse-once: prime the per-thread parse cache before any state runs,
        // so every req_* helper in this invocation shares one parse. Skipped
        // for handlers that never read the request (status/forward only).
        if (kNeedsParse) c.emit_parse_prime();
        if (kNeedsTimeUnlatch) c.emit_time_unlatch();
        // HandlerCtx layout: state (u16) @ offset 0.
        LLVMValueRef state = LLVMBuildLoad2(c.builder, c.i16_ty, c.param_ctx, "state");

        const u32 terminal_block_id =
            fn.has_explicit_resume_blocks
                ? fn.resume_blocks[0]
                : (fn.state_zero_enters_entry ? fn.resume_terminal_block : fn.blocks[0].id.id);
        LLVMBasicBlockRef terminal_bb = c.block_map[terminal_block_id];
        LLVMValueRef sw = LLVMBuildSwitch(
            c.builder,
            state,
            terminal_bb,
            fn.yield_count +
                ((fn.state_zero_enters_entry || fn.has_explicit_resume_blocks) ? 1 : 0));
        if (fn.has_explicit_resume_blocks) {
            for (u32 si = 0; si <= fn.yield_count && si < rir::Function::kMaxResumeBlocks; si++) {
                LLVMAddCase(sw, LLVMConstInt(c.i16_ty, si, 0), c.block_map[fn.resume_blocks[si]]);
            }
        } else if (fn.state_zero_enters_entry) {
            LLVMAddCase(sw, LLVMConstInt(c.i16_ty, 0, 0), c.block_map[fn.state_zero_entry_block]);
        }

        const u32 first_prologue_yield = fn.state_zero_enters_entry ? 1 : 0;
        for (u32 si = fn.has_explicit_resume_blocks ? fn.yield_count : first_prologue_yield;
             si < fn.yield_count;
             si++) {
            char ylabel[24];
            u32 lpos = 0;
            const char* prefix = "yield_";
            while (*prefix && lpos < sizeof(ylabel) - 1) ylabel[lpos++] = *prefix++;
            // minimal itoa for single-digit state indices; slice 0 limits wait_count <= 4
            if (si < 10) {
                ylabel[lpos++] = static_cast<char>('0' + si);
            } else {
                ylabel[lpos++] = '?';
            }
            ylabel[lpos] = 0;
            LLVMBasicBlockRef yield_bb = LLVMAppendBasicBlockInContext(c.llvm_ctx, func, ylabel);
            LLVMMoveBasicBlockBefore(yield_bb, terminal_bb);
            const u32 payload = fn.yield_payload ? fn.yield_payload[si] : 0;
            u8 yield_kind = fn.yield_kinds ? fn.yield_kinds[si] : static_cast<u8>(YieldKind::Timer);
            if (yield_kind == 0) yield_kind = static_cast<u8>(YieldKind::Timer);
            LLVMPositionBuilderAtEnd(c.builder, yield_bb);
            LLVMValueRef result =
                c.make_result_yield(static_cast<u16>(si + 1), yield_kind, payload);
            // Clear the prime before suspending; the resume re-primes at entry.
            c.emit_parse_unprime();
            LLVMBuildRet(c.builder, result);
            LLVMAddCase(sw, LLVMConstInt(c.i16_ty, si, 0), yield_bb);
        }
    } else {
        LLVMPositionBuilderAtEnd(c.builder, c.block_map[fn.blocks[0].id.id]);
        c.ctx_store_sink = LLVMBuildAlloca(c.builder, c.i64_ty, "ctx.slot.store.sink");
        // Parse-once: prime the per-thread parse cache at handler entry,
        // unless the handler never reads the request.
        if (kNeedsParse) c.emit_parse_prime();
        if (kNeedsTimeUnlatch) c.emit_time_unlatch();
    }

    // Block IDs are allocation order, not SSA definition order: inlined
    // optional helpers may append a producer after their outer consumer.
    // Emit blocks only when non-spilled cross-block inputs exist. Phi incoming
    // edges are resolved separately, breaking loop-carried dependencies.
    auto* emitted = fn.block_cap <= 64 ? small_emitted : maps.arena.alloc_array<u8>(fn.block_count);
    if (!emitted) return false;
    u32 emitted_count = 0;
    while (emitted_count < fn.block_count) {
        bool progress = false;
        for (u32 i = 0; i < fn.block_count; ++i) {
            if (emitted[i]) continue;
            const auto& blk = fn.blocks[i];
            bool ready = true;
            {
                for (u32 ii = 0; ii < blk.inst_count && ready; ++ii) {
                    const auto& inst = blk.insts[ii];
                    if (inst.op == rir::Opcode::Phi) continue;
                    for (u32 oi = 0; oi < inst.operand_count; ++oi) {
                        const auto kId = inst.operand(oi);
                        if (kId == rir::kNoValue || kId.id >= fn.value_count) return false;
                        if (fn.values[kId.id].def_block.id != blk.id.id && !c.value_map[kId.id] &&
                            !(c.call_frame && c.call_frame_fields[kId.id])) {
                            ready = false;
                            break;
                        }
                    }
                }
            }
            if (c.call_frame && ready) {
                const auto* term = blk.terminator();
                const u32 edges = term && term->op == rir::Opcode::Br    ? 2u
                                  : term && term->op == rir::Opcode::Jmp ? 1u
                                                                         : 0u;
                for (u32 edge = 0; edge < edges && ready; ++edge) {
                    const auto& next = fn.blocks[term->imm.block_targets[edge].id];
                    for (u32 ii = 0; ii < next.inst_count && ready; ++ii) {
                        const auto& phi = next.insts[ii];
                        if (phi.op != rir::Opcode::Phi) continue;
                        for (u32 incoming = 0; incoming < 2; ++incoming) {
                            if (phi.imm.block_targets[incoming].id != blk.id.id) continue;
                            const auto id = phi.operands[incoming];
                            if (fn.values[id.id].def_block.id != blk.id.id && !c.value_map[id.id] &&
                                !c.call_frame_fields[id.id])
                                ready = false;
                        }
                    }
                }
            }
            if (!ready) continue;
            c.current_block = blk.id.id;
            LLVMPositionBuilderAtEnd(c.builder, c.block_map[blk.id.id]);
            for (u32 j = 0; j < blk.inst_count; ++j) {
                const auto& inst = blk.insts[j];
                if (inst.op != rir::Opcode::Phi) {
                    for (u32 oi = 0; oi < inst.operand_count; ++oi) {
                        const auto kId = inst.operand(oi);
                        if (kId == rir::kNoValue || kId.id >= fn.value_count ||
                            (!c.value_map[kId.id] &&
                             !(c.call_frame && c.call_frame_fields[kId.id])))
                            return false;
                    }
                }
                emit_instruction(c, inst);
            }
            if (!blk.terminator()) LLVMBuildUnreachable(c.builder);
            exits[blk.id.id] = LLVMGetInsertBlock(c.builder);
            emitted[i] = 1;
            ++emitted_count;
            progress = true;
        }
        if (!progress) return false;
    }
    // Resolve incoming edges after every producer and helper continuation is
    // available; RIR block IDs need not be in dependency order.
    for (u32 bi = 0; bi < fn.block_count; ++bi) {
        const auto& block = fn.blocks[bi];
        for (u32 ii = 0; ii < block.inst_count; ++ii) {
            const auto& inst = block.insts[ii];
            if (inst.op != rir::Opcode::Phi ||
                (c.call_frame && c.call_frame_fields[inst.result.id]))
                continue;
            LLVMValueRef values[] = {
                c.call_frame ? c.call_phi_incoming[static_cast<u64>(inst.result.id) * 2]
                             : c.get_value(inst.operands[0]),
                c.call_frame ? c.call_phi_incoming[static_cast<u64>(inst.result.id) * 2 + 1]
                             : c.get_value(inst.operands[1])};
            LLVMBasicBlockRef incoming[] = {exits[inst.imm.block_targets[0].id],
                                            exits[inst.imm.block_targets[1].id]};
            if (!values[0] || !values[1] || !incoming[0] || !incoming[1]) return false;
            LLVMAddIncoming(c.get_value(inst.result), values, incoming, 2);
        }
    }

    return true;
}

// ── Module Codegen ─────────────────────────────────────────────────

static CodegenResult codegen_impl(const rir::Module& rir_mod,
                                  LLVMContextRef shared_context,
                                  bool ws_body_mode,
                                  rir::VerifyResult* verification = nullptr,
                                  const rir::VerifyOptions* options = nullptr) {
    if (verification) *verification = {};
    if (options && options->environment &&
        options->environment->function_index >= rir_mod.func_count) {
        if (verification)
            *verification = rir::verify_fail({},
                                             rir::VerifyIssueCode::ConcurrentProtocolFailure,
                                             options->environment->function_index);
        return {nullptr, nullptr, false};
    }
    if (ws_body_mode && (rir_mod.func_count != 1 || !rir::verify_module(rir_mod).ok))
        return {nullptr, nullptr, false};
    // This variadic RIR operation is emitted by the trusted builder, but keep
    // direct/malformed module callers from indexing beyond its operand list.
    if (rir_mod.func_count > 0 && rir_mod.functions == nullptr) return {nullptr, nullptr, false};
    for (u32 fi = 0; fi < rir_mod.func_count; ++fi) {
        const rir::Function& fn = rir_mod.functions[fi];
        if (ws_body_mode && (fn.yield_count != 0 || fn.is_timer || rir_function_uses_parse(fn) ||
                             rir::function_uses_http_call(fn)))
            return {nullptr, nullptr, false};
        if (fn.block_count > 0 && fn.blocks == nullptr) return {nullptr, nullptr, false};
        for (u32 bi = 0; bi < fn.block_count; ++bi) {
            const rir::Block& block = fn.blocks[bi];
            if (block.inst_count > 0 && block.insts == nullptr) return {nullptr, nullptr, false};
            for (u32 ii = 0; ii < block.inst_count; ++ii) {
                const rir::Instruction& inst = block.insts[ii];
                if (!rir::valid_string_instruction(fn, inst) || !rir::valid_bytes_read(fn, inst) ||
                    !rir::valid_integer_parse(fn, inst) || !rir::valid_bytes_field(fn, inst) ||
                    !rir::valid_collected_instruction(fn, inst) ||
                    !rir::valid_bytes_construction(fn, inst))
                    return {nullptr, nullptr, false};
                if (inst.op == rir::Opcode::CacheGet || inst.op == rir::Opcode::CacheSet) {
                    const u32 kIndex = static_cast<u32>(inst.imm.i32_val);
                    if (kIndex >= rir_mod.cache_instance_count ||
                        kIndex >= rir::Module::kMaxCacheInstances)
                        return {nullptr, nullptr, false};
                    const Str kName = rir_mod.cache_instances[kIndex].name;
                    if (!kName.ptr || kName.len == 0 || kName.len > 31)
                        return {nullptr, nullptr, false};
                }
                // Neither HTTP inputs nor HTTP mutation/response effects belong
                // to an application-message invocation, including hidden helper
                // accesses. Context slots are compiler storage, not HTTP values.
                if (ws_body_mode && inst.op >= rir::Opcode::ReqHeaderCount &&
                    inst.op <= rir::Opcode::ReqSetTargetTransform &&
                    inst.op != rir::Opcode::WsMessageField &&
                    inst.op != rir::Opcode::CtxLoadSlotI32)
                    return {nullptr, nullptr, false};
                if (ws_body_mode &&
                    (inst.op == rir::Opcode::RetForward ||
                     inst.op == rir::Opcode::RetForwardBundle ||
                     inst.op == rir::Opcode::RetRedirect || inst.op == rir::Opcode::RespBody))
                    return {nullptr, nullptr, false};
                if (inst.op == rir::Opcode::WsForward || inst.op == rir::Opcode::WsClose) {
                    const bool kForward = inst.op == rir::Opcode::WsForward;
                    const auto kExactType = [&](rir::ValueId id, rir::TypeKind kind) {
                        if (id == rir::kNoValue || id.id >= fn.value_count || !fn.values)
                            return false;
                        const auto* type = fn.values[id.id].type;
                        return type && type->kind == kind && !type->inner && !type->struct_def;
                    };
                    if (!ws_body_mode || inst.operand_count != (kForward ? 1u : 2u) ||
                        inst.extra_operands || !kExactType(inst.result, rir::TypeKind::I32) ||
                        !kExactType(inst.operands[0],
                                    kForward ? rir::TypeKind::Str : rir::TypeKind::I32) ||
                        (kForward ? inst.imm.i32_val != 1 && inst.imm.i32_val != 2
                                  : !kExactType(inst.operands[1], rir::TypeKind::Str)))
                        return {nullptr, nullptr, false};
                }
                if (inst.op == rir::Opcode::WsMessageField) {
                    if (!ws_body_mode || inst.operand_count != 0 ||
                        !ws_message_field_valid(static_cast<u32>(inst.imm.i32_val)))
                        return {nullptr, nullptr, false};
                }
                if (inst.op == rir::Opcode::ReqTlsClientCertSha256) {
                    if (inst.operand_count != 0 || inst.result == rir::kNoValue ||
                        inst.result.id >= fn.value_count || fn.values == nullptr)
                        return {nullptr, nullptr, false};
                    const rir::Type* result_type = fn.values[inst.result.id].type;
                    if (result_type == nullptr || result_type->kind != rir::TypeKind::Optional ||
                        result_type->inner == nullptr ||
                        result_type->inner->kind != rir::TypeKind::Str ||
                        result_type->inner->inner != nullptr ||
                        result_type->struct_def != nullptr ||
                        result_type->inner->struct_def != nullptr)
                        return {nullptr, nullptr, false};
                }
                if (inst.op == rir::Opcode::JsonOp) {
                    const auto kJsonOp = static_cast<json::Op>(inst.imm.i32_val);
                    const bool kConsumer = kJsonOp == json::Op::ConsumerAuthenticate ||
                                           kJsonOp == json::Op::ConsumerAuthenticateQuery ||
                                           kJsonOp == json::Op::ConsumerAuthenticateForm;
                    if (kJsonOp == json::Op::OauthIntrospectionRequest ||
                        kJsonOp == json::Op::OauthIntrospectionValid ||
                        kJsonOp == json::Op::OauthClientCredentialsRequest ||
                        kJsonOp == json::Op::OauthClientCredentialsResourceRequest ||
                        kJsonOp == json::Op::OauthTokenExchangeRequest || kConsumer) {
                        const u32 kCount =
                            (kJsonOp == json::Op::OauthClientCredentialsResourceRequest ||
                             kJsonOp == json::Op::OauthTokenExchangeRequest || kConsumer)
                                ? 3u
                                : 2u;
                        if (inst.operand_count != kCount || inst.extra_operands ||
                            inst.result == rir::kNoValue || inst.result.id >= fn.value_count ||
                            !fn.values || !fn.values[inst.result.id].type)
                            return {nullptr, nullptr, false};
                        for (u32 oi = 0; oi < kCount; ++oi) {
                            const auto kId = inst.operand(oi);
                            if (kId == rir::kNoValue || kId.id >= fn.value_count ||
                                !fn.values[kId.id].type ||
                                fn.values[kId.id].type->kind != rir::TypeKind::Str ||
                                fn.values[kId.id].type->inner || fn.values[kId.id].type->struct_def)
                                return {nullptr, nullptr, false};
                        }
                        const auto* result = fn.values[inst.result.id].type;
                        if (kJsonOp == json::Op::OauthIntrospectionRequest ||
                            kJsonOp == json::Op::OauthClientCredentialsRequest ||
                            kJsonOp == json::Op::OauthClientCredentialsResourceRequest ||
                            kJsonOp == json::Op::OauthTokenExchangeRequest || kConsumer) {
                            if (result->kind != rir::TypeKind::Optional || !result->inner ||
                                result->struct_def || result->inner->kind != rir::TypeKind::Str ||
                                result->inner->inner || result->inner->struct_def)
                                return {nullptr, nullptr, false};
                        } else if (result->kind != rir::TypeKind::Bool || result->inner ||
                                   result->struct_def) {
                            return {nullptr, nullptr, false};
                        }
                    }
                    if (kJsonOp == json::Op::Sha256HexValid) {
                        if (inst.operand_count != 1 || inst.extra_operands != nullptr ||
                            inst.result == rir::kNoValue || inst.result.id >= fn.value_count ||
                            fn.values == nullptr || fn.values[inst.result.id].type == nullptr ||
                            fn.values[inst.result.id].type->kind != rir::TypeKind::Bool ||
                            fn.values[inst.result.id].type->inner != nullptr ||
                            fn.values[inst.result.id].type->struct_def != nullptr)
                            return {nullptr, nullptr, false};
                        const rir::ValueId kId = inst.operand(0);
                        if (kId == rir::kNoValue || kId.id >= fn.value_count ||
                            fn.values[kId.id].type == nullptr ||
                            fn.values[kId.id].type->kind != rir::TypeKind::Str ||
                            fn.values[kId.id].type->inner != nullptr ||
                            fn.values[kId.id].type->struct_def != nullptr)
                            return {nullptr, nullptr, false};
                    }
                    const bool kJwtIssue = kJsonOp == json::Op::JwtIssueHs256;
                    const bool kJwtIssueWithId = kJsonOp == json::Op::JwtIssueHs256WithId;
                    const bool kJwtIssueWithIdAndScope =
                        kJsonOp == json::Op::JwtIssueHs256WithIdAndScope;
                    if (kJwtIssue || kJwtIssueWithId || kJwtIssueWithIdAndScope) {
                        const u32 kExpectedCount =
                            kJwtIssueWithIdAndScope ? 7u : (kJwtIssueWithId ? 6u : 5u);
                        const u32 kStringCount =
                            kJwtIssueWithIdAndScope ? 6u : (kJwtIssueWithId ? 5u : 4u);
                        if (inst.operand_count != kExpectedCount ||
                            inst.extra_operands == nullptr || inst.result == rir::kNoValue ||
                            inst.result.id >= fn.value_count || fn.values == nullptr)
                            return {nullptr, nullptr, false};
                        const rir::Type* result = fn.values[inst.result.id].type;
                        if (result == nullptr || result->kind != rir::TypeKind::Optional ||
                            result->inner == nullptr || result->inner->kind != rir::TypeKind::Str ||
                            result->inner->inner != nullptr || result->struct_def != nullptr ||
                            result->inner->struct_def != nullptr)
                            return {nullptr, nullptr, false};
                        for (u32 oi = 0; oi < kExpectedCount; ++oi) {
                            const rir::ValueId kId = inst.operand(oi);
                            if (kId == rir::kNoValue || kId.id >= fn.value_count)
                                return {nullptr, nullptr, false};
                            const rir::Type* type = fn.values[kId.id].type;
                            const auto expected =
                                oi == kStringCount ? rir::TypeKind::I32 : rir::TypeKind::Str;
                            if (type == nullptr || type->kind != expected ||
                                type->inner != nullptr || type->struct_def != nullptr)
                                return {nullptr, nullptr, false};
                        }
                    }
                }
                if (inst.op != rir::Opcode::JwtClaimsValidWithLifetime) continue;
                if (inst.operand_count != 5 || inst.extra_operands == nullptr ||
                    inst.result == rir::kNoValue || inst.result.id >= fn.value_count ||
                    fn.values == nullptr || fn.values[inst.result.id].type == nullptr ||
                    fn.values[inst.result.id].type->kind != rir::TypeKind::Bool)
                    return {nullptr, nullptr, false};
                constexpr rir::TypeKind kOperandTypes[] = {rir::TypeKind::Str,
                                                           rir::TypeKind::Str,
                                                           rir::TypeKind::Str,
                                                           rir::TypeKind::I64,
                                                           rir::TypeKind::I64};
                for (u32 oi = 0; oi < 5; ++oi) {
                    const rir::ValueId kId = inst.operand(oi);
                    if (kId == rir::kNoValue || kId.id >= fn.value_count ||
                        fn.values[kId.id].type == nullptr ||
                        fn.values[kId.id].type->kind != kOperandTypes[oi])
                        return {nullptr, nullptr, false};
                }
            }
        }
        // Every handler must pass the state-machine verifier before LLVM can
        // emit executable code. Checking only Phi/HTTP-call functions lets a
        // plain control cycle or an unresumable wait bypass the compiler gate.
        const auto checked =
            rir::verify_function(&fn, fi, options ? *options : rir::VerifyOptions{});
        if (!checked.ok) {
            if (verification) *verification = checked;
            return {nullptr, nullptr, false};
        }
    }
    for (u32 i = 0; i < rir_mod.func_count; ++i)
        if (!rir::password_prefix_valid(rir_mod.functions[i]) ||
            !rir::http_call_profile_valid(rir_mod.functions[i]))
            return {nullptr, nullptr, false};
    static std::atomic<u32> next_regex_module_id{1};
    Ctx c{};
    c.ws_body_mode = ws_body_mode;
    c.source_module = &rir_mod;
    c.llvm_ctx = shared_context != nullptr ? shared_context : LLVMContextCreate();
    c.llvm_mod = LLVMModuleCreateWithNameInContext(
        rir_mod.name.ptr ? rir_mod.name.ptr : "rue_module", c.llvm_ctx);
    c.builder = LLVMCreateBuilderInContext(c.llvm_ctx);

    // Zero out lazy helper pointers
    c.fn_req_path = nullptr;
    c.fn_req_path_only = nullptr;
    c.fn_req_body = nullptr;
    c.fn_req_http_version = nullptr;
    c.fn_req_flag = nullptr;
    c.fn_req_method = nullptr;
    c.fn_req_unique_header = nullptr;
    c.fn_req_header = nullptr;
    c.fn_req_header_count = nullptr;
    c.fn_req_cookie = nullptr;
    c.fn_req_query = nullptr;
    c.fn_req_query_string = nullptr;
    c.fn_req_param = nullptr;
    c.fn_req_remote_addr = nullptr;
    c.fn_req_content_length = nullptr;
    c.fn_cache_get = nullptr;
    c.fn_cache_set = nullptr;
    c.fn_time_now_micros = nullptr;
    c.fn_parse_prime = nullptr;
    c.fn_parse_unprime = nullptr;
    c.fn_http_token_list_allows = nullptr;
    c.fn_bearer_matches = nullptr;
    c.fn_basic_matches = nullptr;
    c.fn_hmac_sha256_matches = nullptr;
    c.fn_standard_webhook_valid = nullptr;
    c.fn_signed_request_valid = nullptr;
    c.fn_jwt_claims_valid_with_lifetime = nullptr;
    c.fn_str_constant_time_equal = nullptr;
    c.fn_str_has_prefix = nullptr;
    c.fn_str_eq = nullptr;
    c.fn_str_cmp = nullptr;
    c.fn_str_regex_match = nullptr;
    c.fn_str_trim_prefix = nullptr;
    c.cur_fn = nullptr;
    c.type_cache_count = 0;
    c.regex_module_id = next_regex_module_id.fetch_add(1);
    c.regex_count = 0;
    c.regex_globals = nullptr;
    c.regex_global_count = 0;
    c.regex_global_cap = 0;

    c.init_types();

    // Set target triple + data layout from host
    // (LLJIT will override, but setting these helps verification)

    bool ok = true;
    for (u32 i = 0; i < rir_mod.func_count && ok; i++) {
        ok = emit_function(c, rir_mod.functions[i]);
    }

    LLVMDisposeBuilder(c.builder);
    free(c.regex_globals);

    if (!ok) {
        LLVMDisposeModule(c.llvm_mod);
        if (shared_context == nullptr) LLVMContextDispose(c.llvm_ctx);
        return {nullptr, nullptr, false};
    }

    return {c.llvm_mod, c.llvm_ctx, true};
}

CodegenResult codegen(const rir::Module& rir_mod,
                      rir::VerifyResult* verification,
                      const rir::VerifyOptions* options) {
    return codegen_impl(rir_mod, nullptr, false, verification, options);
}

CodegenResult codegen_ws_body(const rir::Module& rir_mod, LLVMContextRef shared_context) {
    return codegen_impl(rir_mod, shared_context, true);
}

u32 format_ws_handler_symbol(u32 id, char* out, u32 out_size) {
    if (!out || out_size == 0) return 0;
    static constexpr char kPrefix[] = "ws_handler_";
    u32 pos = 0;
    while (kPrefix[pos] && pos + 1 < out_size) {
        out[pos] = kPrefix[pos];
        pos++;
    }
    // Append the decimal id (digits produced in reverse, then reversed into place).
    char digits[10];
    u32 nd = 0;
    u32 v = id;
    do {
        digits[nd++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    } while (v != 0 && nd < 10);
    for (u32 i = 0; i < nd && pos + 1 < out_size; i++) out[pos++] = digits[nd - 1 - i];
    out[pos] = '\0';
    return pos;
}

u32 format_ws_callback_symbol(u32 id, WsCallbackPhase phase, char* out, u32 out_size) {
    char message[64];
    const u32 kLength = format_ws_handler_symbol(id, message, sizeof(message));
    const char* suffix = phase == WsCallbackPhase::Open    ? "_open"
                         : phase == WsCallbackPhase::Close ? "_close"
                                                           : "";
    u32 extra = 0;
    while (suffix[extra]) ++extra;
    if (!out || out_size <= kLength + extra) return 0;
    __builtin_memcpy(out, message, kLength);
    __builtin_memcpy(out + kLength, suffix, extra + 1);
    return kLength + extra;
}

bool emit_ws_body(LLVMModuleRef module,
                  LLVMContextRef context,
                  const rir::Module& body,
                  u32 handler_id,
                  WsCallbackPhase phase) {
    if (module == nullptr || context == nullptr || LLVMGetModuleContext(module) != context ||
        body.func_count != 1 || body.functions == nullptr)
        return false;
    char wrapper_name[64];
    const u32 kNameLen =
        format_ws_callback_symbol(handler_id, phase, wrapper_name, sizeof(wrapper_name));
    if (kNameLen == 0 || LLVMGetNamedFunction(module, wrapper_name) != nullptr) return false;
    char body_name[80];
    __builtin_memcpy(body_name, wrapper_name, kNameLen);
    static constexpr char kSuffix[] = "_body";
    __builtin_memcpy(body_name + kNameLen, kSuffix, sizeof(kSuffix));
    const Str kBodyName{body_name, kNameLen + static_cast<u32>(sizeof(kSuffix) - 1)};
    char body_symbol[256];
    if (format_handler_symbol(kBodyName, body_symbol, sizeof(body_symbol)) == 0 ||
        LLVMGetNamedFunction(module, body_symbol) != nullptr)
        return false;
    rir::Function function = body.functions[0];
    function.name = kBodyName;
    rir::Module isolated = body;
    isolated.functions = &function;
    auto generated = codegen_ws_body(isolated, context);
    if (!generated.ok) return false;
    // Patterns are startup metadata consumed by JitEngine, rather than IR
    // operands. The linker drops otherwise-unused private globals, so retain
    // their unique names across this link and restore private linkage afterward.
    static constexpr char kRegexPatternPrefix[] = "__rut_regex_pattern_";
    const auto kIsRegexPattern = [](LLVMValueRef global) {
        size_t size = 0;
        const char* name = LLVMGetValueName2(global, &size);
        return size >= sizeof(kRegexPatternPrefix) - 1 &&
               __builtin_memcmp(name, kRegexPatternPrefix, sizeof(kRegexPatternPrefix) - 1) == 0;
    };
    for (LLVMValueRef global = LLVMGetFirstGlobal(generated.mod); global;
         global = LLVMGetNextGlobal(global))
        if (kIsRegexPattern(global)) LLVMSetLinkage(global, LLVMExternalLinkage);
    // Linking consumes the source module on both success and failure. Its
    // context is borrowed from the destination throughout.
    if (LLVMLinkModules2(module, generated.mod) != 0) return false;
    for (LLVMValueRef global = LLVMGetFirstGlobal(module); global;
         global = LLVMGetNextGlobal(global))
        if (kIsRegexPattern(global)) LLVMSetLinkage(global, LLVMPrivateLinkage);
    LLVMValueRef callee = LLVMGetNamedFunction(module, body_symbol);
    if (callee == nullptr) return false;

    LLVMTypeRef ptr_ty = LLVMPointerTypeInContext(context, 0);
    LLVMTypeRef i8_ty = LLVMInt8TypeInContext(context);
    LLVMTypeRef i32_ty = LLVMInt32TypeInContext(context);
    LLVMTypeRef i64_ty = LLVMInt64TypeInContext(context);
    LLVMTypeRef wrapper_params[] = {ptr_ty, i8_ty, ptr_ty, i64_ty, i8_ty};
    LLVMTypeRef wrapper_type = LLVMFunctionType(i8_ty, wrapper_params, 5, 0);
    LLVMValueRef wrapper = LLVMAddFunction(module, wrapper_name, wrapper_type);
    LLVMBuilderRef builder = LLVMCreateBuilderInContext(context);
    if (builder == nullptr) return false;
    LLVMBasicBlockRef entry = LLVMAppendBasicBlockInContext(context, wrapper, "entry");
    LLVMBasicBlockRef evaluate = LLVMAppendBasicBlockInContext(context, wrapper, "evaluate");
    LLVMBasicBlockRef invalid = LLVMAppendBasicBlockInContext(context, wrapper, "invalid");
    LLVMPositionBuilderAtEnd(builder, entry);
    LLVMValueRef conn = LLVMGetParam(wrapper, 0);
    LLVMValueRef opcode = LLVMGetParam(wrapper, 1);
    LLVMValueRef payload = LLVMGetParam(wrapper, 2);
    LLVMValueRef length = LLVMGetParam(wrapper, 3);
    LLVMValueRef from_client = LLVMGetParam(wrapper, 4);
    LLVMValueRef is_text = LLVMBuildICmp(builder,
                                         LLVMIntEQ,
                                         opcode,
                                         LLVMConstInt(i8_ty, static_cast<u8>(WsOpcode::Text), 0),
                                         "text");
    LLVMValueRef is_binary =
        LLVMBuildICmp(builder,
                      LLVMIntEQ,
                      opcode,
                      LLVMConstInt(i8_ty, static_cast<u8>(WsOpcode::Binary), 0),
                      "binary");
    LLVMValueRef kind_ok = LLVMBuildOr(builder, is_text, is_binary, "kind.ok");
    LLVMValueRef length_ok = LLVMBuildICmp(
        builder, LLVMIntULE, length, LLVMConstInt(i64_ty, 0x7fffffffu, 0), "length.ok");
    LLVMValueRef empty =
        LLVMBuildICmp(builder, LLVMIntEQ, length, LLVMConstInt(i64_ty, 0, 0), "empty");
    LLVMValueRef nonnull =
        LLVMBuildICmp(builder, LLVMIntNE, payload, LLVMConstNull(ptr_ty), "nonnull");
    LLVMValueRef data_ok = LLVMBuildOr(builder, empty, nonnull, "data.ok");
    LLVMValueRef valid = LLVMBuildAnd(
        builder, kind_ok, LLVMBuildAnd(builder, length_ok, data_ok, "size.ok"), "input.ok");
    LLVMBuildCondBr(builder, valid, evaluate, invalid);
    LLVMPositionBuilderAtEnd(builder, invalid);
    LLVMBuildRet(builder, LLVMConstInt(i8_ty, static_cast<u8>(WsFrameAction::Close), 0));
    LLVMPositionBuilderAtEnd(builder, evaluate);
    LLVMValueRef zero_byte = LLVMGetNamedGlobal(module, "__rut_ws_empty");
    if (zero_byte == nullptr) {
        zero_byte = LLVMAddGlobal(module, i8_ty, "__rut_ws_empty");
        LLVMSetInitializer(zero_byte, LLVMConstInt(i8_ty, 0, 0));
        LLVMSetGlobalConstant(zero_byte, 1);
        LLVMSetLinkage(zero_byte, LLVMPrivateLinkage);
    }
    LLVMValueRef safe_payload = LLVMBuildSelect(builder, nonnull, payload, zero_byte, "payload");
    LLVMTypeRef frame_type = LLVMArrayType(i8_ty, sizeof(HandlerCtx));
    LLVMValueRef frame = LLVMBuildAlloca(builder, frame_type, "message.ctx");
    LLVMSetAlignment(frame, alignof(HandlerCtx));
    LLVMBuildMemSet(builder,
                    frame,
                    LLVMConstInt(i8_ty, 0, 0),
                    LLVMConstInt(i64_ty, sizeof(HandlerCtx), 0),
                    alignof(HandlerCtx));
    LLVMTypeRef begin_params[] = {ptr_ty};
    LLVMTypeRef begin_type = LLVMFunctionType(LLVMVoidTypeInContext(context), begin_params, 1, 0);
    LLVMValueRef begin = LLVMGetNamedFunction(module, "rut_helper_ws_begin_message");
    if (begin == nullptr)
        begin = LLVMAddFunction(module, "rut_helper_ws_begin_message", begin_type);
    LLVMValueRef begin_args[] = {conn};
    LLVMBuildCall2(builder, begin_type, begin, begin_args, 1, "");
    LLVMValueRef args[] = {conn,
                           frame,
                           safe_payload,
                           LLVMBuildTrunc(builder, length, i32_ty, "length"),
                           LLVMConstNull(ptr_ty),
                           opcode,
                           from_client};
    LLVMValueRef result =
        LLVMBuildCall2(builder, LLVMGlobalGetValueType(callee), callee, args, 7, "decision");
    LLVMValueRef action = LLVMBuildAnd(builder, result, LLVMConstInt(i64_ty, 0xffu, 0), "action");
    LLVMValueRef action_ok =
        LLVMBuildICmp(builder,
                      LLVMIntEQ,
                      action,
                      LLVMConstInt(i64_ty, static_cast<u8>(HandlerAction::ReturnStatus), 0),
                      "action.ok");
    LLVMValueRef extra = LLVMBuildAnd(
        builder, result, LLVMConstInt(i64_ty, ~static_cast<u64>(0xffffffu), 0), "extra");
    LLVMValueRef extra_ok =
        LLVMBuildICmp(builder, LLVMIntEQ, extra, LLVMConstInt(i64_ty, 0, 0), "extra.ok");
    LLVMValueRef verdict =
        LLVMBuildAnd(builder,
                     LLVMBuildLShr(builder, result, LLVMConstInt(i64_ty, 8, 0), "status"),
                     LLVMConstInt(i64_ty, 0xffffu, 0),
                     "verdict");
    LLVMValueRef verdict_ok =
        LLVMBuildICmp(builder,
                      LLVMIntULE,
                      verdict,
                      LLVMConstInt(i64_ty, static_cast<u8>(WsFrameAction::CloseDynamic), 0),
                      "verdict.ok");
    LLVMValueRef output_ok = LLVMBuildAnd(
        builder, action_ok, LLVMBuildAnd(builder, extra_ok, verdict_ok, "value.ok"), "output.ok");
    LLVMValueRef selected =
        LLVMBuildSelect(builder,
                        output_ok,
                        LLVMBuildTrunc(builder, verdict, i8_ty, "verdict.byte"),
                        LLVMConstInt(i8_ty, static_cast<u8>(WsFrameAction::Close), 0),
                        "output");
    LLVMBuildRet(builder, selected);
    LLVMDisposeBuilder(builder);
    return true;
}

bool emit_ws_handler(LLVMModuleRef mod,
                     LLVMContextRef ctx,
                     u8 default_verdict,
                     const WsLenGuardSpec* guards,
                     u32 guard_count,
                     u32 id) {
    if (!mod || !ctx || default_verdict > 11 || guard_count > WsLenGuardSpec::kMaxConditions ||
        (guard_count != 0 && !guards))
        return false;
    // A bounded forest, in postorder: every operand has exactly one parent. Validate
    // before recursive emission so malformed specs cannot create cycles or code expansion.
    u8 parents[WsLenGuardSpec::kMaxConditions]{};
    u32 sequential_roots = 0;
    for (u32 i = 0; i < guard_count; i++) {
        if (guards[i].accessor > 37 || guards[i].cmp > 2 || guards[i].verdict == 3 ||
            guards[i].verdict > 11)
            return false;
        if ((guards[i].accessor == 11 || (guards[i].accessor >= 12 && guards[i].accessor <= 34) ||
             guards[i].accessor == 3 || (guards[i].accessor >= 6 && guards[i].accessor <= 9)) &&
            guards[i].pattern_len != 0 && !guards[i].pattern)
            return false;
        if (((guards[i].accessor >= 13 && guards[i].accessor <= 16) || guards[i].accessor == 21 ||
             (guards[i].accessor >= 25 && guards[i].accessor <= 28) ||
             (guards[i].accessor >= 30 && guards[i].accessor <= 33)) &&
            guards[i].value_len != 0 && !guards[i].value)
            return false;
        if (guards[i].accessor == 34 && (!guards[i].value || guards[i].value_len == 0))
            return false;
        if ((guards[i].accessor == 24 || guards[i].accessor == 29) && guards[i].value_len != 0)
            return false;
        if (guards[i].accessor == 18 && guards[i].bound > 1) return false;
        if (guards[i].accessor == 35 && guards[i].bound > 1) return false;
        if (guards[i].accessor == 23 &&
            (guards[i].int_bound < -2147483648LL || guards[i].int_bound > 2147483647LL))
            return false;
        if (guards[i].accessor == 4 || guards[i].accessor == 5 || guards[i].accessor == 36 ||
            guards[i].accessor == 37) {
            const u32 kChildren[3] = {guards[i].lhs, guards[i].rhs, guards[i].bound};
            const u32 kCount = guards[i].accessor == 37 ? 3u : 2u;
            for (u32 j = 0; j < kCount; ++j) {
                const u32 kChild = kChildren[j];
                if (kChild >= i || !guards[kChild].is_operand || ++parents[kChild] != 1)
                    return false;
            }
        }
        // Source clauses remain bounded by the frontend. Explicit forward roots
        // also represent specialized value alternatives within those clauses.
        if (!guards[i].is_operand && guards[i].pass_target == kWsControlNext &&
            guards[i].fail_target == kWsControlNext &&
            ++sequential_roots > WsLenGuardSpec::kMaxGuards)
            return false;
    }
    for (u32 i = 0; i < guard_count; i++) {
        if (guards[i].is_operand && parents[i] != 1) return false;
        const u32 kTargets[2] = {guards[i].pass_target, guards[i].fail_target};
        for (const u32 kTargetValue : kTargets) {
            if (kTargetValue == kWsControlNext) continue;
            if (guards[i].is_operand) return false;
            if (kTargetValue == kWsControlDefault) continue;
            if (ws_control_is_return(kTargetValue)) {
                const u32 kAction = ws_control_value(kTargetValue);
                if (kAction == 3 || kAction > 11) return false;
            } else if (ws_control_is_after(kTargetValue)) {
                const u32 kBoundary = ws_control_value(kTargetValue);
                if (kBoundary <= i || kBoundary > guard_count) return false;
            } else if (kTargetValue <= i || kTargetValue >= guard_count ||
                       guards[kTargetValue].is_operand) {
                return false;
            }
        }
    }
    LLVMTypeRef i8_ty = LLVMInt8TypeInContext(ctx);
    LLVMTypeRef i64_ty = LLVMInt64TypeInContext(ctx);
    LLVMTypeRef ptr_ty = LLVMPointerTypeInContext(ctx, 0);
    // (ctx, opcode, payload, len, from_client) -> verdict, matching WsMessageHandlerFn's C ABI.
    LLVMTypeRef params[5] = {ptr_ty, i8_ty, ptr_ty, i64_ty, i8_ty};
    LLVMTypeRef fn_ty = LLVMFunctionType(i8_ty, params, 5, 0);

    char sym[64];
    format_ws_handler_symbol(id, sym, sizeof(sym));
    LLVMValueRef fn = LLVMAddFunction(mod, sym, fn_ty);
    if (!fn) return false;
    LLVMTypeRef i32_ty = LLVMInt32TypeInContext(ctx);
    LLVMValueRef len = LLVMGetParam(fn, 3);          // i64 message length == message.len
    LLVMValueRef opcode = LLVMGetParam(fn, 1);       // i8 internal WsOpcode for the message type
    LLVMValueRef payload = LLVMGetParam(fn, 2);      // i8* reassembled message bytes
    LLVMValueRef from_client = LLVMGetParam(fn, 4);  // i8 bool: 1 on the client→upstream leg

    LLVMBasicBlockRef entry = LLVMAppendBasicBlockInContext(ctx, fn, "entry");
    LLVMBuilderRef builder = LLVMCreateBuilderInContext(ctx);
    if (!builder) return false;
    LLVMPositionBuilderAtEnd(builder, entry);

    // u8 tri-state regex helper(ptr payload, i32 len, ptr db);
    // get-or-declare so we don't duplicate a decl the HTTP codegen already put in this module.
    LLVMTypeRef rx_params[3] = {ptr_ty, i32_ty, ptr_ty};
    LLVMTypeRef rx_fn_ty = LLVMFunctionType(i8_ty, rx_params, 3, 0);
    u32 regex_seq = 0;

    // Emit branches rather than eager boolean operations: RHS regex scans must not run
    // when the left operand already determines the result.
    auto emit_condition =
        [&](auto&& self, u32 i, LLVMBasicBlockRef yes, LLVMBasicBlockRef no) -> void {
        if (guards[i].negate) {
            LLVMBasicBlockRef tmp = yes;
            yes = no;
            no = tmp;
        }
        if (guards[i].accessor == 37) {
            LLVMBasicBlockRef then_block = LLVMAppendBasicBlockInContext(ctx, fn, "select.then");
            LLVMBasicBlockRef else_block = LLVMAppendBasicBlockInContext(ctx, fn, "select.else");
            self(self, guards[i].bound, then_block, else_block);
            LLVMPositionBuilderAtEnd(builder, then_block);
            self(self, guards[i].lhs, yes, no);
            LLVMPositionBuilderAtEnd(builder, else_block);
            self(self, guards[i].rhs, yes, no);
            return;
        }
        if (guards[i].accessor == 36) {
            // Equality evaluates both operands once. Keep the LHS value in SSA
            // while emitting the RHS, including its own short-circuit branches.
            LLVMBasicBlockRef left_yes = LLVMAppendBasicBlockInContext(ctx, fn, "eq.left.yes");
            LLVMBasicBlockRef left_no = LLVMAppendBasicBlockInContext(ctx, fn, "eq.left.no");
            LLVMBasicBlockRef left_done = LLVMAppendBasicBlockInContext(ctx, fn, "eq.left.done");
            self(self, guards[i].lhs, left_yes, left_no);
            LLVMPositionBuilderAtEnd(builder, left_yes);
            LLVMBuildBr(builder, left_done);
            LLVMPositionBuilderAtEnd(builder, left_no);
            LLVMBuildBr(builder, left_done);
            LLVMPositionBuilderAtEnd(builder, left_done);
            LLVMTypeRef bool_ty = LLVMInt1TypeInContext(ctx);
            LLVMValueRef left = LLVMBuildPhi(builder, bool_ty, "eq.left");
            LLVMValueRef values[2] = {LLVMConstInt(bool_ty, 1, 0), LLVMConstInt(bool_ty, 0, 0)};
            LLVMBasicBlockRef blocks[2] = {left_yes, left_no};
            LLVMAddIncoming(left, values, blocks, 2);
            LLVMBasicBlockRef right_yes = LLVMAppendBasicBlockInContext(ctx, fn, "eq.right.yes");
            LLVMBasicBlockRef right_no = LLVMAppendBasicBlockInContext(ctx, fn, "eq.right.no");
            self(self, guards[i].rhs, right_yes, right_no);
            LLVMPositionBuilderAtEnd(builder, right_yes);
            LLVMBuildCondBr(builder, left, yes, no);
            LLVMPositionBuilderAtEnd(builder, right_no);
            LLVMBuildCondBr(builder, left, no, yes);
            return;
        }
        if (guards[i].accessor == 4 || guards[i].accessor == 5) {
            LLVMBasicBlockRef rhs = LLVMAppendBasicBlockInContext(ctx, fn, "guard.rhs");
            if (guards[i].accessor == 4)
                self(self, guards[i].lhs, rhs, no);
            else
                self(self, guards[i].lhs, yes, rhs);
            LLVMPositionBuilderAtEnd(builder, rhs);
            self(self, guards[i].rhs, yes, no);
            return;
        }
        LLVMValueRef cond;
        if (guards[i].accessor == 35) {
            cond = LLVMConstInt(LLVMInt1TypeInContext(ctx), guards[i].bound, 0);
        } else if (guards[i].accessor == 11) {  // JsonHasPath: presence includes a JSON null node.
            LLVMTypeRef json_params[4] = {ptr_ty, i64_ty, ptr_ty, i32_ty};
            LLVMTypeRef json_ty = LLVMFunctionType(i8_ty, json_params, 4, 0);
            LLVMValueRef json_fn = LLVMGetNamedFunction(mod, "rut_helper_ws_json_has_path");
            if (!json_fn) json_fn = LLVMAddFunction(mod, "rut_helper_ws_json_has_path", json_ty);
            LLVMValueRef path = LLVMBuildGlobalStringPtr(builder, "", "json.root");
            if (guards[i].pattern_len) {
                LLVMValueRef bytes =
                    LLVMConstStringInContext(ctx, guards[i].pattern, guards[i].pattern_len, 1);
                path = LLVMAddGlobal(mod, LLVMTypeOf(bytes), "json.path");
                LLVMSetInitializer(path, bytes);
                LLVMSetGlobalConstant(path, 1);
                LLVMSetLinkage(path, LLVMPrivateLinkage);
                LLVMSetUnnamedAddress(path, LLVMGlobalUnnamedAddr);
            }
            LLVMValueRef args[4] = {
                payload, len, path, LLVMConstInt(i32_ty, guards[i].pattern_len, 0)};
            LLVMValueRef present =
                LLVMBuildCall2(builder, json_ty, json_fn, args, 4, "json.present");
            cond = LLVMBuildICmp(
                builder, LLVMIntNE, present, LLVMConstInt(i8_ty, 0, 0), "json.has.path");
        } else if (guards[i].accessor == 10) {  // JsonValid: bounded syntax validation only.
            LLVMTypeRef json_params[2] = {ptr_ty, i64_ty};
            LLVMTypeRef json_ty = LLVMFunctionType(i8_ty, json_params, 2, 0);
            LLVMValueRef json_fn = LLVMGetNamedFunction(mod, "rut_helper_ws_json_valid");
            if (!json_fn) json_fn = LLVMAddFunction(mod, "rut_helper_ws_json_valid", json_ty);
            LLVMValueRef args[2] = {payload, len};
            LLVMValueRef valid = LLVMBuildCall2(builder, json_ty, json_fn, args, 2, "json.valid");
            cond = LLVMBuildICmp(builder, LLVMIntNE, valid, LLVMConstInt(i8_ty, 0, 0), "json.ok");
        } else if (guards[i].accessor >= 12 && guards[i].accessor <= 16) {
            const bool valid_only = guards[i].accessor == 12;
            const bool equals = guards[i].accessor == 13;
            const bool match = guards[i].accessor >= 14;
            LLVMTypeRef json_params[6] = {ptr_ty, i64_ty, ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef match_params[7] = {ptr_ty, i64_ty, ptr_ty, i32_ty, ptr_ty, i32_ty, i8_ty};
            LLVMTypeRef json_ty = LLVMFunctionType(
                i8_ty, match ? match_params : json_params, match ? 7 : (equals ? 6 : 4), 0);
            const char* helper = valid_only ? "rut_helper_ws_json_string_at_path"
                                 : equals   ? "rut_helper_ws_json_string_equals_at_path"
                                            : "rut_helper_ws_json_string_matches_at_path";
            LLVMValueRef json_fn = LLVMGetNamedFunction(mod, helper);
            if (!json_fn) json_fn = LLVMAddFunction(mod, helper, json_ty);
            auto bytes_global = [&](const char* value, u32 size, const char* name) {
                LLVMValueRef initializer =
                    LLVMConstStringInContext(ctx, value ? value : "", size, 1);
                LLVMValueRef global = LLVMAddGlobal(mod, LLVMTypeOf(initializer), name);
                LLVMSetInitializer(global, initializer);
                LLVMSetGlobalConstant(global, 1);
                LLVMSetLinkage(global, LLVMPrivateLinkage);
                LLVMSetUnnamedAddress(global, LLVMGlobalUnnamedAddr);
                return global;
            };
            LLVMValueRef path =
                bytes_global(guards[i].pattern,
                             guards[i].pattern_len,
                             equals ? "json.string.equal.path" : "json.string.valid.path");
            LLVMValueRef args[7] = {payload,
                                    len,
                                    path,
                                    LLVMConstInt(i32_ty, guards[i].pattern_len, 0),
                                    nullptr,
                                    nullptr,
                                    nullptr};
            if (!valid_only) {
                args[4] =
                    bytes_global(guards[i].value, guards[i].value_len, "json.string.expected");
                args[5] = LLVMConstInt(i32_ty, guards[i].value_len, 0);
            }
            if (match) args[6] = LLVMConstInt(i8_ty, guards[i].accessor - 13, 0);
            LLVMValueRef valid = LLVMBuildCall2(
                builder, json_ty, json_fn, args, match ? 7 : (equals ? 6 : 4), "json.string");
            cond = LLVMBuildICmp(
                builder, LLVMIntNE, valid, LLVMConstInt(i8_ty, 0, 0), "json.string.matches");
        } else if (guards[i].accessor == 17 || guards[i].accessor == 18) {
            const bool equals = guards[i].accessor == 18;
            LLVMTypeRef bool_params[4] = {ptr_ty, i64_ty, ptr_ty, i32_ty};
            LLVMTypeRef equals_params[5] = {ptr_ty, i64_ty, ptr_ty, i32_ty, i8_ty};
            LLVMTypeRef bool_ty =
                LLVMFunctionType(i8_ty, equals ? equals_params : bool_params, equals ? 5 : 4, 0);
            const char* helper = equals ? "rut_helper_ws_json_bool_equals_at_path"
                                        : "rut_helper_ws_json_bool_at_path";
            LLVMValueRef bool_fn = LLVMGetNamedFunction(mod, helper);
            if (!bool_fn) bool_fn = LLVMAddFunction(mod, helper, bool_ty);
            LLVMValueRef path = LLVMConstStringInContext(
                ctx, guards[i].pattern ? guards[i].pattern : "", guards[i].pattern_len, 1);
            LLVMValueRef path_global = LLVMAddGlobal(mod, LLVMTypeOf(path), "json.bool.path");
            LLVMSetInitializer(path_global, path);
            LLVMSetGlobalConstant(path_global, 1);
            LLVMSetLinkage(path_global, LLVMPrivateLinkage);
            LLVMSetUnnamedAddress(path_global, LLVMGlobalUnnamedAddr);
            LLVMValueRef args[5] = {payload,
                                    len,
                                    path_global,
                                    LLVMConstInt(i32_ty, guards[i].pattern_len, 0),
                                    LLVMConstInt(i8_ty, guards[i].bound, 0)};
            LLVMValueRef valid =
                LLVMBuildCall2(builder, bool_ty, bool_fn, args, equals ? 5 : 4, "json.bool");
            cond = LLVMBuildICmp(
                builder, LLVMIntNE, valid, LLVMConstInt(i8_ty, 0, 0), "json.bool.matches");
        } else if (guards[i].accessor == 19 || guards[i].accessor == 20) {
            const bool compare = guards[i].accessor == 20;
            LLVMTypeRef int_params[4] = {ptr_ty, i64_ty, ptr_ty, i32_ty};
            LLVMTypeRef compare_params[6] = {ptr_ty, i64_ty, ptr_ty, i32_ty, i64_ty, i8_ty};
            LLVMTypeRef int_ty =
                LLVMFunctionType(i8_ty, compare ? compare_params : int_params, compare ? 6 : 4, 0);
            const char* helper = compare ? "rut_helper_ws_json_int_compare_at_path"
                                         : "rut_helper_ws_json_int_at_path";
            LLVMValueRef int_fn = LLVMGetNamedFunction(mod, helper);
            if (!int_fn) int_fn = LLVMAddFunction(mod, helper, int_ty);
            LLVMValueRef path = LLVMConstStringInContext(
                ctx, guards[i].pattern ? guards[i].pattern : "", guards[i].pattern_len, 1);
            LLVMValueRef path_global = LLVMAddGlobal(mod, LLVMTypeOf(path), "json.int.path");
            LLVMSetInitializer(path_global, path);
            LLVMSetGlobalConstant(path_global, 1);
            LLVMSetLinkage(path_global, LLVMPrivateLinkage);
            LLVMSetUnnamedAddress(path_global, LLVMGlobalUnnamedAddr);
            LLVMValueRef args[6] = {payload,
                                    len,
                                    path_global,
                                    LLVMConstInt(i32_ty, guards[i].pattern_len, 0),
                                    LLVMConstInt(i64_ty, static_cast<u64>(guards[i].int_bound), 0),
                                    LLVMConstInt(i8_ty, guards[i].cmp, 0)};
            LLVMValueRef valid =
                LLVMBuildCall2(builder, int_ty, int_fn, args, compare ? 6 : 4, "json.int");
            cond = LLVMBuildICmp(
                builder, LLVMIntNE, valid, LLVMConstInt(i8_ty, 0, 0), "json.int.matches");
        } else if (guards[i].accessor == 21) {
            LLVMTypeRef kind_params[6] = {ptr_ty, i64_ty, ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef kind_ty = LLVMFunctionType(i8_ty, kind_params, 6, 0);
            LLVMValueRef kind_fn =
                LLVMGetNamedFunction(mod, "rut_helper_ws_json_kind_equals_at_path");
            if (!kind_fn)
                kind_fn = LLVMAddFunction(mod, "rut_helper_ws_json_kind_equals_at_path", kind_ty);
            auto bytes_global = [&](const char* bytes, u32 size, const char* name) {
                LLVMValueRef initializer =
                    LLVMConstStringInContext(ctx, bytes ? bytes : "", size, 1);
                LLVMValueRef global = LLVMAddGlobal(mod, LLVMTypeOf(initializer), name);
                LLVMSetInitializer(global, initializer);
                LLVMSetGlobalConstant(global, 1);
                LLVMSetLinkage(global, LLVMPrivateLinkage);
                LLVMSetUnnamedAddress(global, LLVMGlobalUnnamedAddr);
                return global;
            };
            LLVMValueRef path =
                bytes_global(guards[i].pattern, guards[i].pattern_len, "json.kind.path");
            LLVMValueRef expected = bytes_global(guards[i].value, guards[i].value_len, "json.kind");
            LLVMValueRef args[6] = {payload,
                                    len,
                                    path,
                                    LLVMConstInt(i32_ty, guards[i].pattern_len, 0),
                                    expected,
                                    LLVMConstInt(i32_ty, guards[i].value_len, 0)};
            LLVMValueRef valid = LLVMBuildCall2(builder, kind_ty, kind_fn, args, 6, "json.kind");
            cond = LLVMBuildICmp(
                builder, LLVMIntNE, valid, LLVMConstInt(i8_ty, 0, 0), "json.kind.matches");
        } else if (guards[i].accessor == 22 || guards[i].accessor == 23) {
            const bool compare = guards[i].accessor == 23;
            LLVMTypeRef count_params[4] = {ptr_ty, i64_ty, ptr_ty, i32_ty};
            LLVMTypeRef compare_params[6] = {ptr_ty, i64_ty, ptr_ty, i32_ty, i32_ty, i8_ty};
            LLVMTypeRef count_ty = LLVMFunctionType(
                i8_ty, compare ? compare_params : count_params, compare ? 6 : 4, 0);
            const char* helper = compare ? "rut_helper_ws_json_count_compare_at_path"
                                         : "rut_helper_ws_json_count_at_path";
            LLVMValueRef count_fn = LLVMGetNamedFunction(mod, helper);
            if (!count_fn) count_fn = LLVMAddFunction(mod, helper, count_ty);
            LLVMValueRef path = LLVMConstStringInContext(
                ctx, guards[i].pattern ? guards[i].pattern : "", guards[i].pattern_len, 1);
            LLVMValueRef path_global = LLVMAddGlobal(mod, LLVMTypeOf(path), "json.count.path");
            LLVMSetInitializer(path_global, path);
            LLVMSetGlobalConstant(path_global, 1);
            LLVMSetLinkage(path_global, LLVMPrivateLinkage);
            LLVMSetUnnamedAddress(path_global, LLVMGlobalUnnamedAddr);
            LLVMValueRef args[6] = {payload,
                                    len,
                                    path_global,
                                    LLVMConstInt(i32_ty, guards[i].pattern_len, 0),
                                    LLVMConstInt(i32_ty, static_cast<u32>(guards[i].int_bound), 0),
                                    LLVMConstInt(i8_ty, guards[i].cmp, 0)};
            LLVMValueRef valid =
                LLVMBuildCall2(builder, count_ty, count_fn, args, compare ? 6 : 4, "json.count");
            cond = LLVMBuildICmp(
                builder, LLVMIntNE, valid, LLVMConstInt(i8_ty, 0, 0), "json.count.matches");
        } else if (guards[i].accessor >= 24 && guards[i].accessor <= 28) {
            const bool kValidOnly = guards[i].accessor == 24;
            LLVMTypeRef params[7] = {ptr_ty, i64_ty, ptr_ty, i32_ty, ptr_ty, i32_ty, i8_ty};
            LLVMTypeRef valid_params[4] = {ptr_ty, i64_ty, ptr_ty, i32_ty};
            LLVMTypeRef ty =
                LLVMFunctionType(i8_ty, kValidOnly ? valid_params : params, kValidOnly ? 4 : 7, 0);
            const char* helper = kValidOnly ? "rut_helper_ws_json_number_text_at_path"
                                            : "rut_helper_ws_json_number_text_matches_at_path";
            LLVMValueRef fn = LLVMGetNamedFunction(mod, helper);
            if (!fn) fn = LLVMAddFunction(mod, helper, ty);
            LLVMValueRef path = LLVMConstStringInContext(
                ctx, guards[i].pattern ? guards[i].pattern : "", guards[i].pattern_len, 1);
            LLVMValueRef path_global =
                LLVMAddGlobal(mod, LLVMTypeOf(path), "json.number_text.path");
            LLVMSetInitializer(path_global, path);
            LLVMSetGlobalConstant(path_global, 1);
            LLVMSetLinkage(path_global, LLVMPrivateLinkage);
            LLVMSetUnnamedAddress(path_global, LLVMGlobalUnnamedAddr);
            LLVMValueRef args[7] = {payload,
                                    len,
                                    path_global,
                                    LLVMConstInt(i32_ty, guards[i].pattern_len, 0),
                                    nullptr,
                                    nullptr,
                                    nullptr};
            if (!kValidOnly) {
                LLVMValueRef expected = LLVMConstStringInContext(
                    ctx, guards[i].value ? guards[i].value : "", guards[i].value_len, 1);
                LLVMValueRef expected_global =
                    LLVMAddGlobal(mod, LLVMTypeOf(expected), "json.number_text.expected");
                LLVMSetInitializer(expected_global, expected);
                LLVMSetGlobalConstant(expected_global, 1);
                LLVMSetLinkage(expected_global, LLVMPrivateLinkage);
                LLVMSetUnnamedAddress(expected_global, LLVMGlobalUnnamedAddr);
                args[4] = expected_global;
                args[5] = LLVMConstInt(i32_ty, guards[i].value_len, 0);
                args[6] = LLVMConstInt(i8_ty, guards[i].accessor - 25, 0);
            }
            LLVMValueRef result =
                LLVMBuildCall2(builder, ty, fn, args, kValidOnly ? 4 : 7, "json.number_text");
            cond = LLVMBuildICmp(
                builder, LLVMIntNE, result, LLVMConstInt(i8_ty, 0, 0), "json.number_text.matches");
        } else if (guards[i].accessor >= 29 && guards[i].accessor <= 33) {
            const bool kValidOnly = guards[i].accessor == 29;
            LLVMTypeRef params[7] = {ptr_ty, i64_ty, ptr_ty, i32_ty, ptr_ty, i32_ty, i8_ty};
            LLVMTypeRef valid_params[4] = {ptr_ty, i64_ty, ptr_ty, i32_ty};
            LLVMTypeRef ty =
                LLVMFunctionType(i8_ty, kValidOnly ? valid_params : params, kValidOnly ? 4 : 7, 0);
            const char* helper = kValidOnly ? "rut_helper_ws_json_stringify_at_path"
                                            : "rut_helper_ws_json_stringify_matches_at_path";
            LLVMValueRef fn = LLVMGetNamedFunction(mod, helper);
            if (!fn) fn = LLVMAddFunction(mod, helper, ty);
            LLVMValueRef path = LLVMConstStringInContext(
                ctx, guards[i].pattern ? guards[i].pattern : "", guards[i].pattern_len, 1);
            LLVMValueRef path_global = LLVMAddGlobal(mod, LLVMTypeOf(path), "json.stringify.path");
            LLVMSetInitializer(path_global, path);
            LLVMSetGlobalConstant(path_global, 1);
            LLVMSetLinkage(path_global, LLVMPrivateLinkage);
            LLVMSetUnnamedAddress(path_global, LLVMGlobalUnnamedAddr);
            LLVMValueRef args[7] = {payload,
                                    len,
                                    path_global,
                                    LLVMConstInt(i32_ty, guards[i].pattern_len, 0),
                                    nullptr,
                                    nullptr,
                                    nullptr};
            if (!kValidOnly) {
                LLVMValueRef expected = LLVMConstStringInContext(
                    ctx, guards[i].value ? guards[i].value : "", guards[i].value_len, 1);
                LLVMValueRef expected_global =
                    LLVMAddGlobal(mod, LLVMTypeOf(expected), "json.stringify.expected");
                LLVMSetInitializer(expected_global, expected);
                LLVMSetGlobalConstant(expected_global, 1);
                LLVMSetLinkage(expected_global, LLVMPrivateLinkage);
                LLVMSetUnnamedAddress(expected_global, LLVMGlobalUnnamedAddr);
                args[4] = expected_global;
                args[5] = LLVMConstInt(i32_ty, guards[i].value_len, 0);
                args[6] = LLVMConstInt(i8_ty, guards[i].accessor - 30, 0);
            }
            LLVMValueRef result =
                LLVMBuildCall2(builder, ty, fn, args, kValidOnly ? 4 : 7, "json.stringify");
            cond = LLVMBuildICmp(
                builder, LLVMIntNE, result, LLVMConstInt(i8_ty, 0, 0), "json.stringify.matches");
        } else if (guards[i].accessor == 3 || guards[i].accessor == 34) {
            const bool kJsonString = guards[i].accessor == 34;
            const char* pattern = kJsonString ? guards[i].value : guards[i].pattern;
            const u32 kPatternLen = kJsonString ? guards[i].value_len : guards[i].pattern_len;
            // Emit the pattern + db globals JIT finalization compiles & back-patches. The `ws<id>`
            // suffix keeps these distinct from the HTTP regex globals already in this module.
            char pat_name[96];
            char db_name[96];
            snprintf(pat_name, sizeof(pat_name), "__rut_regex_pattern_ws%u_%u", id, regex_seq);
            snprintf(db_name, sizeof(db_name), "__rut_regex_db_ws%u_%u", id, regex_seq);
            regex_seq++;
            LLVMValueRef str_const =
                LLVMConstStringInContext(ctx, pattern, kPatternLen, /*DontNullTerminate=*/0);
            LLVMValueRef pat_global = LLVMAddGlobal(mod, LLVMTypeOf(str_const), pat_name);
            LLVMSetInitializer(pat_global, str_const);
            LLVMSetGlobalConstant(pat_global, 1);
            LLVMSetLinkage(pat_global, LLVMPrivateLinkage);
            LLVMSetUnnamedAddress(pat_global, LLVMGlobalUnnamedAddr);
            LLVMValueRef db_global = LLVMAddGlobal(mod, ptr_ty, db_name);
            LLVMSetLinkage(db_global, LLVMExternalLinkage);

            LLVMValueRef db = LLVMBuildLoad2(builder, ptr_ty, db_global, "regex.db");
            if (kJsonString) {
                LLVMTypeRef json_params[5] = {ptr_ty, i64_ty, ptr_ty, i32_ty, ptr_ty};
                LLVMTypeRef json_ty = LLVMFunctionType(i8_ty, json_params, 5, 0);
                LLVMValueRef scan_fn =
                    LLVMGetNamedFunction(mod, "rut_helper_ws_json_string_regex_at_path");
                if (!scan_fn)
                    scan_fn =
                        LLVMAddFunction(mod, "rut_helper_ws_json_string_regex_at_path", json_ty);
                LLVMValueRef path_bytes = LLVMConstStringInContext(
                    ctx, guards[i].pattern ? guards[i].pattern : "", guards[i].pattern_len, 1);
                LLVMValueRef path = LLVMAddGlobal(mod, LLVMTypeOf(path_bytes), "json.regex.path");
                LLVMSetInitializer(path, path_bytes);
                LLVMSetGlobalConstant(path, 1);
                LLVMSetLinkage(path, LLVMPrivateLinkage);
                LLVMSetUnnamedAddress(path, LLVMGlobalUnnamedAddr);
                LLVMValueRef args[5] = {
                    payload, len, path, LLVMConstInt(i32_ty, guards[i].pattern_len, 0), db};
                LLVMValueRef result =
                    LLVMBuildCall2(builder, json_ty, scan_fn, args, 5, "json.regex");
                LLVMBasicBlockRef scanned = LLVMAppendBasicBlockInContext(ctx, fn, "json.regex.ok");
                LLVMBasicBlockRef error =
                    LLVMAppendBasicBlockInContext(ctx, fn, "json.regex.error");
                LLVMValueRef valid = LLVMBuildICmp(
                    builder, LLVMIntULE, result, LLVMConstInt(i8_ty, 1, 0), "json.regex.valid");
                LLVMBuildCondBr(builder, valid, scanned, error);
                LLVMPositionBuilderAtEnd(builder, error);
                // Decode and regex resource errors close before applying logical negation.
                LLVMBuildRet(builder, LLVMConstInt(i8_ty, 2, 0));  // WsFrameAction::Close
                LLVMPositionBuilderAtEnd(builder, scanned);
                cond = LLVMBuildICmp(
                    builder, LLVMIntEQ, result, LLVMConstInt(i8_ty, 1, 0), "json.regex.matches");
            } else {
                LLVMValueRef rx_fn = LLVMGetNamedFunction(mod, "rut_helper_str_regex_result");
                if (!rx_fn) rx_fn = LLVMAddFunction(mod, "rut_helper_str_regex_result", rx_fn_ty);
                LLVMValueRef len32 = LLVMBuildTrunc(builder, len, i32_ty, "len32");
                LLVMValueRef rx_args[3] = {payload, len32, db};
                LLVMValueRef result = LLVMBuildCall2(builder, rx_fn_ty, rx_fn, rx_args, 3, "rx");
                auto* scanned = LLVMAppendBasicBlockInContext(ctx, fn, "rx.ok");
                auto* failed = LLVMAppendBasicBlockInContext(ctx, fn, "rx.error");
                LLVMValueRef valid = LLVMBuildICmp(
                    builder, LLVMIntULE, result, LLVMConstInt(i8_ty, 1, 0), "rx.valid");
                LLVMBuildCondBr(builder, valid, scanned, failed);
                LLVMPositionBuilderAtEnd(builder, failed);
                LLVMBuildRet(builder,
                             LLVMConstInt(i8_ty, static_cast<u8>(WsFrameAction::Close), 0));
                LLVMPositionBuilderAtEnd(builder, scanned);
                cond = LLVMBuildICmp(builder, LLVMIntEQ, result, LLVMConstInt(i8_ty, 1, 0), "rx.m");
            }
        } else if (guards[i].accessor >= 6) {  // TextEqual / TextPrefix / TextSuffix / TextContains
            // Check the full 64-bit length before reading a literal-sized view.
            // Prefix/suffix comparisons never read beyond a short message.
            LLVMBasicBlockRef compare = LLVMAppendBasicBlockInContext(ctx, fn, "text.equal");
            LLVMValueRef length_matches =
                LLVMBuildICmp(builder,
                              guards[i].accessor == 6 ? LLVMIntEQ : LLVMIntUGE,
                              len,
                              LLVMConstInt(i64_ty, guards[i].pattern_len, 0),
                              "text.len");
            if (guards[i].accessor == 9) {
                // The substring helper accepts u32 lengths; reject before narrowing.
                LLVMValueRef fits = LLVMBuildICmp(
                    builder, LLVMIntULE, len, LLVMConstInt(i64_ty, 0xffffffffULL, 0), "text.fits");
                length_matches = LLVMBuildAnd(builder, length_matches, fits, "text.valid.length");
            }
            LLVMBuildCondBr(builder, length_matches, compare, no);
            LLVMPositionBuilderAtEnd(builder, compare);
            LLVMValueRef literal = LLVMBuildGlobalStringPtr(builder, "", "text.empty");
            if (guards[i].pattern_len != 0) {
                LLVMValueRef bytes =
                    LLVMConstStringInContext(ctx, guards[i].pattern, guards[i].pattern_len, 1);
                literal = LLVMAddGlobal(mod, LLVMTypeOf(bytes), "text.literal");
                LLVMSetInitializer(literal, bytes);
                LLVMSetGlobalConstant(literal, 1);
                LLVMSetLinkage(literal, LLVMPrivateLinkage);
                LLVMSetUnnamedAddress(literal, LLVMGlobalUnnamedAddr);
            }
            LLVMTypeRef eq_params[4] = {ptr_ty, i32_ty, ptr_ty, i32_ty};
            LLVMTypeRef eq_ty = LLVMFunctionType(i8_ty, eq_params, 4, 0);
            const char* helper =
                guards[i].accessor == 9 ? "rut_helper_str_contains" : "rut_helper_str_eq";
            LLVMValueRef eq_fn = LLVMGetNamedFunction(mod, helper);
            if (!eq_fn) eq_fn = LLVMAddFunction(mod, helper, eq_ty);
            LLVMValueRef size = LLVMConstInt(i32_ty, guards[i].pattern_len, 0);
            LLVMValueRef compared_payload = payload;
            if (guards[i].pattern_len != 0 && guards[i].accessor == 8) {
                // Only form the suffix view after the full-width length check.
                LLVMValueRef offset = LLVMBuildSub(
                    builder, len, LLVMConstInt(i64_ty, guards[i].pattern_len, 0), "suffix.offset");
                compared_payload = LLVMBuildGEP2(builder, i8_ty, payload, &offset, 1, "suffix");
            }
            LLVMValueRef text_size =
                guards[i].accessor == 9 ? LLVMBuildTrunc(builder, len, i32_ty, "text.size") : size;
            LLVMValueRef args[4] = {compared_payload, text_size, literal, size};
            LLVMValueRef equal = LLVMBuildCall2(builder, eq_ty, eq_fn, args, 4, "text.eq");
            cond =
                LLVMBuildICmp(builder, LLVMIntNE, equal, LLVMConstInt(i8_ty, 0, 0), "text.match");
        } else {
            LLVMIntPredicate pred = LLVMIntEQ;
            switch (guards[i].cmp) {  // WsLenGuard::Cmp ordinals: 0=Lt, 1=Gt, 2=Eq
                case 0:
                    pred = LLVMIntULT;
                    break;
                case 1:
                    pred = LLVMIntUGT;
                    break;
                case 2:
                    pred = LLVMIntEQ;
                    break;
                default:
                    break;
            }
            // Operand + width by accessor: 1=Opcode reads the i8 opcode param,
            // 2=FromClient reads the i8 from_client param, else (0=Len) the i64 len.
            const bool is_i8 = guards[i].accessor == 1 || guards[i].accessor == 2;
            LLVMValueRef operand = guards[i].accessor == 2   ? from_client
                                   : guards[i].accessor == 1 ? opcode
                                                             : len;
            LLVMTypeRef bound_ty = is_i8 ? i8_ty : i64_ty;
            cond = LLVMBuildICmp(
                builder, pred, operand, LLVMConstInt(bound_ty, guards[i].bound, 0), "g");
        }
        LLVMBuildCondBr(builder, cond, yes, no);
    };
    // Conditions retain their postorder operand trees. Root control edges are
    // strictly forward, so nested arms never re-evaluate a parent or form loops.
    LLVMBasicBlockRef blocks[WsLenGuardSpec::kMaxConditions]{};
    LLVMBasicBlockRef default_block = LLVMAppendBasicBlockInContext(ctx, fn, "default");
    for (u32 i = 0; i < guard_count; ++i)
        if (!guards[i].is_operand) blocks[i] = LLVMAppendBasicBlockInContext(ctx, fn, "condition");
    const auto kNext = [&](u32 start) {
        for (u32 i = start; i < guard_count; ++i)
            if (blocks[i]) return blocks[i];
        return default_block;
    };
    const auto kTarget = [&](u32 target, u32 source, bool pass) {
        if (target == kWsControlNext && pass) return kNext(source + 1);
        if (target == kWsControlDefault) return default_block;
        if (ws_control_is_after(target)) return kNext(ws_control_value(target));
        if (target == kWsControlNext || ws_control_is_return(target)) {
            LLVMBasicBlockRef done = LLVMAppendBasicBlockInContext(ctx, fn, "verdict");
            LLVMPositionBuilderAtEnd(builder, done);
            const u32 kAction =
                target == kWsControlNext ? guards[source].verdict : ws_control_value(target);
            LLVMBuildRet(builder, LLVMConstInt(i8_ty, kAction, 0));
            return done;
        }
        return blocks[target];
    };
    LLVMBuildBr(builder, kNext(0));
    for (u32 i = 0; i < guard_count; ++i) {
        if (!blocks[i]) continue;
        const auto kYes = kTarget(guards[i].pass_target, i, true);
        const auto kNo = kTarget(guards[i].fail_target, i, false);
        LLVMPositionBuilderAtEnd(builder, blocks[i]);
        emit_condition(emit_condition, i, kYes, kNo);
    }
    LLVMPositionBuilderAtEnd(builder, default_block);
    LLVMBuildRet(builder, LLVMConstInt(i8_ty, default_verdict, 0));
    LLVMDisposeBuilder(builder);
    return true;
}

CodegenResult codegen_ws_handler(u8 default_verdict,
                                 const WsLenGuardSpec* guards,
                                 u32 guard_count,
                                 u32 id) {
    LLVMContextRef ctx = LLVMContextCreate();
    LLVMModuleRef mod = LLVMModuleCreateWithNameInContext("rut_ws_handler", ctx);
    if (!emit_ws_handler(mod, ctx, default_verdict, guards, guard_count, id)) {
        LLVMDisposeModule(mod);
        LLVMContextDispose(ctx);
        return {nullptr, nullptr, false};
    }
    return {mod, ctx, true};
}

}  // namespace rut::jit
