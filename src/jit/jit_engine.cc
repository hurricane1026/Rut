#include "rut/jit/jit_engine.h"

#include "rut/jit/runtime_helpers.h"

#include <llvm-c/Analysis.h>
#include <llvm-c/Core.h>
#include <llvm-c/Error.h>
#include <llvm-c/LLJIT.h>
#include <llvm-c/Orc.h>
#include <llvm-c/Target.h>
#include <llvm-c/TargetMachine.h>
#include <llvm-c/Transforms/PassBuilder.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // write (for error logging)

namespace rut::jit {

// ── Error logging (no stdlib) ──────────────────────────────────────

static void log_error(const char* prefix, LLVMErrorRef err) {
    auto write_str = [](const char* s) {
        int len = 0;
        while (s[len]) len++;
        (void)::write(2, s, len);
    };
    write_str(prefix);
    if (err) {
        char* msg = LLVMGetErrorMessage(err);
        write_str(": ");
        write_str(msg);
        LLVMDisposeErrorMessage(msg);
    }
    write_str("\n");
}

// ── Runtime Helper Symbol Table ────────────────────────────────────

struct HelperEntry {
    const char* name;
    void* addr;
};

// Null-terminated table of runtime helper symbols.
static const HelperEntry kHelpers[] = {
    {"rut_helper_req_path", reinterpret_cast<void*>(&rut_helper_req_path)},
    {"rut_helper_req_path_only", reinterpret_cast<void*>(&rut_helper_req_path_only)},
    {"rut_helper_req_body", reinterpret_cast<void*>(&rut_helper_req_body)},
    {"rut_helper_req_http_version", reinterpret_cast<void*>(&rut_helper_req_http_version)},
    {"rut_helper_req_flag", reinterpret_cast<void*>(&rut_helper_req_flag)},
    {"rut_helper_req_method", reinterpret_cast<void*>(&rut_helper_req_method)},
    {"rut_helper_req_header", reinterpret_cast<void*>(&rut_helper_req_header)},
    {"rut_helper_req_set_path", reinterpret_cast<void*>(&rut_helper_req_set_path)},
    {"rut_helper_req_set_header", reinterpret_cast<void*>(&rut_helper_req_set_header)},
    {"rut_helper_req_add_header", reinterpret_cast<void*>(&rut_helper_req_add_header)},
    {"rut_helper_resp_set_header", reinterpret_cast<void*>(&rut_helper_resp_set_header)},
    {"rut_helper_resp_add_header", reinterpret_cast<void*>(&rut_helper_resp_add_header)},
    {"rut_helper_resp_remove_header", reinterpret_cast<void*>(&rut_helper_resp_remove_header)},
    {"rut_helper_resp_set_status", reinterpret_cast<void*>(&rut_helper_resp_set_status)},
    {"rut_helper_resp_set_body", reinterpret_cast<void*>(&rut_helper_resp_set_body)},
    {"rut_helper_resp_commit_headers", reinterpret_cast<void*>(&rut_helper_resp_commit_headers)},
    {"rut_helper_resp_status", reinterpret_cast<void*>(&rut_helper_resp_status)},
    {"rut_helper_resp_body", reinterpret_cast<void*>(&rut_helper_resp_body)},
    {"rut_helper_resp_header", reinterpret_cast<void*>(&rut_helper_resp_header)},
    {"rut_helper_req_cookie", reinterpret_cast<void*>(&rut_helper_req_cookie)},
    {"rut_helper_req_query", reinterpret_cast<void*>(&rut_helper_req_query)},
    {"rut_helper_req_query_all", reinterpret_cast<void*>(&rut_helper_req_query_all)},
    {"rut_helper_req_header_all", reinterpret_cast<void*>(&rut_helper_req_header_all)},
    {"rut_helper_req_query_string", reinterpret_cast<void*>(&rut_helper_req_query_string)},
    {"rut_helper_req_param", reinterpret_cast<void*>(&rut_helper_req_param)},
    {"rut_helper_req_remote_addr", reinterpret_cast<void*>(&rut_helper_req_remote_addr)},
    {"rut_helper_req_content_length", reinterpret_cast<void*>(&rut_helper_req_content_length)},
    {"rut_helper_parse_prime", reinterpret_cast<void*>(&rut_helper_parse_prime)},
    {"rut_helper_parse_unprime", reinterpret_cast<void*>(&rut_helper_parse_unprime)},
    {"rut_helper_json_reset", reinterpret_cast<void*>(&rut_helper_json_reset)},
    {"rut_helper_json_append_raw", reinterpret_cast<void*>(&rut_helper_json_append_raw)},
    {"rut_helper_json_append_str", reinterpret_cast<void*>(&rut_helper_json_append_str)},
    {"rut_helper_json_append_str_list", reinterpret_cast<void*>(&rut_helper_json_append_str_list)},
    {"rut_helper_json_append_i64", reinterpret_cast<void*>(&rut_helper_json_append_i64)},
    {"rut_helper_json_append_bool", reinterpret_cast<void*>(&rut_helper_json_append_bool)},
    {"rut_helper_json_append_control_plane",
     reinterpret_cast<void*>(&rut_helper_json_append_control_plane)},
    {"rut_helper_reload_request", reinterpret_cast<void*>(&rut_helper_reload_request)},
    {"rut_helper_upstream_mark", reinterpret_cast<void*>(&rut_helper_upstream_mark)},
    {"rut_helper_json_capture_data", reinterpret_cast<void*>(&rut_helper_json_capture_data)},
    {"rut_helper_json_capture_len", reinterpret_cast<void*>(&rut_helper_json_capture_len)},
    {"rut_helper_json_finish", reinterpret_cast<void*>(&rut_helper_json_finish)},
    {"rut_helper_str_has_prefix", reinterpret_cast<void*>(&rut_helper_str_has_prefix)},
    {"rut_helper_str_eq", reinterpret_cast<void*>(&rut_helper_str_eq)},
    {"rut_helper_str_cmp", reinterpret_cast<void*>(&rut_helper_str_cmp)},
    {"rut_helper_str_regex_match", reinterpret_cast<void*>(&rut_helper_str_regex_match)},
    {"rut_helper_str_trim_prefix", reinterpret_cast<void*>(&rut_helper_str_trim_prefix)},
    {"rut_helper_cache_get", reinterpret_cast<void*>(&rut_helper_cache_get)},
    {"rut_helper_cache_set", reinterpret_cast<void*>(&rut_helper_cache_set)},
    {"rut_helper_time_now_micros", reinterpret_cast<void*>(&rut_helper_time_now_micros)},
    {"rut_helper_time_unlatch", reinterpret_cast<void*>(&rut_helper_time_unlatch)},
    {nullptr, nullptr},
};

// ── JitEngine ──────────────────────────────────────────────────────

bool JitEngine::init() {
    // Initialize native target (required before creating LLJIT).
    if (LLVMInitializeNativeTarget()) return false;
    LLVMInitializeNativeAsmPrinter();
    ctx_count = 0;
    regex_slot_count = 0;
    regex_slot_cap = 0;
    regex_slots = nullptr;

    // Create LLJIT with default settings (auto-detects host target).
    LLVMErrorRef err = LLVMOrcCreateLLJIT(&lljit, nullptr);
    if (err) {
        log_error("jit: LLJIT creation failed", err);
        return false;
    }

    // Pre-register all runtime helper symbols as absolute addresses.
    // MangleAndIntern produces correctly mangled names for the target.
    LLVMOrcJITDylibRef main_jd = LLVMOrcLLJITGetMainJITDylib(lljit);

    // Derive the stack buffer size from the table so adding a helper cannot
    // silently skip registration or require a second capacity edit. The final
    // entry is the null sentinel and is intentionally excluded.
    static constexpr u32 count = sizeof(kHelpers) / sizeof(kHelpers[0]) - 1;
    LLVMOrcCSymbolMapPair pairs[count];
    for (u32 i = 0; i < count; i++) {
        pairs[i].Name = LLVMOrcLLJITMangleAndIntern(lljit, kHelpers[i].name);
        pairs[i].Sym.Address = reinterpret_cast<LLVMOrcExecutorAddress>(kHelpers[i].addr);
        pairs[i].Sym.Flags.GenericFlags = LLVMJITSymbolGenericFlagsExported;
        pairs[i].Sym.Flags.TargetFlags = 0;
    }

    // LLVMOrcAbsoluteSymbols takes ownership of the Name fields in pairs.
    // Do NOT release them after this call.
    LLVMOrcMaterializationUnitRef mu = LLVMOrcAbsoluteSymbols(pairs, count);
    err = LLVMOrcJITDylibDefine(main_jd, mu);
    if (err) {
        log_error("jit: helper registration failed", err);
        // On failure, ownership of mu stays with us.
        LLVMOrcDisposeMaterializationUnit(mu);
        LLVMOrcDisposeLLJIT(lljit);
        lljit = nullptr;
        return false;
    }

    return true;
}

static bool name_has_prefix(const char* name, size_t name_len, const char* prefix) {
    size_t i = 0;
    while (prefix[i]) {
        if (i >= name_len || name[i] != prefix[i]) return false;
        i++;
    }
    return true;
}

static bool extract_regex_pattern(LLVMValueRef global, const char** out_ptr, u32* out_len) {
    LLVMValueRef init = LLVMGetInitializer(global);
    if (!init) return false;
    size_t len = 0;
    const char* bytes = LLVMGetAsString(init, &len);
    if (!bytes) return false;
    if (len > 0 && bytes[len - 1] == '\0') len--;
    if (len > 0xffffffffu) return false;
    *out_ptr = bytes;
    *out_len = static_cast<u32>(len);
    return true;
}

JitEngine::RegexSlot* JitEngine::alloc_regex_slot() {
    if (regex_slot_count == regex_slot_cap) {
        u32 next_cap = regex_slot_cap ? regex_slot_cap * 2 : 16;
        size_t bytes = static_cast<size_t>(next_cap) * sizeof(RegexSlot*);
        auto** next =
            static_cast<RegexSlot**>(realloc(reinterpret_cast<void*>(regex_slots), bytes));
        if (!next) return nullptr;
        for (u32 i = regex_slot_cap; i < next_cap; i++) next[i] = nullptr;
        regex_slots = next;
        regex_slot_cap = next_cap;
    }

    auto* slot = static_cast<RegexSlot*>(calloc(1, sizeof(RegexSlot)));
    if (!slot) return nullptr;
    regex_slots[regex_slot_count++] = slot;
    return slot;
}

void JitEngine::rollback_regex_symbols(u32 start_count) {
    while (regex_slot_count > start_count) {
        RegexSlot* slot = regex_slots[regex_slot_count - 1];
        if (slot) {
            rut_helper_regex_free(slot->db);
            slot->db = nullptr;
            free(slot);
        }
        regex_slots[regex_slot_count - 1] = nullptr;
        regex_slot_count--;
    }
}

struct CompileLockGuard {
    pthread_mutex_t* mutex;
    explicit CompileLockGuard(pthread_mutex_t* m) : mutex(m) { pthread_mutex_lock(mutex); }
    ~CompileLockGuard() { pthread_mutex_unlock(mutex); }
};

bool JitEngine::prepare_regex_symbols(LLVMModuleRef mod, u32* out_start_count) {
    static constexpr const char* kPatternPrefix = "__rut_regex_pattern_";
    static constexpr const char* kDbPrefix = "__rut_regex_db_";
    *out_start_count = regex_slot_count;

    for (LLVMValueRef global = LLVMGetFirstGlobal(mod); global;
         global = LLVMGetNextGlobal(global)) {
        size_t name_len = 0;
        const char* name = LLVMGetValueName2(global, &name_len);
        if (!name_has_prefix(name, name_len, kPatternPrefix)) continue;

        const char* pattern = nullptr;
        u32 pattern_len = 0;
        if (!extract_regex_pattern(global, &pattern, &pattern_len)) {
            log_error("jit: unable to read regex pattern global", nullptr);
            return false;
        }

        RegexSlot* slot = alloc_regex_slot();
        if (!slot) {
            log_error("jit: regex slot allocation failed", nullptr);
            return false;
        }

        const size_t pattern_prefix_len = strlen(kPatternPrefix);
        const size_t suffix_len = name_len - pattern_prefix_len;
        const size_t db_prefix_len = strlen(kDbPrefix);
        if (db_prefix_len + suffix_len >= sizeof(slot->symbol)) {
            log_error("jit: regex symbol name too long", nullptr);
            return false;
        }
        memcpy(slot->symbol, kDbPrefix, db_prefix_len);
        memcpy(slot->symbol + db_prefix_len, name + pattern_prefix_len, suffix_len);
        slot->symbol[db_prefix_len + suffix_len] = '\0';

        LLVMValueRef db_global = LLVMGetNamedGlobal(mod, slot->symbol);
        if (!db_global) {
            log_error("jit: regex db global missing", nullptr);
            return false;
        }

        slot->db = rut_helper_regex_compile(pattern, pattern_len);
        if (!slot->db) {
            const char* regex_error = rut_helper_regex_last_compile_error();
            char msg[384];
            snprintf(msg,
                     sizeof(msg),
                     "jit: regex compilation failed for %s pattern `%.*s`: %s",
                     slot->symbol,
                     static_cast<int>(pattern_len),
                     pattern,
                     regex_error ? regex_error : "unknown error");
            log_error(msg, nullptr);
            return false;
        }

        LLVMContextRef llvm_ctx = LLVMGetModuleContext(mod);
        LLVMTypeRef i64_ty = LLVMInt64TypeInContext(llvm_ctx);
        LLVMTypeRef ptr_ty = LLVMPointerTypeInContext(llvm_ctx, 0);
        LLVMValueRef db_addr = LLVMConstIntToPtr(
            LLVMConstInt(
                i64_ty, static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(slot->db)), 0),
            ptr_ty);
        LLVMSetInitializer(db_global, db_addr);
        LLVMSetGlobalConstant(db_global, 1);
        LLVMSetLinkage(db_global, LLVMPrivateLinkage);
    }

    return true;
}

// Run the mid-level (new pass manager) optimization pipeline on the
// handler module before it is handed to LLJIT.
//
// Why this is needed: LLJIT's default compile layer only runs the
// backend (instruction selection / scheduling / register allocation).
// It does NOT run the IR-level optimizer, so the codegen output — which
// is fairly direct, mostly unoptimized IR — would otherwise reach the
// backend as-is. Running `default<O2>` here gives mem2reg/SROA/
// instcombine/GVN/DCE/etc., and lets the regex DB pointer constants
// baked in by prepare_regex_symbols() constant-propagate. User functions
// are already inlined at the RIR stage, so this mainly cleans up the
// per-handler IR; runtime helpers remain out-of-line external calls
// (inlining those would need LTO with the runtime bitcode).
//
// The TargetMachine is built for the host CPU/features so the cost model
// matches the code LLJIT will actually emit. It is used only for the IR
// passes here — LLJIT does the final codegen with its own target.
//
// Best-effort: a pipeline failure logs and leaves the (already verified,
// still valid) module unoptimized rather than failing the whole compile.
static const char* opt_pipeline(OptLevel level) {
    switch (level) {
        case OptLevel::O0:
            return nullptr;  // skip the mid-level pipeline entirely
        case OptLevel::O1:
            return "default<O1>";
        case OptLevel::O2:
            return "default<O2>";
        case OptLevel::O3:
            return "default<O3>";
    }
    return "default<O2>";
}

static void optimize_module(const char* triple, LLVMModuleRef mod, OptLevel level) {
    const char* pipeline = opt_pipeline(level);
    if (!pipeline) return;  // O0: nothing to run
    if (!triple) return;

    LLVMTargetRef target = nullptr;
    char* err_msg = nullptr;
    if (LLVMGetTargetFromTriple(triple, &target, &err_msg)) {
        log_error("jit: opt pipeline target lookup failed", nullptr);
        if (err_msg) LLVMDisposeMessage(err_msg);
        return;
    }

    char* cpu = LLVMGetHostCPUName();
    char* features = LLVMGetHostCPUFeatures();
    LLVMTargetMachineRef tm = LLVMCreateTargetMachine(target,
                                                      triple,
                                                      cpu ? cpu : "",
                                                      features ? features : "",
                                                      LLVMCodeGenLevelDefault,
                                                      LLVMRelocDefault,
                                                      LLVMCodeModelJITDefault);
    if (cpu) LLVMDisposeMessage(cpu);
    if (features) LLVMDisposeMessage(features);
    if (!tm) {
        log_error("jit: opt pipeline target machine creation failed", nullptr);
        return;
    }

    LLVMPassBuilderOptionsRef opts = LLVMCreatePassBuilderOptions();
    LLVMErrorRef perr = LLVMRunPasses(mod, pipeline, tm, opts);
    LLVMDisposePassBuilderOptions(opts);
    LLVMDisposeTargetMachine(tm);
    if (perr) {
        // log_error consumes the error via LLVMGetErrorMessage.
        log_error("jit: optimization pipeline failed (continuing unoptimized)", perr);
    }
}

bool JitEngine::compile(LLVMModuleRef mod, LLVMContextRef ctx) {
    // Always takes ownership of mod and ctx regardless of return value.
    if (!lljit) {
        LLVMDisposeModule(mod);
        LLVMContextDispose(ctx);
        return false;
    }
    CompileLockGuard compile_guard(&compile_mutex);

    // Set the module's data layout and target triple from LLJIT.
    const char* dl = LLVMOrcLLJITGetDataLayoutStr(lljit);
    if (dl) LLVMSetDataLayout(mod, dl);
    const char* triple = LLVMOrcLLJITGetTripleString(lljit);
    if (triple) LLVMSetTarget(mod, triple);

    char* verify_msg = nullptr;
    if (LLVMVerifyModule(mod, LLVMReturnStatusAction, &verify_msg)) {
        if (verify_msg) {
            auto write_str = [](const char* s) {
                int len = 0;
                while (s[len]) len++;
                (void)::write(2, s, len);
            };
            write_str("jit: module verification failed: ");
            write_str(verify_msg);
            write_str("\n");
            LLVMDisposeMessage(verify_msg);
        }
        LLVMDisposeModule(mod);
        LLVMContextDispose(ctx);
        return false;
    }

    u32 regex_start_count = 0;
    if (!prepare_regex_symbols(mod, &regex_start_count)) {
        rollback_regex_symbols(regex_start_count);
        LLVMDisposeModule(mod);
        LLVMContextDispose(ctx);
        return false;
    }

    // Run the IR optimization pipeline now that the data layout, target
    // triple, and regex DB constants are all in place. Best-effort.
    optimize_module(triple, mod, opt_level);

    // Wrap module into a ThreadSafeModule for submission to LLJIT.
    // We create a fresh ThreadSafeContext as the lock wrapper. Its internal
    // context differs from the module's context, but LLJIT only uses it
    // for synchronization — the module's own context is used for compilation.
    // The module's original LLVMContext (ctx) is tracked for cleanup in
    // shutdown() after LLJIT has destroyed the module.
    LLVMOrcThreadSafeContextRef tsctx = LLVMOrcCreateNewThreadSafeContext();
    LLVMOrcThreadSafeModuleRef tsm = LLVMOrcCreateNewThreadSafeModule(mod, tsctx);
    LLVMOrcDisposeThreadSafeContext(tsctx);

    // Submit to the main JITDylib. On success, LLJIT owns tsm.
    // We defer tracking `ctx` until *after* the module is accepted: on failure
    // we dispose ctx here rather than letting a failed compile consume a slot
    // in `contexts[]` (and eventually exhaust kMaxContexts).
    LLVMOrcJITDylibRef main_jd = LLVMOrcLLJITGetMainJITDylib(lljit);
    LLVMOrcResourceTrackerRef module_rt = LLVMOrcJITDylibCreateResourceTracker(main_jd);
    LLVMErrorRef err = LLVMOrcLLJITAddLLVMIRModuleWithRT(lljit, module_rt, tsm);
    if (err) {
        log_error("jit: module compilation failed", err);
        rollback_regex_symbols(regex_start_count);
        // On failure, ownership of tsm stays with us; disposing tsm also
        // disposes the inner module. We still own `ctx` (module's original
        // context) — dispose it here to match the verification-failure path.
        LLVMOrcDisposeThreadSafeModule(tsm);
        LLVMContextDispose(ctx);
        LLVMOrcReleaseResourceTracker(module_rt);
        return false;
    }

    LLVMOrcReleaseResourceTracker(module_rt);

    // Track the orphaned context for cleanup in shutdown(), after LLJIT
    // has accepted the module.
    if (ctx_count < kMaxContexts) {
        contexts[ctx_count++] = ctx;
    }

    return true;
}

void* JitEngine::lookup(const char* name) {
    if (!lljit) return nullptr;

    LLVMOrcExecutorAddress addr = 0;
    LLVMErrorRef err = LLVMOrcLLJITLookup(lljit, &addr, name);
    if (err) {
        log_error("jit: symbol lookup failed", err);
        return nullptr;
    }

    // Cast via uintptr_t. The NOLINT suppresses performance-no-int-to-ptr
    // which is unavoidable here — the LLVM C API returns addresses as u64.
    return reinterpret_cast<void*>(  // NOLINT(performance-no-int-to-ptr)
        static_cast<uintptr_t>(addr));
}

void JitEngine::shutdown() {
    // Dispose LLJIT first — this destroys all compiled modules.
    if (lljit) {
        LLVMErrorRef err = LLVMOrcDisposeLLJIT(lljit);
        if (err) {
            log_error("jit: LLJIT disposal failed", err);
        }
        lljit = nullptr;
    }
    // Now safe to dispose orphaned contexts (modules that referenced
    // them have been destroyed by LLJIT above).
    for (u32 i = 0; i < ctx_count; i++) {
        LLVMContextDispose(contexts[i]);
    }
    ctx_count = 0;

    for (u32 i = 0; i < regex_slot_count; i++) {
        RegexSlot* slot = regex_slots[i];
        if (!slot) continue;
        rut_helper_regex_free(slot->db);
        slot->db = nullptr;
        slot->symbol[0] = '\0';
        free(slot);
    }
    regex_slot_count = 0;
    regex_slot_cap = 0;
    free(reinterpret_cast<void*>(regex_slots));
    regex_slots = nullptr;
}

}  // namespace rut::jit
