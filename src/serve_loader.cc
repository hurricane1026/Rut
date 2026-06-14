#include "rut/serve_loader.h"

#include "rut/compiler/analyze.h"
#include "rut/compiler/ast.h"
#include "rut/compiler/hir.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/mir.h"
#include "rut/compiler/mir_build.h"
#include "rut/compiler/parser.h"
#include "rut/jit/codegen.h"
#include "rut/runtime/compile_to_config.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace rut {

void LoadedProgram::destroy() {
    if (jit_inited) {
        engine.shutdown();
        jit_inited = false;
    }
    rir.destroy();
    if (src_map) {
        munmap(src_map, src_map_len);
        src_map = nullptr;
        src_map_len = 0;
    }
}

namespace {

// mmap the source file read-only for the process lifetime. Stored in
// LoadedProgram so any Str that points back into the source stays valid
// while the server runs. A zero-length file maps to {"", 0} and is a
// valid (route-less) program.
bool map_source(const char* path, LoadedProgram& out) {
    const int kFd = ::open(path, O_RDONLY);
    if (kFd < 0) return false;

    struct stat st;
    if (fstat(kFd, &st) < 0) {
        ::close(kFd);
        return false;
    }
    if (st.st_size < 0 || static_cast<u64>(st.st_size) > static_cast<u64>(0xffffffffu)) {
        ::close(kFd);
        return false;
    }
    if (st.st_size == 0) {
        ::close(kFd);
        return true;  // src_map stays null; lex() sees an empty Str
    }

    void* m = mmap(nullptr, static_cast<u64>(st.st_size), PROT_READ, MAP_PRIVATE, kFd, 0);
    ::close(kFd);
    if (m == MAP_FAILED) return false;

    out.src_map = m;
    out.src_map_len = static_cast<u64>(st.st_size);
    return true;
}

}  // namespace

bool load_rut_program(const char* path, LoadedProgram& out, LoadError& err, jit::OptLevel opt) {
    err = LoadError{};

    err.stage = LoadStage::Read;
    if (!map_source(path, out)) return false;

    // A zero-byte program leaves src_map null (nothing to unmap). lex()
    // forms its EOF token at source.ptr + source.len, so hand it a
    // non-null base even when len == 0 to avoid null-pointer arithmetic.
    const char* src_base = out.src_map ? static_cast<const char*>(out.src_map) : "";
    const Str kSource{src_base, static_cast<u32>(out.src_map_len)};

    // ── Frontend: source text → RIR module ──────────────────────────
    // parse_file/analyze_file/build_mir each heap-allocate their result
    // (frontend convention). The intermediate AST/HIR/MIR are only
    // needed up to lowering — the RIR carries its own arena — so free
    // them as the pipeline advances. The source mmap (and the lowered
    // RIR) stay alive in `out` for the whole run.
    err.stage = LoadStage::Lex;
    auto lexed = lex(kSource);
    if (!lexed) {
        err.has_diag = true;
        err.diag = lexed.error();
        return false;
    }

    err.stage = LoadStage::Parse;
    auto ast = parse_file(lexed.value());
    if (!ast) {
        err.has_diag = true;
        err.diag = ast.error();
        return false;
    }

    err.stage = LoadStage::Analyze;
    // Pass the program path so relative `import "..."` resolves against it,
    // matching the frontend's import-aware analysis path. Without a path the
    // analyzer skips imports entirely.
    u32 path_len = 0;
    while (path[path_len]) path_len++;
    auto hir = analyze_file(*ast.value(), Str{path, path_len});
    if (!hir) {
        err.has_diag = true;
        err.diag = hir.error();
        delete ast.value();
        return false;
    }

    err.stage = LoadStage::BuildMir;
    auto mir = build_mir(*hir.value());
    if (!mir) {
        err.has_diag = true;
        err.diag = mir.error();
        delete hir.value();
        delete ast.value();
        return false;
    }

    err.stage = LoadStage::Lower;
    auto lowered = lower_to_rir(*mir.value(), out.rir);
    delete mir.value();
    delete hir.value();
    delete ast.value();
    if (!lowered) {
        err.has_diag = true;
        err.diag = lowered.error();
        return false;
    }

    // ── Backend: RIR → LLVM IR → native code ────────────────────────
    err.stage = LoadStage::Codegen;
    auto cg = jit::codegen(out.rir.module);
    if (!cg.ok) return false;

    err.stage = LoadStage::JitCompile;
    if (!out.engine.init()) return false;
    out.jit_inited = true;
    out.engine.opt_level = opt;
    // compile() takes ownership of cg.mod and cg.ctx unconditionally.
    if (!out.engine.compile(cg.mod, cg.ctx)) return false;

    // ── Bridge: declarative content + route handler registration ────
    // Order matters: populate_route_config fills upstreams / response
    // bodies / header sets (which RetStatus packs 1-based indices into
    // at compile time), and requires an empty route table.
    // register_jit_routes then resolves each handler symbol and adds
    // the routes. Both fail closed.
    err.stage = LoadStage::Register;
    if (!populate_route_config(out.config, out.rir.module)) return false;
    if (!register_jit_routes(out.config, out.rir.module, out.engine)) return false;

    return true;
}

namespace {

void append(char* buf, u32 buf_size, u32* pos, const char* s) {
    while (*s && *pos + 1 < buf_size) buf[(*pos)++] = *s++;
}

void append_u32(char* buf, u32 buf_size, u32* pos, u32 value) {
    char tmp[10];
    u32 n = 0;
    if (value == 0) {
        tmp[n++] = '0';
    } else {
        while (value > 0) {
            tmp[n++] = static_cast<char>('0' + value % 10);
            value /= 10;
        }
    }
    while (n > 0 && *pos + 1 < buf_size) buf[(*pos)++] = tmp[--n];
}

const char* stage_str(LoadStage stage) {
    switch (stage) {
        case LoadStage::Read:
            return "read source file";
        case LoadStage::Lex:
            return "lex";
        case LoadStage::Parse:
            return "parse";
        case LoadStage::Analyze:
            return "type check";
        case LoadStage::BuildMir:
            return "build MIR";
        case LoadStage::Lower:
            return "lower to RIR";
        case LoadStage::Codegen:
            return "codegen (LLVM IR)";
        case LoadStage::JitCompile:
            return "JIT compile";
        case LoadStage::Register:
            return "register routes";
    }
    return "unknown";
}

const char* frontend_error_str(FrontendError code) {
    switch (code) {
        case FrontendError::UnexpectedChar:
            return "unexpected character";
        case FrontendError::UnterminatedString:
            return "unterminated string";
        case FrontendError::InvalidInteger:
            return "invalid integer";
        case FrontendError::UnexpectedToken:
            return "unexpected token";
        case FrontendError::UnexpectedEof:
            return "unexpected end of file";
        case FrontendError::TooManyTokens:
            return "too many tokens";
        case FrontendError::TooManyItems:
            return "too many items";
        case FrontendError::InvalidStatusCode:
            return "invalid status code";
        case FrontendError::DuplicateUpstream:
            return "duplicate upstream";
        case FrontendError::UnknownUpstream:
            return "unknown upstream";
        case FrontendError::OutOfMemory:
            return "out of memory";
        case FrontendError::InvalidRegex:
            return "invalid regex";
        case FrontendError::UnsupportedSyntax:
            return "unsupported syntax";
    }
    return "error";
}

}  // namespace

u32 format_load_error(const LoadError& err, char* buf, u32 buf_size) {
    u32 pos = 0;
    if (buf_size == 0) return 0;

    append(buf, buf_size, &pos, stage_str(err.stage));
    append(buf, buf_size, &pos, " failed");

    if (err.has_diag) {
        append(buf, buf_size, &pos, ": ");
        append(buf, buf_size, &pos, frontend_error_str(err.diag.code));
        if (err.diag.span.line > 0) {
            append(buf, buf_size, &pos, " at line ");
            append_u32(buf, buf_size, &pos, err.diag.span.line);
            append(buf, buf_size, &pos, " col ");
            append_u32(buf, buf_size, &pos, err.diag.span.col);
        }
        if (err.diag.detail.len > 0 && err.diag.detail.ptr) {
            append(buf, buf_size, &pos, " (");
            for (u32 i = 0; i < err.diag.detail.len && pos + 1 < buf_size; i++) {
                buf[pos++] = err.diag.detail.ptr[i];
            }
            if (pos + 1 < buf_size) buf[pos++] = ')';
        }
    }

    buf[pos] = '\0';
    return pos;
}

}  // namespace rut
