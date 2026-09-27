#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/compiler/diagnostic.h"
#include "rut/runtime/mapped_array.h"

namespace rut {

// Token types for the .rut language
enum class TokenType : u8 {
    // Literals
    Ident,
    StringLit,
    IntLit,
    FloatLit,
    // Duration literal: digit run + unit suffix (ms, s, m, h). Emitted
    // only when the suffix follows the digits with no whitespace.
    // Value and unit both live in `text`; parser does the conversion.
    DurLit,

    // Keywords
    KwFunc,
    KwLet,
    KwVar,
    KwConst,
    KwGuard,
    KwCase,
    KwError,
    KwProtocol,
    KwImpl,
    KwVariant,
    KwStruct,
    KwRoute,
    KwMatch,
    KwIf,
    KwElse,
    KwFor,
    KwIn,
    KwReturn,
    KwRespond,
    KwUpstream,
    KwDownstream,
    KwListen,
    KwTls,
    KwDefaults,
    KwForward,
    KwWebsocket,
    KwImport,
    KwPackage,
    KwUsing,
    KwAs,
    KwWhere,
    KwFire,
    KwNotify,
    KwDefer,
    KwSubmit,
    KwWait,
    KwTimer,
    KwInit,
    KwShutdown,
    KwFirewall,
    KwThrottle,
    KwPer,
    KwNil,
    KwTrue,
    KwFalse,

    // HTTP methods
    KwGet,
    KwPost,
    KwPut,
    KwDelete,
    KwPatch,
    KwHead,
    KwOptions,

    // Regex literal
    RegexLit,  // re"pattern"

    // Symbols
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Colon,
    Comma,
    Dot,
    Arrow,      // => (single expression, implicit return)
    ThinArrow,  // ->
    Eq,
    EqEq,
    BangEq,
    Lt,
    Gt,
    LtEq,
    GtEq,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Amp,
    AmpAmp,  // && (logical and — Swift-identical)
    Pipe,
    PipePipe,  // || (logical or — Swift-identical)
    Caret,
    Tilde,
    Bang,  // ! (logical not — Swift-identical)
    Question,
    DoubleQuestion,  // ?? (null coalescing)
    At,
    DoubleStar,  // **
    Underscore,  // _

    // Special
    Eof,
    Error,
};

struct Token {
    TokenType type;
    Str text;
    u32 start;
    u32 end;
    u32 line;
    u32 col;
};

struct LexedTokens {
    // Converter-generated multi-route programs (e.g. the Envoy/nginx RUT
    // lowering, several routes per node, each with a full request/response/
    // failure policy) need far more headroom than a single hand-written
    // route. A 2-node/4-route-method Envoy lowering measures 963 tokens; a
    // realistic upper bound of 8 routes x 2 methods with the same
    // policy-heavy shape is ~4x that (~3,852 tokens). 4096 covers that with
    // margin while staying a single allocation-free FixedVec.
    static constexpr u32 kMaxTokens = 4096;
    FixedVec<Token, kMaxTokens> tokens;
};

using LexResult = core::Expected<LexedTokens, Diagnostic>;

// Keep each bounded lexer result object below 256 KiB on every supported data
// model. At capacity 4096 the current LP64 sizes are 163,848 bytes for
// LexedTokens and 163,856 bytes for LexResult. lex() places both its output
// and the returned value on the call stack (~320 KiB before other
// frames/redzones), so it is only for shallow, non-recursive callers (tests,
// tools). Anything that can recurse -- nested `import` analysis re-enters the
// ~1.3 MiB analyzer frame once per level -- or that keeps tokens alive across
// analysis must use lex_mapped() so no token buffer sits in its frame.
static_assert(sizeof(LexedTokens) <= 256uz * 1024uz,
              "LexedTokens exceeds the bounded 256 KiB object size");
static_assert(sizeof(LexResult) <= 256uz * 1024uz,
              "LexResult exceeds the bounded 256 KiB object size");

LexResult lex(Str source);

// Lex `source` into caller-owned storage. Resets `out` first; on error `out`
// holds a partial token stream and must not be parsed.
FrontendResult<void> lex_into(Str source, LexedTokens& out);

// Lex `source` into an mmap-backed LexedTokens owned by `storage` (a
// one-element MappedArray, initialized here if needed). Keeps the ~160 KiB
// token buffer out of the caller's stack frame; the tokens live until
// `storage` is destroyed. mmap failure reports FrontendError::OutOfMemory.
FrontendResult<const LexedTokens*> lex_mapped(Str source, MappedArray<LexedTokens>& storage);

}  // namespace rut
