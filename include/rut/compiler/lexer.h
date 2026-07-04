#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/compiler/diagnostic.h"

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
    static constexpr u32 kMaxTokens = 512;
    FixedVec<Token, kMaxTokens> tokens;
};

using LexResult = core::Expected<LexedTokens, Diagnostic>;

LexResult lex(Str source);

}  // namespace rut
