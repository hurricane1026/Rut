/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

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
    KwAnd,
    KwOr,
    KwNot,
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
    Pipe,
    Caret,
    Tilde,
    Bang,
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
