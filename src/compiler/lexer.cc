#include "rut/compiler/lexer.h"

#include "rut/common/range_int.h"

namespace rut {

namespace {

static bool is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

static bool is_ident_start(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static bool is_ident_continue(char c) {
    return is_ident_start(c) || is_digit(c);
}

static TokenType keyword_type(Str text) {
    if (text.eq({"func", 4})) return TokenType::KwFunc;
    if (text.eq({"let", 3})) return TokenType::KwLet;
    if (text.eq({"const", 5})) return TokenType::KwConst;
    if (text.eq({"guard", 5})) return TokenType::KwGuard;
    // `case` is recognized CONTEXTUALLY by the parser (only at match-arm position,
    // where it earns the "arms don't use `case`" fix-it), NOT reserved globally —
    // otherwise ordinary identifiers (`let case = ...`, a struct field `case`, a
    // `.case` variant payload) would stop parsing. Mirrors `at`/`timer`/`websocket`.
    if (text.eq({"error", 5})) return TokenType::KwError;
    if (text.eq({"protocol", 8})) return TokenType::KwProtocol;
    if (text.eq({"impl", 4})) return TokenType::KwImpl;
    if (text.eq({"import", 6})) return TokenType::KwImport;
    if (text.eq({"package", 7})) return TokenType::KwPackage;
    if (text.eq({"using", 5})) return TokenType::KwUsing;
    if (text.eq({"as", 2})) return TokenType::KwAs;
    if (text.eq({"where", 5})) return TokenType::KwWhere;
    if (text.eq({"variant", 7})) return TokenType::KwVariant;
    if (text.eq({"struct", 6})) return TokenType::KwStruct;
    if (text.eq({"match", 5})) return TokenType::KwMatch;
    if (text.eq({"if", 2})) return TokenType::KwIf;
    if (text.eq({"else", 4})) return TokenType::KwElse;
    if (text.eq({"for", 3})) return TokenType::KwFor;
    if (text.eq({"in", 2})) return TokenType::KwIn;
    // `and` / `or` / `not` are NOT keywords — boolean operators are the
    // Swift-identical `&&` / `||` / `!`. The words lex as ordinary
    // identifiers so member names like `.or(default)` and `bitwise.and(...)`
    // stay reachable; the parser rejects them with fix-its in operator and
    // operand positions (see kAndDetail etc. in parser.cc).
    if (text.eq({"nil", 3})) return TokenType::KwNil;
    if (text.eq({"upstream", 8})) return TokenType::KwUpstream;
    if (text.eq({"downstream", 10})) return TokenType::KwDownstream;
    if (text.eq({"listen", 6})) return TokenType::KwListen;
    // `at` is deliberately NOT reserved globally — only
    // `parse_upstream` treats the identifier specially, matching the
    // `response()` / `forward()` builder pattern. This keeps `at`
    // available as a regular identifier in user code.
    if (text.eq({"route", 5})) return TokenType::KwRoute;
    if (text.eq({"return", 6})) return TokenType::KwReturn;
    // `respond` is recognized CONTEXTUALLY in statement position, NOT reserved globally,
    // so declarations and members named `respond` remain valid user identifiers.
    if (text.eq({"forward", 7})) return TokenType::KwForward;
    // `timer` is recognized CONTEXTUALLY at top level (a `timer name, every: ...`
    // declaration), NOT reserved — otherwise `wait any(recv, timer)` and any
    // identifier named `timer` would stop parsing. Mirrors `websocket`/`response`.
    // `websocket` is recognized CONTEXTUALLY in the parser (only `websocket(` in
    // return position is the builder), NOT reserved as a keyword — otherwise the
    // `.websocket` variant literal (e.g. `req.upgrade == .websocket`) and any
    // identifier named `websocket` would stop parsing. Mirrors how `response` works.
    if (text.eq({"wait", 4})) return TokenType::KwWait;
    if (text.eq({"true", 4})) return TokenType::KwTrue;
    if (text.eq({"false", 5})) return TokenType::KwFalse;
    if (text.eq({"GET", 3}) || text.eq({"get", 3})) return TokenType::KwGet;
    if (text.eq({"POST", 4}) || text.eq({"post", 4})) return TokenType::KwPost;
    if (text.eq({"PUT", 3}) || text.eq({"put", 3})) return TokenType::KwPut;
    if (text.eq({"DELETE", 6}) || text.eq({"delete", 6})) return TokenType::KwDelete;
    if (text.eq({"PATCH", 5}) || text.eq({"patch", 5})) return TokenType::KwPatch;
    if (text.eq({"HEAD", 4}) || text.eq({"head", 4})) return TokenType::KwHead;
    if (text.eq({"OPTIONS", 7}) || text.eq({"options", 7})) return TokenType::KwOptions;
    return TokenType::Ident;
}

static Span token_span(const Token& tok) {
    return Span{tok.start, tok.end, tok.line, tok.col};
}

// Fix-it details for removed / reserved surface forms (DESIGN.md §3.6).
constexpr Str kForceUnwrapDetail =
    lit_str("postfix `!` (force unwrap) is not supported; use if let / guard let");
constexpr Str kBitwiseDetail = lit_str(
    "bitwise symbols are not Rut syntax; use the bitwise.and/or/xor/flip/"
    "shiftLeft/shiftRight builtins");
constexpr Str kQuestionDetail =
    lit_str("`?` / `??` / `?.` are not supported; use if let, guard let, or .or(default)");

}  // namespace

FrontendResult<void> lex_into(Str source, LexedTokens& out) {
    out.tokens.len = 0;
    // EOF and source locations are one-based for line and column.
    if (source.len == UINT32_MAX)
        return frontend_error(
            FrontendError::TooManyItems, {}, lit_str("source position exceeds 32 bits"));
    u32 pos = 0;
    u32 line = 1;
    u32 col = 1;
    constexpr auto kOne = range_int<1, 2>{};
    constexpr auto kTwo = range_int<2, 3>{};
    constexpr auto kThree = range_int<3, 4>{};
    const auto end = range_int(source.len);
    const auto location_limit = (end + kOne).min(range_int<UINT32_MAX, i64{UINT32_MAX} + 1>{});
    auto position_after = [&](auto step) { return range_int(pos) + step; };
    auto after = [&](auto step) { return position_after(step).value(); };
    // Callers prove that the step consumes existing bytes. The length
    // guard leaves room for the one-based line and column at EOF.
    auto advance = [&](auto step) {
        pos = position_after(step).min(end).template to<u32>();
        col = (range_int(col) + step).min(location_limit).template to<u32>();
    };

    while (pos < source.len) {
        const char c = source.ptr[pos];

        if (is_space(c)) {
            if (c == '\n') {
                line = (range_int(line) + kOne).min(location_limit).to<u32>();
                pos = position_after(kOne).min(end).to<u32>();
                col = 1;
            } else {
                advance(kOne);
            }
            continue;
        }

        if (c == '/' && after(kOne) < source.len && source.ptr[after(kOne)] == '/') {
            advance(kTwo);
            while (pos < source.len && source.ptr[pos] != '\n') {
                advance(kOne);
            }
            continue;
        }

        Token tok{};
        tok.start = pos;
        tok.line = line;
        tok.col = col;

        if (c == 'r' && after(kTwo) < source.len && source.ptr[after(kOne)] == 'e' &&
            source.ptr[after(kTwo)] == '"') {
            const u32 literal_start = pos;
            const u32 literal_col = col;
            const u32 quote_start = position_after(kTwo).min(end).to<u32>();
            advance(kThree);
            tok.start = (range_int(quote_start) + kOne).min(end).to<u32>();
            tok.col = (range_int(tok.col) + kThree).min(location_limit).to<u32>();
            while (pos < source.len) {
                const char cur = source.ptr[pos];
                if (cur == '"') break;
                if (cur == '\\') {
                    if (after(kOne) >= source.len) {
                        return frontend_error(FrontendError::UnterminatedString,
                                              Span{literal_start, pos, tok.line, literal_col});
                    }
                    advance(kTwo);
                    continue;
                }
                if (cur == '\n') {
                    return frontend_error(FrontendError::UnterminatedString,
                                          Span{literal_start, pos, tok.line, literal_col});
                }
                advance(kOne);
            }
            if (pos >= source.len || source.ptr[pos] != '"') {
                return frontend_error(FrontendError::UnterminatedString,
                                      Span{literal_start, pos, tok.line, literal_col});
            }
            tok.type = TokenType::RegexLit;
            tok.end = pos;
            tok.text = source.slice(tok.start, tok.end);
            advance(kOne);
            if (!out.tokens.push(tok))
                return frontend_error(FrontendError::TooManyTokens, token_span(tok));
            continue;
        }

        if (is_ident_start(c)) {
            advance(kOne);
            while (pos < source.len && is_ident_continue(source.ptr[pos])) {
                advance(kOne);
            }
            tok.end = pos;
            tok.text = source.slice(tok.start, tok.end);
            tok.type = tok.text.len == 1 && tok.text.ptr[0] == '_' ? TokenType::Underscore
                                                                   : keyword_type(tok.text);
            if (!out.tokens.push(tok))
                return frontend_error(FrontendError::TooManyTokens, token_span(tok));
            continue;
        }

        if (is_digit(c)) {
            // Swift integer literals require a digit immediately after a radix
            // prefix; subsequent digits may be separated or followed by `_`.
            // `0b` with no binary digit and no identifier continuation is the
            // zero-byte literal: lex `0` as an integer and leave `b` as the
            // adjacent unit identifier. `0b1`/`0b_1`/`0b2` keep their binary
            // prefix diagnostics.
            const bool zero_byte_suffix =
                c == '0' && after(kOne) < source.len && source.ptr[after(kOne)] == 'b' &&
                (after(kTwo) >= source.len || !is_ident_continue(source.ptr[after(kTwo)]));
            if (!zero_byte_suffix && c == '0' && after(kOne) < source.len &&
                (source.ptr[after(kOne)] == 'b' || source.ptr[after(kOne)] == 'o' ||
                 source.ptr[after(kOne)] == 'x')) {
                const char kPrefix = source.ptr[after(kOne)];
                const u32 kRadix = kPrefix == 'b' ? 2u : kPrefix == 'o' ? 8u : 16u;
                advance(kTwo);
                const u32 kDigitsStart = pos;
                bool valid = true;
                while (pos < source.len && is_ident_continue(source.ptr[pos])) {
                    const char kDigit = source.ptr[pos];
                    if (kDigit == '_') {
                        if (pos == kDigitsStart) valid = false;
                    } else {
                        const auto kByte = range_int(static_cast<u8>(kDigit));
                        constexpr auto kHexOffset = range_int<10, 11>{};
                        const i64 kValue =
                            is_digit(kDigit) ? (kByte - range_int<'0', '1'>{}).value()
                            : kDigit >= 'a' && kDigit <= 'f'
                                ? (kByte - range_int<'a', 'b'>{} + kHexOffset).value()
                            : kDigit >= 'A' && kDigit <= 'F'
                                ? (kByte - range_int<'A', 'B'>{} + kHexOffset).value()
                                : 16;
                        if (kValue >= kRadix) valid = false;
                    }
                    advance(kOne);
                }
                tok.end = pos;
                tok.text = source.slice(tok.start, tok.end);
                if (!valid || pos == kDigitsStart)
                    return frontend_error(FrontendError::InvalidInteger, token_span(tok), tok.text);
                tok.type = TokenType::IntLit;
                if (!out.tokens.push(tok))
                    return frontend_error(FrontendError::TooManyTokens, token_span(tok));
                continue;
            }
            advance(kOne);
            bool separated = false;
            while (pos < source.len && (is_digit(source.ptr[pos]) || source.ptr[pos] == '_')) {
                separated |= source.ptr[pos] == '_';
                advance(kOne);
            }
            // Duration suffix check. Must immediately follow the digits
            // (no whitespace). Recognized units: ms, s, m, h. "ms" is
            // greedier than "m", so check it first. Unit must be at a
            // token boundary (not followed by another identifier char)
            // so e.g. `5mystery` isn't consumed as "5m" + "ystery".
            auto is_boundary = [&](i64 after) {
                return after >= source.len || !is_ident_continue(source.ptr[after]);
            };
            bool dur_matched = false;
            u32 unit_end = pos;
            if (after(kOne) < source.len && source.ptr[pos] == 'm' &&
                source.ptr[after(kOne)] == 's' && is_boundary(after(kTwo))) {
                unit_end = position_after(kTwo).min(end).to<u32>();
                dur_matched = true;
            } else if (pos < source.len && is_boundary(after(kOne)) &&
                       (source.ptr[pos] == 's' || source.ptr[pos] == 'm' ||
                        source.ptr[pos] == 'h')) {
                unit_end = position_after(kOne).min(end).to<u32>();
                dur_matched = true;
            }
            if (dur_matched) {
                advance((range_int(unit_end) - range_int(pos)).max(range_int<0, 1>{}));
                tok.end = pos;
                tok.text = source.slice(tok.start, tok.end);
                // Duration is a distinct domain literal with decimal digits
                // only. Do not send separators to its existing unit decoders.
                if (separated)
                    return frontend_error(FrontendError::InvalidInteger, token_span(tok), tok.text);
                tok.type = TokenType::DurLit;
                if (!out.tokens.push(tok))
                    return frontend_error(FrontendError::TooManyTokens, token_span(tok));
                continue;
            }
            tok.end = pos;
            tok.text = source.slice(tok.start, tok.end);
            tok.type = TokenType::IntLit;
            if (!out.tokens.push(tok))
                return frontend_error(FrontendError::TooManyTokens, token_span(tok));
            continue;
        }

        if (c == '"') {
            const u32 quote_start = pos;
            advance(kOne);
            while (pos < source.len) {
                const char cur = source.ptr[pos];
                if (cur == '"') break;
                if (cur == '\\') {
                    if (after(kOne) >= source.len) {
                        return frontend_error(FrontendError::UnterminatedString,
                                              Span{quote_start, pos, tok.line, tok.col});
                    }
                    advance(kTwo);
                    continue;
                }
                if (cur == '\n') {
                    return frontend_error(FrontendError::UnterminatedString,
                                          Span{quote_start, pos, tok.line, tok.col});
                }
                advance(kOne);
            }
            if (pos >= source.len || source.ptr[pos] != '"') {
                return frontend_error(FrontendError::UnterminatedString,
                                      Span{quote_start, pos, tok.line, tok.col});
            }
            tok.type = TokenType::StringLit;
            tok.start = (range_int(quote_start) + kOne).min(end).to<u32>();
            tok.col = (range_int(tok.col) + kOne).min(location_limit).to<u32>();
            tok.end = pos;
            tok.text = source.slice(tok.start, tok.end);
            advance(kOne);
            if (!out.tokens.push(tok))
                return frontend_error(FrontendError::TooManyTokens, token_span(tok));
            continue;
        }

        advance(kOne);
        tok.end = pos;
        tok.text = source.slice(tok.start, tok.end);
        if (c == '=' && pos < source.len && source.ptr[pos] == '=') {
            advance(kOne);
            tok.end = pos;
            tok.text = source.slice(tok.start, tok.end);
            tok.type = TokenType::EqEq;
            if (!out.tokens.push(tok))
                return frontend_error(FrontendError::TooManyTokens, token_span(tok));
            continue;
        }
        if (c == '=' && pos < source.len && source.ptr[pos] == '>') {
            advance(kOne);
            tok.end = pos;
            tok.text = source.slice(tok.start, tok.end);
            tok.type = TokenType::Arrow;
            if (!out.tokens.push(tok))
                return frontend_error(FrontendError::TooManyTokens, token_span(tok));
            continue;
        }
        if (c == '-' && pos < source.len && source.ptr[pos] == '>') {
            advance(kOne);
            tok.end = pos;
            tok.text = source.slice(tok.start, tok.end);
            tok.type = TokenType::ThinArrow;
            if (!out.tokens.push(tok))
                return frontend_error(FrontendError::TooManyTokens, token_span(tok));
            continue;
        }
        // Two-char operators (Swift-identical boolean/comparison set).
        {
            const char next = pos < source.len ? source.ptr[pos] : '\0';
            // Removed shift symbol `<<` gets the bitwise migration fix-it, caught
            // here before `<` would tokenize as two comparison ops (which reports an
            // unrelated unexpected `<` instead of pointing to bitwise.shiftLeft).
            // NOTE: `>>` is NOT caught — it is the legitimate close of a nested
            // generic type (`Hash<K, Foo<V>>`); `bitwise.shiftRight` covers that op.
            if (c == '<' && next == '<')
                return frontend_error(
                    FrontendError::UnsupportedSyntax, token_span(tok), kBitwiseDetail);
            TokenType two = TokenType::Error;
            if (c == '&' && next == '&') two = TokenType::AmpAmp;
            if (c == '|' && next == '|') two = TokenType::PipePipe;
            if (c == '!' && next == '=') two = TokenType::BangEq;
            if (c == '<' && next == '=') two = TokenType::LtEq;
            if (c == '>' && next == '=') two = TokenType::GtEq;
            if (two != TokenType::Error) {
                advance(kOne);
                tok.end = pos;
                tok.text = source.slice(tok.start, tok.end);
                tok.type = two;
                if (!out.tokens.push(tok))
                    return frontend_error(FrontendError::TooManyTokens, token_span(tok));
                continue;
            }
        }
        switch (c) {
            case '{':
                tok.type = TokenType::LBrace;
                break;
            case '}':
                tok.type = TokenType::RBrace;
                break;
            case '(':
                tok.type = TokenType::LParen;
                break;
            case ')':
                tok.type = TokenType::RParen;
                break;
            case '[':
                tok.type = TokenType::LBracket;
                break;
            case ']':
                tok.type = TokenType::RBracket;
                break;
            case ',':
                tok.type = TokenType::Comma;
                break;
            case ':':
                tok.type = TokenType::Colon;
                break;
            case '.':
                tok.type = TokenType::Dot;
                break;
            case '<':
                tok.type = TokenType::Lt;
                break;
            case '>':
                tok.type = TokenType::Gt;
                break;
            case '*':
                tok.type = TokenType::Star;
                break;
            // Arithmetic operators. `->` is consumed as ThinArrow above, so a
            // bare `-` here is unambiguous; `//` comments are consumed in the
            // skip loop, so a bare `/` here is division.
            case '+':
                tok.type = TokenType::Plus;
                break;
            case '-':
                tok.type = TokenType::Minus;
                break;
            case '/':
                tok.type = TokenType::Slash;
                break;
            case '%':
                tok.type = TokenType::Percent;
                break;
            case '|':
                tok.type = TokenType::Pipe;
                break;
            case '=':
                tok.type = TokenType::Eq;
                break;
            case '@':
                tok.type = TokenType::At;
                break;
            case '!': {
                // Postfix `!` (Swift force unwrap) is a removed form. Prefix
                // not (`!x`) never directly follows a value token without
                // whitespace, so "value token immediately before, no gap"
                // identifies the postfix reading.
                range_int<1, i64{UINT32_MAX} + 1> token_count;
                const Token* last =
                    decltype(token_count)::try_from_i64(out.tokens.len, &token_count)
                        ? &out.tokens[(token_count - kOne).index()]
                        : nullptr;
                // String/regex tokens store `end` at the closing quote, so
                // the character after the literal starts at end + 1.
                const bool last_is_quoted =
                    last != nullptr &&
                    (last->type == TokenType::StringLit || last->type == TokenType::RegexLit);
                const i64 last_end =
                    last == nullptr
                        ? 0
                        : (range_int(last->end) + range_int(static_cast<u8>(last_is_quoted)))
                              .value();
                const bool after_value_token =
                    last != nullptr && last_end == tok.start &&
                    (last->type == TokenType::Ident || last->type == TokenType::IntLit ||
                     last->type == TokenType::FloatLit || last->type == TokenType::DurLit ||
                     last->type == TokenType::StringLit || last->type == TokenType::RegexLit ||
                     last->type == TokenType::RParen || last->type == TokenType::RBracket ||
                     last->type == TokenType::KwTrue || last->type == TokenType::KwFalse ||
                     last->type == TokenType::KwNil);
                if (after_value_token) {
                    return frontend_error(
                        FrontendError::UnsupportedSyntax, token_span(tok), kForceUnwrapDetail);
                }
                tok.type = TokenType::Bang;
                break;
            }
            // Removed / reserved symbols get targeted fix-its (DESIGN.md §3.6).
            case '&':
            case '^':
            case '~':
                return frontend_error(
                    FrontendError::UnsupportedSyntax, token_span(tok), kBitwiseDetail);
            case '?':
                return frontend_error(
                    FrontendError::UnsupportedSyntax, token_span(tok), kQuestionDetail);
            default:
                return frontend_error(FrontendError::UnexpectedChar, token_span(tok), tok.text);
        }
        if (!out.tokens.push(tok))
            return frontend_error(FrontendError::TooManyTokens, token_span(tok));
    }

    Token eof{};
    eof.type = TokenType::Eof;
    eof.start = source.len;
    eof.end = source.len;
    eof.line = line;
    eof.col = col;
    eof.text = {source.ptr + source.len, 0};
    if (!out.tokens.push(eof)) return frontend_error(FrontendError::TooManyTokens, token_span(eof));
    return {};
}

FrontendResult<const LexedTokens*> lex_mapped(Str source, MappedArray<LexedTokens>& storage) {
    if (!storage.init(1)) return frontend_error(FrontendError::OutOfMemory, {});
    auto lexed = lex_into(source, storage[0]);
    if (!lexed) return core::make_unexpected(lexed.error());
    return &storage[0];
}

LexResult lex(Str source) {
    LexedTokens out{};
    auto lexed = lex_into(source, out);
    if (!lexed) return core::make_unexpected(lexed.error());
    return out;
}

}  // namespace rut
