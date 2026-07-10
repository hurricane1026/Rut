#include "rut/compiler/parser.h"

#include "rut/common/http_header_validation.h"
#include "rut/common/types.h"  // RUT_ENABLE_WEBSOCKET gate for the websocket() builder
#include "rut/runtime/http_parser.h"
#include <memory>

namespace rut {

namespace {

constexpr Str kGuardMatchArmIfDetail = lit_str("guard match arms do not support if guards");
constexpr Str kEmptyBlockDetail = lit_str("empty block is not supported");
constexpr Str kCaseDetail = lit_str("match arms do not use `case`; write `pattern => ...`");
constexpr Str kMatchColonDetail = lit_str("match arms use `=>`, not `:`");
// The words lex as plain identifiers (so `.or(default)` / `bitwise.and(...)`
// member names work); the parser rejects them in operator/operand positions.
constexpr Str kAndDetail = lit_str("`and` is not Rut syntax; use `&&`");
constexpr Str kOrDetail = lit_str("`or` is not Rut syntax; use `||`");
constexpr Str kNotDetail = lit_str("`not` is not Rut syntax; use `!`");

struct Parser {
    const LexedTokens* toks = nullptr;
    AstFile* file = nullptr;
    u32 pos = 0;
    // While parsing a match-arm body, a postfix `.` on a NEW line ends the
    // expression instead of chaining — the dot begins the next arm's
    // `.variant` pattern. Match arms have no `case` separator, so line
    // position is the only boundary signal (Swift-style newline sensitivity,
    // scoped to arm bodies only).
    bool arm_body_stops_cross_line_dot = false;
    // Depth of enclosing `(...)` / `[...]` while parsing an arm body. The
    // newline-dot boundary only applies at the top level of the arm body: a
    // line-broken member access inside a call argument or group (e.g.
    // `choose(req\n    .header("Host"))`) must chain normally, not be cut as
    // the next arm's pattern.
    u32 arm_body_dot_stop_depth = 0;

    // RAII: suspends the arm-body newline-dot boundary for the extent of a
    // parenthesized/bracketed sub-expression. Restores on every scope exit,
    // including the parser's early error returns.
    struct NestedDelimiterGuard {
        Parser* parser;
        explicit NestedDelimiterGuard(Parser* p) : parser(p) { parser->arm_body_dot_stop_depth++; }
        ~NestedDelimiterGuard() { parser->arm_body_dot_stop_depth--; }
        NestedDelimiterGuard(const NestedDelimiterGuard&) = delete;
        NestedDelimiterGuard& operator=(const NestedDelimiterGuard&) = delete;
    };

    const Token& cur() const { return toks->tokens[pos]; }
    const Token& prev() const { return toks->tokens[pos - 1]; }
    const Token& peek(u32 offset = 1) const {
        const u32 idx = pos + offset;
        if (idx >= toks->tokens.len) return toks->tokens[toks->tokens.len - 1];
        return toks->tokens[idx];
    }

    static Span span_from(const Token& tok) { return Span{tok.start, tok.end, tok.line, tok.col}; }

    const Token* take(TokenType type) {
        if (cur().type != type) return nullptr;
        return &toks->tokens[pos++];
    }

    FrontendResult<const Token*> expect(TokenType type) {
        if (cur().type == type) return &toks->tokens[pos++];
        if (cur().type == TokenType::Eof)
            return frontend_error(FrontendError::UnexpectedEof, span_from(cur()));
        return frontend_error(FrontendError::UnexpectedToken, span_from(cur()), cur().text);
    }

    FrontendResult<const Token*> expect_field_name() {
        if (cur().type == TokenType::Ident || cur().type == TokenType::KwFunc)
            return &toks->tokens[pos++];
        if (cur().type == TokenType::Eof)
            return frontend_error(FrontendError::UnexpectedEof, span_from(cur()));
        return frontend_error(FrontendError::UnexpectedToken, span_from(cur()), cur().text);
    }

    FrontendResult<AstExpr*> alloc_expr(const AstExpr& expr) {
        if (!file->expr_pool.push(expr))
            return frontend_error(FrontendError::TooManyItems, expr.span);
        return &file->expr_pool[file->expr_pool.len - 1];
    }

    FrontendResult<AstStatement*> alloc_stmt(const AstStatement& stmt) {
        if (!file->stmt_pool.push(stmt))
            return frontend_error(FrontendError::TooManyItems, stmt.span);
        return &file->stmt_pool[file->stmt_pool.len - 1];
    }

    FrontendResult<AstTypeRef*> alloc_type(const AstTypeRef& type) {
        if (!file->type_pool.push(type)) return frontend_error(FrontendError::TooManyItems, Span{});
        return &file->type_pool[file->type_pool.len - 1];
    }

    FrontendResult<AstStatement> parse_braced_stmt_body(const Token& lbrace_tok) {
        AstStatement block{};
        block.kind = AstStmtKind::Block;
        block.span = span_from(lbrace_tok);
        // A braced body is delimited by its closing brace, so the match-arm
        // newline-dot heuristic must not cut multiline member chains here.
        const bool saved_dot_stop = arm_body_stops_cross_line_dot;
        arm_body_stops_cross_line_dot = false;
        while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
            auto inner = parse_stmt();
            if (!inner) {
                arm_body_stops_cross_line_dot = saved_dot_stop;
                return core::make_unexpected(inner.error());
            }
            auto inner_ptr = alloc_stmt(inner.value());
            if (!inner_ptr) {
                arm_body_stops_cross_line_dot = saved_dot_stop;
                return core::make_unexpected(inner_ptr.error());
            }
            if (!block.block_stmts.push(inner_ptr.value())) {
                arm_body_stops_cross_line_dot = saved_dot_stop;
                return frontend_error(FrontendError::TooManyItems, inner->span);
            }
        }
        arm_body_stops_cross_line_dot = saved_dot_stop;
        auto rbrace = expect(TokenType::RBrace);
        if (!rbrace) return core::make_unexpected(rbrace.error());
        if (block.block_stmts.len == 0)
            return frontend_error(
                FrontendError::UnsupportedSyntax, span_from(*rbrace.value()), kEmptyBlockDetail);
        block.span.end = rbrace.value()->end;
        if (block.block_stmts.len == 1) return *block.block_stmts[0];
        return block;
    }

#if RUT_ENABLE_WEBSOCKET
    // Parse a WebSocket terminate-mode frame-handler body `{ ... }`. Distinct from
    // parse_braced_stmt_body because frame verdicts are **bare method-call statements**
    // (`frame.forward()`), which the general statement parser (parse_stmt) deliberately
    // rejects — its only statements are keyword-led (let/guard/return/if/match/...). Slice B
    // accepts only bare expression statements; guards/match over `frame` are follow-up slices.
    // Mirrors parse_braced_stmt_body's empty-block rejection and one-statement unwrap so analyze
    // sees the same body shape.
    FrontendResult<AstStatement> parse_ws_frame_body(const Token& lbrace_tok) {
        AstStatement block{};
        block.kind = AstStmtKind::Block;
        block.span = span_from(lbrace_tok);
        while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
            AstStatement st{};
            if (cur().type == TokenType::KwGuard) {
                // `guard <cond> else { <verdict> }` — a conditional verdict.
                const Token gt = cur();
                pos++;
                auto g = parse_ws_frame_guard(gt);
                if (!g) return core::make_unexpected(g.error());
                st = g.value();
            } else {
                auto expr = parse_expr();
                if (!expr) return core::make_unexpected(expr.error());
                st.kind = AstStmtKind::Expr;
                st.expr = expr.value();
                st.span = expr->span;
            }
            auto ptr = alloc_stmt(st);
            if (!ptr) return core::make_unexpected(ptr.error());
            if (!block.block_stmts.push(ptr.value()))
                return frontend_error(FrontendError::TooManyItems, st.span);
        }
        auto rbrace = expect(TokenType::RBrace);
        if (!rbrace) return core::make_unexpected(rbrace.error());
        if (block.block_stmts.len == 0)
            return frontend_error(
                FrontendError::UnsupportedSyntax, span_from(*rbrace.value()), kEmptyBlockDetail);
        block.span.end = rbrace.value()->end;
        if (block.block_stmts.len == 1) return *block.block_stmts[0];
        return block;
    }

    // Parse a frame-handler guard: `guard <cond> else { <verdict> }`. The condition is an
    // expression (analyze accepts only `frame.len <cmp> N` for now); the else body is a single
    // bare frame verdict (frame.drop()/forward()/close()). Reuses AstStmtKind::Guard with
    // expr=cond and else_stmt=the verdict Expr — the WsTerminate analyze path interprets it.
    FrontendResult<AstStatement> parse_ws_frame_guard(const Token& guard_tok) {
        // A leading `!` negates the condition (e.g. `guard !frame.text.matches(re"…")`).
        // It's consumed here, scoped to the frame guard, and carried on cond_negated for
        // the WsTerminate analyze path (which pattern-matches the bare condition shape).
        const bool negated = take(TokenType::Bang) != nullptr;
        auto cond = parse_expr();
        if (!cond) return core::make_unexpected(cond.error());
        auto kw_else = expect(TokenType::KwElse);
        if (!kw_else) return core::make_unexpected(kw_else.error());
        auto lbrace = expect(TokenType::LBrace);
        if (!lbrace) return core::make_unexpected(lbrace.error());
        auto verdict = parse_expr();
        if (!verdict) return core::make_unexpected(verdict.error());
        AstStatement vstmt{};
        vstmt.kind = AstStmtKind::Expr;
        vstmt.expr = verdict.value();
        vstmt.span = verdict->span;
        auto vptr = alloc_stmt(vstmt);
        if (!vptr) return core::make_unexpected(vptr.error());
        auto rbrace = expect(TokenType::RBrace);
        if (!rbrace) return core::make_unexpected(rbrace.error());
        AstStatement stmt{};
        stmt.kind = AstStmtKind::Guard;
        stmt.expr = cond.value();
        stmt.else_stmt = vptr.value();
        stmt.cond_negated = negated;
        stmt.span = Span{guard_tok.start, rbrace.value()->end, guard_tok.line, guard_tok.col};
        return stmt;
    }
#endif

    FrontendResult<AstStatement> parse_func_guard_stmt(const Token& guard_tok) {
        AstStatement stmt{};
        stmt.kind = AstStmtKind::Guard;
        const bool is_match_guard = take(TokenType::KwMatch) != nullptr;
        bool cond_done = false;
        if (!is_match_guard && take(TokenType::KwLet)) {
            auto name = expect(TokenType::Ident);
            if (!name) return core::make_unexpected(name.error());
            stmt.name = name.value()->text;
            stmt.bind_value = true;
            if (cur().type == TokenType::KwElse) {
                // Swift 5.7 shorthand: `guard let x else { ... }` rebinds an
                // existing optional name — sugar for `guard let x = x else`.
                AstExpr self_ref{};
                self_ref.kind = AstExprKind::Ident;
                self_ref.name = stmt.name;
                self_ref.span = span_from(*name.value());
                stmt.expr = self_ref;
                cond_done = true;
            } else {
                auto eq = expect(TokenType::Eq);
                if (!eq) return core::make_unexpected(eq.error());
            }
        }
        if (!cond_done) {
            auto cond = parse_expr();
            if (!cond) return core::make_unexpected(cond.error());
            stmt.expr = cond.value();
        }
        auto kw_else = expect(TokenType::KwElse);
        if (!kw_else) return core::make_unexpected(kw_else.error());
        auto lbrace = expect(TokenType::LBrace);
        if (!lbrace) return core::make_unexpected(lbrace.error());
        if (is_match_guard) {
            while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
                if (cur().type == TokenType::Ident && cur().text.eq({"case", 4}))
                    return frontend_error(
                        FrontendError::UnsupportedSyntax, span_from(cur()), kCaseDetail);
                AstStatement::MatchArm arm{};
                arm.span = span_from(cur());
                if (take(TokenType::Underscore)) {
                    arm.is_wildcard = true;
                } else {
                    auto pattern = parse_primary_expr();
                    if (!pattern) return core::make_unexpected(pattern.error());
                    auto pattern_ptr = alloc_expr(pattern.value());
                    if (!pattern_ptr) return core::make_unexpected(pattern_ptr.error());
                    arm.pattern = pattern_ptr.value();
                }
                if (const Token* kw_if = take(TokenType::KwIf))
                    return frontend_error(FrontendError::UnsupportedSyntax,
                                          span_from(*kw_if),
                                          kGuardMatchArmIfDetail);
                if (cur().type == TokenType::Colon)
                    return frontend_error(
                        FrontendError::UnsupportedSyntax, span_from(cur()), kMatchColonDetail);
                auto arrow = expect(TokenType::Arrow);
                if (!arrow) return core::make_unexpected(arrow.error());
                const bool saved_dot_stop = arm_body_stops_cross_line_dot;
                arm_body_stops_cross_line_dot = arm_body_needs_dot_stop();
                auto arm_stmt = parse_func_body_stmt();
                arm_body_stops_cross_line_dot = saved_dot_stop;
                if (!arm_stmt) return core::make_unexpected(arm_stmt.error());
                if (arm_stmt->kind == AstStmtKind::RespondStatus)
                    return frontend_error(FrontendError::UnsupportedSyntax, arm_stmt->span);
                auto arm_ptr = alloc_stmt(arm_stmt.value());
                if (!arm_ptr) return core::make_unexpected(arm_ptr.error());
                arm.stmt = arm_ptr.value();
                arm.span.end = arm_ptr.value()->span.end;
                if (!stmt.match_arms.push(arm))
                    return frontend_error(FrontendError::TooManyItems, arm.span);
            }
            auto rbrace = expect(TokenType::RBrace);
            if (!rbrace) return core::make_unexpected(rbrace.error());
            if (stmt.match_arms.len == 0)
                return frontend_error(FrontendError::UnexpectedToken, span_from(*rbrace.value()));
            stmt.span = Span{guard_tok.start, rbrace.value()->end, guard_tok.line, guard_tok.col};
            return stmt;
        }
        auto else_stmt = parse_func_body_stmt();
        if (!else_stmt) return core::make_unexpected(else_stmt.error());
        auto rbrace = expect(TokenType::RBrace);
        if (!rbrace) return core::make_unexpected(rbrace.error());
        auto else_ptr = alloc_stmt(else_stmt.value());
        if (!else_ptr) return core::make_unexpected(else_ptr.error());
        stmt.else_stmt = else_ptr.value();
        stmt.span = Span{guard_tok.start, rbrace.value()->end, guard_tok.line, guard_tok.col};
        return stmt;
    }

    FrontendResult<AstExpr> parse_primary_atom() {
        const Token start = cur();
        AstExpr expr{};
        if (take(TokenType::LBracket)) {
            NestedDelimiterGuard nested(this);
            AstExpr arr{};
            arr.kind = AstExprKind::ArrayLit;
            while (!take(TokenType::RBracket)) {
                auto elem = parse_expr();
                if (!elem) return core::make_unexpected(elem.error());
                auto elem_ptr = alloc_expr(elem.value());
                if (!elem_ptr) return core::make_unexpected(elem_ptr.error());
                if (!arr.args.push(elem_ptr.value()))
                    return frontend_error(FrontendError::TooManyItems, elem->span);
                if (take(TokenType::RBracket)) break;
                auto comma = expect(TokenType::Comma);
                if (!comma) return core::make_unexpected(comma.error());
            }
            arr.span = Span{start.start, prev().end, start.line, start.col};
            return arr;
        }
        if (take(TokenType::LParen)) {
            NestedDelimiterGuard nested(this);
            auto first = parse_expr();
            if (!first) return core::make_unexpected(first.error());
            if (!take(TokenType::Comma)) {
                auto rparen = expect(TokenType::RParen);
                if (!rparen) return core::make_unexpected(rparen.error());
                return first.value();
            }

            AstExpr tuple{};
            tuple.kind = AstExprKind::Tuple;
            auto first_ptr = alloc_expr(first.value());
            if (!first_ptr) return core::make_unexpected(first_ptr.error());
            if (!tuple.args.push(first_ptr.value()))
                return frontend_error(FrontendError::TooManyItems, first->span);
            while (true) {
                auto elem = parse_expr();
                if (!elem) return core::make_unexpected(elem.error());
                auto elem_ptr = alloc_expr(elem.value());
                if (!elem_ptr) return core::make_unexpected(elem_ptr.error());
                if (!tuple.args.push(elem_ptr.value()))
                    return frontend_error(FrontendError::TooManyItems, elem->span);
                if (take(TokenType::RParen)) break;
                auto comma = expect(TokenType::Comma);
                if (!comma) return core::make_unexpected(comma.error());
            }
            tuple.span = Span{start.start, prev().end, start.line, start.col};
            return tuple;
        }
        if (take(TokenType::Underscore)) {
            expr.kind = AstExprKind::Placeholder;
            expr.int_value = 1;
            expr.span = span_from(prev());
            return expr;
        }
        if (take(TokenType::Dot)) {
            auto case_name = expect(TokenType::Ident);
            if (!case_name) return core::make_unexpected(case_name.error());
            expr.kind = AstExprKind::VariantCase;
            expr.str_value = case_name.value()->text;
            if (take(TokenType::LParen)) {
                NestedDelimiterGuard nested(this);
                auto payload = parse_expr();
                if (!payload) return core::make_unexpected(payload.error());
                auto rparen = expect(TokenType::RParen);
                if (!rparen) return core::make_unexpected(rparen.error());
                auto payload_ptr = alloc_expr(payload.value());
                if (!payload_ptr) return core::make_unexpected(payload_ptr.error());
                expr.lhs = payload_ptr.value();
                expr.span = Span{start.start, rparen.value()->end, start.line, start.col};
                return expr;
            }
            expr.span = Span{start.start, case_name.value()->end, start.line, start.col};
            return expr;
        }
        if (take(TokenType::KwWait)) {
            auto lparen = expect(TokenType::LParen);
            if (!lparen) return core::make_unexpected(lparen.error());
            expr.kind = AstExprKind::Wait;
            if (const Token* rparen = take(TokenType::RParen)) {
                expr.wait_event_kind = WaitEventKind::Any;
                expr.span = Span{start.start, rparen->end, start.line, start.col};
                return expr;
            }
            const Token* arg = nullptr;
            if (const Token* t = take(TokenType::IntLit)) {
                arg = t;
            } else if (const Token* t = take(TokenType::DurLit)) {
                arg = t;
            } else {
                auto op = parse_expr();
                if (!op) return core::make_unexpected(op.error());
                auto op_ptr = alloc_expr(op.value());
                if (!op_ptr) return core::make_unexpected(op_ptr.error());
                auto rparen = expect(TokenType::RParen);
                if (!rparen) return core::make_unexpected(rparen.error());
                expr.lhs = op_ptr.value();
                expr.wait_event_kind = WaitEventKind::Any;
                expr.span = Span{start.start, rparen.value()->end, start.line, start.col};
                return expr;
            }
            u32 digit_len = arg->text.len;
            u64 multiplier_ms = 1;
            if (arg->type == TokenType::DurLit) {
                if (digit_len >= 2 && arg->text.ptr[digit_len - 2] == 'm' &&
                    arg->text.ptr[digit_len - 1] == 's') {
                    digit_len -= 2;
                } else if (digit_len >= 1) {
                    const char unit = arg->text.ptr[digit_len - 1];
                    digit_len -= 1;
                    if (unit == 's')
                        multiplier_ms = 1000;
                    else if (unit == 'm')
                        multiplier_ms = 60ull * 1000;
                    else if (unit == 'h')
                        multiplier_ms = 3600ull * 1000;
                    else
                        return frontend_error(
                            FrontendError::InvalidInteger, span_from(*arg), arg->text);
                }
            }
            u64 value = 0;
            for (u32 i = 0; i < digit_len; i++) {
                const u32 digit = static_cast<u32>(arg->text.ptr[i] - '0');
                if (value > (static_cast<u64>(0xffffffffu) - static_cast<u64>(digit)) / 10)
                    return frontend_error(
                        FrontendError::InvalidInteger, span_from(*arg), arg->text);
                value = value * 10 + static_cast<u64>(digit);
            }
            const u64 ms = value * multiplier_ms;
            if (ms > 0xffffffffull)
                return frontend_error(FrontendError::InvalidInteger, span_from(*arg), arg->text);
            auto rparen = expect(TokenType::RParen);
            if (!rparen) return core::make_unexpected(rparen.error());
            expr.wait_event_kind = WaitEventKind::Timer;
            expr.wait_ms = static_cast<u32>(ms);
            expr.span = Span{start.start, rparen.value()->end, start.line, start.col};
            return expr;
        }
        if (take(TokenType::KwTrue)) {
            expr.kind = AstExprKind::BoolLit;
            expr.bool_value = true;
            expr.span = span_from(prev());
            return expr;
        }
        if (take(TokenType::KwFalse)) {
            expr.kind = AstExprKind::BoolLit;
            expr.bool_value = false;
            expr.span = span_from(prev());
            return expr;
        }
        if (take(TokenType::KwNil)) {
            expr.kind = AstExprKind::Nil;
            expr.span = span_from(prev());
            return expr;
        }
        if (take(TokenType::KwError)) {
            auto lparen = expect(TokenType::LParen);
            if (!lparen) return core::make_unexpected(lparen.error());
            if (cur().type == TokenType::Ident && peek().type == TokenType::Comma) {
                auto type_name = expect(TokenType::Ident);
                if (!type_name) return core::make_unexpected(type_name.error());
                expr.name = type_name.value()->text;
                auto comma = expect(TokenType::Comma);
                if (!comma) return core::make_unexpected(comma.error());
            }
            auto arg = parse_expr();
            if (!arg) return core::make_unexpected(arg.error());
            Str msg{};
            if (take(TokenType::Comma)) {
                auto msg_expr = parse_expr();
                if (!msg_expr) return core::make_unexpected(msg_expr.error());
                if (msg_expr->kind != AstExprKind::StrLit)
                    return frontend_error(
                        FrontendError::UnsupportedSyntax,
                        msg_expr->span,
                        lit_str("error message argument must be a string literal"));
                msg = msg_expr->str_value;
                while (take(TokenType::Comma)) {
                    auto field_name = expect_field_name();
                    if (!field_name) return core::make_unexpected(field_name.error());
                    auto colon = expect(TokenType::Colon);
                    if (!colon) return core::make_unexpected(colon.error());
                    auto field_value = parse_expr();
                    if (!field_value) return core::make_unexpected(field_value.error());
                    auto field_value_ptr = alloc_expr(field_value.value());
                    if (!field_value_ptr) return core::make_unexpected(field_value_ptr.error());
                    AstExpr::FieldInit field_init{};
                    field_init.name = field_name.value()->text;
                    field_init.value = field_value_ptr.value();
                    if (!expr.field_inits.push(field_init))
                        return frontend_error(FrontendError::TooManyItems, field_value->span);
                }
            }
            auto rparen = expect(TokenType::RParen);
            if (!rparen) return core::make_unexpected(rparen.error());
            auto arg_ptr = alloc_expr(arg.value());
            if (!arg_ptr) return core::make_unexpected(arg_ptr.error());
            expr.kind = AstExprKind::Error;
            expr.lhs = arg_ptr.value();
            expr.msg = msg;
            expr.span = Span{start.start, rparen.value()->end, start.line, start.col};
            return expr;
        }
        if (cur().type == TokenType::IntLit) {
            const Token tok = cur();
            pos++;
            i32 value = 0;
            for (u32 i = 0; i < tok.text.len; i++) {
                const u32 digit = static_cast<u32>(tok.text.ptr[i] - '0');
                if (value > (static_cast<i32>(0x7fffffff) - static_cast<i32>(digit)) / 10)
                    return frontend_error(FrontendError::InvalidInteger, span_from(tok), tok.text);
                value = value * 10 + static_cast<i32>(digit);
            }
            expr.kind = AstExprKind::IntLit;
            expr.int_value = value;
            expr.span = span_from(tok);
            return expr;
        }
        if (cur().type == TokenType::StringLit) {
            const Token tok = cur();
            pos++;
            expr.kind = AstExprKind::StrLit;
            expr.str_value = tok.text;
            expr.span = span_from(tok);
            return expr;
        }
        if (cur().type == TokenType::RegexLit) {
            const Token tok = cur();
            pos++;
            expr.kind = AstExprKind::RegexLit;
            expr.str_value = tok.text;
            expr.span = span_from(tok);
            return expr;
        }
        // HTTP method literals as expressions (POST, GET, …). The
        // lexer already tokenizes these as KwGet/KwPost/etc.; until
        // now they were only consumed in route declarations. Map
        // each keyword to the HttpMethod enum value stored in
        // int_value — sourcing from the runtime enum rather than
        // hard-coded integers so the two stay in sync if the enum
        // ever shifts. Lets `POST` etc. appear in contexts like
        // `guard req.method == POST else { … }`.
        if (is_method_keyword(cur().type)) {
            const Token tok = cur();
            pos++;
            expr.kind = AstExprKind::LitMethod;
            switch (tok.type) {
                case TokenType::KwGet:
                    expr.int_value = static_cast<i32>(HttpMethod::GET);
                    break;
                case TokenType::KwPost:
                    expr.int_value = static_cast<i32>(HttpMethod::POST);
                    break;
                case TokenType::KwPut:
                    expr.int_value = static_cast<i32>(HttpMethod::PUT);
                    break;
                case TokenType::KwDelete:
                    expr.int_value = static_cast<i32>(HttpMethod::DELETE);
                    break;
                case TokenType::KwPatch:
                    expr.int_value = static_cast<i32>(HttpMethod::PATCH);
                    break;
                case TokenType::KwHead:
                    expr.int_value = static_cast<i32>(HttpMethod::HEAD);
                    break;
                case TokenType::KwOptions:
                    expr.int_value = static_cast<i32>(HttpMethod::OPTIONS);
                    break;
                default:
                    return frontend_error(FrontendError::UnsupportedSyntax, span_from(tok));
            }
            expr.span = span_from(tok);
            return expr;
        }
        if (cur().type == TokenType::KwUpstream || cur().type == TokenType::KwDownstream) {
            const Token tok = cur();
            pos++;
            expr.kind = AstExprKind::Ident;
            expr.name = tok.text;
            expr.span = span_from(tok);
            return expr;
        }
        auto ident = expect(TokenType::Ident);
        if (!ident) return core::make_unexpected(ident.error());
        if (ident.value()->text.len >= 2 && ident.value()->text.ptr[0] == '_') {
            bool all_digits = true;
            i32 index = 0;
            for (u32 i = 1; i < ident.value()->text.len; i++) {
                const char ch = ident.value()->text.ptr[i];
                if (ch < '0' || ch > '9') {
                    all_digits = false;
                    break;
                }
                index = index * 10 + static_cast<i32>(ch - '0');
            }
            if (all_digits && index > 0) {
                if (index > 10)
                    return frontend_error(FrontendError::UnsupportedSyntax,
                                          span_from(*ident.value()),
                                          lit_str("placeholder index must be between _1 and _10"));
                expr.kind = AstExprKind::Placeholder;
                expr.int_value = index;
                expr.span = span_from(*ident.value());
                return expr;
            }
        }
        expr.kind = AstExprKind::Ident;
        expr.name = ident.value()->text;
        expr.span = span_from(*ident.value());
        return expr;
    }

    FrontendResult<AstExpr> parse_primary_expr() {
        auto base = parse_primary_atom();
        if (!base) return core::make_unexpected(base.error());
        AstExpr expr = base.value();
        while (true) {
            if (expr.kind == AstExprKind::Ident && expr.type_args.len == 0 &&
                cur().type == TokenType::Lt) {
                const u32 saved_pos = pos;
                pos++;
                FixedVec<AstTypeRef, AstExpr::kMaxTypeArgs> parsed_type_args;
                bool parsed_ok = false;
                while (true) {
                    auto type_arg = parse_func_type_ref();
                    if (!type_arg) {
                        pos = saved_pos;
                        break;
                    }
                    if (!parsed_type_args.push(type_arg.value()))
                        return frontend_error(FrontendError::TooManyItems, expr.span);
                    if (take(TokenType::Gt)) {
                        if (cur().type == TokenType::LParen || cur().type == TokenType::Dot) {
                            expr.type_args = parsed_type_args;
                            parsed_ok = true;
                        } else {
                            pos = saved_pos;
                        }
                        break;
                    }
                    if (!take(TokenType::Comma)) {
                        pos = saved_pos;
                        break;
                    }
                }
                if (parsed_ok) continue;
            }
            if (take(TokenType::LParen)) {
                NestedDelimiterGuard nested(this);
                if (expr.kind != AstExprKind::Ident)
                    return frontend_error(FrontendError::UnsupportedSyntax, expr.span);
                if (!take(TokenType::RParen) &&
                    (cur().type == TokenType::Ident || cur().type == TokenType::KwFunc) &&
                    peek().type == TokenType::Colon) {
                    AstExpr init{};
                    init.kind = AstExprKind::StructInit;
                    init.name = expr.name;
                    init.type_args = expr.type_args;
                    init.span = expr.span;
                    while (true) {
                        auto field_name = expect_field_name();
                        if (!field_name) return core::make_unexpected(field_name.error());
                        auto colon = expect(TokenType::Colon);
                        if (!colon) return core::make_unexpected(colon.error());
                        auto field_value = parse_expr();
                        if (!field_value) return core::make_unexpected(field_value.error());
                        auto field_value_ptr = alloc_expr(field_value.value());
                        if (!field_value_ptr) return core::make_unexpected(field_value_ptr.error());
                        AstExpr::FieldInit field_init{};
                        field_init.name = field_name.value()->text;
                        field_init.value = field_value_ptr.value();
                        if (!init.field_inits.push(field_init))
                            return frontend_error(FrontendError::TooManyItems, field_value->span);
                        if (take(TokenType::RParen)) break;
                        auto comma = expect(TokenType::Comma);
                        if (!comma) return core::make_unexpected(comma.error());
                    }
                    init.span.end = prev().end;
                    expr = init;
                } else {
                    AstExpr call{};
                    call.kind = AstExprKind::Call;
                    call.name = expr.name;
                    call.type_args = expr.type_args;
                    call.span = expr.span;
                    if (prev().type != TokenType::RParen) {
                        while (true) {
                            auto arg = parse_expr();
                            if (!arg) return core::make_unexpected(arg.error());
                            auto arg_ptr = alloc_expr(arg.value());
                            if (!arg_ptr) return core::make_unexpected(arg_ptr.error());
                            if (!call.args.push(arg_ptr.value()))
                                return frontend_error(FrontendError::TooManyItems, arg->span);
                            if (take(TokenType::RParen)) break;
                            auto comma = expect(TokenType::Comma);
                            if (!comma) return core::make_unexpected(comma.error());
                        }
                    }
                    call.span.end = prev().end;
                    expr = call;
                }
                continue;
            }
            if (arm_body_stops_cross_line_dot && arm_body_dot_stop_depth == 0 &&
                cur().type == TokenType::Dot && pos > 0 && cur().line != prev().line) {
                break;  // new-line `.x` starts the next match arm's pattern
            }
            if (!take(TokenType::Dot)) break;
            const Token* field_name = nullptr;
            // After `.` the token is a member name, not a statement keyword, so a reserved
            // word there is unambiguous. `func` is already allowed; `forward` is allowed too
            // so the WebSocket frame verdict can be spelled `frame.forward()` even though
            // `forward` is the proxy-terminator keyword (the `frame.` receiver disambiguates).
            if (cur().type == TokenType::Ident || cur().type == TokenType::KwFunc ||
                cur().type == TokenType::KwForward) {
                field_name = &cur();
                pos++;
            } else {
                auto expected = expect(TokenType::Ident);
                if (!expected) return core::make_unexpected(expected.error());
                field_name = expected.value();
            }
            auto lhs_ptr = alloc_expr(expr);
            if (!lhs_ptr) return core::make_unexpected(lhs_ptr.error());
            AstExpr field{};
            field.kind = AstExprKind::Field;
            field.lhs = lhs_ptr.value();
            field.name = field_name->text;
            field.span = Span{expr.span.start, field_name->end, expr.span.line, expr.span.col};
            if (cur().type == TokenType::Lt) {
                const u32 saved_pos = pos;
                pos++;
                FixedVec<AstTypeRef, AstExpr::kMaxTypeArgs> parsed_type_args;
                bool parsed_ok = false;
                while (true) {
                    auto type_arg = parse_func_type_ref();
                    if (!type_arg) {
                        pos = saved_pos;
                        break;
                    }
                    if (!parsed_type_args.push(type_arg.value()))
                        return frontend_error(FrontendError::TooManyItems, field.span);
                    if (take(TokenType::Gt)) {
                        if (cur().type == TokenType::LParen || cur().type == TokenType::Dot) {
                            field.type_args = parsed_type_args;
                            parsed_ok = true;
                        } else {
                            pos = saved_pos;
                        }
                        break;
                    }
                    if (!take(TokenType::Comma)) {
                        pos = saved_pos;
                        break;
                    }
                }
                if (parsed_ok) {
                    field.span.end = prev().end;
                }
            }
            if (take(TokenType::LParen)) {
                NestedDelimiterGuard nested(this);
                const u32 after_lparen = pos;
                const bool maybe_named_init =
                    expr.kind == AstExprKind::Ident && cur().type != TokenType::RParen &&
                    (cur().type == TokenType::Ident || cur().type == TokenType::KwFunc) &&
                    peek().type == TokenType::Colon;
                if (maybe_named_init) {
                    AstExpr init{};
                    init.kind = AstExprKind::StructInit;
                    init.lhs = lhs_ptr.value();
                    init.name = field.name;
                    init.span = field.span;
                    while (true) {
                        auto field_name = expect_field_name();
                        if (!field_name) return core::make_unexpected(field_name.error());
                        auto colon = expect(TokenType::Colon);
                        if (!colon) return core::make_unexpected(colon.error());
                        auto field_value = parse_expr();
                        if (!field_value) return core::make_unexpected(field_value.error());
                        auto field_value_ptr = alloc_expr(field_value.value());
                        if (!field_value_ptr) return core::make_unexpected(field_value_ptr.error());
                        AstExpr::FieldInit field_init{};
                        field_init.name = field_name.value()->text;
                        field_init.value = field_value_ptr.value();
                        if (!init.field_inits.push(field_init))
                            return frontend_error(FrontendError::TooManyItems, field_value->span);
                        if (take(TokenType::RParen)) break;
                        auto comma = expect(TokenType::Comma);
                        if (!comma) return core::make_unexpected(comma.error());
                    }
                    init.span.end = prev().end;
                    expr = init;
                } else {
                    pos = after_lparen;
                    AstExpr method{};
                    method.kind = AstExprKind::MethodCall;
                    method.lhs = lhs_ptr.value();
                    method.name = field.name;
                    method.span = field.span;
                    if (!take(TokenType::RParen)) {
                        while (true) {
                            auto arg = parse_expr();
                            if (!arg) return core::make_unexpected(arg.error());
                            auto arg_ptr = alloc_expr(arg.value());
                            if (!arg_ptr) return core::make_unexpected(arg_ptr.error());
                            if (!method.args.push(arg_ptr.value()))
                                return frontend_error(FrontendError::TooManyItems, arg->span);
                            if (take(TokenType::RParen)) break;
                            auto comma = expect(TokenType::Comma);
                            if (!comma) return core::make_unexpected(comma.error());
                        }
                    }
                    method.span.end = prev().end;
                    expr = method;
                }
            } else {
                expr = field;
            }
        }
        return expr;
    }

    // Wrap `operand` as `operand == false` — the parse-time desugar shared by
    // prefix `!` and the negated comparisons (`!=`, `<=`, `>=`). No new
    // AST/HIR/MIR node kinds are needed; Bool equality lowers like any Eq.
    FrontendResult<AstExpr> make_eq_false(AstExpr operand) {
        AstExpr false_lit{};
        false_lit.kind = AstExprKind::BoolLit;
        false_lit.bool_value = false;
        false_lit.span = operand.span;
        auto lhs_ptr = alloc_expr(operand);
        if (!lhs_ptr) return core::make_unexpected(lhs_ptr.error());
        auto rhs_ptr = alloc_expr(false_lit);
        if (!rhs_ptr) return core::make_unexpected(rhs_ptr.error());
        AstExpr expr{};
        expr.kind = AstExprKind::Eq;
        expr.lhs = lhs_ptr.value();
        expr.rhs = rhs_ptr.value();
        expr.span = operand.span;
        return expr;
    }

    // An arm body that starts with a statement keyword (or a brace) is
    // self-delimiting — only bare-expression bodies (and `return <expr>`
    // tails) need the newline-dot arm boundary.
    bool arm_body_needs_dot_stop() const {
        const TokenType t = cur().type;
        if (t == TokenType::LBrace) return false;
        if (t == TokenType::KwIf || t == TokenType::KwMatch || t == TokenType::KwGuard ||
            t == TokenType::KwLet || t == TokenType::KwFor || t == TokenType::KwWait ||
            t == TokenType::KwForward)
            return false;
        return true;
    }

    // Removed word-operator check for operand position (`not x`, `or(a, b)`,
    // `and(a, b)`). Member names after `.` never reach here, so `.or(...)`
    // and `bitwise.and(...)` stay valid.
    FrontendResult<bool> reject_word_operator_operand() {
        if (cur().type != TokenType::Ident) return true;
        if (cur().text.eq({"and", 3}))
            return frontend_error(FrontendError::UnsupportedSyntax, span_from(cur()), kAndDetail);
        if (cur().text.eq({"or", 2}))
            return frontend_error(FrontendError::UnsupportedSyntax, span_from(cur()), kOrDetail);
        if (cur().text.eq({"not", 3}))
            return frontend_error(FrontendError::UnsupportedSyntax, span_from(cur()), kNotDetail);
        return true;
    }

    // Prefix `!` — Swift-identical logical not, binds tighter than comparisons.
    FrontendResult<AstExpr> parse_unary_expr() {
        auto word_check = reject_word_operator_operand();
        if (!word_check) return core::make_unexpected(word_check.error());
        const Token* bang = take(TokenType::Bang);
        if (!bang) return parse_primary_expr();
        auto operand = parse_unary_expr();
        if (!operand) return core::make_unexpected(operand.error());
        auto expr = make_eq_false(operand.value());
        if (!expr) return core::make_unexpected(expr.error());
        AstExpr out = expr.value();
        out.span = Span{bang->start, operand->span.end, bang->line, bang->col};
        return out;
    }

    FrontendResult<AstExpr> parse_eq_expr() {
        auto lhs = parse_unary_expr();
        if (!lhs) return core::make_unexpected(lhs.error());
        TokenType op = TokenType::Error;
        if (take(TokenType::EqEq))
            op = TokenType::EqEq;
        else if (take(TokenType::BangEq))
            op = TokenType::BangEq;
        else if (take(TokenType::LtEq))
            op = TokenType::LtEq;
        else if (take(TokenType::GtEq))
            op = TokenType::GtEq;
        else if (take(TokenType::Lt))
            op = TokenType::Lt;
        else if (take(TokenType::Gt))
            op = TokenType::Gt;
        else
            return lhs.value();
        auto rhs = parse_unary_expr();
        if (!rhs) return core::make_unexpected(rhs.error());
        auto lhs_ptr = alloc_expr(lhs.value());
        if (!lhs_ptr) return core::make_unexpected(lhs_ptr.error());
        auto rhs_ptr = alloc_expr(rhs.value());
        if (!rhs_ptr) return core::make_unexpected(rhs_ptr.error());
        AstExpr expr{};
        // `!=` → `(a == b) == false`, `<=` → `(a > b) == false`,
        // `>=` → `(a < b) == false` — parse-time desugar, see make_eq_false.
        const bool negate =
            op == TokenType::BangEq || op == TokenType::LtEq || op == TokenType::GtEq;
        if (op == TokenType::EqEq || op == TokenType::BangEq)
            expr.kind = AstExprKind::Eq;
        else if (op == TokenType::Lt || op == TokenType::GtEq)
            expr.kind = AstExprKind::Lt;
        else
            expr.kind = AstExprKind::Gt;
        expr.lhs = lhs_ptr.value();
        expr.rhs = rhs_ptr.value();
        expr.span = Span{lhs->span.start, rhs->span.end, lhs->span.line, lhs->span.col};
        if (!negate) return expr;
        auto negated = make_eq_false(expr);
        if (!negated) return core::make_unexpected(negated.error());
        AstExpr out = negated.value();
        out.span = expr.span;
        return out;
    }

    FrontendResult<AstExpr> parse_and_expr() {
        auto lhs = parse_eq_expr();
        if (!lhs) return core::make_unexpected(lhs.error());
        while (true) {
            // Operator-position fix-it: `a and b`.
            if (cur().type == TokenType::Ident && cur().text.eq({"and", 3}))
                return frontend_error(
                    FrontendError::UnsupportedSyntax, span_from(cur()), kAndDetail);
            if (!take(TokenType::AmpAmp)) break;
            auto rhs = parse_eq_expr();
            if (!rhs) return core::make_unexpected(rhs.error());
            auto lhs_ptr = alloc_expr(lhs.value());
            if (!lhs_ptr) return core::make_unexpected(lhs_ptr.error());
            auto rhs_ptr = alloc_expr(rhs.value());
            if (!rhs_ptr) return core::make_unexpected(rhs_ptr.error());
            AstExpr expr{};
            expr.kind = AstExprKind::And;
            expr.lhs = lhs_ptr.value();
            expr.rhs = rhs_ptr.value();
            expr.span = Span{lhs->span.start, rhs->span.end, lhs->span.line, lhs->span.col};
            lhs = expr;
        }
        return lhs.value();
    }

    // `&&` binds tighter than `||` (Swift/C precedence).
    FrontendResult<AstExpr> parse_or_expr() {
        auto lhs = parse_and_expr();
        if (!lhs) return core::make_unexpected(lhs.error());
        while (true) {
            // Operator-position fix-it: `a or b`.
            if (cur().type == TokenType::Ident && cur().text.eq({"or", 2}))
                return frontend_error(
                    FrontendError::UnsupportedSyntax, span_from(cur()), kOrDetail);
            if (!take(TokenType::PipePipe)) break;
            auto rhs = parse_and_expr();
            if (!rhs) return core::make_unexpected(rhs.error());
            auto lhs_ptr = alloc_expr(lhs.value());
            if (!lhs_ptr) return core::make_unexpected(lhs_ptr.error());
            auto rhs_ptr = alloc_expr(rhs.value());
            if (!rhs_ptr) return core::make_unexpected(rhs_ptr.error());
            AstExpr expr{};
            expr.kind = AstExprKind::Or;
            expr.lhs = lhs_ptr.value();
            expr.rhs = rhs_ptr.value();
            expr.span = Span{lhs->span.start, rhs->span.end, lhs->span.line, lhs->span.col};
            lhs = expr;
        }
        return lhs.value();
    }

    FrontendResult<AstExpr> parse_expr() {
        auto lhs = parse_or_expr();
        if (!lhs) return core::make_unexpected(lhs.error());
        while (take(TokenType::Pipe)) {
            auto rhs = parse_eq_expr();
            if (!rhs) return core::make_unexpected(rhs.error());
            auto lhs_ptr = alloc_expr(lhs.value());
            if (!lhs_ptr) return core::make_unexpected(lhs_ptr.error());
            auto rhs_ptr = alloc_expr(rhs.value());
            if (!rhs_ptr) return core::make_unexpected(rhs_ptr.error());
            AstExpr expr{};
            expr.kind = AstExprKind::Pipe;
            expr.lhs = lhs_ptr.value();
            expr.rhs = rhs_ptr.value();
            expr.span = Span{lhs->span.start, rhs->span.end, lhs->span.line, lhs->span.col};
            lhs = expr;
        }
        return lhs.value();
    }

    FrontendResult<AstStatement> parse_stmt() {
        const Token start = cur();
        if (take(TokenType::LBrace)) {
            AstStatement stmt{};
            stmt.kind = AstStmtKind::Block;
            stmt.span = span_from(start);
            // Braced blocks are brace-delimited — suspend the match-arm
            // newline-dot heuristic so multiline member chains parse.
            const bool saved_dot_stop = arm_body_stops_cross_line_dot;
            arm_body_stops_cross_line_dot = false;
            while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
                auto inner = parse_stmt();
                if (!inner) {
                    arm_body_stops_cross_line_dot = saved_dot_stop;
                    return core::make_unexpected(inner.error());
                }
                auto inner_ptr = alloc_stmt(inner.value());
                if (!inner_ptr) {
                    arm_body_stops_cross_line_dot = saved_dot_stop;
                    return core::make_unexpected(inner_ptr.error());
                }
                if (!stmt.block_stmts.push(inner_ptr.value())) {
                    arm_body_stops_cross_line_dot = saved_dot_stop;
                    return frontend_error(FrontendError::TooManyItems, inner->span);
                }
            }
            arm_body_stops_cross_line_dot = saved_dot_stop;
            auto rbrace = expect(TokenType::RBrace);
            if (!rbrace) return core::make_unexpected(rbrace.error());
            if (stmt.block_stmts.len == 0)
                return frontend_error(FrontendError::UnsupportedSyntax,
                                      span_from(*rbrace.value()),
                                      kEmptyBlockDetail);
            stmt.span.end = rbrace.value()->end;
            return stmt;
        }
        if (take(TokenType::KwLet)) {
            auto name = expect(TokenType::Ident);
            if (!name) return core::make_unexpected(name.error());
            AstTypeRef type_ref{};
            bool has_type = false;
            if (take(TokenType::Colon)) {
                auto parsed_type = parse_func_type_ref();
                if (!parsed_type) return core::make_unexpected(parsed_type.error());
                type_ref = parsed_type.value();
                has_type = true;
            }
            auto eq = expect(TokenType::Eq);
            if (!eq) return core::make_unexpected(eq.error());
            auto init = parse_expr();
            if (!init) return core::make_unexpected(init.error());
            AstStatement stmt{};
            stmt.kind = AstStmtKind::Let;
            stmt.name = name.value()->text;
            stmt.has_type = has_type;
            stmt.type = type_ref;
            stmt.expr = init.value();
            stmt.span = Span{start.start, init->span.end, start.line, start.col};
            return stmt;
        }
        if (take(TokenType::KwGuard)) {
            const bool is_match_guard = take(TokenType::KwMatch) != nullptr;
            Str bind_name{};
            bool bind_value = false;
            AstExpr cond_expr{};
            bool cond_done = false;
            if (!is_match_guard && take(TokenType::KwLet)) {
                auto name = expect(TokenType::Ident);
                if (!name) return core::make_unexpected(name.error());
                bind_name = name.value()->text;
                bind_value = true;
                if (cur().type == TokenType::KwElse) {
                    // Swift 5.7 shorthand: `guard let x else { ... }` rebinds
                    // an existing optional name — sugar for `guard let x = x`.
                    cond_expr.kind = AstExprKind::Ident;
                    cond_expr.name = bind_name;
                    cond_expr.span = span_from(*name.value());
                    cond_done = true;
                } else {
                    auto eq = expect(TokenType::Eq);
                    if (!eq) return core::make_unexpected(eq.error());
                }
            }
            if (!cond_done) {
                auto cond = parse_expr();
                if (!cond) return core::make_unexpected(cond.error());
                cond_expr = cond.value();
            }
            auto kw_else = expect(TokenType::KwElse);
            if (!kw_else) return core::make_unexpected(kw_else.error());
            auto lbrace = expect(TokenType::LBrace);
            if (!lbrace) return core::make_unexpected(lbrace.error());
            AstStatement stmt{};
            stmt.kind = AstStmtKind::Guard;
            stmt.name = bind_name;
            stmt.bind_value = bind_value;
            stmt.expr = cond_expr;
            if (is_match_guard) {
                while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
                    if (cur().type == TokenType::Ident && cur().text.eq({"case", 4}))
                        return frontend_error(
                            FrontendError::UnsupportedSyntax, span_from(cur()), kCaseDetail);
                    AstStatement::MatchArm arm{};
                    arm.span = span_from(cur());
                    if (take(TokenType::Underscore)) {
                        arm.is_wildcard = true;
                    } else {
                        auto pattern = parse_primary_expr();
                        if (!pattern) return core::make_unexpected(pattern.error());
                        auto pattern_ptr = alloc_expr(pattern.value());
                        if (!pattern_ptr) return core::make_unexpected(pattern_ptr.error());
                        arm.pattern = pattern_ptr.value();
                    }
                    if (const Token* kw_if = take(TokenType::KwIf))
                        return frontend_error(FrontendError::UnsupportedSyntax,
                                              span_from(*kw_if),
                                              kGuardMatchArmIfDetail);
                    if (cur().type == TokenType::Colon)
                        return frontend_error(
                            FrontendError::UnsupportedSyntax, span_from(cur()), kMatchColonDetail);
                    auto arrow = expect(TokenType::Arrow);
                    if (!arrow) return core::make_unexpected(arrow.error());
                    const bool saved_dot_stop = arm_body_stops_cross_line_dot;
                    arm_body_stops_cross_line_dot = arm_body_needs_dot_stop();
                    auto arm_stmt = parse_stmt();
                    arm_body_stops_cross_line_dot = saved_dot_stop;
                    if (!arm_stmt) return core::make_unexpected(arm_stmt.error());
                    if (arm_stmt->kind != AstStmtKind::ReturnStatus &&
                        arm_stmt->kind != AstStmtKind::RespondStatus &&
                        arm_stmt->kind != AstStmtKind::ForwardUpstream) {
                        return frontend_error(FrontendError::UnsupportedSyntax, span_from(start));
                    }
                    auto arm_ptr = alloc_stmt(arm_stmt.value());
                    if (!arm_ptr) return core::make_unexpected(arm_ptr.error());
                    arm.stmt = arm_ptr.value();
                    arm.span.end = arm_ptr.value()->span.end;
                    if (!stmt.match_arms.push(arm))
                        return frontend_error(FrontendError::TooManyItems, arm.span);
                }
                auto rbrace = expect(TokenType::RBrace);
                if (!rbrace) return core::make_unexpected(rbrace.error());
                if (stmt.match_arms.len == 0)
                    return frontend_error(FrontendError::UnexpectedToken,
                                          span_from(*rbrace.value()));
                stmt.span = Span{start.start, rbrace.value()->end, start.line, start.col};
            } else {
                auto else_stmt = parse_braced_stmt_body(*lbrace.value());
                if (!else_stmt) return core::make_unexpected(else_stmt.error());
                auto else_ptr = alloc_stmt(else_stmt.value());
                if (!else_ptr) return core::make_unexpected(else_ptr.error());
                stmt.else_stmt = else_ptr.value();
                stmt.span = Span{start.start, else_stmt->span.end, start.line, start.col};
            }
            return stmt;
        }
        if (cur().type == TokenType::Ident && cur().text.eq(lit_str("respond")) &&
            peek().type == TokenType::IntLit) {
            pos++;
            AstStatement stmt{};
            stmt.kind = AstStmtKind::RespondStatus;

            auto parse_status_i32 = [&](const Token& tok) -> FrontendResult<i32> {
                i32 value = 0;
                for (u32 i = 0; i < tok.text.len; i++) {
                    const u32 digit = static_cast<u32>(tok.text.ptr[i] - '0');
                    if (value > (static_cast<i32>(0x7fffffff) - static_cast<i32>(digit)) / 10)
                        return frontend_error(
                            FrontendError::InvalidInteger, span_from(tok), tok.text);
                    value = value * 10 + static_cast<i32>(digit);
                }
                return value;
            };

            auto status = expect(TokenType::IntLit);
            if (!status) return core::make_unexpected(status.error());
            auto parsed = parse_status_i32(*status.value());
            if (!parsed) return core::make_unexpected(parsed.error());
            stmt.status_code = parsed.value();
            stmt.span = Span{start.start, status.value()->end, start.line, start.col};
            if (take(TokenType::Comma)) {
                auto body_tok = expect(TokenType::StringLit);
                if (!body_tok) return core::make_unexpected(body_tok.error());
                stmt.response_body = body_tok.value()->text;
                stmt.has_response_body = true;
                stmt.span.end = body_tok.value()->end;
            }
            return stmt;
        }
        if (take(TokenType::KwReturn)) {
            // Three forms:
            //   return <IntLit>                           (legacy)
            //   return response(<IntLit>
            //                   [, body: "..."]
            //                   [, headers: { "K": "V", ... }])
            //                                             (response builder)
            //   return forward(<Ident>)                   (forward to upstream)
            // The builder forms are the syntactic entry points for
            // richer responses / proxying. Bare `forward <name>` is
            // intentionally not accepted — the only way to hand off
            // to an upstream is via `return forward(name)` so the
            // control-flow terminator is always explicit.
            AstStatement stmt{};
            stmt.kind = AstStmtKind::ReturnStatus;

            // Expect an IntLit and parse it as a signed i32 with the
            // INT_MAX overflow check that both branches share.
            auto parse_status_i32 = [&](const Token& tok) -> FrontendResult<i32> {
                i32 value = 0;
                for (u32 i = 0; i < tok.text.len; i++) {
                    const u32 digit = static_cast<u32>(tok.text.ptr[i] - '0');
                    if (value > (static_cast<i32>(0x7fffffff) - static_cast<i32>(digit)) / 10)
                        return frontend_error(
                            FrontendError::InvalidInteger, span_from(tok), tok.text);
                    value = value * 10 + static_cast<i32>(digit);
                }
                return value;
            };

            // Peek for the forward builder. `forward` is a keyword, so
            // `return forward(<name>)` is unambiguous. Analyze later
            // resolves the ident to an upstream_index; the RIR layer
            // already has RetForward wired, so we just populate the
            // AstStatement here with ForwardUpstream kind + name.
            if (take(TokenType::KwForward)) {
                auto lparen = expect(TokenType::LParen);
                if (!lparen) return core::make_unexpected(lparen.error());
                auto name = expect(TokenType::Ident);
                if (!name) return core::make_unexpected(name.error());
                stmt.kind = AstStmtKind::ForwardUpstream;
                stmt.name = name.value()->text;
                // Optional kwargs after the upstream name. Currently:
                //   set_path: "<StringLit>"  — rewrite the outbound request path.
                // Each at most once; analyze/lowering emits ReqSetPath.
                while (take(TokenType::Comma)) {
                    auto kw = expect(TokenType::Ident);
                    if (!kw) return core::make_unexpected(kw.error());
                    const Str kw_text = kw.value()->text;
                    auto colon = expect(TokenType::Colon);
                    if (!colon) return core::make_unexpected(colon.error());
                    if (kw_text.eq({"set_path", 8})) {
                        if (stmt.has_forward_set_path)
                            return frontend_error(
                                FrontendError::UnexpectedToken, span_from(*kw.value()), kw_text);
                        auto val = expect(TokenType::StringLit);
                        if (!val) return core::make_unexpected(val.error());
                        stmt.forward_set_path = val.value()->text;
                        stmt.has_forward_set_path = true;
                    } else if (kw_text.eq({"set_header", 10})) {
                        // set_header: { "Name": "Value", ... } — request-header
                        // overrides applied to the outbound proxied request. Same
                        // dict grammar + validation as response(headers:).
                        if (stmt.forward_set_headers.len != 0)
                            return frontend_error(
                                FrontendError::UnexpectedToken, span_from(*kw.value()), kw_text);
                        auto lbrace = expect(TokenType::LBrace);
                        if (!lbrace) return core::make_unexpected(lbrace.error());
                        if (cur().type == TokenType::RBrace)  // empty dict → omit the kwarg
                            return frontend_error(FrontendError::UnsupportedSyntax,
                                                  span_from(cur()));
                        while (true) {
                            auto key_tok = expect(TokenType::StringLit);
                            if (!key_tok) return core::make_unexpected(key_tok.error());
                            auto kcolon = expect(TokenType::Colon);
                            if (!kcolon) return core::make_unexpected(kcolon.error());
                            auto val_tok = expect(TokenType::StringLit);
                            if (!val_tok) return core::make_unexpected(val_tok.error());
                            AstHeaderKV pair{key_tok.value()->text, val_tok.value()->text};
                            // Reuse the shared validator: tchar key, control-free
                            // value, and the framing names (Content-Length /
                            // Transfer-Encoding / Connection) reserved — those are
                            // runtime-managed for requests too.
                            const auto vr = validate_response_header(
                                pair.key.ptr, pair.key.len, pair.value.ptr, pair.value.len);
                            if (vr != HttpHeaderValidation::Ok) {
                                const bool is_value_err =
                                    vr == HttpHeaderValidation::InvalidValueChar;
                                const Token& where =
                                    is_value_err ? *val_tok.value() : *key_tok.value();
                                const Str detail = is_value_err ? pair.value : pair.key;
                                return frontend_error(
                                    FrontendError::UnsupportedSyntax, span_from(where), detail);
                            }
                            for (u32 i = 0; i < stmt.forward_set_headers.len; i++) {
                                if (http_header_name_eq_ci(stmt.forward_set_headers[i].key.ptr,
                                                           stmt.forward_set_headers[i].key.len,
                                                           pair.key.ptr,
                                                           pair.key.len)) {
                                    return frontend_error(FrontendError::UnexpectedToken,
                                                          span_from(*key_tok.value()),
                                                          pair.key);
                                }
                            }
                            if (!stmt.forward_set_headers.push(pair))
                                return frontend_error(FrontendError::TooManyItems,
                                                      span_from(*key_tok.value()));
                            if (!take(TokenType::Comma)) break;
                            if (cur().type == TokenType::RBrace) break;  // trailing comma
                        }
                        auto rbrace = expect(TokenType::RBrace);
                        if (!rbrace) return core::make_unexpected(rbrace.error());
                    } else {
                        return frontend_error(
                            FrontendError::UnexpectedToken, span_from(*kw.value()), kw_text);
                    }
                }
                auto rparen = expect(TokenType::RParen);
                if (!rparen) return core::make_unexpected(rparen.error());
                stmt.span = Span{start.start, rparen.value()->end, start.line, start.col};
                return stmt;
            }

            // `return websocket(<name>)` — proxy to a WebSocket upstream. Recognized
            // CONTEXTUALLY (ident text `websocket` followed by `(`), not via a reserved
            // keyword, so `.websocket` variant literals and identifiers named `websocket`
            // still parse — mirrors how `response` is handled. Phase 0 lowers to the SAME
            // ForwardUpstream terminator as `forward`: the runtime auto-establishes the
            // full-duplex passthrough tunnel when the client requested an Upgrade and the
            // upstream answers 101 (a non-upgrade request just proxies normally, so the
            // route is safe with no edge guard). Per-frame `{ frame ... }`, subprotocol/
            // maxMessageSize kwargs, and a typed `req.upgrade` guard are later phases.
            // NOTE: for now `websocket(x)` is indistinguishable from `forward(x)` after
            // parse — the keyword is intent/documentation only. A distinct WS-only route
            // marker is a later phase if "a forward that must NOT tunnel" is ever needed.
            if (cur().type == TokenType::Ident && cur().text.eq({"websocket", 9}) &&
                peek().type == TokenType::LParen) {
#if RUT_ENABLE_WEBSOCKET
                pos++;  // consume `websocket`
                auto lparen = expect(TokenType::LParen);
                if (!lparen) return core::make_unexpected(lparen.error());
                auto name = expect(TokenType::Ident);
                if (!name) return core::make_unexpected(name.error());
                // Optional `, maxMessageSize: <IntLit><b|kb|mb|gb>` — the per-message reassembly
                // cap for terminate mode. ByteSize lexes as IntLit + a separate unit Ident
                // (mirrors @throttle's bandwidth parse). Only meaningful with a frame-handler
                // block (terminate); rejected on the bare passthrough form below.
                u32 ws_max_size = 0;
                if (cur().type == TokenType::Comma) {
                    pos++;  // consume `,`
                    auto kw = expect(TokenType::Ident);
                    if (!kw || !kw.value()->text.eq({"maxMessageSize", 14}))
                        return frontend_error(FrontendError::UnsupportedSyntax, span_from(start));
                    if (!expect(TokenType::Colon))
                        return frontend_error(FrontendError::UnexpectedToken, span_from(start));
                    auto num = expect(TokenType::IntLit);
                    if (!num) return core::make_unexpected(num.error());
                    u64 amount = 0;
                    for (u32 i = 0; i < num.value()->text.len; i++) {
                        amount = amount * 10 + static_cast<u64>(num.value()->text.ptr[i] - '0');
                        if (amount > 0xffffffffull)
                            return frontend_error(
                                FrontendError::InvalidInteger, span_from(start), num.value()->text);
                    }
                    auto unit = expect(TokenType::Ident);
                    if (!unit) return core::make_unexpected(unit.error());
                    const Str u = unit.value()->text;
                    u64 mult = 0;
                    if (u.eq({"b", 1}))
                        mult = 1;
                    else if (u.eq({"kb", 2}))
                        mult = 1024;
                    else if (u.eq({"mb", 2}))
                        mult = 1024ull * 1024;
                    else if (u.eq({"gb", 2}))
                        mult = 1024ull * 1024 * 1024;
                    else
                        return frontend_error(
                            FrontendError::UnsupportedSyntax, span_from(start), u);
                    const u64 bytes = amount * mult;
                    if (bytes == 0 || bytes > 0xffffffffull)
                        return frontend_error(FrontendError::UnsupportedSyntax, span_from(start));
                    ws_max_size = static_cast<u32>(bytes);
                }
                auto rparen = expect(TokenType::RParen);
                if (!rparen) return core::make_unexpected(rparen.error());
                stmt.name = name.value()->text;
                stmt.ws_max_message_size = ws_max_size;
                // A trailing `{ ... }` block makes this TERMINATE mode (the gateway
                // parses/inspects each message); a bare `websocket(x)` stays the passthrough
                // ForwardUpstream tunnel. The block is the per-message frame handler; its
                // body is stored on then_stmt (reused like For), parsed by the general
                // statement parser (per-message verdicts are a follow-up slice).
                if (cur().type == TokenType::LBrace) {
                    auto lbrace = expect(TokenType::LBrace);
                    if (!lbrace) return core::make_unexpected(lbrace.error());
                    auto body = parse_ws_frame_body(*lbrace.value());
                    if (!body) return core::make_unexpected(body.error());
                    auto body_ptr = alloc_stmt(body.value());
                    if (!body_ptr) return core::make_unexpected(body_ptr.error());
                    stmt.kind = AstStmtKind::WsTerminate;
                    stmt.then_stmt = body_ptr.value();
                    stmt.span = Span{start.start, body.value().span.end, start.line, start.col};
                    return stmt;
                }
                // Passthrough form (no block): maxMessageSize only governs terminate-mode
                // reassembly, so it's meaningless here — reject rather than silently ignore it.
                if (ws_max_size != 0)
                    return frontend_error(FrontendError::UnsupportedSyntax, span_from(start));
                stmt.kind = AstStmtKind::ForwardUpstream;
                stmt.span = Span{start.start, rparen.value()->end, start.line, start.col};
                return stmt;
#else
                // WebSocket tunnel support is compiled out (RUT_ENABLE_WEBSOCKET=0): the
                // runtime has no 101/tunnel path, so reject `websocket(...)` at compile
                // time rather than silently lowering it to a plain forward that can never
                // establish the full-duplex tunnel.
                return frontend_error(FrontendError::UnsupportedSyntax, span_from(start));
#endif
            }

            // Peek for the response builder. We recognise `response`
            // by the literal identifier text; no dedicated keyword yet
            // because `response` is also a valid identifier elsewhere.
            const Token& peek = cur();
            const bool is_builder = peek.type == TokenType::Ident && peek.text.eq({"response", 8});
            if (is_builder) {
                pos++;  // consume `response`
                auto lparen = expect(TokenType::LParen);
                if (!lparen) return core::make_unexpected(lparen.error());
                auto status = expect(TokenType::IntLit);
                if (!status) return core::make_unexpected(status.error());
                auto parsed = parse_status_i32(*status.value());
                if (!parsed) return core::make_unexpected(parsed.error());
                stmt.status_code = parsed.value();
                // Optional kwargs: `body: "<StringLit>"` and/or
                // `headers: { "K": "V", ... }`. Any order, each at
                // most once. An explicit empty dict (`headers: {}`) is
                // a parse error — write no kwarg instead.
                bool seen_headers = false;
                while (take(TokenType::Comma)) {
                    auto kw = expect(TokenType::Ident);
                    if (!kw) return core::make_unexpected(kw.error());
                    const Str kw_text = kw.value()->text;
                    auto colon = expect(TokenType::Colon);
                    if (!colon) return core::make_unexpected(colon.error());
                    if (kw_text.eq({"body", 4})) {
                        if (stmt.has_response_body) {
                            return frontend_error(
                                FrontendError::UnexpectedToken, span_from(*kw.value()), kw_text);
                        }
                        auto body_tok = expect(TokenType::StringLit);
                        if (!body_tok) return core::make_unexpected(body_tok.error());
                        // Lexer strips the surrounding quotes already.
                        stmt.response_body = body_tok.value()->text;
                        stmt.has_response_body = true;
                    } else if (kw_text.eq({"headers", 7})) {
                        if (seen_headers) {
                            return frontend_error(
                                FrontendError::UnexpectedToken, span_from(*kw.value()), kw_text);
                        }
                        seen_headers = true;
                        auto lbrace = expect(TokenType::LBrace);
                        if (!lbrace) return core::make_unexpected(lbrace.error());
                        // Empty dict is rejected — omit the kwarg
                        // instead to express "no custom headers".
                        if (cur().type == TokenType::RBrace) {
                            return frontend_error(FrontendError::UnsupportedSyntax,
                                                  span_from(cur()));
                        }
                        while (true) {
                            auto key_tok = expect(TokenType::StringLit);
                            if (!key_tok) return core::make_unexpected(key_tok.error());
                            auto kcolon = expect(TokenType::Colon);
                            if (!kcolon) return core::make_unexpected(kcolon.error());
                            auto val_tok = expect(TokenType::StringLit);
                            if (!val_tok) return core::make_unexpected(val_tok.error());
                            AstHeaderKV pair{key_tok.value()->text, val_tok.value()->text};
                            // Delegate byte-level validation to the
                            // shared HTTP header validator so the
                            // compiler and the runtime's public
                            // add_response_header_set apply identical
                            // rules (HTTP tchar grammar on keys,
                            // control-char reject on values,
                            // framing/hop-by-hop names reserved).
                            const auto result = validate_response_header(
                                pair.key.ptr, pair.key.len, pair.value.ptr, pair.value.len);
                            if (result != HttpHeaderValidation::Ok) {
                                // Point the span at the offending
                                // token: value-specific failures go
                                // to val_tok so the error message
                                // highlights the bad value, not the
                                // key. Key-side failures (empty,
                                // invalid char, reserved name) keep
                                // the key-token span and detail.
                                const bool is_value_err =
                                    result == HttpHeaderValidation::InvalidValueChar;
                                const Token& where =
                                    is_value_err ? *val_tok.value() : *key_tok.value();
                                const Str detail = is_value_err ? pair.value : pair.key;
                                return frontend_error(
                                    FrontendError::UnsupportedSyntax, span_from(where), detail);
                            }
                            // Reject duplicate keys (case-insensitive
                            // per HTTP) so { "X": "1", "x": "2" } is a
                            // parse error instead of emitting two
                            // contradictory singletons.
                            for (u32 i = 0; i < stmt.response_headers.len; i++) {
                                if (http_header_name_eq_ci(stmt.response_headers[i].key.ptr,
                                                           stmt.response_headers[i].key.len,
                                                           pair.key.ptr,
                                                           pair.key.len)) {
                                    return frontend_error(FrontendError::UnexpectedToken,
                                                          span_from(*key_tok.value()),
                                                          pair.key);
                                }
                            }
                            if (!stmt.response_headers.push(pair)) {
                                return frontend_error(FrontendError::TooManyItems,
                                                      span_from(*key_tok.value()));
                            }
                            if (!take(TokenType::Comma)) break;
                            // Trailing comma before `}` is allowed.
                            if (cur().type == TokenType::RBrace) break;
                        }
                        auto rbrace = expect(TokenType::RBrace);
                        if (!rbrace) return core::make_unexpected(rbrace.error());
                    } else {
                        return frontend_error(
                            FrontendError::UnexpectedToken, span_from(*kw.value()), kw_text);
                    }
                }
                auto rparen = expect(TokenType::RParen);
                if (!rparen) return core::make_unexpected(rparen.error());
                stmt.span = Span{start.start, rparen.value()->end, start.line, start.col};
                return stmt;
            }

            // Legacy `return <IntLit>`.
            auto status = expect(TokenType::IntLit);
            if (!status) return core::make_unexpected(status.error());
            auto parsed = parse_status_i32(*status.value());
            if (!parsed) return core::make_unexpected(parsed.error());
            stmt.status_code = parsed.value();
            stmt.span = Span{start.start, status.value()->end, start.line, start.col};
            return stmt;
        }
        if (take(TokenType::KwWait)) {
            if (cur().type == TokenType::Ident && cur().text.eq({"any", 3}) &&
                peek().type == TokenType::LBrace) {
                const Token any_tok = cur();
                pos++;
                auto lbrace = expect(TokenType::LBrace);
                if (!lbrace) return core::make_unexpected(lbrace.error());
                AstStatement stmt{};
                stmt.kind = AstStmtKind::WaitAny;
                stmt.span = Span{start.start, any_tok.end, start.line, start.col};
                while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
                    AstStatement::MatchArm arm{};
                    arm.span = span_from(cur());
                    if (cur().type == TokenType::Ident && peek().type == TokenType::Eq) {
                        const Token bind_tok = cur();
                        pos += 2;
                        arm.bind_value = true;
                        arm.bind_name = bind_tok.text;
                    }
                    auto event = parse_expr();
                    if (!event) return core::make_unexpected(event.error());
                    auto event_ptr = alloc_expr(event.value());
                    if (!event_ptr) return core::make_unexpected(event_ptr.error());
                    arm.pattern = event_ptr.value();
                    auto arrow = expect(TokenType::Arrow);
                    if (!arrow) return core::make_unexpected(arrow.error());
                    auto body_lbrace = expect(TokenType::LBrace);
                    if (!body_lbrace) return core::make_unexpected(body_lbrace.error());
                    auto body = parse_braced_stmt_body(*body_lbrace.value());
                    if (!body) return core::make_unexpected(body.error());
                    auto body_ptr = alloc_stmt(body.value());
                    if (!body_ptr) return core::make_unexpected(body_ptr.error());
                    arm.stmt = body_ptr.value();
                    arm.span =
                        Span{arm.span.start, body.value().span.end, arm.span.line, arm.span.col};
                    if (!stmt.match_arms.push(arm))
                        return frontend_error(FrontendError::TooManyItems, arm.span);
                }
                auto rbrace = expect(TokenType::RBrace);
                if (!rbrace) return core::make_unexpected(rbrace.error());
                stmt.span = Span{start.start, rbrace.value()->end, start.line, start.col};
                return stmt;
            }
            auto lparen = expect(TokenType::LParen);
            if (!lparen) return core::make_unexpected(lparen.error());
            AstStatement stmt{};
            stmt.kind = AstStmtKind::Wait;
            if (const Token* rparen = take(TokenType::RParen)) {
                stmt.wait_event_kind = WaitEventKind::Any;
                stmt.span = Span{start.start, rparen->end, start.line, start.col};
                return stmt;
            }

            // Accepts either a bare IntLit (milliseconds, legacy form) or
            // a DurLit (digits + ms/s/m/h suffix). u64 accumulator +
            // UINT32_MAX cap — the yield payload is 32 bits wide, so
            // waits up to ~49 days are expressible.
            const Token* arg = nullptr;
            if (const Token* t = take(TokenType::IntLit)) {
                arg = t;
            } else if (const Token* t = take(TokenType::DurLit)) {
                arg = t;
            } else {
                auto op = parse_expr();
                if (!op) return core::make_unexpected(op.error());
                auto rparen = expect(TokenType::RParen);
                if (!rparen) return core::make_unexpected(rparen.error());
                stmt.expr = op.value();
                stmt.wait_event_kind = WaitEventKind::Any;
                stmt.has_wait_expr = true;
                stmt.span = Span{start.start, rparen.value()->end, start.line, start.col};
                return stmt;
            }
            // Peel the unit suffix (if any) off the end of the text:
            // DurLit ends in ms/s/m/h; IntLit has no suffix.
            u32 digit_len = arg->text.len;
            u64 multiplier_ms = 1;  // default: bare IntLit = ms
            if (arg->type == TokenType::DurLit) {
                if (digit_len >= 2 && arg->text.ptr[digit_len - 2] == 'm' &&
                    arg->text.ptr[digit_len - 1] == 's') {
                    digit_len -= 2;
                    multiplier_ms = 1;
                } else if (digit_len >= 1) {
                    char unit = arg->text.ptr[digit_len - 1];
                    digit_len -= 1;
                    if (unit == 's')
                        multiplier_ms = 1000;
                    else if (unit == 'm')
                        multiplier_ms = 60ull * 1000;
                    else if (unit == 'h')
                        multiplier_ms = 3600ull * 1000;
                    else
                        return frontend_error(
                            FrontendError::InvalidInteger, span_from(*arg), arg->text);
                }
            }
            u64 value = 0;
            for (u32 i = 0; i < digit_len; i++) {
                const u32 digit = static_cast<u32>(arg->text.ptr[i] - '0');
                if (value > (static_cast<u64>(0xffffffffu) - static_cast<u64>(digit)) / 10)
                    return frontend_error(
                        FrontendError::InvalidInteger, span_from(*arg), arg->text);
                value = value * 10 + static_cast<u64>(digit);
            }
            // Apply unit; re-check against u32 range after multiplication.
            const u64 ms = value * multiplier_ms;
            if (ms > 0xffffffffull)
                return frontend_error(FrontendError::InvalidInteger, span_from(*arg), arg->text);
            auto rparen = expect(TokenType::RParen);
            if (!rparen) return core::make_unexpected(rparen.error());
            stmt.wait_event_kind = WaitEventKind::Timer;
            stmt.status_code = static_cast<u32>(ms);  // reused field: ms to sleep
            stmt.span = Span{start.start, rparen.value()->end, start.line, start.col};
            return stmt;
        }
        if (take(TokenType::KwIf)) {
            const bool is_const = take(TokenType::KwConst) != nullptr;
            // `if let name = expr { ... } else { ... }` — value-binding form
            // (Swift-identical surface). Parsed exactly like `guard let`: the
            // binding name is captured on `stmt.name`, `bind_value` marks the
            // If as a let-binding, and `stmt.expr` holds the bound expression
            // (analyze lowers it to `HasValue(expr)` and narrows the binding
            // into the then-branch scope only). A plain `if cond { }` leaves
            // bind_value false and `stmt.expr` as the boolean condition.
            bool is_let = false;
            Str let_name{};
            if (!is_const && take(TokenType::KwLet)) {
                auto name = expect(TokenType::Ident);
                if (!name) return core::make_unexpected(name.error());
                let_name = name.value()->text;
                is_let = true;
                auto eq = expect(TokenType::Eq);
                if (!eq) return core::make_unexpected(eq.error());
            }
            auto cond = parse_expr();
            if (!cond) return core::make_unexpected(cond.error());
            auto lbrace = expect(TokenType::LBrace);
            if (!lbrace) return core::make_unexpected(lbrace.error());
            auto then_stmt = parse_braced_stmt_body(*lbrace.value());
            if (!then_stmt) return core::make_unexpected(then_stmt.error());
            auto kw_else = expect(TokenType::KwElse);
            if (!kw_else) return core::make_unexpected(kw_else.error());
            auto else_lbrace = expect(TokenType::LBrace);
            if (!else_lbrace) return core::make_unexpected(else_lbrace.error());
            auto else_stmt = parse_braced_stmt_body(*else_lbrace.value());
            if (!else_stmt) return core::make_unexpected(else_stmt.error());
            auto then_ptr = alloc_stmt(then_stmt.value());
            if (!then_ptr) return core::make_unexpected(then_ptr.error());
            auto else_ptr = alloc_stmt(else_stmt.value());
            if (!else_ptr) return core::make_unexpected(else_ptr.error());
            AstStatement stmt{};
            stmt.kind = AstStmtKind::If;
            stmt.is_const = is_const;
            stmt.bind_value = is_let;
            stmt.name = let_name;
            stmt.expr = cond.value();
            stmt.then_stmt = then_ptr.value();
            stmt.else_stmt = else_ptr.value();
            stmt.span = Span{start.start, else_stmt->span.end, start.line, start.col};
            return stmt;
        }
        if (cur().type == TokenType::Ident && cur().text.eq({"inline", 6}) &&
            peek().type == TokenType::KwFor) {
            return frontend_error(FrontendError::UnsupportedSyntax,
                                  span_from(cur()),
                                  lit_str("use 'for', not 'inline for'"));
        }
        if (cur().type == TokenType::KwFor) {
            return frontend_error(FrontendError::UnsupportedSyntax,
                                  span_from(cur()),
                                  lit_str("for loops are unsupported in Rut Core"));
        }
        if (take(TokenType::KwMatch)) {
            const bool is_const = take(TokenType::KwConst) != nullptr;
            auto subject = parse_expr();
            if (!subject) return core::make_unexpected(subject.error());
            auto lbrace = expect(TokenType::LBrace);
            if (!lbrace) return core::make_unexpected(lbrace.error());
            AstStatement stmt{};
            stmt.kind = AstStmtKind::Match;
            stmt.is_const = is_const;
            stmt.expr = subject.value();
            while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
                if (cur().type == TokenType::Ident && cur().text.eq({"case", 4}))
                    return frontend_error(
                        FrontendError::UnsupportedSyntax, span_from(cur()), kCaseDetail);
                AstStatement::MatchArm arm{};
                arm.span = span_from(cur());
                if (take(TokenType::Underscore)) {
                    arm.is_wildcard = true;
                } else {
                    auto pattern = parse_primary_expr();
                    if (!pattern) return core::make_unexpected(pattern.error());
                    auto pattern_ptr = alloc_expr(pattern.value());
                    if (!pattern_ptr) return core::make_unexpected(pattern_ptr.error());
                    arm.pattern = pattern_ptr.value();
                }
                if (take(TokenType::KwIf)) {
                    auto guard = parse_expr();
                    if (!guard) return core::make_unexpected(guard.error());
                    auto guard_ptr = alloc_expr(guard.value());
                    if (!guard_ptr) return core::make_unexpected(guard_ptr.error());
                    arm.has_guard = true;
                    arm.guard = guard_ptr.value();
                }
                if (cur().type == TokenType::Colon)
                    return frontend_error(
                        FrontendError::UnsupportedSyntax, span_from(cur()), kMatchColonDetail);
                auto arrow = expect(TokenType::Arrow);
                if (!arrow) return core::make_unexpected(arrow.error());
                const bool saved_dot_stop = arm_body_stops_cross_line_dot;
                arm_body_stops_cross_line_dot = arm_body_needs_dot_stop();
                auto arm_stmt = parse_stmt();
                arm_body_stops_cross_line_dot = saved_dot_stop;
                if (!arm_stmt) return core::make_unexpected(arm_stmt.error());
                if (arm_stmt->kind == AstStmtKind::Let || arm_stmt->kind == AstStmtKind::Guard) {
                    return frontend_error(FrontendError::UnsupportedSyntax, span_from(start));
                }
                auto arm_ptr = alloc_stmt(arm_stmt.value());
                if (!arm_ptr) return core::make_unexpected(arm_ptr.error());
                arm.stmt = arm_ptr.value();
                arm.span.end = arm_ptr.value()->span.end;
                if (!stmt.match_arms.push(arm))
                    return frontend_error(FrontendError::TooManyItems, arm.span);
            }
            auto rbrace = expect(TokenType::RBrace);
            if (!rbrace) return core::make_unexpected(rbrace.error());
            if (stmt.match_arms.len == 0)
                return frontend_error(FrontendError::UnexpectedToken, span_from(*rbrace.value()));
            stmt.span = Span{start.start, rbrace.value()->end, start.line, start.col};
            return stmt;
        }
        // Bare `forward <name>` is no longer accepted — use
        // `return forward(<name>)` instead so the terminator is
        // explicit and consistent with `return response(...)`.
        if (cur().type == TokenType::Eof)
            return frontend_error(FrontendError::UnexpectedEof, span_from(cur()));
        return frontend_error(FrontendError::UnexpectedToken, span_from(cur()), cur().text);
    }

    FrontendResult<AstItem> parse_upstream() {
        auto kw = expect(TokenType::KwUpstream);
        if (!kw) return core::make_unexpected(kw.error());
        auto name = expect(TokenType::Ident);
        if (!name) return core::make_unexpected(name.error());
        AstItem item{};
        item.kind = AstItemKind::Upstream;
        item.upstream.name = name.value()->text;
        u32 end_off = name.value()->end;
        // Optional address after the name. Two forms:
        //   `at "<host>:<port>"`          — single string literal
        //   `{ host: "...", port: N }`    — dict form; order-independent,
        //                                    both fields required
        // `at` is a contextual keyword — we peek for an Ident with
        // exactly that text rather than reserving it globally. Keeps
        // `at` available as a user identifier elsewhere.
        const Token& after_name = cur();
        const bool is_at_keyword =
            after_name.type == TokenType::Ident && after_name.text.eq({"at", 2});
        if (is_at_keyword) {
            pos++;  // consume `at`
            auto lit = expect(TokenType::StringLit);
            if (!lit) return core::make_unexpected(lit.error());
            item.upstream.has_address = true;
            item.upstream.host_lit = lit.value()->text;
            item.upstream.addr_span = span_from(*lit.value());
            // port_is_set stays false — analyze splits host_lit into
            // (ip, port) for the `at "..."` form.
            end_off = lit.value()->end;
        } else if (cur().type == TokenType::LBrace) {
            auto lbrace = expect(TokenType::LBrace);
            if (!lbrace) return core::make_unexpected(lbrace.error());
            // has_address is set at the end of the block once we know whether
            // host/port (or backends) were actually present: a block carrying
            // only `health_check` is a name-only upstream with no address
            // (pre-bound by the host application at runtime).
            // Span the whole `{ ... }` block so analyze-time
            // diagnostics (bad host, missing field, out-of-range port)
            // highlight the address site rather than the bare name.
            // We extend addr_span.end to the closing brace below once
            // we've consumed it.
            item.upstream.addr_span = span_from(*lbrace.value());
            bool seen_host = false;
            bool seen_port = false;
            // Empty dict (`upstream foo {}`) is a parse error — omit
            // the braces entirely if no address is being declared.
            if (cur().type == TokenType::RBrace) {
                return frontend_error(FrontendError::UnsupportedSyntax, span_from(cur()));
            }
            while (true) {
                auto field = expect(TokenType::Ident);
                if (!field) return core::make_unexpected(field.error());
                const Str field_name = field.value()->text;
                auto colon = expect(TokenType::Colon);
                if (!colon) return core::make_unexpected(colon.error());
                if (field_name.eq({"host", 4})) {
                    if (seen_host)
                        return frontend_error(
                            FrontendError::UnexpectedToken, span_from(*field.value()), field_name);
                    auto lit = expect(TokenType::StringLit);
                    if (!lit) return core::make_unexpected(lit.error());
                    item.upstream.host_lit = lit.value()->text;
                    seen_host = true;
                } else if (field_name.eq({"port", 4})) {
                    if (seen_port)
                        return frontend_error(
                            FrontendError::UnexpectedToken, span_from(*field.value()), field_name);
                    auto lit = expect(TokenType::IntLit);
                    if (!lit) return core::make_unexpected(lit.error());
                    // Parse digits into u32; analyze range-checks to
                    // 1..65535 with a friendlier diagnostic. Pre-multiply
                    // overflow check prevents long literals (20+ digits
                    // with the right leading byte) from silently
                    // wrapping past 2^64 and landing below 0xffffffff —
                    // the post-multiply guard alone isn't enough.
                    u64 v = 0;
                    for (u32 i = 0; i < lit.value()->text.len; i++) {
                        const u64 digit = static_cast<u64>(lit.value()->text.ptr[i] - '0');
                        if (v > (static_cast<u64>(0xffffffffu) - digit) / 10u) {
                            return frontend_error(FrontendError::InvalidInteger,
                                                  span_from(*lit.value()),
                                                  lit.value()->text);
                        }
                        v = v * 10 + digit;
                    }
                    item.upstream.port_lit = static_cast<u32>(v);
                    item.upstream.port_is_set = true;
                    seen_port = true;
                } else if (field_name.eq({"backends", 8})) {
                    // `backends: ["host:port", ...]` — a non-empty list of
                    // string literals for round-robin load balancing. Analyze
                    // splits each into (ip, port).
                    if (item.upstream.backend_count > 0)
                        return frontend_error(
                            FrontendError::UnexpectedToken, span_from(*field.value()), field_name);
                    auto lbrk = expect(TokenType::LBracket);
                    if (!lbrk) return core::make_unexpected(lbrk.error());
                    if (cur().type == TokenType::RBracket)
                        return frontend_error(FrontendError::UnsupportedSyntax, span_from(cur()));
                    while (true) {
                        auto lit = expect(TokenType::StringLit);
                        if (!lit) return core::make_unexpected(lit.error());
                        if (item.upstream.backend_count >= AstUpstreamDecl::kMaxBackends)
                            return frontend_error(FrontendError::TooManyItems,
                                                  span_from(*lit.value()));
                        item.upstream.backend_lits[item.upstream.backend_count++] =
                            lit.value()->text;
                        if (!take(TokenType::Comma)) break;
                        if (cur().type == TokenType::RBracket) break;  // trailing comma
                    }
                    auto rbrk = expect(TokenType::RBracket);
                    if (!rbrk) return core::make_unexpected(rbrk.error());
                } else if (field_name.eq({"health_check", 12})) {
                    // `health_check: { path: "...", interval: <dur>, status: N }`
                    // — active-health config (data only this slice). path and
                    // interval are required; status defaults to 200. Mirrors the
                    // dict-field error style above (dup/unknown/missing).
                    if (item.upstream.hc_enabled)
                        return frontend_error(
                            FrontendError::UnexpectedToken, span_from(*field.value()), field_name);
                    auto hc_lbrace = expect(TokenType::LBrace);
                    if (!hc_lbrace) return core::make_unexpected(hc_lbrace.error());
                    bool seen_path = false;
                    bool seen_interval = false;
                    bool seen_status = false;
                    while (true) {
                        auto hc_field = expect(TokenType::Ident);
                        if (!hc_field) return core::make_unexpected(hc_field.error());
                        const Str hc_key = hc_field.value()->text;
                        auto hc_colon = expect(TokenType::Colon);
                        if (!hc_colon) return core::make_unexpected(hc_colon.error());
                        if (hc_key.eq({"path", 4})) {
                            if (seen_path)
                                return frontend_error(FrontendError::UnexpectedToken,
                                                      span_from(*hc_field.value()),
                                                      hc_key);
                            auto lit = expect(TokenType::StringLit);
                            if (!lit) return core::make_unexpected(lit.error());
                            // The probe writes this verbatim into
                            // `GET <path> HTTP/1.1`, so it must be an
                            // origin-form target that cannot inject spaces or
                            // control bytes into the request line. A bare
                            // "healthz" would emit a malformed request line
                            // that origins reject — marking an otherwise
                            // healthy backend down. Reject at parse time
                            // (consistent with the other health_check
                            // validations) rather than silently truncating
                            // at runtime.
                            const Str path_text = lit.value()->text;
                            if (path_text.len == 0 || path_text.ptr[0] != '/')
                                return frontend_error(FrontendError::UnsupportedSyntax,
                                                      span_from(*lit.value()),
                                                      path_text);
                            for (u32 i = 0; i < path_text.len; i++) {
                                const unsigned char ch =
                                    static_cast<unsigned char>(path_text.ptr[i]);
                                if (ch <= 0x20 || ch == 0x7f)
                                    return frontend_error(FrontendError::UnsupportedSyntax,
                                                          span_from(*lit.value()),
                                                          path_text);
                            }
                            item.upstream.hc_path_lit = path_text;
                            seen_path = true;
                        } else if (hc_key.eq({"interval", 8})) {
                            if (seen_interval)
                                return frontend_error(FrontendError::UnexpectedToken,
                                                      span_from(*hc_field.value()),
                                                      hc_key);
                            auto dur = expect(TokenType::DurLit);
                            if (!dur) return core::make_unexpected(dur.error());
                            const u32 kIntervalMs = dur_lit_to_ms(dur.value()->text);
                            if (kIntervalMs == 0)
                                return frontend_error(FrontendError::UnsupportedSyntax,
                                                      span_from(*dur.value()),
                                                      dur.value()->text);
                            item.upstream.hc_interval_ms = kIntervalMs;
                            seen_interval = true;
                        } else if (hc_key.eq({"status", 6})) {
                            if (seen_status)
                                return frontend_error(FrontendError::UnexpectedToken,
                                                      span_from(*hc_field.value()),
                                                      hc_key);
                            auto lit = expect(TokenType::IntLit);
                            if (!lit) return core::make_unexpected(lit.error());
                            // Accumulate in u64 with a pre-multiply overflow
                            // guard (mirrors the port literal above). A status
                            // literal that overflows u32 and wraps back into
                            // the valid HTTP range — e.g. 4294967496 -> 200 —
                            // must be rejected, not silently narrowed past the
                            // range check below.
                            u64 sv = 0;
                            for (u32 i = 0; i < lit.value()->text.len; i++) {
                                const u64 digit = static_cast<u64>(lit.value()->text.ptr[i] - '0');
                                if (sv > (0xffffu - digit) / 10u)
                                    return frontend_error(FrontendError::InvalidInteger,
                                                          span_from(*lit.value()),
                                                          lit.value()->text);
                                sv = sv * 10 + digit;
                            }
                            // The probe path parses the upstream reply with
                            // HttpResponseParser, which rejects any response
                            // outside 100..599 BEFORE the equality check — so an
                            // out-of-range expected status (e.g. 0, 99, 600) can
                            // never match and the backend could never be marked
                            // healthy. Reject it here.
                            if (sv < 100 || sv > 599)
                                return frontend_error(FrontendError::InvalidInteger,
                                                      span_from(*lit.value()),
                                                      lit.value()->text);
                            item.upstream.hc_expected_status = static_cast<u16>(sv);
                            seen_status = true;
                        } else {
                            return frontend_error(FrontendError::UnexpectedToken,
                                                  span_from(*hc_field.value()),
                                                  hc_key);
                        }
                        (void)take(TokenType::Comma);
                        if (cur().type == TokenType::RBrace) break;  // trailing comma
                    }
                    auto hc_rbrace = expect(TokenType::RBrace);
                    if (!hc_rbrace) return core::make_unexpected(hc_rbrace.error());
                    if (!seen_path || !seen_interval) {
                        // path before interval in the dict order; name the first
                        // missing required field so the user knows what to add.
                        const Str detail = !seen_path ? Str{"path", 4} : Str{"interval", 8};
                        return frontend_error(
                            FrontendError::UnsupportedSyntax, span_from(*field.value()), detail);
                    }
                    item.upstream.hc_enabled = true;
                } else {
                    return frontend_error(
                        FrontendError::UnexpectedToken, span_from(*field.value()), field_name);
                }
                // Field separator is optional: the DSL accepts both comma-
                // separated (`{ host: "x", port: N }`) and newline-laid-out
                // (`{ backends: [...]\n health_check: {...} }`) blocks. The
                // lexer drops newlines, so we stop only at the closing brace
                // and let the next iteration parse the following `field:`.
                (void)take(TokenType::Comma);
                if (cur().type == TokenType::RBrace) break;
            }
            auto rbrace = expect(TokenType::RBrace);
            if (!rbrace) return core::make_unexpected(rbrace.error());
            if (item.upstream.backend_count > 0) {
                // `backends:` is mutually exclusive with host/port — mixing
                // them is ambiguous about which is the primary endpoint.
                if (seen_host || seen_port)
                    return frontend_error(FrontendError::UnsupportedSyntax,
                                          item.upstream.addr_span);
            } else if (!seen_host && !seen_port && item.upstream.hc_enabled) {
                // Health-check-only, name-only upstream
                // (`upstream api { health_check: {...} }`). The host
                // application binds the address at runtime (pre-bound slot);
                // populate_route_config copies the health-check metadata onto
                // it. No address is required here.
            } else if (!seen_host || !seen_port) {
                // Name the specific missing field in the detail so the
                // diagnostic tells the user what to add. Point the
                // span at the address block (the `{` we captured),
                // not the closing brace. If both are missing, call
                // out "host" first since order in the dict is
                // host-then-port; the user will see "port" missing
                // after fixing the host.
                const Str detail = !seen_host ? Str{"host", 4} : Str{"port", 4};
                return frontend_error(
                    FrontendError::UnsupportedSyntax, item.upstream.addr_span, detail);
            }
            end_off = rbrace.value()->end;
            // Stretch the addr_span to cover the full `{ ... }` block
            // so analyze diagnostics point at the whole address site.
            item.upstream.addr_span.end = rbrace.value()->end;
            // An address is present iff host+port or a backends list was given;
            // a health-check-only block leaves this false (name-only upstream).
            item.upstream.has_address =
                (item.upstream.backend_count > 0) || (seen_host && seen_port);
        }
        item.span = Span{kw.value()->start, end_off, kw.value()->line, kw.value()->col};
        item.upstream.span = item.span;
        return item;
    }

    FrontendResult<AstStatement> parse_func_body_stmt() {
        if (take(TokenType::KwGuard)) {
            return parse_func_guard_stmt(prev());
        }
        if (cur().type == TokenType::Ident && cur().text.eq(lit_str("respond")) &&
            peek().type == TokenType::IntLit) {
            return parse_stmt();
        }
        if (take(TokenType::KwIf)) {
            // `if let name = expr { ... } else { ... }` — value-binding form,
            // parsed like `guard let` (see the route-block If site for the full
            // rationale). Binding name on `stmt.name`, `bind_value` set, bound
            // expr on `stmt.expr`.
            bool is_let = false;
            Str let_name{};
            if (take(TokenType::KwLet)) {
                auto name = expect(TokenType::Ident);
                if (!name) return core::make_unexpected(name.error());
                let_name = name.value()->text;
                is_let = true;
                auto eq = expect(TokenType::Eq);
                if (!eq) return core::make_unexpected(eq.error());
            }
            auto cond = parse_expr();
            if (!cond) return core::make_unexpected(cond.error());
            auto lbrace = expect(TokenType::LBrace);
            if (!lbrace) return core::make_unexpected(lbrace.error());
            auto then_stmt = parse_func_body_stmt();
            if (!then_stmt) return core::make_unexpected(then_stmt.error());
            auto rbrace = expect(TokenType::RBrace);
            if (!rbrace) return core::make_unexpected(rbrace.error());
            auto kw_else = expect(TokenType::KwElse);
            if (!kw_else) return core::make_unexpected(kw_else.error());
            auto else_lbrace = expect(TokenType::LBrace);
            if (!else_lbrace) return core::make_unexpected(else_lbrace.error());
            auto else_stmt = parse_func_body_stmt();
            if (!else_stmt) return core::make_unexpected(else_stmt.error());
            auto else_rbrace = expect(TokenType::RBrace);
            if (!else_rbrace) return core::make_unexpected(else_rbrace.error());
            AstStatement stmt{};
            stmt.kind = AstStmtKind::If;
            stmt.bind_value = is_let;
            stmt.name = let_name;
            stmt.expr = cond.value();
            auto then_ptr = alloc_stmt(then_stmt.value());
            if (!then_ptr) return core::make_unexpected(then_ptr.error());
            auto else_ptr = alloc_stmt(else_stmt.value());
            if (!else_ptr) return core::make_unexpected(else_ptr.error());
            stmt.then_stmt = then_ptr.value();
            stmt.else_stmt = else_ptr.value();
            stmt.span =
                Span{cond->span.start, else_rbrace.value()->end, cond->span.line, cond->span.col};
            return stmt;
        }
        if (take(TokenType::KwMatch)) {
            const bool is_const = take(TokenType::KwConst) != nullptr;
            auto subject = parse_expr();
            if (!subject) return core::make_unexpected(subject.error());
            auto lbrace = expect(TokenType::LBrace);
            if (!lbrace) return core::make_unexpected(lbrace.error());
            AstStatement stmt{};
            stmt.kind = AstStmtKind::Match;
            stmt.is_const = is_const;
            stmt.expr = subject.value();
            while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
                if (cur().type == TokenType::Ident && cur().text.eq({"case", 4}))
                    return frontend_error(
                        FrontendError::UnsupportedSyntax, span_from(cur()), kCaseDetail);
                AstStatement::MatchArm arm{};
                arm.span = span_from(cur());
                if (take(TokenType::Underscore)) {
                    arm.is_wildcard = true;
                } else {
                    auto pattern = parse_primary_expr();
                    if (!pattern) return core::make_unexpected(pattern.error());
                    auto pattern_ptr = alloc_expr(pattern.value());
                    if (!pattern_ptr) return core::make_unexpected(pattern_ptr.error());
                    arm.pattern = pattern_ptr.value();
                }
                if (take(TokenType::KwIf)) {
                    auto guard = parse_expr();
                    if (!guard) return core::make_unexpected(guard.error());
                    auto guard_ptr = alloc_expr(guard.value());
                    if (!guard_ptr) return core::make_unexpected(guard_ptr.error());
                    arm.has_guard = true;
                    arm.guard = guard_ptr.value();
                }
                if (cur().type == TokenType::Colon)
                    return frontend_error(
                        FrontendError::UnsupportedSyntax, span_from(cur()), kMatchColonDetail);
                auto arrow = expect(TokenType::Arrow);
                if (!arrow) return core::make_unexpected(arrow.error());
                const bool saved_dot_stop = arm_body_stops_cross_line_dot;
                arm_body_stops_cross_line_dot = arm_body_needs_dot_stop();
                auto arm_stmt = parse_func_body_stmt();
                arm_body_stops_cross_line_dot = saved_dot_stop;
                if (!arm_stmt) return core::make_unexpected(arm_stmt.error());
                auto arm_ptr = alloc_stmt(arm_stmt.value());
                if (!arm_ptr) return core::make_unexpected(arm_ptr.error());
                arm.stmt = arm_ptr.value();
                arm.span.end = arm_ptr.value()->span.end;
                if (!stmt.match_arms.push(arm))
                    return frontend_error(FrontendError::TooManyItems, arm.span);
            }
            auto rbrace = expect(TokenType::RBrace);
            if (!rbrace) return core::make_unexpected(rbrace.error());
            if (stmt.match_arms.len == 0)
                return frontend_error(FrontendError::UnexpectedToken, span_from(*rbrace.value()));
            stmt.span = Span{
                subject->span.start, rbrace.value()->end, subject->span.line, subject->span.col};
            return stmt;
        }
        if (cur().type == TokenType::LBrace) {
            const Token start = cur();
            pos++;
            AstStatement block{};
            block.kind = AstStmtKind::Block;
            while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
                if (cur().type == TokenType::KwLet) {
                    auto inner = parse_stmt();
                    if (!inner) return core::make_unexpected(inner.error());
                    auto inner_ptr = alloc_stmt(inner.value());
                    if (!inner_ptr) return core::make_unexpected(inner_ptr.error());
                    if (!block.block_stmts.push(inner_ptr.value()))
                        return frontend_error(FrontendError::TooManyItems, inner->span);
                    continue;
                }
                if (cur().type == TokenType::KwGuard) {
                    take(TokenType::KwGuard);
                    auto inner = parse_func_guard_stmt(prev());
                    if (!inner) return core::make_unexpected(inner.error());
                    auto inner_ptr = alloc_stmt(inner.value());
                    if (!inner_ptr) return core::make_unexpected(inner_ptr.error());
                    if (!block.block_stmts.push(inner_ptr.value()))
                        return frontend_error(FrontendError::TooManyItems, inner->span);
                    continue;
                }
                if (cur().type == TokenType::KwIf) {
                    auto inner = parse_func_body_stmt();
                    if (!inner) return core::make_unexpected(inner.error());
                    auto inner_ptr = alloc_stmt(inner.value());
                    if (!inner_ptr) return core::make_unexpected(inner_ptr.error());
                    if (!block.block_stmts.push(inner_ptr.value()))
                        return frontend_error(FrontendError::TooManyItems, inner->span);
                    break;
                }
                if (cur().type == TokenType::KwMatch) {
                    auto inner = parse_func_body_stmt();
                    if (!inner) return core::make_unexpected(inner.error());
                    auto inner_ptr = alloc_stmt(inner.value());
                    if (!inner_ptr) return core::make_unexpected(inner_ptr.error());
                    if (!block.block_stmts.push(inner_ptr.value()))
                        return frontend_error(FrontendError::TooManyItems, inner->span);
                    break;
                }
                auto expr = parse_expr();
                if (!expr) return core::make_unexpected(expr.error());
                AstStatement expr_stmt{};
                expr_stmt.kind = AstStmtKind::Expr;
                expr_stmt.expr = expr.value();
                expr_stmt.span = expr->span;
                auto expr_ptr = alloc_stmt(expr_stmt);
                if (!expr_ptr) return core::make_unexpected(expr_ptr.error());
                if (!block.block_stmts.push(expr_ptr.value()))
                    return frontend_error(FrontendError::TooManyItems, expr->span);
                break;
            }
            auto rbrace = expect(TokenType::RBrace);
            if (!rbrace) return core::make_unexpected(rbrace.error());
            if (block.block_stmts.len == 0)
                return frontend_error(FrontendError::UnsupportedSyntax,
                                      span_from(*rbrace.value()),
                                      kEmptyBlockDetail);
            block.span = Span{start.start, rbrace.value()->end, start.line, start.col};
            return block;
        }
        auto expr = parse_expr();
        if (!expr) return core::make_unexpected(expr.error());
        AstStatement expr_stmt{};
        expr_stmt.kind = AstStmtKind::Expr;
        expr_stmt.expr = expr.value();
        expr_stmt.span = expr->span;
        return expr_stmt;
    }

    FrontendResult<AstTypeRef> parse_func_type_ref() {
        AstTypeRef out{};
        // Surface sugar: `[T]` desugars to `Array<T>`. Recurses for nested
        // forms like `[[Int]]` → `Array<Array<Int>>`. The "Array" name here
        // uses a C-string literal with static storage duration, matching the
        // pattern for other internal names (e.g., `Str{"Self", 4}`).
        if (const Token* lbracket = take(TokenType::LBracket)) {
            auto elem = parse_func_type_ref();
            if (!elem) return core::make_unexpected(elem.error());
            auto rbracket = expect(TokenType::RBracket);
            if (!rbracket) return core::make_unexpected(rbracket.error());
            out.name = Str{"Array", 5};
            auto elem_ptr = alloc_type(elem.value());
            if (!elem_ptr) return core::make_unexpected(elem_ptr.error());
            if (!out.type_arg_namespaces.push(elem->namespace_name))
                return frontend_error(FrontendError::TooManyItems, span_from(*lbracket));
            if (!out.type_arg_names.push(elem->name))
                return frontend_error(FrontendError::TooManyItems, span_from(*lbracket));
            if (!out.type_args.push(elem_ptr.value()))
                return frontend_error(FrontendError::TooManyItems, span_from(*lbracket));
            return out;
        }
        if (take(TokenType::LParen)) {
            out.is_tuple = true;
            while (true) {
                auto elem = parse_func_type_ref();
                if (!elem) return core::make_unexpected(elem.error());
                if (!elem->is_tuple && elem->type_args.len == 0 && elem->name.len != 0) {
                    if (!out.tuple_elem_names.push(elem->name))
                        return frontend_error(FrontendError::TooManyItems, Span{});
                } else {
                    if (!out.tuple_elem_names.push({}))
                        return frontend_error(FrontendError::TooManyItems, Span{});
                }
                auto elem_ptr = alloc_type(elem.value());
                if (!elem_ptr) return core::make_unexpected(elem_ptr.error());
                if (!out.tuple_elem_types.push(elem_ptr.value()))
                    return frontend_error(FrontendError::TooManyItems, Span{});
                if (take(TokenType::RParen)) break;
                auto comma = expect(TokenType::Comma);
                if (!comma) return core::make_unexpected(comma.error());
            }
            if (out.tuple_elem_types.len < 2)
                return frontend_error(FrontendError::UnsupportedSyntax, span_from(prev()));
            return out;
        }
        auto type_name = expect(TokenType::Ident);
        if (!type_name) return core::make_unexpected(type_name.error());
        out.name = type_name.value()->text;
        if (take(TokenType::Dot)) {
            out.namespace_name = out.name;
            auto member_name = expect(TokenType::Ident);
            if (!member_name) return core::make_unexpected(member_name.error());
            out.name = member_name.value()->text;
        }
        if (take(TokenType::Lt)) {
            while (true) {
                auto type_arg = parse_func_type_ref();
                if (!type_arg) return core::make_unexpected(type_arg.error());
                if (!out.type_arg_namespaces.push(type_arg->namespace_name))
                    return frontend_error(FrontendError::TooManyItems,
                                          span_from(*type_name.value()));
                if (!out.type_arg_names.push(type_arg->name))
                    return frontend_error(FrontendError::TooManyItems,
                                          span_from(*type_name.value()));
                auto type_arg_ptr = alloc_type(type_arg.value());
                if (!type_arg_ptr) return core::make_unexpected(type_arg_ptr.error());
                if (!out.type_args.push(type_arg_ptr.value()))
                    return frontend_error(FrontendError::TooManyItems,
                                          span_from(*type_name.value()));
                if (take(TokenType::Gt)) break;
                auto comma = expect(TokenType::Comma);
                if (!comma) return core::make_unexpected(comma.error());
            }
        }
        return out;
    }

    FrontendResult<AstItem> parse_func() {
        auto kw = expect(TokenType::KwFunc);
        if (!kw) return core::make_unexpected(kw.error());
        auto name = expect(TokenType::Ident);
        if (!name) return core::make_unexpected(name.error());

        auto item = std::make_unique<AstItem>();
        AstItem& out = *item;
        out.kind = AstItemKind::Func;
        out.func.name = name.value()->text;
        out.func.span = span_from(*kw.value());

        auto append_constraint = [&](AstFunctionDecl::TypeParamDecl& target,
                                     Str constraint_namespace,
                                     Str constraint_name,
                                     Span span) -> FrontendResult<void> {
            target.has_constraint = true;
            if (target.constraints.len == 0) {
                target.constraint_namespace = constraint_namespace;
                target.constraint = constraint_name;
            }
            if (!target.constraint_namespaces.push(constraint_namespace))
                return frontend_error(FrontendError::TooManyItems, span);
            if (!target.constraints.push(constraint_name))
                return frontend_error(FrontendError::TooManyItems, span);
            return {};
        };

        if (take(TokenType::Lt)) {
            while (true) {
                auto type_param = expect(TokenType::Ident);
                if (!type_param) return core::make_unexpected(type_param.error());
                AstFunctionDecl::TypeParamDecl decl{};
                decl.name = type_param.value()->text;
                if (take(TokenType::Colon)) {
                    while (true) {
                        auto constraint = expect(TokenType::Ident);
                        if (!constraint) return core::make_unexpected(constraint.error());
                        Str constraint_namespace{};
                        Str constraint_name = constraint.value()->text;
                        if (take(TokenType::Dot)) {
                            constraint_namespace = constraint_name;
                            auto member = expect(TokenType::Ident);
                            if (!member) return core::make_unexpected(member.error());
                            constraint_name = member.value()->text;
                        }
                        auto appended = append_constraint(decl,
                                                          constraint_namespace,
                                                          constraint_name,
                                                          span_from(*constraint.value()));
                        if (!appended) return core::make_unexpected(appended.error());
                        if (cur().type != TokenType::Comma || peek(1).type == TokenType::Gt) break;
                        auto comma = expect(TokenType::Comma);
                        if (!comma) return core::make_unexpected(comma.error());
                    }
                }
                if (!out.func.type_params.push(decl))
                    return frontend_error(FrontendError::TooManyItems,
                                          span_from(*type_param.value()));
                if (take(TokenType::Gt)) break;
                auto comma = expect(TokenType::Comma);
                if (!comma) return core::make_unexpected(comma.error());
            }
        }

        auto lparen = expect(TokenType::LParen);
        if (!lparen) return core::make_unexpected(lparen.error());

        if (!take(TokenType::RParen)) {
            while (true) {
                const bool has_underscore = take(TokenType::Underscore) != nullptr;
                auto param_name = expect(TokenType::Ident);
                if (!param_name) return core::make_unexpected(param_name.error());
                auto colon = expect(TokenType::Colon);
                if (!colon) return core::make_unexpected(colon.error());
                auto type_ref = parse_func_type_ref();
                if (!type_ref) return core::make_unexpected(type_ref.error());
                AstFunctionDecl::ParamDecl param{};
                param.name = param_name.value()->text;
                param.type = type_ref.value();
                param.has_underscore_label = has_underscore;
                if (!out.func.params.push(param))
                    return frontend_error(FrontendError::TooManyItems,
                                          span_from(*param_name.value()));
                if (take(TokenType::RParen)) break;
                auto comma = expect(TokenType::Comma);
                if (!comma) return core::make_unexpected(comma.error());
            }
        }

        if (take(TokenType::ThinArrow)) {
            auto ret_type = parse_func_type_ref();
            if (!ret_type) return core::make_unexpected(ret_type.error());
            out.func.has_return_type = true;
            out.func.return_type = ret_type.value();
        }
        if (take(TokenType::KwWhere)) {
            while (true) {
                auto constraint = expect(TokenType::Ident);
                if (!constraint) return core::make_unexpected(constraint.error());
                Str constraint_namespace{};
                Str constraint_name = constraint.value()->text;
                if (take(TokenType::Dot)) {
                    constraint_namespace = constraint_name;
                    auto member = expect(TokenType::Ident);
                    if (!member) return core::make_unexpected(member.error());
                    constraint_name = member.value()->text;
                }
                auto lparen = expect(TokenType::LParen);
                if (!lparen) return core::make_unexpected(lparen.error());
                auto type_param = expect(TokenType::Ident);
                if (!type_param) return core::make_unexpected(type_param.error());
                auto rparen = expect(TokenType::RParen);
                if (!rparen) return core::make_unexpected(rparen.error());

                AstFunctionDecl::TypeParamDecl* target = nullptr;
                for (u32 ti = 0; ti < out.func.type_params.len; ti++) {
                    if (out.func.type_params[ti].name.eq(type_param.value()->text)) {
                        target = &out.func.type_params[ti];
                        break;
                    }
                }
                if (target == nullptr)
                    return frontend_error(FrontendError::UnsupportedSyntax,
                                          span_from(*type_param.value()),
                                          type_param.value()->text);
                auto appended = append_constraint(
                    *target, constraint_namespace, constraint_name, span_from(*constraint.value()));
                if (!appended) return core::make_unexpected(appended.error());

                if (!take(TokenType::Comma)) break;
            }
        }
        AstStatement body_stmt{};
        if (take(TokenType::Arrow)) {
            auto body = parse_expr();
            if (!body) return core::make_unexpected(body.error());
            body_stmt.kind = AstStmtKind::Expr;
            body_stmt.expr = body.value();
            body_stmt.span = body->span;
        } else {
            auto body = parse_func_body_stmt();
            if (!body) return core::make_unexpected(body.error());
            body_stmt = body.value();
        }
        auto body_ptr = alloc_stmt(body_stmt);
        if (!body_ptr) return core::make_unexpected(body_ptr.error());

        out.func.body = body_ptr.value();
        out.span =
            Span{kw.value()->start, body_ptr.value()->span.end, kw.value()->line, kw.value()->col};
        out.func.span = out.span;
        return out;
    }

    FrontendResult<AstItem> parse_variant() {
        auto kw = expect(TokenType::KwVariant);
        if (!kw) return core::make_unexpected(kw.error());
        auto name = expect(TokenType::Ident);
        if (!name) return core::make_unexpected(name.error());

        AstItem item{};
        item.kind = AstItemKind::Variant;
        item.variant.name = name.value()->text;
        item.variant.span =
            Span{kw.value()->start, kw.value()->end, kw.value()->line, kw.value()->col};

        if (take(TokenType::Lt)) {
            while (true) {
                auto type_param = expect(TokenType::Ident);
                if (!type_param) return core::make_unexpected(type_param.error());
                if (!item.variant.type_params.push(type_param.value()->text))
                    return frontend_error(FrontendError::TooManyItems,
                                          span_from(*type_param.value()));
                if (take(TokenType::Gt)) break;
                auto comma = expect(TokenType::Comma);
                if (!comma) return core::make_unexpected(comma.error());
            }
        }

        auto lbrace = expect(TokenType::LBrace);
        if (!lbrace) return core::make_unexpected(lbrace.error());

        while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
            auto case_name = expect(TokenType::Ident);
            if (!case_name) return core::make_unexpected(case_name.error());
            AstVariantDecl::CaseDecl case_decl{};
            case_decl.name = case_name.value()->text;
            if (take(TokenType::LParen)) {
                auto payload_type = parse_func_type_ref();
                if (!payload_type) return core::make_unexpected(payload_type.error());
                case_decl.has_payload = true;
                case_decl.payload_type = payload_type.value();
                auto rparen = expect(TokenType::RParen);
                if (!rparen) return core::make_unexpected(rparen.error());
            }
            if (!item.variant.cases.push(case_decl))
                return frontend_error(FrontendError::TooManyItems, span_from(*case_name.value()));
            take(TokenType::Comma);
        }
        auto rbrace = expect(TokenType::RBrace);
        if (!rbrace) return core::make_unexpected(rbrace.error());
        if (item.variant.cases.len == 0)
            return frontend_error(FrontendError::UnexpectedToken, span_from(*rbrace.value()));
        item.span = Span{kw.value()->start, rbrace.value()->end, kw.value()->line, kw.value()->col};
        item.variant.span = item.span;
        return item;
    }

    FrontendResult<AstItem> parse_protocol() {
        auto kw = expect(TokenType::KwProtocol);
        if (!kw) return core::make_unexpected(kw.error());
        auto name = expect(TokenType::Ident);
        if (!name) return core::make_unexpected(name.error());
        AstItem item{};
        item.kind = AstItemKind::Protocol;
        item.protocol.name = name.value()->text;
        auto lbrace = expect(TokenType::LBrace);
        if (!lbrace) return core::make_unexpected(lbrace.error());
        while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
            if (cur().type == TokenType::Ident && cur().text.eq({"type", 4})) {
                auto type_kw = expect(TokenType::Ident);
                if (!type_kw) return core::make_unexpected(type_kw.error());
                auto assoc_name = expect(TokenType::Ident);
                if (!assoc_name) return core::make_unexpected(assoc_name.error());
                AstProtocolDecl::AssociatedTypeDecl assoc{};
                assoc.name = assoc_name.value()->text;
                if (!item.protocol.associated_types.push(assoc))
                    return frontend_error(FrontendError::TooManyItems,
                                          span_from(*assoc_name.value()));
                continue;
            }
            auto func_kw = expect(TokenType::KwFunc);
            if (!func_kw) return core::make_unexpected(func_kw.error());
            auto method_name = expect(TokenType::Ident);
            if (!method_name) return core::make_unexpected(method_name.error());
            AstProtocolDecl::MethodDecl method{};
            method.name = method_name.value()->text;
            auto lparen = expect(TokenType::LParen);
            if (!lparen) return core::make_unexpected(lparen.error());
            if (!take(TokenType::RParen)) {
                while (true) {
                    const bool has_underscore = take(TokenType::Underscore) != nullptr;
                    auto param_name = expect(TokenType::Ident);
                    if (!param_name) return core::make_unexpected(param_name.error());
                    auto colon = expect(TokenType::Colon);
                    if (!colon) return core::make_unexpected(colon.error());
                    auto type_ref = parse_func_type_ref();
                    if (!type_ref) return core::make_unexpected(type_ref.error());
                    AstProtocolDecl::MethodDecl::ParamDecl param{};
                    param.name = param_name.value()->text;
                    param.type = type_ref.value();
                    param.has_underscore_label = has_underscore;
                    if (!method.params.push(param))
                        return frontend_error(FrontendError::TooManyItems,
                                              span_from(*param_name.value()));
                    if (take(TokenType::RParen)) break;
                    auto comma = expect(TokenType::Comma);
                    if (!comma) return core::make_unexpected(comma.error());
                }
            }
            if (take(TokenType::ThinArrow)) {
                auto ret_type = parse_func_type_ref();
                if (!ret_type) return core::make_unexpected(ret_type.error());
                method.has_return_type = true;
                method.return_type = ret_type.value();
            }
            if (take(TokenType::Arrow)) {
                auto body = parse_expr();
                if (!body) return core::make_unexpected(body.error());
                AstStatement body_stmt{};
                body_stmt.kind = AstStmtKind::Expr;
                body_stmt.expr = body.value();
                body_stmt.span = body->span;
                auto body_ptr = alloc_stmt(body_stmt);
                if (!body_ptr) return core::make_unexpected(body_ptr.error());
                method.default_body = body_ptr.value();
            } else if (cur().type == TokenType::LBrace) {
                auto body = parse_func_body_stmt();
                if (!body) return core::make_unexpected(body.error());
                auto body_ptr = alloc_stmt(body.value());
                if (!body_ptr) return core::make_unexpected(body_ptr.error());
                method.default_body = body_ptr.value();
            }
            if (!item.protocol.methods.push(method))
                return frontend_error(FrontendError::TooManyItems, span_from(*method_name.value()));
        }
        auto rbrace = expect(TokenType::RBrace);
        if (!rbrace) return core::make_unexpected(rbrace.error());
        item.span = Span{kw.value()->start, rbrace.value()->end, kw.value()->line, kw.value()->col};
        item.protocol.span = item.span;
        return item;
    }

    FrontendResult<AstItem> parse_impl() {
        auto target = parse_func_type_ref();
        if (!target) return core::make_unexpected(target.error());
        auto kw = expect(TokenType::KwImpl);
        if (!kw) return core::make_unexpected(kw.error());
        AstItem item{};
        item.kind = AstItemKind::Impl;
        item.impl_decl.target = target.value();
        while (true) {
            auto proto = expect(TokenType::Ident);
            if (!proto) return core::make_unexpected(proto.error());
            Str proto_namespace{};
            Str proto_name = proto.value()->text;
            if (take(TokenType::Dot)) {
                proto_namespace = proto_name;
                auto member = expect(TokenType::Ident);
                if (!member) return core::make_unexpected(member.error());
                proto_name = member.value()->text;
            }
            if (!item.impl_decl.protocol_namespaces.push(proto_namespace))
                return frontend_error(FrontendError::TooManyItems, span_from(*proto.value()));
            if (!item.impl_decl.protocols.push(proto_name))
                return frontend_error(FrontendError::TooManyItems, span_from(*proto.value()));
            if (!take(TokenType::Comma)) break;
        }
        auto lbrace = expect(TokenType::LBrace);
        if (!lbrace) return core::make_unexpected(lbrace.error());
        while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
            if (cur().type == TokenType::Ident && cur().text.eq({"type", 4})) {
                auto type_kw = expect(TokenType::Ident);
                if (!type_kw) return core::make_unexpected(type_kw.error());
                auto assoc_name = expect(TokenType::Ident);
                if (!assoc_name) return core::make_unexpected(assoc_name.error());
                auto eq = expect(TokenType::Eq);
                if (!eq) return core::make_unexpected(eq.error());
                auto type_ref = parse_func_type_ref();
                if (!type_ref) return core::make_unexpected(type_ref.error());
                AstImplDecl::AssociatedTypeBinding assoc{};
                assoc.name = assoc_name.value()->text;
                assoc.type = type_ref.value();
                if (!item.impl_decl.associated_types.push(assoc))
                    return frontend_error(FrontendError::TooManyItems,
                                          span_from(*assoc_name.value()));
                continue;
            }
            auto method = parse_func();
            if (!method) return core::make_unexpected(method.error());
            if (method->kind != AstItemKind::Func)
                return frontend_error(FrontendError::UnsupportedSyntax, item.span);
            if (!item.impl_decl.methods.push(method->func))
                return frontend_error(FrontendError::TooManyItems, span_from(*kw.value()));
        }
        auto rbrace = expect(TokenType::RBrace);
        if (!rbrace) return core::make_unexpected(rbrace.error());
        item.span = Span{kw.value()->start, rbrace.value()->end, kw.value()->line, kw.value()->col};
        item.impl_decl.span = item.span;
        return item;
    }

    FrontendResult<AstItem> parse_import() {
        auto kw = expect(TokenType::KwImport);
        if (!kw) return core::make_unexpected(kw.error());
        AstItem item{};
        item.kind = AstItemKind::Import;
        if (take(TokenType::LBrace)) {
            item.import_decl.selective = true;
            while (true) {
                auto name = expect(TokenType::Ident);
                if (!name) return core::make_unexpected(name.error());
                AstImportDecl::SelectedName selected{};
                selected.name = name.value()->text;
                if (take(TokenType::KwAs)) {
                    auto alias = expect(TokenType::Ident);
                    if (!alias) return core::make_unexpected(alias.error());
                    selected.has_alias = true;
                    selected.alias = alias.value()->text;
                }
                if (!item.import_decl.selected_names.push(selected))
                    return frontend_error(FrontendError::TooManyItems, span_from(*name.value()));
                if (take(TokenType::RBrace)) break;
                auto comma = expect(TokenType::Comma);
                if (!comma) return core::make_unexpected(comma.error());
            }
            auto from_kw = expect(TokenType::Ident);
            if (!from_kw) return core::make_unexpected(from_kw.error());
            if (!from_kw.value()->text.eq({"from", 4}))
                return frontend_error(FrontendError::UnexpectedToken,
                                      span_from(*from_kw.value()),
                                      from_kw.value()->text);
        } else if (take(TokenType::Star)) {
            auto as_kw = expect(TokenType::KwAs);
            if (!as_kw) return core::make_unexpected(as_kw.error());
            auto alias = expect(TokenType::Ident);
            if (!alias) return core::make_unexpected(alias.error());
            item.import_decl.has_namespace_alias = true;
            item.import_decl.namespace_alias = alias.value()->text;
            auto from_kw = expect(TokenType::Ident);
            if (!from_kw) return core::make_unexpected(from_kw.error());
            if (!from_kw.value()->text.eq({"from", 4}))
                return frontend_error(FrontendError::UnexpectedToken,
                                      span_from(*from_kw.value()),
                                      from_kw.value()->text);
        }
        auto path = expect(TokenType::StringLit);
        if (!path) return core::make_unexpected(path.error());
        item.import_decl.path = path.value()->text;
        item.span = Span{kw.value()->start, path.value()->end, kw.value()->line, kw.value()->col};
        item.import_decl.span = item.span;
        return item;
    }

    FrontendResult<AstItem> parse_using() {
        auto kw = expect(TokenType::KwUsing);
        if (!kw) return core::make_unexpected(kw.error());
        auto name = expect(TokenType::Ident);
        if (!name) return core::make_unexpected(name.error());
        auto eq = expect(TokenType::Eq);
        if (!eq) return core::make_unexpected(eq.error());
        auto first = expect(TokenType::Ident);
        if (!first) return core::make_unexpected(first.error());
        AstItem item{};
        item.kind = AstItemKind::Using;
        item.using_decl.name = name.value()->text;
        if (!item.using_decl.target_parts.push(first.value()->text))
            return frontend_error(FrontendError::TooManyItems, span_from(*first.value()));
        while (take(TokenType::Dot)) {
            auto part = expect(TokenType::Ident);
            if (!part) return core::make_unexpected(part.error());
            if (!item.using_decl.target_parts.push(part.value()->text))
                return frontend_error(FrontendError::TooManyItems, span_from(*part.value()));
        }
        if (item.using_decl.target_parts.len < 2)
            return frontend_error(
                FrontendError::UnsupportedSyntax,
                Span{kw.value()->start, cur().start, kw.value()->line, kw.value()->col});
        item.span =
            Span{kw.value()->start, toks->tokens[pos - 1].end, kw.value()->line, kw.value()->col};
        item.using_decl.span = item.span;
        return item;
    }

    FrontendResult<AstItem> parse_type_alias() {
        auto type_kw = expect(TokenType::Ident);
        if (!type_kw) return core::make_unexpected(type_kw.error());
        if (!type_kw.value()->text.eq({"type", 4}))
            return frontend_error(
                FrontendError::UnexpectedToken, span_from(*type_kw.value()), type_kw.value()->text);
        auto name = expect(TokenType::Ident);
        if (!name) return core::make_unexpected(name.error());

        AstItem item{};
        item.kind = AstItemKind::TypeAlias;
        item.span = span_from(*type_kw.value());
        item.type_alias.span = item.span;
        item.type_alias.name = name.value()->text;

        if (take(TokenType::Lt)) {
            while (true) {
                auto type_param = expect(TokenType::Ident);
                if (!type_param) return core::make_unexpected(type_param.error());
                if (!item.type_alias.type_params.push(type_param.value()->text))
                    return frontend_error(FrontendError::TooManyItems,
                                          span_from(*type_param.value()));
                if (take(TokenType::Gt)) break;
                auto comma = expect(TokenType::Comma);
                if (!comma) return core::make_unexpected(comma.error());
            }
        }

        if (take(TokenType::Eq)) {
            auto target = parse_func_type_ref();
            if (!target) return core::make_unexpected(target.error());
            item.type_alias.target = target.value();
            return item;
        }

        auto match_kw = expect(TokenType::KwMatch);
        if (!match_kw) return core::make_unexpected(match_kw.error());
        item.type_alias.is_match = true;
        auto lbrace = expect(TokenType::LBrace);
        if (!lbrace) return core::make_unexpected(lbrace.error());
        while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
            if (cur().type == TokenType::Ident && cur().text.eq({"case", 4}))
                return frontend_error(
                    FrontendError::UnsupportedSyntax, span_from(cur()), kCaseDetail);
            const Token arm_start = cur();
            AstTypeAliasDecl::ArmDecl arm{};
            if (take(TokenType::Underscore)) {
                arm.is_wildcard = true;
            } else {
                auto type_param = expect(TokenType::Ident);
                if (!type_param) return core::make_unexpected(type_param.error());
                arm.type_param = type_param.value()->text;
                if (take(TokenType::Dot)) {
                    auto associated_name = expect(TokenType::Ident);
                    if (!associated_name) return core::make_unexpected(associated_name.error());
                    arm.associated_name = associated_name.value()->text;
                }
                if (take(TokenType::EqEq)) {
                    arm.is_type_equality = true;
                    auto rhs_type_param = expect(TokenType::Ident);
                    if (!rhs_type_param) return core::make_unexpected(rhs_type_param.error());
                    arm.rhs_type_param = rhs_type_param.value()->text;
                    if (take(TokenType::Dot)) {
                        auto rhs_associated_name = expect(TokenType::Ident);
                        if (!rhs_associated_name)
                            return core::make_unexpected(rhs_associated_name.error());
                        arm.rhs_associated_name = rhs_associated_name.value()->text;
                    }
                } else {
                    if (arm.associated_name.len != 0)
                        return frontend_error(FrontendError::UnsupportedSyntax,
                                              span_from(*type_param.value()));
                    auto colon = expect(TokenType::Colon);
                    if (!colon) return core::make_unexpected(colon.error());
                    auto constraint = expect(TokenType::Ident);
                    if (!constraint) return core::make_unexpected(constraint.error());
                    arm.constraint = constraint.value()->text;
                    if (take(TokenType::Dot)) {
                        arm.constraint_namespace = arm.constraint;
                        auto member = expect(TokenType::Ident);
                        if (!member) return core::make_unexpected(member.error());
                        arm.constraint = member.value()->text;
                    }
                }
            }
            auto arrow = expect(TokenType::Arrow);
            if (!arrow) return core::make_unexpected(arrow.error());
            auto target = parse_func_type_ref();
            if (!target) return core::make_unexpected(target.error());
            arm.type = target.value();
            if (!item.type_alias.arms.push(arm))
                return frontend_error(FrontendError::TooManyItems, span_from(arm_start));
        }
        auto rbrace = expect(TokenType::RBrace);
        if (!rbrace) return core::make_unexpected(rbrace.error());
        if (item.type_alias.arms.len == 0)
            return frontend_error(FrontendError::UnexpectedToken, span_from(*rbrace.value()));
        return item;
    }

    FrontendResult<AstItem> parse_struct() {
        auto kw = expect(TokenType::KwStruct);
        if (!kw) return core::make_unexpected(kw.error());
        auto name = expect(TokenType::Ident);
        if (!name) return core::make_unexpected(name.error());
        AstItem item{};
        item.kind = AstItemKind::Struct;
        item.struct_decl.name = name.value()->text;
        item.struct_decl.span =
            Span{kw.value()->start, kw.value()->end, kw.value()->line, kw.value()->col};
        if (take(TokenType::Lt)) {
            while (true) {
                auto type_param = expect(TokenType::Ident);
                if (!type_param) return core::make_unexpected(type_param.error());
                if (!item.struct_decl.type_params.push(type_param.value()->text))
                    return frontend_error(FrontendError::TooManyItems,
                                          span_from(*type_param.value()));
                if (take(TokenType::Gt)) break;
                auto comma = expect(TokenType::Comma);
                if (!comma) return core::make_unexpected(comma.error());
            }
        }
        auto lbrace = expect(TokenType::LBrace);
        if (!lbrace) return core::make_unexpected(lbrace.error());

        while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
            auto field_name = expect_field_name();
            if (!field_name) return core::make_unexpected(field_name.error());
            auto colon = expect(TokenType::Colon);
            if (!colon) return core::make_unexpected(colon.error());
            auto field_type = parse_func_type_ref();
            if (!field_type) return core::make_unexpected(field_type.error());
            AstStructDecl::FieldDecl field{};
            field.name = field_name.value()->text;
            field.type = field_type.value();
            if (!item.struct_decl.fields.push(field))
                return frontend_error(FrontendError::TooManyItems, span_from(*field_name.value()));
            take(TokenType::Comma);
        }
        auto rbrace = expect(TokenType::RBrace);
        if (!rbrace) return core::make_unexpected(rbrace.error());
        if (item.struct_decl.fields.len == 0)
            return frontend_error(FrontendError::UnexpectedToken, span_from(*rbrace.value()));
        item.span = Span{kw.value()->start, rbrace.value()->end, kw.value()->line, kw.value()->col};
        item.struct_decl.span = item.span;
        return item;
    }

    static bool is_method_keyword(TokenType t) {
        return t == TokenType::KwGet || t == TokenType::KwPost || t == TokenType::KwPut ||
               t == TokenType::KwDelete || t == TokenType::KwPatch || t == TokenType::KwHead ||
               t == TokenType::KwOptions;
    }

    FrontendResult<AstDecorator> parse_decorator_atom() {
        auto at = expect(TokenType::At);
        if (!at) return core::make_unexpected(at.error());
        auto name_tok = expect(TokenType::Ident);
        if (!name_tok) return core::make_unexpected(name_tok.error());
        return frontend_error(
            FrontendError::UnsupportedSyntax,
            Span{at.value()->start, name_tok.value()->end, at.value()->line, at.value()->col},
            lit_str("decorators are deprecated"));
    }

    // Convert a DurLit token ("500ms"/"5s"/"2m"/"1h") to whole seconds, rounding
    // up sub-second values to 1. Returns 0 on a malformed literal.
    static u32 dur_lit_to_seconds(Str t) {
        u64 digits = 0;
        u32 i = 0;
        for (; i < t.len && t.ptr[i] >= '0' && t.ptr[i] <= '9'; i++) {
            digits = digits * 10 + static_cast<u64>(t.ptr[i] - '0');
            if (digits > 0xffffffffull) return 0;
        }
        const Str kUnit{t.ptr + i, t.len - i};
        u64 secs = 0;
        if (kUnit.eq({"ms", 2}))
            secs = (digits + 999) / 1000;  // round sub-second up to 1s
        else if (kUnit.eq({"s", 1}))
            secs = digits;
        else if (kUnit.eq({"m", 1}))
            secs = digits * 60;
        else if (kUnit.eq({"h", 1}))
            secs = digits * 3600;
        else
            return 0;
        if (secs == 0 && digits > 0) secs = 1;  // e.g. 1ms → 1s
        return secs > 0xffffffffull ? 0xffffffffu : static_cast<u32>(secs);
    }

    // Parse one official (built-in) decorator: `@name(args)`. Only a fixed
    // whitelist is accepted — there are no user-defined decorators. Unknown
    // names are a parse error.
    // Parse one @rateLimit `by:` key source into `spec`: `ip`, or one of
    // header/query/cookie/param("name"). Sources are plain identifiers.
    FrontendResult<bool> parse_rate_limit_source(RateLimitKeySpec& spec, Span deco_span) {
        auto src = expect(TokenType::Ident);
        if (!src) return core::make_unexpected(src.error());
        const Str kName = src.value()->text;
        if (kName.eq({"ip", 2})) {
            if (!spec.add(RateLimitKeyKind::Ip, nullptr, 0))
                return frontend_error(FrontendError::UnsupportedSyntax, deco_span, kName);
            return true;
        }
        RateLimitKeyKind kind;
        if (kName.eq({"header", 6}))
            kind = RateLimitKeyKind::Header;
        else if (kName.eq({"query", 5}))
            kind = RateLimitKeyKind::Query;
        else if (kName.eq({"cookie", 6}))
            kind = RateLimitKeyKind::Cookie;
        else if (kName.eq({"param", 5}))
            kind = RateLimitKeyKind::Param;
        else
            return frontend_error(FrontendError::UnsupportedSyntax, span_from(*src.value()), kName);
        if (!expect(TokenType::LParen))
            return frontend_error(FrontendError::UnexpectedToken, deco_span, kName);
        auto arg = expect(TokenType::StringLit);
        if (!arg) return core::make_unexpected(arg.error());
        if (!expect(TokenType::RParen))
            return frontend_error(FrontendError::UnexpectedToken, deco_span, kName);
        if (!spec.add(kind, arg.value()->text.ptr, arg.value()->text.len))
            return frontend_error(FrontendError::UnsupportedSyntax, deco_span, kName);
        return true;
    }

    FrontendResult<AstDecorator> parse_official_decorator() {
        auto at = expect(TokenType::At);
        if (!at) return core::make_unexpected(at.error());
        auto name_tok = expect(TokenType::Ident);
        if (!name_tok) return core::make_unexpected(name_tok.error());
        AstDecorator deco{};
        deco.name = name_tok.value()->text;
        deco.span =
            Span{at.value()->start, name_tok.value()->end, at.value()->line, at.value()->col};

        if (deco.name.eq({"rateLimit", 9})) {
            // @rateLimit(limit: <IntLit>, window: <DurLit>)
            if (!expect(TokenType::LParen))
                return frontend_error(FrontendError::UnexpectedToken, deco.span, deco.name);
            auto kw = expect(TokenType::Ident);
            if (!kw || !kw.value()->text.eq({"limit", 5}))
                return frontend_error(FrontendError::UnexpectedToken, deco.span, deco.name);
            if (!expect(TokenType::Colon))
                return frontend_error(FrontendError::UnexpectedToken, deco.span, deco.name);
            auto lim = expect(TokenType::IntLit);
            if (!lim) return core::make_unexpected(lim.error());
            u64 maxv = 0;
            for (u32 i = 0; i < lim.value()->text.len; i++) {
                maxv = maxv * 10 + static_cast<u64>(lim.value()->text.ptr[i] - '0');
                if (maxv > 0xffffffffull)
                    return frontend_error(
                        FrontendError::InvalidInteger, deco.span, lim.value()->text);
            }
            if (!expect(TokenType::Comma))
                return frontend_error(FrontendError::UnexpectedToken, deco.span, deco.name);
            auto win_kw = expect(TokenType::Ident);
            if (!win_kw || !win_kw.value()->text.eq({"window", 6}))
                return frontend_error(FrontendError::UnexpectedToken, deco.span, deco.name);
            if (!expect(TokenType::Colon))
                return frontend_error(FrontendError::UnexpectedToken, deco.span, deco.name);
            auto dur = expect(TokenType::DurLit);
            if (!dur) return core::make_unexpected(dur.error());
            const u32 kWin = dur_lit_to_seconds(dur.value()->text);
            if (kWin == 0 || maxv == 0)
                return frontend_error(
                    FrontendError::UnsupportedSyntax, deco.span, dur.value()->text);
            // Optional trailing named args, in any order:
            //   by: <key>     — single source or [list]; `ip` or
            //                    header/query/cookie/param("name"). Default per-IP.
            //   scope: shard|global — enforcement scope. Default shard.
            while (take(TokenType::Comma)) {
                auto arg = expect(TokenType::Ident);
                if (!arg) return core::make_unexpected(arg.error());
                if (!expect(TokenType::Colon))
                    return frontend_error(FrontendError::UnexpectedToken, deco.span, deco.name);
                if (arg.value()->text.eq({"by", 2})) {
                    if (take(TokenType::LBracket)) {
                        bool first = true;
                        while (cur().type != TokenType::RBracket) {
                            if (!first && !take(TokenType::Comma))
                                return frontend_error(
                                    FrontendError::UnexpectedToken, deco.span, deco.name);
                            first = false;
                            auto s = parse_rate_limit_source(deco.rate_limit_key, deco.span);
                            if (!s) return core::make_unexpected(s.error());
                        }
                        if (!expect(TokenType::RBracket))
                            return frontend_error(
                                FrontendError::UnexpectedToken, deco.span, deco.name);
                    } else {
                        auto s = parse_rate_limit_source(deco.rate_limit_key, deco.span);
                        if (!s) return core::make_unexpected(s.error());
                    }
                } else if (arg.value()->text.eq({"scope", 5})) {
                    auto sv = expect(TokenType::Ident);
                    if (!sv) return core::make_unexpected(sv.error());
                    if (sv.value()->text.eq({"shard", 5}))
                        deco.rate_limit_scope = RateLimitScope::Shard;
                    else if (sv.value()->text.eq({"global", 6}))
                        deco.rate_limit_scope = RateLimitScope::Global;
                    else
                        return frontend_error(
                            FrontendError::UnsupportedSyntax, deco.span, sv.value()->text);
                } else if (arg.value()->text.eq({"burst", 5})) {
                    auto bv = expect(TokenType::IntLit);
                    if (!bv) return core::make_unexpected(bv.error());
                    u64 b = 0;
                    for (u32 i = 0; i < bv.value()->text.len; i++) {
                        b = b * 10 + static_cast<u64>(bv.value()->text.ptr[i] - '0');
                        if (b > 0xffffffffull)
                            return frontend_error(
                                FrontendError::InvalidInteger, deco.span, bv.value()->text);
                    }
                    deco.rate_limit_burst = static_cast<u32>(b);
                } else {
                    return frontend_error(
                        FrontendError::UnsupportedSyntax, deco.span, arg.value()->text);
                }
            }
            if (!expect(TokenType::RParen))
                return frontend_error(FrontendError::UnexpectedToken, deco.span, deco.name);
            deco.rate_limit_max = static_cast<u32>(maxv);
            deco.rate_limit_window_sec = kWin;
            return deco;
        }

        if (deco.name.eq({"throttle", 8})) {
            // @throttle(downstream: <IntLit><b|kb|mb|gb>, window: <DurLit>)
            if (!expect(TokenType::LParen))
                return frontend_error(FrontendError::UnexpectedToken, deco.span, deco.name);
            // `downstream` is a reserved keyword (KwDownstream), not an Ident.
            if (!expect(TokenType::KwDownstream))
                return frontend_error(FrontendError::UnsupportedSyntax, deco.span, deco.name);
            if (!expect(TokenType::Colon))
                return frontend_error(FrontendError::UnexpectedToken, deco.span, deco.name);
            auto num = expect(TokenType::IntLit);
            if (!num) return core::make_unexpected(num.error());
            u64 amount = 0;
            for (u32 i = 0; i < num.value()->text.len; i++) {
                amount = amount * 10 + static_cast<u64>(num.value()->text.ptr[i] - '0');
                if (amount > 0xffffffffull)
                    return frontend_error(
                        FrontendError::InvalidInteger, deco.span, num.value()->text);
            }
            // ByteSize unit — a separate identifier token (e.g. "5mb" lexes as
            // IntLit "5" + Ident "mb"; the duration lexer doesn't claim it).
            auto unit = expect(TokenType::Ident);
            if (!unit) return core::make_unexpected(unit.error());
            u64 mult = 0;
            const Str kUnit2 = unit.value()->text;
            if (kUnit2.eq({"b", 1}))
                mult = 1;
            else if (kUnit2.eq({"kb", 2}))
                mult = 1024;
            else if (kUnit2.eq({"mb", 2}))
                mult = 1024ull * 1024;
            else if (kUnit2.eq({"gb", 2}))
                mult = 1024ull * 1024 * 1024;
            else
                return frontend_error(FrontendError::UnsupportedSyntax, deco.span, kUnit2);
            const u64 kBytes = amount * mult;
            if (!expect(TokenType::Comma))
                return frontend_error(FrontendError::UnexpectedToken, deco.span, deco.name);
            auto win_kw = expect(TokenType::Ident);
            if (!win_kw || !win_kw.value()->text.eq({"window", 6}))
                return frontend_error(FrontendError::UnexpectedToken, deco.span, deco.name);
            if (!expect(TokenType::Colon))
                return frontend_error(FrontendError::UnexpectedToken, deco.span, deco.name);
            auto dur = expect(TokenType::DurLit);
            if (!dur) return core::make_unexpected(dur.error());
            const u32 kWin = dur_lit_to_seconds(dur.value()->text);
            if (kWin == 0)
                return frontend_error(
                    FrontendError::UnsupportedSyntax, deco.span, dur.value()->text);
            if (!expect(TokenType::RParen))
                return frontend_error(FrontendError::UnexpectedToken, deco.span, deco.name);
            const u64 kBps = kBytes / kWin;
            if (kBps == 0 || kBps > 0xffffffffull)
                return frontend_error(FrontendError::UnsupportedSyntax, deco.span, deco.name);
            deco.throttle_down_bps = static_cast<u32>(kBps);
            return deco;
        }
        // Unknown decorator name — only the official whitelist is allowed.
        return frontend_error(FrontendError::UnsupportedSyntax, deco.span, deco.name);
    }

    bool is_use_chain_start() const {
        return cur().type == TokenType::Ident && cur().text.eq({"use", 3}) &&
               peek().type == TokenType::Ident && peek().text.eq({"chain", 5}) &&
               peek(2).type == TokenType::Ident;
    }

    bool is_chain_decl_start() const {
        return cur().type == TokenType::Ident && cur().text.eq({"chain", 5}) &&
               peek().type == TokenType::Ident && peek(2).type == TokenType::LBrace;
    }

    FrontendResult<AstChainUse> parse_use_chain() {
        auto use = expect(TokenType::Ident);
        if (!use) return core::make_unexpected(use.error());
        if (!use.value()->text.eq({"use", 3})) {
            return frontend_error(FrontendError::UnexpectedToken, span_from(*use.value()));
        }
        auto chain = expect(TokenType::Ident);
        if (!chain) return core::make_unexpected(chain.error());
        if (!chain.value()->text.eq({"chain", 5})) {
            return frontend_error(FrontendError::UnexpectedToken, span_from(*chain.value()));
        }
        auto name = expect(TokenType::Ident);
        if (!name) return core::make_unexpected(name.error());
        AstChainUse chain_use{};
        chain_use.name = name.value()->text;
        chain_use.span =
            Span{use.value()->start, name.value()->end, use.value()->line, use.value()->col};
        return chain_use;
    }

    FrontendResult<AstItem> parse_chain() {
        auto kw = expect(TokenType::Ident);
        if (!kw) return core::make_unexpected(kw.error());
        if (!kw.value()->text.eq({"chain", 5}))
            return frontend_error(FrontendError::UnexpectedToken, span_from(*kw.value()));
        auto name = expect(TokenType::Ident);
        if (!name) return core::make_unexpected(name.error());
        auto lbrace = expect(TokenType::LBrace);
        if (!lbrace) return core::make_unexpected(lbrace.error());

        AstItem item{};
        item.kind = AstItemKind::Chain;
        item.chain.name = name.value()->text;
        while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
            AstChainDecl::Step step{};
            const Token start = cur();
            if (cur().type == TokenType::Ident && cur().text.eq({"before", 6})) {
                pos++;
                step.kind = AstChainStepKind::Before;
            } else if (cur().type == TokenType::Ident && cur().text.eq({"after", 5})) {
                pos++;
                step.kind = AstChainStepKind::After;
            } else {
                return frontend_error(FrontendError::UnexpectedToken, span_from(cur()), cur().text);
            }
            auto call = parse_expr();
            if (!call) return core::make_unexpected(call.error());
            step.call = call.value();
            if (step.kind == AstChainStepKind::Before) {
                auto kw_else = expect(TokenType::KwElse);
                if (!kw_else) return core::make_unexpected(kw_else.error());
                auto status = expect(TokenType::IntLit);
                if (!status) return core::make_unexpected(status.error());
                u32 parsed_status = 0;
                for (u32 i = 0; i < status.value()->text.len; i++) {
                    const u32 digit = static_cast<u32>(status.value()->text.ptr[i] - '0');
                    if (parsed_status > (0xffffffffu - digit) / 10)
                        return frontend_error(FrontendError::InvalidInteger,
                                              span_from(*status.value()));
                    parsed_status = parsed_status * 10 + digit;
                }
                step.else_status = parsed_status;
                step.span = Span{start.start, status.value()->end, start.line, start.col};
            } else {
                step.span = Span{start.start, call->span.end, start.line, start.col};
            }
            if (!item.chain.steps.push(step))
                return frontend_error(FrontendError::TooManyItems, step.span);
        }
        auto rbrace = expect(TokenType::RBrace);
        if (!rbrace) return core::make_unexpected(rbrace.error());
        if (item.chain.steps.len == 0)
            return frontend_error(FrontendError::UnexpectedToken, span_from(*rbrace.value()));
        item.span = Span{kw.value()->start, rbrace.value()->end, kw.value()->line, kw.value()->col};
        item.chain.span = item.span;
        return item;
    }

    static bool binding_matches(Str pattern, bool is_wildcard, Str path) {
        if (is_wildcard) return true;
        if (path.len < pattern.len) return false;
        for (u32 i = 0; i < pattern.len; i++) {
            if (path.ptr[i] != pattern.ptr[i]) return false;
        }
        return true;
    }

    FrontendResult<AstItem> parse_route_entry(const Token& kw_route) {
        AstItem item{};
        item.kind = AstItemKind::Route;
        const Token* method = nullptr;
        if (!is_method_keyword(cur().type))
            return frontend_error(FrontendError::UnexpectedToken, span_from(cur()), cur().text);
        method = &toks->tokens[pos++];
        auto path = expect(TokenType::StringLit);
        if (!path) return core::make_unexpected(path.error());
        while (is_use_chain_start()) {
            auto chain_name = parse_use_chain();
            if (!chain_name) return core::make_unexpected(chain_name.error());
            if (!item.route.chains.push(chain_name.value()))
                return frontend_error(FrontendError::TooManyItems, span_from(cur()));
        }
        auto lbrace = expect(TokenType::LBrace);
        if (!lbrace) return core::make_unexpected(lbrace.error());
        while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
            auto stmt = parse_stmt();
            if (!stmt) return core::make_unexpected(stmt.error());
            auto stmt_ptr = alloc_stmt(stmt.value());
            if (!stmt_ptr) return core::make_unexpected(stmt_ptr.error());
            if (!item.route.statements.push(stmt_ptr.value()))
                return frontend_error(FrontendError::TooManyItems, stmt.value().span);
            if (stmt->kind != AstStmtKind::Let && stmt->kind != AstStmtKind::Guard &&
                stmt->kind != AstStmtKind::Wait && stmt->kind != AstStmtKind::For)
                break;
        }
        auto rbrace = expect(TokenType::RBrace);
        if (!rbrace) return core::make_unexpected(rbrace.error());
        if (item.route.statements.len == 0)
            return frontend_error(FrontendError::UnexpectedToken, span_from(*rbrace.value()));
        item.span = Span{kw_route.start, rbrace.value()->end, kw_route.line, kw_route.col};
        item.route.span = item.span;
        item.route.body_span = Span{
            lbrace.value()->start, rbrace.value()->end, lbrace.value()->line, lbrace.value()->col};
        item.route.method = static_cast<u8>(method->type);
        item.route.path = path.value()->text;
        return item;
    }

    FrontendResult<AstItem> parse_route() {
        auto kw = expect(TokenType::KwRoute);
        if (!kw) return core::make_unexpected(kw.error());
        return parse_route_entry(*kw.value());
    }

    // Convert a DurLit token ("5s", "100ms", "1m", "1h") to milliseconds. 0 = bad
    // unit / overflow. Unlike dur_lit_to_seconds this preserves sub-second values
    // for forward compatibility (slice 1 fires on the 1s tick regardless).
    static u32 dur_lit_to_ms(Str t) {
        u64 digits = 0;
        u32 i = 0;
        for (; i < t.len && t.ptr[i] >= '0' && t.ptr[i] <= '9'; i++) {
            digits = digits * 10 + static_cast<u64>(t.ptr[i] - '0');
            if (digits > 0xffffffffull) return 0;
        }
        const Str kUnit{t.ptr + i, t.len - i};
        u64 ms = 0;
        if (kUnit.eq({"ms", 2}))
            ms = digits;
        else if (kUnit.eq({"s", 1}))
            ms = digits * 1000ull;
        else if (kUnit.eq({"m", 1}))
            ms = digits * 60ull * 1000ull;
        else if (kUnit.eq({"h", 1}))
            ms = digits * 3600ull * 1000ull;
        else
            return 0;
        return ms > 0xffffffffull ? 0xffffffffu : static_cast<u32>(ms);
    }

    // `timer <name>, every: <duration> { <body> }` — a background periodic task.
    // (slice 1: the optional `shard: N` selector is not yet parsed.)
    FrontendResult<AstItem> parse_timer() {
        // `timer` is a contextual keyword (an Ident, not reserved). The top-level
        // dispatch only routes here when cur() is the `timer` identifier.
        auto kw = expect(TokenType::Ident);
        if (!kw) return core::make_unexpected(kw.error());
        const Token& kw_timer = *kw.value();
        AstItem item{};
        item.kind = AstItemKind::Timer;
        auto name = expect(TokenType::Ident);
        if (!name) return core::make_unexpected(name.error());
        if (!expect(TokenType::Comma))
            return frontend_error(FrontendError::UnexpectedToken, span_from(cur()), cur().text);
        auto every_kw = expect(TokenType::Ident);
        if (!every_kw || !every_kw.value()->text.eq({"every", 5}))
            return frontend_error(FrontendError::UnexpectedToken, span_from(cur()), cur().text);
        if (!expect(TokenType::Colon))
            return frontend_error(FrontendError::UnexpectedToken, span_from(cur()), cur().text);
        auto dur = expect(TokenType::DurLit);
        if (!dur) return core::make_unexpected(dur.error());
        const u32 kInterval = dur_lit_to_ms(dur.value()->text);
        if (kInterval == 0)
            return frontend_error(
                FrontendError::UnsupportedSyntax, span_from(*dur.value()), dur.value()->text);
        auto lbrace = expect(TokenType::LBrace);
        if (!lbrace) return core::make_unexpected(lbrace.error());
        while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
            auto stmt = parse_stmt();
            if (!stmt) return core::make_unexpected(stmt.error());
            auto stmt_ptr = alloc_stmt(stmt.value());
            if (!stmt_ptr) return core::make_unexpected(stmt_ptr.error());
            if (!item.timer.statements.push(stmt_ptr.value()))
                return frontend_error(FrontendError::TooManyItems, span_from(cur()));
        }
        auto rbrace = expect(TokenType::RBrace);
        if (!rbrace) return core::make_unexpected(rbrace.error());
        item.span = Span{kw_timer.start, rbrace.value()->end, kw_timer.line, kw_timer.col};
        item.timer.span = item.span;
        item.timer.body_span = Span{
            lbrace.value()->start, rbrace.value()->end, lbrace.value()->line, lbrace.value()->col};
        item.timer.name = name.value()->text;
        item.timer.interval_ms = kInterval;
        return item;
    }

    // Block form: route { @binding "pattern"...  @entry-decorator method "path" { stmts } ... }
    // Pushes one AstItem::Route per entry into file->items; bindings are matched against entry
    // paths and merged into each entry's `decorators` list at parse time.
    FrontendResult<u32> parse_route_block() {
        auto kw = expect(TokenType::KwRoute);
        if (!kw) return core::make_unexpected(kw.error());
        auto lbrace = expect(TokenType::LBrace);
        if (!lbrace) return core::make_unexpected(lbrace.error());

        struct PendingBinding {
            AstDecorator decorator{};
            Str pattern{};
            bool is_wildcard = false;
        };
        static constexpr u32 kMaxBindings = AstRouteDecl::kMaxDecorators;
        FixedVec<PendingBinding, kMaxBindings> bindings;
        FixedVec<AstChainUse, AstRouteDecl::kMaxChains> group_chains;

        // Phase 1: route-block bindings. Decorator bindings use
        // `@ident "pattern"`; core chains use `use chain name` and apply to
        // every entry in the block.
        bool parsing_bindings = true;
        while (parsing_bindings) {
            if (cur().type == TokenType::At && peek().type == TokenType::Ident &&
                peek(2).type == TokenType::StringLit) {
                auto deco = parse_decorator_atom();
                if (!deco) return core::make_unexpected(deco.error());
                auto pat = expect(TokenType::StringLit);
                if (!pat) return core::make_unexpected(pat.error());
                PendingBinding pb{};
                pb.decorator = deco.value();
                pb.pattern = pat.value()->text;
                pb.is_wildcard = pb.pattern.len == 1 && pb.pattern.ptr[0] == '*';
                if (!bindings.push(pb))
                    return frontend_error(FrontendError::TooManyItems, deco->span);
                continue;
            }
            if (is_use_chain_start()) {
                auto chain_name = parse_use_chain();
                if (!chain_name) return core::make_unexpected(chain_name.error());
                if (!group_chains.push(chain_name.value()))
                    return frontend_error(FrontendError::TooManyItems, span_from(cur()));
                continue;
            }
            parsing_bindings = false;
        }

        // Phase 2: entries (with optional entry-prefix decorators).
        u32 emitted = 0;
        while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
            FixedVec<AstDecorator, AstRouteDecl::kMaxDecorators> entry_decorators;
            while (cur().type == TokenType::At) {
                auto deco = parse_decorator_atom();
                if (!deco) return core::make_unexpected(deco.error());
                if (!entry_decorators.push(deco.value()))
                    return frontend_error(FrontendError::TooManyItems, deco->span);
            }
            auto entry = parse_route_entry(*kw.value());
            if (!entry) return core::make_unexpected(entry.error());
            FixedVec<AstChainUse, AstRouteDecl::kMaxChains> entry_chains = entry->route.chains;
            entry->route.chains.len = 0;
            for (u32 i = 0; i < group_chains.len; i++) {
                if (!entry->route.chains.push(group_chains[i]))
                    return frontend_error(FrontendError::TooManyItems, entry->span);
            }
            for (u32 i = 0; i < entry_chains.len; i++) {
                if (!entry->route.chains.push(entry_chains[i]))
                    return frontend_error(FrontendError::TooManyItems, entry->span);
            }
            for (u32 i = 0; i < bindings.len; i++) {
                if (binding_matches(
                        bindings[i].pattern, bindings[i].is_wildcard, entry->route.path)) {
                    if (!entry->route.decorators.push(bindings[i].decorator))
                        return frontend_error(FrontendError::TooManyItems,
                                              bindings[i].decorator.span);
                }
            }
            for (u32 i = 0; i < entry_decorators.len; i++) {
                if (!entry->route.decorators.push(entry_decorators[i]))
                    return frontend_error(FrontendError::TooManyItems, entry_decorators[i].span);
            }
            if (!file->items.push(entry.value()))
                return frontend_error(FrontendError::TooManyItems, entry->span);
            emitted++;
        }
        auto rbrace = expect(TokenType::RBrace);
        if (!rbrace) return core::make_unexpected(rbrace.error());
        if (emitted == 0)
            return frontend_error(FrontendError::UnexpectedToken, span_from(*rbrace.value()));
        return emitted;
    }
};

}  // namespace

FrontendResult<AstFile*> parse_file(const LexedTokens& tokens) {
    auto file = std::make_unique<AstFile>();
    Parser p{};
    p.toks = &tokens;
    p.file = file.get();
    if (p.cur().type == TokenType::KwPackage) {
        auto kw = p.expect(TokenType::KwPackage);
        if (!kw) return core::make_unexpected(kw.error());
        auto name = p.expect(TokenType::Ident);
        if (!name) return core::make_unexpected(name.error());
        file->has_package_decl = true;
        file->package_name = name.value()->text;
        file->package_span =
            Span{kw.value()->start, name.value()->end, kw.value()->line, kw.value()->col};
    }
    while (p.cur().type != TokenType::Eof) {
        FrontendResult<AstItem> item = frontend_error(
            FrontendError::UnexpectedToken, Parser::span_from(p.cur()), p.cur().text);
        switch (p.cur().type) {
            case TokenType::KwUpstream:
                item = p.parse_upstream();
                break;
            case TokenType::KwFunc:
                item = p.parse_func();
                break;
            case TokenType::KwStruct:
                item = p.parse_struct();
                break;
            case TokenType::KwProtocol:
                item = p.parse_protocol();
                break;
            case TokenType::KwImport:
                item = p.parse_import();
                break;
            case TokenType::KwUsing:
                item = p.parse_using();
                break;
            case TokenType::KwVariant:
                item = p.parse_variant();
                break;
            case TokenType::KwRoute:
                if (p.peek().type == TokenType::LBrace) {
                    auto block = p.parse_route_block();
                    if (!block) return core::make_unexpected(block.error());
                    continue;
                }
                item = p.parse_route();
                break;
            case TokenType::At: {
                // Official decorators prefixing a single route:
                //   @rateLimit(limit: N per 1m)
                //   route GET "/path" { ... }
                FixedVec<AstDecorator, AstRouteDecl::kMaxDecorators> decos;
                while (p.cur().type == TokenType::At) {
                    auto d = p.parse_official_decorator();
                    if (!d) return core::make_unexpected(d.error());
                    if (!decos.push(d.value()))
                        return frontend_error(FrontendError::TooManyItems, d.value().span);
                }
                if (p.cur().type != TokenType::KwRoute || p.peek().type == TokenType::LBrace)
                    return frontend_error(
                        FrontendError::UnsupportedSyntax, Parser::span_from(p.cur()), p.cur().text);
                auto r = p.parse_route();
                if (!r) return core::make_unexpected(r.error());
                AstItem route_item = r.value();
                for (u32 k = 0; k < decos.len; k++) {
                    if (!route_item.route.decorators.push(decos[k]))
                        return frontend_error(FrontendError::TooManyItems, decos[k].span);
                }
                item = route_item;
                break;
            }
            default:
                if (p.is_chain_decl_start()) {
                    item = p.parse_chain();
                    break;
                }
                if (p.cur().type == TokenType::Ident && p.cur().text.eq({"type", 4})) {
                    item = p.parse_type_alias();
                    break;
                }
                // `timer <name>, every: ...` — contextual top-level declaration.
                // peek == Ident (the timer name) disambiguates from a bare `timer`
                // identifier used elsewhere.
                if (p.cur().type == TokenType::Ident && p.cur().text.eq({"timer", 5}) &&
                    p.peek().type == TokenType::Ident) {
                    item = p.parse_timer();
                    break;
                }
                if (p.cur().type == TokenType::Ident || p.cur().type == TokenType::LParen) {
                    item = p.parse_impl();
                    break;
                }
                if (p.cur().type == TokenType::Eof)
                    return frontend_error(FrontendError::UnexpectedEof, Parser::span_from(p.cur()));
                return frontend_error(
                    FrontendError::UnexpectedToken, Parser::span_from(p.cur()), p.cur().text);
        }
        if (!item) return core::make_unexpected(item.error());
        if (!file->items.push(item.value()))
            return frontend_error(FrontendError::TooManyItems, item.value().span);
    }
    return file.release();
}

}  // namespace rut
