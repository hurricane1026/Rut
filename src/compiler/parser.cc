#include "rut/compiler/parser.h"

#include "rut/common/http_header_validation.h"
#include "rut/runtime/http_parser.h"
#include <memory>

namespace rut {

namespace {

constexpr Str kGuardMatchArmIfDetail = lit_str("guard match arms do not support if guards");
constexpr Str kEmptyBlockDetail = lit_str("empty block is not supported");

struct Parser {
    const LexedTokens* toks = nullptr;
    AstFile* file = nullptr;
    u32 pos = 0;

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
        while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
            auto inner = parse_stmt();
            if (!inner) return core::make_unexpected(inner.error());
            auto inner_ptr = alloc_stmt(inner.value());
            if (!inner_ptr) return core::make_unexpected(inner_ptr.error());
            if (!block.block_stmts.push(inner_ptr.value()))
                return frontend_error(FrontendError::TooManyItems, inner->span);
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

    FrontendResult<AstStatement> parse_func_guard_stmt(const Token& guard_tok) {
        AstStatement stmt{};
        stmt.kind = AstStmtKind::Guard;
        const bool is_match_guard = take(TokenType::KwMatch) != nullptr;
        if (!is_match_guard && take(TokenType::KwLet)) {
            auto name = expect(TokenType::Ident);
            if (!name) return core::make_unexpected(name.error());
            auto eq = expect(TokenType::Eq);
            if (!eq) return core::make_unexpected(eq.error());
            stmt.name = name.value()->text;
            stmt.bind_value = true;
        }
        auto cond = parse_expr();
        if (!cond) return core::make_unexpected(cond.error());
        stmt.expr = cond.value();
        auto kw_else = expect(TokenType::KwElse);
        if (!kw_else) return core::make_unexpected(kw_else.error());
        auto lbrace = expect(TokenType::LBrace);
        if (!lbrace) return core::make_unexpected(lbrace.error());
        if (is_match_guard) {
            while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
                auto kw_case = expect(TokenType::KwCase);
                if (!kw_case) return core::make_unexpected(kw_case.error());
                AstStatement::MatchArm arm{};
                arm.span = span_from(*kw_case.value());
                if (take(TokenType::Underscore)) {
                    arm.is_wildcard = true;
                } else {
                    auto pattern = parse_primary_expr();
                    if (!pattern) return core::make_unexpected(pattern.error());
                    arm.pattern = pattern.value();
                }
                if (const Token* kw_if = take(TokenType::KwIf))
                    return frontend_error(FrontendError::UnsupportedSyntax,
                                          span_from(*kw_if),
                                          kGuardMatchArmIfDetail);
                auto arrow = expect(TokenType::Arrow);
                if (!arrow) return core::make_unexpected(arrow.error());
                auto arm_stmt = parse_func_body_stmt();
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
        if (take(TokenType::KwOr)) {
            auto lparen = expect(TokenType::LParen);
            if (!lparen) return core::make_unexpected(lparen.error());
            auto lhs = parse_expr();
            if (!lhs) return core::make_unexpected(lhs.error());
            auto comma = expect(TokenType::Comma);
            if (!comma) return core::make_unexpected(comma.error());
            auto rhs = parse_expr();
            if (!rhs) return core::make_unexpected(rhs.error());
            auto rparen = expect(TokenType::RParen);
            if (!rparen) return core::make_unexpected(rparen.error());
            auto lhs_ptr = alloc_expr(lhs.value());
            if (!lhs_ptr) return core::make_unexpected(lhs_ptr.error());
            auto rhs_ptr = alloc_expr(rhs.value());
            if (!rhs_ptr) return core::make_unexpected(rhs_ptr.error());
            expr.kind = AstExprKind::Or;
            expr.lhs = lhs_ptr.value();
            expr.rhs = rhs_ptr.value();
            expr.span = Span{start.start, rparen.value()->end, start.line, start.col};
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
            if (!take(TokenType::Dot)) break;
            const Token* field_name = nullptr;
            if (cur().type == TokenType::Ident || cur().type == TokenType::KwFunc) {
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

    FrontendResult<AstExpr> parse_eq_expr() {
        auto lhs = parse_primary_expr();
        if (!lhs) return core::make_unexpected(lhs.error());
        TokenType op = TokenType::Error;
        if (take(TokenType::EqEq))
            op = TokenType::EqEq;
        else if (take(TokenType::Lt))
            op = TokenType::Lt;
        else if (take(TokenType::Gt))
            op = TokenType::Gt;
        else
            return lhs.value();
        auto rhs = parse_primary_expr();
        if (!rhs) return core::make_unexpected(rhs.error());
        auto lhs_ptr = alloc_expr(lhs.value());
        if (!lhs_ptr) return core::make_unexpected(lhs_ptr.error());
        auto rhs_ptr = alloc_expr(rhs.value());
        if (!rhs_ptr) return core::make_unexpected(rhs_ptr.error());
        AstExpr expr{};
        expr.kind = op == TokenType::EqEq
                        ? AstExprKind::Eq
                        : (op == TokenType::Lt ? AstExprKind::Lt : AstExprKind::Gt);
        expr.lhs = lhs_ptr.value();
        expr.rhs = rhs_ptr.value();
        expr.span = Span{lhs->span.start, rhs->span.end, lhs->span.line, lhs->span.col};
        return expr;
    }

    FrontendResult<AstExpr> parse_expr() {
        auto lhs = parse_eq_expr();
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
            while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
                auto inner = parse_stmt();
                if (!inner) return core::make_unexpected(inner.error());
                auto inner_ptr = alloc_stmt(inner.value());
                if (!inner_ptr) return core::make_unexpected(inner_ptr.error());
                if (!stmt.block_stmts.push(inner_ptr.value()))
                    return frontend_error(FrontendError::TooManyItems, inner->span);
            }
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
            if (!is_match_guard && take(TokenType::KwLet)) {
                auto name = expect(TokenType::Ident);
                if (!name) return core::make_unexpected(name.error());
                auto eq = expect(TokenType::Eq);
                if (!eq) return core::make_unexpected(eq.error());
                bind_name = name.value()->text;
                bind_value = true;
            }
            auto cond = parse_expr();
            if (!cond) return core::make_unexpected(cond.error());
            auto kw_else = expect(TokenType::KwElse);
            if (!kw_else) return core::make_unexpected(kw_else.error());
            auto lbrace = expect(TokenType::LBrace);
            if (!lbrace) return core::make_unexpected(lbrace.error());
            AstStatement stmt{};
            stmt.kind = AstStmtKind::Guard;
            stmt.name = bind_name;
            stmt.bind_value = bind_value;
            stmt.expr = cond.value();
            if (is_match_guard) {
                while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
                    auto kw_case = expect(TokenType::KwCase);
                    if (!kw_case) return core::make_unexpected(kw_case.error());
                    AstStatement::MatchArm arm{};
                    arm.span = span_from(*kw_case.value());
                    if (take(TokenType::Underscore)) {
                        arm.is_wildcard = true;
                    } else {
                        auto pattern = parse_primary_expr();
                        if (!pattern) return core::make_unexpected(pattern.error());
                        arm.pattern = pattern.value();
                    }
                    if (const Token* kw_if = take(TokenType::KwIf))
                        return frontend_error(FrontendError::UnsupportedSyntax,
                                              span_from(*kw_if),
                                              kGuardMatchArmIfDetail);
                    auto colon = expect(TokenType::Colon);
                    if (!colon) return core::make_unexpected(colon.error());
                    auto arm_stmt = parse_stmt();
                    if (!arm_stmt) return core::make_unexpected(arm_stmt.error());
                    if (arm_stmt->kind != AstStmtKind::ReturnStatus &&
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
                auto rparen = expect(TokenType::RParen);
                if (!rparen) return core::make_unexpected(rparen.error());
                stmt.kind = AstStmtKind::ForwardUpstream;
                stmt.name = name.value()->text;
                stmt.span = Span{start.start, rparen.value()->end, start.line, start.col};
                return stmt;
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
                    auto event = parse_expr();
                    if (!event) return core::make_unexpected(event.error());
                    arm.pattern = event.value();
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
            stmt.expr = cond.value();
            stmt.then_stmt = then_ptr.value();
            stmt.else_stmt = else_ptr.value();
            stmt.span = Span{start.start, else_stmt->span.end, start.line, start.col};
            return stmt;
        }
        const bool is_inline_for = cur().type == TokenType::Ident && cur().text.eq({"inline", 6}) &&
                                   peek().type == TokenType::KwFor;
        if (is_inline_for || cur().type == TokenType::KwFor) {
            const bool is_inline = is_inline_for;
            if (is_inline) pos++;
            if (auto for_kw = expect(TokenType::KwFor); !for_kw)
                return core::make_unexpected(for_kw.error());
            auto var_name = expect(TokenType::Ident);
            if (!var_name) return core::make_unexpected(var_name.error());
            auto in_kw = take(TokenType::KwIn);
            if (!in_kw)
                return frontend_error(FrontendError::UnsupportedSyntax,
                                      span_from(*var_name.value()),
                                      lit_str("for loop expects 'in' after iterator name"));
            auto iter_expr = parse_expr();
            if (!iter_expr) return core::make_unexpected(iter_expr.error());
            auto lbrace = expect(TokenType::LBrace);
            if (!lbrace) return core::make_unexpected(lbrace.error());
            auto body = parse_braced_stmt_body(*lbrace.value());
            if (!body) return core::make_unexpected(body.error());
            auto body_ptr = alloc_stmt(body.value());
            if (!body_ptr) return core::make_unexpected(body_ptr.error());
            AstStatement stmt{};
            stmt.kind = AstStmtKind::For;
            // Keep the spelling for source fidelity; static unroll decisions
            // are made later from the analyzed iterator/body shape.
            stmt.is_inline = is_inline;
            stmt.name = var_name.value()->text;
            stmt.expr = iter_expr.value();
            stmt.then_stmt = body_ptr.value();
            stmt.span = Span{start.start, body->span.end, start.line, start.col};
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
                auto kw_case = expect(TokenType::KwCase);
                if (!kw_case) return core::make_unexpected(kw_case.error());
                AstStatement::MatchArm arm{};
                arm.span = span_from(*kw_case.value());
                if (take(TokenType::Underscore)) {
                    arm.is_wildcard = true;
                } else {
                    auto pattern = parse_primary_expr();
                    if (!pattern) return core::make_unexpected(pattern.error());
                    arm.pattern = pattern.value();
                }
                if (take(TokenType::KwIf)) {
                    auto guard = parse_expr();
                    if (!guard) return core::make_unexpected(guard.error());
                    auto guard_ptr = alloc_expr(guard.value());
                    if (!guard_ptr) return core::make_unexpected(guard_ptr.error());
                    arm.has_guard = true;
                    arm.guard = guard_ptr.value();
                }
                auto colon = expect(TokenType::Colon);
                if (!colon) return core::make_unexpected(colon.error());
                auto arm_stmt = parse_stmt();
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
            item.upstream.has_address = true;
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
                } else {
                    return frontend_error(
                        FrontendError::UnexpectedToken, span_from(*field.value()), field_name);
                }
                if (!take(TokenType::Comma)) break;
                if (cur().type == TokenType::RBrace) break;  // trailing comma
            }
            auto rbrace = expect(TokenType::RBrace);
            if (!rbrace) return core::make_unexpected(rbrace.error());
            if (!seen_host || !seen_port) {
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
        }
        item.span = Span{kw.value()->start, end_off, kw.value()->line, kw.value()->col};
        item.upstream.span = item.span;
        return item;
    }

    FrontendResult<AstStatement> parse_func_body_stmt() {
        if (take(TokenType::KwGuard)) {
            return parse_func_guard_stmt(prev());
        }
        if (take(TokenType::KwIf)) {
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
                auto kw_case = expect(TokenType::KwCase);
                if (!kw_case) return core::make_unexpected(kw_case.error());
                AstStatement::MatchArm arm{};
                arm.span = span_from(*kw_case.value());
                if (take(TokenType::Underscore)) {
                    arm.is_wildcard = true;
                } else {
                    auto pattern = parse_primary_expr();
                    if (!pattern) return core::make_unexpected(pattern.error());
                    arm.pattern = pattern.value();
                }
                if (take(TokenType::KwIf)) {
                    auto guard = parse_expr();
                    if (!guard) return core::make_unexpected(guard.error());
                    auto guard_ptr = alloc_expr(guard.value());
                    if (!guard_ptr) return core::make_unexpected(guard_ptr.error());
                    arm.has_guard = true;
                    arm.guard = guard_ptr.value();
                }
                auto arrow = expect(TokenType::Arrow);
                if (!arrow) return core::make_unexpected(arrow.error());
                auto arm_stmt = parse_func_body_stmt();
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

        AstItem item{};
        item.kind = AstItemKind::Func;
        item.func.name = name.value()->text;
        item.func.span = span_from(*kw.value());

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
                if (!item.func.type_params.push(decl))
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
                if (!item.func.params.push(param))
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
            item.func.has_return_type = true;
            item.func.return_type = ret_type.value();
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
                for (u32 ti = 0; ti < item.func.type_params.len; ti++) {
                    if (item.func.type_params[ti].name.eq(type_param.value()->text)) {
                        target = &item.func.type_params[ti];
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

        item.func.body = body_ptr.value();
        item.span =
            Span{kw.value()->start, body_ptr.value()->span.end, kw.value()->line, kw.value()->col};
        item.func.span = item.span;
        return item;
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
            auto case_kw = expect(TokenType::KwCase);
            if (!case_kw) return core::make_unexpected(case_kw.error());
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
                return frontend_error(FrontendError::TooManyItems, span_from(*case_kw.value()));
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
        AstDecorator d{};
        d.name = name_tok.value()->text;
        d.span = Span{at.value()->start, name_tok.value()->end, at.value()->line, at.value()->col};
        return d;
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
        auto lbrace = expect(TokenType::LBrace);
        if (!lbrace) return core::make_unexpected(lbrace.error());
        while (cur().type != TokenType::RBrace && cur().type != TokenType::Eof) {
            auto stmt = parse_stmt();
            if (!stmt) return core::make_unexpected(stmt.error());
            if (!item.route.statements.push(stmt.value()))
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

        // Phase 1: bindings — `@ident "pattern"` while next-after-@ident is StringLit.
        while (cur().type == TokenType::At && peek().type == TokenType::Ident &&
               peek(2).type == TokenType::StringLit) {
            auto deco = parse_decorator_atom();
            if (!deco) return core::make_unexpected(deco.error());
            auto pat = expect(TokenType::StringLit);
            if (!pat) return core::make_unexpected(pat.error());
            PendingBinding pb{};
            pb.decorator = deco.value();
            pb.pattern = pat.value()->text;
            pb.is_wildcard = pb.pattern.len == 1 && pb.pattern.ptr[0] == '*';
            if (!bindings.push(pb)) return frontend_error(FrontendError::TooManyItems, deco->span);
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
            default:
                if (p.cur().type == TokenType::Ident && p.cur().text.eq({"type", 4})) {
                    item = p.parse_type_alias();
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
