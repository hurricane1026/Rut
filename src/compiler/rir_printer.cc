#include "rut/compiler/rir_printer.h"

#include <errno.h>
#include <unistd.h>

namespace rut {
namespace rir {

// ── PrintBuf implementation ─────────────────────────────────────────

void PrintBuf::flush() {
    // When fd < 0 (in-memory mode), don't discard buffered data.
    if (fd < 0) return;
    if (len == 0) return;
    u32 written = 0;
    while (written < len) {
        auto n = ::write(fd, data + written, len - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            // Hard error (EPIPE, EBADF, etc.) — mark overflow, drop buffer
            // to avoid unbounded retry loops.
            overflow = true;
            len = 0;
            return;
        }
        written += static_cast<u32>(n);
    }
    len = 0;
}

void PrintBuf::put(char c) {
    if (len >= cap) {
        if (fd < 0) {
            overflow = true;
            return;
        }
        flush();
        if (len >= cap) {
            overflow = true;
            return;
        }
    }
    data[len++] = c;
}

void PrintBuf::put_str(const char* s, u32 n) {
    for (u32 i = 0; i < n; i++) put(s[i]);
}

void PrintBuf::put_cstr(const char* s) {
    while (*s) put(*s++);
}

void PrintBuf::put_u32(u32 val) {
    if (val == 0) {
        put('0');
        return;
    }
    char tmp[10];
    i32 i = 0;
    while (val > 0) {
        tmp[i++] = static_cast<char>('0' + val % 10);
        val /= 10;
    }
    while (i > 0) put(tmp[--i]);
}

void PrintBuf::put_i32(i32 val) {
    if (val < 0) {
        put('-');
        // Handle INT_MIN safely.
        put_u32(static_cast<u32>(-(val + 1)) + 1);
    } else {
        put_u32(static_cast<u32>(val));
    }
}

void PrintBuf::put_i64(i64 val) {
    if (val < 0) {
        put('-');
        u64 abs = static_cast<u64>(-(val + 1)) + 1;
        // Recursively print u64.
        if (abs == 0) {
            put('0');
            return;
        }
        char tmp[20];
        i32 i = 0;
        while (abs > 0) {
            tmp[i++] = static_cast<char>('0' + abs % 10);
            abs /= 10;
        }
        while (i > 0) put(tmp[--i]);
    } else {
        u64 v = static_cast<u64>(val);
        if (v == 0) {
            put('0');
            return;
        }
        char tmp[20];
        i32 i = 0;
        while (v > 0) {
            tmp[i++] = static_cast<char>('0' + v % 10);
            v /= 10;
        }
        while (i > 0) put(tmp[--i]);
    }
}

void PrintBuf::indent(u32 level) {
    for (u32 i = 0; i < level * 2; i++) put(' ');
}

// ── Opcode names ────────────────────────────────────────────────────

void print_opcode(PrintBuf& buf, Opcode op) {
    switch (op) {
        case Opcode::ConstStr:
            buf.put_cstr("const.str");
            break;
        case Opcode::ConstI32:
            buf.put_cstr("const.i32");
            break;
        case Opcode::ConstI64:
            buf.put_cstr("const.i64");
            break;
        case Opcode::ConstBool:
            buf.put_cstr("const.bool");
            break;
        case Opcode::ConstDuration:
            buf.put_cstr("const.duration");
            break;
        case Opcode::ConstByteSize:
            buf.put_cstr("const.bytesize");
            break;
        case Opcode::ConstMethod:
            buf.put_cstr("const.method");
            break;
        case Opcode::ConstStatus:
            buf.put_cstr("const.status");
            break;
        case Opcode::ReqHeader:
            buf.put_cstr("req.header");
            break;
        case Opcode::ReqParam:
            buf.put_cstr("req.param");
            break;
        case Opcode::ReqQuery:
            buf.put_cstr("req.query");
            break;
        case Opcode::ReqQueryString:
            buf.put_cstr("req.queryString");
            break;
        case Opcode::ReqMethod:
            buf.put_cstr("req.method");
            break;
        case Opcode::ReqPath:
            buf.put_cstr("req.path");
            break;
        case Opcode::ReqPathOnly:
            buf.put_cstr("req.pathOnly");
            break;
        case Opcode::ReqBody:
            buf.put_cstr("req.body");
            break;
        case Opcode::ReqKeepAlive:
            buf.put_cstr("req.keepAlive");
            break;
        case Opcode::ReqChunked:
            buf.put_cstr("req.chunked");
            break;
        case Opcode::ReqHasContentLength:
            buf.put_cstr("req.hasContentLength");
            break;
        case Opcode::ReqHttp10:
            buf.put_cstr("req.http10");
            break;
        case Opcode::ReqHttp11:
            buf.put_cstr("req.http11");
            break;
        case Opcode::ReqHttpVersion:
            buf.put_cstr("req.httpVersion");
            break;
        case Opcode::ResumeEventKind:
            buf.put_cstr("resume.event_kind");
            break;
        case Opcode::ResumeEventResult:
            buf.put_cstr("resume.event_result");
            break;
        case Opcode::CtxLoadSlotI32:
            buf.put_cstr("ctx.load_slot_i32");
            break;
        case Opcode::ReqRemoteAddr:
            buf.put_cstr("req.remote_addr");
            break;
        case Opcode::ReqContentLength:
            buf.put_cstr("req.content_length");
            break;
        case Opcode::ReqCookie:
            buf.put_cstr("req.cookie");
            break;
        case Opcode::ReqSetHeader:
            buf.put_cstr("req.set_header");
            break;
        case Opcode::ReqAddHeader:
            buf.put_cstr("req.add_header");
            break;
        case Opcode::RespHeader:
            buf.put_cstr("resp.header");
            break;
        case Opcode::RespSetHeader:
            buf.put_cstr("resp.set_header");
            break;
        case Opcode::RespAddHeader:
            buf.put_cstr("resp.add_header");
            break;
        case Opcode::RespRemoveHeader:
            buf.put_cstr("resp.remove_header");
            break;
        case Opcode::RespCommitHeaders:
            buf.put_cstr("resp.commit_headers");
            break;
        case Opcode::ReqSetPath:
            buf.put_cstr("req.set_path");
            break;
        case Opcode::ReqSetTargetTransform:
            buf.put_cstr("req.set_target_transform");
            break;
        case Opcode::CtxStoreSlotI32:
            buf.put_cstr("ctx.store_slot_i32");
            break;
        case Opcode::StrHasPrefix:
            buf.put_cstr("str.has_prefix");
            break;
        case Opcode::StrTrimPrefix:
            buf.put_cstr("str.trim_prefix");
            break;
        case Opcode::StrRegexMatch:
            buf.put_cstr("str.regex_match");
            break;
        case Opcode::StrInterpolate:
            buf.put_cstr("str.interpolate");
            break;
        case Opcode::BitAnd:
            buf.put_cstr("bit.and");
            break;
        case Opcode::BitOr:
            buf.put_cstr("bit.or");
            break;
        case Opcode::BitXor:
            buf.put_cstr("bit.xor");
            break;
        case Opcode::Add:
            buf.put_cstr("arith.add");
            break;
        case Opcode::Sub:
            buf.put_cstr("arith.sub");
            break;
        case Opcode::Mul:
            buf.put_cstr("arith.mul");
            break;
        case Opcode::Div:
            buf.put_cstr("arith.div");
            break;
        case Opcode::Mod:
            buf.put_cstr("arith.mod");
            break;
        case Opcode::MaxInt:
            buf.put_cstr("arith.max");
            break;
        case Opcode::MinInt:
            buf.put_cstr("arith.min");
            break;
        case Opcode::SextI64:
            buf.put_cstr("sext.i64");
            break;
        case Opcode::BitShl:
            buf.put_cstr("bit.shl");
            break;
        case Opcode::BitShr:
            buf.put_cstr("bit.shr");
            break;
        case Opcode::CmpEq:
            buf.put_cstr("cmp.eq");
            break;
        case Opcode::CmpNe:
            buf.put_cstr("cmp.ne");
            break;
        case Opcode::CmpLt:
            buf.put_cstr("cmp.lt");
            break;
        case Opcode::CmpGt:
            buf.put_cstr("cmp.gt");
            break;
        case Opcode::CmpLe:
            buf.put_cstr("cmp.le");
            break;
        case Opcode::CmpGe:
            buf.put_cstr("cmp.ge");
            break;
        case Opcode::TimeNowMicros:
            buf.put_cstr("time.now_micros");
            break;
        case Opcode::IpInCidr:
            buf.put_cstr("ip.in_cidr");
            break;
        case Opcode::HashHmacSha256:
            buf.put_cstr("hash.hmac_sha256");
            break;
        case Opcode::BytesHex:
            buf.put_cstr("bytes.hex");
            break;
        case Opcode::CacheGet:
            buf.put_cstr("cache.get");
            break;
        case Opcode::CacheSet:
            buf.put_cstr("cache.set");
            break;
        case Opcode::StructField:
            buf.put_cstr("struct.field");
            break;
        case Opcode::StructCreate:
            buf.put_cstr("struct.create");
            break;
        case Opcode::BodyParse:
            buf.put_cstr("body.parse");
            break;
        case Opcode::OptNil:
            buf.put_cstr("opt.nil");
            break;
        case Opcode::OptWrap:
            buf.put_cstr("opt.wrap");
            break;
        case Opcode::ArrayLen:
            buf.put_cstr("array.len");
            break;
        case Opcode::ArrayGet:
            buf.put_cstr("array.get");
            break;
        case Opcode::OptIsNil:
            buf.put_cstr("opt.is_nil");
            break;
        case Opcode::OptUnwrap:
            buf.put_cstr("opt.unwrap");
            break;
        case Opcode::Select:
            buf.put_cstr("select");
            break;
        case Opcode::TraceFuncEnter:
            buf.put_cstr("trace.func_enter");
            break;
        case Opcode::TraceFuncExit:
            buf.put_cstr("trace.func_exit");
            break;
        case Opcode::TraceIoStart:
            buf.put_cstr("trace.io_start");
            break;
        case Opcode::TraceIoEnd:
            buf.put_cstr("trace.io_end");
            break;
        case Opcode::MetricHistRecord:
            buf.put_cstr("metric.histogram_record");
            break;
        case Opcode::MetricCounterIncr:
            buf.put_cstr("metric.counter_incr");
            break;
        case Opcode::AccessLogWrite:
            buf.put_cstr("accesslog.write");
            break;
        case Opcode::Br:
            buf.put_cstr("br");
            break;
        case Opcode::Jmp:
            buf.put_cstr("jmp");
            break;
        case Opcode::RetStatus:
            buf.put_cstr("ret.status");
            break;
        case Opcode::RetForward:
            buf.put_cstr("ret.forward");
            break;
        case Opcode::RetForwardBundle:
            buf.put_cstr("ret.forward_bundle");
            break;
        case Opcode::RetRedirect:
            buf.put_cstr("ret.redirect");
            break;
        case Opcode::YieldTimer:
            buf.put_cstr("yield.timer");
            break;
        case Opcode::YieldHttpGet:
            buf.put_cstr("yield.http_get");
            break;
        case Opcode::YieldHttpPost:
            buf.put_cstr("yield.http_post");
            break;
        case Opcode::YieldForward:
            buf.put_cstr("yield.forward");
            break;
    }
}

// ── Type printing ───────────────────────────────────────────────────

void print_type(PrintBuf& buf, const Type* type) {
    if (!type) {
        buf.put_cstr("void");
        return;
    }
    switch (type->kind) {
        case TypeKind::Void:
            buf.put_cstr("void");
            break;
        case TypeKind::Bool:
            buf.put_cstr("bool");
            break;
        case TypeKind::I32:
            buf.put_cstr("i32");
            break;
        case TypeKind::I64:
            buf.put_cstr("i64");
            break;
        case TypeKind::U32:
            buf.put_cstr("u32");
            break;
        case TypeKind::U64:
            buf.put_cstr("u64");
            break;
        case TypeKind::F64:
            buf.put_cstr("f64");
            break;
        case TypeKind::Str:
            buf.put_cstr("str");
            break;
        case TypeKind::ByteSize:
            buf.put_cstr("ByteSize");
            break;
        case TypeKind::Duration:
            buf.put_cstr("Duration");
            break;
        case TypeKind::Time:
            buf.put_cstr("Time");
            break;
        case TypeKind::IP:
            buf.put_cstr("IP");
            break;
        case TypeKind::CIDR:
            buf.put_cstr("CIDR");
            break;
        case TypeKind::MediaType:
            buf.put_cstr("MediaType");
            break;
        case TypeKind::StatusCode:
            buf.put_cstr("StatusCode");
            break;
        case TypeKind::Method:
            buf.put_cstr("Method");
            break;
        case TypeKind::Bytes:
            buf.put_cstr("Bytes");
            break;
        case TypeKind::Optional:
            buf.put_cstr("Optional(");
            print_type(buf, type->inner);
            buf.put(')');
            break;
        case TypeKind::Struct:
            buf.put_cstr("Struct(");
            if (type->struct_def) buf.put_str(type->struct_def->name);
            buf.put(')');
            break;
        case TypeKind::Array:
            buf.put_cstr("Array(");
            print_type(buf, type->inner);
            buf.put(')');
            break;
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

static void print_value_ref(PrintBuf& buf, ValueId vid) {
    buf.put('%');
    buf.put_u32(vid.id);
}

static void print_quoted_str(PrintBuf& buf, Str s) {
    buf.put('"');
    for (u32 i = 0; i < s.len; i++) {
        auto c = static_cast<unsigned char>(s.ptr[i]);
        switch (c) {
            case '\\':
                buf.put_cstr("\\\\");
                break;
            case '"':
                buf.put_cstr("\\\"");
                break;
            case '\n':
                buf.put_cstr("\\n");
                break;
            case '\t':
                buf.put_cstr("\\t");
                break;
            default:
                if (c >= 0x20 && c <= 0x7e) {
                    buf.put(static_cast<char>(c));
                } else {
                    const char hex[] = "0123456789ABCDEF";
                    buf.put('\\');
                    buf.put('x');
                    buf.put(hex[(c >> 4) & 0x0F]);
                    buf.put(hex[c & 0x0F]);
                }
                break;
        }
    }
    buf.put('"');
}

static void print_redirect_body(PrintBuf& buf, Str body) {
    buf.put_cstr("b\"");
    for (u32 i = 0; i < body.len; i++) {
        const u8 c = static_cast<u8>(body.ptr[i]);
        switch (c) {
            case '\\':
                buf.put_cstr("\\\\");
                break;
            case '"':
                buf.put_cstr("\\\"");
                break;
            case '\n':
                buf.put_cstr("\\n");
                break;
            case '\r':
                buf.put_cstr("\\r");
                break;
            case '\t':
                buf.put_cstr("\\t");
                break;
            default: {
                const char hex[] = "0123456789ABCDEF";
                if (c >= 0x20 && c <= 0x7e) {
                    buf.put(static_cast<char>(c));
                } else {
                    buf.put_cstr("\\x");
                    buf.put(hex[(c >> 4) & 0x0F]);
                    buf.put(hex[c & 0x0F]);
                }
                break;
            }
        }
    }
    buf.put_cstr("\" (len=");
    buf.put_u32(body.len);
    buf.put(')');
}

static void print_redirect_scheme(PrintBuf& buf, RedirectPolicyScheme value) {
    if (value == RedirectPolicyScheme::Http) buf.put_cstr("http");
    else buf.put_cstr("invalid");
}

static void print_redirect_authority(PrintBuf& buf, RedirectPolicyAuthority value) {
    if (value == RedirectPolicyAuthority::RequestHost) buf.put_cstr("request_host");
    else buf.put_cstr("invalid");
}

static void print_redirect_port(PrintBuf& buf, RedirectPolicyPort value) {
    if (value == RedirectPolicyPort::ActualListener) buf.put_cstr("actual_listener");
    else buf.put_cstr("invalid");
}

static void print_redirect_path(PrintBuf& buf, RedirectPolicyPath value) {
    if (value == RedirectPolicyPath::Static) buf.put_cstr("static");
    else buf.put_cstr("invalid");
}

static void print_redirect_query(PrintBuf& buf, RedirectPolicyQuery value) {
    if (value == RedirectPolicyQuery::PreserveRaw) buf.put_cstr("preserve_raw");
    else buf.put_cstr("invalid");
}

static void print_redirect_date(PrintBuf& buf, RedirectPolicyDate value) {
    if (value == RedirectPolicyDate::Current) buf.put_cstr("current");
    else buf.put_cstr("invalid");
}

static void print_redirect_connection(PrintBuf& buf, RedirectPolicyConnection value) {
    if (value == RedirectPolicyConnection::Close) buf.put_cstr("close");
    else buf.put_cstr("invalid");
}

static void print_block_ref(PrintBuf& buf, BlockId bid, const Function& fn) {
    if (bid.id < fn.block_count) {
        buf.put_str(fn.blocks[bid.id].label);
    } else {
        buf.put_cstr("block_?");
    }
}

static void print_source_loc(PrintBuf& buf, SourceLoc loc) {
    if (loc.line > 0) {
        buf.put_cstr("  // line ");
        buf.put_u32(loc.line);
    }
}

// ── Instruction printing ────────────────────────────────────────────

void print_instruction(PrintBuf& buf, const Instruction& inst, const Function& fn) {
    buf.indent(2);

    // Result assignment.
    if (inst.result != kNoValue) {
        print_value_ref(buf, inst.result);
        buf.put_cstr(" = ");
    }

    print_opcode(buf, inst.op);

    // Operands and immediates (opcode-specific formatting).
    switch (inst.op) {
        case Opcode::ConstStr:
            buf.put(' ');
            print_quoted_str(buf, inst.imm.str_val);
            break;
        case Opcode::ConstI32:
        case Opcode::ConstStatus:
            buf.put(' ');
            buf.put_i32(inst.imm.i32_val);
            break;
        case Opcode::ConstI64:
        case Opcode::ConstDuration:
        case Opcode::ConstByteSize:
            buf.put(' ');
            buf.put_i64(inst.imm.i64_val);
            break;
        case Opcode::ConstBool:
            buf.put(' ');
            buf.put_cstr(inst.imm.bool_val ? "true" : "false");
            break;
        case Opcode::ConstMethod:
            buf.put(' ');
            buf.put_u32(inst.imm.method_val);
            break;
        case Opcode::ReqHeader:
        case Opcode::ReqParam:
        case Opcode::ReqQuery:
        case Opcode::ReqCookie:
            buf.put(' ');
            print_quoted_str(buf, inst.imm.str_val);
            break;
        case Opcode::ReqMethod:
        case Opcode::ReqPath:
        case Opcode::ReqPathOnly:
        case Opcode::ReqBody:
        case Opcode::ReqQueryString:
        case Opcode::ReqHttpVersion:
        case Opcode::ResumeEventKind:
        case Opcode::ResumeEventResult:
        case Opcode::RespCommitHeaders:
            break;
        case Opcode::CtxLoadSlotI32:
            buf.put(' ');
            buf.put_i64(static_cast<i64>(inst.imm.i32_val));
            break;
        case Opcode::ReqRemoteAddr:
        case Opcode::ReqContentLength:
        case Opcode::TimeNowMicros:
            // No operands.
            break;
        case Opcode::ReqSetHeader:
        case Opcode::ReqAddHeader:
        case Opcode::RespHeader:
        case Opcode::RespSetHeader:
        case Opcode::RespAddHeader:
            buf.put(' ');
            print_quoted_str(buf, inst.imm.str_val);
            buf.put_cstr(", ");
            print_value_ref(buf, inst.operands[0]);
            break;
        case Opcode::RespRemoveHeader:
            buf.put(' ');
            print_quoted_str(buf, inst.imm.str_val);
            break;
        case Opcode::ReqSetPath:
        case Opcode::SextI64:
            buf.put(' ');
            print_value_ref(buf, inst.operands[0]);
            break;
        case Opcode::ReqSetTargetTransform:
            buf.put(' ');
            buf.put_i64(static_cast<i64>(inst.imm.i32_val));
            break;
        case Opcode::CtxStoreSlotI32:
            buf.put(' ');
            buf.put_i64(static_cast<i64>(inst.imm.i32_val));
            buf.put_cstr(", ");
            print_value_ref(buf, inst.operands[0]);
            break;
        case Opcode::StrHasPrefix:
        case Opcode::StrTrimPrefix:
        case Opcode::CmpEq:
        case Opcode::CmpNe:
        case Opcode::CmpLt:
        case Opcode::CmpGt:
        case Opcode::CmpLe:
        case Opcode::CmpGe:
        case Opcode::BitAnd:
        case Opcode::BitOr:
        case Opcode::BitXor:
        case Opcode::BitShl:
        case Opcode::BitShr:
        case Opcode::Add:
        case Opcode::Sub:
        case Opcode::Mul:
        case Opcode::Div:
        case Opcode::Mod:
        case Opcode::MaxInt:
        case Opcode::MinInt:
            // Binary: %a, %b
            buf.put(' ');
            print_value_ref(buf, inst.operands[0]);
            buf.put_cstr(", ");
            print_value_ref(buf, inst.operands[1]);
            break;
        case Opcode::StrRegexMatch:
            buf.put(' ');
            print_value_ref(buf, inst.operands[0]);
            buf.put_cstr(", ");
            print_quoted_str(buf, inst.imm.str_val);
            break;
        case Opcode::StrInterpolate:
            buf.put_cstr(" [");
            for (u32 i = 0; i < inst.operand_count; i++) {
                if (i > 0) buf.put_cstr(", ");
                print_value_ref(buf, inst.operand(i));
            }
            buf.put(']');
            break;
        case Opcode::IpInCidr:
            buf.put(' ');
            print_value_ref(buf, inst.operands[0]);
            buf.put_cstr(", ");
            print_quoted_str(buf, inst.imm.str_val);
            break;
        case Opcode::OptWrap:
        case Opcode::OptIsNil:
        case Opcode::OptUnwrap:
        case Opcode::BytesHex:
            buf.put(' ');
            print_value_ref(buf, inst.operands[0]);
            break;
        case Opcode::Select:
            buf.put(' ');
            print_value_ref(buf, inst.operands[0]);
            buf.put_cstr(", ");
            print_value_ref(buf, inst.operands[1]);
            buf.put_cstr(", ");
            print_value_ref(buf, inst.operands[2]);
            break;
        case Opcode::StructCreate:
            buf.put(' ');
            if (inst.imm.struct_ref.type && inst.imm.struct_ref.type->struct_def) {
                buf.put_str(inst.imm.struct_ref.type->struct_def->name);
            }
            if (inst.operand_count > 0) {
                buf.put_cstr(" { ");
                for (u32 i = 0; i < inst.operand_count; i++) {
                    if (i > 0) buf.put_cstr(", ");
                    print_value_ref(buf, inst.operand(i));
                }
                buf.put_cstr(" }");
            }
            break;
        case Opcode::StructField:
            buf.put(' ');
            print_value_ref(buf, inst.operands[0]);
            buf.put_cstr(", ");
            print_quoted_str(buf, inst.imm.struct_ref.name);
            break;
        case Opcode::BodyParse:
            buf.put(' ');
            print_type(buf, inst.imm.struct_ref.type);
            break;
        case Opcode::CacheGet:
        case Opcode::CacheSet:
            buf.put(' ');
            print_value_ref(buf, inst.operands[0]);
            if (inst.op == Opcode::CacheSet) {
                buf.put_cstr(", ");
                print_value_ref(buf, inst.operands[1]);
            }
            buf.put_cstr(", inst=");
            buf.put_i64(static_cast<i64>(inst.imm.i32_val));
            break;
        case Opcode::HashHmacSha256:
            buf.put(' ');
            print_value_ref(buf, inst.operands[0]);
            buf.put_cstr(", ");
            print_value_ref(buf, inst.operands[1]);
            break;

        // Terminators
        case Opcode::Br:
            buf.put(' ');
            print_value_ref(buf, inst.operands[0]);
            buf.put_cstr(", ");
            print_block_ref(buf, inst.imm.block_targets[0], fn);
            buf.put_cstr(", ");
            print_block_ref(buf, inst.imm.block_targets[1], fn);
            break;
        case Opcode::Jmp:
            buf.put(' ');
            print_block_ref(buf, inst.imm.block_targets[0], fn);
            break;
        case Opcode::RetStatus:
            buf.put(' ');
            if (inst.operand_count > 0) {
                print_value_ref(buf, inst.operands[0]);
            } else {
                // Literal form packs (status | body_idx<<16 |
                // headers_idx<<32) into i64_val; decode all three so
                // human-facing output stays truthful.
                u64 packed = static_cast<u64>(inst.imm.i64_val);
                buf.put_i32(static_cast<i32>(packed & 0xffffu));
                u32 body_idx = static_cast<u32>((packed >> 16) & 0xffffu);
                if (body_idx != 0) {
                    buf.put_cstr(", body#");
                    buf.put_u32(body_idx);
                }
                u32 headers_idx = static_cast<u32>((packed >> 32) & 0xffffu);
                if (headers_idx != 0) {
                    buf.put_cstr(", headers#");
                    buf.put_u32(headers_idx);
                }
            }
            break;
        case Opcode::RetForward:
        case Opcode::RetForwardBundle:
            buf.put(' ');
            print_value_ref(buf, inst.operands[0]);
            break;
        case Opcode::RetRedirect:
            buf.put(' ');
            buf.put_i32(inst.imm.i32_val);
            break;

        // Yields
        case Opcode::YieldHttpGet:
            buf.put(' ');
            print_quoted_str(buf, inst.imm.str_val);
            if (inst.operand_count > 0) {
                buf.put_cstr(", ");
                print_value_ref(buf, inst.operands[0]);
            }
            break;
        case Opcode::YieldHttpPost:
            buf.put(' ');
            print_quoted_str(buf, inst.imm.str_val);
            for (u32 i = 0; i < inst.operand_count; i++) {
                buf.put_cstr(", ");
                print_value_ref(buf, inst.operand(i));
            }
            break;
        case Opcode::YieldForward:
            buf.put(' ');
            if (inst.operand_count > 0) print_value_ref(buf, inst.operands[0]);
            break;
        case Opcode::YieldTimer: {
            const u64 packed = static_cast<u64>(inst.imm.i64_val);
            buf.put(' ');
            buf.put_u32(static_cast<u32>(packed & 0xffffffffu));
            buf.put_cstr(", state ");
            buf.put_u32(static_cast<u32>((packed >> 32) & 0xffffu));
            break;
        }

        // Instrumentation
        case Opcode::TraceFuncEnter:
        case Opcode::TraceFuncExit:
        case Opcode::TraceIoStart:
        case Opcode::TraceIoEnd:
        case Opcode::MetricHistRecord:
        case Opcode::MetricCounterIncr:
        case Opcode::AccessLogWrite:
        default:
            // Fallback: print all operands comma-separated for opcodes
            // without specialized formatting (StructCreate, ArrayLen, etc.).
            for (u32 i = 0; i < inst.operand_count; i++) {
                if (i == 0) {
                    buf.put(' ');
                } else {
                    buf.put_cstr(", ");
                }
                print_value_ref(buf, inst.operand(i));
            }
            break;
    }

    print_source_loc(buf, inst.loc);
    buf.newline();
}

// ── Block printing ──────────────────────────────────────────────────

void print_block(PrintBuf& buf, const Block& block, const Function& fn) {
    buf.indent(1);
    buf.put_str(block.label);
    buf.put(':');
    buf.newline();

    for (u32 i = 0; i < block.inst_count; i++) {
        print_instruction(buf, block.insts[i], fn);
    }
}

// ── Function printing ───────────────────────────────────────────────

void print_function(PrintBuf& buf, const Function& fn) {
    // Header.
    buf.put_cstr("=== ");
    buf.put_str(fn.name);
    buf.put_cstr(" ===");
    buf.newline();

    // Summary.
    buf.indent(1);
    buf.put_cstr("route: ");
    buf.put_str(fn.route_pattern);
    buf.newline();

    buf.indent(1);
    buf.put_cstr("io_points: ");
    buf.put_u32(fn.yield_count);
    if (fn.yield_count == 0) buf.put_cstr(" (all sync)");
    buf.newline();

    buf.indent(1);
    buf.put_cstr("states: ");
    buf.put_u32(fn.yield_count + 1);
    buf.newline();

    buf.indent(1);
    buf.put_cstr("blocks: ");
    buf.put_u32(fn.block_count);
    buf.newline();

    // Count total instructions.
    u32 total_insts = 0;
    for (u32 i = 0; i < fn.block_count; i++) {
        total_insts += fn.blocks[i].inst_count;
    }
    buf.indent(1);
    buf.put_cstr("instructions: ");
    buf.put_u32(total_insts);
    buf.newline();
    buf.newline();

    // Blocks.
    for (u32 i = 0; i < fn.block_count; i++) {
        print_block(buf, fn.blocks[i], fn);
    }
    buf.flush();
}

// ── Module printing ─────────────────────────────────────────────────

void print_module(PrintBuf& buf, const Module& mod) {
    for (u32 i = 0; i < mod.func_count; i++) {
        if (i > 0) buf.newline();
        print_function(buf, mod.functions[i]);
    }
    if (mod.redirect_policy_count != 0) {
        if (mod.func_count != 0) buf.newline();
        buf.put_cstr("redirect_policies: ");
        buf.put_u32(mod.redirect_policy_count);
        buf.newline();
        for (u32 i = 0; i < mod.redirect_policy_count; i++) {
            const auto& policy = mod.redirect_policies[i];
            buf.put_cstr("  redirect_policy#");
            buf.put_u32(i + 1);
            buf.put_cstr(": scheme=");
            print_redirect_scheme(buf, policy.scheme);
            buf.put_cstr(", authority=");
            print_redirect_authority(buf, policy.authority);
            buf.put_cstr(", port=");
            print_redirect_port(buf, policy.port);
            buf.put_cstr(", path=");
            print_redirect_path(buf, policy.path);
            buf.put_cstr(", query=");
            print_redirect_query(buf, policy.query);
            buf.put_cstr(", date=");
            print_redirect_date(buf, policy.date);
            buf.put_cstr(", connection=");
            print_redirect_connection(buf, policy.connection);
            buf.put_cstr(", status=");
            buf.put_u32(policy.status_code);
            buf.put_cstr(", reason=");
            print_quoted_str(buf, policy.reason);
            buf.put_cstr(", server=");
            print_quoted_str(buf, policy.server);
            buf.put_cstr(", content_type=");
            print_quoted_str(buf, policy.content_type);
            buf.put_cstr(", target_path=");
            print_quoted_str(buf, policy.target_path);
            buf.put_cstr(", body=");
            print_redirect_body(buf, policy.body);
            buf.newline();
        }
    }
    buf.flush();
}

}  // namespace rir
}  // namespace rut
