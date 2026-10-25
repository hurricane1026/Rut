#pragma once

#include "rut/common/types.h"

namespace rut::json {

// RFC 8259 values. Numbers retain their original decimal lexeme: parsing never
// rounds an integer or overflows a floating point value. Missing is not Null.
enum class Kind : u8 { Null, Boolean, Number, String, Array, Object };
enum class Op : u8 {
    Parse,
    Quote,
    Integer,
    Boolean,
    Null,
    EmptyObject,
    EmptyArray,
    Member,
    Element,
    Get,
    Set,
    Remove,
    Append,
    AsString,
    AsNumber,
    AsBool,
    AsInt,
    Count,
    KindName,
    Keys,
    At,
    Number,
    AsI32,
    RequireObject,
    Stringify,
    // jwtDecode(token, secret): verifies an HS256/384/512 JWT and yields the
    // decoded claims object. Kept in the JSON op family so the existing
    // optional-Json carrier and arena lifetime apply unchanged.
    JwtDecode,
    BearerToken,
};
inline constexpr u32 kMaxBytes = 8192;
inline constexpr u32 kMaxNodes = 2048;
inline constexpr u32 kMaxDepth = 64;
inline constexpr u32 kNone = 0xffffffffu;

struct Writer {
    char* data;
    u32 cap = kMaxBytes;
    u32 len = 0;
    bool ok = true;
    void put(char c) {
        if (len == cap) {
            ok = false;
            return;
        }
        data[len++] = c;
    }
    void text(Str s) {
        if (s.len > cap - len) {
            ok = false;
            return;
        }
        for (u32 i = 0; i < s.len; ++i) data[len++] = s.ptr[i];
    }
    void utf8(u32 cp) {
        if (cp < 0x80)
            put(static_cast<char>(cp));
        else if (cp < 0x800) {
            put(static_cast<char>(0xc0 | (cp >> 6)));
            put(static_cast<char>(0x80 | (cp & 63)));
        } else if (cp < 0x10000) {
            put(static_cast<char>(0xe0 | (cp >> 12)));
            put(static_cast<char>(0x80 | ((cp >> 6) & 63)));
            put(static_cast<char>(0x80 | (cp & 63)));
        } else {
            put(static_cast<char>(0xf0 | (cp >> 18)));
            put(static_cast<char>(0x80 | ((cp >> 12) & 63)));
            put(static_cast<char>(0x80 | ((cp >> 6) & 63)));
            put(static_cast<char>(0x80 | (cp & 63)));
        }
    }
};

inline bool hex4(Str s, u32& p, u32& cp) {
    cp = 0;
    for (u32 i = 0; i < 4; ++i) {
        if (p == s.len) return false;
        const char c = s.ptr[p++];
        u32 d;
        if (c >= '0' && c <= '9')
            d = static_cast<u32>(c - '0');
        else if (c >= 'a' && c <= 'f')
            d = static_cast<u32>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            d = static_cast<u32>(c - 'A' + 10);
        else
            return false;
        cp = (cp << 4) | d;
    }
    return true;
}

// Consume one Unicode scalar from a raw UTF-8 string. Reject overlong forms,
// surrogates, truncated sequences, stray continuations and values above U+10FFFF.
inline bool scalar(Str s, u32& p, u32& cp) {
    if (p >= s.len) return false;
    const u8 c = static_cast<u8>(s.ptr[p++]);
    if (c < 128) {
        cp = c;
        return true;
    }
    u32 n;
    u32 min;
    if (c >= 0xc2 && c <= 0xdf) {
        n = 1;
        min = 0x80;
        cp = c & 31;
    } else if (c >= 0xe0 && c <= 0xef) {
        n = 2;
        min = 0x800;
        cp = c & 15;
    } else if (c >= 0xf0 && c <= 0xf4) {
        n = 3;
        min = 0x10000;
        cp = c & 7;
    } else
        return false;
    for (u32 i = 0; i < n; ++i) {
        if (p >= s.len) return false;
        const u8 d = static_cast<u8>(s.ptr[p++]);
        if ((d & 0xc0) != 0x80) return false;
        cp = (cp << 6) | (d & 63);
    }
    return cp >= min && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff);
}

inline bool decode(Str s, u32& p, Writer& out) {
    if (p >= s.len || s.ptr[p] != '"') return false;
    ++p;
    while (p < s.len) {
        if (s.ptr[p] == '"') {
            ++p;
            return out.ok;
        }
        u32 cp;
        if (s.ptr[p] == '\\') {
            ++p;
            if (p == s.len) return false;
            const char e = s.ptr[p++];
            switch (e) {
                case '"':
                    cp = '"';
                    break;
                case '\\':
                    cp = '\\';
                    break;
                case '/':
                    cp = '/';
                    break;
                case 'b':
                    cp = 8;
                    break;
                case 'f':
                    cp = 12;
                    break;
                case 'n':
                    cp = 10;
                    break;
                case 'r':
                    cp = 13;
                    break;
                case 't':
                    cp = 9;
                    break;
                case 'u': {
                    if (!hex4(s, p, cp)) return false;
                    if (cp >= 0xd800 && cp <= 0xdbff) {
                        if (s.len - p < 2 || s.ptr[p] != '\\' || s.ptr[p + 1] != 'u') return false;
                        p += 2;
                        u32 lo;
                        if (!hex4(s, p, lo) || lo < 0xdc00 || lo > 0xdfff) return false;
                        cp = 0x10000 + ((cp - 0xd800) << 10) + lo - 0xdc00;
                    } else if (cp >= 0xdc00 && cp <= 0xdfff)
                        return false;
                    break;
                }
                default:
                    return false;
            }
        } else {
            if (!scalar(s, p, cp) || cp < 32) return false;
        }
        out.utf8(cp);
    }
    return false;
}

inline bool quote(Str s, Writer& out) {
    out.put('"');
    u32 p = 0;
    while (p < s.len) {
        u32 cp;
        if (!scalar(s, p, cp)) return false;
        if (cp == '"' || cp == '\\') {
            out.put('\\');
            out.put(static_cast<char>(cp));
        } else if (cp < 32) {
            constexpr char digits[] = "0123456789abcdef";
            out.text(lit_str("\\u00"));
            out.put(digits[cp >> 4]);
            out.put(digits[cp & 15]);
        } else
            out.utf8(cp);
    }
    out.put('"');
    return out.ok;
}

struct Node {
    Kind kind = Kind::Null;
    u32 start = 0;
    u32 end = 0;
    u32 child = kNone;
    u32 next = kNone;
    u32 key = kNone;
};

// Caller owns bounded workspace; no malloc, standard library or global state.
struct Document {
    Node nodes[kMaxNodes];
    u32 count = 0;
    Str source{};
    char scratch[kMaxBytes];
    char other[kMaxBytes];
    u32 p = 0;
    bool valid = true;

    void whitespace() {
        while (p < source.len && (source.ptr[p] == ' ' || source.ptr[p] == '\t' ||
                                  source.ptr[p] == '\r' || source.ptr[p] == '\n'))
            ++p;
    }
    bool take(char c) {
        if (p < source.len && source.ptr[p] == c) {
            ++p;
            return true;
        }
        return false;
    }
    Str raw(u32 i) const { return source.slice(nodes[i].start, nodes[i].end); }
    bool string(u32 i, Writer& w) const {
        u32 start = nodes[i].start;
        return nodes[i].kind == Kind::String && decode(source, start, w);
    }
    bool key_equal(u32 a, u32 b) {
        Writer x{scratch}, y{other};
        return string(a, x) && string(b, y) && Str{scratch, x.len}.eq({other, y.len});
    }
    u32 parse_value(u32 depth) {
        whitespace();
        if (depth > kMaxDepth || count == kMaxNodes || p == source.len) {
            valid = false;
            return kNone;
        }
        const u32 id = count++;
        nodes[id] = {};
        nodes[id].start = p;
        const char c = source.ptr[p];
        if (c == '"') {
            nodes[id].kind = Kind::String;
            Writer w{scratch};
            if (!decode(source, p, w)) valid = false;
        } else if (c == '[' || c == '{') {
            nodes[id].kind = c == '[' ? Kind::Array : Kind::Object;
            ++p;
            whitespace();
            const char close = c == '[' ? ']' : '}';
            u32 last = kNone;
            if (!take(close)) {
                while (valid) {
                    u32 key = kNone;
                    if (c == '{') {
                        whitespace();
                        if (p == source.len || source.ptr[p] != '"') {
                            valid = false;
                            break;
                        }
                        key = parse_value(depth + 1);
                        whitespace();
                        if (!valid || !take(':')) {
                            valid = false;
                            break;
                        }
                        // Reject decoded duplicate member names, including escaped aliases.
                        for (u32 n = nodes[id].child; n != kNone; n = nodes[n].next) {
                            if (key_equal(nodes[n].key, key)) {
                                valid = false;
                                break;
                            }
                        }
                    }
                    if (!valid) break;
                    const u32 child = parse_value(depth + 1);
                    if (!valid) break;
                    nodes[child].key = key;
                    if (last == kNone)
                        nodes[id].child = child;
                    else
                        nodes[last].next = child;
                    last = child;
                    whitespace();
                    if (take(close)) break;
                    if (!take(',')) {
                        valid = false;
                        break;
                    }
                }
            }
        } else if (c == 'n' || c == 't' || c == 'f') {
            const Str token = c == 'n'   ? lit_str("null")
                              : c == 't' ? lit_str("true")
                                         : lit_str("false");
            if (source.len - p < token.len || !source.slice(p, p + token.len).eq(token))
                valid = false;
            else
                p += token.len;
            nodes[id].kind = c == 'n' ? Kind::Null : Kind::Boolean;
        } else {
            nodes[id].kind = Kind::Number;
            take('-');
            if (!take('0')) {
                if (p == source.len || source.ptr[p] < '1' || source.ptr[p] > '9')
                    valid = false;
                else
                    while (p < source.len && source.ptr[p] >= '0' && source.ptr[p] <= '9') ++p;
            }
            if (valid && take('.')) {
                const u32 start = p;
                while (p < source.len && source.ptr[p] >= '0' && source.ptr[p] <= '9') ++p;
                if (p == start) valid = false;
            }
            if (valid && (take('e') || take('E'))) {
                if (!take('+')) take('-');
                const u32 start = p;
                while (p < source.len && source.ptr[p] >= '0' && source.ptr[p] <= '9') ++p;
                if (p == start) valid = false;
            }
        }
        nodes[id].end = p;
        return valid ? id : kNone;
    }
    bool parse(Str s) {
        source = s;
        count = 0;
        p = 0;
        valid = s.ptr != nullptr && s.len <= kMaxBytes;
        if (!valid || parse_value(0) == kNone) return false;
        whitespace();
        return valid = valid && p == s.len;
    }
    u32 size(u32 id) const {
        u32 n = 0;
        for (u32 i = nodes[id].child; i != kNone; i = nodes[i].next) ++n;
        return n;
    }
    u32 at(u32 id, u32 index) const {
        u32 n = nodes[id].child;
        while (n != kNone && index != 0) {
            n = nodes[n].next;
            --index;
        }
        return n;
    }
    static bool index(Str s, u32& n) {
        if (s.len == 0 || (s.len > 1 && s.ptr[0] == '0')) return false;
        n = 0;
        for (u32 i = 0; i < s.len; ++i) {
            if (s.ptr[i] < '0' || s.ptr[i] > '9' || n > 429496729u) return false;
            const u32 digit = static_cast<u32>(s.ptr[i] - '0');
            if (n == 429496729u && digit > 5) return false;
            n = n * 10 + digit;
        }
        return true;
    }
    // RFC 6901 string form, not URI-fragment form. Empty pointer selects root.
    u32 pointer(Str path) {
        u32 id = 0, pos = 0;
        if (path.len > kMaxBytes) return kNone;
        while (pos < path.len) {
            if (path.ptr[pos++] != '/') return kNone;
            Writer token{other};
            while (pos < path.len && path.ptr[pos] != '/') {
                char c = path.ptr[pos++];
                if (c == '~') {
                    if (pos == path.len) return kNone;
                    c = path.ptr[pos++];
                    if (c == '0')
                        c = '~';
                    else if (c == '1')
                        c = '/';
                    else
                        return kNone;
                }
                token.put(c);
            }
            if (!token.ok) return kNone;
            const Str key{other, token.len};
            if (nodes[id].kind == Kind::Array) {
                u32 n;
                if (!index(key, n)) return kNone;
                id = at(id, n);
            } else if (nodes[id].kind == Kind::Object) {
                u32 found = kNone;
                for (u32 n = nodes[id].child; n != kNone; n = nodes[n].next) {
                    Writer decoded{scratch};
                    if (!string(nodes[n].key, decoded)) return kNone;
                    if (Str{scratch, decoded.len}.eq(key)) {
                        found = n;
                        break;
                    }
                }
                id = found;
            } else
                return kNone;
            if (id == kNone) return kNone;
        }
        return id;
    }
    bool write(u32 id,
               Writer& w,
               u32 replace = kNone,
               Str value = {},
               bool remove = false,
               u32 append = kNone) {
        if (id == replace) {
            if (!remove) w.text(value);
            return w.ok;
        }
        const Node& n = nodes[id];
        if (n.kind != Kind::Object && n.kind != Kind::Array) {
            if (n.kind == Kind::String) {
                Writer decoded{scratch};
                if (!string(id, decoded)) return false;
                return quote({scratch, decoded.len}, w);
            }
            w.text(raw(id));
            return w.ok;
        }
        const bool obj = n.kind == Kind::Object;
        w.put(obj ? '{' : '[');
        bool first = true;
        for (u32 child = n.child; child != kNone; child = nodes[child].next) {
            if (child == replace && remove) continue;
            if (!first) w.put(',');
            first = false;
            if (obj) {
                Writer key{scratch};
                if (!string(nodes[child].key, key) || !quote({scratch, key.len}, w)) return false;
                w.put(':');
            }
            if (!write(child, w, replace, value, remove, append)) return false;
        }
        if (id == append) {
            if (!first) w.put(',');
            w.text(value);
        }
        w.put(obj ? '}' : ']');
        return w.ok;
    }
};

inline bool integer(Str s, i64& out) {
    u32 p = 0;
    const bool negative = s.len && s.ptr[0] == '-';
    if (negative) ++p;
    if (p == s.len) return false;
    u64 n = 0;
    const u64 limit = negative ? (u64(1) << 63) : ((u64(1) << 63) - 1);
    for (; p < s.len; ++p) {
        if (s.ptr[p] < '0' || s.ptr[p] > '9') return false;
        const u32 d = static_cast<u32>(s.ptr[p] - '0');
        if (n > (limit - d) / 10) return false;
        n = n * 10 + d;
    }
    out = negative ? static_cast<i64>(u64(0) - n) : static_cast<i64>(n);
    return true;
}
inline void write_integer(i64 value, Writer& w) {
    u64 n = value < 0 ? u64(0) - static_cast<u64>(value) : static_cast<u64>(value);
    char digits[20];
    u32 count = 0;
    do {
        digits[count++] = static_cast<char>('0' + n % 10);
        n /= 10;
    } while (n);
    if (value < 0) w.put('-');
    while (count) w.put(digits[--count]);
}

// All updates are immutable. Set/remove require an existing RFC 6901 target;
// member upserts an object member and append adds to an existing array.
inline bool apply(
    Document& d, Op op, Str a, Str b, Str c, i64 number, Writer& w, Str& view, i64& scalar_result) {
    view = {};
    if (op == Op::Quote) return quote(a, w);
    if (op == Op::Integer) {
        write_integer(number, w);
        return w.ok;
    }
    if (op == Op::Boolean) {
        w.text(number ? lit_str("true") : lit_str("false"));
        return w.ok;
    }
    if (op == Op::Null) {
        w.text(lit_str("null"));
        return w.ok;
    }
    if (op == Op::EmptyObject) {
        w.text(lit_str("{}"));
        return w.ok;
    }
    if (op == Op::EmptyArray) {
        w.text(lit_str("[]"));
        return w.ok;
    }
    if (op == Op::Set || op == Op::Append || op == Op::Member) {
        if (!d.parse(c)) return false;
    }
    if (op == Op::Element && !d.parse(b)) return false;
    if (!d.parse(a)) return false;
    const Kind kind = d.nodes[0].kind;
    if (op == Op::Parse) {
        view = a;
        return true;
    }
    if (op == Op::Number) {
        if (kind != Kind::Number) return false;
        view = d.raw(0);
        return true;
    }
    if (op == Op::Stringify) return d.write(0, w);
    if (op == Op::Get) {
        const u32 id = d.pointer(b);
        if (id == kNone) return false;
        view = d.raw(id);
        return true;
    }
    if (op == Op::At) {
        if (kind != Kind::Array || number < 0 || static_cast<u64>(number) > kMaxNodes) return false;
        const u32 id = d.at(0, static_cast<u32>(number));
        if (id == kNone) return false;
        view = d.raw(id);
        return true;
    }
    if (op == Op::AsString) return kind == Kind::String && d.string(0, w);
    if (op == Op::AsNumber) {
        if (kind != Kind::Number) return false;
        view = d.raw(0);
        return true;
    }
    if (op == Op::AsBool) {
        if (kind != Kind::Boolean) return false;
        scalar_result = d.raw(0).eq(lit_str("true"));
        return true;
    }
    if (op == Op::RequireObject) {
        if (kind != Kind::Object) return false;
        view = a;
        return true;
    }
    if (op == Op::AsInt || op == Op::AsI32) {
        if (kind != Kind::Number || !integer(d.raw(0), scalar_result)) return false;
        return op != Op::AsI32 || (scalar_result >= -2147483648LL && scalar_result <= 2147483647LL);
    }
    if (op == Op::Count) {
        if (kind != Kind::Array && kind != Kind::Object) return false;
        scalar_result = d.size(0);
        return true;
    }
    if (op == Op::KindName) {
        switch (kind) {
            case Kind::Null:
                view = lit_str("null");
                break;
            case Kind::Boolean:
                view = lit_str("boolean");
                break;
            case Kind::Number:
                view = lit_str("number");
                break;
            case Kind::String:
                view = lit_str("string");
                break;
            case Kind::Array:
                view = lit_str("array");
                break;
            case Kind::Object:
                view = lit_str("object");
                break;
        }
        return true;
    }
    if (op == Op::Keys) {
        if (kind != Kind::Object) return false;
        w.put('[');
        bool first = true;
        for (u32 n = d.nodes[0].child; n != kNone; n = d.nodes[n].next) {
            if (!first) w.put(',');
            first = false;
            if (!d.write(d.nodes[n].key, w)) return false;
        }
        w.put(']');
        return w.ok;
    }
    if (op == Op::Member) {
        if (kind != Kind::Object) return false;
        for (u32 n = d.nodes[0].child; n != kNone; n = d.nodes[n].next) {
            Writer key{d.scratch};
            if (!d.string(d.nodes[n].key, key)) return false;
            if (Str{d.scratch, key.len}.eq(b)) return d.write(0, w, n, c);
        }
        char extra[kMaxBytes];
        Writer member{extra};
        if (!quote(b, member)) return false;
        member.put(':');
        member.text(c);
        return member.ok && d.write(0, w, kNone, {extra, member.len}, false, 0);
    }
    if (op == Op::Element) {
        return kind == Kind::Array && d.write(0, w, kNone, b, false, 0);
    }
    if (op == Op::Set || op == Op::Remove || op == Op::Append) {
        const u32 id = d.pointer(b);
        if (id == kNone) return false;
        if (op == Op::Remove && id == 0) return false;
        if (op == Op::Append) {
            return d.nodes[id].kind == Kind::Array && d.write(0, w, kNone, c, false, id);
        }
        return d.write(0, w, id, c, op == Op::Remove);
    }
    return false;
}

}  // namespace rut::json
