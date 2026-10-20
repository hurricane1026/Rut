#include "rut/compiler/protobuf_source.h"

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/compiler/protobuf_schema.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/protobuf_value.h"
#include "rut/runtime/protobuf_wire.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace rut::protobuf {
namespace {
struct Buffer;
struct Chunk {
    Chunk* next = nullptr;
    const u8* data = nullptr;
    u32 size = 0;
    Buffer* child = nullptr;
    u32 tag = 0;
};
struct Symbol {
    Str name{};
    Symbol* next = nullptr;
};
struct Buffer {
    enum class Error : u8 { None, Limit, Allocation };
    Arena<MmapBackend>& arena;
    Chunk* head = nullptr;
    Chunk* tail = nullptr;
    u32 size = 0;
    Str declared_name{};
    bool optional = false;
    Symbol* symbols = nullptr;
    Error error = Error::None;
    void add(Field field) {
        const u64 kCapacity = static_cast<u64>(field.size) + 20;
        if (error != Error::None) return;
        if (kCapacity > 4ULL * 1024 * 1024) {
            error = Error::Limit;
            return;
        }
        auto* bytes = static_cast<u8*>(arena.alloc(kCapacity));
        auto* chunk = arena.alloc_t<Chunk>();
        if (!bytes || !chunk) {
            error = Error::Allocation;
            return;
        }
        Writer writer(bytes, static_cast<u32>(kCapacity));
        if (!writer.write(field) || writer.size() > 4 * 1024 * 1024 - size) {
            error = Error::Limit;
            return;
        }
        chunk->data = bytes;
        chunk->size = writer.size();
        if (tail)
            tail->next = chunk;
        else
            head = chunk;
        tail = chunk;
        size += chunk->size;
    }
    void symbol(Str name) {
        auto* item = arena.alloc_t<Symbol>();
        if (!item) {
            error = Error::Allocation;
            return;
        }
        *item = {name, symbols};
        symbols = item;
    }
    bool contains(Str name) const {
        for (const auto* item = symbols; item; item = item->next)
            if (item->name.eq(name)) return true;
        return false;
    }
    void number(u32 tag, u64 value) { add({tag, 0, value}); }
    void text(u32 tag, Str value) {
        add({tag, 2, 0, reinterpret_cast<const u8*>(value.ptr), value.len});
    }
    const u8* flatten() {
        if (error != Error::None) return nullptr;
        auto* bytes = static_cast<u8*>(arena.alloc(size ? size : 1));
        if (!bytes) {
            error = Error::Allocation;
            return nullptr;
        }
        u32 offset = 0;
        for (const Chunk* item = head; item; item = item->next) {
            __builtin_memcpy(bytes + offset, item->data, item->size);
            offset += item->size;
        }
        return bytes;
    }
    void child(u32 tag, Buffer& value) {
        const u8* bytes = value.flatten();
        if (!bytes) {
            if (error == Error::None) error = value.error;
            return;
        }
        add({tag, 2, 0, bytes, value.size});
    }
};
struct Import;
struct Source {
    Str name{};
    Str text{};
    Str package{};
    bool active = true;
    Source* next = nullptr;
    Buffer* descriptor = nullptr;
    Import* imports = nullptr;
    u32 import_count = 0;
};
struct Import {
    const Source* source = nullptr;
    Import* next = nullptr;
    u32 index = 0;
    bool is_public = false;
};
struct NamedMessage {
    Str name{};
    NamedMessage* next = nullptr;
    bool concrete = true;
    const Source* file = nullptr;
    bool is_enum = false;
};
struct Reference {
    Str name{};
    Str scope{};
    Buffer* target = nullptr;
    u32 tag = 0;
    Source* file = nullptr;
    u32 line = 0;
    u32 column = 0;
    Reference* next = nullptr;
};
struct Token {
    enum class Kind : u8 { End, Ident, Number, String, Symbol, Bad };
    Kind kind = Kind::End;
    Str text{};
    u32 line = 1;
    u32 column = 1;
};
bool alpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}
bool digit(char c) {
    return c >= '0' && c <= '9';
}
struct Compiler;
struct Parser {
    Compiler& compiler;
    Source& source;
    u32 offset = 0;
    u32 line = 1;
    u32 column = 1;
    Token token{};
    void advance();
    void step() {
        if (source.text.ptr[offset++] == '\n') {
            ++line;
            column = 1;
        } else
            ++column;
    }
    bool is(Str value) const {
        return (token.kind == Token::Kind::Ident || token.kind == Token::Kind::Symbol) &&
               token.text.eq(value);
    }
    bool take(Str value) {
        if (!is(value)) return false;
        advance();
        return true;
    }
    bool expect(Str value);
    bool fail(SourceError::Kind kind, Str detail);
    bool name(Str& out, bool qualified = false);
    bool string(Str& out);
    bool number(u32& out);
    bool type_reference(Buffer& target, u32 tag, Str scope);
    bool message(Buffer& parent, Str scope, u32 depth);
    bool enumeration(Buffer& parent, Str scope, bool nested);
    bool reservation(Buffer& parent, bool enumeration);
    bool field(Buffer& parent, Str scope);
    bool service(Buffer& parent, Str scope);
    bool file_option(Buffer& options, u32& seen);
    bool file();
};
struct Compiler {
    Arena<MmapBackend>& arena;
    SchemaLimits limits;
    SourceError error{};
    bool visible(const Source* file, const Source* owner) const {
        if (file == owner) return true;
        const Source* visited[128]{};
        u32 count = 0;
        auto exported = [&](const Source* from, auto&& self) -> bool {
            if (from == owner) return true;
            for (u32 i = 0; i < count; ++i)
                if (visited[i] == from) return false;
            if (count >= limits.files) return false;
            visited[count++] = from;
            for (const Import* edge = from->imports; edge; edge = edge->next)
                if (edge->is_public && self(edge->source, self)) return true;
            return false;
        };
        for (const Import* imported = file->imports; imported; imported = imported->next)
            if (exported(imported->source, exported)) return true;
        return false;
    }
    Str root_directory{};
    Source* sources = nullptr;
    NamedMessage* messages = nullptr;
    Reference* references = nullptr;
    u32 source_bytes = 0;
    u32 file_count = 0;
    u32 message_count = 0;
    u32 field_count = 0;
    u32 method_count = 0;
    u32 service_count = 0;
    u32 enum_count = 0;
    u32 enum_value_count = 0;
    u32 reserved_count = 0;
    bool failed = false;
    bool fail(SourceError::Kind kind, Str file, u32 line, u32 column, Str detail) {
        if (!failed) error = {kind, file, line, column, detail};
        failed = true;
        return false;
    }
    Str copy(Str value) {
        auto* bytes = static_cast<char*>(arena.alloc(static_cast<u64>(value.len) + 1));
        if (!bytes) return {};
        if (value.len) __builtin_memcpy(bytes, value.ptr, value.len);
        bytes[value.len] = 0;
        return {bytes, value.len};
    }
    Str join(Str left, char separator, Str right) {
        const u64 kSize = static_cast<u64>(left.len) + right.len + 1;
        if (kSize > 4095) return {};
        auto* bytes = static_cast<char*>(arena.alloc(kSize + 1));
        if (!bytes) return {};
        if (left.len) __builtin_memcpy(bytes, left.ptr, left.len);
        bytes[left.len] = separator;
        if (right.len) __builtin_memcpy(bytes + left.len + 1, right.ptr, right.len);
        bytes[kSize] = 0;
        return {bytes, static_cast<u32>(kSize)};
    }
    Str join_scratch(char* bytes, u32 capacity, Str left, char separator, Str right) const {
        const u64 kSize = static_cast<u64>(left.len) + right.len + 1;
        if (kSize >= capacity) return {};
        if (left.len) __builtin_memcpy(bytes, left.ptr, left.len);
        bytes[left.len] = separator;
        if (right.len) __builtin_memcpy(bytes + left.len + 1, right.ptr, right.len);
        bytes[kSize] = 0;
        return {bytes, static_cast<u32>(kSize)};
    }
    bool imported_path(Str path) const {
        if (!path.len || path.ptr[0] == '/' || path.len > 1024) return false;
        u32 begin = 0;
        for (u32 i = 0; i <= path.len; ++i) {
            if (i < path.len && path.ptr[i] == '\0') return false;
            if (i != path.len && path.ptr[i] != '/') continue;
            const Str kPart{path.ptr + begin, i - begin};
            if (!kPart.len || kPart.eq(lit_str(".")) || kPart.eq(lit_str(".."))) return false;
            begin = i + 1;
        }
        return true;
    }
    bool load(Str name, Str path, u32 depth) {
        if (depth > 32) return fail(SourceError::Kind::Limit, name, 1, 1, lit_str("import depth"));
        for (const Source* old = sources; old; old = old->next) {
            if (!old->name.eq(name)) continue;
            return !old->active ||
                   fail(SourceError::Kind::Syntax, name, 1, 1, lit_str("import cycle"));
        }
        if (file_count >= limits.files)
            return fail(SourceError::Kind::Limit, name, 1, 1, lit_str("file count"));
        const Str kKeptPath = copy(path);
        if (!kKeptPath.ptr) return fail(SourceError::Kind::Allocation, name, 1, 1, {});
        const int kFd = open(kKeptPath.ptr, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (kFd < 0)
            return fail(SourceError::Kind::Io, name, 1, 1, lit_str("cannot open proto source"));
        struct stat info{};
        if (fstat(kFd, &info) || !S_ISREG(info.st_mode) || info.st_size < 0 ||
            static_cast<u64>(info.st_size) > limits.bytes - source_bytes) {
            close(kFd);
            return fail(SourceError::Kind::Limit, name, 1, 1, lit_str("source size or file type"));
        }
        const u32 kSize = static_cast<u32>(info.st_size);
        auto* bytes = static_cast<char*>(arena.alloc(static_cast<u64>(kSize) + 1));
        if (!bytes) {
            close(kFd);
            return fail(SourceError::Kind::Allocation, name, 1, 1, {});
        }
        u32 read_bytes = 0;
        while (read_bytes < kSize) {
            const ssize_t kRead = read(kFd, bytes + read_bytes, kSize - read_bytes);
            if (kRead < 0 && errno == EINTR) continue;
            if (kRead <= 0) {
                close(kFd);
                return fail(SourceError::Kind::Io, name, 1, 1, lit_str("short proto read"));
            }
            read_bytes += static_cast<u32>(kRead);
        }
        close(kFd);
        bytes[kSize] = 0;
        source_bytes += kSize;
        auto* source = arena.alloc_t<Source>();
        auto* buffer = arena.alloc_t<Buffer>(arena);
        if (!source || !buffer) return fail(SourceError::Kind::Allocation, name, 1, 1, {});
        source->name = copy(name);
        if (!source->name.ptr) return fail(SourceError::Kind::Allocation, name, 1, 1, {});
        source->text = {bytes, kSize};
        source->descriptor = buffer;
        source->next = sources;
        sources = source;
        ++file_count;
        Parser parser{*this, *source};
        parser.advance();
        if (!parser.file()) return false;
        source->active = false;
        return true;
    }
    bool resolve() {
        for (Reference* item = references; item; item = item->next) {
            Str scope = item->scope;
            Str found{};
            bool is_enum = false;
            char candidate_bytes[4096];
            char first_bytes[4096];
            while (true) {
                const Str kCandidate =
                    item->name.ptr[0] == '.'
                        ? item->name
                        : join_scratch(
                              candidate_bytes, sizeof(candidate_bytes), scope, '.', item->name);
                if (!kCandidate.ptr)
                    return fail(
                        SourceError::Kind::Limit, item->file->name, item->line, item->column, {});
                for (const NamedMessage* type = messages; type; type = type->next)
                    if (type->concrete && type->name.eq(kCandidate) &&
                        visible(item->file, type->file)) {
                        if (type->is_enum && item->tag != 6)
                            return fail(SourceError::Kind::Schema,
                                        item->file->name,
                                        item->line,
                                        item->column,
                                        lit_str("RPC requires a message"));
                        is_enum = type->is_enum;
                        found = type->name;
                        break;
                    }
                bool shadowed = false;
                u32 first = 0;
                while (first < item->name.len && item->name.ptr[first] != '.') ++first;
                const Str kFirst = join_scratch(
                    first_bytes, sizeof(first_bytes), scope, '.', {item->name.ptr, first});
                if (!kFirst.ptr)
                    return fail(
                        SourceError::Kind::Limit, item->file->name, item->line, item->column, {});
                for (const NamedMessage* symbol = messages; symbol; symbol = symbol->next) {
                    const bool kNameMatches =
                        symbol->name.eq(kFirst) ||
                        (symbol->name.len > kFirst.len && symbol->name.ptr[kFirst.len] == '.' &&
                         Str{symbol->name.ptr, kFirst.len}.eq(kFirst));
                    if (kNameMatches && visible(item->file, symbol->file)) shadowed = true;
                }
                for (const Source* package = sources; package; package = package->next) {
                    if (kFirst.len > 1) {
                        const Str kPackagePrefix{kFirst.ptr + 1, kFirst.len - 1};
                        const bool kPackageMatches =
                            package->package.eq(kPackagePrefix) ||
                            (package->package.len > kPackagePrefix.len &&
                             package->package.ptr[kPackagePrefix.len] == '.' &&
                             Str{package->package.ptr, kPackagePrefix.len}.eq(kPackagePrefix));
                        if (kPackageMatches && visible(item->file, package)) shadowed = true;
                    }
                }
                if (found.ptr || shadowed || item->name.ptr[0] == '.' || !scope.len) break;
                u32 n = scope.len;
                while (n && scope.ptr[n - 1] != '.') --n;
                scope.len = n ? n - 1 : 0;
            }
            if (!found.ptr)
                return fail(SourceError::Kind::Schema,
                            item->file->name,
                            item->line,
                            item->column,
                            lit_str("unresolved message type"));
            item->target->text(item->tag, found);
            if (item->tag == 6) item->target->number(5, is_enum ? 14 : 11);
        }
        return true;
    }
};
void Parser::advance() {
    const char* data = source.text.ptr;
    const u32 kSize = source.text.len;
    while (offset < kSize) {
        const char kChar = data[offset];
        if (kChar == ' ' || kChar == '\t' || kChar == '\r' || kChar == '\n') {
            step();
            continue;
        }
        if (kChar == '/' && offset + 1 < kSize && data[offset + 1] == '/') {
            while (offset < kSize && data[offset] != '\n') step();
            continue;
        }
        if (kChar == '/' && offset + 1 < kSize && data[offset + 1] == '*') {
            step();
            step();
            while (offset + 1 < kSize && (data[offset] != '*' || data[offset + 1] != '/')) step();
            if (offset + 1 >= kSize) {
                token = {Token::Kind::Bad, {}, line, column};
                return;
            }
            step();
            step();
            continue;
        }
        break;
    }
    token = {Token::Kind::End, {}, line, column};
    if (offset == kSize) return;
    const u32 kStart = offset;
    const char kChar = data[offset];
    if (alpha(kChar)) {
        step();
        while (offset < kSize && (alpha(data[offset]) || digit(data[offset]))) step();
        token.kind = Token::Kind::Ident;
    } else if (digit(kChar)) {
        step();
        while (offset < kSize && (alpha(data[offset]) || digit(data[offset]))) step();
        token.kind = Token::Kind::Number;
    } else if (kChar == '"' || kChar == '\'') {
        step();
        const u32 kTextStart = offset;
        while (offset < kSize && data[offset] != kChar) {
            if (data[offset] == '\\') {
                step();
                if (offset >= kSize) break;
            }
            if (data[offset] == '\n' || data[offset] == '\r' || !data[offset]) break;
            step();
        }
        if (offset == kSize || data[offset] != kChar)
            token.kind = Token::Kind::Bad;
        else {
            token.kind = Token::Kind::String;
            token.text = {data + kTextStart, offset - kTextStart};
            step();
            return;
        }
    } else {
        step();
        token.kind = kChar ? Token::Kind::Symbol : Token::Kind::Bad;
    }
    token.text = {data + kStart, offset - kStart};
}
bool Parser::fail(SourceError::Kind kind, Str detail) {
    return compiler.fail(kind, source.name, token.line, token.column, detail);
}
bool Parser::expect(Str value) {
    return take(value) || fail(SourceError::Kind::Syntax, value);
}
bool Parser::name(Str& out, bool qualified) {
    const bool kAbsolute = qualified && take(lit_str("."));
    if (token.kind != Token::Kind::Ident)
        return fail(SourceError::Kind::Syntax, lit_str("identifier"));
    if (kAbsolute && token.text.len > 1023)
        return fail(SourceError::Kind::Limit, lit_str("name length"));
    out = token.text;
    advance();
    if (kAbsolute) out = compiler.join({}, '.', out);
    while (qualified && take(lit_str("."))) {
        if (token.kind != Token::Kind::Ident)
            return fail(SourceError::Kind::Syntax, lit_str("type name"));
        if (out.len >= 1024 || token.text.len > 1023 - out.len)
            return fail(SourceError::Kind::Limit, lit_str("name length"));
        out = compiler.join(out, '.', token.text);
        if (!out.ptr) return fail(SourceError::Kind::Allocation, {});
        advance();
    }
    if (!out.ptr) return fail(SourceError::Kind::Allocation, {});
    if (out.len > 1024) return fail(SourceError::Kind::Limit, lit_str("name length"));
    return true;
}
bool Parser::string(Str& out) {
    if (token.kind != Token::Kind::String)
        return fail(SourceError::Kind::Syntax, lit_str("string"));
    // Count adjacent literals before allocating once; comments and whitespace
    // are skipped by advance(). Decoding never expands beyond the raw spelling.
    Parser probe = *this;
    u64 capacity = 0;
    do {
        capacity += probe.token.text.len;
        probe.advance();
    } while (probe.token.kind == Token::Kind::String);
    if (capacity > compiler.limits.bytes)
        return fail(SourceError::Kind::Limit, lit_str("string length"));
    auto* bytes = static_cast<char*>(compiler.arena.alloc(static_cast<u32>(capacity) + 1));
    if (!bytes) return fail(SourceError::Kind::Allocation, {});
    auto hex = [](char c) -> u32 {
        if (c >= '0' && c <= '9') return static_cast<u32>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<u32>(c - 'a') + 10;
        if (c >= 'A' && c <= 'F') return static_cast<u32>(c - 'A') + 10;
        return 16;
    };
    u32 length = 0;
    do {
        for (u32 i = 0; i < token.text.len; ++i) {
            char c = token.text.ptr[i];
            if (c != '\\') {
                bytes[length++] = c;
                continue;
            }
            if (++i == token.text.len)
                return fail(SourceError::Kind::Syntax, lit_str("string escape"));
            c = token.text.ptr[i];
            switch (c) {
                case 'a':
                    c = '\a';
                    break;
                case 'b':
                    c = '\b';
                    break;
                case 'f':
                    c = '\f';
                    break;
                case 'n':
                    c = '\n';
                    break;
                case 'r':
                    c = '\r';
                    break;
                case 't':
                    c = '\t';
                    break;
                case 'v':
                    c = '\v';
                    break;
                case '\\':
                case '\'':
                case '"':
                case '?':
                    break;
                default: {
                    u32 value = 0;
                    if (c >= '0' && c <= '7') {
                        value = static_cast<u32>(c - '0');
                        for (u32 n = 1; n < 3 && i + 1 < token.text.len; ++n) {
                            const char kNext = token.text.ptr[i + 1];
                            if (kNext < '0' || kNext > '7') break;
                            value = value * 8 + static_cast<u32>(kNext - '0');
                            ++i;
                        }
                    } else if (c == 'x' || c == 'X') {
                        if (i + 1 == token.text.len || hex(token.text.ptr[i + 1]) == 16)
                            return fail(SourceError::Kind::Syntax, lit_str("hex escape"));
                        value = hex(token.text.ptr[++i]);
                        if (i + 1 < token.text.len && hex(token.text.ptr[i + 1]) != 16)
                            value = value * 16 + hex(token.text.ptr[++i]);
                    } else if (c == 'u' || c == 'U') {
                        const u32 kDigits = c == 'u' ? 4 : 8;
                        if (token.text.len - i - 1 < kDigits)
                            return fail(SourceError::Kind::Syntax, lit_str("unicode escape"));
                        for (u32 n = 0; n < kDigits; ++n) {
                            const u32 kDigit = hex(token.text.ptr[++i]);
                            if (kDigit == 16)
                                return fail(SourceError::Kind::Syntax, lit_str("unicode escape"));
                            value = value * 16 + kDigit;
                        }
                        // protoc combines adjacent UTF-16 escapes within one literal.
                        if (value >= 0xd800 && value <= 0xdbff && token.text.len - i - 1 >= 6 &&
                            token.text.ptr[i + 1] == '\\' && token.text.ptr[i + 2] == 'u') {
                            u32 low = 0;
                            for (u32 n = 3; n <= 6; ++n) {
                                const u32 kDigit = hex(token.text.ptr[i + n]);
                                if (kDigit == 16)
                                    return fail(SourceError::Kind::Syntax,
                                                lit_str("unicode escape"));
                                low = low * 16 + kDigit;
                            }
                            if (low < 0xdc00 || low > 0xdfff)
                                return fail(SourceError::Kind::Syntax,
                                            lit_str("unicode surrogate"));
                            value = 0x10000 + ((value - 0xd800) << 10) + low - 0xdc00;
                            i += 6;
                        }
                        if (value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
                            return fail(SourceError::Kind::Syntax, lit_str("unicode scalar"));
                        if (value < 0x80) {
                            bytes[length++] = static_cast<char>(value);
                        } else if (value < 0x800) {
                            bytes[length++] = static_cast<char>(0xc0 | (value >> 6));
                            bytes[length++] = static_cast<char>(0x80 | (value & 0x3f));
                        } else {
                            if (value >= 0x10000) {
                                bytes[length++] = static_cast<char>(0xf0 | (value >> 18));
                                bytes[length++] = static_cast<char>(0x80 | ((value >> 12) & 0x3f));
                            } else {
                                bytes[length++] = static_cast<char>(0xe0 | (value >> 12));
                            }
                            bytes[length++] = static_cast<char>(0x80 | ((value >> 6) & 0x3f));
                            bytes[length++] = static_cast<char>(0x80 | (value & 0x3f));
                        }
                        continue;
                    } else {
                        return fail(SourceError::Kind::Syntax, lit_str("string escape"));
                    }
                    c = static_cast<char>(value & 0xff);
                    break;
                }
            }
            bytes[length++] = c;
        }
        advance();
    } while (token.kind == Token::Kind::String);
    bytes[length] = 0;
    out = {bytes, length};
    return true;
}
bool Parser::number(u32& out) {
    if (token.kind != Token::Kind::Number)
        return fail(SourceError::Kind::Syntax, lit_str("field number"));
    u32 base = 10, start = 0;
    if (token.text.len > 1 && token.text.ptr[0] == '0') {
        base = 8;
        if (token.text.len > 2 && (token.text.ptr[1] == 'x' || token.text.ptr[1] == 'X')) {
            base = 16;
            start = 2;
        }
    }
    u64 value = 0;
    for (u32 i = start; i < token.text.len; ++i) {
        const char kChar = token.text.ptr[i];
        const u32 kDigit = digit(kChar)                   ? static_cast<u32>(kChar - '0')
                           : kChar >= 'a' && kChar <= 'f' ? static_cast<u32>(kChar - 'a' + 10)
                           : kChar >= 'A' && kChar <= 'F' ? static_cast<u32>(kChar - 'A' + 10)
                                                          : 16;
        if (kDigit >= base || value > (0xffffffffULL - kDigit) / base)
            return fail(SourceError::Kind::Syntax, lit_str("field number"));
        value = value * base + kDigit;
    }
    out = static_cast<u32>(value);
    advance();
    return true;
}
bool Parser::type_reference(Buffer& target, u32 tag, Str scope) {
    const u32 kLine = token.line, kColumn = token.column;
    Str type{};
    if (!name(type, true)) return false;
    auto* ref = compiler.arena.alloc_t<Reference>();
    if (!ref) return fail(SourceError::Kind::Allocation, {});
    *ref = {type, scope, &target, tag, &source, kLine, kColumn, compiler.references};
    compiler.references = ref;
    return true;
}
bool Parser::field(Buffer& parent, Str scope) {
    if (compiler.field_count++ >= compiler.limits.fields)
        return fail(SourceError::Kind::Limit, lit_str("field count"));
    auto* descriptor = compiler.arena.alloc_t<Buffer>(compiler.arena);
    if (!descriptor) return fail(SourceError::Kind::Allocation, {});
    const bool kOptional = take(lit_str("optional"));
    const bool kRepeated = !kOptional && take(lit_str("repeated"));
    if (is(lit_str("required")) || is(lit_str("map")))
        return fail(SourceError::Kind::Unsupported, lit_str("presence/map fields"));
    const Str kScalars[] = {lit_str("double"),
                            lit_str("float"),
                            lit_str("int64"),
                            lit_str("uint64"),
                            lit_str("int32"),
                            lit_str("fixed64"),
                            lit_str("fixed32"),
                            lit_str("bool"),
                            lit_str("string"),
                            {},
                            {},
                            lit_str("bytes"),
                            lit_str("uint32"),
                            {},
                            lit_str("sfixed32"),
                            lit_str("sfixed64"),
                            lit_str("sint32"),
                            lit_str("sint64")};
    u32 type = 11;
    for (u32 i = 0; i < 18; ++i)
        if (kScalars[i].len && is(kScalars[i])) {
            type = i + 1;
            break;
        }
    if (type == 11) {
        if (!type_reference(*descriptor, 6, scope)) return false;
    } else
        advance();
    Str field_name{};
    u32 tag = 0;
    if (!name(field_name) || !expect(lit_str("=")) || !number(tag)) return false;
    parent.symbol(field_name);
    descriptor->declared_name = field_name;
    descriptor->optional = kOptional;
    descriptor->text(1, field_name);
    descriptor->number(3, tag);
    descriptor->number(4, kRepeated ? 3 : 1);
    if (type != 11) descriptor->number(5, type);
    if (take(lit_str("["))) {
        Buffer options{compiler.arena};
        bool packed_seen = false, json_seen = false;
        u32 generation_seen = 0;
        do {
            if (take(lit_str("packed"))) {
                if (packed_seen)
                    return fail(SourceError::Kind::Syntax, lit_str("duplicate packed"));
                packed_seen = true;
                if (!expect(lit_str("="))) return false;
                const bool kTrue = is(lit_str("true"));
                if (!take(lit_str("true")) && !take(lit_str("false")))
                    return fail(SourceError::Kind::Syntax, lit_str("boolean"));
                options.number(2, kTrue);
            } else if (take(lit_str("json_name"))) {
                if (json_seen)
                    return fail(SourceError::Kind::Syntax, lit_str("duplicate json_name"));
                json_seen = true;
                Str value{};
                if (!expect(lit_str("=")) || !string(value)) return false;
                descriptor->text(10, value);
            } else {
                // Generator hints have no effect on Rut's eager wire codec.
                const Str kNames[] = {lit_str("ctype"),
                                      lit_str("jstype"),
                                      lit_str("lazy"),
                                      lit_str("unverified_lazy"),
                                      lit_str("deprecated"),
                                      lit_str("debug_redact")};
                const u32 kTags[] = {1, 6, 5, 15, 3, 16};
                u32 index = 0;
                while (index < 6 && !is(kNames[index])) ++index;
                if (index == 6)
                    return fail(SourceError::Kind::Unsupported, lit_str("field option"));
                if (generation_seen & (1u << index))
                    return fail(SourceError::Kind::Syntax, lit_str("duplicate field option"));
                generation_seen |= 1u << index;
                advance();
                if (!expect(lit_str("="))) return false;
                u32 value = 0;
                if (index < 2) {
                    const Str kCtype[] = {
                        lit_str("STRING"), lit_str("CORD"), lit_str("STRING_PIECE")};
                    const Str kJstype[] = {
                        lit_str("JS_NORMAL"), lit_str("JS_STRING"), lit_str("JS_NUMBER")};
                    const Str* names = index == 0 ? kCtype : kJstype;
                    while (value < 3 && !is(names[value])) ++value;
                    if (value == 3)
                        return fail(SourceError::Kind::Syntax, lit_str("field option enum"));
                    advance();
                } else {
                    value = is(lit_str("true"));
                    if (!take(lit_str("true")) && !take(lit_str("false")))
                        return fail(SourceError::Kind::Syntax, lit_str("field option boolean"));
                }
                options.number(kTags[index], value);
            }
        } while (take(lit_str(",")));
        if (!expect(lit_str("]"))) return false;
        if (options.size) descriptor->child(8, options);
    }
    if (!expect(lit_str(";"))) return false;
    // Flattening must wait until every type reference has been resolved.
    // Parent links are encoded after type resolution.
    // Defer child serialization until type references have been resolved.
    auto* chunk = compiler.arena.alloc_t<Chunk>();
    if (!chunk) return fail(SourceError::Kind::Allocation, {});
    chunk->child = descriptor;
    chunk->tag = 2;
    if (parent.tail)
        parent.tail->next = chunk;
    else
        parent.head = chunk;
    parent.tail = chunk;
    return true;
}
bool Parser::reservation(Buffer& parent, bool enumeration) {
    advance();
    const bool kNames = token.kind == Token::Kind::String;
    auto bound = [&](i64& value) -> bool {
        const bool kNegative = enumeration && take(lit_str("-"));
        u32 magnitude = 0;
        if (!number(magnitude)) return false;
        if (enumeration) {
            if (magnitude > (kNegative ? 2147483648u : 2147483647u))
                return fail(SourceError::Kind::Syntax, lit_str("enum reserved bound"));
        } else if (!magnitude || magnitude > 0x1fffffffu)
            return fail(SourceError::Kind::Syntax, lit_str("message reserved bound"));
        value = kNegative ? -static_cast<i64>(magnitude) : static_cast<i64>(magnitude);
        return true;
    };
    do {
        if (compiler.reserved_count++ >= compiler.limits.reserved)
            return fail(SourceError::Kind::Limit, lit_str("reserved declaration count"));
        if (kNames) {
            Str value{};
            if (!string(value)) return false;
            parent.text(enumeration ? 5 : 10, value);
        } else {
            i64 first = 0, last = 0;
            if (!bound(first)) return false;
            last = first;
            if (take(lit_str("to"))) {
                if (take(lit_str("max")))
                    last = enumeration ? 2147483647 : 0x1fffffff;
                else if (!bound(last))
                    return false;
            }
            if (last < first)
                return fail(SourceError::Kind::Syntax, lit_str("reversed reserved range"));
            Buffer range{compiler.arena};
            range.number(1, static_cast<u64>(first));
            range.number(2, static_cast<u64>(enumeration ? last : last + 1));
            parent.child(enumeration ? 4 : 9, range);
        }
    } while (take(lit_str(",")));
    return expect(lit_str(";"));
}
bool Parser::enumeration(Buffer& parent, Str scope, bool nested) {
    if (compiler.enum_count++ >= compiler.limits.enums)
        return fail(SourceError::Kind::Limit, lit_str("enum count"));
    advance();
    Str enum_name{};
    if (!name(enum_name)) return false;
    if (enum_name.len > 1023 || scope.len > 1023 - enum_name.len)
        return fail(SourceError::Kind::Limit, lit_str("name length"));
    const Str kFullName = compiler.join(scope, '.', enum_name);
    auto* named = compiler.arena.alloc_t<NamedMessage>();
    auto* descriptor = compiler.arena.alloc_t<Buffer>(compiler.arena);
    if (!named || !descriptor || !kFullName.ptr) return fail(SourceError::Kind::Allocation, {});
    *named = {kFullName, compiler.messages, true, &source, true};
    compiler.messages = named;
    descriptor->text(1, enum_name);
    if (!expect(lit_str("{"))) return false;
    bool options_seen = false;
    while (!take(lit_str("}"))) {
        if (take(lit_str(";"))) continue;
        if (take(lit_str("option"))) {
            if (options_seen)
                return fail(SourceError::Kind::Syntax, lit_str("duplicate enum option"));
            options_seen = true;
            if (!expect(lit_str("allow_alias")) || !expect(lit_str("="))) return false;
            const bool kAliases = is(lit_str("true"));
            if (!take(lit_str("true")) && !take(lit_str("false")))
                return fail(SourceError::Kind::Syntax, lit_str("boolean"));
            if (!expect(lit_str(";"))) return false;
            Buffer options{compiler.arena};
            options.number(2, kAliases);
            descriptor->child(3, options);
            continue;
        }
        if (is(lit_str("reserved"))) {
            if (!reservation(*descriptor, true)) return false;
            continue;
        }
        if (compiler.enum_value_count++ >= compiler.limits.enum_values)
            return fail(SourceError::Kind::Limit, lit_str("enum value count"));
        Str value_name{};
        u32 magnitude = 0;
        if (!name(value_name) || !expect(lit_str("="))) return false;
        const bool kNegative = take(lit_str("-"));
        if (!number(magnitude)) return false;
        if (magnitude > (kNegative ? 2147483648u : 2147483647u))
            return fail(SourceError::Kind::Syntax, lit_str("enum int32 value"));
        const i64 kValue = kNegative ? -static_cast<i64>(magnitude) : static_cast<i64>(magnitude);
        if (!expect(lit_str(";"))) return false;
        Buffer entry{compiler.arena};
        entry.text(1, value_name);
        entry.number(2, static_cast<u64>(kValue));
        descriptor->child(2, entry);
    }
    auto* chunk = compiler.arena.alloc_t<Chunk>();
    if (!chunk) return fail(SourceError::Kind::Allocation, {});
    chunk->child = descriptor;
    chunk->tag = nested ? 4u : 5u;
    if (parent.tail)
        parent.tail->next = chunk;
    else
        parent.head = chunk;
    parent.tail = chunk;
    return true;
}
bool Parser::message(Buffer& parent, Str scope, u32 depth) {
    if (depth > compiler.limits.depth || compiler.message_count++ >= compiler.limits.messages)
        return fail(SourceError::Kind::Limit, lit_str("message depth/count"));
    advance();
    Str message_name{};
    if (!name(message_name)) return false;
    if (message_name.len > 1023 || scope.len > 1023 - message_name.len)
        return fail(SourceError::Kind::Limit, lit_str("name length"));
    const Str kFullName = compiler.join(scope, '.', message_name);
    auto* named = compiler.arena.alloc_t<NamedMessage>();
    auto* descriptor = compiler.arena.alloc_t<Buffer>(compiler.arena);
    if (!named || !descriptor || !kFullName.ptr) return fail(SourceError::Kind::Allocation, {});
    *named = {kFullName, compiler.messages, true, &source};
    compiler.messages = named;
    descriptor->text(1, message_name);
    if (!expect(lit_str("{"))) return false;
    while (!take(lit_str("}"))) {
        if (token.kind == Token::Kind::End || token.kind == Token::Kind::Bad)
            return fail(SourceError::Kind::Syntax, lit_str("message body"));
        if (take(lit_str(";"))) continue;
        if (is(lit_str("message"))) {
            if (!message(*descriptor, kFullName, depth + 1)) return false;
        } else if (is(lit_str("enum"))) {
            if (!enumeration(*descriptor, kFullName, true)) return false;
        } else if (is(lit_str("reserved"))) {
            if (!reservation(*descriptor, false)) return false;
        } else if (is(lit_str("oneof")) || is(lit_str("extensions")) || is(lit_str("extend")) ||
                   is(lit_str("option")))
            return fail(SourceError::Kind::Unsupported, lit_str("message declaration"));
        else if (!field(*descriptor, kFullName))
            return false;
    }
    // Match protoc: synthetic declarations follow all ordinary declarations.
    // Their names avoid field and synthetic oneof names; descriptor validation
    // rejects collisions with nested types and enum values.
    u32 optional_index = 0;
    for (auto* item = descriptor->head; item; item = item->next) {
        if (item->tag != 2 || !item->child || !item->child->optional) continue;
        if (compiler.field_count++ >= compiler.limits.fields)
            return fail(SourceError::Kind::Limit, lit_str("field/oneof count"));
        auto& field = *item->child;
        Str name = field.declared_name;
        if (!name.len || name.ptr[0] != '_') name = compiler.join({}, '_', name);
        while (descriptor->contains(name)) {
            name = compiler.join({}, 'X', name);
            if (!name.ptr) return fail(SourceError::Kind::Allocation, {});
        }
        if (!name.ptr) return fail(SourceError::Kind::Allocation, {});
        descriptor->symbol(name);
        Buffer oneof{compiler.arena};
        oneof.text(1, name);
        descriptor->child(8, oneof);
        field.number(9, optional_index++);
        field.number(17, 1);
    }
    auto* chunk = compiler.arena.alloc_t<Chunk>();
    if (!chunk) return fail(SourceError::Kind::Allocation, {});
    chunk->child = descriptor;
    chunk->tag = depth == 1 ? 4u : 3u;
    if (parent.tail)
        parent.tail->next = chunk;
    else
        parent.head = chunk;
    parent.tail = chunk;
    return true;
}
bool Parser::service(Buffer& parent, Str scope) {
    if (compiler.service_count++ >= compiler.limits.services)
        return fail(SourceError::Kind::Limit, lit_str("service count"));
    advance();
    Str service_name{};
    if (!name(service_name) || !expect(lit_str("{"))) return false;
    auto* symbol = compiler.arena.alloc_t<NamedMessage>();
    const Str kFullName = compiler.join(scope, '.', service_name);
    if (!symbol || !kFullName.ptr) return fail(SourceError::Kind::Allocation, {});
    *symbol = {kFullName, compiler.messages, false, &source};
    compiler.messages = symbol;
    Buffer descriptor{compiler.arena};
    descriptor.text(1, service_name);
    while (!take(lit_str("}"))) {
        if (take(lit_str(";"))) continue;
        if (!expect(lit_str("rpc"))) return false;
        if (compiler.method_count++ >= compiler.limits.methods)
            return fail(SourceError::Kind::Limit, lit_str("method count"));
        auto* method = compiler.arena.alloc_t<Buffer>(compiler.arena);
        if (!method) return fail(SourceError::Kind::Allocation, {});
        Str method_name{};
        if (!name(method_name) || !expect(lit_str("("))) return false;
        method->text(1, method_name);
        method->number(5, take(lit_str("stream")));
        if (!type_reference(*method, 2, scope) || !expect(lit_str(")")) ||
            !expect(lit_str("returns")) || !expect(lit_str("(")))
            return false;
        method->number(6, take(lit_str("stream")));
        if (!type_reference(*method, 3, scope) || !expect(lit_str(")"))) return false;
        if (!take(lit_str(";"))) {
            if (!expect(lit_str("{"))) return false;
            Buffer options{compiler.arena};
            u32 seen = 0;
            while (!take(lit_str("}"))) {
                if (take(lit_str(";"))) continue;
                if (!expect(lit_str("option"))) return false;
                const bool deprecated = is(lit_str("deprecated"));
                if (!deprecated && !is(lit_str("idempotency_level")))
                    return fail(SourceError::Kind::Unsupported, lit_str("RPC option"));
                const u32 bit = deprecated ? 1u : 2u;
                if (seen & bit)
                    return fail(SourceError::Kind::Syntax, lit_str("duplicate RPC option"));
                seen |= bit;
                advance();
                if (!expect(lit_str("="))) return false;
                u32 value = 0;
                if (deprecated) {
                    value = is(lit_str("true"));
                    if (!take(lit_str("true")) && !take(lit_str("false")))
                        return fail(SourceError::Kind::Syntax, lit_str("RPC option boolean"));
                } else if (take(lit_str("IDEMPOTENCY_UNKNOWN")))
                    value = 0;
                else if (take(lit_str("NO_SIDE_EFFECTS")))
                    value = 1;
                else if (take(lit_str("IDEMPOTENT")))
                    value = 2;
                else
                    return fail(SourceError::Kind::Syntax, lit_str("RPC idempotency_level"));
                options.number(deprecated ? 33 : 34, value);
                if (!expect(lit_str(";"))) return false;
            }
            if (options.size || options.error != Buffer::Error::None) method->child(4, options);
        }
        auto* chunk = compiler.arena.alloc_t<Chunk>();
        if (!chunk) return fail(SourceError::Kind::Allocation, {});
        chunk->child = method;
        chunk->tag = 2;
        if (descriptor.tail)
            descriptor.tail->next = chunk;
        else
            descriptor.head = chunk;
        descriptor.tail = chunk;
    }
    // descriptor lives on stack: move the trivially owning list into arena.
    auto* kept = compiler.arena.alloc_t<Buffer>(descriptor);
    auto* chunk = compiler.arena.alloc_t<Chunk>();
    if (!kept || !chunk) return fail(SourceError::Kind::Allocation, {});
    chunk->child = kept;
    chunk->tag = 6;
    if (parent.tail)
        parent.tail->next = chunk;
    else
        parent.head = chunk;
    parent.tail = chunk;
    return true;
}
bool Parser::file_option(Buffer& options, u32& seen) {
    struct Definition {
        Str name;
        u32 tag;
        u8 type;  // FileOptions descriptor scalar type.
    };
    const Definition kOptions[] = {
        {lit_str("java_package"), 1, 9},
        {lit_str("java_outer_classname"), 8, 9},
        {lit_str("java_multiple_files"), 10, 8},
        {lit_str("java_generate_equals_and_hash"), 20, 8},
        {lit_str("java_string_check_utf8"), 27, 8},
        {lit_str("optimize_for"), 9, 14},
        {lit_str("go_package"), 11, 9},
        {lit_str("cc_generic_services"), 16, 8},
        {lit_str("java_generic_services"), 17, 8},
        {lit_str("py_generic_services"), 18, 8},
        {lit_str("deprecated"), 23, 8},
        {lit_str("cc_enable_arenas"), 31, 8},
        {lit_str("objc_class_prefix"), 36, 9},
        {lit_str("csharp_namespace"), 37, 9},
        {lit_str("swift_prefix"), 39, 9},
        {lit_str("php_class_prefix"), 40, 9},
        {lit_str("php_namespace"), 41, 9},
        // Retained for schemas targeting protoc versions that declared
        // FileOptions.php_generic_services (field 42).
        {lit_str("php_generic_services"), 42, 8},
        {lit_str("php_metadata_namespace"), 44, 9},
        {lit_str("ruby_package"), 45, 9},
    };
    advance();  // option
    for (u32 i = 0; i < sizeof(kOptions) / sizeof(kOptions[0]); ++i) {
        if (!is(kOptions[i].name)) continue;
        if (seen & (1u << i))
            return fail(SourceError::Kind::Syntax, lit_str("duplicate file option"));
        seen |= 1u << i;
        advance();
        if (!expect(lit_str("="))) return false;
        if (kOptions[i].type == 9) {
            Str value{};
            if (!string(value)) return false;
            if (!utf8(value)) return fail(SourceError::Kind::Syntax, lit_str("file option UTF-8"));
            options.text(kOptions[i].tag, value);
        } else if (kOptions[i].type == 8) {
            const bool kTrue = is(lit_str("true"));
            if (!take(lit_str("true")) && !take(lit_str("false")))
                return fail(SourceError::Kind::Syntax, lit_str("file option boolean"));
            options.number(kOptions[i].tag, kTrue);
        } else {
            u32 value = 0;
            if (take(lit_str("SPEED")))
                value = 1;
            else if (take(lit_str("CODE_SIZE")))
                value = 2;
            else if (take(lit_str("LITE_RUNTIME")))
                value = 3;
            else
                return fail(SourceError::Kind::Syntax, lit_str("file optimize_for"));
            options.number(kOptions[i].tag, value);
        }
        return expect(lit_str(";"));
    }
    return fail(SourceError::Kind::Unsupported, lit_str("file option"));
}
bool Parser::file() {
    if (!expect(lit_str("syntax")) || !expect(lit_str("="))) return false;
    Str syntax{};
    if (!string(syntax) || !expect(lit_str(";"))) return false;
    if (!syntax.eq(lit_str("proto3")))
        return fail(SourceError::Kind::Unsupported, lit_str("only proto3 is supported"));
    source.descriptor->text(1, source.name);
    source.descriptor->text(12, syntax);
    bool package_seen = false, declarations = false;
    Buffer options{compiler.arena};
    u32 options_seen = 0;
    while (token.kind != Token::Kind::End) {
        if (take(lit_str(";"))) continue;
        if (take(lit_str("package"))) {
            if (package_seen || declarations)
                return fail(SourceError::Kind::Syntax, lit_str("package ordering"));
            package_seen = true;
            if (!name(source.package, true)) return false;
            if (source.package.ptr[0] == '.')
                return fail(SourceError::Kind::Syntax, lit_str("package name"));
            if (source.package.len > 1023)
                return fail(SourceError::Kind::Limit, lit_str("name length"));
            if (!expect(lit_str(";"))) return false;
            source.descriptor->text(2, source.package);
        } else if (is(lit_str("option"))) {
            if (!file_option(options, options_seen)) return false;
        } else if (take(lit_str("import"))) {
            const bool kPublic = take(lit_str("public"));
            if (is(lit_str("weak")))
                return fail(SourceError::Kind::Unsupported, lit_str("weak imports"));
            Str path{};
            if (!string(path) || !expect(lit_str(";"))) return false;
            if (!compiler.imported_path(path))
                return fail(SourceError::Kind::Syntax, lit_str("import path"));
            if (compiler.root_directory.len &&
                static_cast<u64>(compiler.root_directory.len) + 1 + path.len > 4095)
                return compiler.fail(
                    SourceError::Kind::Limit, source.name, token.line, token.column, {});
            const Str kFullPath = compiler.root_directory.len
                                      ? compiler.join(compiler.root_directory, '/', path)
                                      : compiler.copy(path);
            if (!kFullPath.ptr) return fail(SourceError::Kind::Allocation, {});
            u32 depth = 0;
            for (const Source* item = compiler.sources; item; item = item->next)
                if (item->active) ++depth;
            if (!compiler.load(path, kFullPath, depth)) return false;
            const Source* imported = compiler.sources;
            while (imported && !imported->name.eq(path)) imported = imported->next;
            if (!imported) return fail(SourceError::Kind::Syntax, lit_str("unresolved import"));
            Import* entry = source.imports;
            while (entry && entry->source != imported) entry = entry->next;
            if (!entry) {
                entry = compiler.arena.alloc_t<Import>();
                if (!entry) return fail(SourceError::Kind::Allocation, {});
                *entry = {imported, source.imports, source.import_count++, false};
                source.imports = entry;
                source.descriptor->text(3, path);
            }
            if (kPublic && !entry->is_public) {
                entry->is_public = true;
                source.descriptor->number(10, entry->index);
            }
        } else {
            declarations = true;
            const Str kScope = source.package.len ? compiler.join({}, '.', source.package) : Str{};
            if (source.package.len && !kScope.ptr) return fail(SourceError::Kind::Allocation, {});
            if (is(lit_str("message"))) {
                if (!message(*source.descriptor, kScope, 1)) return false;
            } else if (is(lit_str("enum"))) {
                if (!enumeration(*source.descriptor, kScope, false)) return false;
            } else if (is(lit_str("service"))) {
                if (!service(*source.descriptor, kScope)) return false;
            } else
                return fail(SourceError::Kind::Unsupported, lit_str("proto declaration"));
        }
    }
    if (options.size || options.error != Buffer::Error::None) source.descriptor->child(8, options);
    return true;
}
// Resolve deferred nested buffers bottom-up. Structural depth is bounded by the
// parser's declaration limit; each buffer owns its list, so no shared mutation.
bool finish(Buffer& buffer, u32 depth = 0) {
    if (depth > 36) {
        buffer.error = Buffer::Error::Limit;
        return false;
    }
    if (buffer.error != Buffer::Error::None) return false;
    for (Chunk* chunk = buffer.head; chunk; chunk = chunk->next) {
        if (!chunk->child) continue;
        auto* child = chunk->child;
        const u32 kTag = chunk->tag;
        if (!finish(*child, depth + 1)) {
            buffer.error = child->error;
            return false;
        }
        const u8* bytes = child->flatten();
        if (!bytes) {
            buffer.error = child->error;
            return false;
        }
        Buffer encoded{buffer.arena};
        encoded.add({kTag, 2, 0, bytes, child->size});
        if (encoded.error != Buffer::Error::None || !encoded.head ||
            encoded.head->size > 4 * 1024 * 1024 - buffer.size) {
            buffer.error =
                encoded.error == Buffer::Error::None ? Buffer::Error::Limit : encoded.error;
            return false;
        }
        chunk->child = nullptr;
        chunk->data = encoded.head->data;
        chunk->size = encoded.head->size;
        buffer.size += chunk->size;
    }
    return true;
}
}  // namespace
core::Expected<Schema, SourceError> load_proto_source(Arena<MmapBackend>& arena,
                                                      Str path,
                                                      SchemaLimits limits) {
    Compiler compiler{arena, limits};
    const SchemaLimits kCeiling{};
    if (limits.bytes > kCeiling.bytes || limits.files > kCeiling.files ||
        limits.messages > kCeiling.messages || limits.fields > kCeiling.fields ||
        limits.methods > kCeiling.methods || limits.services > kCeiling.services ||
        limits.depth > kCeiling.depth || limits.enums > kCeiling.enums ||
        limits.enum_values > kCeiling.enum_values || limits.reserved > kCeiling.reserved)
        return core::make_unexpected(SourceError{SourceError::Kind::Limit, {}, 1, 1, {}});
    if (!path.len || path.len > 4095)
        return core::make_unexpected(SourceError{SourceError::Kind::Io, {}, 1, 1, {}});
    for (u32 i = 0; i < path.len; ++i)
        if (!path.ptr[i])
            return core::make_unexpected(SourceError{SourceError::Kind::Io, {}, 1, 1, {}});
    path = compiler.copy(path);
    if (!path.ptr)
        return core::make_unexpected(SourceError{SourceError::Kind::Allocation, {}, 1, 1, {}});
    u32 slash = path.len;
    while (slash && path.ptr[slash - 1] != '/') --slash;
    compiler.root_directory = {path.ptr, slash > 1 ? slash - 1 : slash};
    const Str kName{path.ptr + slash, path.len - slash};
    if (!compiler.load(kName, path, 0) || !compiler.resolve())
        return core::make_unexpected(compiler.error);
    Buffer set{arena};
    for (const Source* file = compiler.sources; file; file = file->next) {
        if (!finish(*file->descriptor))
            return core::make_unexpected(SourceError{
                file->descriptor->error == Buffer::Error::Allocation ? SourceError::Kind::Allocation
                                                                     : SourceError::Kind::Limit,
                file->name,
                1,
                1,
                lit_str("descriptor size")});
        set.child(1, *file->descriptor);
        if (set.error != Buffer::Error::None)
            return core::make_unexpected(SourceError{set.error == Buffer::Error::Allocation
                                                         ? SourceError::Kind::Allocation
                                                         : SourceError::Kind::Limit,
                                                     file->name,
                                                     1,
                                                     1,
                                                     lit_str("descriptor size")});
    }
    const u8* bytes = set.flatten();
    if (!bytes)
        return core::make_unexpected(SourceError{SourceError::Kind::Allocation, {}, 1, 1, {}});
    auto schema = load_descriptor_set(arena, bytes, set.size, limits);
    if (!schema) {
        const SourceError::Kind kKind =
            schema.error() == SchemaError::Allocation ? SourceError::Kind::Allocation
            : schema.error() == SchemaError::Limit    ? SourceError::Kind::Limit
                                                      : SourceError::Kind::Schema;
        return core::make_unexpected(SourceError{kKind,
                                                 compiler.sources ? compiler.sources->name : kName,
                                                 1,
                                                 1,
                                                 lit_str("invalid/unsupported protobuf schema")});
    }
    return schema.value();
}
}  // namespace rut::protobuf
