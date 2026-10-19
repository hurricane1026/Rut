#include "rut/compiler/protobuf_schema.h"

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/protobuf_wire.h"

namespace rut::protobuf {
const Message* Schema::find_message(Str name) const {
    for (const Message* item = messages; item; item = item->next)
        if (item->full_name.eq(name)) return item;
    return nullptr;
}
const Method* Schema::find_method(Str path) const {
    for (const Method* item = methods; item; item = item->next)
        if (item->path.eq(path)) return item;
    return nullptr;
}
namespace {
struct View {
    const u8* data = nullptr;
    u32 size = 0;
};
Str text(const Field& field) {
    return {reinterpret_cast<const char*>(field.bytes), field.size};
}
bool identifier(Str name, bool qualified = false) {
    if (name.len > 1024) return false;
    bool start = true;
    for (u32 i = 0; i < name.len; ++i) {
        const char kChar = name.ptr[i];
        if (qualified && kChar == '.' && !start) {
            start = true;
            continue;
        }
        const bool kLetter = (kChar >= 'a' && kChar <= 'z') || (kChar >= 'A' && kChar <= 'Z');
        const bool kDigit = kChar >= '0' && kChar <= '9';
        if (!kLetter && kChar != '_' && (start || !kDigit)) return false;
        start = false;
    }
    return !start;
}
bool reference(Str name) {
    return name.len > 1 && name.ptr[0] == '.' && identifier({name.ptr + 1, name.len - 1}, true);
}
bool packable(Type type) {
    return type != Type::String && type != Type::Bytes && type != Type::Message;
}
struct Loader {
    Arena<MmapBackend>& arena;
    SchemaLimits limits;
    Schema schema{};
    SchemaError error = SchemaError::Malformed;
    u32 files = 0;
    Str file_names[128]{};
    SchemaFile* schema_files[128]{};
    SchemaFile* current_file = nullptr;
    struct ServiceName {
        Str name{};
        ServiceName* next = nullptr;
    };
    ServiceName* services = nullptr;
    u32 service_count = 0;
    struct PackageName {
        Str name{};
        PackageName* next = nullptr;
    };
    PackageName* packages = nullptr;
    bool declared_symbol(Str name) const {
        if (schema.find_message(name)) return true;
        for (const ServiceName* item = services; item; item = item->next)
            if (item->name.eq(name)) return true;
        return false;
    }
    bool package_used(Str name) const {
        for (const PackageName* item = packages; item; item = item->next)
            if (item->name.eq(name)) return true;
        return false;
    }
    bool register_package(Str package) {
        for (u32 i = 0; i <= package.len; ++i) {
            if (i != package.len && package.ptr[i] != '.') continue;
            Str part = {package.ptr, i};
            Str symbol = join({}, '.', part);
            if (!symbol.ptr || declared_symbol(symbol)) return false;
            if (package_used(symbol)) continue;
            auto* item = arena.alloc_t<PackageName>();
            if (!item) return fail(SchemaError::Allocation);
            item->name = symbol;
            item->next = packages;
            packages = item;
        }
        return true;
    }
    bool symbol_used(Str name) const {
        if (schema.find_message(name)) return true;
        for (const ServiceName* item = services; item; item = item->next)
            if (item->name.eq(name)) return true;
        if (package_used(name)) return true;
        return false;
    }
    bool fail(SchemaError reason) {
        error = reason;
        return false;
    }
    bool malformed() { return fail(SchemaError::Malformed); }
    bool wire(const Field& field, u8 expected) { return field.wire == expected || malformed(); }
    Str join(Str prefix, char separator, Str suffix) {
        const u64 kSize = static_cast<u64>(prefix.len) + 1 + suffix.len;
        if (kSize > 1024) {
            fail(SchemaError::Limit);
            return {};
        }
        auto* result = static_cast<char*>(arena.alloc(kSize));
        if (!result) {
            fail(SchemaError::Allocation);
            return {};
        }
        if (prefix.len) __builtin_memcpy(result, prefix.ptr, prefix.len);
        result[prefix.len] = separator;
        if (suffix.len) __builtin_memcpy(result + prefix.len + 1, suffix.ptr, suffix.len);
        return {result, static_cast<u32>(kSize)};
    }
    bool read_bool(const Field& field, bool& value) {
        if (!wire(field, 0) || field.value > 1) return malformed();
        value = field.value != 0;
        return true;
    }
    bool options(View view, bool message_options, bool& packed, bool& explicit_packed) {
        Reader reader(view.data, view.size);
        Field field;
        Status status;
        while ((status = reader.next(field)) == Status::Field) {
            if (message_options && field.number == 7) {
                bool map = false;
                if (!read_bool(field, map)) return false;
                if (map) return fail(SchemaError::Unsupported);
            } else if (!message_options && field.number == 2) {
                if (explicit_packed) return fail(SchemaError::Duplicate);
                explicit_packed = true;
                if (!read_bool(field, packed)) return false;
            }
        }
        return status == Status::End || malformed();
    }
    bool field(View view, Message& owner) {
        if (schema.field_count >= limits.fields) return fail(SchemaError::Limit);
        auto* item = arena.alloc_t<SchemaField>();
        if (!item) return fail(SchemaError::Allocation);
        Reader reader(view.data, view.size);
        Field part;
        Status status;
        u32 seen = 0;
        u64 label = 0;
        bool explicit_packed = false;
        while ((status = reader.next(part)) == Status::Field) {
            if (part.number <= 10 || part.number == 17) {
                const u32 kBit = 1u << part.number;
                if (seen & kBit) return fail(SchemaError::Duplicate);
                seen |= kBit;
            }
            switch (part.number) {
                case 1:
                    if (!wire(part, 2)) return false;
                    item->name = text(part);
                    break;
                case 3:
                    if (!wire(part, 0) || !part.value || part.value > 0x1fffffff ||
                        (part.value >= 19000 && part.value <= 19999))
                        return malformed();
                    item->number = static_cast<u32>(part.value);
                    break;
                case 4:
                    if (!wire(part, 0)) return false;
                    label = part.value;
                    break;
                case 5:
                    if (!wire(part, 0) || !part.value || part.value > 18) return malformed();
                    item->type = static_cast<Type>(part.value);
                    break;
                case 6:
                    if (!wire(part, 2)) return false;
                    item->type_name = text(part);
                    break;
                case 8:
                    if (!wire(part, 2) ||
                        !options({part.bytes, part.size}, false, item->packed, explicit_packed))
                        return false;
                    break;
                case 10:
                    if (!wire(part, 2)) return false;
                    item->json_name = text(part);
                    break;
                case 2:
                case 7:
                case 9:
                    return fail(SchemaError::Unsupported);
                case 17:
                    if (!wire(part, 0) || part.value > 1) return malformed();
                    if (part.value) return fail(SchemaError::Unsupported);
                    break;
                default:
                    break;
            }
        }
        if (status != Status::End || !(seen & (1u << 5)) || !identifier(item->name) ||
            !item->number || (label != 1 && label != 3))
            return malformed();
        if (item->type == Type::Group || item->type == Type::Enum)
            return fail(SchemaError::Unsupported);
        if (item->type == Type::Message) {
            if (!reference(item->type_name)) return malformed();
        } else if (item->type_name.len)
            return malformed();
        item->repeated = label == 3;
        if (explicit_packed && item->packed && (!item->repeated || !packable(item->type)))
            return malformed();
        if (!explicit_packed) item->packed = item->repeated && packable(item->type);
        if (!item->json_name.ptr) {
            auto* name = static_cast<char*>(arena.alloc(item->name.len));
            if (!name) return fail(SchemaError::Allocation);
            bool upper = false;
            u32 length = 0;
            for (u32 i = 0; i < item->name.len; ++i) {
                char c = item->name.ptr[i];
                if (c == '_') {
                    upper = true;
                    continue;
                }
                if (upper && c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
                upper = false;
                name[length++] = c;
            }
            item->json_name = {name, length};
        }
        if (!identifier(item->json_name)) return malformed();
        for (auto* old = owner.fields; old; old = old->next)
            if (old->number == item->number || old->name.eq(item->name) ||
                old->json_name.eq(item->json_name) || old->name.eq(item->json_name) ||
                old->json_name.eq(item->name))
                return fail(SchemaError::Duplicate);
        item->next = owner.fields;
        item->file = current_file;
        owner.fields = item;
        ++schema.field_count;
        return true;
    }
    bool message(View view, Str scope, u32 depth) {
        if (depth > limits.depth || schema.message_count >= limits.messages)
            return fail(SchemaError::Limit);
        Str name{};
        Reader names(view.data, view.size);
        Field part;
        Status status;
        bool seen_name = false;
        while ((status = names.next(part)) == Status::Field) {
            if (part.number == 1) {
                if (seen_name) return fail(SchemaError::Duplicate);
                seen_name = true;
                if (!wire(part, 2)) return false;
                name = text(part);
            }
        }
        if (status != Status::End || !identifier(name)) return malformed();
        const Str kFullName = join(scope, '.', name);
        if (!kFullName.ptr) return false;
        if (symbol_used(kFullName)) return fail(SchemaError::Duplicate);
        auto* item = arena.alloc_t<Message>();
        if (!item) return fail(SchemaError::Allocation);
        item->full_name = kFullName;
        item->file = current_file;
        item->next = schema.messages;
        schema.messages = item;
        ++schema.message_count;
        Reader reader(view.data, view.size);
        while ((status = reader.next(part)) == Status::Field) {
            switch (part.number) {
                case 2:
                    if (!wire(part, 2) || !field({part.bytes, part.size}, *item)) return false;
                    break;
                case 3:
                    if (!wire(part, 2) || !message({part.bytes, part.size}, kFullName, depth + 1))
                        return false;
                    break;
                case 4:
                case 5:
                case 6:
                case 8:
                case 9:
                case 10:
                    return fail(SchemaError::Unsupported);
                case 7: {
                    bool packed = false;
                    bool explicit_packed = false;
                    if (!wire(part, 2) ||
                        !options({part.bytes, part.size}, true, packed, explicit_packed))
                        return false;
                    break;
                }
                default:
                    break;
            }
        }
        if (status != Status::End) return malformed();
        for (const auto* field = item->fields; field; field = field->next) {
            const Str field_symbol = join(item->full_name, '.', field->name);
            if (!field_symbol.ptr) return false;
            if (schema.find_message(field_symbol)) return fail(SchemaError::Duplicate);
        }
        return true;
    }
    bool method(View view, Str service) {
        if (schema.method_count >= limits.methods) return fail(SchemaError::Limit);
        auto* item = arena.alloc_t<Method>();
        if (!item) return fail(SchemaError::Allocation);
        Str name{};
        u32 seen = 0;
        Reader reader(view.data, view.size);
        Field part;
        Status status;
        while ((status = reader.next(part)) == Status::Field) {
            if (part.number >= 1 && part.number <= 6) {
                const u32 kBit = 1u << part.number;
                if (seen & kBit) return fail(SchemaError::Duplicate);
                seen |= kBit;
            }
            if (part.number >= 1 && part.number <= 3) {
                if (!wire(part, 2)) return false;
                if (part.number == 1)
                    name = text(part);
                else if (part.number == 2)
                    item->input_name = text(part);
                else
                    item->output_name = text(part);
            } else if (part.number == 5) {
                if (!read_bool(part, item->client_streaming)) return false;
            } else if (part.number == 6) {
                if (!read_bool(part, item->server_streaming)) return false;
            }
        }
        if (status != Status::End || !identifier(name) || !reference(item->input_name) ||
            !reference(item->output_name))
            return malformed();
        item->path = join(service, '/', name);
        if (!item->path.ptr) return false;
        if (schema.find_method(item->path)) return fail(SchemaError::Duplicate);
        item->next = schema.methods;
        item->file = current_file;
        schema.methods = item;
        ++schema.method_count;
        return true;
    }
    bool service(View view, Str package) {
        Str name{};
        Reader names(view.data, view.size);
        Field part;
        Status status;
        bool seen_name = false;
        while ((status = names.next(part)) == Status::Field) {
            if (part.number == 1) {
                if (seen_name) return fail(SchemaError::Duplicate);
                seen_name = true;
                if (!wire(part, 2)) return false;
                name = text(part);
            }
        }
        if (status != Status::End || !identifier(name)) return malformed();
        if (service_count >= limits.services) return fail(SchemaError::Limit);
        const Str kQualified = package.len ? join(package, '.', name) : name;
        if (!kQualified.ptr) return false;
        const Str kSymbol = join({}, '.', kQualified);
        if (!kSymbol.ptr) return false;
        if (symbol_used(kSymbol)) return fail(SchemaError::Duplicate);
        auto* service_name = arena.alloc_t<ServiceName>();
        if (!service_name) return fail(SchemaError::Allocation);
        service_name->name = kSymbol;
        service_name->next = services;
        services = service_name;
        ++service_count;
        const Str kPath = join({}, '/', kQualified);
        if (!kPath.ptr) return false;
        Reader reader(view.data, view.size);
        while ((status = reader.next(part)) == Status::Field) {
            if (part.number == 2 && (!wire(part, 2) || !method({part.bytes, part.size}, kPath)))
                return false;
        }
        return status == Status::End || malformed();
    }
    bool file(View view) {
        if (files >= limits.files || files >= 128) return fail(SchemaError::Limit);
        Str name{}, package{}, syntax{};
        u32 seen = 0;
        Reader header(view.data, view.size);
        Field part;
        Status status;
        while ((status = header.next(part)) == Status::Field) {
            if (part.number == 1 || part.number == 2 || part.number == 12) {
                const u32 kBit = 1u << part.number;
                if (seen & kBit) return fail(SchemaError::Duplicate);
                seen |= kBit;
                if (!wire(part, 2)) return false;
                if (part.number == 1)
                    name = text(part);
                else if (part.number == 2)
                    package = text(part);
                else
                    syntax = text(part);
            }
        }
        if (status != Status::End || !name.len || (package.len && !identifier(package, true)))
            return malformed();
        if (!syntax.eq(lit_str("proto3"))) return fail(SchemaError::Unsupported);
        for (u32 i = 0; i < files; ++i)
            if (file_names[i].eq(name)) return fail(SchemaError::Duplicate);
        if (package.len) {
            for (u32 i = 0; i <= package.len; ++i) {
                if (i != package.len && package.ptr[i] != '.') continue;
                Str part = {package.ptr, i};
                Str symbol = join({}, '.', part);
                if (!symbol.ptr) return false;
                if (declared_symbol(symbol)) return fail(SchemaError::Duplicate);
            }
            // Register after checking all prefixes so a package's own prefixes
            // are visible to declarations in this and later files.
            if (!register_package(package)) return false;
        }
        auto* schema_file = arena.alloc_t<SchemaFile>();
        if (!schema_file) return fail(SchemaError::Allocation);
        schema_file->name = name;
        schema_file->dependencies = static_cast<Str*>(arena.alloc(sizeof(Str) * limits.files));
        schema_file->public_dependencies = static_cast<u8*>(arena.alloc(limits.files));
        if (!schema_file->dependencies || !schema_file->public_dependencies)
            return fail(SchemaError::Allocation);
        for (u32 i = 0; i < limits.files; ++i) schema_file->public_dependencies[i] = 0;
        schema_files[files] = schema_file;
        file_names[files++] = name;
        const Str kScope = package.len ? join({}, '.', package) : Str{};
        if (package.len && !kScope.ptr) return false;
        Reader reader(view.data, view.size);
        u64 public_indexes[128]{};
        u32 public_index_count = 0;
        while ((status = reader.next(part)) == Status::Field) {
            if (part.number == 3) {
                if (!wire(part, 2) || schema_file->dependency_count >= limits.files)
                    return fail(SchemaError::Limit);
                schema_file->dependencies[schema_file->dependency_count++] = text(part);
            } else if (part.number == 10) {
                if (!wire(part, 0) || public_index_count >= limits.files)
                    return fail(SchemaError::Limit);
                public_indexes[public_index_count++] = part.value;
            }
        }
        if (status != Status::End) return malformed();
        for (u32 i = 0; i < public_index_count; ++i) {
            if (public_indexes[i] >= schema_file->dependency_count) return malformed();
            schema_file->public_dependencies[static_cast<u32>(public_indexes[i])] = 1;
        }
        current_file = schema_file;
        reader = Reader(view.data, view.size);
        while ((status = reader.next(part)) == Status::Field) {
            switch (part.number) {
                case 4:
                    if (!wire(part, 2) || !message({part.bytes, part.size}, kScope, 1))
                        return false;
                    break;
                case 6:
                    if (!wire(part, 2) || !service({part.bytes, part.size}, package)) return false;
                    break;
                case 5:
                case 7:
                case 11:
                case 14:
                    return fail(SchemaError::Unsupported);
                default:
                    break;
            }
        }
        current_file = nullptr;
        return status == Status::End || malformed();
    }
    bool resolve() {
        auto find_file = [&](Str name) -> const SchemaFile* {
            for (u32 i = 0; i < files; ++i)
                if (schema_files[i]->name.eq(name)) return schema_files[i];
            return nullptr;
        };
        u8 colors[128]{};
        auto acyclic = [&](const SchemaFile* file, auto&& self) -> bool {
            u32 index = 0;
            while (index < files && schema_files[index] != file) ++index;
            if (index == files) return true;
            if (colors[index] == 1) return false;
            if (colors[index] == 2) return true;
            colors[index] = 1;
            for (u32 i = 0; i < file->dependency_count; ++i) {
                const SchemaFile* dependency = find_file(file->dependencies[i]);
                if (dependency && !self(dependency, self)) return false;
            }
            colors[index] = 2;
            return true;
        };
        for (u32 i = 0; i < files; ++i)
            if (!acyclic(schema_files[i], acyclic)) return fail(SchemaError::Malformed);
        bool visited[128]{};
        auto public_visible =
            [&](const SchemaFile* from, const SchemaFile* target, auto&& self, u32 depth) -> bool {
            if (from == target) return true;
            if (!from || !target || depth > files) return false;
            for (u32 i = 0; i < files; ++i)
                if (schema_files[i] == from) {
                    if (visited[i]) return false;
                    visited[i] = true;
                    break;
                }
            for (u32 i = 0; i < from->dependency_count; ++i) {
                if (!from->public_dependencies[i]) continue;
                const SchemaFile* dependency = find_file(from->dependencies[i]);
                if (dependency && self(dependency, target, self, depth + 1)) return true;
            }
            return false;
        };
        auto visible = [&](const SchemaFile* from, const SchemaFile* target, u32 depth) -> bool {
            if (from == target) return true;
            if (!from || !target || depth > files) return false;
            for (u32 i = 0; i < files; ++i) visited[i] = false;
            for (u32 i = 0; i < from->dependency_count; ++i) {
                const SchemaFile* dependency = find_file(from->dependencies[i]);
                if (dependency == target ||
                    (dependency && public_visible(dependency, target, public_visible, depth + 1)))
                    return true;
            }
            return false;
        };
        for (auto* item = schema.messages; item; item = item->next)
            for (auto* member = item->fields; member; member = member->next) {
                if (member->type != Type::Message) continue;
                member->message = schema.find_message(member->type_name);
                if (!member->message) return fail(SchemaError::Unresolved);
                if (!visible(member->file, member->message->file, 0))
                    return fail(SchemaError::Unresolved);
            }
        for (auto* item = schema.methods; item; item = item->next) {
            item->input = schema.find_message(item->input_name);
            item->output = schema.find_message(item->output_name);
            if (!item->input || !item->output) return fail(SchemaError::Unresolved);
            if (!visible(item->file, item->input->file, 0) ||
                !visible(item->file, item->output->file, 0))
                return fail(SchemaError::Unresolved);
        }
        return true;
    }
};
}  // namespace
core::Expected<Schema, SchemaError> load_descriptor_set(Arena<MmapBackend>& arena,
                                                        const u8* data,
                                                        u32 size,
                                                        SchemaLimits limits) {
    const SchemaLimits kCeiling{};
    if (limits.bytes > kCeiling.bytes || limits.files > kCeiling.files ||
        limits.messages > kCeiling.messages || limits.fields > kCeiling.fields ||
        limits.methods > kCeiling.methods || limits.services > kCeiling.services ||
        limits.depth > kCeiling.depth)
        return core::make_unexpected(SchemaError::Limit);
    if (!size || !data) return core::make_unexpected(SchemaError::Malformed);
    if (size > limits.bytes) return core::make_unexpected(SchemaError::Limit);
    auto* copy = static_cast<u8*>(arena.alloc(size));
    if (!copy) return core::make_unexpected(SchemaError::Allocation);
    __builtin_memcpy(copy, data, size);
    Loader loader{arena, limits};
    Reader reader(copy, size);
    Field field;
    Status status;
    while ((status = reader.next(field)) == Status::Field) {
        if (field.number == 1 &&
            (!loader.wire(field, 2) || !loader.file({field.bytes, field.size})))
            return core::make_unexpected(loader.error);
    }
    if (status != Status::End || !loader.files)
        return core::make_unexpected(SchemaError::Malformed);
    if (!loader.resolve()) return core::make_unexpected(loader.error);
    return loader.schema;
}
}  // namespace rut::protobuf
