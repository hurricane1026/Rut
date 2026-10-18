#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/compiler/protobuf_schema.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/protobuf_wire.h"
#include "test.h"

#include <string.h>

using namespace rut;
using namespace rut::protobuf;

#include "protobuf/schema_descriptor.inc"

namespace {
struct CompileArena {
    Arena<MmapBackend> arena;
    CompileArena() { (void)arena.init(4096); }
    ~CompileArena() { arena.destroy(); }
};
struct Bytes {
    u8 data[8192]{};
    u32 size = 0;
    bool ok = true;
    void add(Field field) {
        Writer writer(data + size, sizeof(data) - size);
        ok = writer.write(field) && ok;
        size += writer.size();
    }
    void number(u32 tag, u64 value) { add({tag, 0, value}); }
    void text(u32 tag, Str value) {
        add({tag, 2, 0, reinterpret_cast<const u8*>(value.ptr), value.len});
    }
    void child(u32 tag, const Bytes& value) {
        ok = ok && value.ok;
        add({tag, 2, 0, value.data, value.size});
    }
};
Bytes member(Str name = lit_str("value"), u32 number = 1, u32 type = 9, u32 label = 1) {
    Bytes out;
    out.text(1, name);
    out.number(3, number);
    out.number(4, label);
    out.number(5, type);
    return out;
}
Bytes message(const Bytes& field) {
    Bytes out;
    out.text(1, lit_str("Item"));
    out.child(2, field);
    return out;
}
Bytes file(const Bytes& msg, Str syntax = lit_str("proto3")) {
    Bytes out;
    out.text(1, lit_str("test.proto"));
    out.text(2, lit_str("example"));
    out.text(12, syntax);
    out.child(4, msg);
    return out;
}
Bytes descriptor(const Bytes& msg, Str syntax = lit_str("proto3")) {
    Bytes out;
    out.child(1, file(msg, syntax));
    return out;
}
const SchemaField* find_field(const Message& owner, Str name) {
    for (const auto* item = owner.fields; item; item = item->next)
        if (item->name.eq(name)) return item;
    return nullptr;
}
}  // namespace

TEST(protobuf_schema, protoc_descriptor_resolves_imports_nested_recursion_and_all_rpc_shapes) {
    CompileArena storage;
    auto result = load_descriptor_set(storage.arena, kDescriptor, sizeof(kDescriptor));
    REQUIRE(result.has_value());
    const Schema& schema = result.value();
    CHECK_EQ(schema.message_count, 3u);
    CHECK_EQ(schema.field_count, 23u);
    CHECK_EQ(schema.method_count, 4u);
    const auto* request = schema.find_message(lit_str(".test.gateway.Request"));
    const auto* child = schema.find_message(lit_str(".test.gateway.Request.Child"));
    const auto* payload = schema.find_message(lit_str(".test.shared.Payload"));
    REQUIRE(request && child && payload);
    REQUIRE(find_field(*child, lit_str("parent")));
    CHECK(find_field(*child, lit_str("parent"))->message == request);
    REQUIRE(find_field(*request, lit_str("child")));
    CHECK(find_field(*request, lit_str("child"))->message == child);
    REQUIRE(find_field(*request, lit_str("payload")));
    CHECK(find_field(*request, lit_str("payload"))->message == payload);
    const Str kMethods[] = {lit_str("/test.gateway.Gateway/Unary"),
                            lit_str("/test.gateway.Gateway/ServerStream"),
                            lit_str("/test.gateway.Gateway/ClientStream"),
                            lit_str("/test.gateway.Gateway/Chat")};
    for (u32 i = 0; i < 4; ++i) {
        const auto* method = schema.find_method(kMethods[i]);
        REQUIRE(method);
        CHECK(method->input == request);
        CHECK(method->output == payload);
        CHECK_EQ(method->client_streaming, (i & 2) != 0);
        CHECK_EQ(method->server_streaming, (i & 1) != 0);
    }
    CHECK_FALSE(schema.find_message(lit_str("Request")));
    CHECK_FALSE(schema.find_method(lit_str("/unknown")));
}

TEST(protobuf_schema, scalar_types_json_names_and_packing_match_protoc) {
    CompileArena storage;
    auto result = load_descriptor_set(storage.arena, kDescriptor, sizeof(kDescriptor));
    REQUIRE(result.has_value());
    const auto* request = result->find_message(lit_str(".test.gateway.Request"));
    REQUIRE(request);
    const Type kTypes[] = {
        Type::String,   Type::Double,  Type::Float,  Type::Int64,   Type::Uint64,  Type::Int32,
        Type::Fixed64,  Type::Fixed32, Type::Bool,   Type::Bytes,   Type::Uint32,  Type::Sfixed32,
        Type::Sfixed64, Type::Sint32,  Type::Sint64, Type::Message, Type::Message, Type::Sint64,
        Type::Int32,    Type::String,  Type::String};
    u32 count = 0;
    for (const auto* field = request->fields; field; field = field->next) {
        REQUIRE(field->number > 0 && field->number <= 21);
        CHECK(field->type == kTypes[field->number - 1]);
        CHECK_EQ(field->repeated, field->number >= 18 && field->number <= 20);
        CHECK_EQ(field->packed, field->number == 18);
        if (field->number == 1) CHECK(field->json_name.eq(lit_str("displayName")));
        if (field->number == 21) CHECK(field->json_name.eq(lit_str("customAlias")));
        ++count;
    }
    CHECK_EQ(count, 21u);
}

TEST(protobuf_schema, arena_owns_input_and_derived_names) {
    CompileArena storage;
    Bytes input = descriptor(message(member(lit_str("display_name"))));
    REQUIRE(input.ok);
    auto result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE(result.has_value());
    memset(input.data, 0xff, sizeof(input.data));
    const auto* item = result->find_message(lit_str(".example.Item"));
    REQUIRE(item && item->fields);
    CHECK(item->fields->name.eq(lit_str("display_name")));
    CHECK(item->fields->json_name.eq(lit_str("displayName")));
}

TEST(protobuf_schema, malformed_wire_and_incomplete_descriptors_fail_closed) {
    CompileArena storage;
    CHECK_FALSE(load_descriptor_set(storage.arena, nullptr, 1));
    CHECK_FALSE(load_descriptor_set(storage.arena, nullptr, 0));
    const u8 kMalformed[][4] = {{0}, {0x0a, 0x7f}, {0x08, 1}, {0x0a, 1, 0}};
    const u32 kSizes[] = {1, 2, 2, 3};
    for (u32 i = 0; i < 4; ++i) {
        auto result = load_descriptor_set(storage.arena, kMalformed[i], kSizes[i]);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == SchemaError::Malformed);
    }
    const Bytes kEmptyMessage;
    Bytes input = descriptor(kEmptyMessage);
    auto result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == SchemaError::Malformed);
}

TEST(protobuf_schema, field_number_type_label_and_identifier_validation) {
    CompileArena storage;
    const Bytes kInvalid[] = {member(lit_str("a"), 0),
                              member(lit_str("a"), 19000),
                              member(lit_str("a"), 19999),
                              member(lit_str("a"), 0x20000000),
                              member(lit_str("a"), 1, 0),
                              member(lit_str("a"), 1, 19),
                              member(lit_str("a"), 1, 9, 2),
                              member(lit_str("a"), 1, 9, 4),
                              member(lit_str("1bad")),
                              member(lit_str("bad.name"))};
    for (const auto& field : kInvalid) {
        Bytes input = descriptor(message(field));
        REQUIRE(input.ok);
        auto result = load_descriptor_set(storage.arena, input.data, input.size);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == SchemaError::Malformed);
    }
}

TEST(protobuf_schema, unsupported_schema_semantics_are_not_silently_dropped) {
    CompileArena storage;
    const u32 kTypes[] = {10u, 14u};
    for (const u32 kType : kTypes) {
        Bytes input = descriptor(message(member(lit_str("a"), 1, kType)));
        auto result = load_descriptor_set(storage.arena, input.data, input.size);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == SchemaError::Unsupported);
    }
    const u32 kFieldTags[] = {2u, 7u, 9u, 17u};
    for (const u32 kTag : kFieldTags) {
        Bytes field = member();
        field.number(kTag, 0);
        Bytes input = descriptor(message(field));
        auto result = load_descriptor_set(storage.arena, input.data, input.size);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == SchemaError::Unsupported);
    }
    Bytes input = descriptor(message(member()), lit_str("proto2"));
    auto result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == SchemaError::Unsupported);
    const u32 kMessageTags[] = {4u, 5u, 6u, 8u};
    for (const u32 kTag : kMessageTags) {
        Bytes msg = message(member());
        const Bytes kEmpty;
        msg.child(kTag, kEmpty);
        input = descriptor(msg);
        result = load_descriptor_set(storage.arena, input.data, input.size);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == SchemaError::Unsupported);
    }
    Bytes options;
    options.number(7, 1);
    Bytes msg = message(member());
    msg.child(7, options);
    input = descriptor(msg);
    result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == SchemaError::Unsupported);
}

TEST(protobuf_schema, duplicates_and_json_alias_collisions_are_rejected) {
    CompileArena storage;
    for (u32 kind = 0; kind < 4; ++kind) {
        const Bytes kFirst = member(lit_str("display_name"));
        Bytes second =
            member(kind == 1 ? lit_str("display_name") : lit_str("other"), kind == 0 ? 1 : 2);
        if (kind == 2) second.text(10, lit_str("displayName"));
        if (kind == 3) second.text(10, lit_str("display_name"));
        Bytes msg = message(kFirst);
        msg.child(2, second);
        Bytes input = descriptor(msg);
        auto result = load_descriptor_set(storage.arena, input.data, input.size);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == SchemaError::Duplicate);
    }
    const Bytes kMessage = message(member());
    Bytes input;
    const Bytes kFile = file(kMessage);
    input.child(1, kFile);
    input.child(1, kFile);
    auto result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == SchemaError::Duplicate);
    Bytes duplicate = member();
    duplicate.number(3, 2);
    input = descriptor(message(duplicate));
    result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == SchemaError::Duplicate);
}

TEST(protobuf_schema, references_require_included_fully_qualified_messages) {
    CompileArena storage;
    const Str kNames[] = {lit_str(".example.Missing"), lit_str("Item"), lit_str(".bad..Name")};
    for (u32 i = 0; i < 3; ++i) {
        Bytes field = member(lit_str("value"), 1, 11);
        field.text(6, kNames[i]);
        Bytes input = descriptor(message(field));
        auto result = load_descriptor_set(storage.arena, input.data, input.size);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == (i == 0 ? SchemaError::Unresolved : SchemaError::Malformed));
    }
}

TEST(protobuf_schema, resource_limits_and_arena_failure_are_explicit) {
    Bytes input = descriptor(message(member()));
    const SchemaLimits kLimits[] = {{input.size - 1},
                                    {4096, 0},
                                    {4096, 1, 0},
                                    {4096, 1, 1, 0},
                                    {4096, 1, 1, 1, 0, 0},
                                    {4096, 129},
                                    {4096, 1, 1, 1, 1, 33}};
    for (const auto& limits : kLimits) {
        CompileArena storage;
        auto result = load_descriptor_set(storage.arena, input.data, input.size, limits);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == SchemaError::Limit);
    }
    Arena<MmapBackend> uninitialized;
    auto result = load_descriptor_set(uninitialized, input.data, input.size);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == SchemaError::Allocation);
}

TEST(protobuf_schema, nesting_limit_bounds_real_recursion) {
    Bytes nested = message(member());
    for (u32 depth = 1; depth <= 33; ++depth) {
        Bytes input = descriptor(nested);
        REQUIRE(input.ok);
        CompileArena storage;
        auto result = load_descriptor_set(storage.arena, input.data, input.size);
        if (depth <= 32) {
            REQUIRE(result.has_value());
            CHECK_EQ(result->message_count, depth);
        } else {
            REQUIRE_FALSE(result.has_value());
            CHECK(result.error() == SchemaError::Limit);
        }
        Bytes outer;
        outer.text(1, lit_str("Item"));
        outer.child(3, nested);
        nested = outer;
    }
}

TEST(protobuf_schema, duplicate_services_types_and_methods_are_rejected) {
    const u32 kCases[] = {0, 1, 2, 3};
    for (const u32 kCase : kCases) {
        Bytes method;
        method.text(1, lit_str("Call"));
        method.text(2, lit_str(".example.Item"));
        method.text(3, lit_str(".example.Item"));
        Bytes service;
        service.text(1, kCase == 0 ? lit_str("Item") : lit_str("Service"));
        if (kCase >= 2) service.child(2, method);
        if (kCase == 2) service.child(2, method);
        Bytes source = file(message(member()));
        source.child(6, service);
        if (kCase == 1) source.child(6, service);
        if (kCase == 3) source.child(4, message(member()));
        Bytes input;
        input.child(1, source);
        CompileArena storage;
        auto result = load_descriptor_set(storage.arena, input.data, input.size);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == SchemaError::Duplicate);
    }
}

TEST(protobuf_schema, packed_options_and_method_references_are_validated) {
    for (u32 kind = 0; kind < 5; ++kind) {
        Bytes field = member(lit_str("value"), 1, kind == 0 ? 9 : 5, kind == 1 ? 1 : 3);
        Bytes options;
        options.number(2, kind == 2 ? 2 : 1);
        if (kind == 3) options.number(2, 0);
        field.child(8, options);
        Bytes source = file(message(field));
        if (kind == 4) {
            source = file(message(member()));
            Bytes method;
            method.text(1, lit_str("Call"));
            method.text(2, lit_str(".example.Item"));
            method.text(3, lit_str(".example.Missing"));
            Bytes service;
            service.text(1, lit_str("Service"));
            service.child(2, method);
            source.child(6, service);
        }
        Bytes input;
        input.child(1, source);
        CompileArena storage;
        auto result = load_descriptor_set(storage.arena, input.data, input.size);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == (kind == 4   ? SchemaError::Unresolved
                                 : kind == 3 ? SchemaError::Duplicate
                                             : SchemaError::Malformed));
    }
}

TEST(protobuf_schema, mutated_real_descriptors_preserve_valid_schema_invariants) {
    CompileArena storage;
    u32 state = 0x87654321;
    for (u32 iteration = 0; iteration < 2000; ++iteration) {
        u8 input[sizeof(kDescriptor)];
        memcpy(input, kDescriptor, sizeof(input));
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        input[state % sizeof(input)] ^= static_cast<u8>((state >> 16) | 1);
        const u32 kSize = iteration < 1000 ? iteration % sizeof(input) : sizeof(input);
        auto result = load_descriptor_set(storage.arena, input, kSize);
        if (result) {
            CHECK(result->message_count <= 1024);
            CHECK(result->field_count <= 16384);
            for (const auto* method = result->methods; method; method = method->next)
                CHECK(method->input && method->output);
            for (const auto* owner = result->messages; owner; owner = owner->next)
                for (const auto* field = owner->fields; field; field = field->next)
                    if (field->type == Type::Message) CHECK(field->message);
        }
        storage.arena.reset();
    }
}

TEST(protobuf_schema, review_limits_packing_namespaces_and_import_visibility) {
    // Explicit false is legal even when the field cannot be packed; true remains
    // legal only for repeated packable scalar fields.
    Bytes false_options;
    false_options.number(2, 0);
    Bytes unpackable = member(lit_str("text"), 1, 9, 3);
    unpackable.child(8, false_options);
    Bytes input = descriptor(message(unpackable));
    CompileArena storage;
    auto result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE(result.has_value());
    CHECK_FALSE(result->find_message(lit_str(".example.Item"))->fields->packed);

    Bytes singular = member(lit_str("number"), 1, 5, 1);
    singular.child(8, false_options);
    input = descriptor(message(singular));
    storage.arena.reset();
    result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE(result.has_value());

    Bytes true_options;
    true_options.number(2, 1);
    Bytes invalid_true = member(lit_str("text"), 1, 9, 3);
    invalid_true.child(8, true_options);
    input = descriptor(message(invalid_true));
    storage.arena.reset();
    result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == SchemaError::Malformed);

    Bytes packed = member(lit_str("value"), 1, 5, 3);
    packed.child(8, true_options);
    input = descriptor(message(packed));
    storage.arena.reset();
    result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE(result.has_value());
    CHECK(result->find_message(lit_str(".example.Item"))->fields->packed);

    Bytes empty_service;
    empty_service.text(1, lit_str("Service"));
    Bytes service_file;
    service_file.text(1, lit_str("service.proto"));
    service_file.text(12, lit_str("proto3"));
    service_file.child(6, empty_service);
    Bytes services;
    services.child(1, service_file);
    storage.arena.reset();
    SchemaLimits no_services{};
    no_services.services = 0;
    result = load_descriptor_set(storage.arena, services.data, services.size, no_services);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == SchemaError::Limit);

    auto make_file = [](Str name, Str package, Str message_name, Str dependency = {}) {
        Bytes msg;
        msg.text(1, message_name);
        Bytes file;
        file.text(1, name);
        if (package.len) file.text(2, package);
        if (dependency.len) file.text(3, dependency);
        file.text(12, lit_str("proto3"));
        file.child(4, msg);
        return file;
    };
    auto make_set = [](const Bytes& first, const Bytes& second) {
        Bytes set;
        set.child(1, first);
        set.child(1, second);
        return set;
    };
    for (u32 order = 0; order < 2; ++order) {
        Bytes one = make_file(lit_str("one.proto"), lit_str("a"), lit_str("b"));
        Bytes two = make_file(lit_str("two.proto"), lit_str("a.b"), lit_str("c"));
        input = order ? make_set(two, one) : make_set(one, two);
        storage.arena.reset();
        result = load_descriptor_set(storage.arena, input.data, input.size);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == SchemaError::Duplicate);
    }

    Bytes source_message;
    source_message.text(1, lit_str("A"));
    Bytes source_field = member(lit_str("other"), 1, 11);
    source_field.text(6, lit_str(".q.B"));
    source_message.child(2, source_field);
    Bytes source_a = make_file(lit_str("a.proto"), lit_str("p"), lit_str("A"));
    // Replace the generated message with the referenced-field message.
    source_a = Bytes{};
    source_a.text(1, lit_str("a.proto"));
    source_a.text(2, lit_str("p"));
    source_a.text(12, lit_str("proto3"));
    source_a.child(4, source_message);
    Bytes source_b = make_file(lit_str("b.proto"), lit_str("q"), lit_str("B"));
    input = make_set(source_a, source_b);
    storage.arena.reset();
    result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == SchemaError::Unresolved);

    Bytes oversized_public;
    oversized_public.text(1, lit_str("oversized.proto"));
    oversized_public.text(3, lit_str("b.proto"));
    oversized_public.text(12, lit_str("proto3"));
    oversized_public.number(10, 0x100000000ULL);
    Bytes oversized_message;
    oversized_message.text(1, lit_str("Oversized"));
    oversized_public.child(4, oversized_message);
    input = make_set(source_b, oversized_public);
    storage.arena.reset();
    result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == SchemaError::Malformed);

    source_a.text(3, lit_str("b.proto"));
    input = make_set(source_a, source_b);
    storage.arena.reset();
    result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE(result.has_value());

    Bytes public_a;
    Bytes public_a_message;
    public_a_message.text(1, lit_str("A"));
    public_a.text(1, lit_str("a.proto"));
    public_a.text(2, lit_str("p"));
    public_a.text(12, lit_str("proto3"));
    public_a.child(4, public_a_message);
    Bytes public_b =
        make_file(lit_str("public.proto"), lit_str("q"), lit_str("B"), lit_str("a.proto"));
    public_b.number(10, 0);
    Bytes public_c_message;
    public_c_message.text(1, lit_str("C"));
    Bytes public_c_field = member(lit_str("a"), 1, 11);
    public_c_field.text(6, lit_str(".p.A"));
    public_c_message.child(2, public_c_field);
    Bytes public_c;
    public_c.text(1, lit_str("consumer.proto"));
    public_c.text(2, lit_str("r"));
    public_c.text(3, lit_str("public.proto"));
    public_c.text(12, lit_str("proto3"));
    public_c.child(4, public_c_message);
    input = make_set(public_a, public_b);
    input.child(1, public_c);
    storage.arena.reset();
    result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE(result.has_value());
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
