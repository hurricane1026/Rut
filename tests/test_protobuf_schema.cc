#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/compiler/protobuf_schema.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/protobuf_wire.h"
#include "test.h"

#include <string.h>

using namespace rut;
using namespace rut::protobuf;

#include "protobuf/optional_schema_oracle.inc"
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

TEST(protobuf_schema, message_options_reject_duplicate_containers) {
    CompileArena storage;

    Bytes valid_options;
    valid_options.number(3, 1);
    valid_options.number(7, 0);
    Bytes valid_message = message(member());
    valid_message.child(7, valid_options);
    Bytes valid_input = descriptor(valid_message);
    auto valid = load_descriptor_set(storage.arena, valid_input.data, valid_input.size);
    REQUIRE(valid.has_value());

    Bytes deprecated;
    deprecated.number(3, 1);
    Bytes duplicate = message(member());
    duplicate.child(7, deprecated);
    duplicate.child(7, deprecated);
    Bytes duplicate_input = descriptor(duplicate);
    auto duplicate_result =
        load_descriptor_set(storage.arena, duplicate_input.data, duplicate_input.size);
    REQUIRE_FALSE(duplicate_result.has_value());
    CHECK(duplicate_result.error() == SchemaError::Duplicate);
}

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
    const u32 kTypes[] = {10u};
    for (const u32 kType : kTypes) {
        Bytes input = descriptor(message(member(lit_str("a"), 1, kType)));
        auto result = load_descriptor_set(storage.arena, input.data, input.size);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == SchemaError::Unsupported);
    }
    const u32 kFieldTags[] = {2u, 7u, 9u};
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
    const u32 kMessageTags[] = {5u, 6u, 8u};
    for (const u32 kTag : kMessageTags) {
        Bytes msg = message(member());
        const Bytes kEmpty;
        msg.child(kTag, kEmpty);
        input = descriptor(msg);
        result = load_descriptor_set(storage.arena, input.data, input.size);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == (kTag == 8 ? SchemaError::Malformed : SchemaError::Unsupported));
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

    Bytes explicit_false = member();
    explicit_false.number(17, 0);
    input = descriptor(message(explicit_false));
    storage.arena.reset();
    result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE(result.has_value());

    Bytes explicit_true = member();
    explicit_true.number(17, 1);
    input = descriptor(message(explicit_true));
    storage.arena.reset();
    result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == SchemaError::Malformed);

    Bytes invalid_optional = member();
    invalid_optional.number(17, 2);
    input = descriptor(message(invalid_optional));
    storage.arena.reset();
    result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == SchemaError::Malformed);

    Bytes malformed_optional = member();
    malformed_optional.text(17, lit_str("true"));
    input = descriptor(message(malformed_optional));
    storage.arena.reset();
    result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == SchemaError::Malformed);

    for (u32 order = 0; order < 2; ++order) {
        Bytes collision;
        collision.text(1, lit_str("M"));
        Bytes nested;
        nested.text(1, lit_str("X"));
        Bytes field = member(lit_str("X"));
        collision.child(order ? 3 : 2, order ? nested : field);
        collision.child(order ? 2 : 3, order ? field : nested);
        input = descriptor(collision);
        storage.arena.reset();
        result = load_descriptor_set(storage.arena, input.data, input.size);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error() == SchemaError::Duplicate);
    }

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
    Bytes cycle_a = make_file(lit_str("cycle-a.proto"), {}, lit_str("A"), lit_str("cycle-b.proto"));
    Bytes cycle_b = make_file(lit_str("cycle-b.proto"), {}, lit_str("B"), lit_str("cycle-a.proto"));
    input = make_set(cycle_a, cycle_b);
    storage.arena.reset();
    result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == SchemaError::Malformed);
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

TEST(protobuf_schema, enum_descriptors_validate_open_numeric_types_and_references) {
    Bytes zero, negative, enumeration;
    zero.text(1, lit_str("ZERO"));
    zero.number(2, 0);
    negative.text(1, lit_str("NEG"));
    negative.number(2, static_cast<u64>(i64{-1}));
    enumeration.text(1, lit_str("State"));
    enumeration.child(2, zero);
    enumeration.child(2, negative);
    Bytes field = member(lit_str("state"), 1, 14, 3);
    field.text(6, lit_str(".example.State"));
    Bytes source = file(message(field));
    source.child(5, enumeration);
    Bytes input;
    input.child(1, source);
    CompileArena arena;
    auto result = load_descriptor_set(arena.arena, input.data, input.size);
    REQUIRE(result);
    const auto* e = result->find_enum(lit_str(".example.State"));
    REQUIRE(e);
    REQUIRE(e->values);
    CHECK_EQ(e->values->number, -1);
    const auto* msg = result->find_message(lit_str(".example.Item"));
    REQUIRE(msg);
    REQUIRE(msg->fields);
    CHECK(msg->fields->type == Type::Enum);
    CHECK(msg->fields->packed);
    Bytes missing;
    missing.child(1, file(message(field)));
    CompileArena unresolved;
    auto bad = load_descriptor_set(unresolved.arena, missing.data, missing.size);
    REQUIRE_FALSE(bad);
    CHECK(bad.error() == SchemaError::Unresolved);
    SchemaLimits limits{};
    limits.enums = 0;
    CompileArena bounded;
    bad = load_descriptor_set(bounded.arena, input.data, input.size, limits);
    REQUIRE_FALSE(bad);
    CHECK(bad.error() == SchemaError::Limit);
}

TEST(protobuf_schema, enum_descriptor_alias_and_malformed_value_rules) {
    for (u32 scenario = 0; scenario < 7; ++scenario) {
        Bytes enumeration;
        enumeration.text(1, lit_str("E"));
        Bytes first;
        first.text(1, lit_str("ZERO"));
        first.number(2, scenario == 0 ? 1u : scenario == 1 ? (u64{1} << 32) : 0u);
        if (scenario == 2) first.number(2, 0);  // Duplicate descriptor field.
        if (scenario != 3) enumeration.child(2, first);
        if (scenario >= 4) {
            Bytes second;
            second.text(1, scenario == 6 ? lit_str("ZERO") : lit_str("ALIAS"));
            second.number(2, 0);
            enumeration.child(2, second);
            if (scenario >= 5) {
                Bytes options;
                options.number(2, 1);
                enumeration.child(3, options);
            }
        }
        Bytes source = file(message(member()));
        source.child(5, enumeration);
        Bytes input;
        input.child(1, source);
        CompileArena arena;
        auto result = load_descriptor_set(arena.arena, input.data, input.size);
        if (scenario == 5) {
            REQUIRE(result);
            CHECK_EQ(result->enum_value_count, 2u);
        } else {
            REQUIRE_FALSE(result);
            CHECK(result.error() == (scenario == 0 || scenario == 1 || scenario == 3
                                         ? SchemaError::Malformed
                                         : SchemaError::Duplicate));
        }
    }
}

TEST(protobuf_schema, reserved_descriptor_wire_ranges_duplicates_and_limits) {
    for (u32 kind = 0; kind < 2; ++kind) {
        const bool enumeration = kind != 0;
        for (u32 scenario = 0; scenario < 10; ++scenario) {
            Bytes range;
            range.number(1, enumeration ? static_cast<u64>(i64{-2}) : 2u);
            if (scenario == 2)
                range.text(2, lit_str("bad"));
            else if (scenario != 1)
                range.number(2,
                             scenario == 3   ? (enumeration ? static_cast<u64>(i64{-3}) : 2u)
                             : scenario == 4 ? (enumeration ? 2147483648u : 536870913u)
                             : enumeration   ? static_cast<u64>(i64{-2})
                                             : 3u);
            if (scenario == 6) range.number(2, 3);
            Bytes owner;
            owner.text(1, lit_str("Owner"));
            const u32 range_tag = enumeration ? 4u : 9u;
            const u32 name_tag = enumeration ? 5u : 10u;
            if (scenario >= 8) {
                const char invalid[] = {static_cast<char>(255)};
                owner.text(name_tag, scenario == 8 ? Str{invalid, 1} : lit_str("old"));
                if (scenario == 9) owner.text(name_tag, lit_str("old"));
            } else {
                owner.child(range_tag, range);
                if (scenario == 5) owner.child(range_tag, range);
            }
            if (enumeration) {
                Bytes zero;
                zero.text(1, lit_str("ZERO"));
                zero.number(2, 0);
                owner.child(2, zero);
            }
            Bytes source;
            source.text(1, lit_str("reserved.proto"));
            source.text(12, lit_str("proto3"));
            source.child(enumeration ? 5u : 4u, owner);
            Bytes input;
            input.child(1, source);
            CompileArena arena;
            SchemaLimits limits{};
            if (scenario == 7) limits.reserved = 0;
            auto result = load_descriptor_set(arena.arena, input.data, input.size, limits);
            if (scenario == 0) {
                REQUIRE(result);
                CHECK_EQ(result->reserved_count, 1u);
            } else {
                REQUIRE_FALSE(result);
                CHECK(result.error() == (scenario == 5 || scenario == 6 || scenario == 9
                                             ? SchemaError::Duplicate
                                         : scenario == 7 ? SchemaError::Limit
                                                         : SchemaError::Malformed));
            }
        }
    }
}

TEST(protobuf_schema, optional_metadata_matches_official_descriptor) {
    CompileArena storage;
    auto result = load_descriptor_set(
        storage.arena, kOptionalSchemaDescriptor, sizeof(kOptionalSchemaDescriptor));
    REQUIRE(result.has_value());
    CHECK_EQ(result->synthetic_oneof_count, 5u);
    const auto* message = result->find_message(lit_str(".presence.Message"));
    REQUIRE(message != nullptr);
    u32 optional = 0, implicit = 0;
    for (const auto* field = message->fields; field; field = field->next) {
        if (field->proto3_optional) {
            ++optional;
            CHECK_EQ(field->oneof_index, field->number < 4 ? field->number - 1 : field->number - 2);
            const SyntheticOneof* declaration = message->synthetic_oneofs;
            while (declaration && declaration->index != field->oneof_index)
                declaration = declaration->next;
            REQUIRE(declaration != nullptr);
            CHECK_EQ(declaration->name.len, field->name.len + 1);
            CHECK_EQ(declaration->name.ptr[0], '_');
            CHECK((Str{declaration->name.ptr + 1, declaration->name.len - 1}).eq(field->name));
            CHECK_FALSE(field->repeated);
        } else {
            ++implicit;
            CHECK_EQ(field->oneof_index, 0xffffffffu);
        }
    }
    CHECK_EQ(optional, 5u);
    CHECK_EQ(implicit, 1u);
    SchemaLimits limits;
    limits.fields = 4;
    CompileArena bounded;
    CHECK_FALSE(
        load_descriptor_set(
            bounded.arena, kOptionalSchemaDescriptor, sizeof(kOptionalSchemaDescriptor), limits)
            .has_value());
}

TEST(protobuf_schema, fields_and_synthetic_oneofs_share_budget_in_wire_order) {
    for (u32 order = 0; order < 2; ++order) {
        Bytes field = member(lit_str("value"), 1, 5);
        field.number(17, 1);
        field.number(9, 0);
        Bytes oneof;
        oneof.text(1, lit_str("_value"));
        Bytes item;
        item.text(1, lit_str("Item"));
        item.child(order ? 8 : 2, order ? oneof : field);
        item.child(order ? 2 : 8, order ? field : oneof);
        Bytes input = descriptor(item);

        SchemaLimits tight;
        tight.fields = 1;
        CompileArena bounded;
        auto rejected = load_descriptor_set(bounded.arena, input.data, input.size, tight);
        REQUIRE_FALSE(rejected.has_value());
        CHECK(rejected.error() == SchemaError::Limit);

        SchemaLimits exact;
        exact.fields = 2;
        CompileArena allowed;
        auto result = load_descriptor_set(allowed.arena, input.data, input.size, exact);
        REQUIRE(result);
        CHECK_EQ(result->field_count, 1u);
        CHECK_EQ(result->synthetic_oneof_count, 1u);
    }
}

TEST(protobuf_schema, repeated_message_preserves_nested_optional_metadata) {
    // This is the descriptor shape that reaches the compiler's repeated
    // message layout path.  The source parser intentionally rejects the
    // `optional` keyword, so keep the regression at the descriptor boundary
    // where proto3 presence is represented by proto3_optional + a synthetic
    // oneof.
    Bytes optional_field = member(lit_str("value"), 1, 5);
    optional_field.number(17, 1);
    optional_field.number(9, 0);
    Bytes synthetic_oneof;
    synthetic_oneof.text(1, lit_str("_value"));
    Bytes child;
    child.text(1, lit_str("Child"));
    child.child(2, optional_field);
    child.child(8, synthetic_oneof);

    Bytes repeated_child = member(lit_str("children"), 1, 11, 3);
    repeated_child.text(6, lit_str(".example.Child"));
    Bytes root;
    root.text(1, lit_str("Root"));
    root.child(2, repeated_child);
    Bytes source = file(child);
    source.child(4, root);
    Bytes input;
    input.child(1, source);

    CompileArena storage;
    auto result = load_descriptor_set(storage.arena, input.data, input.size);
    REQUIRE(result);
    const auto* root_message = result->find_message(lit_str(".example.Root"));
    const auto* child_message = result->find_message(lit_str(".example.Child"));
    REQUIRE(root_message && child_message);
    REQUIRE(root_message->fields && root_message->fields->message == child_message);
    CHECK(root_message->fields->repeated);
    REQUIRE(child_message->fields);
    CHECK(child_message->fields->proto3_optional);
    CHECK_EQ(child_message->fields->oneof_index, 0u);
}

TEST(protobuf_schema, synthetic_oneof_validation) {
    // Descriptor declaration order must not affect index validation.
    for (u32 order = 0; order < 2; ++order) {
        Bytes field = member();
        field.number(17, 1);
        field.number(9, 0);
        Bytes oneof;
        oneof.text(1, lit_str("_value"));
        Bytes msg;
        msg.text(1, lit_str("Item"));
        msg.child(order ? 8 : 2, order ? oneof : field);
        msg.child(order ? 2 : 8, order ? field : oneof);
        Bytes input = descriptor(msg);
        CompileArena storage;
        auto result = load_descriptor_set(storage.arena, input.data, input.size);
        REQUIRE(result.has_value());
        const auto* item = result->find_message(lit_str(".example.Item"));
        REQUIRE(item != nullptr);
        CHECK(item->fields->proto3_optional);
        CHECK(item->synthetic_oneofs->name.eq(lit_str("_value")));
    }
    for (u32 scenario = 0; scenario < 14; ++scenario) {
        Bytes field = member(lit_str("value"), 1, 9, scenario == 0 ? 3 : 1);
        if (scenario != 1) field.number(17, 1);
        field.number(9, scenario == 2 ? 1 : 0);
        if (scenario == 3) field.number(9, 0);
        Bytes oneof;
        if (scenario != 10)
            oneof.text(1,
                       scenario == 4    ? lit_str("value")
                       : scenario == 11 ? lit_str("bad.name")
                                        : lit_str("_value"));
        if (scenario == 12) oneof.number(1, 1);
        if (scenario == 13) field.number(9, 0xffffffffffffffffULL);
        if (scenario == 5) oneof.text(1, lit_str("again"));
        if (scenario == 6) oneof.child(2, Bytes{});
        Bytes msg = message(field);
        if (scenario != 7) msg.child(8, oneof);
        if (scenario == 8) msg.child(8, oneof);
        if (scenario == 9) {
            Bytes second = member(lit_str("other"), 2);
            second.number(17, 1);
            second.number(9, 0);
            msg.child(2, second);
        }
        Bytes input = descriptor(msg);
        CompileArena storage;
        CHECK_FALSE(load_descriptor_set(storage.arena, input.data, input.size).has_value());
    }
    Bytes empty;
    empty.text(1, lit_str("Item"));
    Bytes oneof;
    oneof.text(1, lit_str("_empty"));
    empty.child(8, oneof);
    Bytes input = descriptor(empty);
    CompileArena storage;
    CHECK_FALSE(load_descriptor_set(storage.arena, input.data, input.size).has_value());
    SchemaLimits limits;
    limits.fields = 0;
    CompileArena bounded;
    auto limited = load_descriptor_set(bounded.arena, input.data, input.size, limits);
    REQUIRE_FALSE(limited.has_value());
    CHECK(limited.error() == SchemaError::Limit);
}

TEST(protobuf_schema, rpc_option_wire_values_and_duplicates) {
    for (u32 scenario = 0; scenario < 8; ++scenario) {
        Bytes options;
        if (scenario == 0) options.number(33, 2);
        if (scenario == 1) options.text(33, lit_str("true"));
        if (scenario == 2) options.number(34, 3);
        if (scenario == 3) options.text(34, lit_str("IDEMPOTENT"));
        if (scenario == 4) {
            options.number(33, 1);
            options.number(33, 0);
        }
        if (scenario == 5) {
            options.number(34, 1);
            options.number(34, 2);
        }
        if (scenario == 6) options.number(34, 0xffffffffffffffffULL);
        if (scenario == 7) {
            options.number(33, 1);
            options.number(34, 2);
        }
        Bytes method;
        method.text(1, lit_str("Call"));
        method.text(2, lit_str(".example.Item"));
        method.text(3, lit_str(".example.Item"));
        method.child(4, options);
        Bytes service;
        service.text(1, lit_str("S"));
        service.child(2, method);
        Bytes source = file(message(member()));
        source.child(6, service);
        Bytes input;
        input.child(1, source);
        CompileArena storage;
        auto result = load_descriptor_set(storage.arena, input.data, input.size);
        if (scenario == 7) {
            REQUIRE(result);
            CHECK(result->methods->deprecated);
            CHECK(result->methods->idempotency == IdempotencyLevel::Idempotent);
        } else {
            REQUIRE_FALSE(result);
            CHECK(result.error() == (scenario == 4 || scenario == 5 ? SchemaError::Duplicate
                                                                    : SchemaError::Malformed));
        }
    }
}

TEST(protobuf_schema, service_option_wire_validation) {
    for (u32 scenario = 0; scenario < 8; ++scenario) {
        Bytes options;
        if (scenario == 0) options.number(33, 2);
        if (scenario == 1) options.text(33, lit_str("true"));
        if (scenario == 2) {
            options.number(33, 1);
            options.number(33, 0);
        }
        if (scenario >= 4) options.number(33, scenario == 4 ? 0 : 1);
        Bytes method;
        method.text(1, lit_str("Call"));
        method.text(2, lit_str(".example.Item"));
        method.text(3, lit_str(".example.Item"));
        Bytes service;
        service.text(1, lit_str("S"));
        service.child(2, method);
        if (scenario == 3)
            service.number(3, 1);
        else
            service.child(3, options);
        if (scenario == 6) service.child(3, options);
        if (scenario == 7) {
            // Even a service without methods must validate its options.
            service = Bytes{};
            service.text(1, lit_str("S"));
            options = Bytes{};
            options.number(33, 3);
            service.child(3, options);
        }
        Bytes source = file(message(member()));
        source.child(6, service);
        Bytes input;
        input.child(1, source);
        CompileArena storage;
        auto result = load_descriptor_set(storage.arena, input.data, input.size);
        if (scenario == 4 || scenario == 5) {
            REQUIRE(result);
            CHECK_EQ(result->methods->service_deprecated, scenario == 5);
            CHECK_FALSE(result->methods->deprecated);
        } else {
            REQUIRE_FALSE(result);
            CHECK(result.error() == (scenario == 2 || scenario == 6 ? SchemaError::Duplicate
                                                                    : SchemaError::Malformed));
        }
    }
}
TEST(protobuf_schema, declaration_option_boolean_validation) {
    // Message deprecated, enum deprecated, enum-value deprecated/debug_redact.
    for (u32 scope = 0; scope < 4; ++scope) {
        for (u32 scenario = 0; scenario < 5; ++scenario) {
            Bytes options;
            const u32 kTag = scope == 2 ? 1 : 3;
            if (scenario == 0) options.number(kTag, 0);
            if (scenario == 1) options.number(kTag, 1);
            if (scenario == 2) options.number(kTag, 2);
            if (scenario == 3) options.text(kTag, lit_str("true"));
            if (scenario == 4) {
                options.number(kTag, 0);
                options.number(kTag, 1);
            }
            Bytes msg = message(member());
            Bytes enumeration;
            enumeration.text(1, lit_str("E"));
            Bytes value;
            value.text(1, lit_str("ZERO"));
            value.number(2, 0);
            if (scope >= 2) value.child(3, options);
            enumeration.child(2, value);
            if (scope == 1) enumeration.child(3, options);
            if (scope == 0) msg.child(7, options);
            Bytes source = file(msg);
            source.child(5, enumeration);
            Bytes input;
            input.child(1, source);
            CompileArena storage;
            auto result = load_descriptor_set(storage.arena, input.data, input.size);
            if (scenario < 2)
                REQUIRE(result);
            else {
                REQUIRE_FALSE(result);
                CHECK(result.error() ==
                      (scenario == 4 ? SchemaError::Duplicate : SchemaError::Malformed));
            }
        }
    }
}
