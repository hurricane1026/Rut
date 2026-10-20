#include "rut/common/types.h"
#include "rut/compiler/protobuf_schema.h"
#include "rut/compiler/protobuf_source.h"
#include "rut/runtime/arena.h"
#include "test.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

using namespace rut;
using namespace rut::protobuf;
#include "protobuf/enum_oracle.inc"
#include "protobuf/field_options_oracle.inc"
#include "protobuf/file_options_oracle.inc"
#include "protobuf/optional_schema_oracle.inc"
#include "protobuf/public_oracle.inc"
#include "protobuf/reserved_oracle.inc"
#include "protobuf/rpc_options_oracle.inc"
#include "protobuf/schema_descriptor.inc"
#include "protobuf/strings_oracle.inc"

namespace {
struct Storage {
    MmapArena arena;
    Storage() { (void)arena.init(4096); }
    ~Storage() { arena.destroy(); }
};
struct Files {
    char directory[128] = "/tmp/rut-proto-source-XXXXXX";
    bool ok = false;
    Files() { ok = mkdtemp(directory) != nullptr; }
    ~Files() {
        const char* names[] = {"root.proto", "types.proto", "extra.proto", "mid.proto"};
        for (const char* name : names) {
            char path[256];
            snprintf(path, sizeof(path), "%s/%s", directory, name);
            unlink(path);
        }
        rmdir(directory);
    }
    bool write_file(const char* name, const char* text) {
        char path[256];
        snprintf(path, sizeof(path), "%s/%s", directory, name);
        FILE* f = fopen(path, "wb");
        if (!f) return false;
        const size_t kSize = strlen(text);
        const bool kSuccess = fwrite(text, 1, kSize, f) == kSize;
        return fclose(f) == 0 && kSuccess;
    }
    auto load(Storage& storage, SchemaLimits limits = {}) {
        char path[256];
        snprintf(path, sizeof(path), "%s/root.proto", directory);
        return load_proto_source(storage.arena, {path, static_cast<u32>(strlen(path))}, limits);
    }
    auto load_path(Storage& storage, const char* path, u32 length) {
        return load_proto_source(storage.arena, {path, length});
    }
};
}  // namespace
TEST(protobuf_source, native_parser_matches_protoc_schema) {
    Storage source, descriptor;
    auto parsed =
        load_proto_source(source.arena, lit_str(RUT_SOURCE_DIR "/tests/protobuf/schema.proto"));
    auto golden = load_descriptor_set(descriptor.arena, kDescriptor, sizeof(kDescriptor));
    REQUIRE(parsed.has_value());
    REQUIRE(golden.has_value());
    CHECK_EQ(parsed->message_count, golden->message_count);
    CHECK_EQ(parsed->field_count, golden->field_count);
    CHECK_EQ(parsed->method_count, golden->method_count);
    for (const auto* message = golden->messages; message; message = message->next) {
        const auto* actual = parsed->find_message(message->full_name);
        REQUIRE(actual);
        for (const auto* field = message->fields; field; field = field->next) {
            const auto* match = actual->fields;
            while (match && !match->name.eq(field->name)) match = match->next;
            REQUIRE(match);
            CHECK_EQ(match->number, field->number);
            CHECK(match->type == field->type);
            CHECK_EQ(match->packed, field->packed);
            CHECK_EQ(match->repeated, field->repeated);
            CHECK(match->json_name.eq(field->json_name));
            CHECK(match->type_name.eq(field->type_name));
        }
    }
    for (const auto* method = golden->methods; method; method = method->next) {
        const auto* actual = parsed->find_method(method->path);
        REQUIRE(actual);
        CHECK(actual->input_name.eq(method->input_name));
        CHECK(actual->output_name.eq(method->output_name));
        CHECK_EQ(actual->client_streaming, method->client_streaming);
        CHECK_EQ(actual->server_streaming, method->server_streaming);
    }
}
TEST(protobuf_source, comments_scopes_forward_references_and_integer_bases) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file(
        "root.proto",
        "syntax = 'proto3'; package example /*x*/ . gateway; message Outer { Inner child = 0x10; "
        "message Inner { .example /*hello*/ . gateway.Outer parent = 021; } } service S { rpc "
        "Call(Outer.Inner) returns (Outer) {} } //done\n"));
    Storage storage;
    auto result = files.load(storage);
    REQUIRE(result.has_value());
    const auto* outer = result->find_message(lit_str(".example.gateway.Outer"));
    const auto* inner = result->find_message(lit_str(".example.gateway.Outer.Inner"));
    REQUIRE(outer && inner);
    REQUIRE(outer->fields && inner->fields);
    CHECK(outer->fields->message == inner);
    CHECK(inner->fields->message == outer);
    CHECK_EQ(outer->fields->number, 16u);
    CHECK_EQ(inner->fields->number, 17u);
}
TEST(protobuf_source, import_deduplication_cycle_and_missing_file) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file(
        "root.proto",
        "syntax='proto3'; import 'types.proto'; import 'types.proto'; message A { B other=1; }"));
    REQUIRE(files.write_file("types.proto", "syntax='proto3'; message B { string text=1; }"));
    Storage storage;
    auto result = files.load(storage);
    REQUIRE(result.has_value());
    CHECK_EQ(result->message_count, 2u);
    REQUIRE(files.write_file("types.proto", "syntax='proto3'; import 'root.proto'; message B {}"));
    result = files.load(storage);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().kind == SourceError::Kind::Syntax);
    REQUIRE(files.write_file("root.proto", "syntax='proto3'; import 'missing.proto';"));
    result = files.load(storage);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().kind == SourceError::Kind::Io);
}
TEST(protobuf_source, syntax_and_unsupported_semantics_are_explicit) {
    const char* cases[] = {"syntax='proto2'; message A {}",
                           "syntax='proto3'; message A { map<string,string> a=1; }",
                           "syntax='proto3'; message A { oneof a { string s=1; } }",
                           "syntax='proto3'; message A { string a=1 [default='x']; }",
                           "syntax='proto3'; import '../x.proto';",
                           "syntax='proto3'; /*unterminated",
                           "syntax='proto3'; message A { string a=0; }",
                           "syntax='proto3'; message A { string a=1; string b=1; }",
                           "syntax='proto3'; message A { Missing a=1; }",
                           "syntax='proto3'; message A { string a=09; }",
                           "syntax='proto3'; message A { string a=429496729600; }",
                           "syntax='proto3'; import weak 'x.proto';",
                           "\"syntax\"='proto3';"};
    for (const char* text : cases) {
        Files files;
        REQUIRE(files.ok);
        REQUIRE(files.write_file("root.proto", text));
        Storage storage;
        auto result = files.load(storage);
        CHECK_FALSE(result.has_value());
        if (!result) {
            CHECK(result.error().line > 0);
            CHECK(result.error().column > 0);
        }
    }
}
TEST(protobuf_source, source_budgets_and_empty_files) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file("root.proto", "syntax='proto3'; message A { string text=1; }"));
    const SchemaLimits kLimits[] = {
        {8}, {4096, 0}, {4096, 1, 0}, {4096, 1, 1, 0}, {4096, 1, 1, 1, 1, 0}};
    for (const auto& limit : kLimits) {
        Storage storage;
        auto result = files.load(storage, limit);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().kind == SourceError::Kind::Limit);
    }
    REQUIRE(files.write_file("root.proto", ""));
    Storage storage;
    CHECK_FALSE(files.load(storage));
}
TEST(protobuf_source, source_budget_excludes_descriptor_overhead_until_finalization) {
    Files files;
    REQUIRE(files.ok);
    const char* source = "syntax='proto3';";
    REQUIRE(files.write_file("root.proto", source));
    Storage storage;
    SchemaLimits limits{};
    limits.bytes = static_cast<u32>(strlen(source));
    auto result = files.load(storage, limits);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().kind == SourceError::Kind::Limit);
    storage.arena.reset();
    result = files.load(storage);
    REQUIRE(result.has_value());
}
TEST(protobuf_source, import_path_join_limit_is_reported_before_allocation) {
#if PATH_MAX < 4096
    SKIP("PATH_MAX is too small for the long path fixture");
#endif
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file("types.proto", "syntax='proto3'; message T {}"));
    REQUIRE(files.write_file("root.proto", "syntax='proto3'; import 'types.proto';"));
    char path[4096];
    u32 length = static_cast<u32>(strlen(files.directory));
    memcpy(path, files.directory, length);
    while (length + 12 < 4095) {
        path[length++] = '/';
        path[length++] = '.';
    }
    path[length++] = '/';
    memcpy(path + length, "root.proto", 10);
    length += 10;
    path[length] = 0;
    Storage storage;
    auto result = files.load_path(storage, path, length);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().kind == SourceError::Kind::Limit);
}
TEST(protobuf_source, uninitialized_arena_reports_allocation_failure) {
    Arena<MmapBackend> arena;
    auto result = load_proto_source(arena, lit_str("/tmp/missing.proto"));
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().kind == SourceError::Kind::Allocation);
}

TEST(protobuf_source, service_budget_honors_zero_and_boundary) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file("root.proto", "syntax='proto3'; service S {}"));
    SchemaLimits zero{};
    zero.services = 0;
    Storage storage;
    auto result = files.load(storage, zero);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().kind == SourceError::Kind::Limit);
    storage.arena.reset();
    SchemaLimits one{};
    one.services = 1;
    result = files.load(storage, one);
    REQUIRE(result.has_value());
}
TEST(protobuf_source, inner_type_name_shadows_outer_namespace) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file(
        "root.proto",
        "syntax='proto3'; message A { message B {} } message Outer { message A {} A.B wrong=1; }"));
    Storage storage;
    auto result = files.load(storage);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().kind == SourceError::Kind::Schema);
}
TEST(protobuf_source, field_and_nested_message_symbols_collide_in_both_orders) {
    Files files;
    REQUIRE(files.ok);
    const char* bodies[] = {"syntax='proto3'; message M { string X=1; message X {} }",
                            "syntax='proto3'; message M { message X {} string X=1; }"};
    for (const char* body : bodies) {
        REQUIRE(files.write_file("root.proto", body));
        Storage storage;
        auto result = files.load(storage);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().kind == SourceError::Kind::Schema);
    }
}
TEST(protobuf_source, imported_package_namespace_shadows_outer_type_fallback) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file("types.proto", "syntax='proto3'; package p.x; message A {}"));
    for (u32 index = 0; index < 2; ++index) {
        REQUIRE(files.write_file(
            "extra.proto",
            index == 0 ? "syntax='proto3'; package p.q.x;" : "syntax='proto3'; package p.q.y;"));
        REQUIRE(files.write_file("root.proto",
                                 "syntax='proto3'; package p.q; import 'types.proto'; import "
                                 "'extra.proto'; message M { x.A value=1; }"));
        Storage storage;
        auto result = files.load(storage);
        if (index == 0) {
            REQUIRE_FALSE(result.has_value());
            CHECK(result.error().kind == SourceError::Kind::Schema);
        } else
            REQUIRE(result.has_value());
    }
}
TEST(protobuf_source, transitive_symbols_do_not_shadow_visible_outer_type) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file("types.proto", "syntax='proto3'; package p.x; message A {}"));
    REQUIRE(files.write_file("extra.proto", "syntax='proto3'; package p.q.x; message A {}"));
    REQUIRE(files.write_file("mid.proto", "syntax='proto3'; package p.q; import 'extra.proto';"));
    REQUIRE(files.write_file("root.proto",
                             "syntax='proto3'; package p.q; import 'types.proto'; import "
                             "'mid.proto'; message M { x.A value=1; }"));
    Storage storage;
    auto result = files.load(storage);
    REQUIRE(result.has_value());
    REQUIRE(files.write_file(
        "root.proto",
        "syntax='proto3'; package p.q; import 'mid.proto'; message M { x.A value=1; }"));
    storage.arena.reset();
    result = files.load(storage);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().kind == SourceError::Kind::Schema);
}
TEST(protobuf_source, public_package_prefix_shadows_outer_fallback_only_when_visible) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file("types.proto", "syntax='proto3'; package p.x; message A {}"));
    REQUIRE(files.write_file("extra.proto", "syntax='proto3'; package p.q.x; message B {}"));
    REQUIRE(files.write_file("mid.proto", "syntax='proto3'; import 'extra.proto';"));
    REQUIRE(files.write_file("root.proto",
                             "syntax='proto3'; package p.q; import 'types.proto'; import "
                             "'mid.proto'; message M { x.A value=1; }"));
    Storage private_storage;
    REQUIRE(files.load(private_storage).has_value());

    REQUIRE(files.write_file("mid.proto", "syntax='proto3'; import public 'extra.proto';"));
    Storage public_storage;
    auto rejected = files.load(public_storage);
    REQUIRE_FALSE(rejected.has_value());
    CHECK(rejected.error().kind == SourceError::Kind::Schema);
}
TEST(protobuf_source, deep_relative_references_do_not_materialize_probe_names) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file("types.proto", "syntax='proto3'; message A {}"));
    char source[20000];
    u32 offset = 0;
    const char* prefix = "syntax='proto3'; package ";
    memcpy(source + offset, prefix, strlen(prefix));
    offset += static_cast<u32>(strlen(prefix));
    for (u32 component = 0; component < 200; ++component) {
        source[offset++] = 'a';
        if (component + 1 < 200) source[offset++] = '.';
    }
    memcpy(source + offset, "; import 'types.proto';", 23);
    offset += 23;
    for (u32 depth = 0; depth < 20; ++depth) {
        offset += static_cast<u32>(
            snprintf(source + offset, sizeof(source) - offset, " message M%u {", depth));
    }
    for (u32 field = 0; field < 512; ++field) {
        offset += static_cast<u32>(
            snprintf(source + offset, sizeof(source) - offset, " A f%u=%u;", field, field + 1));
    }
    for (u32 depth = 0; depth < 20; ++depth) source[offset++] = '}';
    source[offset] = 0;
    REQUIRE(files.write_file("root.proto", source));
    Storage storage;
    auto result = files.load(storage);
    REQUIRE(result.has_value());
    CHECK(storage.arena.space_allocated() < 4 * 1024 * 1024);
}
TEST(protobuf_source, qualified_name_limit_is_reported_before_join_allocation) {
    Files files;
    REQUIRE(files.ok);
    char source[5000];
    const char* prefix = "syntax='proto3'; package ";
    const u32 prefix_len = static_cast<u32>(strlen(prefix));
    memcpy(source, prefix, prefix_len);
    u32 offset = prefix_len;
    for (u32 i = 0; i < 2100; ++i) {
        source[offset++] = 'a';
        if (i + 1 < 2100) source[offset++] = '.';
    }
    const char* suffix = "; message A {}";
    memcpy(source + offset, suffix, strlen(suffix) + 1);
    REQUIRE(files.write_file("root.proto", source));
    Storage storage;
    auto result = files.load(storage);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().kind == SourceError::Kind::Limit);

    const u32 lengths[] = {1023, 1024};
    const char* boundary_suffix = ";";
    for (u32 length : lengths) {
        offset = prefix_len;
        for (u32 i = 0; i < length; ++i) source[offset++] = 'a';
        memcpy(source + offset, boundary_suffix, strlen(boundary_suffix) + 1);
        REQUIRE(files.write_file("root.proto", source));
        storage.arena.reset();
        result = files.load(storage);
        if (length == 1023)
            REQUIRE(result.has_value());
        else {
            REQUIRE_FALSE(result.has_value());
            CHECK(result.error().kind == SourceError::Kind::Limit);
        }
    }
}
TEST(protobuf_source, transitive_import_does_not_grant_type_visibility) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file("root.proto",
                             "syntax='proto3'; import 'types.proto'; message A { C c=1; }"));
    REQUIRE(files.write_file("types.proto", "syntax='proto3'; import 'extra.proto'; message B {}"));
    REQUIRE(files.write_file("extra.proto", "syntax='proto3'; message C {}"));
    Storage storage;
    auto result = files.load(storage);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().kind == SourceError::Kind::Schema);
    REQUIRE(files.write_file(
        "root.proto",
        "syntax='proto3'; import 'types.proto'; import 'extra.proto'; message A { C c=1; }"));
    result = files.load(storage);
    REQUIRE(result.has_value());
    CHECK_EQ(result->message_count, 3u);
}
int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}

TEST(protobuf_source, open_enums_resolve_nested_imports_and_validate_declarations) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file("types.proto",
                             "syntax='proto3'; package common; enum State { ZERO=0; NEG=-1; }"));
    REQUIRE(files.write_file(
        "root.proto",
        "syntax='proto3'; package example; import 'types.proto'; "
        "message Box { enum Mode { option allow_alias=true; OFF=0; ALSO_OFF=0; ON=1; } "
        "Mode mode=1; repeated common.State states=2; } "
        "service S { rpc Call(Box) returns(Box); }"));
    Storage storage;
    auto result = files.load(storage);
    REQUIRE(result);
    CHECK_EQ(result->enum_count, 2u);
    CHECK_EQ(result->enum_value_count, 5u);
    REQUIRE(result->find_enum(lit_str(".example.Box.Mode")));
    const auto* box = result->find_message(lit_str(".example.Box"));
    REQUIRE(box);
    for (const auto* f = box->fields; f; f = f->next) CHECK(f->type == Type::Enum);
    const char* invalid[] = {"enum E {}",
                             "enum E { A=1; }",
                             "enum E { A=0; A=1; }",
                             "enum E { A=0; B=0; }",
                             "enum E { A=0; B=2147483648; }",
                             "enum E { A=0; B=-2147483649; }",
                             "enum E { A=0; } enum F { A=0; }",
                             "enum E { A=0; } message A {}",
                             "message M { int32 A=1; enum E { A=0; } }",
                             "enum E { A=0; } service S { rpc Call(E) returns(E); }",
                             "enum E { A=0; } message M { Missing e=1; }"};
    for (const char* body : invalid) {
        char text[512];
        snprintf(text, sizeof(text), "syntax='proto3'; %s", body);
        REQUIRE(files.write_file("root.proto", text));
        Storage bad;
        CHECK_FALSE(files.load(bad));
    }
    REQUIRE(files.write_file(
        "root.proto", "syntax='proto3'; enum E { ZERO=0; MIN=-2147483648; MAX=2147483647; }"));
    Storage limits;
    SchemaLimits cap{};
    cap.enum_values = 2;
    CHECK_FALSE(files.load(limits, cap));
    Storage boundaries;
    CHECK(files.load(boundaries));
}

TEST(protobuf_source, enum_source_matches_independent_google_descriptor) {
    Storage source, descriptor;
    auto actual =
        load_proto_source(source.arena, lit_str(RUT_SOURCE_DIR "/tests/protobuf/enum.proto"));
    auto golden = load_descriptor_set(descriptor.arena, kEnumDescriptor, sizeof(kEnumDescriptor));
    REQUIRE(actual);
    REQUIRE(golden);
    CHECK_EQ(actual->enum_count, golden->enum_count);
    CHECK_EQ(actual->enum_value_count, golden->enum_value_count);
    for (const auto* e = golden->enums; e; e = e->next) {
        const auto* found = actual->find_enum(e->full_name);
        REQUIRE(found);
        for (const auto* v = e->values; v; v = v->next) {
            const auto* match = found->values;
            while (match && !match->name.eq(v->name)) match = match->next;
            REQUIRE(match);
            CHECK_EQ(match->number, v->number);
            CHECK(match->full_name.eq(v->full_name));
        }
    }
    for (const auto* m = golden->messages; m; m = m->next) {
        const auto* found = actual->find_message(m->full_name);
        REQUIRE(found);
        for (const auto* f = m->fields; f; f = f->next) {
            const auto* match = found->fields;
            while (match && !match->name.eq(f->name)) match = match->next;
            REQUIRE(match);
            CHECK(match->type == f->type);
            CHECK(match->type_name.eq(f->type_name));
            CHECK_EQ(match->number, f->number);
            CHECK_EQ(match->packed, f->packed);
            CHECK_EQ(match->repeated, f->repeated);
        }
    }
}
TEST(protobuf_source, enum_import_visibility_shadowing_and_exact_limits) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file("types.proto", "syntax='proto3'; package common; enum E { ZERO=0; }"));
    REQUIRE(files.write_file("mid.proto", "syntax='proto3'; import 'types.proto'; message Mid {}"));
    REQUIRE(files.write_file(
        "root.proto", "syntax='proto3'; import 'mid.proto'; message M { common.E state=1; }"));
    Storage hidden;
    CHECK_FALSE(files.load(hidden));
    REQUIRE(files.write_file(
        "root.proto", "syntax='proto3'; import 'types.proto'; message M { common.E state=1; }"));
    SchemaLimits cap{};
    cap.enums = 1;
    cap.enum_values = 1;
    Storage exact;
    REQUIRE(files.load(exact, cap));
    cap.enums = 0;
    Storage no_types;
    CHECK_FALSE(files.load(no_types, cap));
    cap.enums = 1;
    cap.enum_values = 0;
    Storage no_values;
    CHECK_FALSE(files.load(no_values, cap));
    REQUIRE(files.write_file("root.proto",
                             "syntax='proto3'; enum E { OUTER_ZERO=0; } message M { enum E { "
                             "INNER_ZERO=0; } E state=1; }"));
    Storage nested;
    auto result = files.load(nested);
    REQUIRE(result);
    const auto* m = result->find_message(lit_str(".M"));
    REQUIRE(m);
    REQUIRE(m->fields);
    CHECK(m->fields->type_name.eq(lit_str(".M.E")));
}

TEST(protobuf_source, reserved_ranges_names_boundaries_and_open_enum_values) {
    Storage storage;
    auto schema =
        load_proto_source(storage.arena, lit_str(RUT_SOURCE_DIR "/tests/protobuf/reserved.proto"));
    REQUIRE(schema);
    const auto* message = schema->find_message(lit_str(".example.ReservedBatch"));
    REQUIRE(message);
    REQUIRE(message->reserved_ranges);
    CHECK_EQ(message->reserved_ranges->first, 100);
    CHECK_EQ(message->reserved_ranges->last, 536870911);
    REQUIRE(message->reserved_ranges->next);
    CHECK_EQ(message->reserved_ranges->next->last, 5);
    const auto* enumeration = schema->find_enum(lit_str(".example.ReservedBatch.Local"));
    REQUIRE(enumeration);
    REQUIRE(enumeration->reserved_ranges);
    CHECK_EQ(enumeration->reserved_ranges->first, 12345);
    CHECK_EQ(enumeration->reserved_ranges->last, 12345);
    REQUIRE(enumeration->reserved_ranges->next);
    CHECK_EQ(enumeration->reserved_ranges->next->first, -10);
    CHECK_EQ(enumeration->reserved_ranges->next->last, -2);
    CHECK_EQ(schema->reserved_count, 7u);
    Files files;
    REQUIRE(files.ok);
    const char* invalid[] = {"message M { reserved 1; int32 value=1; }",
                             "message M { int32 value=1; reserved 1; }",
                             "message M { reserved 'value'; int32 value=1; }",
                             "message M { reserved 1 to 3,3 to 4; }",
                             "message M { reserved 'old','old'; }",
                             "message M { reserved 0; }",
                             "message M { reserved 536870912; }",
                             "message M { reserved 2 to 1; }",
                             "message M { reserved 1,'old'; }",
                             "message M { reserved 'old',1; }",
                             "message M { reserved 1 to; }",
                             "enum E { ZERO=0; reserved 0; }",
                             "enum E { reserved 'ZERO'; ZERO=0; }",
                             "enum E { ZERO=0; reserved -2 to -1; NEG=-1; }",
                             "enum E { ZERO=0; reserved 1 to max; MAX=2147483647; }",
                             "enum E { ZERO=0; reserved -2147483649; }",
                             "enum E { ZERO=0; reserved 2147483648; }",
                             "enum E { ZERO=0; reserved -3 to -2,-2; }"};
    for (const char* body : invalid) {
        char text[512];
        snprintf(text, sizeof(text), "syntax='proto3'; %s", body);
        REQUIRE(files.write_file("root.proto", text));
        Storage bad;
        CHECK_FALSE(files.load(bad));
    }
    REQUIRE(files.write_file("root.proto",
                             "syntax='proto3'; message M { reserved 2 to 3; reserved 'old'; int32 "
                             "new_name=1 [json_name='old']; int32 edge=4; } enum E { ZERO=0; "
                             "reserved -2147483648 to -1,1 to max; }"));
    SchemaLimits cap{};
    cap.reserved = 4;
    Storage exact;
    REQUIRE(files.load(exact, cap));
    cap.reserved = 3;
    Storage short_budget;
    CHECK_FALSE(files.load(short_budget, cap));
}

TEST(protobuf_source, reserved_source_matches_independent_descriptor_metadata) {
    Storage source, descriptor;
    auto actual =
        load_proto_source(source.arena, lit_str(RUT_SOURCE_DIR "/tests/protobuf/reserved.proto"));
    auto expected =
        load_descriptor_set(descriptor.arena, kReservedDescriptor, sizeof(kReservedDescriptor));
    REQUIRE(actual);
    REQUIRE(expected);
    CHECK_EQ(actual->reserved_count, expected->reserved_count);
    auto compare = [&](const ReservedRange* left,
                       const ReservedRange* right,
                       const ReservedName* names_left,
                       const ReservedName* names_right) {
        u32 actual_count = 0, expected_count = 0;
        for (const auto* r = left; r; r = r->next) ++actual_count;
        for (const auto* r = right; r; r = r->next) {
            ++expected_count;
            const auto* found = left;
            while (found && (found->first != r->first || found->last != r->last))
                found = found->next;
            CHECK(found);
        }
        CHECK_EQ(actual_count, expected_count);
        actual_count = 0;
        expected_count = 0;
        for (const auto* n = names_left; n; n = n->next) ++actual_count;
        for (const auto* n = names_right; n; n = n->next) {
            ++expected_count;
            const auto* found = names_left;
            while (found && !found->name.eq(n->name)) found = found->next;
            CHECK(found);
        }
        CHECK_EQ(actual_count, expected_count);
    };
    for (const auto* m = expected->messages; m; m = m->next) {
        const auto* found = actual->find_message(m->full_name);
        REQUIRE(found);
        compare(
            found->reserved_ranges, m->reserved_ranges, found->reserved_names, m->reserved_names);
    }
    for (const auto* e = expected->enums; e; e = e->next) {
        const auto* found = actual->find_enum(e->full_name);
        REQUIRE(found);
        compare(
            found->reserved_ranges, e->reserved_ranges, found->reserved_names, e->reserved_names);
    }
}

TEST(protobuf_source, public_imports_export_messages_enums_and_rpc_types) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file("extra.proto",
                             "syntax='proto3'; package shared; message Item { string text=1; } "
                             "enum State { ZERO=0; READY=1; }"));
    REQUIRE(files.write_file("types.proto", "syntax='proto3'; import public 'extra.proto';"));
    REQUIRE(files.write_file("mid.proto", "syntax='proto3'; import public 'types.proto';"));
    REQUIRE(files.write_file(
        "root.proto",
        "syntax='proto3'; import 'mid.proto'; message Request { shared.Item item=1; "
        "shared.State state=2; } service Echo { rpc Call(shared.Item) returns (Request); }"));
    Storage storage;
    auto schema = files.load(storage);
    REQUIRE(schema.has_value());
    const auto* request = schema->find_message(lit_str(".Request"));
    REQUIRE(request);
    CHECK_EQ(schema->message_count, 2u);
    CHECK_EQ(schema->enum_count, 1u);
    const auto* method = schema->find_method(lit_str("/Echo/Call"));
    REQUIRE(method);
    CHECK(method->input == schema->find_message(lit_str(".shared.Item")));
    CHECK(method->output == request);
    // A private edge breaks re-export, even when all files have been loaded.
    REQUIRE(files.write_file("types.proto", "syntax='proto3'; import 'extra.proto';"));
    Storage hidden;
    auto rejected = files.load(hidden);
    REQUIRE_FALSE(rejected.has_value());
    CHECK(rejected.error().kind == SourceError::Kind::Schema);
    // The importing file's own public flag cannot expose its dependency's private imports.
    REQUIRE(files.write_file(
        "root.proto",
        "syntax='proto3'; import public 'mid.proto'; message Request { shared.Item item=1; }"));
    Storage private_edge;
    CHECK_FALSE(files.load(private_edge).has_value());
}

TEST(protobuf_source, public_import_diamond_deduplication_cycles_and_limits) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file("extra.proto", "syntax='proto3'; message Item {}"));
    REQUIRE(files.write_file("types.proto", "syntax='proto3'; import public 'extra.proto';"));
    REQUIRE(files.write_file("mid.proto", "syntax='proto3'; import public 'extra.proto';"));
    REQUIRE(files.write_file(
        "root.proto",
        "syntax='proto3'; import 'types.proto'; import public 'types.proto'; "
        "import public 'types.proto'; import 'mid.proto'; message Root { Item item=1; }"));
    Storage storage;
    SchemaLimits limits;
    limits.files = 4;
    auto schema = files.load(storage, limits);
    REQUIRE(schema.has_value());
    CHECK_EQ(schema->message_count, 2u);
    const auto* root = schema->find_message(lit_str(".Root"));
    REQUIRE(root);
    CHECK_EQ(root->file->dependency_count, 2u);
    CHECK_EQ(root->file->public_dependencies[0], 1u);
    CHECK_EQ(root->file->public_dependencies[1], 0u);
    limits.files = 3;
    Storage bounded;
    auto limited = files.load(bounded, limits);
    REQUIRE_FALSE(limited.has_value());
    CHECK(limited.error().kind == SourceError::Kind::Limit);
    REQUIRE(files.write_file("extra.proto", "syntax='proto3'; import public 'root.proto';"));
    Storage cyclic;
    CHECK_FALSE(files.load(cyclic).has_value());
}

TEST(protobuf_source, public_imports_match_google_descriptor_visibility) {
    Storage source, descriptor;
    auto parsed = load_proto_source(source.arena,
                                    lit_str(RUT_SOURCE_DIR "/tests/protobuf/public_root.proto"));
    auto golden =
        load_descriptor_set(descriptor.arena, kPublicDescriptor, sizeof(kPublicDescriptor));
    REQUIRE(parsed.has_value());
    REQUIRE(golden.has_value());
    CHECK_EQ(parsed->message_count, golden->message_count);
    CHECK_EQ(parsed->enum_count, golden->enum_count);
    CHECK_EQ(parsed->field_count, golden->field_count);
    CHECK_EQ(parsed->method_count, golden->method_count);
    for (const auto* message = golden->messages; message; message = message->next) {
        const auto* actual = parsed->find_message(message->full_name);
        REQUIRE(actual);
        CHECK_EQ(actual->file->dependency_count, message->file->dependency_count);
        for (u32 i = 0; i < actual->file->dependency_count; ++i) {
            CHECK(actual->file->dependencies[i].eq(message->file->dependencies[i]));
            CHECK_EQ(actual->file->public_dependencies[i], message->file->public_dependencies[i]);
        }
        for (const auto* field = message->fields; field; field = field->next) {
            const auto* match = actual->fields;
            while (match && !match->name.eq(field->name)) match = match->next;
            REQUIRE(match);
            CHECK(match->type == field->type);
            CHECK(match->type_name.eq(field->type_name));
        }
    }
    const auto* method = parsed->find_method(lit_str("/PublicCodec/Echo"));
    REQUIRE(method);
    CHECK(method->output == parsed->find_message(lit_str(".example.ReservedBatch")));
}

TEST(protobuf_source, string_literals_match_protoc_escapes_and_concatenation) {
    Storage source, descriptor;
    auto parsed =
        load_proto_source(source.arena, lit_str(RUT_SOURCE_DIR "/tests/protobuf/strings.proto"));
    auto golden =
        load_descriptor_set(descriptor.arena, kStringsDescriptor, sizeof(kStringsDescriptor));
    REQUIRE(parsed.has_value());
    REQUIRE(golden.has_value());
    CHECK_EQ(parsed->message_count, golden->message_count);
    CHECK_EQ(parsed->method_count, golden->method_count);
    const auto* actual = parsed->find_message(lit_str(".example.StringBatch"));
    const auto* expected = golden->find_message(lit_str(".example.StringBatch"));
    REQUIRE(actual && expected);
    u32 count = 0;
    for (const auto* name = expected->reserved_names; name; name = name->next) {
        bool found = false;
        for (const auto* match = actual->reserved_names; match; match = match->next)
            found = found || name->name.eq(match->name);
        CHECK(found);
        ++count;
    }
    CHECK_EQ(count, 10u);
    CHECK_EQ(parsed->reserved_count, golden->reserved_count);
    for (const auto* field = actual->fields; field; field = field->next) {
        const auto* match = expected->fields;
        while (match && !match->name.eq(field->name)) match = match->next;
        REQUIRE(match);
        CHECK(field->json_name.eq(match->json_name));
        CHECK(field->type_name.eq(match->type_name));
    }
}

TEST(protobuf_source, malformed_string_escapes_and_decoded_path_guards) {
    const char* cases[] = {
        R"(syntax='proto3'; message M { reserved '\q'; })",
        R"(syntax='proto3'; message M { reserved '\8'; })",
        R"(syntax='proto3'; message M { reserved '\x'; })",
        R"(syntax='proto3'; message M { reserved '\xg0'; })",
        R"(syntax='proto3'; message M { reserved '\u123'; })",
        R"(syntax='proto3'; message M { reserved '\u12gg'; })",
        R"(syntax='proto3'; message M { reserved '\U0000000'; })",
        R"(syntax='proto3'; message M { reserved '\U00110000'; })",
        R"(syntax='proto3'; message M { reserved '\UFFFFFFFF'; })",
        R"(syntax='proto3'; message M { reserved '\uD800'; })",
        R"(syntax='proto3'; message M { reserved '\uDC00'; })",
        R"(syntax='proto3'; message M { reserved '\uD800\u0041'; })",
        R"(syntax='proto3'; message M { reserved '\uD800\uZZZZ'; })",
        R"(syntax='proto3'; message M { reserved '\xff'; })",
        R"(syntax='proto3'; message M { reserved '\uD800' '\uDC00'; })",
        R"(syntax='proto3'; message M { reserved '\U0000D800'; })",
        R"(syntax='proto3'; message M { reserved '\U0000D800\u0041'; })",
        R"(syntax='proto3'; message M { reserved '\uD800\U0000DC00'; })",
        R"(syntax='proto3'; message M { reserved '\U0000D800\U0000DC00'; })",
        R"(syntax='proto3'; import '\056\056/x.proto';)",
        R"(syntax='proto3'; import 'types\0.proto';)",
        R"(syntax='proto3'; import '\x2ftypes.proto';)",
        R"(syntax='proto3'; import '.' /*x*/ './types.proto';)",
        "syntax='proto3'; message M { reserved 'line\nbreak'; }",
        "syntax='proto3'; message M { reserved 'line\\\nbreak'; }",
        "syntax='proto3'; message M { reserved 'trailing\\",
    };
    for (const char* text : cases) {
        Files files;
        REQUIRE(files.ok);
        REQUIRE(files.write_file("root.proto", text));
        Storage storage;
        CHECK_FALSE(files.load(storage).has_value());
    }
    // Name conflicts must be checked after decoding and concatenating literals.
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file(
        "root.proto",
        R"(syntax='proto3'; message M { reserved 'de' "\154eted"; string deleted=1; })"));
    Storage storage;
    CHECK_FALSE(files.load(storage).has_value());
}

TEST(protobuf_source, standard_file_options_match_official_protoc_schema) {
    Storage source, descriptor;
    auto parsed = load_proto_source(source.arena,
                                    lit_str(RUT_SOURCE_DIR "/tests/protobuf/file_options.proto"));
    auto golden = load_descriptor_set(
        descriptor.arena, kFileOptionsDescriptor, sizeof(kFileOptionsDescriptor));
    REQUIRE(parsed.has_value());
    REQUIRE(golden.has_value());
    CHECK_EQ(parsed->message_count, golden->message_count);
    CHECK_EQ(parsed->enum_count, golden->enum_count);
    CHECK_EQ(parsed->field_count, golden->field_count);
    CHECK_EQ(parsed->method_count, golden->method_count);
    for (const auto* method = golden->methods; method; method = method->next) {
        const auto* match = parsed->find_method(method->path);
        REQUIRE(match);
        CHECK(match->input_name.eq(method->input_name));
        CHECK(match->output_name.eq(method->output_name));
    }
}

TEST(protobuf_source, legacy_php_generic_services_file_option) {
    const char* accepted[] = {
        "syntax='proto3'; option php_generic_services=true; message M {}",
        "syntax='proto3'; option php_generic_services=false; message M {}",
    };
    for (const char* text : accepted) {
        Files files;
        REQUIRE(files.ok);
        REQUIRE(files.write_file("root.proto", text));
        Storage storage;
        REQUIRE(files.load(storage).has_value());
    }
    const char* rejected[] = {
        "syntax='proto3'; option php_generic_services=1; message M {}",
        "syntax='proto3'; option php_generic_services='true'; message M {}",
        "syntax='proto3'; option php_generic_services=true; "
        "option php_generic_services=false; message M {}",
    };
    for (const char* text : rejected) {
        Files files;
        REQUIRE(files.ok);
        REQUIRE(files.write_file("root.proto", text));
        Storage storage;
        CHECK_FALSE(files.load(storage).has_value());
    }
}

TEST(protobuf_source, file_options_types_duplicates_scopes_and_limits) {
    const char* invalid[] = {
        "option unknown = true;",
        "option (custom.name) = 'value';",
        "option features.field_presence = EXPLICIT;",
        "option optimize_for = BAD;",
        "option optimize_for = 1;",
        "option optimize_for = 'SPEED';",
        "option deprecated = 1;",
        "option deprecated = 'true';",
        "option go_package = false;",
        "option java_package = 1;",
        "option go_package = 'x'",
        "option cc_enable_arenas true;",
        "option go_package = 'x'; option go_package = 'x';",
        "option deprecated = false; option deprecated = true;",
        "option optimize_for = SPEED; option optimize_for = CODE_SIZE;",
        R"(option go_package = '\xff';)",
        "message M { option java_package = 'x'; }",
    };
    for (const char* declaration : invalid) {
        Files files;
        REQUIRE(files.ok);
        char code[512];
        snprintf(code, sizeof(code), "syntax='proto3'; %s", declaration);
        REQUIRE(files.write_file("root.proto", code));
        Storage storage;
        CHECK_FALSE(files.load(storage).has_value());
    }
    const char* modes[] = {"SPEED", "CODE_SIZE", "LITE_RUNTIME"};
    for (const char* mode : modes) {
        Files files;
        REQUIRE(files.ok);
        char code[512];
        snprintf(code,
                 sizeof(code),
                 "syntax='proto3'; option optimize_for=%s; import 'types.proto'; "
                 "message M { Child value=1; } option go_package='root';",
                 mode);
        REQUIRE(files.write_file("root.proto", code));
        REQUIRE(files.write_file("types.proto",
                                 "syntax='proto3'; option go_package='child'; message Child {}"));
        Storage storage;
        auto schema = files.load(storage);
        REQUIRE(schema.has_value());
        CHECK_EQ(schema->message_count, 2u);
        SchemaLimits limits;
        limits.bytes = static_cast<u32>(strlen(code)) - 1;
        Storage bounded;
        CHECK_FALSE(files.load(bounded, limits).has_value());
    }
}

TEST(protobuf_source, field_generation_options_match_protoc) {
    Storage source, descriptor;
    auto parsed = load_proto_source(source.arena,
                                    lit_str(RUT_SOURCE_DIR "/tests/protobuf/field_options.proto"));
    auto golden = load_descriptor_set(
        descriptor.arena, kFieldOptionsDescriptor, sizeof(kFieldOptionsDescriptor));
    REQUIRE(parsed.has_value());
    REQUIRE(golden.has_value());
    CHECK_EQ(parsed->field_count, golden->field_count);
    const auto* message = parsed->find_message(lit_str(".field_options.Message"));
    const auto* expected = golden->find_message(lit_str(".field_options.Message"));
    REQUIRE(message != nullptr);
    REQUIRE(expected != nullptr);
    auto* field = message->fields;
    auto* reference = expected->fields;
    for (; field && reference; field = field->next, reference = reference->next) {
        CHECK(field->name.eq(reference->name));
        CHECK_EQ(field->number, reference->number);
        CHECK(field->type == reference->type);
        CHECK_EQ(field->repeated, reference->repeated);
        CHECK_EQ(field->packed, reference->packed);
    }
    CHECK(field == nullptr);
    CHECK(reference == nullptr);
}

TEST(protobuf_source, field_generation_option_validation) {
    const char* invalid[] = {"deprecated=1",
                             "deprecated='true'",
                             "deprecated=true, deprecated=false",
                             "debug_redact=0",
                             "lazy=TRUE",
                             "unverified_lazy='false'",
                             "ctype=0",
                             "ctype='CORD'",
                             "ctype=JS_STRING",
                             "ctype=CORD, ctype=STRING",
                             "jstype=CORD",
                             "jstype=JS_STRING, jstype=JS_NUMBER",
                             "unknown=true",
                             "(custom.name)=true",
                             "features.field_presence=EXPLICIT",
                             "weak=true",
                             "deprecated=true,",
                             "deprecated true"};
    for (const char* option : invalid) {
        Files files;
        REQUIRE(files.ok);
        char code[512];
        snprintf(code, sizeof(code), "syntax='proto3'; message M { string value=1 [%s]; }", option);
        REQUIRE(files.write_file("root.proto", code));
        Storage storage;
        CHECK_FALSE(files.load(storage).has_value());
    }
    const char* valid[] = {"ctype=STRING",
                           "ctype=CORD",
                           "ctype=STRING_PIECE",
                           "jstype=JS_NORMAL",
                           "jstype=JS_STRING",
                           "jstype=JS_NUMBER",
                           "lazy=false",
                           "unverified_lazy=true",
                           "debug_redact=false",
                           "deprecated=false"};
    for (const char* option : valid) {
        Files files;
        REQUIRE(files.ok);
        char code[512];
        snprintf(code, sizeof(code), "syntax='proto3'; message M { string value=1 [%s]; }", option);
        REQUIRE(files.write_file("root.proto", code));
        Storage storage;
        CHECK(files.load(storage).has_value());
    }
}

TEST(protobuf_source, rpc_options_match_official_protoc) {
    Storage source, descriptor;
    auto parsed = load_proto_source(source.arena,
                                    lit_str(RUT_SOURCE_DIR "/tests/protobuf/rpc_options.proto"));
    auto golden =
        load_descriptor_set(descriptor.arena, kRpcOptionsDescriptor, sizeof(kRpcOptionsDescriptor));
    REQUIRE(parsed);
    REQUIRE(golden);
    CHECK_EQ(parsed->method_count, 5u);
    for (auto* method = parsed->methods; method; method = method->next) {
        const auto* reference = golden->find_method(method->path);
        REQUIRE(reference != nullptr);
        CHECK(method->input_name.eq(reference->input_name));
        CHECK(method->output_name.eq(reference->output_name));
        CHECK_EQ(method->deprecated, reference->deprecated);
        CHECK(method->idempotency == reference->idempotency);
        CHECK_EQ(method->client_streaming, reference->client_streaming);
        CHECK_EQ(method->server_streaming, reference->server_streaming);
    }
    const auto* client = parsed->find_method(lit_str("/rpc_options.Counter/Client"));
    REQUIRE(client != nullptr);
    CHECK(client->deprecated);
    CHECK(client->idempotency == IdempotencyLevel::NoSideEffects);
    CHECK(parsed->find_method(lit_str("/rpc_options.Counter/Server"))->idempotency ==
          IdempotencyLevel::Idempotent);
    CHECK(parsed->find_method(lit_str("/rpc_options.Counter/Bare"))->idempotency ==
          IdempotencyLevel::Unknown);
}

TEST(protobuf_source, rpc_option_types_duplicates_and_scopes) {
    const char* invalid[] = {
        "option deprecated=1;",
        "option deprecated='true';",
        "option deprecated=true; option deprecated=false;",
        "option idempotency_level=2;",
        "option idempotency_level='IDEMPOTENT';",
        "option idempotency_level=BAD;",
        "option idempotency_level=true;",
        "option idempotency_level=IDEMPOTENT; option idempotency_level=IDEMPOTENT;",
        "option unknown=true;",
        "option (custom.name)=true;",
        "option features.field_presence=EXPLICIT;",
        "option deprecated=true",
        "option deprecated true;",
        "option deprecated=;",
        "option deprecated=true; rpc Nested(M) returns(M);"};
    for (const char* option : invalid) {
        Files files;
        REQUIRE(files.ok);
        char code[512];
        snprintf(code,
                 sizeof(code),
                 "syntax='proto3'; message M {} service S { rpc Call(M) returns(M) { %s } }",
                 option);
        REQUIRE(files.write_file("root.proto", code));
        Storage storage;
        CHECK_FALSE(files.load(storage).has_value());
    }
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file(
        "root.proto",
        "syntax='proto3'; message M {} service S { rpc A(M) returns(M) { ; option deprecated=true; "
        "; } rpc B(M) returns(M) { option deprecated=true; } rpc C(M) returns(M) {} }"));
    Storage storage;
    auto result = files.load(storage);
    REQUIRE(result);
    CHECK_EQ(result->method_count, 3u);
}

TEST(protobuf_source, imported_rpc_options_and_method_budget) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file(
        "types.proto",
        "syntax='proto3'; package child; message M {} service Imported { rpc Get(M) returns(M) { "
        "option deprecated=true; option idempotency_level=IDEMPOTENT; } }"));
    REQUIRE(files.write_file("root.proto",
                             "syntax='proto3'; import 'types.proto'; message M {} service Local { "
                             "rpc Get(M) returns(M) {} }"));
    Storage storage;
    auto result = files.load(storage);
    REQUIRE(result);
    const auto* imported = result->find_method(lit_str("/child.Imported/Get"));
    const auto* local = result->find_method(lit_str("/Local/Get"));
    REQUIRE(imported != nullptr);
    REQUIRE(local != nullptr);
    CHECK(imported->deprecated);
    CHECK(imported->idempotency == IdempotencyLevel::Idempotent);
    CHECK_FALSE(local->deprecated);
    CHECK(local->idempotency == IdempotencyLevel::Unknown);
    SchemaLimits limits;
    limits.methods = 1;
    Storage bounded;
    auto limited = files.load(bounded, limits);
    REQUIRE_FALSE(limited);
    CHECK(limited.error().kind == SourceError::Kind::Limit);
}

TEST(protobuf_source, optional_metadata_matches_protoc) {
    Storage source, oracle;
    auto parsed = load_proto_source(
        source.arena, lit_str(RUT_SOURCE_DIR "/tests/protobuf/optional_schema.proto"));
    auto expected = load_descriptor_set(
        oracle.arena, kOptionalSchemaDescriptor, sizeof(kOptionalSchemaDescriptor));
    REQUIRE(parsed);
    REQUIRE(expected);
    CHECK_EQ(parsed->synthetic_oneof_count, expected->synthetic_oneof_count);
    for (const auto* message = expected->messages; message; message = message->next) {
        const auto* actual = parsed->find_message(message->full_name);
        REQUIRE(actual);
        for (const auto* field = message->fields; field; field = field->next) {
            const auto* match = actual->fields;
            while (match && !match->name.eq(field->name)) match = match->next;
            REQUIRE(match);
            CHECK_EQ(match->proto3_optional, field->proto3_optional);
            CHECK_EQ(match->oneof_index, field->oneof_index);
            CHECK(match->type == field->type);
        }
        auto* a = actual->synthetic_oneofs;
        auto* b = message->synthetic_oneofs;
        while (a && b) {
            CHECK(a->name.eq(b->name));
            CHECK_EQ(a->index, b->index);
            a = a->next;
            b = b->next;
        }
        CHECK(a == nullptr && b == nullptr);
    }
}
TEST(protobuf_source, optional_names_avoid_later_message_symbols) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file("root.proto",
                             "syntax='proto3'; message A { "
                             "optional int32 value=1; int32 _value=2; "
                             "message X_value {} enum E { XX_value=0; } "
                             "optional bool _flag=3; }"));
    Storage storage;
    auto parsed = files.load(storage);
    REQUIRE(parsed);
    const auto* message = parsed->find_message(lit_str(".A"));
    REQUIRE(message);
    const auto* oneof = message->synthetic_oneofs;
    bool value_seen = false, flag_seen = false;
    for (; oneof; oneof = oneof->next) {
        value_seen |= oneof->name.eq(lit_str("XXX_value"));
        flag_seen |= oneof->name.eq(lit_str("X_flag"));
    }
    CHECK(value_seen);
    CHECK(flag_seen);
    SchemaLimits limits;
    limits.fields = 4;  // Three fields plus two synthetic declarations exceed this.
    Storage bounded;
    auto rejected = files.load(bounded, limits);
    REQUIRE_FALSE(rejected);
    CHECK(rejected.error().kind == SourceError::Kind::Limit);
}

TEST(protobuf_source, optional_imports_nested_types_and_invalid_labels) {
    Files files;
    REQUIRE(files.ok);
    REQUIRE(files.write_file("types.proto",
                             "syntax='proto3'; package types; "
                             "enum Kind { ZERO=0; } message Child { optional string text=1; }"));
    REQUIRE(
        files.write_file("root.proto",
                         "syntax='proto3'; import 'types.proto'; "
                         "message A { optional types.Kind kind=1; optional types.Child child=2; "
                         "message Nested { optional bytes raw=1; } }"));
    Storage storage;
    auto parsed = files.load(storage);
    REQUIRE(parsed);
    CHECK_EQ(parsed->synthetic_oneof_count, 4u);
    const auto* message = parsed->find_message(lit_str(".A"));
    REQUIRE(message);
    for (auto* field = message->fields; field; field = field->next) {
        CHECK(field->proto3_optional);
        CHECK_FALSE(field->repeated);
    }
    const char* invalid[] = {"optional repeated int32 a=1;",
                             "repeated optional int32 a=1;",
                             "required int32 a=1;",
                             "optional map<string,string> a=1;",
                             "optional int32 a=1 [packed=true];"};
    for (const char* field : invalid) {
        char text[256];
        snprintf(text, sizeof(text), "syntax='proto3'; message A { %s }", field);
        REQUIRE(files.write_file("root.proto", text));
        Storage bad;
        CHECK_FALSE(files.load(bad));
    }
}
