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
#include "protobuf/schema_descriptor.inc"

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
                           "syntax='proto3'; message A { optional string a=1; }",
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
                           "syntax='proto3'; import public 'x.proto';",
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
