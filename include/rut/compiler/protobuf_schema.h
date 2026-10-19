#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/arena.h"

namespace rut::protobuf {
// Compiler-owned proto3 schema. Numeric values match FieldDescriptorProto.Type.
enum class Type : u8 {
    Double = 1,
    Float,
    Int64,
    Uint64,
    Int32,
    Fixed64,
    Fixed32,
    Bool,
    String,
    Group,
    Message,
    Bytes,
    Uint32,
    Enum,
    Sfixed32,
    Sfixed64,
    Sint32,
    Sint64
};
struct Message;
struct Enum;
struct SchemaFile;
struct SchemaField {
    Str name{};
    Str json_name{};
    Str type_name{};
    u32 number = 0;
    Type type = Type::Int32;
    bool repeated = false;
    bool packed = false;
    const Message* message = nullptr;
    const SchemaFile* file = nullptr;
    SchemaField* next = nullptr;
};
struct EnumValue {
    Str name{};
    Str full_name{};
    i32 number = 0;
    EnumValue* next = nullptr;
};
struct Enum {
    Str full_name{};
    EnumValue* values = nullptr;
    const SchemaFile* file = nullptr;
    Enum* next = nullptr;
};
struct Message {
    Str full_name{};  // Leading dot, e.g. .example.Message
    SchemaField* fields = nullptr;
    Message* next = nullptr;
    const SchemaFile* file = nullptr;
};
struct Method {
    Str path{};  // /package.Service/Method
    Str input_name{};
    Str output_name{};
    const Message* input = nullptr;
    const Message* output = nullptr;
    bool client_streaming = false;
    bool server_streaming = false;
    Method* next = nullptr;
    const SchemaFile* file = nullptr;
};
struct SchemaFile {
    Str name{};
    Str* dependencies = nullptr;
    u8* public_dependencies = nullptr;
    u32 dependency_count = 0;
};
struct Schema {
    Message* messages = nullptr;
    Enum* enums = nullptr;
    u32 enum_count = 0;
    u32 enum_value_count = 0;
    Method* methods = nullptr;
    u32 message_count = 0;
    u32 field_count = 0;
    u32 method_count = 0;
    const Message* find_message(Str full_name) const;
    const Enum* find_enum(Str full_name) const;
    const Method* find_method(Str path) const;
};
enum class SchemaError : u8 { Malformed, Unsupported, Duplicate, Unresolved, Limit, Allocation };
// Limits can only tighten these built-in ceilings. Qualified names cap at 1024 bytes.
struct SchemaLimits {
    u32 bytes = 4 * 1024 * 1024;
    u32 files = 128;
    u32 messages = 1024;
    u32 fields = 16384;
    u32 methods = 1024;
    u32 depth = 32;
    u32 services = 1024;
    u32 enums = 1024;
    u32 enum_values = 16384;
};
// Copies input into arena: output never borrows the supplied descriptor buffer.
// Arena must be initialized and outlive the schema. Failure consumes arena space;
// callers should discard/reset their compile arena. No filesystem or LLVM access.
// Initial subset: proto3 scalars, nested/recursive messages and repeated fields,
// packed scalars, open enums and RPC signatures. Oneof/optional presence, maps, proto2,
// extensions and editions are rejected. This does not expose a Rut API or emit IR.
core::Expected<Schema, SchemaError> load_descriptor_set(Arena<MmapBackend>& arena,
                                                        const u8* data,
                                                        u32 size,
                                                        SchemaLimits limits = {});
}  // namespace rut::protobuf
