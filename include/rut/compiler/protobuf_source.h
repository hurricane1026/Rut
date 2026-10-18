#pragma once

#include "rut/compiler/protobuf_schema.h"

namespace rut::protobuf {
struct SourceError {
    enum class Kind : u8 { Io, Syntax, Unsupported, Limit, Allocation, Schema };
    Kind kind = Kind::Syntax;
    Str file{};
    u32 line = 1;
    u32 column = 1;
    Str detail{};
};
// Built-in proto3 compiler front end. Imports resolve under the root file's
// directory; no subprocess, generated source, protoc or protobuf library.
// All source/schema/diagnostic strings belong to arena, including on failure.
core::Expected<Schema, SourceError> load_proto_source(Arena<MmapBackend>& arena,
                                                      Str path,
                                                      SchemaLimits limits = {});
}  // namespace rut::protobuf
