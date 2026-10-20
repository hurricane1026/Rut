#pragma once

#include "rut/compiler/hir.h"
#include "rut/compiler/protobuf_schema.h"

namespace rut {

// Test-only seam for descriptor metadata that the source parser deliberately
// cannot express, such as proto3_optional fields.
bool proto_array_layout_for_test(const HirModule& mod, u32 index, const protobuf::Message* message);

}  // namespace rut
