#pragma once

#include "rut/common/types.h"

namespace rut {

// Typed application-message inputs for the shared compiler backend. These are
// language values, independent of the frame parser's wire representation.
enum class WsMessageFieldId : u8 {
    Payload,
    Length,
    Kind,
    Direction,
    FromClient,
    IsText,
    IsBinary,
};

constexpr bool ws_message_field_valid(u32 field) {
    return field <= static_cast<u32>(WsMessageFieldId::IsBinary);
}

}  // namespace rut
