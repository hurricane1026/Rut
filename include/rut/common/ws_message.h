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
    ConnectionRemoteAddr,
    ConnectionRemotePort,
    ConnectionIsTls,
    ConnectionSubprotocol,
};

constexpr bool ws_message_field_valid(u32 field) {
    return field <= static_cast<u32>(WsMessageFieldId::ConnectionSubprotocol);
}

constexpr bool ws_message_field_is_string(WsMessageFieldId field) {
    return field == WsMessageFieldId::Payload || field == WsMessageFieldId::ConnectionSubprotocol;
}

constexpr bool ws_message_field_is_bool(WsMessageFieldId field) {
    return field == WsMessageFieldId::FromClient || field == WsMessageFieldId::IsText ||
           field == WsMessageFieldId::IsBinary || field == WsMessageFieldId::ConnectionIsTls;
}

}  // namespace rut
