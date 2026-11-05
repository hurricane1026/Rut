#pragma once

#include "rut/common/types.h"

namespace rut {

enum class WsCallbackPhase : u8 { Message, Open, Close };

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
    CloseCode,
    CloseReason,
    CloseUpstreamCode,
    CloseUpstreamReason,
    CloseWasClean,
};

constexpr bool ws_message_field_valid(u32 field) {
    return field <= static_cast<u32>(WsMessageFieldId::CloseWasClean);
}

constexpr bool ws_message_field_is_string(WsMessageFieldId field) {
    return field == WsMessageFieldId::Payload || field == WsMessageFieldId::ConnectionSubprotocol ||
           field == WsMessageFieldId::CloseReason || field == WsMessageFieldId::CloseUpstreamReason;
}

constexpr bool ws_message_field_is_bool(WsMessageFieldId field) {
    return field == WsMessageFieldId::FromClient || field == WsMessageFieldId::IsText ||
           field == WsMessageFieldId::IsBinary || field == WsMessageFieldId::ConnectionIsTls ||
           field == WsMessageFieldId::CloseWasClean;
}

}  // namespace rut
