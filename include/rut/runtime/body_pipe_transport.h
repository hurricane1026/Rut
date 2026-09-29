#pragma once

#include "rut/runtime/io_event.h"

namespace rut {

// Raw ring tags live outside IoEventType. A distinct kind for the cancel SQE
// prevents its positive result from being mistaken for transferred bytes.
// Keep the entire 32-bit serial; the owner must never wrap/reuse it while a
// stale target or cancel can exist, including across connection slot reuse.
enum class BodyPipeOperation : u8 {
    Input,
    Output,
    InputReady,
    OutputReady,
    CancelInput,
    CancelOutput,
    CancelInputReady,
    CancelOutputReady,
    Count,
};
inline constexpr u8 kBodyPipeRawTag = 0x80;
struct BodyPipeToken {
    u32 conn_id = 0;
    u32 serial = 0;
    BodyPipeOperation operation = BodyPipeOperation::Count;
};
inline constexpr bool is_body_pipe_raw_tag(u8 tag) {
    return tag >= kBodyPipeRawTag && tag < kBodyPipeRawTag + 8;
}
inline constexpr u64 encode_body_pipe_token(const BodyPipeToken& token) {
    if (token.conn_id > kIoUserDataMaxConnId || token.serial == 0 ||
        static_cast<u8>(token.operation) >= static_cast<u8>(BodyPipeOperation::Count))
        return kInvalidIoUserData;
    return (static_cast<u64>(token.serial) << 32) | (static_cast<u64>(token.conn_id) << 8) |
           (kBodyPipeRawTag + static_cast<u8>(token.operation));
}
inline constexpr bool decode_body_pipe_token(u64 data, BodyPipeToken* out) {
    const u8 tag = static_cast<u8>(data);
    const u32 serial = static_cast<u32>(data >> 32);
    if (!out || !is_body_pipe_raw_tag(tag) || serial == 0) return false;
    *out = {static_cast<u32>((data >> 8) & kIoUserDataMaxConnId),
            serial,
            static_cast<BodyPipeOperation>(tag - kBodyPipeRawTag)};
    return true;
}
inline constexpr bool body_pipe_operation_is_target(BodyPipeOperation op) {
    return static_cast<u8>(op) < 4;
}
inline constexpr BodyPipeOperation body_pipe_cancel_operation(BodyPipeOperation target) {
    return body_pipe_operation_is_target(target)
               ? static_cast<BodyPipeOperation>(static_cast<u8>(target) + 4)
               : BodyPipeOperation::Count;
}

}  // namespace rut
