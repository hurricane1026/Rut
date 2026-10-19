#pragma once
#include "rut/runtime/protobuf_value.h"

namespace rut::protobuf {
inline constexpr u64 kRepeated = u64{1} << 62;
inline constexpr u32 kMaxArrayElements = 512;
inline constexpr u32 kMaxRequestArrayElements = 4096;
inline constexpr u32 kMaxRequestValueBytes = 262144;
struct ArrayPlan {
    u32 count = 0;
    u32 bytes = 0;
};
inline u32 array_element_size(u8 type) {
    if (type == 9 || type == 12) return sizeof(Str);
    if (type == 8) return sizeof(u8);
    if (type == 5 || type == 15 || type == 17) return sizeof(i32);
    if (type == 3 || type == 16 || type == 18 || type == 7 || type == 13) return sizeof(i64);
    return 0;
}
// Two bounded scans: validate/count, then fill caller-provided contiguous slots.
// The caller keeps the input immutable between scans. String payloads are copied
// into a separate, exact-sized byte allocation; no slot borrows receive storage.
template <typename Visit>
inline bool walk_array(u64 op, Str input, Visit visit) {
    const u32 tag = static_cast<u32>((op & ~(kRepeated | kEncode)) >> 8);
    const u8 type = static_cast<u8>(op);
    if (!tag || tag > 0x1fffffff || !array_element_size(type) || input.len > kMaxMessageBytes ||
        (input.len && !input.ptr))
        return false;
    const u8 wire = type == 9 || type == 12 ? 2 : type == 7 || type == 15 ? 5 : type == 16 ? 1 : 0;
    Reader reader(reinterpret_cast<const u8*>(input.ptr), input.len);
    Field field;
    Status status;
    u32 count = 0;
    while ((status = reader.next(field)) == Status::Field) {
        if (field.number != tag || (field.wire != wire && !(wire != 2 && field.wire == 2)))
            continue;
        const bool packed = wire != 2 && field.wire == 2;
        u32 cursor = 0;
        do {
            u64 raw = field.value;
            Str bytes{};
            if (packed) {
                if (cursor == field.size) break;
                if (wire == 0) {
                    if (!read_varint(field.bytes, field.size, cursor, raw)) return false;
                } else {
                    const u32 width = wire == 1 ? 8 : 4;
                    if (width > field.size - cursor) return false;
                    raw = 0;
                    for (u32 i = 0; i < width; ++i)
                        raw |= static_cast<u64>(field.bytes[cursor++]) << (8 * i);
                }
            } else if (wire == 2) {
                bytes = {reinterpret_cast<const char*>(field.bytes), field.size};
                if (type == 9 && !utf8(bytes)) return false;
            }
            i64 value = static_cast<i64>(raw);
            if (type == 17)
                value = zigzag_decode(static_cast<u32>(raw));
            else if (type == 18)
                value = zigzag_decode(raw);
            else if (type == 5 || type == 15)
                value = static_cast<i32>(raw);
            else if (type == 7 || type == 13)
                value = static_cast<u32>(raw);
            else if (type == 8)
                value = raw != 0;
            if (count == kMaxArrayElements || !visit(count, value, bytes)) return false;
            ++count;
        } while (packed && cursor < field.size);
    }
    return status == Status::End;
}
inline bool plan_array(u64 op, Str input, ArrayPlan& out) {
    ArrayPlan plan{};
    if (!walk_array(op, input, [&](u32, i64, Str bytes) {
            if (bytes.len > kMaxMessageBytes - plan.bytes) return false;
            ++plan.count;
            plan.bytes += bytes.len;
            return true;
        }))
        return false;
    out = plan;
    return true;
}
inline bool fill_array(u64 op, Str input, u8* slots, u8* payload, const ArrayPlan& plan) {
    const u8 type = static_cast<u8>(op);
    const u32 stride = array_element_size(type);
    u32 copied = 0, count = 0;
    if (!stride || plan.count > kMaxArrayElements || (plan.count && !slots) ||
        (plan.bytes && !payload))
        return false;
    if (!walk_array(op, input, [&](u32 index, i64 value, Str bytes) {
            if (index >= plan.count || copied > plan.bytes || bytes.len > plan.bytes - copied)
                return false;
            u8* slot = slots + static_cast<u64>(index) * stride;
            if (type == 9 || type == 12) {
                const Str owned{bytes.len ? reinterpret_cast<const char*>(payload + copied) : "",
                                bytes.len};
                if (bytes.len) __builtin_memcpy(payload + copied, bytes.ptr, bytes.len);
                copied += bytes.len;
                __builtin_memcpy(slot, &owned, sizeof(owned));
            } else if (stride == 1) {
                const u8 scalar = value != 0;
                __builtin_memcpy(slot, &scalar, 1);
            } else if (stride == 4) {
                const i32 scalar = static_cast<i32>(value);
                __builtin_memcpy(slot, &scalar, 4);
            } else
                __builtin_memcpy(slot, &value, 8);
            ++count;
            return true;
        }))
        return false;
    return count == plan.count && copied == plan.bytes;
}
inline bool encode_array(
    u64 op, Str prefix, const u8* slots, u32 count, u8* output, u32 capacity, Str& result) {
    const u8 type = static_cast<u8>(op);
    const u32 stride = array_element_size(type);
    const u32 tag = static_cast<u32>((op & ~(kRepeated | kEncode)) >> 8);
    if (!stride || !tag || tag > 0x1fffffff || count > kMaxArrayElements || (count && !slots) ||
        !prefix.ptr || prefix.len > kMaxMessageBytes || prefix.len > capacity || !output)
        return false;
    if (prefix.len) __builtin_memcpy(output, prefix.ptr, prefix.len);
    Writer writer(output + prefix.len, capacity - prefix.len);
    const u8 wire = type == 9 || type == 12 ? 2 : type == 7 || type == 15 ? 5 : type == 16 ? 1 : 0;
    for (u32 i = 0; i < count; ++i) {
        const u8* slot = slots + static_cast<u64>(i) * stride;
        i64 scalar = 0;
        Str bytes{};
        if (wire == 2) {
            __builtin_memcpy(&bytes, slot, sizeof(bytes));
            if (bytes.len > kMaxMessageBytes || (bytes.len && !bytes.ptr) ||
                (type == 9 && !utf8(bytes)))
                return false;
        } else if (stride == 1)
            scalar = *slot != 0;
        else if (stride == 4) {
            i32 value = 0;
            __builtin_memcpy(&value, slot, 4);
            scalar = value;
        } else
            __builtin_memcpy(&scalar, slot, 8);
        if ((type == 7 || type == 13) && (scalar < 0 || static_cast<u64>(scalar) > 0xffffffffu))
            return false;
        const u64 value =
            type == 17 || type == 18 ? zigzag_encode(scalar) : static_cast<u64>(scalar);
        if (!writer.write({tag, wire, value, reinterpret_cast<const u8*>(bytes.ptr), bytes.len}))
            return false;
    }
    if (writer.size() > kMaxMessageBytes - prefix.len) return false;
    result = {reinterpret_cast<const char*>(output), prefix.len + writer.size()};
    return true;
}
}  // namespace rut::protobuf
