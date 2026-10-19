#pragma once

#include "rut/common/types.h"
#include "rut/runtime/protobuf_wire.h"

namespace rut::protobuf {
inline constexpr u32 kMaxMessageBytes = 8192;
inline constexpr u64 kEncode = u64{1} << 63;
// No schema reflection: the compiler embeds the field number/type in each op.
inline bool utf8(Str input) {
    u32 remaining = 0, code = 0, minimum = 0;
    for (u32 i = 0; i < input.len; ++i) {
        const u8 kByte = static_cast<u8>(input.ptr[i]);
        if (!remaining) {
            if (kByte < 0x80) continue;
            if (kByte >= 0xc2 && kByte <= 0xdf) {
                remaining = 1;
                code = kByte & 31;
                minimum = 0x80;
            } else if (kByte >= 0xe0 && kByte <= 0xef) {
                remaining = 2;
                code = kByte & 15;
                minimum = 0x800;
            } else if (kByte >= 0xf0 && kByte <= 0xf4) {
                remaining = 3;
                code = kByte & 7;
                minimum = 0x10000;
            } else
                return false;
        } else {
            if ((kByte & 0xc0) != 0x80) return false;
            code = (code << 6) | (kByte & 63);
            if (!--remaining &&
                (code < minimum || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)))
                return false;
        }
    }
    return !remaining;
}
// output is scratch storage and must not overlap a/b. The returned view may
// borrow a/b or output; callers must own/copy it before source reuse.
inline bool apply(
    u64 op, Str a, Str b, i64 number, u8* output, u32 capacity, Str& view, i64& scalar) {
    view = {"", 0};
    scalar = 0;
    if (a.len > kMaxMessageBytes || (a.len && !a.ptr)) return false;
    if (op == 2) {
        view = a;
        return a.ptr != nullptr;
    }
    const bool kEncoding = (op & kEncode) != 0;
    const u32 kTag = static_cast<u32>((op & ~kEncode) >> 8);
    const u32 kType = static_cast<u32>(op & 255);
    if (!op || op == 3) {
        if (op == 3 && !a.ptr) return false;
        Reader reader(reinterpret_cast<const u8*>(a.ptr), a.len);
        Field field;
        Status status;
        while ((status = reader.next(field)) == Status::Field) {
        }
        return status == Status::End;
    }
    if (!kTag || kTag > 0x1fffffff || kType > 18 || !kType || kType == 1 || kType == 2 ||
        kType == 4 || kType == 6 || kType == 10 || kType == 14)
        return false;
    const u8 kWire = kType == 9 || kType == 11 || kType == 12 ? 2
                     : kType == 7 || kType == 15              ? 5
                     : kType == 16                            ? 1
                                                              : 0;
    if (!kEncoding) {
        if (kType == 11 && !a.ptr) return false;
        u32 merged = 0;
        Reader reader(reinterpret_cast<const u8*>(a.ptr), a.len);
        Field field;
        Status status;
        while ((status = reader.next(field)) == Status::Field) {
            if (field.number != kTag || field.wire != kWire) continue;
            if (kType == 11) {
                // Each duplicate is a complete submessage; concatenation must
                // not repair a truncated fragment using the next occurrence.
                Reader nested(field.bytes, field.size);
                Field child;
                Status nested_status;
                while ((nested_status = nested.next(child)) == Status::Field) {
                }
                if (nested_status != Status::End) return false;
                if (field.size > capacity - merged || field.size > kMaxMessageBytes - merged)
                    return false;
                if (field.size) __builtin_memcpy(output + merged, field.bytes, field.size);
                merged += field.size;
                view = {reinterpret_cast<const char*>(output), merged};
            } else if (kWire == 2) {
                view = {reinterpret_cast<const char*>(field.bytes), field.size};
                if (kType == 9 && !utf8(view)) return false;
            } else if (kType == 17)
                scalar = zigzag_decode(static_cast<u32>(field.value));
            else if (kType == 18)
                scalar = zigzag_decode(field.value);
            else if (kType == 8)
                scalar = field.value != 0;
            else if (kType == 5 || kType == 15)
                scalar = static_cast<i32>(field.value);
            else if (kType == 7 || kType == 13)
                scalar = static_cast<u32>(field.value);
            else
                scalar = static_cast<i64>(field.value);
        }
        return status == Status::End;
    }
    if (!a.ptr || b.len > kMaxMessageBytes || (b.len && !b.ptr)) return false;
    if (kType == 11 && !b.ptr) return false;
    if (kType == 9 && !utf8(b)) return false;
    if (kType == 7 || kType == 13)
        if (number < 0 || static_cast<u64>(number) > 0xffffffffu) return false;
    if ((kWire == 2 && kType != 11 && !b.len) || (kWire != 2 && !number)) {
        view = a;
        return true;
    }
    u64 value = static_cast<u64>(number);
    if (kType == 17 || kType == 18) value = zigzag_encode(number);
    if (kType == 8) value = number != 0;
    if (a.len > capacity) return false;
    if (a.len) __builtin_memcpy(output, a.ptr, a.len);
    Writer writer(output + a.len, capacity - a.len);
    if (!writer.write({kTag, kWire, value, reinterpret_cast<const u8*>(b.ptr), b.len}))
        return false;
    if (writer.size() > kMaxMessageBytes - a.len) return false;
    view = {reinterpret_cast<const char*>(output), a.len + writer.size()};
    return true;
}
}  // namespace rut::protobuf
