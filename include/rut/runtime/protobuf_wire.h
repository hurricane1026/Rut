#pragma once

#include "rut/common/types.h"

namespace rut::protobuf {
// Complete-message wire primitives. Views borrow the caller's immutable input.
// Groups are deliberately unsupported; callers must reject rather than skip them.
enum class Status : u8 { Field, End, Invalid };
struct Field {
    u32 number = 0;
    u8 wire = 0;
    u64 value = 0;
    const u8* bytes = nullptr;
    u32 size = 0;
};

inline bool read_varint(const u8* data, u32 size, u32& pos, u64& value) {
    u32 cursor = pos;
    u64 result = 0;
    for (u32 i = 0; i < 10; ++i) {
        if (cursor >= size) return false;
        const u8 kByte = data[cursor++];
        if (i == 9 && kByte > 1) return false;
        result |= static_cast<u64>(kByte & 0x7f) << (7 * i);
        if (!(kByte & 0x80)) {
            pos = cursor;
            value = result;
            return true;
        }
    }
    return false;
}

class Reader {
    const u8* storage;
    u32 length;
    u32 position = 0;
    u32 remaining_fields;
    bool failed = false;

public:
    Reader(const u8* data, u32 size, u32 max_fields = 65536)
        : storage(data), length(size), remaining_fields(max_fields) {}
    Status next(Field& out) {
        if (failed) return Status::Invalid;
        if (position == length) return Status::End;
        u32 cursor = position;
        u64 tag = 0;
        Field field;
        bool valid = storage && remaining_fields && read_varint(storage, length, cursor, tag);
        valid = valid && (tag >> 3) > 0 && (tag >> 3) <= 0x1fffffff;
        if (valid) {
            field.number = static_cast<u32>(tag >> 3);
            field.wire = static_cast<u8>(tag & 7);
            switch (field.wire) {
                case 0:
                    valid = read_varint(storage, length, cursor, field.value);
                    break;
                case 1:
                case 5: {
                    const u32 kWidth = field.wire == 1 ? 8 : 4;
                    valid = kWidth <= length - cursor;
                    if (valid) {
                        for (u32 i = 0; i < kWidth; ++i)
                            field.value |= static_cast<u64>(storage[cursor++]) << (8 * i);
                    }
                    break;
                }
                case 2: {
                    u64 payload_length = 0;
                    valid = read_varint(storage, length, cursor, payload_length);
                    valid = valid && payload_length <= length - cursor;
                    if (valid) {
                        field.bytes = storage + cursor;
                        field.size = static_cast<u32>(payload_length);
                        cursor += field.size;
                    }
                    break;
                }
                default:
                    valid = false;
            }
        }
        if (!valid) {
            failed = true;
            return Status::Invalid;
        }
        --remaining_fields;
        position = cursor;
        out = field;
        return Status::Field;
    }
};

inline u64 zigzag_encode(i64 value) {
    return (static_cast<u64>(value) << 1) ^ (value < 0 ? ~u64{0} : u64{0});
}
inline i64 zigzag_decode(u64 value) {
    return static_cast<i64>(value >> 1) ^ -static_cast<i64>(value & 1);
}

class Writer {
    u8* storage;
    u32 capacity;
    u32 length = 0;
    static u32 varint_size(u64 value) {
        u32 size = 1;
        while (value >= 128) {
            value >>= 7;
            ++size;
        }
        return size;
    }
    void varint(u64 value) {
        while (value >= 128) {
            storage[length++] = static_cast<u8>(value) | 0x80;
            value >>= 7;
        }
        storage[length++] = static_cast<u8>(value);
    }

public:
    Writer(u8* data, u32 available) : storage(data), capacity(available) {}
    u32 size() const { return length; }
    // Payload views must not overlap this writer's output storage.
    // Failure leaves both output bytes and size unchanged. Reserved schema field
    // numbers are legal wire data; descriptor validation owns schema restrictions.
    bool write(const Field& field) {
        if (!field.number || field.number > 0x1fffffff || !storage) return false;
        const u64 kTag = (static_cast<u64>(field.number) << 3) | field.wire;
        u64 needed = varint_size(kTag);
        switch (field.wire) {
            case 0:
                needed += varint_size(field.value);
                break;
            case 1:
                needed += 8;
                break;
            case 5:
                needed += 4;
                break;
            case 2:
                if (field.size && !field.bytes) return false;
                needed += varint_size(field.size) + static_cast<u64>(field.size);
                break;
            default:
                return false;
        }
        if (needed > capacity - length) return false;
        varint(kTag);
        if (field.wire == 0) {
            varint(field.value);
        } else if (field.wire == 2) {
            varint(field.size);
            if (field.size) __builtin_memmove(storage + length, field.bytes, field.size);
            length += field.size;
        } else {
            const u32 kWidth = field.wire == 1 ? 8 : 4;
            for (u32 i = 0; i < kWidth; ++i)
                storage[length++] = static_cast<u8>(field.value >> (8 * i));
        }
        return true;
    }
};
}  // namespace rut::protobuf
