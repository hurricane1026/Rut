#pragma once

#include "rut/runtime/protobuf_value.h"

namespace rut::protobuf {
// Internal wire tree, independent of compiler/LLVM types. Layouts are immutable,
// compiler-validated and must outlive each call. Values and byte views borrow
// caller storage; copy input before reusing an asynchronous receive buffer.
struct MessageLayout;
struct MessageField {
    u32 number;
    u8 type;
    bool repeated = false;
    const MessageLayout* message = nullptr;
};
struct MessageLayout {
    const MessageField* fields;
    u32 count;
};
struct MessageValue {
    u32 field = 0;   // Index in the containing layout.
    u64 scalar = 0;  // Raw protobuf bits (including ZigZag), not a Rut integer.
    Str bytes{};
    u32 child = 0;
    u32 next = 0;  // Indexes are one-based; zero is the empty list.
};
struct MessageStorage {
    MessageValue* values;
    u32 capacity;
    u32 used = 0;
};
enum class MessageStatus : u8 { Ok, Invalid, Limit };
inline constexpr u32 kMaxMessageDepth = 16;
inline constexpr u32 kMaxMessageFields = 64;

namespace message_detail {
inline u8 wire(u8 type) {
    switch (type) {
        case 1:
        case 6:
        case 16:
            return 1;
        case 2:
        case 7:
        case 15:
            return 5;
        case 9:
        case 11:
        case 12:
            return 2;
        case 3:
        case 4:
        case 5:
        case 8:
        case 13:
        case 14:
        case 17:
        case 18:
            return 0;
        default:
            return 255;
    }
}
inline bool valid(const MessageLayout& layout) {
    if (layout.count > kMaxMessageFields || (layout.count && !layout.fields)) return false;
    for (u32 i = 0; i < layout.count; ++i) {
        const auto& f = layout.fields[i];
        if (!f.number || f.number > 0x1fffffff || wire(f.type) == 255 ||
            (f.type == 11 && !f.message))
            return false;
        for (u32 j = 0; j < i; ++j)
            if (layout.fields[j].number == f.number) return false;
    }
    return true;
}
// Merge duplicate singular embedded messages, as required by proto3. Repeated
// values append in wire order. Every occurrence consumes the shared slot budget,
// even when a later scalar overwrites it, bounding total decode work/storage.
inline MessageStatus decode(
    const MessageLayout& layout, Str input, MessageStorage& storage, u32& head, u32 depth) {
    if (depth > kMaxMessageDepth) return MessageStatus::Limit;
    if (!valid(layout)) return MessageStatus::Invalid;
    u32 last[kMaxMessageFields]{};
    u32 tail = 0;
    for (u32 n = head; n; n = storage.values[n - 1].next) {
        last[storage.values[n - 1].field] = n;
        tail = n;
    }
    Reader reader(reinterpret_cast<const u8*>(input.ptr), input.len);
    Field value;
    Status status;
    while ((status = reader.next(value)) == Status::Field) {
        u32 index = 0;
        while (index < layout.count && layout.fields[index].number != value.number) ++index;
        if (index == layout.count) continue;
        const auto& field = layout.fields[index];
        const u8 kExpected = wire(field.type);
        const bool kPacked = field.repeated && kExpected != 2 && value.wire == 2;
        if (value.wire != kExpected && !kPacked) continue;
        u32 cursor = 0;
        do {
            u64 scalar = value.value;
            if (kPacked) {
                if (cursor == value.size) break;
                if (kExpected == 0) {
                    if (!read_varint(value.bytes, value.size, cursor, scalar))
                        return MessageStatus::Invalid;
                } else {
                    const u32 kWidth = kExpected == 1 ? 8 : 4;
                    if (kWidth > value.size - cursor) return MessageStatus::Invalid;
                    scalar = 0;
                    for (u32 b = 0; b < kWidth; ++b)
                        scalar |= static_cast<u64>(value.bytes[cursor++]) << (8 * b);
                }
            }
            if (storage.used == storage.capacity) return MessageStatus::Limit;
            const u32 kSlot = ++storage.used;
            storage.values[kSlot - 1] = {};
            u32 target = !field.repeated ? last[index] : 0;
            if (!target) {
                target = kSlot;
                storage.values[target - 1].field = index;
                if (tail)
                    storage.values[tail - 1].next = target;
                else
                    head = target;
                tail = target;
                last[index] = target;
            }
            auto& out = storage.values[target - 1];
            out.scalar = scalar;
            if (kExpected == 2) {
                const Str kBytes{reinterpret_cast<const char*>(value.bytes), value.size};
                if (field.type == 9 && !utf8(kBytes)) return MessageStatus::Invalid;
                if (field.type == 11) {
                    const auto kResult =
                        decode(*field.message, kBytes, storage, out.child, depth + 1);
                    if (kResult != MessageStatus::Ok) return kResult;
                } else
                    out.bytes = kBytes;
            }
        } while (kPacked && cursor < value.size);
    }
    return status == Status::End ? MessageStatus::Ok : MessageStatus::Invalid;
}
inline MessageStatus encode(const MessageLayout& layout,
                            const MessageStorage& storage,
                            u32 head,
                            u8* output,
                            u32 capacity,
                            u32& size,
                            u32 depth,
                            u32& remaining) {
    if (depth > kMaxMessageDepth) return MessageStatus::Limit;
    if (!valid(layout)) return MessageStatus::Invalid;
    u32 position = 0;
    auto varint_size = [](u64 value) {
        u32 count = 1;
        while (value >= 128) {
            value >>= 7;
            ++count;
        }
        return count;
    };
    auto emit_varint = [&](u64 value) {
        do {
            const u8 kByte = static_cast<u8>(value & 127);
            value >>= 7;
            if (output) output[position] = kByte | (value ? 128 : 0);
            ++position;
        } while (value);
    };
    for (u32 n = head; n;) {
        if (!remaining) return MessageStatus::Limit;
        --remaining;
        if (n > storage.used) return MessageStatus::Invalid;
        const auto& value = storage.values[n - 1];
        if (value.field >= layout.count) return MessageStatus::Invalid;
        const auto& field = layout.fields[value.field];
        const u8 kExpected = wire(field.type);
        const Str kBytes = value.bytes;
        u32 length = kBytes.len;
        if (field.type == 11) {
            length = 0;
            u32 budget = remaining;
            const auto kResult = encode(*field.message,
                                        storage,
                                        value.child,
                                        nullptr,
                                        kMaxMessageBytes,
                                        length,
                                        depth + 1,
                                        budget);
            if (kResult != MessageStatus::Ok) return kResult;
            if (!output) remaining = budget;
        } else if (kExpected == 2) {
            if (kBytes.len > kMaxMessageBytes) return MessageStatus::Limit;
            if (kBytes.len && !kBytes.ptr) return MessageStatus::Invalid;
            if (field.type == 9 && !utf8(kBytes)) return MessageStatus::Invalid;
        }
        // Repeated defaults and embedded-message presence must be retained.
        const bool kOmit =
            !field.repeated && field.type != 11 && (kExpected == 2 ? !length : !value.scalar);
        if (!kOmit) {
            const u64 kTag = (static_cast<u64>(field.number) << 3) | kExpected;
            const u32 kPayload = kExpected == 2   ? varint_size(length) + length
                                 : kExpected == 0 ? varint_size(value.scalar)
                                 : kExpected == 1 ? 8
                                                  : 4;
            if (varint_size(kTag) + kPayload > capacity - position) return MessageStatus::Limit;
            emit_varint(kTag);
            if (kExpected == 2) {
                emit_varint(length);
                if (output && field.type == 11) {
                    u32 written = 0;
                    const auto kResult = encode(*field.message,
                                                storage,
                                                value.child,
                                                output + position,
                                                capacity - position,
                                                written,
                                                depth + 1,
                                                remaining);
                    if (kResult != MessageStatus::Ok) return kResult;
                } else if (output && length)
                    __builtin_memcpy(output + position, kBytes.ptr, length);
                position += length;
            } else if (kExpected == 0)
                emit_varint(value.scalar);
            else {
                for (u32 i = 0; i < kPayload; ++i) {
                    if (output) output[position] = static_cast<u8>(value.scalar >> (8 * i));
                    ++position;
                }
            }
        }
        n = value.next;
    }
    size = position;
    return MessageStatus::Ok;
}
}  // namespace message_detail

// On failure no tree is published and the slot watermark is restored. Scratch
// slots/output bytes may change. Encoding output must not overlap input views. Zero-valued absent
// scalars have no tree node.
inline MessageStatus decode_message(const MessageLayout& layout,
                                    Str input,
                                    MessageStorage& storage,
                                    u32& head) {
    head = 0;
    if (storage.used > storage.capacity || (storage.capacity && !storage.values) ||
        (input.len && !input.ptr))
        return MessageStatus::Invalid;
    if (input.len > kMaxMessageBytes) return MessageStatus::Limit;
    const u32 kMark = storage.used;
    u32 result = 0;
    const auto kStatus = message_detail::decode(layout, input, storage, result, 1);
    if (kStatus == MessageStatus::Ok)
        head = result;
    else
        storage.used = kMark;
    return kStatus;
}
inline MessageStatus encode_message(const MessageLayout& layout,
                                    const MessageStorage& storage,
                                    u32 head,
                                    u8* output,
                                    u32 capacity,
                                    u32& size) {
    size = 0;
    if (storage.used > storage.capacity || (storage.used && !storage.values) || !output)
        return MessageStatus::Invalid;
    u32 remaining = storage.used;
    u32 result = 0;
    const auto kStatus =
        message_detail::encode(layout,
                               storage,
                               head,
                               output,
                               capacity < kMaxMessageBytes ? capacity : kMaxMessageBytes,
                               result,
                               1,
                               remaining);
    if (kStatus == MessageStatus::Ok) size = result;
    return kStatus;
}
}  // namespace rut::protobuf
