#pragma once

#include "rut/runtime/arena.h"
#include "rut/runtime/protobuf_array.h"
#include "rut/runtime/slice_pool.h"

namespace rut::protobuf {
inline constexpr u64 kStructArray = u64{1} << 61;

// Compiler-owned, little-endian layout: size, alignment, field count, followed
// by (tag, type | repeated<<8, offset, child-layout length, child-layout bytes).
// Only native bool/i32/i64/Str/array/struct carriers are admitted. No source
// schema, descriptor object, or filesystem lookup survives compilation.
namespace struct_array_detail {
struct FieldLayout {
    u32 tag = 0, type = 0, offset = 0;
    bool repeated = false;
    Str child{};
};
struct Layout {
    u32 size = 0, alignment = 1, count = 0;
    FieldLayout fields[8]{};
};
inline bool word(Str input, u32& cursor, u32& out) {
    if (cursor > input.len || input.len - cursor < 4 || !input.ptr) return false;
    out = 0;
    for (u32 i = 0; i < 4; ++i)
        out |= static_cast<u32>(static_cast<u8>(input.ptr[cursor++])) << (8 * i);
    return true;
}
inline bool layout(Str bytes, Layout& out, u32 depth = 0) {
    if (depth > 8 || bytes.len > kMaxMessageBytes) return false;
    u32 cursor = 0;
    if (!word(bytes, cursor, out.size) || !word(bytes, cursor, out.alignment) ||
        !word(bytes, cursor, out.count) || out.count > 8 || !out.alignment || out.alignment > 8 ||
        (out.alignment & (out.alignment - 1)) ||
        out.size > SlicePool::kSliceSize - SliceArena::Block::kHeaderSize)
        return false;
    u32 position = 0, alignment = 1;
    for (u32 i = 0; i < out.count; ++i) {
        auto& field = out.fields[i];
        u32 flags = 0, length = 0;
        if (!word(bytes, cursor, field.tag) || !word(bytes, cursor, flags) ||
            !word(bytes, cursor, field.offset) || !word(bytes, cursor, length) || !field.tag ||
            field.tag > 0x1fffffff || flags > 511 || length > bytes.len - cursor)
            return false;
        field.type = flags & 255;
        field.repeated = flags & 256;
        field.child = {bytes.ptr + cursor, length};
        cursor += length;
        u32 size = array_element_size(static_cast<u8>(field.type));
        u32 align = size == 1 ? 1 : size == 4 ? 4 : 8;
        if (field.type == 11) {
            Layout child;
            if (!layout(field.child, child, depth + 1)) return false;
            size = child.size;
            align = child.alignment;
        } else if (!size || length)
            return false;
        if (field.repeated) {
            size = sizeof(Str);
            align = alignof(Str);
        }
        position = (position + align - 1) & ~(align - 1);
        if (field.offset != position || size > out.size || position > out.size - size) return false;
        position += size;
        if (alignment < align) alignment = align;
        for (u32 j = 0; j < i; ++j)
            if (field.tag == out.fields[j].tag) return false;
    }
    return cursor == bytes.len && alignment == out.alignment &&
           ((position + alignment - 1) & ~(alignment - 1)) == out.size;
}
struct Budget {
    u32 items = 0, slots = 0, bytes = 0;
    bool array(u32 count, u32 stride) {
        if (count > kMaxArrayElements || count > kMaxRequestArrayElements - items ||
            (stride && count > (SlicePool::kSliceSize - SliceArena::Block::kHeaderSize) / stride))
            return false;
        const u32 allocation = (count * stride + 7) & ~7u;
        if (allocation > kMaxRequestValueBytes - slots) return false;
        items += count;
        slots += allocation;
        return true;
    }
    bool payload(u32 count) {
        if (count > kMaxMessageBytes - bytes) return false;
        bytes += count;
        return true;
    }
};
inline u64 array_op(u32 tag, u32 type) {
    return kRepeated | (static_cast<u64>(tag) << 8) | type;
}
// Message occurrences use the byte-array walker, retaining separate wire
// boundaries: malformed duplicate fragments cannot repair one another.
template <typename Visit>
inline bool messages(u32 tag, Str input, Visit visit) {
    return walk_array(
        array_op(tag, 12), input, [&](u32 index, i64, Str bytes) { return visit(index, bytes); });
}
inline bool measure_message(Str schema, Str input, Budget& budget, u32 depth);
inline bool measure_array(u32 tag, Str schema, Str input, Budget& budget, u32 depth) {
    Layout plan;
    if (depth > 8 || !layout(schema, plan)) return false;
    u32 count = 0;
    if (!messages(tag, input, [&](u32, Str bytes) {
            ++count;
            return measure_message(schema, bytes, budget, depth);
        }))
        return false;
    return budget.array(count, plan.size);
}
inline bool measure_message(Str schema, Str input, Budget& budget, u32 depth) {
    Layout plan;
    if (depth > 8 || !layout(schema, plan)) return false;
    u8 scratch[kMaxMessageBytes];
    Str selected;
    i64 scalar = 0;
    if (!apply(3, input, {}, 0, scratch, sizeof(scratch), selected, scalar)) return false;
    for (u32 i = 0; i < plan.count; ++i) {
        const auto& f = plan.fields[i];
        if (f.repeated) {
            if (f.type == 11) {
                if (!measure_array(f.tag, f.child, input, budget, depth + 1)) return false;
            } else {
                ArrayPlan array;
                if (!plan_array(array_op(f.tag, f.type), input, array) ||
                    !budget.array(array.count, array_element_size(static_cast<u8>(f.type))) ||
                    !budget.payload(array.bytes))
                    return false;
            }
        } else {
            if (!apply((static_cast<u64>(f.tag) << 8) | f.type,
                       input,
                       {},
                       0,
                       scratch,
                       sizeof(scratch),
                       selected,
                       scalar))
                return false;
            if (f.type == 11) {
                if (!measure_message(f.child, selected, budget, depth + 1)) return false;
            } else if (!budget.payload(selected.len))
                return false;
        }
    }
    return true;
}
struct Fill {
    SliceArena& arena;
    u8* payload;
    u32 capacity, copied = 0;
    bool copy(Str input, Str& output) {
        if (input.len > capacity - copied) return false;
        output = {input.len ? reinterpret_cast<const char*>(payload + copied) : "", input.len};
        if (input.len) __builtin_memcpy(payload + copied, input.ptr, input.len);
        copied += input.len;
        return true;
    }
};
inline bool fill_message(Str schema, Str input, u8* output, Fill& fill, u32 depth);
inline bool fill_messages(u32 tag, Str schema, Str input, Str& output, Fill& fill, u32 depth) {
    Layout plan;
    if (depth > 8 || !layout(schema, plan)) return false;
    u32 count = 0;
    if (!messages(tag, input, [&](u32, Str) {
            ++count;
            return true;
        }))
        return false;
    auto* slots = count && plan.size
                      ? static_cast<u8*>(fill.arena.alloc(static_cast<u64>(count) * plan.size))
                      : nullptr;
    if (count && plan.size && !slots) return false;
    if (!messages(tag, input, [&](u32 index, Str bytes) {
            return fill_message(schema,
                                bytes,
                                slots ? slots + static_cast<u64>(index) * plan.size : nullptr,
                                fill,
                                depth);
        }))
        return false;
    output = {slots ? reinterpret_cast<const char*>(slots) : "", count};
    return true;
}
inline bool fill_message(Str schema, Str input, u8* output, Fill& fill, u32 depth) {
    Layout plan;
    if (depth > 8 || !layout(schema, plan)) return false;
    if (plan.size) __builtin_memset(output, 0, plan.size);
    u8 scratch[kMaxMessageBytes];
    Str selected;
    i64 scalar = 0;
    for (u32 i = 0; i < plan.count; ++i) {
        const auto& f = plan.fields[i];
        u8* slot = output ? output + f.offset : nullptr;
        if (f.repeated) {
            Str array;
            if (f.type == 11) {
                if (!fill_messages(f.tag, f.child, input, array, fill, depth + 1)) return false;
            } else {
                ArrayPlan array_plan;
                const u64 op = array_op(f.tag, f.type);
                if (!plan_array(op, input, array_plan) ||
                    array_plan.bytes > fill.capacity - fill.copied)
                    return false;
                const u32 bytes = array_plan.count * array_element_size(static_cast<u8>(f.type));
                auto* data = bytes ? static_cast<u8*>(fill.arena.alloc(bytes)) : nullptr;
                if (bytes && !data) return false;
                if (!fill_array(op,
                                input,
                                data,
                                array_plan.bytes ? fill.payload + fill.copied : nullptr,
                                array_plan))
                    return false;
                fill.copied += array_plan.bytes;
                array = {data ? reinterpret_cast<const char*>(data) : "", array_plan.count};
            }
            __builtin_memcpy(slot, &array, sizeof(array));
        } else {
            if (!apply((static_cast<u64>(f.tag) << 8) | f.type,
                       input,
                       {},
                       0,
                       scratch,
                       sizeof(scratch),
                       selected,
                       scalar))
                return false;
            if (f.type == 11) {
                if (!fill_message(f.child, selected, slot, fill, depth + 1)) return false;
            } else if (f.type == 9 || f.type == 12) {
                Str owned;
                if (!fill.copy(selected, owned)) return false;
                __builtin_memcpy(slot, &owned, sizeof(owned));
            } else {
                const u32 size = array_element_size(static_cast<u8>(f.type));
                if (size == 1) {
                    const u8 value = scalar != 0;
                    __builtin_memcpy(slot, &value, 1);
                } else if (size == 4) {
                    const i32 value = static_cast<i32>(scalar);
                    __builtin_memcpy(slot, &value, 4);
                } else
                    __builtin_memcpy(slot, &scalar, 8);
            }
        }
    }
    return true;
}
inline bool encode_message(
    Str schema, const u8* input, u8* output, u32 capacity, u32& size, Budget& budget, u32 depth);
inline bool encode_messages(u32 tag,
                            Str schema,
                            Str array,
                            u8* output,
                            u32 capacity,
                            u32& size,
                            Budget& budget,
                            u32 depth) {
    Layout plan;
    if (depth > 8 || !layout(schema, plan) || !budget.array(array.len, plan.size) ||
        (array.len && !array.ptr))
        return false;
    Writer writer(output, capacity);
    for (u32 i = 0; i < array.len; ++i) {
        u8 scratch[kMaxMessageBytes];
        u32 bytes = 0;
        if (!encode_message(
                schema,
                reinterpret_cast<const u8*>(array.ptr) + static_cast<u64>(i) * plan.size,
                scratch,
                sizeof(scratch),
                bytes,
                budget,
                depth) ||
            !writer.write({tag, 2, 0, scratch, bytes}))
            return false;
    }
    size = writer.size();
    return true;
}
inline bool encode_message(
    Str schema, const u8* input, u8* output, u32 capacity, u32& size, Budget& budget, u32 depth) {
    Layout plan;
    if (depth > 8 || !layout(schema, plan) || (plan.size && !input)) return false;
    u32 position = 0;
    for (u32 i = 0; i < plan.count; ++i) {
        const auto& f = plan.fields[i];
        const u8* slot = input ? input + f.offset : nullptr;
        if (f.repeated) {
            Str array;
            __builtin_memcpy(&array, slot, sizeof(array));
            u32 bytes = 0;
            if (f.type == 11) {
                if (!encode_messages(f.tag,
                                     f.child,
                                     array,
                                     output + position,
                                     capacity - position,
                                     bytes,
                                     budget,
                                     depth + 1))
                    return false;
            } else {
                Str encoded;
                if (!budget.array(array.len, array_element_size(static_cast<u8>(f.type))) ||
                    !encode_array(array_op(f.tag, f.type) | kEncode,
                                  {"", 0},
                                  reinterpret_cast<const u8*>(array.ptr),
                                  array.len,
                                  output + position,
                                  capacity - position,
                                  encoded))
                    return false;
                bytes = encoded.len;
            }
            position += bytes;
        } else {
            Str bytes{};
            i64 value = 0;
            u8 scratch[kMaxMessageBytes];
            if (f.type == 11) {
                u32 length = 0;
                if (!encode_message(
                        f.child, slot, scratch, sizeof(scratch), length, budget, depth + 1))
                    return false;
                bytes = {reinterpret_cast<const char*>(scratch), length};
            } else if (f.type == 9 || f.type == 12) {
                __builtin_memcpy(&bytes, slot, sizeof(bytes));
                if (bytes.len > kMaxMessageBytes || (bytes.len && !bytes.ptr) ||
                    (f.type == 9 && !utf8(bytes)))
                    return false;
                if (!bytes.len) continue;
            } else {
                const u32 width = array_element_size(static_cast<u8>(f.type));
                if (width == 1)
                    value = *slot != 0;
                else if (width == 4) {
                    i32 narrow = 0;
                    __builtin_memcpy(&narrow, slot, 4);
                    value = narrow;
                } else
                    __builtin_memcpy(&value, slot, 8);
                if ((f.type == 7 || f.type == 13) &&
                    (value < 0 || static_cast<u64>(value) > 0xffffffffu))
                    return false;
                if (!value) continue;
            }
            const u8 wire = f.type == 9 || f.type == 11 || f.type == 12 ? 2
                            : f.type == 7 || f.type == 15               ? 5
                            : f.type == 16                              ? 1
                                                                        : 0;
            const u64 raw =
                f.type == 17 || f.type == 18 ? zigzag_encode(value) : static_cast<u64>(value);
            Writer writer(output + position, capacity - position);
            if (!writer.write(
                    {f.tag, wire, raw, reinterpret_cast<const u8*>(bytes.ptr), bytes.len}))
                return false;
            position += writer.size();
        }
    }
    size = position;
    return true;
}
}  // namespace struct_array_detail

inline bool decode_struct_array(u32 tag,
                                Str schema,
                                Str input,
                                SliceArena* arena,
                                Str& output,
                                const struct_array_detail::Budget* measured = nullptr) {
    // A supplied plan must come from measure_array on this immutable schema/input pair.
    using namespace struct_array_detail;
    Budget budget;
    if (measured != nullptr)
        budget = *measured;
    else if (!measure_array(tag, schema, input, budget, 0))
        return false;
    if (!budget.items) {
        output = {"", 0};
        return true;
    }
    const u32 needed = budget.slots + ((budget.bytes + 7) & ~7u);
    if (!arena || arena->collection_items() > kMaxRequestArrayElements - budget.items ||
        needed > kMaxRequestValueBytes || arena->space_used() > kMaxRequestValueBytes - needed)
        return false;
    auto* payload = budget.bytes ? static_cast<u8*>(arena->alloc(budget.bytes)) : nullptr;
    if (budget.bytes && !payload) return false;
    Fill fill{*arena, payload, budget.bytes};
    Str result;
    if (!fill_messages(tag, schema, input, result, fill, 0) || fill.copied != budget.bytes)
        return false;
    arena->set_collection_items(arena->collection_items() + budget.items);
    output = result;
    return true;
}
inline bool encode_struct_array(
    u32 tag, Str schema, Str prefix, Str array, u8* output, u32 capacity, Str& result) {
    if (capacity > kMaxMessageBytes) capacity = kMaxMessageBytes;
    if (!tag || tag > 0x1fffffff || !output || !prefix.ptr || prefix.len > capacity) return false;
    if (prefix.len) __builtin_memcpy(output, prefix.ptr, prefix.len);
    struct_array_detail::Budget budget;
    u32 bytes = 0;
    if (!struct_array_detail::encode_messages(
            tag, schema, array, output + prefix.len, capacity - prefix.len, bytes, budget, 0) ||
        bytes > kMaxMessageBytes - prefix.len)
        return false;
    result = {reinterpret_cast<const char*>(output), prefix.len + bytes};
    return true;
}
}  // namespace rut::protobuf
