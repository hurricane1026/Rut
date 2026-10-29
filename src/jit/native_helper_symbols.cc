#include "rut/jit/native_helper_symbols.h"

#include "rut/jit/runtime_helpers.h"

namespace rut {
namespace {
const NativeHelperSymbol kSymbols[] = {
#define RUT_NATIVE_HELPER_ENTRY(name) {#name, reinterpret_cast<void*>(&(name))},
    RUT_NATIVE_HELPER_SYMBOLS(RUT_NATIVE_HELPER_ENTRY)
#undef RUT_NATIVE_HELPER_ENTRY
};
}  // namespace

const NativeHelperSymbol* native_helper_symbols(u32& count) {
    count = static_cast<u32>(sizeof(kSymbols) / sizeof(kSymbols[0]));
    return kSymbols;
}

void* find_native_helper(Str name) {
    if (!name.ptr || !name.len || name.len > 128) return nullptr;
    u32 count = 0;
    const auto* symbols = native_helper_symbols(count);
    for (u32 i = 0; i < count; ++i) {
        u32 n = 0;
        while (symbols[i].name[n]) ++n;
        if (name.eq({symbols[i].name, n})) return symbols[i].address;
    }
    return nullptr;
}
}  // namespace rut
