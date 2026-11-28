#include "rut/common/types.h"
#include "rut/runtime/io_event.h"

namespace rut {
namespace {

// Compute the expected successor in a wider type so the oracle cannot wrap
// when the real counter reaches UINT32_MAX.
consteval bool allocation_matches(u32 initial, u32 maximum) {
    u32 counter = initial;
    u32 owner = 73;
    const i64 kNext = i64{initial} + 1;
    const bool kFits = kNext <= maximum;
    const bool kIssued = allocate_io_generation(counter, owner, maximum);
    return kIssued == kFits && counter == (kFits ? static_cast<u32>(kNext) : initial) &&
           owner == (kFits ? static_cast<u32>(kNext) : 73);
}

consteval bool allocation_contract(u32 maximum) {
    if (!allocation_matches(static_cast<u32>(static_cast<i64>(maximum) - 1), maximum) ||
        !allocation_matches(maximum, maximum) || !allocation_matches(0xffffffffu, maximum))
        return false;
    // Exercise every carry length, and both sides of every power of two.
    for (u32 bit = 0; bit < 32; ++bit) {
        const u32 kPivot = 1u << bit;
        if (!allocation_matches(static_cast<u32>(static_cast<i64>(kPivot) - 1), maximum) ||
            !allocation_matches(kPivot, maximum) ||
            !allocation_matches(static_cast<u32>(static_cast<i64>(kPivot) + 1), maximum))
            return false;
    }
    return true;
}

static_assert(kNonUpstreamSendGenerationMask == u32{i64{kNonUpstreamSendCancelBit} - 1} &&
                  kResponseReadTimerGenerationMask == u32{i64{kResponseReadTimerCancelBit} - 1} &&
                  kNonUpstreamSendCancelBit == (1u << 31) &&
                  kResponseReadTimerCancelBit == (1u << 31),
              "Cancellation marker must remain outside the generation range");
static_assert(allocation_contract(kNonUpstreamSendGenerationMask) &&
                  allocation_contract(kResponseReadTimerGenerationMask) &&
                  allocation_contract(0xffffffffu),
              "I/O generation allocation violates the non-wrapping contract");

}  // namespace
}  // namespace rut
