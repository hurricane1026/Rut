#pragma once

#include "rut/common/range_int.h"

#ifdef __linux__
#include <linux/time_types.h>
#else
#include <time.h>
#endif

namespace rut {

#ifdef __linux__
using IoTimespec = __kernel_timespec;
#else
using IoTimespec = timespec;
#endif

[[nodiscard]] constexpr IoTimespec io_timespec_from_ms(u32 ms) {
    const auto seconds = range_int(ms).divided_by<1000>();
    const auto nanos = bounded_remainder<1000>(ms).scaled_by<1'000'000>();
    return {seconds.to<i32>(), nanos.to<i32>()};
}

[[nodiscard]] constexpr bool valid_positive_io_timespec(const IoTimespec& ts) {
    return ts.tv_sec >= 0 && ts.tv_nsec >= 0 && ts.tv_nsec < 1'000'000'000 &&
           (ts.tv_sec != 0 || ts.tv_nsec != 0);
}

}  // namespace rut
