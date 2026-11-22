#pragma once

#include "rut/common/types.h"

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

constexpr IoTimespec io_timespec_from_ms(u32 ms) {
    IoTimespec ts{};
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = static_cast<decltype(ts.tv_nsec)>(ms % 1000) * 1'000'000;
    return ts;
}

constexpr bool valid_positive_io_timespec(const IoTimespec& ts) {
    return ts.tv_sec >= 0 && ts.tv_nsec >= 0 && ts.tv_nsec < 1'000'000'000 &&
           (ts.tv_sec != 0 || ts.tv_nsec != 0);
}

}  // namespace rut
