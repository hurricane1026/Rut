#pragma once

#include "rut/common/types.h"

#include <errno.h>
#include <unistd.h>

namespace rut {

inline void signal_background_timer_eventfd(i32 fd) {
    const u64 one = 1;
    // A saturated eventfd is already readable. The mailbox holds the work.
    while (write(fd, &one, sizeof(one)) < 0 && errno == EINTR) {
    }
}

inline void drain_background_timer_eventfd(i32 fd) {
    u64 signals;
    while (read(fd, &signals, sizeof(signals)) < 0 && errno == EINTR) {
    }
}

}  // namespace rut
