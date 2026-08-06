#pragma once

#include "rut/common/types.h"

#include <errno.h>

namespace rut {

inline bool signal_wait_failed(i32 result, i32 saved_errno) {
    return result < 0 && saved_errno != EAGAIN && saved_errno != EINTR;
}

}  // namespace rut
