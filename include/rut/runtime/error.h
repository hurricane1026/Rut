#pragma once

#include "rut/common/types.h"

#include <errno.h>

namespace rut {

// A kernel errno fits i32 in either sign. Widen before negating so the
// arithmetic is defined for the entire storage type.
constexpr i32 reverse_kernel_error(i32 value) {
    return static_cast<i32>(-static_cast<i64>(value));
}

// Runtime error — carries errno + context about where the error occurred.
// Used as the E type in Expected<T, Error> for init/setup functions.
struct Error {
    i32 code;  // errno value (positive, e.g., ENOMEM=12)

    enum class Source : u8 {
        Mmap,        // mmap failed
        Epoll,       // epoll_create/ctl failed
        IoUring,     // io_uring_setup/register failed
        Timerfd,     // timerfd_create/settime failed
        Socket,      // socket/bind/listen failed
        Thread,      // pthread_create failed
        Arena,       // Arena block allocation failed
        SlicePool,   // SlicePool init failed
        SlabPool,    // SlabPool init failed
        RouteTable,  // RouteTable capacity exceeded
        HttpParser,  // HTTP parse error (invalid input)
        Kqueue,      // kqueue/kevent failed
        Pipe,        // worker notification pipe setup failed
    };
    Source source;

    static Error from_errno(Source src) { return {static_cast<i32>(errno), src}; }
    static Error make(i32 code, Source src) { return {code, src}; }
};

}  // namespace rut
