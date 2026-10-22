#pragma once

#include "rut/common/types.h"
#include "rut/runtime/grpc_timeout.h"

namespace rut {

enum class LocalGrpcDeadlineParse : u8 {
    Present,
    Invalid,
    Duplicate,
};

struct LocalGrpcDeadline {
    bool present = false;
    u64 deadline_us = 0;

    void reset() {
        present = false;
        deadline_us = 0;
    }

    bool expired(u64 now_us) const { return present && now_us >= deadline_us; }
};

inline LocalGrpcDeadlineParse local_grpc_deadline_from_value(Str value,
                                                             u64 base_us,
                                                             LocalGrpcDeadline& out) {
    if (out.present) return LocalGrpcDeadlineParse::Duplicate;
    u64 timeout_us = 0;
    if (!grpc_timeout(value, &timeout_us)) return LocalGrpcDeadlineParse::Invalid;
    out.present = true;
    out.deadline_us = UINT64_MAX - base_us < timeout_us ? UINT64_MAX : base_us + timeout_us;
    return LocalGrpcDeadlineParse::Present;
}

}  // namespace rut
