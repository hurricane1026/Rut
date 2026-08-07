#pragma once

#include "rut/common/types.h"

namespace rut {

enum class BackendPreference : u8 {
    Auto,
    IoUring,
    Epoll,
};

enum class ServerBackend : u8 {
    IoUring,
    Epoll,
};

enum class BackendSelectionError : u8 {
    None,
    IoUringUnavailable,
    HealthProbesUnsupported,
};

struct BackendSelection {
    ServerBackend backend = ServerBackend::Epoll;
    BackendSelectionError error = BackendSelectionError::None;
    bool health_probe_fallback = false;

    [[nodiscard]] bool ok() const { return error == BackendSelectionError::None; }
};

inline BackendSelection select_server_backend(BackendPreference preference,
                                              bool io_uring_available,
                                              bool requires_health_probes) {
    if (preference == BackendPreference::Epoll) return {ServerBackend::Epoll};
    if (preference == BackendPreference::IoUring) {
        if (!io_uring_available)
            return {ServerBackend::IoUring, BackendSelectionError::IoUringUnavailable};
        if (requires_health_probes)
            return {ServerBackend::IoUring, BackendSelectionError::HealthProbesUnsupported};
        return {ServerBackend::IoUring};
    }
    if (requires_health_probes)
        return {ServerBackend::Epoll, BackendSelectionError::None, io_uring_available};
    return {io_uring_available ? ServerBackend::IoUring : ServerBackend::Epoll};
}

}  // namespace rut
