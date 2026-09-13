#pragma once

#include "core/expected.h"
#include "rut/common/access_log_sink.h"
#include "rut/common/types.h"

namespace rut {

enum class AccessLogStartupMode : u8 {
    Disabled = 0,
    LegacyCli = 1,
    SourceLive = 2,
};

enum class AccessLogStartupResolutionError : u8 {
    InvalidSourceSpec,
    InvalidCliPath,
    ConflictingCliPath,
    ConflictingCliCompression,
    ConflictingCliLevel,
    ConflictingEnvironmentCompression,
};

struct AccessLogStartupInputs {
    AccessLogSinkSpec source{};
    bool cli_path_present = false;
    const char* cli_path = nullptr;
    bool cli_compression_present = false;
    bool cli_compression = false;
    bool cli_level_present = false;
    i32 cli_level = 0;
    bool environment_compression_present = false;
};

struct AccessLogStartupResolution {
    AccessLogStartupMode mode = AccessLogStartupMode::Disabled;
    // LegacyCli preserves the argv-backed path and existing periodic flusher
    // controls. The caller must retain argv for the process lifetime.
    const char* legacy_path = nullptr;
    bool legacy_compression = false;
    i32 legacy_level = 0;
    // SourceLive is an owned copy and never borrows parser, loader, or input
    // storage. It is not a publisher; #366 must consume it later.
    AccessLogSinkSpec source_live{};
};

core::Expected<AccessLogStartupResolution, AccessLogStartupResolutionError>
resolve_access_log_startup(const AccessLogStartupInputs& inputs);

enum class SourceAccessLogOpenErrorKind : u8 {
    InvalidSpec,
    OpenFailed,
    StatFailed,
    NotRegularFile,
};

struct SourceAccessLogOpenError {
    SourceAccessLogOpenErrorKind kind = SourceAccessLogOpenErrorKind::InvalidSpec;
    i32 system_error = 0;
};

// Narrow ownership wrapper for the one source-declared startup descriptor.
// It is move-only and closes exactly once.
class SourceAccessLogFd {
public:
    SourceAccessLogFd() = default;
    explicit SourceAccessLogFd(i32 fd) : fd_(fd) {}
    SourceAccessLogFd(const SourceAccessLogFd&) = delete;
    SourceAccessLogFd& operator=(const SourceAccessLogFd&) = delete;
    SourceAccessLogFd(SourceAccessLogFd&& other) noexcept;
    SourceAccessLogFd& operator=(SourceAccessLogFd&& other) noexcept;
    ~SourceAccessLogFd();

    i32 get() const { return fd_; }
    explicit operator bool() const { return fd_ >= 0; }
    void reset();

private:
    i32 fd_ = -1;
};

// Opens with O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK,
// then immediately requires fstat() to report a regular file. O_NONBLOCK is
// intentionally retained; it has no effect for regular files and guarantees a
// FIFO cannot block startup before the type gate.
core::Expected<SourceAccessLogFd, SourceAccessLogOpenError> open_source_access_log(
    const AccessLogSinkSpec& spec);

}  // namespace rut
